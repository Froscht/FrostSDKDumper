#pragma once

// =============================================================================
// ARC Raiders – GObjects external reader (newest patch)
//
// Architecture: FChunkedFixedUObjectArray (chunked object array)
//
// The game stores all UObjects in a chunked array accessed via encrypted
// global pointers. Each chunk holds up to 65536 FUObjectItems (20 bytes each).
//
// Key globals (RVAs relative to module base 0x140000000):
//   GOBJECT_ARRAY_DATA  0xDB4DD20  → encrypted FChunkedFixedUObjectArray*
//   SIMD tables at 0xAAA18A0, 0xAAA18B0, 0xAAF4740-0xAAF4760
//
// FUObjectItem layout (20 bytes):
//   +0x00 [8]  Object       UObject* (NOT encrypted)
//   +0x08 [4]  Flags
//   +0x0C [4]  ClusterRootIndex
//   +0x10 [4]  SerialNumber
//
// Chunk indexing:
//   chunk_index = index >> 16    (HIWORD)
//   item_index  = index & 0xFFFF (LOWORD)
//   chunk_ptr   = ChunkArray[chunk_index]
//   item        = chunk_ptr + 20 * item_index
//   object      = *(uint64_t*)item
// =============================================================================

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <utility>
#include <immintrin.h>
#include "kernel_module/include/memreader_iface.h"
#include "arc_decrypt.h"

namespace gobjects
{
    constexpr uint32_t FUOBJECTITEM_SIZE  = 20;
    constexpr uint32_t FUOBJECTITEM_OBJ  = 0;   // Object* at +0x00
    constexpr uint32_t CHUNK_ITEM_COUNT   = 65536; // items per chunk

    // ChunkPtr decrypt constants (from SIGNATURES.md section 3.7)
    constexpr uint64_t RVA_CHUNKPTR_KEY1  = 0xAB2DE50;  // pxor key1 (SIMD runtime table)
    constexpr uint64_t RVA_CHUNKPTR_KEY2  = 0xAB2DE60;  // pxor key2 (SIMD runtime table)
    constexpr uint32_t CHUNKPTR_PEB_ADD   = 0x72AC9D29;  // addend for PEB cookie
    constexpr uint8_t  CHUNKPTR_SHUFLO    = 0x72;         // pshuflw immediate
    constexpr int      CHUNKPTR_DATA_OFF  = 0x70;         // encrypted data at struct+0x70
    constexpr int      CHUNKPTR_ROL       = 43;           // ROL64 amount

    // ─────────────────────────────────────────────────────────────────────
    // GObjectArray – runtime context for FChunkedFixedUObjectArray access
    // ─────────────────────────────────────────────────────────────────────
    class GObjectArray {
    public:
        GObjectArray(uint64_t module_base, IMemoryReader& reader)
            : m_base(module_base), m_reader(reader),
              m_arrayBase(0), m_chunkPtr(0), m_numElements(0),
              m_pebAddr(0), m_pid(0), m_initialized(false)
        {
            memset(m_xorKey,   0, 16);
            memset(m_shufMask, 0, 16);
            memset(m_numMask1, 0, 16);
            memset(m_numMask2, 0, 16);
            memset(m_numShuf,  0, 16);
            memset(m_chunkKey1, 0, 16);
            memset(m_chunkKey2, 0, 16);
        }

        void SetPid(int pid) { m_pid = pid; }

        // Load SIMD tables, decrypt array base, count, and decrypt chunk ptr.
        bool Init() {
            if (m_initialized) return true;

            // Load SIMD tables from process memory
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_OBJARRAY_XOR,  m_xorKey,   16)) return false;
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_OBJARRAY_SHUF, m_shufMask, 16)) return false;
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_NUMELEM_MASK1, m_numMask1, 16)) return false;
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_NUMELEM_MASK2, m_numMask2, 16)) return false;
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_NUMELEM_SHUF,  m_numShuf,  16)) return false;

            // Validate SIMD tables (detect uninitialized game state)
            if (!ValidateSIMDTables()) {
                std::printf("[-] SIMD tables are invalid (game may not be fully loaded)\n");
                return false;
            }

            // Load ChunkPtr SIMD XOR keys
            if (!m_reader.Read(m_base + RVA_CHUNKPTR_KEY1, m_chunkKey1, 16)) return false;
            if (!m_reader.Read(m_base + RVA_CHUNKPTR_KEY2, m_chunkKey2, 16)) return false;

            // ── Stage 1: Find GObjectArray base ──────────────────────────
            m_arrayBase = DecryptObjectArray();
            m_numElements = DecryptNumElements(m_arrayBase);

            if (!m_arrayBase || m_numElements < 1000 || m_numElements > 2000000) {
                std::printf("[!] SIMD decrypt for ObjectArray failed (base=0x%llX count=%d), "
                    "trying XOR probe...\n",
                    (unsigned long long)m_arrayBase, m_numElements);

                // Try to find the XOR constant dynamically
                m_arrayBase = ProbeObjectArrayXOR();
                if (m_arrayBase)
                    m_numElements = DecryptNumElements(m_arrayBase);
            }

            if (!m_arrayBase || m_numElements < 1000 || m_numElements > 2000000) {
                std::printf("[!] XOR probe failed, trying heap scan...\n");
                m_arrayBase = ScanHeapForObjectArray();
                if (m_arrayBase)
                    m_numElements = DecryptNumElements(m_arrayBase);
            }

            if (!m_arrayBase || m_numElements < 1000) {
                std::printf("[-] GObjectArray init failed: base=0x%llX count=%d\n",
                    (unsigned long long)m_arrayBase, m_numElements);
                return false;
            }

            std::printf("[+] GObjectArray base=0x%llX  count=%d\n",
                (unsigned long long)m_arrayBase, m_numElements);

            // ── Stage 2: Find chunk pointer ──────────────────────────────
            m_pebAddr = FindPEB();
            if (m_pebAddr) {
                std::printf("[+] PEB address: 0x%llX\n", (unsigned long long)m_pebAddr);
                m_chunkPtr = DecryptChunkPtr();
            }

            if (!m_chunkPtr || !ValidateChunkPtr(m_chunkPtr)) {
                std::printf("[!] SIMD decrypt chunk ptr failed (got 0x%llX), trying brute-force PEB...\n",
                    (unsigned long long)m_chunkPtr);
                m_chunkPtr = BruteForceChunkPtr();
            }

            if (!m_chunkPtr) {
                m_chunkPtr = ProbeChunkPtr();
            }

            if (!m_chunkPtr) {
                std::printf("[!] All chunk pointer methods failed.\n");
                PrintDiagnostics();
                return false;
            }

            m_initialized = true;
            std::printf("[+] GObjectArray: base=0x%llX  count=%d  chunks=0x%llX\n",
                (unsigned long long)m_arrayBase, m_numElements,
                (unsigned long long)m_chunkPtr);
            return true;
        }

        bool IsInitialized() const { return m_initialized; }

        void SetChunkPtr(uint64_t ptr) {
            m_chunkPtr = ptr;
            if (m_arrayBase && m_numElements > 0 && m_chunkPtr)
                m_initialized = true;
        }

        uint64_t GetArrayBase()   const { return m_arrayBase; }
        int32_t  GetNumElements() const { return m_numElements; }
        uint64_t GetChunkPtr()    const { return m_chunkPtr; }

        uint64_t GetObjectPtr(int32_t index) const {
            if (!m_chunkPtr || index < 0 || index >= m_numElements)
                return 0;

            uint32_t chunk_idx = static_cast<uint32_t>(index) >> 16;
            uint32_t item_idx  = static_cast<uint16_t>(index);

            uint64_t chunk = 0;
            if (!m_reader.Read(m_chunkPtr + 8ULL * chunk_idx, &chunk, 8))
                return 0;
            if (!chunk) return 0;

            uint64_t obj = 0;
            m_reader.Read(chunk + (uint64_t)FUOBJECTITEM_SIZE * item_idx + FUOBJECTITEM_OBJ, &obj, 8);
            return obj;
        }

        void IterateObjects(
                void (*callback)(uint64_t obj, int32_t idx, void* ctx),
                void* ctx,
                int32_t max_count = 0) const
        {
            int32_t total = m_numElements;
            if (max_count > 0 && total > max_count)
                total = max_count;

            for (int32_t i = 0; i < total; ++i) {
                uint64_t obj = GetObjectPtr(i);
                if (!obj) continue;
                callback(obj, i, ctx);
            }
        }

        void PrintDiagnostics() const {
            std::printf("[diag] FChunkedFixedUObjectArray @ 0x%llX\n",
                (unsigned long long)m_arrayBase);
            std::printf("[diag] NumElements = %d\n", m_numElements);

            if (m_arrayBase) {
                uint8_t raw[0x100] = {};
                m_reader.Read(m_arrayBase, raw, 0x100);
                std::printf("[diag] Raw struct bytes:\n");
                for (int row = 0; row < 0x10; ++row) {
                    std::printf("  +%02X: ", row * 16);
                    for (int col = 0; col < 16; ++col)
                        std::printf("%02X ", raw[row * 16 + col]);
                    std::printf("\n");
                }

                std::printf("[diag] Potential heap pointers in struct:\n");
                for (int off = 0; off <= 0xF8; off += 8) {
                    uint64_t v = 0;
                    memcpy(&v, raw + off, 8);
                    if (v > 0x10000ULL && v < 0x7FFFFFFFFFFFULL &&
                        !(v >= m_base && v < m_base + 0x10000000ULL))
                        std::printf("  +0x%02X: 0x%llX\n", off, (unsigned long long)v);
                }
            }

            if (m_arrayBase) {
                uint64_t vtbl_ptr = 0;
                m_reader.Read(m_arrayBase + 0x40, &vtbl_ptr, 8);
                if (vtbl_ptr) {
                    uint64_t func_ptr = 0;
                    m_reader.Read(vtbl_ptr + 48, &func_ptr, 8);
                    std::printf("[diag] GetChunkPtr virtual call:\n");
                    std::printf("  vtable @ base+0x40 = 0x%llX\n", (unsigned long long)vtbl_ptr);
                    std::printf("  func   @ vtbl+48   = 0x%llX (RVA=0x%llX)\n",
                        (unsigned long long)func_ptr,
                        (unsigned long long)(func_ptr >= m_base ? func_ptr - m_base : func_ptr));
                }
            }
        }

    private:
        uint64_t       m_base;
        IMemoryReader& m_reader;
        uint64_t       m_arrayBase;
        uint64_t       m_chunkPtr;
        int32_t        m_numElements;
        uint64_t       m_pebAddr;
        int            m_pid;
        bool           m_initialized;

        // SIMD tables (loaded during Init)
        alignas(16) uint8_t m_xorKey[16];
        alignas(16) uint8_t m_shufMask[16];
        alignas(16) uint8_t m_numMask1[16];
        alignas(16) uint8_t m_numMask2[16];
        alignas(16) uint8_t m_numShuf[16];
        alignas(16) uint8_t m_chunkKey1[16];
        alignas(16) uint8_t m_chunkKey2[16];

        // ── Validate SIMD tables are populated (not all zeros) ───────────
        bool ValidateSIMDTables() {
            auto isAllZero = [](const uint8_t* buf, int len) {
                for (int i = 0; i < len; ++i)
                    if (buf[i] != 0) return false;
                return true;
            };
            if (isAllZero(m_xorKey, 16) && isAllZero(m_shufMask, 16)) {
                std::printf("[dbg] ObjectArray SIMD tables are all zeros\n");
                return false;
            }
            if (isAllZero(m_numMask1, 16) && isAllZero(m_numMask2, 16) && isAllZero(m_numShuf, 16)) {
                std::printf("[dbg] NumElements SIMD tables are all zeros\n");
                return false;
            }
            return true;
        }

        // ── Compute SIMD intermediate for ObjectArray (before final XOR) ─
        uint64_t ComputeObjectArrayIntermediate() {
            alignas(16) uint8_t data[16] = {};
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_GOBJECT_ARRAY_DATA + 32, data, 16))
                return 0;

            __m128i v3 = _mm_xor_si128(
                _mm_load_si128((const __m128i*)data),
                _mm_load_si128((const __m128i*)m_xorKey));

            __m128i rotated = _mm_or_si128(
                _mm_slli_epi64(v3, 0x22),
                _mm_srli_epi64(v3, 0x1E));

            __m128i shuffled = _mm_shuffle_epi8(rotated,
                _mm_load_si128((const __m128i*)m_shufMask));

            uint64_t result;
            _mm_storel_epi64((__m128i*)&result, shuffled);
            return result;
        }

        // ── Decrypt FChunkedFixedUObjectArray pointer ────────────────────
        uint64_t DecryptObjectArray() {
            uint64_t intermediate = ComputeObjectArrayIntermediate();
            if (!intermediate) return 0;
            return intermediate ^ ArcDecrypt::GOBJECT_ARRAY_XOR;
        }

        // ── Probe for ObjectArray XOR constant ───────────────────────────
        // Tries nearby .rdata addresses to find the XOR key if the hardcoded
        // one is per-session (VMProtect-mutated).
        uint64_t ProbeObjectArrayXOR() {
            uint64_t intermediate = ComputeObjectArrayIntermediate();
            if (!intermediate) return 0;

            // Strategy 1: scan .rdata near the known SIMD tables for 8-byte
            // values that, when XORed with intermediate, produce a valid base.
            const uint64_t scan_ranges[][2] = {
                {0xAAA1880, 0xAAA1A00},   // near ObjectArray SIMD tables
                {0xAAF4700, 0xAAF4800},   // near NumElements tables
                {0xAB2DE00, 0xAB2DF00},   // near ChunkPtr keys
            };
            for (auto& range : scan_ranges) {
                for (uint64_t rva = range[0]; rva < range[1]; rva += 8) {
                    uint64_t candidate_xor = 0;
                    if (!m_reader.Read(m_base + rva, &candidate_xor, 8)) continue;
                    if (!candidate_xor) continue;
                    uint64_t candidate = intermediate ^ candidate_xor;
                    int32_t count = DecryptNumElements(candidate);
                    if (count > 5000 && count < 2000000) {
                        std::printf("[+] Found ObjectArray XOR at RVA 0x%llX = 0x%llX → base=0x%llX count=%d\n",
                            (unsigned long long)rva, (unsigned long long)candidate_xor,
                            (unsigned long long)candidate, count);
                        return candidate;
                    }
                }
            }

            // Strategy 2: read the encrypted data area itself for XOR keys
            // (game sometimes stores keys near the encrypted pointer)
            for (int off = -64; off <= 128; off += 8) {
                if (off == 32) continue; // skip the data itself
                uint64_t candidate_xor = 0;
                if (!m_reader.Read(m_base + ArcDecrypt::RVA_GOBJECT_ARRAY_DATA + off, &candidate_xor, 8))
                    continue;
                if (!candidate_xor) continue;
                uint64_t candidate = intermediate ^ candidate_xor;
                int32_t count = DecryptNumElements(candidate);
                if (count > 5000 && count < 2000000) {
                    std::printf("[+] Found ObjectArray XOR at data%+d = 0x%llX → base=0x%llX count=%d\n",
                        off, (unsigned long long)candidate_xor,
                        (unsigned long long)candidate, count);
                    return candidate;
                }
            }

            return 0;
        }

        // ── Scan heap for FChunkedFixedUObjectArray ──────────────────────
        // Uses DecryptNumElements (all-dynamic SIMD, no hardcoded constants)
        // to validate candidates from /proc/pid/maps heap regions.
        uint64_t ScanHeapForObjectArray() {
            if (m_pid <= 0) return 0;

            char path[64];
            snprintf(path, sizeof(path), "/proc/%d/maps", m_pid);
            FILE* f = fopen(path, "r");
            if (!f) {
                std::printf("[!] Cannot open %s for heap scan\n", path);
                return 0;
            }

            // Collect rw- anonymous regions (heap candidates)
            struct Region { uint64_t start, end; };
            std::vector<Region> regions;
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                uint64_t start = 0, end = 0;
                char perms[5] = {};
                sscanf(line, "%llx-%llx %4s", (unsigned long long*)&start, (unsigned long long*)&end, perms);
                if (perms[0] != 'r' || perms[1] != 'w') continue;
                uint64_t size = end - start;
                // Only large anonymous regions (likely heap/mmap)
                if (size < 0x100000) continue;
                if (start < 0x10000 || start > 0x7FFFFFFFFFFFULL) continue;
                // Skip module range
                if (start >= m_base && start < m_base + 0x10000000ULL) continue;
                regions.push_back({start, end});
            }
            fclose(f);

            std::printf("[*] Heap scan: %zu regions to probe\n", regions.size());

            for (const auto& reg : regions) {
                // Probe first 256 pages of each large region
                uint64_t scan_end = reg.start + 0x100000;
                if (scan_end > reg.end) scan_end = reg.end;

                for (uint64_t addr = reg.start; addr < scan_end; addr += 0x1000) {
                    int32_t count = DecryptNumElements(addr);
                    if (count > 5000 && count < 2000000) {
                        // Validate further: check that ChunkPtr area has data
                        uint8_t probe[16] = {};
                        if (m_reader.Read(addr + CHUNKPTR_DATA_OFF, probe, 16)) {
                            bool allzero = true;
                            for (int i = 0; i < 16; ++i)
                                if (probe[i]) { allzero = false; break; }
                            if (!allzero) {
                                std::printf("[+] Heap scan found candidate @ 0x%llX count=%d\n",
                                    (unsigned long long)addr, count);
                                return addr;
                            }
                        }
                    }
                }
            }

            std::printf("[!] Heap scan found no candidates\n");
            return 0;
        }

        // ── Decrypt NumElements from FChunkedFixedUObjectArray ──────────
        // Uses ONLY dynamic SIMD tables — no hardcoded constants.
        int32_t DecryptNumElements(uint64_t array_base) {
            if (!array_base) return 0;

            alignas(16) uint8_t data[16] = {};
            if (!m_reader.Read(array_base + 9 * 16, data, 16))
                return 0;

            __m128i si = _mm_load_si128((const __m128i*)data);

            __m128i blended = _mm_or_si128(
                _mm_and_si128(si,    _mm_load_si128((const __m128i*)m_numMask1)),
                _mm_andnot_si128(si, _mm_load_si128((const __m128i*)m_numMask2)));

            __m128i shuffled = _mm_shuffle_epi8(blended,
                _mm_load_si128((const __m128i*)m_numShuf));

            __m128i shifted = _mm_srli_epi64(shuffled, 5);

            return _mm_cvtsi128_si32(shifted);
        }

        // ── Find PEB address (Wine: search for ImageBaseAddress in low mem) ──
        uint64_t FindPEB() {
            // PEB+0x10 = ImageBaseAddress = module base (0x140000000)
            const uint64_t candidates[] = {
                0x7FFD0000, 0x7FFC0000, 0x7FFB0000, 0x7FFA0000,
                0x00060000, 0x00050000, 0x00040000, 0x00030000,
            };
            for (uint64_t addr : candidates) {
                uint64_t img_base = 0;
                if (m_reader.Read(addr + 0x10, &img_base, 8) && img_base == m_base)
                    return addr;
            }
            for (uint64_t addr = 0x7FF00000; addr < 0x7FFE0000; addr += 0x1000) {
                uint64_t img_base = 0;
                if (m_reader.Read(addr + 0x10, &img_base, 8) && img_base == m_base)
                    return addr;
            }
            for (uint64_t addr = 0x00010000; addr < 0x00200000; addr += 0x1000) {
                uint64_t img_base = 0;
                if (m_reader.Read(addr + 0x10, &img_base, 8) && img_base == m_base)
                    return addr;
            }
            return 0;
        }

        // ── Runtime pshuflw ─────────────────────────────────────────────
        static __m128i RuntimeShuffleLo(__m128i v, uint8_t imm) {
            alignas(16) uint16_t w[8];
            _mm_store_si128((__m128i*)w, v);
            uint16_t lo[4] = { w[0], w[1], w[2], w[3] };
            w[0] = lo[(imm >> 0) & 3];
            w[1] = lo[(imm >> 2) & 3];
            w[2] = lo[(imm >> 4) & 3];
            w[3] = lo[(imm >> 6) & 3];
            return _mm_load_si128((const __m128i*)w);
        }

        // ══════════════════════════════════════════════════════════════════
        // Mini x86-64 SIMD emulator for VMProtect-polymorphic decrypt stubs
        //
        // VMProtect's mutation engine randomizes the decrypt function on
        // every game launch.  Instead of pattern-matching, we emulate the
        // instruction stream from the entry point to the first RET (C3).
        //
        // ── Comprehensive opcode coverage ──────────────────────────────
        //
        // Movement:
        //   movq xmm,[mem]   F3 0F 7E /r        load 8 bytes, zero upper
        //   movdqa xmm,xmm   66 0F 6F /r        copy / load aligned 16
        //   movdqu xmm,[mem]  F3 0F 6F /r        load unaligned 16
        //   movd/q xmm,r32/64 66 [W] 0F 6E /r   GPR → XMM
        //   movaps xmm,xmm    0F 28 /r           copy (no 66 prefix)
        //
        // Shifts (immediate):
        //   psrlw/psraw/psllw  66 0F 71 /2,/4,/6 imm  word shifts
        //   psrld/psrad/pslld  66 0F 72 /2,/4,/6 imm  dword shifts
        //   psrlq/psllq        66 0F 73 /2,/6 imm     qword shifts
        //   psrldq/pslldq      66 0F 73 /3,/7 imm     byte shifts
        //
        // Logical:
        //   pand    66 0F DB    AND
        //   pandn   66 0F DF    AND-NOT (~dst & src)
        //   por     66 0F EB    OR
        //   pxor    66 0F EF    XOR  (reg-reg, [rip+disp32], [rdx])
        //
        // Arithmetic:
        //   paddb/w/d/q   66 0F FC/FD/FE/D4    add
        //   psubb/w/d/q   66 0F F8/F9/FA/FB    subtract
        //   pmullw         66 0F D5             multiply words (lo16)
        //   pmulld         66 0F 38 40          multiply dwords (SSE4.1)
        //
        // Shuffle:
        //   pshufd    66 0F 70 /r imm     dword shuffle
        //   pshuflw   F2 0F 70 /r imm     low-word shuffle
        //   pshufhw   F3 0F 70 /r imm     high-word shuffle
        //   pshufb    66 0F 38 00 /r      byte shuffle (SSSE3)
        //   palignr   66 0F 3A 0F /r imm  byte align (SSSE3)
        //   punpckl*  66 0F 60-62,6C      unpack low
        //   punpckh*  66 0F 68-6A,6D      unpack high
        //
        // Comparison (mask generation):
        //   pcmpeqb/w/d  66 0F 74/75/76    all-ones when equal (for NOT)
        //
        // GPR operations (VMProtect may use any GPR for PEB cookie):
        //   mov r32, imm32        B8+rd  (or REX.B + B8+rd for r8d-r15d)
        //   mov r64, imm64        REX.W B8+rd imm64  (10-byte form)
        //   add rax, gs:[0x60]    65 48 03 04 25 60 00 00 00
        //   xor r64, r64          REX.W 31/33 modrm
        //   add/sub/or/and r64    REX.W 01/29/09/21/31 modrm
        // ══════════════════════════════════════════════════════════════════

        uint64_t EmulateChunkPtrDecrypt(const uint8_t* c, int len,
                                         const uint8_t* input_data,
                                         uint64_t peb_addr, uint64_t func_addr)
        {
            alignas(16) uint8_t xmm[8][16] = {};   // xmm0-xmm7
            uint64_t gpr[16] = {};                   // rax=0,rcx=1,rdx=2,rbx=3,...
            // GPR index from ModRM rm or reg field + REX.B/R
            // 0=rax 1=rcx 2=rdx 3=rbx 4=rsp 5=rbp 6=rsi 7=rdi 8-15=r8-r15

            // Helper: read RIP-relative 16 bytes from process memory
            auto readMem128 = [&](int ip_after_insn, int32_t disp, uint8_t* out) {
                uint64_t target = func_addr + ip_after_insn + disp;
                m_reader.Read(target, out, 16);
            };

            // Helper: decode ModRM reg fields (handles REX.R and REX.B)
            // Returns next offset past the operand
            auto decodeModRM = [](uint8_t modrm, bool rex_r, bool rex_b,
                                   int& reg, int& rm) {
                reg = ((modrm >> 3) & 7) | (rex_r ? 8 : 0);
                rm  = (modrm & 7) | (rex_b ? 8 : 0);
            };

            int ip = 0;
            while (ip < len) {
                if (c[ip] == 0xC3) break;  // RET

                // ── NOP / padding ────────────────────────────────────────
                if (c[ip] == 0x90) { ip++; continue; }
                // multi-byte NOP: 0F 1F ...
                if (c[ip] == 0x0F && ip+2 < len && c[ip+1] == 0x1F) {
                    uint8_t modrm = c[ip+2];
                    int mod = modrm >> 6;
                    ip += (mod == 0) ? 3 : (mod == 1) ? 4 : 7;
                    continue;
                }

                // ── REX prefix + GPR operations ─────────────────────────
                if ((c[ip] & 0xF0) == 0x40 && ip+1 < len) {
                    uint8_t rex = c[ip];
                    bool rex_w = (rex & 0x08) != 0;
                    bool rex_b = (rex & 0x01) != 0;
                    uint8_t next = c[ip+1];

                    // REX.W B8-BF imm64 — mov r64, imm64 (10-byte form)
                    if (rex_w && next >= 0xB8 && next <= 0xBF && ip+10 <= len) {
                        int reg = (next - 0xB8) | (rex_b ? 8 : 0);
                        uint64_t imm; memcpy(&imm, c+ip+2, 8);
                        gpr[reg] = imm;
                        ip += 10;
                        continue;
                    }
                    // REX 31/33 modrm — xor r64, r64
                    if (rex_w && (next == 0x31 || next == 0x33) && ip+3 <= len) {
                        uint8_t modrm = c[ip+2];
                        if ((modrm & 0xC0) == 0xC0) {
                            int src, dst;
                            if (next == 0x31) { // xor r/m, r
                                src = ((modrm>>3)&7) | ((rex&0x04)?8:0);
                                dst = (modrm&7) | (rex_b?8:0);
                            } else { // xor r, r/m
                                dst = ((modrm>>3)&7) | ((rex&0x04)?8:0);
                                src = (modrm&7) | (rex_b?8:0);
                            }
                            gpr[dst] ^= gpr[src];
                            ip += 3; continue;
                        }
                    }
                    // REX + 66/F2/F3/0F → fall through to SSE handlers
                    if (next == 0x0F || next == 0x66 || next == 0xF2 || next == 0xF3) {
                        ip++; continue; // skip REX, re-enter loop for SSE
                    }
                    // Other REX GPR ops: skip instruction (best effort)
                    ip += 2; continue;
                }

                // ── mov r32, imm32 (B8-BF, no REX) ─────────────────────
                if (c[ip] >= 0xB8 && c[ip] <= 0xBF && ip+5 <= len) {
                    int reg = c[ip] - 0xB8;
                    uint32_t imm; memcpy(&imm, c+ip+1, 4);
                    gpr[reg] = imm;  // zero-extended
                    ip += 5;
                    // gs:[0x60] add: 65 48 03 04 25 60 00 00 00
                    if (ip+9 <= len && c[ip]==0x65 && c[ip+1]==0x48 &&
                        c[ip+2]==0x03 && c[ip+3]==0x04 && c[ip+4]==0x25 &&
                        c[ip+5]==0x60) {
                        gpr[0] += peb_addr; // rax += PEB
                        ip += 9;
                    }
                    continue;
                }

                // ── gs:[0x60] add (standalone, if not consumed after mov) ──
                if (c[ip] == 0x65 && ip+9 <= len && c[ip+1]==0x48 &&
                    c[ip+2]==0x03 && c[ip+3]==0x04 && c[ip+4]==0x25 &&
                    c[ip+5]==0x60 && c[ip+6]==0x00 && c[ip+7]==0x00 && c[ip+8]==0x00) {
                    gpr[0] += peb_addr; // add rax, gs:[0x60]
                    ip += 9; continue;
                }

                // ── F3 prefix: movq load / movdqu / pshufhw ─────────────
                if (c[ip] == 0xF3 && ip+1 < len) {
                    int off = ip + 1;
                    if ((c[off] & 0xF0) == 0x40) off++; // REX
                    if (off+3 <= len && c[off]==0x0F) {
                        uint8_t op2 = c[off+1];
                        uint8_t modrm = c[off+2];
                        int reg = (modrm >> 3) & 7, rm = modrm & 7;

                        // F3 0F 7E /r — movq xmm, [mem]/xmm (load 8, zero hi)
                        if (op2 == 0x7E) {
                            if ((modrm & 0xC7) == 0x02) // [rdx]
                                { memcpy(xmm[reg], input_data, 8); memset(xmm[reg]+8,0,8); }
                            else if ((modrm & 0xC0) == 0xC0) // reg
                                { memcpy(xmm[reg], xmm[rm], 8); memset(xmm[reg]+8,0,8); }
                            ip = off+3; continue;
                        }
                        // F3 0F 6F /r — movdqu xmm, [mem]/xmm
                        if (op2 == 0x6F) {
                            if ((modrm & 0xC7) == 0x02) memcpy(xmm[reg], input_data, 16);
                            else if ((modrm & 0xC0) == 0xC0) memcpy(xmm[reg], xmm[rm], 16);
                            ip = off+3; continue;
                        }
                        // F3 0F 70 /r imm — pshufhw
                        if (op2 == 0x70 && off+3 < len) {
                            uint8_t imm = c[off+3];
                            alignas(16) uint16_t w[8];
                            _mm_store_si128((__m128i*)w, _mm_load_si128((const __m128i*)xmm[rm]));
                            uint16_t hi[4] = {w[4],w[5],w[6],w[7]};
                            w[4]=hi[(imm>>0)&3]; w[5]=hi[(imm>>2)&3];
                            w[6]=hi[(imm>>4)&3]; w[7]=hi[(imm>>6)&3];
                            _mm_store_si128((__m128i*)xmm[reg], _mm_load_si128((const __m128i*)w));
                            ip = off+4; continue;
                        }
                    }
                    ip++; continue;
                }

                // ── F2 prefix: pshuflw ──────────────────────────────────
                if (c[ip] == 0xF2 && ip+1 < len) {
                    int off = ip + 1;
                    if ((c[off] & 0xF0) == 0x40) off++;
                    if (off+3 < len && c[off]==0x0F && c[off+1]==0x70) {
                        uint8_t modrm = c[off+2];
                        int reg = (modrm>>3)&7, rm = modrm&7;
                        uint8_t imm = c[off+3];
                        _mm_store_si128((__m128i*)xmm[reg],
                            RuntimeShuffleLo(_mm_load_si128((const __m128i*)xmm[rm]), imm));
                        ip = off+4; continue;
                    }
                    ip++; continue;
                }

                // ── 0F xx (no 66 prefix): movaps ────────────────────────
                if (c[ip] == 0x0F && ip+2 < len) {
                    uint8_t op2 = c[ip+1], modrm = c[ip+2];
                    int reg = (modrm>>3)&7, rm = modrm&7;
                    // 0F 28 /r — movaps xmm, xmm
                    if (op2 == 0x28 && (modrm & 0xC0) == 0xC0) {
                        memcpy(xmm[reg], xmm[rm], 16);
                        ip += 3; continue;
                    }
                    // 0F 10 /r — movups xmm, xmm/[mem]
                    if (op2 == 0x10 && (modrm & 0xC0) == 0xC0) {
                        memcpy(xmm[reg], xmm[rm], 16);
                        ip += 3; continue;
                    }
                }

                // ── 66 prefix: all SSE2/SSSE3 ops ───────────────────────
                if (c[ip] == 0x66 && ip+1 < len) {
                    int off = ip + 1;
                    bool rex_w = false, rex_r = false, rex_b = false;
                    if ((c[off] & 0xF0) == 0x40) {
                        rex_w = (c[off] & 0x08) != 0;
                        rex_r = (c[off] & 0x04) != 0;
                        rex_b = (c[off] & 0x01) != 0;
                        off++;
                    }
                    if (off+1 >= len) { ip++; continue; }

                    uint8_t op1 = c[off], op2 = c[off+1];

                    if (op1 != 0x0F) { ip++; continue; }
                    // Now op2 is the second opcode byte after 0F

                    // ── 66 0F 6F — movdqa xmm, xmm/[mem] ───────────────
                    if (op2 == 0x6F && off+2 < len) {
                        uint8_t modrm = c[off+2];
                        int reg, rm; decodeModRM(modrm, rex_r, rex_b, reg, rm);
                        if ((modrm & 0xC0) == 0xC0) memcpy(xmm[reg&7], xmm[rm&7], 16);
                        else if ((modrm & 0xC7) == 0x02) memcpy(xmm[reg&7], input_data, 16);
                        ip = off+3; continue;
                    }
                    // ── 66 [W] 0F 6E — movd/movq xmm, r32/r64 ──────────
                    if (op2 == 0x6E && off+2 < len) {
                        uint8_t modrm = c[off+2];
                        int xdst = (modrm >> 3) & 7;
                        int gsrc = (modrm & 7) | (rex_b ? 8 : 0);
                        uint64_t val = gpr[gsrc];
                        memcpy(xmm[xdst], &val, rex_w ? 8 : 4);
                        if (!rex_w) memset(xmm[xdst]+4, 0, 12);
                        else memset(xmm[xdst]+8, 0, 8);
                        ip = off+3; continue;
                    }

                    // ── 66 0F 71 /r imm — psrlw(/2) psraw(/4) psllw(/6) ─
                    if (op2 == 0x71 && off+3 < len) {
                        int r = (c[off+2]>>3)&7, d = c[off+2]&7;
                        uint8_t imm = c[off+3];
                        __m128i v = _mm_load_si128((const __m128i*)xmm[d]);
                        if      (r==2) v = _mm_srli_epi16(v, imm);
                        else if (r==4) v = _mm_srai_epi16(v, imm);
                        else if (r==6) v = _mm_slli_epi16(v, imm);
                        _mm_store_si128((__m128i*)xmm[d], v);
                        ip = off+4; continue;
                    }
                    // ── 66 0F 72 /r imm — psrld(/2) psrad(/4) pslld(/6) ─
                    if (op2 == 0x72 && off+3 < len) {
                        int r = (c[off+2]>>3)&7, d = c[off+2]&7;
                        uint8_t imm = c[off+3];
                        __m128i v = _mm_load_si128((const __m128i*)xmm[d]);
                        if      (r==2) v = _mm_srli_epi32(v, imm);
                        else if (r==4) v = _mm_srai_epi32(v, imm);
                        else if (r==6) v = _mm_slli_epi32(v, imm);
                        _mm_store_si128((__m128i*)xmm[d], v);
                        ip = off+4; continue;
                    }
                    // ── 66 0F 73 /r imm — psrlq(/2) psrldq(/3) psllq(/6) pslldq(/7)
                    if (op2 == 0x73 && off+3 < len) {
                        int r = (c[off+2]>>3)&7, d = c[off+2]&7;
                        uint8_t imm = c[off+3];
                        __m128i v = _mm_load_si128((const __m128i*)xmm[d]);
                        if      (r==2) v = _mm_srli_epi64(v, imm);
                        else if (r==3) { // psrldq: byte shift right
                            alignas(16) uint8_t tmp[32] = {};
                            _mm_store_si128((__m128i*)tmp, v);
                            memset(tmp+16, 0, 16);
                            v = _mm_load_si128((const __m128i*)(tmp + (imm > 16 ? 16 : imm)));
                        }
                        else if (r==6) v = _mm_slli_epi64(v, imm);
                        else if (r==7) { // pslldq: byte shift left
                            alignas(16) uint8_t tmp[32] = {};
                            _mm_store_si128((__m128i*)(tmp + 16), v);
                            int shift = imm > 16 ? 16 : imm;
                            v = _mm_load_si128((const __m128i*)(tmp + 16 - shift));
                        }
                        _mm_store_si128((__m128i*)xmm[d], v);
                        ip = off+4; continue;
                    }

                    // ── Two-operand reg-reg SSE ops: 66 0F xx modrm ──────
                    // Handle all reg-reg and [rip+disp32] forms
                    if (off+2 < len) {
                        uint8_t modrm = c[off+2];
                        int dst = (modrm>>3)&7, src = modrm&7;
                        bool is_rr  = (modrm & 0xC0) == 0xC0;
                        bool is_rip = (modrm & 0xC7) == 0x05;
                        bool is_rdx = (modrm & 0xC7) == 0x02;

                        // Load src operand
                        alignas(16) uint8_t src_data[16] = {};
                        int next_ip = off + 3;
                        if (is_rr) {
                            memcpy(src_data, xmm[src], 16);
                        } else if (is_rip && off+6 < len) {
                            int32_t disp; memcpy(&disp, c+off+3, 4);
                            next_ip = off + 7;
                            readMem128(next_ip, disp - (next_ip - (off+7)), src_data);
                            // Correct: target = func_addr + next_ip_of_insn + disp
                            // The readMem128 helper already does this
                            uint64_t target = func_addr + next_ip + disp;
                            // Re-read with correct offset
                            m_reader.Read(func_addr + (off+7) + disp, src_data, 16);
                        } else if (is_rdx) {
                            memcpy(src_data, input_data, 16);
                        } else if (op2 != 0x38 && op2 != 0x3A) {
                            ip++; continue; // unsupported addressing (two-byte ops only)
                        }
                        // For 0x38/0x3A three-byte opcodes, fall through —
                        // they handle their own src loading below.

                        __m128i a = _mm_load_si128((const __m128i*)xmm[dst]);
                        __m128i b = _mm_load_si128((const __m128i*)src_data);
                        bool handled = true;

                        switch (op2) {
                        // ── Logical ──
                        case 0xDB: a = _mm_and_si128(a, b); break;          // pand
                        case 0xDF: a = _mm_andnot_si128(a, b); break;       // pandn
                        case 0xEB: a = _mm_or_si128(a, b); break;           // por
                        case 0xEF: a = _mm_xor_si128(a, b); break;          // pxor
                        // ── Arithmetic ──
                        case 0xFC: a = _mm_add_epi8(a, b); break;           // paddb
                        case 0xFD: a = _mm_add_epi16(a, b); break;          // paddw
                        case 0xFE: a = _mm_add_epi32(a, b); break;          // paddd
                        case 0xD4: a = _mm_add_epi64(a, b); break;          // paddq
                        case 0xF8: a = _mm_sub_epi8(a, b); break;           // psubb
                        case 0xF9: a = _mm_sub_epi16(a, b); break;          // psubw
                        case 0xFA: a = _mm_sub_epi32(a, b); break;          // psubd
                        case 0xFB: a = _mm_sub_epi64(a, b); break;          // psubq
                        case 0xD5: a = _mm_mullo_epi16(a, b); break;        // pmullw
                        // ── Compare (mask generation) ──
                        case 0x74: a = _mm_cmpeq_epi8(a, b); break;         // pcmpeqb
                        case 0x75: a = _mm_cmpeq_epi16(a, b); break;        // pcmpeqw
                        case 0x76: a = _mm_cmpeq_epi32(a, b); break;        // pcmpeqd
                        // ── Unpack ──
                        case 0x60: a = _mm_unpacklo_epi8(a, b); break;      // punpcklbw
                        case 0x61: a = _mm_unpacklo_epi16(a, b); break;     // punpcklwd
                        case 0x62: a = _mm_unpacklo_epi32(a, b); break;     // punpckldq
                        case 0x6C: a = _mm_unpacklo_epi64(a, b); break;     // punpcklqdq
                        case 0x68: a = _mm_unpackhi_epi8(a, b); break;      // punpckhbw
                        case 0x69: a = _mm_unpackhi_epi16(a, b); break;     // punpckhwd
                        case 0x6A: a = _mm_unpackhi_epi32(a, b); break;     // punpckhdq
                        case 0x6D: a = _mm_unpackhi_epi64(a, b); break;     // punpckhqdq
                        // ── pshufd ──
                        case 0x70: {
                            if (next_ip < len) {
                                uint8_t imm = c[next_ip]; next_ip++;
                                alignas(16) uint32_t dw[4], out[4];
                                _mm_store_si128((__m128i*)dw, b);
                                out[0]=dw[(imm>>0)&3]; out[1]=dw[(imm>>2)&3];
                                out[2]=dw[(imm>>4)&3]; out[3]=dw[(imm>>6)&3];
                                a = _mm_load_si128((const __m128i*)out);
                            }
                            break;
                        }
                        default: handled = false; break;
                        }

                        if (handled) {
                            _mm_store_si128((__m128i*)xmm[dst], a);
                            ip = next_ip; continue;
                        }

                        // ── 66 0F 38 xx — SSSE3/SSE4 three-byte opcodes ──
                        if (op2 == 0x38 && off+3 < len) {
                            uint8_t op3 = c[off+2];
                            modrm = c[off+3];
                            dst = (modrm>>3)&7; src = modrm&7;
                            is_rr  = (modrm & 0xC0) == 0xC0;
                            is_rip = (modrm & 0xC7) == 0x05;

                            // Load src
                            memset(src_data, 0, 16);
                            next_ip = off + 4;
                            if (is_rr) {
                                memcpy(src_data, xmm[src], 16);
                            } else if (is_rip && off+7 < len) {
                                int32_t disp; memcpy(&disp, c+off+4, 4);
                                next_ip = off + 8;
                                m_reader.Read(func_addr + next_ip + disp, src_data, 16);
                            } else { ip++; continue; }

                            a = _mm_load_si128((const __m128i*)xmm[dst]);
                            b = _mm_load_si128((const __m128i*)src_data);

                            if (op3 == 0x00) {          // pshufb
                                a = _mm_shuffle_epi8(a, b);
                                _mm_store_si128((__m128i*)xmm[dst], a);
                                ip = next_ip; continue;
                            }
                            if (op3 == 0x40) {          // pmulld (SSE4.1)
                                a = _mm_mullo_epi32(a, b);
                                _mm_store_si128((__m128i*)xmm[dst], a);
                                ip = next_ip; continue;
                            }
                            ip++; continue;
                        }

                        // ── 66 0F 3A xx — SSSE3 three-byte with imm8 ─────
                        if (op2 == 0x3A && off+4 < len) {
                            uint8_t op3 = c[off+2];
                            modrm = c[off+3];
                            dst = (modrm>>3)&7; src = modrm&7;
                            uint8_t imm = c[off+4];

                            if (op3 == 0x0F && (modrm & 0xC0) == 0xC0) { // palignr
                                a = _mm_load_si128((const __m128i*)xmm[dst]);
                                b = _mm_load_si128((const __m128i*)xmm[src]);
                                // palignr: concatenate dst:src, shift right by imm bytes
                                alignas(16) uint8_t concat[32];
                                memcpy(concat, xmm[src], 16);
                                memcpy(concat+16, xmm[dst], 16);
                                if (imm <= 16) memcpy(xmm[dst], concat+imm, 16);
                                else memset(xmm[dst], 0, 16);
                                ip = off+5; continue;
                            }
                            if (op3 == 0x0E && (modrm & 0xC0) == 0xC0) { // pblendw
                                alignas(16) uint16_t wa[8], wb[8];
                                _mm_store_si128((__m128i*)wa, _mm_load_si128((const __m128i*)xmm[dst]));
                                _mm_store_si128((__m128i*)wb, _mm_load_si128((const __m128i*)xmm[src]));
                                for (int i = 0; i < 8; i++)
                                    if (imm & (1 << i)) wa[i] = wb[i];
                                _mm_store_si128((__m128i*)xmm[dst], _mm_load_si128((const __m128i*)wa));
                                ip = off+5; continue;
                            }
                            ip++; continue;
                        }
                    }
                    ip++; continue;
                }

                // Skip any unhandled byte
                ip++;
            }

            uint64_t result;
            memcpy(&result, xmm[0], 8);
            return result;
        }

        // ── Decrypt ChunkPtr via SIMD emulation ─────────────────────────
        uint64_t DecryptChunkPtr() {
            if (!m_arrayBase || !m_pebAddr) return 0;

            // Get function address from vtable at base+0x40
            uint64_t vtbl_ptr = 0;
            if (!m_reader.Read(m_arrayBase + 0x40, &vtbl_ptr, 8) || !vtbl_ptr) return 0;
            uint64_t func_addr = 0;
            if (!m_reader.Read(vtbl_ptr + 48, &func_addr, 8) || !func_addr) return 0;

            // Read function code (only need up to first ret, typically < 128 bytes)
            uint8_t code[256] = {};
            if (!m_reader.Read(func_addr, code, 256)) return 0;

            // Find first ret to bound emulation
            int path_len = 256;
            for (int i = 4; i < 256; i++) {
                if (code[i] == 0xC3) { path_len = i + 1; break; }
            }

            std::printf("[dbg] ChunkPtr func @ RVA 0x%llX, path1 len=%d\n",
                (unsigned long long)(func_addr - m_base), path_len);

            // Read encrypted data from base+0x70
            alignas(16) uint8_t data[16] = {};
            if (!m_reader.Read(m_arrayBase + CHUNKPTR_DATA_OFF, data, 16))
                return 0;

            uint64_t result = EmulateChunkPtrDecrypt(code, path_len, data, m_pebAddr, func_addr);

            std::printf("[dbg] ChunkPtr emulated result: 0x%llX\n", (unsigned long long)result);
            return result;
        }

        // ── Validate a candidate chunk pointer ───────────────────────────
        bool ValidateChunkPtr(uint64_t candidate) {
            if (candidate < 0x10000ULL || candidate > 0x7FFFFFFFFFFFULL)
                return false;
            if (candidate >= m_base && candidate < m_base + 0x10000000ULL)
                return false;
            uint64_t chunk0 = 0;
            if (!m_reader.Read(candidate, &chunk0, 8)) return false;
            if (chunk0 < 0x10000ULL || chunk0 > 0x7FFFFFFFFFFFULL) return false;
            uint64_t obj0 = 0;
            if (!m_reader.Read(chunk0, &obj0, 8)) return false;
            if (obj0 < 0x10000ULL || obj0 > 0x7FFFFFFFFFFFULL) return false;
            uint64_t vtbl = 0;
            if (!m_reader.Read(obj0, &vtbl, 8)) return false;
            return (vtbl >= m_base && vtbl < m_base + 0x10000000ULL);
        }

        // ── Compute ChunkPtr intermediate (for brute-force PEB scan) ────
        // Emulates without the PEB XOR (passes peb=0 so PEB cookie = addend only)
        // Then caller XORs with candidate PEB values.
        // NOTE: This won't work for the emulator approach since PEB is embedded
        // in the instruction stream. Instead, brute-force tries full emulation
        // with each candidate PEB.
        uint64_t BruteForceChunkPtr() {
            if (!m_arrayBase) return 0;

            uint64_t vtbl_ptr = 0;
            if (!m_reader.Read(m_arrayBase + 0x40, &vtbl_ptr, 8) || !vtbl_ptr) return 0;
            uint64_t func_addr = 0;
            if (!m_reader.Read(vtbl_ptr + 48, &func_addr, 8) || !func_addr) return 0;

            uint8_t code[256] = {};
            if (!m_reader.Read(func_addr, code, 256)) return 0;
            int path_len = 256;
            for (int i = 4; i < 256; i++) {
                if (code[i] == 0xC3) { path_len = i + 1; break; }
            }

            alignas(16) uint8_t data[16] = {};
            if (!m_reader.Read(m_arrayBase + CHUNKPTR_DATA_OFF, data, 16))
                return 0;

            // Try PEB candidates in typical Wine ranges
            static const uint64_t ranges[][2] = {
                {0x7FF00000, 0x7FFE0000},
                {0x00010000, 0x00200000},
            };
            for (const auto& range : ranges) {
                for (uint64_t peb = range[0]; peb < range[1]; peb += 0x1000) {
                    // Quick check: PEB+0x10 should be module base
                    uint64_t img = 0;
                    if (!m_reader.Read(peb + 0x10, &img, 8) || img != m_base) continue;

                    uint64_t candidate = EmulateChunkPtrDecrypt(code, path_len, data, peb, func_addr);
                    if (candidate && ValidateChunkPtr(candidate)) {
                        m_pebAddr = peb;
                        std::printf("[+] Brute-forced PEB=0x%llX → chunks=0x%llX\n",
                            (unsigned long long)peb, (unsigned long long)candidate);
                        return candidate;
                    }
                }
            }
            return 0;
        }


        // ── Probe for chunk pointer array base (raw scan fallback) ───────
        uint64_t ProbeChunkPtr() {
            if (!m_arrayBase) return 0;

            uint8_t raw[0x100] = {};
            if (!m_reader.Read(m_arrayBase, raw, 0x100))
                return 0;

            for (int off = 0; off <= 0xF8; off += 8) {
                uint64_t candidate = 0;
                memcpy(&candidate, raw + off, 8);

                if (candidate < 0x10000ULL || candidate > 0x7FFFFFFFFFFFULL)
                    continue;
                if (candidate >= m_base && candidate < m_base + 0x10000000ULL)
                    continue;

                uint64_t chunk0 = 0;
                if (!m_reader.Read(candidate, &chunk0, 8))
                    continue;
                if (chunk0 < 0x10000ULL || chunk0 > 0x7FFFFFFFFFFFULL)
                    continue;

                uint64_t obj0 = 0;
                if (!m_reader.Read(chunk0 + FUOBJECTITEM_OBJ, &obj0, 8))
                    continue;
                if (obj0 < 0x10000ULL || obj0 > 0x7FFFFFFFFFFFULL)
                    continue;

                uint64_t vtbl = 0;
                if (!m_reader.Read(obj0, &vtbl, 8))
                    continue;
                if (vtbl >= m_base && vtbl < m_base + 0x10000000ULL) {
                    int valid = 1;
                    for (int i = 1; i < 5 && i < m_numElements; ++i) {
                        uint64_t obj_n = 0;
                        m_reader.Read(chunk0 + (uint64_t)FUOBJECTITEM_SIZE * i, &obj_n, 8);
                        if (!obj_n) continue;
                        uint64_t vt_n = 0;
                        m_reader.Read(obj_n, &vt_n, 8);
                        if (vt_n >= m_base && vt_n < m_base + 0x10000000ULL)
                            ++valid;
                    }
                    if (valid >= 3) {
                        std::printf("[+] Probed chunk ptr at array+0x%02X = 0x%llX\n",
                            off, (unsigned long long)candidate);
                        return candidate;
                    }
                }
            }

            return 0;
        }
    };

} // namespace gobjects
