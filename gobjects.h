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
#include <immintrin.h>
#include "kernel_module/include/memreader_iface.h"
#include "arc_decrypt.h"

namespace gobjects
{
    constexpr uint32_t FUOBJECTITEM_SIZE  = 20;
    constexpr uint32_t FUOBJECTITEM_OBJ  = 0;   // Object* at +0x00
    constexpr uint32_t CHUNK_ITEM_COUNT   = 65536; // items per chunk

    // ChunkPtr decrypt constants (from disassembly of virtual func @ RVA 0x49AAA0)
    constexpr uint64_t RVA_CHUNKPTR_KEY1  = 0xAB2DE50;  // pxor key (step 1)
    constexpr uint64_t RVA_CHUNKPTR_KEY2  = 0xAB2DE60;  // pxor key (step 5)
    constexpr uint32_t CHUNKPTR_PEB_ADD   = 0x72AC9D29;  // addend for PEB cookie
    constexpr int      CHUNKPTR_ROL_BITS  = 43;           // ROL64 amount
    constexpr uint8_t  CHUNKPTR_SHUFLO    = 0x72;         // pshuflw immediate
    constexpr int      CHUNKPTR_DATA_OFF  = 0x70;         // encrypted data at struct+0x70

    // ─────────────────────────────────────────────────────────────────────
    // GObjectArray – runtime context for FChunkedFixedUObjectArray access
    // ─────────────────────────────────────────────────────────────────────
    class GObjectArray {
    public:
        GObjectArray(uint64_t module_base, IMemoryReader& reader)
            : m_base(module_base), m_reader(reader),
              m_arrayBase(0), m_chunkPtr(0), m_numElements(0),
              m_pebAddr(0), m_initialized(false)
        {
            memset(m_xorKey,   0, 16);
            memset(m_shufMask, 0, 16);
            memset(m_numMask1, 0, 16);
            memset(m_numMask2, 0, 16);
            memset(m_numShuf,  0, 16);
            memset(m_chunkKey1, 0, 16);
            memset(m_chunkKey2, 0, 16);
        }

        // Load SIMD tables, decrypt array base, count, and decrypt chunk ptr.
        bool Init() {
            if (m_initialized) return true;

            // Load SIMD tables from process memory
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_OBJARRAY_XOR,  m_xorKey,   16)) return false;
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_OBJARRAY_SHUF, m_shufMask, 16)) return false;
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_NUMELEM_MASK1, m_numMask1, 16)) return false;
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_NUMELEM_MASK2, m_numMask2, 16)) return false;
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_NUMELEM_SHUF,  m_numShuf,  16)) return false;

            // Load ChunkPtr SIMD keys
            if (!m_reader.Read(m_base + RVA_CHUNKPTR_KEY1, m_chunkKey1, 16)) return false;
            if (!m_reader.Read(m_base + RVA_CHUNKPTR_KEY2, m_chunkKey2, 16)) return false;

            m_arrayBase   = DecryptObjectArray();
            m_numElements = DecryptNumElements(m_arrayBase);

            if (!m_arrayBase || m_numElements <= 0) {
                std::printf("[-] GObjectArray init failed: base=0x%llX count=%d\n",
                    (unsigned long long)m_arrayBase, m_numElements);
                return false;
            }

            // Find PEB address and decrypt chunk pointer
            m_pebAddr = FindPEB();
            if (m_pebAddr) {
                std::printf("[+] PEB address: 0x%llX\n", (unsigned long long)m_pebAddr);
                m_chunkPtr = DecryptChunkPtr();
            }

            // Validate decrypted chunk pointer
            if (!m_chunkPtr || !ValidateChunkPtr(m_chunkPtr)) {
                std::printf("[!] SIMD decrypt chunk ptr failed (got 0x%llX), trying brute-force PEB...\n",
                    (unsigned long long)m_chunkPtr);
                m_chunkPtr = BruteForcePEB();
            }

            if (!m_chunkPtr) {
                // Last resort: raw probe
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

        // Manual override for chunk pointer (if auto-probe fails)
        void SetChunkPtr(uint64_t ptr) {
            m_chunkPtr = ptr;
            if (m_arrayBase && m_numElements > 0 && m_chunkPtr)
                m_initialized = true;
        }

        uint64_t GetArrayBase()   const { return m_arrayBase; }
        int32_t  GetNumElements() const { return m_numElements; }
        uint64_t GetChunkPtr()    const { return m_chunkPtr; }

        // Read UObject* at the given object index
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

        // Iterate all non-null objects
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

        // Print diagnostic info for debugging
        void PrintDiagnostics() const {
            std::printf("[diag] FChunkedFixedUObjectArray @ 0x%llX\n",
                (unsigned long long)m_arrayBase);
            std::printf("[diag] NumElements = %d\n", m_numElements);

            // Dump first 0x100 bytes of struct for manual analysis
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

                // Show potential pointers
                std::printf("[diag] Potential heap pointers in struct:\n");
                for (int off = 0; off <= 0xF8; off += 8) {
                    uint64_t v = 0;
                    memcpy(&v, raw + off, 8);
                    if (v > 0x10000ULL && v < 0x7FFFFFFFFFFFULL &&
                        !(v >= m_base && v < m_base + 0x10000000ULL))
                        std::printf("  +0x%02X: 0x%llX\n", off, (unsigned long long)v);
                }
            }

            // Print the virtual call info for manual reverse-engineering
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
                    std::printf("  → Decompile this function in IDA to get the SIMD decrypt pipeline\n");
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
        bool           m_initialized;

        // SIMD tables (loaded during Init)
        alignas(16) uint8_t m_xorKey[16];
        alignas(16) uint8_t m_shufMask[16];
        alignas(16) uint8_t m_numMask1[16];
        alignas(16) uint8_t m_numMask2[16];
        alignas(16) uint8_t m_numShuf[16];
        alignas(16) uint8_t m_chunkKey1[16];
        alignas(16) uint8_t m_chunkKey2[16];

        // ── Decrypt FChunkedFixedUObjectArray pointer ────────────────────
        // Game: XOR(data @ +32, key @ 0xAAA18A0) → ROL64(34) →
        //       shuffle_epi8(mask @ 0xAAA18B0) → XOR(0xAB8F9C79978619C2)
        uint64_t DecryptObjectArray() {
            alignas(16) uint8_t data[16] = {};
            if (!m_reader.Read(m_base + ArcDecrypt::RVA_GOBJECT_ARRAY_DATA + 32, data, 16))
                return 0;

            __m128i v3 = _mm_xor_si128(
                _mm_load_si128((const __m128i*)data),
                _mm_load_si128((const __m128i*)m_xorKey));

            // ROL64(34) per qword
            __m128i rotated = _mm_or_si128(
                _mm_slli_epi64(v3, 0x22),
                _mm_srli_epi64(v3, 0x1E));

            __m128i shuffled = _mm_shuffle_epi8(rotated,
                _mm_load_si128((const __m128i*)m_shufMask));

            uint64_t result;
            _mm_storel_epi64((__m128i*)&result, shuffled);
            return result ^ ArcDecrypt::GOBJECT_ARRAY_XOR;
        }

        // ── Decrypt NumElements from FChunkedFixedUObjectArray ──────────
        // Game: Read(base+0x90) → blend(mask1,mask2) → shuffle_epi8 → srli(5) → lo32
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
            // Search common Wine PEB locations
            const uint64_t candidates[] = {
                0x7FFD0000, 0x7FFC0000, 0x7FFB0000, 0x7FFA0000,
                0x00060000, 0x00050000, 0x00040000, 0x00030000,
            };
            for (uint64_t addr : candidates) {
                uint64_t img_base = 0;
                if (m_reader.Read(addr + 0x10, &img_base, 8) && img_base == m_base) {
                    return addr;
                }
            }
            // Brute scan 0x7FFD0000-0x7FFE0000 page by page
            for (uint64_t addr = 0x7FFD0000; addr < 0x7FFE0000; addr += 0x1000) {
                uint64_t img_base = 0;
                if (m_reader.Read(addr + 0x10, &img_base, 8) && img_base == m_base)
                    return addr;
            }
            return 0;
        }

        // ── Runtime pshuflw (compile-time immediate not possible) ─────────
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

        // ── Decrypt ChunkPtr via SIMD pipeline ───────────────────────────
        // Disassembled from virtual func @ RVA 0x49AAA0:
        //   movq xmm0,[rdx]       → load 8 bytes from struct+0x70
        //   pxor xmm0,[KEY1]      → XOR with key1
        //   ROL64(43)             → psrlq(21) + psllq(43) + por
        //   pshuflw $0x72         → shuffle low words
        //   pxor xmm1,[KEY2]      → XOR with key2
        //   XOR(PEB+0x72AC9D29)  → broadcast PEB cookie, final XOR
        uint64_t DecryptChunkPtr() {
            if (!m_arrayBase || !m_pebAddr) return 0;

            // Load encrypted data (8 bytes from struct+0x70, high qword = 0)
            alignas(16) uint8_t data[16] = {};
            if (!m_reader.Read(m_arrayBase + CHUNKPTR_DATA_OFF, data, 8))
                return 0;

            __m128i v = _mm_load_si128((const __m128i*)data);

            // Step 1: pxor with key1
            v = _mm_xor_si128(v, _mm_load_si128((const __m128i*)m_chunkKey1));

            // Step 2: ROL64(43) per qword
            v = _mm_or_si128(
                _mm_slli_epi64(v, CHUNKPTR_ROL_BITS),
                _mm_srli_epi64(v, 64 - CHUNKPTR_ROL_BITS));

            // Step 3: pshuflw(0x72)
            v = RuntimeShuffleLo(v, CHUNKPTR_SHUFLO);

            // Step 4: pxor with key2
            v = _mm_xor_si128(v, _mm_load_si128((const __m128i*)m_chunkKey2));

            // Step 5: XOR with broadcast PEB cookie
            uint64_t peb_cookie = m_pebAddr + CHUNKPTR_PEB_ADD;
            __m128i cookie = _mm_set1_epi64x(static_cast<int64_t>(peb_cookie));
            v = _mm_xor_si128(v, cookie);

            uint64_t result;
            _mm_storel_epi64((__m128i*)&result, v);

            std::printf("[dbg] ChunkPtr decrypt: peb=0x%llX cookie=0x%llX result=0x%llX\n",
                (unsigned long long)m_pebAddr, (unsigned long long)peb_cookie,
                (unsigned long long)result);
            return result;
        }

        // ── Validate a candidate chunk pointer ───────────────────────────
        bool ValidateChunkPtr(uint64_t candidate) {
            if (candidate < 0x10000ULL || candidate > 0x7FFFFFFFFFFFULL)
                return false;
            // Must not be in module range
            if (candidate >= m_base && candidate < m_base + 0x10000000ULL)
                return false;
            // Read first chunk
            uint64_t chunk0 = 0;
            if (!m_reader.Read(candidate, &chunk0, 8)) return false;
            if (chunk0 < 0x10000ULL || chunk0 > 0x7FFFFFFFFFFFULL) return false;
            // Validate first object has vtable in module range
            uint64_t obj0 = 0;
            if (!m_reader.Read(chunk0, &obj0, 8)) return false;
            if (obj0 < 0x10000ULL || obj0 > 0x7FFFFFFFFFFFULL) return false;
            uint64_t vtbl = 0;
            if (!m_reader.Read(obj0, &vtbl, 8)) return false;
            return (vtbl >= m_base && vtbl < m_base + 0x10000000ULL);
        }

        // ── Brute-force PEB by trying addresses in Wine mapped regions ───
        uint64_t BruteForcePEB() {
            if (!m_arrayBase) return 0;
            // Load encrypted data once
            alignas(16) uint8_t data[16] = {};
            if (!m_reader.Read(m_arrayBase + CHUNKPTR_DATA_OFF, data, 8))
                return 0;

            // Compute intermediate (steps 1-4, everything except PEB XOR)
            __m128i v = _mm_load_si128((const __m128i*)data);
            v = _mm_xor_si128(v, _mm_load_si128((const __m128i*)m_chunkKey1));
            v = _mm_or_si128(
                _mm_slli_epi64(v, CHUNKPTR_ROL_BITS),
                _mm_srli_epi64(v, 64 - CHUNKPTR_ROL_BITS));
            v = RuntimeShuffleLo(v, CHUNKPTR_SHUFLO);
            v = _mm_xor_si128(v, _mm_load_si128((const __m128i*)m_chunkKey2));

            uint64_t intermediate;
            _mm_storel_epi64((__m128i*)&intermediate, v);

            // Try PEB addresses in likely Wine ranges
            for (uint64_t peb = 0x7FF00000; peb < 0x7FFE0000; peb += 0x1000) {
                uint64_t cookie = peb + CHUNKPTR_PEB_ADD;
                uint64_t candidate = intermediate ^ cookie;
                if (ValidateChunkPtr(candidate)) {
                    m_pebAddr = peb;
                    std::printf("[+] Brute-forced PEB=0x%llX → chunks=0x%llX\n",
                        (unsigned long long)peb, (unsigned long long)candidate);
                    return candidate;
                }
            }
            // Also try low-memory range
            for (uint64_t peb = 0x00020000; peb < 0x00100000; peb += 0x1000) {
                uint64_t cookie = peb + CHUNKPTR_PEB_ADD;
                uint64_t candidate = intermediate ^ cookie;
                if (ValidateChunkPtr(candidate)) {
                    m_pebAddr = peb;
                    std::printf("[+] Brute-forced PEB=0x%llX → chunks=0x%llX\n",
                        (unsigned long long)peb, (unsigned long long)candidate);
                    return candidate;
                }
            }
            return 0;
        }

        // ── Probe for chunk pointer array base (fallback) ────────────────
        // Raw pointer scan – works if chunk ptr happens to be unencrypted.
        uint64_t ProbeChunkPtr() {
            if (!m_arrayBase) return 0;

            // Read first 0x100 bytes of the struct
            uint8_t raw[0x100] = {};
            if (!m_reader.Read(m_arrayBase, raw, 0x100))
                return 0;

            // Try each 8-byte aligned offset as a potential chunk array pointer
            for (int off = 0; off <= 0xF8; off += 8) {
                uint64_t candidate = 0;
                memcpy(&candidate, raw + off, 8);

                // Must be a valid userspace heap pointer
                if (candidate < 0x10000ULL || candidate > 0x7FFFFFFFFFFFULL)
                    continue;
                // Skip module code range
                if (candidate >= m_base && candidate < m_base + 0x10000000ULL)
                    continue;

                // Read first chunk pointer
                uint64_t chunk0 = 0;
                if (!m_reader.Read(candidate, &chunk0, 8))
                    continue;
                if (chunk0 < 0x10000ULL || chunk0 > 0x7FFFFFFFFFFFULL)
                    continue;

                // Validate: first FUObjectItem should have a valid Object*
                uint64_t obj0 = 0;
                if (!m_reader.Read(chunk0 + FUOBJECTITEM_OBJ, &obj0, 8))
                    continue;
                if (obj0 < 0x10000ULL || obj0 > 0x7FFFFFFFFFFFULL)
                    continue;

                // Check vtable of first object (should be in module range)
                uint64_t vtbl = 0;
                if (!m_reader.Read(obj0, &vtbl, 8))
                    continue;
                if (vtbl >= m_base && vtbl < m_base + 0x10000000ULL) {
                    // Extra validation: check a few more objects
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

            return 0;  // Failed – use SetChunkPtr() or reverse GetChunkPtr virtual
        }
    };

} // namespace gobjects
