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
#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <immintrin.h>
#ifdef _WIN32
#include <Windows.h>
#endif
#include "memreader_iface.h"
#include "arc_decrypt.h"
#include "auto_discovery.h"
#include "zydis/Zydis.h"

namespace gobjects
{
    // FUObjectItem: {ObjectPtr, InternalIndex, ClassSerialNumber, WeakPtrSerial} = 20 bytes (confirmed in IDA 3sw0)
    constexpr uint32_t FUOBJECTITEM_SIZE  = 20;
    constexpr uint32_t FUOBJECTITEM_OBJ  = 0;   // Object* at +0x00
    constexpr uint32_t CHUNK_ITEM_COUNT   = 65536; // items per chunk

    // ChunkPtr decrypt constants (patch 20260414, probed from vtable[5] at base+96)
    // Pipeline: load 8B @ base+0x90 → ROL16(13) → PSHUFLW(0x8D) → PEB XOR → PSHUFD(0x44) → PXOR
    constexpr uint32_t CHUNKPTR_PEB_ADD   = 0x996E6F1D;  // mov eax, imm32 (was 0x72AC9D29)
    constexpr uint64_t CHUNKPTR_XOR_CONST = 0x725BFAF9AE494AF3ULL; // mov rcx, imm64
    constexpr uint8_t  CHUNKPTR_SHUFLO    = 0x8D;         // pshuflw immediate (was 0x72)
    constexpr uint8_t  CHUNKPTR_PSHUFD    = 0x44;         // pshufd immediate
    constexpr int      CHUNKPTR_ROL16     = 13;           // ROL16 amount (psllw 13, psrlw 3)
    constexpr int      CHUNKPTR_DATA_OFF  = 0x90;         // encrypted data at base+0x90 (was 0xE0)
    constexpr int      CHUNKPTR_VTABLE_OFF = 96;          // vtable struct at base+96 (0x60)
    constexpr int      CHUNKPTR_VFUNC_OFF  = 40;          // function at vtable+40

    // ─────────────────────────────────────────────────────────────────────
    // Helper Functions
    // ─────────────────────────────────────────────────────────────────────
    inline std::string FormatHex(const uint8_t* data, size_t len) {
        std::string result;
        for (size_t i = 0; i < len; ++i) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X ", data[i]);
            result += buf;
        }
        if (!result.empty()) result.pop_back();  // Remove trailing space
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────
    // GObjectArray – runtime context for FChunkedFixedUObjectArray access
    // ─────────────────────────────────────────────────────────────────────
    class GObjectArray {
    public:
        GObjectArray(uint64_t module_base, IMemoryReader& reader)
            : m_base(module_base), m_reader(reader),
              m_arrayBase(0), m_chunkPtr(0), m_numElements(0),
              m_pebAddr(0), m_pid(0), m_initialized(false),
                            m_useWorldFallback(false),
                            m_chunkEntriesIndirect(false), m_itemStride(FUOBJECTITEM_SIZE)
        {
            memset(m_objXorKey,  0, 16);
            memset(m_elemMaskA, 0, 16);
            memset(m_elemMaskB, 0, 16);
            memset(m_elemXorKey,0, 16);
            memset(m_chunkKey1, 0, 16);
            memset(m_chunkKey2, 0, 16);
        }

        void SetPid(int pid) { m_pid = pid; }
        void SetPeb(uint64_t peb) { m_pebAddr = peb; }

        // Late module-base update — used when the live module base differs
        // from the constructor value (e.g. HyperVReader reports the real
        // base via NtQueryInformationProcess after construction).
        void SetBase(uint64_t b) { m_base = b; }

        // Load SIMD tables, decrypt array base, count, and decrypt chunk ptr.
        bool Init() {
            if (m_initialized) return true;

            // ── CL-1201801 path (preferred) ──────────────────────────────
            // RVA_GOBJECT_ARRAY_BASE is a pointer variable; FCA heap ptr is
            // encrypted at module+0xE3B6270. Decrypts via ROL32(26)+PSHUFB+ROL16(4).
            // NumElements at FCA+0x30; chunks_array via vtable[8] Vt2Interpret.
            if (InitPatch20260519()) {
                return true;
            }
            std::printf("[!] Patch 20260519 path failed, trying 20260428...\n");

            // ── Patch 20260428 path ──────────────────────────────────────
            // 20260428 layout exposes NumElements as a PLAIN u64 at
            // GUObjectArray + 0x38 (verified via live probe on PID 92919).
            // The chunks-manager-pointer pipeline shape changed too, but
            // since we can't enumerate via vtable[5/7] without live RE we
            // just lean on StructuralScanFUObjectItems as before.
            if (InitPatch20260428()) {
                return true;
            }
            std::printf("[!] Patch 20260428 path failed, trying 20260421 path...\n");

            // ── Patch 20260421 path ──────────────────────────────────────
            // New GUObjectArray RVA + decrypt pipeline; vtable[7] is VMProtected
            // so the chunks-ptr-array is recovered via structural heap scan
            // instead. On success the chunk list is materialized as a flat
            // UObject* vector served through the world-fallback accessor.
            if (InitPatch20260421()) {
                return true;
            }
            std::printf("[!] Patch 20260421 path failed, trying legacy pipeline...\n");

            // Load SIMD tables for GUObjectArray decrypt (ROL32(20)→XOR→ROL16(12)) — patch 20260414
            const bool haveSimdTables =
                m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_OBJARRAY_XOR,  m_objXorKey,  16) &&
                m_reader.Read(m_base + ArcDecrypt::RVA_ELEM_MASK_A,        m_elemMaskA,  16) &&
                m_reader.Read(m_base + ArcDecrypt::RVA_ELEM_MASK_B,        m_elemMaskB,  16) &&
                m_reader.Read(m_base + ArcDecrypt::RVA_ELEM_XOR_KEY,       m_elemXorKey, 16);

            bool simdReady = haveSimdTables;
            if (simdReady && !ValidateSIMDTables()) {
                std::printf("[!] SIMD tables are invalid (game may not be fully loaded)\n");
                simdReady = false;
            }

            // ChunkPtr keys no longer needed — decrypt is PEB-based (patch 20260414)

            // ── GUObjectArray Access (patch 20260414) ────────────────────
            // Struct at RVA_GOBJECT_ARRAY_BASE; encrypted qword at struct+0x30
            // Pipeline: ROL32(20) → XOR(key) → ROL16(12) → extract lo64 = base ptr
            m_arrayBase = m_base + ArcDecrypt::RVA_GOBJECT_ARRAY_BASE;
            std::printf("[+] GUObjectArray struct at 0x%llX\n",
                (unsigned long long)m_arrayBase);

            uint64_t decrypted_base = 0;
            bool directValid = false;
            if (simdReady) {
                decrypted_base = DecryptObjectArray();
                if (decrypted_base) {
                    m_numElements = DecryptNumElements(decrypted_base);
                    std::printf("[+] SIMD decrypt: base=0x%llX count=%d\n",
                        (unsigned long long)decrypted_base, m_numElements);
                    directValid = (m_numElements >= 1000 && m_numElements <= 2000000);
                    if (directValid) m_arrayBase = decrypted_base;
                }
            }

            if (!directValid) {
                std::printf("[!] SIMD decrypt for ObjectArray failed (base=0x%llX count=%d)\n",
                    (unsigned long long)decrypted_base, m_numElements);
                m_arrayBase = 0;
                m_numElements = 0;
            }

            if (!m_arrayBase || m_numElements < 1000) {
                std::printf("[-] GObjectArray init failed: base=0x%llX count=%d\n",
                    (unsigned long long)m_arrayBase, m_numElements);
                // Aggressive diagnostic dump on failure so next session can see
                // exactly where the pipeline went wrong.
                SelfTestDecryptStages();
                return false;
            }

            std::printf("[+] GObjectArray base=0x%llX  count=%d\n",
                (unsigned long long)m_arrayBase, m_numElements);

            // ── Stage 2: Find chunk pointer ──────────────────────────────
            m_pebAddr = FindPEB();
            if (m_pebAddr) {
                std::printf("[+] PEB address: 0x%llX\n", (unsigned long long)m_pebAddr);
                std::printf("[+] Attempting PEB-based chunk decrypt...\n");
                m_chunkPtr = DecryptChunkPtr();
            }

            if (!m_chunkPtr || !ValidateChunkPtr(m_chunkPtr)) {
                std::printf("[!] SIMD decrypt chunk ptr failed (got 0x%llX), trying brute-force PEB...\n",
                    (unsigned long long)m_chunkPtr);
                m_chunkPtr = BruteForceChunkPtr();
            }

            if (!m_chunkPtr) {
                m_chunkPtr = TryDirectChunkPtrFromStruct();
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

        // ── World-traversal fallback: accept a pre-built flat object list ─────
        // Called by SDKDumper when GUObjectArray init fails. The list is built
        // by walking GWorld → Levels → actors and BFS-expanding UClass chains.
        bool InitWithSeedObjects(std::vector<uint64_t>&& objs) {
            if (objs.empty()) return false;
            m_worldFallbackObjects = std::move(objs);
            m_useWorldFallback = true;
            m_numElements = static_cast<int32_t>(m_worldFallbackObjects.size());
            m_initialized = true;
            std::printf("[+] GObjectArray (world fallback): %d objects\n", m_numElements);
            return true;
        }

        // Read-only access to the seed object list. Used by AutoDiscovery to
        // cluster vtables before the vtable scan runs.
        const std::vector<uint64_t>& GetSeedObjects() const {
            return m_worldFallbackObjects;
        }

        // Run the engine-vtable scan against the current seed list, expanding
        // it with hits from heap arenas not tracked by the FUObjectItem array
        // (UScriptStruct + UEnum + extra BPGCs etc.). Uses the auto-discovered
        // vtable map when valid, otherwise the compile-time fallback list.
        // Safe to call from either canonical (vtable[7]) or structural paths
        // — dedups against the existing seed set internally.
        size_t RunDiscoveredVtableScan() {
            if (!m_useWorldFallback || m_worldFallbackObjects.empty()) return 0;

            const auto& Disc = AutoDiscovery::g_DiscoveredVTables;
            const bool UseDiscovered = Disc.Valid();

            std::vector<VtableScanTarget> vt_targets;
            m_knownTypeVtables.clear();

            auto AddIf = [&](uint64_t Rva) {
                if (Rva) m_knownTypeVtables.insert(m_base + Rva);
            };
            auto AddTargetIf = [&](uint64_t Va, uint32_t Stride) {
                if (Va && Stride) vt_targets.push_back({Va, Stride});
            };

            // Compile-time CL-1177146/CL-1177678 baseline — fallback ONLY for
            // kinds that auto-discovery missed. When Phase 1 returns a live
            // RVA for a kind, we skip the compile-time entries tagged with
            // that kind: stale RVAs from older patches generate +0-hit noise
            // and obscure which scans actually matter.
            enum VtKind {
                KIND_ScriptStruct, KIND_Class, KIND_Function, KIND_Enum,
                KIND_Package, KIND_BPGC, KIND_WBPGC, KIND_AnimBPGC,
                KIND_SMBPGC, KIND_ASClass, KIND_ASStruct, KIND_ASFunction
            };
            auto KindName = [](VtKind k) -> const char* {
                switch (k) {
                    case KIND_ScriptStruct: return "ScriptStruct";
                    case KIND_Class:        return "Class";
                    case KIND_Function:     return "Function";
                    case KIND_Enum:         return "Enum";
                    case KIND_Package:      return "Package";
                    case KIND_BPGC:         return "BPGC";
                    case KIND_WBPGC:        return "WBPGC";
                    case KIND_AnimBPGC:     return "AnimBPGC";
                    case KIND_SMBPGC:       return "SMBPGC";
                    case KIND_ASClass:      return "ASClass";
                    case KIND_ASStruct:     return "ASStruct";
                    case KIND_ASFunction:   return "ASFunction";
                }
                return "?";
            };
            struct Vt { uint64_t Rva; uint32_t Stride; VtKind Kind; const char* Tag; };
            static constexpr Vt CompileTime[] = {
                { 0xAD9DC20, 0x130, KIND_ScriptStruct, "CL-1177146" },
                { 0xAD9E500, 0x300, KIND_Class,        "CL-1177146" },
                { 0xAD9EA70, 0x200, KIND_Function,     "CL-1177146" },
                { 0xADA1140, 0x130, KIND_Enum,         "CL-1177146" },
                { 0xADBC9A0, 0x000, KIND_Package,      "CL-1177146" },
                { 0xB5653C0, 0x490, KIND_BPGC,         "CL-1177146" },
                { 0xB35B400, 0x5D0, KIND_WBPGC,        "CL-1177146" },
                { 0xB512510, 0x7F0, KIND_AnimBPGC,     "CL-1177146" },
                { 0xB7BBCF0, 0x490, KIND_SMBPGC,       "CL-1177146" },
                { 0xB8ED140, 0x340, KIND_ASClass,      "CL-1177146" },
                { 0xB8F6920, 0x150, KIND_ASStruct,     "CL-1177146" },
                { 0xB8EDA70, 0x200, KIND_ASFunction,   "CL-1177146" },
                { 0xB8EDEC0, 0x200, KIND_ASFunction,   "CL-1177146" },
                { 0xADF4820, 0x130, KIND_ScriptStruct, "CL-1177678" },
                { 0xB63A840, 0x300, KIND_Class,        "CL-1177678" },
                { 0xB940DC0, 0x200, KIND_Function,     "CL-1177678" },
                { 0xADF7AC0, 0x130, KIND_Enum,         "CL-1177678" },
                { 0xAE13030, 0x000, KIND_Package,      "CL-1177678" },
                { 0xB583B90, 0x490, KIND_BPGC,         "CL-1177678" },
                { 0xB3AF490, 0x5D0, KIND_WBPGC,        "CL-1177678" },
                { 0xBECF7F0, 0x7F0, KIND_AnimBPGC,     "CL-1177678" },
            };
            auto KindCovered = [&](VtKind k) -> bool {
                if (!UseDiscovered) return false;
                switch (k) {
                    case KIND_ScriptStruct: return Disc.ScriptStructRVA != 0;
                    case KIND_Class:        return Disc.ClassNativeRVA  != 0;
                    case KIND_Function:     return Disc.FunctionRVA     != 0;
                    case KIND_Enum:         return Disc.EnumRVA         != 0;
                    case KIND_Package:      return Disc.PackageRVA      != 0;
                    case KIND_BPGC:         return Disc.BPGCRVA         != 0;
                    case KIND_WBPGC:        return Disc.WBPGCRVA        != 0;
                    case KIND_AnimBPGC:     return Disc.AnimBPGCRVA     != 0;
                    case KIND_SMBPGC:       return Disc.SMBPGCRVA       != 0;
                    case KIND_ASClass:      return Disc.ASClassRVA      != 0;
                    case KIND_ASStruct:     return Disc.ASStructRVA     != 0;
                    case KIND_ASFunction:   return !Disc.ASFunctionRVAs.empty();
                }
                return false;
            };

            // Phase 1 entries FIRST — these are live, per-session RVAs.
            if (UseDiscovered) {
                std::printf("[vt-rescan] auto-discovered vtable map takes priority\n");
                auto AddDisc = [&](VtKind k, uint64_t Rva, uint32_t Stride) {
                    if (!Rva) return;
                    AddIf(Rva);
                    AddTargetIf(m_base + Rva, Stride);
                    std::printf("[vt-rescan]   [autodisc] %-12s RVA=0x%llX stride=0x%X\n",
                        KindName(k), (unsigned long long)Rva, Stride);
                };
                AddDisc(KIND_ScriptStruct, Disc.ScriptStructRVA, Disc.ScriptStructStride);
                AddDisc(KIND_Class,        Disc.ClassNativeRVA,  Disc.ClassNativeStride);
                AddDisc(KIND_Function,     Disc.FunctionRVA,     Disc.FunctionStride);
                AddDisc(KIND_Enum,         Disc.EnumRVA,         Disc.EnumStride);
                AddDisc(KIND_Package,      Disc.PackageRVA,      0);
                AddDisc(KIND_BPGC,         Disc.BPGCRVA,         Disc.BPGCStride);
                AddDisc(KIND_WBPGC,        Disc.WBPGCRVA,        Disc.WBPGCStride);
                AddDisc(KIND_AnimBPGC,     Disc.AnimBPGCRVA,     Disc.AnimBPGCStride);
                AddDisc(KIND_SMBPGC,       Disc.SMBPGCRVA,       Disc.SMBPGCStride);
                AddDisc(KIND_ASClass,      Disc.ASClassRVA,      Disc.ASClassStride);
                AddDisc(KIND_ASStruct,     Disc.ASStructRVA,     Disc.ASStructStride);
                for (uint64_t Rva : Disc.ASFunctionRVAs)
                    AddDisc(KIND_ASFunction, Rva, Disc.ASFunctionStride);
            } else {
                std::printf("[vt-rescan] auto-discovery unavailable; compile-time vtable list only\n");
            }

            // Compile-time fallback ONLY for kinds Phase 1 didn't cover.
            for (const auto& v : CompileTime) {
                if (KindCovered(v.Kind)) continue;
                AddIf(v.Rva);
                AddTargetIf(m_base + v.Rva, v.Stride);
                std::printf("[vt-rescan]   [fallback %s] %-12s RVA=0x%llX stride=0x%X\n",
                    v.Tag, KindName(v.Kind), (unsigned long long)v.Rva, v.Stride);
            }

            size_t pre = m_worldFallbackObjects.size();
            ScanByVtables(vt_targets, m_worldFallbackObjects);
            size_t added = m_worldFallbackObjects.size() - pre;
            m_numElements = static_cast<int32_t>(m_worldFallbackObjects.size());
            std::printf("[vt-rescan] vtable scan added %zu UObjects (new total %zu)\n",
                added, m_worldFallbackObjects.size());
            return added;
        }

        // ── Canonical chunks-array enumeration (patch 20260421 vtable[7] path) ─
        // Given the chunks-array base (as returned by emulating vtable[7] of
        // chunks_manager) and the chunk count, iterate 65536 * 20 bytes per
        // chunk, collecting every non-null Object pointer into the flat list.
        // Drops duplicates so the object count reflects unique UObjects.
        bool InitFromChunksCanonical(uint64_t chunks_array, int num_chunks,
                                     int32_t max_expected = 0) {
            if (!chunks_array || num_chunks <= 0) return false;
            constexpr uint32_t ITEMS_PER_CHUNK = 65536;
            constexpr uint32_t STRIDE = 20;
            const uint64_t vt_lo = m_base + 0x1000;
            const uint64_t vt_hi = m_base + 0x10000000ULL;

            std::vector<uint64_t> objs;
            objs.reserve(static_cast<size_t>(num_chunks) * ITEMS_PER_CHUNK);
            std::unordered_set<uint64_t> seen;

            for (int ci = 0; ci < num_chunks; ++ci) {
                uint64_t chunk_ptr = 0;
                if (!m_reader.Read(chunks_array + 8ULL * ci, &chunk_ptr, 8)) break;
                if (!chunk_ptr) break;
                if (chunk_ptr < 0x100000ULL || chunk_ptr >= 0x800000000000ULL) break;

                std::vector<uint8_t> buf(ITEMS_PER_CHUNK * STRIDE);
                if (!m_reader.Read(chunk_ptr, buf.data(), buf.size())) continue;
                uint32_t non_null = 0, valid = 0;
                for (uint32_t i = 0; i < ITEMS_PER_CHUNK; ++i) {
                    uint64_t obj = 0;
                    std::memcpy(&obj, buf.data() + i * STRIDE, 8);
                    if (!obj) continue;
                    ++non_null;
                    uint64_t vt = 0;
                    if (!m_reader.Read(obj, &vt, 8)) continue;
                    if (vt < vt_lo || vt >= vt_hi) continue;
                    ++valid;
                    if (seen.insert(obj).second) objs.push_back(obj);
                }
                std::printf("[canon] chunk[%d] @ 0x%llX: %u non-null, %u valid-vtable\n",
                    ci, (unsigned long long)chunk_ptr, non_null, valid);
            }

            std::printf("[canon] canonical enumeration: %zu unique UObjects (expected ~%d)\n",
                objs.size(), max_expected);
            if (objs.empty()) return false;
            return InitWithSeedObjects(std::move(objs));
        }

        uint64_t GetArrayBase()   const { return m_arrayBase; }
        int32_t  GetNumElements() const { return m_numElements; }
        uint64_t GetChunkPtr()    const { return m_chunkPtr; }

        uint64_t GetObjectPtr(int32_t index) const {
            if (index < 0 || index >= m_numElements) return 0;

            if (m_useWorldFallback)
                return m_worldFallbackObjects[static_cast<size_t>(index)];

            if (!m_chunkPtr) return 0;

            uint32_t chunk_idx = static_cast<uint32_t>(index) >> 16;
            uint32_t item_idx  = static_cast<uint16_t>(index);

            uint64_t chunk = 0;
            if (!m_reader.Read(m_chunkPtr + 8ULL * chunk_idx, &chunk, 8))
                return 0;
            if (!chunk) return 0;

            if (m_chunkEntriesIndirect) {
                uint64_t chunk_data = 0;
                if (!m_reader.Read(chunk, &chunk_data, 8) || !chunk_data)
                    return 0;
                chunk = chunk_data;
            }

            uint64_t obj = 0;
            m_reader.Read(chunk + (uint64_t)m_itemStride * item_idx + FUOBJECTITEM_OBJ, &obj, 8);
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
                    m_reader.Read(vtbl_ptr + 32, &func_ptr, 8); // vtable[4]
                    std::printf("[diag] GetChunkPtr virtual call:\n");
                    std::printf("  vtable @ base+0x40 = 0x%llX\n", (unsigned long long)vtbl_ptr);
                    std::printf("  func   @ vtbl+32   = 0x%llX (RVA=0x%llX)\n",
                        (unsigned long long)func_ptr,
                        (unsigned long long)(func_ptr >= m_base ? func_ptr - m_base : func_ptr));
                }
            }
        }

    private:
        struct Region { uint64_t lo, hi; };
        // Parse /proc/<pid>/maps and append every rw- region whose size falls
        // in [min_sz, max_sz] and which doesn't overlap the loaded module image.
        // Used by ScanByVtable, ProbeChunkTableNoPEB, and the structural FUObjectItem
        // walker — all three need the same heap-region enumeration.
        void EnumerateRwHeapRegions(uint64_t min_sz, uint64_t max_sz,
                                    std::vector<Region>& out) const {
            if (m_pid <= 0) return;
            char path[64];
            std::snprintf(path, sizeof(path), "/proc/%d/maps", m_pid);
            FILE* f = std::fopen(path, "r");
            if (!f) return;
            char line[512];
            while (std::fgets(line, sizeof(line), f)) {
                uint64_t s = 0, e = 0;
                char perms[5] = {};
                std::sscanf(line, "%llx-%llx %4s",
                    (unsigned long long*)&s, (unsigned long long*)&e, perms);
                if (perms[0] != 'r' || perms[1] != 'w') continue;
                uint64_t sz = e - s;
                if (sz < min_sz || sz > max_sz) continue;
                if (s >= m_base && s < m_base + 0x10000000ULL) continue;
                out.push_back({s, e});
            }
            std::fclose(f);
        }

        uint64_t       m_base;
        IMemoryReader& m_reader;
        uint64_t       m_arrayBase;
        uint64_t       m_chunkPtr;
        int32_t        m_numElements;
        uint64_t       m_pebAddr;
        int            m_pid;
        bool           m_initialized;
        bool           m_useWorldFallback;
        bool           m_chunkEntriesIndirect;
        int            m_itemStride;
        std::vector<uint64_t> m_worldFallbackObjects;

        // Pre-captured SIMD chunk_table-decrypt XOR key. When set (by
        // main.cpp's uprobe shot at the chunk_table-decrypt function),
        // bypasses the entire PEB sweep — feed it straight into the
        // SIMD pipeline. Equals `*(gs:[0x60]) + 0x647A6348` as observed
        // by the target. Wine PEB is stable per-session so one capture
        // suffices for the entire run.
        uint64_t       m_simdPebKey      = 0;
        bool           m_simdPebKeyValid = false;
    public:
        void SetSimdPebKey(uint64_t key) {
            m_simdPebKey = key;
            m_simdPebKeyValid = true;
        }
    private:

        // SIMD tables (loaded during Init)
        alignas(16) uint8_t m_objXorKey[16];  // GUObjectArray XOR key (AD2FC50) — patch 20260414
        alignas(16) uint8_t m_elemMaskA[16]; // Element count ANDNOT mask (AD8EE10)
        alignas(16) uint8_t m_elemMaskB[16]; // Element count AND mask (AD8EE20)
        alignas(16) uint8_t m_elemXorKey[16];// Element count XOR key (AD8EE30)
        alignas(16) uint8_t m_chunkKey1[16];
        alignas(16) uint8_t m_chunkKey2[16];

        // ── Canonical chunk walker for patch 20260428 ────────────────────
        // Live-RE'd 2026-04-29 from sub_398180 (GC_GatherUnreachable_20260428):
        //   chunks_manager = decrypt(GUObjectArray + 0xB0)
        //   total = decrypt-u32(chunks_manager + 0x14)
        //   chunk_table = decrypt(chunks_manager + 0xB0, via vtable[5])
        //   for idx in [0, total):
        //     chunk_idx = idx >> 16; slot_idx = idx & 0xFFFF
        //     chunk_ptr = chunk_table[chunk_idx] (8B aligned, header at -8)
        //     item     = chunk_ptr + 20*slot_idx; obj = u64 at item
        //
        // CRUCIAL: GUObjectArray + 0x38 holds a *partial* NumActive counter
        // (= 70592 in the verified live session) — NOT the true element count.
        // The true count comes from chunks_manager + 0x14 (= 279375 in verified
        // session). The structural-scan-only path was capping itself at the
        // partial counter and missing 200K+ objects.
        //
        // chunks_manager pipeline (from sub_398180, also matches FField NamePrivate
        // decrypt shape):
        //   raw     = load 8B from GUObjectArray + 0xB0
        //   shuf    = PSHUFLW(raw, 0x1E)
        //   xored   = shuf XOR qword[0xAD0FE50]   (verified bytes
        //               38 BA 6F 75 E8 89 57 36 = 0x365789E8756FBA38;
        //             this RVA is FField_NamePrivate_XOR_Const_20260428 in IDA)
        //   chunks_manager = ROL16(xored, 1) per uint16-lane
        //
        // Total NumElements decrypt (from inline asm in sub_398180):
        //   total = ROL32(*(u32*)(chunks_manager + 0x14) ^ 0xC88F6121, 17)
        //         ^ 0x4CF4AED0
        //
        // chunk_table decrypt (vt[5] of *(u64*)(chunks_manager + 0x80),
        // live-RE'd 2026-04-29 from sub_49AC60 — pure inline SIMD with PEB,
        // no VMP, returns chunk_table base in xmm0):
        //   blob   = load 8B from chunks_manager + 0xB0   (rdx → xmm0)
        //   ROL16(blob, 13) per word    (psllw 13 | psrlw 3)
        //   PSHUFLW(_, 0x8D)
        //   ROL32(_, 10) per dword      (pslld 10 | psrld 22)
        //   key    = (PEB + 0x647A6348) broadcast as {lo32,hi32,lo32,hi32}
        //                              ^^^ this CONST is per-binary; lives at
        //                              RVA 0x49AC65 (5 bytes after the function
        //                              entry — `mov eax, imm32`). Read live.
        //   chunk_table = lo64(_ XOR key)
        //
        // PEB on Wine: gs:[0x60] in-process; externally located at one of the
        // standard candidate addresses (0x7FFD0000 etc.) and validated via
        // PEB_LDR_DATA.Length == 0x58. See FindPEB() below.
        //
        // No-PEB fallback: if FindPEB() fails or the SIMD output looks bogus,
        // ProbeChunkTableNoPEB() scans all rw heap regions for a 16B-aligned
        // pointer-array shape (≥3 entries, all in heap range, slot 0 of chunk[0]
        // holds a UObject with vtable in module range).
        //
        // chunk_table[ci] points 8 bytes INTO each chunk's heap allocation
        // (the 8B header at chunk_ptr - 8 holds the per-chunk capacity, e.g.
        // 0x10000 = 65536). FUObjectItem array starts at chunk_ptr + 0.

        // ── PEB-free chunk_table locator ─────────────────────────────────
        // Walk all rw regions and find an 8-byte-aligned uint64_t array of
        // exactly `num_chunks` entries where every entry points to a heap
        // allocation whose first slot holds a real UObject (vtable in module
        // range). Used as a fallback when the SIMD/PEB pipeline fails.
        //
        // The shape constraint (num_chunks consecutive heap pointers, each
        // backed by a UObject*) is restrictive enough that we essentially
        // never get a false positive even on multi-GB heaps.
        uint64_t ProbeChunkTableNoPEB(uint32_t num_chunks,
                                       uint64_t vt_lo, uint64_t vt_hi) {
            if (m_pid <= 0 || num_chunks == 0 || num_chunks > 64) return 0;

            std::vector<Region> ranges;
            ranges.reserve(64);
            // Chunk-tables live in small dedicated allocations; engine
            // bookkeeping is at the small end of the heap.
            EnumerateRwHeapRegions(0x1000ULL, 0xC800000ULL, ranges);

            // Pre-build the set of all rw-heap regions so we can verify each
            // candidate chunk-pointer points into one of them.
            auto inAnyHeap = [&](uint64_t p) {
                for (const auto& rg : ranges) if (p >= rg.lo && p < rg.hi) return true;
                return false;
            };

            const uint64_t CHUNK = 0x400000ULL;
            std::vector<uint8_t> buf(CHUNK);

            for (const auto& rg : ranges) {
                for (uint64_t base_addr = rg.lo; base_addr < rg.hi; base_addr += CHUNK) {
                    uint64_t want = std::min<uint64_t>(CHUNK, rg.hi - base_addr);
                    if (!m_reader.Read(base_addr, buf.data(), want)) continue;
                    // Walk every 8-byte-aligned position. We accept the FIRST
                    // position that has num_chunks consecutive heap pointers
                    // whose chunk[0] looks like a real FUObjectItem array.
                    for (size_t off = 0; off + 8ULL * num_chunks <= want; off += 8) {
                        // Quick reject: first qword must be a heap pointer.
                        uint64_t cp0 = 0;
                        std::memcpy(&cp0, buf.data() + off, 8);
                        if (cp0 < 0x10000ULL || cp0 >= 0x800000000000ULL) continue;
                        if (!inAnyHeap(cp0)) continue;

                        // All N entries must be heap pointers.
                        bool all_heap = true;
                        for (uint32_t i = 1; i < num_chunks; ++i) {
                            uint64_t cp = 0;
                            std::memcpy(&cp, buf.data() + off + 8ULL*i, 8);
                            if (cp < 0x10000ULL || cp >= 0x800000000000ULL ||
                                !inAnyHeap(cp)) { all_heap = false; break; }
                        }
                        if (!all_heap) continue;

                        // chunk[0] slot 0 must hold a UObject* with vtable
                        // in module range. This is the load-bearing check
                        // that separates real chunk-tables from incidental
                        // pointer arrays (e.g. TArray data, vtable arenas).
                        uint64_t obj0 = 0;
                        if (!m_reader.Read(cp0, &obj0, 8)) continue;
                        if (obj0 < 0x10000ULL || obj0 >= 0x800000000000ULL) continue;
                        uint64_t vt0 = 0;
                        if (!m_reader.Read(obj0, &vt0, 8)) continue;
                        if (vt0 < vt_lo || vt0 >= vt_hi) continue;

                        // Strict per-chunk validation:
                        //   (a) chunk[i] slot 0 reads a distinct UObject with
                        //       a module-range vtable
                        //   (b) all chunks are pairwise ≥ ITEMS_PER_CHUNK*STRIDE
                        //       (1.25 MB) apart — they can't physically overlap
                        //   (c) chunk[0] is a contiguous readable allocation
                        //       of ≥ 1.25 MB AND a deep-sample of its items
                        //       contains many UObject-shaped pointers
                        // Live RE history:
                        //   2026-04-29 #1: 0xC7C720 had {real, 0x800000002,
                        //     real+0x10, …} — caught by (a).
                        //   2026-04-29 #2: 0xC97C98 had distinct slot-0 objs
                        //     but chunk[5]@0x19FF803F0 / chunk[7]@0x19FF80940
                        //     were 1360 bytes apart, and chunk[0]'s 1.25 MB
                        //     bulk read failed — caught by (b)/(c).
                        constexpr uint32_t ITEMS_PER_CHUNK = 65536;
                        constexpr uint32_t ITEM_STRIDE     = 20;
                        constexpr uint64_t CHUNK_BYTES =
                            static_cast<uint64_t>(ITEMS_PER_CHUNK) * ITEM_STRIDE;

                        std::vector<uint64_t> cps(num_chunks, 0);
                        for (uint32_t i = 0; i < num_chunks; ++i) {
                            std::memcpy(&cps[i], buf.data() + off + 8ULL*i, 8);
                        }

                        // (a) distinct slot-0 UObjects
                        std::unordered_set<uint64_t> chunk_objs;
                        chunk_objs.reserve(num_chunks);
                        bool ok_a = true;
                        for (uint32_t i = 0; i < num_chunks && ok_a; ++i) {
                            uint64_t obj_i = 0;
                            if (!m_reader.Read(cps[i], &obj_i, 8) ||
                                obj_i < 0x10000ULL || obj_i >= 0x800000000000ULL) {
                                ok_a = false; break;
                            }
                            uint64_t vt_i = 0;
                            if (!m_reader.Read(obj_i, &vt_i, 8) ||
                                vt_i < vt_lo || vt_i >= vt_hi) {
                                ok_a = false; break;
                            }
                            if (!chunk_objs.insert(obj_i).second) ok_a = false;
                        }
                        if (!ok_a) continue;

                        // (b) pairwise non-overlap
                        bool ok_b = true;
                        for (uint32_t i = 0; i < num_chunks && ok_b; ++i) {
                            for (uint32_t j = i+1; j < num_chunks; ++j) {
                                uint64_t a = cps[i], b = cps[j];
                                uint64_t diff = (a > b) ? (a - b) : (b - a);
                                if (diff < CHUNK_BYTES) { ok_b = false; break; }
                            }
                        }
                        if (!ok_b) continue;

                        // (c) EVERY chunk (not just chunk[0]) must be a real
                        // 1.25 MB allocation densely populated with
                        // FUObjectItem-shaped entries. For each chunk:
                        //   - probe the LAST item slot to confirm the full
                        //     1.25 MB is readable (rejects bogus pointers
                        //     into small allocations);
                        //   - sample 32 items spread across the chunk;
                        //     ≥ 30% must be valid UObjects with module-range
                        //     vtables.
                        // Real chunks consistently show > 90% valid; false
                        // positives where slot 0 aliases a UObject usually
                        // yield single-digit % — and chunks beyond the first
                        // are completely unreadable garbage.
                        // Live RE history:
                        //   2026-04-30 #3: 0xCA817300 — chunk[0] passed the
                        //     old chunk[0]-only deep-sample (1706/65536 = 2.6%
                        //     >= 25% of 64-sample = 16 items by chance), but
                        //     chunks 1 & 3 were unreadable, chunks 2 & 4 at
                        //     0.1–0.7%. cap-8 = 0x8FFFFFFFF was nonsense.
                        bool ok_c = true;
                        constexpr int N_SAMPLES = 32;
                        constexpr uint64_t LAST_ITEM_OFF =
                            (ITEMS_PER_CHUNK - 1) * ITEM_STRIDE;
                        uint8_t sample_buf[ITEM_STRIDE];
                        for (uint32_t ci = 0; ci < num_chunks && ok_c; ++ci) {
                            // (c.1) full-range readability — read the LAST
                            // item slot of the chunk. If this fails the
                            // chunk pointer is either bogus or the chunk
                            // is much smaller than 1.25 MB.
                            if (!m_reader.Read(cps[ci] + LAST_ITEM_OFF,
                                               sample_buf, ITEM_STRIDE)) {
                                ok_c = false;
                                break;
                            }
                            // (c.2) deep sample — 32 spread evenly.
                            int valid = 0, sampled = 0;
                            for (int s = 0; s < N_SAMPLES; ++s) {
                                uint64_t item_off = static_cast<uint64_t>(s) *
                                    (ITEMS_PER_CHUNK / N_SAMPLES) * ITEM_STRIDE;
                                if (!m_reader.Read(cps[ci] + item_off,
                                                   sample_buf, ITEM_STRIDE)) continue;
                                ++sampled;
                                uint64_t obj = 0;
                                std::memcpy(&obj, sample_buf, 8);
                                if (obj < 0x10000ULL || obj >= 0x800000000000ULL) continue;
                                uint64_t vt = 0;
                                if (!m_reader.Read(obj, &vt, 8)) continue;
                                if (vt >= vt_lo && vt < vt_hi) ++valid;
                            }
                            // ≥ 50% sampled AND ≥ 30% valid. The last chunk
                            // is partially populated; relax to 10% if it's
                            // the trailing chunk (ci == num_chunks-1).
                            int min_valid_pct = (ci + 1 == num_chunks) ? 10 : 30;
                            if (sampled < N_SAMPLES / 2 ||
                                valid * 100 < sampled * min_valid_pct) {
                                ok_c = false;
                            }
                        }
                        if (!ok_c) continue;

                        // (d) chunk_ptr[0]-8 sanity. Real allocators put the
                        // chunk capacity (0x10000 = 65536) or a small heap
                        // header there. Anything in the obviously-broken
                        // range (e.g. 0x8FFFFFFFF) is the smoking gun for
                        // a misaligned candidate. Permit "small" cap (≤ 1 MB)
                        // and the legitimate sentinel (== ITEMS_PER_CHUNK);
                        // reject everything else.
                        uint64_t cap = 0;
                        if (cp0 >= 8 && !m_reader.Read(cp0 - 8, &cap, 8)) cap = 0;
                        bool cap_plausible =
                            cap == 0 ||
                            cap == ITEMS_PER_CHUNK ||
                            cap < 0x100000ULL;
                        if (!cap_plausible) {
                            std::printf("[canon28] heap-scan reject @ 0x%llX: cap-8=0x%llX implausible\n",
                                (unsigned long long)(base_addr + off),
                                (unsigned long long)cap);
                            continue;
                        }
                        std::printf("[canon28] heap-scan candidate @ 0x%llX: "
                                    "cp0=0x%llX cap-8=0x%llX obj0=0x%llX vt0=0x%llX\n",
                            (unsigned long long)(base_addr + off),
                            (unsigned long long)cp0,
                            (unsigned long long)cap,
                            (unsigned long long)obj0,
                            (unsigned long long)vt0);
                        return base_addr + off;
                    }
                }
            }
            return 0;
        }

        bool CanonicalChunkWalk20260428(std::vector<uint64_t>& out_objects,
                                        int32_t& out_num_elements) {
            uint64_t base = m_base + ArcDecrypt::RVA_GOBJECT_ARRAY_BASE;

            // CL-1177146 layout shift: NumElements is plain at +0x30 instead
            // of the encrypted FChunkedFixedUObjectArray pipeline. Detect this
            // up front by sanity-checking the value at +0x30 — if it looks
            // like a plain UObject count, skip the encrypted-blob path entirely
            // and let the structural-scan fallback do the work.
            uint64_t NumAt30 = 0;
            if (m_reader.Read(base + 0x30, &NumAt30, 8)) {
                uint32_t Lo = static_cast<uint32_t>(NumAt30 & 0xFFFFFFFFu);
                if ((NumAt30 >> 32) == 0 && Lo >= 1000 && Lo <= 2000000) {
                    std::printf("[canon28] CL-1177146 layout detected (+0x30 plain NumElements=%u); skipping encrypted decrypt\n", Lo);
                    return false;
                }
            }

            // Step 1: decrypt chunks_manager pointer.
            alignas(16) uint8_t blob[16] = {};
            if (!m_reader.Read(base + 0xB0, blob, 16)) {
                std::printf("[canon28] read GUObjectArray+0xB0 failed\n");
                return false;
            }
            uint64_t xor_const = 0;
            constexpr uint64_t kXorConstRva = 0xB7FF0E0;
            if (!m_reader.Read(m_base + kXorConstRva, &xor_const, 8)) {
                std::printf("[canon28] read XOR const @ 0x%llX failed\n",
                    (unsigned long long)kXorConstRva);
                return false;
            }

            uint16_t bw[4];
            std::memcpy(bw, blob, 8);
            uint16_t shuf[4] = { bw[2], bw[3], bw[1], bw[0] };  // PSHUFLW imm 0x1E = idx [2,3,1,0]
            uint64_t shuf_q = 0;
            std::memcpy(&shuf_q, shuf, 8);
            uint64_t xored = shuf_q ^ xor_const;
            uint16_t xw[4];
            std::memcpy(xw, &xored, 8);
            for (int i = 0; i < 4; ++i)
                xw[i] = static_cast<uint16_t>((xw[i] << 1) | (xw[i] >> 15));
            uint64_t chunks_manager = 0;
            std::memcpy(&chunks_manager, xw, 8);

            if (chunks_manager < 0x10000ULL || chunks_manager >= 0x800000000000ULL) {
                std::printf("[canon28] chunks_manager 0x%llX out of range\n",
                    (unsigned long long)chunks_manager);
                return false;
            }
            std::printf("[canon28] chunks_manager = 0x%llX\n",
                (unsigned long long)chunks_manager);

            // Step 2: decrypt total NumElements from chunks_manager + 0x14.
            uint32_t enc_count = 0;
            if (!m_reader.Read(chunks_manager + 0x14, &enc_count, 4)) {
                std::printf("[canon28] read chunks_manager+0x14 failed\n");
                return false;
            }
            uint32_t xored32 = enc_count ^ 0xC88F6121u;
            uint32_t rol = (xored32 << 17) | (xored32 >> 15);
            uint32_t total = rol ^ 0x4CF4AED0u;
            if (total < 1000 || total > 2000000) {
                std::printf("[canon28] total NumElements %u out of range (raw 0x%08X)\n",
                    total, enc_count);
                return false;
            }
            std::printf("[canon28] total NumElements = %u (decrypted from chunks_mgr+0x14)\n",
                total);

            // Step 3: decrypt chunk_table base.
            //
            // Two paths, tried in order:
            //   (a) SIMD pipeline (replicates the inline asm at sub_49AC60 vt[5]).
            //       Needs PEB + a per-binary "mov eax, imm32" constant which we
            //       read live from the binary at RVA 0x49AC65. The SIMD output
            //       is validated by reading slot[0] of chunk[0] and checking it
            //       holds a UObject* whose vtable lies in module range.
            //   (b) PEB-free heap scan (ProbeChunkTableNoPEB). Walks all rw
            //       heap regions and finds an 8-byte-aligned array of N>=1
            //       chunk pointers (each pointing into a heap allocation
            //       whose first slot holds a real UObject).
            //
            // Either path independently produces the chunk_table; if (a) fails,
            // we try (b). This makes the walker robust against PEB shifts and
            // per-session keystream variation in the SIMD const RVA.

            constexpr uint32_t ITEMS_PER_CHUNK = 65536;
            constexpr uint32_t STRIDE = 20;
            uint32_t num_chunks = (total + ITEMS_PER_CHUNK - 1) / ITEMS_PER_CHUNK;
            const uint64_t vt_lo = m_base + 0x1000;
            const uint64_t vt_hi = m_base + 0x10000000ULL;

            alignas(16) uint8_t enc_table[16] = {};
            if (!m_reader.Read(chunks_manager + 0xB0, enc_table, 16)) {
                std::printf("[canon28] read chunks_manager+0xB0 failed\n");
                return false;
            }

            uint64_t chunk_table = 0;

            // ── Path (a): SIMD with PEB ──────────────────────────────────
            // Pipeline (live-RE'd from sub_49AC60 on patch 20260428):
            //   xmm0 = movq([rdx])              # rdx = chunks_mgr+0xB0 stack copy
            //   xmm0 = ROL16(xmm0, 13) per word
            //   xmm1 = PSHUFLW(xmm0, 0x8D)      # idx [1,3,0,2]
            //   xmm1 = ROL32(xmm1, 10) per dword
            //   rax  = (gs:[0x60] + 0x647A6348) # PEB + per-binary imm32
            //   xmm0 = pshufd(broadcast(rax), 0x44) # {lo32,hi32,lo32,hi32}
            //   ret xmm1 ^ xmm0  → chunk_table = lo64
            //
            // The 4-byte imm32 is the immediate of the `mov eax, imm32`
            // instruction at function-entry+5. Reading it live makes us
            // robust against patch-day randomization of this constant.
            //
            // RVA 0x49AC60 is the entry of the chunk_table-decrypt SIMD
            // function (= vt[5] of *(chunks_manager+0x80)) on patch 20260428.
            // If patch shifts this RVA, both the SIMD path and the const-read
            // will fail; path (b) catches that case.
            constexpr uint64_t RVA_CHUNK_TABLE_DECRYPT_FN = 0x49AC60;
            uint32_t peb_add_const = 0;
            bool have_peb_const = m_reader.Read(
                m_base + RVA_CHUNK_TABLE_DECRYPT_FN + 5, &peb_add_const, 4);
            if (have_peb_const) {
                std::printf("[canon28] PEB-add const (read live @ RVA 0x%llX+5) = 0x%08X\n",
                    (unsigned long long)RVA_CHUNK_TABLE_DECRYPT_FN, peb_add_const);
            } else {
                std::printf("[canon28] failed to read PEB-add const at RVA 0x%llX+5\n",
                    (unsigned long long)RVA_CHUNK_TABLE_DECRYPT_FN);
            }

            auto runSimdWithKey = [&](uint64_t key64) -> uint64_t {
                uint16_t w[4];
                std::memcpy(w, enc_table, 8);
                // ROL16(13) per word — no shared helper for 16-bit rotates.
                for (int i = 0; i < 4; ++i)
                    w[i] = static_cast<uint16_t>((w[i] << 13) | (w[i] >> 3));
                // PSHUFLW imm=0x8D → idx [1,3,0,2] (b'10001101' lo→hi)
                uint16_t shuf_w[4] = { w[1], w[3], w[0], w[2] };
                uint32_t d[2];
                std::memcpy(d, shuf_w, 8);
                d[0] = ArcDecrypt::ROL32(d[0], 10);
                d[1] = ArcDecrypt::ROL32(d[1], 10);
                d[0] ^= static_cast<uint32_t>(key64);
                d[1] ^= static_cast<uint32_t>(key64 >> 32);
                return (static_cast<uint64_t>(d[1]) << 32) | d[0];
            };
            auto runSimdDecrypt = [&](uint64_t peb_addr) -> uint64_t {
                if (!have_peb_const) return 0;
                return runSimdWithKey(peb_addr + static_cast<uint64_t>(peb_add_const));
            };

            auto validateChunkTable = [&](uint64_t cand) -> bool {
                if (cand < 0x10000ULL || cand >= 0x800000000000ULL) return false;
                // chunk_table[0] should be a heap pointer whose +0 holds a UObject.
                uint64_t cp0 = 0;
                if (!m_reader.Read(cand, &cp0, 8)) return false;
                if (cp0 < 0x10000ULL || cp0 >= 0x800000000000ULL) return false;
                uint64_t obj0 = 0;
                if (!m_reader.Read(cp0, &obj0, 8)) return false;
                if (obj0 < 0x10000ULL || obj0 >= 0x800000000000ULL) return false;
                uint64_t vt0 = 0;
                if (!m_reader.Read(obj0, &vt0, 8)) return false;
                return vt0 >= vt_lo && vt0 < vt_hi;
            };

            // ── Path (a0): pre-captured SIMD key (uprobe shot) ───────────
            // If main.cpp captured the runtime XOR key by uprobing the
            // target's chunk_table-decrypt function, plug it straight in.
            // Bypasses every PEB-discovery heuristic.
            if (m_simdPebKeyValid) {
                uint64_t ct = runSimdWithKey(m_simdPebKey);
                if (validateChunkTable(ct)) {
                    chunk_table = ct;
                    std::printf("[canon28] chunk_table = 0x%llX (uprobe-captured key 0x%llX)\n",
                        (unsigned long long)ct, (unsigned long long)m_simdPebKey);
                } else {
                    std::printf("[canon28] uprobe key 0x%llX produced invalid chunk_table 0x%llX — falling through\n",
                        (unsigned long long)m_simdPebKey, (unsigned long long)ct);
                }
            }

            if (!chunk_table && have_peb_const) {
                // Try cached PEB first, then full discovery list.
                if (m_pebAddr) {
                    uint64_t ct = runSimdDecrypt(m_pebAddr);
                    if (validateChunkTable(ct)) {
                        chunk_table = ct;
                        std::printf("[canon28] chunk_table = 0x%llX (cached PEB 0x%llX)\n",
                            (unsigned long long)ct, (unsigned long long)m_pebAddr);
                    }
                }
                auto try_peb = [&](uint64_t cand) -> bool {
                    uint64_t ct = runSimdDecrypt(cand);
                    if (!validateChunkTable(ct)) return false;
                    chunk_table = ct;
                    m_pebAddr   = cand;
                    return true;
                };

                // Sweep the legacy Windows PEB range first — cheap and
                // sometimes still right on older Wine versions.
                if (!chunk_table) {
                    for (uint64_t c = 0x7FF00000; c < 0x7FFE0000; c += 0x10000) {
                        if (try_peb(c)) {
                            std::printf("[canon28] chunk_table = 0x%llX (PEB @ 0x%llX, legacy sweep)\n",
                                (unsigned long long)chunk_table, (unsigned long long)c);
                            break;
                        }
                    }
                }
                if (!chunk_table) {
                    for (uint64_t c = 0x00010000; c < 0x00200000; c += 0x10000) {
                        if (try_peb(c)) {
                            std::printf("[canon28] chunk_table = 0x%llX (PEB @ 0x%llX, low sweep)\n",
                                (unsigned long long)chunk_table, (unsigned long long)c);
                            break;
                        }
                    }
                }

                // Modern Wine allocates the PEB at a randomized address
                // outside the legacy ranges. Locate it by signature: the
                // PEB is page-aligned (Wine allocates via wine_anon_mmap),
                // and stores ImageBaseAddress at +0x10 — which equals our
                // module base (0x140000000). So at exactly one offset per
                // 4 KiB page we expect 8 bytes == m_base. Iterate page-by-
                // page (not slot-by-slot) — 512× fewer comparisons. The
                // SIMD decrypt + chunk_table validation disambiguates real
                // PEB hits from any incidental page that happens to hold
                // m_base at +0x10 (e.g. mirrored Ldr entries).
                if (!chunk_table) {
                    std::vector<Region> ranges;
                    ranges.reserve(64);
                    EnumerateRwHeapRegions(0x1000ULL, ~0ULL, ranges);
                    const uint64_t CHUNK = 0x400000ULL;       // 4 MiB read
                    const uint64_t PAGE  = 0x1000ULL;         // 4 KiB
                    std::vector<uint8_t> buf(CHUNK);
                    const uint64_t target = m_base;
                    size_t cands_tried = 0;
                    std::printf("[canon28] PEB sig-scan: %zu rw regions\n",
                        ranges.size());
                    for (const auto& rg : ranges) {
                        if (chunk_table) break;
                        // Skip the loaded module itself — its data section
                        // contains many references to ImageBaseAddress that
                        // are not PEBs and would inflate the candidate set.
                        if (rg.lo >= m_base && rg.lo < m_base + 0x10000000ULL) continue;
                        // Align region start to 4 KiB so the 0x10 offset
                        // probe lands on the actual page header.
                        uint64_t rg_lo = (rg.lo + (PAGE - 1)) & ~(PAGE - 1);
                        for (uint64_t base_addr = rg_lo;
                             base_addr < rg.hi && !chunk_table;
                             base_addr += CHUNK) {
                            uint64_t want = std::min<uint64_t>(CHUNK, rg.hi - base_addr);
                            if (want < PAGE) break;
                            if (!m_reader.Read(base_addr, buf.data(), want)) continue;
                            // 1 probe per page at offset +0x10
                            for (uint64_t poff = 0; poff + 0x18 <= want; poff += PAGE) {
                                uint64_t v;
                                std::memcpy(&v, buf.data() + poff + 0x10, 8);
                                if (v != target) continue;
                                uint64_t cand = base_addr + poff;
                                ++cands_tried;
                                if (try_peb(cand)) {
                                    std::printf("[canon28] chunk_table = 0x%llX (PEB @ 0x%llX, sig-scan, %zu tried)\n",
                                        (unsigned long long)chunk_table,
                                        (unsigned long long)cand,
                                        cands_tried);
                                    break;
                                }
                            }
                        }
                    }
                    if (!chunk_table) {
                        std::printf("[canon28] PEB sig-scan tried %zu candidates, none decrypted to a valid chunk_table\n",
                            cands_tried);
                    }
                }
            }

            // ── Path (b): no-PEB heap scan ───────────────────────────────
            // Walk all rw regions and find an aligned uint64_t array shaped
            // like a chunk-table: at least N consecutive entries, each into
            // a heap allocation whose +0 is a UObject* with vtable in module
            // range. We require N == num_chunks (computed from `total`) so
            // false positives are vanishingly rare.
            if (!chunk_table) {
                std::printf("[canon28] SIMD chunk_table decrypt failed; falling back to heap-scan\n");
                chunk_table = ProbeChunkTableNoPEB(num_chunks, vt_lo, vt_hi);
                if (chunk_table) {
                    std::printf("[canon28] chunk_table = 0x%llX (heap-scan fallback, %u chunks)\n",
                        (unsigned long long)chunk_table, num_chunks);
                }
            }

            if (!chunk_table) {
                std::printf("[canon28] could not locate chunk_table — bailing\n");
                return false;
            }

            // Bulk read all chunk pointers (≤512B for max 64 chunks).
            std::vector<uint64_t> chunk_ptrs(num_chunks, 0);
            if (!m_reader.Read(chunk_table, chunk_ptrs.data(), 8ULL * num_chunks)) {
                std::printf("[canon28] bulk read of chunk_table @ 0x%llX failed\n",
                    (unsigned long long)chunk_table);
                return false;
            }
            for (uint32_t ci = 0; ci < num_chunks; ++ci) {
                if (chunk_ptrs[ci] < 0x10000ULL || chunk_ptrs[ci] >= 0x800000000000ULL) {
                    std::printf("[canon28] chunk_ptrs[%u] = 0x%llX invalid\n",
                        ci, (unsigned long long)chunk_ptrs[ci]);
                    return false;
                }
            }

            // Quick validation: chunk[0] slot 0 should hold a real UObject.
            uint64_t obj0 = 0;
            if (!m_reader.Read(chunk_ptrs[0], &obj0, 8) ||
                obj0 < 0x10000ULL || obj0 >= 0x800000000000ULL) {
                std::printf("[canon28] chunk[0] slot 0 read failed or invalid\n");
                return false;
            }
            uint64_t vt0 = 0;
            if (!m_reader.Read(obj0, &vt0, 8) || vt0 < vt_lo || vt0 >= vt_hi) {
                std::printf("[canon28] chunk[0] slot 0 vtable 0x%llX outside module range\n",
                    (unsigned long long)vt0);
                return false;
            }

            out_objects.clear();
            out_objects.reserve(total);
            std::unordered_set<uint64_t> seen;
            seen.reserve(total);

            // Read each chunk in a single bulk read for speed.
            std::vector<uint8_t> buf(ITEMS_PER_CHUNK * STRIDE);
            for (uint32_t ci = 0; ci < num_chunks; ++ci) {
                uint64_t cp = chunk_ptrs[ci];
                uint32_t chunk_base_idx = ci * ITEMS_PER_CHUNK;
                uint32_t chunk_lim = std::min(ITEMS_PER_CHUNK,
                    (total > chunk_base_idx) ? (total - chunk_base_idx) : 0u);
                if (chunk_lim == 0) break;
                if (!m_reader.Read(cp, buf.data(), static_cast<size_t>(chunk_lim) * STRIDE)) {
                    std::printf("[canon28] bulk read chunk[%u] @ 0x%llX failed (lim=%u)\n",
                        ci, (unsigned long long)cp, chunk_lim);
                    continue;
                }
                uint32_t valid = 0;
                for (uint32_t i = 0; i < chunk_lim; ++i) {
                    uint64_t obj = 0;
                    std::memcpy(&obj, buf.data() + i * STRIDE, 8);
                    if (!obj) continue;
                    if (obj < 0x10000ULL || obj >= 0x800000000000ULL) continue;
                    // Re-validate vtable per object — runtime can hold stale
                    // pointers in tail slots beyond NumActive.
                    uint64_t vt = 0;
                    if (!m_reader.Read(obj, &vt, 8)) continue;
                    if (vt < vt_lo || vt >= vt_hi) continue;
                    if (seen.insert(obj).second) {
                        out_objects.push_back(obj);
                        ++valid;
                    }
                }
                std::printf("[canon28] chunk[%u] @ 0x%llX: %u/%u valid\n",
                    ci, (unsigned long long)cp, valid, chunk_lim);
            }

            if (out_objects.size() < 1000) {
                std::printf("[canon28] only %zu valid UObjects collected — bailing\n",
                    out_objects.size());
                return false;
            }

            out_num_elements = static_cast<int32_t>(total);
            return true;
        }

        // ─────────────────────────────────────────────────────────────────
        // Vt2Interpret — dynamic mini-interpreter for chunks_manager vtable[2].
        //
        // Each game session picks one of ~37 vtable variants (hash on heap ptr
        // in sub_49EFF0). All variants share the same template:
        //   1. movq xmm0, [rdx]         ; load 8B encrypted from second arg
        //   2. mov  eax, IMM32          ; PEB_ADD constant
        //   3. add  rax, gs:[0x60]      ; rax = IMM32 + PEB
        //   4. some sequence of SIMD ops on xmm0 (pshuflw, pshufhw, pshufd,
        //      psllw/psrlw, pslld/psrld, psllq/psrlq, por, pxor with [rip+disp]
        //      or another xmm, pcmpgtw/pcmpgtb/pcmpgtd, pmovzxwd, movdqa)
        //   5. mov  rcx, IMM64 (optional) + xor rcx, rax (rcx becomes broadcast key)
        //   6. movq xmm, rax_or_rcx + pshufd 0x44 (broadcast lo64 to all 128b)
        //   7. pxor xmmA, xmmB (final XOR)
        //   8. ret
        // The lo64 of xmm0 (or whichever was final pxor target) is the
        // chunks_array pointer.
        //
        // We decode each instruction via Zydis and execute it against a small
        // VM state (4 xmm regs, rax, rcx). Returns the decrypted lo64, or 0
        // on failure (unsupported instruction, read failure, fell off the end).
        // ─────────────────────────────────────────────────────────────────
        uint64_t Vt2Interpret(uint64_t fn_addr, uint64_t enc_addr) {
            // Read function bytes
            uint8_t code[256] = {};
            if (!m_reader.Read(fn_addr, code, sizeof(code))) {
                std::printf("[vt2] read fn @ 0x%llX failed\n", (unsigned long long)fn_addr);
                return 0;
            }
            // Read full 16B encrypted input (some variants use movdqa [rdx])
            alignas(16) uint8_t enc_buf[16] = {};
            if (!m_reader.Read(enc_addr, enc_buf, 16)) {
                std::printf("[vt2] read enc @ 0x%llX failed\n", (unsigned long long)enc_addr);
                return 0;
            }

            // VM state
            alignas(16) uint8_t xmm[8][16] = {}; // xmm0..xmm7
            uint64_t gpr[16] = {};               // [0]=rax [1]=rcx [2]=rdx [3]=rbx ... (Intel encoding)
            gpr[2] = enc_addr;                   // rdx = ptr to encrypted blob (caller convention)

            ZydisDecoder dec;
            ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

            ZyanUSize ip = 0;
            for (int step = 0; step < 64 && ip < sizeof(code); ++step) {
                ZydisDecodedInstruction inst;
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + ip, sizeof(code) - ip, &inst, ops))) {
                    std::printf("[vt2] decode failed at +0x%llX\n", (unsigned long long)ip);
                    return 0;
                }
                uint64_t insn_rip_after = fn_addr + ip + inst.length;

                auto getXmmIdx = [](const ZydisDecodedOperand& op) -> int {
                    if (op.type != ZYDIS_OPERAND_TYPE_REGISTER) return -1;
                    int r = op.reg.value;
                    if (r >= ZYDIS_REGISTER_XMM0 && r <= ZYDIS_REGISTER_XMM7)
                        return r - ZYDIS_REGISTER_XMM0;
                    return -1;
                };
                auto getGprIdx = [](const ZydisDecodedOperand& op) -> int {
                    if (op.type != ZYDIS_OPERAND_TYPE_REGISTER) return -1;
                    int r = op.reg.value;
                    if (r >= ZYDIS_REGISTER_RAX && r <= ZYDIS_REGISTER_R15)
                        return r - ZYDIS_REGISTER_RAX;
                    if (r >= ZYDIS_REGISTER_EAX && r <= ZYDIS_REGISTER_R15D)
                        return r - ZYDIS_REGISTER_EAX;
                    return -1;
                };

                switch (inst.mnemonic) {
                    case ZYDIS_MNEMONIC_MOVQ:
                    case ZYDIS_MNEMONIC_MOVD: {
                        // movq xmm, [mem] or movq xmm, gpr or movq gpr, xmm
                        int xd = getXmmIdx(ops[0]);
                        if (xd >= 0 && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                            // movq xmm, [rdx]  (load 8B from enc input)
                            std::memset(xmm[xd], 0, 16);
                            std::memcpy(xmm[xd], enc_buf, 8);
                        } else if (xd >= 0) {
                            int gs = getGprIdx(ops[1]);
                            if (gs < 0) goto unsupported;
                            std::memset(xmm[xd], 0, 16);
                            std::memcpy(xmm[xd], &gpr[gs], 8);
                        } else {
                            int gd = getGprIdx(ops[0]);
                            int xs = getXmmIdx(ops[1]);
                            if (gd < 0 || xs < 0) goto unsupported;
                            std::memcpy(&gpr[gd], xmm[xs], 8);
                        }
                        break;
                    }
                    case ZYDIS_MNEMONIC_MOV: {
                        // mov eax/rax, imm or mov gpr, mem (gs:[0x60] = PEB)
                        int gd = getGprIdx(ops[0]);
                        if (gd < 0) goto unsupported;
                        if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                            uint64_t val = (uint64_t)ops[1].imm.value.u;
                            // mov eax → zero-extends to rax
                            if (ops[0].size == 32) val &= 0xFFFFFFFFULL;
                            gpr[gd] = val;
                        } else {
                            goto unsupported;
                        }
                        break;
                    }
                    case ZYDIS_MNEMONIC_ADD: {
                        // add rax, qword ptr gs:[0x60]  → rax += PEB
                        int gd = getGprIdx(ops[0]);
                        if (gd < 0) goto unsupported;
                        if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                            ops[1].mem.segment == ZYDIS_REGISTER_GS &&
                            ops[1].mem.disp.value == 0x60) {
                            gpr[gd] += m_pebAddr;
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                            gpr[gd] += (uint64_t)ops[1].imm.value.u;
                        } else {
                            goto unsupported;
                        }
                        break;
                    }
                    case ZYDIS_MNEMONIC_XOR: {
                        // xor rax, rcx or xor rcx, rax
                        int gd = getGprIdx(ops[0]);
                        int gs = getGprIdx(ops[1]);
                        if (gd < 0 || gs < 0) goto unsupported;
                        gpr[gd] ^= gpr[gs];
                        break;
                    }
                    case ZYDIS_MNEMONIC_MOVDQA:
                    case ZYDIS_MNEMONIC_MOVDQU: {
                        int xd = getXmmIdx(ops[0]);
                        if (xd < 0) goto unsupported;
                        if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                            int xs = getXmmIdx(ops[1]);
                            if (xs < 0) goto unsupported;
                            std::memcpy(xmm[xd], xmm[xs], 16);
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                   ops[1].mem.base == ZYDIS_REGISTER_RDX &&
                                   ops[1].mem.disp.value == 0) {
                            // movdqa xmm, [rdx]  — full 16B encrypted blob
                            std::memcpy(xmm[xd], enc_buf, 16);
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                   ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                            uint64_t target = insn_rip_after + (int64_t)ops[1].mem.disp.value;
                            alignas(16) uint8_t mask[16] = {};
                            if (!m_reader.Read(target, mask, 16)) {
                                std::printf("[vt2] read rip-rel @ 0x%llX failed\n",
                                            (unsigned long long)target);
                                return 0;
                            }
                            std::memcpy(xmm[xd], mask, 16);
                        } else {
                            goto unsupported;
                        }
                        break;
                    }
                    case ZYDIS_MNEMONIC_PSHUFB: {
                        int xd = getXmmIdx(ops[0]);
                        if (xd < 0) goto unsupported;
                        alignas(16) uint8_t mask_bytes[16] = {};
                        if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                            int xs = getXmmIdx(ops[1]);
                            if (xs < 0) goto unsupported;
                            std::memcpy(mask_bytes, xmm[xs], 16);
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                   ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                            uint64_t target = insn_rip_after + (int64_t)ops[1].mem.disp.value;
                            if (!m_reader.Read(target, mask_bytes, 16)) {
                                std::printf("[vt2] pshufb mask read @ 0x%llX failed\n",
                                            (unsigned long long)target);
                                return 0;
                            }
                        } else {
                            goto unsupported;
                        }
                        // PSHUFB: for each byte, if mask byte high bit set → 0, else use src[mask[i] & 0xF]
                        uint8_t src[16];
                        std::memcpy(src, xmm[xd], 16);
                        uint8_t out[16];
                        for (int i = 0; i < 16; ++i) {
                            uint8_t m = mask_bytes[i];
                            out[i] = (m & 0x80) ? 0 : src[m & 0x0F];
                        }
                        std::memcpy(xmm[xd], out, 16);
                        break;
                    }
                    case ZYDIS_MNEMONIC_PSLLW:
                    case ZYDIS_MNEMONIC_PSRLW:
                    case ZYDIS_MNEMONIC_PSLLD:
                    case ZYDIS_MNEMONIC_PSRLD:
                    case ZYDIS_MNEMONIC_PSLLQ:
                    case ZYDIS_MNEMONIC_PSRLQ: {
                        int xd = getXmmIdx(ops[0]);
                        if (xd < 0 || ops[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) goto unsupported;
                        int shift = (int)ops[1].imm.value.u;
                        __m128i v = _mm_loadu_si128((const __m128i*)xmm[xd]);
                        __m128i r;
                        switch (inst.mnemonic) {
                            case ZYDIS_MNEMONIC_PSLLW: r = _mm_slli_epi16(v, shift); break;
                            case ZYDIS_MNEMONIC_PSRLW: r = _mm_srli_epi16(v, shift); break;
                            case ZYDIS_MNEMONIC_PSLLD: r = _mm_slli_epi32(v, shift); break;
                            case ZYDIS_MNEMONIC_PSRLD: r = _mm_srli_epi32(v, shift); break;
                            case ZYDIS_MNEMONIC_PSLLQ: r = _mm_slli_epi64(v, shift); break;
                            case ZYDIS_MNEMONIC_PSRLQ: r = _mm_srli_epi64(v, shift); break;
                            default: goto unsupported;
                        }
                        _mm_storeu_si128((__m128i*)xmm[xd], r);
                        break;
                    }
                    case ZYDIS_MNEMONIC_POR: {
                        int xd = getXmmIdx(ops[0]);
                        if (xd < 0) goto unsupported;
                        __m128i a = _mm_loadu_si128((const __m128i*)xmm[xd]);
                        __m128i b;
                        if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                            int xs = getXmmIdx(ops[1]);
                            if (xs < 0) goto unsupported;
                            b = _mm_loadu_si128((const __m128i*)xmm[xs]);
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                   ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                            uint64_t target = insn_rip_after + (int64_t)ops[1].mem.disp.value;
                            alignas(16) uint8_t tmp[16] = {};
                            if (!m_reader.Read(target, tmp, 16)) goto unsupported;
                            b = _mm_loadu_si128((const __m128i*)tmp);
                        } else goto unsupported;
                        _mm_storeu_si128((__m128i*)xmm[xd], _mm_or_si128(a, b));
                        break;
                    }
                    case ZYDIS_MNEMONIC_PXOR: {
                        int xd = getXmmIdx(ops[0]);
                        if (xd < 0) goto unsupported;
                        __m128i a = _mm_loadu_si128((const __m128i*)xmm[xd]);
                        __m128i b;
                        if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                            int xs = getXmmIdx(ops[1]);
                            if (xs < 0) goto unsupported;
                            b = _mm_loadu_si128((const __m128i*)xmm[xs]);
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                   ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                            // pxor xmm, [rip+disp32] — read 16B mask from process
                            uint64_t target = insn_rip_after + (int64_t)ops[1].mem.disp.value;
                            alignas(16) uint8_t mask[16] = {};
                            if (!m_reader.Read(target, mask, 16)) {
                                std::printf("[vt2] read rdata mask @ 0x%llX failed\n",
                                            (unsigned long long)target);
                                return 0;
                            }
                            b = _mm_loadu_si128((const __m128i*)mask);
                        } else {
                            goto unsupported;
                        }
                        _mm_storeu_si128((__m128i*)xmm[xd], _mm_xor_si128(a, b));
                        break;
                    }
                    case ZYDIS_MNEMONIC_PSHUFLW:
                    case ZYDIS_MNEMONIC_PSHUFHW: {
                        int xd = getXmmIdx(ops[0]);
                        if (xd < 0 || ops[2].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) goto unsupported;
                        int imm = (int)ops[2].imm.value.u;
                        // Source: register OR memory ([rdx] for the cipher's first
                        // insn, or [rip+disp32] for inline-data variants).
                        alignas(16) uint8_t src_buf[16] = {};
                        if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                            int xs = getXmmIdx(ops[1]);
                            if (xs < 0) goto unsupported;
                            std::memcpy(src_buf, xmm[xs], 16);
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                   ops[1].mem.base == ZYDIS_REGISTER_RDX &&
                                   ops[1].mem.disp.value == 0) {
                            // pshuflw xmm, qword ptr [rdx], imm — only lo64 matters
                            std::memcpy(src_buf, enc_buf, 8);
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                   ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                            uint64_t target = insn_rip_after + (int64_t)ops[1].mem.disp.value;
                            if (!m_reader.Read(target, src_buf, 16)) {
                                std::printf("[vt2] pshuf %s rip-rel read @ 0x%llX failed\n",
                                            (inst.mnemonic == ZYDIS_MNEMONIC_PSHUFLW) ? "lw" : "hw",
                                            (unsigned long long)target);
                                return 0;
                            }
                        } else {
                            goto unsupported;
                        }
                        __m128i v = _mm_loadu_si128((const __m128i*)src_buf);
                        __m128i r;
                        if (inst.mnemonic == ZYDIS_MNEMONIC_PSHUFLW) {
                            // Note: _mm_shufflelo_epi16 requires compile-time constant.
                            // Inline switch table over the 256 possible imm values:
                            #define SHUFLO(I) case I: r = _mm_shufflelo_epi16(v, I); break;
                            switch (imm) {
                                SHUFLO(0x00) SHUFLO(0x01) SHUFLO(0x02) SHUFLO(0x03) SHUFLO(0x04) SHUFLO(0x05) SHUFLO(0x06) SHUFLO(0x07)
                                SHUFLO(0x08) SHUFLO(0x09) SHUFLO(0x0A) SHUFLO(0x0B) SHUFLO(0x0C) SHUFLO(0x0D) SHUFLO(0x0E) SHUFLO(0x0F)
                                SHUFLO(0x10) SHUFLO(0x11) SHUFLO(0x12) SHUFLO(0x13) SHUFLO(0x14) SHUFLO(0x15) SHUFLO(0x16) SHUFLO(0x17)
                                SHUFLO(0x18) SHUFLO(0x19) SHUFLO(0x1A) SHUFLO(0x1B) SHUFLO(0x1C) SHUFLO(0x1D) SHUFLO(0x1E) SHUFLO(0x1F)
                                SHUFLO(0x20) SHUFLO(0x21) SHUFLO(0x22) SHUFLO(0x23) SHUFLO(0x24) SHUFLO(0x25) SHUFLO(0x26) SHUFLO(0x27)
                                SHUFLO(0x28) SHUFLO(0x29) SHUFLO(0x2A) SHUFLO(0x2B) SHUFLO(0x2C) SHUFLO(0x2D) SHUFLO(0x2E) SHUFLO(0x2F)
                                SHUFLO(0x30) SHUFLO(0x31) SHUFLO(0x32) SHUFLO(0x33) SHUFLO(0x34) SHUFLO(0x35) SHUFLO(0x36) SHUFLO(0x37)
                                SHUFLO(0x38) SHUFLO(0x39) SHUFLO(0x3A) SHUFLO(0x3B) SHUFLO(0x3C) SHUFLO(0x3D) SHUFLO(0x3E) SHUFLO(0x3F)
                                SHUFLO(0x40) SHUFLO(0x41) SHUFLO(0x42) SHUFLO(0x43) SHUFLO(0x44) SHUFLO(0x45) SHUFLO(0x46) SHUFLO(0x47)
                                SHUFLO(0x48) SHUFLO(0x49) SHUFLO(0x4A) SHUFLO(0x4B) SHUFLO(0x4C) SHUFLO(0x4D) SHUFLO(0x4E) SHUFLO(0x4F)
                                SHUFLO(0x50) SHUFLO(0x51) SHUFLO(0x52) SHUFLO(0x53) SHUFLO(0x54) SHUFLO(0x55) SHUFLO(0x56) SHUFLO(0x57)
                                SHUFLO(0x58) SHUFLO(0x59) SHUFLO(0x5A) SHUFLO(0x5B) SHUFLO(0x5C) SHUFLO(0x5D) SHUFLO(0x5E) SHUFLO(0x5F)
                                SHUFLO(0x60) SHUFLO(0x61) SHUFLO(0x62) SHUFLO(0x63) SHUFLO(0x64) SHUFLO(0x65) SHUFLO(0x66) SHUFLO(0x67)
                                SHUFLO(0x68) SHUFLO(0x69) SHUFLO(0x6A) SHUFLO(0x6B) SHUFLO(0x6C) SHUFLO(0x6D) SHUFLO(0x6E) SHUFLO(0x6F)
                                SHUFLO(0x70) SHUFLO(0x71) SHUFLO(0x72) SHUFLO(0x73) SHUFLO(0x74) SHUFLO(0x75) SHUFLO(0x76) SHUFLO(0x77)
                                SHUFLO(0x78) SHUFLO(0x79) SHUFLO(0x7A) SHUFLO(0x7B) SHUFLO(0x7C) SHUFLO(0x7D) SHUFLO(0x7E) SHUFLO(0x7F)
                                SHUFLO(0x80) SHUFLO(0x81) SHUFLO(0x82) SHUFLO(0x83) SHUFLO(0x84) SHUFLO(0x85) SHUFLO(0x86) SHUFLO(0x87)
                                SHUFLO(0x88) SHUFLO(0x89) SHUFLO(0x8A) SHUFLO(0x8B) SHUFLO(0x8C) SHUFLO(0x8D) SHUFLO(0x8E) SHUFLO(0x8F)
                                SHUFLO(0x90) SHUFLO(0x91) SHUFLO(0x92) SHUFLO(0x93) SHUFLO(0x94) SHUFLO(0x95) SHUFLO(0x96) SHUFLO(0x97)
                                SHUFLO(0x98) SHUFLO(0x99) SHUFLO(0x9A) SHUFLO(0x9B) SHUFLO(0x9C) SHUFLO(0x9D) SHUFLO(0x9E) SHUFLO(0x9F)
                                SHUFLO(0xA0) SHUFLO(0xA1) SHUFLO(0xA2) SHUFLO(0xA3) SHUFLO(0xA4) SHUFLO(0xA5) SHUFLO(0xA6) SHUFLO(0xA7)
                                SHUFLO(0xA8) SHUFLO(0xA9) SHUFLO(0xAA) SHUFLO(0xAB) SHUFLO(0xAC) SHUFLO(0xAD) SHUFLO(0xAE) SHUFLO(0xAF)
                                SHUFLO(0xB0) SHUFLO(0xB1) SHUFLO(0xB2) SHUFLO(0xB3) SHUFLO(0xB4) SHUFLO(0xB5) SHUFLO(0xB6) SHUFLO(0xB7)
                                SHUFLO(0xB8) SHUFLO(0xB9) SHUFLO(0xBA) SHUFLO(0xBB) SHUFLO(0xBC) SHUFLO(0xBD) SHUFLO(0xBE) SHUFLO(0xBF)
                                SHUFLO(0xC0) SHUFLO(0xC1) SHUFLO(0xC2) SHUFLO(0xC3) SHUFLO(0xC4) SHUFLO(0xC5) SHUFLO(0xC6) SHUFLO(0xC7)
                                SHUFLO(0xC8) SHUFLO(0xC9) SHUFLO(0xCA) SHUFLO(0xCB) SHUFLO(0xCC) SHUFLO(0xCD) SHUFLO(0xCE) SHUFLO(0xCF)
                                SHUFLO(0xD0) SHUFLO(0xD1) SHUFLO(0xD2) SHUFLO(0xD3) SHUFLO(0xD4) SHUFLO(0xD5) SHUFLO(0xD6) SHUFLO(0xD7)
                                SHUFLO(0xD8) SHUFLO(0xD9) SHUFLO(0xDA) SHUFLO(0xDB) SHUFLO(0xDC) SHUFLO(0xDD) SHUFLO(0xDE) SHUFLO(0xDF)
                                SHUFLO(0xE0) SHUFLO(0xE1) SHUFLO(0xE2) SHUFLO(0xE3) SHUFLO(0xE4) SHUFLO(0xE5) SHUFLO(0xE6) SHUFLO(0xE7)
                                SHUFLO(0xE8) SHUFLO(0xE9) SHUFLO(0xEA) SHUFLO(0xEB) SHUFLO(0xEC) SHUFLO(0xED) SHUFLO(0xEE) SHUFLO(0xEF)
                                SHUFLO(0xF0) SHUFLO(0xF1) SHUFLO(0xF2) SHUFLO(0xF3) SHUFLO(0xF4) SHUFLO(0xF5) SHUFLO(0xF6) SHUFLO(0xF7)
                                SHUFLO(0xF8) SHUFLO(0xF9) SHUFLO(0xFA) SHUFLO(0xFB) SHUFLO(0xFC) SHUFLO(0xFD) SHUFLO(0xFE) SHUFLO(0xFF)
                                default: r = v;
                            }
                            #undef SHUFLO
                        } else {
                            // PSHUFHW — implement manually since less common.
                            // Source already loaded into src_buf above.
                            uint16_t in_words[8];
                            std::memcpy(in_words, src_buf, 16);
                            uint16_t out_words[8];
                            for (int i = 0; i < 4; ++i) out_words[i] = in_words[i];
                            for (int i = 0; i < 4; ++i) {
                                int sel = (imm >> (2*i)) & 3;
                                out_words[4+i] = in_words[4+sel];
                            }
                            r = _mm_loadu_si128((const __m128i*)out_words);
                        }
                        _mm_storeu_si128((__m128i*)xmm[xd], r);
                        break;
                    }
                    case ZYDIS_MNEMONIC_PSHUFD: {
                        int xd = getXmmIdx(ops[0]);
                        int xs = getXmmIdx(ops[1]);
                        if (xd < 0 || xs < 0 || ops[2].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) goto unsupported;
                        int imm = (int)ops[2].imm.value.u;
                        uint32_t in_dwords[4];
                        std::memcpy(in_dwords, xmm[xs], 16);
                        uint32_t out_dwords[4];
                        for (int i = 0; i < 4; ++i) {
                            int sel = (imm >> (2*i)) & 3;
                            out_dwords[i] = in_dwords[sel];
                        }
                        std::memcpy(xmm[xd], out_dwords, 16);
                        break;
                    }
                    case ZYDIS_MNEMONIC_PADDW:
                    case ZYDIS_MNEMONIC_PADDD:
                    case ZYDIS_MNEMONIC_PADDQ:
                    case ZYDIS_MNEMONIC_PSUBW:
                    case ZYDIS_MNEMONIC_PSUBD:
                    case ZYDIS_MNEMONIC_PSUBQ:
                    case ZYDIS_MNEMONIC_PANDN:
                    case ZYDIS_MNEMONIC_PAND:
                    case ZYDIS_MNEMONIC_PMULLW:
                    case ZYDIS_MNEMONIC_PMULLD: {
                        int xd = getXmmIdx(ops[0]);
                        if (xd < 0) goto unsupported;
                        alignas(16) uint8_t Src[16] = {};
                        if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                            int xs = getXmmIdx(ops[1]);
                            if (xs < 0) goto unsupported;
                            std::memcpy(Src, xmm[xs], 16);
                        } else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                   ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                            uint64_t target = insn_rip_after + (int64_t)ops[1].mem.disp.value;
                            if (!m_reader.Read(target, Src, 16)) goto unsupported;
                        } else {
                            goto unsupported;
                        }
                        __m128i A = _mm_loadu_si128(reinterpret_cast<const __m128i*>(xmm[xd]));
                        __m128i B = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Src));
                        __m128i R;
                        switch (inst.mnemonic) {
                            case ZYDIS_MNEMONIC_PADDW:  R = _mm_add_epi16(A, B); break;
                            case ZYDIS_MNEMONIC_PADDD:  R = _mm_add_epi32(A, B); break;
                            case ZYDIS_MNEMONIC_PADDQ:  R = _mm_add_epi64(A, B); break;
                            case ZYDIS_MNEMONIC_PSUBW:  R = _mm_sub_epi16(A, B); break;
                            case ZYDIS_MNEMONIC_PSUBD:  R = _mm_sub_epi32(A, B); break;
                            case ZYDIS_MNEMONIC_PSUBQ:  R = _mm_sub_epi64(A, B); break;
                            case ZYDIS_MNEMONIC_PANDN:  R = _mm_andnot_si128(A, B); break;
                            case ZYDIS_MNEMONIC_PAND:   R = _mm_and_si128(A, B); break;
                            case ZYDIS_MNEMONIC_PMULLW: R = _mm_mullo_epi16(A, B); break;
                            case ZYDIS_MNEMONIC_PMULLD: R = _mm_mullo_epi32(A, B); break;
                            default: R = A; break;
                        }
                        _mm_storeu_si128(reinterpret_cast<__m128i*>(xmm[xd]), R);
                        break;
                    }
                    case ZYDIS_MNEMONIC_RET: {
                        uint64_t out;
                        std::memcpy(&out, xmm[0], 8);
                        return out;
                    }
                    default:
                    unsupported:
                        std::printf("[vt2] unsupported insn at +0x%llX: %s\n",
                                    (unsigned long long)ip,
                                    ZydisMnemonicGetString(inst.mnemonic));
                        return 0;
                }

                ip += inst.length;
            }
            std::printf("[vt2] fell off without ret\n");
            return 0;
        }

        // ─────────────────────────────────────────────────────────────────
        // InitPatch20260519 — CL-1201801 (ARC Steam patch 2026-05-21)
        // RVA_GOBJECT_ARRAY_BASE (0xE4F8F60) is now a POINTER VARIABLE holding
        // the encrypted FCA heap address; the FCA itself lives on the heap.
        //
        // FCA ptr decrypt (xmmword @ module+0xE3B6270):
        //   ROL32(26) per dword → PSHUFB(mask@0xB1E8ED0) → ROL16(4) per word → lo64
        //
        // NumElements (at FCA+0x30):
        //   shufflelo(0x8C) → srli_epi64(18) → XOR(mask@0xB23C120) → lo32 ^ 0xDB155ED3
        //
        // chunks_array: vtable[8] of FCA's embedded vtable object.
        //   vtable_ptr = *(qword*)(FCA+0x60)
        //   vtable8_fn = *(qword*)(vtable_ptr+0x40)
        //   chunks_array = Vt2Interpret(vtable8_fn, FCA+0x90)
        //
        // Each chunk: 65536 × FUObjectItem (20 bytes); Object at +0.
        // ─────────────────────────────────────────────────────────────────
        bool InitPatch20260519() {
            constexpr uint64_t kFcaEncRva     = 0xE3B6270;   // encrypted FCA ptr xmmword
            constexpr uint64_t kFcaMaskRva    = 0xB1E8ED0;   // PSHUFB mask (16B)
            constexpr uint64_t kNumElXorRva   = 0xB23C120;   // NumElements XOR const (16B)
            constexpr uint32_t kNumElFinalXor = 0xDB155ED3u;
            constexpr uint32_t kSlotsPerChunk = 65536;
            constexpr uint32_t kItemStride    = 20;

            auto isHeap = [](uint64_t p) {
                return p >= 0x10000ULL && p < 0x7FFFFFFFFFFFULL;
            };
            auto isModule = [&](uint64_t p) {
                return p >= m_base && p < m_base + 0x10000000ULL;
            };
            auto validateAsChunksArray = [&](uint64_t arr) -> bool {
                if (!isHeap(arr)) return false;
                uint64_t cp[2] = {};
                if (!m_reader.Read(arr, cp, 16)) return false;
                if (!isHeap(cp[0]) || !isHeap(cp[1])) {
                    std::printf("[p519]   validate fail: cp0=0x%llX cp1=0x%llX not heap\n",
                        (unsigned long long)cp[0], (unsigned long long)cp[1]);
                    return false;
                }
                uint64_t obj0 = 0, obj1 = 0;
                if (!m_reader.Read(cp[0], &obj0, 8) || !m_reader.Read(cp[1], &obj1, 8)) return false;
                if (!isHeap(obj0) || !isHeap(obj1)) {
                    std::printf("[p519]   validate fail: obj0=0x%llX obj1=0x%llX not heap\n",
                        (unsigned long long)obj0, (unsigned long long)obj1);
                    return false;
                }
                uint64_t vt0 = 0;
                if (!m_reader.Read(obj0, &vt0, 8)) return false;
                if (!isModule(vt0)) {
                    std::printf("[p519]   validate fail: vt0=0x%llX not module\n",
                        (unsigned long long)vt0);
                    return false;
                }
                return true;
            };

            // Step 1: decrypt FCA heap ptr from module+kFcaEncRva.
            // ROL32(26) per dword → PSHUFB(mask) → ROL16(4) per word → lo64
            alignas(16) uint8_t enc_buf[16]  = {};
            alignas(16) uint8_t mask_buf[16] = {};
            if (!m_reader.Read(m_base + kFcaEncRva, enc_buf, 16)) {
                std::printf("[p519] read FCA enc blob @ RVA 0x%llX failed\n",
                            (unsigned long long)kFcaEncRva);
                return false;
            }
            if (!m_reader.Read(m_base + kFcaMaskRva, mask_buf, 16)) {
                std::printf("[p519] read FCA PSHUFB mask @ RVA 0x%llX failed\n",
                            (unsigned long long)kFcaMaskRva);
                return false;
            }
            {
                __m128i Enc  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc_buf));
                __m128i Mask = _mm_loadu_si128(reinterpret_cast<const __m128i*>(mask_buf));
                __m128i R32  = _mm_or_si128(_mm_slli_epi32(Enc, 26), _mm_srli_epi32(Enc, 6));
                __m128i Shuf = _mm_shuffle_epi8(R32, Mask);
                __m128i R16  = _mm_or_si128(_mm_slli_epi16(Shuf, 4), _mm_srli_epi16(Shuf, 12));
                uint64_t FcaAddr = static_cast<uint64_t>(_mm_cvtsi128_si64(R16));
                std::printf("[p519] FCA addr = 0x%llX\n", (unsigned long long)FcaAddr);
                if (!isHeap(FcaAddr)) {
                    std::printf("[p519] FCA addr out of heap range\n");
                    return false;
                }

                // Step 2: decode NumElements from FCA+0x30.
                // shufflelo(0x8C) → srli_epi64(18) → XOR(kNumElXorRva lo64) → lo32 ^ kNumElFinalXor
                alignas(16) uint8_t ne_buf[16]  = {};
                alignas(16) uint8_t ne_mask[16] = {};
                if (!m_reader.Read(FcaAddr + 0x30, ne_buf, 16)) {
                    std::printf("[p519] read NumElements blob @ FCA+0x30 failed\n");
                    return false;
                }
                if (!m_reader.Read(m_base + kNumElXorRva, ne_mask, 16)) {
                    std::printf("[p519] read NumElements XOR mask @ RVA 0x%llX failed\n",
                                (unsigned long long)kNumElXorRva);
                    return false;
                }
                __m128i NeV    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ne_buf));
                __m128i NeMask = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ne_mask));
                __m128i NeShuf = _mm_shufflelo_epi16(NeV, 0x8C);
                __m128i NeSrl  = _mm_srli_epi64(NeShuf, 18);
                __m128i NeXor  = _mm_xor_si128(NeSrl, NeMask);
                uint32_t NumElements = static_cast<uint32_t>(_mm_cvtsi128_si32(NeXor)) ^ kNumElFinalXor;
                std::printf("[p519] NumElements = %u\n", NumElements);
                if (NumElements < 1000 || NumElements > 4000000) {
                    std::printf("[p519] NumElements %u implausible\n", NumElements);
                    return false;
                }

                uint32_t NumChunksNeeded = (NumElements + kSlotsPerChunk - 1) / kSlotsPerChunk;

                // Step 3: get vtable[8] function for chunks_array decrypt.
                // vtable_ptr = *(FCA+0x60); vtable8_fn = *(vtable_ptr+0x40)
                uint64_t VtablePtr = 0;
                if (!m_reader.Read(FcaAddr + 0x60, &VtablePtr, 8) || !isModule(VtablePtr)) {
                    std::printf("[p519] FCA vtable ptr @ FCA+0x60 = 0x%llX (not module)\n",
                                (unsigned long long)VtablePtr);
                    return false;
                }
                uint64_t Vtable8Fn = 0;
                if (!m_reader.Read(VtablePtr + 0x40, &Vtable8Fn, 8) || !isModule(Vtable8Fn)) {
                    std::printf("[p519] vtable[8] fn @ vtable+0x40 = 0x%llX (not module)\n",
                                (unsigned long long)Vtable8Fn);
                    return false;
                }
                std::printf("[p519] FCA=0x%llX vtable_ptr=0x%llX vtable8_fn=0x%llX\n",
                            (unsigned long long)FcaAddr, (unsigned long long)VtablePtr,
                            (unsigned long long)Vtable8Fn);

                // Step 4: PEB + Vt2Interpret → chunks_array.
                // vtable[8] cipher: MOV EAX, imm32 → ADD RAX, GS:[0x60] → MOVDQA XMM1, [RDX]
                //                   → PSHUFB/PXOR/etc. → return XMM0.lo64
                if (m_pebAddr == 0) {
                    m_pebAddr = FindPEB();
                    std::printf("[p519] FindPEB() => 0x%llX\n", (unsigned long long)m_pebAddr);
                    std::fflush(stdout);
                }

                uint64_t ChunksArray = 0;
                if (m_pebAddr) {
                    uint64_t Cand = Vt2Interpret(Vtable8Fn, FcaAddr + 0x90);
                    std::printf("[p519] Vt2Interpret => 0x%llX\n", (unsigned long long)Cand);
                    std::fflush(stdout);
                    if (validateAsChunksArray(Cand)) {
                        ChunksArray = Cand;
                        std::printf("[p519] chunks_array via Vt2Interpret = 0x%llX\n",
                                    (unsigned long long)ChunksArray);
                    }
                }

                if (!ChunksArray) {
                    std::printf("[p519] Vt2Interpret failed, trying heap scan (num_chunks=%u)\n",
                                NumChunksNeeded);
                    uint64_t VtLo = m_base + 0x1000ULL;
                    uint64_t VtHi = m_base + 0x10000000ULL;
                    ChunksArray = ProbeChunkTableNoPEB(NumChunksNeeded, VtLo, VtHi);
                    if (ChunksArray) {
                        std::printf("[p519] chunks_array via heap-scan = 0x%llX\n",
                                    (unsigned long long)ChunksArray);
                    }
                }

                if (!ChunksArray) {
                    std::printf("[p519] no chunks_array found\n");
                    return false;
                }

                // Step 5: walk chunks_array → flatten to m_worldFallbackObjects.
                uint32_t NumChunks = NumChunksNeeded;
                m_worldFallbackObjects.clear();
                m_worldFallbackObjects.reserve(NumElements);

                uint64_t ChunkPtrs[1024] = {};
                if (NumChunks > 1024) NumChunks = 1024;
                if (!m_reader.Read(ChunksArray, ChunkPtrs, NumChunks * 8)) {
                    std::printf("[p519] read chunk_ptrs batch failed\n");
                    return false;
                }

                uint32_t ValidChunks = 0;
                for (uint32_t Ci = 0; Ci < NumChunks; ++Ci) {
                    uint64_t Chunk = ChunkPtrs[Ci];
                    if (!Chunk || !isHeap(Chunk)) continue;
                    uint32_t SlotsInChunk = kSlotsPerChunk;
                    if (Ci == NumChunks - 1) {
                        uint32_t Rem = NumElements - (Ci * kSlotsPerChunk);
                        if (Rem < SlotsInChunk) SlotsInChunk = Rem;
                    }
                    std::vector<uint8_t> ChunkBuf(SlotsInChunk * kItemStride);
                    if (!m_reader.Read(Chunk, ChunkBuf.data(), ChunkBuf.size())) continue;
                    for (uint32_t Si = 0; Si < SlotsInChunk; ++Si) {
                        uint64_t Obj = 0;
                        std::memcpy(&Obj, ChunkBuf.data() + Si * kItemStride, 8);
                        if (isHeap(Obj)) {
                            m_worldFallbackObjects.push_back(Obj);
                        }
                    }
                    ++ValidChunks;
                }

                std::printf("[p519] walked %u chunks, collected %zu objects\n",
                            ValidChunks, m_worldFallbackObjects.size());

                if (m_worldFallbackObjects.size() < 1000) {
                    std::printf("[p519] too few objects\n");
                    m_worldFallbackObjects.clear();
                    return false;
                }

                m_arrayBase = FcaAddr;
                m_numElements = static_cast<int32_t>(NumElements);
                m_useWorldFallback = true;
                m_initialized = true;
                return true;
            }
        }

        // ── Patch 20260421: primary init path ────────────────────────────
        // 1. Decrypt GUObjectArray → chunks_manager (new RVA 0xDDCB420, new pipeline).
        // 2. Decrypt chunks_manager+0x70 → max_elements.
        // 3. Structural scan of live heap for 20-byte-stride FUObjectItem chunks
        //    (vtable[7] is VMProtected so the canonical chunks-ptr-array is
        //    unreachable without bytecode emulation). Accept any region with
        //    ≥500 consecutive valid items, concatenate all regions, cap at
        //    max_elements, and store as a flat UObject* list.
        // Patch 20260428: switched to CANONICAL chunk walker via the
        // chunks_manager pipeline (live-RE'd 2026-04-29 from sub_398180,
        // GC_GatherUnreachable_20260428). +0x38 is misleading (= 70592 NumActive
        // counter only); the TRUE total is encrypted at chunks_manager+0x14:
        //   total = ROL32(*(u32*)(chunks_mgr+0x14) ^ 0xC88F6121, 17) ^ 0x4CF4AED0
        // The chunk_table base is decrypted from chunks_manager+0xB0 via
        // vtable[5] of chunks_manager+0x80:
        //   ROL32(blob, 9) → PSHUFLW(0x39) → ROL32(1) → XOR(broadcast(PEB+0xAD77D882))
        // Then standard IndexToObject:
        //   chunk_idx = idx>>16; slot_idx = idx&0xFFFF
        //   chunk_ptr = chunk_table[chunk_idx]   (each chunk has 8B header at -8)
        //   item_ptr  = chunk_ptr + 20*slot_idx
        // Recovers ~277K UObjects (vs ~90K via structural scan), eliminating
        // the 65K-slot chunk-0 coverage gap and missing 8K UFunctions / 1K UEnums /
        // 366 UPackages from previous structural-scan output.
        bool InitPatch20260428() {
            uint64_t base = m_base + ArcDecrypt::RVA_GOBJECT_ARRAY_BASE;

            // Try canonical chunk walker first. Falls through to structural
            // scan on failure (e.g. game in early init before chunks_manager
            // is allocated, or PEB not yet readable).
            std::vector<uint64_t> objects;
            int32_t max_elements = 0;
            bool canonical_ok = CanonicalChunkWalk20260428(objects, max_elements);

            if (!canonical_ok) {
                std::printf("[p28] canonical chunk walk failed, falling back to structural scan\n");

                uint8_t StructBuf[0x180] = {};
                if (!m_reader.Read(base, StructBuf, sizeof(StructBuf))) {
                    std::printf("[p28] failed to read GUObjectArray @ 0x%llX\n",
                        (unsigned long long)base);
                    return false;
                }
                uint32_t BestNm = 0;
                uint32_t BestOff = 0;
                for (uint32_t Off = 0x20; Off + 4 <= sizeof(StructBuf); Off += 4) {
                    uint32_t V = 0;
                    std::memcpy(&V, StructBuf + Off, 4);
                    if (V >= 10000 && V <= 2'000'000 && V > BestNm) {
                        BestNm = V;
                        BestOff = Off;
                    }
                }
                if (!BestNm) {
                    std::printf("[p28] no plausible NumElements in +0x20..+0x17C\n");
                    return false;
                }
                max_elements = static_cast<int32_t>(BestNm);
                std::printf("[p28] NumElements (plain @ +0x%X, fallback) = %d\n",
                    BestOff, max_elements);

                if (!StructuralScanFUObjectItems(max_elements, objects)) {
                    std::printf("[p28] structural chunk scan failed\n");
                    return false;
                }
                std::printf("[p28] structural scan collected %zu UObject pointers\n",
                    objects.size());
                if (objects.size() < 1000) return false;
            } else {
                std::printf("[p28] canonical chunk walk: %zu UObjects (NumElements=%d)\n",
                    objects.size(), max_elements);
            }

            // Direct vtable scan recovers UObjects allocated in heap arenas
            // that aren't tracked by the FUObjectItem array (UScriptStruct +
            // UClass-of-UScriptStruct + UEnum + UFunction). Each adds a few
            // thousand objects to the seed set; downstream classification then
            // routes them through Path A / Pass-3 emit.
            // Populate the known-metaclass-vtable set used by ScanByVtable's
            // neighbor check. Verified live (agent vtable distribution sweep,
            // 2026-04-28/29). Per-kind instance counts and verified strides:
            //   UScriptStruct  5779  stride 0x130
            //   UClass         4222  stride 0x300
            //   UFunction      21802 stride 0x200
            //   UEnum          855   stride 0x130
            //   UPackage       (universe ~13K, mostly false hits)
            //   BPGC           747   stride 0x490
            //   WBPGC          16    stride 0x5D0
            //   SMBPGC         31    stride 0x490
            //   AnimBPGC       6     stride 0x7F0
            //   ASClass        2986  stride 0x340
            //   ASStruct       1136  stride 0x150
            // CL-1177146 vtable map — live-verified 2026-04-30 by reading
            // the +0x00 pointer of known-name objects. 20260428 RVAs all hit
            // +0 on this patch — the engine type-pool relocated en masse with
            // the patch CRT shift. Probe targets used:
            //   PostProcessSettings/Vector/Rotator      → 0xAD9DC20  UScriptStruct
            //   ABBHighCompressedVectorMixinLibrary etc → 0xAD9E500  UClass (native)
            //   ReceiveTick/ReceiveBeginPlay/GetActorLocation → 0xAD9EA70 UFunction
            //   ETeleportType/EAttachmentRule/EAICombatPhase  → 0xADA1140 UEnum
            //   /Script/EngineMessages                   → 0xADBC9A0 UPackage
            //   BP_Placement_Deployable_SoundTrap_C etc  → 0xB5653C0 BPGC
            //   WBP_VignetteContainer_C etc              → 0xB35B400 WBPGC
            //   ABP_Master_C, ABP_MainLayer_C            → 0xB512510 AnimBPGC
            //   SK_WorkshopStation_RecycleStation_01_C   → 0xB7BBCF0 SMBPGC
            //   PowerComponent/AIBSMEncounterModifierTransition → 0xB8ED140 ASClass
            //   ASStruct LevelSequenceListEntry etc      → 0xB8F6920 ASStruct
            //   AS-bound Tick (MainMenuCarouselWidget)   → 0xB8EDA70 ASFunction-A
            //   AS-bound Destruct                        → 0xB8EDEC0 ASFunction-B
            //
            // CL-1177146+ — these RVAs are auto-discovered at runtime via
            // AutoDiscovery::DiscoverEngineVTables (called from main.cpp before
            // this method). When the discovered map is valid, it overrides the
            // hardcoded list below — patch-resilient. The hardcoded values are
            // only the fallback for first-run-on-stale-patch.
            const auto& Disc = AutoDiscovery::g_DiscoveredVTables;
            const bool UseDiscovered = Disc.Valid();

            auto AddIf = [&](std::unordered_set<uint64_t>& Set, uint64_t Rva) {
                if (Rva) Set.insert(m_base + Rva);
            };
            auto AddTargetIf = [](std::vector<VtableScanTarget>& Targets,
                                  uint64_t Va, uint32_t Stride) {
                if (Va && Stride) Targets.push_back({Va, Stride});
            };

            std::vector<VtableScanTarget> vt_targets;
            m_knownTypeVtables.clear();

            // Compile-time CL-1177146/CL-1177678 baseline — fallback ONLY for
            // kinds Phase 1 missed. Stale RVAs from older patches generate
            // +0-hit log noise and steal scan budget from live vtables, so
            // when auto-discovery has a live RVA for a kind we skip every
            // compile-time entry tagged with that kind.
            enum VtKind {
                KIND_ScriptStruct, KIND_Class, KIND_Function, KIND_Enum,
                KIND_Package, KIND_BPGC, KIND_WBPGC, KIND_AnimBPGC,
                KIND_SMBPGC, KIND_ASClass, KIND_ASStruct, KIND_ASFunction
            };
            auto KindName = [](VtKind k) -> const char* {
                switch (k) {
                    case KIND_ScriptStruct: return "ScriptStruct";
                    case KIND_Class:        return "Class";
                    case KIND_Function:     return "Function";
                    case KIND_Enum:         return "Enum";
                    case KIND_Package:      return "Package";
                    case KIND_BPGC:         return "BPGC";
                    case KIND_WBPGC:        return "WBPGC";
                    case KIND_AnimBPGC:     return "AnimBPGC";
                    case KIND_SMBPGC:       return "SMBPGC";
                    case KIND_ASClass:      return "ASClass";
                    case KIND_ASStruct:     return "ASStruct";
                    case KIND_ASFunction:   return "ASFunction";
                }
                return "?";
            };
            struct Vt { uint64_t Rva; uint32_t Stride; VtKind Kind; const char* Tag; };
            static constexpr Vt CompileTime[] = {
                { 0xAD9DC20, 0x130, KIND_ScriptStruct, "CL-1177146" },
                { 0xAD9E500, 0x300, KIND_Class,        "CL-1177146" },
                { 0xAD9EA70, 0x200, KIND_Function,     "CL-1177146" },
                { 0xADA1140, 0x130, KIND_Enum,         "CL-1177146" },
                { 0xADBC9A0, 0x000, KIND_Package,      "CL-1177146" },
                { 0xB5653C0, 0x490, KIND_BPGC,         "CL-1177146" },
                { 0xB35B400, 0x5D0, KIND_WBPGC,        "CL-1177146" },
                { 0xB512510, 0x7F0, KIND_AnimBPGC,     "CL-1177146" },
                { 0xB7BBCF0, 0x490, KIND_SMBPGC,       "CL-1177146" },
                { 0xB8ED140, 0x340, KIND_ASClass,      "CL-1177146" },
                { 0xB8F6920, 0x150, KIND_ASStruct,     "CL-1177146" },
                { 0xB8EDA70, 0x200, KIND_ASFunction,   "CL-1177146" },
                { 0xB8EDEC0, 0x200, KIND_ASFunction,   "CL-1177146" },
                { 0xADF4820, 0x130, KIND_ScriptStruct, "CL-1177678" },
                { 0xB63A840, 0x300, KIND_Class,        "CL-1177678" },
                { 0xB940DC0, 0x200, KIND_Function,     "CL-1177678" },
                { 0xADF7AC0, 0x130, KIND_Enum,         "CL-1177678" },
                { 0xAE13030, 0x000, KIND_Package,      "CL-1177678" },
                { 0xB583B90, 0x490, KIND_BPGC,         "CL-1177678" },
                { 0xB3AF490, 0x5D0, KIND_WBPGC,        "CL-1177678" },
                { 0xBECF7F0, 0x7F0, KIND_AnimBPGC,     "CL-1177678" },
            };
            auto KindCovered = [&](VtKind k) -> bool {
                if (!UseDiscovered) return false;
                switch (k) {
                    case KIND_ScriptStruct: return Disc.ScriptStructRVA != 0;
                    case KIND_Class:        return Disc.ClassNativeRVA  != 0;
                    case KIND_Function:     return Disc.FunctionRVA     != 0;
                    case KIND_Enum:         return Disc.EnumRVA         != 0;
                    case KIND_Package:      return Disc.PackageRVA      != 0;
                    case KIND_BPGC:         return Disc.BPGCRVA         != 0;
                    case KIND_WBPGC:        return Disc.WBPGCRVA        != 0;
                    case KIND_AnimBPGC:     return Disc.AnimBPGCRVA     != 0;
                    case KIND_SMBPGC:       return Disc.SMBPGCRVA       != 0;
                    case KIND_ASClass:      return Disc.ASClassRVA      != 0;
                    case KIND_ASStruct:     return Disc.ASStructRVA     != 0;
                    case KIND_ASFunction:   return !Disc.ASFunctionRVAs.empty();
                }
                return false;
            };

            // Phase 1 entries FIRST — these are live, per-session RVAs.
            if (UseDiscovered) {
                std::printf("[p28] auto-discovered vtable map takes priority\n");
                auto AddDisc = [&](VtKind k, uint64_t Rva, uint32_t Stride) {
                    if (!Rva) return;
                    AddIf(m_knownTypeVtables, Rva);
                    AddTargetIf(vt_targets, m_base + Rva, Stride);
                    std::printf("[p28]   [autodisc] %-12s RVA=0x%llX stride=0x%X\n",
                        KindName(k), (unsigned long long)Rva, Stride);
                };
                AddDisc(KIND_ScriptStruct, Disc.ScriptStructRVA, Disc.ScriptStructStride);
                AddDisc(KIND_Class,        Disc.ClassNativeRVA,  Disc.ClassNativeStride);
                AddDisc(KIND_Function,     Disc.FunctionRVA,     Disc.FunctionStride);
                AddDisc(KIND_Enum,         Disc.EnumRVA,         Disc.EnumStride);
                AddDisc(KIND_Package,      Disc.PackageRVA,      0);
                AddDisc(KIND_BPGC,         Disc.BPGCRVA,         Disc.BPGCStride);
                AddDisc(KIND_WBPGC,        Disc.WBPGCRVA,        Disc.WBPGCStride);
                AddDisc(KIND_AnimBPGC,     Disc.AnimBPGCRVA,     Disc.AnimBPGCStride);
                AddDisc(KIND_SMBPGC,       Disc.SMBPGCRVA,       Disc.SMBPGCStride);
                AddDisc(KIND_ASClass,      Disc.ASClassRVA,      Disc.ASClassStride);
                AddDisc(KIND_ASStruct,     Disc.ASStructRVA,     Disc.ASStructStride);
                for (uint64_t Rva : Disc.ASFunctionRVAs)
                    AddDisc(KIND_ASFunction, Rva, Disc.ASFunctionStride);
            } else {
                std::printf("[p28] auto-discovery unavailable; compile-time vtable list only\n");
            }

            // Compile-time fallback ONLY for kinds Phase 1 didn't cover.
            for (const auto& v : CompileTime) {
                if (KindCovered(v.Kind)) continue;
                AddIf(m_knownTypeVtables, v.Rva);
                AddTargetIf(vt_targets, m_base + v.Rva, v.Stride);
                std::printf("[p28]   [fallback %s] %-12s RVA=0x%llX stride=0x%X\n",
                    v.Tag, KindName(v.Kind), (unsigned long long)v.Rva, v.Stride);
            }

            size_t pre = objects.size();
            ScanByVtables(vt_targets, objects);
            std::printf("[p28] vtable scan added %zu UObject pointers (total %zu)\n",
                objects.size() - pre, objects.size());

            m_arrayBase = base;
            m_numElements = max_elements;
            return InitWithSeedObjects(std::move(objects));
        }

        // The set of all known metaclass vtables — used for neighbor validation
        // in ScanByVtable. UScriptStructs and UEnums cluster in mixed arenas
        // so a strict same-vtable neighbor check rejects too many real hits;
        // accepting any known metaclass vtable as the neighbor is sufficient
        // to suppress incidental data-as-pointer false positives.
        std::unordered_set<uint64_t> m_knownTypeVtables;

        struct VtableScanTarget {
            uint64_t target_vt;
            uint32_t neighbor_stride;
        };

        // Scan all rw- heap regions (from /proc/<pid>/maps) once, matching
        // every requested vtable in a single pass. For each hit, accept it
        // if a neighbor at ±neighbor_stride holds ANY known metaclass vtable
        // (suppresses lone vtable-as-data false positives). Neighbor reads
        // are served from the in-memory chunk buffer when the neighbor lives
        // in the current window — only cross-chunk edges fall back to a live
        // read. This avoids the previous N-targets × full-heap re-scan and
        // the per-hit small-read storm that stalled the game's mmap_lock.
        void ScanByVtables(const std::vector<VtableScanTarget>& targets,
                           std::vector<uint64_t>& out_objects) {
            if (m_pid <= 0 || targets.empty()) return;

            std::unordered_map<uint64_t, size_t> vt_to_idx;
            vt_to_idx.reserve(targets.size() * 2);
            for (size_t i = 0; i < targets.size(); ++i) {
                if (targets[i].target_vt) vt_to_idx.emplace(targets[i].target_vt, i);
            }
            if (vt_to_idx.empty()) return;

            std::vector<Region> ranges;
            ranges.reserve(64);
            EnumerateRwHeapRegions(0x10000ULL, 0xC800000ULL, ranges);

            std::unordered_set<uint64_t> dedup(out_objects.begin(), out_objects.end());
            std::vector<size_t> per_target_hits(targets.size(), 0);

            // 4 MB chunks — 8 MB caused short-read failures on /dev/memreader.
            const uint64_t CHUNK = 0x400000ULL;
            std::vector<uint8_t> buf(CHUNK);

            for (const auto& rg : ranges) {
                for (uint64_t base_addr = rg.lo; base_addr < rg.hi; base_addr += CHUNK) {
                    uint64_t want = std::min<uint64_t>(CHUNK, rg.hi - base_addr);
                    if (!m_reader.Read(base_addr, buf.data(), want)) continue;
                    const uint8_t* p = buf.data();

                    // 8-byte aligned (UObject allocations are 0x10-aligned;
                    // vtable always lives at +0x00 with 8-byte alignment).
                    for (size_t off = 0; off + 8 <= want; off += 8) {
                        uint64_t v;
                        std::memcpy(&v, p + off, 8);
                        auto it = vt_to_idx.find(v);
                        if (it == vt_to_idx.end()) continue;

                        uint64_t cand = base_addr + off;
                        uint32_t stride = targets[it->second].neighbor_stride;

                        auto neighbor_known = [&](uint64_t addr) -> bool {
                            uint64_t vt_n = 0;
                            if (addr >= base_addr && addr + 8 <= base_addr + want) {
                                std::memcpy(&vt_n, p + (addr - base_addr), 8);
                            } else if (!m_reader.Read(addr, &vt_n, 8)) {
                                return false;
                            }
                            return m_knownTypeVtables.count(vt_n) > 0;
                        };
                        bool ok = neighbor_known(cand + stride);
                        if (!ok && cand >= stride) ok = neighbor_known(cand - stride);
                        if (!ok) continue;

                        if (dedup.insert(cand).second) {
                            out_objects.push_back(cand);
                            ++per_target_hits[it->second];
                        }
                    }
                }
            }

            for (size_t i = 0; i < targets.size(); ++i) {
                std::printf("[p28] ScanByVtable(0x%llX, stride=0x%x): +%zu hits\n",
                    (unsigned long long)targets[i].target_vt,
                    targets[i].neighbor_stride,
                    per_target_hits[i]);
            }
        }

        bool InitPatch20260421() {
            using namespace ArcDecrypt::Patch20260421;

            uint8_t enc[16] = {}, mask[8] = {};
            uint64_t xor_key = 0;
            if (!m_reader.Read(m_base + RVA_GUOBJECT_ARRAY_NEW, enc, 16)) {
                std::printf("[p21] read GUObjectArray@0x%llX failed\n",
                    (unsigned long long)(m_base + RVA_GUOBJECT_ARRAY_NEW));
                return false;
            }
            if (!m_reader.Read(m_base + RVA_GOBJ_PSHUFB_MASK, mask, 8)) return false;
            if (!m_reader.Read(m_base + RVA_GOBJ_MAX_XOR_KEY, &xor_key, 8)) return false;

            uint64_t chunks_mgr = DecryptGObjChunksManager(enc, mask);
            if (chunks_mgr < 0x10000ULL || chunks_mgr >= 0x800000000000ULL) {
                std::printf("[p21] chunks_manager decrypt gave implausible 0x%llX\n",
                    (unsigned long long)chunks_mgr);
                return false;
            }

            uint8_t max_enc[16] = {};
            if (!m_reader.Read(chunks_mgr + GOBJ_MANAGER_MAX_OFFSET, max_enc, 16)) {
                std::printf("[p21] read chunks_mgr+0x70 failed (chunks_mgr=0x%llX)\n",
                    (unsigned long long)chunks_mgr);
                return false;
            }
            int32_t max_elements = DecryptGObjMaxElements(max_enc, xor_key);
            if (max_elements < 1000 || max_elements > 2000000) {
                std::printf("[p21] max_elements=%d out of range — decrypt constants drifted?\n",
                    max_elements);
                return false;
            }
            std::printf("[p21] chunks_manager=0x%llX  max_elements=%d\n",
                (unsigned long long)chunks_mgr, max_elements);

            std::vector<uint64_t> objects;
            if (!StructuralScanFUObjectItems(max_elements, objects)) {
                std::printf("[p21] structural chunk scan failed\n");
                return false;
            }

            std::printf("[p21] structural scan collected %zu UObject pointers\n",
                objects.size());
            if (objects.size() < 1000) return false;

            m_arrayBase = chunks_mgr;
            return InitWithSeedObjects(std::move(objects));
        }

        // ── Structural heap scan for FUObjectItem chunks ─────────────────
        // Sweeps mapped rw- regions for runs of 20-byte entries whose +0
        // points to a valid UObject (first qword is a module-range vtable).
        // Runs two passes and unions the results:
        //   Pass A (MIN_RUN=500, MAX_GAP=0): reliable UObject chunks; no
        //     gap tolerance so noise fragments don't chain together.
        //   Pass B (MIN_RUN=32,  MAX_GAP=64): picks up the tiny-chunk case
        //     where engine metaclasses ("Class", "ScriptStruct", ...) live;
        //     filtered after the fact against max_elements so noise can't
        //     dominate.
        bool StructuralScanFUObjectItems(int32_t max_elements,
                                         std::vector<uint64_t>& out_objects) {
            std::unordered_set<uint64_t> seen;
            ScanPass(max_elements, seen, out_objects, /*MIN_RUN=*/500, /*MAX_GAP=*/0);
            size_t after_a = out_objects.size();
            // Pass B needs MAX_GAP>0 to find the small metaclass chunks (Class,
            // ScriptStruct, Enum). Noise is now filtered in ScanPass emission
            // via vtable re-validation — so gap tolerance is safe here.
            ScanPass(max_elements, seen, out_objects, /*MIN_RUN=*/32,  /*MAX_GAP=*/64);
            std::printf("[p21] scan pass A: %zu objs, pass B added %zu (total %zu)\n",
                after_a, out_objects.size() - after_a, out_objects.size());
            return !out_objects.empty();
        }

        void ScanPass(int32_t max_elements,
                      std::unordered_set<uint64_t>& seen,
                      std::vector<uint64_t>& out_objects,
                      uint32_t MIN_RUN, uint32_t MAX_GAP) {
            const uint32_t STRIDE = ArcDecrypt::Patch20260421::FUOBJECTITEM_STRIDE;
            const uint64_t vt_lo = m_base + 0x1000;
            const uint64_t vt_hi = m_base + 0x10000000ULL;

            auto is_heap = [](uint64_t p) {
                return p >= 0x100000ULL && p < 0x800000000000ULL;
            };
            auto is_vtable = [&](uint64_t p) {
                return p >= vt_lo && p < vt_hi;
            };

            // Resolve heap map from /proc; fall back to a wide numeric sweep.
            std::vector<Region> ranges;
            EnumerateRwHeapRegions(0x100000ULL, ~0ULL, ranges);
            if (ranges.empty()) {
                ranges.push_back({0x10000000ULL,  0x80000000ULL});
                ranges.push_back({0x100000000ULL, 0x400000000ULL});
            }

            // 4MB scan window: 64× fewer process_vm_readv calls for the
            // bulk page reads vs the old 64KB window. The per-slot vtable
            // check inside the inner loop stays — dropping it for speed
            // collapsed counts (Pass A's MAX_GAP=0 splits real chunks at
            // null slots; without vtable filtering, runs are formed on
            // noise heap-pointer arrays instead of real FUObjectItem chunks).
            const uint64_t WIN = 0x400000ULL;
            std::vector<uint8_t> buf(WIN);
            uint64_t cur_start = 0;
            uint32_t cur_count = 0;
            uint32_t cur_gap   = 0;     // consecutive null/bad items
            std::vector<uint64_t> run_starts;
            std::vector<uint32_t> run_counts;

            auto flush = [&]() {
                if (cur_count >= MIN_RUN) {
                    run_starts.push_back(cur_start);
                    run_counts.push_back(cur_count);
                }
                cur_start = 0;
                cur_count = 0;
                cur_gap = 0;
            };

            for (const auto& rg : ranges) {
                for (uint64_t page = rg.lo; page < rg.hi; page += WIN) {
                    // Clamp to the region tail so regions smaller than WIN
                    // (and the final partial chunk of any region) still get
                    // scanned. The previous `page + WIN <= rg.hi` loop
                    // condition skipped entire 1-4MB heap regions where
                    // metaclass chunks (UClass arrays etc.) live.
                    uint64_t this_win = (rg.hi - page < WIN) ? (rg.hi - page) : WIN;
                    if (!m_reader.Read(page, buf.data(), this_win)) { flush(); continue; }
                    size_t start_off = 0;
                    if (cur_count && (page % STRIDE)) {
                        start_off = (STRIDE - (page - cur_start) % STRIDE) % STRIDE;
                    }
                    for (size_t off = start_off; off + STRIDE <= this_win; off += STRIDE) {
                        uint64_t obj_ptr = 0;
                        std::memcpy(&obj_ptr, buf.data() + off, 8);
                        bool ok = is_heap(obj_ptr);
                        if (ok) {
                            uint64_t vt = 0;
                            ok = m_reader.Read(obj_ptr, &vt, 8) && is_vtable(vt);
                        }
                        if (!ok) {
                            if (cur_count == 0) continue;   // not in a run
                            if (++cur_gap > MAX_GAP) { flush(); }
                            else { cur_count++; }            // count the null slot in the run
                            continue;
                        }
                        cur_gap = 0;
                        if (cur_count == 0) cur_start = page + off;
                        cur_count++;
                    }
                }
                flush();
            }

            if (run_starts.empty()) return;

            // Sort runs by size desc — the actual chunks dominate, tiny
            // lookalike runs (heap fragments with occasional vtable ptrs)
            // contribute little.
            std::vector<size_t> idx(run_starts.size());
            for (size_t i = 0; i < idx.size(); ++i) idx[i] = i;
            std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
                return run_counts[a] > run_counts[b];
            });

            const size_t cap = static_cast<size_t>(max_elements) + 256;
            out_objects.reserve(cap);
            for (size_t i : idx) {
                uint64_t start = run_starts[i];
                uint32_t count = run_counts[i];
                for (uint32_t k = 0; k < count && out_objects.size() < cap; ++k) {
                    uint64_t item = start + (uint64_t)STRIDE * k;
                    uint64_t obj = 0;
                    if (!m_reader.Read(item, &obj, 8) || !obj) continue;
                    // Re-validate the object's vtable here — the run may span
                    // gap slots whose obj_ptr isn't actually a UObject. Cheap
                    // check and tosses the bulk of heap-noise false-positives.
                    uint64_t vt = 0;
                    if (!m_reader.Read(obj, &vt, 8) || !is_vtable(vt)) continue;
                    if (!seen.insert(obj).second) continue;  // dedup across passes
                    out_objects.push_back(obj);
                }
                if (out_objects.size() >= cap) break;
            }
            std::printf("[p21] scan (MIN_RUN=%u,MAX_GAP=%u): %zu runs (largest=%u); total %zu objs\n",
                MIN_RUN, MAX_GAP, run_starts.size(),
                run_starts.empty() ? 0 : run_counts[idx[0]], out_objects.size());
        }

        // ── Validate SIMD tables are populated (not all zeros) ───────────
        bool ValidateSIMDTables() {
            auto isAllZero = [](const uint8_t* buf, int len) {
                for (int i = 0; i < len; ++i)
                    if (buf[i] != 0) return false;
                return true;
            };
            if (isAllZero(m_objXorKey, 16) && isAllZero(m_elemMaskA, 16)) {
                std::printf("[dbg] ObjectArray SIMD tables are all zeros\n");
                return false;
            }
            return true;
        }

        // ── Decrypt GUObjectArray pointer (patch 20260414) ───────────────
        // Pipeline: ROL32(20) → XOR(key) → ROL16(12) → extract lo64 = heap ptr
        //
        // NOTE: every intermediate stage is dumped to stdout so the next
        // session can diagnose where the decrypt diverges when live runs
        // produce garbage (e.g. base=0x40071006B4569106 count=0).
        uint64_t ComputeObjectArrayIntermediate() {
            // Read encrypted xmmword from struct + GOBJ_ENCRYPTED_OFF
            alignas(16) uint8_t data[16] = {};
            uint64_t enc_addr = m_base + ArcDecrypt::RVA_GOBJECT_ARRAY_BASE + ArcDecrypt::GOBJ_ENCRYPTED_OFF;
            if (!m_reader.Read(enc_addr, data, 16)) {
                std::printf("[decrypt][objarr] FAILED to read encrypted qword @ 0x%llX\n",
                    (unsigned long long)enc_addr);
                return 0;
            }

            auto hex16 = [](const __m128i& v) -> std::string {
                alignas(16) uint8_t buf[16];
                _mm_store_si128((__m128i*)buf, v);
                return FormatHex(buf, 16);
            };

            // Pipeline: ROL32(20) → XOR(key) → ROL16(12)
            __m128i v = _mm_load_si128((const __m128i*)data);
            // Step 1: ROL32(20) = PSLLD(20) | PSRLD(12)
            __m128i rol = _mm_or_si128(
                _mm_slli_epi32(v, ArcDecrypt::OBJARRAY_ROL32),
                _mm_srli_epi32(v, 32 - ArcDecrypt::OBJARRAY_ROL32));
            // Step 2: XOR with key
            __m128i xored = _mm_xor_si128(rol, _mm_load_si128((const __m128i*)m_objXorKey));
            // Step 3: ROL16(12) = PSLLW(12) | PSRLW(4)
            __m128i result = _mm_or_si128(
                _mm_slli_epi16(xored, ArcDecrypt::OBJARRAY_ROL16),
                _mm_srli_epi16(xored, 16 - ArcDecrypt::OBJARRAY_ROL16));

            std::printf("[decrypt][objarr] enc_addr = 0x%llX (base+0x%llX)\n",
                (unsigned long long)enc_addr,
                (unsigned long long)(ArcDecrypt::RVA_GOBJECT_ARRAY_BASE + ArcDecrypt::GOBJ_ENCRYPTED_OFF));
            std::printf("[decrypt][objarr] xorkey  = %s\n", FormatHex(m_objXorKey, 16).c_str());
            std::printf("[decrypt][objarr] enc     = %s\n", hex16(v).c_str());
            std::printf("[decrypt][objarr] rol32   = %s  (shift=%d)\n",
                hex16(rol).c_str(), ArcDecrypt::OBJARRAY_ROL32);
            std::printf("[decrypt][objarr] xored   = %s\n", hex16(xored).c_str());
            std::printf("[decrypt][objarr] rol16   = %s  (shift=%d)\n",
                hex16(result).c_str(), ArcDecrypt::OBJARRAY_ROL16);

            uint64_t r;
            _mm_storel_epi64((__m128i*)&r, result);
            std::printf("[decrypt][objarr] lo64    = 0x%016llX\n", (unsigned long long)r);
            return r;
        }

        // ── Decrypt FChunkedFixedUObjectArray pointer ────────────────────
        uint64_t DecryptObjectArray() {
            return ComputeObjectArrayIntermediate();
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
                if (!m_reader.Read(m_base + ArcDecrypt::RVA_GOBJECT_ARRAY_BASE + off, &candidate_xor, 8))
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

        // ── Decrypt NumElements (patch 20260414) ─────────────────────────
        // Read 8 bytes at base+0x50, AND/ANDNOT blend → XOR → ROL16(12) → PSHUFB(0x05040607) → extract i32
        //
        // Always-on diagnostics: dump raw bytes + every intermediate so we
        // can see at a glance whether the masks, XOR key, or base address
        // are wrong.
        int32_t DecryptNumElements(uint64_t array_base) {
            if (!array_base) return 0;

            alignas(16) uint8_t data[16] = {};
            uint64_t read_addr = array_base + 5 * 16;
            if (!m_reader.Read(read_addr, data, 16)) {
                std::printf("[decrypt][count] FAILED to read @ 0x%llX\n",
                    (unsigned long long)read_addr);
                return 0;
            }

            auto hex16 = [](const __m128i& v) -> std::string {
                alignas(16) uint8_t buf[16];
                _mm_store_si128((__m128i*)buf, v);
                return FormatHex(buf, 16);
            };

            __m128i v = _mm_loadl_epi64((const __m128i*)data);
            __m128i mA = _mm_load_si128((const __m128i*)m_elemMaskA);
            __m128i mB = _mm_load_si128((const __m128i*)m_elemMaskB);
            __m128i xk = _mm_loadl_epi64((const __m128i*)m_elemXorKey);
            __m128i bl = _mm_or_si128(_mm_and_si128(v, mB), _mm_andnot_si128(v, mA));
            __m128i xo = _mm_xor_si128(bl, xk);
            __m128i r16 = _mm_or_si128(_mm_slli_epi16(xo, 12), _mm_srli_epi16(xo, 4));
            __m128i final_v = _mm_shuffle_epi8(r16, _mm_cvtsi32_si128(0x05040607));
            int32_t result = _mm_cvtsi128_si32(final_v);

            std::printf("[decrypt][count] read @ 0x%llX = %s\n",
                (unsigned long long)read_addr, FormatHex(data, 16).c_str());
            std::printf("[decrypt][count] maskA  = %s\n", FormatHex(m_elemMaskA, 16).c_str());
            std::printf("[decrypt][count] maskB  = %s\n", FormatHex(m_elemMaskB, 16).c_str());
            std::printf("[decrypt][count] xorKey = %s\n", FormatHex(m_elemXorKey, 16).c_str());
            std::printf("[decrypt][count] v      = %s\n", hex16(v).c_str());
            std::printf("[decrypt][count] blend  = %s\n", hex16(bl).c_str());
            std::printf("[decrypt][count] xored  = %s\n", hex16(xo).c_str());
            std::printf("[decrypt][count] rol16  = %s\n", hex16(r16).c_str());
            std::printf("[decrypt][count] pshufb = %s\n", hex16(final_v).c_str());
            std::printf("[decrypt][count] result = %d (0x%08X)\n", result, (uint32_t)result);

            return result;
        }

        // ── Self-test: dump all decrypt stages with current state ────────
        // Runs ComputeObjectArrayIntermediate (which already logs every
        // pipeline stage), then DecryptNumElements on the produced base.
        // Wired into Init() right before the "GObjectArray init failed"
        // bail-out so the diagnostic is always visible when decrypt fails.
        void SelfTestDecryptStages() {
            std::printf("\n[selftest] ==== Decrypt stage dump ====\n");
            std::printf("[selftest] module_base      = 0x%llX\n",
                (unsigned long long)m_base);
            std::printf("[selftest] RVA_GOBJECT_BASE = 0x%llX\n",
                (unsigned long long)ArcDecrypt::RVA_GOBJECT_ARRAY_BASE);
            std::printf("[selftest] GOBJ_ENC_OFF     = 0x%llX\n",
                (unsigned long long)ArcDecrypt::GOBJ_ENCRYPTED_OFF);
            std::printf("[selftest] OBJARRAY_ROL32   = %d\n", ArcDecrypt::OBJARRAY_ROL32);
            std::printf("[selftest] OBJARRAY_ROL16   = %d\n", ArcDecrypt::OBJARRAY_ROL16);
            std::printf("[selftest] item_stride      = %d (FUOBJECTITEM_SIZE=%u)\n",
                m_itemStride, FUOBJECTITEM_SIZE);

            // Dump ObjectArray pipeline
            uint64_t base_candidate = ComputeObjectArrayIntermediate();
            std::printf("[selftest] ObjectArray candidate base = 0x%016llX\n",
                (unsigned long long)base_candidate);

            // Dump NumElements pipeline against the candidate
            if (base_candidate) {
                int32_t n = DecryptNumElements(base_candidate);
                std::printf("[selftest] NumElements @ candidate = %d\n", n);
            } else {
                std::printf("[selftest] skipping NumElements (no candidate)\n");
            }
            std::printf("[selftest] ==== End dump ====\n\n");
        }

        // ── Find PEB address (Wine: search for ImageBaseAddress in low mem) ──
        // Validate a candidate PEB address by checking PEB_LDR_DATA.Length == 0x58.
        // Anti-cheat (EAC) zeroes PEB.ImageBaseAddress so we cannot use that field.
        bool IsPEBValid(uint64_t peb_addr) {
            uint64_t ldr = 0;
            if (!m_reader.Read(peb_addr + 0x18, &ldr, 8) || !ldr) return false;
            // Must be a canonical user-space address
            if (ldr < 0x10000ULL || ldr > 0x7FFFFFFFFFFFULL) return false;
            uint32_t ldr_len = 0;
            if (!m_reader.Read(ldr, &ldr_len, 4)) return false;
            return ldr_len == 0x58;
        }

        uint64_t FindPEB() {
            // Note: PEB.ImageBaseAddress is zeroed by anti-cheat; validate via PEB_LDR_DATA.Length.
            const uint64_t candidates[] = {
                0x7FFD0000, 0x7FFC0000, 0x7FFB0000, 0x7FFA0000,
                0x00060000, 0x00050000, 0x00040000, 0x00030000,
            };
            for (uint64_t addr : candidates) {
                if (IsPEBValid(addr)) return addr;
            }
            for (uint64_t addr = 0x7FF00000; addr < 0x7FFE0000; addr += 0x1000) {
                if (IsPEBValid(addr)) return addr;
            }
            for (uint64_t addr = 0x00010000; addr < 0x00200000; addr += 0x1000) {
                if (IsPEBValid(addr)) return addr;
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
                            int mod = (modrm >> 6) & 3;
                            int insn_end = off + 3;
                            if (mod == 3) {
                                // reg-reg
                                memcpy(xmm[reg], xmm[rm], 8); memset(xmm[reg]+8,0,8);
                            } else {
                                // Any memory form — treat as a load from input_data.
                                // Advance past disp8/disp32/SIB for correct IP.
                                bool has_sib = (rm == 4);
                                int sib_len = has_sib ? 1 : 0;
                                if      (mod == 0 && rm == 5) insn_end = off + 3 + 4;  // [rip+disp32]
                                else if (mod == 0)             insn_end = off + 3 + sib_len;
                                else if (mod == 1)             insn_end = off + 3 + sib_len + 1;
                                else if (mod == 2)             insn_end = off + 3 + sib_len + 4;
                                memcpy(xmm[reg], input_data, 8); memset(xmm[reg]+8,0,8);
                            }
                            ip = insn_end; continue;
                        }
                        // F3 0F 6F /r — movdqu xmm, [mem]/xmm
                        if (op2 == 0x6F) {
                            int mod = (modrm >> 6) & 3;
                            int insn_end = off + 3;
                            if (mod == 3) {
                                memcpy(xmm[reg], xmm[rm], 16);
                            } else {
                                bool has_sib = (rm == 4);
                                int sib_len = has_sib ? 1 : 0;
                                if      (mod == 0 && rm == 5) insn_end = off + 3 + 4;
                                else if (mod == 0)             insn_end = off + 3 + sib_len;
                                else if (mod == 1)             insn_end = off + 3 + sib_len + 1;
                                else if (mod == 2)             insn_end = off + 3 + sib_len + 4;
                                memcpy(xmm[reg], input_data, 16);
                            }
                            ip = insn_end; continue;
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
                        int mod = (modrm >> 6) & 3;
                        int insn_end = off + 3;
                        if (mod == 3) {
                            memcpy(xmm[reg&7], xmm[rm&7], 16);
                        } else if ((modrm & 0xC7) == 0x05) {
                            // [rip+disp32] — load from module memory
                            int32_t disp; memcpy(&disp, c+off+3, 4);
                            insn_end = off + 7;
                            m_reader.Read(func_addr + (off+7) + disp, xmm[reg&7], 16);
                        } else {
                            // Any GP-register memory form → input_data
                            int rm_field = modrm & 7;
                            bool has_sib = (rm_field == 4);
                            int sib_len = has_sib ? 1 : 0;
                            if      (mod == 0 && rm_field == 5) insn_end = off + 3 + 4;
                            else if (mod == 0)                  insn_end = off + 3 + sib_len;
                            else if (mod == 1)                  insn_end = off + 3 + sib_len + 1;
                            else if (mod == 2)                  insn_end = off + 3 + sib_len + 4;
                            memcpy(xmm[reg&7], input_data, 16);
                        }
                        ip = insn_end; continue;
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
                    // Handle reg-reg, [rip+disp32], and any [GPReg] / [GPReg+disp]
                    // memory form. Any memory load from a general-purpose
                    // register is treated as a load from `input_data` — the
                    // assumption is that the caller pointed that register at
                    // the encrypted struct block we're trying to decrypt.
                    // This fixes the class of bug where the real function
                    // reads encrypted bytes via `[rcx+N]` or `[rax]` etc.,
                    // which previously fell through as "unsupported" and
                    // left xmm0=0 → constant decrypt output regardless of
                    // which data offset the caller passed in.
                    if (off+2 < len) {
                        uint8_t modrm = c[off+2];
                        int dst = (modrm>>3)&7, src = modrm&7;
                        int mod = (modrm >> 6) & 3;
                        bool is_rr  = mod == 3;
                        bool is_rip = (modrm & 0xC7) == 0x05;

                        // Load src operand
                        alignas(16) uint8_t src_data[16] = {};
                        int next_ip = off + 3;
                        if (is_rr) {
                            memcpy(src_data, xmm[src], 16);
                        } else if (is_rip && off+6 < len) {
                            int32_t disp; memcpy(&disp, c+off+3, 4);
                            next_ip = off + 7;
                            m_reader.Read(func_addr + (off+7) + disp, src_data, 16);
                        } else if (op2 != 0x38 && op2 != 0x3A) {
                            // Memory form via a GP register: [reg], [reg+disp8],
                            // [reg+disp32], possibly with SIB (rm==4). Advance
                            // `next_ip` correctly, then feed `input_data`.
                            bool has_sib = (modrm & 7) == 4 && mod != 3;
                            int sib_len  = has_sib ? 1 : 0;
                            if      (mod == 0 && (modrm & 7) == 5) next_ip = off + 3 + 4;    // [rip+disp] handled above, but also [r13] (mod=0 rm=5) has disp32
                            else if (mod == 0) next_ip = off + 3 + sib_len;                   // [reg] or [reg+SIB]
                            else if (mod == 1) next_ip = off + 3 + sib_len + 1;               // +disp8
                            else if (mod == 2) next_ip = off + 3 + sib_len + 4;               // +disp32
                            if (next_ip > len) { ip++; continue; }
                            memcpy(src_data, input_data, 16);
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

        // ── Validate indirect chunk table candidate ─────────────────────
        bool ValidateChunkTableIndirect(uint64_t candidate, int stride) {
            if (candidate < 0x10000ULL || candidate > 0x7FFFFFFFFFFFULL)
                return false;
            if (candidate >= m_base && candidate < m_base + 0x10000000ULL)
                return false;

            int good = 0;
            int chunks_to_probe = (m_numElements > 65536) ? 2 : 1;
            for (int c = 0; c < chunks_to_probe; ++c) {
                uint64_t entry = 0;
                if (!m_reader.Read(candidate + 8ULL * c, &entry, 8))
                    continue;
                if (entry < 0x10000ULL || entry > 0x7FFFFFFFFFFFULL)
                    continue;
                if (entry >= m_base && entry < m_base + 0x10000000ULL)
                    continue;

                uint64_t chunk = 0;
                if (!m_reader.Read(entry, &chunk, 8))
                    continue;
                if (chunk < 0x10000ULL || chunk > 0x7FFFFFFFFFFFULL)
                    continue;
                if (chunk >= m_base && chunk < m_base + 0x10000000ULL)
                    continue;

                for (int i = 0; i < 64; ++i) {
                    uint64_t obj = 0;
                    if (!m_reader.Read(chunk + (uint64_t)stride * i + FUOBJECTITEM_OBJ, &obj, 8))
                        continue;
                    if (obj < 0x10000ULL || obj > 0x7FFFFFFFFFFFULL)
                        continue;
                    uint64_t vtbl = 0;
                    if (!m_reader.Read(obj, &vtbl, 8))
                        continue;
                    if (vtbl >= m_base && vtbl < m_base + 0x10000000ULL)
                        ++good;
                    if (good >= 6)
                        return true;
                }
            }

            return false;
        }

        // ── Direct ChunkPtr Decryption (patch 20260409, vtable[5]) ──────
        // Pipeline (from sub_1404A7F40):
        //   1. Load 8B from base+0xB0 → xmm0
        //   2. PSHUFLW(xmm0, 0x8D) → xmm1
        //   3. PXOR(xmm1, table@0x14ACB8690)
        //   4. ROL64(46): PSLLQ(0x2E) | PSRLQ(0x12)
        //   5. PEB key: (0xB2DA4299DB155ED3 ^ (0x0D7DC434 + PEB)) → broadcast → PXOR
        //   6. lo64 = chunk table pointer
        uint64_t DecryptChunkPtrDirect() {
            if (!m_arrayBase || !m_pebAddr) return 0;

            // Dynamic probe: read vtable[5] function and extract constants per-session
            uint64_t vt_ptr = 0;
            if (!m_reader.Read(m_arrayBase + 0x60, &vt_ptr, 8) || !vt_ptr) return 0;
            uint64_t fn_addr = 0;
            if (!m_reader.Read(vt_ptr + 40, &fn_addr, 8) || !fn_addr) return 0;

            uint8_t code[128] = {};
            if (!m_reader.Read(fn_addr, code, sizeof(code))) return 0;

            // Parse the function sequentially:
            // Pipeline variants:
            //  a) movq xmm0,[rdx] → PSHUFLW → [pre-PXOR] → ROL16 → PEB XOR
            //  b) movq xmm0,[rdx] → ROL16 → PSHUFLW → [pre-PXOR] → PEB XOR
            uint32_t peb_add = 0;
            uint64_t xor_const = 0;
            uint8_t pshuflw_imm = 0;
            int rot_right = 0, rot_left = 0;
            int rot_width = 0;   // 16, 32, or 64 — tracked alongside rot_left
            uint64_t prexor_addr = 0;
            // Record order of operations to apply them correctly
            enum StepType { STEP_NONE, STEP_PSHUFLW, STEP_ROL, STEP_PREXOR };
            StepType steps[8] = {};
            int step_count = 0;

            for (int i = 0; i < 100; i++) {
                if (code[i] == 0xB8 && i+14 <= 128 &&
                    code[i+5] == 0x65 && code[i+6] == 0x48 && code[i+7] == 0x03) {
                    peb_add = *(uint32_t*)(code + i + 1);
                }
                if (code[i] == 0x48 && code[i+1] == 0xB9) {
                    xor_const = *(uint64_t*)(code + i + 2);
                }
                if (code[i] == 0xF2 && code[i+1] == 0x0F && code[i+2] == 0x70) {
                    if (pshuflw_imm == 0) {
                        pshuflw_imm = code[i+4];
                        if (step_count < 8) steps[step_count++] = STEP_PSHUFLW;
                    }
                }
                // 66 0F 71 = word (16-bit), 66 0F 72 = dword (32-bit), 66 0F 73 = qword (64-bit)
                if (code[i] == 0x66 && code[i+1] == 0x0F &&
                    (code[i+2] == 0x71 || code[i+2] == 0x72 || code[i+2] == 0x73)) {
                    int w = (code[i+2] == 0x71) ? 16 : (code[i+2] == 0x72) ? 32 : 64;
                    uint8_t sub = code[i+3]; uint8_t imm = code[i+4];
                    // /2=psrl*, /6=psll* (reg-encoded in ModRM middle field)
                    if ((sub & 0xF8) == 0xD0 && !rot_right) {
                        rot_right = imm;
                        if (step_count < 8) steps[step_count++] = STEP_ROL;
                    }
                    if ((sub & 0xF8) == 0xF0 && !rot_left) {
                        rot_left = imm;
                        rot_width = w;
                    }
                }
                if (code[i] == 0x66 && code[i+1] == 0x0F && code[i+2] == 0xEF &&
                    (code[i+3] & 0xC7) == 0x05 && !prexor_addr) {
                    int32_t disp = *(int32_t*)(code + i + 4);
                    prexor_addr = fn_addr + i + 8 + disp;
                    if (step_count < 8) steps[step_count++] = STEP_PREXOR;
                }
                if (code[i] == 0xC3) break;  // ret
            }

            if (!peb_add || !rot_left) {
                std::printf("[!] Chunk probe failed: peb=0x%X xor=0x%llX rol=%d/%d w=%d pshuflw=0x%02X\n",
                    peb_add, (unsigned long long)xor_const, rot_left, rot_right, rot_width, pshuflw_imm);
                // Pattern parser failed (e.g. function uses PSLLD/PSLLQ instead of
                // PSLLW). Fall back to the full x86 emulator which understands all
                // three shift widths. Try several known encrypted-data offsets.
                int path_len = 128;
                for (int i = 4; i < 128; i++) if (code[i] == 0xC3) { path_len = i + 1; break; }

                static const int kDataOffs[] = {0x90, 0x30, 0x70, 0xB0};
                for (int doff : kDataOffs) {
                    alignas(16) uint8_t data[16] = {};
                    if (!m_reader.Read(m_arrayBase + (uint64_t)doff, data, 16))
                        continue;
                    uint64_t candidate = EmulateChunkPtrDecrypt(
                        code, path_len, data, m_pebAddr, fn_addr);
                    if (!candidate || candidate < 0x10000ULL || candidate > 0x7FFFFFFFFFFFULL)
                        continue;
                    if (ValidateChunkPtr(candidate)) {
                        std::printf("[+] ChunkPtr (emulator/data+0x%X) = 0x%llX\n",
                            doff, (unsigned long long)candidate);
                        return candidate;
                    }
                    // Indirect: candidate might be a struct containing the table
                    for (int off = 0; off <= 0x40; off += 8) {
                        uint64_t inner = 0;
                        if (!m_reader.Read(candidate + off, &inner, 8)) continue;
                        if (inner < 0x10000ULL || inner > 0x7FFFFFFFFFFFULL) continue;
                        if (ValidateChunkPtr(inner)) {
                            std::printf("[+] ChunkPtr (emulator/data+0x%X, indirect+0x%X) = 0x%llX\n",
                                doff, off, (unsigned long long)inner);
                            return inner;
                        }
                    }
                }
                return 0;
            }

            std::printf("[+] Chunk probe @ fn=0x%llX: PEB_ADD=0x%X XOR=0x%llX PSHUFLW=0x%02X ROL%d=%d prexor=0x%llX\n",
                (unsigned long long)fn_addr, peb_add, (unsigned long long)xor_const,
                pshuflw_imm, rot_width, rot_left, (unsigned long long)prexor_addr);

            alignas(16) uint8_t enc[16] = {};
            if (!m_reader.Read(m_arrayBase + 0x90, enc, 16)) return 0;

            __m128i v = _mm_loadl_epi64((const __m128i*)enc);

            // Apply steps in the order they appeared in the function
            for (int s = 0; s < step_count; s++) {
                if (steps[s] == STEP_PSHUFLW) {
                    alignas(16) uint16_t w_in[8], w_out[8];
                    _mm_store_si128((__m128i*)w_in, v);
                    w_out[0] = w_in[(pshuflw_imm >> 0) & 3];
                    w_out[1] = w_in[(pshuflw_imm >> 2) & 3];
                    w_out[2] = w_in[(pshuflw_imm >> 4) & 3];
                    w_out[3] = w_in[(pshuflw_imm >> 6) & 3];
                    for (int j = 4; j < 8; j++) w_out[j] = w_in[j];
                    v = _mm_load_si128((const __m128i*)w_out);
                }
                else if (steps[s] == STEP_ROL) {
                    if (rot_width == 16) {
                        v = _mm_or_si128(_mm_slli_epi16(v, rot_left),
                                         _mm_srli_epi16(v, rot_right));
                    } else if (rot_width == 32) {
                        v = _mm_or_si128(_mm_slli_epi32(v, rot_left),
                                         _mm_srli_epi32(v, rot_right));
                    } else if (rot_width == 64) {
                        v = _mm_or_si128(_mm_slli_epi64(v, rot_left),
                                         _mm_srli_epi64(v, rot_right));
                    }
                }
                else if (steps[s] == STEP_PREXOR && prexor_addr) {
                    alignas(16) uint8_t pxk[16] = {};
                    if (m_reader.Read(prexor_addr, pxk, 16))
                        v = _mm_xor_si128(v, _mm_load_si128((const __m128i*)pxk));
                }
            }

            // Final: PEB XOR (broadcast)
            uint64_t peb_val = static_cast<uint64_t>(peb_add) + m_pebAddr;
            uint64_t peb_key = peb_val ^ xor_const;  // xor_const may be 0
            __m128i k = _mm_set1_epi64x(static_cast<int64_t>(peb_key));
            __m128i result = _mm_xor_si128(k, v);

            uint64_t table_ptr;
            _mm_storel_epi64((__m128i*)&table_ptr, result);

            std::printf("[+] ChunkPtr vtable[5] decrypt: table=0x%llX (PEB=0x%llX)\n",
                (unsigned long long)table_ptr, (unsigned long long)m_pebAddr);

            // Validate: the table should contain pointers to chunk arrays
            if (table_ptr < 0x10000ULL || table_ptr > 0x7FFFFFFFFFFFULL)
                return 0;

            // Check if this is a direct chunk table (array of chunk pointers)
            if (ValidateChunkPtr(table_ptr))
                return table_ptr;

            // Try indirect: table_ptr might point to a struct with the actual chunk table
            for (int off = 0; off <= 0x40; off += 8) {
                uint64_t inner = 0;
                if (!m_reader.Read(table_ptr + off, &inner, 8)) continue;
                if (inner < 0x10000ULL || inner > 0x7FFFFFFFFFFFULL) continue;
                if (ValidateChunkPtr(inner)) {
                    std::printf("[+] Indirect chunk table at table+0x%X = 0x%llX\n",
                        off, (unsigned long long)inner);
                    return inner;
                }
            }

            return 0;

            /* Original code disabled:

            // Stage 1: decrypt manager pointer from array+0xE0
            alignas(16) uint8_t enc_mgr[16] = {};
            if (!m_reader.Read(m_arrayBase + CHUNKPTR_DATA_OFF, enc_mgr, 16))
                return 0;

            __m128i data = _mm_load_si128(reinterpret_cast<const __m128i*>(enc_mgr));
            __m128i rol_step = _mm_or_si128(
                _mm_slli_epi32(data, 21),
                _mm_srli_epi32(data, 11)
            );

            // Use m_shufMask as best-effort (TODO: confirm correct table for ChunkPtr)
            __m128i shuffled = _mm_shuffle_epi8(
                rol_step,
                _mm_load_si128(reinterpret_cast<const __m128i*>(m_shufMask)));
            uint64_t manager = _mm_cvtsi128_si64(shuffled) ^ ArcDecrypt::CHUNK_PTR_XOR_KEY;
            if (manager < 0x10000ULL || manager > 0x7FFFFFFFFFFFULL)
                return 0;

            // Stage 2: emulate vtable+56 transform on manager+0x30 block.
            alignas(16) uint8_t blk[16] = {};
            if (!m_reader.Read(manager + 0x30, blk, 16))
                return 0;

            alignas(16) uint8_t mask1[16] = {};
            alignas(16) uint8_t mask2[16] = {};
            if (!m_reader.Read(m_base + RVA_CHUNKPTR_V56_SHUF, mask1, 16)) return 0;
            if (!m_reader.Read(m_base + RVA_CHUNKPTR_V56_XOR,  mask2, 16)) return 0;

            __m128i s = _mm_shuffle_epi8(
                _mm_load_si128(reinterpret_cast<const __m128i*>(blk)),
                _mm_load_si128(reinterpret_cast<const __m128i*>(mask1)));
            __m128i x = _mm_xor_si128(s, _mm_load_si128(reinterpret_cast<const __m128i*>(mask2)));
            __m128i r = _mm_or_si128(_mm_srli_epi32(x, 3), _mm_slli_epi32(x, 29)); // ror32(3)

            uint64_t key64 = (m_pebAddr + 0xE5814B12ULL) ^ 0x99D23C9DF3E47D2DULL;
            __m128i k = _mm_set_epi64x((long long)key64, (long long)key64);
            __m128i out = _mm_xor_si128(r, k);
            uint64_t table = _mm_cvtsi128_si64(out);

            if (ValidateChunkTableIndirect(table, 16)) {
                m_chunkEntriesIndirect = true;
                m_itemStride = 16;
                std::printf("[+] Chunk table (v56) = 0x%llX (indirect, stride=16)\n",
                    (unsigned long long)table);
                return table;
            }

            if (ValidateChunkTableIndirect(table, 24)) {
                m_chunkEntriesIndirect = true;
                m_itemStride = 24;
                std::printf("[+] Chunk table (v56) = 0x%llX (indirect, stride=24)\n",
                    (unsigned long long)table);
                return table;
            }

            return 0;
            */ // end disabled DecryptChunkPtrDirect code
        }

        // ── ChunkPtr Decryption – vtable[4] ROL32 algorithm (patch 20260402) ──
        // Confirmed by live memory analysis: vtable[4]=0x14049C4D0 uses
        //   ROL32(23) per dword → PSHUFB(mask@RVA 0xAC6F950) → ROL32(13) → XOR key
        // where key = broadcast(PEB + 0x8974FAB4) as {lo32,hi32,lo32,hi32}.
        // Encrypted xmmword (lo64==hi64) is at GObjectArray+0x70.
        uint64_t DecryptChunkPtrV4() {
            if (!m_arrayBase || !m_pebAddr) return 0;

            alignas(16) uint8_t enc[16] = {};
            if (!m_reader.Read(m_arrayBase + 0x70, enc, 16))
                return 0;

            // PSHUFB mask lives in .rdata at RVA 0xAC6F950
            alignas(16) uint8_t shuf[16] = {};
            if (!m_reader.Read(m_base + 0x0AC6F950ULL, shuf, 16))
                return 0;

            uint64_t key64 = m_pebAddr + 0x8974FAB4ULL;

            __m128i v      = _mm_load_si128((const __m128i*)enc);
            __m128i rol23  = _mm_or_si128(_mm_slli_epi32(v, 23), _mm_srli_epi32(v, 9));
            __m128i shufv  = _mm_shuffle_epi8(rol23, _mm_load_si128((const __m128i*)shuf));
            __m128i rol13  = _mm_or_si128(_mm_slli_epi32(shufv, 13), _mm_srli_epi32(shufv, 19));
            // movq xmm0,rax + pshufd xmm0,xmm0,0x44  → {lo32,hi32,lo32,hi32}
            __m128i k      = _mm_shuffle_epi32(_mm_cvtsi64_si128((long long)key64), 0x44);
            __m128i result = _mm_xor_si128(k, rol13);

            uint64_t out = 0;
            _mm_storel_epi64((__m128i*)&out, result);
            return out;
        }

        // ── Decrypt ChunkPtr via SIMD emulation ─────────────────────────
        uint64_t DecryptChunkPtr() {
            // Primary: vtable[4] ROL32 algorithm (verified patch 20260402)
            uint64_t v4 = DecryptChunkPtrV4();
            if (v4 && ValidateChunkPtr(v4)) {
                std::printf("[+] ChunkPtr (ROL32/vtable[4]) = 0x%llX\n",
                    (unsigned long long)v4);
                return v4;
            }
            if (v4) std::printf("[!] ROL32 result 0x%llX failed validation\n",
                (unsigned long long)v4);

            // Try direct decryption first (from sub_4999C0)
            uint64_t direct = DecryptChunkPtrDirect();
            if (direct) return direct;

            // Fallback to emulation if direct fails
            if (!m_arrayBase || !m_pebAddr) return 0;

            // Get function address from vtable at base+0x40  (vtable[4] = offset 32)
            uint64_t vtbl_ptr = 0;
            if (!m_reader.Read(m_arrayBase + 0x40, &vtbl_ptr, 8) || !vtbl_ptr) return 0;
            uint64_t func_addr = 0;
            if (!m_reader.Read(vtbl_ptr + 32, &func_addr, 8) || !func_addr) return 0;

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
            if (chunk0 >= m_base && chunk0 < m_base + 0x10000000ULL) return false;

            // Some chunks start with null/stale items. Sample a window and
            // accept when at least one UObject has an in-module vtable.
            int valid_samples = 0;
            const int max_samples = (m_numElements > 0 && m_numElements < 64) ? m_numElements : 64;
            for (int i = 0; i < max_samples; ++i) {
                uint64_t obj = 0;
                if (!m_reader.Read(chunk0 + (uint64_t)FUOBJECTITEM_SIZE * i + FUOBJECTITEM_OBJ, &obj, 8))
                    continue;
                if (obj < 0x10000ULL || obj > 0x7FFFFFFFFFFFULL)
                    continue;
                uint64_t vtbl = 0;
                if (!m_reader.Read(obj, &vtbl, 8))
                    continue;
                if (vtbl >= m_base && vtbl < m_base + 0x10000000ULL)
                    ++valid_samples;
                if (valid_samples >= 3)
                    return true;
            }
            return false;
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
            if (!m_reader.Read(vtbl_ptr + 32, &func_addr, 8) || !func_addr) return 0; // vtable[4]

            uint8_t code[256] = {};
            if (!m_reader.Read(func_addr, code, 256)) return 0;
            int path_len = 256;
            for (int i = 4; i < 256; i++) {
                if (code[i] == 0xC3) { path_len = i + 1; break; }
            }

            alignas(16) uint8_t data[16] = {};
            if (!m_reader.Read(m_arrayBase + 0x70, data, 16)) // vtable[4] reads from +0x70
                return 0;

            // Try PEB candidates in typical Wine ranges
            // Note: anti-cheat zeroes PEB.ImageBaseAddress so we use IsPEBValid() instead
            static const uint64_t ranges[][2] = {
                {0x7FF00000, 0x7FFE0000},
                {0x00010000, 0x00200000},
            };
            for (const auto& range : ranges) {
                for (uint64_t peb = range[0]; peb < range[1]; peb += 0x1000) {
                    if (!IsPEBValid(peb)) continue;

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

        // ── Direct struct-field extraction for chunk pointer ────────────
        uint64_t TryDirectChunkPtrFromStruct() {
            if (!m_arrayBase) return 0;

            // Observed stable candidates in latest patch: +0x70 is primary.
            static const int kOffsets[] = {0x70, 0x68, 0x78, 0xB0};
            for (int off : kOffsets) {
                uint64_t candidate = 0;
                if (!m_reader.Read(m_arrayBase + (uint64_t)off, &candidate, 8))
                    continue;
                if (!ValidateChunkPtr(candidate))
                    continue;

                std::printf("[+] Direct chunk ptr from array+0x%02X = 0x%llX\n",
                    off, (unsigned long long)candidate);
                return candidate;
            }
            return 0;
        }
    };

} // namespace gobjects
