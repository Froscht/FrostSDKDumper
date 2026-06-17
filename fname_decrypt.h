#pragma once

// =============================================================================
// ARC Raiders – FName decryption pipeline (patch 20260402)
//
// RE'd by IDA session 20260402 from Arc_Raiders_Binary_20260402_180339.exe
// Key functions: FName_ToString (14022A740), FName_CompareString (14022EAC0),
//                FName_GetBlockPtr (1402280A0), FName_DecryptBlockAddr (140231280)
//
// Full FName resolution pipeline (5 steps, pure computation + 2 memory reads):
//   1. CIdx decode:   ROL32_epi32(ci,2) → PSHUFB(AC1BB10) → PXOR(AC1BB60) → PXOR(AC1BA50)
//   2. Block header:  OR(AND(ci_decoded, AC1BE50), ANDNOT(ci_decoded, AC1BE40)) → PSHUFB(AC1BE60)
//                     → PXOR(AC1BE70) → cvtsi32 → XOR(0x8440FBE5) → ROL32(30) = v5
//                     NOTE: ci_decoded feeds directly here; NO intermediate PSHUFD/blend step.
//   3. Pool address:  pool_base + ((v5>>8) & 0xFFFF00) = v6;  word_off = (uint16_t)v5
//   4. Slot index:    FNV32-4step(v6 + 0x7080) → slot_idx = (lo8^byte2) & 7
//      Slot decrypt:  loadl_64(v6 + 0x7090 + 32*slot_idx) → ROL32(18) →
//                     OR(AND(v, AC1BE20), ANDNOT(v, AC1BD60)) = v11
//                     load_128(v6 + 0x7090 + 32*((slot+1)&7)) → ROL32(18) → lo64 ^ BLOCK2_XOR
//   5. FNV64 chain:   fnv = P * ROL64(P * ROL64(v11, 3) + FNV_ADD, 38) + FNV_ADD
//                     entry_ptr = ROL64(v11,14) + (ROL64(second,14) ^ fnv) + 2*word_off
//
// String decrypt (FName_CompareString path):
//   isWide = (*entry_ptr & 0x80) != 0;  length = ROL16(*entry_ptr, 3) & 0x3FF
//   key = (int8_t)(length - 38);  update: key = -92*key+63
//   narrow: buf[i]   ^= table[(key & 0x3F) + 60] >> 3
//           buf[i+1] ^= table[((38*key+41) & 0x3F) + 60] >> 3
//   wide:   same but XOR full uint16_t (no >> 3)
// =============================================================================

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cstdio>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <immintrin.h>
#include "memreader_ioctl.h"
#include "arc_decrypt.h"

namespace FName {

// ─────────────────────────────────────────────────────────────────────────────
// Scalar helpers
// ─────────────────────────────────────────────────────────────────────────────
static inline uint32_t fn_rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint64_t fn_rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

static inline uint64_t u64_lo_xmm(__m128i v) {
    uint64_t arr[2];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(arr), v);
    return arr[0];
}

static inline uint32_t u32_lo_xmm(__m128i v) {
    return static_cast<uint32_t>(_mm_cvtsi128_si32(v));
}

// ─────────────────────────────────────────────────────────────────────────────
// FNamePool Constants (patch 20260409)
// ─────────────────────────────────────────────────────────────────────────────

// Pool base and key table (patch 20260409)
static uint64_t& FNAME_GNAMES_BASE_OFF              = ArcDecrypt::RVA_GNAMES_BASE;
static uint64_t& FNAME_KEY_TABLE_OFF                = ArcDecrypt::RVA_FNAME_KEY_TABLE;

// CIdx / FName SIMD tables (patch 20260414)
static uint64_t& RVA_CIDX_XOR1_OFF                   = ArcDecrypt::RVA_CIDX_XOR1;
static constexpr uint64_t RVA_CIDX_XOR3_OFF          = ArcDecrypt::RVA_CIDX_XOR3;
static constexpr uint64_t RVA_BLOCK_HDR_AND_OFF      = ArcDecrypt::RVA_BLOCK_HDR_AND;
static constexpr uint64_t RVA_BLOCK_HDR_ANDNOT_OFF   = ArcDecrypt::RVA_BLOCK_HDR_ANDNOT;
static constexpr uint64_t RVA_BLOCK_HDR_SHUF_OFF     = ArcDecrypt::RVA_BLOCK_HDR_SHUF;
static constexpr uint64_t RVA_BLOCK_HDR_XOR_OFF      = ArcDecrypt::RVA_BLOCK_HDR_XOR;
static constexpr uint64_t RVA_BLOCK_SLOT_SHUF_OFF    = ArcDecrypt::RVA_BLOCK_SLOT_SHUF;
static constexpr uint64_t RVA_BLOCK_SLOT_SHUF2_OFF   = ArcDecrypt::RVA_BLOCK_SLOT_SHUF2;

// Key table: 64 uint16 entries, sequential access with (key & 0x3F)


// ─────────────────────────────────────────────────────────────────────────────
// Slot decrypt helper (patch 20260414): ROL16(14) → PSHUFLW(0x93) → PXOR(key)
// Used in both FName_ToString and FName_DecryptBlockAddr for slot data decrypt
// ─────────────────────────────────────────────────────────────────────────────
static inline uint64_t DecryptSlot_ROL16_PSHUFLW_PXOR(const __m128i& data,
                                                       const __m128i& xor_key)
{
    __m128i rol16 = _mm_or_si128(
        _mm_slli_epi16(data, 14),
        _mm_srli_epi16(data, 2));
    __m128i shuf = _mm_shufflelo_epi16(rol16, 0x93);
    __m128i result = _mm_xor_si128(shuf, xor_key);
    return static_cast<uint64_t>(_mm_cvtsi128_si64(result));
}

// ─────────────────────────────────────────────────────────────────────────────
// FNameDecryptor
// ─────────────────────────────────────────────────────────────────────────────
class FNameDecryptor {
public:
    // Active FName pipeline (selected at Init() time by probing keytables).
    //   CL1177146    — patch 2026-04-30 pipeline (legacy primary path)
    //   Build20260519— patch 2026-05-19 (new resolver: stage A1+A2+A3, FNV57/56,
    //                                    LCG name decrypt, slot @ ROL32(9))
    enum class Pipeline {
        CL1177146,
        Build20260519,
    };

    FNameDecryptor(uint64_t module_base, IMemoryReader& reader)
        : m_base(module_base), m_reader(reader), m_keyLoaded(false)
    {
        memset(m_keyTable, 0, sizeof(m_keyTable));
    }

    void SetBase(uint64_t b) { m_base = b; }
    Pipeline ActivePipeline() const { return m_pipeline; }
    void ForcePipeline(Pipeline p) { m_pipeline = p; }

    bool Init() {
        if (m_keyLoaded) return true;

        // ── Dual-pipeline probe ──
        // 1) Try the CL-1177146 keytable RVA. Valid ⇒ legacy pipeline.
        // 2) Otherwise try the 2026-05-19 keytable RVA. Valid ⇒ new pipeline,
        //    additionally pre-load all 9 SIMD-stage masks.
        // 3) If both yield <16 nonzero u16 entries, fall through and let the
        //    legacy path's auto-discovery / emu fallback take over.
        auto TryLoadKeytable = [&](uint64_t Rva, uint16_t* Out) -> int {
            if (!m_reader.Read(m_base + Rva, Out, 64 * sizeof(uint16_t))) return -1;
            int Nz = 0;
            for (int I = 0; I < 64; ++I) Nz += (Out[I] != 0);
            return Nz;
        };

        uint16_t Kt146[64] = {};
        uint16_t Kt519[64] = {};
        const uint64_t Rva146 = ArcDecrypt::RVA_FNAME_KEY_TABLE;          // 0xDAF88EC
        const uint64_t Rva519 = ArcDecrypt::v20260519::RVA_FNAME_KEYTABLE; // 0xE17C7FC

        int Nz146 = TryLoadKeytable(Rva146, Kt146);
        int Nz519 = TryLoadKeytable(Rva519, Kt519);

        std::printf("[fname] keytable probe: CL1177146@0x%llX=%d nz, 20260519@0x%llX=%d nz\n",
            (unsigned long long)(m_base + Rva146), Nz146,
            (unsigned long long)(m_base + Rva519), Nz519);

        // Prefer whichever has more nonzero entries; threshold 16 for "valid".
        bool Use519 = (Nz519 >= 16) && (Nz519 >= Nz146);
        bool Use146 = (Nz146 >= 16) && !Use519;

        if (Use519) {
            std::memcpy(m_keyTable, Kt519, sizeof(Kt519));
            FNAME_KEY_TABLE_OFF = Rva519;
            m_pipeline = Pipeline::Build20260519;
            std::printf("[fname] Pipeline = Build20260519 (keytable @ 0x%llX, %d nz)\n",
                (unsigned long long)(m_base + Rva519), Nz519);
        } else if (Use146) {
            std::memcpy(m_keyTable, Kt146, sizeof(Kt146));
            FNAME_KEY_TABLE_OFF = Rva146;
            m_pipeline = Pipeline::CL1177146;
            std::printf("[fname] Pipeline = CL1177146 (keytable @ 0x%llX, %d nz)\n",
                (unsigned long long)(m_base + Rva146), Nz146);
        } else {
            std::printf("[-] FName key table looks invalid at BOTH known RVAs "
                        "(146=%d nz, 519=%d nz)\n", Nz146, Nz519);
            return false;
        }
        std::printf("[+] FName key table OK (first: 0x%04X 0x%04X 0x%04X 0x%04X)\n",
            m_keyTable[0], m_keyTable[1], m_keyTable[2], m_keyTable[3]);

        m_keyLoaded = true;
        return true;
    }

    bool IsInitialized() const { return m_keyLoaded; }

private:
public:

    // Re-read the key table from the current `RVA_FNAME_KEY_TABLE` value.
    // Used after auto-discovery patches the RVA: the initial Init() reads
    // from the (possibly stale) compile-time RVA; once a keystream-discovery
    // pass updates the RVA, callers re-run this to load from the correct
    // address. Idempotent — safe to call repeatedly.
    bool ReloadKeyTable() {
        m_keyLoaded = false;
        std::memset(m_keyTable, 0, sizeof(m_keyTable));
        return Init();
    }

    // ── Inline-handle offset calibration ─────────────────────────────────
    // The UObject inline FName handle lives at one of a few candidate
    // offsets (observed +0x28 on patch 20260421, +0x18 on older patches).
    // SDKDumper::CalibrateInlineHandleOffset samples live objects to find
    // which offset produces the most valid decodes, then sets it as the
    // primary so GetName tries it first (the legacy candidates remain as
    // fallbacks). Empty (0) means "use the default candidate list".
    void SetPrimaryHandleOffset(uint64_t off) { m_primaryHandleOffset = off; }
    uint64_t PrimaryHandleOffset() const { return m_primaryHandleOffset; }

    // ── Emulation fallback ──────────────────────────────────────────────────
    // When the static decrypt pipeline cannot resolve a CompIndex (signature
    // drift, table-key drift, FNV mismatch, …) we hand the CI off to the
    // game's own FName function running inside Unicorn. The wiring lives in
    // main.cpp; here we accept an opaque std::function so this header stays
    // free of any Unicorn / EmuFName include.
    using EmuFallback = std::function<std::string(int32_t /*comp_index*/)>;
    void SetEmuFallback(EmuFallback fn) { m_emuFallback = std::move(fn); }
    void ClearEmuCache() { m_emuCache.clear(); }
    size_t EmuCacheSize() const { return m_emuCache.size(); }

    // ── Emu-primary mode ────────────────────────────────────────────────────
    // When set, CompIndexToName / CompIndexToNameLenient / GetName try the
    // Unicorn-emulated game function FIRST and only fall back to the static
    // SIMD pipeline if emu fails. Use this on patches where the static path
    // is broken (FNamePool resolver shape changed, FNameEntry decrypt rotated,
    // etc.) — wired up automatically by main.cpp::Init() when the Phase 0.6
    // sanity check on actor names fails. Default = false (static primary).
    void SetEmuPrimary(bool enabled) {
        if (m_emuPrimary == enabled) return;
        m_emuPrimary = enabled;
        std::printf("[fname] emu-primary mode %s — %s\n",
            enabled ? "ENABLED" : "DISABLED",
            enabled ? "all CompIndex resolution routes through Unicorn first"
                    : "static decrypt path is primary");
    }
    bool EmuPrimary() const { return m_emuPrimary; }
    bool HasEmuFallback() const { return !!m_emuFallback; }

    // Emu-only path. Skips StaticResolve entirely — for callers that know
    // the static pipeline produces wrong-but-printable garbage on this
    // patch (e.g. UEnum::Names entries on patch 20260421 store an obfuscated
    // CompIndex that the standard FNamePool walk maps to the wrong slot).
    // Routes through sub_23D3E0 in-game (the inline SIMD pipeline).
    std::string DecryptCIByEmu(int32_t comp_index) {
        return TryEmuFallback(comp_index);
    }

    void DumpKeyTable(int n) const {
        std::printf("[dbg] FName KeyTable (addr=0x%llX, first %d entries):\n",
            (unsigned long long)(m_base + FNAME_KEY_TABLE_OFF), n);
        for (int i = 0; i < n && i < 256; i++)
            std::printf("  [%2d] = 0x%04X\n", i, m_keyTable[i]);
    }

    // ── Step 1: slot index from object address (UObject::GetNamePrivate) ──
    uint32_t GetSlotIndex(uint64_t obj_base) const {
        if (m_pipeline == Pipeline::Build20260519 || AutoDiscovery::g_DiscoveredUObjSlot.Valid) {
            return Build20260519_ObjNameSlot(obj_base);
        }
        return ArcDecrypt::GetFNameSlotIndex(obj_base);
    }

    // ── Build20260519 slot-picker hash (verified from sub_1404CEAD0) ──────
    //   p = obj+0x10, lo=p&0xFFFFFFFF, hi=p>>32
    //   h  = ROL32(lo, 17)
    //   h  = P*h + ADD; h = ROL32(h, 19)
    //   h  = P*h + hi + ADD; h = ROL32(h, 17)
    //   h  = P*h + ADD; h >>= 13
    //   v12 = P*h + ADD
    //   slot_byte = u8(v12) ^ u8(v12 >> 16)
    // Slot indices:
    //   NAME  = (slot_byte & 3) ^ 2
    //   OUTER = (slot_byte + 1) & 3
    //   CLASS =  slot_byte & 3
    static uint8_t Build20260519_ObjSlotMixByte(uint64_t obj_ptr) {
        const bool Is616 = AutoDiscovery::g_DiscoveredUObjSlot.Valid;
        const uint32_t P   = 0x01000193u;
        const uint32_t ADD = Is616 ? ArcDecrypt::v20260616::SLOT_HASH_ADD
                                   : ArcDecrypt::v20260519::SLOT_HASH_ADD;
        uint64_t p = obj_ptr + 0x10;
        uint32_t lo32 = static_cast<uint32_t>(p);
        uint32_t hi32 = static_cast<uint32_t>(p >> 32);

        uint32_t h;
        if (Is616) {
            h = fn_rotl32(lo32, 26);
            h = P * h + ADD;
            h = fn_rotl32(h, 27);
            h = P * h + hi32 + ADD;
            h >>= 6;
            h = P * h + ADD;
            h >>= 5;
        } else {
            h = fn_rotl32(lo32, 17);
            h = P * h + ADD;
            h = fn_rotl32(h, 19);
            h = P * h + hi32 + ADD;
            h = fn_rotl32(h, 17);
            h = P * h + ADD;
            h >>= 13;
        }
        uint32_t v12 = P * h + ADD;

        return static_cast<uint8_t>(v12) ^ static_cast<uint8_t>(v12 >> 16);
    }
    static uint32_t Build20260519_ObjNameSlot(uint64_t obj_ptr) {
        return ((uint32_t)Build20260519_ObjSlotMixByte(obj_ptr) & 3u) ^ 2u;
    }
    static uint32_t Build20260519_ObjOuterSlot(uint64_t obj_ptr) {
        return ((uint32_t)Build20260519_ObjSlotMixByte(obj_ptr) + 1u) & 3u;
    }
    static uint32_t Build20260519_ObjClassSlot(uint64_t obj_ptr) {
        return (uint32_t)Build20260519_ObjSlotMixByte(obj_ptr) & 3u;
    }

    // ── Hash-based slot selector (CL-1177678) ────────────────────────────
    // Verified IDA `sub_2D9270` @ 0x2D9292..0x2D9311 (the OuterPrivate walker
    // at xref site 0x2D9415 of xmmword_AD97CC0). The chain is:
    //   ecx = ROL32(addr_lo, 26)
    //   ecx = P * ecx + ADD
    //   ecx = ROL32(ecx, 25)
    //   ecx = P * ecx + addr_hi + ADD
    //   ecx = (ecx >> 6) * P + ADD
    //   ecx = (ecx >> 7) * P + ADD
    //   raw_idx  = ((ecx ^ (ecx >> 16)) + N) & 3   where N = 0(Class) / 1(Outer) / xor 2 (Name)
    //
    // Drift from CL-1177146:
    //   ROL32(24) → ROL32(26) (first stage)
    //   ROL32(24) → shifted to plain >>6 (third stage, no rotate)
    //   HASH_ADD = 0x8E195662 → 0x98689957
    static uint32_t ObjSlotHash(uint64_t ObjPtr) {
        constexpr uint32_t P   = 0x01000193u;
        constexpr uint32_t ADD = 0x98689957u;          // CL-1177678 (was 0x8E195662)
        uint64_t Ptr = ObjPtr + 0x10;
        uint32_t Lo  = static_cast<uint32_t>(Ptr);
        uint32_t Hi  = static_cast<uint32_t>(Ptr >> 32);

        uint32_t E = fn_rotl32(Lo, 26);                 // CL-1177678: 26 (was 24)
        E = P * E + ADD;
        E = fn_rotl32(E, 25);
        E = P * E + Hi + ADD;
        E = (E >> 6) * P + ADD;                         // CL-1177678: plain shr 6 (was ROL32(24))
        E = (E >> 7) * P + ADD;                         // unchanged
        return E;
    }
    static uint32_t ObjNameSlot(uint64_t obj_ptr) {
        // CL-1177678 Name-slot selector: ((E ^ (E >> 16)) & 3) ^ 2
        // (extrapolated from the CL-1177146 selector pattern; the IDA
        // sub_2D9270 +1 is the OUTER variant — Name uses ^2 instead).
        uint32_t E = ObjSlotHash(obj_ptr);
        return (uint32_t)(((E ^ (E >> 16)) & 3u) ^ 2u);
    }
    // Alternate slot picker (Steam/Xbox reference pipeline, 2026-04-29):
    //   r1 = rol(lo, 19); r2 = rol(P*r1 + ADD2, 22)
    //   v12 = rol(hi + P*r2 + ADD2, 19)
    //   y = (P*v12 + ADD2) >> 10
    //   pa = uint8(-109 * y); pb = uint8((P*y + 213064) >> 16)
    //   slot = ((pa ^ pb) & 3) ^ 2
    // Different scalar constants from the Wine pipeline above. If our build's
    // constants happen to misfire on certain objects, the alt picker may pick
    // the right slot for them — used as a fallback in TryAlternateNameSlot().
    static uint32_t ObjNameSlot_Alt(uint64_t obj_ptr) {
        constexpr uint32_t P     = 0x01000193u;
        constexpr uint32_t ADD2  = 0x48A34048u;       // 1218658376
        constexpr uint32_t ADD2B = 0x340048u;         // 213064
        uint64_t a = obj_ptr + 0x10;
        uint32_t lo = static_cast<uint32_t>(a);
        uint32_t hi = static_cast<uint32_t>(a >> 32);
        uint32_t r1  = fn_rotl32(lo, 19);
        uint32_t r2  = fn_rotl32(P * r1 + ADD2, 22);
        uint32_t v12 = fn_rotl32(hi + P * r2 + ADD2, 19);
        uint32_t y   = (P * v12 + ADD2) >> 10;
        uint8_t  pa  = static_cast<uint8_t>(-109 * static_cast<int>(y));
        uint8_t  pb  = static_cast<uint8_t>((P * y + ADD2B) >> 16);
        return (uint32_t)(((pa ^ pb) & 3u) ^ 2u);
    }
    // Outer-slot formula verified from sub_2D9270 @ 0x2D930C-0x2D9311 (CL-1177678):
    //   raw_idx = (E ^ (E >> 16) + 1) & 3
    static uint32_t ObjOuterSlot(uint64_t obj_ptr) {
        uint32_t E = ObjSlotHash(obj_ptr);
        return (uint32_t)(((E ^ (E >> 16)) + 1u) & 3u);
    }
    // Class-slot formula (CL-1177678): no +1, no ^2
    static uint32_t ObjClassSlot(uint64_t obj_ptr) {
        uint32_t E = ObjSlotHash(obj_ptr);
        return (uint32_t)((E ^ (E >> 16)) & 3u);
    }

    // ── Decrypt one UObject slot (CL-1177678) ───────────────────────────
    // Forwards to DecryptUObjSlotCL1177678 — the actual current-patch
    // algorithm: shufflelo(0x39) → ROL32(26) → PSHUFB(xmmword_ADEAC80) →
    // lo64 → ROL64(32). The legacy CL-1177146 algorithm (PSHUFB + XOR +
    // ROL64) doesn't match this patch.
    //
    // For NAME slot: result.lo32 = CompIndex, result.hi32 = FName::Number.
    // For pointer slots (Class/Outer): the same decode produces a 64-bit
    // value where (hi32 << 32) | lo32 reconstructs the original pointer
    // (= ROL64(real_ptr, 32) is its own inverse). Callers that want the
    // raw pointer should swap halves: `((u32)dec << 32) | (dec >> 32)`.
    uint64_t DecryptUObjSlotNew(const uint8_t enc[16]) const {
        const auto& Disc = AutoDiscovery::g_DiscoveredUObjSlot;
        if (Disc.Valid) {
            __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
            alignas(16) uint8_t FullMask[16] = {};
            std::memcpy(FullMask, Disc.ShufMaskBytes, 8);
            __m128i Mask = _mm_load_si128(reinterpret_cast<const __m128i*>(FullMask));
            __m128i Shuffled = _mm_shuffle_epi8(V, Mask);
            __m128i Xored = _mm_xor_si128(Shuffled, _mm_set_epi64x(0, static_cast<int64_t>(Disc.XorScalar)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xored);
            return fn_rotl64(Lo, Disc.Rol64Amount);
        }
        if (m_pipeline == Pipeline::Build20260519) {
            return DecryptUObjSlot_Build20260519(enc);
        }
        return DecryptUObjSlotCL1177678(enc);
    }

    // ── Build20260519 UObject NAME slot decoder (verified sub_140498A50) ──
    // CL-1201801 pipeline: PSHUFLW(0xB1) → lo64 → XOR(0xD22BC6399DD7BE75) → ROL64(37)
    // Returns (Number<<32)|CI; CI in lo32.
    uint64_t DecryptUObjSlot_Build20260519(const uint8_t enc[16]) const {
        using namespace ArcDecrypt::v20260519;
        __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i S = _mm_shufflelo_epi16(V, 0xB1);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), S);
        return fn_rotl64(Lo ^ UOBJ_SLOT_XOR_64, UOBJ_SLOT_FINAL_ROL);
    }

    // ── Build20260519 UObject CLASS/OUTER slot decoder ───────────────────
    // Same PSHUFLW+XOR but ROL64(5) — result is the raw pointer directly.
    uint64_t DecryptUObjSlotPtr_Build20260519(const uint8_t enc[16]) const {
        const auto& Disc = AutoDiscovery::g_DiscoveredUObjSlot;
        if (Disc.Valid) {
            __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
            alignas(16) uint8_t FullMask[16] = {};
            std::memcpy(FullMask, Disc.ShufMaskBytes, 8);
            __m128i Mask = _mm_load_si128(reinterpret_cast<const __m128i*>(FullMask));
            __m128i Shuffled = _mm_shuffle_epi8(V, Mask);
            __m128i Xored = _mm_xor_si128(Shuffled, _mm_set_epi64x(0, static_cast<int64_t>(Disc.XorScalar)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xored);
            return Lo;
        }
        using namespace ArcDecrypt::v20260519;
        __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i S = _mm_shufflelo_epi16(V, 0xB1);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), S);
        return fn_rotl64(Lo ^ UOBJ_SLOT_XOR_64, UOBJ_SLOT_PTR_ROL);
    }

    // ── CL-1177678 UObject slot decoder ─────────────────────────────────
    // Verified via IDA sub_4CD5B0 @ 0x4CD75C..0x4CD7A3 (FName comparison
    // routine that takes a UObject and a candidate FName). The full pipeline:
    //
    //   slot_bytes = read 16 from obj + 0x20 + name_slot_idx * 0x20
    //   v = pshuflw(slot_bytes, 0x39)                     // shufflelo, mask 0x39
    //   v = ROL32(v, 26) per u32 lane                       // PSLLD 0x1A | PSRLD 6
    //   v = PSHUFB(v, xmmword_ADEAC80)
    //   lo64 = v.m128i_u64[0]
    //   final = ROL64(lo64, 32)                              // ← swaps halves
    //   ci = final & 0xFFFFFFFF                              // low 32 = CompIndex
    //   number = final >> 32                                  // high 32 = Number
    //
    // Verified against known CIs:
    //   obj=0x2A5A1300 (NAME slot 0) → final=0x1F9 → CI=505 = "Object" ✓
    //   obj=0x88060000 (NAME slot 1) → final=0x6A4 → CI=1700
    //
    // The PSHUFB mask `xmmword_ADEAC80` lives at RVA 0xADEAC80 (live):
    //   `06 00 01 04 07 03 02 05 00 00 00 00 00 00 00 00`
    // hi8 of mask is zero → hi8 of result is zero → final after ROL64(32)
    // has CI in low 32 and Number in high 32, matching the standard FName
    // layout {ComparisonIndex, Number}.
    //
    // .rdata RVA hardcoded for now (TODO: auto-discover by binding the
    // PSHUFB mask referenced inside the NAME slot decoder to the live
    // xmmword via the call-chain rip-rel scan).
    uint64_t DecryptUObjSlotCL1177678(const uint8_t enc[16]) const {
        static thread_local bool s_loaded = false;
        alignas(16) static thread_local uint8_t s_mask[16];
        if (!s_loaded) {
            if (!m_reader.Read(m_base + 0xADEAC80, s_mask, 16)) return 0;
            s_loaded = true;
        }

        __m128i V    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i Sh   = _mm_shufflelo_epi16(V, 0x39);
        __m128i Rot  = _mm_or_si128(_mm_slli_epi32(Sh, 26),
                                    _mm_srli_epi32(Sh, 6));
        __m128i Mask = _mm_load_si128(reinterpret_cast<const __m128i*>(s_mask));
        __m128i Out  = _mm_shuffle_epi8(Rot, Mask);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Out);
        return (Lo << 32) | (Lo >> 32);    // ROL64(32)
    }

    // ── FField NamePrivate slot decrypt (patch CL-1177146) ───────────────
    // Verified IDA: function at 0x4544A0 (FBoolProperty's GetCPPType / "Unsupported
    // FBoolProperty %s size %d." error path). It loads FField+0x70 and runs:
    //   1. ROL32(_, 13) per uint32-lane  (PSLLD 13 | PSRLD 19)
    //   2. take lo64
    //   3. XOR with 0x9A492C85DDF6F193ULL  (auto-discovered at runtime)
    //   4. ROL64(_, 7)
    //   → result u64 = (Number << 32) | CI ; CI in lo32.
    //
    // The XOR const, ROL32 amount, and ROL64 amount are auto-discovered
    // by AutoDiscovery::DiscoverFFieldNameDecrypt (see auto_discovery.h)
    // via live FField slot inspection (no sig-scan needed — the const
    // falls out of the data math). The hardcoded fallback below is the
    // CL-1177146 value, used until discovery has run.
    static constexpr uint64_t FFIELD_NAME_XOR_CL1177146 = 0x9A492C85DDF6F193ULL;
    uint64_t DecryptFFieldNameSlot(const uint8_t enc[16]) const {
        {
            using namespace ArcDecrypt::v20260616;
            __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
            V = _mm_shufflelo_epi16(V, FFIELD_NAME_SHUF_IMM);
            V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(FFIELD_NAME_XOR_KEY)));
            V = _mm_or_si128(_mm_add_epi16(V, V), _mm_srli_epi16(V, 15));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            uint64_t Out = (Lo << FFIELD_NAME_ROL64) | (Lo >> (64 - FFIELD_NAME_ROL64));
            uint32_t CiN = static_cast<uint32_t>(Out);
            if (CiN > 1 && CiN < 0x2000000u) return Out;
        }

        {
            const auto& Disc = AutoDiscovery::g_DiscoveredFFieldName;
            if (Disc.Valid && Disc.TwoShuffle) {
                auto ApplyShuf = [](__m128i V, uint8_t Imm) -> __m128i {
                    switch (Imm) {
                        case 0x1E: return _mm_shufflelo_epi16(V, 0x1E);
                        case 0x72: return _mm_shufflelo_epi16(V, 0x72);
                        case 0x4B: return _mm_shufflelo_epi16(V, 0x4B);
                        case 0x39: return _mm_shufflelo_epi16(V, 0x39);
                        case 0x93: return _mm_shufflelo_epi16(V, 0x93);
                        case 0xB1: return _mm_shufflelo_epi16(V, 0xB1);
                        case 0x2E: return _mm_shufflelo_epi16(V, 0x2E);
                        case 0x1B: return _mm_shufflelo_epi16(V, 0x1B);
                        case 0x4E: return _mm_shufflelo_epi16(V, 0x4E);
                        case 0x8D: return _mm_shufflelo_epi16(V, 0x8D);
                        case 0xD8: return _mm_shufflelo_epi16(V, 0xD8);
                        case 0xE1: return _mm_shufflelo_epi16(V, 0xE1);
                        default:   return V;
                    }
                };
                __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
                V = ApplyShuf(V, Disc.ShufImm1);
                uint64_t Mid;
                _mm_storel_epi64(reinterpret_cast<__m128i*>(&Mid), V);
                Mid = (Mid << Disc.TsRol64) | (Mid >> (64 - Disc.TsRol64));
                V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(&Mid));
                V = ApplyShuf(V, Disc.ShufImm2);
                uint64_t Out;
                _mm_storel_epi64(reinterpret_cast<__m128i*>(&Out), V);
                uint32_t Ci = static_cast<uint32_t>(Out);
                if (Ci > 1 && Ci < 0x2000000u) return Out;
            }
        }

        {
            const auto& Disc = AutoDiscovery::g_DiscoveredFFieldName;
            if (Disc.Valid && !Disc.TwoShuffle && Disc.XorConst == 0 && Disc.Rol32Amount > 0) {
                auto ApplyShuf = [](__m128i V, uint8_t Imm) -> __m128i {
                    switch (Imm) {
                        case 0x1E: return _mm_shufflelo_epi16(V, 0x1E);
                        case 0x72: return _mm_shufflelo_epi16(V, 0x72);
                        case 0x4B: return _mm_shufflelo_epi16(V, 0x4B);
                        case 0x39: return _mm_shufflelo_epi16(V, 0x39);
                        case 0x93: return _mm_shufflelo_epi16(V, 0x93);
                        case 0xB1: return _mm_shufflelo_epi16(V, 0xB1);
                        case 0x2E: return _mm_shufflelo_epi16(V, 0x2E);
                        case 0x1B: return _mm_shufflelo_epi16(V, 0x1B);
                        case 0x4E: return _mm_shufflelo_epi16(V, 0x4E);
                        case 0x8D: return _mm_shufflelo_epi16(V, 0x8D);
                        case 0xD8: return _mm_shufflelo_epi16(V, 0xD8);
                        case 0xE1: return _mm_shufflelo_epi16(V, 0xE1);
                        default:   return V;
                    }
                };
                __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
                V = _mm_or_si128(_mm_slli_epi32(V, Disc.Rol32Amount),
                                 _mm_srli_epi32(V, 32 - Disc.Rol32Amount));
                V = ApplyShuf(V, Disc.ShufImm1);
                uint64_t Lo;
                _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
                uint64_t Out = (Lo << Disc.Rol64Amount) | (Lo >> (64 - Disc.Rol64Amount));
                uint32_t Ci = static_cast<uint32_t>(Out);
                if (Ci > 1 && Ci < 0x2000000u) return Out;
            }
        }

        if (m_pipeline == Pipeline::Build20260519) {
            const auto& Masks = AutoDiscovery::g_DiscoveredFFieldMasks;
            uint64_t UseKey1 = Masks.Valid ? Masks.Key1 : ArcDecrypt::v20260519::FFIELD_NAME_KEY1;
            uint64_t UseKey2 = Masks.Valid ? Masks.Key2 : ArcDecrypt::v20260519::FFIELD_NAME_KEY2;
            int      UseRol32 = Masks.Valid ? Masks.Rol32Amount : ArcDecrypt::v20260519::FFIELD_NAME_ROL32;
            int      UseRol64 = Masks.Valid ? Masks.Rol64Amount : ArcDecrypt::v20260519::FFIELD_NAME_ROL64;
            __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
            V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(UseKey1)));
            V = _mm_or_si128(_mm_slli_epi32(V, UseRol32), _mm_srli_epi32(V, 32 - UseRol32));
            V = _mm_shufflelo_epi16(V, 0x1E);
            V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(UseKey2)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            uint64_t Out = (Lo << UseRol64) | (Lo >> (64 - UseRol64));
            uint32_t Ci  = static_cast<uint32_t>(Out);
            if (Ci > 1 && Ci < 0x2000000u) return Out;
        }

        // CL-1195482 (Build20260519+CL-1195482 hotfix) FField NamePrivate decode.
        // Verified IDA sub_441436 / sub_43BF16 (FBoolProperty GetCPPType callers):
        //   v4   = PSHUFLW(field+0x50, 0x4B)
        //   rol  = POR(PADDD(v4,v4), PSRLD(v4,31))   // ROL32(1) per 32-bit lane
        //   shuf = PSHUFB(rol, xmmword_B34DF20)
        //   out  = ROL64(shuf.lo64 ^ 0x5C61A9C2230CDE97, 32)
        if (m_pipeline == Pipeline::Build20260519) {
            __m128i V    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
            __m128i Sh   = _mm_shufflelo_epi16(V, 0x4B);
            __m128i Rot  = _mm_or_si128(_mm_add_epi32(Sh, Sh), _mm_srli_epi32(Sh, 31));
            alignas(16) static const uint8_t MaskBytes[16] = {
                0x04, 0x06, 0x07, 0x05, 0x02, 0x01, 0x00, 0x03,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            __m128i Mask = _mm_load_si128(reinterpret_cast<const __m128i*>(MaskBytes));
            __m128i Sft  = _mm_shuffle_epi8(Rot, Mask);
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Sft);
            uint64_t Xored = Lo ^ 0x5C61A9C2230CDE97ULL;
            uint64_t Out   = (Xored << 32) | (Xored >> 32);
            uint32_t Ci    = static_cast<uint32_t>(Out);
            if (Ci > 1 && Ci < 0x2000000u) return Out;
        }

        {
            __m128i V   = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
            __m128i Rot = _mm_or_si128(_mm_slli_epi64(V, 55), _mm_srli_epi64(V, 9));
            alignas(16) static const uint8_t MaskBytes[16] = {
                0x06, 0x05, 0x03, 0x01, 0x02, 0x07, 0x00, 0x04,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            alignas(16) static const uint8_t XorBytes[16] = {
                0x3B, 0x3F, 0xA4, 0x49, 0xC8, 0xC8, 0x82, 0x48,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            __m128i Mask  = _mm_load_si128(reinterpret_cast<const __m128i*>(MaskBytes));
            __m128i XorK  = _mm_load_si128(reinterpret_cast<const __m128i*>(XorBytes));
            __m128i Shuf  = _mm_shuffle_epi8(Rot, Mask);
            __m128i Xored = _mm_xor_si128(Shuf, XorK);
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xored);
            uint64_t Out = (Lo << 32) | (Lo >> 32);
            uint32_t Ci  = static_cast<uint32_t>(Out);
            if (Ci > 1 && Ci < 0x2000000u) return Out;
        }

        {
            uint64_t cl678 = DecryptUObjSlotCL1177678(enc);
            uint32_t ci = static_cast<uint32_t>(cl678);
            if (ci > 1 && ci < 0x2000000u) return cl678;
        }

        const auto& Disc = AutoDiscovery::g_DiscoveredFFieldName;
        const uint64_t XorConst = Disc.Valid ? Disc.XorConst : FFIELD_NAME_XOR_CL1177146;
        const int      Rol32Amt = Disc.Valid ? Disc.Rol32Amount : 13;
        const int      Rol64Amt = Disc.Valid ? Disc.Rol64Amount : 7;

        __m128i V    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i Rot  = _mm_or_si128(
            _mm_slli_epi32(V, Rol32Amt),
            _mm_srli_epi32(V, 32 - Rol32Amt));
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Rot);
        uint64_t Xored = Lo ^ XorConst;
        return (Xored << Rol64Amt) | (Xored >> (64 - Rol64Amt));
    }

    // ── UObject FName accessor (CL-1177678) ─────────────────────────────
    // Verified IDA sub_4CD5B0: pick NAME slot via FNV-chain hash on
    // (obj+0x10), decrypt slot bytes via shufflelo(0x39)+ROL32(26)+
    // PSHUFB(xmmword_ADEAC80)+lo64+ROL64(32). The result's lo32 is the
    // CompIndex, hi32 is FName::Number.
    //
    // Tested live:
    //   obj=0x2A5A1300 (NAME slot 0) → CI=505 ("Object" — verified)
    //   obj=0x88060000 (NAME slot 1) → CI=1700
    int32_t GetCompIndex(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;
        auto is_ci = [](uint32_t h) { return h > 1 && h < 0x2000000u; };

        auto try_slot = [&](int slot) -> int32_t {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) return 0;
            bool nonzero = false;
            for (int b = 0; b < 16; ++b) if (enc[b]) { nonzero = true; break; }
            if (!nonzero) return 0;

            uint64_t dec = DecryptUObjSlotNew(enc);   // dispatches to Build20260519 when active
            uint32_t lo = static_cast<uint32_t>(dec);   // CI is in low 32 after ROL64(32)
            if (is_ci(lo)) return static_cast<int32_t>(lo);
            return 0;
        };

        // Tier 0: hash-picked NAME slot.
        uint32_t ns = (m_pipeline == Pipeline::Build20260519 || AutoDiscovery::g_DiscoveredUObjSlot.Valid)
                          ? Build20260519_ObjNameSlot(obj_base)
                          : ObjNameSlot(obj_base);
        if (int32_t ci = try_slot(static_cast<int>(ns))) return ci;
        // Tier 1: walk all 4 slots as fallback. Validate each via emu — only
        // accept the slot whose CI resolves to a non-empty, mostly-printable
        // string. Without validation, non-name slots (Class/Outer/Inner)
        // produce in-range-but-bogus CIs that emu-resolves to garbage.
        auto looks_name = [](const std::string& s) {
            if (s.empty() || s.size() > 256) return false;
            int printable = 0;
            for (unsigned char c : s)
                if (c >= 32 && c <= 126) ++printable;
            return printable * 4 >= static_cast<int>(s.size()) * 3;
        };
        for (int s = 0; s < 4; ++s) {
            if (s == static_cast<int>(ns)) continue;
            int32_t ci = try_slot(s);
            if (!ci) continue;
            if (m_emuFallback) {
                std::string nm = TryEmuFallback(ci);
                if (looks_name(nm)) return ci;
            } else {
                return ci;  // no validator available — best-effort
            }
        }
        return 0;
    }

    // Return ALL pointer-shaped slot decryptions (up to 4). Used by SDK
    // classifier to cross-check against the metaclass set — GetClassPrivate
    // alone is unstable since it picks the first match, and different
    // objects encode their class in different slots.
    std::array<uint64_t, 4> GetAllClassCandidates(uint64_t obj_base) {
        std::array<uint64_t, 4> out{};
        if (!obj_base || !m_keyLoaded) return out;
        bool Is519 = (m_pipeline == Pipeline::Build20260519 || AutoDiscovery::g_DiscoveredUObjSlot.Valid);
        for (int slot = 0; slot < 4; ++slot) {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) continue;
            uint64_t ptr;
            if (Is519) {
                ptr = DecryptUObjSlotPtr_Build20260519(enc);
                if (ptr < 0x10000ULL || ptr >= 0x800000000000ULL) continue;
            } else {
                uint64_t dec = DecryptUObjSlotNew(enc);
                if (!dec) continue;
                uint32_t lo = static_cast<uint32_t>(dec);
                uint32_t hi = static_cast<uint32_t>(dec >> 32);
                if (hi < 0x10000u) continue;
                ptr = (static_cast<uint64_t>(lo) << 32) | hi;
                if (ptr < 0x100000ULL || ptr >= 0x800000000000ULL) continue;
            }
            out[slot] = ptr;
        }
        return out;
    }

    uint64_t GetClassPrivate(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;
        bool Is519 = (m_pipeline == Pipeline::Build20260519 || AutoDiscovery::g_DiscoveredUObjSlot.Valid);
        uint32_t cs = Is519 ? Build20260519_ObjClassSlot(obj_base) : ObjClassSlot(obj_base);
        auto tryDecode = [&](int slot) -> uint64_t {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) return 0;
            if (Is519) {
                uint64_t ptr = DecryptUObjSlotPtr_Build20260519(enc);
                if (ptr < 0x10000ULL || ptr >= 0x800000000000ULL) return 0;
                return ptr;
            }
            uint64_t dec = DecryptUObjSlotNew(enc);
            if (!dec) return 0;
            uint32_t lo = static_cast<uint32_t>(dec);
            uint32_t hi = static_cast<uint32_t>(dec >> 32);
            if (hi < 0x10000u) return 0;
            uint64_t ptr = (static_cast<uint64_t>(lo) << 32) | hi;
            if (ptr < 0x100000ULL || ptr >= 0x800000000000ULL) return 0;
            return ptr;
        };
        uint64_t p = tryDecode(static_cast<int>(cs));
        if (p) return p;
        uint32_t ns = Is519 ? Build20260519_ObjNameSlot(obj_base) : ObjNameSlot(obj_base);
        uint32_t os = Is519 ? Build20260519_ObjOuterSlot(obj_base) : ObjOuterSlot(obj_base);
        for (int slot = 0; slot < 4; ++slot) {
            if (static_cast<uint32_t>(slot) == ns || static_cast<uint32_t>(slot) == os) continue;
            p = tryDecode(slot);
            if (p) return p;
        }
        for (int slot = 0; slot < 4; ++slot) {
            p = tryDecode(slot);
            if (p) return p;
        }
        return 0;
    }

    // ── FField::NamePrivate → comp_index (patch 20260414) ───────────────
    // Confirmed via IDA: sub_428C57 in qoc9 (FField_GetFName_CompareCI_NEW).
    //   *(a1+0x138) = FField*; reads [FField+0x90] (movq lo 8 bytes only).
    //   Second 8 bytes at +0x98 are ROR64(first, 16) — pure self-check, ignored here.
    // Pipeline: PSHUFLW(0x39) → ROL64(33) → AND(0x84)/ANDNOT(0x7B) blend
    //           → PSHUFB({07,02,03,06,05,00,01,04}) → PXOR(B5B5A3D2F313FAB5)
    //           → ROL64(32) → lo64 = FName u64 = (Number << 32) | pool_index_29bit
    // Math optimisation: blend has A=~B per byte, so it equals (v XOR 0x7B). PSHUFB
    // commutes with byte-broadcast XOR, so blend+pxor collapse into one XOR with
    // EFF_KEY = (0x84 XOR XorKey)_per_byte = {0x31,0x7E,0x97,0x77,0x56,0x27,0x31,0x31}.
    // The returned int32 is the low 32 bits of the FName (= the 29-bit pool_index +
    // 3 case bits in 0xE0000000); ResolveNamePtrFull below splits it into chunk_idx
    // and name_offset to walk the FNamePool.
    int32_t DecryptFFieldNameCI(uint64_t ff_addr) {
        if (!ff_addr) return 0;
        // Patch CL-1177146 PRIMARY PATH: FField+0x70 with the NEW pipeline
        // verified from IDA sub_4544A0 (FBoolProperty GetCPPType, the error
        // path that calls FName_ToString_Wide on FField NamePrivate):
        //   ROL32(13) per uint32-lane → lo64 → XOR(0x9A492C85DDF6F193) → ROL64(7)
        // Different from UObject 4-slot AND from 20260428's FField pipeline.
        {
            // CL-1177678: NamePrivate moved from +0x70 to +0x30. Use the
            // configured offset (auto-disc may have pre-set it) and fall
            // back to the new compile-time value.
            const uint64_t primary_off = ArcDecrypt::Offsets::FField::NamePrivate;
            alignas(16) uint8_t enc[16] = {};
            if (m_reader.Read(ff_addr + primary_off, enc, 16)) {
                bool any = false;
                for (uint8_t b : enc) if (b) { any = true; break; }
                if (any) {
                    uint64_t fn = DecryptFFieldNameSlot(enc);
                    int32_t ci = static_cast<int32_t>(fn & 0xFFFFFFFFu);
                    if (ci > 1 && (uint32_t)ci < 0x06A00000u) {
                        if (m_ffieldNameOff == 0) m_ffieldNameOff = primary_off;
                        return ci;
                    }
                }
            }
        }

        // Fallback: legacy auto-cal in case the +0x70 pipeline produces a
        // bogus CI (e.g., subclass with different layout). Tries UObject
        // 4-slot at various candidate offsets — kept for graceful degrade.
        // CL-1177146 (live-verified): NamePrivate is at +0x70 — same as
        // 20260428. Earlier auto-cal locked onto +0x118 because the bytes
        // there happened to decrypt for a single FField; +0x70 is the real
        // universal offset per IDA chain walker sub_353F40 and live SIMD
        // shape across PostProcessSettings/RigidBodyState samples.
        static constexpr uint64_t kCandOffs[] = {
            0x70,                                          // primary CL-1177146
            0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xE0,
            0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x110, 0x118,
        };
        if (m_ffieldNameOff != 0) {
            int32_t ci = TryDecodeFFieldNameAt(ff_addr, m_ffieldNameOff);
            if (ci > 1 && (uint32_t)ci < 0x06A00000u) return ci;
            return 0;
        }
        for (uint64_t off : kCandOffs) {
            int32_t ci = TryDecodeFFieldNameAt(ff_addr, off);
            if (ci <= 1) continue;
            uint64_t chunk_off = (static_cast<uint64_t>(ci) >> 8) & 0xFFFF00ULL;
            if (chunk_off == 0 || chunk_off > 0x6A0000ULL) continue;
            uint64_t name_ptr = ResolveNamePtrFull(ci);
            if (!name_ptr) continue;
            std::string nm = DecryptNameString(name_ptr);
            if (nm.empty()) continue;
            bool printable = true;
            int letters = 0;
            for (char c : nm) {
                if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')) ++letters;
                else if (!((c>='0'&&c<='9')||c=='_')) { printable = false; break; }
            }
            if (!printable || letters < 2) continue;
            m_ffieldNameOff = off;
            std::printf("[ffield] auto-calibrated NamePrivate offset = +0x%llX (sample name='%s' CI=%d)\n",
                (unsigned long long)off, nm.c_str(), ci);
            return ci;
        }
        return 0;
    }

private:
    int32_t TryDecodeFFieldNameAt(uint64_t ff_addr, uint64_t off) {
        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(ff_addr + off, enc, 16)) return 0;
        bool any = false;
        for (uint8_t b : enc) if (b) { any = true; break; }
        if (!any) return 0;
        uint64_t dec = DecryptUObjSlotNew(enc);
        return static_cast<int32_t>(dec & 0xFFFFFFFFu);
    }
public:

    // ── FFieldClass → type name comp_index ───────────────────────────────
    // Verified against CL-1177146 IDA in FFieldClass ctor sub_3E80E0.
    //
    // The slot at FFieldClass+NamePrivateOff is an OBFUSCATED 8-byte FName
    // HANDLE (NOT a CompIndex). The encryption pipeline is:
    //   handle = sub_232730(wide_string)           ; FName interner returns 8-byte handle
    //   complex(handle) = ROL64(handle, 32)        ; observed: (~A&K1 | A&K2) ^ ... = A | B = ROL64
    //   v9 = PSHUFLW(complex(handle), 27)
    //   stored = ROL32(v9, 25) ^ KEY               ; 16 bytes at fclass+offset
    //
    // Inverse (this function):
    //   tmp = stored ^ KEY                         ; (lo64 of XOR const used)
    //   tmp = ROL32(tmp, 7) per uint32 lane        ; reverse ROL32(25) ; PSRLD 0x19 | PSLLD 7
    //   tmp = PSHUFLW(tmp, 0x1B)                   ; PSHUFLW(0x1B) is involution
    //   tmp = lo64(tmp)
    //   handle = ROL64(tmp, 32)                    ; reverse ROL64(32) (its own inverse)
    //
    // The recovered `handle` is an FName HANDLE (8-byte encrypted entry ptr,
    // same form as inline-handle slots on UObjects). To turn it into a
    // CompIndex / name string, the caller passes it to DecryptByHandle.
    //
    // All parameters auto-discovered at runtime via Phase 7.
    // Returns the FName handle (8 bytes) or 0 if decode failed / not yet
    // calibrated.
    // Pure SIMD pipeline — operates on raw 16-byte slot bytes. Used by the
    // sdk_generator FFieldClass calibration loop which needs to test multiple
    // offsets without re-reading per offset, and by DecryptFFieldClassNameSlot
    // below.
    uint64_t DecryptFFieldClassNameSlotFromBytes(const uint8_t enc[16]) const {
        bool nonzero = false;
        for (int i = 0; i < 16; ++i) if (enc[i]) { nonzero = true; break; }
        if (!nonzero) return 0;

        if (AutoDiscovery::g_DiscoveredUObjSlot.Valid) {
            using namespace ArcDecrypt::v20260616;
            alignas(16) uint64_t K2[2] = { FCLASS_NAME_XOR2, FCLASS_NAME_XOR2 };
            alignas(16) uint64_t K1[2] = { FCLASS_NAME_XOR1, FCLASS_NAME_XOR1 };
            __m128i V     = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
            __m128i Step1 = _mm_xor_si128(V, _mm_load_si128(reinterpret_cast<const __m128i*>(K2)));
            __m128i Step2 = _mm_shufflelo_epi16(Step1, FCLASS_NAME_SHUF_DEC);
            __m128i Step3 = _mm_or_si128(
                _mm_slli_epi32(Step2, FCLASS_NAME_ROR32),
                _mm_srli_epi32(Step2, 32 - FCLASS_NAME_ROR32));
            __m128i Step4 = _mm_xor_si128(Step3, _mm_load_si128(reinterpret_cast<const __m128i*>(K1)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Step4);
            uint32_t Ci = static_cast<uint32_t>(Lo >> 32);
            if (Ci > 1 && Ci < 0x2000000u) return static_cast<uint64_t>(Ci);
        }

        {
            const auto& Disc = AutoDiscovery::g_DiscoveredFFieldClassName;
            if (Disc.Valid) {
                __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
                alignas(16) uint64_t XorBuf[2] = { Disc.XorLo64, Disc.XorLo64 };
                __m128i xored = _mm_xor_si128(v, _mm_load_si128(reinterpret_cast<const __m128i*>(XorBuf)));
                const int rol32 = Disc.Rol32Amount ? Disc.Rol32Amount : 7;
                __m128i rot = _mm_or_si128(
                    _mm_slli_epi32(xored, rol32),
                    _mm_srli_epi32(xored, 32 - rol32));
                __m128i s = _mm_shufflelo_epi16(rot, 0x1B);
                uint64_t lo;
                _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo), s);
                const int rol64 = Disc.Rol64Amount ? Disc.Rol64Amount : 32;
                uint64_t Out = (lo << rol64) | (lo >> (64 - rol64));
                uint32_t Ci = static_cast<uint32_t>(Out);
                if (Ci > 1 && Ci < 0x2000000u) return Out;
            }
        }

        if (m_pipeline == Pipeline::Build20260519) {
            using namespace ArcDecrypt::v20260519;
            alignas(16) static const uint8_t PshufbMask[16] = {
                0x06, 0x05, 0x03, 0x01, 0x02, 0x04, 0x07, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            __m128i V    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
            __m128i Mask = _mm_load_si128(reinterpret_cast<const __m128i*>(PshufbMask));
            __m128i Shuf = _mm_shuffle_epi8(V, Mask);
            __m128i Xord = _mm_xor_si128(Shuf, _mm_set_epi64x(0, static_cast<int64_t>(FFIELD_CLASS_NAME_KEY)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xord);
            uint64_t Out = (Lo << FFIELD_CLASS_NAME_ROL64) | (Lo >> (64 - FFIELD_CLASS_NAME_ROL64));
            uint32_t Ci = static_cast<uint32_t>(Out);
            if (Ci > 1 && Ci < 0x2000000u) return Out;
        }

        return 0;
    }

    uint64_t DecryptFFieldClassNameSlot(uint64_t fclass_addr) {
        if (!fclass_addr) return 0;
        const auto& Disc = AutoDiscovery::g_DiscoveredFFieldClassName;
        uint32_t NameOff = Disc.Valid ? Disc.NamePrivateOffset
            : (m_pipeline == Pipeline::Build20260519 ? ArcDecrypt::v20260519::FFIELD_CLASS_NAME_OFF : 0u);
        if (NameOff == 0) return 0;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(fclass_addr + NameOff, enc, 16)) return 0;
        return DecryptFFieldClassNameSlotFromBytes(enc);
    }

    // Convenience wrapper: decode FFieldClass name slot → FName handle →
    // entry pointer → CompIndex. Returns 0 on any failure in the chain.
    int32_t DecryptFFieldClassNameCI(uint64_t fclass_addr) {
        uint64_t handle = DecryptFFieldClassNameSlot(fclass_addr);
        if (!handle) return 0;
        // FFieldClass handle layout on CL-1177146 is `(Number << 32) | CI`
        // (post-decode), NOT an encrypted entry-pointer. Don't run it through
        // DecryptEntryHandle — that's for inline UObject handle slots and
        // its validation rejects valid CIs whose `bswap64(handle ^ XOR)`
        // happens to land in the module range. Just take the lo32 directly.
        uint32_t ci_candidate = static_cast<uint32_t>(handle);
        if (ci_candidate >= 2 && ci_candidate <= 0x2000000u) {
            return static_cast<int32_t>(ci_candidate);
        }
        return 0;
    }

    // ── ResolveNamePtrFull (CL-1177678) ──────────────────────────────────
    // Faithful port of sub_2311B0 → sub_245AA0 → sub_2458C0 from the live
    // binary. Pipeline:
    //
    //   sub_2311B0:
    //     v3   = ROL64(53)+shufflelo(75) on CompIndex
    //     v11  = (v3 AND xmmword_ADB8B10) | (v3 ANDNOT xmmword_AD9F790)
    //     [pass v11 down through sub_245AA0 → sub_2458C0]
    //     entry = bswap64( sub_245AA0_result XOR 0x5849435C00000000 )
    //
    //   sub_245AA0:
    //     wraps sub_2458C0; XORs result with 0x60801E00000000
    //
    //   sub_2458C0:
    //     v5   = shufflelo(46) XOR xmmword_ADD1110, then ROL64(11)
    //     v7   = u16(v5)                                  (= NameOffset/2)
    //     chunk = GNamePool + ((v5 >> 8) & 0xFFFF00)      (chunk address)
    //     v9   = FNV1a-32 hash of chunk address + 0x7000
    //     v10  = u8((-109*v9 - 58) ^ ((HP*v9 + HA) >> 16)) (block-pair selector)
    //     blk1 = chunk[0x7010 + 32*(v10 & 7)]
    //     blk2 = chunk[0x7010 + 32*((v10+1) & 7)]
    //     v13  = ROL32(12)+shufflelo(27)+XOR(xmmword_ADD0CA0) of blk1
    //     v14d = ROL32(12)+shufflelo(27)+XOR(xmmword_ADD0CA0) of blk2
    //     fnv_mix = FNV64 fold: P64 * ROL64(P64 * ROL64(v13,31) - F64, 36) - F64
    //     mixed = bswap64( (v13 + (fnv_mix XOR v14d) + 2*v7) XOR 0x42C32958 )
    //     return mixed
    //
    // Constants verified two ways: live Zydis on 0x2311B0 extracted the
    // imm64s (0x5849435C..., 0x9861E39DEBEE5306, 0x100000001B3) and IDA
    // decompile of 0x2458C0 confirmed the structural constants (HASH_ADD,
    // chunk offsets, FINAL_XOR). Note 0x9861E39DEBEE5306 = -0x679E1C621411ACFA
    // mod 2^64 — same FNV_OFFSET, just compiler emitted as `+ neg` vs `- pos`.
    //
    // .rdata RVAs are still hardcoded for now — TODO: auto-discover via the
    // FName-fn rip-rel scan (we already collect candidates in
    // g_DiscoveredFName.AllRDataLeas; just need the role-binding pass).
    uint64_t ResolveNamePtrFull(int32_t CompIndex) {
        if (CompIndex <= 0 || !m_keyLoaded) return 0;

        // ── Dispatch on active pipeline ──
        if (m_pipeline == Pipeline::Build20260519) {
            return ResolveNamePtr_Build20260519(CompIndex);
        }

        // .rdata constants (read once, cached via static + first-time fetch).
        // Live values at these RVAs verified to match IDA's identification.
        // TODO: auto-discover RVAs via Phase 5 Zydis call-chain bind pass.
        static thread_local bool s_loaded = false;
        alignas(16) static thread_local uint8_t s_AndMask[16];      // xmmword_ADB8B10
        alignas(16) static thread_local uint8_t s_AndNotMask[16];   // xmmword_AD9F790
        alignas(16) static thread_local uint8_t s_PxorIn[16];       // xmmword_ADD1110
        alignas(16) static thread_local uint8_t s_PxorBlock[16];    // xmmword_ADD0CA0

        if (!s_loaded) {
            if (!m_reader.Read(m_base + 0xADB8B10, s_AndMask,    16)) return 0;
            if (!m_reader.Read(m_base + 0xAD9F790, s_AndNotMask, 16)) return 0;
            if (!m_reader.Read(m_base + 0xADD1110, s_PxorIn,     16)) return 0;
            if (!m_reader.Read(m_base + 0xADD0CA0, s_PxorBlock,  16)) return 0;
            s_loaded = true;
        }

        // Cryptographic constants (verified IDA + matching compile-time imm64s
        // in the live binary).
        constexpr uint32_t HASH_PRIME       = 0x01000193u;
        constexpr uint32_t HASH_ADD         = 0x5AE45BC6u;          // 1524766406
        constexpr uint64_t CHUNK_SEED_OFF   = 28672ULL;             // 0x7000
        constexpr uint64_t CHUNK_BLOCKS_OFF = 28688ULL;             // 0x7010
        constexpr uint64_t FNV_PRIME_64     = 0x100000001B3ULL;
        constexpr uint64_t FNV_OFFSET       = 0x679E1C621411ACFAULL; // = -0x9861E39DEBEE5306
        constexpr uint32_t FINAL_XOR        = 0x42C32958u;
        constexpr uint64_t SUB_245AA0_XOR   = 0x60801E00000000ULL;
        constexpr uint64_t ENTRY_HANDLE_XOR = 0x5849435C00000000ULL;

        // ── sub_2311B0 phase 1: SIMD input transform ──
        __m128i Ci  = _mm_cvtsi32_si128(CompIndex);
        __m128i Rot = _mm_or_si128(_mm_slli_epi64(Ci, 53), _mm_srli_epi64(Ci, 11));
        __m128i V3  = _mm_shufflelo_epi16(Rot, 75);
        __m128i AND_M    = _mm_load_si128(reinterpret_cast<const __m128i*>(s_AndMask));
        __m128i ANDNOT_M = _mm_load_si128(reinterpret_cast<const __m128i*>(s_AndNotMask));
        __m128i V11 = _mm_or_si128(_mm_and_si128(V3, AND_M),
                                   _mm_andnot_si128(V3, ANDNOT_M));

        // ── sub_2458C0 phase 2: chunk address selector ──
        __m128i PXOR_IN = _mm_load_si128(reinterpret_cast<const __m128i*>(s_PxorIn));
        __m128i Sh      = _mm_shufflelo_epi16(V11, 46);
        __m128i V5_xor  = _mm_xor_si128(Sh, PXOR_IN);
        __m128i V5_rot  = _mm_or_si128(_mm_slli_epi64(V5_xor, 11),
                                       _mm_srli_epi64(V5_xor, 53));
        uint32_t V6 = static_cast<uint32_t>(_mm_cvtsi128_si32(V5_rot));
        uint16_t V7 = static_cast<uint16_t>(V6);

        uint64_t GNamesBase = m_base + FNAME_GNAMES_BASE_OFF;
        uint64_t Chunk      = GNamesBase + ((static_cast<uint64_t>(V6) >> 8) & 0xFFFF00ULL);

        // ── FNV chain on chunk address (hash → block-pair selector) ──
        uint64_t Addr   = Chunk + CHUNK_SEED_OFF;
        uint32_t AddrLo = static_cast<uint32_t>(Addr);
        uint32_t AddrHi = static_cast<uint32_t>(Addr >> 32);

        uint32_t StepA = HASH_PRIME * (AddrLo >> 6) + HASH_ADD;
        StepA = fn_rotl32(StepA, 14);
        uint32_t StepB = HASH_PRIME * StepA + AddrHi + HASH_ADD;
        StepB = fn_rotl32(StepB, 26);
        uint32_t V9 = HASH_PRIME * StepB + HASH_ADD;
        V9 = fn_rotl32(V9, 14);

        uint8_t V10 = static_cast<uint8_t>(
            (static_cast<uint32_t>(-109) * V9 - 58u) ^
            ((HASH_PRIME * V9 + HASH_ADD) >> 16)
        );

        // ── Block reads + decode ──
        uint64_t B1Addr = Chunk + CHUNK_BLOCKS_OFF + 32ULL * (V10 & 7u);
        uint64_t B2Addr = Chunk + CHUNK_BLOCKS_OFF + 32ULL * ((V10 + 1u) & 7u);

        alignas(16) uint8_t Sb1[16] = {}, Sb2[16] = {};
        if (!m_reader.Read(B1Addr, Sb1, 16)) return 0;
        if (!m_reader.Read(B2Addr, Sb2, 16)) return 0;

        __m128i PXOR_B = _mm_load_si128(reinterpret_cast<const __m128i*>(s_PxorBlock));
        // Note: ADD0CA0 is loaded with _mm_loadl_epi64 (8 bytes, hi8 zero); we
        // load 16 bytes here but the upper 8 are zero anyway because the
        // .rdata stored value has hi8 == 0 (verified live).
        auto XformBlock = [&](const uint8_t* BlkBytes) -> uint64_t {
            __m128i V    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(BlkBytes));
            __m128i Rotd = _mm_or_si128(_mm_slli_epi32(V, 12), _mm_srli_epi32(V, 20));
            __m128i Shf  = _mm_shufflelo_epi16(Rotd, 27);
            __m128i Xrd  = _mm_xor_si128(Shf, PXOR_B);
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xrd);
            return Lo;
        };
        uint64_t V13      = XformBlock(Sb1);
        uint64_t V14Decoded = XformBlock(Sb2);

        // ── FNV64 mixer ──
        uint64_t FnvStep1 = FNV_PRIME_64 * fn_rotl64(V13, 31) - FNV_OFFSET;
        uint64_t FnvStep2 = FNV_PRIME_64 * fn_rotl64(FnvStep1, 36) - FNV_OFFSET;

        uint64_t Mixed = (V13 + (FnvStep2 ^ V14Decoded) + 2ULL * V7) ^ FINAL_XOR;
        uint64_t Sub2458Result = __builtin_bswap64(Mixed);

        // ── sub_245AA0 wrap + sub_2311B0 final ──
        uint64_t Sub245Result = Sub2458Result ^ SUB_245AA0_XOR;
        uint64_t EntryPtr     = __builtin_bswap64(Sub245Result ^ ENTRY_HANDLE_XOR);

        return EntryPtr;
    }

    // ── ResolveNamePtr (Build 2026-05-19) ─────────────────────────────
    // RE'd from FName_Index2Name @ 0x2317B0 → sub_235220 → sub_23A1B0.
    // Pipeline:
    //   Stage A1: v = pshufb(cvtsi32_si128(CI), m_v519_stageA1Pshufb)
    //             v = ROL16(v, 4) ; v ^= m_v519_stageA1Xor
    //   Stage A2: v ^= m_v519_stageA2Xor
    //             v = ROL16(v, 12) ; v = pshufd(v, 0x44) ; v = ROL16(v, 4)
    //             v ^= m_v519_stageA1Xor
    //   Stage A3: v = move_epi64(v)   // zero hi 64
    //             v = (v & A3_AND) | (~v & A3_ANDNOT)
    //             v ^= A3_XOR ; v = ROL16(v, 12) ; v = pshufb(v, A3_PSHUFB_OUT)
    //   Outputs:   v6 = lo32(v); name_offset = u16(v6); chunk_offset = (v6>>8)&0xFFFF00
    //
    // CL-1201801 shard hash-table resolver. The binary's 3-function chain
    // (sub_2337C0 → sub_23A6B0 → sub_236E80) uses PSHUFB+ROL64+XOR layers
    // that algebraically cancel to identity: NameOff = CI & 0xFFFF,
    // ChunkOff = (CI >> 8) & 0xFFFF00. The triple bswap64+XOR across the
    // three return paths also cancels: entry_ptr = v14 directly.
    uint64_t ResolveNamePtr_Build20260519(int32_t CompIndex) {
        if (CompIndex <= 0 || !m_keyLoaded) return 0;

        const bool Is616 = AutoDiscovery::g_DiscoveredUObjSlot.Valid;
        uint32_t Ci       = static_cast<uint32_t>(CompIndex);
        uint16_t NameOff  = static_cast<uint16_t>(Ci & 0xFFFFu);
        uint32_t ChunkOff = (Ci >> 8) & 0xFFFF00u;

        uint64_t GnpRva = ArcDecrypt::RVA_GNAMES_BASE
                         ? ArcDecrypt::RVA_GNAMES_BASE
                         : ArcDecrypt::v20260519::RVA_GNAMEPOOL;
        uint64_t ChunkAddr = m_base + GnpRva + ChunkOff;

        uint8_t Bidx1, Bidx2;
        uint64_t BlockBase;

        if (Is616) {
            namespace V616 = ArcDecrypt::v20260616;
            uint64_t HashAddr = ChunkAddr + V616::SHARD_HASH_SEED_OFF;
            uint32_t HLo = static_cast<uint32_t>(HashAddr);
            uint32_t HHi = static_cast<uint32_t>(HashAddr >> 32);

            uint32_t S1 = fn_rotl32(HLo, V616::SHARD_HASH_ROL_A);
            uint32_t S2 = V616::HASH_PRIME * S1 + V616::SHARD_HASH_ADD;
            uint32_t S3 = fn_rotl32(S2, V616::SHARD_HASH_ROL_B);
            uint32_t S4 = V616::HASH_PRIME * S3 + HHi + V616::SHARD_HASH_ADD;
            uint32_t S5 = fn_rotl32(S4, V616::SHARD_HASH_ROL_A);
            uint32_t S6 = V616::HASH_PRIME * S5 + V616::SHARD_HASH_ADD;
            uint32_t V20 = fn_rotl32(S6, V616::SHARD_HASH_ROL_B);

            uint8_t Pa = static_cast<uint8_t>(static_cast<int8_t>(-109) * static_cast<int>(V20) + 54);
            uint8_t Pb = static_cast<uint8_t>((V616::HASH_PRIME * V20 + V616::SHARD_HASH_ADD) >> 16);
            uint8_t V10 = Pa ^ Pb;
            Bidx1 = V10 & 7u;
            Bidx2 = (V10 + 1u) & 7u;
            BlockBase = ChunkAddr + V616::SHARD_BLOCK_BASE_OFF;
        } else {
            using namespace ArcDecrypt::v20260519;
            uint64_t HashAddr = ChunkAddr + SHARD_HASH_SEED_OFF;
            uint32_t HLo = static_cast<uint32_t>(HashAddr);
            uint32_t HHi = static_cast<uint32_t>(HashAddr >> 32);

            uint32_t S1 = fn_rotl32(HLo, SHARD_HASH_ROL_A);
            uint32_t S2 = HASH_PRIME * S1 + SHARD_HASH_ADD;
            uint32_t S3 = fn_rotl32(S2, SHARD_HASH_ROL_B);
            uint32_t S4 = HASH_PRIME * S3 + HHi + SHARD_HASH_ADD;
            uint32_t S5 = fn_rotl32(S4, SHARD_HASH_ROL_A);
            uint32_t S6 = HASH_PRIME * S5 + SHARD_HASH_ADD;
            uint32_t V9 = HASH_PRIME * (S6 >> 6) + SHARD_HASH_ADD;

            uint8_t V10 = static_cast<uint8_t>(V9) ^ static_cast<uint8_t>(V9 >> 16);
            Bidx1 = V10 & 7u;
            Bidx2 = (V10 + 1u) & 7u;
            BlockBase = ChunkAddr + SHARD_BLOCK_BASE_OFF;
        }

        alignas(16) uint8_t Sb1[16] = {}, Sb2[16] = {};
        if (!m_reader.Read(BlockBase + 32ULL * Bidx1, Sb1, 16)) return 0;
        if (!m_reader.Read(BlockBase + 32ULL * Bidx2, Sb2, 16)) return 0;

        auto DecBlock = [&](const uint8_t* Raw) -> uint64_t {
            __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Raw));
            if (Is616) {
                namespace V616 = ArcDecrypt::v20260616;
                V = _mm_or_si128(_mm_slli_epi64(V, V616::ENTRY_ROL64),
                                 _mm_srli_epi64(V, 64 - V616::ENTRY_ROL64));
                alignas(16) uint8_t Mask[16], Xk[16];
                std::memcpy(Mask, V616::ENTRY_PSHUFB_MASK, 16);
                std::memcpy(Xk,   V616::ENTRY_XOR_MASK,    16);
                V = _mm_shuffle_epi8(V, _mm_load_si128(reinterpret_cast<const __m128i*>(Mask)));
                V = _mm_xor_si128(V, _mm_load_si128(reinterpret_cast<const __m128i*>(Xk)));
                uint64_t Lo;
                _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
                return Lo ^ V616::ENTRY_XOR;
            }
            using namespace ArcDecrypt::v20260519;
            V = _mm_shufflelo_epi16(V, BLOCK_SHUF_A);
            V = _mm_or_si128(_mm_slli_epi64(V, BLOCK_ROL),
                             _mm_srli_epi64(V, 64 - BLOCK_ROL));
            V = _mm_shufflelo_epi16(V, BLOCK_SHUF_B);
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            return Lo;
        };
        uint64_t Block1 = DecBlock(Sb1);
        uint64_t Block2 = DecBlock(Sb2);

        uint64_t Fv1, Fv2;
        if (Is616) {
            namespace V616 = ArcDecrypt::v20260616;
            Fv1 = V616::FNV_PRIME * fn_rotl64(Block1, V616::FNV_ROL1) + V616::FNV_ADD;
            Fv2 = V616::FNV_PRIME * fn_rotl64(Fv1,    V616::FNV_ROL2) + V616::FNV_ADD;
        } else {
            using namespace ArcDecrypt::v20260519;
            Fv1 = FNV_PRIME * fn_rotl64(Block1, FNV_ROL1) + FNV_ADD;
            Fv2 = FNV_PRIME * fn_rotl64(Fv1,    FNV_ROL2) + FNV_ADD;
        }

        uint64_t EntryPtr = Block1 + (Block2 ^ Fv2) + 2ULL * NameOff;
        return EntryPtr;
    }

    uint64_t ResolveNamePtr(int32_t comp_index) {
        return ResolveNamePtrFull(comp_index);
    }

    // Legacy alias kept for callers that pass a pre-decoded index.
    uint64_t ResolveNamePtrFromDecoded(uint32_t decoded_index) {
        return ResolveNamePtrFull(static_cast<int32_t>(decoded_index));
    }

    // ── Debug trace for a single CI — prints all intermediate pipeline values ──
    void DebugResolve(int32_t comp_index) {
        std::printf("[dbg] DebugResolve(CI=%d)\n", comp_index);
        if (!comp_index || !m_keyLoaded) { std::printf("  -> early exit\n"); return; }

        uint64_t entry_ptr = ResolveNamePtrFull(comp_index);
        std::printf("  entry_ptr=0x%016llX\n", (unsigned long long)entry_ptr);
        if (!entry_ptr) return;

        uint16_t hdr = 0;
        bool rh = m_reader.Read(entry_ptr, &hdr, 2);
        std::printf("  hdr read=%s  hdr=0x%04X\n", rh?"ok":"FAIL", (unsigned)hdr);
        if (rh && hdr) {
            int  length = static_cast<int>((static_cast<uint16_t>(hdr << 2) | (hdr >> 14)) & 0x3FF);
            bool isWide = (hdr & 0x100u) != 0;
            std::printf("  isWide=%d  length=%d\n", isWide, length);
            std::string s = DecryptNameString(entry_ptr);
            std::printf("  -> string='%s'\n", s.c_str());
        }
    }

    // ── DecryptNameString (CL-1177678) ─────────────────────────────────
    // Direct port of sub_23F2D0 (FNameEntry_AppendNameToString) verified
    // by IDA decompile. Layout differs from prior patches:
    //   header: u16
    //     bit 0       = isWide (NOT bit 8/15 as on older patches)
    //     length      = (hdr & 0x3FE) | (hdr >> 15)
    //   key init      = (u16)(length - 10563)        -- was -25107 on 20260428
    //   per pair:
    //     ANSI:  byte[i] ^= u8(keystream_u16[(key+i) & 0x3F] >> 3)
    //     WIDE:  word[i] ^= keystream_u16[(key+i) & 0x3F]
    //   key advances by 1 per byte (ANSI) / per word (WIDE).
    //   The IDA decompile shows a SIMD batch optimization that processes
    //   16 bytes at a time when length >= 16 with specific alignment;
    //   our scalar implementation produces the same output (just slower)
    //   because both compute byte[i] ^= keystream[(key+i)&0x3F] >> bitshift.
    std::string DecryptNameString(uint64_t NameEntryPtr) {
        if (!NameEntryPtr || !m_keyLoaded) return {};

        // ── Dispatch on active pipeline ──
        if (m_pipeline == Pipeline::Build20260519) {
            return DecryptNameString_Build20260519(NameEntryPtr);
        }

        uint16_t Header = 0;
        if (!m_reader.Read(NameEntryPtr, &Header, 2) || !Header) return {};

        bool IsWide = (Header & 1u) != 0;
        int Length = (Header & 0x3FE) | (Header >> 15);
        if (Length <= 0 || Length > 1023) return {};

        int ByteCount = IsWide ? Length * 2 : Length;
        if (ByteCount > 2048) ByteCount = 2048;

        std::vector<uint8_t> Buf(ByteCount, 0);
        if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), ByteCount)) return {};

        uint16_t Key = static_cast<uint16_t>(Length - 10563);

        if (!IsWide) {
            for (int I = 0; I < Length; ++I) {
                Buf[I] ^= static_cast<uint8_t>(m_keyTable[(Key + I) & 0x3F] >> 3);
            }
            return std::string(reinterpret_cast<char*>(Buf.data()), Length);
        } else {
            auto* WBuf = reinterpret_cast<uint16_t*>(Buf.data());
            for (int I = 0; I < Length; ++I) {
                WBuf[I] ^= m_keyTable[(Key + I) & 0x3F];
            }
            std::string Result;
            Result.reserve(Length);
            for (int J = 0; J < Length; ++J) {
                if (WBuf[J]) Result += static_cast<char>(WBuf[J] & 0xFF);
            }
            return Result;
        }
    }

    // ── DecryptNameString (CL-1201801) ───────────────────────────────────
    // RE'd from FNameEntry_DecryptAndAppend @ sub_24AB20. Header format and
    // decrypt algorithm changed from LCG-based to sequential keytable walk.
    //   Header:
    //     length = (h & 0x3F) | ((h >> 1) & 0x3C0)    // 10-bit (6+4)
    //     isWide = (h & 0x40) != 0                     // bit 6
    //   Narrow: byte[i] ^= (u8)(keytable[((len - 93 + i) & 0x3F)] >> 3)
    //   Wide:   word[i] ^=      keytable[((len - 93 + i) & 0x3F)]
    std::string DecryptNameString_Build20260519(uint64_t NameEntryPtr) {
        using namespace ArcDecrypt::v20260519;

        uint16_t Header = 0;
        if (!m_reader.Read(NameEntryPtr, &Header, 2) || !Header) return {};

        int  Length = static_cast<int>((Header & HDR_LENGTH_LO_MASK)
                                       | ((static_cast<unsigned>(Header) >> HDR_LENGTH_HI_SHIFT) & HDR_LENGTH_HI_MASK));
        bool IsWide = (Header & HDR_IS_WIDE_BIT) != 0;
        if (Length <= 0 || Length > 1023) return {};

        uint8_t KeyStart = static_cast<uint8_t>(Length + KEY_INIT_BIAS_NARROW);

        if (!IsWide) {
            std::vector<uint8_t> Bytes(Length, 0);
            if (!m_reader.Read(NameEntryPtr + 2, Bytes.data(), Length)) return {};

            for (int I = 0; I < Length; ++I) {
                Bytes[I] ^= static_cast<uint8_t>(m_keyTable[(KeyStart + I) & KEY_INDEX_MASK] >> 3);
            }

            std::string Out;
            Out.reserve(Length);
            for (int J = 0; J < Length; ++J) {
                if (!Bytes[J]) break;
                Out.push_back(static_cast<char>(Bytes[J]));
            }
            return Out;
        } else {
            std::vector<uint16_t> Wides(Length, 0);
            if (!m_reader.Read(NameEntryPtr + 2, Wides.data(),
                               static_cast<size_t>(Length) * sizeof(uint16_t))) return {};

            for (int I = 0; I < Length; ++I) {
                Wides[I] ^= m_keyTable[(KeyStart + I) & KEY_INDEX_MASK];
            }

            std::string Out;
            Out.reserve(Length);
            for (int J = 0; J < Length; ++J) {
                if (!Wides[J]) break;
                Out.push_back(static_cast<char>(Wides[J] & 0xFFu));
            }
            return Out;
        }
    }

    // ── Patch 20260421: handle → FNameEntry pointer ──────────────────────
    // The 16-byte inline FName field stores an obfuscated FNameEntry pointer
    // directly; the FNV/CI chain is bypassed. Decrypt:
    //     entry_ptr = bswap64(handle ^ 0x59B07C3D00000000)
    // Probe both qwords of the 16B field (patch-20260421 FName layout stores
    // the handle at one of {qword[0], qword[1]} depending on field kind);
    // accept the first qword whose decrypt lands on a readable FNameEntry.
    std::string GetNameByHandle(uint64_t obj_ptr, uint64_t fname_off) {
        if (!obj_ptr || !m_keyLoaded) return {};
        uint8_t bytes[16] = {};
        if (!m_reader.Read(obj_ptr + fname_off, bytes, 16)) return {};

        auto tryHandle = [&](uint64_t h) -> std::string {
            if (!h || h == ArcDecrypt::Patch20260421::ENTRY_HANDLE_XOR) return {};
            uint64_t entry = ArcDecrypt::Patch20260421::DecryptEntryHandle(h);
            if (entry < 0x10000ULL || entry >= 0x800000000000ULL) return {};
            // Reject pointers that land in the module image — valid entries
            // live on the heap/FNamePool pages.
            if (entry >= m_base && entry < m_base + 0x10000000ULL) return {};
            return DecryptNameString(entry);
        };

        uint64_t h0 = 0, h1 = 0;
        std::memcpy(&h0, bytes + 0, 8);
        std::memcpy(&h1, bytes + 8, 8);
        std::string s = tryHandle(h0);
        if (!s.empty()) return s;
        return tryHandle(h1);
    }

    // ── Full pipeline: object pointer → name string ───────────────────────
    std::string GetName(uint64_t obj_ptr) {
        if (!obj_ptr || !m_keyLoaded) return {};

        auto isSaneName = [](const std::string& s) {
            if (s.empty() || s.size() > 128) return false;
            int printable = 0;
            for (unsigned char c : s)
                if (c >= 32 && c <= 126)
                    ++printable;
            return printable * 5 >= static_cast<int>(s.size()) * 4;
        };

        // Emu-primary path: skip every static FNameEntry/FNamePool-based
        // resolver. Slot decrypt (GetCompIndex) is the only static piece left
        // — and that's auto-discovered (Phase 4 + Phase 0 ENTRY_HANDLE_XOR
        // extract), not patch-bound. Routing through CompIndexToNameLenient
        // hits Unicorn for the actual CI→string lookup.
        if (m_emuPrimary && m_emuFallback) {
            int32_t comp = GetCompIndex(obj_ptr);
            if (comp > 0) {
                std::string out = CompIndexToNameLenient(comp);
                if (isSaneName(out)) return out;
            }
            // Last-ditch: the inline-handle path (also static, but uses
            // auto-extracted ENTRY_HANDLE_XOR — sometimes survives even when
            // the FNamePool pipeline drifts).
            if (m_primaryHandleOffset) {
                std::string s = GetNameByHandle(obj_ptr, m_primaryHandleOffset);
                if (isSaneName(s)) return s;
            }
            return {};
        }

        // Patch 20260421 primary path: inline encrypted FName handle at
        // obj+0x28 → bswap64(h ^ sentinel) = FNameEntry*. Try the calibrated
        // primary offset first (set by SDKDumper::CalibrateInlineHandleOffset
        // — only fires when the probe finds an offset with ≥25% hit rate);
        // fall back to the original 3-offset shortlist that's been verified
        // across recent patches. A wider scan would risk hitting wrong-but-
        // sane-looking offsets for UFunction-class objects.
        if (m_primaryHandleOffset) {
            std::string s = GetNameByHandle(obj_ptr, m_primaryHandleOffset);
            if (isSaneName(s)) return s;
        }
        for (uint64_t off : {uint64_t(0x28), uint64_t(0x18), uint64_t(0x30)}) {
            if (off == m_primaryHandleOffset) continue;  // already tried
            std::string s = GetNameByHandle(obj_ptr, off);
            if (isSaneName(s)) return s;
        }

        int32_t comp = GetCompIndex(obj_ptr);
        if (comp > 0) {
            uint64_t nptr = ResolveNamePtrFull(comp);
            if (nptr) {
                std::string out = DecryptNameString(nptr);
                if (isSaneName(out)) return out;
            }
        }

        return {};
    }

    // ── Resolve comp_index → string ──────────────────────────────────────
    // Strict: identifier-shaped only (alphanum + _:./- space). Used for
    // class/enum/struct names that go straight into the SDK output.
    // When m_emuPrimary is set, hits Unicorn first and only falls back to
    // the static SIMD pipeline if emu fails — used on patches where the
    // FNamePool resolver / FNameEntry decrypt has drifted.
    std::string CompIndexToName(int32_t comp_index) {
        // Emu-primary: skip static entirely. ResolveNamePtrFull's compile-time
        // BLOCK1_XOR / BLOCK2_AND constants drift every patch — on a relocated
        // build the static path returns plausible-looking but wrong garbage,
        // which would defeat the IsStrictName filter half the time. Trusting
        // emu only is both correct and faster than running the static path
        // first to throw the result away.
        if (m_emuPrimary) {
            std::string e = TryEmuFallback(comp_index);
            return IsStrictName(e) ? e : std::string{};
        }
        std::string s = StaticResolve(comp_index);
        if (IsStrictName(s)) return s;
        std::string e = TryEmuFallback(comp_index);
        return IsStrictName(e) ? e : std::string{};
    }

    // Lenient: any mostly-printable ASCII. Used for FField names which can
    // legitimately contain weirder characters.
    std::string CompIndexToNameLenient(int32_t comp_index) {
        if (m_emuPrimary) {
            std::string e = TryEmuFallback(comp_index);
            return IsLenientName(e) ? e : std::string{};
        }
        std::string s = StaticResolve(comp_index);
        if (IsLenientName(s)) return s;
        std::string e = TryEmuFallback(comp_index);
        if (IsLenientName(e)) return e;
        if (m_lenientFailCount < 20) {
            ++m_lenientFailCount;
            uint64_t nptr = ResolveNamePtrFull(comp_index);
            uint32_t ci_u = static_cast<uint32_t>(comp_index);
            uint16_t name_off = static_cast<uint16_t>(ci_u & 0xFFFFu);
            uint32_t chunk_off = (ci_u >> 8) & 0xFFFF00u;
            std::printf("[fname-dbg] CI=%d (0x%X) chunk_off=0x%X name_off=0x%X entry_ptr=0x%llX",
                comp_index, ci_u, chunk_off, name_off, (unsigned long long)nptr);
            if (nptr) {
                uint8_t hdr_bytes[4] = {};
                bool ok = m_reader.Read(nptr, hdr_bytes, 4);
                std::printf(" hdr_read=%s hdr=[%02X %02X %02X %02X]",
                    ok ? "ok" : "FAIL", hdr_bytes[0], hdr_bytes[1], hdr_bytes[2], hdr_bytes[3]);
                if (ok) {
                    std::string raw = DecryptNameString(nptr);
                    std::printf(" decrypt='%s'", raw.empty() ? "<empty>" : raw.c_str());
                }
            }
            std::printf(" emu='%s'\n", e.empty() ? "<empty>" : e.c_str());
        }
        return {};
    }

    // ── Patch 20260421: 8-byte obfuscated handle → name string ───────────
    // Used by callers that already have the raw 8-byte handle in hand
    // (e.g. UEnum::Names entries on patch 20260421 where the name field is
    // 8 bytes of obfuscated handle, not a 4-byte CompIndex).
    std::string DecryptByHandle(uint64_t handle) {
        if (!handle || !m_keyLoaded) return {};
        if (handle == ArcDecrypt::Patch20260421::ENTRY_HANDLE_XOR) return {};
        uint64_t entry = ArcDecrypt::Patch20260421::DecryptEntryHandle(handle);
        if (entry < 0x10000ULL || entry >= 0x800000000000ULL) return {};
        // Module-image addresses are not valid pool entries.
        if (entry >= m_base && entry < m_base + 0x10000000ULL) return {};
        return DecryptNameString(entry);
    }

    // ── Old UProperty FName (obj+0x50) → comp_index ─────────────────────
    // UProperty (UObject subclass) stores its FName at obj+0x50 with a different
    // encrypt pipeline than the modern UObject slot system.
    // Confirmed from sub_140441080 (ctor) and sub_1403D5A10 (name reader):
    //   Decrypt: load16(obj+0x50) → inv_PSHUFB({4,0,6,1,5,3,7,2,...})
    //            → ROR32_epi32(6) → XOR(0x1DB6DE4B85F51BC2) → ROL64(32) → lo32 = CI
    int32_t GetUPropertyCompIndex(uint64_t obj) {
        if (!obj || !m_keyLoaded) return 0;

        alignas(16) uint8_t buf[16] = {};
        if (!m_reader.Read(obj + ArcDecrypt::UPROP_FNAME_OFFSET, buf, 16)) return 0;

        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf));

        // Inverse PSHUFB mask: {4,0,6,1,5,3,7,2, 4,0,6,1,5,3,7,2}
        // (derived from forward mask {1,3,7,5,0,4,2,6,...} at xmmword_14AC42090)
        alignas(16) static const uint8_t kInvMask[16] =
            {4,0,6,1,5,3,7,2, 4,0,6,1,5,3,7,2};
        __m128i inv_shuf = _mm_load_si128(reinterpret_cast<const __m128i*>(kInvMask));
        __m128i v2 = _mm_shuffle_epi8(v, inv_shuf);

        // ROR32_epi32(6) = ROL32_epi32(26)
        __m128i v3 = _mm_or_si128(_mm_srli_epi32(v2, 6), _mm_slli_epi32(v2, 26));

        // Extract lo64 and XOR with key
        uint64_t lo64;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo64), v3);
        lo64 ^= ArcDecrypt::UPROP_FNAME_XOR_KEY;

        // ROL64(lo64, 32): CI is in lo32 of the rotated value = hi32 of lo64
        uint32_t ci = static_cast<uint32_t>(lo64 >> 32);
        return static_cast<int32_t>(ci);
    }

    // ── Old UProperty object address → name string ───────────────────────
    std::string GetUPropertyName(uint64_t obj) {
        int32_t ci = GetUPropertyCompIndex(obj);
        if (!ci) return {};
        return CompIndexToName(ci);
    }

    // ── FField address → name string (patch 20260409) ───────────────────
    std::string GetFFieldName(uint64_t ff_addr) {
        int32_t ci = DecryptFFieldNameCI(ff_addr);
        if (ci <= 0) return {};
        return CompIndexToNameLenient(ci);
    }

    // ── FFieldClass address → type name string ───────────────────────────
    std::string GetFFieldClassName(uint64_t fclass_addr) {
        int32_t ci = DecryptFFieldClassNameCI(fclass_addr);
        if (!ci) return {};
        return CompIndexToName(ci);
    }

    // ── Outer pointer from one of the 4 slots (patch 20260421) ───────────
    // Tries all 4 slots and returns the first heap-pointer candidate that's
    // distinct from GetClassPrivate's answer. Good enough for package walks.
    uint64_t GetOuterPtr(uint64_t obj_ptr) {
        if (!obj_ptr || !m_keyLoaded) return 0;
        // 20260428: same swapped-halves shape as GetClassPrivate. See comment there.
        auto tryDecode = [&](int slot) -> uint64_t {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_ptr + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) return 0;
            uint64_t dec = DecryptUObjSlotNew(enc);
            if (!dec) return 0;
            uint32_t lo = static_cast<uint32_t>(dec);
            uint32_t hi = static_cast<uint32_t>(dec >> 32);
            if (hi < 0x10000u) return 0;  // FName-shaped, not pointer
            uint64_t ptr = (static_cast<uint64_t>(lo) << 32) | hi;
            if (ptr < 0x100000ULL || ptr >= 0x800000000000ULL) return 0;
            return ptr;
        };
        uint32_t os = (m_pipeline == Pipeline::Build20260519 || AutoDiscovery::g_DiscoveredUObjSlot.Valid)
                          ? Build20260519_ObjOuterSlot(obj_ptr) : ObjOuterSlot(obj_ptr);
        uint64_t p = tryDecode(static_cast<int>(os));
        if (p) return p;
        // Fallback: any heap-pointer slot distinct from class.
        uint64_t cls = GetClassPrivate(obj_ptr);
        for (int slot = 0; slot < 4; ++slot) {
            if (static_cast<uint32_t>(slot) == os) continue;
            uint64_t d = tryDecode(slot);
            if (d && d != cls) return d;
        }
        return 0;
    }

    // ── Walk outer chain → UPackage pointer ──────────────────────────────
    //
    // Patch-20260428 reality (verified live across 20+ classes via
    // tools/probe_pkg_resolver.py):
    //   • The slot index that holds the UPackage outer is INTRINSIC to each
    //     object — it is NOT a function of obj_ptr. Different sibling classes
    //     in the same package put the package pointer in slots {0,1,2,3}.
    //   • The hash-based outer-slot picker (`ObjOuterSlot`) is correct for
    //     only ~10-20% of objects; on the remainder it points at the
    //     metaclass slot (e.g. 0x2A40E800 = "Class"), causing
    //     `GetPackagePtr → GetOuterPtr` to terminate at the metaclass and
    //     mis-bucket the class as `/Script/Class.X`.
    //
    // Fix: probe ALL 4 pointer-shape slots, classify by the target's vtable.
    //   1. UPackage detected (vtable == m_base + UPACKAGE_VT_RVA) → done.
    //   2. Otherwise pick the first slot whose target is a UObject (vtable in
    //      module range, not yet visited, not a self-loop) and recurse. We
    //      deliberately do NOT skip slots that resolve to the metaclass —
    //      walking the metaclass UClass eventually reaches its own package
    //      (/Script/CoreUObject for "Class", /Script/Engine for engine
    //      metaclasses, /Game/.../Foo for blueprint classes). That package
    //      is a reasonable owner for the original object and is strictly
    //      better than terminating at the metaclass and labelling
    //      everything `/Script/Class.X`.
    //   3. After max_depth or no progress, return the deepest non-package
    //      pointer we reached so the caller can still try a name lookup.
    //
    // Live verification (tools/estimate_recovery.py against PID 11984):
    //   5303 / 5303 of the previously-mis-bucketed classes now resolve
    //   to a real /Script/X or /Game/X UPackage (chain terminates at a
    //   UPackage vtable, never stalls on a non-package UObject).
    //
    // The UPACKAGE_VT_RVA is auto-discovered at runtime via AutoDiscovery::
    // DiscoverEngineVTables (name-clusters: any UObject whose name starts
    // with "/" is a UPackage; the cluster's vtable IS UPACKAGE_VT_RVA). The
    // hardcoded fallback 0xADBC9A0 is the CL-1177146 value, used only when
    // discovery hasn't run yet (e.g. during the very first GetPackagePtr
    // call before the post-init Phase-1 hook fires).
    //
    // Without the correct value, GetPackagePtr never recognizes that the
    // outer chain has reached a real UPackage and instead stalls at the
    // UPackage METACLASS UClass — whose own NamePrivate is literally
    // "Package", causing every recovered class to bucket into
    // `/Script/Package.X`.
    static constexpr uint64_t UPACKAGE_VT_RVA_FALLBACK = 0xADBC9A0ULL;
    static uint64_t UPackageVtRva() {
        uint64_t Rva = AutoDiscovery::g_DiscoveredVTables.PackageRVA;
        return Rva ? Rva : UPACKAGE_VT_RVA_FALLBACK;
    }

    uint64_t GetPackagePtr(uint64_t obj_ptr) {
        if (!obj_ptr || !m_keyLoaded) return 0;
        const uint64_t upkg_vt = m_base + UPackageVtRva();
        const uint64_t mod_lo  = m_base;
        const uint64_t mod_hi  = m_base + 0x10000000ULL;

        uint64_t cur = obj_ptr;
        uint64_t last_uobj_outer = 0;  // best non-package pointer seen so far
        std::unordered_set<uint64_t> visited;

        auto tryDecode = [&](uint64_t base, int slot) -> uint64_t {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) return 0;
            uint64_t dec = DecryptUObjSlotNew(enc);
            if (!dec) return 0;
            uint32_t lo = static_cast<uint32_t>(dec);
            uint32_t hi = static_cast<uint32_t>(dec >> 32);
            if (hi < 0x10000u) return 0;  // FName-shaped
            uint64_t ptr = (static_cast<uint64_t>(lo) << 32) | hi;
            if (ptr < 0x100000ULL || ptr >= 0x800000000000ULL) return 0;
            return ptr;
        };
        auto readVT = [&](uint64_t p) -> uint64_t {
            uint64_t vt = 0;
            if (!m_reader.Read(p, &vt, 8)) return 0;
            return vt;
        };

        for (int depth = 0; depth < 24; ++depth) {
            if (!visited.insert(cur).second) break;  // cycle

            // Pass 1: any slot whose target *is* a UPackage → done.
            for (int slot = 0; slot < 4; ++slot) {
                uint64_t p = tryDecode(cur, slot);
                if (!p) continue;
                if (readVT(p) == upkg_vt) return p;
            }

            // Pass 2: pick a slot that points to a UObject (vtable in module
            // range). DON'T skip the self-class slot — even when the slot
            // we picked is the metaclass (e.g. "BlueprintGeneratedClass"),
            // walking through it eventually lands on its UPackage. That
            // package is *some* meaningful owner — the engine package for
            // engine metaclasses, the asset package for blueprint classes —
            // and is definitively better than terminating at the metaclass
            // and labelling everything `/Script/Class.X`.
            uint64_t next = 0;
            for (int slot = 0; slot < 4; ++slot) {
                uint64_t p = tryDecode(cur, slot);
                if (!p) continue;
                if (p == cur) continue;  // self-loop
                if (visited.count(p)) continue;
                uint64_t vt = readVT(p);
                if (vt < mod_lo || vt >= mod_hi) continue;
                next = p;
                break;
            }
            if (!next) {
                // No further outer; return the deepest non-package object
                // reached (caller will resolve its name and either match a
                // known package or report "Unknown").
                return last_uobj_outer ? last_uobj_outer : cur;
            }
            last_uobj_outer = next;
            cur = next;
        }
        return last_uobj_outer ? last_uobj_outer : cur;
    }

    // ── DecryptFNameRaw: UObject slot → raw 64-bit value (patch 20260414)
    // Pipeline: ROL32(15) → PSHUFB(mask) → ROL16(4) → extract lo64 → ROL64(32)
    // No XOR with sentinel!
    // PSHUFB mask: {0x05,0x02,0x07,0x06,0x01,0x00,0x04,0x03}
    uint64_t DecryptFNameRaw(__m128i enc) const {
        alignas(16) static const uint8_t ACTOR_SHUF_MASK[16] = {
            0x05,0x02,0x07,0x06,0x01,0x00,0x04,0x03,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };
        __m128i shuf = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(ACTOR_SHUF_MASK));
        __m128i rot32 = _mm_or_si128(_mm_slli_epi32(enc, 15), _mm_srli_epi32(enc, 17));
        __m128i shuffled = _mm_shuffle_epi8(rot32, shuf);
        __m128i rot16 = _mm_or_si128(_mm_slli_epi16(shuffled, 4), _mm_srli_epi16(shuffled, 12));
        return fn_rotl64(u64_lo_xmm(rot16), 32);
    }

    // ── DecryptSlot16: UObject FName slot → comp_index (int32) ──────────
    uint64_t DecryptSlot16(const uint8_t enc[16]) const {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        return DecryptFNameRaw(v);
    }

    // ── DecryptPtrSlot: UObject pointer slot → heap pointer ──────────────
    // Same pipeline as FName, but result interpreted as pointer (ROL64(32) applied)
    uint64_t DecryptPtrSlot(const uint8_t enc[16]) const {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        return fn_rotl64(DecryptFNameRaw(v), 32);
    }

private:
    // Static decrypt path with no validation — returns whatever the pool
    // walk produced (possibly garbage). Callers apply their own filter.
    std::string StaticResolve(int32_t comp_index) {
        if (!comp_index || !m_keyLoaded) return {};
        uint64_t nptr = ResolveNamePtrFromDecoded(static_cast<uint32_t>(comp_index));
        if (!nptr) return {};
        return DecryptNameString(nptr);
    }

    // Static-path failure → ask Unicorn-emulated game function. Result is
    // cached (positive and negative) since each emu call costs ~ms. The
    // cache stores raw emu output (only sanitized for non-printable bytes
    // and length); callers apply their own strict/lenient filter.
    std::string TryEmuFallback(int32_t comp_index) {
        if (!m_emuFallback || comp_index <= 0) return {};
        auto it = m_emuCache.find(comp_index);
        if (it != m_emuCache.end()) return it->second;
        std::string s = m_emuFallback(comp_index);
        if (s.size() > 256) s.clear();
        for (unsigned char c : s) {
            if (c < 32 || c > 126) { s.clear(); break; }
        }
        m_emuCache.emplace(comp_index, s);
        return s;
    }

    // Strict identifier filter: alphanum + _:./- and space. Reject `?` and
    // any other non-identifier ASCII so emu garbage like "?????" cannot
    // sneak through to the SDK as an enum/class name.
    static bool IsStrictName(const std::string& s) {
        if (s.empty() || s.size() > 256) return false;
        for (unsigned char c : s) {
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == ':' ||
                  c == '/' || c == '.' || c == ' ' || c == '-'))
                return false;
        }
        return true;
    }

    // Lenient: mostly-printable ASCII (≥75% printable).
    static bool IsLenientName(const std::string& s) {
        if (s.empty() || s.size() > 256) return false;
        int bad = 0;
        for (unsigned char c : s)
            if (c < 32 || c > 126) ++bad;
        return bad * 4 <= static_cast<int>(s.size());
    }

    uint64_t       m_base;
    IMemoryReader& m_reader;
    bool           m_keyLoaded;
    uint16_t       m_keyTable[256];
    EmuFallback    m_emuFallback;
    std::unordered_map<int32_t, std::string> m_emuCache;
    bool           m_emuPrimary = false;       // see SetEmuPrimary()
    int            m_lenientFailCount = 0;
    uint64_t       m_primaryHandleOffset = 0;  // 0 = no calibration yet, fall back to candidate list
    uint64_t       m_ffieldNameOff = 0;        // 0 = uncalibrated; first valid offset wins

    // ── Pipeline selection (set in Init()) ──
    Pipeline       m_pipeline = Pipeline::CL1177146;

};

// ── Free-function shims ────────────────────────────────────────────────────
static inline std::string GetActorFNameString(uint64_t actor_base,
                                               uint64_t game_base,
                                               IMemoryReader& reader)
{
    FNameDecryptor dec(game_base, reader);
    dec.Init();
    return dec.GetName(actor_base);
}

static inline int32_t GetActorFNameId(uint64_t actor_base,
                                       uint64_t game_base,
                                       IMemoryReader& reader)
{
    FNameDecryptor dec(game_base, reader);
    return dec.GetCompIndex(actor_base);
}

} // namespace FName
