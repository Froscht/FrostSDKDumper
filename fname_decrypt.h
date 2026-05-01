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
    FNameDecryptor(uint64_t module_base, IMemoryReader& reader)
        : m_base(module_base), m_reader(reader), m_keyLoaded(false)
    {
        memset(m_keyTable,       0, sizeof(m_keyTable));
        memset(m_cidxXor1,       0, 16);
        memset(m_cidxXor3,       0, 16);
        memset(m_blkSlotShuf,    0, 16);
        memset(m_blkSlotShuf2,   0, 16);
        memset(m_blkHdrAnd,      0, 16);
        memset(m_blkHdrAndnot,   0, 16);
        memset(m_blkHdrShuf,     0, 16);
        memset(m_blkHdrXor,      0, 16);
    }

    bool Init() {
        if (m_keyLoaded) return true;

        uint64_t KtAddr = m_base + FNAME_KEY_TABLE_OFF;
        std::printf("[dbg] Reading FName key table @ 0x%llX ...\n", (unsigned long long)KtAddr);
        std::memset(m_keyTable, 0, sizeof(m_keyTable));
        if (!m_reader.Read(KtAddr, m_keyTable, 64 * sizeof(uint16_t))) {
            std::printf("[-] Failed to read FName key table\n");
            return false;
        }
        int Nonzero = 0;
        for (int I = 0; I < 64; ++I) Nonzero += m_keyTable[I] != 0;
        if (Nonzero < 32) {
            std::printf("[-] FName key table looks invalid at 0x%llX (nonzero=%d/64)\n",
                (unsigned long long)KtAddr, Nonzero);
            return false;
        }
        std::printf("[+] FName key table OK (first: 0x%04X 0x%04X 0x%04X 0x%04X)\n",
            m_keyTable[0], m_keyTable[1], m_keyTable[2], m_keyTable[3]);

        // SIMD tables for CIdx decode pipeline (patch 20260402)
        auto loadTable = [&](uint64_t rva, uint8_t* dst, const char* name) -> bool {
            if (!m_reader.Read(m_base + rva, dst, 16)) {
                std::printf("[-] Failed to read SIMD table %s @ RVA 0x%llX\n",
                    name, (unsigned long long)rva);
                return false;
            }
            return true;
        };

        // UObject slot decrypt tables (patch CL-1177146)
        if (!loadTable(ArcDecrypt::Patch20260421::UObjSlot20260421::RVA_SHUF_MASK, m_uobjShufMask, "uobjShufMask")) return false;
        {
            uint64_t Lo = ArcDecrypt::Patch20260421::UObjSlot20260421::SLOT_XOR_CONST;
            std::memcpy(&m_uobjXorConst[0], &Lo, 8);
            std::memcpy(&m_uobjXorConst[8], &Lo, 8);
        }
        // FField name decrypt constant (patch 20260421)
        if (!loadTable(ArcDecrypt::Patch20260421::FFieldName20260421::RVA_XOR_CONST, m_fFieldXorConst, "fFieldXorConst")) return false;

        // Patch 20260428 FNamePool resolver tables (best-effort: skip warnings
        // if pages aren't mapped — DecryptUObjSlotNew uses hardcoded MASK
        // bytes, but the resolver requires live values).
        loadTable(ArcDecrypt::Patch20260421::FNamePool20260428::RVA_GIDX_SHUF1,   m_p28_gidxShuf1,   "p28_gidxShuf1");
        loadTable(ArcDecrypt::Patch20260421::FNamePool20260428::RVA_GIDX_XOR1,    m_p28_gidxXor1,    "p28_gidxXor1");
        loadTable(ArcDecrypt::Patch20260421::FNamePool20260428::RVA_STAGE2_XOR,   m_p28_stage2Xor,   "p28_stage2Xor");
        loadTable(ArcDecrypt::Patch20260421::FNamePool20260428::RVA_EXTRACT_SHUF, m_p28_extractShuf, "p28_extractShuf");
        loadTable(ArcDecrypt::Patch20260421::FNamePool20260428::RVA_EXTRACT_XOR,  m_p28_extractXor,  "p28_extractXor");
        loadTable(ArcDecrypt::Patch20260421::FNamePool20260428::RVA_BLOCK_SHUF,   m_p28_blockShuf,   "p28_blockShuf");

        loadTable(RVA_CIDX_XOR1_OFF,          m_cidxXor1,      "cidxXor1");
        loadTable(RVA_CIDX_XOR3_OFF,          m_cidxXor3,      "cidxXor3");
        loadTable(RVA_BLOCK_HDR_AND_OFF,      m_blkHdrAnd,     "blkHdrAnd");
        loadTable(RVA_BLOCK_HDR_ANDNOT_OFF,   m_blkHdrAndnot,  "blkHdrAndnot");
        loadTable(RVA_BLOCK_HDR_SHUF_OFF,     m_blkHdrShuf,    "blkHdrShuf");
        loadTable(RVA_BLOCK_HDR_XOR_OFF,      m_blkHdrXor,     "blkHdrXor");
        loadTable(RVA_BLOCK_SLOT_SHUF_OFF,    m_blkSlotShuf,   "blkSlotShuf");
        loadTable(RVA_BLOCK_SLOT_SHUF2_OFF,   m_blkSlotShuf2,  "blkSlotShuf2");

        std::printf("[+] FName SIMD tables loaded OK\n");
        m_keyLoaded = true;
        return true;
    }

    bool IsInitialized() const { return m_keyLoaded; }

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
        return ArcDecrypt::GetFNameSlotIndex(obj_base);
    }

    // ── Hash-based slot selector (patch CL-1177146) ──────────────────────
    // Verified IDA lf50 sub_2CB4E0 / sub_2D6900 / sub_2D4500:
    //   s1 = P * ROL32(lo, 24) + ADD
    //   s2 = P * ROL32(s1, 25) + ADD
    //   t  = hi + s2
    //   s3 = P * ROL32(t, 24) + ADD
    //   v3 = P * (s3 >> 7) + ADD
    //   raw_idx   = (u8(v3) ^ BYTE2(v3)) & 3
    //   name_slot = (raw_idx ^ 2) & 3
    static uint32_t ObjSlotHash(uint64_t ObjPtr) {
        constexpr uint32_t P = 0x01000193u;
        constexpr uint32_t ADD = 0x8E195662u;
        uint64_t Ptr = ObjPtr + 0x10;
        uint32_t Lo = static_cast<uint32_t>(Ptr);
        uint32_t Hi = static_cast<uint32_t>(Ptr >> 32);
        uint32_t H = fn_rotl32(Lo, 24);
        H = P * H + ADD;
        H = fn_rotl32(H, 25);
        H = P * H + Hi + ADD;
        H = fn_rotl32(H, 24);
        H = P * H + ADD;
        H >>= 7;
        uint32_t V8 = P * H + ADD;
        return V8;
    }
    static uint32_t ObjNameSlot(uint64_t obj_ptr) {
        uint32_t v7 = ObjSlotHash(obj_ptr);
        uint8_t lo8 = static_cast<uint8_t>(v7);
        uint8_t hi8 = static_cast<uint8_t>(v7 >> 16);
        return (uint32_t)(((lo8 ^ hi8) & 3u) ^ 2u);
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
    // Outer-slot formula verified from UObject_GetOuter @ 0x23EA680 (20260430):
    //   slot = (((u8)v ^ BYTE2(v)) + 1) & 3
    static uint32_t ObjOuterSlot(uint64_t obj_ptr) {
        uint32_t V7 = ObjSlotHash(obj_ptr);
        uint8_t Lo8 = static_cast<uint8_t>(V7);
        uint8_t Byte2 = static_cast<uint8_t>(V7 >> 16);
        return (uint32_t)((((uint32_t)(Lo8 ^ Byte2)) + 1u) & 3u);
    }

    // ── Decrypt one UObject slot (patch CL-1177146) ──────────────────────
    // Verified IDA lf50 sub_2CB4E0 / sub_2D4500:
    //   v22 = loadl_epi64(0xAD93EF0)        // PSHUFB mask 06 05 02 03 04 01 00 07
    //   v23 = loadl_epi64(0xAD93F00)        // XOR const lo64 = 0x5EA772D07F910744
    //   dec = lo64( shuffle_epi8(slot, v22) XOR v23 )
    //   For NAME slot:    final = ROL64(dec, 32)  → lo32 = CI, hi32 = Number
    //   For pointer slots: dec is the heap pointer directly (no ROL64)
    // We always apply ROL64(32) here; callers that interpret the result as
    // a pointer (GetClassPrivate / GetAllClassCandidates) re-swap halves.
    uint64_t DecryptUObjSlotNew(const uint8_t enc[16]) const {
        using namespace ArcDecrypt::Patch20260421::UObjSlot20260428;
        const auto& Disc = AutoDiscovery::g_DiscoveredUObjSlot;

        // Auto-discovered values take priority. If discovery hasn't run or
        // failed, fall back to compile-time constants from arc_decrypt.h.
        alignas(16) uint8_t KShufMask[16] = {};
        uint64_t XorVal;
        int      Rol64Amt;
        if (Disc.Valid) {
            std::memcpy(KShufMask, Disc.ShufMaskBytes, 8);
            XorVal   = Disc.XorScalar;
            Rol64Amt = Disc.Rol64Amount;
        } else {
            const uint8_t kFallback[8] = {
                SHUF_MASK_BYTES[0], SHUF_MASK_BYTES[1], SHUF_MASK_BYTES[2], SHUF_MASK_BYTES[3],
                SHUF_MASK_BYTES[4], SHUF_MASK_BYTES[5], SHUF_MASK_BYTES[6], SHUF_MASK_BYTES[7],
            };
            std::memcpy(KShufMask, kFallback, 8);
            XorVal   = XOR_SCALAR;
            Rol64Amt = ROL64_AMT;
        }

        __m128i V   = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i Shm = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(KShufMask));
        __m128i B   = _mm_shuffle_epi8(V, Shm);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), B);
        uint64_t Raw = Lo ^ XorVal;
        // ROL64 by Rol64Amt (typically 32 — swaps hi/lo halves)
        if (Rol64Amt == 0) return Raw;
        return (Raw << Rol64Amt) | (Raw >> (64 - Rol64Amt));
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
        const auto& Disc = AutoDiscovery::g_DiscoveredFFieldName;
        const uint64_t XorConst = Disc.Valid ? Disc.XorConst : FFIELD_NAME_XOR_CL1177146;
        const int      Rol32Amt = Disc.Valid ? Disc.Rol32Amount : 13;
        const int      Rol64Amt = Disc.Valid ? Disc.Rol64Amount : 7;

        __m128i V    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        // ROL32(N) per uint32-lane
        __m128i Rot  = _mm_or_si128(
            _mm_slli_epi32(V, Rol32Amt),
            _mm_srli_epi32(V, 32 - Rol32Amt));
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Rot);
        uint64_t Xored = Lo ^ XorConst;
        // ROL64 by N
        return (Xored << Rol64Amt) | (Xored >> (64 - Rol64Amt));
    }

    // ── UObject FName accessor (patch 20260428) ──────────────────────────
    // After DecryptUObjSlotNew_20260428 (PSHUFB → ROL32(17) → XOR → ROL64(32)),
    // the comp_index lives in the LO 32 bits of the decrypted u64 (matches
    // REFERENCE_FName_20260428.h::GetActorFNameId, which casts result to int32_t).
    // Hi32 holds whatever the slot's hi-half encoded — for class/outer slots
    // that's pointer bits, so we filter on lo32 magnitude.
    int32_t GetCompIndex(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;
        alignas(16) uint8_t enc[4][16] = {};
        uint64_t dec[4] = {};
        bool valid[4] = {};
        for (int slot = 0; slot < 4; ++slot) {
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc[slot], 16)) continue;
            // Skip all-zero slots (uninitialized) — decrypting zeros gives a
            // garbage "CI" that wastes a resolve attempt.
            bool nonzero = false;
            for (int b = 0; b < 16; ++b) if (enc[slot][b]) { nonzero = true; break; }
            if (!nonzero) continue;
            dec[slot] = DecryptUObjSlotNew(enc[slot]);
            valid[slot] = true;
        }
        // CI=1 is a "no-name" sentinel; reject it explicitly (raises naming
        // success from 99% to 100% per empirical study of 1441 objects).
        auto is_ci = [](uint32_t h) { return h > 1 && h < 0x2000000u; };

        // Tier 0: hash-picked name slot (RE'd from UObject::GetFName).
        uint32_t ns = ObjNameSlot(obj_base);
        if (valid[ns]) {
            uint32_t lo = static_cast<uint32_t>(dec[ns]);
            if (is_ci(lo)) return static_cast<int32_t>(lo);
        }
        // Tier 1: first slot whose lo32 is a valid CI.
        for (int s = 0; s < 4; ++s) {
            if (!valid[s]) continue;
            uint32_t lo = static_cast<uint32_t>(dec[s]);
            if (is_ci(lo)) return static_cast<int32_t>(lo);
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
        for (int slot = 0; slot < 4; ++slot) {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) continue;
            uint64_t dec = DecryptUObjSlotNew(enc);
            if (!dec) continue;
            uint32_t lo = static_cast<uint32_t>(dec);
            uint32_t hi = static_cast<uint32_t>(dec >> 32);
            if (hi < 0x10000u) continue;
            uint64_t ptr = (static_cast<uint64_t>(lo) << 32) | hi;
            if (ptr < 0x100000ULL || ptr >= 0x800000000000ULL) continue;
            out[slot] = ptr;
        }
        return out;
    }

    uint64_t GetClassPrivate(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;
        // 20260428: slot decrypt ends with ROL64(32). For an FName slot the
        // result is `(Number << 32) | CI` (CI in lo32, Number typically 0).
        // For a pointer slot the halves are SWAPPED:
        //   result.hi32 = ptr.lo32 (the bulk of the address)
        //   result.lo32 = ptr.hi32 (typically 0 or 1 for Wine heap)
        // Distinguisher: pointer slots have result.hi32 ≥ 0x10000; FName
        // slots have result.hi32 small (= Number, usually 0).
        uint32_t ns = ObjNameSlot(obj_base);
        uint32_t os = ObjOuterSlot(obj_base);
        auto tryDecode = [&](int slot) -> uint64_t {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) return 0;
            uint64_t dec = DecryptUObjSlotNew(enc);
            if (!dec) return 0;
            uint32_t lo = static_cast<uint32_t>(dec);
            uint32_t hi = static_cast<uint32_t>(dec >> 32);
            if (hi < 0x10000u) return 0;  // not pointer-shaped (looks like FName Number=0)
            uint64_t ptr = (static_cast<uint64_t>(lo) << 32) | hi;
            if (ptr < 0x100000ULL || ptr >= 0x800000000000ULL) return 0;
            return ptr;
        };
        // Preferred order: non-name, non-outer slots first.
        for (int slot = 0; slot < 4; ++slot) {
            if (static_cast<uint32_t>(slot) == ns || static_cast<uint32_t>(slot) == os) continue;
            uint64_t p = tryDecode(slot);
            if (p) return p;
        }
        // Fallback: if the preferred slots yielded nothing (e.g. hash mispicked),
        // accept any heap-pointer slot so we don't regress pre-hash behavior.
        for (int slot = 0; slot < 4; ++slot) {
            uint64_t p = tryDecode(slot);
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
            alignas(16) uint8_t enc[16] = {};
            if (m_reader.Read(ff_addr + 0x70, enc, 16)) {
                bool any = false;
                for (uint8_t b : enc) if (b) { any = true; break; }
                if (any) {
                    uint64_t fn = DecryptFFieldNameSlot(enc);
                    int32_t ci = static_cast<int32_t>(fn & 0xFFFFFFFFu);
                    if (ci > 1 && (uint32_t)ci < 0x06A00000u) {
                        // Stash the offset for downstream callers (auto-cal short-circuit).
                        if (m_ffieldNameOff == 0) m_ffieldNameOff = 0x70;
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
    // Verified against 20260421 IDA in FProperty_GetNameCPP @ 0x3AFE70:
    //   pshuflw xmm0, [fclass+NamePrivateOff], 0x4B
    //   ROL32(xmm0, 3) per uint32 lane     (PSLLD 3 | PSRLD 0x1D)
    //   pshuflw xmm0, xmm0, 0x72
    //   pxor    xmm0, [rip+xmmword_XOR_CONST]
    //   movq    rax, xmm0                  (lo64)
    //   rol     rax, 0x20                  (ROL64(32))
    //   → result lo32 = CompIndex of type name (e.g. "BoolProperty")
    //
    // All parameters auto-discovered at runtime via Phase 7
    // (AutoDiscovery::DiscoverFFieldClassNameDecrypt). Returns 0 if Phase 7
    // didn't run / didn't validate — caller falls back to the legacy
    // vtable-to-type map.
    int32_t DecryptFFieldClassNameCI(uint64_t fclass_addr) {
        const auto& Disc = AutoDiscovery::g_DiscoveredFFieldClassName;
        if (!Disc.Valid) return 0;
        if (!fclass_addr) return 0;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(fclass_addr + Disc.NamePrivateOffset, enc, 16)) return 0;
        // Skip all-zero (uninitialized) — produces a garbage CI.
        bool nonzero = false;
        for (int i = 0; i < 16; ++i) if (enc[i]) { nonzero = true; break; }
        if (!nonzero) return 0;

        // Step 1: PSHUFLW imm1 (0x4B by default).
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i s1;
        switch (Disc.PshuflwImm1) {
            case 0x4B: s1 = _mm_shufflelo_epi16(v, 0x4B); break;
            default:   s1 = _mm_shufflelo_epi16(v, 0x4B); break;
        }
        // Step 2: ROL32(N) per uint32 lane.
        const int rol32 = Disc.Rol32Amount ? Disc.Rol32Amount : 3;
        __m128i rot = _mm_or_si128(
            _mm_slli_epi32(s1, rol32),
            _mm_srli_epi32(s1, 32 - rol32));
        // Step 3: PSHUFLW imm2 (0x72 by default).
        __m128i s2;
        switch (Disc.PshuflwImm2) {
            case 0x72: s2 = _mm_shufflelo_epi16(rot, 0x72); break;
            default:   s2 = _mm_shufflelo_epi16(rot, 0x72); break;
        }
        // Step 4: scalar XOR with discovered lo64 const.
        uint64_t lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo), s2);
        uint64_t xored = lo ^ Disc.XorLo64;
        // Step 5: ROL64(32 by default).
        const int rol64 = Disc.Rol64Amount ? Disc.Rol64Amount : 32;
        uint64_t rolled = (xored << rol64) | (xored >> (64 - rol64));

        uint32_t ci = static_cast<uint32_t>(rolled);
        if (ci < 2 || ci > 0x2000000u) return 0;
        return static_cast<int32_t>(ci);
    }

    // ── Step 4-7: comp_index → FNameEntry heap address (patch 20260421) ──
    // Derived from sub_242FC0 @ RVA 0x242FC0. Packed CI layout:
    //   name_offset_word = ci & 0xFFFF
    //   chunk_off        = (ci >> 8) & 0xFFFF00  (bytes into FNamePool base)
    // Each chunk at GNAMES + chunk_off holds an FNV seed at +0x6570 and an
    // 8-way slot array of 32-byte entries at +0x6580. FNV32 picks slot_idx;
    // the two adjacent 16-byte slots are decrypted and combined via FNV64
    // fold. The sentinel XOR + bswap chain collapses to `result ^ 0x086B0040`.
    // ── ResolveNamePtrFull (patch 20260428) ──────────────────────────────
    // Direct port of REFERENCE_FName_20260428.h::ResolveNamePtr. Three-stage
    // SIMD CI transform → block-selector hash → 2 block decrypts → FNV fold
    // → 3-XOR pointer fixup chain.
    uint64_t ResolveNamePtrFull(int32_t CompIndex) {
        if (CompIndex <= 0 || !m_keyLoaded) return 0;

        constexpr uint32_t HASH_PRIME = 16777619u;
        constexpr uint32_t HASH_ADD_MAIN = 0x8E195662u;
        constexpr uint32_t BHASH_ADD = 0x0CCB8743u;
        constexpr uint64_t CHUNK_HASH_SEED_OFF = 0x7050ULL;
        constexpr uint64_t CHUNK_BLOCK_BASE_OFF = 0x7060ULL;
        constexpr uint64_t FNV_PRIME = 0x100000001B3ULL;
        constexpr uint64_t FNV_OFFSET = 0x34E6ED2249E469DULL;
        constexpr uint64_t PTR_XOR_1 = 0x9DD41EF0ULL;
        constexpr uint64_t PTR_XOR_2 = 0x18E0021000000000ULL;
        constexpr uint64_t PTR_XOR_3 = 0xE8FED68D00000000ULL;

        alignas(16) static const uint8_t BLOCK1_XOR[16] = {
            0x12,0x09,0x73,0x66,0xC3,0x14,0x7D,0xE8, 0,0,0,0,0,0,0,0
        };
        alignas(16) static const uint8_t BLOCK2_AND[16] = {
            0x73,0xC7,0x73,0xC7,0x73,0xC7,0x73,0xC7, 0x73,0xC7,0x73,0xC7,0x73,0xC7,0x73,0xC7
        };
        alignas(16) static const uint8_t BLOCK2_ANDNOT[16] = {
            0x8C,0x38,0x8C,0x38,0x8C,0x38,0x8C,0x38, 0x8C,0x38,0x8C,0x38,0x8C,0x38,0x8C,0x38
        };
        alignas(16) static const uint8_t BLOCK2_XOR[16] = {
            0x9E,0x31,0xFF,0x5E,0x4F,0x2C,0xF1,0xD0, 0,0,0,0,0,0,0,0
        };

        __m128i Ci = _mm_cvtsi32_si128(CompIndex);
        __m128i V1 = _mm_or_si128(_mm_slli_epi32(Ci, 22), _mm_srli_epi32(Ci, 10));
        __m128i V2 = _mm_shufflelo_epi16(V1, 0x72);
        __m128i V3 = _mm_or_si128(_mm_slli_epi16(V2, 3), _mm_srli_epi16(V2, 13));
        __m128i V4 = _mm_or_si128(_mm_slli_epi16(V3, 13), _mm_srli_epi16(V3, 3));
        __m128i V5 = _mm_shufflelo_epi16(V4, 0xED);
        __m128i V6 = _mm_or_si128(_mm_slli_epi32(V5, 10), _mm_srli_epi32(V5, 22));
        uint32_t V5Int = static_cast<uint32_t>(_mm_cvtsi128_si32(V6));

        uint64_t NameOffset = 2ULL * static_cast<uint16_t>(V5Int);
        uint64_t ChunkOff   = (static_cast<uint64_t>(V5Int) >> 8) & 0xFFFF00ULL;

        uint64_t GnamesBase = m_base + FNAME_GNAMES_BASE_OFF;
        uint64_t ChunkAddr  = GnamesBase + ChunkOff;

        uint64_t Seed = ChunkAddr + CHUNK_HASH_SEED_OFF;
        uint32_t SeedLo = static_cast<uint32_t>(Seed);
        uint32_t SeedHi = static_cast<uint32_t>(Seed >> 32);

        uint32_t H = fn_rotl32(SeedLo, 21);
        H = HASH_PRIME * H + BHASH_ADD;
        H = fn_rotl32(H, 17);
        H = HASH_PRIME * H + SeedHi + BHASH_ADD;
        H = fn_rotl32(H, 21);
        H = HASH_PRIME * H + BHASH_ADD;
        H = fn_rotl32(H, 17);

        uint32_t V8 = HASH_PRIME * H + BHASH_ADD;
        uint32_t V9 = V8 ^ (V8 >> 16);
        uint32_t Bidx1 = V9 & 7u;
        uint32_t Bidx2 = (V9 + 1u) & 7u;

        uint64_t BlockBase = ChunkAddr + CHUNK_BLOCK_BASE_OFF;
        uint64_t B1Addr = BlockBase + 32ULL * Bidx1;
        uint64_t B2Addr = BlockBase + 32ULL * Bidx2;

        alignas(16) uint8_t Sb1[16] = {}, Sb2[16] = {};
        if (!m_reader.Read(B1Addr, Sb1, 16)) return 0;
        if (!m_reader.Read(B2Addr, Sb2, 16)) return 0;

        __m128i B1V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Sb1));
        __m128i B1R1 = _mm_or_si128(_mm_slli_epi16(B1V, 13), _mm_srli_epi16(B1V, 3));
        __m128i B1Xor = _mm_load_si128(reinterpret_cast<const __m128i*>(BLOCK1_XOR));
        __m128i B1X = _mm_xor_si128(B1R1, B1Xor);
        __m128i B1R2 = _mm_or_si128(_mm_slli_epi16(B1X, 4), _mm_srli_epi16(B1X, 12));
        uint64_t B1Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&B1Lo), B1R2);

        __m128i B2V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Sb2));
        __m128i B2R1 = _mm_or_si128(_mm_slli_epi16(B2V, 13), _mm_srli_epi16(B2V, 3));
        __m128i B2And = _mm_load_si128(reinterpret_cast<const __m128i*>(BLOCK2_AND));
        __m128i B2AndNot = _mm_load_si128(reinterpret_cast<const __m128i*>(BLOCK2_ANDNOT));
        __m128i B2XorK = _mm_load_si128(reinterpret_cast<const __m128i*>(BLOCK2_XOR));
        __m128i B2Blend = _mm_or_si128(_mm_and_si128(B2R1, B2And),
                                       _mm_andnot_si128(B2R1, B2AndNot));
        __m128i B2X = _mm_xor_si128(B2Blend, B2XorK);
        __m128i B2R2 = _mm_or_si128(_mm_slli_epi16(B2X, 4), _mm_srli_epi16(B2X, 12));
        uint64_t B2Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&B2Lo), B2R2);

        uint64_t Fnv = FNV_PRIME * fn_rotl64(B1Lo, 49) - FNV_OFFSET;
        Fnv = FNV_PRIME * fn_rotl64(Fnv, 47) - FNV_OFFSET;

        uint64_t R = B1Lo + (Fnv ^ B2Lo) + NameOffset;

        uint64_t A = __builtin_bswap64(R ^ PTR_XOR_1);
        uint64_t B = A ^ PTR_XOR_2 ^ PTR_XOR_3;
        return __builtin_bswap64(B);
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

    // ── DecryptNameString (patch 20260428) ────────────────────────────
    // Direct port of REFERENCE_FName_20260428.h::DecryptNameString. Char-based
    // (8-bit signed) LCG keystream advancing per pair, with two distinct
    // keytable indices per pair.
    //   length = (hdr & 0x7F) | ((hdr >> 5) & 0x380)   (different bit layout)
    //   isWide = bit15
    //   key0   = (char)(length - 68)
    //   per pair (i, i+1):
    //     idx_a = key & 0x3F           ; word ^= kt[8 + idx_a]   (ANSI: >>3)
    //     idx_b = (68*key + 96) & 0x3C ; word ^= kt[8 + idx_b]   (ANSI: >>3)
    //     key = (char)(16*key - 32)
    //   trailing odd: word ^= kt[8 + (key & 0x3F)]   (ANSI: >>3)
    std::string DecryptNameString(uint64_t NameEntryPtr) {
        if (!NameEntryPtr || !m_keyLoaded) return {};

        uint16_t Header = 0;
        if (!m_reader.Read(NameEntryPtr, &Header, 2) || !Header) return {};

        bool IsWide = (Header & 1u) != 0;
        int V3 = Header >> 9;
        int V4 = (2 * static_cast<int>(Header)) & 0x380;
        int CharCount = V3 + V4;
        if (CharCount <= 0 || CharCount > 1023) return {};

        int ByteCount = IsWide ? CharCount * 2 : CharCount;
        if (ByteCount > 2048) ByteCount = 2048;

        std::vector<uint8_t> Buf(ByteCount, 0);
        if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), ByteCount)) return {};

        uint16_t Key = static_cast<uint16_t>(static_cast<int>(CharCount) - 25107);

        if (!IsWide) {
            for (int I = 0; I < CharCount; ++I) {
                Buf[I] ^= static_cast<uint8_t>(m_keyTable[(Key + I) & 0x3F] >> 3);
            }
            return std::string(reinterpret_cast<char*>(Buf.data()), CharCount);
        } else {
            auto* WBuf = reinterpret_cast<uint16_t*>(Buf.data());
            for (int I = 0; I < CharCount; ++I) {
                WBuf[I] ^= m_keyTable[(Key + I) & 0x3F];
            }
            std::string Result;
            Result.reserve(CharCount);
            for (int J = 0; J < CharCount; ++J) {
                if (WBuf[J]) Result += static_cast<char>(WBuf[J] & 0xFF);
            }
            return Result;
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
    std::string CompIndexToName(int32_t comp_index) {
        std::string s = StaticResolve(comp_index);
        if (IsStrictName(s)) return s;
        std::string e = TryEmuFallback(comp_index);
        return IsStrictName(e) ? e : std::string{};
    }

    // Lenient: any mostly-printable ASCII. Used for FField names which can
    // legitimately contain weirder characters.
    std::string CompIndexToNameLenient(int32_t comp_index) {
        std::string s = StaticResolve(comp_index);
        if (IsLenientName(s)) return s;
        std::string e = TryEmuFallback(comp_index);
        return IsLenientName(e) ? e : std::string{};
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
        // Tier 0: hash-based outer-slot selection (RE'd from UObject::GetOuter).
        uint32_t os = ObjOuterSlot(obj_ptr);
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
    uint64_t       m_primaryHandleOffset = 0;  // 0 = no calibration yet, fall back to candidate list
    uint64_t       m_ffieldNameOff = 0;        // 0 = uncalibrated; first valid offset wins

    // SIMD tables loaded from process memory during Init()
    alignas(16) uint8_t m_cidxXor1[16];      // slot PXOR key           (AD30540)
    alignas(16) uint8_t m_cidxXor3[16];      // Level-2 CIdx XOR        (AD30590)
    alignas(16) uint8_t m_blkSlotShuf[16];   // slot data pshufb        (AD305A0)
    alignas(16) uint8_t m_blkSlotShuf2[16];  // slot decrypt pshufb     (AD30550)
    alignas(16) uint8_t m_blkHdrAnd[16];     // block header AND        (AD305C0)
    alignas(16) uint8_t m_blkHdrAndnot[16];  // block header ANDNOT     (AD305B0)
    alignas(16) uint8_t m_blkHdrShuf[16];    // block header pshufb     (AD2FCC0)
    alignas(16) uint8_t m_blkHdrXor[16];     // block header pxor       (AD305D0)

    // Patch 20260421 UObject slot decrypt constants
    alignas(16) uint8_t m_uobjShufMask[16] = {};   // (AD128C0) 05,03,01,04,02,07,00,06
    alignas(16) uint8_t m_uobjXorConst[16] = {};   // (AD128D0) 09,43,BD,C8,4B,4B,BC,FF

    // Patch 20260421 FField name decrypt constant
    alignas(16) uint8_t m_fFieldXorConst[16] = {}; // (AD15750) 38,BA,6F,75,E8,89,57,36,0,0,0,0,0,0,0,0

    // Patch 20260428 FNamePool resolver SIMD tables
    alignas(16) uint8_t m_p28_gidxShuf1[16]   = {}; // (AD49100) Stage-1 PSHUFB mask (replicated to hi8)
    alignas(16) uint8_t m_p28_gidxXor1[16]    = {}; // (AD49110) Stage-1 / Stage-2 XOR key (replicated to hi8)
    alignas(16) uint8_t m_p28_stage2Xor[16]   = {}; // (AD49390) Stage-2 XOR key (replicated to hi8)
    alignas(16) uint8_t m_p28_extractShuf[16] = {}; // (AD49140) CI extract PSHUFB mask
    alignas(16) uint8_t m_p28_extractXor[16]  = {}; // (AD49150) CI extract XOR const
    alignas(16) uint8_t m_p28_blockShuf[16]   = {}; // (AD49130) Block decrypt PSHUFB mask (lo8 valid)
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
