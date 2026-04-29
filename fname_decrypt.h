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

        // FName XOR key table (at RVA_FNAME_KEY_TABLE; accessed as table[key+60])
        uint64_t kt_addr = m_base + FNAME_KEY_TABLE_OFF;
        std::printf("[dbg] Reading FName key table @ 0x%llX ...\n", (unsigned long long)kt_addr);
        if (!m_reader.Read(kt_addr, m_keyTable, sizeof(m_keyTable))) {
            std::printf("[-] Failed to read FName key table\n");
            return false;
        }
        int nonzero = 0;
        for (uint16_t value : m_keyTable) nonzero += value != 0;
        if (nonzero < 64) {
            std::printf("[-] FName key table looks invalid at 0x%llX (nonzero=%d)\n",
                (unsigned long long)kt_addr, nonzero);
            return false;
        }
        std::printf("[+] FName key table OK (first: 0x%04X 0x%04X)\n", m_keyTable[0], m_keyTable[1]);

        // SIMD tables for CIdx decode pipeline (patch 20260402)
        auto loadTable = [&](uint64_t rva, uint8_t* dst, const char* name) -> bool {
            if (!m_reader.Read(m_base + rva, dst, 16)) {
                std::printf("[-] Failed to read SIMD table %s @ RVA 0x%llX\n",
                    name, (unsigned long long)rva);
                return false;
            }
            return true;
        };

        // UObject slot decrypt tables (patch 20260421)
        if (!loadTable(ArcDecrypt::Patch20260421::UObjSlot20260421::RVA_SHUF_MASK, m_uobjShufMask, "uobjShufMask")) return false;
        if (!loadTable(ArcDecrypt::Patch20260421::UObjSlot20260421::RVA_XOR_CONST, m_uobjXorConst, "uobjXorConst")) return false;
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

        if (!loadTable(RVA_CIDX_XOR1_OFF,          m_cidxXor1,      "cidxXor1"))      return false;
        if (!loadTable(RVA_CIDX_XOR3_OFF,          m_cidxXor3,      "cidxXor3"))      return false;
        if (!loadTable(RVA_BLOCK_HDR_AND_OFF,      m_blkHdrAnd,     "blkHdrAnd"))     return false;
        if (!loadTable(RVA_BLOCK_HDR_ANDNOT_OFF,   m_blkHdrAndnot,  "blkHdrAndnot"))  return false;
        if (!loadTable(RVA_BLOCK_HDR_SHUF_OFF,     m_blkHdrShuf,    "blkHdrShuf"))    return false;
        if (!loadTable(RVA_BLOCK_HDR_XOR_OFF,      m_blkHdrXor,     "blkHdrXor"))     return false;
        if (!loadTable(RVA_BLOCK_SLOT_SHUF_OFF,    m_blkSlotShuf,   "blkSlotShuf"))   return false;
        if (!loadTable(RVA_BLOCK_SLOT_SHUF2_OFF,   m_blkSlotShuf2,  "blkSlotShuf2"))  return false;

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

    // ── Hash-based slot selector (patch 20260428) ────────────────────────
    // From REFERENCE_FName_20260428.h ComputeHashAndIndex:
    //   h = ROL32(lo, 25) → P*h + ADD
    //   h = ROL32(h, 27)  → P*h + hi + ADD
    //   h >>= 7; h = P*h + ADD
    //   h >>= 5; v7 = P*h + ADD
    //   slot_idx = ((uint8(v7) ^ uint8(v7 >> 16)) & 3) ^ 2
    static uint32_t ObjSlotHash(uint64_t obj_ptr) {
        using namespace ArcDecrypt::Patch20260421::UObjSlot20260428;
        uint64_t p = obj_ptr + 0x10;
        uint32_t lo = static_cast<uint32_t>(p);
        uint32_t hi = static_cast<uint32_t>(p >> 32);
        uint32_t h = fn_rotl32(lo, HASH_ROL1);
        h = HASH_PRIME * h + HASH_ADD;
        h = fn_rotl32(h, HASH_ROL2);
        h = HASH_PRIME * h + hi + HASH_ADD;
        h >>= HASH_SHR1;
        h = HASH_PRIME * h + HASH_ADD;
        h >>= HASH_SHR2;
        return HASH_PRIME * h + HASH_ADD;
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
    // Outer-slot formula not yet RE'd for 20260428 — keep heuristic.
    static uint32_t ObjOuterSlot(uint64_t obj_ptr) {
        return (ObjNameSlot(obj_ptr) + 1u) & 3u;
    }

    // ── Decrypt one UObject slot (patch 20260428) ────────────────────────
    // Pipeline ENTIRELY DIFFERENT from 20260421. From REFERENCE_FName_20260428.h:
    //   shuffle_epi8(enc, MASK = 01 06 00 04 07 03 02 05) → ROL32(17) →
    //   XOR(scalar 0x4834C6DEA02581C7) → ROL64(32)
    // After the final ROL64(32), the lo32 of the result IS the comp_index
    // (no high-half "Number" packing in this patch). We still return the
    // full 64-bit so existing callers can shape-classify (the file's
    // GetActorFNameId casts to int32_t — equivalent to taking lo32).
    uint64_t DecryptUObjSlotNew(const uint8_t enc[16]) const {
        using namespace ArcDecrypt::Patch20260421::UObjSlot20260428;
        alignas(16) static constexpr uint8_t kShufMask[16] = {
            SHUF_MASK_BYTES[0], SHUF_MASK_BYTES[1], SHUF_MASK_BYTES[2], SHUF_MASK_BYTES[3],
            SHUF_MASK_BYTES[4], SHUF_MASK_BYTES[5], SHUF_MASK_BYTES[6], SHUF_MASK_BYTES[7],
            0,0,0,0, 0,0,0,0
        };
        __m128i v   = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i shm = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(kShufMask));
        __m128i b   = _mm_shuffle_epi8(v, shm);
        __m128i r   = _mm_or_si128(_mm_slli_epi32(b, ROL32_AMT),
                                   _mm_srli_epi32(b, 32 - ROL32_AMT));
        uint64_t lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo), r);
        uint64_t raw = lo ^ XOR_SCALAR;
        // ROL64(32) = swap hi32/lo32
        return (raw << 32) | (raw >> 32);
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
        // Patch 20260428 — VERIFIED via IDA decompile of FBoolProperty error
        // handler at sub_4586C6. Pipeline:
        //   1. enc16 = load(FField + 0x70)
        //   2. tmp1  = ROL64(enc16, 21) per 64-bit lane
        //   3. tmp2  = tmp1 XOR xmmword_AD65E90  (lo64=0xC8727080CA112779, hi64=0)
        //   4. tmp3  = ROL16(tmp2, 15) per uint16-lane = ROR16(_, 1)
        //   5. lo64  = lo 8 bytes of tmp3
        //   6. ROL64(lo64, 32) → swap halves → (Number<<32) | CI (CI in lo32)
        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(ff_addr + ArcDecrypt::Offsets::FField::NameEncrypted, enc, 16))
            return 0;
        uint64_t hi_check;
        std::memcpy(&hi_check, enc + 8, 8);
        if (hi_check == 0) return 0;  // uninitialized slot

        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        // Step 2: ROL64(v, 21) per 64-bit lane
        __m128i r1 = _mm_or_si128(_mm_slli_epi64(v, 21),
                                  _mm_srli_epi64(v, 64 - 21));
        // Step 3: XOR with constant (16-byte; only lo64 is non-zero)
        alignas(16) static const uint8_t kXor[16] = {
            0x79, 0x27, 0x11, 0xCA, 0x80, 0x70, 0x72, 0xC8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        __m128i xk = _mm_load_si128(reinterpret_cast<const __m128i*>(kXor));
        __m128i x = _mm_xor_si128(r1, xk);
        // Step 4: ROL16(x, 15) per uint16-lane
        __m128i r2 = _mm_or_si128(_mm_slli_epi16(x, 15),
                                  _mm_srli_epi16(x, 1));
        // Step 5+6: lo64 then ROL64(_, 32)
        uint64_t lo64;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo64), r2);
        uint64_t rot = (lo64 >> 32) | (lo64 << 32);
        return static_cast<int32_t>(rot & 0xFFFFFFFFu);  // CI in lo32
    }

    // ── FFieldClass → type name comp_index ───────────────────────────────
    // FFieldClass does not store a plain FName at a discoverable offset in the known
    // 128-byte layout.  Type identification is done via vtable-to-type map in the
    // SDK generator (AutoDiscoverVTables).  This function is kept as a no-op fallback.
    int32_t DecryptFFieldClassNameCI(uint64_t /*fclass_addr*/) {
        return 0;
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
    uint64_t ResolveNamePtrFull(int32_t comp_index) {
        if (comp_index <= 0 || !m_keyLoaded) return 0;

        using namespace ArcDecrypt::Patch20260421::FNamePool20260428;

        // ── Stage 1..3 SIMD CI → GNames-location transform ──────────────
        __m128i shuf1  = _mm_load_si128(reinterpret_cast<const __m128i*>(m_p28_gidxShuf1));
        __m128i xor1   = _mm_load_si128(reinterpret_cast<const __m128i*>(m_p28_gidxXor1));
        __m128i s2xor  = _mm_load_si128(reinterpret_cast<const __m128i*>(m_p28_stage2Xor));
        __m128i eshuf  = _mm_load_si128(reinterpret_cast<const __m128i*>(m_p28_extractShuf));
        __m128i exor   = _mm_load_si128(reinterpret_cast<const __m128i*>(m_p28_extractXor));

        // Stage 1: shuffle_epi8(ci, SHUF1) → XOR(XOR1) → ROL32(17) → shufflelo(0xB1)
        __m128i ci = _mm_cvtsi32_si128(comp_index);
        __m128i t1 = _mm_xor_si128(_mm_shuffle_epi8(ci, shuf1), xor1);
        __m128i r1 = _mm_or_si128(_mm_slli_epi32(t1, STAGE_ROL32_A),
                                  _mm_srli_epi32(t1, 32 - STAGE_ROL32_A));
        __m128i state1 = _mm_shufflelo_epi16(r1, STAGE_PSHUFLW_IMM);

        // Stage 2: shufflelo(0xB1) → ROL32(15) → shuffle_epi32(0x44) → XOR(STAGE2_XOR) → XOR(XOR1) → ROL32(17) → shufflelo(0xB1)
        __m128i s2a = _mm_shufflelo_epi16(state1, STAGE_PSHUFLW_IMM);
        __m128i s2b = _mm_or_si128(_mm_slli_epi32(s2a, STAGE_ROL32_B),
                                   _mm_srli_epi32(s2a, 32 - STAGE_ROL32_B));
        __m128i s2c = _mm_shuffle_epi32(s2b, 0x44);
        __m128i s2d = _mm_xor_si128(_mm_xor_si128(s2c, s2xor), xor1);
        __m128i s2e = _mm_or_si128(_mm_slli_epi32(s2d, STAGE_ROL32_A),
                                   _mm_srli_epi32(s2d, 32 - STAGE_ROL32_A));
        __m128i state2 = _mm_shufflelo_epi16(s2e, STAGE_PSHUFLW_IMM);

        // Stage 3: shufflelo(0xB1) → ROL32(15) → shuffle_epi8(EXTRACT) → XOR(EXTRACT_XOR)
        __m128i s3a = _mm_shufflelo_epi16(state2, STAGE_PSHUFLW_IMM);
        __m128i s3b = _mm_or_si128(_mm_slli_epi32(s3a, STAGE_ROL32_B),
                                   _mm_srli_epi32(s3a, 32 - STAGE_ROL32_B));
        __m128i s3c = _mm_shuffle_epi8(s3b, eshuf);
        __m128i s3d = _mm_xor_si128(s3c, exor);
        uint32_t v5 = static_cast<uint32_t>(_mm_cvtsi128_si32(s3d));

        uint64_t name_offset = 2ULL * static_cast<uint16_t>(v5);
        uint64_t chunk_off   = (static_cast<uint64_t>(v5) >> 8) & 0xFFFF00ULL;

        uint64_t gnames_base = m_base + FNAME_GNAMES_BASE_OFF;
        uint64_t chunk_addr  = gnames_base + chunk_off;

        // ── Block-selector hash ─────────────────────────────────────────
        uint64_t seed = chunk_addr + CHUNK_FNV_SEED_OFF;
        uint32_t seed_lo = static_cast<uint32_t>(seed);
        uint32_t seed_hi = static_cast<uint32_t>(seed >> 32);
        uint32_t h = (seed_lo >> 6) | 0x40000000u;
        h = BHASH_PRIME * h + BHASH_ADD;
        h = fn_rotl32(h, BHASH_ROL);
        h = BHASH_PRIME * h + seed_hi + BHASH_ADD;
        h >>= 6;
        h = BHASH_PRIME * h + BHASH_ADD;
        h >>= 4;
        uint32_t finalH = BHASH_PRIME * h + BHASH_ADD;
        // Verified C# reference: bidx = (finalH ^ (finalH >> 16)) & 7
        // (No -109*h step — earlier IDA-derived version was incorrect.)
        uint8_t bidx = static_cast<uint8_t>(finalH ^ (finalH >> 16));

        uint64_t block_base = chunk_addr + CHUNK_BLOCK_BASE_OFF;
        uint64_t b1addr = block_base + 32ULL * (bidx & 7u);
        uint64_t b2addr = block_base + 32ULL * ((bidx + 1u) & 7u);

        alignas(16) uint8_t sb1[16] = {}, sb2[16] = {};
        if (!m_reader.Read(b1addr, sb1, 16)) return 0;
        if (!m_reader.Read(b2addr, sb2, 16)) return 0;

        // ── Block decrypt: shuffle_epi8(BLOCK_SHUF) → ROL16(5) → XOR(scalar) ─
        __m128i bshuf = _mm_load_si128(reinterpret_cast<const __m128i*>(m_p28_blockShuf));
        auto decryptBlock = [&](const uint8_t* raw) -> uint64_t {
            __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw));
            __m128i b = _mm_shuffle_epi8(v, bshuf);
            __m128i r = _mm_or_si128(_mm_slli_epi16(b, BLOCK_ROL16_AMT),
                                     _mm_srli_epi16(b, 16 - BLOCK_ROL16_AMT));
            uint64_t lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo), r);
            return lo ^ BLOCK_POST_XOR;
        };
        uint64_t v14 = decryptBlock(sb1);
        uint64_t v15 = decryptBlock(sb2);

        // ── FNV fold ───────────────────────────────────────────────────
        uint64_t fnv = FNV64_PRIME * fn_rotl64(v14, FNV64_ROL1) + FNV64_OFF;
        fnv = FNV64_PRIME * fn_rotl64(fnv, FNV64_ROL2) + FNV64_OFF;

        uint64_t R = v14 + (fnv ^ v15) + name_offset;

        // ── 3-XOR pointer fixup ───────────────────────────────────────
        uint64_t a = __builtin_bswap64(R ^ PTR_XOR_1);
        uint64_t b = a ^ PTR_XOR_2;
        return __builtin_bswap64(b ^ PTR_XOR_3);
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
    std::string DecryptNameString(uint64_t name_entry_ptr) {
        if (!name_entry_ptr || !m_keyLoaded) return {};

        int16_t header_s = 0;
        if (!m_reader.Read(name_entry_ptr, &header_s, 2) || !header_s) return {};

        uint16_t header = static_cast<uint16_t>(header_s);
        bool isWide = (header_s < 0);
        int v3 = header & 0x7F;
        int v4 = (header >> 5) & 0x380;
        int charCount = v3 + v4;
        if (charCount <= 0 || charCount > 1023) return {};

        int byteCount = isWide ? charCount * 2 : charCount;
        if (byteCount > 2048) byteCount = 2048;

        std::vector<uint8_t> buf(byteCount, 0);
        if (!m_reader.Read(name_entry_ptr + 2, buf.data(), byteCount)) return {};

        using namespace ArcDecrypt::Patch20260421::FNameEntryString20260428;

        int8_t key = static_cast<int8_t>(charCount + KEY_START_BIAS);

        auto idx_a = [&]() -> int { return (static_cast<uint8_t>(key) & IDX_A_MASK) + KEY_TABLE_UINT16_OFFSET; };
        auto idx_b = [&]() -> int {
            uint8_t k = static_cast<uint8_t>(key);
            return ((IDX_B_MUL * k + IDX_B_ADD) & IDX_B_MASK) + KEY_TABLE_UINT16_OFFSET;
        };

        if (!isWide) {
            // ANSI: file uses loopCount = v3 | v4 (== charCount when bits don't overlap; same here)
            int loopCount = v3 | v4;
            int i = 0;
            for (; i + 1 < loopCount; i += 2) {
                if (i     < byteCount) buf[i]     ^= static_cast<uint8_t>(m_keyTable[idx_a()] >> 3);
                if (i + 1 < byteCount) buf[i + 1] ^= static_cast<uint8_t>(m_keyTable[idx_b()] >> 3);
                key = static_cast<int8_t>(KEY_LCG_MUL * key + KEY_LCG_ADD);
            }
            if ((loopCount & 1) && i < byteCount)
                buf[i] ^= static_cast<uint8_t>(m_keyTable[idx_a()] >> 3);
            int outLen = (charCount < byteCount) ? charCount : byteCount;
            return std::string(reinterpret_cast<char*>(buf.data()), outLen);
        } else {
            auto* wbuf = reinterpret_cast<uint16_t*>(buf.data());
            int wcharCount = byteCount / 2;
            int i = 0;
            for (; i + 1 < charCount; i += 2) {
                if (i     < wcharCount) wbuf[i]     ^= m_keyTable[idx_a()];
                if (i + 1 < wcharCount) wbuf[i + 1] ^= m_keyTable[idx_b()];
                key = static_cast<int8_t>(KEY_LCG_MUL * key + KEY_LCG_ADD);
            }
            if ((charCount & 1) && i < wcharCount)
                wbuf[i] ^= m_keyTable[idx_a()];
            std::string result;
            result.reserve(wcharCount);
            for (int j = 0; j < wcharCount; ++j) {
                if (wbuf[j]) result += static_cast<char>(wbuf[j] & 0xFF);
            }
            return result;
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
    uint64_t GetPackagePtr(uint64_t obj_ptr) {
        if (!obj_ptr) return 0;
        uint64_t cur = obj_ptr;
        for (int depth = 0; depth < 24; ++depth) {
            uint64_t outer = GetOuterPtr(cur);
            if (!outer) return cur;
            cur = outer;
        }
        return cur;
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
