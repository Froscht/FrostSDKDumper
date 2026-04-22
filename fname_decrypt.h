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
#include <immintrin.h>
#include "kernel_module/include/memreader_ioctl.h"
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

    // ── Decrypt one UObject slot (patch 20260421) ────────────────────────
    // From sub_24DEB60: PSHUFLW(0xB1) → ROL32(15) per 32-bit lane →
    //                   PSHUFB(mask@0xAD128C0) → XOR(const@0xAD128D0) → lo64.
    // If the slot stores an FName: result == (CI << 32) | Number.
    // If it stores a pointer: result == heap pointer (low 32 bits populated).
    uint64_t DecryptUObjSlotNew(const uint8_t enc[16]) const {
        using namespace ArcDecrypt::Patch20260421::UObjSlot20260421;
        __m128i v  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i s  = _mm_shufflelo_epi16(v, PSHUFLW_IMM);
        __m128i r  = _mm_or_si128(_mm_slli_epi32(s, ROL32_AMT),
                                  _mm_srli_epi32(s, 32 - ROL32_AMT));
        __m128i b  = _mm_shuffle_epi8(r, _mm_load_si128(reinterpret_cast<const __m128i*>(m_uobjShufMask)));
        __m128i xo = _mm_xor_si128(b, _mm_load_si128(reinterpret_cast<const __m128i*>(m_uobjXorConst)));
        uint64_t lo64;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo64), xo);
        return lo64;
    }

    // ── UObject FName / Class / Outer accessors (patch 20260421) ─────────
    // The game picks slot via an FNV hash of (obj+16) and additional selectors
    // for {FName, Class, Outer, Number/something}. External dumper just tries
    // all 4 slots and classifies each decrypted value by shape:
    //   lo32 == 0 & hi32 < some CI cap → FName (hi32 is CI)
    //   lo32 in heap range & hi32 == 0 → pointer (Class/Outer/etc.)
    int32_t GetCompIndex(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;
        // FName shape: decrypted slot = (CI << 32) | Number. Accept only when
        // Number is zero and CI is nonzero + within plausible pool capacity —
        // this is empirically what works on live UObjects. Relaxing the check
        // (allowing nonzero Number) lets Class/Outer-slot noise leak in and
        // tanks the hit rate.
        for (int slot = 0; slot < 4; ++slot) {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) continue;
            uint64_t dec = DecryptUObjSlotNew(enc);
            uint32_t lo32 = static_cast<uint32_t>(dec);
            uint32_t hi32 = static_cast<uint32_t>(dec >> 32);
            if (lo32 == 0 && hi32 > 0 && hi32 < 0x2000000) {
                return static_cast<int32_t>(hi32);
            }
        }
        return 0;
    }

    uint64_t GetClassPrivate(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;
        for (int slot = 0; slot < 4; ++slot) {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) continue;
            uint64_t dec = DecryptUObjSlotNew(enc);
            // Class slot: lo32 in heap range, hi32 = 0.
            uint64_t ptr = dec;  // decrypted value IS the pointer when applicable.
            if ((ptr >> 32) == 0 && ptr >= 0x100000ULL && ptr < 0x800000000000ULL) {
                // Reject Outer candidates by preferring the FIRST heap pointer we see —
                // callers that need Outer specifically use GetOuterPtr.
                // (Class vs Outer resolution via slot shape is ambiguous externally;
                // the main dumper uses GetClassPrivate to classify and doesn't need
                // perfect discrimination for the name dump.)
                // TODO: distinguish Class from Outer by reading target's vtable.
                return ptr;
            }
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
        // Patch 20260421: FField::NamePrivate is a plain uint32 — no decrypt.
        uint32_t ci = 0;
        if (!m_reader.Read(ff_addr + ArcDecrypt::Offsets::FField::NamePrivate, &ci, 4))
            return 0;
        return static_cast<int32_t>(ci);
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
    uint64_t ResolveNamePtrFull(int32_t comp_index) {
        if (comp_index <= 0 || !m_keyLoaded) return 0;

        using namespace ArcDecrypt::Patch20260421::FNamePool20260421;

        uint32_t ci = static_cast<uint32_t>(comp_index);
        uint64_t name_offset_word = ci & 0xFFFFu;
        uint64_t chunk_off        = (static_cast<uint64_t>(ci) >> 8) & 0xFFFF00ULL;

        uint64_t chunk_base = m_base + FNAME_GNAMES_BASE_OFF + chunk_off;

        // FNV32 on (chunk_base + 25968)
        uint64_t seed = chunk_base + CHUNK_FNV_SEED_OFF;
        uint32_t seed_lo = static_cast<uint32_t>(seed);
        uint32_t seed_hi = static_cast<uint32_t>(seed >> 32);
        uint32_t h1 = FNV32_PRIME * fn_rotl32(seed_lo, 19) + FNV32_K;
        uint32_t h2 = FNV32_PRIME * fn_rotl32(h1, 14) + seed_hi + FNV32_K;
        uint32_t h3 = FNV32_PRIME * fn_rotl32(h2, 19) + FNV32_K;
        uint32_t v8 = fn_rotl32(h3, 14);
        uint8_t  v9 = static_cast<uint8_t>(
            static_cast<uint32_t>(-109 * v8 - 30) ^
            ((FNV32_PRIME * v8 + FNV32_K) >> 16));
        unsigned slot_idx = v9 & 7u;

        alignas(16) uint8_t sb1[16] = {}, sb2[16] = {};
        uint64_t s1_addr = chunk_base + CHUNK_SLOT_BASE + 32ULL * slot_idx;
        uint64_t s2_addr = chunk_base + CHUNK_SLOT_BASE + 32ULL * ((slot_idx + 1) & 7);
        if (!m_reader.Read(s1_addr, sb1, 16)) return 0;
        if (!m_reader.Read(s2_addr, sb2, 16)) return 0;

        // Slot decrypt: PSHUFLW(0x93) → ROL32(25) → lo64 → XOR(SLOT_XOR)
        auto decryptSlot = [](const uint8_t* raw) -> uint64_t {
            __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw));
            __m128i s = _mm_shufflelo_epi16(v, SLOT_PSHUFLW_IMM);
            __m128i r = _mm_or_si128(_mm_slli_epi32(s, SLOT_ROL32),
                                     _mm_srli_epi32(s, 32 - SLOT_ROL32));
            uint64_t lo64;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo64), r);
            return lo64 ^ SLOT_XOR;
        };
        uint64_t v11 = decryptSlot(sb1);
        uint64_t v13 = decryptSlot(sb2);

        // FNV64 fold on v11
        uint64_t fnv = FNV64_PRIME * fn_rotl64(v11, FNV64_ROL1) + FNV64_OFF;
        fnv = FNV64_PRIME * fn_rotl64(fnv, FNV64_ROL2) + FNV64_OFF;

        uint64_t result = v11 + (fnv ^ v13) + 2ULL * name_offset_word;
        return result ^ RESULT_TO_ENTRY_XOR;
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

    // ── Step 8: read + decrypt FNameEntry string (patch 20260421) ──────────
    // Derived from FNameEntry_AppendNameToString[_WithNumber] @ 0x22EC20/0x245880.
    // New header layout — length bits are scrambled:
    //   length = (hdr & 3) | ((hdr >> 5) & 0x3FC)
    //   isWide = bit15 (header < 0 as int16), unchanged
    // Key schedule:
    //   key = (uint16)(length - 17564)
    //   ANSI: byte[i] ^= keyTable[52 + ((key + i) & 0x3F)] >> 3
    //   Wide: word[i] ^= keyTable[52 + ((key + i) & 0x3F)]
    std::string DecryptNameString(uint64_t name_entry_ptr) {
        if (!name_entry_ptr || !m_keyLoaded) return {};

        int16_t header_s = 0;
        if (!m_reader.Read(name_entry_ptr, &header_s, 2) || !header_s) return {};

        uint16_t header = static_cast<uint16_t>(header_s);
        bool isWide = (header_s < 0);
        int charCount = (header & 3) | ((header >> 5) & 0x3FC);
        if (charCount <= 0 || charCount >= 1023) return {};

        int byteCount = isWide ? charCount * 2 : charCount;
        if (byteCount > 2048) byteCount = 2048;

        std::vector<uint8_t> buf(byteCount, 0);
        if (!m_reader.Read(name_entry_ptr + 2, buf.data(), byteCount)) return {};

        constexpr int TBL = ArcDecrypt::Patch20260421::FNameEntry20260421::KEY_TABLE_UINT16_OFFSET;
        uint16_t key = static_cast<uint16_t>(
            charCount + ArcDecrypt::Patch20260421::FNameEntry20260421::KEY_START_BIAS);

        if (!isWide) {
            for (int i = 0; i < charCount && i < byteCount; ++i)
                buf[i] ^= static_cast<uint8_t>(m_keyTable[TBL + ((key + i) & 0x3F)] >> 3);
            return std::string(reinterpret_cast<char*>(buf.data()), charCount);
        } else {
            auto* wbuf = reinterpret_cast<uint16_t*>(buf.data());
            int wcharCount = byteCount / 2;
            for (int i = 0; i < wcharCount; ++i)
                wbuf[i] ^= m_keyTable[TBL + ((key + i) & 0x3F)];
            std::string result;
            result.reserve(wcharCount);
            for (int n = 0; n < wcharCount; ++n)
                if (wbuf[n]) result += static_cast<char>(wbuf[n] & 0xFF);
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
        // obj+0x28 → bswap64(h ^ sentinel) = FNameEntry*. Try a few candidate
        // offsets (observed +0x28 on live UObjects; +0x18 as legacy fallback).
        for (uint64_t off : {uint64_t(0x28), uint64_t(0x18), uint64_t(0x30)}) {
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
    std::string CompIndexToName(int32_t comp_index) {
        if (!comp_index || !m_keyLoaded) return {};
        uint64_t nptr = ResolveNamePtrFromDecoded(static_cast<uint32_t>(comp_index));
        if (!nptr) return {};
        std::string s = DecryptNameString(nptr);
        // Strict sanity check for class/enum/struct names
        if (s.empty() || s.size() > 256) return {};
        for (unsigned char c : s) {
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == ':' ||
                  c == '/' || c == '.' || c == ' ' || c == '-'))
                return {};
        }
        return s;
    }

    // Lenient version for FField names — accepts any printable ASCII
    std::string CompIndexToNameLenient(int32_t comp_index) {
        if (!comp_index || !m_keyLoaded) return {};
        uint64_t nptr = ResolveNamePtrFromDecoded(static_cast<uint32_t>(comp_index));
        if (!nptr) return {};
        std::string s = DecryptNameString(nptr);
        if (s.empty() || s.size() > 256) return {};
        int bad = 0;
        for (unsigned char c : s)
            if (c < 32 || c > 126) ++bad;
        if (bad * 4 > (int)s.size()) return {};
        return s;
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
        uint64_t cls = GetClassPrivate(obj_ptr);
        for (int slot = 0; slot < 4; ++slot) {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_ptr + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) continue;
            uint64_t dec = DecryptUObjSlotNew(enc);
            if ((dec >> 32) == 0 && dec >= 0x100000ULL && dec < 0x800000000000ULL && dec != cls) {
                return dec;
            }
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
    uint64_t       m_base;
    IMemoryReader& m_reader;
    bool           m_keyLoaded;
    uint16_t       m_keyTable[256];

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
