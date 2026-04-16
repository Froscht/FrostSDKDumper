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
static constexpr uint64_t FNAME_GNAMES_BASE_OFF     = ArcDecrypt::RVA_GNAMES_BASE;
static constexpr uint64_t FNAME_KEY_TABLE_OFF       = ArcDecrypt::RVA_FNAME_KEY_TABLE;

// CIdx / FName SIMD tables (patch 20260414)
static constexpr uint64_t RVA_CIDX_XOR1_OFF          = ArcDecrypt::RVA_CIDX_XOR1;
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

    // ── Step 2: decrypt UObject FName slot → comp_index ──────────────────
    // Pipeline (patch 20260402): PSHUFB(ABE2BD0) → PXOR(ABE2BE0) → ROL64(58) → PSHUFLW(30) → lo32
    // Slot layout: 4 slots at obj+0x20, +0x40, +0x60, +0x80 (stride=0x20)
    int32_t GetCompIndex(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;

        uint32_t slot = ArcDecrypt::GetFNameSlotIndex(obj_base);
        uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(addr, enc, 16)) return 0;

        return static_cast<int32_t>(DecryptSlot16(enc));
    }

    // ── UObject::GetClassPrivate → UClass* pointer ───────────────────────
    // Same slot decrypt pipeline as GetCompIndex; slot selected by GetClassSlotIndex.
    uint64_t GetClassPrivate(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;

        uint32_t slot = ArcDecrypt::GetClassSlotIndex(obj_base);
        uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(addr, enc, 16)) return 0;

        return DecryptPtrSlot(enc);  // pointer via ROL64(15)
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
        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(ff_addr + ArcDecrypt::Offsets::FField::NameEncrypted, enc, 16))
            return 0;

        // Step 1: PSHUFLW(0x39)
        __m128i v = _mm_loadl_epi64((const __m128i*)enc);
        __m128i s1 = _mm_shufflelo_epi16(v, 0x39);
        // Step 2: ROL64(33)
        __m128i r = _mm_or_si128(_mm_slli_epi64(s1, 33), _mm_srli_epi64(s1, 31));
        // Steps 3-5 combined: PSHUFB → XOR(effective_key)
        // The AND/ANDNOT blend + PXOR combine into: PSHUFB(val) XOR effective_key
        // where effective_key = flip_mask XOR pxor_key (same for all call sites)
        alignas(16) static const uint8_t SHUF[16] = {0x07,0x02,0x03,0x06,0x05,0x00,0x01,0x04,0,0,0,0,0,0,0,0};
        __m128i shuffled = _mm_shuffle_epi8(r, _mm_load_si128((const __m128i*)SHUF));
        alignas(16) static const uint8_t EFF_KEY[16] = {0x31,0x7E,0x97,0x77,0x56,0x27,0x31,0x31,0,0,0,0,0,0,0,0};
        __m128i result = _mm_xor_si128(shuffled, _mm_load_si128((const __m128i*)EFF_KEY));
        // Step 6: ROL64(32) → lo32 = CI
        uint64_t lo64 = static_cast<uint64_t>(_mm_cvtsi128_si64(result));
        return static_cast<int32_t>(fn_rotl64(lo64, 32) & 0xFFFFFFFF);
    }

    // ── FFieldClass → type name comp_index ───────────────────────────────
    // FFieldClass does not store a plain FName at a discoverable offset in the known
    // 128-byte layout.  Type identification is done via vtable-to-type map in the
    // SDK generator (AutoDiscoverVTables).  This function is kept as a no-op fallback.
    int32_t DecryptFFieldClassNameCI(uint64_t /*fclass_addr*/) {
        return 0;
    }

    // ── Step 4-7: comp_index → FNameEntry heap address (patch 20260414) ──
    // CI is a 29-bit pool index: bits 16..28 = chunk_idx, bits 0..15 = name_offset_word
    // Chunk header at GNAMES + 0xC8 + chunk_idx*0x40 (stride 0x40).
    //   chunk_header + 0x08 = per-chunk heap block pointer (unused by this resolver)
    //   chunk_header + 0x10 = module cache pointer (SHARED across all chunks; same value)
    // Per game's FNamePool_FindOrAddEntry (sub_2408F0 in qoc9):
    //   sub_block_addr = module_cache_ptr + ((CI >> 8) & 0x1FFF00)
    //   FNV hash sub_block_addr+16 to pick block_idx
    //   Decrypt 2 adjacent 16-byte blocks; combine via FNV-fold; add name_offset.
    // Block decrypt: PSHUFLW(45) → ROL16(15)
    // FNV fold: ROL64(57,42), P=0x100000001B3, ADD=0x2AE2DE663CDF7F3A
    // Pointer fixup: bswap64(R^XOR1) ^ XOR2 → bswap64(^XOR3)
    uint64_t ResolveNamePtrFull(int32_t comp_index) {
        if (comp_index <= 0 || !m_keyLoaded) return 0;

        uint32_t ci = static_cast<uint32_t>(comp_index) & 0x1FFFFFFF;
        uint64_t name_offset    = 2ULL * (ci & 0xFFFF);
        uint64_t sub_block_off  = (static_cast<uint64_t>(ci) >> 8) & 0x1FFF00ULL;

        uint64_t gnames = m_base + FNAME_GNAMES_BASE_OFF;

        // Read shared module cache pointer (same value for all chunks; just use chunk 0).
        uint64_t module_cache = 0;
        if (!m_reader.Read(gnames + 0xC8 + 0x10, &module_cache, 8) || !module_cache)
            return 0;

        uint64_t block_base = module_cache + sub_block_off;

        // Block hash: FNV32 on (block_base + 16)
        constexpr uint32_t P32 = ArcDecrypt::FNV32_SLOT_PRIME;
        constexpr uint32_t BK  = ArcDecrypt::FNAME_BHASH_ADD;
        uint64_t seed = block_base + 16;
        uint32_t lo = static_cast<uint32_t>(seed);
        uint32_t hi = static_cast<uint32_t>(seed >> 32);
        uint32_t h = fn_rotl32(lo, 20);
        h = P32 * h + BK;
        h = fn_rotl32(h, 22);
        h = P32 * h + hi + BK;
        h = fn_rotl32(h, 20);
        h = P32 * h + BK;
        h >>= 10;
        uint32_t v9 = P32 * h + BK;
        uint8_t bidx = static_cast<uint8_t>(v9) ^ static_cast<uint8_t>(v9 >> 16);

        // Read two adjacent blocks
        uint64_t b1_addr = block_base + 32 + 32ULL * (bidx & 7);
        uint64_t b2_addr = block_base + 32 + 32ULL * ((bidx + 1) & 7);
        alignas(16) uint8_t sb1[16] = {}, sb2[16] = {};
        if (!m_reader.Read(b1_addr, sb1, 16)) return 0;
        if (!m_reader.Read(b2_addr, sb2, 16)) return 0;

        // Block decrypt: PSHUFLW(45) → ROL16(15)
        auto decryptBlock = [](__m128i raw) -> uint64_t {
            __m128i shuf = _mm_shufflelo_epi16(raw, 0x2D);
            __m128i rot = _mm_or_si128(_mm_slli_epi16(shuf, 15), _mm_srli_epi16(shuf, 1));
            return static_cast<uint64_t>(_mm_cvtsi128_si64(rot));
        };
        uint64_t v12 = decryptBlock(_mm_load_si128((const __m128i*)sb1));
        uint64_t v13 = decryptBlock(_mm_load_si128((const __m128i*)sb2));

        // FNV fold
        constexpr uint64_t P64 = ArcDecrypt::FNAME_FNV_PRIME;
        constexpr uint64_t FO  = ArcDecrypt::FNAME_FNV_OFFSET;
        uint64_t fnv = P64 * fn_rotl64(v12, ArcDecrypt::FNAME_FNV_ROL1) + FO;
        fnv = P64 * fn_rotl64(fnv, ArcDecrypt::FNAME_FNV_ROL2) + FO;

        uint64_t R = v12 + (fnv ^ v13) + name_offset;

        // Pointer fixup chain
        uint64_t a = __builtin_bswap64(R ^ ArcDecrypt::FNAME_PTR_XOR1);
        uint64_t b = a ^ ArcDecrypt::FNAME_PTR_XOR2;
        return __builtin_bswap64(b ^ ArcDecrypt::FNAME_PTR_XOR3);
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

    // ── Step 8: read + decrypt FNameEntry string (patch 20260414) ──────────
    // Header: isWide = bit15 (header < 0 as int16), charCount = header & 0x3FF
    // ANSI: key = (uint16)(charCount - 25184); buf[i] ^= keyTable[(key+i) & 0x3F] >> 3
    // Wide: key = charCount + 40352; word[i] ^= keyTable[(key+i) & 0x3F]
    std::string DecryptNameString(uint64_t name_entry_ptr) {
        if (!name_entry_ptr || !m_keyLoaded) return {};

        int16_t header_s = 0;
        if (!m_reader.Read(name_entry_ptr, &header_s, 2) || !header_s) return {};

        uint16_t header = static_cast<uint16_t>(header_s);
        bool isWide = (header_s < 0);
        int charCount = header & 0x3FF;
        // Be lenient: reject clearly invalid (1023 = max, often stale) but accept the rest
        if (charCount <= 0 || charCount >= 1023) return {};

        int byteCount = isWide ? charCount * 2 : charCount;
        if (byteCount > 2048) byteCount = 2048;

        std::vector<uint8_t> buf(byteCount, 0);
        if (!m_reader.Read(name_entry_ptr + 2, buf.data(), byteCount)) return {};

        if (!isWide) {
            int key = static_cast<uint16_t>(charCount + ArcDecrypt::FNAME_ANSI_KEY_BASE);
            for (int i = 0; i < charCount && i < byteCount; ++i)
                buf[i] ^= static_cast<uint8_t>(m_keyTable[(key + i) & 0x3F] >> 3);
            return std::string(reinterpret_cast<char*>(buf.data()), charCount);
        } else {
            auto* wbuf = reinterpret_cast<uint16_t*>(buf.data());
            int wcharCount = byteCount / 2;
            int key = charCount + ArcDecrypt::FNAME_WIDE_KEY_BASE;
            for (int i = 0; i < wcharCount; ++i)
                wbuf[i] ^= m_keyTable[(key + i) & 0x3F];
            std::string result;
            result.reserve(wcharCount);
            for (int n = 0; n < wcharCount; ++n)
                if (wbuf[n]) result += static_cast<char>(wbuf[n] & 0xFF);
            return result;
        }
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

    // ── Outer pointer from the outer slot ────────────────────────────────
    // OuterPrivate slot = (class_slot + 1) & 3. Confirmed from sub_1404E2130: `inc r8d; and r8d, 3`.
    // Pipeline: PSHUFLW(0x93) → XOR(sentinel) → ROL64(15) → ptr.
    uint64_t GetOuterPtr(uint64_t obj_ptr) {
        if (!obj_ptr) return 0;
        uint32_t os   = ArcDecrypt::GetOuterSlotIndex(obj_ptr);
        uint64_t addr = obj_ptr + 0x20 + static_cast<uint64_t>(os) * 0x20;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(addr, enc, 16)) return 0;

        return DecryptPtrSlot(enc);
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
