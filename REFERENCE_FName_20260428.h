#pragma once
#include <string>
#include <cstdint>
#include <immintrin.h>
 
// ===== PORTABLE HELPERS =====
 
static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
 
static inline uint64_t u64_lo(__m128i v) {
    alignas(16) uint64_t arr[2];
    _mm_store_si128(reinterpret_cast<__m128i*>(arr), v);
    return arr[0];
}
 
static inline uint32_t u32_lo(__m128i v) {
    return static_cast<uint32_t>(_mm_cvtsi128_si32(v));
}
 
 
// ===== OFFSETS (imagebase 7FF69D4A0000) =====
 
constexpr uint64_t GNAMES_BASE_OFFSET     = 0xDB5BE80;   // unk_7FF6AAFFBE80
constexpr uint64_t FNAME_KEY_TABLE_OFFSET  = 0xDAA0804;   // unk_7FF6AAF407F4 + 8 WORDs (+16 bytes)
 
 
// ===== SIMD CONSTANTS (all script-verified) =====
 
// Actor decrypt: shuffle_epi8(mask) -> ROL32(17) -> XOR(scalar) -> ROL64(32)
// xmmword_7FF6A8203080 = 0x0000000000000000_0502030704000601
alignas(16) inline const uint8_t ACTOR_SHUF_MASK[16] = {
    0x01, 0x06, 0x00, 0x04, 0x07, 0x03, 0x02, 0x05,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
constexpr uint64_t ACTOR_DECRYPT_XOR = 0x4834C6DEA02581C7ULL;
 
// GNames index stage 1: shuffle_epi8(ci, SHUF1) -> XOR(XOR1) -> ROL32(17) -> shufflelo(177)
// xmmword_7FF6A81E9100
alignas(16) inline const uint8_t GIDX_SHUF1[16] = {
    0x00, 0x02, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00
};
// xmmword_7FF6A81E9110 (shared XOR key)
alignas(16) inline const uint8_t GIDX_XOR1[16] = {
    0xBC, 0xBD, 0x4B, 0x43, 0xC8, 0x09, 0xFF, 0x4B,
    0xBC, 0xBD, 0x4B, 0x43, 0xC8, 0x09, 0xFF, 0x4B
};
 
// Stage 2 XOR: xmmword_7FF6A81E9390
alignas(16) inline const uint8_t STAGE2_XOR[16] = {
    0x00, 0xBD, 0x00, 0x43, 0xC8, 0x09, 0x00, 0x00,
    0x00, 0xBD, 0x00, 0x43, 0xC8, 0x09, 0x00, 0x00
};
 
// Stage 3 extract: shuffle_epi8(9140) -> XOR(9150)
// xmmword_7FF6A81E9140
alignas(16) inline const uint8_t EXTRACT_SHUF[16] = {
    0x05, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// xmmword_7FF6A81E9150
alignas(16) inline const uint8_t EXTRACT_XOR[16] = {
    0x09, 0x43, 0xBD, 0xC8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
 
// Block decrypt: shuffle_epi8(SHUF) -> ROL16(5) -> XOR(scalar)
// stru_7FF6A81E9130 (raw bytes)
alignas(16) inline const uint8_t BLOCK_SHUF[16] = {
    0x05, 0x00, 0x06, 0x04, 0x03, 0x07, 0x02, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
constexpr uint64_t BLOCK_POST_XOR = 0x9F737271C0F041C4ULL;
 
 
// ===== SCALAR CONSTANTS =====
 
// Main hash: ROL32(25/27), >>7, >>5, additive 290405715
constexpr uint32_t HASH_PRIME    = 16777619u;
constexpr uint32_t HASH_ADD_MAIN = 290405715u;  // 0x114E4953
 
// Block hash: |0x40000000, >>6, ROL32(28), >>6, >>4, additive -904904318
constexpr uint32_t BHASH_ADD = static_cast<uint32_t>(-904904318);  // 0xCA104182
constexpr uint32_t CHUNK_HASH_SEED_OFF  = 28816;   // 0x7090
constexpr uint32_t CHUNK_BLOCK_BASE_OFF = 28832;    // 0x70A0
 
// FNV fold
constexpr uint64_t FNV_PRIME  = 0x100000001B3ULL;
constexpr uint64_t FNV_OFFSET = 0x7631B6D6E2D67842ULL;  // added
 
// Pointer fixup chain XORs
constexpr uint64_t PTR_XOR_1 = 0xBD8F879CULL;
constexpr uint64_t PTR_XOR_2 = 0x003E22B700000000ULL;
constexpr uint64_t PTR_XOR_3 = 0x9CB9AD0A00000000ULL;
 
 
// ===== GLOBALS =====
 
inline WORD g_wFNameKeyTable[64] = { 0 };
inline bool g_bReadFNameKeyTable = false;
 
 
// ===== HASH FUNCTIONS =====
 
// ROL32(25) -> *P+ADD -> ROL32(27) -> *P+hi+ADD -> >>7 -> *P+ADD -> >>5 -> *P+ADD
// Index: ((v7 ^ HIWORD(v7)) & 3) ^ 2
inline uint32_t ComputeHashAndIndex(uintptr_t base_addr, uint32_t& out_idx)
{
    uint64_t ptr = base_addr + 0x10;
    uint32_t lo = static_cast<uint32_t>(ptr);
    uint32_t hi = static_cast<uint32_t>(ptr >> 32);
 
    uint32_t h = rotl32(lo, 25);
    h = HASH_PRIME * h + HASH_ADD_MAIN;
    h = rotl32(h, 27);
    h = HASH_PRIME * h + hi + HASH_ADD_MAIN;
    h >>= 7;
    h = HASH_PRIME * h + HASH_ADD_MAIN;
    h >>= 5;
    uint32_t v7 = HASH_PRIME * h + HASH_ADD_MAIN;
 
    out_idx = ((static_cast<uint8_t>(v7) ^ static_cast<uint8_t>(v7 >> 16)) & 3u) ^ 2u;
    return v7;
}
 
// Block hash: (lo>>6)|0x40000000 -> *P+BHASH -> ROL32(28) -> *P+hi+BHASH -> >>6 -> *P+BHASH -> >>4
// Index: (-109*h-126) ^ ((P*h+BHASH)>>16) & 7
inline uint8_t ComputeBlockIdx(uintptr_t chunk_addr)
{
    uint64_t seed = chunk_addr + CHUNK_HASH_SEED_OFF;
    uint32_t lo = static_cast<uint32_t>(seed);
    uint32_t hi = static_cast<uint32_t>(seed >> 32);
 
    // (lo | 0x1000000000) >> 6 = (lo >> 6) | 0x40000000
    uint32_t h = (lo >> 6) | 0x40000000u;
    h = HASH_PRIME * h + BHASH_ADD;
    h = rotl32(h, 28);
    h = HASH_PRIME * h + hi + BHASH_ADD;
    h >>= 6;
    h = HASH_PRIME * h + BHASH_ADD;
    h >>= 4;
 
    uint32_t nxt = HASH_PRIME * h + BHASH_ADD;
    return static_cast<uint8_t>(static_cast<uint8_t>(-109 * h - 126) ^ static_cast<uint8_t>(nxt >> 16));
}
 
 
// ===== ACTOR FNAME ID DECRYPT =====
// Pipeline: shuffle_epi8(mask) -> ROL32(17) -> XOR(0x4834C6DEA02581C7) -> ROL64(32)
 
inline uint64_t DecryptFNameRaw(const __m128i& enc)
{
    __m128i shuf = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(ACTOR_SHUF_MASK));
    __m128i shuffled = _mm_shuffle_epi8(enc, shuf);
    __m128i rot = _mm_or_si128(_mm_slli_epi32(shuffled, 17), _mm_srli_epi32(shuffled, 15));
    uint64_t raw = u64_lo(rot) ^ ACTOR_DECRYPT_XOR;
    return rotl64(raw, 32);
}
 
inline int32_t GetActorFNameId(uintptr_t actor_base)
{
    if (!ValidPtr(actor_base))
        return 0;
 
    uint32_t idx = 0;
    ComputeHashAndIndex(actor_base, idx);
 
    uint64_t addr = actor_base + static_cast<uint64_t>(idx) * 32 + 0x20;
    if (!ValidPtr(addr))
        return 0;
 
    __m128i enc = {};
    mem::read_physical2(addr, &enc, sizeof(__m128i));
 
    return static_cast<int32_t>(DecryptFNameRaw(enc));
}
 
 
// ===== GNAMES INDEX TRANSFORM =====
// Stage 1: shuffle_epi8(ci, SHUF1) -> XOR(XOR1) -> ROL32(17) -> shufflelo(177)
// Stage 2: shufflelo(s1, 177) -> ROL32(15) -> shuffle_epi32(68) -> XOR(9390) -> XOR(9110) -> ROL32(17) -> shufflelo(177)
// Stage 3: shufflelo(s2, 177) -> ROL32(15) -> shuffle_epi8(EXTRACT) -> XOR(EXTRACT_XOR)
 
struct GNamesLocation {
    uint32_t v5;
    uint64_t name_offset;
    uint64_t chunk_off;
};
 
inline GNamesLocation ComputeGNamesLocation(int32_t comp_index)
{
    __m128i shuf1  = _mm_load_si128(reinterpret_cast<const __m128i*>(GIDX_SHUF1));
    __m128i xor1   = _mm_load_si128(reinterpret_cast<const __m128i*>(GIDX_XOR1));
    __m128i s2xor  = _mm_load_si128(reinterpret_cast<const __m128i*>(STAGE2_XOR));
    __m128i eshuf  = _mm_load_si128(reinterpret_cast<const __m128i*>(EXTRACT_SHUF));
    __m128i exor   = _mm_load_si128(reinterpret_cast<const __m128i*>(EXTRACT_XOR));
 
    // Stage 1
    __m128i ci = _mm_cvtsi32_si128(comp_index);
    __m128i t1 = _mm_xor_si128(_mm_shuffle_epi8(ci, shuf1), xor1);
    __m128i r1 = _mm_or_si128(_mm_slli_epi32(t1, 17), _mm_srli_epi32(t1, 15));
    __m128i state1 = _mm_shufflelo_epi16(r1, 0xB1);   // 177
 
    // Stage 2
    __m128i s2a = _mm_shufflelo_epi16(state1, 0xB1);   // 177
    __m128i s2b = _mm_or_si128(_mm_slli_epi32(s2a, 15), _mm_srli_epi32(s2a, 17));
    __m128i s2c = _mm_shuffle_epi32(s2b, 0x44);        // 68
    __m128i s2d = _mm_xor_si128(_mm_xor_si128(s2c, s2xor), xor1);
    __m128i s2e = _mm_or_si128(_mm_slli_epi32(s2d, 17), _mm_srli_epi32(s2d, 15));
    __m128i state2 = _mm_shufflelo_epi16(s2e, 0xB1);   // 177
 
    // Stage 3
    __m128i s3a = _mm_shufflelo_epi16(state2, 0xB1);   // 177
    __m128i s3b = _mm_or_si128(_mm_slli_epi32(s3a, 15), _mm_srli_epi32(s3a, 17));
    __m128i s3c = _mm_shuffle_epi8(s3b, eshuf);
    __m128i s3d = _mm_xor_si128(s3c, exor);
    uint32_t v5 = u32_lo(s3d);
 
    GNamesLocation loc;
    loc.v5          = v5;
    loc.name_offset = 2ULL * static_cast<uint16_t>(v5);
    loc.chunk_off   = (static_cast<uint64_t>(v5) >> 8) & 0xFFFF00ULL;
    return loc;
}
 
 
// ===== BLOCK DECRYPT =====
// Pipeline: shuffle_epi8(data, BLOCK_SHUF) -> ROL16(5) -> XOR(0x9F737271C0F041C4)
 
inline uint64_t DecryptBlock(const __m128i& raw)
{
    __m128i bshuf = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(BLOCK_SHUF));
    __m128i shuffled = _mm_shuffle_epi8(raw, bshuf);
    __m128i rot = _mm_or_si128(_mm_slli_epi16(shuffled, 5), _mm_srli_epi16(shuffled, 11));
    return u64_lo(rot) ^ BLOCK_POST_XOR;
}
 
 
// ===== RESOLVE NAME ENTRY POINTER =====
 
inline uintptr_t ResolveNamePtr(int32_t comp_index)
{
    GNamesLocation loc = ComputeGNamesLocation(comp_index);
 
    uintptr_t gnames_base = process_base + GNAMES_BASE_OFFSET;
    uintptr_t chunk_addr  = gnames_base + loc.chunk_off;
 
    // ---- block selector hash ----
    uint8_t bidx = ComputeBlockIdx(chunk_addr);
    uintptr_t block_base = chunk_addr + CHUNK_BLOCK_BASE_OFF;
 
    // ---- block 1 decrypt ----
    uintptr_t b1addr = block_base + 32ULL * (bidx & 7u);
    __m128i sb1 = {};
    mem::read_physical2(b1addr, &sb1, sizeof(__m128i));
    uint64_t v14 = DecryptBlock(sb1);
 
    // ---- block 2 decrypt ----
    uintptr_t b2addr = block_base + 32ULL * ((bidx + 1u) & 7u);
    __m128i sb2 = {};
    mem::read_physical2(b2addr, &sb2, sizeof(__m128i));
    uint64_t v15_dec = DecryptBlock(sb2);
 
    // ---- FNV fold (rots 50/56, added offset) ----
    uint64_t fnv = FNV_PRIME * rotl64(v14, 50) + FNV_OFFSET;
    fnv = FNV_PRIME * rotl64(fnv, 56) + FNV_OFFSET;
 
    // ---- compute raw result ----
    uint64_t R = v14 + (fnv ^ v15_dec) + loc.name_offset;
 
    // ---- pointer fixup chain ----
    uint64_t a = _byteswap_uint64(R ^ PTR_XOR_1);
    uint64_t b = a ^ PTR_XOR_2;
    uint64_t name_ptr = _byteswap_uint64(b ^ PTR_XOR_3);
 
    return static_cast<uintptr_t>(name_ptr);
}
 
 
// ===== NAME STRING DECRYPT =====
// Header:
//   v3 = header & 0x7F
//   v4 = (header >> 5) & 0x380
//   charCount = v4 + v3
//   isWide = bit 15 (header < 0)
// Key: init = charCount - 68
// Step: key_next = 16*key - 32
// Offset: (68*key + 96) & 0x3C  (note: &0x3C not &0x3F!)
// Table: g_wFNameKeyTable[key & 0x3F], ANSI uses >>3
 
inline std::string DecryptNameString(uintptr_t name_entry_ptr)
{
    int16_t header_s = 0;
    mem::read_physical2(name_entry_ptr, &header_s, sizeof(int16_t));
    if (!header_s)
        return "";
 
    uint16_t header = static_cast<uint16_t>(header_s);
    bool isWide    = (header_s < 0);
    uint16_t v3    = header & 0x7F;
    uint16_t v4    = (header >> 5) & 0x380;
    int charCount  = v4 + v3;
    if (charCount <= 0 || charCount > 1023)
        return "";
 
    int byteCount = isWide ? charCount * 2 : charCount;
    int modLen    = (byteCount > 2048) ? 2048 : byteCount;
 
    uintptr_t stringAddr = name_entry_ptr + 2;
    if (!IsUsermodePtr(stringAddr))
        return "";
 
    char buf[2048] = { 0 };
    mem::read_physical2(stringAddr, buf, modLen);
 
    if (isWide)
    {
        uint16_t* wbuf = reinterpret_cast<uint16_t*>(buf);
        int wcharCount = modLen / 2;
        char key = static_cast<char>(charCount - 68);
        int i = 0;
 
        for (; i + 1 < charCount; i += 2)
        {
            if (i < wcharCount)
                wbuf[i] ^= g_wFNameKeyTable[key & 0x3F];
            if (i + 1 < wcharCount)
                wbuf[i + 1] ^= g_wFNameKeyTable[(68 * key + 96) & 0x3C];
            key = static_cast<char>(16 * key - 32);
        }
        if ((charCount & 1) && i < wcharCount)
            wbuf[i] ^= g_wFNameKeyTable[key & 0x3F];
 
        std::string result;
        result.reserve(wcharCount);
        for (int j = 0; j < wcharCount; j++) {
            if (wbuf[j] != 0) result += static_cast<char>(wbuf[j] & 0xFF);
        }
        return result;
    }
    else
    {
        char key = static_cast<char>(charCount - 68);
        int i = 0;
        // ANSI loopCount = v3 | v4
        int loopCount = v3 | v4;
 
        for (; i + 1 < loopCount; i += 2)
        {
            if (i < modLen)
                buf[i] ^= static_cast<char>(g_wFNameKeyTable[key & 0x3F] >> 3);
            if (i + 1 < modLen)
                buf[i + 1] ^= static_cast<char>(g_wFNameKeyTable[(68 * key + 96) & 0x3C] >> 3);
            key = static_cast<char>(16 * key - 32);
        }
        if ((loopCount & 1) && i < modLen)
            buf[i] ^= static_cast<char>(g_wFNameKeyTable[key & 0x3F] >> 3);
 
        int outLen = (charCount < modLen) ? charCount : modLen;
        return std::string(buf, outLen);
    }
}
 
 
// ===== MAIN ENTRY =====
 
inline std::string GetActorFNameString(uintptr_t actor_base)
{
    if (!ValidPtr(actor_base))
        return "";
 
    try
    {
        // ---- lazy-load key table ----
        if (!g_bReadFNameKeyTable) {
            uintptr_t kt_addr = process_base + FNAME_KEY_TABLE_OFFSET;
            if (!IsUsermodePtr(kt_addr))
                return "";
            mem::read_physical2(kt_addr, g_wFNameKeyTable, 64 * sizeof(WORD));
            if (!g_wFNameKeyTable[0] && !g_wFNameKeyTable[1])
                return "";
            g_bReadFNameKeyTable = true;
        }
 
        // ---- get ComparisonIndex ----
        int32_t comp_index = GetActorFNameId(actor_base);
        if (comp_index == 0)
            return "";
 
        // ---- resolve name entry pointer ----
        uintptr_t name_ptr = ResolveNamePtr(comp_index);
        if (!IsUsermodePtr(name_ptr))
            return "";
 
        // ---- decrypt name string ----
        return DecryptNameString(name_ptr);
    }
    catch (...)
    {
        return "";
    }
}