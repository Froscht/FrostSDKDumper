#pragma once

// =============================================================================
// ARC Raiders – FName decryption pipeline (newest patch)
//
// ALL FNamePool stages updated from Fname.txt reference implementation:
//   1. Key table RVA: 0xD7D6804 (was 0xD841864)
//   2. GNames base: 0xD892880 (was 0xD8FD880)
//   3. ComputeGNamesLocation: new 3-stage SIMD pipeline (was simple bit extract)
//   4. ComputeBlockIdx: >>4, ROL16/28/16, +1133438190, seed+9472 (all changed)
//   5. DecryptBlock: shufflelo(57) → ROL64(51) → shuffle_epi8 → XOR (all changed)
//   6. FNV: ROL 38/31, +0x5BD41B159509682E (was ROL 36/43, -0x77011A...)
//   7. Pointer fixup: 3-step XOR+bswap chain (was none)
//   8. DecryptNameString: header bit0=wide, key=-81, step=-95k-72, off=81k+124
//   9. Actor name: shufflelo(27) → ROL16(13) → shuffle_epi8(runtime table) (unchanged)
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
// FNamePool Constants (ALL updated from Fname.txt)
// ─────────────────────────────────────────────────────────────────────────────

// Pool base and key table
static constexpr uint64_t FNAME_GNAMES_BASE_OFF    = 0xD892880;
static constexpr uint64_t FNAME_KEY_TABLE_OFF       = 0xD7D6804;

// Hash primitives
static constexpr uint32_t FNAME_HASH_PRIME = 16777619u;

// ComputeBlockIdx constants
static constexpr uint32_t FNAME_CHUNK_SEED_OFF       = 9472u;
static constexpr uint32_t FNAME_CHUNK_BLOCK_BASE_OFF  = 9488u;
static constexpr uint32_t FNAME_BHASH_ADD             = 1133438190u;  // 0x438FB4EE

// GNames index SIMD stage 1: shuffle_epi8(cvtsi32(ci), mask) → XOR(key) → ROL32(11)
alignas(16) static const uint8_t GIDX_SHUF1[16] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03
};
alignas(16) static const uint8_t GIDX_XOR1[16] = {
    0x89, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x05, 0x46,
    0x89, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x05, 0x46
};

// GNames index SIMD stage 3: shuffle_epi8 mask + XOR scalar
alignas(16) static const uint8_t GIDX_EXTRACT_SHUF[16] = {
    0x04, 0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static constexpr uint32_t GIDX_EXTRACT_XOR = 0x4689054Bu;

// DecryptBlock SIMD keys
alignas(16) static const uint8_t FNAME_BLOCK_SHUF[16] = {
    0x01, 0x04, 0x06, 0x07, 0x05, 0x02, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
alignas(16) static const uint8_t FNAME_BLOCK_XOR_KEY[16] = {
    0xA4, 0x5B, 0xA9, 0xEB, 0x21, 0xAE, 0x9A, 0x4F,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// FNV chain
static constexpr uint64_t FNAME_FNV_PRIME  = 0x100000001B3ULL;
static constexpr uint64_t FNAME_FNV_OFFSET = 0x5BD41B159509682EULL;
static constexpr int      FNAME_FNV_ROL1   = 38;
static constexpr int      FNAME_FNV_ROL2   = 31;

// Pointer fixup chain XORs
static constexpr uint64_t FNAME_PTR_XOR_1 = 0x9B7E4246ULL;
static constexpr uint64_t FNAME_PTR_XOR_2 = 0x5C76BDF000000000ULL;
static constexpr uint64_t FNAME_PTR_XOR_3 = 0x1A34C36B00000000ULL;

// Name string decrypt constants
static constexpr int NAME_KEY_INIT_ADD = -81;
static constexpr int NAME_KEY_STEP_MUL = -95;
static constexpr int NAME_KEY_STEP_ADD = -72;
static constexpr int NAME_KEY_OFF_MUL  = 81;
static constexpr int NAME_KEY_OFF_ADD  = 124;

// ─────────────────────────────────────────────────────────────────────────────
// GNames location computed from comp_index via 3-stage SIMD pipeline
// ─────────────────────────────────────────────────────────────────────────────
struct GNamesLocation {
    uint32_t v5;
    uint64_t name_offset;
    uint64_t chunk_off;
};

static inline GNamesLocation ComputeGNamesLocation(int32_t comp_index) {
    __m128i s1_mask = _mm_load_si128(reinterpret_cast<const __m128i*>(GIDX_SHUF1));
    __m128i s1_xor  = _mm_load_si128(reinterpret_cast<const __m128i*>(GIDX_XOR1));
    __m128i s3_mask = _mm_load_si128(reinterpret_cast<const __m128i*>(GIDX_EXTRACT_SHUF));

    // Stage 1: shuffle_epi8 → XOR → ROL32(11)
    __m128i ci = _mm_cvtsi32_si128(comp_index);
    __m128i x1 = _mm_xor_si128(_mm_shuffle_epi8(ci, s1_mask), s1_xor);
    __m128i state1 = _mm_or_si128(_mm_slli_epi32(x1, 11), _mm_srli_epi32(x1, 21));

    // Stage 2: ROL32(21) → shuffle_epi32(68) → ROL32(11)
    __m128i r2 = _mm_or_si128(_mm_slli_epi32(state1, 21), _mm_srli_epi32(state1, 11));
    __m128i sh2 = _mm_shuffle_epi32(r2, 68);  // 0x44
    __m128i state2 = _mm_or_si128(_mm_slli_epi32(sh2, 11), _mm_srli_epi32(sh2, 21));

    // Stage 3: ROL32(21) → shuffle_epi8 → XOR(scalar)
    __m128i r3 = _mm_or_si128(_mm_slli_epi32(state2, 21), _mm_srli_epi32(state2, 11));
    __m128i sh3 = _mm_shuffle_epi8(r3, s3_mask);
    uint32_t v5 = u32_lo_xmm(sh3) ^ GIDX_EXTRACT_XOR;

    GNamesLocation loc;
    loc.v5          = v5;
    loc.name_offset = 2ULL * static_cast<uint16_t>(v5);
    loc.chunk_off   = (static_cast<uint64_t>(v5) >> 8) & 0xFFFF00ULL;
    return loc;
}

// ─────────────────────────────────────────────────────────────────────────────
// FNameDecryptor
// ─────────────────────────────────────────────────────────────────────────────
class FNameDecryptor {
public:
    FNameDecryptor(uint64_t module_base, IMemoryReader& reader)
        : m_base(module_base), m_reader(reader), m_keyLoaded(false)
    {
        memset(m_keyTable, 0, sizeof(m_keyTable));
        memset(m_actorShufTable, 0, 16);
        memset(m_ffieldShufTable, 0, 16);
    }

    bool Init() {
        if (m_keyLoaded) return true;

        // FName key table
        uint64_t kt_addr = m_base + FNAME_KEY_TABLE_OFF;
        std::printf("[dbg] Reading FName key table @ 0x%llX ...\n", (unsigned long long)kt_addr);
        if (!m_reader.Read(kt_addr, m_keyTable, 64 * sizeof(uint16_t))) {
            std::printf("[-] Failed to read FName key table\n");
            return false;
        }
        if (!m_keyTable[0] && !m_keyTable[1]) {
            std::printf("[-] FName key table is all zeros at 0x%llX\n", (unsigned long long)kt_addr);
            return false;
        }
        std::printf("[+] FName key table OK (first: 0x%04X 0x%04X)\n", m_keyTable[0], m_keyTable[1]);

        // SIMD shuffle table for actor name / class decrypt
        if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_ACTOR_SHUF, m_actorShufTable, 16)) {
            std::printf("[-] Failed to read actor SIMD table\n");
            return false;
        }
        std::printf("[+] Actor SIMD table OK\n");

        // SIMD shuffle table for FField name decrypt
        if (!m_reader.Read(m_base + ArcDecrypt::RVA_SIMD_FFIELD_SHUF, m_ffieldShufTable, 16)) {
            std::printf("[-] Failed to read FField SIMD table\n");
            return false;
        }
        std::printf("[+] FField SIMD table OK\n");

        m_keyLoaded = true;
        return true;
    }

    bool IsInitialized() const { return m_keyLoaded; }

    void DumpKeyTable(int n) const {
        std::printf("[dbg] FName KeyTable (addr=0x%llX, first %d entries):\n",
            (unsigned long long)(m_base + FNAME_KEY_TABLE_OFF), n);
        for (int i = 0; i < n && i < 64; i++)
            std::printf("  [%2d] = 0x%04X\n", i, m_keyTable[i]);
    }

    // ── Step 1: slot index from object address (UObject::GetNamePrivate) ──
    uint32_t GetSlotIndex(uint64_t obj_base) const {
        return ArcDecrypt::GetFNameSlotIndex(obj_base);
    }

    // ── Step 2: decrypt UObject FName slot → comp_index ──────────────────
    // Pipeline: shufflelo(27) → ROL16(13) → shuffle_epi8(runtime table) → ROL64(32) → lo32
    int32_t GetCompIndex(uint64_t obj_base) {
        uint32_t slot = GetSlotIndex(obj_base);
        uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(addr, enc, 16))
            return 0;

        __m128i data = _mm_load_si128(reinterpret_cast<const __m128i*>(enc));

        __m128i shuflo = _mm_shufflelo_epi16(data, 27);
        __m128i rot = _mm_or_si128(
            _mm_slli_epi16(shuflo, 13),
            _mm_srli_epi16(shuflo, 3));
        __m128i result = _mm_shuffle_epi8(rot,
            _mm_load_si128(reinterpret_cast<const __m128i*>(m_actorShufTable)));

        uint64_t packed = u64_lo_xmm(result);
        packed = fn_rotl64(packed, 32);

        return static_cast<int32_t>(packed & 0xFFFFFFFF);
    }

    // ── UObject::GetClassPrivate → UClass* pointer ───────────────────────
    uint64_t GetClassPrivate(uint64_t obj_base) {
        if (!obj_base) return 0;

        uint32_t slot = ArcDecrypt::GetClassSlotIndex(obj_base);
        uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(addr, enc, 16))
            return 0;

        __m128i data = _mm_load_si128(reinterpret_cast<const __m128i*>(enc));

        __m128i shuflo = _mm_shufflelo_epi16(data, 27);
        __m128i rot = _mm_or_si128(
            _mm_slli_epi16(shuflo, 13),
            _mm_srli_epi16(shuflo, 3));
        __m128i result = _mm_shuffle_epi8(rot,
            _mm_load_si128(reinterpret_cast<const __m128i*>(m_actorShufTable)));

        return u64_lo_xmm(result);
    }

    // ── Decrypt FField::NamePrivate → comp_index ─────────────────────────
    // Pipeline: shuffle_epi8(runtime table) → ROL64(15) → shufflelo(30) → ROL64(32) → lo32
    int32_t DecryptFFieldNameCI(uint64_t ff_addr) {
        if (!ff_addr) return 0;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(ff_addr + ArcDecrypt::Offsets::FField::NamePrivate, enc, 16))
            return 0;

        __m128i data = _mm_load_si128(reinterpret_cast<const __m128i*>(enc));

        __m128i shuf = _mm_shuffle_epi8(data,
            _mm_load_si128(reinterpret_cast<const __m128i*>(m_ffieldShufTable)));
        __m128i rot = _mm_or_si128(
            _mm_slli_epi64(shuf, 15),
            _mm_srli_epi64(shuf, 49));
        __m128i shuflo = _mm_shufflelo_epi16(rot, 30);

        uint64_t packed = u64_lo_xmm(shuflo);
        packed = fn_rotl64(packed, 32);

        return static_cast<int32_t>(packed & 0xFFFFFFFF);
    }

    // ── Decrypt FFieldClass::NamePrivate → comp_index ────────────────────
    int32_t DecryptFFieldClassNameCI(uint64_t fclass_addr) {
        if (!fclass_addr) return 0;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(fclass_addr + ArcDecrypt::Offsets::FFieldClass::NamePrivate, enc, 16))
            return 0;

        __m128i data = _mm_load_si128(reinterpret_cast<const __m128i*>(enc));

        // Same pipeline as FField name (TODO: verify)
        __m128i shuf = _mm_shuffle_epi8(data,
            _mm_load_si128(reinterpret_cast<const __m128i*>(m_ffieldShufTable)));
        __m128i rot = _mm_or_si128(
            _mm_slli_epi64(shuf, 15),
            _mm_srli_epi64(shuf, 49));
        __m128i shuflo = _mm_shufflelo_epi16(rot, 30);

        uint64_t packed = u64_lo_xmm(shuflo);
        packed = fn_rotl64(packed, 32);

        return static_cast<int32_t>(packed & 0xFFFFFFFF);
    }

    // ── Step 3: block index for a chunk address (FNamePool) ──────────────
    // Hash: >>4, ROL16/28/16, +BHASH_ADD
    // Final: (-109*v8 - 18) ^ ((P*v8 + BHASH_ADD) >> 16)
    uint8_t ComputeBlockIdx(uint64_t chunk_addr) const {
        uint64_t seed = chunk_addr + FNAME_CHUNK_SEED_OFF;
        uint32_t lo   = static_cast<uint32_t>(seed);
        uint32_t hi   = static_cast<uint32_t>(seed >> 32);

        uint32_t h = lo >> 4;
        h = FNAME_HASH_PRIME * h + FNAME_BHASH_ADD;
        h = fn_rotl32(h, 16);
        h = FNAME_HASH_PRIME * h + hi + FNAME_BHASH_ADD;
        h = fn_rotl32(h, 28);
        h = FNAME_HASH_PRIME * h + FNAME_BHASH_ADD;
        uint32_t v8 = fn_rotl32(h, 16);

        return static_cast<uint8_t>(
            static_cast<uint8_t>(static_cast<uint32_t>(-109) * v8 - 18u) ^
            static_cast<uint8_t>((FNAME_HASH_PRIME * v8 + FNAME_BHASH_ADD) >> 16));
    }

    // ── Step 4: decrypt one 128-bit block → 64-bit value ─────────────────
    // Pipeline: shufflelo(57) → ROL64(51) → shuffle_epi8(mask) → XOR(key)
    uint64_t DecryptBlock(const uint8_t raw[16]) const {
        __m128i v     = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw));
        __m128i bshuf = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(FNAME_BLOCK_SHUF));
        __m128i bxor  = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(FNAME_BLOCK_XOR_KEY));

        // shufflelo(57)
        __m128i s1  = _mm_shufflelo_epi16(v, 57);  // 0x39

        // ROL64(51)
        __m128i rot = _mm_or_si128(
            _mm_slli_epi64(s1, 51),
            _mm_srli_epi64(s1, 13));

        // shuffle_epi8(mask)
        __m128i shuf = _mm_shuffle_epi8(rot, bshuf);

        // XOR(key)
        __m128i xored = _mm_xor_si128(shuf, bxor);

        return u64_lo_xmm(xored);
    }

    // ── Step 5: comp_index → name_entry pointer ──────────────────────────
    // Uses 3-stage SIMD GNames location + FNV + pointer fixup chain
    uint64_t ResolveNamePtr(int32_t comp_index) {
        GNamesLocation loc = ComputeGNamesLocation(comp_index);

        uint64_t pool_base  = m_base + FNAME_GNAMES_BASE_OFF;
        uint64_t chunk_addr = pool_base + loc.chunk_off;

        uint8_t  bidx       = ComputeBlockIdx(chunk_addr);
        uint64_t block_base = chunk_addr + FNAME_CHUNK_BLOCK_BASE_OFF;

        // Block 1
        alignas(16) uint8_t sb1[16] = {};
        uint64_t b1addr = block_base + 32ULL * (bidx & 7u);
        if (!m_reader.Read(b1addr, sb1, 16)) return 0;
        uint64_t v13 = DecryptBlock(sb1);

        // Block 2
        alignas(16) uint8_t sb2[16] = {};
        uint64_t b2addr = block_base + 32ULL * ((bidx + 1u) & 7u);
        if (!m_reader.Read(b2addr, sb2, 16)) return 0;
        uint64_t v14_dec = DecryptBlock(sb2);

        // FNV fold: ROL 38/31, ADDED offset
        uint64_t fnv = FNAME_FNV_PRIME * fn_rotl64(v13, FNAME_FNV_ROL1) + FNAME_FNV_OFFSET;
        fnv          = FNAME_FNV_PRIME * fn_rotl64(fnv, FNAME_FNV_ROL2) + FNAME_FNV_OFFSET;

        // Compute raw result
        uint64_t R = v13 + (v14_dec ^ fnv) + loc.name_offset;

        // Pointer fixup chain: bswap64(R ^ XOR1) → XOR2 → bswap64(result ^ XOR3)
        uint64_t a = __builtin_bswap64(R ^ FNAME_PTR_XOR_1);
        uint64_t b = a ^ FNAME_PTR_XOR_2;
        uint64_t name_ptr = __builtin_bswap64(b ^ FNAME_PTR_XOR_3);

        return name_ptr;
    }

    // ── Step 6: read + decrypt name string ───────────────────────────────
    // Header: bit0 = isWide, bits[1..10] = length
    // Key: init = length - 81, step = -95*key - 72, secondary = (81*key + 124) & 0x3F
    std::string DecryptNameString(uint64_t name_entry_ptr) {
        if (!name_entry_ptr || !m_keyLoaded) return {};

        uint16_t header = 0;
        if (!m_reader.Read(name_entry_ptr, &header, 2) || !header) return {};

        // New header format: bit0 = isWide, bits 1-10 = length
        bool isWide = (header & 1) != 0;
        int  length = (header >> 1) & 0x3FF;
        if (length <= 0 || length > 1024) return {};

        int byteCount = isWide ? length * 2 : length;
        int readLen   = (byteCount > 254) ? 254 : byteCount;

        uint8_t buf[256] = {};
        if (!m_reader.Read(name_entry_ptr + 2, buf, readLen)) return {};

        if (isWide) {
            auto* wbuf   = reinterpret_cast<uint16_t*>(buf);
            int   wCount = readLen / 2;
            char  key    = static_cast<char>(length + NAME_KEY_INIT_ADD);

            for (int i = 0; i + 1 < length; i += 2) {
                if (i     < wCount) wbuf[i]   ^= m_keyTable[key & 0x3F];
                if (i + 1 < wCount) wbuf[i+1] ^= m_keyTable[(NAME_KEY_OFF_MUL * key + NAME_KEY_OFF_ADD) & 0x3F];
                key = static_cast<char>(NAME_KEY_STEP_MUL * key + NAME_KEY_STEP_ADD);
            }
            if ((length & 1) && (length - 1) < wCount)
                wbuf[length - 1] ^= m_keyTable[key & 0x3F];

            std::string result;
            result.reserve(wCount);
            for (int j = 0; j < wCount; ++j)
                if (wbuf[j]) result += static_cast<char>(wbuf[j] & 0xFF);
            return result;
        } else {
            int len = length < readLen ? length : readLen;
            char key = static_cast<char>(length + NAME_KEY_INIT_ADD);

            for (int i = 0; i + 1 < len; i += 2) {
                buf[i]   ^= static_cast<uint8_t>(m_keyTable[key & 0x3F] >> 3);
                buf[i+1] ^= static_cast<uint8_t>(m_keyTable[(NAME_KEY_OFF_MUL * key + NAME_KEY_OFF_ADD) & 0x3F] >> 3);
                key = static_cast<char>(NAME_KEY_STEP_MUL * key + NAME_KEY_STEP_ADD);
            }
            if ((len & 1))
                buf[len - 1] ^= static_cast<uint8_t>(m_keyTable[key & 0x3F] >> 3);
            return std::string(reinterpret_cast<char*>(buf), readLen);
        }
    }

    // ── Full pipeline: object pointer → name string ───────────────────────
    std::string GetName(uint64_t obj_ptr) {
        if (!obj_ptr || !m_keyLoaded) return {};
        int32_t comp = GetCompIndex(obj_ptr);
        if (!comp) return {};
        uint64_t nptr = ResolveNamePtr(comp);
        if (!nptr) return {};
        return DecryptNameString(nptr);
    }

    // ── Resolve comp_index → string ──────────────────────────────────────
    std::string CompIndexToName(int32_t comp_index) {
        if (!comp_index || !m_keyLoaded) return {};
        uint64_t nptr = ResolveNamePtr(comp_index);
        if (!nptr) return {};
        return DecryptNameString(nptr);
    }

    // ── FField address → name string ─────────────────────────────────────
    std::string GetFFieldName(uint64_t ff_addr) {
        int32_t ci = DecryptFFieldNameCI(ff_addr);
        if (!ci) return {};
        return CompIndexToName(ci);
    }

    // ── FFieldClass address → type name string ───────────────────────────
    std::string GetFFieldClassName(uint64_t fclass_addr) {
        int32_t ci = DecryptFFieldClassNameCI(fclass_addr);
        if (!ci) return {};
        return CompIndexToName(ci);
    }

    // ── Outer pointer from the outer slot ────────────────────────────────
    uint64_t GetOuterPtr(uint64_t obj_ptr) {
        if (!obj_ptr) return 0;
        uint32_t fs   = GetSlotIndex(obj_ptr);
        uint32_t os   = (fs + 3u) & 3u;
        uint64_t addr = obj_ptr + 0x20 + static_cast<uint64_t>(os) * 0x20;

        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(addr, enc, 16)) return 0;

        __m128i data = _mm_load_si128(reinterpret_cast<const __m128i*>(enc));

        __m128i shuflo = _mm_shufflelo_epi16(data, 27);
        __m128i rot = _mm_or_si128(
            _mm_slli_epi16(shuflo, 13),
            _mm_srli_epi16(shuflo, 3));
        __m128i result = _mm_shuffle_epi8(rot,
            _mm_load_si128(reinterpret_cast<const __m128i*>(m_actorShufTable)));

        return u64_lo_xmm(result);
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

private:
    uint64_t       m_base;
    IMemoryReader& m_reader;
    bool           m_keyLoaded;
    uint16_t       m_keyTable[64];

    alignas(16) uint8_t m_actorShufTable[16];
    alignas(16) uint8_t m_ffieldShufTable[16];
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
