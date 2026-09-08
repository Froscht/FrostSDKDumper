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

#include <cctype>
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

static inline uint64_t SoftPshuflw(uint64_t Val, int Imm8) {
    uint16_t W[4];
    std::memcpy(W, &Val, 8);
    uint16_t R[4] = {
        W[(Imm8 >> 0) & 3], W[(Imm8 >> 2) & 3],
        W[(Imm8 >> 4) & 3], W[(Imm8 >> 6) & 3]
    };
    uint64_t Out;
    std::memcpy(&Out, R, 8);
    return Out;
}

static inline __m128i SoftPshuflwXmm(__m128i V, uint8_t Imm) {
    uint64_t Lo;
    _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
    Lo = SoftPshuflw(Lo, Imm);
    return _mm_loadl_epi64(reinterpret_cast<const __m128i*>(&Lo));
}

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

    // Patch 2026-08 detector.
    //
    // Deliberately self-validating rather than signature-based: it installs the
    // pipeline, resolves real CompIndexes and demands printable names back. The
    // recurring patch-day failure in this codebase has been detectors that
    // accept a plausible-looking constant and then silently produce garbage
    // (and, worse, persist it to decrypt_export.json), so "does it actually
    // decode names" is the only acceptance test used here.
    bool TryPatch20260805() {
        namespace P805 = ArcDecrypt::v20260805;

        uint64_t KsRva = P805::RVA_FNAME_KEYTABLE;
        if (!m_reader.Read(m_base + KsRva, m_ks805, sizeof(m_ks805))) return false;
        int Nz = 0;
        for (int I = 0; I < 64; ++I) Nz += (m_ks805[I] != 0);
        if (Nz < 32) {
            std::printf("[fname805] keystream @0x%llX only %d/64 nonzero — not this patch\n",
                (unsigned long long)(m_base + KsRva), Nz);
            return false;
        }

        m_patch0805Active = true;
        int Good = 0;
        std::string First;
        for (uint32_t Ci = 1; Ci <= 96 && Good < 8; ++Ci) {
            uint64_t Ep = ResolveNamePtr_Patch20260805(static_cast<int32_t>(Ci));
            if (!Ep) continue;
            std::string S = DecryptNameString_Patch20260805(Ep);
            if (S.empty() || S.size() > 128) continue;
            bool Printable = true;
            for (char C : S)
                if (static_cast<unsigned char>(C) < 0x20 ||
                    static_cast<unsigned char>(C) > 0x7E) { Printable = false; break; }
            if (!Printable) continue;
            if (First.empty()) First = S;
            ++Good;
        }
        if (Good < 4) {
            std::printf("[fname805] pipeline installed but only %d/96 CIs gave readable names "
                        "— rejecting (pool may not be built yet)\n", Good);
            m_patch0805Active = false;
            return false;
        }

        std::memcpy(m_keyTable, m_ks805, sizeof(m_ks805));
        FNAME_KEY_TABLE_OFF = KsRva;
        m_keyLoaded = true;
        // Only now that names actually decode do we trust the rest of the
        // patch's layout enough to install it. It came from the field-writing
        // constructors, so it outranks the live pointer-shape probes.
        ArcDecrypt::Offsets::g_Authoritative = true;
        ArcDecrypt::Offsets::g_AuthoritySrc  = "patch-2026-08 ctor disasm";
        std::printf("[fname805] Pipeline = Patch20260805 (pool @0x%llX, keystream @0x%llX, "
                    "%d nz, %d/96 names OK, first=\"%s\")\n",
            (unsigned long long)(m_base + P805::RVA_GNAMEPOOL),
            (unsigned long long)(m_base + KsRva), Nz, Good, First.c_str());
        return true;
    }

    bool Init() {
        if (m_keyLoaded) return true;

        // Newest patch first — it validates by actually decoding names, so a
        // false positive here is far less likely than in the keytable-nonzero
        // heuristics below.
        if (TryPatch20260805()) return true;

        // ── Dual-pipeline probe ──
        // 1) Try the CL-1177146 keytable RVA. Valid ⇒ legacy pipeline.
        // 2) Otherwise try the 2026-05-19 keytable RVA. Valid ⇒ new pipeline,
        //    additionally pre-load all 9 SIMD-stage masks.
        // 3) If both yield <16 nonzero u16 entries, fall through and let the
        //    legacy path's auto-discovery take over.
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

        bool LegacyLoaded = false;
        if (Use519) {
            std::memcpy(m_keyTable, Kt519, sizeof(Kt519));
            FNAME_KEY_TABLE_OFF = Rva519;
            m_pipeline = Pipeline::Build20260519;
            LegacyLoaded = true;
            std::printf("[fname] Pipeline = Build20260519 (keytable @ 0x%llX, %d nz)\n",
                (unsigned long long)(m_base + Rva519), Nz519);
        } else if (Use146) {
            std::memcpy(m_keyTable, Kt146, sizeof(Kt146));
            FNAME_KEY_TABLE_OFF = Rva146;
            m_pipeline = Pipeline::CL1177146;
            LegacyLoaded = true;
            std::printf("[fname] Pipeline = CL1177146 (keytable @ 0x%llX, %d nz)\n",
                (unsigned long long)(m_base + Rva146), Nz146);
        } else {
            std::printf("[fname] legacy keytables invalid (146=%d nz, 519=%d nz) — trying V707\n",
                Nz146, Nz519);
            m_pipeline = Pipeline::Build20260519;
        }
        if (LegacyLoaded) {
            std::printf("[+] FName key table OK (first: 0x%04X 0x%04X 0x%04X 0x%04X)\n",
                m_keyTable[0], m_keyTable[1], m_keyTable[2], m_keyTable[3]);
        }

        if (m_pipeline == Pipeline::CL1177146 && AutoDiscovery::g_DiscoveredUObjSlot.Valid) {
            m_pipeline = Pipeline::Build20260519;
            std::printf("[fname] Pipeline upgraded CL1177146 → Build20260519 (UObjSlot auto-disc valid)\n");
        }

        if (AutoDiscovery::g_DiscoveredUObjSlot.Valid) {
            namespace V616 = ArcDecrypt::v20260616;
            uint16_t KsRaw[160] = {};
            if (m_reader.Read(m_base + V616::RVA_KEYSTREAM, KsRaw, sizeof(KsRaw))) {
                std::memcpy(m_keyTable616, KsRaw, sizeof(KsRaw));
                m_ks616Loaded = true;
                std::printf("[fname] v616 keystream loaded @ 0x%llX (160 entries, base=%d)\n",
                    (unsigned long long)(m_base + V616::RVA_KEYSTREAM),
                    V616::KEYSTREAM_DECRYPT_BASE);
            } else {
                std::printf("[-] v616 keystream read failed @ 0x%llX\n",
                    (unsigned long long)(m_base + V616::RVA_KEYSTREAM));
            }
        }

        {
            namespace V707 = ArcDecrypt::v20260707;
            const auto& GN = AutoDiscovery::g_DiscoveredGNames;
            uint64_t SimdBase = GN.SimdBlockRva ? GN.SimdBlockRva : (V707::RVA_KEYTABLE - 0xF0);

            int BestNz = 0;
            int BestOff = 0xF0;
            uint16_t BestKt[64] = {};
            for (int Off : {0xE8, 0xF0}) {
                uint16_t Kt[64] = {};
                uint64_t Rva = SimdBase + Off;
                if (!m_reader.Read(m_base + Rva, Kt, sizeof(Kt))) continue;
                int Nz = 0;
                for (int I = 0; I < 64; ++I) Nz += (Kt[I] != 0);
                if (Nz > BestNz) {
                    BestNz = Nz;
                    BestOff = Off;
                    std::memcpy(BestKt, Kt, sizeof(Kt));
                }
            }

            if (BestNz >= 16) {
                std::memcpy(m_keyTable707, BestKt, sizeof(m_keyTable707));
                std::memcpy(m_keyTableNewPatch, BestKt, sizeof(m_keyTableNewPatch));
                m_ks707Loaded = true;
                uint64_t KtRva = SimdBase + BestOff;
                std::printf("[fname] keytable loaded @ 0x%llX (offset +0x%X, %d nz, first: 0x%04X 0x%04X 0x%04X 0x%04X)\n",
                    (unsigned long long)(m_base + KtRva), BestOff, BestNz,
                    BestKt[0], BestKt[1], BestKt[2], BestKt[3]);
                if (BestOff == 0xE8) {
                    m_newPatchActive = true;
                    std::printf("[fname] new patch detected (keytable at +0xE8) — using v20260709 pipeline\n");
                }
            } else {
                std::printf("[fname] keytable @ SimdBase+0xE8/0xF0 only %d nz — skipped\n", BestNz);
            }
        }

        if (m_ks707Loaded && !m_newPatchActive) {
            namespace V707 = ArcDecrypt::v20260707;
            int64_t RdataShift = 0;
            const auto& Bounds = AutoDiscovery::g_DiscoveredBounds;
            if (Bounds.Valid && Bounds.RDataRva && Bounds.RDataRva != V707::RDATA_BASE_REF) {
                RdataShift = (int64_t)Bounds.RDataRva - (int64_t)V707::RDATA_BASE_REF;
                std::printf("[fname] .rdata shift: %+lld (0x%llX → 0x%llX)\n",
                    (long long)RdataShift,
                    (unsigned long long)V707::RDATA_BASE_REF,
                    (unsigned long long)Bounds.RDataRva);
            }
            auto LoadMask = [&](uint64_t Rva) -> __m128i {
                alignas(16) uint8_t Buf[16] = {};
                m_reader.Read(m_base + (uint64_t)((int64_t)Rva + RdataShift), Buf, 16);
                return _mm_load_si128(reinterpret_cast<const __m128i*>(Buf));
            };
            m_seedXor1     = LoadMask(V707::RVA_SEED_XOR1);
            m_seedBlend    = LoadMask(V707::RVA_SEED_BLEND);
            m_seedBlendNot = LoadMask(V707::RVA_SEED_BLEND_NOT);
            m_seedXor2     = LoadMask(V707::RVA_SEED_XOR2);
            m_seedXor3     = LoadMask(V707::RVA_SEED_XOR3);
            m_seedXor4     = LoadMask(V707::RVA_SEED_XOR4);
            m_chunkXor     = LoadMask(V707::RVA_CHUNK_XOR);
            m_seedLoaded   = true;
            std::printf("[fname] v707 seed SIMD masks loaded (7 masks, rdata_shift=%+lld)\n", (long long)RdataShift);
        }

        if (m_newPatchActive) {
            namespace V709 = ArcDecrypt::v20260709;
            uint64_t FnvXorRva = V709::BLOCK_FNV_XOR_RVA;
            uint64_t FnvXorVal = 0;
            if (m_reader.Read(m_base + FnvXorRva, &FnvXorVal, 8) && FnvXorVal) {
                V709::BLOCK_FNV_XOR = FnvXorVal;
                std::printf("[fname] v709 FnvXor loaded from RVA 0x%llX = 0x%llX\n",
                    (unsigned long long)FnvXorRva, (unsigned long long)FnvXorVal);
            } else {
                std::printf("[fname] v709 FnvXor read failed @ 0x%llX, using default 0x%llX\n",
                    (unsigned long long)FnvXorRva, (unsigned long long)V709::BLOCK_FNV_XOR);
            }
            m_seedLoaded = true;
        }

        if (!LegacyLoaded && !m_ks707Loaded) {
            std::printf("[-] FName: no keytable loaded (legacy invalid, V707 failed)\n");
            return false;
        }

        m_keyLoaded = true;
        return true;
    }

    bool IsInitialized() const { return m_keyLoaded; }

    bool IsV808Active() const { return m_v808Active; }

    // Adopt the CL-1325322 pipeline once Phase 6.7 has pinned the pool and
    // keystream against known plaintext. Called from main after auto-discovery;
    // it takes priority over every older pipeline because both of its anchors
    // are plaintext-verified rather than sig-scanned.
    bool IsV811Active() const { return m_v811Active; }

    bool IsV818Active() const { return m_v818Active; }

    // Steam build CL-1341255. Same contract as AdoptV811 and the same single
    // acceptance test: CI=0 must decode to "None". The keystream is read LIVE —
    // the module image holds the at-rest form and shares no value with it.
    bool AdoptV818() { return TryV818(true); }

    // Quiet form, so auto-resolve can sweep candidate keystream windows without
    // printing a rejection per attempt. Reverts cleanly on failure, which is
    // what makes it safe to call in a loop.
    bool TryV818(bool Verbose) {
        const auto& Sh = ArcDecrypt::g_Sheet;
        m_v818Active = false;
        if (!m_reader.Read(m_base + Sh.Keystream818Rva, m_keyTable818, sizeof(m_keyTable818))) {
            if (Verbose)
                std::printf("[fname] v818 keystream read failed @ 0x%llX\n",
                    (unsigned long long)(m_base + Sh.Keystream818Rva));
            return false;
        }
        m_pool818Rva = Sh.Pool818Rva;
        m_v818Active = true;
        m_keyLoaded  = true;

        std::string Probe = DecryptNameString_V818(ResolveNamePtr_V818(0));
        if (Probe != "None") {
            if (Verbose)
                std::printf("[fname] v818 self-test failed (CI=0 gave \"%s\", expected \"None\") - not adopting\n",
                    Probe.c_str());
            m_v818Active = false;
            return false;
        }
        // Entries sit several CompIndex steps apart, so CI=1 lands mid-string.
        // Sweep for the first genuine name instead of probing a fixed index.
        std::string Second;
        for (int32_t Ci = 1; Ci < 512 && Second.empty(); ++Ci) {
            std::string S = DecryptNameString_V818(ResolveNamePtr_V818(Ci));
            if (S.size() < 3) continue;
            bool Clean = true;
            for (unsigned char C : S)
                if (!std::isalnum(C) && C != '_') { Clean = false; break; }
            if (Clean) Second = S;
        }
        // A second, longer plaintext is required, not merely reported: "None"
        // is four bytes and a wrong constant can still land on it, while no
        // wrong constant survives both tests.
        if (Second.empty()) {
            if (Verbose)
                std::printf("[fname] v818 self-test: CI=0 gave \"None\" but no second "
                            "plaintext decoded - not adopting\n");
            m_v818Active = false;
            return false;
        }
        if (Verbose)
            std::printf("[fname] Pipeline = v20260818 (pool 0x%llX, keystream window 0x%llX%s) "
                        "- CI=0 -> \"None\" OK, 2nd plaintext: %s\n",
                (unsigned long long)Sh.Pool818Rva, (unsigned long long)Sh.Keystream818Rva,
                ArcDecrypt::g_Sheet.Resolved818 ? ", auto-resolved" : "",
                Second.c_str());
        return true;
    }

    uint64_t ResolveNamePtr_V818(int32_t CompIndex) const {
        if (CompIndex < 0 || !m_v818Active) return 0;
        return AutoDiscovery::V818Detail::ResolveEntry(m_reader, m_base, CompIndex);
    }

    std::string DecryptNameString_V818(uint64_t NameEntryPtr) {
        namespace V = ArcDecrypt::v20260818;
        namespace X = AutoDiscovery::V818Detail;
        if (!NameEntryPtr || !m_v818Active) return {};

        X::EntryHeader H;
        if (!X::ReadHeader(m_reader, NameEntryPtr, H)) return {};
        if (H.Bytes <= 0 || H.Bytes > 2048) return {};

        std::vector<uint8_t> Buf((size_t)H.Bytes, 0);
        if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), (size_t)H.Bytes)) return {};

        uint32_t Key = (uint32_t)H.Length + ArcDecrypt::g_Sheet.KeyInitAdd818;
        auto Slot = [&](uint32_t K) -> uint16_t {
            return m_keyTable818[K & V::KEY_INDEX_MASK];
        };

        std::string Out;
        Out.reserve(H.Length);
        if (!H.IsWide) {
            for (int I = 0; I < H.Length; ++I) {
                uint8_t C = Buf[I] ^ (uint8_t)(Slot(Key + (uint32_t)I) >> V::NARROW_KEY_SHIFT);
                if (!C) break;
                Out.push_back((char)C);
            }
            return Out;
        }
        for (int I = 0; I < H.Length; ++I) {
            uint16_t C = (uint16_t)(Buf[I * 2] | ((uint16_t)Buf[I * 2 + 1] << 8));
            uint16_t W = (uint16_t)(C ^ Slot(Key + (uint32_t)I));
            if (!W) break;
            Out.push_back((char)(W & 0xFF));
        }
        return Out;
    }

    // The slot is 16 bytes on this build, not 8: the decoder mixes both halves.
    uint64_t DecodeObjSlot16_V818(uint64_t ObjPtr, uint32_t Idx) const {
        namespace V = ArcDecrypt::v20260818;
        uint64_t Raw[2] = { 0, 0 };
        const auto& Sh = ArcDecrypt::g_Sheet;
        uint64_t Slot = ObjPtr + Sh.Slot818Base + Sh.Slot818Stride * Idx;
        if (!m_reader.Read(Slot, Raw, 16)) return 0;
        if (!Raw[0] && !Raw[1]) return 0;
        return AutoDiscovery::V818Detail::DecodeSlot16(Raw[0], Raw[1]);
    }

    uint64_t GetObjFNameV818(uint64_t ObjPtr) const {
        namespace V = ArcDecrypt::v20260818;
        uint32_t Idx = AutoDiscovery::V818Detail::NameSlotIndex(ObjPtr);
        uint64_t Vv = DecodeObjSlot16_V818(ObjPtr, Idx);
        if (!Vv) return 0;
        return fn_rotl64(Vv, ArcDecrypt::g_Sheet.Slot818FinalRol);
    }

    std::string GetNameV818(uint64_t ObjPtr) {
        uint64_t F = GetObjFNameV818(ObjPtr);
        if (!F) return {};
        std::string S = DecryptNameString_V818(
            ResolveNamePtr_V818((int32_t)(F & 0xFFFFFFFFu)));
        uint32_t Number = (uint32_t)(F >> 32);
        if (S.empty() || Number == 0) return S;
        return S + "_" + std::to_string(Number - 1);
    }

    // Class sits at (S & 3), Outer at (S + 1) & 3 — measured from the raw hash,
    // exactly as on build 24653108. Verified live over 198 sampled objects:
    // rel 0 named Package/Function/SoundWave/ASClass, rel 1 named the outers.
    uint64_t DecodeObjSlotPtrV818(uint64_t ObjPtr, uint32_t SlotRel) const {
        uint32_t Idx = (AutoDiscovery::V818Detail::SlotHash(ObjPtr) + SlotRel) & 3u;
        uint64_t Ptr = DecodeObjSlot16_V818(ObjPtr, Idx);
        if (Ptr < 0x10000ULL || Ptr >= 0x800000000000ULL) return 0;
        return Ptr;
    }
    uint64_t GetClassPtrV818(uint64_t ObjPtr) const {
        return DecodeObjSlotPtrV818(ObjPtr, ArcDecrypt::g_Sheet.Slot818ClassAdj);
    }
    uint64_t GetOuterPtrV818(uint64_t ObjPtr) const {
        return DecodeObjSlotPtrV818(ObjPtr, ArcDecrypt::g_Sheet.Slot818OuterAdj);
    }

    int32_t DecryptFFieldNameCI_V818(uint64_t FieldAddr) const {
        namespace V = ArcDecrypt::v20260818;
        uint64_t Enc = 0;
        if (!m_reader.Read(FieldAddr + ArcDecrypt::g_Sheet.FFieldName818Off, &Enc, 8) || !Enc)
            return 0;
        uint64_t Vv = AutoDiscovery::V818Detail::DecodeFFieldName(Enc);
        return (int32_t)(Vv & 0xFFFFFFFFu);
    }


    // ─────────────────────────────────────────────────────────────────────────
    // Steam CL-1372005 (UE 5.7, 2026-09-08). Same self-test contract as v818:
    // the pipeline is installed against the compiled anchors, then CI=0 is
    // required to decode to "None", followed by a second printable name.
    // If either check fails, m_v908Active is reset and the caller falls through
    // to older pipelines.
    // ─────────────────────────────────────────────────────────────────────────
    bool IsV908Active() const { return m_v908Active; }

    bool AdoptV908() { return TryV908(true); }

    bool TryV908(bool Verbose) {
        namespace V = ArcDecrypt::v20260908;
        const auto& Sh = ArcDecrypt::g_Sheet;
        m_v908Active = false;

        // Keystream lives at (base + Keystream908Rva); the window covers the
        // decryptable range. Read the full table so the +BaseIdx form works.
        size_t Bytes = sizeof(m_keyTable908);
        if (!m_reader.Read(m_base + Sh.Keystream908Rva, m_keyTable908, Bytes)) {
            if (Verbose)
                std::printf("[fname] v908 keystream read failed @ 0x%llX\n",
                    (unsigned long long)(m_base + Sh.Keystream908Rva));
            return false;
        }
        m_pool908Rva = Sh.Pool908Rva;
        m_v908Active = true;
        m_keyLoaded  = true;

        std::string Probe = DecryptNameString_V908(ResolveNamePtr_V908(0));
        if (Probe != "None") {
            if (Verbose)
                std::printf("[fname] v908 self-test failed (CI=0 gave \"%s\", expected \"None\") - not adopting\n",
                    Probe.c_str());
            m_v908Active = false;
            return false;
        }
        std::string Second;
        for (int32_t Ci = 1; Ci < 512 && Second.empty(); ++Ci) {
            std::string S = DecryptNameString_V908(ResolveNamePtr_V908(Ci));
            if (S.size() < 3) continue;
            bool Clean = true;
            for (unsigned char C : S)
                if (!std::isalnum(C) && C != '_') { Clean = false; break; }
            if (Clean) Second = S;
        }
        if (Second.empty()) {
            if (Verbose)
                std::printf("[fname] v908 self-test: CI=0 gave \"None\" but no second "
                            "plaintext decoded - not adopting\n");
            m_v908Active = false;
            return false;
        }
        if (Verbose)
            std::printf("[fname] Pipeline = v20260908 (pool 0x%llX, keystream window 0x%llX) "
                        "- CI=0 -> \"None\" OK, 2nd plaintext: %s\n",
                (unsigned long long)Sh.Pool908Rva,
                (unsigned long long)Sh.Keystream908Rva,
                Second.c_str());
        return true;
    }

    uint64_t ResolveNamePtr_V908(int32_t CompIndex) const {
        if (CompIndex < 0 || !m_v908Active) return 0;
        return AutoDiscovery::V908Detail::ResolveEntry(m_reader, m_base, CompIndex);
    }

    std::string DecryptNameString_V908(uint64_t NameEntryPtr) {
        namespace V = ArcDecrypt::v20260908;
        namespace X = AutoDiscovery::V908Detail;
        if (!NameEntryPtr || !m_v908Active) return {};

        X::EntryHeader H;
        if (!X::ReadHeader(m_reader, NameEntryPtr, H)) return {};
        if (H.Bytes <= 0 || H.Bytes > 2048) return {};

        std::vector<uint8_t> Buf((size_t)H.Bytes, 0);
        if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), (size_t)H.Bytes)) return {};

        // Keystream is indexed from base 0 because we loaded from the window
        // start (Keystream908Rva already carries the +0xF0 offset).
        if (!H.IsWide) return X::DecryptNarrow(Buf, H.Length, m_keyTable908, 0);
        return X::DecryptWide(Buf, H.Length, m_keyTable908, 0);
    }

    // 16-byte slot decode. Only lo64 is used by the decoder itself, but the
    // signature mirrors DecodeObjSlot16_V818 to keep call sites uniform.
    uint64_t DecodeObjSlot16_V908(uint64_t ObjPtr, uint32_t Idx) const {
        namespace V = ArcDecrypt::v20260908;
        uint64_t Raw[2] = { 0, 0 };
        uint64_t Slot = ObjPtr + V::UOBJ_NAME_SLOT_BASE + V::UOBJ_NAME_SLOT_STRIDE * Idx;
        if (!m_reader.Read(Slot, Raw, 16)) return 0;
        if (!Raw[0] && !Raw[1]) return 0;
        return AutoDiscovery::V908Detail::DecodeSlot16(Raw[0], Raw[1]);
    }

    uint64_t GetObjFNameV908(uint64_t ObjPtr) const {
        uint32_t Idx = AutoDiscovery::V908Detail::NameSlotIndex(ObjPtr);
        return DecodeObjSlot16_V908(ObjPtr, Idx);
    }

    std::string GetNameV908(uint64_t ObjPtr) {
        // F=0 is a legitimate CI value (== "None"), so we do NOT bail on it.
        // Only bail if the slot decode itself failed (Raw[0]==Raw[1]==0) — but
        // in that case DecryptNameString_V908 will return empty and the caller
        // falls through to older pipelines.
        uint64_t F = GetObjFNameV908(ObjPtr);
        std::string S = DecryptNameString_V908(
            ResolveNamePtr_V908((int32_t)(F & 0xFFFFFFFFu)));
        uint32_t Number = (uint32_t)(F >> 32);
        if (S.empty() || Number == 0) return S;
        return S + "_" + std::to_string(Number - 1);
    }

    uint64_t DecodeObjSlotPtrV908(uint64_t ObjPtr, uint32_t /*SlotRel*/, uint32_t Which) const {
        // Which: 0 = Name (Idx ^ 2), 1 = Class ((Idx+1)&3), 2 = Outer (Idx)
        uint32_t Idx;
        switch (Which) {
            case 0: Idx = AutoDiscovery::V908Detail::NameSlotIndex(ObjPtr); break;
            case 1: Idx = AutoDiscovery::V908Detail::ClassSlotIndex(ObjPtr); break;
            default: Idx = AutoDiscovery::V908Detail::OuterSlotIndex(ObjPtr); break;
        }
        uint64_t Raw = DecodeObjSlot16_V908(ObjPtr, Idx);
        // Slot decode's final ROL64(32) puts the FName {CI, Number} in the
        // right order for name slots, but leaves POINTER slots halves-swapped
        // (a real 0x7FFFXXXXXXXX pointer appears as 0xXXXXXXXX00007FFF).
        // Un-swap here to recover the raw pointer.
        uint64_t Ptr = ((Raw << 32) | (Raw >> 32)) & 0xFFFFFFFFFFFFFFFFULL;
        if (Ptr < 0x10000ULL || Ptr >= 0x800000000000ULL) return 0;
        return Ptr;
    }
    uint64_t GetClassPtrV908(uint64_t ObjPtr) const {
        return DecodeObjSlotPtrV908(ObjPtr, 0, 1);
    }
    uint64_t GetOuterPtrV908(uint64_t ObjPtr) const {
        return DecodeObjSlotPtrV908(ObjPtr, 0, 2);
    }

    int32_t DecryptFFieldNameCI_V908(uint64_t FieldAddr) const {
        namespace V = ArcDecrypt::v20260908;
        uint64_t Enc = 0;
        if (!m_reader.Read(FieldAddr + V::FFIELD_NAME_OFF, &Enc, 8) || !Enc) return 0;
        uint64_t Vv = AutoDiscovery::V908Detail::DecodeFFieldName(Enc);
        return (int32_t)(Vv & 0xFFFFFFFFu);
    }


    // Steam build 24653108. Both anchors are fixed RVAs rather than sig-scan
    // results, so the only thing that can validate them is plaintext: CI=0
    // must decode to "None". The keystream MUST be read from live memory —
    // the module image holds an at-rest form that shares no value with it.
    bool AdoptV811() {
        namespace V = ArcDecrypt::v20260811;
        const auto& Sh = ArcDecrypt::g_Sheet;
        // Read from the window (table + base index) so a resolved keystream
        // needs no separate base, and read it LIVE: the module image holds an
        // at-rest form that shares no value with the running table.
        if (!m_reader.Read(m_base + Sh.KeystreamWindowRva, m_keyTable811, 128)) {
            std::printf("[fname] v811 keystream read failed @ 0x%llX\n",
                (unsigned long long)(m_base + Sh.KeystreamWindowRva));
            return false;
        }
        m_pool811Rva = Sh.PoolRva;
        m_ks811Base  = 0;
        m_v811Active = true;
        m_keyLoaded  = true;

        std::string Probe = DecryptNameString_V811(ResolveNamePtr_V811(0));
        if (Probe != "None") {
            std::printf("[fname] v811 self-test failed (CI=0 gave \"%s\", expected \"None\") — not adopting\n",
                Probe.c_str());
            m_v811Active = false;
            return false;
        }
        // Entries sit 4-8 CompIndex steps apart, so CI=1 lands mid-string and
        // decodes to noise. Sweep for the first genuine name instead.
        std::string Second;
        for (int32_t Ci = 1; Ci < 512 && Second.empty(); ++Ci) {
            std::string S = DecryptNameString_V811(ResolveNamePtr_V811(Ci));
            if (S.size() < 3) continue;
            bool Clean = true;
            for (unsigned char C : S)
                if (!std::isalnum(C) && C != '_') { Clean = false; break; }
            if (Clean) Second = S;
        }
        std::printf("[fname] Pipeline = v20260811 (pool 0x%llX, keystream window 0x%llX%s) — CI=0 -> \"None\" ✓%s%s\n",
            (unsigned long long)Sh.PoolRva, (unsigned long long)Sh.KeystreamWindowRva,
            Sh.Resolved ? ", auto-resolved" : "",
            Second.empty() ? "" : " 2nd plaintext: ", Second.c_str());
        return true;
    }

    bool AdoptV808(const AutoDiscovery::V808Discovery& Disc) {
        namespace V = ArcDecrypt::v20260808;
        if (!Disc.Valid || !Disc.PoolRva) return false;
        if (!m_reader.Read(m_base + Disc.KeystreamRva, m_keyTable808, sizeof(m_keyTable808))) {
            std::printf("[fname] v808 keystream read failed @ 0x%llX\n",
                (unsigned long long)(m_base + Disc.KeystreamRva));
            return false;
        }
        m_pool808Rva = Disc.PoolRva;
        m_ks808Base  = Disc.KeystreamBase;
        m_v808Active = true;
        m_keyLoaded  = true;

        std::string Probe = DecryptNameString_V808(ResolveNamePtr_V808(0));
        if (Probe != "None") {
            std::printf("[fname] v808 self-test failed (CI=0 gave \"%s\", expected \"None\") — not adopting\n",
                Probe.c_str());
            m_v808Active = false;
            return false;
        }
        std::printf("[fname] Pipeline = v20260808 (pool 0x%llX, keystream 0x%llX+%d) — CI=0 -> \"None\" ✓%s\n",
            (unsigned long long)Disc.PoolRva, (unsigned long long)Disc.KeystreamRva,
            Disc.KeystreamBase, Disc.Confirmed ? " (2nd plaintext confirmed)" : "");
        return true;
    }

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
        constexpr uint32_t P = 0x01000193u;
        uint64_t Addr = obj_ptr + 0x10;
        uint32_t Lo = static_cast<uint32_t>(Addr);
        uint32_t Hi = static_cast<uint32_t>(Addr >> 32);

        const auto& Sh = AutoDiscovery::g_DiscoveredSlotHash;
        if (Sh.Valid && Sh.OpCount >= 4) {
            auto Apply = [](uint32_t V, const AutoDiscovery::SlotHashDiscovery::Op& O) -> uint32_t {
                return O.IsShr ? (V >> O.Amount) : fn_rotl32(V, O.Amount);
            };
            uint32_t H = Apply(Lo, Sh.Ops[0]);
            H = P * H + Sh.SlotHashAdd;
            H = Apply(H, Sh.Ops[1]);
            H = P * H + Hi + Sh.SlotHashAdd;
            H = Apply(H, Sh.Ops[2]);
            H = P * H + Sh.SlotHashAdd;
            H = Apply(H, Sh.Ops[3]);
            uint32_t V12 = P * H + Sh.SlotHashAdd;
            return static_cast<uint8_t>(V12) ^ static_cast<uint8_t>(V12 >> 16);
        }

        const bool Is709 = AutoDiscovery::g_UseV709SlotHash;
        const bool Is707 = !Is709 && AutoDiscovery::g_UseV707SlotHash;
        const bool Is616 = !Is709 && !Is707 && AutoDiscovery::g_DiscoveredUObjSlot.Valid;
        const uint32_t ADD = Is709 ? ArcDecrypt::v20260709::SLOT_HASH_ADD
                           : Is707 ? ArcDecrypt::v20260707::SLOT_HASH_ADD
                           : Is616 ? ArcDecrypt::v20260616::SLOT_HASH_ADD
                                   : ArcDecrypt::v20260519::SLOT_HASH_ADD;
        uint32_t H;
        if (Is709) {
            H = fn_rotl32(Lo, ArcDecrypt::v20260709::SLOT_HASH_ROL1);
            H = P * H + ADD;
            H = fn_rotl32(H, ArcDecrypt::v20260709::SLOT_HASH_ROL2);
            H = P * H + Hi + ADD;
            H = fn_rotl32(H, ArcDecrypt::v20260709::SLOT_HASH_ROL3);
            H = P * H + ADD;
            H = fn_rotl32(H, ArcDecrypt::v20260709::SLOT_HASH_ROL4);
        } else if (Is707) {
            H = fn_rotl32(Lo, ArcDecrypt::v20260707::HASH_ROL1);
            H = P * H + ADD;
            H = fn_rotl32(H, ArcDecrypt::v20260707::HASH_ROL2);
            H = P * H + Hi + ADD;
            H = fn_rotl32(H, ArcDecrypt::v20260707::HASH_ROL3);
            H = P * H + ADD;
            H = fn_rotl32(H, ArcDecrypt::v20260707::HASH_ROL4);
        } else if (Is616) {
            H = fn_rotl32(Lo, 26);
            H = P * H + ADD;
            H = fn_rotl32(H, 27);
            H = P * H + Hi + ADD;
            H >>= 6;
            H = P * H + ADD;
            H >>= 5;
        } else {
            H = fn_rotl32(Lo, 17);
            H = P * H + ADD;
            H = fn_rotl32(H, 19);
            H = P * H + Hi + ADD;
            H = fn_rotl32(H, 17);
            H = P * H + ADD;
            H >>= 13;
        }
        uint32_t V12 = P * H + ADD;
        return static_cast<uint8_t>(V12) ^ static_cast<uint8_t>(V12 >> 16);
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
    // CL-1299607 slot decrypt: ROL32(13) → lo64 → XOR → ROL64(39).
    // Result layout: hi32 = CompIndex, lo32 = FName::Number (for name slot),
    // or a raw 64-bit pointer (for class/outer slots).
    // Callers extracting CompIndex must use (dec >> 32).
    uint64_t DecryptUObjSlotNew(const uint8_t enc[16]) const {
        if (m_newPatchActive) {
            const auto& Sv = AutoDiscovery::g_DiscoveredSlotV709;
            int R64Amt = Sv.Valid ? Sv.Rol64First : ArcDecrypt::v20260709::UOBJ_SLOT_ROL64_FIRST;
            int ShImm  = Sv.Valid ? Sv.PshuflwImm : ArcDecrypt::v20260709::UOBJ_SLOT_PSHUFLW;
            int R32Amt = Sv.Valid ? Sv.Rol32Per   : ArcDecrypt::v20260709::UOBJ_SLOT_ROL32_PER;
            uint64_t Lo, Hi;
            std::memcpy(&Lo, enc, 8);
            std::memcpy(&Hi, enc + 8, 8);
            Lo = fn_rotl64(Lo, R64Amt);
            Hi = fn_rotl64(Hi, R64Amt);
            Lo = SoftPshuflw(Lo, ShImm);
            uint32_t D[4];
            D[0] = fn_rotl32(static_cast<uint32_t>(Lo), R32Amt);
            D[1] = fn_rotl32(static_cast<uint32_t>(Lo >> 32), R32Amt);
            D[2] = fn_rotl32(static_cast<uint32_t>(Hi), R32Amt);
            D[3] = fn_rotl32(static_cast<uint32_t>(Hi >> 32), R32Amt);
            return static_cast<uint64_t>(D[0]) | (static_cast<uint64_t>(D[1]) << 32);
        }
        namespace V707 = ArcDecrypt::v20260707;
        __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc));
        __m128i Rot = _mm_or_si128(
            _mm_slli_epi32(V, V707::UOBJ_SLOT_ROL32),
            _mm_srli_epi32(V, 32 - V707::UOBJ_SLOT_ROL32));
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Rot);
        return fn_rotl64(Lo ^ V707::UOBJ_SLOT_XOR_64, V707::UOBJ_SLOT_FINAL_ROL);
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
        return DecryptUObjSlotNew(enc);
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
        auto ApplyShuf = [](__m128i V, uint8_t Imm) -> __m128i {
            return SoftPshuflwXmm(V, Imm);
        };

        {
            const auto& Lay = AutoDiscovery::g_DiscoveredFFieldLayout;
            if (Lay.PipelineValid && Lay.PipelineLen >= 2) {
                __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
                for (int Pi = 0; Pi < Lay.PipelineLen; ++Pi) {
                    switch (Lay.Pipeline[Pi]) {
                    case AutoDiscovery::FFOP_XOR64:
                        V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(Lay.XorKey)));
                        break;
                    case AutoDiscovery::FFOP_PSHUFB: {
                        alignas(16) uint8_t M[16] = {};
                        std::memcpy(M, Lay.PshufbMask, 8);
                        V = _mm_shuffle_epi8(V, _mm_load_si128(reinterpret_cast<const __m128i*>(M)));
                        break;
                    }
                    case AutoDiscovery::FFOP_ROL16:
                        if (Lay.Rol16Amount > 0 && Lay.Rol16Amount < 16)
                            V = _mm_or_si128(_mm_slli_epi16(V, Lay.Rol16Amount),
                                             _mm_srli_epi16(V, 16 - Lay.Rol16Amount));
                        break;
                    case AutoDiscovery::FFOP_PSHUFLW:
                        V = SoftPshuflwXmm(V, Lay.PshuflwImm);
                        break;
                    case AutoDiscovery::FFOP_ROL32:
                        if (Lay.Rol32Amount > 0 && Lay.Rol32Amount < 32)
                            V = _mm_or_si128(_mm_slli_epi32(V, Lay.Rol32Amount),
                                             _mm_srli_epi32(V, 32 - Lay.Rol32Amount));
                        break;
                    case AutoDiscovery::FFOP_ROL64: {
                        uint64_t Lo;
                        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
                        if (Lay.Rol64Amount > 0 && Lay.Rol64Amount < 64)
                            Lo = (Lo << Lay.Rol64Amount) | (Lo >> (64 - Lay.Rol64Amount));
                        uint32_t Ci = static_cast<uint32_t>(Lo);
                        if (Ci > 1 && Ci < 0x2000000u) return Lo;
                        break;
                    }
                    }
                }
            }
        }

        {
            const auto& Lay = AutoDiscovery::g_DiscoveredFFieldLayout;
            if (Lay.Valid && Lay.XorKey != 0 && !Lay.PipelineValid) {
                __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
                V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(Lay.XorKey)));
                V = _mm_or_si128(_mm_slli_epi16(V, Lay.Rol16Amount),
                                 _mm_srli_epi16(V, 16 - Lay.Rol16Amount));
                alignas(16) uint8_t PshufMask[16] = {};
                std::memcpy(PshufMask, Lay.PshufbMask, 8);
                V = _mm_shuffle_epi8(V, _mm_load_si128(reinterpret_cast<const __m128i*>(PshufMask)));
                uint64_t Lo;
                _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
                uint64_t Out = (Lo << Lay.Rol64Amount) | (Lo >> (64 - Lay.Rol64Amount));
                uint32_t Ci = static_cast<uint32_t>(Out);
                if (Ci > 1 && Ci < 0x2000000u) return Out;
            }
        }

        {
            const auto& Disc = AutoDiscovery::g_DiscoveredFFieldName;
            if (Disc.Valid && !Disc.TwoShuffle && Disc.XorConst == 0 && Disc.Rol32Amount > 0 && Disc.ShufImm1 != 0) {
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

        {
            const auto& Disc = AutoDiscovery::g_DiscoveredFFieldName;
            if (Disc.Valid && Disc.TwoShuffle && Disc.ShufImm1 != 0) {
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
            if (Disc.Valid && Disc.XorConst != 0) {
                __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
                V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(Disc.XorConst)));
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

        {
            using namespace ArcDecrypt::v20260709;
            __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
            V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(FFIELD_NAME_XOR_KEY)));
            V = _mm_or_si128(_mm_slli_epi16(V, FFIELD_NAME_ROL16),
                             _mm_srli_epi16(V, 16 - FFIELD_NAME_ROL16));
            alignas(16) uint8_t PshufMask[16] = {};
            std::memcpy(PshufMask, FFIELD_NAME_PSHUFB, 8);
            V = _mm_shuffle_epi8(V, _mm_load_si128(reinterpret_cast<const __m128i*>(PshufMask)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            uint64_t Out = (Lo << FFIELD_NAME_ROL64) | (Lo >> (64 - FFIELD_NAME_ROL64));
            uint32_t CiN = static_cast<uint32_t>(Out);
            if (CiN > 1 && CiN < 0x2000000u) return Out;
        }

        {
            using namespace ArcDecrypt::v20260707;
            __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(enc));
            alignas(16) uint8_t PshufMask[16] = {};
            std::memcpy(PshufMask, FFIELD_NAME_PSHUFB, 8);
            V = _mm_shuffle_epi8(V, _mm_load_si128(reinterpret_cast<const __m128i*>(PshufMask)));
            V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(FFIELD_NAME_XOR_KEY)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            uint64_t Out = (Lo << FFIELD_NAME_ROL64) | (Lo >> (64 - FFIELD_NAME_ROL64));
            uint32_t CiN = static_cast<uint32_t>(Out);
            if (CiN > 1 && CiN < 0x2000000u) return Out;
        }

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
        m_lastHashSlotStale = false;
        auto is_ci = [](uint32_t h) { return h > 1 && h < 0x2000000u; };

        auto try_slot = [&](int slot) -> int32_t {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_base + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) return 0;
            bool nonzero = false;
            for (int b = 0; b < 16; ++b) if (enc[b]) { nonzero = true; break; }
            if (!nonzero) return 0;

            uint64_t dec = DecryptUObjSlotNew(enc);
            uint32_t ci = static_cast<uint32_t>(dec >> 32);
            if (is_ci(ci)) return static_cast<int32_t>(ci);
            return 0;
        };

        // Tier 0: hash-picked NAME slot.
        uint32_t ns = (m_pipeline == Pipeline::Build20260519 || AutoDiscovery::g_DiscoveredUObjSlot.Valid)
                          ? Build20260519_ObjNameSlot(obj_base)
                          : ObjNameSlot(obj_base);
        if (int32_t ci = try_slot(static_cast<int>(ns))) return ci;
        m_lastHashSlotStale = true;
        // Tier 1: walk all 4 slots as fallback. Accept the first slot
        // whose CI is in valid range.
        auto looks_name = [](const std::string& s) {
            if (s.empty() || s.size() > 1024) return false;
            int printable = 0;
            for (unsigned char c : s)
                if (c >= 32 && c <= 126) ++printable;
            return printable * 4 >= static_cast<int>(s.size()) * 3;
        };
        for (int s = 0; s < 4; ++s) {
            if (s == static_cast<int>(ns)) continue;
            int32_t ci = try_slot(s);
            if (!ci) continue;
            return ci;
        }
        return 0;
    }

    bool WasLastHashSlotStale() const { return m_lastHashSlotStale; }

    bool IsLikelyStaleObj(uint64_t obj_ptr) {
        if (!obj_ptr || !m_keyLoaded) return true;
        uint32_t ns = (m_pipeline == Pipeline::Build20260519 || AutoDiscovery::g_DiscoveredUObjSlot.Valid)
                          ? Build20260519_ObjNameSlot(obj_ptr)
                          : ObjNameSlot(obj_ptr);
        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(obj_ptr + 0x20 + static_cast<uint64_t>(ns) * 0x20, enc, 16))
            return true;
        bool nonzero = false;
        for (int b = 0; b < 16; ++b) if (enc[b]) { nonzero = true; break; }
        if (!nonzero) return false;
        uint64_t dec = DecryptUObjSlotNew(enc);
        uint32_t ci = static_cast<uint32_t>(dec >> 32);
        if (ci > 1 && ci < 0x2000000u) return false;
        return true;
    }

    // Return ALL pointer-shaped slot decryptions (up to 4). Used by SDK
    // classifier to cross-check against the metaclass set — GetClassPrivate
    // alone is unstable since it picks the first match, and different
    // objects encode their class in different slots.
    std::array<uint64_t, 4> GetAllClassCandidates(uint64_t obj_base) {
        std::array<uint64_t, 4> out{};
        if (!obj_base || !m_keyLoaded) return out;

        if (m_v908Active) {
            // Iterate all 4 raw slots at obj+0x20+i*0x20. The slot decoder
            // leaves pointers halves-swapped, so ROL64(32) to recover them
            // (same fix as DecodeObjSlotPtrV908).
            int n = 0;
            for (uint32_t Slot = 0; Slot < 4; ++Slot) {
                uint64_t Raw = DecodeObjSlot16_V908(obj_base, Slot);
                uint64_t P = ((Raw << 32) | (Raw >> 32)) & 0xFFFFFFFFFFFFFFFFULL;
                if (P >= 0x10000ULL && P < 0x800000000000ULL) {
                    out[n++] = P;
                }
                if (n == 4) break;
            }
            return out;
        }

        if (m_v818Active) {
            int n = 0;
            for (uint32_t Rel = 0; Rel < 4; ++Rel) {
                uint64_t P = DecodeObjSlotPtrV818(obj_base, Rel);
                if (P) out[n++] = P;
                if (n == 4) break;
            }
            return out;
        }

        if (m_v811Active) {
            int n = 0;
            for (uint32_t Rel = 0; Rel < 4; ++Rel) {
                uint64_t P = DecodeObjSlotPtrV811(obj_base, Rel);
                if (P) out[n++] = P;
                if (n == 4) break;
            }
            if (n) return out;
        }

        if (m_v808Active) {
            int n = 0;
            for (uint32_t Rel = 0; Rel < 4; ++Rel) {
                uint64_t P = DecodeObjSlotPtrV808(obj_base, Rel);
                if (P) out[n++] = P;
                if (n == 4) break;
            }
            if (n) return out;
        }

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
                ptr = dec;
                if (ptr < 0x100000ULL || ptr >= 0x800000000000ULL) continue;
            }
            out[slot] = ptr;
        }
        return out;
    }

    uint64_t GetClassPrivate(uint64_t obj_base) {
        if (!obj_base || !m_keyLoaded) return 0;

        // Without these the modern pipelines fall through to the legacy
        // Build20260519 decoders, which return plausible-looking garbage.
        // That is what left the bone dump unable to find any "Skeleton".
        if (m_v908Active) {
            // v908 is authoritative: do NOT fall through on a zero result.
            return GetClassPtrV908(obj_base);
        }
        if (m_v818Active) {
            uint64_t P = GetClassPtrV818(obj_base);
            if (P) return P;
        }
        if (m_v811Active) {
            uint64_t P = GetClassPtrV811(obj_base);
            if (P) return P;
        }
        if (m_v808Active) {
            uint64_t P = GetClassPtrV808(obj_base);
            if (P) return P;
        }

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
            uint64_t ptr = dec;
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
    // CL-1325322 FField::NamePrivate (+0x60). Transcribed from the FBoolProperty
    // size-check at RVA 0x4478A0, whose error path decodes the field name:
    //   blend (E & A) | (~E & B) with B = ~A  ⇒  plain XOR with B
    //   PSHUFLW(0x39) → XOR C → ROL32(9) per dword → XOR D → ROL64(32)
    // Live-verified: yields MaxScrollbackSize / PrimaryActorTick / StaticMesh …
    // Key-free on this patch: no XOR constant anywhere in the chain.
    int32_t DecryptFFieldNameCI_V811(uint64_t FieldAddr) const {
        namespace V = ArcDecrypt::v20260811;
        uint64_t Enc = 0;
        if (!m_reader.Read(FieldAddr + V::FFIELD_NAME_OFF, &Enc, 8) || !Enc) return 0;
        uint64_t Vv = SoftPshuflw(Enc, V::FFIELD_NAME_PSHUFLW_A);
        Vv = fn_rotl64(Vv, V::FFIELD_NAME_ROL64_A);
        Vv = SoftPshuflw(Vv, V::FFIELD_NAME_PSHUFLW_B);
        Vv = fn_rotl64(Vv, V::FFIELD_NAME_ROL64_B);
        return static_cast<int32_t>(Vv & 0xFFFFFFFFu);
    }

    int32_t DecryptFFieldNameCI_V808(uint64_t FieldAddr) const {
        namespace V = ArcDecrypt::v20260808;
        uint64_t Enc = 0;
        if (!m_reader.Read(FieldAddr + V::FFIELD_NAME_OFF, &Enc, 8) || !Enc) return 0;
        uint64_t Vv = SoftPshuflw(Enc ^ V::FFIELD_NAME_BLEND, V::FFIELD_NAME_PSHUFLW)
                      ^ V::FFIELD_NAME_XOR1;
        Vv = (uint64_t)fn_rotl32((uint32_t)Vv, V::FFIELD_NAME_ROL32)
           | ((uint64_t)fn_rotl32((uint32_t)(Vv >> 32), V::FFIELD_NAME_ROL32) << 32);
        Vv = fn_rotl64(Vv ^ V::FFIELD_NAME_XOR2, V::FFIELD_NAME_ROL64);
        return static_cast<int32_t>(Vv & 0xFFFFFFFFu);
    }

    int32_t DecryptFFieldNameCI(uint64_t ff_addr) {
        if (!ff_addr) return 0;

        // On v808 this is authoritative. Falling through would re-run the very
        // same ciphertext through eight wrong-patch transforms whose acceptance
        // window (ci < 0x06A00000) is far wider than ours, so a bogus decode
        // would win and latch m_ffieldNameOff on the way out.
        if (m_v818Active)
            return DecryptFFieldNameCI_V818(ff_addr);

        if (m_v811Active)
            return DecryptFFieldNameCI_V811(ff_addr);

        if (m_v808Active)
            return DecryptFFieldNameCI_V808(ff_addr);
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
    // Patch 2026-08 FField::NamePrivate decode, from the inlined decoder at
    // RVA 0x454A9F (cross-checked against a second, independently compiled site
    // at 0x3975B7 whose key differs by exactly one PSHUFLW(0x39) because the
    // shuffle sits on the other side of the XOR — the two agree algebraically).
    //
    // Validated end-to-end on a static template: the compile-time NamePrivate
    // at .rdata 0xB4E9AC0 (0xE9125C1BEE9842D2) decodes to CI=0/Number=0, i.e.
    // NAME_None, and re-encoding NAME_None reproduces that constant exactly.
    uint64_t DecodeFFieldName_Patch20260805(uint64_t Enc) const {
        namespace P805 = ArcDecrypt::v20260805;
        uint64_t T = Enc ^ P805::FFIELD_NAME_XOR_K2;
        T = SoftPshuflw(T, P805::FFIELD_NAME_PSHUFLW);
        // ROL32 is applied per dword lane (psrld/pslld/por), not to the qword.
        uint32_t Lo = static_cast<uint32_t>(T);
        uint32_t Hi = static_cast<uint32_t>(T >> 32);
        Lo = fn_rotl32(Lo, P805::FFIELD_NAME_ROL32);
        Hi = fn_rotl32(Hi, P805::FFIELD_NAME_ROL32);
        T = (static_cast<uint64_t>(Hi) << 32) | Lo;
        T ^= P805::FFIELD_NAME_XOR_K1;
        // ROL64(...,32) swaps the halves, leaving CI in lo32 and Number in hi32.
        return fn_rotl64(T, P805::FFIELD_NAME_ROL64);
    }

    int32_t TryDecodeFFieldNameAt(uint64_t ff_addr, uint64_t off) {
        alignas(16) uint8_t enc[16] = {};
        if (!m_reader.Read(ff_addr + off, enc, 16)) return 0;
        bool any = false;
        for (uint8_t b : enc) if (b) { any = true; break; }
        if (!any) return 0;
        if (m_patch0805Active) {
            uint64_t Raw;
            std::memcpy(&Raw, enc, 8);
            return static_cast<int32_t>(DecodeFFieldName_Patch20260805(Raw) & 0xFFFFFFFFu);
        }
        uint64_t dec = DecryptUObjSlotNew(enc);
        return static_cast<int32_t>(dec >> 32);
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
        if (m_v818Active)
            return (CompIndex < 0) ? 0 : ResolveNamePtr_V818(CompIndex);

        if (m_v811Active)
            return (CompIndex < 0) ? 0 : ResolveNamePtr_V811(CompIndex);

        if (m_v808Active)
            return (CompIndex < 0) ? 0 : ResolveNamePtr_V808(CompIndex);

        if (CompIndex <= 0 || !m_keyLoaded) return 0;

        if (m_patch0805Active)
            return ResolveNamePtr_Patch20260805(CompIndex);

        if (m_newPatchActive)
            return ResolveNamePtr_NewPatch(CompIndex);

        if (m_ks707Loaded)
            return ResolveNamePtr_V707(CompIndex);

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
    static __m128i RolLow64_128(__m128i V, int Amt) {
        __m128i Lo = _mm_unpacklo_epi64(V, _mm_setzero_si128());
        __m128i Left  = _mm_slli_epi64(Lo, Amt);
        __m128i Right = _mm_srli_epi64(Lo, 64 - Amt);
        return _mm_or_si128(Left, Right);
    }

    __m128i ComputeNameSeed(int32_t CompIndex) const {
        namespace V707 = ArcDecrypt::v20260707;
        __m128i X = _mm_set_epi32(0, 0, 0, static_cast<int>(CompIndex));
        X = _mm_xor_si128(X, m_seedXor1);
        X = RolLow64_128(X, 2);
        X = _mm_or_si128(_mm_and_si128(X, m_seedBlend),
                         _mm_andnot_si128(X, m_seedBlendNot));
        X = _mm_shufflelo_epi16(X, 0x93);
        X = _mm_xor_si128(X, m_seedXor2);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), X);
        X = _mm_set_epi64x(0, static_cast<int64_t>(Lo));
        X = _mm_shufflelo_epi16(X, 0x39);
        X = _mm_xor_si128(X, m_seedXor3);
        X = RolLow64_128(X, 62);
        X = _mm_xor_si128(_mm_set_epi64x(0, static_cast<int64_t>(V707::SEED_MID_XOR)), X);
        X = RolLow64_128(X, 2);
        X = _mm_shufflelo_epi16(X, 0x93);
        X = _mm_xor_si128(X, m_seedXor4);
        return X;
    }

    uint64_t ResolveNamePtr_V707(int32_t CompIndex) {
        namespace V707 = ArcDecrypt::v20260707;
        if (CompIndex <= 0 || !m_ks707Loaded || !m_seedLoaded) return 0;

        const auto& Pipe = AutoDiscovery::g_DiscoveredFNamePipeline;
        const bool UsePipe = Pipe.ShardHashValid;

        __m128i Seed = ComputeNameSeed(CompIndex);
        uint64_t SeedLo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&SeedLo), Seed);
        uint64_t Shifted = SeedLo >> 18;
        __m128i V5Vec = _mm_xor_si128(
            _mm_set_epi64x(0, static_cast<int64_t>(Shifted)), m_chunkXor);
        uint32_t V5 = static_cast<uint32_t>(_mm_cvtsi128_si32(V5Vec)) ^ V707::CHUNK_ID_XOR;
        uint16_t NameOff = static_cast<uint16_t>(V5);
        uint64_t GnpRva707 = AutoDiscovery::g_DiscoveredGNames.Valid
                           ? AutoDiscovery::g_DiscoveredGNames.GNamesRva
                           : (ArcDecrypt::RVA_GNAMES_BASE
                              ? ArcDecrypt::RVA_GNAMES_BASE
                              : V707::RVA_GNAMEPOOL);
        uint64_t ChunkAddr = m_base + GnpRva707 +
                             (static_cast<uint64_t>(V5 >> 8) & 0xFFFF00ULL);

        const uint64_t SeedOff  = (UsePipe && Pipe.ShardSeedOff)  ? Pipe.ShardSeedOff  : V707::SHARD_HASH_SEED_OFF;
        const uint64_t BlockOff = (UsePipe && Pipe.ShardBlockBaseOff) ? Pipe.ShardBlockBaseOff : V707::SHARD_BLOCK_BASE_OFF;
        const uint32_t ShardAdd = UsePipe ? Pipe.ShardHashAdd : V707::SHARD_HASH_ADD;
        constexpr uint32_t HP   = V707::HASH_PRIME;

        uint64_t HashAddr = ChunkAddr + SeedOff;
        uint32_t HLo = static_cast<uint32_t>(HashAddr);
        uint32_t HHi = static_cast<uint32_t>(HashAddr >> 32);

        uint32_t H;
        if (UsePipe && Pipe.ShardHashRolCount >= 3) {
            H = fn_rotl32(HLo, Pipe.ShardHashRols[0]);
            H = HP * H + ShardAdd;
            H = fn_rotl32(H, Pipe.ShardHashRols[1]);
            H = HP * H + HHi + ShardAdd;
            H = fn_rotl32(H, Pipe.ShardHashRols[2]);
            H = HP * H + ShardAdd;
        } else {
            H = fn_rotl32(HLo, V707::SHARD_HASH_ROL_A);
            H = HP * H + ShardAdd;
            H = fn_rotl32(H, V707::SHARD_HASH_ROL_B);
            H = HP * H + HHi + ShardAdd;
            H = fn_rotl32(H, V707::SHARD_HASH_ROL_C);
            H = HP * H + ShardAdd;
        }

        uint32_t T;
        if (UsePipe && Pipe.ShardHashFinalShift > 0)
            T = H >> Pipe.ShardHashFinalShift;
        else if (UsePipe && Pipe.ShardHashRolCount >= 4)
            T = fn_rotl32(H, Pipe.ShardHashRols[3]);
        else
            T = H >> V707::SHARD_HASH_SHIFT;

        int SlotAdd = (UsePipe && Pipe.SlotSelectValid)
                    ? Pipe.SlotSelectAdd : V707::SHARD_SLOT_SELECT_ADD;
        uint8_t Pa = static_cast<uint8_t>(-109 * static_cast<int>(T) + SlotAdd);
        uint8_t Pb = static_cast<uint8_t>((HP * T + ShardAdd) >> 16);
        uint32_t Bidx1 = (Pa ^ Pb) & 7u;
        uint32_t Bidx2 = (Bidx1 + 1u) & 7u;

        uint64_t BlockBase = ChunkAddr + BlockOff;
        uint64_t Raw1 = 0, Raw2 = 0;
        if (!m_reader.Read(BlockBase + 32ULL * Bidx1, &Raw1, 8)) return 0;
        if (!m_reader.Read(BlockBase + 32ULL * Bidx2, &Raw2, 8)) return 0;
        if (!Raw1 && !Raw2) return 0;

        const int  BRol = (UsePipe && Pipe.BlockDecryptValid) ? Pipe.BlockRol64    : V707::BLOCK_ROL64;
        const int  BShf = (UsePipe && Pipe.BlockDecryptValid) ? Pipe.BlockPshuflw  : V707::BLOCK_PSHUFLW;
        const uint64_t BFnvXor = (UsePipe && Pipe.BlockDecryptValid && Pipe.BlockFnvXor) ? Pipe.BlockFnvXor : V707::BLOCK_FNV_XOR;

        auto DecBlock = [BRol, BShf](uint64_t Raw) -> uint64_t {
            return SoftPshuflw(fn_rotl64(Raw, BRol), BShf);
        };

        uint64_t V13 = DecBlock(Raw1) ^ BFnvXor;
        uint64_t V15 = DecBlock(Raw2);

        const int FR1 = (UsePipe && Pipe.FnvFoldValid) ? Pipe.FnvRol1 : V707::FNV_ROL1;
        const int FR2 = (UsePipe && Pipe.FnvFoldValid) ? Pipe.FnvRol2 : V707::FNV_ROL2;
        const uint64_t FA = (UsePipe && Pipe.FnvFoldValid) ? Pipe.FnvAdd : V707::FNV_ADD;

        uint64_t Fv1 = V707::FNV_PRIME * fn_rotl64(V13, FR1) + FA;
        uint64_t Fv2 = V707::FNV_PRIME * fn_rotl64(Fv1, FR2) + FA;

        uint64_t EntryPtr = (Fv2 ^ BFnvXor ^ V15) + V13 + 2ULL * NameOff;
        if (EntryPtr < 0x10000ULL || EntryPtr >= 0x800000000000ULL) return 0;
        return EntryPtr;
    }

    // ── Patch 2026-08 (image 0x11853000) ──────────────────────────────────────
    // Separate from ResolveNamePtr_NewPatch because three stages changed shape,
    // not just constants: the shard hash mixes with right shifts instead of
    // rotates, the slot selector dropped the `-109*T` multiply for a plain
    // `H^(H>>16)` fold, and block decode reordered to PSHUFLW -> XOR -> ROL64.
    // Trying to express that through the v709 parameter struct would have meant
    // adding three mode flags to a path that is still needed for older patches.
    //
    // Constants and provenance: ArcDecrypt::v20260805 in arc_decrypt.h.
    uint64_t ResolveNamePtr_Patch20260805(int32_t CompIndex) {
        namespace P805 = ArcDecrypt::v20260805;
        if (CompIndex <= 0) return 0;

        // CI needs no decode this patch (the 3 SIMD layers cancel).
        uint32_t Ci       = static_cast<uint32_t>(CompIndex);
        uint32_t NameOff  = Ci & 0xFFFFu;
        uint32_t ChunkOff = (Ci >> 8) & 0xFFFF00u;

        uint64_t GnpRva = AutoDiscovery::g_DiscoveredGNames.Valid
                        ? AutoDiscovery::g_DiscoveredGNames.GNamesRva
                        : P805::RVA_GNAMEPOOL;
        uint64_t ChunkAddr = m_base + GnpRva + ChunkOff;

        uint64_t SeedAddr = ChunkAddr + P805::SHARD_HASH_SEED_OFF;
        uint32_t Lo = static_cast<uint32_t>(SeedAddr);
        uint32_t Hi = static_cast<uint32_t>(SeedAddr >> 32);

        constexpr uint32_t HP  = P805::HASH_PRIME;
        constexpr uint32_t ADD = P805::SHARD_HASH_ADD;

        uint32_t H = (Lo >> P805::SHARD_SEED_SHR) * HP + ADD;
        H = (H >> P805::SHARD_SHR_A) * HP;
        H = ((H + Hi + ADD) >> P805::SHARD_SHR_B) * HP + ADD;
        H = (H >> P805::SHARD_SHR_C) * HP + ADD;

        uint32_t T = H ^ (H >> P805::SHARD_SELECT_SHR);
        uint32_t Bidx1 = T & 7u;
        uint32_t Bidx2 = (T + 1u) & 7u;

        uint64_t BlockBase = ChunkAddr + P805::SHARD_BLOCK_BASE_OFF;
        uint64_t Raw1 = 0, Raw2 = 0;
        if (!m_reader.Read(BlockBase + P805::SHARD_BLOCK_STRIDE * Bidx1, &Raw1, 8)) return 0;
        if (!m_reader.Read(BlockBase + P805::SHARD_BLOCK_STRIDE * Bidx2, &Raw2, 8)) return 0;
        if (!Raw1 && !Raw2) return 0;

        uint64_t Dec1 = SoftPshuflw(Raw1, P805::BLOCK_PSHUFLW) ^ P805::BLOCK_FNV_XOR;
        uint64_t Dec2 = SoftPshuflw(Raw2, P805::BLOCK_PSHUFLW) ^ P805::BLOCK_FNV_XOR;
        uint64_t V13  = fn_rotl64(Dec1, P805::BLOCK_ROL64);
        uint64_t V15  = fn_rotl64(Dec2, P805::BLOCK_ROL64);

        uint64_t Fv = P805::FNV_PRIME * fn_rotl64(Dec1, P805::FNV_ROL1_PREROT) + P805::FNV_ADD;
        Fv = P805::FNV_PRIME * fn_rotl64(Fv, P805::FNV_ROL2) + P805::FNV_ADD;

        uint64_t RawPtr = V13 + (V15 ^ Fv) + 2ULL * NameOff;

        uint64_t EntryPtr;
        if (P805::PTR_CHAIN_IS_IDENTITY) {
            EntryPtr = RawPtr;
        } else {
            uint64_t S1 = __builtin_bswap64(RawPtr ^ P805::FNAME_PTR_XOR1);
            uint64_t S2 = S1 ^ P805::FNAME_PTR_XOR2;
            EntryPtr = __builtin_bswap64(S2 ^ P805::FNAME_PTR_XOR3);
        }

        if (EntryPtr < 0x10000ULL || EntryPtr >= 0x800000000000ULL) return 0;
        return EntryPtr;
    }

    // ── CL-1325322 (v20260808) ────────────────────────────────────────────
    // Straight transcription of sub_1402319F0 → sub_14023B120 → sub_14023AAE0.
    // The CI SIMD chain across those three frames cancels to identity, so the
    // raw CompIndex feeds the offset split directly.
    uint64_t SoftPshuflwPublic(uint64_t V, int Imm) const { return SoftPshuflw(V, Imm); }
    uint64_t Rotl64Public(uint64_t V, int N) const { return fn_rotl64(V, N); }

    uint64_t ResolveNamePtr_V811(int32_t CompIndex) const {
        namespace V = ArcDecrypt::v20260811;
        namespace X = AutoDiscovery::V811Detail;
        if (CompIndex < 0 || !m_v811Active) return 0;

        const auto& Sh = ArcDecrypt::g_Sheet;
        uint32_t Ci = static_cast<uint32_t>(CompIndex);
        uint32_t NameOff  = Ci & 0xFFFFu;
        uint32_t ChunkOff = (Ci >> 8) & 0xFFFF00u;
        uint64_t ChunkAddr = m_base + m_pool811Rva + ChunkOff;

        uint32_t H = X::ShardHash(ChunkAddr + Sh.SeedOff);
        uint32_t S = H ^ (H >> 16);
        uint32_t Bidx1 = S & 7u;
        uint32_t Bidx2 = (S + 1u) & 7u;

        uint64_t BlockBase = ChunkAddr + Sh.BlockBase;
        uint64_t Raw1 = 0, Raw2 = 0;
        if (!m_reader.Read(BlockBase + Sh.BlockStride * Bidx1, &Raw1, 8)) return 0;
        if (!m_reader.Read(BlockBase + Sh.BlockStride * Bidx2, &Raw2, 8)) return 0;
        if (!Raw1 && !Raw2) return 0;

        uint64_t V13 = X::DecodeBlock(Raw1);
        uint64_t V15 = X::DecodeBlock(Raw2);

        uint64_t Fv = Sh.FnvPrime * fn_rotl64(V13, Sh.FnvRol1) + Sh.FnvAdd;
        Fv = Sh.FnvPrime * fn_rotl64(Fv, Sh.FnvRol2) + Sh.FnvAdd;

        // The four-step xor/bswap chain cancels to the identity here, so the
        // raw sum already is the entry address. See CLAUDE.md.
        uint64_t EntryPtr = V13 + (V15 ^ Fv) + 2ULL * NameOff;
        if (EntryPtr < 0x10000ULL || EntryPtr >= 0x800000000000ULL) return 0;
        return EntryPtr;
    }

    uint64_t ResolveNamePtr_V808(int32_t CompIndex) const {
        namespace V = ArcDecrypt::v20260808;
        if (CompIndex < 0 || !m_v808Active) return 0;

        uint32_t Ci = static_cast<uint32_t>(CompIndex);
        uint32_t NameOff  = Ci & 0xFFFFu;
        uint32_t ChunkOff = (Ci >> 8) & 0xFFFF00u;
        uint64_t ChunkAddr = m_base + m_pool808Rva + ChunkOff;

        uint32_t H = AutoDiscovery::V808Detail::ShardHash(ChunkAddr + V::SHARD_HASH_SEED_OFF);
        uint32_t S = H ^ (H >> 16);
        uint32_t Bidx1 = S & 7u;
        uint32_t Bidx2 = (S + 1u) & 7u;

        uint64_t BlockBase = ChunkAddr + V::SHARD_BLOCK_BASE_OFF;
        uint64_t Raw1 = 0, Raw2 = 0;
        if (!m_reader.Read(BlockBase + V::SHARD_BLOCK_STRIDE * Bidx1, &Raw1, 8)) return 0;
        if (!m_reader.Read(BlockBase + V::SHARD_BLOCK_STRIDE * Bidx2, &Raw2, 8)) return 0;
        if (!Raw1 && !Raw2) return 0;

        uint64_t V13 = AutoDiscovery::V808Detail::DecodeBlock(Raw1);
        uint64_t V15 = AutoDiscovery::V808Detail::DecodeBlock(Raw2);

        uint64_t Fv = V::FNV_PRIME * fn_rotl64(V13, V::FNV_ROL1) + V::FNV_ADD;
        Fv = V::FNV_PRIME * fn_rotl64(Fv, V::FNV_ROL2) + V::FNV_ADD;

        uint64_t RawPtr = V13 + (V15 ^ Fv) + 2ULL * NameOff;
        uint64_t Step1 = __builtin_bswap64(RawPtr ^ V::FNAME_PTR_XOR1);
        uint64_t Step2 = Step1 ^ V::FNAME_PTR_XOR2;
        uint64_t EntryPtr = __builtin_bswap64(Step2 ^ V::FNAME_PTR_XOR3);

        if (EntryPtr < 0x10000ULL || EntryPtr >= 0x800000000000ULL) return 0;
        return EntryPtr;
    }

    std::string DecryptNameString_Patch20260805(uint64_t NameEntryPtr) {
        namespace P805 = ArcDecrypt::v20260805;
        if (!NameEntryPtr) return {};

        uint16_t Hdr = 0;
        if (!m_reader.Read(NameEntryPtr, &Hdr, 2)) return {};

        int  Len    = (Hdr >> P805::HDR_LENGTH_SHIFT) & P805::HDR_LENGTH_MASK;
        bool IsWide = (Hdr & P805::HDR_IS_WIDE_BIT) != 0;
        if (Len <= 0 || Len > 512) return {};

        std::vector<uint8_t> Buf(static_cast<size_t>(Len) * (IsWide ? 2 : 1));
        if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), Buf.size())) return {};

        const uint16_t* Ks = m_ks805;
        uint32_t Key = static_cast<uint32_t>(Len) + P805::KEY_INIT_ADD;
        int Pairs = Len & ~1;
        for (int I = 0; I < Pairs; I += 2) {
            uint16_t KA = Ks[Key & P805::KEY_INDEX_MASK];
            uint16_t KB = Ks[(Key + P805::KEY_PAIR_DELTA) & P805::KEY_INDEX_MASK];
            if (!IsWide) {
                Buf[I]     ^= static_cast<uint8_t>(KA >> P805::KEY_NARROW_SHR);
                Buf[I + 1] ^= static_cast<uint8_t>(KB >> P805::KEY_NARROW_SHR);
            } else {
                reinterpret_cast<uint16_t*>(Buf.data())[I]     ^= KA;
                reinterpret_cast<uint16_t*>(Buf.data())[I + 1] ^= KB;
            }
            Key += P805::KEY_STEP;
        }
        if (Len & 1) {
            uint16_t KA = Ks[Key & P805::KEY_INDEX_MASK];
            if (!IsWide) Buf[Pairs] ^= static_cast<uint8_t>(KA >> P805::KEY_NARROW_SHR);
            else reinterpret_cast<uint16_t*>(Buf.data())[Pairs] ^= KA;
        }

        std::string Out;
        Out.reserve(Len);
        for (int I = 0; I < Len; ++I) {
            uint16_t C = IsWide ? reinterpret_cast<const uint16_t*>(Buf.data())[I] : Buf[I];
            Out += static_cast<char>(C & 0xFF);
        }
        return Out;
    }

    // Transcription of sub_140230020. The trailing narrow→wide widening pass
    // in the original writes UTF-16 into the caller's buffer; we consume the
    // narrow bytes directly and skip it.
    std::string DecryptNameString_V811(uint64_t NameEntryPtr) {
        namespace V = ArcDecrypt::v20260811;
        if (!NameEntryPtr || !m_v811Active) return {};

        uint16_t Header = 0;
        if (!m_reader.Read(NameEntryPtr, &Header, 2) || !Header) return {};

        bool IsWide = (Header & V::HDR_IS_WIDE_BIT) != 0;
        int Length = static_cast<int>(
            ((static_cast<uint32_t>(Header) >> V::HDR_LENGTH_HI_SHIFT) & V::HDR_LENGTH_HI_MASK)
            | (static_cast<uint32_t>(Header) & V::HDR_LENGTH_LO_MASK));
        if (Length <= 0 || Length > 1023) return {};

        int ByteCount = IsWide ? Length * 2 : Length;
        if (ByteCount <= 0 || ByteCount > 2048) return {};

        std::vector<uint8_t> Buf(ByteCount, 0);
        if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), ByteCount)) return {};

        // One cyclic sequence, +1 per element. No pairing, no LCG.
        uint32_t Key = static_cast<uint32_t>(Length) + ArcDecrypt::g_Sheet.KeyInitAdd;
        auto Slot = [&](uint32_t K) -> uint16_t {
            return m_keyTable811[(K & V::KEY_INDEX_MASK) + m_ks811Base];
        };

        std::string Out;
        Out.reserve(Length);
        if (!IsWide) {
            for (int I = 0; I < Length; ++I) {
                uint8_t C = Buf[I] ^ static_cast<uint8_t>(Slot(Key + static_cast<uint32_t>(I))
                                                          >> V::NARROW_KEY_SHIFT);
                if (!C) break;
                Out.push_back(static_cast<char>(C));
            }
            return Out;
        }

        // Wide XORs the full uint16 with no shift.
        for (int I = 0; I < Length; ++I) {
            uint16_t C = static_cast<uint16_t>(Buf[I * 2] | (static_cast<uint16_t>(Buf[I * 2 + 1]) << 8));
            uint16_t W = static_cast<uint16_t>(C ^ Slot(Key + static_cast<uint32_t>(I)));
            if (!W) break;
            Out.push_back(static_cast<char>(W & 0xFF));
        }
        return Out;
    }

    std::string DecryptNameString_V808(uint64_t NameEntryPtr) {
        namespace V = ArcDecrypt::v20260808;
        if (!NameEntryPtr || !m_v808Active) return {};

        uint16_t Header = 0;
        if (!m_reader.Read(NameEntryPtr, &Header, 2) || !Header) return {};

        bool IsWide = (Header & V::HDR_IS_WIDE_BIT) != 0;
        int Length = (Header >> V::HDR_LENGTH_SHIFT) & V::HDR_LENGTH_MASK;
        if (Length <= 0 || Length > 1023) return {};

        int ByteCount = IsWide ? ((Header >> 4) & 0x7FE) : (Header >> V::HDR_LENGTH_SHIFT);
        if (ByteCount <= 0 || ByteCount > 2048) return {};

        std::vector<uint8_t> Buf(ByteCount, 0);
        if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), ByteCount)) return {};

        uint32_t Key = (static_cast<uint32_t>(Length) + V::KEY_INIT_ADD) & 0xFFu;
        auto Slot = [&](uint32_t K) -> uint16_t {
            return m_keyTable808[(K & V::KEY_INDEX_MASK) + m_ks808Base];
        };

        if (!IsWide) {
            int I = 0;
            for (; I + 1 < Length; I += 2) {
                Buf[I]     ^= static_cast<uint8_t>(Slot(Key) >> V::NARROW_KEY_SHIFT);
                Buf[I + 1] ^= static_cast<uint8_t>(Slot(Key + V::KEY_SECOND_DELTA) >> V::NARROW_KEY_SHIFT);
                Key = (Key + V::KEY_PAIR_ADVANCE) & 0xFFu;
            }
            if (Length & 1)
                Buf[I] ^= static_cast<uint8_t>(Slot(Key) >> V::NARROW_KEY_SHIFT);

            std::string Out;
            Out.reserve(Length);
            for (int J = 0; J < Length; ++J) {
                if (!Buf[J]) break;
                Out.push_back(static_cast<char>(Buf[J]));
            }
            return Out;
        }

        auto* WBuf = reinterpret_cast<uint16_t*>(Buf.data());
        int WordCap = ByteCount / 2;
        int I = 0;
        for (; I + 1 < Length && I + 1 < WordCap; I += 2) {
            WBuf[I]     ^= Slot(Key);
            WBuf[I + 1] ^= Slot(Key + V::KEY_SECOND_DELTA);
            Key = (Key + V::KEY_PAIR_ADVANCE) & 0xFFu;
        }
        if ((Length & 1) && I < WordCap)
            WBuf[I] ^= Slot(Key);

        std::string Out;
        Out.reserve(Length);
        for (int J = 0; J < Length && J < WordCap; ++J) {
            uint16_t W = WBuf[J];
            if (!W) break;
            Out.push_back(W < 0x80 ? static_cast<char>(W) : '?');
        }
        return Out;
    }

    uint64_t ResolveNamePtr_NewPatch(int32_t CompIndex) {
        namespace V709 = ArcDecrypt::v20260709;
        if (CompIndex <= 0) return 0;

        const auto& Pipe = AutoDiscovery::g_DiscoveredFNamePipeline;
        const bool UsePipe = Pipe.ShardHashValid;

        uint32_t Ci = static_cast<uint32_t>(CompIndex);
        uint16_t WordOff = static_cast<uint16_t>(Ci & 0xFFFFu);
        uint32_t ChunkOff = (Ci >> 8) & 0xFFFF00u;

        uint64_t GnpRva = AutoDiscovery::g_DiscoveredGNames.Valid
                         ? AutoDiscovery::g_DiscoveredGNames.GNamesRva
                         : ArcDecrypt::v20260707::RVA_GNAMEPOOL;
        uint64_t ChunkAddr = m_base + GnpRva + ChunkOff;

        const uint64_t SeedOff  = (UsePipe && Pipe.ShardSeedOff) ? Pipe.ShardSeedOff : V709::SHARD_HASH_SEED_OFF;
        const uint64_t BlockOff = (UsePipe && Pipe.ShardBlockBaseOff) ? Pipe.ShardBlockBaseOff : V709::SHARD_BLOCK_BASE_OFF;
        const uint32_t ShardAdd = UsePipe ? Pipe.ShardHashAdd : V709::SHARD_HASH_ADD;
        constexpr uint32_t HP   = V709::HASH_PRIME;

        uint64_t SeedAddr = ChunkAddr + SeedOff;
        uint32_t Lo = static_cast<uint32_t>(SeedAddr);
        uint32_t Hi = static_cast<uint32_t>(SeedAddr >> 32);

        uint32_t H;
        if (UsePipe && Pipe.ShardHashRolCount >= 3) {
            H = HP * fn_rotl32(Lo, Pipe.ShardHashRols[0]) + ShardAdd;
            H = HP * fn_rotl32(H, Pipe.ShardHashRols[1]) + Hi + ShardAdd;
            H = HP * fn_rotl32(H, Pipe.ShardHashRols[2]) + ShardAdd;
        } else {
            H = HP * fn_rotl32(Lo, V709::SHARD_HASH_ROL_A) + ShardAdd;
            H = HP * fn_rotl32(H, V709::SHARD_HASH_ROL_B) + Hi + ShardAdd;
            H = HP * fn_rotl32(H, V709::SHARD_HASH_ROL_A) + ShardAdd;
        }
        int SlotRol = (UsePipe && Pipe.ShardHashRolCount >= 4) ? Pipe.ShardHashRols[3] : V709::SHARD_HASH_ROL_B;
        uint32_t T = fn_rotl32(H, SlotRol);
        int SlotAdd709 = (UsePipe && Pipe.SlotSelectValid)
                       ? Pipe.SlotSelectAdd : V709::SHARD_SLOT_SELECT_ADD;
        uint8_t Pa = static_cast<uint8_t>(-109 * static_cast<int>(T) + SlotAdd709);
        uint8_t Pb = static_cast<uint8_t>((HP * T + ShardAdd) >> 16);
        uint32_t Bidx1 = (Pa ^ Pb) & 7u;
        uint32_t Bidx2 = (Bidx1 + 1u) & 7u;

        uint64_t BlockBase = ChunkAddr + BlockOff;
        uint64_t Raw1 = 0, Raw2 = 0;
        if (!m_reader.Read(BlockBase + 32ULL * Bidx1, &Raw1, 8)) return 0;
        if (!m_reader.Read(BlockBase + 32ULL * Bidx2, &Raw2, 8)) return 0;
        if (!Raw1 && !Raw2) return 0;

        const int BRol  = (UsePipe && Pipe.BlockDecryptValid) ? Pipe.BlockRol64   : V709::BLOCK_ROL64;
        const int BShf  = (UsePipe && Pipe.BlockDecryptValid) ? Pipe.BlockPshuflw : V709::BLOCK_PSHUFLW;
        const uint64_t BFnvXor = (UsePipe && Pipe.BlockDecryptValid && Pipe.BlockFnvXor) ? Pipe.BlockFnvXor : V709::BLOCK_FNV_XOR;

        auto DecBlock = [BRol, BShf, BFnvXor](uint64_t Raw) -> uint64_t {
            return SoftPshuflw(fn_rotl64(Raw, BRol), BShf) ^ BFnvXor;
        };

        uint64_t V13 = DecBlock(Raw1);
        uint64_t V15 = DecBlock(Raw2);

        const int FR1 = (UsePipe && Pipe.FnvFoldValid) ? Pipe.FnvRol1 : V709::FNV_ROL1;
        const int FR2 = (UsePipe && Pipe.FnvFoldValid) ? Pipe.FnvRol2 : V709::FNV_ROL2;
        const uint64_t FA = (UsePipe && Pipe.FnvFoldValid) ? Pipe.FnvAdd : V709::FNV_ADD;

        uint64_t Fv1 = V709::FNV_PRIME * fn_rotl64(V13, FR1) + FA;
        uint64_t Fv2 = V709::FNV_PRIME * fn_rotl64(Fv1, FR2) + FA;

        uint64_t RawPtr = V13 + (V15 ^ Fv2) + 2ULL * WordOff;

        if (UsePipe && Pipe.PtrXorCount >= 3) {
            uint64_t Step1 = __builtin_bswap64(RawPtr ^ Pipe.PtrXor[0]);
            uint64_t Step2 = Step1 ^ Pipe.PtrXor[1];
            uint64_t EntryPtr = __builtin_bswap64(Step2 ^ Pipe.PtrXor[2]);
            if (EntryPtr < 0x10000ULL || EntryPtr >= 0x800000000000ULL) return 0;
            return EntryPtr;
        }
        uint64_t Step1 = __builtin_bswap64(RawPtr ^ V709::FNAME_PTR_XOR1);
        uint64_t Step2 = Step1 ^ V709::FNAME_PTR_XOR2;
        uint64_t EntryPtr = __builtin_bswap64(Step2 ^ V709::FNAME_PTR_XOR3);
        if (EntryPtr < 0x10000ULL || EntryPtr >= 0x800000000000ULL) return 0;
        return EntryPtr;
    }

    std::string DecryptNameString_NewPatch(uint64_t NameEntryPtr) {
        namespace V709 = ArcDecrypt::v20260709;
        if (!NameEntryPtr) return {};

        const auto& Sd = AutoDiscovery::g_DiscoveredStringDecrypt;
        const bool UseSd = Sd.Valid;

        const uint16_t WideBit  = UseSd ? Sd.HdrIsWideBit    : V709::HDR_IS_WIDE_BIT;
        const int      LenShift = UseSd ? Sd.HdrLengthShift  : V709::HDR_LENGTH_SHIFT;
        const uint32_t KInit    = (UseSd && Sd.KeyInitAdd)    ? Sd.KeyInitAdd     : V709::KEY_INIT_ADD;
        const uint8_t  KMask    = (UseSd && Sd.KeyIndexMask)  ? Sd.KeyIndexMask   : V709::KEY_INDEX_MASK;
        const uint32_t KMulIn   = (UseSd && Sd.KeyMulInner)   ? Sd.KeyMulInner    : V709::KEY_MUL_INNER;
        const uint32_t KAddIn   = (UseSd && Sd.KeyAddInner)   ? Sd.KeyAddInner    : V709::KEY_ADD_INNER;
        const uint32_t KMaskIn  = (UseSd && Sd.KeyMulInner)   ? static_cast<uint32_t>(KMask) : V709::KEY_MASK_INNER;
        const uint32_t KMulAdv  = (UseSd && Sd.KeyMulAdvance) ? Sd.KeyMulAdvance  : V709::KEY_MUL_ADVANCE;
        const uint32_t KAddAdv  = (UseSd && Sd.KeyAddAdvance) ? Sd.KeyAddAdvance  : V709::KEY_ADD_ADVANCE;

        uint16_t Header = 0;
        if (!m_reader.Read(NameEntryPtr, &Header, 2) || !Header) return {};

        bool IsWide = (Header & WideBit) != 0;
        int Length = static_cast<int>(Header >> LenShift);
        if (Length <= 0 || Length > 1023) return {};

        int ByteCount = IsWide ? Length * 2 : Length;
        if (ByteCount > 2048) ByteCount = 2048;

        std::vector<uint8_t> Buf(ByteCount, 0);
        if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), ByteCount)) return {};

        uint32_t Key = static_cast<uint32_t>(Length) + KInit;

        if (!IsWide) {
            int PairCount = Length / 2;
            for (int I = 0; I < PairCount; ++I) {
                uint32_t Idx1 = Key & KMask;
                Buf[2 * I] ^= static_cast<uint8_t>(m_keyTableNewPatch[Idx1] >> 3);

                uint32_t Idx2 = (Key * KMulIn + KAddIn) & KMaskIn;
                Buf[2 * I + 1] ^= static_cast<uint8_t>(m_keyTableNewPatch[Idx2] >> 3);

                Key = Key * KMulAdv + KAddAdv;
            }
            if (Length & 1) {
                uint32_t Idx = Key & KMask;
                Buf[Length - 1] ^= static_cast<uint8_t>(m_keyTableNewPatch[Idx] >> 3);
            }

            std::string Out;
            Out.reserve(Length);
            for (int J = 0; J < Length; ++J) {
                if (!Buf[J]) break;
                Out.push_back(static_cast<char>(Buf[J]));
            }
            return Out;
        } else {
            auto* WBuf = reinterpret_cast<uint16_t*>(Buf.data());
            int PairCount = Length / 2;
            for (int I = 0; I < PairCount; ++I) {
                uint32_t Idx1 = Key & KMask;
                WBuf[2 * I] ^= m_keyTableNewPatch[Idx1];

                uint32_t Idx2 = (Key * KMulIn + KAddIn) & KMaskIn;
                WBuf[2 * I + 1] ^= m_keyTableNewPatch[Idx2];

                Key = Key * KMulAdv + KAddAdv;
            }
            if (Length & 1) {
                uint32_t Idx = Key & KMask;
                WBuf[Length - 1] ^= m_keyTableNewPatch[Idx];
            }

            std::string Out;
            Out.reserve(Length);
            for (int J = 0; J < Length; ++J) {
                if (!WBuf[J]) break;
                Out.push_back(static_cast<char>(WBuf[J] & 0xFFu));
            }
            return Out;
        }
    }

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

        uint64_t GnpRva = Is616 ? ArcDecrypt::v20260616::RVA_GNAMEPOOL
                         : (ArcDecrypt::RVA_GNAMES_BASE
                            ? ArcDecrypt::RVA_GNAMES_BASE
                            : ArcDecrypt::v20260519::RVA_GNAMEPOOL);
        uint64_t ChunkAddr = m_base + GnpRva + ChunkOff;

        uint8_t Bidx1, Bidx2;
        uint64_t BlockBase;

        if (Is616) {
            namespace V616 = ArcDecrypt::v20260616;
            uint64_t SeedAddr = ChunkAddr + V616::SHARD_HASH_SEED_OFF;
            uint32_t SeedLo = static_cast<uint32_t>(SeedAddr);
            uint32_t SeedHi = static_cast<uint32_t>(SeedAddr >> 32);
            uint64_t V8 = (16ULL << 32) | SeedLo;
            uint32_t H = V616::HASH_PRIME * static_cast<uint32_t>(V8 >> 5) + V616::SHARD_HASH_ADD;
            H = fn_rotl32(H, 18);
            H = V616::HASH_PRIME * H + SeedHi + V616::SHARD_HASH_ADD;
            H = fn_rotl32(H, 27);
            H = V616::HASH_PRIME * H + V616::SHARD_HASH_ADD;
            uint32_t V9 = fn_rotl32(H, 18);

            uint8_t Pa = static_cast<uint8_t>(static_cast<int8_t>(-109) * static_cast<int>(V9) + 54);
            uint8_t Pb = static_cast<uint8_t>((V616::HASH_PRIME * V9 + V616::SHARD_HASH_ADD) >> 16);
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

        auto DecBlock616 = [&](const uint8_t* Raw, bool IsSecond) -> uint64_t {
            namespace V616 = ArcDecrypt::v20260616;
            __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Raw));
            V = _mm_or_si128(_mm_slli_epi64(V, V616::ENTRY_ROL64),
                             _mm_srli_epi64(V, 64 - V616::ENTRY_ROL64));
            alignas(16) uint8_t Mask[16];
            std::memcpy(Mask, V616::ENTRY_PSHUFB_MASK, 16);
            if (IsSecond) {
                alignas(16) uint8_t Bx[16];
                std::memcpy(Bx, V616::ENTRY_BLEND_XOR, 16);
                V = _mm_xor_si128(V, _mm_load_si128(reinterpret_cast<const __m128i*>(Bx)));
                V = _mm_shuffle_epi8(V, _mm_load_si128(reinterpret_cast<const __m128i*>(Mask)));
                uint64_t Lo;
                _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
                return Lo ^ V616::ENTRY_XOR;
            }
            alignas(16) uint8_t Xk[16];
            std::memcpy(Xk, V616::ENTRY_XOR_MASK, 16);
            V = _mm_shuffle_epi8(V, _mm_load_si128(reinterpret_cast<const __m128i*>(Mask)));
            V = _mm_xor_si128(V, _mm_load_si128(reinterpret_cast<const __m128i*>(Xk)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            return Lo ^ V616::ENTRY_XOR;
        };
        auto DecBlock519 = [&](const uint8_t* Raw) -> uint64_t {
            using namespace ArcDecrypt::v20260519;
            __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Raw));
            V = _mm_shufflelo_epi16(V, BLOCK_SHUF_A);
            V = _mm_or_si128(_mm_slli_epi64(V, BLOCK_ROL),
                             _mm_srli_epi64(V, 64 - BLOCK_ROL));
            V = _mm_shufflelo_epi16(V, BLOCK_SHUF_B);
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            return Lo;
        };
        uint64_t Block1, Block2;
        if (Is616) {
            Block1 = DecBlock616(Sb1, false);
            Block2 = DecBlock616(Sb2, true);
        } else {
            Block1 = DecBlock519(Sb1);
            Block2 = DecBlock519(Sb2);
        }

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

        if (m_v818Active)
            return DecryptNameString_V818(NameEntryPtr);

        if (m_v811Active)
            return DecryptNameString_V811(NameEntryPtr);

        if (m_v808Active)
            return DecryptNameString_V808(NameEntryPtr);

        if (m_patch0805Active)
            return DecryptNameString_Patch20260805(NameEntryPtr);

        if (m_newPatchActive)
            return DecryptNameString_NewPatch(NameEntryPtr);

        if (m_newPatchActive)
            return DecryptNameString_NewPatch(NameEntryPtr);

        if (m_ks707Loaded)
            return DecryptNameString_V707(NameEntryPtr);

        if (m_ks616Loaded) {
            return DecryptNameString_CL1233465(NameEntryPtr);
        }
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

    std::string DecryptNameString_V707(uint64_t NameEntryPtr) {
        namespace V707 = ArcDecrypt::v20260707;
        if (!NameEntryPtr || !m_ks707Loaded) return {};

        uint16_t Header = 0;
        if (!m_reader.Read(NameEntryPtr, &Header, 2) || !Header) return {};

        int Length = static_cast<int>(((Header >> 12) | ((Header >> 2) & 0x3F8)) & 0xFFFF);
        bool IsWide = (Header & V707::HDR_IS_WIDE_BIT) != 0;
        if (Length <= 0 || Length > 1023) return {};

        if (!IsWide) {
            std::vector<uint8_t> Buf(Length, 0);
            if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), Length)) return {};

            uint32_t Eax = (static_cast<uint32_t>(Length) + V707::KEY_BIAS_NARROW) & 0xFFFFFFFFu;
            int HalfLen = Length & ~1;
            int K = 0;
            while (2 * K < HalfLen) {
                Buf[2 * K]     ^= static_cast<uint8_t>(m_keyTable707[(Eax - V707::KEY_BIAS_ADD) & V707::KEY_INDEX_MASK] >> 3);
                Buf[2 * K + 1] ^= static_cast<uint8_t>(m_keyTable707[Eax & V707::KEY_INDEX_MASK] >> 3);
                Eax = (Eax + V707::KEY_PAIR_STEP) & 0xFFFFFFFFu;
                ++K;
            }
            if (Length & 1) {
                Buf[Length - 1] ^= static_cast<uint8_t>(m_keyTable707[(Eax - V707::KEY_BIAS_ADD) & V707::KEY_INDEX_MASK] >> 3);
            }

            std::string Out;
            Out.reserve(Length);
            for (int J = 0; J < Length; ++J) {
                if (!Buf[J]) break;
                Out.push_back(static_cast<char>(Buf[J]));
            }
            return Out;
        } else {
            std::vector<uint16_t> Wides(Length, 0);
            if (!m_reader.Read(NameEntryPtr + 2, Wides.data(),
                               static_cast<size_t>(Length) * sizeof(uint16_t))) return {};

            uint32_t Eax = (static_cast<uint32_t>(Length) + V707::KEY_BIAS_NARROW) & 0xFFFFFFFFu;
            int HalfLen = Length & ~1;
            int K = 0;
            while (2 * K < HalfLen) {
                Wides[2 * K]     ^= m_keyTable707[(Eax - V707::KEY_BIAS_ADD) & V707::KEY_INDEX_MASK];
                Wides[2 * K + 1] ^= m_keyTable707[Eax & V707::KEY_INDEX_MASK];
                Eax = (Eax + V707::KEY_PAIR_STEP) & 0xFFFFFFFFu;
                ++K;
            }
            if (Length & 1) {
                Wides[Length - 1] ^= m_keyTable707[(Eax - V707::KEY_BIAS_ADD) & V707::KEY_INDEX_MASK];
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

    std::string DecryptNameString_CL1233465(uint64_t NameEntryPtr) {
        namespace V616 = ArcDecrypt::v20260616;
        if (!m_ks616Loaded) return DecryptNameString_Build20260519(NameEntryPtr);

        uint16_t Header = 0;
        if (!m_reader.Read(NameEntryPtr, &Header, 2) || !Header) return {};

        int Length = static_cast<int>((Header >> 14) | ((Header >> 4) & 0x3FC));
        bool IsWide = (Header & V616::HDR_IS_WIDE_BIT) != 0;
        if (Length <= 0 || Length > 1023) return {};

        if (!IsWide) {
            std::vector<uint8_t> Buf(Length, 0);
            if (!m_reader.Read(NameEntryPtr + 2, Buf.data(), Length)) return {};

            uint8_t KeyLo = static_cast<uint8_t>((Length + V616::KEY_INIT_BIAS_NARROW) & 0xFF);
            uint8_t Kv = static_cast<uint8_t>((KeyLo + V616::KEY_PAIR_OFFSET) & 0xFF);
            int I = 0;
            while (I + 1 < Length) {
                int K1i = ((Kv - V616::KEY_PAIR_OFFSET) & V616::KEY_INDEX_MASK) + V616::KEYSTREAM_DECRYPT_BASE;
                int K2i = (Kv & V616::KEY_INDEX_MASK) + V616::KEYSTREAM_DECRYPT_BASE;
                Buf[I]     ^= static_cast<uint8_t>(m_keyTable616[K1i] >> 3);
                Buf[I + 1] ^= static_cast<uint8_t>(m_keyTable616[K2i] >> 3);
                I += 2;
                Kv = static_cast<uint8_t>((Kv + V616::KEY_PAIR_STEP) & 0xFF);
            }
            if ((Length & 1) && I < Length) {
                int Ki = ((Kv - V616::KEY_PAIR_OFFSET) & V616::KEY_INDEX_MASK) + V616::KEYSTREAM_DECRYPT_BASE;
                Buf[I] ^= static_cast<uint8_t>(m_keyTable616[Ki] >> 3);
            }

            std::string Out;
            Out.reserve(Length);
            for (int J = 0; J < Length; ++J) {
                if (!Buf[J]) break;
                Out.push_back(static_cast<char>(Buf[J]));
            }
            return Out;
        } else {
            std::vector<uint16_t> Wides(Length, 0);
            if (!m_reader.Read(NameEntryPtr + 2, Wides.data(),
                               static_cast<size_t>(Length) * sizeof(uint16_t))) return {};

            uint16_t Key = static_cast<uint16_t>((Length + V616::KEY_INIT_BIAS_WIDE) & 0xFFFF);
            int I = 0;
            while (I + 1 < Length) {
                int K1i = (Key & V616::KEY_INDEX_MASK) + V616::KEYSTREAM_DECRYPT_BASE;
                int K2i = ((Key + V616::KEY_PAIR_OFFSET) & V616::KEY_INDEX_MASK) + V616::KEYSTREAM_DECRYPT_BASE;
                Wides[I]     ^= m_keyTable616[K1i];
                Wides[I + 1] ^= m_keyTable616[K2i];
                I += 2;
                Key = static_cast<uint16_t>((Key + V616::KEY_PAIR_STEP_WIDE) & 0xFFFF);
            }
            if ((Length & 1) && I < Length) {
                int Ki = (Key & V616::KEY_INDEX_MASK) + V616::KEYSTREAM_DECRYPT_BASE;
                Wides[I] ^= m_keyTable616[Ki];
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
    // ── CL-1325322 UObject::GetFName ─────────────────────────────────────
    // Transcribed from the native AngelScript binding at RVA 0x343950. The
    // slot holding NamePrivate is picked by an FNV32 hash of (Obj + 0x10), so
    // no fixed offset works — that is why offset sweeps all came up empty.
    // UObject::GetFName @ RVA 0x5027E0. Every mask is parenthesised on
    // purpose: `&` binds looser than `+` in C++, so `(x * P) & M + Hi + ADD`
    // silently becomes `(x * P) & (M + Hi + ADD)` and produces a hash with
    // zero correlation to the real slot while looking entirely reasonable.
    uint32_t ObjSlotHashV811(uint64_t ObjPtr) const {
        return AutoDiscovery::V811Detail::SlotHash(ObjPtr);
    }

    uint32_t ObjNameSlotIndexV811(uint64_t ObjPtr) const {
        return AutoDiscovery::V811Detail::NameSlotIndex(ObjPtr);
    }

    uint64_t GetObjFNameV811(uint64_t ObjPtr) const {
        namespace V = ArcDecrypt::v20260811;
        (void)sizeof(V::UOBJ_NAME_SLOT_BASE);
        const auto& Sh = ArcDecrypt::g_Sheet;
        uint64_t Slot = ObjPtr + Sh.SlotBase + Sh.SlotStride * ObjNameSlotIndexV811(ObjPtr);
        uint64_t Enc = 0;
        if (!m_reader.Read(Slot, &Enc, 8)) return 0;
        return fn_rotl64(AutoDiscovery::V811Detail::DecodeSlot(Enc), Sh.SlotFinalRol);
    }

    std::string GetNameV811(uint64_t ObjPtr) {
        uint64_t F = GetObjFNameV811(ObjPtr);
        return DecryptNameString_V811(ResolveNamePtr_V811(static_cast<int32_t>(F & 0xFFFFFFFFu)));
    }

    uint32_t ObjNameSlotIndexV808(uint64_t ObjPtr) const {
        namespace V = ArcDecrypt::v20260808;
        uint64_t Seed = ObjPtr + V::UOBJ_NAME_SEED_OFF;
        uint32_t Lo = static_cast<uint32_t>(Seed);
        uint32_t Hi = static_cast<uint32_t>(Seed >> 32);
        constexpr uint32_t P = V::UOBJ_SLOT_HASH_PRIME;
        constexpr uint32_t A = V::UOBJ_SLOT_HASH_ADD;

        uint32_t H = (Lo >> V::UOBJ_SLOT_SHIFT_A) * P + A;
        H = fn_rotl32(H, V::UOBJ_SLOT_HASH_ROL) * P;
        H = H + Hi + A;
        H = (H >> V::UOBJ_SLOT_SHIFT_B) * P + A;
        H = (H >> V::UOBJ_SLOT_SHIFT_C) * P + A;

        uint32_t S = H ^ (H >> 16);
        uint32_t X = (((~S) | V::UOBJ_SLOT_MASK_A) & V::UOBJ_SLOT_MASK_B) | (S & 2u);
        return (X ^ V::UOBJ_SLOT_MASK_C) & 3u;
    }

    uint64_t GetObjFNameV808(uint64_t ObjPtr) const {
        namespace V = ArcDecrypt::v20260808;
        uint64_t Slot = ObjPtr + V::UOBJ_NAME_SLOT_BASE +
                        V::UOBJ_NAME_SLOT_STRIDE * ObjNameSlotIndexV808(ObjPtr);
        uint64_t Enc = 0;
        if (!m_reader.Read(Slot, &Enc, 8)) return 0;
        uint64_t Val = fn_rotl64(SoftPshuflw(Enc, V::UOBJ_NAME_PSHUFLW) ^ V::UOBJ_NAME_XOR1,
                                 V::UOBJ_NAME_ROL1) ^ V::UOBJ_NAME_XOR2;
        return fn_rotl64(Val, V::UOBJ_NAME_ROL2);
    }

    std::string GetNameV808(uint64_t ObjPtr) {
        uint64_t F = GetObjFNameV808(ObjPtr);
        if (!F) return {};
        return DecryptNameString_V808(ResolveNamePtr_V808(static_cast<int32_t>(F & 0xFFFFFFFFu)));
    }

    std::string GetName(uint64_t obj_ptr) {
        if (!obj_ptr || !m_keyLoaded) return {};

        // v908 is authoritative: an object with a valid slot but no name
        // (e.g. the metaclass singletons whose name-slot decrypts to 0/None)
        // must NOT fall through to legacy paths — those return plausible
        // garbage which pollutes downstream classification with names like
        // '>ƪ��_3590549823'.
        if (m_v908Active) {
            return GetNameV908(obj_ptr);
        }

        if (m_v818Active) {
            std::string S = GetNameV818(obj_ptr);
            if (!S.empty()) return S;
        }

        if (m_v811Active) {
            std::string S = GetNameV811(obj_ptr);
            if (!S.empty()) return S;
        }

        if (m_v808Active) {
            std::string S = GetNameV808(obj_ptr);
            if (!S.empty()) return S;
        }

        auto isSaneName = [](const std::string& s) {
            if (s.empty() || s.size() > 1024) return false;
            int printable = 0;
            for (unsigned char c : s)
                if (c >= 32 && c <= 126)
                    ++printable;
            return printable * 5 >= static_cast<int>(s.size()) * 4;
        };

        if (!m_ks707Loaded) {
            if (m_primaryHandleOffset) {
                std::string s = GetNameByHandle(obj_ptr, m_primaryHandleOffset);
                if (isSaneName(s)) return s;
            }
            for (uint64_t off : {uint64_t(0x28), uint64_t(0x18), uint64_t(0x30)}) {
                if (off == m_primaryHandleOffset) continue;
                std::string s = GetNameByHandle(obj_ptr, off);
                if (isSaneName(s)) return s;
            }
        }

        int32_t comp = GetCompIndex(obj_ptr);
        if (comp > 0) {
            uint64_t nptr = ResolveNamePtrFull(comp);
            if (nptr) {
                std::string out = DecryptNameString(nptr);
                if (isSaneName(out)) return out;
            }
            m_lastHashSlotStale = true;
        }

        return {};
    }

    // ── Resolve comp_index → string ──────────────────────────────────────
    // Strict: identifier-shaped only (alphanum + _:./- space). Used for
    // class/enum/struct names that go straight into the SDK output.
    // Strict: returns empty string if the result is not identifier-shaped.
    std::string CompIndexToName(int32_t comp_index) {
        std::string s = StaticResolve(comp_index);
        return IsStrictName(s) ? s : std::string{};
    }

    // ── FName::Number suffix ─────────────────────────────────────────────
    // An FName is {ComparisonIndex, Number}, and UE splits a trailing number
    // off the literal when it interns one: "H5_5" is stored as the entry "H5"
    // with Number 6. Resolving the CompIndex alone therefore silently truncates
    // every such name, which is how EEmbarkUITextType came out with H5 twice.
    // UE's own ToString appends `_(Number - 1)`.
    static std::string ApplyNameNumber(const std::string& Base, uint32_t Number) {
        if (Base.empty() || Number == 0) return Base;
        return Base + "_" + std::to_string(Number - 1);
    }

    std::string CompIndexToNameNumbered(int32_t comp_index, uint32_t number) {
        return ApplyNameNumber(CompIndexToNameLenient(comp_index), number);
    }

    std::string CompIndexToNameLenient(int32_t comp_index) {
        std::string s = StaticResolve(comp_index);
        if (IsLenientName(s)) return s;
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
            std::printf("\n");
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
    // All four UObject slots share one transform; the name simply needs a final
    // ROL64(32) to bring CompIndex into the low dword, while Class/Outer are the
    // pre-rotation value used directly as a pointer. Slot roles are relative to
    // the hash-selected name slot — verified on 120 UFunctions: rel+2 resolved to
    // the "Function" UClass for every one, rel+3 to a plausible Outer.
    // Class sits at (S & 3), Outer at (S + 1) & 3, Name at (S + 2) & 3 —
    // i.e. SlotRel is measured from the class slot, not the name slot.
    uint64_t DecodeObjSlotPtrV811(uint64_t ObjPtr, uint32_t SlotRel) const {
        namespace V = ArcDecrypt::v20260811;
        (void)sizeof(V::UOBJ_NAME_SLOT_BASE);
        const auto& Sh = ArcDecrypt::g_Sheet;
        uint32_t Idx = (ObjSlotHashV811(ObjPtr) + SlotRel) & 3u;
        uint64_t Enc = 0;
        if (!m_reader.Read(ObjPtr + Sh.SlotBase + Sh.SlotStride * Idx, &Enc, 8) || !Enc)
            return 0;
        uint64_t Ptr = AutoDiscovery::V811Detail::DecodeSlot(Enc);
        if (Ptr < 0x10000ULL || Ptr >= 0x800000000000ULL) return 0;
        return Ptr;
    }
    uint64_t GetClassPtrV811(uint64_t ObjPtr) const {
        return DecodeObjSlotPtrV811(ObjPtr, ArcDecrypt::g_Sheet.SlotClassAdj);
    }
    uint64_t GetOuterPtrV811(uint64_t ObjPtr) const {
        return DecodeObjSlotPtrV811(ObjPtr, ArcDecrypt::g_Sheet.SlotOuterAdj);
    }

    uint64_t DecodeObjSlotPtrV808(uint64_t ObjPtr, uint32_t SlotRel) const {
        namespace V = ArcDecrypt::v20260808;
        uint32_t Idx = (ObjNameSlotIndexV808(ObjPtr) + SlotRel) & 3u;
        uint64_t Enc = 0;
        if (!m_reader.Read(ObjPtr + V::UOBJ_NAME_SLOT_BASE +
                           V::UOBJ_NAME_SLOT_STRIDE * Idx, &Enc, 8) || !Enc)
            return 0;
        uint64_t Ptr = fn_rotl64(SoftPshuflw(Enc, V::UOBJ_NAME_PSHUFLW) ^ V::UOBJ_NAME_XOR1,
                                 V::UOBJ_NAME_ROL1) ^ V::UOBJ_NAME_XOR2;
        if (Ptr < 0x10000ULL || Ptr >= 0x800000000000ULL) return 0;
        return Ptr;
    }
    uint64_t GetClassPtrV808(uint64_t ObjPtr) const { return DecodeObjSlotPtrV808(ObjPtr, 2); }
    // Picks whichever pipeline is live so call sites do not have to.
    uint64_t GetClassPtrAuto(uint64_t ObjPtr) const {
        if (m_v908Active) return GetClassPtrV908(ObjPtr);
        if (m_v818Active) return GetClassPtrV818(ObjPtr);
        if (m_v811Active) return GetClassPtrV811(ObjPtr);
        if (m_v808Active) return GetClassPtrV808(ObjPtr);
        return 0;
    }
    uint64_t GetOuterPtrV808(uint64_t ObjPtr) const { return DecodeObjSlotPtrV808(ObjPtr, 3); }

    uint64_t GetOuterPtr(uint64_t obj_ptr) {
        if (!obj_ptr || !m_keyLoaded) return 0;

        if (m_v908Active) {
            // v908 is authoritative — no fall-through.
            return GetOuterPtrV908(obj_ptr);
        }

        if (m_v818Active) {
            uint64_t P = GetOuterPtrV818(obj_ptr);
            if (P) return P;
        }

        if (m_v811Active) {
            uint64_t P = GetOuterPtrV811(obj_ptr);
            if (P) return P;
        }

        if (m_v808Active) {
            uint64_t P = GetOuterPtrV808(obj_ptr);
            if (P) return P;
        }
        // 20260428: same swapped-halves shape as GetClassPrivate. See comment there.
        auto tryDecode = [&](int slot) -> uint64_t {
            alignas(16) uint8_t enc[16] = {};
            uint64_t addr = obj_ptr + 0x20 + static_cast<uint64_t>(slot) * 0x20;
            if (!m_reader.Read(addr, enc, 16)) return 0;
            uint64_t dec = DecryptUObjSlotNew(enc);
            if (!dec) return 0;
            uint64_t ptr = dec;
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

        // The walk below decodes slots with DecryptUObjSlotNew, which is the
        // legacy decoder: on a modern pipeline it returns noise, every step
        // fails the UPackage vtable test, and the caller falls back to
        // synthesising "/Script/<ClassName>" from the type's own name. Walk
        // the Outer chain with whichever decoder is live instead, and take
        // the first object whose name reads as a package path.
        if (m_v818Active || m_v811Active || m_v808Active) {
            uint64_t Cur = obj_ptr;
            for (int Depth = 0; Depth < 24; ++Depth) {
                uint64_t Next = GetOuterPtr(Cur);
                if (!Next || Next == Cur) break;
                std::string N = GetName(Next);
                if (!N.empty() && N[0] == '/') return Next;
                Cur = Next;
            }
            return 0;
        }
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
            uint64_t ptr = dec;
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
        return DecryptUObjSlotNew(enc);
    }

    uint64_t DecryptPtrSlot(const uint8_t enc[16]) const {
        return DecryptUObjSlotPtr_Build20260519(enc);
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
    uint16_t       m_keyTable616[160];
    bool           m_ks616Loaded = false;
    uint16_t       m_keyTable707[64];
    bool           m_ks707Loaded = false;
    uint16_t       m_keyTableNewPatch[64];
    uint16_t       m_keyTable811[ArcDecrypt::v20260811::KEYSTREAM_ENTRIES] = {};
    bool           m_v811Active  = false;
    uint16_t       m_keyTable818[64] = {};
    bool           m_v818Active  = false;
    uint64_t       m_pool818Rva  = ArcDecrypt::v20260818::RVA_GNAMEPOOL;
    // v908 (CL-1372005, UE 5.7). The keystream table entry count is the same
    // 160-uint16 shape as CL-1325322/v20260808; the effective decrypt window
    // starts at byte offset +0xA0 above KEYSTREAM_RVA.
    uint16_t       m_keyTable908[ArcDecrypt::v20260908::KEYSTREAM_ENTRIES] = {};
    bool           m_v908Active  = false;
    uint64_t       m_pool908Rva  = ArcDecrypt::v20260908::RVA_GNAMEPOOL;
    uint64_t       m_pool811Rva  = 0;
    int            m_ks811Base   = ArcDecrypt::v20260811::KEYSTREAM_BASE_INDEX;

    uint16_t       m_keyTable808[ArcDecrypt::v20260808::KEYSTREAM_ENTRIES] = {};
    bool           m_v808Active  = false;
    uint64_t       m_pool808Rva  = 0;
    int            m_ks808Base   = ArcDecrypt::v20260808::KEYSTREAM_BASE_INDEX;
    bool           m_newPatchActive = false;
    uint16_t       m_ks805[64] = {};
    bool           m_patch0805Active = false;
    __m128i        m_seedXor1 = {};
    __m128i        m_seedBlend = {};
    __m128i        m_seedBlendNot = {};
    __m128i        m_seedXor2 = {};
    __m128i        m_seedXor3 = {};
    __m128i        m_seedXor4 = {};
    __m128i        m_chunkXor = {};
    bool           m_seedLoaded = false;
    int            m_lenientFailCount = 0;
    uint64_t       m_primaryHandleOffset = 0;  // 0 = no calibration yet, fall back to candidate list
    uint64_t       m_ffieldNameOff = 0;        // 0 = uncalibrated; first valid offset wins
    bool           m_lastHashSlotStale = false;

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
