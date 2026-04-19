#pragma once
// =============================================================================
// Signature scanner — patch-resilient RVA discovery.
//
// Works in addition to the hardcoded RVAs in arc_decrypt.h. The hardcoded
// values stay as the primary source (they're correct for the current patch);
// the scanner runs at startup and overwrites any RVA where the signature
// resolves to something different (i.e. after a patch). Each anchor is
// independent — scan failure falls through to the hardcoded value.
//
// VMProtect-cold pages: the on-disk PE dump is used as a read fallback when
// the live kernel reader returns 0xCC padding. See pe_reader.h.
// =============================================================================

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <cstdio>

#include "decoder.h"
#include "pe_reader.h"

namespace SigScan {

// IDA-style pattern: "48 8D 0D ? ? ? ?". '?' or '??' = wildcard byte.
struct Pattern {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;   // true = literal

    static Pattern Parse(const char* sig) {
        Pattern p;
        const char* s = sig;
        auto hx = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        while (*s) {
            while (*s == ' ' || *s == '\t') ++s;
            if (!*s) break;
            if (*s == '?') {
                p.bytes.push_back(0); p.mask.push_back(false);
                ++s; if (*s == '?') ++s;
            } else {
                int h = hx(s[0]); int l = hx(s[1]);
                if (h < 0 || l < 0) break;
                p.bytes.push_back((uint8_t)((h << 4) | l));
                p.mask.push_back(true);
                s += 2;
            }
        }
        return p;
    }
};

template <class Reader>
class Scanner {
public:
    Scanner(Reader& reader, uint64_t module_base, uint64_t module_size)
        : m_reader(reader), m_base(module_base), m_size(module_size) {}

    void SetPEFallback(PEFileReader* pe) { m_pe = pe; }

    // Live → PE-fallback page read. Signatures authored against IDA's static
    // view match equally on live memory and on-disk PE.
    bool ReadPage(uint64_t addr, uint8_t* out, size_t len) {
        if (m_reader.Read(addr, out, len)) return true;
        if (m_pe && m_pe->IsOpen() && addr >= m_base) {
            uint32_t rva = (uint32_t)(addr - m_base);
            int64_t delta = (int64_t)m_base - (int64_t)m_pe->PreferredBase();
            return m_pe->ReadAtRVA(rva, out, len, delta);
        }
        return false;
    }

    // First pattern match across the module, or 0.
    // Page-by-page scan with rolling tail so matches straddle boundaries.
    uint64_t Find(const Pattern& pat) {
        if (pat.bytes.empty()) return 0;
        constexpr size_t kPage = 0x1000;
        const size_t kTail = pat.bytes.size() - 1;
        std::vector<uint8_t> buf(kPage + kTail);
        uint64_t end = m_base + m_size;
        bool have_tail = false;
        for (uint64_t cursor = m_base; cursor < end; cursor += kPage) {
            size_t read_len = (size_t)std::min<uint64_t>(end - cursor, kPage);
            uint8_t* target = buf.data() + kTail;
            if (!ReadPage(cursor, target, read_len)) { have_tail = false; continue; }
            size_t start_off = have_tail ? 0 : kTail;
            size_t region_len = read_len + kTail;
            size_t scan_end = (region_len >= pat.bytes.size()) ? region_len - pat.bytes.size() + 1 : 0;
            for (size_t i = start_off; i < scan_end; ++i)
                if (MatchAt(buf.data() + i, pat)) return cursor - kTail + i;
            if (read_len >= kTail) { std::memcpy(buf.data(), target + read_len - kTail, kTail); have_tail = true; }
            else have_tail = false;
        }
        return 0;
    }

    uint64_t ResolveRipDisp(uint64_t lea_va, int insn_len, int disp_off) {
        int32_t v = 0;
        uint8_t b[4];
        if (!ReadPage(lea_va + disp_off, b, 4)) return 0;
        std::memcpy(&v, b, 4);
        return lea_va + insn_len + (int64_t)v;
    }

    // ── Typed finders ───────────────────────────────────────────────────────

    // GObjectArray accessor prologue. Cross-patch verified Apr 02/09/14.
    // Pattern: LEA rcx,[rip+g_GObj]; CALL; MOV+CMP+JNE+CMP+JNE init-once sled.
    uint64_t FindGObjectArrayRVA() {
        static const char* kSig =
            "48 8D 0D ? ? ? ? E8 ? ? ? ? C6 05 ? ? ? ? 00 "
            "80 3D ? ? ? ? 00 75 ? 80 3D ? ? ? ? 01 0F 85 ? ? 00 00";
        auto pat = Pattern::Parse(kSig);
        uint64_t hit = Find(pat);
        if (!hit) return 0;
        uint64_t t = ResolveRipDisp(hit, 7, 3);
        return InRange(t) ? (t - m_base) : 0;
    }

    // GWorld. Cross-patch verified.
    // Pattern: mov rax,[rip+gworld]; lea r15,[rip+gworld+0x10]; mov ecx,esi; jmp
    uint64_t FindGWorldRVA() {
        static const char* kSig = "48 8B 05 ? ? ? ? 4C 8D 3D ? ? ? ? 89 F1 EB ?";
        auto pat = Pattern::Parse(kSig);
        uint64_t hit = Find(pat);
        if (!hit) return 0;
        uint64_t t = ResolveRipDisp(hit, 7, 3);
        return InRange(t) ? (t - m_base) : 0;
    }

    // FNamePool base (GNames). Apr 14 only — older patches lack `add rdi, 0xC0`.
    uint64_t FindGNamesRVA() {
        static const char* kSig = "48 8D 1D ? ? ? ? 48 8D 3C 1E 48 81 C7 C0 00 00 00";
        auto pat = Pattern::Parse(kSig);
        uint64_t hit = Find(pat);
        if (!hit) return 0;
        uint64_t t = ResolveRipDisp(hit, 7, 3);
        return InRange(t) ? (t - m_base) : 0;
    }

    // FName XOR key table. Only xref lives in a VMProtect-encrypted function,
    // so we go two-stage: try the hint, then scan near GNames for a region
    // with key-table shape (64 uint16, ≥50 non-zero, no value repeats > 6×).
    uint64_t FindFNameKeyTableRVA(uint64_t hint_rva, uint64_t gnames_rva) {
        if (hint_rva && LooksLikeKeyTable(m_base + hint_rva)) return hint_rva;
        if (!gnames_rva) return 0;
        const uint64_t radius = 4 * 0x100000ULL;
        uint64_t gn = m_base + gnames_rva;
        uint64_t lo = (gn > m_base + radius) ? gn - radius : m_base;
        uint64_t hi = std::min<uint64_t>(gn + radius, m_base + m_size);
        for (uint64_t va = (lo + 15) & ~15ULL; va < hi; va += 16)
            if (LooksLikeKeyTable(va)) return va - m_base;
        return 0;
    }

    // GObjectArray decrypt function's 4 SIMD-table RIP-relative loads.
    // Only `decrypt_key` (first LEA) resolves cleanly in older patches; the
    // elem-count triplet is Apr 14-specific.
    struct SimdTables { uint64_t decrypt_key, elem_mask_a, elem_mask_b, elem_xor_key; };
    static constexpr const char* kDecryptFnSig =
        "48 8D 05 ? ? ? ? 48 89 01 C7 41 08 FF FF FF FF "
        "48 C7 41 10 00 00 00 00 41 BC FF FF FF FF 45 84 C0";
    SimdTables FindObjArraySimdTables() {
        SimdTables t = {};
        auto pat = Pattern::Parse(kDecryptFnSig);
        uint64_t fn = Find(pat);
        if (!fn) return t;
        std::vector<uint8_t> body(128);
        if (!ReadPage(fn, body.data(), 128)) return t;
        auto hits = m_decoder.ScanRipLoads(body.data(), 128, fn, 96);
        int sidx = 0;
        for (const auto& h : hits) {
            if (h.off < 40) continue;
            uint64_t rva = InRange(h.target_va) ? (h.target_va - m_base) : 0;
            if (!rva) continue;
            if (sidx == 0) t.decrypt_key = rva;
            else if (sidx == 1) t.elem_mask_a = rva;
            else if (sidx == 2) t.elem_mask_b = rva;
            else if (sidx == 3) t.elem_xor_key = rva;
            if (++sidx >= 4) break;
        }
        return t;
    }

    // CIdx decrypt key — anchored on the FNV-hash tail inside FName_DecryptBlockAddr.
    uint64_t FindCIdxXor1RVA() {
        static const char* kSig =
            "69 C0 93 01 00 01 05 ? ? ? ? C1 C0 11 "
            "69 C0 93 01 00 01 05 ? ? ? ?";
        auto pat = Pattern::Parse(kSig);
        uint64_t hit = Find(pat);
        if (!hit) return 0;
        uint8_t scan[128] = {};
        uint64_t scan_va = hit + 25;
        if (!ReadPage(scan_va, scan, 128)) return 0;
        auto hits = m_decoder.ScanRipLoads(scan, sizeof(scan), scan_va, 32);
        for (const auto& h : hits)
            if (h.mem_size >= 8 && InRange(h.target_va)) return h.target_va - m_base;
        return 0;
    }

private:
    static bool MatchAt(const uint8_t* buf, const Pattern& pat) {
        const size_t n = pat.bytes.size();
        for (size_t i = 0; i < n; ++i)
            if (pat.mask[i] && buf[i] != pat.bytes[i]) return false;
        return true;
    }

    bool InRange(uint64_t va) const {
        return va >= m_base && va < m_base + m_size;
    }

    // 64 uint16, ≥50 non-zero, no value repeats more than 6×.
    bool LooksLikeKeyTable(uint64_t va) {
        uint16_t t[64] = {};
        if (!m_reader.Read(va, t, sizeof(t))) return false;
        int nz = 0, peak = 0;
        for (int i = 0; i < 64; ++i) {
            if (t[i]) ++nz;
            int count = 0;
            for (int j = 0; j < 64; ++j) if (t[j] == t[i]) ++count;
            if (count > peak) peak = count;
        }
        return nz >= 50 && peak <= 6;
    }

    Reader&       m_reader;
    uint64_t      m_base;
    uint64_t      m_size;
    Decoder       m_decoder;
    PEFileReader* m_pe = nullptr;
};

} // namespace SigScan
