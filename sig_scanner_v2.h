#pragma once

// =============================================================================
// sig_scanner_v2.h — full module-cache + IDA-style AOB scanner adapted from
// ArcAutoDiscovery for FrostSDKDumper's IMemoryReader.
//
// What it does:
//   1. Parses live PE headers from `module_base` to enumerate sections.
//   2. Reads the entire module into a local `std::vector<uint8_t>` cache (with
//      a per-page validity bitmap for unreadable VMProtect / paged-out pages).
//   3. Optional disk cache (module_dump_<base>.bin) for repeat runs — keyed
//      on a 64-byte hash of .text head so game updates invalidate it.
//   4. IDA-style pattern scanning (`"48 8D 0D ?? ?? ?? ??"`) over the cache —
//      no live-memory page reads in the hot loop.
//   5. Section-aware helpers (IsTextRVA / IsRDataRVA / IsDataRVA) and
//      `GetLocalPtr(rva)` for callers that want to disassemble with Zydis.
//
// This replaces the page-streaming `sig_scan.h` for auto-discovery work.
// Keep `sig_scan.h` only for the legacy 6-RVA scanner main.cpp::Init() does
// before this scanner is up.
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>

#include "memreader_iface.h"

namespace SigScanV2 {

// ─────────────────────────────────────────────────────────────────────────────
// PE structures (subset — only what we need)
// ─────────────────────────────────────────────────────────────────────────────
struct PESection {
    char     Name[9]   = {};   // null-terminated
    uint32_t VA        = 0;    // RVA start
    uint32_t VSize     = 0;    // VirtualSize
    uint32_t RawSize   = 0;
    uint32_t RawOffset = 0;
    uint32_t Chars     = 0;

    uint32_t End() const { return VA + VSize; }
    bool IsExecutable() const { return (Chars & 0x20000000u) != 0; }
    bool IsReadable()   const { return (Chars & 0x40000000u) != 0; }
    bool IsWritable()   const { return (Chars & 0x80000000u) != 0; }
};

// ─────────────────────────────────────────────────────────────────────────────
// IDA-style AOB pattern parser. "48 8D 0D ?? ?? ?? ??" → bytes + mask.
// `?` and `??` are wildcards. Whitespace tolerant.
// ─────────────────────────────────────────────────────────────────────────────
struct Pattern {
    std::vector<uint8_t> Bytes;
    std::vector<bool>    Mask;   // true = literal, false = wildcard

    static int HexNibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
    static Pattern Parse(const char* sig) {
        Pattern p;
        const char* s = sig;
        while (*s) {
            while (*s == ' ' || *s == '\t') ++s;
            if (!*s) break;
            if (*s == '?') {
                p.Bytes.push_back(0); p.Mask.push_back(false);
                ++s; if (*s == '?') ++s;
            } else {
                int hi = HexNibble(s[0]); int lo = HexNibble(s[1]);
                if (hi < 0 || lo < 0) break;
                p.Bytes.push_back((uint8_t)((hi << 4) | lo));
                p.Mask.push_back(true);
                s += 2;
            }
        }
        return p;
    }
    static Pattern Parse(const std::string& sig) { return Parse(sig.c_str()); }
};

// ─────────────────────────────────────────────────────────────────────────────
// Scanner — owns the local module cache + section table.
// ─────────────────────────────────────────────────────────────────────────────
class Scanner {
public:
    static constexpr uint32_t kPage = 0x1000;

    Scanner() = default;

    // Initialize: parse PE headers from live memory, walk sections, then
    // read every page (skipping unreadable ones) into m_cache. Tries to
    // load from disk cache first (if present and validates).
    bool Initialize(IMemoryReader& reader, uint64_t module_base) {
        m_reader = &reader;
        m_base   = module_base;

        // Read PE header (first 0x1000 bytes).
        uint8_t hdr[kPage] = {};
        if (!m_reader->Read(m_base, hdr, sizeof(hdr))) {
            std::printf("[sigscan] PE header read failed @ 0x%llX\n",
                (unsigned long long)m_base);
            return false;
        }
        if (hdr[0] != 'M' || hdr[1] != 'Z') {
            std::printf("[sigscan] not a PE (no MZ at base)\n");
            return false;
        }
        uint32_t e_lfanew = *(uint32_t*)(hdr + 0x3C);
        if (e_lfanew >= kPage - 0x100) return false;
        if (*(uint32_t*)(hdr + e_lfanew) != 0x00004550u) return false;  // "PE\0\0"

        uint16_t numSections   = *(uint16_t*)(hdr + e_lfanew + 6);
        uint16_t optHeaderSize = *(uint16_t*)(hdr + e_lfanew + 0x14);
        uint32_t optHdrOff     = e_lfanew + 0x18;
        uint32_t sectStart     = optHdrOff + optHeaderSize;
        m_imageSize            = *(uint32_t*)(hdr + optHdrOff + 0x38);

        // Sanity clamp.
        if (m_imageSize == 0 || m_imageSize > 0x40000000u /* 1 GiB */) {
            std::printf("[sigscan] implausible SizeOfImage 0x%X — using 0xE9AF000 fallback\n",
                m_imageSize);
            m_imageSize = 0xE9AF000;
        }

        // Walk section headers.
        m_sections.clear();
        for (uint16_t i = 0;
             i < numSections && sectStart + (i + 1) * 0x28 <= sizeof(hdr); ++i)
        {
            const uint8_t* s = hdr + sectStart + i * 0x28;
            PESection sec;
            std::memcpy(sec.Name, s, 8);
            sec.VSize     = *(uint32_t*)(s + 8);
            sec.VA        = *(uint32_t*)(s + 12);
            sec.RawSize   = *(uint32_t*)(s + 16);
            sec.RawOffset = *(uint32_t*)(s + 20);
            sec.Chars     = *(uint32_t*)(s + 36);
            m_sections.push_back(sec);
        }
        if (m_sections.empty()) return false;

        const PESection* tx = FindSection(".text");
        const PESection* rd = FindSection(".rdata");
        const PESection* dt = FindSection(".data");
        if (!tx || !rd || !dt) {
            std::printf("[sigscan] missing required section: text=%p rdata=%p data=%p\n",
                (void*)tx, (void*)rd, (void*)dt);
            return false;
        }

        std::printf("[sigscan] PE: image=0x%X .text=0x%X..0x%X .rdata=0x%X..0x%X .data=0x%X..0x%X\n",
            m_imageSize, tx->VA, tx->End(), rd->VA, rd->End(), dt->VA, dt->End());

        // Try disk cache.
        std::string cachePath = DumpCachePath();
        if (TryLoadDumpCache(cachePath, hdr)) {
            std::printf("[sigscan] loaded module cache from %s\n", cachePath.c_str());
            return true;
        }

        // Read entire module page-by-page.
        m_cache.assign(m_imageSize, 0);
        size_t totalPages = (m_imageSize + kPage - 1) / kPage;
        m_pageValid.assign(totalPages, 0);

        // Cache the PE header pages we already have.
        std::memcpy(m_cache.data(), hdr, sizeof(hdr));
        m_pageValid[0] = 1;

        size_t goodPages = 1, badPages = 0;
        for (size_t p = 1; p < totalPages; ++p) {
            uint64_t pageRva  = (uint64_t)p * kPage;
            uint64_t pageAddr = m_base + pageRva;
            size_t   want     = std::min<uint64_t>(kPage, m_imageSize - pageRva);
            if (m_reader->Read(pageAddr, m_cache.data() + pageRva, want)) {
                m_pageValid[p] = 1;
                ++goodPages;
            } else {
                ++badPages;
            }
        }
        std::printf("[sigscan] cached %zu pages (%zu unreadable)\n", goodPages, badPages);

        SaveDumpCache(cachePath, hdr);
        return goodPages > totalPages / 2;  // demand >50% coverage
    }

    // ─── Section / RVA introspection ───────────────────────────────────────

    const PESection* FindSection(const char* name) const {
        for (const auto& s : m_sections)
            if (std::strcmp(s.Name, name) == 0) return &s;
        return nullptr;
    }

    bool IsTextRVA(uint64_t rva) const {
        const auto* s = FindSection(".text");
        return s && rva >= s->VA && rva < s->End();
    }
    bool IsRDataRVA(uint64_t rva) const {
        const auto* s = FindSection(".rdata");
        return s && rva >= s->VA && rva < s->End();
    }
    bool IsDataRVA(uint64_t rva) const {
        const auto* s = FindSection(".data");
        return s && rva >= s->VA && rva < s->End();
    }
    bool IsValidRVA(uint64_t rva) const { return rva < m_imageSize; }
    bool IsPageValid(uint64_t rva) const {
        size_t p = rva / kPage;
        return p < m_pageValid.size() && m_pageValid[p] != 0;
    }

    uint64_t   GameBase()   const { return m_base; }
    uint32_t   ModuleSize() const { return m_imageSize; }
    const uint8_t* CacheData() const { return m_cache.data(); }
    size_t         CacheSize() const { return m_cache.size(); }

    // Returns a pointer into the local cache. Returns nullptr if the page
    // wasn't readable (or if rva is out of range).
    const uint8_t* GetLocalPtr(uint64_t rva) const {
        if (rva >= m_imageSize) return nullptr;
        if (!IsPageValid(rva)) return nullptr;
        return m_cache.data() + rva;
    }

    // ─── Pattern scanning over the local cache ─────────────────────────────

    std::vector<uint64_t> Scan(const Pattern& pat) const {
        std::vector<uint64_t> hits;
        if (pat.Bytes.empty() || m_cache.empty()) return hits;
        size_t n = pat.Bytes.size();
        if (n > m_cache.size()) return hits;

        for (size_t i = 0; i + n <= m_cache.size(); ++i) {
            // Skip if first byte is a wildcard (rare); the initial byte
            // check is the dominant fast path.
            if (pat.Mask[0] && m_cache[i] != pat.Bytes[0]) continue;
            // Skip if this offset isn't in a valid page.
            if (!IsPageValid(i)) {
                // Jump to next page boundary.
                i = (i + kPage) & ~((size_t)kPage - 1);
                if (i == 0) break;
                --i;  // for-loop ++i
                continue;
            }
            bool ok = true;
            for (size_t j = 0; j < n; ++j) {
                if (pat.Mask[j] && m_cache[i + j] != pat.Bytes[j]) { ok = false; break; }
            }
            if (ok) hits.push_back(i);
        }
        return hits;
    }
    std::vector<uint64_t> Scan(const std::string& sig) const {
        return Scan(Pattern::Parse(sig));
    }
    std::vector<uint64_t> Scan(const char* sig) const {
        return Scan(Pattern::Parse(sig));
    }

    // Section-bounded scan.
    std::vector<uint64_t> ScanSection(const Pattern& pat, const char* section) const {
        std::vector<uint64_t> hits;
        const auto* s = FindSection(section);
        if (!s || pat.Bytes.empty()) return hits;
        size_t n = pat.Bytes.size();
        size_t lo = s->VA;
        size_t hi = std::min<uint64_t>((uint64_t)s->End(), (uint64_t)m_cache.size());
        if (hi < lo + n) return hits;
        for (size_t i = lo; i + n <= hi; ++i) {
            if (pat.Mask[0] && m_cache[i] != pat.Bytes[0]) continue;
            if (!IsPageValid(i)) {
                i = (i + kPage) & ~((size_t)kPage - 1);
                if (i == 0) break;
                --i;
                continue;
            }
            bool ok = true;
            for (size_t j = 0; j < n; ++j) {
                if (pat.Mask[j] && m_cache[i + j] != pat.Bytes[j]) { ok = false; break; }
            }
            if (ok) hits.push_back(i);
        }
        return hits;
    }
    std::vector<uint64_t> ScanSection(const std::string& sig, const char* section) const {
        return ScanSection(Pattern::Parse(sig), section);
    }
    std::vector<uint64_t> ScanSection(const char* sig, const char* section) const {
        return ScanSection(Pattern::Parse(sig), section);
    }

    // Find a literal C-string in .rdata, return its RVA (0 if absent).
    uint64_t FindString(const char* str, const char* section = ".rdata") const {
        std::string pat;
        for (const char* s = str; *s; ++s) {
            char buf[4]; std::snprintf(buf, sizeof(buf), "%02X ", (uint8_t)*s);
            pat += buf;
        }
        pat += "00";
        auto hits = ScanSection(pat, section);
        return hits.empty() ? 0 : hits[0];
    }

    // Find a wide (UTF-16LE) string in .rdata.
    uint64_t FindWString(const char* str, const char* section = ".rdata") const {
        std::string pat;
        for (const char* s = str; *s; ++s) {
            char buf[8]; std::snprintf(buf, sizeof(buf), "%02X 00 ", (uint8_t)*s);
            pat += buf;
        }
        pat += "00 00";
        auto hits = ScanSection(pat, section);
        return hits.empty() ? 0 : hits[0];
    }

    // Resolve a RIP-relative displacement at insn_rva+disp_off (4 bytes LE)
    // into an absolute RVA. insn_len = total instruction length.
    uint64_t ResolveRipDisp(uint64_t insn_rva, int insn_len, int disp_off) const {
        const uint8_t* p = GetLocalPtr(insn_rva + disp_off);
        if (!p) return 0;
        int32_t v = 0;
        std::memcpy(&v, p, 4);
        return insn_rva + insn_len + (int64_t)v;
    }

    // Find every LEA r64,[rip+disp32] in .text whose target == targetRVA.
    // Returns the RVAs of the LEA instructions themselves (not their targets).
    std::vector<uint64_t> FindLeaXrefs(uint64_t targetRVA) const {
        std::vector<uint64_t> out;
        const auto* tx = FindSection(".text");
        if (!tx || m_cache.empty()) return out;
        size_t lo = tx->VA;
        size_t hi = std::min<uint64_t>((uint64_t)tx->End(), (uint64_t)m_cache.size());
        if (hi < lo + 7) return out;
        for (size_t i = lo; i + 7 <= hi; ++i) {
            // REX.W (0x48..0x4F) + 0x8D + ModR/M (mod=0, rm=5)
            if ((m_cache[i] & 0xF8) != 0x48) continue;
            if (m_cache[i + 1] != 0x8D) continue;
            uint8_t modrm = m_cache[i + 2];
            if ((modrm & 0xC7) != 0x05) continue;
            int32_t disp = 0;
            std::memcpy(&disp, &m_cache[i + 3], 4);
            uint64_t resolved = (uint64_t)i + 7 + (int64_t)disp;
            if (resolved == targetRVA) out.push_back(i);
        }
        return out;
    }

private:
    // ─── Disk dump cache (header + bitmap + module bytes) ──────────────────
    static constexpr uint32_t kDumpMagic   = 0x56444D48u;  // "HMDV"
    static constexpr uint32_t kDumpVersion = 1u;

    struct DumpHeader {
        uint32_t Magic;
        uint32_t Version;
        uint64_t GameBase;
        uint32_t SizeOfImage;
        uint32_t TotalPages;
        uint64_t TextHeadHash;  // FNV1a of first 64 bytes of .text — change = patch
    };

    std::string DumpCachePath() const {
        char path[256];
        std::snprintf(path, sizeof(path), "module_dump_0x%llX.bin",
            (unsigned long long)m_base);
        return path;
    }

    static uint64_t Fnv1a(const uint8_t* d, size_t n) {
        uint64_t h = 0xcbf29ce484222325ULL;
        for (size_t i = 0; i < n; ++i) { h ^= d[i]; h *= 0x100000001b3ULL; }
        return h;
    }

    bool TryLoadDumpCache(const std::string& path, const uint8_t* peHdr) {
        FILE* f = std::fopen(path.c_str(), "rb");
        if (!f) return false;

        DumpHeader hdr{};
        if (std::fread(&hdr, sizeof(hdr), 1, f) != 1 ||
            hdr.Magic != kDumpMagic || hdr.Version != kDumpVersion ||
            hdr.GameBase != m_base || hdr.SizeOfImage != m_imageSize)
        {
            std::fclose(f);
            return false;
        }

        std::vector<uint8_t> bitmap(hdr.TotalPages);
        if (std::fread(bitmap.data(), 1, hdr.TotalPages, f) != hdr.TotalPages) {
            std::fclose(f);
            return false;
        }
        std::vector<uint8_t> data(m_imageSize);
        if (std::fread(data.data(), 1, m_imageSize, f) != m_imageSize) {
            std::fclose(f);
            return false;
        }
        std::fclose(f);

        // Verify .text head hash against live: if the game updated since this
        // cache was written, the bytes won't match and we must re-read.
        uint64_t liveHash = 0;
        const auto* tx = FindSection(".text");
        if (tx && tx->VA + 64 <= m_imageSize) {
            uint8_t live[64] = {};
            if (m_reader->Read(m_base + tx->VA, live, 64)) {
                liveHash = Fnv1a(live, 64);
            }
        }
        if (liveHash != 0 && liveHash != hdr.TextHeadHash) {
            std::printf("[sigscan] cache stale (.text head hash drift) — re-reading\n");
            return false;
        }

        m_cache     = std::move(data);
        m_pageValid = std::move(bitmap);
        return true;
    }

    void SaveDumpCache(const std::string& path, const uint8_t* peHdr) {
        FILE* f = std::fopen(path.c_str(), "wb");
        if (!f) return;
        DumpHeader hdr{};
        hdr.Magic       = kDumpMagic;
        hdr.Version     = kDumpVersion;
        hdr.GameBase    = m_base;
        hdr.SizeOfImage = m_imageSize;
        hdr.TotalPages  = (uint32_t)m_pageValid.size();
        const auto* tx = FindSection(".text");
        if (tx && tx->VA + 64 <= m_cache.size())
            hdr.TextHeadHash = Fnv1a(m_cache.data() + tx->VA, 64);
        std::fwrite(&hdr, sizeof(hdr), 1, f);
        std::fwrite(m_pageValid.data(), 1, m_pageValid.size(), f);
        std::fwrite(m_cache.data(), 1, m_cache.size(), f);
        std::fclose(f);
        std::printf("[sigscan] saved module cache to %s\n", path.c_str());
    }

    IMemoryReader*        m_reader   = nullptr;
    uint64_t              m_base     = 0;
    uint32_t              m_imageSize = 0;
    std::vector<PESection> m_sections;
    std::vector<uint8_t>   m_cache;
    std::vector<uint8_t>   m_pageValid;  // 1 = page readable in m_cache
};

}  // namespace SigScanV2
