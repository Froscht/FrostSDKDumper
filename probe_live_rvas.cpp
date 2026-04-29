// probe_live_rvas.cpp — scan live process memory for current-session RVAs of:
//   1. FName XOR key table (128-byte region, 64 uint16)
//   2. GUObjectArray struct base
//   3. FNamePool (GNames) header
//
// Usage:  probe_live_rvas [PID]
//   If no PID given, auto-detect by pgrep GameThread / PioneerGame etc.
//
// Build (standalone):
//   g++ -std=c++17 -O2 -march=native -I. -o probe_live_rvas probe_live_rvas.cpp -lm
//
// Output lines:
//   [probe] FNameKeyTbl = 0x14XXXXXXX
//   [probe] GUObjArray  = 0x14XXXXXXX  (cand N/3)
//   [probe] FNamePool   = 0x14XXXXXXX  (cand N/3)
//
// Reads are done via process_vm_readv first, falling back to /dev/memreader ioctl
// (matches the approach in main.cpp's KernelReader).

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <cmath>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <string>

#include "memreader_ioctl.h"

// ─────────────────────────────────────────────────────────────────────────────
// Scan configuration
// ─────────────────────────────────────────────────────────────────────────────
static constexpr uint64_t MODULE_BASE = 0x140000000ULL;
static constexpr uint64_t DATA_LO     = 0x14DA4F000ULL;
static constexpr uint64_t DATA_HI     = 0x14E1B4000ULL;
// .rdata region (FField decrypt constants, keystreams, SIMD xor keys)
static constexpr uint64_t RDATA_LO    = 0x140ACB9000ULL;
static constexpr uint64_t RDATA_HI    = 0x140DA4F000ULL;
static constexpr size_t   STRIDE      = 16;              // 16-byte aligned
static constexpr size_t   PAGE_SZ     = 0x1000;

// ─────────────────────────────────────────────────────────────────────────────
// Reader (self-contained, mirrors main.cpp::KernelReader)
// ─────────────────────────────────────────────────────────────────────────────
struct Reader {
    int fd  = -1;
    int pid = 0;

    bool Open(int target_pid) {
        pid = target_pid;
        fd  = open("/dev/memreader", O_RDWR);
        if (fd < 0) {
            fprintf(stderr, "[probe] warn: /dev/memreader not available (%s); using process_vm_readv only\n",
                    strerror(errno));
        }
        return true;
    }

    ~Reader() { if (fd >= 0) close(fd); }

    bool Read(uint64_t addr, void* buf, size_t sz) {
        if (!buf || !sz) return false;
        struct iovec loc = { buf, sz };
        struct iovec rem = { reinterpret_cast<void*>(addr), sz };
        ssize_t n = process_vm_readv(pid, &loc, 1, &rem, 1, 0);
        if (n == static_cast<ssize_t>(sz)) return true;

        if (fd < 0) return false;
        struct memreader_read_request req = {};
        req.pid = pid;
        req.address = addr;
        req.size = sz;
        req.buffer = buf;
        return ioctl(fd, MEMREADER_READ_MEMORY, &req) == 0;
    }

    // Bulk-read a whole page; caller handles per-page failures.
    bool ReadPage(uint64_t page_va, uint8_t* out) {
        return Read(page_va, out, PAGE_SZ);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Auto-detect PID (GameThread / PioneerGame / ARC)
// ─────────────────────────────────────────────────────────────────────────────
static int AutoDetectPid() {
    static const char* kPats[] = {
        "pgrep GameThread 2>/dev/null | head -1",
        "pgrep -f 'PioneerGame.*Binaries' 2>/dev/null | head -1",
        "pgrep -f 'ARC-Win64-Ship' 2>/dev/null | head -1",
        "pgrep -f 'ARC-WinGDK-Ship' 2>/dev/null | head -1",
    };
    for (const char* p : kPats) {
        FILE* f = popen(p, "r");
        if (!f) continue;
        int pid = 0;
        if (fscanf(f, "%d", &pid) == 1 && pid > 0) { pclose(f); return pid; }
        pclose(f);
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: plausible user-mode pointer check
// ─────────────────────────────────────────────────────────────────────────────
static inline bool IsUserPtr(uint64_t p) {
    return p >= 0x10000ULL && p < 0x7FFFFFFFFFFFULL;
}
static inline bool IsUserPtrOrZero(uint64_t p) {
    return p == 0 || IsUserPtr(p);
}

// ─────────────────────────────────────────────────────────────────────────────
// Candidate 1: FName key table — 128 bytes = 64 uint16
//   • ≥50 non-zero uint16
//   • no single uint16 value repeats more than 6 times
//   • fast-reject via first 8 bytes (4 uint16): need ≥3 non-zero
// ─────────────────────────────────────────────────────────────────────────────
static bool IsKeyTable(const uint8_t* buf) {
    const uint16_t* w = reinterpret_cast<const uint16_t*>(buf);
    int nz = 0;
    std::unordered_map<uint16_t, int> freq;
    freq.reserve(64);
    for (int i = 0; i < 64; ++i) {
        if (w[i]) { ++nz; ++freq[w[i]]; }
    }
    if (nz < 50) return false;
    for (auto& kv : freq) if (kv.second > 6) return false;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Candidate 2: GUObjectArray heuristic
//   • +0x30..+0x3F: entropy-high (not all zero, not all FF), encrypted-looking
//   • +0x00..+0x07: plausible user-mode pointer
//   • +0xB8..+0xBF: zero-pad
// Score = higher shannon-ish byte diversity in [0x30..0x40)
// ─────────────────────────────────────────────────────────────────────────────
static double ByteDiversity(const uint8_t* p, size_t n) {
    int counts[256] = {};
    for (size_t i = 0; i < n; ++i) counts[p[i]]++;
    double h = 0.0;
    for (int c : counts) {
        if (!c) continue;
        double q = (double)c / (double)n;
        h -= q * std::log2(q);
    }
    return h;
}
static bool GUObjCandidate(const uint8_t* buf, double& score_out) {
    uint64_t p0 = *reinterpret_cast<const uint64_t*>(buf + 0x00);
    if (!IsUserPtr(p0)) return false;

    // +0xB8..+0xBF must be zero-pad
    uint64_t pad_b8 = *reinterpret_cast<const uint64_t*>(buf + 0xB8);
    if (pad_b8 != 0) return false;

    // +0x30..+0x3F: encrypted-looking
    const uint8_t* enc = buf + 0x30;
    bool all_zero = true, all_ff = true;
    for (int i = 0; i < 16; ++i) {
        if (enc[i] != 0x00) all_zero = false;
        if (enc[i] != 0xFF) all_ff   = false;
    }
    if (all_zero || all_ff) return false;

    double h = ByteDiversity(enc, 16);
    if (h < 2.5) return false;  // need decent diversity

    score_out = h;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Candidate 3: FNamePool header
//   • +0xC8 : plausible user-mode ptr
//   • +0xD8 : plausible user-mode ptr
//   • +0xD0 : plausible user-mode ptr OR zero
// Score = 1 if +0xD0 is a ptr, 0 otherwise (rank by that then address).
// ─────────────────────────────────────────────────────────────────────────────
static bool FNamePoolCandidate(const uint8_t* buf, int& score_out) {
    uint64_t c8 = *reinterpret_cast<const uint64_t*>(buf + 0xC8);
    uint64_t d0 = *reinterpret_cast<const uint64_t*>(buf + 0xD0);
    uint64_t d8 = *reinterpret_cast<const uint64_t*>(buf + 0xD8);
    if (!IsUserPtr(c8))         return false;
    if (!IsUserPtr(d8))         return false;
    if (!IsUserPtrOrZero(d0))   return false;
    score_out = IsUserPtr(d0) ? 1 : 0;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Candidate 4: FField PSHUFB mask
//   Uniquely identifies the FField decrypt pipeline. Exact 16-byte signature.
// ─────────────────────────────────────────────────────────────────────────────
static const uint8_t kFFieldPshufbMask[16] = {
    0x07, 0x02, 0x03, 0x06, 0x05, 0x00, 0x01, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// ─────────────────────────────────────────────────────────────────────────────
// Candidate 5: FField XOR constant — first 8 bytes are specific.
//   Full 16-byte form would over-constrain; match first 8 then accept.
// ─────────────────────────────────────────────────────────────────────────────
static const uint8_t kFFieldXorConst8[8] = {
    0x31, 0x7E, 0x97, 0x77, 0x56, 0x27, 0x31, 0x31,
};

// ─────────────────────────────────────────────────────────────────────────────
// Candidate 6: FNamePool keystream table
//   256-byte region where no byte value repeats more than 3×.
//   (A uniform random table of 256 bytes would average ~1 per value; tables
//    with heavy repetition or all-zero runs are rejected.)
// ─────────────────────────────────────────────────────────────────────────────
static bool IsKeystream256(const uint8_t* buf) {
    int counts[256] = {};
    for (int i = 0; i < 256; ++i) counts[buf[i]]++;
    // Need broad distribution: every value bucket ≤3 occurrences.
    int distinct = 0;
    for (int v = 0; v < 256; ++v) {
        if (counts[v] > 3) return false;
        if (counts[v] > 0) ++distinct;
    }
    // A pseudorandom 256-byte block should touch many distinct values.
    // Empirically ≥100 distinct values eliminates most structured tables.
    if (distinct < 100) return false;
    // Reject tables whose first byte windows are all zero/FF.
    int zeros = 0, ffs = 0;
    for (int i = 0; i < 256; ++i) {
        if (buf[i] == 0x00) ++zeros;
        if (buf[i] == 0xFF) ++ffs;
    }
    if (zeros > 3 || ffs > 3) return false;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main scan loop
// ─────────────────────────────────────────────────────────────────────────────
struct GUObjHit  { uint64_t addr; double score; };
struct FNPoolHit { uint64_t addr; int    score; };

int main(int argc, char** argv) {
    int pid = 0;
    if (argc >= 2) pid = atoi(argv[1]);
    if (pid <= 0)  pid = AutoDetectPid();
    if (pid <= 0) {
        fprintf(stderr, "[probe] No PID supplied and auto-detect failed.\n");
        return 1;
    }
    printf("[probe] PID = %d\n", pid);
    printf("[probe] scanning .data range 0x%lX .. 0x%lX (stride %zu)\n",
           DATA_LO, DATA_HI, STRIDE);

    Reader R;
    R.Open(pid);

    std::vector<uint64_t>   key_hits;
    std::vector<GUObjHit>   guobj_hits;
    std::vector<FNPoolHit>  fnpool_hits;
    std::vector<uint64_t>   pshufb_hits;
    std::vector<uint64_t>   xor_hits;
    std::vector<uint64_t>   keystream_hits;

    std::vector<uint8_t> page(PAGE_SZ);
    // Window large enough for FNamePool probe (needs up to +0xE0 for safety).
    static constexpr size_t WIN_BYTES = 0x100;

    uint64_t pages_ok = 0, pages_fail = 0;

    // ──────────────── KEY SCAN LOOP ───────────────────────────────────────
    for (uint64_t page_va = DATA_LO & ~(PAGE_SZ - 1); page_va < DATA_HI; page_va += PAGE_SZ) {
        if (!R.ReadPage(page_va, page.data())) { ++pages_fail; continue; }
        ++pages_ok;

        for (size_t off = 0; off + WIN_BYTES <= PAGE_SZ; off += STRIDE) {
            uint64_t va = page_va + off;
            if (va < DATA_LO || va + WIN_BYTES > DATA_HI) continue;
            const uint8_t* p = page.data() + off;

            // (1) FName key table: fast-reject via first 8 bytes (4 uint16: ≥3 non-zero)
            {
                const uint16_t* w = reinterpret_cast<const uint16_t*>(p);
                int nz4 = (w[0]!=0) + (w[1]!=0) + (w[2]!=0) + (w[3]!=0);
                if (nz4 >= 3 && IsKeyTable(p)) key_hits.push_back(va);
            }

            // (2) GUObjectArray candidate
            {
                double s = 0.0;
                if (GUObjCandidate(p, s)) guobj_hits.push_back({va, s});
            }

            // (3) FNamePool candidate
            {
                int s = 0;
                if (FNamePoolCandidate(p, s)) fnpool_hits.push_back({va, s});
            }
        }
    }

    printf("[probe] .data pages OK=%lu fail=%lu\n", pages_ok, pages_fail);

    // ──────────────── .rdata scan (FField consts, keystream tables) ───────
    printf("[probe] scanning .rdata range 0x%lX .. 0x%lX\n", RDATA_LO, RDATA_HI);
    uint64_t rpages_ok = 0, rpages_fail = 0;

    // Read each page into a buffer that keeps 16 bytes of overlap from the
    // previous page to catch patterns straddling a page boundary.
    std::vector<uint8_t> rpage(PAGE_SZ + 256);
    bool have_prev = false;

    for (uint64_t page_va = RDATA_LO & ~(PAGE_SZ - 1); page_va < RDATA_HI; page_va += PAGE_SZ) {
        // Preserve trailing 256 bytes of previous page for cross-page matching.
        if (have_prev) {
            memmove(rpage.data(), rpage.data() + PAGE_SZ, 256);
        } else {
            memset(rpage.data(), 0, 256);
        }

        if (!R.ReadPage(page_va, rpage.data() + 256)) {
            ++rpages_fail;
            have_prev = false;
            continue;
        }
        ++rpages_ok;
        have_prev = true;

        // Scan the window [rpage.data()+256 - 256 .. rpage.data()+256 + PAGE_SZ - 16]
        // Map index i (0..PAGE_SZ-1) of current page → buffer offset (256 + i)
        // and i may be negative (from previous-page tail).
        for (ssize_t i = -256; i < static_cast<ssize_t>(PAGE_SZ); ++i) {
            const uint8_t* p = rpage.data() + 256 + i;
            uint64_t va = page_va + i;
            if (va < RDATA_LO || va + 16 > RDATA_HI) continue;

            // PSHUFB mask (exact 16 bytes)
            if (memcmp(p, kFFieldPshufbMask, 16) == 0) {
                pshufb_hits.push_back(va);
            }
            // XOR const (first 8 bytes match)
            if (memcmp(p, kFFieldXorConst8, 8) == 0) {
                xor_hits.push_back(va);
            }
        }

        // 256-byte keystream candidate: check every 16-byte aligned offset.
        for (size_t off = 0; off + 256 <= PAGE_SZ; off += 16) {
            uint64_t va = page_va + off;
            if (va < RDATA_LO || va + 256 > RDATA_HI) continue;
            const uint8_t* p = rpage.data() + 256 + off;
            if (IsKeystream256(p)) {
                keystream_hits.push_back(va);
            }
        }
    }
    printf("[probe] .rdata pages OK=%lu fail=%lu\n", rpages_ok, rpages_fail);

    // ──────────────── Report: FName key table ─────────────────────────────
    if (key_hits.empty()) {
        printf("[probe] FNameKeyTbl = <none found>\n");
    } else {
        // Report all; first is usually the right one.
        for (size_t i = 0; i < key_hits.size(); ++i) {
            printf("[probe] FNameKeyTbl = 0x%lX%s\n",
                   key_hits[i], i ? "  (alt)" : "");
        }
    }

    // ──────────────── Report: GUObjectArray (top 3 by score) ──────────────
    std::sort(guobj_hits.begin(), guobj_hits.end(),
              [](const GUObjHit& a, const GUObjHit& b) { return a.score > b.score; });
    if (guobj_hits.empty()) {
        printf("[probe] GUObjArray  = <none found>\n");
    } else {
        size_t n = std::min<size_t>(3, guobj_hits.size());
        for (size_t i = 0; i < n; ++i) {
            printf("[probe] GUObjArray  = 0x%lX  (cand %zu/3, entropy=%.2f)\n",
                   guobj_hits[i].addr, i + 1, guobj_hits[i].score);
        }
    }

    // ──────────────── Report: FNamePool (top 3, prefer +0xD0 ptr) ─────────
    std::sort(fnpool_hits.begin(), fnpool_hits.end(),
              [](const FNPoolHit& a, const FNPoolHit& b) {
                  if (a.score != b.score) return a.score > b.score;
                  return a.addr < b.addr;
              });
    if (fnpool_hits.empty()) {
        printf("[probe] FNamePool   = <none found>\n");
    } else {
        size_t n = std::min<size_t>(3, fnpool_hits.size());
        for (size_t i = 0; i < n; ++i) {
            printf("[probe] FNamePool   = 0x%lX  (cand %zu/3, score=%d)\n",
                   fnpool_hits[i].addr, i + 1, fnpool_hits[i].score);
        }
    }

    // ──────────────── Report: FField PSHUFB mask ──────────────────────────
    // Sort and dedupe (we may have scanned overlapping boundaries).
    std::sort(pshufb_hits.begin(), pshufb_hits.end());
    pshufb_hits.erase(std::unique(pshufb_hits.begin(), pshufb_hits.end()), pshufb_hits.end());
    if (pshufb_hits.empty()) {
        printf("[probe] FField_PshufbMask = <none found>\n");
    } else {
        for (size_t i = 0; i < pshufb_hits.size(); ++i) {
            printf("[probe] FField_PshufbMask = 0x%lX%s\n",
                   pshufb_hits[i], i ? "  (alt)" : "");
        }
    }

    // ──────────────── Report: FField XOR constant ─────────────────────────
    std::sort(xor_hits.begin(), xor_hits.end());
    xor_hits.erase(std::unique(xor_hits.begin(), xor_hits.end()), xor_hits.end());
    if (xor_hits.empty()) {
        printf("[probe] FField_XorConst   = <none found>\n");
    } else {
        for (size_t i = 0; i < xor_hits.size(); ++i) {
            printf("[probe] FField_XorConst   = 0x%lX%s\n",
                   xor_hits[i], i ? "  (alt)" : "");
        }
    }

    // ──────────────── Report: SIMD xor keys near the PSHUFB mask ──────────
    // The GObjectArray decrypt pipeline uses 16-byte xmmword keys that sit
    // near the PSHUFB mask. Print the 2-3 16-byte regions adjacent to each
    // mask hit (−32, −16, +16 from the mask).
    if (!pshufb_hits.empty()) {
        for (uint64_t mask_va : pshufb_hits) {
            printf("[probe] SIMD xor neighbourhood (mask @ 0x%lX):\n", mask_va);
            for (int delta : {-32, -16, 16, 32}) {
                uint64_t va = mask_va + static_cast<int64_t>(delta);
                if (va < RDATA_LO || va + 16 > RDATA_HI) continue;
                uint8_t buf[16] = {};
                if (!R.Read(va, buf, 16)) {
                    printf("[probe]   0x%lX  <read fail>\n", va);
                    continue;
                }
                printf("[probe]   0x%lX  "
                       "%02X %02X %02X %02X %02X %02X %02X %02X "
                       "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                       va,
                       buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                       buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
            }
        }
    }

    // ──────────────── Report: FNamePool keystream table ───────────────────
    std::sort(keystream_hits.begin(), keystream_hits.end());
    keystream_hits.erase(std::unique(keystream_hits.begin(), keystream_hits.end()),
                        keystream_hits.end());
    if (keystream_hits.empty()) {
        printf("[probe] FNamePool_Keystream = <none found>\n");
    } else {
        size_t n = std::min<size_t>(8, keystream_hits.size());
        for (size_t i = 0; i < n; ++i) {
            printf("[probe] FNamePool_Keystream = 0x%lX  (cand %zu/%zu)\n",
                   keystream_hits[i], i + 1, keystream_hits.size());
        }
    }

    // ──────────────── Machine-parsable summary block ──────────────────────
    // Format consumed by the main dumper (shell-exec + regex).
    // Emits best candidate for each global; "0x0" if none found.
    auto best_u64 = [](const std::vector<uint64_t>& v) -> uint64_t {
        return v.empty() ? 0ULL : v.front();
    };
    uint64_t rva_guobj = guobj_hits.empty() ? 0ULL : guobj_hits.front().addr;
    uint64_t rva_fnp   = fnpool_hits.empty() ? 0ULL : fnpool_hits.front().addr;

    printf("[rvas] GObjectArray=0x%lX\n",        rva_guobj);
    printf("[rvas] FNameKeyTbl=0x%lX\n",         best_u64(key_hits));
    printf("[rvas] FNamePool=0x%lX\n",           rva_fnp);
    printf("[rvas] FField_PshufbMask=0x%lX\n",   best_u64(pshufb_hits));
    printf("[rvas] FField_XorConst=0x%lX\n",     best_u64(xor_hits));
    printf("[rvas] FNamePool_Keystream=0x%lX\n", best_u64(keystream_hits));

    return 0;
}
