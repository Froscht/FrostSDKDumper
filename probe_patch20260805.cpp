// probe_patch20260805 — standalone validation harness for the 2026-08 ARC patch
// (image size 0x11853000).
//
// Mirrors ArcDecrypt::v20260805 with zero dependencies on the rest of the
// dumper, so it still answers "are these constants right?" when an earlier
// discovery phase in FrostDumper crashes or bails first. Uses process_vm_readv
// only — the .data/heap pages it touches do not need the kernel module.
//
//   build: g++ -std=c++17 -O2 -o probe_patch20260805 probe_patch20260805.cpp
//   run:   sudo ./probe_patch20260805 $(pgrep -f PioneerGame.exe | head -1)
//
// Expected on a healthy patch: section 2 prints readable engine names
// (None, ByteProperty, IntProperty, ...) and section 3 prints an off-image
// heap FCA pointer with NumElements in the 200k-900k range.
// Verifies the statically-recovered FName + FField + GObjectArray constants
// against the live process. Read-only, single process, no kernel module needed
// for .data pages.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <sys/uio.h>
#include <string>
#include <vector>

static pid_t g_pid;
static bool R(uint64_t a, void* o, size_t n) {
    iovec l{o, n}, r{(void*)a, n};
    return process_vm_readv(g_pid, &l, 1, &r, 1, 0) == (ssize_t)n;
}
template <class T> static T Rd(uint64_t a, bool* ok = nullptr) {
    T v{}; bool k = R(a, &v, sizeof(T)); if (ok) *ok = k; return v;
}
static uint64_t rol64(uint64_t v, int n) { return n ? ((v << n) | (v >> (64 - n))) : v; }
static uint32_t rol32(uint32_t v, int n) { return n ? ((v << n) | (v >> (32 - n))) : v; }
// PSHUFLW on the low qword: out word i = in word ((imm >> 2i) & 3)
static uint64_t pshuflw(uint64_t v, uint8_t imm) {
    uint16_t w[4], o[4];
    std::memcpy(w, &v, 8);
    for (int i = 0; i < 4; ++i) o[i] = w[(imm >> (2 * i)) & 3];
    uint64_t r; std::memcpy(&r, o, 8); return r;
}

static constexpr uint64_t BASE = 0x140000000ULL;

// ── FName pipeline (RVA 0x2319F0 / 0x23AAE0), verified by disassembly ──
static constexpr uint64_t POOL_RVA       = 0xE431980;
static constexpr uint32_t SHARD_SEED_OFF = 0x4C90;
static constexpr uint32_t BLOCK_BASE_OFF = 0x4CA0;
static constexpr uint32_t P32            = 0x01000193;
static constexpr uint32_t SHARD_ADD      = 0x46BD406E;
static constexpr uint64_t BLOCK_XOR      = 0x07C3784BD4ECB382ULL;
static constexpr uint64_t P64            = 0x100000001B3ULL;
static constexpr uint64_t FNV_ADD        = 0xBB3A9A3B042493AEULL;
static constexpr uint64_t KS_RVA         = 0xE37084C;

static uint64_t ResolveEntry(uint32_t ci) {
    uint32_t nameOff  = ci & 0xFFFF;
    uint32_t chunkOff = (ci >> 8) & 0xFFFF00;
    uint64_t chunkVA  = BASE + POOL_RVA + chunkOff;

    uint64_t seedAddr = chunkVA + SHARD_SEED_OFF;
    uint32_t lo = (uint32_t)seedAddr, hi = (uint32_t)(seedAddr >> 32);
    uint32_t H = (lo >> 4) * P32 + SHARD_ADD;
    H = (H >> 3) * P32;
    H = ((H + hi + SHARD_ADD) >> 4) * P32 + SHARD_ADD;
    H = (H >> 3) * P32 + SHARD_ADD;
    uint32_t T = H ^ (H >> 16);
    uint32_t b1 = T & 7, b2 = (T + 1) & 7;

    bool ok1, ok2;
    uint64_t raw1 = Rd<uint64_t>(chunkVA + BLOCK_BASE_OFF + b1 * 32, &ok1);
    uint64_t raw2 = Rd<uint64_t>(chunkVA + BLOCK_BASE_OFF + b2 * 32, &ok2);
    if (!ok1 || !ok2) return 0;

    uint64_t d1 = pshuflw(raw1, 0x93) ^ BLOCK_XOR;
    uint64_t d2 = pshuflw(raw2, 0x93) ^ BLOCK_XOR;
    uint64_t V13 = rol64(d1, 15), V15 = rol64(d2, 15);

    uint64_t Fv = P64 * rol64(d1, 55) + FNV_ADD;
    Fv = P64 * rol64(Fv, 57) + FNV_ADD;
    // pointer XOR chain across the 3 frames is algebraically identity
    return V13 + (V15 ^ Fv) + 2ULL * nameOff;
}

static bool GetName(uint32_t ci, std::string& out) {
    uint64_t ep = ResolveEntry(ci);
    if (!ep) return false;
    bool ok;
    uint16_t hdr = Rd<uint16_t>(ep, &ok);
    if (!ok) return false;
    int  len    = (hdr >> 5) & 0x3FF;
    bool isWide = (hdr & 0x8000) != 0;
    if (len <= 0 || len > 512) return false;

    static uint16_t KS[64];
    static bool ksLoaded = false;
    if (!ksLoaded) { if (!R(BASE + KS_RVA, KS, sizeof(KS))) return false; ksLoaded = true; }

    std::vector<uint8_t> buf(len * (isWide ? 2 : 1));
    if (!R(ep + 2, buf.data(), buf.size())) return false;

    uint32_t key = (uint32_t)len + 0x6C22;
    int n = len & ~1;
    for (int i = 0; i < n; i += 2) {
        if (!isWide) {
            buf[i]     ^= (uint8_t)(KS[key & 0x3F] >> 3);
            buf[i + 1] ^= (uint8_t)(KS[(key + 0x0B) & 0x3F] >> 3);
        } else {
            ((uint16_t*)buf.data())[i]     ^= KS[key & 0x3F];
            ((uint16_t*)buf.data())[i + 1] ^= KS[(key + 0x0B) & 0x3F];
        }
        key += 0x716;
    }
    if (len & 1) {
        if (!isWide) buf[n] ^= (uint8_t)(KS[key & 0x3F] >> 3);
        else ((uint16_t*)buf.data())[n] ^= KS[key & 0x3F];
    }
    out.clear();
    for (int i = 0; i < len; ++i)
        out += isWide ? (char)((uint16_t*)buf.data())[i] : (char)buf[i];
    return true;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: probe_patch <pid>\n"); return 1; }
    g_pid = atoi(argv[1]);

    std::printf("=== 1. FName pool sanity ===\n");
    bool ok;
    uint64_t poolHead = Rd<uint64_t>(BASE + POOL_RVA, &ok);
    std::printf("pool@0x%llX readable=%d head=0x%llX  initflag=%d\n",
        (unsigned long long)(BASE + POOL_RVA), ok, (unsigned long long)poolHead,
        (int)Rd<uint8_t>(BASE + 0xE431978));

    std::printf("\n=== 2. FName resolve over low CompIndexes ===\n");
    int good = 0, tried = 0;
    for (uint32_t ci = 1; ci <= 60; ++ci) {
        std::string s;
        ++tried;
        if (GetName(ci, s) && !s.empty()) {
            bool printable = true;
            for (char c : s) if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) printable = false;
            if (printable) { ++good; std::printf("  CI %-4u -> \"%s\"\n", ci, s.c_str()); }
        }
    }
    std::printf("  readable names: %d / %d\n", good, tried);

    std::printf("\n=== 3. GUObjectArray (encrypted FCA ptr @ 0xE6ED2A0) ===\n");
    uint64_t encLo = Rd<uint64_t>(BASE + 0xE6ED2A0, &ok);
    uint64_t pxorK = Rd<uint64_t>(BASE + 0xB48A020);
    std::printf("  enc=0x%llX (ok=%d)  xorkey=0x%llX\n",
        (unsigned long long)encLo, ok, (unsigned long long)pxorK);
    uint64_t fca = pshuflw(rol64(encLo ^ pxorK, 38), 0x39);
    std::printf("  FCA ptr = 0x%llX\n", (unsigned long long)fca);
    if (fca > 0x10000 && fca < 0x800000000000ULL) {
        uint64_t rawN = Rd<uint64_t>(fca + 0x70, &ok);
        uint32_t nxor = Rd<uint32_t>(BASE + 0xB4DD440);
        uint32_t numEl = (uint32_t)pshuflw(rol64(rawN, 13), 0xE3) ^ nxor;
        std::printf("  raw@+0x70=0x%llX (ok=%d) nxor=0x%X -> NumElements=%u\n",
            (unsigned long long)rawN, ok, nxor, numEl);
        std::printf("  vtobj@+0xA0=0x%llX  blob@+0xD0=0x%llX\n",
            (unsigned long long)Rd<uint64_t>(fca + 0xA0),
            (unsigned long long)Rd<uint64_t>(fca + 0xD0));
    }
    return 0;
}
