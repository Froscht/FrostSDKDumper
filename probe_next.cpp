// probe_next.cpp — find UField::Next offset within UFunction
// Strategy: iterate all UClass objects, for each that has a UFunction at +0x110,
// scan all 8-byte slots [0x00..0x200) in that UFunction for a value that:
//   (a) is a valid heap pointer (looks like UFunction memory)
//   (b) itself has vtable == UFUNCTION_VTBL
//   (c) is NOT a pointer back to a module RVA
// Print a histogram of which offsets contained a valid "next UFunction" pointer.
// Also print the first 5 classes that have ≥3 functions so we can see the chain.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <algorithm>
#include <unordered_map>
#include <vector>

// ----------- IOCTL interface (same as main project) --------------------------
#define MEMREADER_IOC_MAGIC  'M'
struct MemReadRequest { uint64_t addr; void* buf; uint64_t size; };
#define MEMREADER_IOC_READ  _IOW(MEMREADER_IOC_MAGIC, 1, struct MemReadRequest)
#define MEMREADER_IOC_SETPID _IOW(MEMREADER_IOC_MAGIC, 2, int)

static int g_fd = -1;

static bool KRead(uint64_t addr, void* buf, size_t sz) {
    if (!addr) return false;
    MemReadRequest req{ addr, buf, sz };
    return ioctl(g_fd, MEMREADER_IOC_READ, &req) == 0;
}
template<typename T> static T R(uint64_t addr, T def = T{}) {
    T v{}; return KRead(addr, &v, sizeof(v)) ? v : def;
}

// ----------- GObjects bootstrap (identical to main) --------------------------
// Module base is stable at 0x140000000
// GObjects is a FUObjectArray — we scan for it via known RVA pattern
static constexpr uint64_t MODULE_BASE     = 0x140000000ULL;
static constexpr uint64_t GOBJECTS_ARRAY_RVA = 0xDBB9380ULL;  // → ptr to 32-byte entry array
static constexpr uint64_t GOBJECTS_COUNT_RVA = 0xDBB9388ULL;  // → uint32 entry count
static constexpr uint64_t UFUNCTION_VTBL  = MODULE_BASE + 0xAB74190ULL;
static constexpr uint64_t UCLASS_VTBL     = MODULE_BASE + 0xAB73C40ULL;

// GObjects structure: arr_ptr @ rva, count @ rva+0x10 (typical layout)
// We just read them directly using the same scan as main.cpp.
// The entry array is: base_ptr + i*8 = FUObjectItem*, deref = UObject*

// ----------- Entry point -----------------------------------------------------
int main(int argc, char** argv) {
    int pid = 0;
    if (argc >= 2) pid = atoi(argv[1]);
    if (!pid) {
        // auto-detect
        FILE* f = popen("pgrep -f PioneerGame", "r");
        if (f) { fscanf(f, "%d", &pid); pclose(f); }
    }
    if (!pid) { fprintf(stderr, "No PID\n"); return 1; }
    printf("PID: %d\n", pid);

    g_fd = open("/dev/memreader", O_RDWR);
    if (g_fd < 0) { perror("open /dev/memreader"); return 1; }
    if (ioctl(g_fd, MEMREADER_IOC_SETPID, &pid) < 0) { perror("SETPID"); return 1; }

    // Read GObjects: 32-byte entry array (March 2026 patch)
    uint64_t gobjects_base = R<uint64_t>(MODULE_BASE + GOBJECTS_ARRAY_RVA);
    uint32_t count32       = R<uint32_t>(MODULE_BASE + GOBJECTS_COUNT_RVA);
    printf("GObjects arr=0x%lX count=%u\n", gobjects_base, count32);
    if (!gobjects_base || count32 < 1000) {
        // fallback: try the entry_arr directly as used recently
        // From session: entry_arr=0x3B0760000, count=264144
        printf("Falling back to known values from last run\n");
        gobjects_base = 0x3B0760000ULL;
        count32 = 264168;
    }

    // histogram: offset → count of times that slot held a valid next UFunction
    std::unordered_map<int, int> hist;
    // for each offset also track: when did we first see a chain of 3+
    struct ChainInfo { uint64_t cls_addr; int chain_len; int next_off; };
    std::vector<ChainInfo> chains;

    int checked = 0;
    int uclass_found = 0;

    for (uint32_t i = 0; i < count32 && checked < 600000; ++i) {
        // Entry is 32 bytes; obj ptr is at offset +8 within entry
        uint64_t entry_ptr = R<uint64_t>(gobjects_base + (uint64_t)i * 32 + 8);
        if (!entry_ptr) continue;
        uint64_t vtbl = R<uint64_t>(entry_ptr);
        if (vtbl != UCLASS_VTBL) continue;
        ++uclass_found;

        // Read Children @ +0x110
        uint64_t first_func = R<uint64_t>(entry_ptr + 0x110);
        if (!first_func) continue;
        // Verify it's a UFunction
        if (R<uint64_t>(first_func) != UFUNCTION_VTBL) continue;
        ++checked;

        // Scan all 8-byte slots in [0x28..0x200) of first_func
        // looking for a slot that holds another valid UFunction pointer
        for (int off = 0x28; off < 0x200; off += 8) {
            uint64_t candidate = R<uint64_t>(first_func + off);
            if (!candidate) continue;
            // must not be a module pointer
            if (candidate >= MODULE_BASE && candidate < MODULE_BASE + 0x10000000ULL) continue;
            // check vtable of candidate
            uint64_t cand_vtbl = R<uint64_t>(candidate);
            if (cand_vtbl == UFUNCTION_VTBL) {
                hist[off]++;
                // try chain depth from this offset
                if (hist[off] == 5) {
                    // Record a chain example
                    int depth = 0;
                    uint64_t cur = first_func;
                    while (cur && depth < 200) {
                        uint64_t nxt = R<uint64_t>(cur + off);
                        if (!nxt || R<uint64_t>(nxt) != UFUNCTION_VTBL) break;
                        cur = nxt;
                        ++depth;
                    }
                    if (depth >= 2)
                        chains.push_back({entry_ptr, depth+1, off});
                }
            }
        }

        if (uclass_found >= 3000) break;
    }

    printf("Scanned %d UClass with first-child UFunction\n", checked);
    printf("\nHistogram (offset → times slot held next UFunction):\n");
    // sort and print top hits
    std::vector<std::pair<int,int>> sorted(hist.begin(), hist.end());
    std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b){ return a.second > b.second; });
    for (auto& [off, cnt] : sorted) {
        printf("  +0x%03X : %d classes\n", off, cnt);
        if (cnt < 5) break;
    }

    printf("\nChain examples (chain_len >= 3):\n");
    for (auto& c : chains) {
        printf("  UClass=0x%lX  NextOff=+0x%03X  chain=%d\n", c.cls_addr, c.next_off, c.chain_len);
        if ((&c - &chains[0]) > 5) break;
    }

    close(g_fd);
    return 0;
}
