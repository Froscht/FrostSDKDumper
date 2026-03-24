// probe_subprop.cpp — find real FArrayProperty::Inner and FMapProperty::Key/Value offsets
// Uses process_vm_readv (no kernel module needed) — run with sudo
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <unordered_map>
#include <vector>
#include <sys/uio.h>
#include <stdint.h>

static int g_pid = 0;

static bool R(uint64_t addr, void* buf, size_t sz) {
    if (!addr) return false;
    struct iovec l = { buf, sz };
    struct iovec r = { (void*)addr, sz };
    return process_vm_readv(g_pid, &l, 1, &r, 1, 0) == (ssize_t)sz;
}
template<typename T> static T Rd(uint64_t a, T def = T{}) {
    T v{}; return R(a, &v, sizeof(v)) ? v : def;
}

static constexpr uint64_t MODULE_BASE = 0x140000000ULL;
// Known vtable RVAs
static constexpr uint64_t UCLASS_VTBL     = MODULE_BASE + 0xAB73C40ULL;
static constexpr uint64_t USSTRUCT_VTBL   = MODULE_BASE + 0xAB73370ULL;
static constexpr uint64_t UFUNCTION_VTBL  = MODULE_BASE + 0xAB74190ULL;
// Property vtable RVAs
static constexpr uint64_t VTBL_ARRAY  = MODULE_BASE + 0xAB928B0ULL;
static constexpr uint64_t VTBL_MAP    = MODULE_BASE + 0xABA9210ULL;
static constexpr uint64_t VTBL_STRUCT = MODULE_BASE + 0xAB9BAE0ULL;
static constexpr uint64_t VTBL_OBJECT = MODULE_BASE + 0xAB9B260ULL; // typical FObjectProperty vtable
// All known FProperty vtables (for "is this a valid FProperty?" check)
static const uint64_t PROP_VTBLS[] = {
    MODULE_BASE + 0xAB994A0ULL,  // FDoubleProperty
    MODULE_BASE + 0xAB99290ULL,  // FFloatProperty
    MODULE_BASE + 0xAB98840ULL,  // FIntProperty
    MODULE_BASE + 0xAB9BAE0ULL,  // FStructProperty
    MODULE_BASE + 0xAB92F30ULL,  // FBoolProperty
    MODULE_BASE + 0xAB97F50ULL,  // FNameProperty
    MODULE_BASE + 0xAB931E0ULL,  // FByteProperty
    MODULE_BASE + 0xAB76AD0ULL,  // FEnumProperty
    MODULE_BASE + 0xABA9210ULL,  // FMapProperty
    MODULE_BASE + 0xAB928B0ULL,  // FArrayProperty
    MODULE_BASE + 0xAB9B260ULL,  // FObjectProperty (approx)
    MODULE_BASE + 0xAB9B5D0ULL,  // FWeakObjectProperty (approx)
    MODULE_BASE + 0xAB9B960ULL,  // FSoftObjectProperty (approx)
    MODULE_BASE + 0xAB98480ULL,  // FInt8Property
    MODULE_BASE + 0xAB98630ULL,  // FInt16Property
    MODULE_BASE + 0xAB98A50ULL,  // FUInt32/Int64Property
    MODULE_BASE + 0xAB98C60ULL,
    MODULE_BASE + 0xAB98E70ULL,
    MODULE_BASE + 0xAB99090ULL,
    MODULE_BASE + 0xAB99CA0ULL,  // FStrProperty
    MODULE_BASE + 0xAB9A680ULL,  // FTextProperty
    MODULE_BASE + 0xAB9A890ULL,  // FSoftClassProperty
};
static bool IsPropVtbl(uint64_t v) {
    for (auto x : PROP_VTBLS) if (x == v) return true;
    // Also accept any vtable in module range with heuristic: in .rdata section
    if (v >= MODULE_BASE + 0xAB00000ULL && v < MODULE_BASE + 0xAC00000ULL) return true;
    return false;
}
static bool IsUStructPtr(uint64_t v) {
    if (!v || (v & 7)) return false;
    uint64_t vtbl = Rd<uint64_t>(v);
    return (vtbl == UCLASS_VTBL || vtbl == USSTRUCT_VTBL);
}

int main(int argc, char** argv) {
    g_pid = argc >= 2 ? atoi(argv[1]) : 0;
    if (!g_pid) {
        FILE* f = popen("pgrep -a PioneerGame | head -1 | awk '{print $1}'", "r");
        if (f) { fscanf(f, "%d", &g_pid); pclose(f); }
    }
    if (!g_pid) { fprintf(stderr, "No PID\n"); return 1; }
    printf("PID: %d\n", g_pid);

    // Read GObjects (March 2026 patch RVAs – matches gobjects.h / Findings.md)
    uint64_t entry_arr = Rd<uint64_t>(MODULE_BASE + 0xDBB9380ULL);
    uint32_t count     = Rd<uint32_t>(MODULE_BASE + 0xDBB9388ULL);
    printf("GObjects arr=0x%lX count=%u\n", entry_arr, count);
    if (!entry_arr || count < 1000) { fprintf(stderr, "Bad GObjects\n"); return 1; }

    // Histogram: for each property class, offset → count of valid sub-ptr
    std::unordered_map<int, int> arr_hist;   // FArrayProperty::Inner candidates
    std::unordered_map<int, int> map_hist_k; // FMapProperty::KeyProp candidates
    std::unordered_map<int, int> map_hist_v; // FMapProperty::ValueProp candidates
    std::unordered_map<int, int> str_hist;   // FStructProperty::Struct (UScriptStruct*) candidates

    int arr_found = 0, map_found = 0, str_found = 0;
    int uclass_checked = 0;

    for (uint32_t i = 0; i < count && uclass_checked < 5000; ++i) {
        // Entry is 32 bytes; obj ptr is at offset +8 within entry
        uint64_t obj = Rd<uint64_t>(entry_arr + (uint64_t)i * 32 + 8);
        if (!obj) continue;
        uint64_t vtbl = Rd<uint64_t>(obj);
        if (vtbl != UCLASS_VTBL && vtbl != USSTRUCT_VTBL) continue;
        ++uclass_checked;

        // Walk ChildProperties @ +0xC0 (ArcDecrypt::Offsets::UStruct::ChildProperties)
        uint64_t ff = Rd<uint64_t>(obj + 0xC0);
        int prop_count = 0;
        while (ff && prop_count < 512) {
            uint64_t prop_vtbl = Rd<uint64_t>(ff); // vtable at +0x00
            ++prop_count;

            if (prop_vtbl == VTBL_ARRAY && arr_found < 2000) {
                ++arr_found;
                // Scan 0x70..0x1C0 for a slot holding a valid FProperty ptr
                for (int off = 0x70; off < 0x1C0; off += 8) {
                    uint64_t cand = Rd<uint64_t>(ff + off);
                    if (!cand || (cand & 7)) { off += 0; continue; }
                    uint64_t cv = Rd<uint64_t>(cand);
                    if (IsPropVtbl(cv)) arr_hist[off]++;
                }
            }
            if (prop_vtbl == VTBL_MAP && map_found < 2000) {
                ++map_found;
                for (int off = 0x70; off < 0x200; off += 8) {
                    uint64_t cand = Rd<uint64_t>(ff + off);
                    if (!cand || (cand & 7)) continue;
                    uint64_t cv = Rd<uint64_t>(cand);
                    if (IsPropVtbl(cv)) {
                        map_hist_k[off]++;  // first candidate logged as key
                        // check if the slot AFTER it is also a property ptr
                        uint64_t cand2 = Rd<uint64_t>(ff + off + 8);
                        if (cand2 && !(cand2 & 7)) {
                            uint64_t cv2 = Rd<uint64_t>(cand2);
                            if (IsPropVtbl(cv2)) map_hist_v[off]++;
                        }
                    }
                }
            }
            if (prop_vtbl == VTBL_STRUCT && str_found < 2000) {
                ++str_found;
                for (int off = 0x70; off < 0x200; off += 8) {
                    uint64_t cand = Rd<uint64_t>(ff + off);
                    if (!cand || (cand & 7)) continue;
                    if (IsUStructPtr(cand)) str_hist[off]++;
                }
            }

            ff = Rd<uint64_t>(ff + 0x58); // FField::Next (ArcDecrypt::Offsets::FField::Next)
        }
    }

    printf("\nScanned %d UClass/UScriptStruct, found %d FArrayProperty, %d FMapProperty, %d FStructProperty\n",
           uclass_checked, arr_found, map_found, str_found);

    auto print_hist = [](const char* label, std::unordered_map<int,int>& h, int sample_count) {
        std::vector<std::pair<int,int>> sv(h.begin(), h.end());
        std::sort(sv.begin(), sv.end(), [](auto& a, auto& b){ return a.second > b.second; });
        printf("\n%s (sample=%d):\n", label, sample_count);
        for (int i = 0; i < (int)sv.size() && i < 8; ++i)
            printf("  +0x%03X : %d hits (%.0f%%)\n", sv[i].first, sv[i].second,
                   100.0 * sv[i].second / (sample_count > 0 ? sample_count : 1));
    };

    print_hist("FArrayProperty::Inner candidates", arr_hist, arr_found);
    print_hist("FMapProperty::KeyProp candidates (key offset)", map_hist_k, map_found);
    print_hist("FMapProperty::ValueProp candidates (key+8 also valid)", map_hist_v, map_found);
    print_hist("FStructProperty::Struct (UScriptStruct*) candidates", str_hist, str_found);

    return 0;
}
