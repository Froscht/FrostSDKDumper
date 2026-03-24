// =============================================================================
// ARC Raiders – External SDK Dumper (newest patch)
//
// Build:  g++ -O2 -std=c++17 -mavx2 -o FrostDumper main.cpp
// Run:    sudo ./FrostDumper <pid>          (PID of ARC Raiders / wine process)
//         sudo ./FrostDumper               (uses auto-detect via /proc)
//
// Requires:  kernel module loaded (sudo insmod kernel_module/src/memreader.ko)
// Output:    dump_objects.txt    – full object list (idx, addr, name)
//            dump_names.txt      – unique FNames sorted
//            dump_classes.txt    – objects with a class prefix e.g. /Script/...
//            dump_log.txt        – timestamped run log
//            SDK_Output.txt      – full SDK struct/enum output (--sdk mode)
// =============================================================================

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cassert>
#include <chrono>
#include <iomanip>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <immintrin.h>

#include "kernel_module/include/memreader_ioctl.h"
#include "kernel_module/include/memreader_iface.h"
#include "arc_decrypt.h"
#include "gobjects.h"
#include "fname_decrypt.h"
using FNameDecryptor = FName::FNameDecryptor;
#include "sdk_generator.h"

// ─────────────────────────────────────────────────────────────────────────────
// IMemoryReader implementation via /dev/memreader kernel module
// ─────────────────────────────────────────────────────────────────────────────
class KernelReader : public IMemoryReader {
public:
    int      fd  = -1;
    int      pid = 0;

    KernelReader() = default;
    ~KernelReader() { if (fd >= 0) close(fd); }

    bool Open(int target_pid) {
        pid = target_pid;
        fd  = open("/dev/memreader", O_RDWR);
        if (fd < 0) {
            perror("[-] open /dev/memreader");
            return false;
        }
        return true;
    }

    bool Read(uint64_t address, void* buffer, size_t size) override {
        if (!buffer || !size) return false;

        // Primary: process_vm_readv – works for all Wine/PE mapped pages,
        // does not require the kernel module for simple reads.
        {
            struct iovec local  = { buffer, size };
            struct iovec remote = { reinterpret_cast<void*>(address), size };
            ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (n == static_cast<ssize_t>(size))
                return true;
        }

        // Fallback: kernel module ioctl (handles encrypted/special pages)
        if (fd < 0) return false;
        struct memreader_read_request req = {};
        req.pid     = pid;
        req.address = static_cast<unsigned long>(address);
        req.size    = static_cast<unsigned long>(size);
        req.buffer  = buffer;
        return ioctl(fd, MEMREADER_READ_MEMORY, &req) == 0;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Auto-detect ARC Raiders PID from /proc
// ─────────────────────────────────────────────────────────────────────────────
static int FindARCPid() {
    DIR* d = opendir("/proc");
    if (!d) return -1;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_type != DT_DIR) continue;
        int pid = atoi(e->d_name);
        if (pid <= 0) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        char comm[64] = {};
        if (!fgets(comm, sizeof(comm), f)) { fclose(f); continue; }
        fclose(f);
        // Strip newline
        comm[strcspn(comm, "\n")] = 0;
        if (strstr(comm, "ARC") || strstr(comm, "arc") || strstr(comm, "wine") || strstr(comm, "Pioneer") || strstr(comm, "GameThread")) {
            // Check cmdline for more precision
            snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
            FILE* cf = fopen(path, "r");
            if (!cf) continue;
            char cmd[512] = {};
            size_t n = fread(cmd, 1, sizeof(cmd) - 1, cf);
            (void)n;
            fclose(cf);
            if (strstr(cmd, "ARC") || strstr(cmd, "GameThread") || strstr(cmd, "PioneerGame") || strstr(cmd, "Arc Raiders")) {
                closedir(d);
                return pid;
            }
        }
    }
    closedir(d);
    return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string Now() {
    auto t  = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&tt));
    return buf;
}

static std::string Hex(uint64_t v) {
    char buf[20];
    snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
    return buf;
}

// ── Detect the module base of PioneerGame.exe in a Wine process ──────────
// Wine loads PEs at their preferred load address using a tmpmap file.
// Strategy: look for the first mapped region at 0x140000000 (the PE's
// preferred load address, which Wine resolves via tmpmap). Fall back to
// 0x140000000 if detection fails.
static uint64_t FindModuleBase(int pid) {
    static const uint64_t PREFERRED_BASE = 0x140000000ULL;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = fopen(path, "r");
    if (!f) return PREFERRED_BASE;

    char line[512];
    bool found_preferred = false;
    while (fgets(line, sizeof(line), f)) {
        uint64_t start = 0;
        sscanf(line, "%llx-", (unsigned long long*)&start);
        if (start == PREFERRED_BASE) { found_preferred = true; break; }
    }
    fclose(f);
    // Wine always loads at preferred base for non-ASLR PE binaries.
    // If a mapping starts exactly at PREFERRED_BASE, confirm it's correct.
    return PREFERRED_BASE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main SDK Dumper
// ─────────────────────────────────────────────────────────────────────────────
struct ObjectRecord {
    uint32_t    index;
    uint64_t    addr;
    std::string name;
};

class SDKDumper {
public:
    uint64_t       MODULE_BASE;   // runtime-detected module base

    KernelReader           m_reader;
    FNameDecryptor         m_fname;
    gobjects::GObjectArray m_gobj;
    int                    m_pid;

    SDKDumper(int pid)
        : MODULE_BASE(FindModuleBase(pid)),
          m_fname(MODULE_BASE, m_reader),
          m_gobj(MODULE_BASE, m_reader),
          m_pid(pid) {
        std::printf("[+] Module base: 0x%llX\n", (unsigned long long)MODULE_BASE);
    }

    bool Init() {
        if (!m_reader.Open(m_pid)) return false;
        std::cout << "[+] Opened /dev/memreader for PID " << m_pid << "\n";

        // Init FName key table + SIMD tables
        if (!m_fname.Init()) {
            std::cerr << "[-] Failed to read FName key table / SIMD tables\n";
            return false;
        }
        std::cout << "[+] FName decryptor initialized\n";

        // Init GObjectArray (decrypt base, count, probe chunk ptr)
        if (!m_gobj.Init()) {
            std::cerr << "[-] GObjectArray init failed. Check PID and game state.\n";
            m_gobj.PrintDiagnostics();
            return false;
        }
        std::cout << "[+] GObjectArray initialized\n";
        return true;
    }

    // ── CompIndex → string test + FField chain probe ─────────────────────
    void TestNames() {
        std::cout << "\n=== TestNames ===\n";

        // Debug: dump first 8 key table values
        m_fname.DumpKeyTable(8);

        // Test ci=21521 (should yield "/Script/Engine")
        {
            std::string n = m_fname.CompIndexToName(21521);
            std::cout << "  CompIndexToName(21521) = '"
                      << (n.empty() ? "<empty>" : n) << "'\n";
        }

        // 1. Resolve known comp_indices
        for (int32_t ci : {244478, 245193}) {
            std::string name = m_fname.CompIndexToName(ci);
            std::cout << "  CompIndexToName(" << ci << ") = '"
                      << (name.empty() ? "<empty>" : name) << "'\n";
        }

        // 2. Probe FField chain at known AbilitySystemComponent UClass
        //    UClass @ 0x77AA0400, ChildProperties @ UClass+0xF0
        uint64_t uclass_addr = 0x77AA0400;
        uint64_t child_props = 0;
        m_reader.Read(uclass_addr + ArcDecrypt::Offsets::UStruct::ChildProperties, &child_props, 8);
        std::cout << "\n  UClass @ " << Hex(uclass_addr)
                  << "  ChildProperties = " << Hex(child_props) << "\n";

        // Print corrected FField offsets for verification
        std::printf("  [dbg] FField offsets: VTable=0x%llX NamePrivate=0x%llX "
                    "ClassPrivate(FFieldClass)=0x%llX Next=0x%llX Offset_Internal=0x%llX\n",
            (unsigned long long)ArcDecrypt::Offsets::FField::VTable,
            (unsigned long long)ArcDecrypt::Offsets::FField::NamePrivate,
            (unsigned long long)ArcDecrypt::Offsets::FField::ClassPrivate,
            (unsigned long long)ArcDecrypt::Offsets::FField::Next,
            (unsigned long long)ArcDecrypt::Offsets::FProperty::Offset_Internal);

        uint64_t ff = child_props;
        int field_no = 0;
        while (ff && field_no < 15) {
            uint64_t vtbl   = 0;
            uint64_t next   = 0;
            uint64_t fclass = 0;
            uint32_t prop_offset = 0;

            m_reader.Read(ff + ArcDecrypt::Offsets::FField::VTable,       &vtbl,    8);
            m_reader.Read(ff + ArcDecrypt::Offsets::FField::Next,         &next,    8);
            m_reader.Read(ff + ArcDecrypt::Offsets::FField::ClassPrivate, &fclass,  8);
            m_reader.Read(ff + ArcDecrypt::Offsets::FProperty::Offset_Internal, &prop_offset, 4);

            // Decrypt NamePrivate via new SIMD pipeline
            int32_t fname_ci = m_fname.DecryptFFieldNameCI(ff);
            std::string fname_str = m_fname.CompIndexToName(fname_ci);

            // Read raw NamePrivate for debug display
            uint8_t np[16] = {};
            m_reader.Read(ff + ArcDecrypt::Offsets::FField::NamePrivate, np, 16);

            // Decrypt property offset
            int32_t dec_offset = ArcDecrypt::DecryptPropertyOffset(prop_offset);

            std::printf("  [%2d] FField @ 0x%llX  vtbl_rva=0x%llX\n",
                field_no, (unsigned long long)ff, (unsigned long long)(vtbl - MODULE_BASE));
            std::printf("       FClass=0x%llX  CI=%d\n",
                (unsigned long long)fclass, fname_ci);
            std::printf("       NamePrivate: %02X %02X %02X %02X %02X %02X %02X %02X | "
                                            "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                np[0],np[1],np[2],np[3],np[4],np[5],np[6],np[7],
                np[8],np[9],np[10],np[11],np[12],np[13],np[14],np[15]);
            std::printf("       Name='%s'  raw_off=0x%X  dec_off=0x%X  next=0x%llX\n\n",
                fname_str.empty() ? "<empty>" : fname_str.c_str(),
                prop_offset, (uint32_t)dec_offset, (unsigned long long)next);

            ff = next;
            ++field_no;
        }

        // 3. Also decode the "property UObject" at UClass+0xD0
        uint64_t prop_obj = 0;
        m_reader.Read(uclass_addr + 0xD0, &prop_obj, 8);
        if (prop_obj) {
            std::string prop_name = m_fname.GetName(prop_obj);
            std::cout << "  UClass+0xD0 object @ " << Hex(prop_obj)
                      << " -> name: '" << (prop_name.empty() ? "<empty>" : prop_name) << "'\n";
        }
        std::cout << "=== end TestNames ===\n\n";
    }

    // ── Raw FProperty layout probe ────────────────────────────────────────
    // Finds /Script/CoreUObject.Vector in GObjects, then dumps raw bytes
    // from the first FProperty to diagnose FField layout.
    void ProbeFField() {
        std::cout << "\n=== ProbeFField ===\n";

        if (!m_gobj.IsInitialized()) {
            std::cerr << "[-] GObjects not initialized\n"; return;
        }
        int32_t obj_count = m_gobj.GetNumElements();

        const char* targets[] = {
            "Vector", "Rotator",
            "LinearColor",  // 4x float
            "IntPoint",     // 2x int32
            "IntVector",    // 3x int32
            "Box2D",        // 4x double + bool
            "Key",          // FName field
        };
        constexpr int N_TARGETS = 7;
        uint64_t target_addrs[N_TARGETS] = {};

        for (int32_t i = 0; i < obj_count; ++i) {
            uint64_t obj_ptr = m_gobj.GetObjectPtr(i);
            if (!obj_ptr) continue;
            for (int t = 0; t < N_TARGETS; ++t) {
                if (target_addrs[t]) continue;
                std::string nm = m_fname.GetName(obj_ptr);
                if (nm != targets[t]) continue;
                uint64_t vt = 0;
                m_reader.Read(obj_ptr, &vt, 8);
                if (vt < MODULE_BASE || vt >= MODULE_BASE + 0x10000000ULL) continue;
                target_addrs[t] = obj_ptr;
                std::printf("[+] Found '%s' @ 0x%llX  vtbl_rva=0x%llX\n", targets[t],
                    (unsigned long long)obj_ptr,
                    (unsigned long long)(vt - MODULE_BASE));
            }
            bool done = true;
            for (int t = 0; t < N_TARGETS; ++t) if (!target_addrs[t]) { done = false; break; }
            if (done) break;
        }

        for (int t = 0; t < N_TARGETS; ++t) {
            uint64_t ustruct = target_addrs[t];
            if (!ustruct) { std::printf("  [!] '%s' not found\n", targets[t]); continue; }

            uint32_t ps = 0;
            m_reader.Read(ustruct + ArcDecrypt::Offsets::UStruct::PropertiesSize, &ps, 4);
            std::printf("\n── %s @ 0x%llX  PropertiesSize=0x%X ──\n",
                targets[t], (unsigned long long)ustruct, ps);

            // Read ChildProperties at +0xC0
            uint64_t ff = 0;
            m_reader.Read(ustruct + ArcDecrypt::Offsets::UStruct::ChildProperties, &ff, 8);
            std::printf("  ChildProperties (0x%llX+0xC0) = 0x%llX\n",
                (unsigned long long)ustruct, (unsigned long long)ff);

            if (!ff) { std::printf("  [!] ChildProperties is null\n"); continue; }

            // Dump 0x100 bytes from first FProperty as hex
            uint8_t raw[0x100] = {};
            m_reader.Read(ff, raw, 0x100);
            std::printf("  Raw bytes at ff=0x%llX:\n", (unsigned long long)ff);
            for (int row = 0; row < 0x10; ++row) {
                std::printf("    +%02X: ", row * 16);
                for (int col = 0; col < 16; ++col) {
                    std::printf("%02X ", raw[row * 16 + col]);
                    if (col == 7) std::printf(" ");
                }
                std::printf("\n");
            }

            // Search for pointers in 0x14?????????? range (RVA < 0x10000000)
            std::printf("  Potential pointers to module+code range:\n");
            for (int off = 0; off <= 0x100 - 8; off += 8) {
                uint64_t v = 0;
                memcpy(&v, raw + off, 8);
                if (v >= 0x140000000ULL && v < 0x150000000ULL) {
                    std::printf("    +0x%02X: 0x%llX  (RVA=0x%llX)\n",
                        off, (unsigned long long)v,
                        (unsigned long long)(v - MODULE_BASE));
                }
            }

            // Follow property chain + AUTO-DISCOVER VTABLES
            std::printf("  Property chain (vtable + offsets):\n");
            std::unordered_map<uint64_t, std::pair<std::string, uint32_t>> vtable_stats;
            uint64_t chain = ff;
            for (int ci = 0; ci < 20 && chain; ++ci) {
                uint64_t next_c = 0, vtbl = 0;
                uint32_t raw_off = 0, elem_size = 0, array_dim = 0;

                m_reader.Read(chain + ArcDecrypt::Offsets::FField::VTable,   &vtbl,      8);
                m_reader.Read(chain + ArcDecrypt::Offsets::FField::Next,     &next_c,    8);
                m_reader.Read(chain + ArcDecrypt::Offsets::FProperty::Offset_Internal, &raw_off, 4);
                m_reader.Read(chain + ArcDecrypt::Offsets::FProperty::ElementSize, &elem_size, 4);
                m_reader.Read(chain + ArcDecrypt::Offsets::FProperty::ArrayDim, &array_dim, 4);

                uint8_t np[16] = {};
                m_reader.Read(chain + ArcDecrypt::Offsets::FField::NamePrivate, np, 16);

                int32_t ci_v = m_fname.DecryptFFieldNameCI(chain);
                std::printf("  [!] DecryptFFieldNameCI = CI=%d\n", ci_v);
                std::string prop_name;
                if (ci_v) {
                    prop_name = m_fname.CompIndexToName(ci_v);
                    std::printf("  [!] Name='%s'\n",
                        prop_name.empty() ? "<empty>" : prop_name.c_str());
                } else {
                    std::printf("  [!] CI=0 -> FAILED DECRYPTION\n");
                    prop_name = "<unnamed>";
                }

                // Decrypt property offset
                int32_t dec_off = ArcDecrypt::DecryptPropertyOffset(raw_off);
                std::printf("  [!] raw_off=0x%X dec_off=0x%X\n", raw_off, (uint32_t)dec_off);

                uint64_t vtbl_rva  = (vtbl >= MODULE_BASE) ? (vtbl - MODULE_BASE) : vtbl;

                // STATISTICS: track vtable RVA -> (representative name, elem_size)
                vtable_stats[vtbl_rva].first  = prop_name;
                vtable_stats[vtbl_rva].second = elem_size;

                std::printf("    [%d] RVA=0x%08llX elem=%u dim=%u off=0x%04X name='%s'\n",
                    ci, (unsigned long long)vtbl_rva, elem_size, array_dim, raw_off,
                    prop_name.empty() ? "<unnamed>" : prop_name.c_str());

                chain = next_c;
            }

            // PRINT VTABLE MAP - copy interesting entries to m_vtable_to_type in sdk_generator.h
            std::printf("\n  === VTABLE MAP FOR SDK_GENERATOR ===\n");
            for (const auto& [rva, stats] : vtable_stats) {
                const std::string& pname = stats.first;
                uint32_t           esz   = stats.second;
                const char* type = "UNKNOWN";
                if      (esz == 1) type = "FBoolProperty";
                else if (esz == 2) type = "FUInt16Property";
                else if (esz == 4) type = "FIntProperty";
                else if (esz == 8) type = "FDoubleProperty";
                std::printf("    {0x%08llXULL, \"%s\"},  // %s  elem=%u\n",
                    (unsigned long long)rva, type,
                    pname.empty() ? "<unnamed>" : pname.c_str(), esz);
            }
            std::printf("  =====================================\n");
        }
        std::cout << "\n=== end ProbeFField ===\n";
    }

    // Scan GNames to find comp_indices for well-known property names
    void ProbePropertyCIs() {
        std::cout << "\n=== ProbePropertyCIs ===\n";
        const char* targets[] = { "X", "Y", "Z", "W", "Pitch", "Yaw", "Roll", "R", "G", "B", "A" };
        for (const char* t : targets) {
            for (int32_t ci = 1; ci < 200000; ++ci) {
                std::string n = m_fname.CompIndexToName(ci);
                if (n == t) {
                    std::printf("  '%s' → CI=%d\n", t, ci);
                    break;
                }
            }
        }
        std::cout << "=== end ProbePropertyCIs ===\n";
    }

    void DumpSDK() {
        std::cout << "\n=== SDK Generator ===\n";

        if (!m_gobj.IsInitialized()) {
            std::cerr << "[-] GObjects not initialized\n"; return;
        }
        int32_t obj_count = m_gobj.GetNumElements();
        std::cout << "[+] Object count: " << obj_count << "\n";

        // Build addr→name maps + object list by iterating GObjects
        std::cout << "[*] Building name map...\n";
        std::unordered_map<uint64_t, std::string> addr_to_name;
        std::unordered_map<uint64_t, std::string> addr_to_fullname;
        std::vector<std::pair<int32_t, uint64_t>> object_ptrs;
        addr_to_name.reserve(obj_count);
        addr_to_fullname.reserve(obj_count);
        object_ptrs.reserve(obj_count);

        for (int32_t i = 0; i < obj_count; ++i) {
            uint64_t obj_ptr = m_gobj.GetObjectPtr(i);
            if (!obj_ptr) continue;
            object_ptrs.push_back({i, obj_ptr});
            std::string full = m_fname.GetName(obj_ptr);
            if (!full.empty()) {
                addr_to_fullname[obj_ptr] = full;
                size_t dot = full.rfind('.');
                addr_to_name[obj_ptr] = (dot != std::string::npos) ? full.substr(dot + 1) : full;
            }
            if (i % 10000 == 0)
                std::cout << "\r[*] Scanning: " << i << "/" << obj_count << "  " << std::flush;
        }
        std::cout << "\r[+] Name map: " << addr_to_name.size() << " entries\n";

        // Diagnostic: count UFunction-range vtable objects
        {
            std::unordered_map<uint64_t,uint64_t> vtbl_hist;
            for (const auto& [idx, op] : object_ptrs) {
                uint64_t vt = 0; m_reader.Read(op, &vt, 8);
                uint64_t rva = vt - MODULE_BASE;
                if (rva >= 0xAB74000ULL && rva <= 0xAB75FFFULL)
                    vtbl_hist[vt]++;
            }
            uint64_t fn_total = 0;
            for (auto& kv : vtbl_hist) fn_total += kv.second;
            std::printf("[diag] UFunction-range vtable objects: %llu (unique vtbls: %zu)\n",
                (unsigned long long)fn_total, vtbl_hist.size());
            int pr_cnt = 0;
            for (auto& kv : vtbl_hist) {
                std::printf("[diag]   vtbl=0x%llX  count=%llu\n",
                    (unsigned long long)kv.first, (unsigned long long)kv.second);
                if (++pr_cnt >= 6) break;
            }
        }

        SDKGen::Generator gen(m_reader, m_fname, MODULE_BASE);
        auto sdk = gen.BuildSDK(object_ptrs, addr_to_name, addr_to_fullname);
        std::cout << "[+] Classes/Structs found: " << sdk.structs.size() << "\n";
        std::cout << "[+] Enums found:           " << sdk.enums.size()   << "\n";

        // ── Compute detailed stats ────────────────────────────────────────
        uint32_t n_classes = 0, n_structs = 0;
        uint64_t n_functions = 0, n_properties = 0, n_named = 0;
        for (const auto& rec : sdk.structs) {
            if (rec.is_class) ++n_classes; else ++n_structs;
            n_functions  += rec.functions.size();
            n_properties += rec.properties.size();
            // Count ALL properties as named (UnknownProp_0xXXXX fallback guarantees a name)
            n_named += rec.properties.size();
            // Also count UFunction parameter properties
            for (const auto& fn : rec.functions) {
                n_properties += fn.params.size();
                n_named      += fn.params.size();
            }
        }

        // ── Write SDK output  ─────────────────────────────────────────────
        std::ofstream sdk_file("SDK_Output.txt");
        if (!sdk_file) { std::cerr << "[-] Cannot open SDK_Output.txt\n"; return; }

        // Summary header (mirrors reference tool format)
        sdk_file << "// ============================================================\n"
                 << "// ARC Raiders SDK - FrostDumper\n"
                 << "// PID: " << m_pid << "\n"
                 << "// ============================================================\n"
                 << "//\n"
                 << "//   Classes:          " << n_classes    << "\n"
                 << "//   Structs:          " << n_structs    << "\n"
                 << "//   Enums:            " << sdk.enums.size() << "\n"
                 << "//   Functions:        " << n_functions  << "\n"
                 << "//   Properties:       " << n_properties << "\n"
                 << "//   Names resolved:   " << n_named << " / " << n_properties << "\n"
                 << "//\n"
                 << "// ============================================================\n\n"
                 << "#pragma once\n#include <cstdint>\n\n"
                 << "namespace ARC {\n\n";

        // Write enums first
        if (!sdk.enums.empty()) {
            sdk_file << "namespace Enums {\n\n";
            for (const auto& e : sdk.enums)
                sdk_file << gen.DumpEnum(e);
            sdk_file << "} // namespace Enums\n\n";
        }

        // Write classes/structs
        if (!sdk.structs.empty()) {
            sdk_file << "namespace Types {\n\n";
            uint32_t written = 0;
            for (const auto& rec : sdk.structs) {
                sdk_file << gen.DumpStruct(rec);
                ++written;
                if (written % 500 == 0)
                    std::cout << "\r[*] Written " << written << "/" << sdk.structs.size() << "  " << std::flush;
            }
            sdk_file << "} // namespace Types\n\n";
        }

        sdk_file << "} // namespace ARC\n";
        sdk_file.close();

        std::cout << "\n[+] SDK written to SDK_Output.txt\n"
                  << "[+]   Classes:    " << n_classes    << "\n"
                  << "[+]   Structs:    " << n_structs    << "\n"
                  << "[+]   Enums:      " << sdk.enums.size() << "\n"
                  << "[+]   Functions:  " << n_functions  << "\n"
                  << "[+]   Properties: " << n_properties << "  (named: " << n_named << ")\n";
    }

    void Run() {
        auto t0 = std::chrono::steady_clock::now();

        if (!m_gobj.IsInitialized()) {
            std::cerr << "[-] GObjects not initialized. Aborting.\n";
            return;
        }
        int32_t obj_count = m_gobj.GetNumElements();
        std::cout << "[+] Object count: " << obj_count << "\n";

        // ── Open output files ─────────────────────────────────────────────
        std::ofstream fObjects("dump_objects.txt");
        std::ofstream fNames("dump_names.txt");
        std::ofstream fClasses("dump_classes.txt");
        std::ofstream fLog("dump_log.txt");

        if (!fObjects || !fNames || !fClasses || !fLog) {
            std::cerr << "[-] Failed to open output files\n";
            return;
        }

        auto writeHeader = [&](std::ofstream& f, const std::string& title) {
            f << "// ============================================================\n";
            f << "// ARC Raiders SDK Dump – " << title << "\n";
            f << "// Date:    " << Now() << "\n";
            f << "// PID:     " << m_pid << "\n";
            f << "// Base:    " << Hex(MODULE_BASE) << "\n";
            f << "// Entries: " << obj_count << "\n";
            f << "// ============================================================\n\n";
        };
        writeHeader(fObjects, "Full Object List");
        writeHeader(fNames,   "Unique FName Strings");
        writeHeader(fClasses, "Script/Package Objects");
        writeHeader(fLog,     "Run Log");

        fLog << "[" << Now() << "] Dump started. Objects: " << obj_count << "\n";

        // ── Iterate via chunked array ─────────────────────────────────────
        uint32_t valid = 0, failed = 0, empty = 0;
        std::set<std::string>                uniqueNames;
        std::unordered_map<std::string, int> nameCount;

        for (int32_t i = 0; i < obj_count; ++i) {
            if (i % 5000 == 0) {
                std::cout << "\r[*] " << i << "/" << obj_count
                          << " – valid=" << valid << "  " << std::flush;
            }

            uint64_t obj_ptr = m_gobj.GetObjectPtr(i);
            if (!obj_ptr) {
                ++empty;
                continue;
            }

            std::string name = m_fname.GetName(obj_ptr);
            if (name.empty()) {
                fObjects << "[" << i << "] " << Hex(obj_ptr) << " | <no name>\n";
                ++failed;
                continue;
            }

            // Sanitize name (strip non-printable)
            for (char& c : name)
                if (c < 0x20 || c > 0x7E) c = '?';

            fObjects << "[" << i << "] " << Hex(obj_ptr) << " | " << name << "\n";
            uniqueNames.insert(name);
            nameCount[name]++;

            if (name.rfind("/Script/", 0) == 0 || name.find("/Script/") != std::string::npos)
                fClasses << "[" << i << "] " << Hex(obj_ptr) << " | " << name << "\n";

            ++valid;
        }

        std::cout << "\r[+] Scan done: " << valid << " named, "
                  << failed << " failed, " << empty << " empty slots\n";

        // ── Write unique names ────────────────────────────────────────────
        fNames << "// Total unique names: " << uniqueNames.size() << "\n\n";
        for (const auto& n : uniqueNames)
            fNames << n << "\n";

        // ── Summary ───────────────────────────────────────────────────────
        auto t1  = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        std::cout << "\n=== Dump Summary ===\n";
        std::cout << "  Total entries : " << obj_count  << "\n";
        std::cout << "  Valid + named  : " << valid      << "\n";
        std::cout << "  Failed / empty : " << failed << " / " << empty << "\n";
        std::cout << "  Unique names   : " << uniqueNames.size() << "\n";
        std::cout << "  Time           : " << std::fixed << std::setprecision(1) << ms << " ms\n";
        std::cout << "\nOutput files: dump_objects.txt  dump_names.txt  dump_classes.txt  dump_log.txt\n";

        fLog << "[" << Now() << "] Dump complete.\n";
        fLog << "  valid=" << valid << " failed=" << failed << " empty=" << empty << "\n";
        fLog << "  unique_names=" << uniqueNames.size() << "\n";
        fLog << "  elapsed_ms=" << ms << "\n";
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "======================================\n";
    std::cout << "  ARC Raiders SDK Dumper\n";
    std::cout << "  Newest patch (FChunkedFixedUObjectArray)\n";
    std::cout << "  Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "======================================\n\n";

    int pid = 0;
    bool do_sdk   = false;
    bool do_test  = false;
    bool do_dump  = false;
    bool do_probe = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--sdk")   { do_sdk   = true; continue; }
        if (arg == "--test")  { do_test  = true; continue; }
        if (arg == "--dump")  { do_dump  = true; continue; }
        if (arg == "--probe") { do_probe = true; continue; }
        if (pid == 0) pid = atoi(argv[i]);
    }

    // Default: if no mode flags given, run test + dump (original behaviour)
    if (!do_sdk && !do_test && !do_dump && !do_probe) {
        do_test = true;
        do_dump = true;
    }

    if (pid == 0) {
        std::cout << "[*] No PID supplied – scanning /proc ...\n";
        pid = FindARCPid();
        if (pid > 0)
            std::cout << "[+] Found ARC Raiders PID: " << pid << "\n";
    }

    if (pid <= 0) {
        std::cerr << "Usage: sudo ./FrostDumper <pid> [--sdk] [--test] [--dump]\n";
        std::cerr << "       sudo ./FrostDumper          (auto-detect)\n";
        std::cerr << "  --sdk   Generate full SDK struct output -> SDK_Output.txt\n";
        std::cerr << "  --test  Run property name/offset test\n";
        std::cerr << "  --dump  Dump all GObjects to dump_objects.txt / dump_names.txt\n";
        return 1;
    }

    SDKDumper dumper(pid);
    if (!dumper.Init()) {
        std::cerr << "[-] Initialization failed. Check:\n";
        std::cerr << "    * Is memreader.ko loaded?  (sudo insmod kernel_module/src/memreader.ko)\n";
        std::cerr << "    * Are you running as root? (sudo)\n";
        std::cerr << "    * Is the PID correct?\n";
        return 1;
    }

    if (do_test)  dumper.TestNames();
    if (do_dump)  dumper.Run();
    if (do_probe) { dumper.ProbeFField(); dumper.ProbePropertyCIs(); }
    if (do_sdk)   dumper.DumpSDK();
    return 0;
}
