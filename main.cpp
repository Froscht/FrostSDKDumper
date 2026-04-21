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
#include <unordered_set>
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
#include "sig_scan.h"
#include "emu_engine.h"
#include "emu_fname.h"
#include "find_fname_func.h"
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
        if (fd >= 0 && pid == target_pid) return true;
        pid = target_pid;
        fd  = open("/dev/memreader", O_RDWR);
        if (fd < 0) { perror("[-] open /dev/memreader"); return false; }
        return true;
    }

    bool IsOpen() const { return fd >= 0; }

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
            // Reject UE's CrashReportClient.exe — it names its own thread
            // "GameThread" and references "PioneerGame" in the crash-dump
            // path, so a naive substring match picks it over the real game.
            if (strstr(cmd, "CrashReportClient")) continue;
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

        // ── Signature scan — patch-resilient RVA auto-discovery ─────────
        // Hardcoded RVAs in arc_decrypt.h are the primary source and remain
        // correct for the current patch. The scanner runs alongside and
        // overwrites any RVA it resolves to a different value (i.e. after
        // a future patch). Scan failures fall back to the hardcoded value.
        {
            SigScan::Scanner<KernelReader> scan(m_reader, MODULE_BASE, 0xE900000);
            static SigScan::PEFileReader s_pe;
            static const char* pe_path =
                "/media/frost/Coding Stuf/Linux/FrostBinaryDumper/Arc_Raiders_Binary_20260421_160408.exe";
            if (s_pe.Open(pe_path)) {
                scan.SetPEFallback(&s_pe);
                std::printf("[sig] PE fallback enabled: %s\n", pe_path);
            }

            auto apply = [](const char* name, uint64_t& slot, uint64_t dyn) {
                if (!dyn) {
                    std::printf("[sig] %-14s scan failed; using constant 0x%llX\n",
                        name, (unsigned long long)slot);
                    return;
                }
                if (dyn == slot) {
                    std::printf("[sig] %-14s 0x%llX (matches constant)\n",
                        name, (unsigned long long)dyn);
                } else {
                    std::printf("[sig] %-14s 0x%llX → 0x%llX (patch drift — auto-fixed)\n",
                        name, (unsigned long long)slot, (unsigned long long)dyn);
                    slot = dyn;
                }
            };
            apply("GObjectArray", ArcDecrypt::RVA_GOBJECT_ARRAY_BASE, scan.FindGObjectArrayRVA());
            apply("GWorld",       ArcDecrypt::RVA_GWORLD,             scan.FindGWorldRVA());
            apply("GNames",       ArcDecrypt::RVA_GNAMES_BASE,        scan.FindGNamesRVA());
            apply("FNameKeyTbl",  ArcDecrypt::RVA_FNAME_KEY_TABLE,
                  scan.FindFNameKeyTableRVA(ArcDecrypt::RVA_FNAME_KEY_TABLE,
                                            ArcDecrypt::RVA_GNAMES_BASE));
            auto st = scan.FindObjArraySimdTables();
            apply("SimdObjXor",   ArcDecrypt::RVA_SIMD_OBJARRAY_XOR, st.decrypt_key);
            apply("ElemMaskA",    ArcDecrypt::RVA_ELEM_MASK_A,       st.elem_mask_a);
            apply("ElemMaskB",    ArcDecrypt::RVA_ELEM_MASK_B,       st.elem_mask_b);
            apply("ElemXorKey",   ArcDecrypt::RVA_ELEM_XOR_KEY,      st.elem_xor_key);
            apply("CIdxXor1",     ArcDecrypt::RVA_CIDX_XOR1,         scan.FindCIdxXor1RVA());
        }

        // Init FName key table + SIMD tables
        if (!m_fname.Init()) {
            std::cerr << "[-] Failed to read FName key table / SIMD tables\n";
            return false;
        }
        std::cout << "[+] FName decryptor initialized\n";

        // Init GObjectArray (decrypt base, count, probe chunk ptr)
        m_gobj.SetPid(m_pid);
        if (!m_gobj.Init()) {
            std::cerr << "[-] GObjectArray direct init failed, trying world traversal...\n";
            m_gobj.PrintDiagnostics();
            if (!CollectWorldObjects()) {
                std::cerr << "[-] World traversal also failed. Aborting.\n";
                return false;
            }
        }
        std::cout << "[+] GObjectArray initialized (" << m_gobj.GetNumElements() << " objects)\n";
        return true;
    }

    // ── World traversal: GWorld → Levels → actors + BFS UClass expansion ─────
    // Used as fallback when GUObjectArray direct init fails (e.g. ObjObjects
    // decrypt params unknown). Mirrors the auto-discovery SDK dumper's
    // "Levels + BFS" path.  Discovered offsets from arc_config_cache.txt:
    //   gworldRVA=0xDEDF078 (double-deref), persistentLevelOffset=0xE0,
    //   actorsListOffset=0x108, actorsCountOffset=0x110,
    //   streaming levels TArray at GWorld+0x200 (hardcoded stable offset)
    bool CollectWorldObjects() {
        static auto isValidPtr = [](uint64_t p) {
            return p > 0x10000ULL && p < 0x7FFFFFFFFFFFULL;
        };
        auto isLikelyUObject = [&](uint64_t p) {
            if (!isValidPtr(p)) return false;
            uint64_t vtbl = 0;
            if (!m_reader.Read(p + ArcDecrypt::Offsets::UObject::VTable, &vtbl, 8))
                return false;
            return vtbl >= MODULE_BASE && vtbl < MODULE_BASE + 0x10000000ULL;
        };

        // ── Step 1: Get GWorld (single-deref) ────────────────────────────
        uint64_t gworld = 0;
        if (!m_reader.Read(MODULE_BASE + ArcDecrypt::RVA_GWORLD, &gworld, 8) || !isValidPtr(gworld)) {
            std::printf("[-] WorldTraversal: GWorld invalid (0x%llX)\n",
                (unsigned long long)gworld);
            return false;
        }
        std::printf("[+] WorldTraversal: GWorld = 0x%llX\n", (unsigned long long)gworld);

        // ── Step 2: Collect levels ────────────────────────────────────────
        std::vector<uint64_t> levels;

        // Persistent level at GWorld+PersistentLevel
        uint64_t plev = 0;
        m_reader.Read(gworld + ArcDecrypt::Offsets::UWorld::PersistentLevel, &plev, 8);
        if (isValidPtr(plev)) {
            levels.push_back(plev);
            std::printf("[+] WorldTraversal: PersistentLevel = 0x%llX\n",
                (unsigned long long)plev);
        } else {
            std::printf("[!] WorldTraversal: PersistentLevel at GWorld+0x%llX invalid\n",
                (unsigned long long)ArcDecrypt::Offsets::UWorld::PersistentLevel);
            // Probe alternate offsets
            for (uint64_t off = 0x80; off <= 0x180; off += 8) {
                if (off == ArcDecrypt::Offsets::UWorld::PersistentLevel) continue;
                uint64_t cand = 0;
                m_reader.Read(gworld + off, &cand, 8);
                if (!isValidPtr(cand)) continue;
                // Quick validation: actors TArray at cand+0x108 should look valid
                uint64_t adata = 0; int32_t acount = 0;
                m_reader.Read(cand + 0x108, &adata, 8);
                m_reader.Read(cand + 0x110, &acount, 4);
                if (isValidPtr(adata) && acount > 0 && acount < 500000) {
                    levels.push_back(cand);
                    std::printf("[+] WorldTraversal: PersistentLevel found at GWorld+0x%llX = 0x%llX\n",
                        (unsigned long long)off, (unsigned long long)cand);
                    break;
                }
            }
        }

        // Streaming levels TArray at GWorld+0x200
        {
            uint64_t levData = 0; int32_t levCount = 0;
            m_reader.Read(gworld + 0x200, &levData, 8);
            m_reader.Read(gworld + 0x208, &levCount, 4);
            if (isValidPtr(levData) && levCount > 0 && levCount < 2000) {
                std::printf("[+] WorldTraversal: StreamingLevels[%d] at GWorld+0x200\n", levCount);
                for (int i = 0; i < levCount; ++i) {
                    uint64_t lev = 0;
                    if (!m_reader.Read(levData + 8ULL * i, &lev, 8)) continue;
                    if (!isValidPtr(lev)) continue;
                    // lev is a ULevelStreaming* — get its LoadedLevel
                    // Try common offsets for ULevelStreaming::LoadedLevel
                    bool added = false;
                    for (uint64_t off : {0xF8ULL, 0x100ULL, 0x108ULL, 0x110ULL}) {
                        uint64_t loaded = 0;
                        if (!m_reader.Read(lev + off, &loaded, 8)) continue;
                        if (!isValidPtr(loaded)) continue;
                        uint64_t adata = 0; int32_t acount = 0;
                        m_reader.Read(loaded + 0x108, &adata, 8);
                        m_reader.Read(loaded + 0x110, &acount, 4);
                        if (isValidPtr(adata) && acount > 0 && acount < 500000) {
                            bool dup = false;
                            for (auto& ex : levels) if (ex == loaded) { dup = true; break; }
                            if (!dup) levels.push_back(loaded);
                            added = true;
                            break;
                        }
                    }
                    (void)added;
                }
            } else {
                // Probe alternate streaming levels offsets
                for (uint64_t off = 0x180; off <= 0x300; off += 8) {
                    if (off == 0x200) continue;
                    uint64_t ld = 0; int32_t lc = 0;
                    m_reader.Read(gworld + off, &ld, 8);
                    m_reader.Read(gworld + off + 8, &lc, 4);
                    if (isValidPtr(ld) && lc > 0 && lc < 2000) {
                        std::printf("[+] WorldTraversal: StreamingLevels[%d] at GWorld+0x%llX\n",
                            lc, (unsigned long long)off);
                        for (int i = 0; i < lc; ++i) {
                            uint64_t lev = 0;
                            if (!m_reader.Read(ld + 8ULL * i, &lev, 8)) continue;
                            if (!isValidPtr(lev)) continue;
                            bool dup = false;
                            for (auto& ex : levels) if (ex == lev) { dup = true; break; }
                            if (!dup) levels.push_back(lev);
                        }
                        break;
                    }
                }
            }
        }
        std::printf("[+] WorldTraversal: %zu levels total\n", levels.size());
        if (levels.empty()) return false;

        // ── Step 3: Collect actors from all levels ────────────────────────
        std::vector<uint64_t> seed_objects;
        int total_actors = 0;
        for (uint64_t level : levels) {
            uint64_t adata = 0; int32_t acount = 0;
            if (!m_reader.Read(level + 0x108, &adata, 8)) continue;
            if (!m_reader.Read(level + 0x110, &acount, 4)) continue;
            if (!isValidPtr(adata) || acount <= 0 || acount > 500000) continue;

            for (int32_t i = 0; i < acount; ++i) {
                uint64_t actor = 0;
                if (!m_reader.Read(adata + 8ULL * i, &actor, 8)) continue;
                if (!isLikelyUObject(actor)) continue;
                seed_objects.push_back(actor);
                ++total_actors;
            }
        }
        std::printf("[+] WorldTraversal: %d actors collected\n", total_actors);
        if (seed_objects.empty()) return false;

        // ── Step 4: BFS UClass expansion ─────────────────────────────────
        // From each actor → GetClassPrivate → UClass → SuperStruct chain
        // This expands the ~1500 actors to ~17K objects (matching auto-discovery)
        std::unordered_set<uint64_t> seen(seed_objects.begin(), seed_objects.end());
        std::vector<uint64_t> bfs_queue;

        // Seed with UClass pointers of all actors
        for (uint64_t actor : seed_objects) {
            uint64_t uclass = m_fname.GetClassPrivate(actor);
            if (isLikelyUObject(uclass) && seen.find(uclass) == seen.end()) {
                seen.insert(uclass);
                bfs_queue.push_back(uclass);
            }
        }

        // BFS: from each UClass, follow GetClassPrivate (metaclass) and SuperStruct chain
        constexpr int MAX_BFS_ROUNDS = 8;
        for (int round = 0; round < MAX_BFS_ROUNDS && !bfs_queue.empty(); ++round) {
            std::vector<uint64_t> next_queue;
            for (uint64_t obj : bfs_queue) {
                // Follow GetClassPrivate (gets the metaclass, e.g. "Class")
                uint64_t metaclass = m_fname.GetClassPrivate(obj);
                if (isLikelyUObject(metaclass) && seen.find(metaclass) == seen.end()) {
                    seen.insert(metaclass);
                    next_queue.push_back(metaclass);
                }
                // Follow SuperStruct at UStruct+0xB0
                uint64_t super = 0;
                m_reader.Read(obj + ArcDecrypt::Offsets::UStruct::SuperStruct, &super, 8);
                if (isLikelyUObject(super) && seen.find(super) == seen.end()) {
                    seen.insert(super);
                    next_queue.push_back(super);
                }
            }
            std::printf("[+] WorldTraversal: BFS round %d: +%zu objects (total %zu)\n",
                round + 1, next_queue.size(), seen.size());
            if (next_queue.empty()) break;
            bfs_queue = std::move(next_queue);
        }

        // Flatten all discovered objects into the result vector
        std::vector<uint64_t> all_objects(seen.begin(), seen.end());
        std::printf("[+] WorldTraversal: Total objects collected: %zu\n", all_objects.size());

        return m_gobj.InitWithSeedObjects(std::move(all_objects));
    }

    // ── CompIndex → string test + FField chain probe ─────────────────────
    void TestNames() {
        std::cout << "\n=== TestNames ===\n";

        // Debug: dump first 8 key table values
        m_fname.DumpKeyTable(8);

        // Always debug CI=505 (known "Object") and CI=21521
        m_fname.DebugResolve(505);
        m_fname.DebugResolve(21521);

        // 1. Resolve known comp_indices
        for (int32_t ci : {244478, 245193}) {
            std::string name = m_fname.CompIndexToName(ci);
            std::cout << "  CompIndexToName(" << ci << ") = '"
                      << (name.empty() ? "<empty>" : name) << "'\n";
            if (name.empty()) m_fname.DebugResolve(ci);
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
                { uint64_t pfc = 0; m_reader.Read(chain + ArcDecrypt::Offsets::FField::ClassPrivate, &pfc, 8);
                  if (pfc) m_reader.Read(pfc + ArcDecrypt::Offsets::FFieldClass::ElementSize, &elem_size, 4); }
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
        gen.DumpVTableMap("vtable_map.md");
        std::cout << "[+] Classes/Structs found: " << sdk.structs.size() << "\n";
        std::cout << "[+] Enums found:           " << sdk.enums.size()   << "\n";

        // ── Compute detailed stats ────────────────────────────────────────
        uint32_t n_classes = 0, n_structs = 0;
        uint64_t n_functions = 0, n_properties = 0, n_named = 0;
        uint64_t n_struct_props = 0, n_param_props = 0;
        uint64_t fn_0p = 0, fn_1p = 0, fn_2p = 0, fn_3p = 0;
        for (const auto& rec : sdk.structs) {
            if (rec.is_class) ++n_classes; else ++n_structs;
            n_properties += rec.properties.size();
            n_struct_props += rec.properties.size();
            n_named += rec.properties.size();
            for (const auto& fn : rec.functions) {
                n_properties += fn.params.size();
                n_param_props += fn.params.size();
                n_named      += fn.params.size();
                if (fn.params.empty()) ++fn_0p;
                else if (fn.params.size() == 1) ++fn_1p;
                else if (fn.params.size() == 2) ++fn_2p;
                else ++fn_3p;
            }
        }
        // n_functions = total UFunction objects discovered (across all owners),
        // not just those attached to a struct in our output.
        for (const auto& [owner, fns] : gen.GetOwnerFuncMap())
            n_functions += fns.size();
        std::printf("[stats] struct_props=%llu param_props=%llu total=%llu\n",
            (unsigned long long)n_struct_props, (unsigned long long)n_param_props,
            (unsigned long long)n_properties);
        std::printf("[stats] fn_params: 0p=%llu 1p=%llu 2p=%llu 3+p=%llu\n",
            (unsigned long long)fn_0p, (unsigned long long)fn_1p,
            (unsigned long long)fn_2p, (unsigned long long)fn_3p);

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
            // Track which class addresses had functions written
            std::unordered_set<uint64_t> seen_owners;
            for (const auto& rec : sdk.structs) {
                sdk_file << gen.DumpStruct(rec);
                seen_owners.insert(rec.addr);
                ++written;
                if (written % 500 == 0)
                    std::cout << "\r[*] Written " << written << "/" << sdk.structs.size() << "  " << std::flush;
            }
            // Write orphan functions (functions whose owner wasn't dumped as a type)
            sdk_file << "\n// === Orphan Functions ===\n";
            sdk_file << "namespace Globals {\n";
            int orphan_count = 0;
            for (const auto& [owner, fn_list] : gen.GetOwnerFuncMap()) {
                if (seen_owners.count(owner)) continue;
                std::string owner_name = "Owner_0x";
                char buf[32]; std::snprintf(buf, sizeof(buf), "%llX", (unsigned long long)owner);
                owner_name += buf;
                sdk_file << "// Orphan owner @ 0x" << std::hex << owner << " (" << fn_list.size() << " functions)\n";
                for (uint64_t fn_addr : fn_list) {
                    std::string fn_name = m_fname.GetName(fn_addr);
                    if (fn_name.empty()) fn_name = "<unnamed>";
                    sdk_file << "// fn 0x" << std::hex << fn_addr << " " << owner_name << "::" << fn_name << "\n";
                    ++orphan_count;
                }
            }
            sdk_file << "// Total orphan functions: " << std::dec << orphan_count << "\n";
            sdk_file << "} // namespace Globals\n";
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

            // Build a richer class/package record even when names are short.
            uint64_t cls_ptr = m_fname.GetClassPrivate(obj_ptr);
            std::string cls_name = m_fname.GetName(cls_ptr);
            uint64_t pkg_ptr = m_fname.GetPackagePtr(obj_ptr);
            std::string pkg_name = m_fname.GetName(pkg_ptr);

            if (!cls_name.empty() || !pkg_name.empty() ||
                name.rfind("/Script/", 0) == 0 || name.find("/Script/") != std::string::npos)
            {
                std::string qualified = name;
                if (!pkg_name.empty())
                    qualified = pkg_name + "." + qualified;

                fClasses << "[" << i << "] " << Hex(obj_ptr) << " | ";
                if (!cls_name.empty())
                    fClasses << cls_name << " ";
                fClasses << qualified << "\n";
            }

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
    bool do_sdk   = false, do_test = false, do_dump = false, do_probe = false;
    bool do_emu_smoke = false, do_emu_fname = false, want_help = false;
    bool do_decrypt_handle = false, do_test_gobj = false, do_dump_gobj_chunks = false;
    bool do_scan_chunks = false, do_list_uobjects = false;
    uint32_t emu_fname_ci = 505;
    uint64_t decrypt_handle_val = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { want_help = true; continue; }
        if (arg == "--sdk")       { do_sdk   = true; continue; }
        if (arg == "--test")      { do_test  = true; continue; }
        if (arg == "--dump")      { do_dump  = true; continue; }
        if (arg == "--probe")     { do_probe = true; continue; }
        if (arg == "--emu-smoke") { do_emu_smoke = true; continue; }
        if (arg == "--emu-fname") {
            do_emu_fname = true;
            if (i + 1 < argc && argv[i+1][0] != '-')
                emu_fname_ci = (uint32_t)std::strtoul(argv[++i], nullptr, 0);
            continue;
        }
        if (arg == "--test-gobj")  { do_test_gobj = true; continue; }
        if (arg == "--dump-gobj-chunks") { do_dump_gobj_chunks = true; continue; }
        if (arg == "--scan-chunks") { do_scan_chunks = true; continue; }
        if (arg == "--list-uobjects") { do_list_uobjects = true; continue; }
        if (arg == "--decrypt-handle") {
            // Patch 20260421: apply bswap64(handle ^ 0x59B07C3D00000000)
            // to the raw FName handle qword and print the resulting pointer.
            do_decrypt_handle = true;
            if (i + 1 < argc && argv[i+1][0] != '-')
                decrypt_handle_val = std::strtoull(argv[++i], nullptr, 0);
            continue;
        }
        if (pid == 0) pid = atoi(argv[i]);
    }

    auto print_help = []() {
        std::cerr <<
            "Usage: sudo ./FrostDumper [<pid>] [mode flags]\n"
            "Mode flags (one or more; no flag → --test + --dump):\n"
            "  --test       Sample known FName CIs to verify decryptor.\n"
            "  --dump       Enumerate GObjects → dump_*.txt.\n"
            "  --sdk        Full C++ SDK → SDK_Output.txt.\n"
            "  --probe      FField / property CI probes.\n"
            "  --emu-smoke  Boot Unicorn engine + PE fallback; map a VMProtect-cold page.\n"
            "               Runs before dumper.Init() — works from any game state.\n"
            "  --emu-fname [CI]\n"
            "               Find FName decrypt by signature, call game's code inside\n"
            "               Unicorn for CI (default 505 = \"Object\"), print result.\n"
            "  --decrypt-handle <hex>\n"
            "               Patch 20260421 test: apply bswap64(X ^ 0x59B07C3D00000000)\n"
            "               to the given raw FName handle and print the entry pointer.\n"
            "  --test-gobj  Patch 20260421: read live GUObjectArray (0xDDCB420),\n"
            "               apply new decrypt pipeline, print chunks_manager + max.\n"
            "  --dump-gobj-chunks\n"
            "               Emulate VMProtected vtable[7] via Unicorn to fetch\n"
            "               the chunk-ptr-array. BROKEN: VMP anti-emu defeats us;\n"
            "               left as a probe for further analysis.\n"
            "  --help, -h   This message.\n";
    };
    if (want_help) { print_help(); return 0; }

    // --decrypt-handle is pure computation, no PID needed.
    if (do_decrypt_handle) {
        uint64_t entry = ArcDecrypt::Patch20260421::DecryptEntryHandle(decrypt_handle_val);
        std::printf("[decrypt-handle] handle=0x%016llX\n",
            (unsigned long long)decrypt_handle_val);
        std::printf("[decrypt-handle] entry =0x%016llX   (sentinel-xor → bswap64)\n",
            (unsigned long long)entry);
        if (decrypt_handle_val == ArcDecrypt::Patch20260421::ENTRY_HANDLE_XOR)
            std::printf("[decrypt-handle] NOTE: handle == sentinel → represents NAME_None (null)\n");
        return 0;
    }

    // --list-uobjects: after --scan-chunks finds the array, print each UObject
    // with its vtable and decrypted NamePrivate (FName handle at +0x18).
    if (do_list_uobjects) {
        if (pid == 0) { pid = FindARCPid(); if (pid <= 0) { std::cerr << "[list] no PID\n"; return 1; } }
        KernelReader r;
        if (!r.Open(pid)) { std::cerr << "[list] reader open failed\n"; return 1; }
        const uint64_t base = 0x140000000ULL;
        const uint64_t vt_lo = base + 0x1000;
        const uint64_t vt_hi = base + 0xAD2B448;

        // Find the FUObjectItem array (reuse scan logic condensed).
        auto is_heap = [&](uint64_t p){ return p >= 0x100000 && p < 0x800000000000ULL; };
        auto is_vt   = [&](uint64_t p){ return p >= vt_lo && p < vt_hi; };
        const uint64_t WIN = 0x10000ULL;
        const uint32_t STRIDE = 20;
        std::vector<uint8_t> buf(WIN);
        uint64_t array_start = 0;
        uint32_t array_count = 0;
        uint64_t cur_start = 0;
        uint32_t cur_count = 0;
        auto flush_best = [&]() {
            if (cur_count > array_count) { array_start = cur_start; array_count = cur_count; }
            cur_start = 0; cur_count = 0;
        };
        std::printf("[list] scanning for UObject array ...\n");
        for (uint64_t page = 0x10000000ULL; page + WIN <= 0x80000000ULL; page += WIN) {
            if (!r.Read(page, buf.data(), WIN)) { flush_best(); continue; }
            for (size_t off = 0; off + STRIDE <= WIN; off += STRIDE) {
                uint64_t op = 0;
                std::memcpy(&op, buf.data() + off, 8);
                bool ok = is_heap(op);
                if (ok) { uint64_t vt = 0; ok = r.Read(op, &vt, 8) && is_vt(vt); }
                if (!ok) { flush_best(); continue; }
                if (cur_count == 0) cur_start = page + off;
                cur_count++;
            }
        }
        flush_best();
        if (!array_count) { std::cerr << "[list] no UObject array found\n"; return 1; }
        std::printf("[list] UObject array @ 0x%llX  items=%u\n",
            (unsigned long long)array_start, array_count);

        // Enumerate and decrypt names. The UObject NamePrivate (16B) is at
        // some offset we need to probe; prior-patch used +0x90 (UObject FName
        // at +0x18, the raw handle qword is inside that 16B field).
        // Per patch 20260421, the second qword of the 16B FName IS the
        // encrypted entry-pointer handle → decrypt via DecryptEntryHandle.
        // Common UObjectBase layout offsets to try for NamePrivate: +0x18.
        int limit = 30;
        std::printf("[list] first %d UObjects (obj, vtable, handle→entry):\n", limit);
        int listed = 0, valid_names = 0;
        for (uint32_t i = 0; i < array_count && listed < limit; ++i) {
            uint64_t item = array_start + (uint64_t)STRIDE * i;
            uint64_t obj = 0;
            if (!r.Read(item, &obj, 8) || !obj) continue;
            uint64_t vt = 0;
            r.Read(obj, &vt, 8);
            // NamePrivate is stored as an inline 16-byte FName at obj+0x28
            // (UObjectBase layout for patch 20260421, confirmed by reading
            // live UObject: +0x18/+0x20 are zero, first 16-byte encrypted
            // FName block starts at +0x28).
            uint8_t name_bytes[16] = {};
            r.Read(obj + 0x28, name_bytes, 16);
            uint64_t handle_lo = 0, handle_hi = 0;
            std::memcpy(&handle_lo, name_bytes + 0, 8);
            std::memcpy(&handle_hi, name_bytes + 8, 8);
            uint64_t entry1 = ArcDecrypt::Patch20260421::DecryptEntryHandle(handle_lo);
            uint64_t entry2 = ArcDecrypt::Patch20260421::DecryptEntryHandle(handle_hi);
            bool v1 = entry1 >= 0x10000 && entry1 < 0x800000000000ULL;
            bool v2 = entry2 >= 0x10000 && entry2 < 0x800000000000ULL;
            if (v1 || v2) valid_names++;
            std::printf("[list] [%5u] obj=0x%012llX vt=0x%09llX  h_lo→0x%016llX %s  h_hi→0x%016llX %s\n",
                i, (unsigned long long)obj, (unsigned long long)vt,
                (unsigned long long)entry1, v1 ? "✓" : " ",
                (unsigned long long)entry2, v2 ? "✓" : " ");
            listed++;
        }
        std::printf("[list] %d listed, %d with candidate name pointers\n", listed, valid_names);
        return 0;
    }

    // --scan-chunks: structural scan for FUObjectItem chunks in live memory.
    // Looks for regions of 20-byte-stride entries whose first qword is a
    // plausible UObject pointer (first qword of pointed-to is a vtable in
    // .text/.rdata range). Reports regions with ≥500 consecutive valid items.
    if (do_scan_chunks) {
        if (pid == 0) { pid = FindARCPid(); if (pid <= 0) { std::cerr << "[scan] no PID\n"; return 1; } }
        KernelReader r;
        if (!r.Open(pid)) { std::cerr << "[scan] reader open failed\n"; return 1; }
        const uint64_t base = 0x140000000ULL;
        const uint64_t vt_lo = base + 0x1000;          // .text start
        const uint64_t vt_hi = base + 0xAD2B448;       // .rdata end (vtables live there too)

        auto is_vtable_ptr = [&](uint64_t p) {
            return p >= vt_lo && p < vt_hi;
        };
        auto is_heap_ptr = [&](uint64_t p) {
            // Wine heap: 0x10000..0x800000000000
            return p >= 0x100000 && p < 0x800000000000ULL;
        };

        // Scan candidate heap regions. UE's tagged allocator may place
        // FUObjectItem chunks anywhere in process address space, so we cover
        // a wide range. Wine pointers we've seen: 0x14x (module), 0x18x..0x2x
        // (chunks_manager area), 0x1E3x (chunks_manager internal), and higher.
        struct Region { uint64_t start; uint32_t count; };
        std::vector<Region> regions;
        const std::pair<uint64_t,uint64_t> scan_ranges[] = {
            {0x10000000ULL, 0x80000000ULL},     // 2 GB: 0x10000000..0x80000000
            {0x100000000ULL, 0x400000000ULL},   // 12 GB: 0x100000000..0x400000000
        };
        const uint64_t WIN     = 0x10000ULL;           // 64 KB per read
        const uint32_t STRIDE  = 20;

        std::vector<uint8_t> buf(WIN);
        uint64_t total_pages = 0, ok_pages = 0;
        uint64_t current_start = 0;
        uint32_t current_count = 0;

        auto flush_region = [&]() {
            if (current_count >= 500) {
                regions.push_back({current_start, current_count});
                std::printf("[scan]   region @ 0x%llX  count=%u\n",
                    (unsigned long long)current_start, current_count);
            }
            current_start = 0;
            current_count = 0;
        };

        for (auto [lo, hi] : scan_ranges) {
            std::printf("[scan] range 0x%llX..0x%llX (stride %u)\n",
                (unsigned long long)lo, (unsigned long long)hi, STRIDE);
            // Continuous sweep: carry an in-progress region across pages.
            // Mark current_count=0 only on a concrete invalid entry, not on
            // page-boundary read failure.
            for (uint64_t page = lo; page + WIN <= hi; page += WIN) {
                total_pages++;
                if (!r.Read(page, buf.data(), WIN)) { flush_region(); continue; }
                ok_pages++;
                // Start at the residue of previous window: if current region
                // was in progress at the LAST stride-aligned position of prev
                // window, its tail is at page+0 minus the remainder.
                size_t start_off = 0;
                if (current_count && (page % STRIDE)) {
                    // realign to stride boundary relative to region start
                    start_off = (STRIDE - (page - current_start) % STRIDE) % STRIDE;
                }
                for (size_t off = start_off; off + STRIDE <= WIN; off += STRIDE) {
                    uint64_t obj_ptr = 0;
                    std::memcpy(&obj_ptr, buf.data() + off, 8);
                    bool ok = is_heap_ptr(obj_ptr);
                    if (ok) {
                        uint64_t vt = 0;
                        ok = r.Read(obj_ptr, &vt, 8) && is_vtable_ptr(vt);
                    }
                    if (!ok) { flush_region(); continue; }
                    if (current_count == 0) current_start = page + off;
                    current_count++;
                }
            }
            flush_region();
        }
        std::printf("[scan] done. pages_read=%llu/%llu  regions_found=%zu\n",
            (unsigned long long)ok_pages, (unsigned long long)total_pages, regions.size());
        if (regions.empty()) {
            std::printf("[scan] no large chunk-array candidates found\n");
            return 1;
        }
        // Dump the best region's first 10 FUObjectItems to verify
        auto& best = *std::max_element(regions.begin(), regions.end(),
            [](const Region& a, const Region& b){ return a.count < b.count; });
        std::printf("[scan] best region: 0x%llX (count=%u → %u objects approx)\n",
            (unsigned long long)best.start, best.count, best.count);
        for (uint32_t i = 0; i < 10 && i < best.count; ++i) {
            uint64_t item = best.start + (uint64_t)STRIDE * i;
            uint64_t obj = 0; uint32_t a = 0, b = 0, c = 0;
            r.Read(item,      &obj, 8);
            r.Read(item + 8,  &a, 4);
            r.Read(item + 12, &b, 4);
            r.Read(item + 16, &c, 4);
            std::printf("[scan]   item[%2u] @ 0x%llX: obj=0x%llX  %08X %08X %08X\n",
                i, (unsigned long long)item, (unsigned long long)obj, a, b, c);
        }
        return 0;
    }

    // --dump-gobj-chunks: emulate the VMProtected vtable[7] of chunks_manager
    // to obtain the chunk-pointer-array, then walk FUObjectItems.
    if (do_dump_gobj_chunks) {
        if (pid == 0) { pid = FindARCPid(); if (pid <= 0) { std::cerr << "[gobj] no PID\n"; return 1; } }
        KernelReader r;
        if (!r.Open(pid)) { std::cerr << "[gobj] reader open failed\n"; return 1; }
        using namespace ArcDecrypt::Patch20260421;
        const uint64_t base = 0x140000000ULL;

        uint8_t enc[16] = {}, mask[8] = {};
        uint64_t xor_key = 0;
        if (!r.Read(base + RVA_GUOBJECT_ARRAY_NEW, enc, 16) ||
            !r.Read(base + RVA_GOBJ_PSHUFB_MASK,   mask, 8) ||
            !r.Read(base + RVA_GOBJ_MAX_XOR_KEY,   &xor_key, 8)) {
            std::cerr << "[gobj] read constants failed\n"; return 1;
        }
        uint64_t chunks_mgr = ArcDecrypt::Patch20260421::DecryptGObjChunksManager(enc, mask);
        std::printf("[gobj] chunks_manager = 0x%llX\n", (unsigned long long)chunks_mgr);

        // Read chunks_manager's vtable[7] target (offset +0x38 in vtable at [chunks_mgr])
        uint64_t vtable = 0;
        if (!r.Read(chunks_mgr, &vtable, 8) || !vtable) {
            std::cerr << "[gobj] failed reading chunks_manager vtable\n"; return 1;
        }
        uint64_t vt7 = 0;
        if (!r.Read(vtable + 0x38, &vt7, 8) || !vt7) {
            std::cerr << "[gobj] failed reading vtable[7]\n"; return 1;
        }
        std::printf("[gobj] vtable=0x%llX  vtable[7]=0x%llX\n",
            (unsigned long long)vtable, (unsigned long long)vt7);

        // Read the xmmword at chunks_manager+0x30 (scratch input passed to vt7)
        uint8_t scratch_in[16] = {};
        if (!r.Read(chunks_mgr + 0x30, scratch_in, 16)) {
            std::cerr << "[gobj] failed reading chunks_manager+0x30\n"; return 1;
        }

        // Boot Unicorn, map live memory on demand.
        EmuEngine eng;
        if (!eng.Initialize(&r, base, 0xE9AF000,
                "/media/frost/Coding Stuf/Linux/FrostSDKDumper/Arc_Raiders_Binary_20260421_213315.exe")) {
            std::cerr << "[gobj] emu init failed\n"; return 1;
        }
        // Pre-map chunks_manager pages + vt7 pages
        eng.PreMapRange(chunks_mgr & ~0xFFFULL, 0x4000);
        eng.PreMapRange(vt7 & ~0xFFFULL, 0x4000);

        // Set up fake TEB at 0x7FFFFFFE0000 so GS:[0x60] → PEB works.
        constexpr uint64_t FAKE_TEB = 0x00007FFFFFFE0000ULL;
        constexpr uint64_t FAKE_PEB = 0x7FFD0000ULL;
        uc_mem_map(eng.UC(), FAKE_TEB, 0x1000, UC_PROT_ALL);
        uint8_t teb_zero[0x1000] = {};
        uc_mem_write(eng.UC(), FAKE_TEB, teb_zero, sizeof(teb_zero));
        uint64_t self = FAKE_TEB, stack_b = 0x200000 + 0x100000, stack_l = 0x200000;
        uc_mem_write(eng.UC(), FAKE_TEB + 0x08, &stack_b, 8);
        uc_mem_write(eng.UC(), FAKE_TEB + 0x10, &stack_l, 8);
        uc_mem_write(eng.UC(), FAKE_TEB + 0x30, &self, 8);
        uc_mem_write(eng.UC(), FAKE_TEB + 0x60, &FAKE_PEB, 8);
        eng.SetGSBase(FAKE_TEB);
        eng.MapGamePage(FAKE_PEB);  // PEB page (may be read)

        // Layout a scratch struct in INPUT region. The VMProtected dispatcher
        // at vtable[7] interprets a bytecode stream whose pointer is at
        // [rdx+0x20]. In the original caller's stack, that slot held a pointer
        // to an adjacent __int128 zero buffer. Reproduce that layout:
        //   scratch+0x00..+0x1F: undefined stack data (zero is fine)
        //   scratch+0x20: pointer to bytecode stream (set to scratch+0x40)
        //   scratch+0x30: the xmmword copied from chunks_manager+0x30
        //   scratch+0x40: bytecode (start with 0 = opcode 0 = "return" in
        //                 most VMP dispatchers we've seen)
        const uint64_t SCRATCH_ADDR = 0x10000ULL;      // EmuEngine::INPUT_BASE
        uint8_t scratch[0x200] = {};
        uint64_t bc_stream = SCRATCH_ADDR + 0x40;
        std::memcpy(scratch + 0x20, &bc_stream, 8);    // [rdx+0x20] = bytecode ptr
        std::memcpy(scratch + 0x30, scratch_in, 16);   // [rdx+0x30] = xmmword from chunks_mgr+0x30
        // scratch+0x40..+0x1FF = bytecode; all zeros (opcode 0 repeated)
        eng.EmuWrite(SCRATCH_ADDR, scratch, sizeof(scratch));

        // Call vtable[7](chunks_mgr, scratch)
        eng.ResetCPU();
        eng.WriteReg(UC_X86_REG_RCX, chunks_mgr);
        eng.WriteReg(UC_X86_REG_RDX, SCRATCH_ADDR);
        // Set up return address = SENTINEL_RIP (EmuEngine provides an implicit
        // sentinel page mapped at 0xDEAD0000 / 0x1000 filled with CCs).
        uint64_t sentinel = 0xDEAD0000ULL;
        uint64_t rsp = eng.ReadReg(UC_X86_REG_RSP);
        rsp -= 8;
        eng.EmuWrite(rsp, &sentinel, 8);
        eng.WriteReg(UC_X86_REG_RSP, rsp);

        std::printf("[gobj] running vtable[7] emulation...\n");
        uc_err er = eng.Run(vt7, sentinel, /*timeout_us*/2'000'000, /*max*/500000);
        uint64_t rax = eng.ReadReg(UC_X86_REG_RAX);
        std::printf("[gobj] run status: %d (%s)  rax=0x%llX\n",
            (int)er, uc_strerror(er), (unsigned long long)rax);

        if (!rax || rax < 0x10000 || rax >= 0x800000000000) {
            std::printf("[gobj] emu returned implausible rax=0x%llX\n",
                (unsigned long long)rax);
            std::printf("[gobj] (VMProtect anti-emulation is likely defeating Unicorn here)\n");
            std::printf("[gobj] TODO: implement bytecode interpreter, or find a non-VMP\n");
            std::printf("[gobj]       path to the chunks-ptr-array inside chunks_manager.\n");
            return 1;
        }

        // rax should point to the chunk-ptr-array
        uint64_t chunks_array = rax;
        std::printf("[gobj] chunk-ptr-array @ 0x%llX\n",
            (unsigned long long)chunks_array);
        for (int ci = 0; ci < 8; ++ci) {
            uint64_t cp = 0;
            if (!r.Read(chunks_array + 8 * ci, &cp, 8)) break;
            std::printf("[gobj]   chunk[%d] = 0x%llX\n", ci, (unsigned long long)cp);
            if (!cp) break;
            // Probe first FUObjectItem
            uint64_t obj_ptr = 0;
            r.Read(cp, &obj_ptr, 8);
            std::printf("[gobj]     item[0].obj = 0x%llX\n", (unsigned long long)obj_ptr);
        }
        return 0;
    }

    // --test-gobj: read live GUObjectArray, apply patch-20260421 decrypt.
    if (do_test_gobj) {
        if (pid == 0) {
            std::cout << "[test-gobj] No PID — scanning /proc ...\n";
            pid = FindARCPid();
            if (pid <= 0) { std::cerr << "[test-gobj] game not found\n"; return 1; }
            std::cout << "[test-gobj] PID: " << pid << "\n";
        }
        KernelReader r;
        if (!r.Open(pid)) { std::cerr << "[test-gobj] reader open failed\n"; return 1; }

        using namespace ArcDecrypt::Patch20260421;
        const uint64_t base = 0x140000000ULL;

        uint8_t enc[16] = {}, mask[8] = {}, max_enc[16] = {};
        uint64_t xor_key = 0;

        if (!r.Read(base + RVA_GUOBJECT_ARRAY_NEW, enc, 16)) {
            std::cerr << "[test-gobj] failed to read GUObjectArray\n"; return 1;
        }
        if (!r.Read(base + RVA_GOBJ_PSHUFB_MASK, mask, 8)) {
            std::cerr << "[test-gobj] failed to read PSHUFB mask\n"; return 1;
        }
        if (!r.Read(base + RVA_GOBJ_MAX_XOR_KEY, &xor_key, 8)) {
            std::cerr << "[test-gobj] failed to read XOR key\n"; return 1;
        }

        std::printf("[test-gobj] GUObjectArray @ 0x%llX\n",
            (unsigned long long)(base + RVA_GUOBJECT_ARRAY_NEW));
        std::printf("[test-gobj]   enc xmmword : ");
        for (int i = 0; i < 16; ++i) std::printf("%02x", enc[i]);
        std::printf("\n[test-gobj]   pshufb mask: ");
        for (int i = 0; i < 8;  ++i) std::printf("%02x", mask[i]);
        std::printf("\n[test-gobj]   xor_key_lo8: 0x%016llX\n",
            (unsigned long long)xor_key);

        uint64_t chunks_mgr = ArcDecrypt::Patch20260421::DecryptGObjChunksManager(enc, mask);
        std::printf("[test-gobj] chunks_manager = 0x%llX\n",
            (unsigned long long)chunks_mgr);

        if (!r.Read(chunks_mgr + GOBJ_MANAGER_MAX_OFFSET, max_enc, 16)) {
            std::cerr << "[test-gobj] failed to read chunks_manager+0x70\n";
            std::cerr << "[test-gobj] (decrypt produced bad pointer?)\n";
            return 1;
        }
        std::printf("[test-gobj]   +0x70 enc : ");
        for (int i = 0; i < 16; ++i) std::printf("%02x", max_enc[i]);
        int32_t max_elem = ArcDecrypt::Patch20260421::DecryptGObjMaxElements(max_enc, xor_key);
        std::printf("\n[test-gobj] max_elements = %d (0x%X)\n", max_elem, max_elem);

        if (chunks_mgr && max_elem > 0 && max_elem < 2000000) {
            std::printf("[test-gobj] PIPELINE OK — chunks_manager and max look valid\n");
        } else {
            std::printf("[test-gobj] pipeline gave implausible values; review constants\n");
        }
        std::printf("[test-gobj] TODO: chunk-ptr-array access requires emulating\n");
        std::printf("[test-gobj]       VMProtected vtable[7] @ chunks_manager[0x38]\n");
        return 0;
    }

    if (!do_sdk && !do_test && !do_dump && !do_probe && !do_emu_smoke && !do_emu_fname) {
        do_test = true;
        do_dump = true;
    }

    if (pid == 0) {
        std::cout << "[*] No PID supplied – scanning /proc ...\n";
        pid = FindARCPid();
        if (pid > 0)
            std::cout << "[+] Found ARC Raiders PID: " << pid << "\n";
    }
    if (pid <= 0) { print_help(); return 1; }

    SDKDumper dumper(pid);

    // --emu-smoke / --emu-fname run before the heavy dumper Init() so they
    // work even when the game is mid-loading (chunk-ptr decrypt unavailable).
    if (do_emu_smoke) {
        std::printf("\n=== emu smoke test ===\n");
        if (!dumper.m_reader.Open(pid)) {
            std::printf("[emu-smoke] /dev/memreader open failed\n"); return 1;
        }
        EmuEngine eng;
        if (!eng.Initialize(&dumper.m_reader, dumper.MODULE_BASE, 0xE9AF000,
                "/media/frost/Coding Stuf/Linux/FrostBinaryDumper/Arc_Raiders_Binary_20260421_160408.exe")) {
            std::printf("[emu-smoke] init failed\n"); return 1;
        }
        uint64_t probe = dumper.MODULE_BASE + 0x22F9A4;
        bool ok = eng.MapGamePage(probe);
        std::printf("[emu-smoke] MapGamePage(0x%llX) → %s\n",
            (unsigned long long)probe, ok ? "mapped" : "FAILED");
        uint8_t bytes[16] = {};
        if (ok && eng.EmuRead(probe, bytes, 16)) {
            std::printf("[emu-smoke] first 16 bytes:");
            for (int i = 0; i < 16; ++i) std::printf(" %02X", bytes[i]);
            std::printf("\n");
        }
        if (!do_test && !do_dump && !do_sdk && !do_probe && !do_emu_fname) return 0;
    }

    if (do_emu_fname) {
        std::printf("\n=== emu FName decrypt (CI=%u) ===\n", emu_fname_ci);
        if (!dumper.m_reader.IsOpen() && !dumper.m_reader.Open(pid)) {
            std::printf("[emu-fname] /dev/memreader open failed\n"); return 1;
        }
        auto findRes = FNameFuncFinder::Find(dumper.m_reader, dumper.MODULE_BASE);
        if (!findRes.found) {
            std::printf("[emu-fname] couldn't locate FName decrypt in .text\n"); return 1;
        }
        EmuEngine eng;
        if (!eng.Initialize(&dumper.m_reader, dumper.MODULE_BASE, 0xE9AF000,
                "/media/frost/Coding Stuf/Linux/FrostBinaryDumper/Arc_Raiders_Binary_20260421_160408.exe")) {
            std::printf("[emu-fname] engine init failed\n"); return 1;
        }
        EmuFName fn;
        if (!fn.Init(&eng, dumper.MODULE_BASE, findRes.best_target_rva)) {
            std::printf("[emu-fname] EmuFName init failed\n"); return 1;
        }
        fn.SetGamePeb(0x7FFD0000ULL);
        eng.MapGamePage(0x7FFD0000ULL);
        std::string s = fn.DecryptByIndex(emu_fname_ci);
        std::printf("[emu-fname] CI %u → \"%s\"\n", emu_fname_ci, s.c_str());
        if (!do_test && !do_dump && !do_sdk && !do_probe) return 0;
    }

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
