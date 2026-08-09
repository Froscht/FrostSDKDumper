// =============================================================================
// ARC Raiders – External SDK Dumper (newest patch)
//
// Build:  g++ -O2 -std=c++17 -mavx2 -o FrostDumper main.cpp -lcapstone
// Run:    sudo ./FrostDumper <pid>          (PID of ARC Raiders / wine process)
//         sudo ./FrostDumper                (uses auto-detect via /proc)
//
// No flags needed — the default does the full automatic pipeline:
//   1. /dev/memreader open + sig-scan auto-discovery of all critical RVAs
//   2. Sig-scan FName decrypt fn + auto-discover pipeline constants
//   3. Enumerate GObjects via canonical chunks_manager vtable[7] path
//   4. Walk every UClass/UStruct/UEnum and emit sdk/SDK_Output.txt
//
// Requires:  kernel module loaded (sudo insmod ../KernelDriver/src/memreader.ko)
// Output:    dump_objects.txt    – full object list (idx, addr, name)
//            dump_names.txt      – unique FNames sorted
//            dump_classes.txt    – objects with a class prefix e.g. /Script/...
//            dump_log.txt        – timestamped run log
//            sdk/SDK_Output.txt      – full SDK struct/enum output
// =============================================================================

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <chrono>
#include <iomanip>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <immintrin.h>
#include <glob.h>

#include "memreader_ioctl.h"
#include "memreader_iface.h"
#include "arc_decrypt.h"
#include "sig_scan.h"
#include "sig_scanner_v2.h"
#include "insn_decoder.h"
#include "func_analyzer.h"
#include "find_fname_func.h"
#include "gobjects.h"
#include "fname_decrypt.h"
using FNameDecryptor = FName::FNameDecryptor;
#include "auto_offsets.h"
#include "auto_export.h"
#include "config_loader.h"
#include "sdk_generator.h"

// ─────────────────────────────────────────────────────────────────────────────
// PE binary path — glob ARC binary files in the dumper directory and pick the
// one with the most-recent mtime. Matches multiple naming schemes the user
// has used historically: Arc_Raiders_Binary_*, pioneer_steam_*, ARC_RAIDERS_*,
// *PagesDecrypted*. Returns "" if nothing matches; callers treat that as
// "no PE fallback".
// ─────────────────────────────────────────────────────────────────────────────
static const std::string& GetPEBinaryPath() {
    static std::string cached = []() -> std::string {
        const char* dir = "/media/frost/Coding Stuf/Linux/FrostSDKDumper";
        const char* patterns[] = {
            "Arc_Raiders_Binary_*.exe",
            "pioneer_steam_*.exe",
            "ARC_RAIDERS_*.exe",
            "*PagesDecrypted*.exe",
            "*pct.exe",
        };
        std::string best;
        time_t bestMtime = 0;
        for (const char* pat : patterns) {
            std::string fullPat = std::string(dir) + "/" + pat;
            glob_t g{};
            if (glob(fullPat.c_str(), 0, nullptr, &g) == 0) {
                for (size_t i = 0; i < g.gl_pathc; ++i) {
                    std::string p = g.gl_pathv[i];
                    struct stat st{};
                    if (stat(p.c_str(), &st) != 0) continue;
                    if (st.st_mtime > bestMtime) {
                        bestMtime = st.st_mtime;
                        best = p;
                    }
                }
            }
            globfree(&g);
        }
        if (!best.empty())
            std::printf("[pe] PE binary auto-selected: %s\n", best.c_str());
        else
            std::printf("[pe] no PE binary found in %s — PE fallback disabled\n", dir);
        return best;
    }();
    return cached;
}

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
        if (pid == target_pid && pid != 0) return true;
        pid = target_pid;
        if (fd < 0) {
            fd = open("/dev/memreader", O_RDWR);
            if (fd < 0) {
                std::printf("[!] /dev/memreader unavailable (%s) — falling back to process_vm_readv only\n",
                    std::strerror(errno));
            }
        }
        return true;
    }

    bool IsOpen() const { return pid > 0; }

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

    KernelReader               m_reader;
    FNameDecryptor             m_fname;
    gobjects::GObjectArray     m_gobj;
    int                        m_pid;
    SigScanV2::Scanner         m_sigScanner;  // Zydis-aware module cache for autodiscovery
    SigScan::PEFileReader      m_sigPe;       // shared PE fallback for legacy SigScan (open once)
    bool                       m_sigPeReady = false;
    ConfigLoader::LoadResult   m_configResult;
    int                        m_boneArrayOffset = 0xE8;

    std::unordered_map<uint64_t, std::string> m_cachedAddrToName;
    std::unordered_map<uint64_t, std::string> m_cachedAddrToFullname;
    std::vector<std::pair<int32_t, uint64_t>> m_cachedObjectPtrs;
    bool m_hasCachedNames = false;

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

        AutoDiscovery::g_DiscoveredBounds =
            AutoDiscovery::DiscoverModuleBounds(m_reader, MODULE_BASE);

        m_configResult = ConfigLoader::LoadDiscoveryConfig("decrypt_export.json");
        const uint64_t ModuleSize = AutoDiscovery::g_DiscoveredBounds.Valid
            ? AutoDiscovery::g_DiscoveredBounds.ImageSize
            : 0xE900000ULL;

        // ── Open the on-disk PE early ──────────────────────────────────
        // Phase 8 (FFieldClass globals) needs PE-on-disk because the
        // FFieldClass ctor sub_3E80E0 is VMProtected: live module bytes
        // don't match the PE. Hoisting m_sigPe init here lets every later
        // phase use the on-disk fallback without waiting for the legacy
        // sigscan block.
        {
            const std::string& pe_path = GetPEBinaryPath();
            if (!m_sigPeReady && !pe_path.empty() && m_sigPe.Open(pe_path.c_str())) {
                m_sigPeReady = true;
            }
        }

        // ── Phase 0b: SigScanV2 — full module cache + Zydis-aware scanner ──
        // Replaces the page-streaming legacy SigScan for everything that
        // needs Zydis disassembly. The legacy SigScan stays around for the
        // first 6 anchors (GObjectArray, GWorld, GNames, key table, SIMD
        // tables) since those are deeply baked into init.
        if (!m_sigScanner.Initialize(m_reader, MODULE_BASE)) {
            std::printf("[autodisc] SigScanV2 init failed — Zydis-driven phases disabled\n");
        } else {
            // Re-derive bounds from the scanner's section table — more accurate
            // than the standalone PE parse (catches multi-`.data` segments etc.).
            AutoDiscovery::g_DiscoveredBounds =
                AutoDiscovery::DiscoverModuleBoundsFromScanner(m_sigScanner);

            // ── Phase 2c/2d: FField + FProperty layout from code ──────
            // Must run FIRST — Theia randomizes struct layouts per session.
            // All subsequent phases depend on correct offsets.
            {
                std::printf("\n=== Phase 2c: FField layout from binary code ===\n");
                AutoDiscovery::g_DiscoveredFFieldLayout =
                    AutoDiscovery::DiscoverFFieldLayoutFromCode(
                        m_sigScanner, m_reader, MODULE_BASE);

                std::printf("\n=== Phase 2d: FProperty layout from binary code ===\n");
                AutoDiscovery::g_DiscoveredFPropertyLayout =
                    AutoDiscovery::DiscoverFPropertyLayoutFromCode(
                        m_sigScanner, m_reader, MODULE_BASE);

                AutoDiscovery::ApplyDiscoveredLayouts(
                    AutoDiscovery::g_DiscoveredFFieldLayout,
                    AutoDiscovery::g_DiscoveredFPropertyLayout);
            }

            // ── Phase 3: FProperty Offset_Internal XOR key ─────────────
            if (AutoDiscovery::g_DiscoveredFProperty.Valid) {
                std::printf("[autodisc] Phase 3 skipped — FProperty offset XOR loaded from config (0x%08X)\n",
                    AutoDiscovery::g_DiscoveredFProperty.XorKey);
            } else {
                AutoDiscovery::g_DiscoveredFProperty =
                    AutoDiscovery::DiscoverFPropertyOffsetXor(m_sigScanner);
                if (AutoDiscovery::g_DiscoveredFProperty.Valid) {
                    uint32_t Hard = ArcDecrypt::Patch20260421::g_PropertyOffsetXor;
                    uint32_t Live = AutoDiscovery::g_DiscoveredFProperty.XorKey;
                    if (Live == Hard) {
                        std::printf("[autodisc] FProperty Offset XOR matches constant 0x%08X\n", Live);
                    } else {
                        std::printf("[autodisc] FProperty Offset XOR drift: 0x%08X → 0x%08X (auto-fixed)\n",
                            Hard, Live);
                        ArcDecrypt::Patch20260421::g_PropertyOffsetXor = Live;
                    }
                }
            }

            // ── Phase 2b: FField NamePrivate SIMD masks ──────────────
            if (AutoDiscovery::g_DiscoveredFFieldMasks.Valid) {
                std::printf("[autodisc] Phase 2b skipped — FField name masks loaded from config\n");
            } else {
                AutoDiscovery::g_DiscoveredFFieldMasks =
                    AutoDiscovery::DiscoverFFieldNameMasks(
                        m_sigScanner, m_reader, MODULE_BASE,
                        AutoDiscovery::g_DiscoveredBounds);
            }

            if (!AutoDiscovery::g_DiscoveredSlotV709.Valid) {
                std::printf("\n=== Phase 4b: UObject slot decrypt (v709-style) ===\n");
                AutoDiscovery::g_DiscoveredSlotV709 =
                    AutoDiscovery::DiscoverUObjSlotV709(m_sigScanner);
            }
            if (AutoDiscovery::g_DiscoveredSlotV709.Valid) {
                AutoDiscovery::g_UseV709SlotHash = true;
                AutoDiscovery::g_UseV707SlotHash = false;
                const auto& Sv = AutoDiscovery::g_DiscoveredSlotV709;
                std::printf("[autodisc] Phase 4: auto-discovered V709 slot (ROL64=%d, PSHUFLW=0x%02X, ROL32=%d, %d sites)\n",
                    Sv.Rol64First, Sv.PshuflwImm, Sv.Rol32Per, Sv.SiteCount);
            } else {
                namespace V709 = ArcDecrypt::v20260709;
                AutoDiscovery::g_UseV709SlotHash = true;
                AutoDiscovery::g_UseV707SlotHash = false;
                std::printf("[autodisc] Phase 4: fallback V709 slot constants (ROL64=%d, PSHUFLW=0x%02X, ROL32=%d)\n",
                    V709::UOBJ_SLOT_ROL64_FIRST, V709::UOBJ_SLOT_PSHUFLW, V709::UOBJ_SLOT_ROL32_PER);
            }

            {
                std::printf("\n=== Phase 4c: QD generic UObject slot recorder ===\n");
                AutoDiscovery::g_DiscoveredQDSlot =
                    AutoDiscovery::QDDiscoverUObjSlot(m_sigScanner);
                if (AutoDiscovery::g_DiscoveredQDSlot.Valid) {
                    std::printf("[autodisc] Phase 4c: QD slot program recorded (%d ops, %d sites)\n",
                        AutoDiscovery::g_DiscoveredQDSlot.Program.OpCount,
                        AutoDiscovery::g_DiscoveredQDSlot.SiteCount);
                }
            }

            // ── Phase 7: FFieldClass NamePrivate decode pipeline ───────
            if (AutoDiscovery::g_DiscoveredFFieldClassName.Valid) {
                std::printf("[autodisc] Phase 7 skipped — FFieldClass name decrypt loaded from config (xor=0x%016llX)\n",
                    (unsigned long long)AutoDiscovery::g_DiscoveredFFieldClassName.XorLo64);
            } else {
                AutoDiscovery::g_DiscoveredFFieldClassName =
                    AutoDiscovery::DiscoverFFieldClassNameDecrypt(
                        m_sigScanner, m_reader, MODULE_BASE);
                if (AutoDiscovery::g_DiscoveredFFieldClassName.Valid) {
                    std::printf("[autodisc] FFieldClass NamePrivate auto-discovered: "
                                "name_off=+0x%X fclass_off=+0x%X xor_lo64=0x%016llX (%d sites)\n",
                        AutoDiscovery::g_DiscoveredFFieldClassName.NamePrivateOffset,
                        AutoDiscovery::g_DiscoveredFFieldClassName.FFieldClassOffset,
                        (unsigned long long)AutoDiscovery::g_DiscoveredFFieldClassName.XorLo64,
                        AutoDiscovery::g_DiscoveredFFieldClassName.ConsensusSiteCount);
                }
            }

            // ── Phase 8: enumerate FFieldClass init callers → (RVA, name) ─
            if (!AutoDiscovery::g_DiscoveredFClassGlobals.empty()) {
                std::printf("[autodisc] Phase 8 skipped — %zu FFieldClass globals loaded from config\n",
                    AutoDiscovery::g_DiscoveredFClassGlobals.size());
            } else {
                if (m_sigPeReady) {
                    AutoDiscovery::g_DiscoveredFClassGlobals =
                        AutoDiscovery::DiscoverFFieldClassGlobals(
                            m_sigPe, AutoDiscovery::g_DiscoveredBounds);
                }
                if (!AutoDiscovery::g_DiscoveredFClassGlobals.empty()) {
                    std::printf("[autodisc] FFieldClass globals discovered: %zu (%s, %s, ...)\n",
                        AutoDiscovery::g_DiscoveredFClassGlobals.size(),
                        AutoDiscovery::g_DiscoveredFClassGlobals[0].TypeName.c_str(),
                        AutoDiscovery::g_DiscoveredFClassGlobals.size() > 1
                            ? AutoDiscovery::g_DiscoveredFClassGlobals[1].TypeName.c_str()
                            : "—");
                }
            }
        }

        // ── Signature scan — patch-resilient RVA auto-discovery ─────────
        // Hardcoded RVAs in arc_decrypt.h are the primary source and remain
        // correct for the current patch. The scanner runs alongside and
        // overwrites any RVA it resolves to a different value (i.e. after
        // a future patch). Scan failures fall back to the hardcoded value.
        {
            SigScan::Scanner<KernelReader> scan(m_reader, MODULE_BASE, ModuleSize);
            if (AutoDiscovery::g_DiscoveredBounds.Valid) {
                const auto& B = AutoDiscovery::g_DiscoveredBounds;
                scan.SetSectionBounds(B.TextRva, B.TextEnd(),
                                      B.RDataRva, B.RDataEnd(),
                                      B.DataRva, B.DataEnd());
                std::printf("[sig] Dynamic section bounds from PE header: "
                            ".text=0x%llX-0x%llX .rdata=0x%llX-0x%llX .data=0x%llX-0x%llX\n",
                            (unsigned long long)B.TextRva, (unsigned long long)B.TextEnd(),
                            (unsigned long long)B.RDataRva, (unsigned long long)B.RDataEnd(),
                            (unsigned long long)B.DataRva, (unsigned long long)B.DataEnd());
            }
            const std::string& pe_path = GetPEBinaryPath();
            if (!m_sigPeReady && !pe_path.empty() && m_sigPe.Open(pe_path.c_str())) {
                m_sigPeReady = true;
            }
            if (m_sigPeReady) {
                scan.SetPEFallback(&m_sigPe);
                std::printf("[sig] PE fallback enabled: %s\n", pe_path.c_str());
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
            auto applyTrusted = [](const char* name, uint64_t& slot, uint64_t dyn) {
                constexpr uint64_t kTolerance = 0x1000000ULL;
                if (!dyn) {
                    std::printf("[sig] %-14s scan failed; using config 0x%llX\n",
                        name, (unsigned long long)slot);
                    return;
                }
                uint64_t Diff = dyn > slot ? dyn - slot : slot - dyn;
                if (dyn == slot) {
                    std::printf("[sig] %-14s 0x%llX (matches config)\n",
                        name, (unsigned long long)dyn);
                } else if (Diff > kTolerance) {
                    std::printf("[sig] %-14s 0x%llX scan diverges from config 0x%llX (Δ=0x%llX); keeping config\n",
                        name, (unsigned long long)dyn, (unsigned long long)slot,
                        (unsigned long long)Diff);
                } else {
                    std::printf("[sig] %-14s 0x%llX → 0x%llX (patch drift — auto-fixed)\n",
                        name, (unsigned long long)slot, (unsigned long long)dyn);
                    slot = dyn;
                }
            };
            auto applyStrict = [](const char* name, uint64_t& slot, uint64_t dyn) {
                if (!dyn) {
                    std::printf("[sig] %-14s scan failed; using config 0x%llX (strict)\n",
                        name, (unsigned long long)slot);
                    return;
                }
                if (dyn == slot) {
                    std::printf("[sig] %-14s 0x%llX (matches config, strict)\n",
                        name, (unsigned long long)dyn);
                } else {
                    std::printf("[sig] %-14s scan=0x%llX config=0x%llX (strict — keeping config)\n",
                        name, (unsigned long long)dyn, (unsigned long long)slot);
                }
            };
            applyTrusted("GObjectArray", ArcDecrypt::RVA_GOBJECT_ARRAY_BASE, scan.FindGObjectArrayRVA());
            // GWorld auto-discovery moved to Phase 0.5 — the legacy sigscan
            // here picks a sibling global within tolerance and silently
            // overwrites the working RVA. Phase 0.5 sigscans for the canonical
            // double-deref shape and live-validates each candidate via UWorld
            // → PersistentLevel → Actors, so it can never substitute garbage.
            applyTrusted("GNames",       ArcDecrypt::RVA_GNAMES_BASE,        scan.FindGNamesRVA());
            applyTrusted("FNameKeyTbl",  ArcDecrypt::RVA_FNAME_KEY_TABLE,
                  scan.FindFNameKeyTableRVA(ArcDecrypt::RVA_FNAME_KEY_TABLE,
                                            ArcDecrypt::RVA_GNAMES_BASE));
            auto st = scan.FindObjArraySimdTables();
            apply("SimdObjXor",   ArcDecrypt::RVA_SIMD_OBJARRAY_XOR, st.decrypt_key);
            apply("ElemMaskA",    ArcDecrypt::RVA_ELEM_MASK_A,       st.elem_mask_a);
            apply("ElemMaskB",    ArcDecrypt::RVA_ELEM_MASK_B,       st.elem_mask_b);
            apply("ElemXorKey",   ArcDecrypt::RVA_ELEM_XOR_KEY,      st.elem_xor_key);
            apply("CIdxXor1",     ArcDecrypt::RVA_CIDX_XOR1,         scan.FindCIdxXor1RVA());
        }

        // ── Phase 0.5: full GWorld discovery (sigscan → live-validate) ──
        if (AutoDiscovery::g_DiscoveredWorld.Valid) {
            std::printf("[autodisc] Phase 0.5 skipped — GWorld loaded from config (rva=0x%llX)\n",
                (unsigned long long)AutoDiscovery::g_DiscoveredWorld.GWorldRva);
        } else if (m_sigPeReady) {
            AutoDiscovery::g_DiscoveredWorld = AutoDiscovery::DiscoverGWorld(
                m_sigScanner, m_reader, MODULE_BASE,
                AutoDiscovery::g_DiscoveredBounds);
        }
        if (AutoDiscovery::g_DiscoveredWorld.Valid) {
            uint64_t Hard = ArcDecrypt::RVA_GWORLD;
            uint64_t Live = AutoDiscovery::g_DiscoveredWorld.GWorldRva;
            if (Live == Hard) {
                std::printf("[autodisc] GWorld RVA matches constant 0x%llX\n",
                    (unsigned long long)Live);
            } else {
                std::printf("[autodisc] GWorld RVA drift: 0x%llX → 0x%llX (live-validated, auto-fixed)\n",
                    (unsigned long long)Hard, (unsigned long long)Live);
                ArcDecrypt::RVA_GWORLD = Live;
            }
            uint32_t HardPL = (uint32_t)ArcDecrypt::Offsets::UWorld::PersistentLevel;
            uint32_t LivePL = AutoDiscovery::g_DiscoveredWorld.PersistentLevelOffset;
            if (LivePL == HardPL)
                std::printf("[autodisc] UWorld::PersistentLevel matches constant 0x%X\n", LivePL);
            else
                std::printf("[autodisc] UWorld::PersistentLevel drift: 0x%X → 0x%X (probe-found)\n",
                    HardPL, LivePL);
        } else {
            std::printf("[autodisc] GWorld phase did not validate (expected if game is in main menu); "
                        "keeping compile-time RVA 0x%llX\n",
                (unsigned long long)ArcDecrypt::RVA_GWORLD);
        }

        // Earliest snapshot — fires before any failure-prone live-memory
        // bootstrapping (FName key table read, GObjectArray init).
        // Captures auto-discovery output even when later phases bail out.
        AutoExport::WriteAll("decrypt_export.json", MODULE_BASE);

        // Init FName key table + SIMD tables
        if (!m_fname.Init()) {
            std::cerr << "[-] Failed to read FName key table / SIMD tables\n";
            return false;
        }
        std::cout << "[+] FName decryptor initialized\n";

        // ── Auto-discover FName function + pipeline constants ────────────────
        DiscoverFNameConsts();

        // ── Optional: capture SIMD chunk_table-decrypt XOR key live ──────
        // The chunk_table-decrypt function reads the Wine PEB pointer from
        // gs:[0x60] and adds 0x647A6348. We can't read gs:[0x60] from
        // outside without ptrace, and Wine's PEB layout is not Windows-
        // canonical (sig-scan for *(PEB+0x10) == m_base only finds 1 hit
        // and it's not the real PEB). Instead, set a uprobe right after
        // the `add rax, gs:[0x60]` and capture the resulting rax — that
        // IS the key we need. The game calls this function continuously
        // (every chunks_manager+0xB0 read during GC / name resolution),
        // so a 200 ms wait is more than enough. Best-effort: failure
        // here just falls through to the existing PEB sweep + heap-scan
        // probe, both of which still work.
        CaptureSimdPebKey();

        // ── GObjectArray init: 3-tier auto-discovery ─────────────────────
        // Tier 1: GUObjectArray field-layout BFS — works when chunks-array
        //         is discoverable via structural probing.
        // Tier 2: structural heap scan — last resort, slow but always works.
        m_gobj.SetPid(m_pid);
        m_gobj.SetNameProbe([this](uint64_t Obj) -> std::string {
            return m_fname.GetName(Obj);
        });
        bool gobj_ok = false;

        AutoExport::WriteAll("decrypt_export.json", MODULE_BASE);

        // Tier 0: CL-1325322 chunks_manager path. Goes first because its
        // result is checked against the FUObjectItem InternalIndex invariant,
        // which is ground truth — the structural tiers below only ever produce
        // "looks array-shaped" candidates.
        {
            int NumChunks = 0;
            int32_t NumElements = 0;
            uint64_t Arr = m_gobj.DiscoverChunkArrayV808(NumChunks, NumElements);
            if (Arr && NumChunks > 0 &&
                m_gobj.InitFromChunksCanonical(Arr, NumChunks, NumElements))
            {
                std::cout << "[+] GObjectArray initialized via v808 chunks_manager ("
                          << m_gobj.GetNumElements() << " objects)\n";
                gobj_ok = true;
            }
        }

        // Tier 1: layout BFS
        if (!gobj_ok) {
            AutoDiscovery::g_DiscoveredGObjLayout =
                AutoDiscovery::DiscoverGUObjectArrayLayout(
                    m_reader, MODULE_BASE, ArcDecrypt::RVA_GOBJECT_ARRAY_BASE,
                    AutoDiscovery::g_DiscoveredBounds);
            if (AutoDiscovery::g_DiscoveredGObjLayout.Valid) {
                const auto& L = AutoDiscovery::g_DiscoveredGObjLayout;
                if (m_gobj.InitFromChunksCanonical(L.ChunksArrayPtr, L.NumChunks,
                                                   (int)L.NumElements)) {
                    std::cout << "[+] GObjectArray initialized via auto-discovered layout ("
                              << m_gobj.GetNumElements() << " objects, no decrypt needed)\n";
                    gobj_ok = true;
                }
            }
        }

        // Tier 2: structural heap scan
        if (!gobj_ok) {
            std::cout << "[+] Going straight to structural scan (no auto-discoverable layout)\n";
            if (!m_gobj.Init()) {
                std::cerr << "[-] GObjectArray direct init failed, trying world traversal...\n";
                m_gobj.PrintDiagnostics();
                if (!CollectWorldObjects()) {
                    std::cerr << "[-] World traversal also failed. Aborting.\n";
                    return false;
                }
            }
            std::cout << "[+] GObjectArray initialized (" << m_gobj.GetNumElements() << " objects)\n";
            gobj_ok = true;
        }

        // Patch resilience: with GObjects up and the runtime ENTRY_HANDLE_XOR
        // settled, sample objects to find which inline-handle offset works
        // best on this build. Sets the FNameDecryptor primary so GetName tries
        // it first instead of walking the legacy candidate list every call.
        if (gobj_ok) CalibrateInlineHandleOffset();

        // ── Phase 0.6: FName sanity check ───────────────────────────────
        // Runs after FName boot + GObjects + handle calibration. Prefers
        // the validated GWorld actor sample (best signal: known-good live
        // UObjects from a fresh tick), but falls back to the structural
        // scan's seed list when the game is in main menu / no world loaded.
        // Without the fallback the auto-flip would never fire on patch days
        // where the user can't yet get into a match.
        {
            AutoDiscovery::NameResolver SanityResolver = [this](uint64_t Obj) -> std::string {
                return m_fname.GetName(Obj);
            };
            std::vector<uint64_t> SanitySample;
            const char* SanitySource = "(none)";
            if (AutoDiscovery::g_DiscoveredWorld.Valid &&
                !AutoDiscovery::g_DiscoveredWorld.Actors.empty())
            {
                SanitySample = AutoDiscovery::g_DiscoveredWorld.Actors;
                SanitySource = "GWorld actor sample";
            } else {
                // Pull a random-ish slice from the structural-scan seed list.
                const auto& Seeds = m_gobj.GetSeedObjects();
                size_t TakeN = std::min<size_t>(Seeds.size(), 64);
                size_t Step = Seeds.size() / std::max<size_t>(TakeN, 1);
                if (Step == 0) Step = 1;
                for (size_t I = 0; I < Seeds.size() && SanitySample.size() < TakeN; I += Step) {
                    if (Seeds[I]) SanitySample.push_back(Seeds[I]);
                }
                SanitySource = "GObjects seed sample (no GWorld)";
            }

            if (SanitySample.empty()) {
                std::printf("[!] FName sanity check skipped — no objects to sample\n");
            } else {
                std::printf("[autodisc-fnchk] sanity sample source: %s (%zu objects)\n",
                    SanitySource, SanitySample.size());
                AutoDiscovery::g_DiscoveredFNameSanity =
                    AutoDiscovery::ValidateFNameOnActors(SanitySample, SanityResolver);
                if (!AutoDiscovery::g_DiscoveredFNameSanity.Valid) {
                    std::printf("[!] FName sanity check FAILED — static decrypt "
                                "pipeline is broken on this patch. "
                                "Investigate FName pipeline (key table, SIMD const, "
                                "entry handle XOR, slot decrypt).\n");
                }
            }
        }

        // ── Phase 0.7: UWorld map-state classification ──────────────────
        // FName resolution quality is dramatically lower in main-menu /
        // loading state than in-match (≥85% naming rate vs ~40-72%). The
        // dumper still produces output but it's degraded — and degraded
        // FName cascades into wrong cluster scoring (Phase 1), missing
        // FFieldClass canonical-name matches (Phase 7), and incomplete
        // SDK structs/classes. Resolve UWorld's FName and classify per UE
        // convention: empty name OR contains Menu/Lobby/Loading/Title/
        // Frontend → main-menu state. Log loudly so the user knows the
        // dump quality is environmental, not a code bug.
        //
        // Classification logic mirrors NewESP's arc_pointer_cache.cpp:55-95.
        // Resolve UWorld pointer: prefer the auto-discovered Valid path; fall
        // back to reading the compile-time RVA (may still be correct on a
        // patch where Phase 0.5's stricter validator rejected all candidates
        // even though the hardcoded slot still works).
        uint64_t UWorldPtr = 0;
        if (AutoDiscovery::g_DiscoveredWorld.Valid &&
            AutoDiscovery::g_DiscoveredWorld.GWorldAbs)
        {
            UWorldPtr = AutoDiscovery::g_DiscoveredWorld.GWorldAbs;
        } else if (AutoDiscovery::g_DiscoveredBounds.Valid) {
            // Try compile-time GWorld RVAs as a fallback. NewESP's verified
            // CL-1177146 value is 0xE07CFD8; the FrostSDKDumper compile-time
            // is 0xDFDB4D8 (older patch). UE5 GWorld is double-deref on this
            // build (the .data slot holds a pointer-to-pointer for stable
            // hot-reload), so single-deref candidates are silently rejected
            // here — they typically point at unrelated UObjects (e.g. the
            // current Discovery-tab item) and would mislabel the map.
            //
            // VALIDATION: candidate must pass the same PL+Actors+Levels[0]
            // check that auto_discovery's Phase 0.5 runs. A vtable-in-module
            // check alone isn't enough — every UObject passes that, and an
            // un-validated candidate produced wrong map names like
            // 'ApiGatewayDiscoveryGameItem' from non-UWorld pointers.
            const uint64_t kCandidateRvas[] = {
                ArcDecrypt::RVA_GWORLD,   // current dumper compile-time
                0xE07CFD8ULL,             // NewESP-verified CL-1177146
            };
            for (uint64_t Rva : kCandidateRvas) {
                uint64_t Slot = 0;
                if (!m_reader.Read(MODULE_BASE + Rva, &Slot, 8) || !Slot) continue;
                if (Slot < 0x10000ULL || Slot >= 0x800000000000ULL) continue;
                uint64_t Inner = 0;
                if (!m_reader.Read(Slot, &Inner, 8) || !Inner) continue;
                if (Inner < 0x10000ULL || Inner >= 0x800000000000ULL) continue;
                uint32_t PlOff = 0, AlOff = 0, AcOff = 0;
                int Actors = 0;
                if (AutoDiscovery::ValidateUWorldCandidate(
                        m_reader, MODULE_BASE, Inner,
                        AutoDiscovery::g_DiscoveredBounds,
                        PlOff, AlOff, AcOff, Actors))
                {
                    UWorldPtr = Inner;
                    std::printf("[autodisc-mapstate] resolved UWorld via double-deref @ RVA 0x%llX -> 0x%llX -> 0x%llX (PL+0x%X Actors+0x%X count=%d)\n",
                        (unsigned long long)Rva,
                        (unsigned long long)Slot,
                        (unsigned long long)UWorldPtr,
                        PlOff, AlOff, Actors);
                    break;
                }
            }
        }
        if (UWorldPtr)
        {
            std::string MapName = m_fname.GetName(UWorldPtr);
            auto ContainsCi = [&](const char* needle) -> bool {
                size_t n = std::strlen(needle);
                if (MapName.size() < n) return false;
                for (size_t i = 0; i + n <= MapName.size(); ++i) {
                    bool ok = true;
                    for (size_t j = 0; j < n; ++j) {
                        char a = MapName[i+j], b = needle[j];
                        if (a >= 'A' && a <= 'Z') a = char(a - 'A' + 'a');
                        if (b >= 'A' && b <= 'Z') b = char(b - 'A' + 'a');
                        if (a != b) { ok = false; break; }
                    }
                    if (ok) return true;
                }
                return false;
            };
            bool InMatch = !MapName.empty()
                        && !ContainsCi("Menu")
                        && !ContainsCi("Lobby")
                        && !ContainsCi("Loading")
                        && !ContainsCi("Title")
                        && !ContainsCi("Frontend");
            if (InMatch) {
                std::printf("[autodisc-mapstate] UWorld map = '%s' (in-match — SDK quality optimal)\n",
                    MapName.c_str());
            } else {
                std::printf("\n");
                std::printf("[!] ====================================================================\n");
                std::printf("[!] WARNING: UWorld in main-menu / loading state\n");
                std::printf("[!]   Map name: '%s'\n", MapName.c_str());
                std::printf("[!]   FName resolution quality is significantly degraded in this state.\n");
                std::printf("[!]   Expected naming rate: 30-70%% (vs 85%%+ in-match).\n");
                std::printf("[!]   SDK output will have ~30-50%% of baseline class/struct/enum counts.\n");
                std::printf("[!]   To get a full-quality dump: launch a match, then re-run the dumper.\n");
                std::printf("[!] ====================================================================\n");
                std::printf("\n");
            }
        } else {
            std::printf("[autodisc-mapstate] UWorld unavailable (Phase 0.5 + compile-time RVA both empty) — game likely in main-menu / loading\n");
            std::printf("[!] SDK quality will be reduced. To get baseline counts: launch a match first.\n");
        }

        // ── Phase 1: auto-discover engine type-pool vtables ─────────────
        // With FName resolution working and the seed object list populated
        // (canonical vtable[7] OR structural fallback), cluster all sampled
        // UObjects by vtable[0] and identify each kind via name oracles.
        // Replaces the 13 hardcoded vtable RVAs in main.cpp/gobjects.h —
        // patch-resilient. After discovery, re-run vtable scan to pick up
        // heap arena hits (UScriptStruct, UEnum, BPGCs) that the canonical
        // walk misses.
        if (gobj_ok && AutoDiscovery::g_DiscoveredBounds.Valid) {
            AutoDiscovery::NameResolver Resolver = [this](uint64_t Obj) -> std::string {
                return m_fname.GetName(Obj);
            };
            auto ConfigVT = AutoDiscovery::g_DiscoveredVTables;
            AutoDiscovery::g_DiscoveredVTables = AutoDiscovery::DiscoverEngineVTables(
                m_gobj.GetSeedObjects(), Resolver, m_reader, MODULE_BASE,
                AutoDiscovery::g_DiscoveredBounds);
            {
                auto& VT = AutoDiscovery::g_DiscoveredVTables;
                auto Merge = [](uint64_t& Live, uint64_t Cfg, const char* Name) {
                    if (Live && Cfg && Cfg != Live) {
                        std::printf("[autodisc] Phase 1 merge: %s config=0x%llX live=0x%llX → keeping LIVE (auto-discovered)\n",
                            Name, (unsigned long long)Cfg, (unsigned long long)Live);
                    } else if (!Live && Cfg) {
                        std::printf("[autodisc] Phase 1 merge: %s config=0x%llX (live=0) → using config fallback\n",
                            Name, (unsigned long long)Cfg);
                        Live = Cfg;
                    }
                };
                Merge(VT.ScriptStructRVA, ConfigVT.ScriptStructRVA, "ScriptStruct");
                Merge(VT.ClassNativeRVA,  ConfigVT.ClassNativeRVA,  "Class");
                Merge(VT.FunctionRVA,     ConfigVT.FunctionRVA,     "Function");
                Merge(VT.EnumRVA,         ConfigVT.EnumRVA,         "Enum");
                Merge(VT.PackageRVA,      ConfigVT.PackageRVA,      "Package");
                Merge(VT.BPGCRVA,         ConfigVT.BPGCRVA,         "BPGC");
                Merge(VT.WBPGCRVA,        ConfigVT.WBPGCRVA,        "WBPGC");
                Merge(VT.SMBPGCRVA,       ConfigVT.SMBPGCRVA,       "SMBPGC");
                Merge(VT.AnimBPGCRVA,     ConfigVT.AnimBPGCRVA,     "AnimBPGC");
                if (ConfigVT.ASClassRVA && ConfigVT.ASClassRVA != VT.ASClassRVA)
                    std::printf("[autodisc] Phase 1 merge: ASClass config=0x%llX live=0x%llX → keeping LIVE (session-specific)\n",
                        (unsigned long long)ConfigVT.ASClassRVA, (unsigned long long)VT.ASClassRVA);
                if (ConfigVT.ASStructRVA && ConfigVT.ASStructRVA != VT.ASStructRVA)
                    std::printf("[autodisc] Phase 1 merge: ASStruct config=0x%llX live=0x%llX → keeping LIVE (session-specific)\n",
                        (unsigned long long)ConfigVT.ASStructRVA, (unsigned long long)VT.ASStructRVA);
            }

            // ── Phase 1.5: wide-string anchor fallback ─────────────────────
            // Phase 1 needs FName resolution AND enough sampled instances to
            // form per-kind clusters above the count gate. When either fails
            // (e.g. game in a sparse state, or naming-rate degraded), the
            // engine-core kinds (ScriptStruct/Class/Function/Enum/Package)
            // come back NOT FOUND. Phase 1.5 anchors on the kind's UTF-16
            // wide string in .rdata and walks the function body for the
            // vtable-write idiom — patch-resilient, doesn't depend on FName.
            {
                auto& VT = AutoDiscovery::g_DiscoveredVTables;
                bool needAnchor = !VT.ScriptStructRVA || !VT.ClassNativeRVA ||
                                  !VT.FunctionRVA    || !VT.EnumRVA ||
                                  !VT.PackageRVA    ||
                                  !VT.BPGCRVA       || !VT.AnimBPGCRVA ||
                                  !VT.WBPGCRVA;
                if (needAnchor) {
                    std::printf("[autodisc] Phase 1.5 (wide-string anchor) — Phase 1 left engine roots NOT FOUND\n");
                    auto anchor = AutoDiscovery::DiscoverEngineVTablesByWideStringAnchor(
                        m_sigScanner, m_reader, MODULE_BASE,
                        AutoDiscovery::g_DiscoveredBounds);
                    if (!VT.ScriptStructRVA && anchor.ScriptStructRVA)
                        VT.ScriptStructRVA = anchor.ScriptStructRVA;
                    if (!VT.ClassNativeRVA  && anchor.ClassNativeRVA)
                        VT.ClassNativeRVA  = anchor.ClassNativeRVA;
                    if (!VT.FunctionRVA     && anchor.FunctionRVA)
                        VT.FunctionRVA     = anchor.FunctionRVA;
                    if (!VT.EnumRVA         && anchor.EnumRVA)
                        VT.EnumRVA         = anchor.EnumRVA;
                    if (!VT.PackageRVA      && anchor.PackageRVA)
                        VT.PackageRVA      = anchor.PackageRVA;
                    if (!VT.BPGCRVA         && anchor.BPGCRVA)
                        VT.BPGCRVA         = anchor.BPGCRVA;
                    if (!VT.AnimBPGCRVA     && anchor.AnimBPGCRVA)
                        VT.AnimBPGCRVA     = anchor.AnimBPGCRVA;
                    if (!VT.WBPGCRVA        && anchor.WBPGCRVA)
                        VT.WBPGCRVA        = anchor.WBPGCRVA;
                }
            }

            // ── Phase 1.6: validate ScriptStruct vtable via named seed objects ──
            // Phase 1.5 often picks a parent vtable (UStruct base) instead of
            // the derived UScriptStruct vtable. Validate by scanning seed
            // objects whose names match struct-oracle names (Vector, Rotator,
            // etc.) and reading their actual vtable pointer.
            {
                auto& VT = AutoDiscovery::g_DiscoveredVTables;
                const auto& Seeds = m_gobj.GetSeedObjects();
                uint64_t WantVt = VT.ScriptStructRVA ? MODULE_BASE + VT.ScriptStructRVA : 0;

                std::unordered_map<uint64_t, int> VtHits;
                int Probed = 0;
                size_t Step = std::max<size_t>(1, Seeds.size() / 16000);
                for (size_t I = 0; I < Seeds.size() && Probed < 200; I += Step) {
                    uint64_t Obj = Seeds[I];
                    if (!Obj) continue;
                    std::string N = Resolver(Obj);
                    if (N.empty()) continue;
                    bool Match = false;
                    for (const char* Oracle : AutoDiscovery::VTableOracles::ScriptStruct) {
                        if (N == Oracle) { Match = true; break; }
                    }
                    if (!Match) continue;
                    uint64_t Vt = 0;
                    if (!m_reader.Read(Obj, &Vt, 8)) continue;
                    if (Vt < MODULE_BASE || Vt >= MODULE_BASE + AutoDiscovery::g_DiscoveredBounds.ImageSize) continue;
                    VtHits[Vt]++;
                    Probed++;
                }

                if (Probed > 0) {
                    uint64_t BestVt = 0;
                    int BestCount = 0;
                    for (auto& [Vt, Cnt] : VtHits) {
                        if (Cnt > BestCount) { BestCount = Cnt; BestVt = Vt; }
                    }
                    uint64_t BestRva = BestVt - MODULE_BASE;
                    if (BestVt && BestRva != VT.ScriptStructRVA) {
                        std::printf("[autodisc] Phase 1.6: ScriptStruct vtable corrected 0x%llX → 0x%llX (%d oracle objects probed)\n",
                            (unsigned long long)VT.ScriptStructRVA, (unsigned long long)BestRva, Probed);
                        VT.ScriptStructRVA = BestRva;
                    } else if (BestVt && BestRva == VT.ScriptStructRVA) {
                        std::printf("[autodisc] Phase 1.6: ScriptStruct vtable 0x%llX confirmed (%d oracle objects)\n",
                            (unsigned long long)VT.ScriptStructRVA, Probed);
                    }
                } else if (WantVt) {
                    int ObjsWithVt = 0;
                    size_t Step2 = std::max<size_t>(1, Seeds.size() / 16000);
                    for (size_t I = 0; I < Seeds.size() && ObjsWithVt < 1; I += Step2) {
                        uint64_t Obj = Seeds[I];
                        if (!Obj) continue;
                        uint64_t Vt = 0;
                        if (!m_reader.Read(Obj, &Vt, 8)) continue;
                        if (Vt == WantVt) ObjsWithVt++;
                    }
                    if (ObjsWithVt == 0) {
                        std::printf("[autodisc] Phase 1.6: ScriptStruct vtable 0x%llX has 0 matching objects — clearing\n",
                            (unsigned long long)VT.ScriptStructRVA);
                        VT.ScriptStructRVA = 0;
                    }
                }
            }

            // Re-run the heap vtable scan with the (possibly fresh) discovered
            // map. Idempotent — duplicates against the seed list are dropped.
            m_gobj.RunDiscoveredVtableScan();

            // ── Phase 2: FField NamePrivate XOR const (live extraction) ──
            // Skip if Phase 2c already extracted valid decode constants from
            // binary code — the code-extracted values are authoritative and
            // the data-math Phase 2 can produce false positives (e.g. XOR=0)
            // when Theia randomizes struct layouts.
            if (AutoDiscovery::g_DiscoveredFFieldLayout.Valid &&
                AutoDiscovery::g_DiscoveredFFieldLayout.XorKey != 0) {
                std::printf("[autodisc] Phase 2 skipped — FField decode constants already extracted from binary code\n");
            } else {
                std::vector<uint64_t> uss_samples;
                const auto& VT = AutoDiscovery::g_DiscoveredVTables;
                std::vector<uint64_t> WantVts;
                if (VT.ScriptStructRVA) WantVts.push_back(MODULE_BASE + VT.ScriptStructRVA);
                if (VT.ClassNativeRVA)  WantVts.push_back(MODULE_BASE + VT.ClassNativeRVA);
                if (VT.ASClassRVA)      WantVts.push_back(MODULE_BASE + VT.ASClassRVA);
                if (VT.ASStructRVA)     WantVts.push_back(MODULE_BASE + VT.ASStructRVA);
                if (VT.BPGCRVA)         WantVts.push_back(MODULE_BASE + VT.BPGCRVA);
                if (VT.WBPGCRVA)        WantVts.push_back(MODULE_BASE + VT.WBPGCRVA);
                if (VT.FunctionRVA)     WantVts.push_back(MODULE_BASE + VT.FunctionRVA);
                std::unordered_set<uint64_t> WantSet(WantVts.begin(), WantVts.end());
                for (uint64_t Obj : m_gobj.GetSeedObjects()) {
                    if (uss_samples.size() >= 64) break;
                    uint64_t Vt = 0;
                    if (!m_reader.Read(Obj, &Vt, 8)) continue;
                    if (WantSet.count(Vt)) uss_samples.push_back(Obj);
                }
                std::printf("[autodisc] Phase 2: %zu FField samples from %zu vtable families\n",
                    uss_samples.size(), WantVts.size());
                if (!uss_samples.empty()) {
                    AutoDiscovery::g_DiscoveredFFieldName =
                        AutoDiscovery::DiscoverFFieldNameDecrypt(
                            m_reader, MODULE_BASE, uss_samples);
                    if (AutoDiscovery::g_DiscoveredFFieldName.Valid) {
                        uint64_t Live = AutoDiscovery::g_DiscoveredFFieldName.XorConst;
                        uint64_t Hard = FNameDecryptor::FFIELD_NAME_XOR_CL1177146;
                        if (Live == Hard) {
                            std::printf("[autodisc] FField NamePrivate XOR matches constant 0x%016llX\n",
                                (unsigned long long)Live);
                        } else {
                            std::printf("[autodisc] FField NamePrivate XOR drift: 0x%016llX → 0x%016llX (auto-fixed)\n",
                                (unsigned long long)Hard, (unsigned long long)Live);
                        }
                    }
                }
            }

            // ── Phase 2c.5: Live-probe Owner + ClassPrivate offsets ──────
            // Requires: ChildProperties + Next offsets from Phase 2c, plus
            // GObjects seed list and vtable map from Phase 1.
            if (AutoDiscovery::g_DiscoveredFFieldLayout.Valid &&
                (!AutoDiscovery::g_DiscoveredFFieldLayout.OwnerOff ||
                 !AutoDiscovery::g_DiscoveredFFieldLayout.ClassPrivateOff)) {
                AutoDiscovery::ProbeFFieldOwnerAndClassPrivate(
                    AutoDiscovery::g_DiscoveredFFieldLayout,
                    m_reader, MODULE_BASE,
                    AutoDiscovery::g_DiscoveredBounds,
                    m_gobj.GetSeedObjects(),
                    AutoDiscovery::g_DiscoveredVTables);
                AutoDiscovery::ApplyDiscoveredLayouts(
                    AutoDiscovery::g_DiscoveredFFieldLayout,
                    AutoDiscovery::g_DiscoveredFPropertyLayout);
            }

            // ── Phase 2c.6: FProperty sub-pointer offset discovery ──────
            {
                std::printf("\n=== Phase 2c.6: FProperty sub-pointer offset ===\n");
                uint32_t SubOff = AutoDiscovery::DiscoverFPropertySubPointerOffset(
                    m_reader, MODULE_BASE,
                    AutoDiscovery::g_DiscoveredBounds,
                    m_gobj.GetSeedObjects(),
                    AutoDiscovery::g_DiscoveredVTables);
                if (SubOff) {
                    AutoDiscovery::g_DiscoveredFPropertyLayout.SubPointerOff = SubOff;
                    AutoDiscovery::ApplyDiscoveredLayouts(
                        AutoDiscovery::g_DiscoveredFFieldLayout,
                        AutoDiscovery::g_DiscoveredFPropertyLayout);
                }
            }

            // ── Phase 2f: Build live FFieldClass-to-type map ──────────
            {
                std::printf("\n=== Phase 2f: Live FFieldClass-to-type map ===\n");
                AutoDiscovery::g_LiveFClassMap = AutoDiscovery::BuildLiveFFieldClassMap(
                    m_reader, MODULE_BASE,
                    AutoDiscovery::g_DiscoveredBounds,
                    m_gobj.GetSeedObjects(),
                    AutoDiscovery::g_DiscoveredVTables);
                for (auto& [Addr, TypeName] : AutoDiscovery::g_LiveFClassMap) {
                    uint64_t Rva = Addr - MODULE_BASE;
                    bool Already = false;
                    for (const auto& G : AutoDiscovery::g_DiscoveredFClassGlobals) {
                        if (G.TargetRva == Rva) { Already = true; break; }
                    }
                    if (!Already) {
                        AutoDiscovery::FFieldClassGlobal Entry;
                        Entry.TargetRva = Rva;
                        Entry.TypeName  = TypeName;
                        AutoDiscovery::g_DiscoveredFClassGlobals.push_back(std::move(Entry));
                    }
                }
                std::printf("[live-fclass] g_DiscoveredFClassGlobals now has %zu entries\n",
                    AutoDiscovery::g_DiscoveredFClassGlobals.size());
            }

            // If code-discovered ChildProperties offset produced 0 FFields,
            // the offset is wrong for this session (Theia per-session layout
            // randomization). Clear it so auto_offsets runtime probe runs.
            // On v808 the layout is binary-derived and independently verified,
            // so an empty FClass map means the FFieldClass probe failed — not
            // that the offsets are wrong. Resetting them here would replace
            // correct values with stale CL-1299607 constants and poison every
            // probe that runs afterwards.
            if (AutoDiscovery::g_DiscoveredFFieldLayout.Valid &&
                AutoDiscovery::g_LiveFClassMap.empty() &&
                !m_fname.IsV808Active()) {
                std::printf("[layout-fix] Code-discovered ChildProperties=+0x%X produced 0 FFields "
                    "— clearing for runtime re-probe\n",
                    AutoDiscovery::g_DiscoveredFFieldLayout.ChildPropsOff);
                AutoDiscovery::g_DiscoveredFFieldLayout.ChildPropsOff = 0;
                AutoDiscovery::g_DiscoveredFFieldLayout.NextOff = 0;
                AutoDiscovery::g_DiscoveredFFieldLayout.OwnerOff = 0;
                AutoDiscovery::g_DiscoveredFFieldLayout.ClassPrivateOff = 0;
                AutoDiscovery::g_DiscoveredFFieldLayout.NamePrivateOff = 0;
                AutoDiscovery::g_DiscoveredFFieldLayout.Valid = false;
                ArcDecrypt::Offsets::UStruct::ChildProperties = 0xC8;
                ArcDecrypt::Offsets::UStruct::Children = 0xC8;
                ArcDecrypt::Offsets::FField::Next = 0x60;
                ArcDecrypt::Offsets::FField::ClassPrivate = 0x70;
            }

            // ── Phase 9-15: live structure-offset probe (auto_offsets.h) ──
            AutoDiscovery::SeedHardcodedFClassGlobals_CL1201801();
            AutoOffsets::DiscoverAll(m_reader, MODULE_BASE,
                                     m_gobj.GetSeedObjects(), m_fname);

            // The generic Phase 2 / auto_offsets probes cannot resolve the
            // FField layout on this patch (they need a working name decode to
            // score candidates, which is exactly what they are trying to find)
            // and they overwrite the values we already know. Re-assert the
            // binary-derived layout afterwards so it wins.
            if (m_fname.IsV808Active()) {
                namespace V = ArcDecrypt::v20260808;
                namespace Off = ArcDecrypt::Offsets;
                Off::FField::NamePrivate      = V::FFIELD_NAME_OFF;
                Off::FField::NameEncrypted    = V::FFIELD_NAME_OFF;
                Off::FField::Next             = V::FFIELD_NEXT_OFF;
                Off::UStruct::ChildProperties = V::USTRUCT_CHILDPROPS;
                Off::FBoolProperty::FieldSize = V::FBOOLPROP_FIELDSIZE;
                Off::FField::Owner            = V::FFIELD_OWNER_OFF;
                Off::FField::ClassPrivate     = V::FFIELD_CLASSPRIV_OFF;
                Off::FProperty::ArrayDim      = V::FPROP_ARRAYDIM_OFF;
                Off::FProperty::ElementSize   = V::FPROP_ELEMSIZE_OFF;
                Off::FProperty::PropertyFlags = V::FPROP_PROPFLAGS_OFF;
                Off::FProperty::Offset_Internal = V::FPROP_OFFSETINT_OFF;
                Off::FProperty::Offset_XOR    = V::FPROP_OFFSET_XOR;
                Off::UStruct::PropertiesSize  = V::USTRUCT_PROPSIZE_OFF;
                Off::UStruct::SuperStruct     = V::USTRUCT_SUPER_OFF;
                Off::UEnum::Names             = V::UENUM_NAMES_OFF;
                Off::FBoolProperty::ByteOffset = V::FBOOLPROP_BYTEOFFSET;
                Off::FBoolProperty::ByteMask   = V::FBOOLPROP_BYTEMASK;
                Off::FBoolProperty::FieldMask  = V::FBOOLPROP_FIELDMASK;
                ArcDecrypt::Patch20260421::g_PropertyOffsetXor = V::FPROP_OFFSET_XOR;
                std::printf("[v808] re-asserted FField layout after auto_offsets\n");
            }

            // If auto_offsets found a new ChildProperties offset, re-run
            // live FFieldClass map with the corrected offsets.
            if (AutoDiscovery::g_LiveFClassMap.empty()) {
                std::printf("\n=== Phase 2f retry: Live FFieldClass-to-type map (post auto_offsets) ===\n");
                AutoDiscovery::g_LiveFClassMap = AutoDiscovery::BuildLiveFFieldClassMap(
                    m_reader, MODULE_BASE,
                    AutoDiscovery::g_DiscoveredBounds,
                    m_gobj.GetSeedObjects(),
                    AutoDiscovery::g_DiscoveredVTables);
                for (auto& [Addr, TypeName] : AutoDiscovery::g_LiveFClassMap) {
                    uint64_t Rva = Addr - MODULE_BASE;
                    bool Already = false;
                    for (const auto& G : AutoDiscovery::g_DiscoveredFClassGlobals) {
                        if (G.TargetRva == Rva) { Already = true; break; }
                    }
                    if (!Already) {
                        AutoDiscovery::FFieldClassGlobal Entry;
                        Entry.TargetRva = Rva;
                        Entry.TypeName  = TypeName;
                        AutoDiscovery::g_DiscoveredFClassGlobals.push_back(std::move(Entry));
                    }
                }
                std::printf("[live-fclass-retry] g_DiscoveredFClassGlobals now has %zu entries\n",
                    AutoDiscovery::g_DiscoveredFClassGlobals.size());
            }
        }

        // (FProperty Offset_Internal XOR key auto-discovery already ran
        // inside the SigScanV2 init block above; the discovered value is in
        // ArcDecrypt::Patch20260421::g_PropertyOffsetXor.)

        // Snapshot every runtime-resolved decryption constant / offset /
        // anchor to a JSON file next to sdk/SDK_Output.txt. Forensic trail for
        // patch days + consumable by external tooling.
        AutoExport::WriteAll("decrypt_export.json", MODULE_BASE);

        return true;
    }

    // ── Capture SIMD chunk_table-decrypt XOR key via uprobe ──────────────
    // Sig-scans the running module for the `mov eax, 0x647A6348; add rax,
    // gs:[0x60]` sequence (RVA-stable across patches because both the
    // imm32 and the gs:[0x60] read are load-bearing and unchanged since
    // 20260421). Sets a uprobe right after the `add` so the kernel
    // captures rax = peb_pointer + 0x647A6348 — exactly the key the SIMD
    // pipeline XORs against. Polls briefly for a hit (the function runs
    // continuously during normal play). On success, hands the key to
    // GObjectArray; failure is non-fatal — we fall through to the
    // existing PEB sweep + heap-scan probe.
    bool CaptureSimdPebKey() {
        if (m_reader.fd < 0) {
            std::printf("[uprobe-key] /dev/memreader not open; skipping live key capture\n");
            return false;
        }

        // Locate any chunk_table-decrypt function — there are 90-108 vt[N]
        // dispatch variants per binary, all sharing the same prologue idiom:
        //   F3 0F 7E 02              movq xmm0, [rdx]              ; load 8B blob
        //   B8 ?? ?? ?? ??           mov  eax, imm32               ; per-binary PEB add const
        //   65 48 03 04 25 60 00 00 00  add  rax, gs:[0x60]        ; PEB load
        //
        // Cross-patch verified 2026-05-01: the original sig with hardcoded
        // imm32 (`B8 48 63 7A 64 ...`) only fires on the ONE binary it was
        // extracted from; the imm32 rotates per build. The structural anchor
        // below (movq xmm0,[rdx] + 14-byte PEB-load pair) hits 90-108×
        // across all 6 tested binaries — any single hit is a valid uprobe
        // target since every variant returns the same key.
        SigScan::Scanner<KernelReader> scan(m_reader, MODULE_BASE, 0xE900000);
        // Reuse the dumper-wide PE-on-disk fallback (already opened by the
        // earlier signature-scan block in Init()).
        if (m_sigPeReady) {
            scan.SetPEFallback(&m_sigPe);
        }
        auto pat = SigScan::Pattern::Parse(
            "F3 0F 7E 02 B8 ?? ?? ?? ?? 65 48 03 04 25 60 00 00 00");
        uint64_t hit_va = scan.Find(pat);
        if (!hit_va) {
            std::printf("[uprobe-key] sig-scan for chunk_table-decrypt prologue failed\n");
            return false;
        }
        // The MOV starts 4 bytes into the match (after movq xmm0,[rdx]).
        // Probe address = right after `add rax, gs:[0x60]` finishes:
        //   hit + 4 (movq) + 5 (mov eax,imm32) + 9 (add rax,gs:[0x60]) = hit + 18.
        uint64_t mov_va   = hit_va + 4;
        uint64_t probe_va = hit_va + 18;
        std::printf("[uprobe-key] mov+add prologue @ 0x%llX  probe @ 0x%llX\n",
            (unsigned long long)mov_va, (unsigned long long)probe_va);

        // Set the uprobe.
        struct memreader_uprobe_request req = {};
        req.pid       = m_pid;
        req.address   = static_cast<unsigned long>(probe_va);
        req.probe_id  = 0;
        if (ioctl(m_reader.fd, MEMREADER_SET_UPROBE, &req) != 0) {
            std::printf("[uprobe-key] SET_UPROBE failed: %s\n", strerror(errno));
            return false;
        }

        // Poll for a hit. The chunk_table-decrypt is only called during
        // GC sweeps (sub_398180 → vt[5]), which run every ~1–5 s during
        // an active match. 5 s in 100 ms increments — exits early on the
        // first hit. If we time out, the function genuinely isn't being
        // called yet (loading screen, paused, alt-tabbed) and the caller
        // falls through to the heap-scan path.
        struct memreader_uprobe_hit hit_buf = {};
        struct memreader_uprobe_hits hits_req = {};
        hits_req.probe_id = 0;
        hits_req.max_hits = 1;
        hits_req.hits     = &hit_buf;
        bool got_hit = false;
        for (int attempt = 0; attempt < 50 && !got_hit; ++attempt) {
            usleep(100 * 1000);
            hits_req.num_hits = 0;
            if (ioctl(m_reader.fd, MEMREADER_GET_UPROBE_HITS, &hits_req) == 0
                && hits_req.num_hits > 0) {
                got_hit = true;
            }
        }

        // Disarm the uprobe regardless of outcome.
        struct memreader_uprobe_request clr = {};
        clr.pid      = m_pid;
        clr.address  = static_cast<unsigned long>(probe_va);
        clr.probe_id = 0;
        ioctl(m_reader.fd, MEMREADER_CLEAR_UPROBE, &clr);

        if (!got_hit) {
            std::printf("[uprobe-key] no hits in 5000 ms — function not firing (paused / loading?)\n");
            return false;
        }

        // The captured rax IS the SIMD key (peb + peb_add_const).
        // Sanity check: high 32 bits should be plausibly within Wine's
        // user space (anything below ~0x800000_00000000). If the captured
        // value looks broken, log and bail rather than poison the SIMD
        // path.
        uint64_t key = hit_buf.rax;
        if (key == 0 || key < 0x100000) {
            std::printf("[uprobe-key] captured rax=0x%llX looks broken; ignoring\n",
                (unsigned long long)key);
            return false;
        }
        std::printf("[uprobe-key] captured rax=0x%llX (key for SIMD chunk_table decrypt)\n",
            (unsigned long long)key);
        m_gobj.SetSimdPebKey(key);
        return true;
    }

    // ── Probe: find the most-productive UObject inline-handle offset ─────
    // For each candidate offset in [0x10..0x80] step 8, read 8 bytes from a
    // sample of live objects, run them through DecryptByHandle, count the
    // ones that yield a sane name. Highest-scoring offset wins. Robust to
    // ENTRY_HANDLE_XOR drift because DiscoverFNameConsts already updated
    // the XOR before we get here.
    void CalibrateInlineHandleOffset() {
        // Same sanity check the dump phase uses (≥80% printable chars).
        // Stricter would reject quirky-but-real names; looser would credit
        // random heap garbage as a "name" and pick a bogus offset.
        auto isSaneName = [](const std::string& s) {
            if (s.empty() || s.size() > 128) return false;
            int printable = 0;
            for (unsigned char c : s)
                if (c >= 32 && c <= 126) ++printable;
            return printable * 5 >= static_cast<int>(s.size()) * 4;
        };

        const int kSampleTarget = 500;
        std::unordered_map<uint64_t, int> hits;
        int sampled = 0;
        int total = m_gobj.GetNumElements();
        // Emit the first sample's raw layout for patch-day forensics — if
        // the inline-handle path stops working, the bytes here show why.
        bool dumped_sample = false;
        for (int i = 0; i < total && sampled < kSampleTarget; ++i) {
            uint64_t obj = m_gobj.GetObjectPtr(i);
            if (!obj) continue;
            ++sampled;
            if (!dumped_sample) {
                uint8_t bytes[0x80] = {};
                bool ok = m_reader.Read(obj, bytes, sizeof(bytes));
                std::string via_get = m_fname.GetName(obj);
                std::printf("[probe-dbg] sample obj[%d]=0x%llX  GetName='%s'\n",
                            i, (unsigned long long)obj, via_get.c_str());
                if (ok) {
                    std::printf("[probe-dbg]   bytes 0x10..0x40: ");
                    for (int b = 0x10; b < 0x40; ++b) std::printf("%02X ", bytes[b]);
                    std::printf("\n");
                }
                dumped_sample = true;
            }
            for (uint64_t off = 0x10; off <= 0x80; off += 8) {
                std::string s = m_fname.GetNameByHandle(obj, off);
                if (isSaneName(s)) hits[off]++;
            }
        }

        uint64_t best_off = 0;
        int      best_cnt = 0, runner_up = 0;
        for (auto& [off, cnt] : hits) {
            if (cnt > best_cnt) { runner_up = best_cnt; best_cnt = cnt; best_off = off; }
            else if (cnt > runner_up) runner_up = cnt;
        }

        // Always print the full distribution — invaluable for patch-day debug.
        std::printf("[probe] inline-handle calibration (%d objects sampled):\n", sampled);
        for (uint64_t off = 0x10; off <= 0x80; off += 8) {
            int cnt = hits.count(off) ? hits[off] : 0;
            if (cnt) std::printf("[probe]   +0x%02llX: %d hits (%d%%)\n",
                                 (unsigned long long)off, cnt, sampled ? cnt * 100 / sampled : 0);
        }

        // Set as primary if best is meaningfully ahead (≥25% hit rate AND
        // ≥1.5× the runner-up). Anything weaker risks picking a wrong offset
        // that also produces sane-shaped strings by coincidence.
        if (best_off && best_cnt * 4 >= sampled && best_cnt * 2 >= runner_up * 3) {
            std::printf("[probe] UObject inline handle offset = 0x%llX (winner by %d vs %d)\n",
                        (unsigned long long)best_off, best_cnt, runner_up);
            m_fname.SetPrimaryHandleOffset(best_off);
        } else {
            std::printf("[probe] no dominant offset (best 0x%llX: %d, runner-up: %d) — "
                        "GetName uses 0x28/0x18/0x30 fallback list\n",
                        (unsigned long long)best_off, best_cnt, runner_up);
        }
    }

    void DiscoverFNameConsts() {
        // 1. Locate the outer FName decrypt entry. Two anchors run in
        //    sequence; whichever finds it first wins. Both must come back
        //    with the same RVA (or the SIMD anchor takes priority — its
        //    fingerprint targets the algorithm body itself, not a caller).
        //
        //    Plan A — caller-side opcode pattern (LEA RCX, LEA RDX, CALL).
        //             Brittle if callers' stack layout shifts on a patch.
        //    Plan B — distinctive SIMD body fingerprint (PSHUFB + PSRLD 0x1A
        //             + PSLLD 6 + POR + PSHUFLW 0x93). Targets the algorithm
        //             itself; survives caller rearrangement and most code
        //             reshuffling.
        auto find = FNameFuncFinder::Find(m_reader, MODULE_BASE);
        uint64_t simd_rva = FNameFuncFinder::FindBySimdFingerprint(m_reader, MODULE_BASE);

        // Quick prologue validator — the FName function ALWAYS has a x64 ABI
        // prologue with `SUB RSP, imm` somewhere in the first 16 bytes. Used
        // to guard against picking an off-by-N back-walked address that lands
        // mid-instruction (the SIMD fingerprint can over-shoot when sibling
        // functions share the same body shape).
        auto has_clean_prologue = [&](uint64_t rva) -> bool {
            if (!rva) return false;
            uint8_t pro[16] = {};
            if (!m_reader.Read(MODULE_BASE + rva, pro, sizeof(pro))) return false;
            for (int i = 0; i + 3 < 16; ++i) {
                bool sub_imm8  = (pro[i] == 0x48 && pro[i+1] == 0x83 && pro[i+2] == 0xEC);
                bool sub_imm32 = (pro[i] == 0x48 && pro[i+1] == 0x81 && pro[i+2] == 0xEC);
                if (sub_imm8 || sub_imm32) return true;
            }
            return false;
        };

        // Priority: caller-pattern (proven across many dumps) > SIMD anchor.
        // If both succeed and disagree, prefer caller — but if caller's pick
        // doesn't have a clean prologue (i.e. signature drifted to a wrong
        // target), fall back to SIMD. Same for SIMD without prologue → reject.
        uint64_t fname_rva = 0;
        if (find.found && has_clean_prologue(find.best_target_rva)) {
            fname_rva = find.best_target_rva;
            if (simd_rva == fname_rva) {
                std::printf("[autodisc] FName decrypt @ rva=0x%llX  (caller+SIMD agree)\n",
                            (unsigned long long)fname_rva);
            } else if (simd_rva) {
                std::printf("[autodisc] FName decrypt @ rva=0x%llX  (caller pattern; "
                            "SIMD anchor disagreed at 0x%llX — kept caller as proven)\n",
                            (unsigned long long)fname_rva, (unsigned long long)simd_rva);
            } else {
                std::printf("[autodisc] FName decrypt @ rva=0x%llX  (caller pattern; "
                            "SIMD anchor missed — encryption shape may have shifted)\n",
                            (unsigned long long)fname_rva);
            }
        } else if (simd_rva && has_clean_prologue(simd_rva)) {
            fname_rva = simd_rva;
            std::printf("[autodisc] FName decrypt @ rva=0x%llX  (SIMD fingerprint; "
                        "caller pattern %s)\n",
                        (unsigned long long)fname_rva,
                        find.found ? "found wrong target" : "missed");
        } else {
            std::printf("[autodisc] FName decrypt not located with clean prologue "
                        "(caller=0x%llX simd=0x%llX) — fallback disabled\n",
                        (unsigned long long)(find.found ? find.best_target_rva : 0),
                        (unsigned long long)simd_rva);
            return;
        }

        // 1b. Extract ENTRY_HANDLE_XOR from the function body (patch-resilient).
        //     The constant lives in a `MOV r64,imm64; XOR; BSWAP r64` triple
        //     near the top of the function. If extraction succeeds, override
        //     the compile-time default in ArcDecrypt::Patch20260421.
        uint64_t live_xor = FNameFuncFinder::ExtractEntryHandleXor(
            m_reader, MODULE_BASE, fname_rva);
        if (live_xor) {
            uint64_t old_xor = ArcDecrypt::Patch20260421::ENTRY_HANDLE_XOR;
            if (live_xor != old_xor) {
                std::printf("[autodisc] ENTRY_HANDLE_XOR drifted: 0x%016llX → 0x%016llX (auto-fixed)\n",
                            (unsigned long long)old_xor, (unsigned long long)live_xor);
            } else {
                std::printf("[autodisc] ENTRY_HANDLE_XOR matches constant (0x%016llX)\n",
                            (unsigned long long)live_xor);
            }
            ArcDecrypt::Patch20260421::SetEntryHandleXor(live_xor);
        } else {
            std::printf("[autodisc] ENTRY_HANDLE_XOR extraction failed; using constant 0x%016llX\n",
                        (unsigned long long)ArcDecrypt::Patch20260421::ENTRY_HANDLE_XOR);
        }

        // ── Phase 5+6: FName resolver + GNames ────────────────────
        if (AutoDiscovery::g_DiscoveredBounds.Valid) {
            if (AutoDiscovery::g_DiscoveredFName.Valid) {
                std::printf("[autodisc] Phase 5 skipped — FName resolver consts loaded from config\n");
            } else {
                AutoDiscovery::g_DiscoveredFName =
                    AutoDiscovery::DiscoverFNameResolverConsts(m_sigScanner, fname_rva);
            }

            if (AutoDiscovery::g_DiscoveredGNames.Valid) {
                std::printf("[autodisc] Phase 6 skipped — GNames loaded from config (rva=0x%llX)\n",
                    (unsigned long long)AutoDiscovery::g_DiscoveredGNames.GNamesRva);
            } else {
                std::vector<AutoDiscovery::GNamesExcludeZone> ExcludeZones;
                {
                    AutoDiscovery::GNamesExcludeZone z;
                    z.CenterRva = ArcDecrypt::RVA_FNAME_KEY_TABLE > 0xF8u
                        ? (ArcDecrypt::RVA_FNAME_KEY_TABLE - 0xF8u)
                        : ArcDecrypt::RVA_FNAME_KEY_TABLE;
                    z.Radius = 0x200;
                    ExcludeZones.push_back(z);
                }
                AutoDiscovery::g_DiscoveredGNames =
                    AutoDiscovery::DiscoverGNamesViaFNameWalk(
                        m_sigScanner, fname_rva, ExcludeZones);
            }
            if (AutoDiscovery::g_DiscoveredGNames.Valid) {
                uint64_t Hard = ArcDecrypt::RVA_GNAMES_BASE;
                uint64_t Live = AutoDiscovery::g_DiscoveredGNames.GNamesRva;
                if (Live == Hard) {
                    std::printf("[autodisc] GNamePool RVA matches constant 0x%llX\n",
                        (unsigned long long)Live);
                } else {
                    std::printf("[autodisc] GNamePool RVA drift: 0x%llX → 0x%llX (auto-fixed via heap-probe)\n",
                        (unsigned long long)Hard, (unsigned long long)Live);
                    ArcDecrypt::RVA_GNAMES_BASE = Live;
                }
            }

            // ── Phase 6.5: FName keystream RVA = SIMD-block + 0xA0 ────────
            // Only applies when the FName decryptor is NOT yet initialized —
            // if keytable was already probed and validated (m_fname.IsInitialized()),
            // the SIMD-block+0xA0 inference is irrelevant (and on CL-1201801+ the
            // key table no longer sits at SimdBlock+0xA0 anyway).
            if (AutoDiscovery::g_DiscoveredGNames.SimdBlockRva) {
                uint64_t Hard = ArcDecrypt::RVA_FNAME_KEY_TABLE;
                uint64_t Live = AutoDiscovery::g_DiscoveredGNames.SimdBlockRva + 0xA0;
                if (Live == Hard) {
                    std::printf("[autodisc] FName keystream RVA matches constant 0x%llX\n",
                        (unsigned long long)Live);
                } else {
                    std::printf("[autodisc] FName keystream RVA drift: 0x%llX → 0x%llX "
                                "(auto-fixed via SIMD-block + 0xA0)\n",
                        (unsigned long long)Hard, (unsigned long long)Live);
                    ArcDecrypt::RVA_FNAME_KEY_TABLE = Live;
                    if (!m_fname.ReloadKeyTable()) {
                        std::printf("[autodisc] WARNING: ReloadKeyTable failed at new RVA 0x%llX\n",
                            (unsigned long long)Live);
                    } else {
                        std::printf("[autodisc] FName key table re-loaded from corrected RVA\n");
                    }
                    if (AutoDiscovery::g_DiscoveredUObjSlot.Valid &&
                        m_fname.ActivePipeline() != FNameDecryptor::Pipeline::Build20260519) {
                        m_fname.ForcePipeline(FNameDecryptor::Pipeline::Build20260519);
                        std::printf("[autodisc] forced pipeline Build20260519 (UObj slot auto-discovered)\n");
                    }
                }
            } else {
                uint64_t LiveKs = FNameFuncFinder::AutoDiscoverFNameKeystream(
                    m_reader, MODULE_BASE,
                    AutoDiscovery::g_DiscoveredGNames.SimdBlockRva,
                    fname_rva);
                if (LiveKs) {
                    uint64_t Hard = ArcDecrypt::RVA_FNAME_KEY_TABLE;
                    if (LiveKs == Hard) {
                        std::printf("[autodisc] FName keystream RVA (Phase 6.6 entropy probe) matches constant 0x%llX\n",
                            (unsigned long long)LiveKs);
                    } else {
                        std::printf("[autodisc] FName keystream RVA drift: 0x%llX → 0x%llX "
                                    "(auto-fixed via Phase 6.6 entropy probe)\n",
                            (unsigned long long)Hard, (unsigned long long)LiveKs);
                        ArcDecrypt::RVA_FNAME_KEY_TABLE = LiveKs;
                        if (!m_fname.ReloadKeyTable()) {
                            std::printf("[autodisc] WARNING: ReloadKeyTable failed at new RVA 0x%llX\n",
                                (unsigned long long)LiveKs);
                        } else {
                            std::printf("[autodisc] FName key table re-loaded from corrected RVA\n");
                        }
                    }
                }
            }

            // ── Phase 6.7: CL-1325322 plaintext-verified pipeline ────────
            // Runs before Phase 5.5 so that a confirmed v808 adoption makes the
            // older sig-scan-derived constants irrelevant instead of fighting
            // them. Both anchors are pinned by decoding "None"/"ByteProperty",
            // so a successful adopt is ground truth, not a heuristic.
            {
                std::printf("\n=== Phase 6.7: v20260808 FName pipeline (plaintext-verified) ===\n");
                AutoDiscovery::g_DiscoveredV808 =
                    AutoDiscovery::DiscoverV808Pipeline(
                        m_sigScanner, m_reader, MODULE_BASE,
                        AutoDiscovery::g_DiscoveredBounds,
                        AutoDiscovery::g_DiscoveredGNames);
                if (AutoDiscovery::g_DiscoveredV808.Valid &&
                    m_fname.AdoptV808(AutoDiscovery::g_DiscoveredV808))
                {
                    // FField/UStruct layout that goes with this patch. Derived
                    // from the PropertyBool.cpp assert path and confirmed by
                    // live probing; the generic Phase 2 probes cannot find them
                    // because they need a working FField name decode first.
                    namespace V = ArcDecrypt::v20260808;
                    namespace Off = ArcDecrypt::Offsets;
                    Off::FField::NamePrivate      = V::FFIELD_NAME_OFF;
                    Off::FField::NameEncrypted    = V::FFIELD_NAME_OFF;
                    Off::FField::Next             = V::FFIELD_NEXT_OFF;
                    Off::UStruct::ChildProperties = V::USTRUCT_CHILDPROPS;
                    Off::FBoolProperty::FieldSize = V::FBOOLPROP_FIELDSIZE;
                    Off::FField::Owner            = V::FFIELD_OWNER_OFF;
                    Off::FField::ClassPrivate     = V::FFIELD_CLASSPRIV_OFF;
                    Off::FProperty::ArrayDim      = V::FPROP_ARRAYDIM_OFF;
                    Off::FProperty::ElementSize   = V::FPROP_ELEMSIZE_OFF;
                    Off::FProperty::PropertyFlags = V::FPROP_PROPFLAGS_OFF;
                    Off::FProperty::Offset_Internal = V::FPROP_OFFSETINT_OFF;
                    Off::FProperty::Offset_XOR    = V::FPROP_OFFSET_XOR;
                    Off::UStruct::PropertiesSize  = V::USTRUCT_PROPSIZE_OFF;
                Off::UStruct::SuperStruct     = V::USTRUCT_SUPER_OFF;
                Off::UEnum::Names             = V::UENUM_NAMES_OFF;
                    Off::UStruct::SuperStruct     = V::USTRUCT_SUPER_OFF;
                Off::UEnum::Names             = V::UENUM_NAMES_OFF;
                    Off::UEnum::Names             = V::UENUM_NAMES_OFF;
                    Off::FBoolProperty::ByteOffset = V::FBOOLPROP_BYTEOFFSET;
                    Off::FBoolProperty::ByteMask   = V::FBOOLPROP_BYTEMASK;
                    Off::FBoolProperty::FieldMask  = V::FBOOLPROP_FIELDMASK;
                    ArcDecrypt::Patch20260421::g_PropertyOffsetXor = V::FPROP_OFFSET_XOR;

                    // Publish it as a Phase-2c result too. Every downstream
                    // re-probe (auto_offsets ProbeChildProperties/ProbeFFieldNext,
                    // sdk_generator's autocal-next brute force) is already gated
                    // on this struct being valid, so filling it in makes them all
                    // stand down instead of overwriting binary-derived values with
                    // weaker heuristics. The autocal-next sweep in particular only
                    // scans 0x00..0x78 and can therefore never re-find Next=0x80.
                    auto& L = AutoDiscovery::g_DiscoveredFFieldLayout;
                    L.ChildPropsOff   = static_cast<uint32_t>(V::USTRUCT_CHILDPROPS);
                    L.NextOff         = static_cast<uint32_t>(V::FFIELD_NEXT_OFF);
                    L.NamePrivateOff  = static_cast<uint32_t>(V::FFIELD_NAME_OFF);
                    L.OwnerOff        = static_cast<uint32_t>(V::FFIELD_OWNER_OFF);
                    L.ClassPrivateOff = static_cast<uint32_t>(V::FFIELD_CLASSPRIV_OFF);
                    L.Valid           = true;

                    auto& FP = AutoDiscovery::g_DiscoveredFPropertyLayout;
                    FP.ArrayDimOff    = static_cast<uint32_t>(V::FPROP_ARRAYDIM_OFF);
                    FP.ElementSizeOff = static_cast<uint32_t>(V::FPROP_ELEMSIZE_OFF);

                    std::printf("[v808] FField layout applied: Name=+0x%llX Next=+0x%llX "
                                "ChildProperties=+0x%llX\n",
                        (unsigned long long)V::FFIELD_NAME_OFF,
                        (unsigned long long)V::FFIELD_NEXT_OFF,
                        (unsigned long long)V::USTRUCT_CHILDPROPS);
                }
            }

            // ── Phase 5.5: Structured FName pipeline extraction ──────────
            if (!m_fname.IsV808Active() && !AutoDiscovery::g_DiscoveredFNamePipeline.Valid) {
                std::printf("\n=== Phase 5.5: FName pipeline structured extraction ===\n");
                AutoDiscovery::g_DiscoveredFNamePipeline =
                    AutoDiscovery::DiscoverFNamePipeline(m_sigScanner, fname_rva);
                const auto& Pipe = AutoDiscovery::g_DiscoveredFNamePipeline;
                if (Pipe.Valid) {
                    std::printf("[Phase 5.5] FName pipeline discovery: shard=%d block=%d fnv=%d ptrXor=%d seedOff=0x%llX\n",
                        Pipe.ShardHashValid, Pipe.BlockDecryptValid, Pipe.FnvFoldValid,
                        Pipe.PtrXorCount, (unsigned long long)Pipe.ShardSeedOff);
                }
            }

            // ── Phase 4.5: Slot hash constant extraction ─────────────────
            {
                uint64_t SlotSiteRva = 0;
                if (AutoDiscovery::g_DiscoveredUObjSlot.Valid && AutoDiscovery::g_DiscoveredUObjSlot.FirstSiteRva)
                    SlotSiteRva = AutoDiscovery::g_DiscoveredUObjSlot.FirstSiteRva;
                else if (AutoDiscovery::g_DiscoveredSlotV709.Valid && AutoDiscovery::g_DiscoveredSlotV709.FirstSiteRva)
                    SlotSiteRva = AutoDiscovery::g_DiscoveredSlotV709.FirstSiteRva;
                if (!AutoDiscovery::g_DiscoveredSlotHash.Valid && SlotSiteRva) {
                    std::printf("\n=== Phase 4.5: UObject slot hash extraction ===\n");
                    AutoDiscovery::g_DiscoveredSlotHash =
                        AutoDiscovery::DiscoverSlotHashConsts(m_sigScanner, SlotSiteRva);
                }
            }

            // ── Phase 5.7: String decrypt parameter extraction ───────────
            if (!AutoDiscovery::g_DiscoveredStringDecrypt.Valid) {
                std::printf("\n=== Phase 5.7: String decrypt parameter extraction ===\n");
                AutoDiscovery::g_DiscoveredStringDecrypt =
                    AutoDiscovery::DiscoverStringDecryptParams(m_sigScanner, fname_rva);
            }
        }

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

        // ── Step 1: Get GWorld (CL-1177146 needs double-deref) ───────────
        uint64_t gworld = 0;
        uint64_t GWorldStage1 = 0;
        if (!m_reader.Read(MODULE_BASE + ArcDecrypt::RVA_GWORLD, &GWorldStage1, 8) || !isValidPtr(GWorldStage1)) {
            std::printf("[-] WorldTraversal: GWorld stage1 invalid (0x%llX)\n",
                (unsigned long long)GWorldStage1);
            return false;
        }
        gworld = GWorldStage1;
        uint64_t GWorldStage2 = 0;
        if (m_reader.Read(GWorldStage1, &GWorldStage2, 8) && isValidPtr(GWorldStage2)) {
            uint64_t Vtbl2 = 0;
            if (m_reader.Read(GWorldStage2, &Vtbl2, 8) && Vtbl2 >= MODULE_BASE && Vtbl2 < MODULE_BASE + 0x10000000ULL)
                gworld = GWorldStage2;
        }
        std::printf("[+] WorldTraversal: GWorld = 0x%llX (stage1=0x%llX)\n",
            (unsigned long long)gworld, (unsigned long long)GWorldStage1);

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
    void BruteForcePipelines(const uint8_t* Enc16) {
        auto TryCi = [&](const char* Tag, uint32_t Ci) {
            if (Ci <= 1 || Ci >= 0x4000000u) return;
            uint64_t Ptr = m_fname.ResolveNamePtrFull(static_cast<int32_t>(Ci));
            if (!Ptr) return;
            std::string Nm = m_fname.DecryptNameString(Ptr);
            if (Nm.empty()) return;
            bool Ok = true;
            for (char C : Nm) {
                if (!((C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') ||
                      (C >= '0' && C <= '9') || C == '_'))
                { Ok = false; break; }
            }
            std::printf("    %-50s CI=%-10u name='%s'%s\n", Tag, Ci, Nm.c_str(),
                        Ok ? " *MATCH*" : "");
        };
        auto Try64 = [&](const char* Tag, uint64_t Lo64Final, bool DoRol32) {
            uint64_t Final = DoRol32 ? Rotl64(Lo64Final, 32) : Lo64Final;
            uint32_t Ci = static_cast<uint32_t>(Final & 0xFFFFFFFFu);
            TryCi(Tag, Ci);
            if (DoRol32) {
                uint32_t Hi = static_cast<uint32_t>(Final >> 32);
                if (Hi != Ci) {
                    char Buf[80];
                    snprintf(Buf, sizeof(Buf), "%s[hi32]", Tag);
                    TryCi(Buf, Hi);
                }
            }
        };

        __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Enc16));

        alignas(16) uint8_t MaskUobjBuf[16] = {
            0x06, 0x05, 0x02, 0x03, 0x04, 0x01, 0x00, 0x07,
            0,0,0,0, 0,0,0,0
        };
        __m128i ShufUobj = _mm_load_si128(reinterpret_cast<const __m128i*>(MaskUobjBuf));
        constexpr uint64_t FFieldXorLo = 0x36578989E8756FBAULL;

        alignas(16) uint8_t Kxor8[16] = {
            0x38, 0xBA, 0x6F, 0x75, 0xE8, 0x89, 0x57, 0x36,
            0,0,0,0, 0,0,0,0
        };
        __m128i Xk8 = _mm_load_si128(reinterpret_cast<const __m128i*>(Kxor8));

        alignas(16) uint8_t Kxor16[16] = {
            0x38, 0xBA, 0x6F, 0x75, 0xE8, 0x89, 0x57, 0x36,
            0x57, 0x36, 0xE8, 0x89, 0x38, 0xBA, 0x6F, 0x75
        };
        __m128i Xk16 = _mm_load_si128(reinterpret_cast<const __m128i*>(Kxor16));

        auto RolE64 = [](__m128i Q, int N) {
            return _mm_or_si128(_mm_slli_epi64(Q, N), _mm_srli_epi64(Q, 64 - N));
        };
        auto RolE16 = [](__m128i Q, int N) {
            return _mm_or_si128(_mm_slli_epi16(Q, N), _mm_srli_epi16(Q, 16 - N));
        };
        auto Lo64Of = [](__m128i Q) {
            uint64_t L; _mm_storel_epi64(reinterpret_cast<__m128i*>(&L), Q); return L;
        };

        Try64("A:UObj-PSHUFB+XOR(FF)+ROL64", Lo64Of(_mm_shuffle_epi8(V, ShufUobj)) ^ FFieldXorLo, true);
        Try64("A2:UObj-PSHUFB+XOR(FF) noROL", Lo64Of(_mm_shuffle_epi8(V, ShufUobj)) ^ FFieldXorLo, false);
        {
            __m128i R1 = RolE64(V, 21);
            __m128i Xo = _mm_xor_si128(R1, Xk8);
            __m128i R2 = RolE16(Xo, 15);
            Try64("B:ROL64(21)+XOR8+ROL16(15)+ROL64", Lo64Of(R2), true);
        }
        {
            __m128i Sh = _mm_shufflelo_epi16(V, 0x1E);
            __m128i Xo = _mm_xor_si128(Sh, Xk8);
            __m128i R2 = RolE16(Xo, 1);
            Try64("C:PSHUFLW(1E)+XOR8+ROL16(1)+ROL64", Lo64Of(R2), true);
        }
        {
            __m128i Sh = _mm_shufflelo_epi16(V, 0xB1);
            __m128i Xo = _mm_xor_si128(Sh, Xk8);
            Try64("D:PSHUFLW(B1)+XOR8+ROL64", Lo64Of(Xo), true);
        }
        {
            __m128i B = _mm_shuffle_epi8(V, ShufUobj);
            __m128i Xo = _mm_xor_si128(B, Xk16);
            Try64("E:PSHUFB+XOR16+ROL64", Lo64Of(Xo), true);
        }
        {
            __m128i Xo = _mm_xor_si128(V, Xk16);
            Try64("F:XOR16-only+ROL64", Lo64Of(Xo), true);
        }
        {
            __m128i Xo = _mm_xor_si128(V, Xk16);
            Try64("G:XOR16-only", Lo64Of(Xo), false);
        }
        {
            __m128i R1 = RolE64(V, 21);
            __m128i Xo = _mm_xor_si128(R1, Xk16);
            __m128i R2 = RolE16(Xo, 15);
            Try64("H:ROL64(21)+XOR16+ROL16(15)+ROL64", Lo64Of(R2), true);
        }
        {
            __m128i Sh = _mm_shufflelo_epi16(V, 0x1E);
            __m128i Xo = _mm_xor_si128(Sh, Xk16);
            __m128i R2 = RolE16(Xo, 1);
            Try64("I:PSHUFLW(1E)+XOR16+ROL16(1)+ROL64", Lo64Of(R2), true);
        }
        {
            __m128i Sh = _mm_shufflelo_epi16(V, 0xB1);
            __m128i Xo = _mm_xor_si128(Sh, Xk16);
            Try64("J:PSHUFLW(B1)+XOR16+ROL64", Lo64Of(Xo), true);
        }
        {
            __m128i Sh = _mm_shufflelo_epi16(V, 0xB1);
            __m128i Xo = _mm_xor_si128(Sh, Xk16);
            Try64("J2:PSHUFLW(B1)+XOR16 noROL", Lo64Of(Xo), false);
        }
        {
            __m128i B = _mm_shuffle_epi8(V, ShufUobj);
            __m128i Xo = _mm_xor_si128(B, Xk8);
            Try64("K:PSHUFB+XOR8+ROL64", Lo64Of(Xo), true);
        }
        {
            __m128i B = _mm_shuffle_epi8(V, ShufUobj);
            __m128i Xo = _mm_xor_si128(B, Xk8);
            Try64("K2:PSHUFB+XOR8 noROL", Lo64Of(Xo), false);
        }
        {
            __m128i B = _mm_shuffle_epi8(V, ShufUobj);
            __m128i Xo = _mm_xor_si128(B, Xk8);
            __m128i R = RolE16(Xo, 1);
            Try64("L:PSHUFB+XOR8+ROL16(1)+ROL64", Lo64Of(R), true);
        }
        {
            __m128i B = _mm_shuffle_epi8(V, ShufUobj);
            __m128i Xo = _mm_xor_si128(B, Xk8);
            __m128i R = RolE16(Xo, 15);
            Try64("M:PSHUFB+XOR8+ROL16(15)+ROL64", Lo64Of(R), true);
        }
        {
            __m128i B = _mm_shuffle_epi8(V, ShufUobj);
            __m128i Xo = _mm_xor_si128(B, Xk16);
            __m128i R = RolE16(Xo, 1);
            Try64("N:PSHUFB+XOR16+ROL16(1)+ROL64", Lo64Of(R), true);
        }
        {
            __m128i B = _mm_shuffle_epi8(V, ShufUobj);
            __m128i Xo = _mm_xor_si128(B, Xk16);
            __m128i R = RolE16(Xo, 15);
            Try64("O:PSHUFB+XOR16+ROL16(15)+ROL64", Lo64Of(R), true);
        }
        {
            uint64_t Lo;
            std::memcpy(&Lo, Enc16, 8);
            Try64("P:raw lo64+XOR(FF)+ROL64", Lo ^ FFieldXorLo, true);
        }
        {
            uint64_t Lo;
            std::memcpy(&Lo, Enc16, 8);
            Try64("P2:raw lo64+XOR(FF)", Lo ^ FFieldXorLo, false);
        }
        {
            uint64_t Hi;
            std::memcpy(&Hi, Enc16 + 8, 8);
            Try64("Q:raw hi64+XOR(FF)+ROL64", Hi ^ FFieldXorLo, true);
        }
        {
            uint64_t Hi;
            std::memcpy(&Hi, Enc16 + 8, 8);
            Try64("Q2:raw hi64+XOR(FF)", Hi ^ FFieldXorLo, false);
        }
    }

    static uint64_t Rotl64(uint64_t X, int N) { return (X << N) | (X >> (64 - N)); }

    void ProbeFField() {
        std::cout << "\n=== ProbeFField ===\n";

        if (!m_gobj.IsInitialized()) {
            std::cerr << "[-] GObjects not initialized\n"; return;
        }
        int32_t obj_count = m_gobj.GetNumElements();

        std::printf("[scan] looking for objects with non-empty ChildProperties chain...\n");
        int Hits = 0;
        int Inspected = 0;
        for (int32_t I = 0; I < obj_count && Hits < 8; ++I) {
            uint64_t Obj = m_gobj.GetObjectPtr(I);
            if (!Obj) continue;
            ++Inspected;
            uint64_t FfHead = 0;
            m_reader.Read(Obj + ArcDecrypt::Offsets::UStruct::ChildProperties, &FfHead, 8);
            if (!FfHead || FfHead < 0x100000ULL || FfHead >= 0x800000000000ULL) continue;
            uint64_t Vt = 0;
            m_reader.Read(FfHead, &Vt, 8);
            if (Vt < MODULE_BASE || Vt >= MODULE_BASE + 0xE9D0000ULL) continue;
            uint64_t Salt = 0;
            m_reader.Read(FfHead + 0x78, &Salt, 8);
            if (Salt != 0x893BCE4393840650ULL) continue;
            std::printf("\n[hit %d] obj=0x%llX FF=0x%llX salt=0x%llX\n",
                        Hits, (unsigned long long)Obj,
                        (unsigned long long)FfHead, (unsigned long long)Salt);
            uint64_t Chain = FfHead;
            std::unordered_set<uint64_t> Seen;
            for (int W = 0; W < 4 && Chain; ++W) {
                if (Seen.count(Chain)) break;
                Seen.insert(Chain);
                alignas(16) uint8_t Enc[16] = {};
                m_reader.Read(Chain + 0x70, Enc, 16);
                bool AllZero = true;
                for (uint8_t B : Enc) if (B) { AllZero = false; break; }
                std::printf("  FF[%d] @ 0x%llX  enc16=", W, (unsigned long long)Chain);
                for (int B : Enc) std::printf("%02X ", (uint8_t)B);
                std::printf("  zero=%d\n", AllZero ? 1 : 0);
                if (!AllZero) BruteForcePipelines(Enc);
                uint64_t Next = 0;
                m_reader.Read(Chain + 0x48, &Next, 8);
                Chain = Next;
            }
            ++Hits;
        }
        std::printf("[scan] done; inspected=%d hits=%d\n\n", Inspected, Hits);

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

                alignas(16) uint8_t np[16] = {};
                m_reader.Read(chain + ArcDecrypt::Offsets::FField::NamePrivate, np, 16);

                std::printf("  [enc16] ");
                for (int B = 0; B < 16; ++B) std::printf("%02X ", np[B]);
                std::printf("\n");
                BruteForcePipelines(np);

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

    // Steam records the shipped build in the app manifest; the game binary
    // itself has its version strings stripped by Theia, so this is the only
    // reliable build identifier available at runtime.
    struct SteamBuildInfo {
        std::string BuildId;
        std::string Updated;
    };
    SteamBuildInfo ReadSteamBuildInfo() const {
        SteamBuildInfo Out;
        // Under sudo, HOME points at root. The manifest lives in the
        // invoking user's Steam library, so prefer SUDO_USER.
        std::vector<std::string> Homes;
        if (const char* SudoUser = std::getenv("SUDO_USER"))
            Homes.push_back(std::string("/home/") + SudoUser);
        if (const char* H = std::getenv("HOME")) Homes.push_back(H);
        std::vector<std::string> Roots;
        for (const auto& Home : Homes) {
            Roots.push_back(std::string(Home) + "/.local/share/Steam/steamapps");
            Roots.push_back(std::string(Home) + "/.steam/steam/steamapps");
            Roots.push_back(std::string(Home) + "/Steam/steamapps");
        }
        for (const auto& R : Roots) {
            std::ifstream F(R + "/appmanifest_1808500.acf");
            if (!F) continue;
            std::string Line;
            while (std::getline(F, Line)) {
                auto Field = [&](const char* Key, std::string& Dst) {
                    if (!Dst.empty()) return;
                    size_t K = Line.find(Key);
                    if (K == std::string::npos) return;
                    size_t A = Line.find('"', K + std::strlen(Key));
                    if (A == std::string::npos) return;
                    size_t B = Line.find('"', A + 1);
                    if (B == std::string::npos) return;
                    Dst = Line.substr(A + 1, B - A - 1);
                };
                Field("\"buildid\"", Out.BuildId);
                Field("\"LastUpdated\"", Out.Updated);
            }
            if (!Out.BuildId.empty()) break;
        }
        if (!Out.Updated.empty()) {
            time_t T = (time_t)std::strtoll(Out.Updated.c_str(), nullptr, 10);
            char Buf[32] = {};
            struct tm Tm{};
            if (gmtime_r(&T, &Tm)) std::strftime(Buf, sizeof(Buf), "%Y-%m-%d", &Tm);
            Out.Updated = Buf;
        }
        return Out;
    }

    void DumpSDK() {
        std::cout << "\n=== SDK Generator ===\n";

        if (!m_gobj.IsInitialized()) {
            std::cerr << "[-] GObjects not initialized\n"; return;
        }
        int32_t obj_count = m_gobj.GetNumElements();
        std::cout << "[+] Object count: " << obj_count << "\n";

        std::unordered_map<uint64_t, std::string> addr_to_name;
        std::unordered_map<uint64_t, std::string> addr_to_fullname;
        std::vector<std::pair<int32_t, uint64_t>> object_ptrs;

        if (m_hasCachedNames && !m_cachedObjectPtrs.empty()) {
            std::printf("[sdk] using cached name data from Run() (%zu names, %zu objects)\n",
                m_cachedAddrToName.size(), m_cachedObjectPtrs.size());
            addr_to_name     = m_cachedAddrToName;
            addr_to_fullname = m_cachedAddrToFullname;
            object_ptrs      = m_cachedObjectPtrs;
        } else {
            std::cout << "[*] Building name map (live scan)...\n";
            addr_to_name.reserve(obj_count);
            addr_to_fullname.reserve(obj_count);
            object_ptrs.reserve(obj_count);
            for (int32_t i = 0; i < obj_count; ++i) {
                uint64_t obj_ptr = m_gobj.GetObjectPtr(i);
                if (!obj_ptr) continue;
                object_ptrs.push_back({i, obj_ptr});
                std::string full = m_fname.GetName(obj_ptr);
                if (full.empty()) {
                    int32_t Ci = m_fname.DecryptFFieldNameCI(obj_ptr - 8);
                    if (Ci > 1) full = m_fname.CompIndexToNameLenient(Ci);
                }
                if (!full.empty()) {
                    bool Plausible = full.size() <= 256;
                    if (Plausible) {
                        for (unsigned char Cc : full) {
                            if (Cc < 0x20 || Cc > 0x7E) { Plausible = false; break; }
                        }
                    }
                    if (Plausible) {
                        addr_to_fullname[obj_ptr] = full;
                        size_t dot = full.rfind('.');
                        addr_to_name[obj_ptr] = (dot != std::string::npos) ? full.substr(dot + 1) : full;
                    }
                }
                if (i % 10000 == 0)
                    std::cout << "\r[*] Scanning: " << i << "/" << obj_count << "  " << std::flush;
            }
        }
        std::printf("[+] Name map: %zu entries\n", addr_to_name.size());

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
            for (const auto& p : rec.properties)
                if (p.name.rfind("Prop_CI", 0) != 0) ++n_named;
            for (const auto& fn : rec.functions) {
                n_properties += fn.params.size();
                n_param_props += fn.params.size();
                for (const auto& p : fn.params)
                    if (p.name.rfind("Prop_CI", 0) != 0) ++n_named;
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
        {
            std::unordered_map<std::string, uint32_t> TypeHist;
            for (const auto& Rec : sdk.structs)
                for (const auto& P : Rec.properties) {
                    std::string Base = P.type_name;
                    if (Base.find("TArray<") == 0) Base = "TArray<...>";
                    else if (Base.find("TMap<") == 0) Base = "TMap<...>";
                    else if (Base.find("TSet<") == 0) Base = "TSet<...>";
                    else if (Base.find("TSubclassOf<") == 0) Base = "TSubclassOf<...>";
                    else if (Base.find("TScriptInterface<") == 0) Base = "TScriptInterface<...>";
                    else if (Base.find("TDelegate<") == 0) Base = "TDelegate<...>";
                    else if (Base.size() > 2 && Base.back() == '*') Base = "Object*";
                    TypeHist[Base]++;
                }
            std::vector<std::pair<std::string, uint32_t>> Sorted(TypeHist.begin(), TypeHist.end());
            std::sort(Sorted.begin(), Sorted.end(),
                      [](const auto& A, const auto& B){ return A.second > B.second; });
            std::printf("[type-hist] Property type distribution (top 20):\n");
            for (size_t I = 0; I < std::min<size_t>(Sorted.size(), 20); ++I)
                std::printf("[type-hist]   %-40s  %u\n", Sorted[I].first.c_str(), Sorted[I].second);
            uint32_t Unk = TypeHist.count("FProperty_Unknown") ? TypeHist["FProperty_Unknown"] : 0;
            std::printf("[type-hist] FProperty_Unknown: %u / %llu (%.1f%%)\n",
                Unk, (unsigned long long)n_struct_props,
                n_struct_props ? 100.0 * Unk / n_struct_props : 0.0);
        }
        SteamBuildInfo SteamInfo = ReadSteamBuildInfo();
        std::ofstream sdk_file("SDK_Output.txt");
        if (!sdk_file) { std::cerr << "[-] Cannot open SDK_Output.txt\n"; return; }

        // Summary header (mirrors reference tool format)
        sdk_file << "// ============================================================\n"
                 << "// ARC Raiders SDK - FrostDumper\n"
                 << "// Dumper build:  " __DATE__ " " __TIME__ "\n"
                 << "// Game build:    Steam AppID 1808500"
                 << (SteamInfo.BuildId.empty() ? std::string()
                        : "  buildid " + SteamInfo.BuildId) << "\n"
                 << "// Game updated:  " << (SteamInfo.Updated.empty() ? "unknown" : SteamInfo.Updated) << "\n"
                 << "// Image size:    0x" << std::hex << AutoDiscovery::g_DiscoveredBounds.ImageSize
                 << std::dec << "  (module base 0x" << std::hex << MODULE_BASE << std::dec << ")\n"
                 << "// FName pipeline: " << (m_fname.IsV808Active() ? "v20260808" : "legacy") << "\n"
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
            // Write orphan functions (functions whose owner wasn't dumped as a type).
            // Walk parameters via ReadFunctionsFromMap so each orphan emits a real
            // signature instead of a stub line — recovers ~85% of UFunctions that
            // would otherwise be dropped.
            sdk_file << "\n// === Orphan Functions ===\n";
            sdk_file << "namespace Globals {\n";
            int orphan_count = 0;
            for (const auto& [owner, fn_list] : gen.GetOwnerFuncMap()) {
                if (seen_owners.count(owner)) continue;
                std::string owner_name = "Owner_0x";
                char buf[32]; std::snprintf(buf, sizeof(buf), "%llX", (unsigned long long)owner);
                owner_name += buf;
                std::string owner_resolved = m_fname.GetName(owner);
                sdk_file << "// Orphan owner @ 0x" << std::hex << owner;
                if (!owner_resolved.empty()) sdk_file << " (" << owner_resolved << ")";
                sdk_file << " — " << std::dec << fn_list.size() << " functions\n";
                sdk_file << "namespace " << owner_name << " {\n";
                auto fns = gen.ReadFunctionsFromMap(owner);
                for (const auto& fn : fns) {
                    sdk_file << gen.FormatFunction(fn);
                    ++orphan_count;
                }
                sdk_file << "} // namespace " << owner_name << "\n";
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

        // Dumper-7 style per-package tree (opt-in via Generator::kEmitDumper7).
        if (SDKGen::Generator::kEmitDumper7) {
            gen.EmitDumper7(sdk, ".");
        }

        DumpBoneArrays(object_ptrs, addr_to_name, addr_to_fullname);
    }

    int ProbeBoneArrayOffset(const std::vector<uint64_t>& SkeletonAddrs)
    {
        constexpr uint32_t kBoneInfoStride = 12;
        constexpr uint32_t kMaxBones = 2048;
        constexpr int kFallback = 0xE8;

        int SampleCount = (int)std::min<size_t>(SkeletonAddrs.size(), 8);
        std::unordered_map<int, int> OffsetVotes;

        for (int S = 0; S < SampleCount; S++) {
            uint8_t Obj[0x400];
            if (!m_reader.Read(SkeletonAddrs[S], Obj, sizeof(Obj))) continue;

            for (int Off = 0x80; Off <= 0x200; Off += 8) {
                uint64_t ArrPtr = 0;
                uint32_t ArrCount = 0, ArrMax = 0;
                std::memcpy(&ArrPtr, Obj + Off, 8);
                std::memcpy(&ArrCount, Obj + Off + 8, 4);
                std::memcpy(&ArrMax, Obj + Off + 12, 4);

                if (ArrPtr < 0x10000ULL || ArrPtr > 0xFFFFFFFFFFFFULL) continue;
                if (ArrCount < 1 || ArrCount > kMaxBones) continue;
                if (ArrMax < ArrCount || ArrMax > kMaxBones * 2) continue;

                uint32_t ReadSize = std::min(ArrCount, 32u) * kBoneInfoStride;
                std::vector<uint8_t> Buf(ReadSize);
                if (!m_reader.Read(ArrPtr, Buf.data(), ReadSize)) continue;

                if (ArrCount >= 2) {
                    int32_t Parent0 = 0;
                    std::memcpy(&Parent0, Buf.data() + 8, 4);
                    if (Parent0 != -1 && Parent0 != 0) continue;

                    bool ValidHierarchy = true;
                    uint32_t CheckCount = std::min(ArrCount, 32u);
                    for (uint32_t I = 1; I < CheckCount; I++) {
                        int32_t P = 0;
                        std::memcpy(&P, Buf.data() + I * kBoneInfoStride + 8, 4);
                        if (P < -1 || P >= (int32_t)ArrCount || (P >= (int32_t)I && I > 0)) {
                            ValidHierarchy = false;
                            break;
                        }
                    }
                    if (!ValidHierarchy) continue;
                }

                int32_t Ci0 = 0;
                std::memcpy(&Ci0, Buf.data(), 4);
                if (Ci0 <= 0 || Ci0 > 50000000) continue;

                std::string TestName = m_fname.CompIndexToName(Ci0);
                if (TestName.empty()) continue;

                OffsetVotes[Off]++;
            }
        }

        if (OffsetVotes.empty()) {
            std::printf("[bones-probe] no valid offset found, using fallback +0x%X\n", kFallback);
            return kFallback;
        }

        int BestOff = kFallback, BestVotes = 0;
        for (const auto& [Off, Votes] : OffsetVotes) {
            if (Votes > BestVotes) { BestVotes = Votes; BestOff = Off; }
        }
        std::printf("[bones-probe] auto-discovered BoneInfo offset: +0x%X (%d/%d skeletons voted)\n",
            BestOff, BestVotes, SampleCount);
        return BestOff;
    }

    void DumpBoneArrays(
            const std::vector<std::pair<int32_t, uint64_t>>& ObjectPtrs,
            const std::unordered_map<uint64_t, std::string>& AddrToName,
            const std::unordered_map<uint64_t, std::string>& AddrToFullname)
    {
        constexpr uint32_t kBoneInfoStride  = 12;
        constexpr uint32_t kMaxBones        = 2048;

        std::vector<uint64_t> SkeletonAddrs;
        for (const auto& [Idx, ObjPtr] : ObjectPtrs) {
            auto It = AddrToName.find(ObjPtr);
            if (It == AddrToName.end()) continue;
            uint64_t ClsPtr = m_fname.GetClassPrivate(ObjPtr);
            std::string ClsName = m_fname.GetName(ClsPtr);
            if (ClsName == "Skeleton")
                SkeletonAddrs.push_back(ObjPtr);
        }
        if (SkeletonAddrs.empty()) {
            std::printf("[bones] no USkeleton objects found\n");
            return;
        }
        std::printf("[bones] found %zu USkeleton objects\n", SkeletonAddrs.size());

        m_boneArrayOffset = ProbeBoneArrayOffset(SkeletonAddrs);
        int BoneArrayOffset = m_boneArrayOffset;

        std::ofstream Out("dump_bones.txt");
        if (!Out) { std::printf("[bones] failed to open dump_bones.txt\n"); return; }
        Out << "// ============================================================\n";
        Out << "// ARC Raiders – Skeleton Bone Dump\n";
        Out << "// USkeleton objects: " << SkeletonAddrs.size() << "\n";
        Out << "// BoneInfo offset: +0x" << std::hex << BoneArrayOffset << std::dec << "\n";
        Out << "// ============================================================\n\n";

        uint32_t TotalSkeletons = 0, TotalBones = 0;

        for (uint64_t SkelPtr : SkeletonAddrs) {
            auto FullIt = AddrToFullname.find(SkelPtr);
            std::string SkelName = (FullIt != AddrToFullname.end()) ? FullIt->second : "???";

            uint64_t ArrPtr = 0;
            uint32_t ArrCount = 0, ArrMax = 0;
            if (!m_reader.Read(SkelPtr + BoneArrayOffset, &ArrPtr, 8)) continue;
            if (!m_reader.Read(SkelPtr + BoneArrayOffset + 8, &ArrCount, 4)) continue;
            if (!m_reader.Read(SkelPtr + BoneArrayOffset + 12, &ArrMax, 4)) continue;

            if (ArrCount == 0 || ArrCount > kMaxBones || ArrPtr < 0x10000ULL) continue;

            std::vector<uint8_t> Buf(ArrCount * kBoneInfoStride);
            if (!m_reader.Read(ArrPtr, Buf.data(), Buf.size())) continue;

            struct BoneInfo { int32_t CompIndex; int32_t Number; int32_t ParentIndex; };
            std::vector<BoneInfo> Bones(ArrCount);
            for (uint32_t i = 0; i < ArrCount; ++i) {
                std::memcpy(&Bones[i].CompIndex,   Buf.data() + i * kBoneInfoStride + 0, 4);
                std::memcpy(&Bones[i].Number,      Buf.data() + i * kBoneInfoStride + 4, 4);
                std::memcpy(&Bones[i].ParentIndex, Buf.data() + i * kBoneInfoStride + 8, 4);
            }

            bool AnyValid = false;
            for (uint32_t i = 0; i < ArrCount; ++i) {
                if (Bones[i].CompIndex > 0) { AnyValid = true; break; }
            }
            if (!AnyValid) continue;

            Out << "// " << SkelName << "  (0x" << std::hex << SkelPtr << ")\n";
            Out << "// Bones: " << std::dec << ArrCount << "\n";
            Out << "enum class " << [&]() -> std::string {
                std::string S = SkelName;
                size_t Dot = S.rfind('.');
                if (Dot != std::string::npos) S = S.substr(Dot + 1);
                for (char& C : S) if (C == '-' || C == ' ' || C == '/') C = '_';
                return S;
            }() << "_Bones {\n";

            for (uint32_t i = 0; i < ArrCount; ++i) {
                std::string BoneName = m_fname.CompIndexToName(Bones[i].CompIndex);
                if (BoneName.empty())
                    BoneName = "Bone_CI" + std::to_string(Bones[i].CompIndex);
                if (Bones[i].Number > 0)
                    BoneName += "_" + std::to_string(Bones[i].Number);

                Out << "    " << BoneName << " = " << std::dec << i;
                Out << ", // parent=" << Bones[i].ParentIndex << "\n";
            }
            Out << "};\n\n";

            ++TotalSkeletons;
            TotalBones += ArrCount;
        }

        Out.close();
        std::printf("[bones] dumped %u skeletons, %u total bones → dump_bones.txt\n",
            TotalSkeletons, TotalBones);
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
        uint32_t valid = 0, failed = 0, empty = 0, stale = 0;
        uint32_t staleVt = 0, staleCi = 0, staleResolve = 0;
        std::set<std::string>                uniqueNames;
        std::unordered_map<std::string, int> nameCount;
        m_cachedObjectPtrs.clear();
        m_cachedObjectPtrs.reserve(obj_count);
        m_cachedAddrToName.clear();
        m_cachedAddrToFullname.clear();
        m_cachedAddrToName.reserve(obj_count);
        m_cachedAddrToFullname.reserve(obj_count);

        uint64_t VtLo = MODULE_BASE + 0x1000;
        uint64_t VtHi = MODULE_BASE + (AutoDiscovery::g_DiscoveredBounds.Valid
            ? AutoDiscovery::g_DiscoveredBounds.ImageSize
            : 0x117E1000ULL);
        uint32_t ConsecutiveReadFails = 0;

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

            uint64_t Vt = 0;
            if (!m_reader.Read(obj_ptr, &Vt, 8)) {
                ++ConsecutiveReadFails;
                if (ConsecutiveReadFails >= 500) {
                    std::printf("\n[!] %u consecutive read failures — game likely crashed (PID %d)\n",
                        ConsecutiveReadFails, m_pid);
                    stale += (obj_count - i);
                    staleVt += (obj_count - i);
                    break;
                }
                ++stale; ++staleVt;
                continue;
            }
            ConsecutiveReadFails = 0;
            if (Vt < VtLo || Vt >= VtHi || (Vt & 0x7) != 0) {
                ++stale; ++staleVt;
                continue;
            }

            m_cachedObjectPtrs.push_back({i, obj_ptr});

            std::string name = m_fname.GetName(obj_ptr);
            if (name.empty()) {
                int32_t Ci = m_fname.DecryptFFieldNameCI(obj_ptr - 8);
                if (Ci > 1) name = m_fname.CompIndexToNameLenient(Ci);
            }
            if (name.empty()) {
                if (m_fname.WasLastHashSlotStale()) {
                    ++stale; ++staleResolve;
                } else {
                    fObjects << "[" << i << "] " << Hex(obj_ptr) << " | <no name>\n";
                    ++failed;
                }
                continue;
            }

            // Sanitize name (strip non-printable)
            for (char& c : name)
                if (c < 0x20 || c > 0x7E) c = '?';

            fObjects << "[" << i << "] " << Hex(obj_ptr) << " | " << name << "\n";
            uniqueNames.insert(name);
            nameCount[name]++;

            m_cachedAddrToFullname[obj_ptr] = name;
            {
                size_t dot = name.rfind('.');
                m_cachedAddrToName[obj_ptr] = (dot != std::string::npos) ? name.substr(dot + 1) : name;
            }

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

        uint32_t LiveTotal = valid + failed;
        double Pct = LiveTotal > 0 ? 100.0 * valid / LiveTotal : 0.0;
        std::cout << "\r[+] Scan done: " << valid << " named, "
                  << failed << " failed, " << stale << " stale/freed, " << empty << " empty slots\n";
        std::printf("  Naming rate (live objects): %u / %u = %.1f%%\n", valid, LiveTotal, Pct);

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
        std::cout << "  Stale/freed    : " << stale << "  (vtable=" << staleVt << " resolve=" << staleResolve << ")\n";
        std::cout << "  Failed / empty : " << failed << " / " << empty << "\n";
        std::cout << "  Unique names   : " << uniqueNames.size() << "\n";
        std::cout << "  Time           : " << std::fixed << std::setprecision(1) << ms << " ms\n";
        std::cout << "\nOutput files: dump_objects.txt  dump_names.txt  dump_classes.txt  dump_log.txt\n";

        fLog << "[" << Now() << "] Dump complete.\n";
        fLog << "  valid=" << valid << " failed=" << failed << " empty=" << empty << "\n";
        fLog << "  unique_names=" << uniqueNames.size() << "\n";
        fLog << "  elapsed_ms=" << ms << "\n";

        m_hasCachedNames = true;
        std::printf("[run] cached %zu names, %zu objects for SDK generator\n",
            m_cachedAddrToName.size(), m_cachedObjectPtrs.size());
    }

    void EmitDecryptCode() {
        FILE* F = fopen("generated_decrypt.h", "w");
        if (!F) { std::printf("[-] Cannot open generated_decrypt.h for writing\n"); return; }

        const auto& Fl  = AutoDiscovery::g_DiscoveredFFieldLayout;
        const auto& Fp  = AutoDiscovery::g_DiscoveredFPropertyLayout;
        const auto& Sv  = AutoDiscovery::g_DiscoveredSlotV709;
        const auto& Sh  = AutoDiscovery::g_DiscoveredSlotHash;
        const auto& Pipe = AutoDiscovery::g_DiscoveredFNamePipeline;
        const auto& Sd  = AutoDiscovery::g_DiscoveredStringDecrypt;
        const auto& Gn  = AutoDiscovery::g_DiscoveredGNames;
        const auto& Gw  = AutoDiscovery::g_DiscoveredWorld;

        namespace V709 = ArcDecrypt::v20260709;

        int SlotRol64  = Sv.Valid ? Sv.Rol64First : V709::UOBJ_SLOT_ROL64_FIRST;
        int SlotShuf   = Sv.Valid ? Sv.PshuflwImm : V709::UOBJ_SLOT_PSHUFLW;
        int SlotRol32  = Sv.Valid ? Sv.Rol32Per   : V709::UOBJ_SLOT_ROL32_PER;

        uint32_t PropertyXor = Fp.Valid ? Fp.OffsetXorKey
            : static_cast<uint32_t>(ArcDecrypt::Offsets::FProperty::Offset_XOR);

        uint64_t FFieldXor = Fl.Valid ? Fl.XorKey : V709::FFIELD_NAME_XOR_KEY;
        int FFieldRol16    = Fl.Valid ? Fl.Rol16Amount : 12;
        int FFieldRol64    = Fl.Valid ? Fl.Rol64Amount : V709::FFIELD_NAME_ROL64;

        uint32_t ShardHashAdd = Pipe.Valid ? Pipe.ShardHashAdd : V709::SHARD_HASH_ADD;
        uint64_t BlockFnvXor  = Pipe.Valid ? Pipe.BlockFnvXor  : V709::BLOCK_FNV_XOR;
        int      BlockRol64   = Pipe.Valid ? Pipe.BlockRol64    : V709::BLOCK_ROL64;
        uint8_t  BlockShuf    = Pipe.Valid ? Pipe.BlockPshuflw  : V709::BLOCK_PSHUFLW;
        uint64_t FnvAdd       = Pipe.Valid ? Pipe.FnvAdd        : V709::FNV_ADD;
        int      FnvRol1      = Pipe.Valid ? Pipe.FnvRol1       : V709::FNV_ROL1;
        int      FnvRol2      = Pipe.Valid ? Pipe.FnvRol2       : V709::FNV_ROL2;

        int SlotMul = Pipe.SlotSelectValid ? Pipe.SlotSelectMul : -109;
        int SlotAdd = Pipe.SlotSelectValid ? Pipe.SlotSelectAdd : 82;

        uint64_t PtrXor0 = (Pipe.PtrXorCount >= 1) ? Pipe.PtrXor[0] : V709::FNAME_PTR_XOR1;
        uint64_t PtrXor1 = (Pipe.PtrXorCount >= 2) ? Pipe.PtrXor[1] : V709::FNAME_PTR_XOR2;
        uint64_t PtrXor2 = (Pipe.PtrXorCount >= 3) ? Pipe.PtrXor[2] : V709::FNAME_PTR_XOR3;

        int ShardRolCount = Pipe.ShardHashValid ? Pipe.ShardHashRolCount : 2;
        int ShardRols[4] = {17, 13, 0, 0};
        if (Pipe.ShardHashValid) {
            for (int I = 0; I < Pipe.ShardHashRolCount && I < 4; I++)
                ShardRols[I] = Pipe.ShardHashRols[I];
        }
        int ShardFinalShift = 13;
        if (Pipe.ShardHashValid && Pipe.ShardHashFinalShift != 0)
            ShardFinalShift = Pipe.ShardHashFinalShift;
        else if (Pipe.ShardHashValid && Pipe.ShardHashRolCount >= 2)
            ShardFinalShift = Pipe.ShardHashRols[1];

        uint64_t ShardSeedOff = Pipe.Valid ? Pipe.ShardSeedOff : 0x2F90;
        uint64_t ShardBlockOff = Pipe.Valid ? Pipe.ShardBlockBaseOff : 0x2FA0;

        uint32_t SlotHashAdd = Sh.Valid ? Sh.SlotHashAdd : V709::SLOT_HASH_ADD;

        int HdrShift = Sd.Valid ? Sd.HdrLengthShift : V709::HDR_LENGTH_SHIFT;
        uint16_t WideBit = Sd.Valid ? Sd.HdrIsWideBit : V709::HDR_IS_WIDE_BIT;
        uint32_t KeyInitAdd = Sd.Valid ? Sd.KeyInitAdd : 0xA7B4;
        uint32_t KeyMulAdv  = Sd.Valid ? Sd.KeyMulAdvance : 0x6DDC5690;
        uint32_t KeyAddAdv  = Sd.Valid ? Sd.KeyAddAdvance : 0x5EBF2255;
        uint32_t KeyMulInn  = Sd.Valid ? Sd.KeyMulInner : 0xFFFF584C;
        uint32_t KeyAddInn  = Sd.Valid ? Sd.KeyAddInner : 0xF629;
        uint8_t  KeyMask    = Sd.Valid ? Sd.KeyIndexMask : 0x3F;

        uint64_t GNamePoolBase = Gn.Valid ? Gn.GNamesRva : 0xE4F2A00;
        uint64_t KeyTableRva   = Gn.Valid ? Gn.SimdBlockRva : 0xE4317F4;
        uint64_t GWorldRva     = Gw.Valid ? Gw.GWorldRva : ArcDecrypt::RVA_GWORLD;
        uint64_t GObjArrayRva  = ArcDecrypt::RVA_GOBJECT_ARRAY_BASE;

        uint32_t UObjSlotOff   = static_cast<uint32_t>(ArcDecrypt::Offsets::UObject::FieldsSlots);
        uint32_t UObjSlotStride = 0x20;

        fprintf(F,
"#pragma once\n"
"// =============================================================================\n"
"// ARC Raiders — Auto-Generated Decrypt Functions\n"
"// Generated by FrostDumper on %s\n"
"// Patch image size: 0x%X\n"
"// =============================================================================\n"
"//\n"
"// USAGE: #include this file. Provide ReadMemory(uint64_t addr, void* buf, size_t len)\n"
"//        and MODULE_BASE (e.g. 0x140000000 for Wine).\n"
"//\n"
"// All functions are standalone, no dependencies except <cstdint> and <cstring>.\n"
"// =============================================================================\n"
"\n"
"#include <cstdint>\n"
"#include <cstring>\n"
"\n"
"#ifndef MODULE_BASE\n"
"#define MODULE_BASE 0x140000000ULL\n"
"#endif\n"
"\n"
"#ifndef READ_MEMORY\n"
"#error \"Define READ_MEMORY(addr, buf, len) before including this file\"\n"
"#endif\n"
"\n"
"namespace ArcDecrypt {\n"
"\n"
"// ─── Helpers ─────────────────────────────────────────────────────────────────\n"
"\n"
"static inline uint32_t Rotl32(uint32_t X, int N) { return (X << N) | (X >> (32 - N)); }\n"
"static inline uint64_t Rotl64(uint64_t X, int N) { return (X << N) | (X >> (64 - N)); }\n"
"static inline uint32_t Bswap32(uint32_t X) {\n"
"    return ((X >> 24) & 0xFF) | ((X >> 8) & 0xFF00) |\n"
"           ((X << 8) & 0xFF0000) | ((X << 24) & 0xFF000000);\n"
"}\n"
"static inline uint64_t Bswap64(uint64_t X) {\n"
"    X = ((X & 0x00000000FFFFFFFFULL) << 32) | ((X & 0xFFFFFFFF00000000ULL) >> 32);\n"
"    X = ((X & 0x0000FFFF0000FFFFULL) << 16) | ((X & 0xFFFF0000FFFF0000ULL) >> 16);\n"
"    X = ((X & 0x00FF00FF00FF00FFULL) << 8)  | ((X & 0xFF00FF00FF00FF00ULL) >> 8);\n"
"    return X;\n"
"}\n"
"\n"
"static inline uint64_t SoftPshuflw(uint64_t V, int Imm) {\n"
"    uint16_t W[4];\n"
"    memcpy(W, &V, 8);\n"
"    uint16_t R[4] = {\n"
"        W[(Imm >> 0) & 3], W[(Imm >> 2) & 3],\n"
"        W[(Imm >> 4) & 3], W[(Imm >> 6) & 3]\n"
"    };\n"
"    uint64_t Out;\n"
"    memcpy(&Out, R, 8);\n"
"    return Out;\n"
"}\n"
"\n"
"static inline void SoftPshufb8(uint8_t Out[8], const uint8_t In[8], const uint8_t Mask[8]) {\n"
"    for (int I = 0; I < 8; I++)\n"
"        Out[I] = (Mask[I] & 0x80) ? 0 : In[Mask[I] & 7];\n"
"}\n"
"\n", __DATE__ " " __TIME__,
        (unsigned)AutoDiscovery::g_DiscoveredBounds.ImageSize);

        fprintf(F,
"// ─── Constants (auto-discovered from binary) ─────────────────────────────────\n"
"\n"
"constexpr uint64_t GNAME_POOL_BASE    = 0x%llXULL;  // MODULE_BASE + this\n"
"constexpr uint64_t KEY_TABLE_RVA      = 0x%llXULL;  // MODULE_BASE + this\n"
"constexpr uint64_t GWORLD_RVA         = 0x%llXULL;  // MODULE_BASE + this → UWorld**\n"
"constexpr uint64_t GOBJECT_ARRAY_RVA  = 0x%llXULL;  // MODULE_BASE + this → FChunkedFixedUObjectArray\n"
"\n",
        (unsigned long long)GNamePoolBase,
        (unsigned long long)KeyTableRva,
        (unsigned long long)GWorldRva,
        (unsigned long long)GObjArrayRva);

        fprintf(F,
"// ─── 1. UObject Slot Decode ──────────────────────────────────────────────────\n"
"// Pipeline: ROL64(%d) → PSHUFLW(0x%02X) → ROL32(%d) → extract lo64\n"
"// Input: 16 bytes from UObject + 0x%X (stride 0x%X, 4 slots)\n"
"// Output: lo32 = ComparisonIndex, hi32 = FName::Number\n"
"\n"
"static inline uint64_t DecryptUObjectSlot(const uint8_t Enc[16]) {\n"
"    uint64_t Lo, Hi;\n"
"    memcpy(&Lo, Enc, 8);\n"
"    memcpy(&Hi, Enc + 8, 8);\n"
"    Lo = Rotl64(Lo, %d);\n"
"    Hi = Rotl64(Hi, %d);\n"
"    Lo = SoftPshuflw(Lo, 0x%02X);\n"
"    uint32_t D0 = Rotl32((uint32_t)Lo, %d);\n"
"    uint32_t D1 = Rotl32((uint32_t)(Lo >> 32), %d);\n"
"    return (uint64_t)D0 | ((uint64_t)D1 << 32);\n"
"}\n"
"\n",
        SlotRol64, SlotShuf, SlotRol32, UObjSlotOff, UObjSlotStride,
        SlotRol64, SlotRol64, SlotShuf, SlotRol32, SlotRol32);

        if (AutoDiscovery::g_DiscoveredQDSlot.Valid) {
            std::string QDCode = QDProgramToC(AutoDiscovery::g_DiscoveredQDSlot.Program, "DecryptUObjectSlot_QD");
            fprintf(F,
"// ─── 1b. QD-recorded UObject Slot Decode (generic, auto-recorded from binary) ───\n"
"%s\n", QDCode.c_str());
        }

        fprintf(F,
"// ─── 2. UObject Slot Hash (selects which of 4 slots to read) ────────────────\n"
"// FNV32-based, input is UObject address + 0x10\n"
"\n"
"static inline int ComputeSlotIndex(uint64_t ObjAddr) {\n"
"    uint64_t P = ObjAddr + 0x10;\n"
"    uint32_t Lo = (uint32_t)P;\n"
"    uint32_t Hi = (uint32_t)(P >> 32);\n"
"    uint32_t H = Rotl32(Lo, 25) * 0x01000193u + 0x%08Xu;\n"
"    H = Rotl32(H, 15) * 0x01000193u + Hi + 0x%08Xu;\n"
"    H = Rotl32(H, 25) * 0x01000193u + 0x%08Xu;\n"
"    H = Rotl32(H, 15) * 0x01000193u + 0x%08Xu;\n"
"    return ((H ^ (H >> 16)) & 3) ^ 2;\n"
"}\n"
"\n"
"static inline uint32_t GetUObjectCI(uint64_t ObjAddr) {\n"
"    int Slot = ComputeSlotIndex(ObjAddr);\n"
"    uint8_t Enc[16];\n"
"    READ_MEMORY(ObjAddr + 0x%X + Slot * 0x%X, Enc, 16);\n"
"    return (uint32_t)DecryptUObjectSlot(Enc);\n"
"}\n"
"\n",
        SlotHashAdd, SlotHashAdd, SlotHashAdd, SlotHashAdd,
        UObjSlotOff, UObjSlotStride);

        fprintf(F,
"// ─── 3. FField NamePrivate Decode ────────────────────────────────────────────\n"
"// Decrypts the encrypted ComparisonIndex stored at FField + 0x%X\n"
"// Pipeline: ", Fl.Valid ? Fl.NamePrivateOff : 0xA0);

        if (Fl.PipelineValid) {
            for (int I = 0; I < Fl.PipelineLen; I++) {
                if (I > 0) fprintf(F, " → ");
                switch (Fl.Pipeline[I]) {
                    case AutoDiscovery::FFOP_XOR64:  fprintf(F, "XOR64"); break;
                    case AutoDiscovery::FFOP_PSHUFB: fprintf(F, "PSHUFB"); break;
                    case AutoDiscovery::FFOP_ROL16:  fprintf(F, "ROL16(%d)", FFieldRol16); break;
                    case AutoDiscovery::FFOP_PSHUFLW:fprintf(F, "PSHUFLW"); break;
                    case AutoDiscovery::FFOP_ROL32:  fprintf(F, "ROL32"); break;
                    case AutoDiscovery::FFOP_ROL64:  fprintf(F, "ROL64(%d)", FFieldRol64); break;
                }
            }
        } else {
            fprintf(F, "XOR64 → ROL16(%d) → PSHUFB → ROL64(%d)", FFieldRol16, FFieldRol64);
        }

        fprintf(F, "\n"
"\n"
"static inline uint32_t DecryptFFieldName(uint64_t Encrypted) {\n"
"    uint64_t V = Encrypted;\n");

        if (Fl.PipelineValid) {
            for (int I = 0; I < Fl.PipelineLen; I++) {
                switch (Fl.Pipeline[I]) {
                    case AutoDiscovery::FFOP_XOR64:
                        fprintf(F, "    V ^= 0x%016llXULL;\n", (unsigned long long)FFieldXor);
                        break;
                    case AutoDiscovery::FFOP_ROL16: {
                        int Amt = FFieldRol16;
                        fprintf(F,
"    { uint16_t W[4]; memcpy(W, &V, 8);\n"
"      for (int I = 0; I < 4; I++) W[I] = (W[I] << %d) | (W[I] >> %d);\n"
"      memcpy(&V, W, 8); }\n", Amt, 16 - Amt);
                        break;
                    }
                    case AutoDiscovery::FFOP_PSHUFB:
                        fprintf(F,
"    { uint8_t Mask[8] = {0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X};\n"
"      uint8_t In[8], Out[8]; memcpy(In, &V, 8);\n"
"      SoftPshufb8(Out, In, Mask); memcpy(&V, Out, 8); }\n",
                            Fl.PshufbMask[0], Fl.PshufbMask[1], Fl.PshufbMask[2], Fl.PshufbMask[3],
                            Fl.PshufbMask[4], Fl.PshufbMask[5], Fl.PshufbMask[6], Fl.PshufbMask[7]);
                        break;
                    case AutoDiscovery::FFOP_PSHUFLW:
                        fprintf(F, "    V = SoftPshuflw(V, 0x%02X);\n", Fl.PshuflwImm);
                        break;
                    case AutoDiscovery::FFOP_ROL32:
                        fprintf(F,
"    { uint32_t D0 = Rotl32((uint32_t)V, %d);\n"
"      uint32_t D1 = Rotl32((uint32_t)(V >> 32), %d);\n"
"      V = (uint64_t)D0 | ((uint64_t)D1 << 32); }\n",
                            Fl.Rol32Amount, Fl.Rol32Amount);
                        break;
                    case AutoDiscovery::FFOP_ROL64:
                        fprintf(F, "    V = Rotl64(V, %d);\n", FFieldRol64);
                        break;
                }
            }
        } else {
            fprintf(F,
"    V ^= 0x%016llXULL;\n"
"    { uint16_t W[4]; memcpy(W, &V, 8);\n"
"      for (int I = 0; I < 4; I++) W[I] = (W[I] << %d) | (W[I] >> %d);\n"
"      memcpy(&V, W, 8); }\n"
"    { uint8_t Mask[8] = {0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X};\n"
"      uint8_t In[8], Out[8]; memcpy(In, &V, 8);\n"
"      SoftPshufb8(Out, In, Mask); memcpy(&V, Out, 8); }\n"
"    V = Rotl64(V, %d);\n",
                (unsigned long long)FFieldXor,
                FFieldRol16, 16 - FFieldRol16,
                Fl.PshufbMask[0], Fl.PshufbMask[1], Fl.PshufbMask[2], Fl.PshufbMask[3],
                Fl.PshufbMask[4], Fl.PshufbMask[5], Fl.PshufbMask[6], Fl.PshufbMask[7],
                FFieldRol64);
        }

        fprintf(F,
"    return (uint32_t)V;\n"
"}\n"
"\n");

        fprintf(F,
"// ─── 4. FProperty Offset Decode ──────────────────────────────────────────────\n"
"\n"
"static inline int32_t DecryptPropertyOffset(uint32_t Stored) {\n"
"    return (int32_t)(Bswap32(Stored) ^ 0x%08Xu);\n"
"}\n"
"\n", PropertyXor);

        fprintf(F,
"// ─── 5. FName Resolution (ComparisonIndex → string) ─────────────────────────\n"
"// Shard hash: FNV32 with ROLs, slot-select formula: (%d*T+%d) ^ ((P*T+ADD)>>16) & 7\n"
"// Block decode: ROL64(%d) → PSHUFLW(0x%02X) → XOR\n"
"// FNV64 fold: ROL(%d) + ADD, ROL(%d) + ADD\n"
"// Pointer: 3-step bswap+XOR chain\n"
"\n"
"static inline uint64_t FNameResolveEntry(uint32_t CI) {\n"
"    uint32_t NameOff = CI & 0xFFFF;\n"
"    uint32_t ChunkOff = (CI >> 8) & 0xFFFF00;\n"
"    uint64_t ChunkAddr = MODULE_BASE + GNAME_POOL_BASE + ChunkOff;\n"
"\n"
"    // Shard hash\n"
"    uint64_t SeedAddr = ChunkAddr + 0x%llXULL;\n"
"    uint32_t SeedLo = 0, SeedHi = 0;\n"
"    READ_MEMORY(SeedAddr, &SeedLo, 4);\n"
"    READ_MEMORY(SeedAddr + 4, &SeedHi, 4);\n"
"    uint32_t H = 0x01000193u * Rotl32(SeedLo, %d) + 0x%08Xu;\n"
"    H = 0x01000193u * Rotl32(H, %d) + SeedHi + 0x%08Xu;\n"
"    H = 0x01000193u * Rotl32(H, %d) + 0x%08Xu;\n"
"    uint32_t T = Rotl32(H, %d);\n"
"    uint8_t Pa = (uint8_t)(%d * T + %d);\n"
"    uint8_t Pb = (uint8_t)((0x01000193u * T + 0x%08Xu) >> 16);\n"
"    int Bidx1 = (Pa ^ Pb) & 7;\n"
"    int Bidx2 = (Bidx1 + 1) & 7;\n"
"\n"
"    // Block decode\n"
"    uint64_t BlockBase = ChunkAddr + 0x%llXULL;\n"
"    uint64_t Raw1 = 0, Raw2 = 0;\n"
"    READ_MEMORY(BlockBase + Bidx1 * 32, &Raw1, 8);\n"
"    READ_MEMORY(BlockBase + Bidx2 * 32, &Raw2, 8);\n"
"    uint64_t B1 = SoftPshuflw(Rotl64(Raw1, %d), 0x%02X) ^ 0x%016llXULL;\n"
"    uint64_t B2 = SoftPshuflw(Rotl64(Raw2, %d), 0x%02X) ^ 0x%016llXULL;\n"
"\n"
"    // FNV64 chain\n"
"    uint64_t Fv1 = 0x100000001B3ULL * Rotl64(B1, %d) + 0x%016llXULL;\n"
"    uint64_t Fv2 = 0x100000001B3ULL * Rotl64(Fv1, %d) + 0x%016llXULL;\n"
"    uint64_t RawPtr = B1 + (B2 ^ Fv2) + 2 * NameOff;\n"
"\n"
"    // Pointer XOR chain\n"
"    uint64_t Step1 = Bswap64(RawPtr ^ 0x%016llXULL);\n"
"    uint64_t Step2 = Step1 ^ 0x%016llXULL;\n"
"    uint64_t EntryPtr = Bswap64(Step2 ^ 0x%016llXULL);\n"
"    return EntryPtr;\n"
"}\n"
"\n",
        SlotMul, SlotAdd, BlockRol64, BlockShuf, FnvRol1, FnvRol2,
        (unsigned long long)ShardSeedOff,
        ShardRols[0], ShardHashAdd,
        ShardRols[1], ShardHashAdd,
        ShardRols[0], ShardHashAdd,
        ShardFinalShift,
        SlotMul, SlotAdd, ShardHashAdd,
        (unsigned long long)ShardBlockOff,
        BlockRol64, BlockShuf, (unsigned long long)BlockFnvXor,
        BlockRol64, BlockShuf, (unsigned long long)BlockFnvXor,
        FnvRol1, (unsigned long long)FnvAdd,
        FnvRol2, (unsigned long long)FnvAdd,
        (unsigned long long)PtrXor0,
        (unsigned long long)PtrXor1,
        (unsigned long long)PtrXor2);

        fprintf(F,
"// ─── 6. String Decrypt (FNameEntry → readable string) ───────────────────────\n"
"// Header: length = hdr >> %d, isWide = (hdr & 0x%X) != 0\n"
"// Key schedule: init = length + 0x%X, advance = key * 0x%X + 0x%X\n"
"\n"
"static inline int FNameDecryptString(uint64_t EntryPtr, char* OutBuf, int MaxLen) {\n"
"    uint16_t Hdr = 0;\n"
"    READ_MEMORY(EntryPtr, &Hdr, 2);\n"
"    int Length = Hdr >> %d;\n"
"    bool IsWide = (Hdr & 0x%X) != 0;\n"
"    if (Length <= 0 || Length > MaxLen - 1) return 0;\n"
"\n"
"    uint16_t KeyTable[64];\n"
"    READ_MEMORY(MODULE_BASE + KEY_TABLE_RVA + 0xE8, KeyTable, sizeof(KeyTable));\n"
"\n"
"    if (!IsWide) {\n"
"        uint8_t Buf[1024];\n"
"        int ByteLen = Length * 2;\n"
"        if (ByteLen > 1024) ByteLen = 1024;\n"
"        READ_MEMORY(EntryPtr + 2, Buf, ByteLen);\n"
"        uint32_t Key = (uint32_t)(Length + 0x%Xu);\n"
"        for (int I = 0; I < ByteLen; I += 2) {\n"
"            Buf[I]     ^= (uint8_t)(KeyTable[Key & 0x%Xu] >> 3);\n"
"            uint32_t Idx2 = (Key * 0x%Xu + 0x%Xu) & 0x%Xu;\n"
"            if (I + 1 < ByteLen)\n"
"                Buf[I + 1] ^= (uint8_t)(KeyTable[Idx2] >> 3);\n"
"            Key = Key * 0x%Xu + 0x%Xu;\n"
"        }\n"
"        int OutLen = 0;\n"
"        for (int I = 0; I < ByteLen && OutLen < MaxLen - 1; I++) {\n"
"            if (Buf[I] >= 0x20 && Buf[I] < 0x7F)\n"
"                OutBuf[OutLen++] = (char)Buf[I];\n"
"        }\n"
"        OutBuf[OutLen] = 0;\n"
"        return OutLen;\n"
"    }\n"
"    return 0;\n"
"}\n"
"\n",
        HdrShift, WideBit, KeyInitAdd, KeyMulAdv, KeyAddAdv,
        HdrShift, WideBit,
        KeyInitAdd, KeyMask, KeyMulInn, KeyAddInn, KeyMask,
        KeyMulAdv, KeyAddAdv);

        fprintf(F,
"// ─── 7. Full FName Resolve (CI → string, convenience wrapper) ───────────────\n"
"\n"
"static inline int ResolveFName(uint32_t CI, char* OutBuf, int MaxLen) {\n"
"    if (CI == 0) { OutBuf[0] = 0; return 0; }\n"
"    uint64_t Entry = FNameResolveEntry(CI);\n"
"    if (Entry < 0x10000 || Entry > 0x7FFFFFFFFFFFULL) { OutBuf[0] = 0; return 0; }\n"
"    return FNameDecryptString(Entry, OutBuf, MaxLen);\n"
"}\n"
"\n");

        fprintf(F,
"// ─── 7b. UWorld Access ──────────────────────────────────────────────────────\n"
"\n"
"static inline uint64_t GetUWorld() {\n"
"    uint64_t Ptr = 0;\n"
"    READ_MEMORY(MODULE_BASE + GWORLD_RVA, &Ptr, 8);\n"
"    return Ptr;\n"
"}\n"
"\n");

        fprintf(F,
"// ─── 8. Player Name Decrypt (FNV-1a stream cipher) ──────────────────────────\n"
"// Steam variant: UTF-16, single-round FNV-1a\n"
"// Constants from game binary (update per patch if changed):\n"
"//   InnerKey = FNV offset basis modifier\n"
"//   Rol32Key = ROL amount for hash mixing\n"
"\n"
"static inline void DecryptPlayerName(uint16_t* S, int MaxChars,\n"
"                                      uint32_t InnerKey = 0x87400B27,\n"
"                                      int Rol32Key = 22) {\n"
"    if (!S || MaxChars < 2) return;\n"
"    uint16_t Ch = S[0];\n"
"    if (Ch == 0) return;\n"
"    int32_t V8 = 0;\n"
"    for (int I = 0; I < MaxChars && Ch != 0; I++) {\n"
"        int32_t Inner = 0x1000193 * V8 + (int32_t)InnerKey;\n"
"        int32_t Rotated = (int32_t)Rotl32((uint32_t)Inner, Rol32Key);\n"
"        int32_t V9 = V8 + Rotated;\n"
"        V8 = 0x1000193 * V9;\n"
"        int32_t V10 = Ch ^ ((-109 * (uint8_t)V9) & 0x1F);\n"
"        int32_t V11 = 0;\n"
"        if ((uint32_t)(V10 - 80) < 0x2F) V11 = -47;\n"
"        if ((uint32_t)(V10 - 33) < 0x2F) V11 = 47;\n"
"        uint32_t V12 = V11 + V10 - 48;\n"
"        uint32_t V13 = V11 + V10 - 53;\n"
"        int32_t V14 = V10 + V11;\n"
"        int32_t V15 = 5 * (V13 >= 5) - 5;\n"
"        if (V12 < 5) V15 = 5;\n"
"        int32_t V16 = V14 + V15;\n"
"        int32_t V17 = 0;\n"
"        if ((uint32_t)(V15 + V14 - 110) < 0xD) V17 = -13;\n"
"        if ((uint32_t)(V15 + V14 - 97) < 0xD) V17 = 13;\n"
"        int32_t V18 = V16 + V17;\n"
"        int32_t V19 = 0;\n"
"        if ((uint32_t)(V17 + V16 - 78) < 0xD) V19 = -13;\n"
"        if ((uint32_t)(V17 + V16 - 65) < 0xD) V19 = 13;\n"
"        uint32_t V20 = V19 + V18 - 33;\n"
"        uint32_t V21 = V19 + V18 - 80;\n"
"        int16_t V22 = (int16_t)(V18 + V19);\n"
"        int16_t V23 = 0;\n"
"        if (V21 < 0x2F) V23 = -47;\n"
"        if (V20 < 0x2F) V23 = 47;\n"
"        S[I] = (uint16_t)(V22 + V23);\n"
"        if (I + 1 < MaxChars) Ch = S[I + 1]; else break;\n"
"    }\n"
"}\n"
"\n");

        fprintf(F,
"// ─── 9. Bone Array (USkeleton) ──────────────────────────────────────────────\n"
"// USkeleton::ReferenceSkeleton contains TArray<FMeshBoneInfo> (auto-probed).\n"
"// Each FMeshBoneInfo = { FName(CompIndex, Number), int32 ParentIndex } = 12 bytes.\n"
"// FNames resolve through the standard FName pipeline (no separate bone decrypt).\n"
"constexpr uint32_t USkeleton_BoneArrayOffset = 0x%X;\n"
"constexpr uint32_t BoneInfoStride            = 12;\n"
"\n", m_boneArrayOffset);

        fprintf(F,
"// ─── Layout Offsets ──────────────────────────────────────────────────────────\n"
"\n"
"namespace Offsets {\n"
"    constexpr uint32_t UObject_Slot0          = 0x%X;\n"
"    constexpr uint32_t UObject_SlotStride     = 0x%X;\n"
"    constexpr uint32_t UStruct_SuperStruct    = 0x%X;\n"
"    constexpr uint32_t UStruct_ChildProperties = 0x%X;\n"
"    constexpr uint32_t UStruct_PropertiesSize = 0x%X;\n"
"    constexpr uint32_t FField_NamePrivate     = 0x%X;\n"
"    constexpr uint32_t FField_Next            = 0x%X;\n"
"    constexpr uint32_t FField_Owner           = 0x%X;\n"
"    constexpr uint32_t FField_ClassPrivate    = 0x%X;\n"
"    constexpr uint32_t FProperty_Offset       = 0x%X;\n"
"    constexpr uint32_t FProperty_ElementSize  = 0x%X;\n"
"    constexpr uint32_t FProperty_ArrayDim     = 0x%X;\n"
"    constexpr uint32_t FStructProperty_Struct = 0x%X;\n"
"    constexpr uint32_t FObjectProperty_Class  = 0x%X;\n"
"    constexpr uint32_t FBoolProperty_FieldSize = 0x%X;\n"
"    constexpr uint32_t FArrayProperty_Inner   = 0x%X;\n"
"    constexpr uint32_t UFunction_NativeFunc   = 0x%X;\n"
"} // namespace Offsets\n"
"\n"
"} // namespace ArcDecrypt\n",
        UObjSlotOff, UObjSlotStride,
        (unsigned)ArcDecrypt::Offsets::UStruct::SuperStruct,
        Fl.Valid ? Fl.ChildPropsOff : (unsigned)ArcDecrypt::Offsets::UStruct::ChildProperties,
        (unsigned)ArcDecrypt::Offsets::UStruct::PropertiesSize,
        Fl.Valid ? Fl.NamePrivateOff : (unsigned)ArcDecrypt::Offsets::FField::NamePrivate,
        Fl.Valid ? Fl.NextOff : (unsigned)ArcDecrypt::Offsets::FField::Next,
        Fl.Valid ? Fl.OwnerOff : (unsigned)ArcDecrypt::Offsets::FField::Owner,
        Fl.Valid ? Fl.ClassPrivateOff : (unsigned)ArcDecrypt::Offsets::FField::ClassPrivate,
        Fp.Valid ? Fp.OffsetInternalOff : (unsigned)ArcDecrypt::Offsets::FProperty::Offset_Internal,
        Fp.Valid ? Fp.ElementSizeOff : (unsigned)ArcDecrypt::Offsets::FProperty::ElementSize,
        Fp.Valid ? Fp.ArrayDimOff : (unsigned)ArcDecrypt::Offsets::FProperty::ArrayDim,
        (unsigned)ArcDecrypt::Offsets::FStructProperty::Struct,
        (unsigned)ArcDecrypt::Offsets::FObjectProperty::PropertyClass,
        (unsigned)ArcDecrypt::Offsets::FBoolProperty::FieldSize,
        (unsigned)ArcDecrypt::Offsets::FArrayProperty::Inner,
        (unsigned)ArcDecrypt::Offsets::UFunction::NativeFunc);

        fclose(F);
        std::printf("[codegen] Wrote generated_decrypt.h with all auto-discovered constants\n");
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IOLBF, 0);   // line-buffered: see real progress in piped logs
    std::cout << "======================================\n";
    std::cout << "  ARC Raiders SDK Dumper\n";
    std::cout << "  Newest patch (FChunkedFixedUObjectArray)\n";
    std::cout << "  Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "======================================\n\n";

    int pid = 0;
    bool do_sdk   = false, do_test = false, do_dump = false, do_probe = false;
    bool want_help = false;
    bool do_decrypt_handle = false, do_test_gobj = false;
    bool do_scan_chunks = false, do_list_uobjects = false;
    uint64_t decrypt_handle_val = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { want_help = true; continue; }
        if (arg == "--sdk")       { do_sdk   = true; continue; }
        if (arg == "--test")      { do_test  = true; continue; }
        if (arg == "--dump")      { do_dump  = true; continue; }
        if (arg == "--probe")     { do_probe = true; continue; }
        if (arg == "--test-gobj")  { do_test_gobj = true; continue; }
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
            "No flags → full automatic SDK dump (sig-scan + sdk/SDK_Output.txt + dump_*.txt).\n"
            "Mode flags (override the auto behaviour for development / debugging):\n"
            "  --test       Sample known FName CIs to verify decryptor.\n"
            "  --dump       Enumerate GObjects → dump_*.txt.\n"
            "  --sdk        Full C++ SDK → sdk/SDK_Output.txt.\n"
            "  --probe      FField / property CI probes.\n"
            "  --decrypt-handle <hex>\n"
            "               Patch 20260421 test: apply bswap64(X ^ 0x59B07C3D00000000)\n"
            "               to the given raw FName handle and print the entry pointer.\n"
            "  --test-gobj  Patch 20260421: read live GUObjectArray (0xDDCB420),\n"
            "               apply new decrypt pipeline, print chunks_manager + max.\n"
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

        // Probe the first few UObjects: dump 0x100 bytes and locate the FName
        // handle slot by trying every 8-byte offset and checking whether
        // DecryptEntryHandle lands on a plausible heap pointer whose first
        // uint16 looks like an FNameEntry header (non-zero, length bits <1023).
        auto lookLikeEntryHdr = [&](uint64_t entry_ptr) -> bool {
            if (entry_ptr < 0x10000ULL || entry_ptr >= 0x800000000000ULL) return false;
            uint16_t hdr = 0;
            if (!r.Read(entry_ptr, &hdr, 2)) return false;
            if (!hdr) return false;
            int charCount = hdr & 0x3FF;
            return charCount > 0 && charCount < 1023;
        };
        // Read raw bytes at a candidate FNameEntry and print both the hex
        // and an ASCII interpretation so we can eyeball whether it's really
        // an FNameEntry (either plain-text or XOR-encrypted with the keystream).
        auto sniffEntry = [&](uint64_t entry_ptr) {
            uint8_t raw[48] = {};
            if (!r.Read(entry_ptr, raw, sizeof(raw))) { std::printf(" <read-fail>"); return; }
            uint16_t hdr = 0; std::memcpy(&hdr, raw, 2);
            int charCount = hdr & 0x3FF;
            bool isWide = (hdr & 0x8000) != 0;
            std::printf(" hdr=0x%04X len=%d%s  hex:", hdr, charCount, isWide?" wide":"");
            for (int k = 2; k < 2 + std::min(charCount, 20); ++k) std::printf(" %02X", raw[k]);
            std::printf("  ascii:'");
            for (int k = 2; k < 2 + std::min(charCount, 20); ++k)
                std::printf("%c", (raw[k] >= 32 && raw[k] < 127) ? raw[k] : '.');
            std::printf("'");
        };

        int limit = 6;
        std::printf("[list] scanning first %d UObjects for FName handle offset...\n", limit);
        std::unordered_map<int, int> hits_by_off;
        for (uint32_t i = 0; i < array_count && i < (uint32_t)limit; ++i) {
            uint64_t item = array_start + (uint64_t)STRIDE * i;
            uint64_t obj = 0;
            if (!r.Read(item, &obj, 8) || !obj) continue;
            uint8_t dump[0x100] = {};
            if (!r.Read(obj, dump, 0x100)) continue;

            std::printf("\n[list] [%u] obj=0x%012llX raw first 0x100 bytes:\n",
                i, (unsigned long long)obj);
            for (int row = 0; row < 0x10; ++row) {
                std::printf("  +%02X:", row * 16);
                for (int col = 0; col < 16; ++col)
                    std::printf(" %02X", dump[row * 16 + col]);
                std::printf("\n");
            }

            std::printf("[list]   probing handle candidates:\n");
            for (int off = 0; off + 8 <= 0x100; off += 8) {
                uint64_t h = 0;
                std::memcpy(&h, dump + off, 8);
                if (!h) continue;
                if (lookLikeEntryHdr(h)) {
                    std::printf("    +0x%02X: PLAIN ptr=0x%012llX", off, (unsigned long long)h);
                    sniffEntry(h);
                    std::printf("\n");
                    hits_by_off[off]++;
                }
                uint64_t entry = ArcDecrypt::Patch20260421::DecryptEntryHandle(h);
                if (entry != h && lookLikeEntryHdr(entry)) {
                    std::printf("    +0x%02X: HANDLE 0x%016llX → entry=0x%012llX",
                        off, (unsigned long long)h, (unsigned long long)entry);
                    sniffEntry(entry);
                    std::printf("\n");
                    hits_by_off[off | 0x1000]++;
                }
            }
        }
        std::printf("\n[list] offset frequency (handle→entry-header looked valid):\n");
        for (auto& kv : hits_by_off)
            std::printf("  +0x%02X: %d/%d hits\n", kv.first, kv.second, limit);
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
        std::printf("[test-gobj] chunk-ptr-array access requires structural scan (see Init())\n");
        return 0;
    }

    // Default behaviour — no flags = full automatic SDK dump.
    // The `--test`, `--dump`, `--probe` flags are diagnostic
    // overrides retained for development; passing none of them runs the
    // canonical pipeline (sig-scan + autodiscovery + sdk/SDK_Output.txt).
    // dump_*.txt comes free as side output of DumpSDK's GObject walk.
    if (!do_sdk && !do_test && !do_dump && !do_probe) {
        do_sdk  = true;
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

    if (!dumper.Init()) {
        std::cerr << "[-] Initialization failed. Check:\n";
        std::cerr << "    * Is memreader.ko loaded?  (sudo insmod ../KernelDriver/src/memreader.ko)\n";
        std::cerr << "    * Are you running as root? (sudo)\n";
        std::cerr << "    * Is the PID correct?\n";
        return 1;
    }

    if (do_test)  dumper.TestNames();
    if (do_dump)  dumper.Run();
    if (do_probe) { dumper.ProbeFField(); dumper.ProbePropertyCIs(); }
    if (do_sdk)   dumper.DumpSDK();

    dumper.EmitDecryptCode();

    return 0;
}
