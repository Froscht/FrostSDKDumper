// probe_uobject_fullname.cpp — ground-truth validator for the dumper's
// static name decoder. Boots Unicorn against the live game, calls the real
// UObject::GetFullName, reads back the FString, and compares with whatever
// FrostDumper's static path would have produced.
//
// Usage:
//   sudo ./probe_uobject_fullname <PID> [UObjectAddr]
//   sudo ./probe_uobject_fullname <PID>             # samples 10 random named objs
//
// Verified anchors (patch 20260428):
//   UObject::GetFullName = module + 0x4FF420
//   FString layout       = { TCHAR* Data, int32 Num, int32 Max }  (16 bytes)
//
// Calling convention (Win64): RCX = this UObject*, RDX = output FString*,
//                             R8  = StopOuter (NULL), R9 = flags (default 0)
// Returns: RAX = output FString* (same as RDX)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <random>
#include <algorithm>

#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include "memreader_iface.h"
#include "memreader_ioctl.h"
#include "emu_engine.h"
#include "fname_decrypt.h"
#include "gobjects.h"

using EmuEngineNS::EmuEngine;
using FNameDecryptor = FName::FNameDecryptor;

static constexpr uint64_t MODULE_BASE       = 0x140000000ULL;
static constexpr uint64_t MODULE_SIZE       = 0xE9AF000ULL;
static constexpr uint64_t RVA_GETFULLNAME   = 0x4FF420ULL;
static constexpr uint64_t FAKE_PEB_ADDR     = 0x7FFD0000ULL;
static constexpr uint64_t FSTRING_OUT_ADDR  = 0x00040000ULL;
static constexpr uint64_t FSTRING_BUF_ADDR  = 0x00041000ULL;

// Mirror of KernelReader from main.cpp — minimal copy so the probe does not
// pull in main.cpp's SDKDumper symbol soup.
class KernelReader : public IMemoryReader {
public:
    int fd  = -1;
    int pid = 0;

    ~KernelReader() override { if (fd >= 0) close(fd); }

    bool Open(int target_pid) {
        pid = target_pid;
        if (fd < 0) {
            fd = open("/dev/memreader", O_RDWR);
            if (fd < 0) {
                std::printf("[!] /dev/memreader unavailable (%s) — using process_vm_readv only\n",
                            std::strerror(errno));
            }
        }
        return true;
    }

    bool IsOpen() const { return pid > 0; }

    bool Read(uint64_t address, void* buffer, size_t size) override {
        if (!buffer || !size) return false;
        struct iovec local  = { buffer, size };
        struct iovec remote = { reinterpret_cast<void*>(address), size };
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n == static_cast<ssize_t>(size)) return true;
        if (fd < 0) return false;
        struct memreader_read_request req = {};
        req.pid     = pid;
        req.address = static_cast<unsigned long>(address);
        req.size    = static_cast<unsigned long>(size);
        req.buffer  = buffer;
        return ioctl(fd, MEMREADER_READ_MEMORY, &req) == 0;
    }
};

// ── Locate latest Arc_Raiders_Binary_*.exe alongside the probe binary ───────
static std::string FindPEBinary() {
    const char* dir = "/media/frost/Coding Stuf/Linux/FrostSDKDumper";
    char glob_buf[1024];
    std::string best;
    FILE* p = popen((std::string("ls -1 \"") + dir + "\"/Arc_Raiders_Binary_*.exe 2>/dev/null").c_str(), "r");
    if (p) {
        while (fgets(glob_buf, sizeof(glob_buf), p)) {
            std::string s = glob_buf;
            if (!s.empty() && s.back() == '\n') s.pop_back();
            if (s > best) best = s;
        }
        pclose(p);
    }
    if (!best.empty())
        std::printf("[pe] PE binary: %s\n", best.c_str());
    else
        std::printf("[pe] no Arc_Raiders_Binary_*.exe — fallback disabled\n");
    return best;
}

// ── Auto-detect ARC PID via /proc (mirror of FindARCPid in main.cpp) ────────
static int FindARCPid() {
    FILE* p = popen("pgrep GameThread", "r");
    if (!p) return -1;
    int pid = -1;
    char line[64];
    while (fgets(line, sizeof(line), p)) {
        int candidate = atoi(line);
        if (candidate <= 0) continue;
        char cm[256];
        snprintf(cm, sizeof(cm), "/proc/%d/cmdline", candidate);
        FILE* cf = fopen(cm, "r");
        if (!cf) continue;
        char buf[512] = {};
        fread(buf, 1, sizeof(buf) - 1, cf);
        fclose(cf);
        if (strstr(buf, "CrashReportClient")) continue;
        pid = candidate;
        break;
    }
    pclose(p);
    return pid;
}

// ─────────────────────────────────────────────────────────────────────────────
// EmuFullName — wraps the UObject::GetFullName call inside Unicorn.
// ─────────────────────────────────────────────────────────────────────────────
class EmuFullName {
public:
    bool Init(EmuEngine* eng, uint64_t module_base, uint64_t func_rva) {
        if (!eng || !eng->IsReady()) return false;
        m_eng     = eng;
        m_funcAbs = module_base + func_rva;

        // Map scratch pages for FString out-struct + heap-style data buffer.
        uc_mem_map(m_eng->UC(), FSTRING_OUT_ADDR, 0x1000, UC_PROT_ALL);
        uc_mem_map(m_eng->UC(), FSTRING_BUF_ADDR, 0x4000, UC_PROT_ALL);

        // One-time fake TEB / PEB setup (same as EmuFName).
        constexpr uint64_t FAKE_TEB = 0x00007FFF'FFFE0000ULL;
        uc_mem_map(m_eng->UC(), FAKE_TEB, 0x1000, UC_PROT_ALL);
        uint8_t zeros[0x1000] = {};
        uc_mem_write(m_eng->UC(), FAKE_TEB, zeros, sizeof(zeros));

        uint64_t stack_base  = EmuEngine::STACK_BASE + EmuEngine::STACK_SIZE;
        uint64_t stack_limit = EmuEngine::STACK_BASE;
        uint64_t self_ptr    = FAKE_TEB;
        uint64_t peb         = FAKE_PEB_ADDR;

        uc_mem_write(m_eng->UC(), FAKE_TEB + 0x08, &stack_base,  8);
        uc_mem_write(m_eng->UC(), FAKE_TEB + 0x10, &stack_limit, 8);
        uc_mem_write(m_eng->UC(), FAKE_TEB + 0x30, &self_ptr,    8);
        uc_mem_write(m_eng->UC(), FAKE_TEB + 0x60, &peb,         8);
        m_eng->SetGSBase(FAKE_TEB);
        m_eng->MapGamePage(FAKE_PEB_ADDR);

        std::printf("[FullName] target @ abs=0x%llX (rva=0x%llX), fake TEB=0x%llX, PEB=0x%llX\n",
                    (unsigned long long)m_funcAbs,
                    (unsigned long long)func_rva,
                    (unsigned long long)FAKE_TEB,
                    (unsigned long long)FAKE_PEB_ADDR);
        return true;
    }

    std::string Call(uint64_t uobj) {
        if (!m_eng || !uobj) return {};

        // Zero out the FString out-struct + heap buffer before each call.
        uint8_t zero_out[0x40] = {};
        m_eng->EmuWrite(FSTRING_OUT_ADDR, zero_out, sizeof(zero_out));
        uint8_t zero_buf[0x100] = {};
        m_eng->EmuWrite(FSTRING_BUF_ADDR, zero_buf, sizeof(zero_buf));

        m_eng->ResetCPU();

        const uint64_t rsp = EmuEngine::STACK_BASE + EmuEngine::STACK_SIZE - 0x28;
        m_eng->WriteReg(UC_X86_REG_RSP, rsp);
        m_eng->WriteReg(UC_X86_REG_RBP, rsp);
        const uint64_t sentinel = EmuEngine::SENTINEL_RIP;
        m_eng->EmuWrite(rsp, &sentinel, 8);

        m_eng->WriteReg(UC_X86_REG_RCX, uobj);              // this UObject*
        m_eng->WriteReg(UC_X86_REG_RDX, FSTRING_OUT_ADDR);  // out FString*
        m_eng->WriteReg(UC_X86_REG_R8,  0);                 // StopOuter = null
        m_eng->WriteReg(UC_X86_REG_R9,  0);                 // flags = default

        uc_err err = m_eng->Run(m_funcAbs,
                                EmuEngine::SENTINEL_RIP,
                                /*timeout_us*/ 30'000'000,
                                /*max_insns */ 5'000'000);

        if (err != UC_ERR_OK) {
            uint64_t rip = m_eng->ReadReg(UC_X86_REG_RIP);
            std::printf("[FullName] uc_emu_start err=%d (%s) RIP=0x%llX  fault=0x%llX (type=%d)\n",
                        (int)err, uc_strerror(err),
                        (unsigned long long)rip,
                        (unsigned long long)m_eng->LastFaultAddr(),
                        m_eng->LastFaultType());
            return {};
        }

        // Read FString header { TCHAR* Data, int32 Num, int32 Max }.
        uint8_t hdr[16] = {};
        if (!m_eng->EmuRead(FSTRING_OUT_ADDR, hdr, sizeof(hdr))) return {};

        uint64_t data_ptr = 0;
        int32_t  num      = 0;
        std::memcpy(&data_ptr, hdr, 8);
        std::memcpy(&num,      hdr + 8, 4);

        if (num <= 0 || num > 1024) return {};
        if (data_ptr < 0x1000 || data_ptr >= 0x800000000000ULL) return {};

        std::vector<uint8_t> wbuf(static_cast<size_t>(num) * 2);
        if (!m_eng->EmuRead(data_ptr, wbuf.data(), wbuf.size())) return {};

        std::string out;
        out.reserve(num);
        for (int32_t j = 0; j < num; ++j) {
            uint16_t wc = (uint16_t)wbuf[j*2] | ((uint16_t)wbuf[j*2+1] << 8);
            if (wc == 0) break;
            out.push_back(wc < 0x80 ? (char)wc : '?');
        }
        return out;
    }

private:
    EmuEngine* m_eng     = nullptr;
    uint64_t   m_funcAbs = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// Static GetFullName equivalent — reproduces UE format
// "<Class> <Outer1>.<Outer2>...<Object>"
// using the existing FNameDecryptor primitives. This is the dumper's
// ground-truth-equivalent that we want to validate.
// ─────────────────────────────────────────────────────────────────────────────
static std::string DumperGetFullName(FNameDecryptor& fname, uint64_t obj) {
    if (!obj) return {};

    std::string self_name = fname.GetName(obj);
    if (self_name.empty()) return {};

    uint64_t cls = fname.GetClassPrivate(obj);
    std::string cls_name = cls ? fname.GetName(cls) : std::string();

    // Walk Outer chain, collect names in reverse, terminate at UPackage or
    // when the chain stops or repeats.
    std::vector<std::string> chain;
    uint64_t cur = obj;
    for (int depth = 0; depth < 32; ++depth) {
        uint64_t outer = fname.GetOuterPtr(cur);
        if (!outer || outer == cur) break;
        std::string nm = fname.GetName(outer);
        if (nm.empty()) break;
        chain.push_back(nm);
        cur = outer;
    }

    std::string path;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        if (!path.empty()) path += '.';
        path += *it;
    }
    if (!path.empty()) path += '.';
    path += self_name;

    if (cls_name.empty()) return path;
    return cls_name + " " + path;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-map the .text region around GetFullName so the function's static jumps
// land in already-mapped pages and the lazy fault path doesn't thrash.
// ─────────────────────────────────────────────────────────────────────────────
static void PreloadCriticalRanges(EmuEngine& eng) {
    // GetFullName + AppendTCHAR + FName::ToString + GetName cluster (.text).
    // These are conservative ranges around each verified anchor.
    eng.PreMapRange(MODULE_BASE + 0x4FF000ULL,  0x4000);   // GetFullName + neighbors
    eng.PreMapRange(MODULE_BASE + 0x4FA000ULL,  0x4000);   // GetPathName + Recursive
    eng.PreMapRange(MODULE_BASE + 0x35EB00ULL,  0x2000);   // GetName
    eng.PreMapRange(MODULE_BASE + 0x24BE000ULL, 0x4000);   // FName::ToString
    // Common .rdata (vtables, FName pool ptr, security cookie, key tables)
    eng.PreMapRange(MODULE_BASE + 0xAB70000ULL, 0x10000);  // vtable cluster
    eng.PreMapRange(MODULE_BASE + 0xDAA0000ULL, 0x10000);  // FName key/pool tables
}

// ─────────────────────────────────────────────────────────────────────────────
// Pick N named UObjects pseudo-randomly from GObjects.
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<uint64_t> PickRandomObjects(gobjects::GObjectArray& gobj,
                                               FNameDecryptor& fname,
                                               int want)
{
    std::vector<uint64_t> picks;
    int total = (int)gobj.GetNumElements();
    if (total <= 0) return picks;

    std::mt19937 rng(0xF005BA11);
    std::uniform_int_distribution<int> dist(0, total - 1);

    int attempts = 0;
    while ((int)picks.size() < want && attempts < want * 200) {
        ++attempts;
        int idx = dist(rng);
        uint64_t op = gobj.GetObjectPtr(idx);
        if (!op) continue;
        std::string n = fname.GetName(op);
        if (n.empty()) continue;
        // Skip pure package names (start with "/Script/" or "/Game/") so we
        // exercise objects that have meaningful Outer chains.
        if (n.size() > 1 && n[0] == '/') continue;
        // Skip duplicates
        bool dup = false;
        for (auto p : picks) if (p == op) { dup = true; break; }
        if (dup) continue;
        picks.push_back(op);
    }
    return picks;
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    int      pid       = 0;
    uint64_t single_obj = 0;

    if (argc >= 2) pid = atoi(argv[1]);
    if (argc >= 3) single_obj = std::strtoull(argv[2], nullptr, 0);
    if (!pid) pid = FindARCPid();
    if (pid <= 0) {
        std::fprintf(stderr, "[-] no PID supplied and auto-detect failed\n");
        return 1;
    }
    std::printf("[+] PID = %d\n", pid);

    KernelReader reader;
    reader.Open(pid);

    // Boot Unicorn engine + PE fallback.
    EmuEngine eng;
    std::string pe = FindPEBinary();
    if (!eng.Initialize(&reader, MODULE_BASE, MODULE_SIZE,
                        pe.empty() ? nullptr : pe.c_str())) {
        std::fprintf(stderr, "[-] EmuEngine init failed\n");
        return 1;
    }
    PreloadCriticalRanges(eng);

    EmuFullName ef;
    if (!ef.Init(&eng, MODULE_BASE, RVA_GETFULLNAME)) {
        std::fprintf(stderr, "[-] EmuFullName init failed\n");
        return 1;
    }

    // ── Single-object mode ──────────────────────────────────────────────────
    if (single_obj) {
        std::string out = ef.Call(single_obj);
        std::printf("\n=== single-object probe ===\n");
        std::printf("UObject*       : 0x%llX\n", (unsigned long long)single_obj);
        std::printf("EMU GetFullName: \"%s\"\n", out.c_str());
        return 0;
    }

    // ── Comparison mode: pick 10 random named objects and compare ──────────
    FNameDecryptor fname(MODULE_BASE, reader);
    if (!fname.Init()) {
        std::fprintf(stderr, "[!] FNameDecryptor::Init returned false — proceeding anyway\n");
    }

    gobjects::GObjectArray gobj(MODULE_BASE, reader);
    gobj.SetPid(pid);
    if (!gobj.Init()) {
        std::fprintf(stderr, "[-] GObjectArray::Init failed\n");
        return 1;
    }
    std::printf("[+] GObjects ready, count=%d\n", (int)gobj.GetNumElements());

    auto picks = PickRandomObjects(gobj, fname, 10);
    if (picks.empty()) {
        std::fprintf(stderr, "[-] could not pick any named objects\n");
        return 1;
    }

    std::printf("\n=== 10-object comparison: dumper vs emu ===\n");
    std::printf("%-3s  %-18s  %-50s  %-50s  %s\n",
                "#", "UObject*", "DUMPER OUTPUT", "EMU OUTPUT", "MATCH");
    std::printf("%-3s  %-18s  %-50s  %-50s  %s\n",
                "---", "------------------",
                "--------------------------------------------------",
                "--------------------------------------------------",
                "-----");

    int match = 0, total = 0;
    for (size_t i = 0; i < picks.size(); ++i) {
        uint64_t obj = picks[i];
        std::string dumper = DumperGetFullName(fname, obj);
        std::string emu    = ef.Call(obj);
        bool eq = (!dumper.empty() && !emu.empty() && dumper == emu);
        ++total;
        if (eq) ++match;
        char addrbuf[24];
        snprintf(addrbuf, sizeof(addrbuf), "0x%llX", (unsigned long long)obj);
        auto trim = [](const std::string& s, size_t n) {
            if (s.size() <= n) return s;
            return s.substr(0, n - 3) + "...";
        };
        std::printf("%-3zu  %-18s  %-50s  %-50s  %s\n",
                    i + 1,
                    addrbuf,
                    trim(dumper, 50).c_str(),
                    trim(emu, 50).c_str(),
                    eq ? "MATCH" : "MISMATCH");
    }
    std::printf("\nResult: %d / %d match\n", match, total);
    return 0;
}
