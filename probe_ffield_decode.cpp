#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <unordered_set>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <immintrin.h>

#include "memreader_ioctl.h"
#include "memreader_iface.h"
#include "arc_decrypt.h"
#include "sig_scan.h"
#include "find_fname_func.h"
#include "gobjects.h"
#include "fname_decrypt.h"

class KernelMemReader : public IMemoryReader {
public:
    int Fd = -1;
    int Pid = 0;
    KernelMemReader(int Pid) : Pid(Pid) { Fd = open("/dev/memreader", O_RDWR); }
    ~KernelMemReader() { if (Fd >= 0) close(Fd); }
    bool Read(uint64_t Addr, void* Buf, size_t Sz) override {
        if (Fd >= 0) {
            memreader_read_request Req{};
            Req.pid = Pid;
            Req.address = Addr;
            Req.size = Sz;
            Req.buffer = Buf;
            if (ioctl(Fd, MEMREADER_READ_MEMORY, &Req) == 0) return true;
        }
        struct iovec L{ Buf, Sz };
        struct iovec R{ (void*)Addr, Sz };
        return process_vm_readv(Pid, &L, 1, &R, 1, 0) == (ssize_t)Sz;
    }
};

static int FindGamePid() {
    DIR* D = opendir("/proc");
    if (!D) return 0;
    int Best = 0;
    while (auto* E = readdir(D)) {
        if (E->d_type != DT_DIR) continue;
        int Pid = atoi(E->d_name);
        if (Pid <= 0) continue;
        char P[256];
        snprintf(P, sizeof(P), "/proc/%d/comm", Pid);
        FILE* F = fopen(P, "r");
        if (!F) continue;
        char Comm[64] = {};
        fgets(Comm, sizeof(Comm), F);
        fclose(F);
        if (!strstr(Comm, "GameThread")) continue;
        snprintf(P, sizeof(P), "/proc/%d/cmdline", Pid);
        F = fopen(P, "r");
        if (!F) continue;
        char Cmd[1024] = {};
        fread(Cmd, 1, sizeof(Cmd) - 1, F);
        fclose(F);
        if (strstr(Cmd, "CrashReportClient")) continue;
        Best = Pid;
        break;
    }
    closedir(D);
    return Best;
}

template <typename T>
static T Rd(IMemoryReader& R, uint64_t Addr, T Def = T{}) {
    T V{};
    return R.Read(Addr, &V, sizeof(V)) ? V : Def;
}

static uint64_t Rotl64(uint64_t X, int N) { return (X << N) | (X >> (64 - N)); }

static __m128i RolEpi64(__m128i V, int N) {
    return _mm_or_si128(_mm_slli_epi64(V, N), _mm_srli_epi64(V, 64 - N));
}
static __m128i RolEpi16(__m128i V, int N) {
    return _mm_or_si128(_mm_slli_epi16(V, N), _mm_srli_epi16(V, 16 - N));
}

struct CandidateResult {
    const char* Name;
    uint32_t Ci;
    std::string DecodedName;
};

static std::vector<CandidateResult> RunPipelines(const uint8_t* Enc16, FName::FNameDecryptor& Fn) {
    std::vector<CandidateResult> Out;
    auto Try = [&](const char* PipeName, uint64_t FinalLo64) {
        uint64_t Rot = (FinalLo64 >> 32) | (FinalLo64 << 32);
        uint32_t Ci = static_cast<uint32_t>(Rot & 0xFFFFFFFFu);
        std::string Name;
        if (Ci > 1 && Ci < 0x4000000u) {
            uint64_t Ptr = Fn.ResolveNamePtrFull(static_cast<int32_t>(Ci));
            if (Ptr) Name = Fn.DecryptNameString(Ptr);
        }
        Out.push_back({ PipeName, Ci, Name });
    };
    auto TryNoRot = [&](const char* PipeName, uint64_t FinalLo64) {
        uint32_t Ci = static_cast<uint32_t>(FinalLo64 & 0xFFFFFFFFu);
        std::string Name;
        if (Ci > 1 && Ci < 0x4000000u) {
            uint64_t Ptr = Fn.ResolveNamePtrFull(static_cast<int32_t>(Ci));
            if (Ptr) Name = Fn.DecryptNameString(Ptr);
        }
        Out.push_back({ PipeName, Ci, Name });
    };

    __m128i V = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Enc16));

    static const alignas(16) uint8_t MaskUobj[16] = {
        0x06, 0x05, 0x02, 0x03, 0x04, 0x01, 0x00, 0x07,
        0,0,0,0, 0,0,0,0
    };
    __m128i ShufUobj = _mm_load_si128(reinterpret_cast<const __m128i*>(MaskUobj));
    constexpr uint64_t UobjXor = 0x5EA772D07F910744ULL;
    constexpr uint64_t FFieldXorLo = 0x36578989E8756FBAULL; // bytes 38 BA 6F 75 E8 89 57 36

    // Pipeline A: UObject-style with FField XOR
    {
        __m128i B = _mm_shuffle_epi8(V, ShufUobj);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), B);
        Try("A: PSHUFB+XOR(FF)+ROL64(32)", Lo ^ FFieldXorLo);
    }
    // Pipeline A2: UObject-style without final ROL64
    {
        __m128i B = _mm_shuffle_epi8(V, ShufUobj);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), B);
        TryNoRot("A2: PSHUFB+XOR(FF) noROL", Lo ^ FFieldXorLo);
    }
    // Pipeline B: 20260428-style ROL64(21)+XOR+ROL16(15)+ROL64(32)
    {
        __m128i R1 = RolEpi64(V, 21);
        alignas(16) uint8_t Kxor[16] = {
            0xBA, 0x6F, 0x75, 0xE8, 0x89, 0x57, 0x36, 0x00, // wrong test
            0,0,0,0, 0,0,0,0
        };
        // correct: lo8 = 38 BA 6F 75 E8 89 57 36
        Kxor[0]=0x38; Kxor[1]=0xBA; Kxor[2]=0x6F; Kxor[3]=0x75;
        Kxor[4]=0xE8; Kxor[5]=0x89; Kxor[6]=0x57; Kxor[7]=0x36;
        __m128i Xk = _mm_load_si128(reinterpret_cast<const __m128i*>(Kxor));
        __m128i Xo = _mm_xor_si128(R1, Xk);
        __m128i R2 = RolEpi16(Xo, 15);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), R2);
        Try("B: ROL64(21)+XOR(FF)+ROL16(15)+ROL64(32)", Lo);
    }
    // Pipeline C: 20260421-style PSHUFLW(0x1E)+XOR+ROL16(1)+ROL64(32)
    {
        __m128i Sh = _mm_shufflelo_epi16(V, 0x1E);
        alignas(16) uint8_t Kxor[16] = {
            0x38, 0xBA, 0x6F, 0x75, 0xE8, 0x89, 0x57, 0x36,
            0,0,0,0, 0,0,0,0
        };
        __m128i Xk = _mm_load_si128(reinterpret_cast<const __m128i*>(Kxor));
        __m128i Xo = _mm_xor_si128(Sh, Xk);
        __m128i R2 = RolEpi16(Xo, 1);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), R2);
        Try("C: PSHUFLW(1E)+XOR(FF)+ROL16(1)+ROL64(32)", Lo);
    }
    // Pipeline D: just PSHUFLW(0xB1)+XOR+ROL64(32) (CL-1177146 simplification)
    {
        __m128i Sh = _mm_shufflelo_epi16(V, 0xB1);
        alignas(16) uint8_t Kxor[16] = {
            0x38, 0xBA, 0x6F, 0x75, 0xE8, 0x89, 0x57, 0x36,
            0,0,0,0, 0,0,0,0
        };
        __m128i Xk = _mm_load_si128(reinterpret_cast<const __m128i*>(Kxor));
        __m128i Xo = _mm_xor_si128(Sh, Xk);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xo);
        Try("D: PSHUFLW(B1)+XOR(FF)+ROL64(32)", Lo);
    }
    // Pipeline E: same as UObject but full 16-byte XOR variant
    {
        __m128i B = _mm_shuffle_epi8(V, ShufUobj);
        alignas(16) uint8_t Kxor[16] = {
            0x38, 0xBA, 0x6F, 0x75, 0xE8, 0x89, 0x57, 0x36,
            0x57, 0x36, 0xE8, 0x89, 0x38, 0xBA, 0x6F, 0x75
        };
        __m128i Xk = _mm_load_si128(reinterpret_cast<const __m128i*>(Kxor));
        __m128i Xo = _mm_xor_si128(B, Xk);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xo);
        Try("E: PSHUFB+XOR16(FF)+ROL64(32)", Lo);
    }
    // Pipeline F: same as E without ROL64
    {
        __m128i B = _mm_shuffle_epi8(V, ShufUobj);
        alignas(16) uint8_t Kxor[16] = {
            0x38, 0xBA, 0x6F, 0x75, 0xE8, 0x89, 0x57, 0x36,
            0x57, 0x36, 0xE8, 0x89, 0x38, 0xBA, 0x6F, 0x75
        };
        __m128i Xk = _mm_load_si128(reinterpret_cast<const __m128i*>(Kxor));
        __m128i Xo = _mm_xor_si128(B, Xk);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xo);
        TryNoRot("F: PSHUFB+XOR16(FF) noROL", Lo);
    }
    // Pipeline G: UObject pipeline with different masks for FField
    {
        // Try inverted mask
        static const alignas(16) uint8_t Mask2[16] = {
            0x00, 0x06, 0x05, 0x02, 0x03, 0x04, 0x01, 0x07,
            0,0,0,0, 0,0,0,0
        };
        __m128i Sm = _mm_load_si128(reinterpret_cast<const __m128i*>(Mask2));
        __m128i B = _mm_shuffle_epi8(V, Sm);
        uint64_t Lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), B);
        Try("G: PSHUFB(alt)+XOR(FF)+ROL64(32)", Lo ^ FFieldXorLo);
    }

    return Out;
}

int main(int Argc, char** Argv) {
    int Pid = Argc >= 2 ? atoi(Argv[1]) : FindGamePid();
    if (!Pid) { fprintf(stderr, "no PID\n"); return 1; }
    printf("[probe] PID=%d\n", Pid);

    KernelMemReader Reader(Pid);
    constexpr uint64_t Base = 0x140000000ULL;

    // Initialize FName decryptor — reads keytable + UObject slot const + FField xor const
    FName::FNameDecryptor FNameD(Base, Reader);
    if (!FNameD.Init()) {
        fprintf(stderr, "[probe] FName Init failed\n");
        return 1;
    }
    printf("[probe] FName decryptor init OK\n");

    // Initialize GObjects via the same pipeline as the main dumper
    GObjectArray Gobj(Reader, Base, FNameD);
    if (!Gobj.Init()) {
        fprintf(stderr, "[probe] GObjectArray Init failed\n");
        return 1;
    }
    printf("[probe] GObjectArray init OK, count=%zu\n", Gobj.Count());

    // Collect a few UObjects with non-empty ChildProperties chains.
    // Probe each as if it's a UClass/UStruct: read +0xD0 → FField head;
    // walk Next and dump NamePrivate.
    std::vector<uint64_t> SampleClassPtrs;
    int Inspected = 0;
    for (size_t I = 0; I < Gobj.Count() && SampleClassPtrs.size() < 25; ++I) {
        uint64_t Obj = Gobj.Get(I);
        if (!Obj) continue;
        ++Inspected;
        uint64_t FfHead = Rd<uint64_t>(Reader, Obj + ArcDecrypt::Offsets::UStruct::ChildProperties);
        if (!FfHead) continue;
        if (FfHead < 0x100000ULL || FfHead >= 0x800000000000ULL) continue;
        // Validate FField vtable
        uint64_t Vt = Rd<uint64_t>(Reader, FfHead);
        if (Vt < Base || Vt >= Base + 0xE9D0000ULL) continue;
        // Validate salt
        uint64_t Salt = Rd<uint64_t>(Reader, FfHead + 0x78);
        if (Salt != 0 && Salt != 0x893BCE4393840650ULL) continue;
        SampleClassPtrs.push_back(Obj);
    }
    printf("[probe] inspected=%d, sample classes with ChildProperties=%zu\n",
           Inspected, SampleClassPtrs.size());
    if (SampleClassPtrs.empty()) return 1;

    // For each candidate, walk a few FField nodes, dump encrypted bytes,
    // and run all candidate pipelines.
    int FfShown = 0;
    for (uint64_t ClassObj : SampleClassPtrs) {
        if (FfShown >= 12) break;
        uint64_t Ff = Rd<uint64_t>(Reader, ClassObj + ArcDecrypt::Offsets::UStruct::ChildProperties);
        std::unordered_set<uint64_t> Visited;
        printf("\n[probe] === Class @ 0x%lX  ChildProperties=0x%lX ===\n", ClassObj, Ff);
        int Walk = 0;
        while (Ff && Walk < 4 && FfShown < 12) {
            if (Visited.count(Ff)) break;
            Visited.insert(Ff);
            uint64_t Vt = Rd<uint64_t>(Reader, Ff);
            if (Vt < Base || Vt >= Base + 0xE9D0000ULL) break;
            alignas(16) uint8_t Enc[16] = {};
            Reader.Read(Ff + 0x70, Enc, 16);
            bool AllZero = true;
            for (uint8_t B : Enc) if (B) { AllZero = false; break; }
            if (AllZero) {
                Ff = Rd<uint64_t>(Reader, Ff + 0x48);
                ++Walk;
                continue;
            }
            ++FfShown;
            printf("  FField @ 0x%lX  vt=0x%lX\n", Ff, Vt);
            printf("    enc16 = ");
            for (int B : Enc) printf("%02X ", (uint8_t)B);
            printf("\n");
            auto Results = RunPipelines(Enc, FNameD);
            for (auto& R : Results) {
                printf("    %-40s CI=%-10u name='%s'\n", R.Name, R.Ci, R.DecodedName.c_str());
            }
            Ff = Rd<uint64_t>(Reader, Ff + 0x48);
            ++Walk;
        }
    }

    return 0;
}
