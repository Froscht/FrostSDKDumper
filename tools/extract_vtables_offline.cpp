// extract_vtables_offline.cpp — offline engine vtable extractor.
//
// Standalone CLI that takes a UE5 game .exe on disk, parses the PE, walks
// .rdata for UTF-16 kind strings ("ScriptStruct", "Class", "Function", ...),
// scans .text for LEA xrefs to each string, then identifies the engine
// type-pool vtable each xref site writes via a density-validated
// LEA + MOV-store idiom. Emits an `extracted_vtables.h` header that can be
// #included to skip Phase 1 auto-discovery at runtime.
//
// Ports the core helpers (wide_pattern, scan_lea_mov_targets,
// walk_to_fn_start, density_score, looks_like_vtable) from
// auto_discovery.h::DiscoverEngineVTablesByWideStringAnchor — re-implemented
// against an mmap'd PE image instead of a live IMemoryReader.
//
// Usage: ./extract_vtables_offline <path-to-exe> [output.h]

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

namespace {

struct PESection {
    char     Name[9]   = {};
    uint32_t VA        = 0;
    uint32_t VSize     = 0;
    uint32_t RawSize   = 0;
    uint32_t RawOffset = 0;
    uint32_t Chars     = 0;
    uint32_t End() const { return VA + VSize; }
};

class PEImage {
public:
    bool Open(const char* Path) {
        Fd = ::open(Path, O_RDONLY);
        if (Fd < 0) { std::fprintf(stderr, "[err] open %s: %s\n", Path, std::strerror(errno)); return false; }
        struct stat St{};
        if (::fstat(Fd, &St) < 0) { std::fprintf(stderr, "[err] fstat: %s\n", std::strerror(errno)); return false; }
        FileSize = (size_t)St.st_size;
        FileMap = (const uint8_t*)::mmap(nullptr, FileSize, PROT_READ, MAP_PRIVATE, Fd, 0);
        if (FileMap == MAP_FAILED) { std::fprintf(stderr, "[err] mmap: %s\n", std::strerror(errno)); return false; }
        return Parse();
    }
    ~PEImage() {
        if (FileMap && FileMap != MAP_FAILED) ::munmap((void*)FileMap, FileSize);
        if (Image.data()) {}
        if (Fd >= 0) ::close(Fd);
    }

    const std::vector<PESection>& Sections() const { return Sections_; }
    uint64_t ImageBase() const { return ImageBase_; }
    uint32_t SizeOfImage() const { return SizeOfImage_; }
    const uint8_t* AtRVA(uint64_t Rva, size_t Need = 1) const {
        if (Rva + Need > Image.size()) return nullptr;
        return Image.data() + Rva;
    }
    const PESection* FindSection(const char* Name) const {
        for (const auto& S : Sections_) if (std::strcmp(S.Name, Name) == 0) return &S;
        return nullptr;
    }
    bool InText(uint64_t Rva) const  { return Text  && Rva >= Text->VA  && Rva < Text->End(); }
    bool InRData(uint64_t Rva) const { return RData && Rva >= RData->VA && Rva < RData->End(); }

    const PESection* Text  = nullptr;
    const PESection* RData = nullptr;
    const PESection* Data  = nullptr;

private:
    bool Parse() {
        if (FileSize < 0x400) return false;
        if (FileMap[0] != 'M' || FileMap[1] != 'Z') {
            std::fprintf(stderr, "[err] not a PE (no MZ)\n"); return false;
        }
        uint32_t ELfanew = *(const uint32_t*)(FileMap + 0x3C);
        if (ELfanew + 0x18 + 0x70 > FileSize) return false;
        const uint8_t* Nt = FileMap + ELfanew;
        if (*(const uint32_t*)Nt != 0x00004550u) {
            std::fprintf(stderr, "[err] no PE\\0\\0 signature\n"); return false;
        }
        uint16_t NumSections   = *(const uint16_t*)(Nt + 6);
        uint16_t OptHeaderSize = *(const uint16_t*)(Nt + 0x14);
        uint16_t OptMagic      = *(const uint16_t*)(Nt + 0x18);
        if (OptMagic != 0x20B) {
            std::fprintf(stderr, "[err] PE32+ only (magic=0x%X)\n", OptMagic); return false;
        }
        ImageBase_   = *(const uint64_t*)(Nt + 0x18 + 24);
        SizeOfImage_ = *(const uint32_t*)(Nt + 0x18 + 56);

        uint32_t SectOff = ELfanew + 0x18 + OptHeaderSize;
        if (SectOff + (uint32_t)NumSections * 0x28 > FileSize) return false;

        Sections_.clear();
        for (uint16_t I = 0; I < NumSections; ++I) {
            const uint8_t* S = FileMap + SectOff + I * 0x28;
            PESection Sec;
            std::memcpy(Sec.Name, S, 8);
            Sec.Name[8] = 0;
            Sec.VSize     = *(const uint32_t*)(S + 8);
            Sec.VA        = *(const uint32_t*)(S + 12);
            Sec.RawSize   = *(const uint32_t*)(S + 16);
            Sec.RawOffset = *(const uint32_t*)(S + 20);
            Sec.Chars     = *(const uint32_t*)(S + 36);
            Sections_.push_back(Sec);
        }

        if (SizeOfImage_ == 0 || SizeOfImage_ > 0x40000000u) return false;
        Image.assign(SizeOfImage_, 0);
        std::memcpy(Image.data(), FileMap, std::min<size_t>(0x1000, FileSize));
        for (const auto& Sec : Sections_) {
            if (Sec.RawSize == 0 || Sec.VA == 0) continue;
            uint32_t Copy = std::min(Sec.RawSize, Sec.VSize);
            if (Sec.RawOffset + Copy > FileSize) continue;
            if ((uint64_t)Sec.VA + Copy > Image.size()) continue;
            std::memcpy(Image.data() + Sec.VA, FileMap + Sec.RawOffset, Copy);
        }

        Text  = FindSection(".text");
        RData = FindSection(".rdata");
        Data  = FindSection(".data");
        if (!Text || !RData) {
            std::fprintf(stderr, "[err] missing .text or .rdata section\n"); return false;
        }
        std::printf("[pe] %s\n", "loaded");
        std::printf("[pe] ImageBase=0x%llX SizeOfImage=0x%X\n",
                    (unsigned long long)ImageBase_, SizeOfImage_);
        std::printf("[pe] .text  RVA=0x%X..0x%X\n", Text->VA,  Text->End());
        std::printf("[pe] .rdata RVA=0x%X..0x%X\n", RData->VA, RData->End());
        if (Data) std::printf("[pe] .data  RVA=0x%X..0x%X\n", Data->VA,  Data->End());
        return true;
    }

    int Fd = -1;
    const uint8_t* FileMap = nullptr;
    size_t FileSize = 0;
    std::vector<uint8_t> Image;
    std::vector<PESection> Sections_;
    uint64_t ImageBase_   = 0;
    uint32_t SizeOfImage_ = 0;
};

static std::vector<uint8_t> WidePattern(const char* Kind) {
    std::vector<uint8_t> Bytes;
    for (const char* C = Kind; *C; ++C) {
        Bytes.push_back((uint8_t)*C);
        Bytes.push_back(0x00);
    }
    Bytes.push_back(0x00);
    Bytes.push_back(0x00);
    return Bytes;
}

static std::vector<uint64_t> ScanRDataWide(const PEImage& Pe, const std::vector<uint8_t>& Pat) {
    std::vector<uint64_t> Hits;
    if (!Pe.RData || Pat.empty()) return Hits;
    const uint8_t* Base = Pe.AtRVA(Pe.RData->VA, Pe.RData->VSize);
    if (!Base) return Hits;
    size_t N = Pat.size();
    size_t Hi = Pe.RData->VSize;
    if (Hi < N) return Hits;
    for (size_t I = 0; I + N <= Hi; ++I) {
        if (Base[I] != Pat[0]) continue;
        if (std::memcmp(Base + I, Pat.data(), N) == 0) {
            Hits.push_back((uint64_t)Pe.RData->VA + I);
        }
    }
    return Hits;
}

static std::vector<uint64_t> ScanTextLeaXrefs(const PEImage& Pe, const std::vector<uint64_t>& StrRVAs) {
    std::vector<uint64_t> Out;
    if (!Pe.Text || StrRVAs.empty()) return Out;
    const uint8_t* Tx = Pe.AtRVA(Pe.Text->VA, Pe.Text->VSize);
    if (!Tx) return Out;
    size_t TxSize = Pe.Text->VSize;
    for (size_t I = 0; I + 7 <= TxSize; ++I) {
        if (Tx[I] != 0x48 || Tx[I+1] != 0x8D) continue;
        uint8_t Modrm = Tx[I+2];
        if ((Modrm & 0xC7) != 0x05) continue;
        int32_t Disp = 0;
        std::memcpy(&Disp, Tx + I + 3, 4);
        uint64_t Target = ((uint64_t)Pe.Text->VA + I + 7) + (int64_t)Disp;
        for (uint64_t S : StrRVAs) {
            if (Target == S) {
                Out.push_back((uint64_t)Pe.Text->VA + I);
                break;
            }
        }
    }
    return Out;
}

static int DensityScore(const PEImage& Pe, uint64_t VtRva) {
    if (!Pe.InRData(VtRva)) return 0;
    const uint8_t* P = Pe.AtRVA(VtRva, 0x200);
    if (!P) return 0;
    uint64_t Qbuf[64] = {};
    std::memcpy(Qbuf, P, sizeof(Qbuf));
    uint64_t First = Qbuf[0];
    if (First < Pe.ImageBase()) return 0;
    uint64_t FirstRva = First - Pe.ImageBase();
    if (!Pe.InText(FirstRva)) return 0;
    int TextCount = 0;
    for (int I = 0; I < 64; ++I) {
        if (!Qbuf[I]) continue;
        if (Qbuf[I] < Pe.ImageBase()) continue;
        uint64_t R = Qbuf[I] - Pe.ImageBase();
        if (Pe.InText(R)) ++TextCount;
    }
    return TextCount;
}

static bool LooksLikeVtable(const PEImage& Pe, uint64_t VtRva) {
    return DensityScore(Pe, VtRva) >= 10;
}

static std::vector<uint64_t> ScanLeaMovTargets(const PEImage& Pe, uint64_t FnStart,
                                               size_t Window, bool Require140) {
    std::vector<uint64_t> Hits;
    if (!Pe.Text) return Hits;
    const uint8_t* P = Pe.AtRVA(FnStart, 1);
    if (!P) return Hits;
    size_t Bound = Window;
    uint64_t TextEnd = (uint64_t)Pe.Text->End();
    if (FnStart + Window > TextEnd) Bound = TextEnd - FnStart;
    for (size_t S = 0; S + 1 < Bound; ++S) {
        if (P[S] == 0xC3) {
            size_t Look = std::min<size_t>(16, Bound - S);
            for (size_t T = 1; T < Look; ++T) {
                if (P[S+T] == 0xCC) { Bound = S + 1; goto BoundSet; }
            }
        }
        if (P[S] == 0xCC && P[S+1] == 0xCC) { Bound = S; break; }
    }
    BoundSet: ;
    for (size_t I = 0; I + 10 <= Bound; ++I) {
        if (P[I] != 0x48 && P[I] != 0x4C) continue;
        if (P[I+1] != 0x8D) continue;
        uint8_t Modrm = P[I+2];
        if ((Modrm & 0xC7) != 0x05) continue;
        uint8_t LeaDst = ((Modrm >> 3) & 7) | ((P[I] & 4) ? 8 : 0);
        int32_t Disp = 0;
        std::memcpy(&Disp, P + I + 3, 4);
        uint64_t Target = (FnStart + I + 7) + (int64_t)Disp;

        bool Matched = false;
        uint64_t MovDispImm = 0;
        for (size_t J = I + 7; J + 3 <= Bound && J < I + 7 + 24; ++J) {
            if ((P[J] & 0xF0) != 0x40) continue;
            if (!(P[J] & 0x08)) continue;
            if (P[J+1] != 0x89) continue;
            uint8_t Mr = P[J+2];
            uint8_t MovSrc = ((Mr >> 3) & 7) | ((P[J] & 4) ? 8 : 0);
            if (MovSrc != LeaDst) continue;
            uint8_t Mod = Mr >> 6;
            if (Mod == 3) continue;
            uint8_t Rm = Mr & 7;
            size_t OpPos = J + 3;
            if (Rm == 4) {
                if (OpPos >= Bound) break;
                ++OpPos;
            }
            if (Mod == 0 && Rm == 5) continue;
            if (Mod == 1) {
                if (OpPos >= Bound) break;
                MovDispImm = (int8_t)P[OpPos];
                OpPos += 1;
            } else if (Mod == 2) {
                if (OpPos + 4 > Bound) break;
                int32_t D = 0;
                std::memcpy(&D, P + OpPos, 4);
                MovDispImm = (uint64_t)(int64_t)D;
                OpPos += 4;
            }
            if (Require140 && MovDispImm != 0x140) continue;
            Matched = true;
            break;
        }
        if (Matched) Hits.push_back(Target);
    }
    return Hits;
}

static uint64_t ResolveKind(const PEImage& Pe, const char* Kind) {
    auto Wpat = WidePattern(Kind);
    auto StrHits = ScanRDataWide(Pe, Wpat);
    if (StrHits.empty()) {
        std::printf("[anchor] %s: ANCHOR MISSING (wide string not in .rdata)\n", Kind);
        return 0;
    }
    auto XrefRvas = ScanTextLeaXrefs(Pe, StrHits);
    if (XrefRvas.empty()) {
        std::printf("[anchor] %s: no LEA xrefs to %zu string occurrences\n",
                    Kind, StrHits.size());
        return 0;
    }

    std::unordered_map<uint64_t, int> VtCounts;
    for (uint64_t Xref : XrefRvas) {
        uint64_t ScanLo = Xref;
        size_t   ScanSz = 0x300;

        uint64_t LastDirect = 0;
        for (uint64_t Cand : ScanLeaMovTargets(Pe, ScanLo, ScanSz, false)) {
            if (LooksLikeVtable(Pe, Cand)) LastDirect = Cand;
        }
        if (LastDirect) ++VtCounts[LastDirect];

        for (uint64_t CtorRva : ScanLeaMovTargets(Pe, ScanLo, ScanSz, true)) {
            if (!Pe.InText(CtorRva)) continue;
            uint64_t LastSub = 0;
            for (uint64_t Cand : ScanLeaMovTargets(Pe, CtorRva, 0x200, false)) {
                if (LooksLikeVtable(Pe, Cand)) LastSub = Cand;
            }
            if (LastSub) VtCounts[LastSub] += 2;
        }
    }
    if (VtCounts.empty()) {
        std::printf("[anchor] %s: no vtable candidates from %zu xrefs\n",
                    Kind, XrefRvas.size());
        return 0;
    }

    uint64_t BestVt = 0;
    int BestScore = 0;
    int BestDensity = 0;
    for (const auto& Kv : VtCounts) {
        int D = DensityScore(Pe, Kv.first);
        int Total = Kv.second * 100 + D;
        if (Total > BestScore) { BestScore = Total; BestVt = Kv.first; BestDensity = D; }
    }
    std::printf("[anchor] %s: vtable_rva=0x%llX (xref_count=%d, density=%d, %zu cands from %zu xrefs)\n",
                Kind, (unsigned long long)BestVt, BestScore / 100, BestDensity,
                VtCounts.size(), XrefRvas.size());
    return BestVt;
}

struct KindResult {
    const char* Kind;
    const char* Macro;
    uint64_t    Rva;
};

static const char* KKindList[][2] = {
    { "ScriptStruct",                       "SCRIPTSTRUCT" },
    { "Class",                              "CLASS" },
    { "Function",                           "FUNCTION" },
    { "Enum",                               "ENUM" },
    { "Package",                            "PACKAGE" },
    { "BlueprintGeneratedClass",            "BPGC" },
    { "WidgetBlueprintGeneratedClass",      "WBPGC" },
    { "SkeletalMeshBlueprintGeneratedClass","SKMBPGC" },
    { "AnimBlueprintGeneratedClass",        "ANIMBPGC" },
    { "AngelscriptClass",                   "ASCLASS" },
    { "AngelscriptStruct",                  "ASSTRUCT" },
    { "AngelscriptFunction",                "ASFUNCTION" },
};

} // namespace

int main(int Argc, char** Argv) {
    if (Argc < 2) {
        std::fprintf(stderr,
            "usage: %s <path-to-exe> [output.h]\n"
            "  Scans an offline PE for engine type-pool vtables via\n"
            "  UTF-16 kind-string anchors and emits a header of\n"
            "  static const uint64_t K_<KIND>_VTABLE_RVA constants.\n",
            Argv[0]);
        return 1;
    }
    const char* InPath  = Argv[1];
    const char* OutPath = (Argc >= 3) ? Argv[2] : "extracted_vtables.h";

    PEImage Pe;
    if (!Pe.Open(InPath)) return 2;

    std::vector<KindResult> Results;
    int Found = 0;
    for (const auto& K : KKindList) {
        KindResult R{ K[0], K[1], ResolveKind(Pe, K[0]) };
        Results.push_back(R);
        if (R.Rva) ++Found;
    }
    std::printf("[anchor] resolved %d/%zu kinds\n", Found, sizeof(KKindList)/sizeof(KKindList[0]));

    FILE* F = std::fopen(OutPath, "w");
    if (!F) {
        std::fprintf(stderr, "[err] fopen %s: %s\n", OutPath, std::strerror(errno));
        return 3;
    }
    std::fprintf(F, "#pragma once\n");
    std::fprintf(F, "// Auto-generated by extract_vtables_offline.cpp\n");
    std::fprintf(F, "// Source: %s\n", InPath);
    std::fprintf(F, "// ImageBase=0x%llX SizeOfImage=0x%X\n",
                 (unsigned long long)Pe.ImageBase(), Pe.SizeOfImage());
    std::fprintf(F, "// Resolved %d/%zu engine type-pool vtables.\n\n",
                 Found, sizeof(KKindList)/sizeof(KKindList[0]));
    std::fprintf(F, "#include <cstdint>\n\n");
    std::fprintf(F, "struct VTableInfo { uint64_t Rva; uint32_t Stride; };\n\n");
    for (const auto& R : Results) {
        if (R.Rva) {
            std::fprintf(F, "static const uint64_t K_%s_VTABLE_RVA = 0x%llXULL;\n",
                         R.Macro, (unsigned long long)R.Rva);
        } else {
            std::fprintf(F, "// K_%s_VTABLE_RVA = (not found — ANCHOR MISSING)\n", R.Macro);
        }
    }
    std::fprintf(F, "\n");
    for (const auto& R : Results) {
        if (R.Rva) {
            std::fprintf(F,
                "static const VTableInfo K_%s_VTABLE = { 0x%llXULL, 0 };\n",
                R.Macro, (unsigned long long)R.Rva);
        }
    }
    std::fclose(F);
    std::printf("[out] wrote %s\n", OutPath);
    return Found > 0 ? 0 : 4;
}
