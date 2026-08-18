#pragma once
// =============================================================================
// Static UE reflection extraction for Theia-obfuscated builds.
//
// Theia encrypts the NameUTF8 literals in the generated Z_Construct_*
// descriptor tables, but the cipher is a PRNG stream seeded with ZERO
// (ConstructU* @ RVA 0x4ED320 on build 24653108: `xor ecx, ecx` right before
// the decode loop), so every name is recoverable offline with no live state.
//
//   State' = ROL32(State * 0x1000193 + 0xA7A3FF6B, 0x13)
//   State  = (State' + State) * 0x1000193
//   Out    = Wrap((State & 0x1F) ^ Cipher)
//
// Wrap is a branch-free cascade of range corrections that keeps the result
// inside the identifier alphabet. The plaintext NUL terminates; the ciphertext
// is NOT NUL-terminated.
//
// What this reaches: UEnum / UScriptStruct / UFunction / UDelegateFunction
// descriptors and every member they declare, including types that never get
// instantiated and so never appear in GUObjectArray. UClass descriptors are
// NOT reachable statically — Theia passes their name pointers as encrypted
// 16-byte blobs rather than rip-relative leas, so no anchor survives. The live
// pipeline already resolves those at 100%, so this is complementary, not a
// replacement.
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstdlib>

#include "memreader_iface.h"

namespace TheiaStr {

constexpr uint32_t kPrime = 0x1000193u;
constexpr uint32_t kAdd   = 0xA7A3FF6Bu;

inline uint32_t Rol32(uint32_t V, int N) {
    return (V << N) | (V >> (32 - N));
}

inline uint8_t StepDecrypt(uint8_t Cipher, uint32_t& State) {
    uint32_t T = Rol32(State * kPrime + kAdd, 0x13);
    State = (T + State) * kPrime;
    int32_t C = (int32_t)(int8_t)Cipher;
    uint32_t V = (State & 0x1Fu) ^ (uint32_t)C;

    int32_t A = ((V - 0x50u) < 0x2Fu) ? -47 : 0;
    if ((V - 0x21u) < 0x2Fu) A = 47;
    uint32_t X = V + (uint32_t)A;

    int32_t F = ((X - 53u) >= 5u) ? 1 : 0;
    int32_t B = ((X - 48u) < 5u) ? 5 : (F * 5 - 5);
    uint32_t Y = X + (uint32_t)B;

    int32_t C2 = ((Y - 110u) < 13u) ? -13 : 0;
    if ((Y - 97u) < 13u) C2 = 13;
    uint32_t Z = Y + (uint32_t)C2;

    int32_t D = ((Z - 78u) < 13u) ? -13 : 0;
    if ((Z - 65u) < 13u) D = 13;
    uint32_t W = Z + (uint32_t)D;

    int32_t E = ((W - 80u) < 0x2Fu) ? 209 : 0;
    if ((W - 33u) < 0x2Fu) E = 47;

    return (uint8_t)(W + (uint32_t)E);
}

inline std::string Decrypt(const uint8_t* Buf, size_t Max) {
    std::string Out;
    uint32_t State = 0;
    for (size_t I = 0; I < Max; ++I) {
        uint8_t Ch = StepDecrypt(Buf[I], State);
        if (Ch == 0) break;
        Out.push_back((char)Ch);
    }
    return Out;
}

inline bool Encrypt(const std::string& Plain, std::vector<uint8_t>& Out) {
    Out.clear();
    uint32_t State = 0;
    for (size_t I = 0; I <= Plain.size(); ++I) {
        uint8_t Want = (I < Plain.size()) ? (uint8_t)Plain[I] : 0;
        bool Found = false;
        for (int Cand = 0; Cand < 256; ++Cand) {
            uint32_t Probe = State;
            if (StepDecrypt((uint8_t)Cand, Probe) == Want) {
                Out.push_back((uint8_t)Cand);
                State = Probe;
                Found = true;
                break;
            }
        }
        if (!Found) return false;
    }
    return true;
}

inline bool IsIdentChar(uint8_t C, bool AllowColon) {
    if (C >= 'A' && C <= 'Z') return true;
    if (C >= 'a' && C <= 'z') return true;
    if (C >= '0' && C <= '9') return true;
    if (C == '_') return true;
    if (AllowColon && C == ':') return true;
    return false;
}

inline bool PlausibleName(const std::string& S, bool AllowColon) {
    if (S.empty() || S.size() > 128) return false;
    for (unsigned char C : S)
        if (!IsIdentChar(C, AllowColon)) return false;
    return true;
}

} // namespace TheiaStr

namespace TheiaStatic {

constexpr uint64_t kParamBase = 0x38;

inline const char* GenFlagName(uint32_t Gen) {
    switch (Gen & 0x3Fu) {
        case 0x00: return "Byte";
        case 0x01: return "Int8";
        case 0x02: return "Int16";
        case 0x03: return "Int";
        case 0x04: return "Int64";
        case 0x05: return "UInt16";
        case 0x06: return "UInt32";
        case 0x07: return "UInt64";
        case 0x08: return "UnsizedInt";
        case 0x09: return "UnsizedUInt";
        case 0x0A: return "Float";
        case 0x0B: return "Double";
        case 0x0C: return "Bool";
        case 0x0D: return "SoftClass";
        case 0x0E: return "WeakObject";
        case 0x0F: return "LazyObject";
        case 0x10: return "SoftObject";
        case 0x11: return "Class";
        case 0x12: return "Object";
        case 0x13: return "Interface";
        case 0x14: return "Name";
        case 0x15: return "Str";
        case 0x16: return "Array";
        case 0x17: return "Map";
        case 0x18: return "Set";
        case 0x19: return "Struct";
        case 0x1A: return "Delegate";
        case 0x1B: return "InlineMulticastDelegate";
        case 0x1C: return "SparseMulticastDelegate";
        case 0x1D: return "Text";
        case 0x1E: return "Enum";
        case 0x1F: return "FieldPath";
        case 0x20: return "LargeWorldCoordinatesReal";
        case 0x21: return "Optional";
        default:   return "Unknown";
    }
}

struct MemberRecord {
    std::string Name;
    std::string TypeName;
    uint32_t    Gen        = 0;
    uint32_t    Mods       = 0;
    uint64_t    PropFlags  = 0;
    uint32_t    ArrayDim   = 0;
    uint64_t    ParamRva   = 0;
    uint64_t    ExtraRva   = 0;
};

struct EnumEntry {
    std::string Name;
    int64_t     Value = 0;
};

struct TypeRecord {
    std::string             Name;
    std::string             Package;
    std::string             Kind;
    uint64_t                DescRva  = 0;
    uint64_t                NameOff  = 0;
    std::vector<MemberRecord> Members;
    std::vector<EnumEntry>    Entries;
};

struct Result {
    std::vector<TypeRecord> Types;
    size_t Packages   = 0;
    size_t Candidates = 0;
    size_t NoName     = 0;
    size_t Enums      = 0;
    size_t Structs    = 0;
    size_t Bare       = 0;
    size_t Members    = 0;
    size_t EnumValues = 0;
};

class Sweeper {
public:
    Sweeper(IMemoryReader& Reader, uint64_t ModuleBase,
            uint64_t TextRva, uint64_t TextSize,
            uint64_t RDataRva, uint64_t RDataSize)
        : m_Reader(Reader), m_Base(ModuleBase),
          m_TextRva(TextRva), m_TextSize(TextSize),
          m_RDataRva(RDataRva), m_RDataSize(RDataSize) {}

    bool LoadSections(const char* FallbackA = nullptr,
                      const char* FallbackB = nullptr) {
        m_Text.resize((size_t)m_TextSize);
        m_RData.resize((size_t)m_RDataSize);
        size_t TextGaps = ReadPaged(m_TextRva, m_Text);
        size_t RDataGaps = ReadPaged(m_RDataRva, m_RData);
        if (TextGaps || RDataGaps)
            std::printf("[theia-static] live read gaps: .text %zu pages, .rdata %zu pages\n",
                TextGaps, RDataGaps);
        for (const char* Fb : { FallbackA, FallbackB }) {
            if (!Fb || !*Fb || m_Gaps.empty()) continue;
            size_t Before = m_Gaps.size();
            size_t Filled = FillFromImage(Fb, 0, 0);
            std::printf("[theia-static] filled %zu of %zu remaining pages from %s\n",
                Filled, Before, Fb);
        }
        if (!m_Gaps.empty())
            std::printf("[theia-static] %zu pages still zero-filled\n", m_Gaps.size());
        return true;
    }

    Result Run(const char* ImageA = nullptr, const char* ImageB = nullptr) {
        Result Out;
        FindPackages();
        // Live .text can be *behind* an externally unpacked image: those pages
        // read fine (so they never count as gaps) but hold different bytes, and
        // the wrapper prologue with `lea rdx,[rip+FPackageParams]` is missing.
        // Measured on build 24653108: 146 of 359 wrappers live, while .rdata is
        // byte-identical (313 FPackageParams, 174k code pointers either way).
        // .text only ever supplies wrapper NAMES, so reloading it wholesale
        // from a full image costs nothing and recovers the rest.
        if (m_PkgParamCount && m_PkgByFn.size() * 5 < m_PkgParamCount * 4) {
            for (const char* Img : { ImageA, ImageB }) {
                if (!Img || !*Img) continue;
                if (!ReloadTextFromImage(Img)) continue;
                m_PkgByFn.clear();
                FindPackages();
                std::printf("[theia-static] .text reloaded from %s -> %zu wrappers\n",
                    Img, m_PkgByFn.size());
                if (m_PkgByFn.size() * 5 >= m_PkgParamCount * 4) break;
            }
        }
        size_t Named = m_PkgByFn.size();
        // The .rdata vote recovers wrappers when .text is unreadable, but it
        // admits functions that are not package wrappers: measured against the
        // live dump it leaves exact member agreement flat (4239 -> 4236 types)
        // while missing members climb 1175 -> 2130 and 3212 names duplicate.
        // Off by default; the strict .text-keyed set is the trustworthy one.
        if (std::getenv("FROST_THEIA_VOTE")) VoteOuterFuncs();
        Out.Packages = m_PkgByFn.size();
        std::printf("[theia-static] package wrappers: %zu named from .text, %zu total\n",
            Named, m_PkgByFn.size());
        if (m_PkgByFn.empty()) return Out;

        std::vector<std::pair<uint64_t, uint64_t>> Descs;
        FindDescriptors(Descs);
        Out.Candidates = Descs.size();

        for (const auto& [DescRva, PkgFn] : Descs) {
            TypeRecord Rec;
            Rec.DescRva = DescRva;
            uint64_t NameOff = 0;
            if (!TypeName(DescRva, Rec.Name, NameOff)) { ++Out.NoName; continue; }
            Rec.NameOff = NameOff;
            auto It = m_PkgByFn.find(PkgFn);
            bool KnownPkg = (It != m_PkgByFn.end());
            Rec.Package = KnownPkg ? It->second : "?";

            if (ReadEnumArray(DescRva, Rec.Entries)) {
                Rec.Kind = "enum";
                ++Out.Enums;
                Out.EnumValues += Rec.Entries.size();
            } else if (ReadParamArray(DescRva, Rec.Members)) {
                Rec.Kind = "struct_or_func";
                ++Out.Structs;
                Out.Members += Rec.Members.size();
            } else {
                Rec.Kind = "bare";
                ++Out.Bare;
            }
            (void)KnownPkg;
            Out.Types.push_back(std::move(Rec));
        }
        return Out;
    }

private:
    size_t ReadPaged(uint64_t Rva, std::vector<uint8_t>& Dst) {
        constexpr size_t kPage = 0x1000;
        constexpr size_t kBatch = 0x10000;
        size_t Gaps = 0;
        size_t Done = 0;
        while (Done < Dst.size()) {
            size_t N = std::min(kBatch, Dst.size() - Done);
            if (m_Reader.Read(m_Base + Rva + Done, Dst.data() + Done, N)) {
                Done += N;
                continue;
            }
            size_t End = Done + N;
            while (Done < End) {
                size_t P = std::min(kPage, End - Done);
                if (!m_Reader.Read(m_Base + Rva + Done, Dst.data() + Done, P)) {
                    std::memset(Dst.data() + Done, 0, P);
                    m_Gaps.push_back(Rva + Done);
                    ++Gaps;
                }
                Done += P;
            }
        }
        return Gaps;
    }

    struct ImageMap {
        bool Identity = true;
        long long Size = 0;
    };

    // A file-backed fallback is either a dumped image (file offset == RVA) or a
    // real PE (offset from the section table). Detecting which keeps the same
    // code path usable for both instead of silently reading the wrong bytes.
    bool BuildImageMap(FILE* F, ImageMap& Map,
                       std::vector<std::pair<uint64_t, std::pair<uint64_t, uint64_t>>>& Secs) {
        std::fseek(F, 0, SEEK_END);
        Map.Size = std::ftell(F);
        uint8_t Hdr[0x400] = {};
        std::fseek(F, 0, SEEK_SET);
        if (std::fread(Hdr, 1, sizeof(Hdr), F) != sizeof(Hdr)) return false;
        if (Hdr[0] != 'M' || Hdr[1] != 'Z') return false;
        uint32_t PeOff = 0;
        std::memcpy(&PeOff, Hdr + 0x3C, 4);
        if (PeOff + 0x108 > sizeof(Hdr)) return true;
        if (std::memcmp(Hdr + PeOff, "PE\0\0", 4) != 0) return true;
        uint16_t NumSec = 0, OptSize = 0;
        std::memcpy(&NumSec, Hdr + PeOff + 6, 2);
        std::memcpy(&OptSize, Hdr + PeOff + 20, 2);
        uint32_t SizeOfImage = 0;
        std::memcpy(&SizeOfImage, Hdr + PeOff + 24 + 56, 4);
        // A flat memory dump keeps the original section table, whose
        // PointerToRawData describes the on-disk layout and not the dump. Size
        // is what separates the two: a dump spans the whole image.
        if (SizeOfImage && Map.Size >= (long long)SizeOfImage - 0x100000) {
            Map.Identity = true;
            return true;
        }
        uint32_t SecOff = PeOff + 24 + OptSize;
        std::vector<uint8_t> Table((size_t)NumSec * 40);
        std::fseek(F, (long)SecOff, SEEK_SET);
        if (std::fread(Table.data(), 1, Table.size(), F) != Table.size()) return true;
        for (uint16_t I = 0; I < NumSec; ++I) {
            const uint8_t* E = Table.data() + I * 40;
            uint32_t VSize = 0, VAddr = 0, RSize = 0, RAddr = 0;
            std::memcpy(&VSize, E + 8, 4);
            std::memcpy(&VAddr, E + 12, 4);
            std::memcpy(&RSize, E + 16, 4);
            std::memcpy(&RAddr, E + 20, 4);
            if (!VAddr || !RSize) continue;
            Secs.push_back({ VAddr, { RAddr, std::max(VSize, RSize) } });
            if (VAddr != RAddr) Map.Identity = false;
        }
        return true;
    }

    bool ReloadTextFromImage(const char* Path) {
        FILE* F = std::fopen(Path, "rb");
        if (!F) return false;
        ImageMap Map;
        std::vector<std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> Secs;
        BuildImageMap(F, Map, Secs);
        auto FileOffset = [&](uint64_t Rva) -> long long {
            if (Map.Identity) return (long long)Rva;
            for (const auto& Sc : Secs) {
                uint64_t VAddr = Sc.first, RAddr = Sc.second.first, Span = Sc.second.second;
                if (Rva >= VAddr && Rva < VAddr + Span)
                    return (long long)(RAddr + (Rva - VAddr));
            }
            return -1;
        };
        long long Where = FileOffset(m_TextRva);
        if (Where < 0 || Where + (long long)m_Text.size() > Map.Size) {
            std::fclose(F);
            return false;
        }
        std::fseek(F, (long)Where, SEEK_SET);
        size_t Got = std::fread(m_Text.data(), 1, m_Text.size(), F);
        std::fclose(F);
        return Got == m_Text.size();
    }

    size_t FillFromImage(const char* Path, size_t, size_t) {
        FILE* F = std::fopen(Path, "rb");
        if (!F) {
            std::printf("[theia-static] fallback image not readable: %s\n", Path);
            return 0;
        }
        ImageMap Map;
        std::vector<std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> Secs;
        BuildImageMap(F, Map, Secs);
        long long Size = Map.Size;
        auto FileOffset = [&](uint64_t Rva) -> long long {
            if (Map.Identity) return (long long)Rva;
            for (const auto& S : Secs) {
                uint64_t VAddr = S.first, RAddr = S.second.first, Span = S.second.second;
                if (Rva >= VAddr && Rva < VAddr + Span)
                    return (long long)(RAddr + (Rva - VAddr));
            }
            return -1;
        };
        size_t Filled = 0;
        std::vector<uint64_t> Done;
        uint8_t Page[0x1000];
        for (uint64_t GapRva : m_Gaps) {
            long long Where = FileOffset(GapRva);
            if (Where < 0 || Where + (long long)sizeof(Page) > Size) continue;
            if (std::fseek(F, (long)Where, SEEK_SET) != 0) continue;
            if (std::fread(Page, 1, sizeof(Page), F) != sizeof(Page)) continue;
            // A dump produced from live reads carries the same holes, and a
            // successful read of an all-zero page is not a fill: accepting it
            // would retire the gap and starve the next fallback.
            bool AnyData = false;
            for (size_t K = 0; K < sizeof(Page); ++K)
                if (Page[K]) { AnyData = true; break; }
            if (!AnyData) continue;
            uint8_t* Dst = nullptr;
            if (InSection(GapRva, m_RDataRva, m_RDataSize))
                Dst = m_RData.data() + (GapRva - m_RDataRva);
            else if (InSection(GapRva, m_TextRva, m_TextSize))
                Dst = m_Text.data() + (GapRva - m_TextRva);
            if (!Dst) continue;
            std::memcpy(Dst, Page, sizeof(Page));
            Done.push_back(GapRva);
            ++Filled;
        }
        std::fclose(F);
        if (Filled) {
            std::unordered_set<uint64_t> Gone(Done.begin(), Done.end());
            std::vector<uint64_t> Left;
            for (uint64_t G : m_Gaps)
                if (!Gone.count(G)) Left.push_back(G);
            m_Gaps.swap(Left);
        }
        return Filled;
    }

    bool InSection(uint64_t Rva, uint64_t Base, uint64_t Size) const {
        return Rva >= Base && Rva < Base + Size;
    }

    const uint8_t* At(uint64_t Rva, size_t Need) const {
        if (InSection(Rva, m_RDataRva, m_RDataSize)) {
            uint64_t Off = Rva - m_RDataRva;
            if (Off + Need <= m_RData.size()) return m_RData.data() + Off;
        }
        if (InSection(Rva, m_TextRva, m_TextSize)) {
            uint64_t Off = Rva - m_TextRva;
            if (Off + Need <= m_Text.size()) return m_Text.data() + Off;
        }
        return nullptr;
    }

    bool U64(uint64_t Rva, uint64_t& Out) const {
        const uint8_t* P = At(Rva, 8);
        if (!P) return false;
        std::memcpy(&Out, P, 8);
        return true;
    }

    bool U32(uint64_t Rva, uint32_t& Out) const {
        const uint8_t* P = At(Rva, 4);
        if (!P) return false;
        std::memcpy(&Out, P, 4);
        return true;
    }

    bool PtrRva(uint64_t Rva, uint64_t& OutRva) const {
        uint64_t V = 0;
        if (!U64(Rva, V)) return false;
        if (V < m_Base || V >= m_Base + 0x20000000ULL) return false;
        OutRva = V - m_Base;
        return true;
    }

    bool NameAtRva(uint64_t Rva, std::string& Out, bool AllowColon) {
        auto Key = std::make_pair(Rva, AllowColon ? 1 : 0);
        auto It = m_NameCache.find(Key.first * 2 + Key.second);
        if (It != m_NameCache.end()) {
            Out = It->second;
            return !Out.empty();
        }
        std::string Res;
        const uint8_t* P = At(Rva, 8);
        if (P) {
            size_t Avail = 160;
            const uint8_t* Probe = At(Rva, Avail);
            if (!Probe) { Avail = 32; Probe = At(Rva, Avail); }
            if (Probe) {
                std::string D = TheiaStr::Decrypt(Probe, Avail);
                if (TheiaStr::PlausibleName(D, AllowColon)) Res = D;
            }
        }
        m_NameCache[Rva * 2 + (AllowColon ? 1 : 0)] = Res;
        Out = Res;
        return !Res.empty();
    }

    bool NameField(uint64_t FieldRva, std::string& Out, bool AllowColon = false) {
        uint64_t Target = 0;
        if (!PtrRva(FieldRva, Target)) return false;
        return NameAtRva(Target, Out, AllowColon);
    }

    void FindPackages() {
        static const char kMagic[] = "/Script/";
        const size_t MagicLen = 8;
        std::vector<std::pair<uint64_t, std::string>> ParamsByRva;
        for (size_t I = 0; I + MagicLen < m_RData.size(); ++I) {
            if (std::memcmp(m_RData.data() + I, kMagic, MagicLen) != 0) continue;
            size_t End = I;
            while (End < m_RData.size() && m_RData[End] != 0 && End - I < 96) ++End;
            if (End >= m_RData.size() || m_RData[End] != 0) continue;
            std::string Name((const char*)m_RData.data() + I, End - I);
            if (Name.size() < 9) continue;
            uint64_t StrRva = m_RDataRva + I;
            if (StrRva < 0x20) continue;
            uint64_t ParamsRva = StrRva - 0x20;
            uint64_t NamePtr = 0;
            if (!PtrRva(ParamsRva, NamePtr) || NamePtr != StrRva) continue;
            uint32_t Flags = 0;
            if (!U32(ParamsRva + 0x14, Flags)) continue;
            if ((Flags & 0x10u) == 0) continue;
            ParamsByRva.emplace_back(ParamsRva, Name);
        }

        std::unordered_map<uint64_t, std::string> PkgByParams;
        for (auto& Pr : ParamsByRva) PkgByParams[Pr.first] = Pr.second;
        m_PkgParamCount = PkgByParams.size();
        std::printf("[theia-static] FPackageParams found in .rdata: %zu\n", PkgByParams.size());
        if (PkgByParams.empty()) return;

        std::unordered_set<uint64_t> FnCandidates;
        for (size_t Off = 0; Off + 8 <= m_RData.size(); Off += 8) {
            uint64_t V = 0;
            std::memcpy(&V, m_RData.data() + Off, 8);
            if (V < m_Base) continue;
            uint64_t Rva = V - m_Base;
            if (!InSection(Rva, m_TextRva, m_TextSize)) continue;
            FnCandidates.insert(Rva);
        }

        std::printf("[theia-static] .rdata qwords pointing into .text: %zu distinct\n",
            FnCandidates.size());
        for (uint64_t FnRva : FnCandidates) {
            const uint8_t* Code = At(FnRva, 0x60);
            if (!Code) continue;
            for (int I = 0; I + 7 <= 0x60; ++I) {
                if (Code[I] != 0x48 || Code[I + 1] != 0x8D) continue;
                if ((Code[I + 2] & 0xC7) != 0x05) continue;
                int32_t Disp = 0;
                std::memcpy(&Disp, Code + I + 3, 4);
                uint64_t Target = FnRva + I + 7 + (uint64_t)(int64_t)Disp;
                auto It = PkgByParams.find(Target);
                if (It == PkgByParams.end()) continue;
                m_PkgByFn[m_Base + FnRva] = It->second;
                break;
            }
        }
    }

    // Accepting every .rdata position with a code pointer at +0x00 triples the
    // record count but the extra records are noise: shifted views of real
    // descriptors whose member walks run into neighbouring data. Measured
    // against the live dump the missing-member count went 1175 -> 6412 and
    // 8452 records were duplicate names. So the sweep stays keyed on the
    // package-wrapper set, and the wrapper set is recovered from .rdata rather
    // than .text — Theia leaves most of .text unmapped in a live process, and
    // .text is only ever needed to put a NAME on a wrapper.
    void VoteOuterFuncs() {
        std::unordered_map<uint64_t, uint32_t> Votes;
        for (size_t Off = 0; Off + 8 <= m_RData.size(); Off += 8) {
            uint64_t V = 0;
            std::memcpy(&V, m_RData.data() + Off, 8);
            if (V < m_Base) continue;
            if (!InSection(V - m_Base, m_TextRva, m_TextSize)) continue;
            uint64_t DescRva = m_RDataRva + Off;
            std::string Nm;
            uint64_t NameOff = 0;
            if (!TypeName(DescRva, Nm, NameOff)) continue;
            std::vector<EnumEntry> Ents;
            std::vector<MemberRecord> Members;
            if (!ReadEnumArray(DescRva, Ents) && !ReadParamArray(DescRva, Members))
                continue;
            ++Votes[V];
        }
        for (const auto& [Fn, N] : Votes) {
            if (N < 3) continue;
            if (m_PkgByFn.find(Fn) != m_PkgByFn.end()) continue;
            m_PkgByFn[Fn] = "?";
        }
    }

    void FindDescriptors(std::vector<std::pair<uint64_t, uint64_t>>& Out) {
        for (size_t Off = 0; Off + 8 <= m_RData.size(); Off += 8) {
            uint64_t V = 0;
            std::memcpy(&V, m_RData.data() + Off, 8);
            if (!V) continue;
            if (m_PkgByFn.find(V) == m_PkgByFn.end()) continue;
            Out.emplace_back(m_RDataRva + Off, V);
        }
    }

    bool TypeName(uint64_t DescRva, std::string& Out, uint64_t& OffOut) {
        static const uint64_t kOffsets[] = { 0x10, 0x18, 0x20, 0x28, 0x08 };
        for (uint64_t O : kOffsets) {
            if (NameField(DescRva + O, Out)) { OffOut = O; return true; }
        }
        return false;
    }

    bool ReadParam(uint64_t ParamRva, MemberRecord& Out) {
        if (!NameField(ParamRva, Out.Name)) return false;
        uint32_t Gen = 0;
        U32(ParamRva + 0x18, Gen);
        uint64_t Flags = 0;
        U64(ParamRva + 0x10, Flags);
        uint32_t Dim = 0;
        U32(ParamRva + 0x30, Dim);
        uint64_t Extra = 0;
        PtrRva(ParamRva + kParamBase, Extra);
        Out.Gen       = Gen;
        Out.Mods      = Gen & ~0x3Fu;
        Out.TypeName  = GenFlagName(Gen);
        Out.PropFlags = Flags;
        Out.ArrayDim  = Dim;
        Out.ParamRva  = ParamRva;
        Out.ExtraRva  = Extra;
        return true;
    }

    bool ReadParamArray(uint64_t DescRva, std::vector<MemberRecord>& Out) {
        std::vector<MemberRecord> Best;
        for (uint64_t O = 0x08; O < 0x40; O += 8) {
            uint64_t ArrRva = 0;
            if (!PtrRva(DescRva + O, ArrRva)) continue;
            std::vector<MemberRecord> Cur;
            for (int K = 0; K < 512; ++K) {
                uint64_t Entry = 0;
                if (!PtrRva(ArrRva + 8ULL * K, Entry)) break;
                MemberRecord Rec;
                if (!ReadParam(Entry, Rec)) break;
                Cur.push_back(std::move(Rec));
            }
            if (Cur.size() > Best.size()) Best = std::move(Cur);
        }
        if (Best.empty()) return false;
        Out = std::move(Best);
        return true;
    }

    bool ReadEnumArray(uint64_t DescRva, std::vector<EnumEntry>& Out) {
        for (uint64_t O = 0x08; O < 0x40; O += 8) {
            uint64_t ArrRva = 0;
            if (!PtrRva(DescRva + O, ArrRva)) continue;
            std::vector<EnumEntry> Cur;
            for (int K = 0; K < 4096; ++K) {
                uint64_t NamePtr = 0;
                if (!PtrRva(ArrRva + 16ULL * K, NamePtr)) break;
                std::string Nm;
                if (!NameAtRva(NamePtr, Nm, true)) break;
                uint64_t Val = 0;
                U64(ArrRva + 16ULL * K + 8, Val);
                EnumEntry E;
                E.Name  = Nm;
                E.Value = (int64_t)Val;
                Cur.push_back(std::move(E));
            }
            if (Cur.size() >= 2) { Out = std::move(Cur); return true; }
        }
        return false;
    }

    IMemoryReader& m_Reader;
    uint64_t m_Base;
    uint64_t m_TextRva, m_TextSize, m_RDataRva, m_RDataSize;
    std::vector<uint8_t> m_Text, m_RData;
    size_t m_PkgParamCount = 0;
    std::vector<uint64_t> m_Gaps;
    std::unordered_map<uint64_t, std::string> m_PkgByFn;
    std::unordered_map<uint64_t, std::string> m_NameCache;
};

inline bool SelfTest() {
    const uint8_t kCipher[] = { 0x31, 0x67, 0x36, 0x22, 0x6C, 0x7E, 0x7B,
                               0x67, 0x2B, 0x64, 0x4D, 0x67, 0x20, 0x03 };
    std::string Got = TheiaStr::Decrypt(kCipher, sizeof(kCipher));
    if (Got != "InstanceIndex") {
        std::printf("[theia-static] SELF-TEST FAILED: decrypt gave '%s'\n", Got.c_str());
        return false;
    }
    std::vector<uint8_t> Enc;
    if (!TheiaStr::Encrypt("InstanceIndex", Enc) ||
        Enc.size() != sizeof(kCipher) ||
        std::memcmp(Enc.data(), kCipher, sizeof(kCipher)) != 0) {
        std::printf("[theia-static] SELF-TEST FAILED: encrypt is not the inverse\n");
        return false;
    }
    return true;
}

inline void WriteReport(const Result& Res, const char* Path) {
    FILE* F = std::fopen(Path, "w");
    if (!F) {
        std::printf("[theia-static] cannot open %s for writing\n", Path);
        return;
    }
    std::fprintf(F, "# static UE reflection, decrypted from Z_Construct_* descriptors\n");
    std::fprintf(F, "# packages=%zu descriptors=%zu types=%zu members=%zu enum_values=%zu\n",
        Res.Packages, Res.Candidates, Res.Types.size(), Res.Members, Res.EnumValues);
    for (const auto& T : Res.Types) {
        std::fprintf(F, "\n%s %s.%s  desc=0x%llX name_off=0x%llX\n",
            T.Kind.c_str(), T.Package.c_str(), T.Name.c_str(),
            (unsigned long long)T.DescRva, (unsigned long long)T.NameOff);
        for (const auto& E : T.Entries)
            std::fprintf(F, "    = %-52s %lld\n", E.Name.c_str(), (long long)E.Value);
        for (const auto& M : T.Members)
            std::fprintf(F, "    . %-44s %-26s gen=0x%02X mods=0x%X flags=0x%llX dim=%u extra=0x%llX\n",
                M.Name.c_str(), M.TypeName.c_str(), M.Gen & 0x3Fu, M.Mods,
                (unsigned long long)M.PropFlags, M.ArrayDim,
                (unsigned long long)M.ExtraRva);
    }
    std::fclose(F);
    std::printf("[theia-static] wrote %s\n", Path);
}

inline Result Run(IMemoryReader& Reader, uint64_t ModuleBase,
                  uint64_t TextRva, uint64_t TextSize,
                  uint64_t RDataRva, uint64_t RDataSize,
                  const char* OutPath,
                  const char* FallbackImage = nullptr,
                  const char* FallbackImageB = nullptr) {
    Result Res;
    if (!SelfTest()) return Res;
    Sweeper S(Reader, ModuleBase, TextRva, TextSize, RDataRva, RDataSize);
    if (!S.LoadSections(FallbackImage, FallbackImageB)) {
        std::printf("[theia-static] section load failed\n");
        return Res;
    }
    Res = S.Run(FallbackImage, FallbackImageB);
    std::printf("[theia-static] packages=%zu descriptors=%zu -> types=%zu "
                "(enum=%zu struct/func=%zu bare=%zu no-name=%zu) members=%zu enum_values=%zu\n",
        Res.Packages, Res.Candidates, Res.Types.size(),
        Res.Enums, Res.Structs, Res.Bare, Res.NoName, Res.Members, Res.EnumValues);
    if (OutPath && !Res.Types.empty()) WriteReport(Res, OutPath);
    return Res;
}

} // namespace TheiaStatic
