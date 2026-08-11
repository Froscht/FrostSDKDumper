// ─────────────────────────────────────────────────────────────────────────────
// auto_resolve.h — patch-day automation for the pieces that cost the most
// manual reversing.
//
// The lesson of the 24653108 port: the *shapes* are stable across patches and
// the *constants* are not. Theia moves every RVA, every XOR key, every rotate
// amount, and ships interchangeable code variants — but it has never moved the
// FNV-32 prime 0x1000193, never changed FUObjectItem's 20-byte stride, and
// never stopped putting CompIndex 0 at the name "None". Those three invariants
// are enough to relocate and re-extract the two functions that took the longest
// to find by hand.
//
// So: locate by invariant, extract by disassembly, and validate against ground
// truth. Never pattern-match a fixed instruction list — 73 of the 74 chunk
// thunks in this build are structurally unique, which is proof that approach
// cannot survive.
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <functional>

#include "sig_scanner_v2.h"
#include "insn_decoder.h"
#include "func_analyzer.h"
#include "auto_discovery.h"

namespace AutoResolve {

// The one arithmetic constant Theia has never moved. Both the FNamePool shard
// hash and UObject::GetFName are FNV-32 chains built on it.
constexpr uint32_t FNV32_PRIME = 0x01000193u;

// ─────────────────────────────────────────────────────────────────────────────
// Every `imul r32, r32, 0x1000193` in .text, grouped by containing function.
//
// Encoding is `69 /r id`, so the 4 immediate bytes sit exactly 2 bytes after
// the 0x69 opcode whether or not a REX prefix is present (the ModR/M byte is
// always 1 byte). Scanning for the immediate and checking backwards is both
// cheaper and more robust than enumerating REX permutations.
// ─────────────────────────────────────────────────────────────────────────────
struct FnvSite {
    uint64_t Rva      = 0;   // the imul itself
    uint64_t FuncRva  = 0;   // containing function start, 0 if not recoverable
};

inline std::vector<FnvSite> FindFnvImulSites(const SigScanV2::Scanner& Scanner,
                                             const AutoDiscovery::ModuleBounds& Bounds)
{
    std::vector<FnvSite> Out;
    if (!Bounds.Valid || !Bounds.TextSize) return Out;

    const uint8_t Imm[4] = { 0x93, 0x01, 0x00, 0x01 };
    uint64_t Lo = Bounds.TextRva, Hi = Bounds.TextEnd();

    for (uint64_t R = Lo + 2; R + 4 <= Hi; ++R) {
        const uint8_t* P = Scanner.GetLocalPtr(R);
        if (!P) continue;
        if (std::memcmp(P, Imm, 4) != 0) continue;
        const uint8_t* Op = Scanner.GetLocalPtr(R - 2);
        if (!Op || *Op != 0x69) continue;

        FnvSite S;
        S.Rva = R - 2;
        S.FuncRva = FuncAnalyze::FindFunctionStart(Scanner, S.Rva);
        Out.push_back(S);
    }
    return Out;
}

// Group sites by containing function, most-hits first. GetFName has 4; the
// FName resolver has 4 as well but sits in a much longer function.
inline std::vector<std::pair<uint64_t, int>>
GroupFnvSitesByFunction(const std::vector<FnvSite>& Sites)
{
    std::unordered_map<uint64_t, int> Counts;
    for (const auto& S : Sites)
        if (S.FuncRva) ++Counts[S.FuncRva];

    std::vector<std::pair<uint64_t, int>> Out(Counts.begin(), Counts.end());
    std::sort(Out.begin(), Out.end(),
        [](const auto& A, const auto& B) { return A.second > B.second; });
    return Out;
}

// ─────────────────────────────────────────────────────────────────────────────
// UObject::GetFName — located and fully extracted.
//
// Shape (stable since at least CL-1325322; only the numbers move):
//   lea   rax, [rcx + SeedOff]
//   mov   r8, rax ; shr r8, 32                 <- Hi
//   rol   eax, ROL                             <- Lo
//   imul/add/shr  x4, prime 0x1000193, one ADD
//   mov   r8d, eax ; shr r8d, 16 ; xor r8d, eax   <- S = H ^ (H >> 16)
//   and   r8d, 3 ; xor r8d, SLOTXOR ; shl r8d, 5
//   movdqa xmm0, [rcx + r8 + SlotBase]
//   pshufb xmm0, [rip + MaskRva]
//   psrlw/psllw/por                            <- ROL16
//   movq  rcx, xmm0 ; movabs rdx, XOR64 ; xor rdx, rcx
//   rol   rdx, FINALROL ; mov [rax], rdx ; ret
// ─────────────────────────────────────────────────────────────────────────────
struct GetFNameInfo {
    bool     Valid        = false;
    uint64_t Rva          = 0;

    uint32_t Prime        = FNV32_PRIME;
    uint32_t Add          = 0;
    int      Rol          = 0;      // rol eax, N on the low dword
    int      ShiftA       = 0;      // the three shr amounts, in order
    int      ShiftB       = 0;
    int      ShiftC       = 0;

    uint32_t SlotXor      = 0;      // `xor r, N` right after `and r, 3`
    uint64_t SlotBase     = 0;      // displacement in movdqa [rcx + r + disp]
    uint64_t SlotStride   = 0;      // 1 << (shl amount)

    uint64_t PshufbMaskRva = 0;
    int      Rol16         = 0;
    uint64_t Xor64         = 0;
    int      FinalRol64    = 0;

    // Class, Outer and Name accessors share one FNV chain and differ only in
    // how they adjust the slot index. Extracting a copy without deciding which
    // one it is silently mixes all three together.
    enum class Role { Unknown, Class, Outer, Name };
    Role     Which = Role::Unknown;

    std::string Reject;             // why a candidate was turned down
};

inline const char* RoleName(GetFNameInfo::Role R) {
    switch (R) {
        case GetFNameInfo::Role::Class: return "Class";
        case GetFNameInfo::Role::Outer: return "Outer";
        case GetFNameInfo::Role::Name:  return "Name";
        default:                        return "Unknown";
    }
}

namespace Detail {

// `xor r32, imm8` is `83 /6 ib`, optionally REX-prefixed. The decoder folds
// this into INSN_UNKNOWN, so read it off the bytes.
inline bool ReadXorImm8(const SigScanV2::Scanner& Scanner, uint64_t Rva, uint32_t& Out) {
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    int I = 0;
    if ((P[0] & 0xF0) == 0x40) I = 1;          // REX
    if (P[I] != 0x83) return false;
    if (((P[I + 1] >> 3) & 7) != 6) return false;   // /6 == xor
    Out = P[I + 2];
    return true;
}

// Displacement of `movdqa xmm, [base + index + disp8/32]`. Only the disp is
// wanted; the SIB form is fixed (base=rcx, index=the scaled slot register).
inline bool ReadMovdqaDisp(const SigScanV2::Scanner& Scanner, uint64_t Rva,
                           uint8_t Len, uint64_t& Out)
{
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P || Len < 5) return false;
    // Walk past prefixes to the 0F 6F opcode, then ModR/M (+SIB) and disp.
    int I = 0;
    while (I < Len && (P[I] == 0x66 || P[I] == 0xF3 || (P[I] & 0xF0) == 0x40)) ++I;
    if (I + 2 >= Len || P[I] != 0x0F || P[I + 1] != 0x6F) return false;
    int M = I + 2;
    uint8_t Mod = (P[M] >> 6) & 3;
    uint8_t Rm  = P[M] & 7;
    int D = M + 1;
    if (Rm == 4) ++D;                          // SIB present
    if (Mod == 1) { Out = P[D]; return true; }
    if (Mod == 2) { uint32_t V; std::memcpy(&V, P + D, 4); Out = V; return true; }
    if (Mod == 0) { Out = 0; return true; }
    return false;
}

// `add r32, 1` (83 /0 01) or `inc r32` (FF /0) — the Outer accessor's marker.
inline bool IsPlusOne(const SigScanV2::Scanner& Scanner, uint64_t Rva) {
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    int I = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
    if (P[I] == 0x83 && ((P[I + 1] >> 3) & 7) == 0 && P[I + 2] == 1) return true;
    if (P[I] == 0xFF && ((P[I + 1] >> 3) & 7) == 0) return true;
    return false;
}

} // namespace Detail

inline GetFNameInfo ExtractGetFName(const SigScanV2::Scanner& Scanner,
                                    uint64_t FuncRva)
{
    GetFNameInfo Info;
    Info.Rva = FuncRva;

    auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, FuncRva, 256);
    if (Insns.size() < 20) { Info.Reject = "too short to decode"; return Info; }

    // Cut at the first RET — GetFName is a leaf with a single exit.
    size_t End = Insns.size();
    for (size_t I = 0; I < Insns.size(); ++I)
        if (Insns[I].type == INSN_RET) { End = I + 1; break; }
    if (End == Insns.size()) { Info.Reject = "no ret within window"; return Info; }

    std::vector<uint32_t> Adds;
    std::vector<int>      Shrs;
    int  ImulCount = 0;
    bool SawAnd3 = false;

    for (size_t I = 0; I < End; ++I) {
        const auto& In = Insns[I];

        if (In.type == INSN_IMUL && In.hasImm32 && In.imm32 == FNV32_PRIME) {
            ++ImulCount;
            continue;
        }
        if (In.type == INSN_ADD_IMM && In.hasImm32) { Adds.push_back(In.imm32); continue; }

        // Only shifts inside the hash chain count. The prologue's
        // `shr r8, 0x20` extracts the seed's high dword and would otherwise
        // be mistaken for the first hash shift, pushing every later one out
        // of position.
        if (In.type == INSN_SHR && In.hasImm8) {
            if (ImulCount >= 1 && In.imm8 != 16 && In.imm8 != 32) Shrs.push_back(In.imm8);
            continue;
        }

        // First ROL is the seed rotate, last is the final FName rotate.
        // Do not key this on REX.W: the decoder does not reliably flag it.
        if (In.type == INSN_ROL && In.hasImm8) {
            if (!Info.Rol) Info.Rol = In.imm8;
            Info.FinalRol64 = In.imm8;
        }

        if (In.type == INSN_AND_IMM && In.imm32 == 3u) {
            SawAnd3 = true;
            uint32_t Xv = 0;
            bool HasXor = false;
            for (size_t K = I + 1; K < End && K <= I + 3; ++K)
                if (Detail::ReadXorImm8(Scanner, Insns[K].rva, Xv)) { HasXor = true; break; }
            bool PlusOne = false;
            for (size_t K = (I >= 3 ? I - 3 : 0); K < I; ++K)
                if (Detail::IsPlusOne(Scanner, Insns[K].rva)) { PlusOne = true; break; }

            if (HasXor)      { Info.SlotXor = Xv;  Info.Which = GetFNameInfo::Role::Name;  }
            else if (PlusOne) {                    Info.Which = GetFNameInfo::Role::Outer; }
            else              {                    Info.Which = GetFNameInfo::Role::Class; }
            continue;
        }

        if (In.type == INSN_SHL && In.hasImm8 && SawAnd3 && !Info.SlotStride)
            Info.SlotStride = 1ULL << In.imm8;

        if (In.type == INSN_MOVDQA && !In.hasRipRel && SawAnd3 && !Info.SlotBase)
            Detail::ReadMovdqaDisp(Scanner, In.rva, In.length, Info.SlotBase);

        if (In.type == INSN_PSHUFB && In.hasRipRel && !Info.PshufbMaskRva)
            Info.PshufbMaskRva = In.ResolveRipRVA();

        if (In.type == INSN_PSLLW && In.hasImm8 && !Info.Rol16)
            Info.Rol16 = In.imm8;

        if (In.imm64 && !Info.Xor64) Info.Xor64 = In.imm64;

    }

    if (ImulCount < 4)          { Info.Reject = "fewer than 4 FNV multiplies";      return Info; }
    if (Adds.empty())           { Info.Reject = "no add-immediate found";           return Info; }
    if (Shrs.size() < 3)        { Info.Reject = "fewer than 3 shift-rights";        return Info; }
    if (!Info.PshufbMaskRva)    { Info.Reject = "no rip-relative pshufb mask";      return Info; }
    if (!Info.Xor64)            { Info.Reject = "no 64-bit xor constant";           return Info; }
    if (!Info.SlotStride)       { Info.Reject = "no slot stride (shl after and 3)"; return Info; }
    if (!Info.SlotBase)         { Info.Reject = "no slot base displacement";        return Info; }

    // All four ADDs carry the same constant; take the majority so one
    // mis-decode cannot poison it.
    std::sort(Adds.begin(), Adds.end());
    uint32_t Best = Adds[0]; size_t BestN = 0, Run = 0; uint32_t Cur = Adds[0];
    for (uint32_t A : Adds) {
        if (A == Cur) ++Run; else { Cur = A; Run = 1; }
        if (Run > BestN) { BestN = Run; Best = Cur; }
    }
    Info.Add = Best;

    Info.ShiftA = Shrs[0];
    Info.ShiftB = Shrs[1];
    Info.ShiftC = Shrs[2];
    if (!Info.Rol16) Info.Rol16 = 2;
    Info.Valid = true;
    return Info;
}

// Search every FNV-bearing function for the one that is GetFName.
inline GetFNameInfo FindGetFName(const SigScanV2::Scanner& Scanner,
                                 const AutoDiscovery::ModuleBounds& Bounds)
{
    GetFNameInfo Best;
    auto Sites  = FindFnvImulSites(Scanner, Bounds);
    auto Groups = GroupFnvSitesByFunction(Sites);

    std::printf("[autoresolve] %zu FNV-prime multiplies across %zu functions\n",
        Sites.size(), Groups.size());

    // Theia ships many structurally identical copies of GetFName. Rather than
    // trusting whichever one is found first, extract every copy and take the
    // majority value per field — the duplication Theia added for obfuscation
    // becomes free redundancy, and a single mis-decoded clone cannot win.
    // Thousands of functions carry four FNV multiplies, so decoding them all
    // is too slow and capping the list silently drops the real accessors —
    // 0x5027E0 sat past a 2000-entry cap on this build. Prefilter on raw
    // bytes instead: a slot accessor always contains a `pshufb xmm,[rip]`
    // (66 0F 38 00) within its first 256 bytes, which almost nothing else in
    // an FNV-bearing function does.
    auto LooksLikeAccessor = [&](uint64_t Func) {
        for (uint64_t K = 0; K + 4 < 256; ++K) {
            const uint8_t* P = Scanner.GetLocalPtr(Func + K);
            if (!P) return false;
            if (P[0] == 0x66 && P[1] == 0x0F && P[2] == 0x38 && P[3] == 0x00) return true;
            if (P[0] == 0xC3) return false;    // ret — function ended
        }
        return false;
    };

    std::vector<GetFNameInfo> Hits;
    int Scanned = 0;
    for (const auto& [Func, Count] : Groups) {
        if (Count < 4) break;                  // sorted descending
        ++Scanned;
        if (!LooksLikeAccessor(Func)) continue;
        GetFNameInfo I = ExtractGetFName(Scanner, Func);
        if (!I.Valid) continue;
        if (I.SlotStride != 0x20 || I.SlotBase == 0 || I.SlotBase > 0x200) continue;
        Hits.push_back(I);
    }

    int NClass = 0, NOuter = 0, NName = 0;
    for (const auto& H : Hits) {
        if (H.Which == GetFNameInfo::Role::Class) ++NClass;
        else if (H.Which == GetFNameInfo::Role::Outer) ++NOuter;
        else if (H.Which == GetFNameInfo::Role::Name) ++NName;
    }
    std::printf("[autoresolve] %d functions with 4+ FNV multiplies, %zu slot-accessor "
                "copies: %d Class, %d Outer, %d Name\n",
        Scanned, Hits.size(), NClass, NOuter, NName);

    // Only the Name copies carry the final ROL64 and the slot xor, so the
    // consensus has to be taken over those alone.
    std::vector<GetFNameInfo> NameHits;
    for (const auto& H : Hits)
        if (H.Which == GetFNameInfo::Role::Name) NameHits.push_back(H);
    if (!NameHits.empty()) Hits.swap(NameHits);

    if (!Hits.empty()) {
        auto Mode = [&](auto Get) {
            std::unordered_map<uint64_t, int> C;
            for (const auto& H : Hits) ++C[(uint64_t)Get(H)];
            uint64_t BestV = 0; int BestN = 0;
            for (const auto& [V, N] : C) if (N > BestN) { BestN = N; BestV = V; }
            return std::pair<uint64_t, int>{ BestV, BestN };
        };
        Best = Hits.front();
        Best.Add           = (uint32_t)Mode([](const GetFNameInfo& H){ return H.Add; }).first;
        Best.Rol           = (int)     Mode([](const GetFNameInfo& H){ return H.Rol; }).first;
        Best.ShiftA        = (int)     Mode([](const GetFNameInfo& H){ return H.ShiftA; }).first;
        Best.ShiftB        = (int)     Mode([](const GetFNameInfo& H){ return H.ShiftB; }).first;
        Best.ShiftC        = (int)     Mode([](const GetFNameInfo& H){ return H.ShiftC; }).first;
        Best.SlotXor       = (uint32_t)Mode([](const GetFNameInfo& H){ return H.SlotXor; }).first;
        Best.SlotBase      =           Mode([](const GetFNameInfo& H){ return H.SlotBase; }).first;
        Best.PshufbMaskRva =           Mode([](const GetFNameInfo& H){ return H.PshufbMaskRva; }).first;
        Best.Rol16         = (int)     Mode([](const GetFNameInfo& H){ return H.Rol16; }).first;
        Best.Xor64         =           Mode([](const GetFNameInfo& H){ return H.Xor64; }).first;
        Best.FinalRol64    = (int)     Mode([](const GetFNameInfo& H){ return H.FinalRol64; }).first;
        auto AddAgree = Mode([](const GetFNameInfo& H){ return H.Add; });
        std::printf("[autoresolve] consensus over %zu %s copies; add 0x%08X held by %d\n",
            Hits.size(), RoleName(Best.Which), Best.Add, AddAgree.second);
        Best.Valid = true;
    }

    if (Best.Valid) {
        std::printf("[autoresolve] GetFName @ RVA 0x%llX — prime 0x%X add 0x%08X "
                    "rol %d shr %d/%d/%d, slot (S&3)^%u at +0x%llX stride 0x%llX\n",
            (unsigned long long)Best.Rva, Best.Prime, Best.Add, Best.Rol,
            Best.ShiftA, Best.ShiftB, Best.ShiftC, Best.SlotXor,
            (unsigned long long)Best.SlotBase, (unsigned long long)Best.SlotStride);
        std::printf("[autoresolve]   pshufb mask 0x%llX, rol16 %d, xor 0x%016llX, final rol64 %d\n",
            (unsigned long long)Best.PshufbMaskRva, Best.Rol16,
            (unsigned long long)Best.Xor64, Best.FinalRol64);
    } else {
        std::printf("[autoresolve] GetFName not located — falling back to compile-time RVA\n");
    }
    return Best;
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural validation of the slot selector.
//
// This is the check that matters most, because the failure it catches is
// silent. A hash with a transposed shift or a C++ precedence slip (`&` binds
// looser than `+`, so `(x * P) & M + Hi + ADD` becomes `(x * P) & (M + Hi +
// ADD)`) still returns a plausible number and still selects *a* slot — it just
// selects the wrong one, and the only symptom is a naming rate that looks
// merely mediocre instead of broken.
//
// The name slot can be identified WITHOUT the hash: after decryption, a name
// holds CompIndex in the high dword and FName::Number (almost always 0) in the
// low dword, while the class/outer pointers occupy the low dword and leave the
// high dword clear. Objects where exactly one slot has that shape are ground
// truth to score any candidate hash against.
// ─────────────────────────────────────────────────────────────────────────────
struct SlotScore {
    int    Samples   = 0;   // objects with exactly one name-shaped slot
    int    Agree     = 0;   // ... where the predicted index matched
    double Rate      = 0.0;
    bool   Confident = false;
};

inline SlotScore ScoreNameSlotSelector(
        const std::vector<uint64_t>& Objects,
        const std::function<uint64_t(uint64_t)>& ReadSlotDecrypted,
        const std::function<uint32_t(uint64_t)>& PredictIndex,
        uint64_t SlotBase, uint64_t SlotStride, int MaxSamples = 400)
{
    (void)SlotBase; (void)SlotStride;
    SlotScore S;
    for (uint64_t Obj : Objects) {
        if (S.Samples >= MaxSamples) break;

        int Found = -1, Count = 0;
        for (uint32_t I = 0; I < 4; ++I) {
            uint64_t V = ReadSlotDecrypted(Obj + I);   // caller encodes index in the low bits
            if ((V & 0xFFFFFFFFull) == 0 && (V >> 32) != 0) { Found = (int)I; ++Count; }
        }
        if (Count != 1) continue;                      // ambiguous — skip

        ++S.Samples;
        if (PredictIndex(Obj) == (uint32_t)Found) ++S.Agree;
    }
    if (S.Samples) S.Rate = (double)S.Agree / (double)S.Samples;
    S.Confident = S.Samples >= 50 && S.Rate >= 0.95;
    return S;
}

// ─────────────────────────────────────────────────────────────────────────────
// The chunks_manager global.
//
// On build 24653108 this stopped being a field inside a GUObjectArray struct
// and became a standalone encrypted 16-byte global, addressed rip-absolute at
// all 838 of its read sites with zero writes and zero LEAs. No base pointer and
// no xref ranking can find it — but the routine that *uses* it is unmistakable,
// because FUObjectItem's 20-byte stride forces a distinctive index computation:
//
//   lea r, [r + r*4]      ; *5
//   shl r32, 2            ; *4  => *20
//   add r, [base + idx*8] ; chunk pointer
//
// Find that, take the containing function, and the first rip-relative SIMD load
// from .data in it is the global.
// ─────────────────────────────────────────────────────────────────────────────
struct ChunkMgrGlobal {
    bool     Valid    = false;
    uint64_t GlobalRva = 0;
    uint64_t FuncRva   = 0;
    int      Candidates = 0;
};

inline std::vector<uint64_t> FindStride20Sites(const SigScanV2::Scanner& Scanner,
                                               const AutoDiscovery::ModuleBounds& Bounds)
{
    std::vector<uint64_t> Out;
    if (!Bounds.Valid || !Bounds.TextSize) return Out;

    for (uint64_t R = Bounds.TextRva; R + 8 <= Bounds.TextEnd(); ++R) {
        const uint8_t* P = Scanner.GetLocalPtr(R);
        if (!P) continue;
        // REX.W + 8D (lea) + ModR/M with mod=00, rm=100 (SIB follows)
        if ((P[0] & 0xF8) != 0x48 || P[1] != 0x8D) continue;
        if ((P[2] & 0xC7) != 0x04) continue;
        uint8_t Sib = P[3];
        if (((Sib >> 6) & 3) != 2) continue;                 // scale *4
        if (((Sib >> 3) & 7) != (Sib & 7)) continue;         // index == base
        // `shl r32, 2` within the next few bytes: C1 /4 02
        bool Shl = false;
        for (int K = 4; K < 12; ++K) {
            const uint8_t* Q = Scanner.GetLocalPtr(R + K);
            if (!Q) break;
            int J = ((Q[0] & 0xF0) == 0x40) ? 1 : 0;
            if (Q[J] == 0xC1 && ((Q[J + 1] >> 3) & 7) == 4 && Q[J + 2] == 2) { Shl = true; break; }
        }
        if (Shl) Out.push_back(R);
    }
    return Out;
}

inline ChunkMgrGlobal FindChunkMgrGlobal(const SigScanV2::Scanner& Scanner,
                                         const AutoDiscovery::ModuleBounds& Bounds,
                                         const std::function<bool(uint64_t)>& ValidateGlobal)
{
    ChunkMgrGlobal Out;
    auto Sites = FindStride20Sites(Scanner, Bounds);
    std::printf("[autoresolve] %zu FUObjectItem stride-20 index sites\n", Sites.size());

    std::unordered_map<uint64_t, int> GlobalVotes;
    std::unordered_map<uint64_t, uint64_t> GlobalFunc;

    for (uint64_t Site : Sites) {
        uint64_t Func = FuncAnalyze::FindFunctionStart(Scanner, Site);
        if (!Func) continue;

        auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, Func, 512);
        for (const auto& In : Insns) {
            if (!In.hasRipRel) continue;
            if (In.type != INSN_PSHUFLW && In.type != INSN_MOVDQA && In.type != INSN_MOVQ)
                continue;
            uint64_t T = In.ResolveRipRVA();
            if (T < Bounds.DataRva || T >= Bounds.DataEnd()) continue;
            ++GlobalVotes[T];
            GlobalFunc[T] = Func;
            break;                                   // first .data SIMD load only
        }
    }

    std::vector<std::pair<uint64_t, int>> Ranked(GlobalVotes.begin(), GlobalVotes.end());
    std::sort(Ranked.begin(), Ranked.end(),
        [](const auto& A, const auto& B) { return A.second > B.second; });
    Out.Candidates = (int)Ranked.size();

    for (size_t I = 0; I < Ranked.size() && I < 16; ++I) {
        std::printf("[autoresolve]   candidate .data 0x%llX (%d site%s)%s\n",
            (unsigned long long)Ranked[I].first, Ranked[I].second,
            Ranked[I].second == 1 ? "" : "s",
            I == 0 ? "  <- highest" : "");
        if (ValidateGlobal && ValidateGlobal(Ranked[I].first)) {
            Out.Valid     = true;
            Out.GlobalRva = Ranked[I].first;
            Out.FuncRva   = GlobalFunc[Ranked[I].first];
            std::printf("[autoresolve] chunks_manager global = RVA 0x%llX "
                        "(accessed from 0x%llX, passed validation)\n",
                (unsigned long long)Out.GlobalRva, (unsigned long long)Out.FuncRva);
            return Out;
        }
    }

    std::printf("[autoresolve] no chunks_manager candidate passed validation\n");
    return Out;
}

} // namespace AutoResolve
