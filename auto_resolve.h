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
#include <cctype>
#include <cstdlib>

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
// The live sheet.
//
// Everything auto-resolve can extract and validate lives here rather than in a
// constexpr namespace, so a patch that moves these values does not require a
// rebuild. Defaults are the compile-time v20260811 numbers; Phase 6.5
// overwrites them only after the extraction has been checked, and the FName
// self-test ("None") plus the slot scorer are the two things that get to say
// whether it was right.
// ─────────────────────────────────────────────────────────────────────────────
// Fold an extracted GetFName into the sheet. The PSHUFB mask is read from the
// module rather than assumed, because it is the one field whose bytes are not
// recoverable from the instruction stream.
inline bool AdoptGetFName(const GetFNameInfo& I,
                          const SigScanV2::Scanner& Scanner,
                          ArcDecrypt::LiveSheet& S = ArcDecrypt::g_Sheet)
{
    if (!I.Valid || I.Which != GetFNameInfo::Role::Name) return false;
    if (!I.Add || !I.Rol || !I.SlotStride || !I.Xor64) return false;

    uint8_t Mask[8];
    const uint8_t* P = Scanner.GetLocalPtr(I.PshufbMaskRva);
    if (!P) return false;
    std::memcpy(Mask, P, 8);
    for (int K = 0; K < 8; ++K)
        if ((Mask[K] & 0x80) == 0 && (Mask[K] & 0x7F) > 7) return false;   // not a byte permute

    S.SlotHashPrime = I.Prime;
    S.SlotHashAdd   = I.Add;
    S.SlotHashRol   = I.Rol;
    S.SlotShiftA    = I.ShiftA;
    S.SlotShiftB    = I.ShiftB;
    S.SlotShiftC    = I.ShiftC;
    S.SlotNameXor   = I.SlotXor;
    S.SlotBase      = I.SlotBase;
    S.SlotStride    = I.SlotStride;
    std::memcpy(S.SlotPshufb, Mask, 8);
    S.SlotRol16     = I.Rol16;
    S.SlotXor64     = I.Xor64;
    S.SlotFinalRol  = I.FinalRol64;
    S.Resolved      = true;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// The FNamePool resolver.
//
// Anchored on the FNV-64 prime 0x100000001B3, which has moved no more than its
// 32-bit sibling. Only a handful of functions carry it, and the resolver is the
// one that also loads a .data global with a LEA.
//
// The shard hash is NOT extracted as a fixed op list. Its shape already changed
// once — CL-1325322 seeded it with `Lo >> 4`, build 24653108 with a
// `mov r8d,0x10 ; shld r8d,edx,0x1A` pair that yields (0x40000000 | (Lo >> 6))
// — so it is recorded as a small program and interpreted. Same reasoning as the
// chunk thunks: assume the alphabet, never the sequence.
// ─────────────────────────────────────────────────────────────────────────────
struct FNameResolverInfo {
    bool     Valid = false;
    uint64_t Rva   = 0;

    uint64_t PoolRva     = 0;
    uint64_t SeedOff     = 0;
    uint64_t BlockBase   = 0;

    std::vector<ArcDecrypt::HashOp> Hash;

    uint64_t BlockMaskRva = 0;
    int      BlockRol16   = 0;
    uint64_t BlockXor     = 0;

    uint64_t FnvPrime = 0;
    uint64_t FnvAdd   = 0;
    int      FnvRol1  = 0;
    int      FnvRol2  = 0;

    std::string Reject;
};

namespace Detail {

// `add r32, r32` — how the seed's high dword joins the chain. Register-to-
// register adds do not come back from the decoder with usable operands.
inline bool IsRegAdd32(const SigScanV2::Scanner& Scanner, uint64_t Rva) {
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    int I = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
    return P[I] == 0x01 && (P[I + 1] & 0xC0) == 0xC0;
}

// `mov r32, imm32` (B8+r). Feeds the SHLD seed form.
inline bool ReadMovImm32(const SigScanV2::Scanner& Scanner, uint64_t Rva, uint32_t& Out) {
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    int I = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
    if ((P[I] & 0xF8) != 0xB8) return false;
    std::memcpy(&Out, P + I + 1, 4);
    return true;
}

} // namespace Detail

inline std::vector<uint64_t> FindFnv64Sites(const SigScanV2::Scanner& Scanner,
                                            const AutoDiscovery::ModuleBounds& Bounds)
{
    std::vector<uint64_t> Out;
    if (!Bounds.Valid || !Bounds.TextSize) return Out;
    const uint8_t Imm[8] = { 0xB3, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    for (uint64_t R = Bounds.TextRva; R + 8 <= Bounds.TextEnd(); ++R) {
        const uint8_t* P = Scanner.GetLocalPtr(R);
        if (!P || std::memcmp(P, Imm, 8) != 0) continue;
        uint64_t F = FuncAnalyze::FindFunctionStart(Scanner, R);
        if (F) Out.push_back(F);
    }
    std::sort(Out.begin(), Out.end());
    Out.erase(std::unique(Out.begin(), Out.end()), Out.end());
    return Out;
}

inline FNameResolverInfo ExtractFNameResolver(const SigScanV2::Scanner& Scanner,
                                              const AutoDiscovery::ModuleBounds& Bounds,
                                              uint64_t FuncRva)
{
    FNameResolverInfo R;
    R.Rva = FuncRva;

    auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, FuncRva, 1024);
    if (Insns.size() < 30) { R.Reject = "too short"; return R; }

    size_t End = Insns.size();
    std::vector<uint64_t> Movabs;
    bool InHash = false;
    bool HashDone = false;
    int  ImulSeen = 0;

    for (size_t I = 0; I < End; ++I) {
        const auto& In = Insns[I];

        if (In.type == INSN_LEA && In.hasRipRel && !R.PoolRva) {
            uint64_t T = In.ResolveRipRVA();
            if (T >= Bounds.DataRva && T < Bounds.DataEnd()) R.PoolRva = T;
        }

        // The seed offset is a large add-immediate on a 64-bit register, just
        // before the hash starts.
        if (In.type == INSN_ADD_IMM && In.hasImm32 && !InHash &&
            In.imm32 >= 0x100 && In.imm32 < 0x100000 && !R.SeedOff)
            R.SeedOff = In.imm32;

        if (In.type == INSN_SHLD && In.hasImm8) {
            uint32_t Mv = 0;
            for (size_t K = (I >= 3 ? I - 3 : 0); K < I; ++K)
                if (Detail::ReadMovImm32(Scanner, Insns[K].rva, Mv)) break;
            R.Hash.push_back({ ArcDecrypt::HashOp::SeedShld, In.imm8, Mv });
            InHash = true;
            continue;
        }

        if (In.type == INSN_IMUL && In.hasImm32 && In.imm32 == FNV32_PRIME) {
            if (!InHash) {
                // No SHLD seed: whatever shaped Lo immediately before is it.
                for (size_t K = I; K-- > 0 && K + 4 > I; ) {
                    if (Insns[K].type == INSN_SHR && Insns[K].hasImm8) {
                        R.Hash.push_back({ ArcDecrypt::HashOp::SeedShr, Insns[K].imm8, 0 }); break;
                    }
                    if (Insns[K].type == INSN_ROL && Insns[K].hasImm8) {
                        R.Hash.push_back({ ArcDecrypt::HashOp::SeedRol, Insns[K].imm8, 0 }); break;
                    }
                }
                InHash = true;
            }
            ++ImulSeen;
            if (!HashDone) R.Hash.push_back({ ArcDecrypt::HashOp::Imul, FNV32_PRIME, 0 });
            continue;
        }

        if (!InHash) continue;

        // The hash ends at `S = H ^ (H >> 16)`. Without this the collector runs
        // on into the FNV-64 fold and swallows its 40/41-bit rotates as if they
        // were hash steps — the constants all come out right and only the
        // program is wrong, which resolves CI=0 to garbage and looks like a
        // bad pool address.
        if (!HashDone && In.type == INSN_SHR && In.hasImm8 && In.imm8 == 16 && ImulSeen >= 3)
            HashDone = true;

        if (!HashDone) {
            if (In.type == INSN_ADD_IMM && In.hasImm32) { R.Hash.push_back({ ArcDecrypt::HashOp::Add, In.imm32, 0 }); continue; }
            if (In.type == INSN_ROL && In.hasImm8)      { R.Hash.push_back({ ArcDecrypt::HashOp::Rol, In.imm8, 0 }); continue; }
            if (In.type == INSN_SHR && In.hasImm8) {
                if (In.imm8 == 16 || In.imm8 == 32) continue;   // S fold, Hi extract
                R.Hash.push_back({ ArcDecrypt::HashOp::Shr, In.imm8, 0 });
                continue;
            }
            if (Detail::IsRegAdd32(Scanner, In.rva)) { R.Hash.push_back({ ArcDecrypt::HashOp::AddHi, 0, 0 }); continue; }
        }

        if (In.type == INSN_MOVDQA && !In.hasRipRel && !R.BlockBase) {
            uint64_t Disp = 0;
            if (Detail::ReadMovdqaDisp(Scanner, In.rva, In.length, Disp) && Disp >= 0x100)
                R.BlockBase = Disp;
        }
        if ((In.type == INSN_PSHUFB || In.type == INSN_MOVQ) && In.hasRipRel && !R.BlockMaskRva) {
            uint64_t T = In.ResolveRipRVA();
            if (T >= Bounds.RDataRva && T < Bounds.RDataEnd()) R.BlockMaskRva = T;
        }
        if (In.type == INSN_PSLLW && In.hasImm8 && !R.BlockRol16) R.BlockRol16 = In.imm8;
        if (In.imm64) Movabs.push_back(In.imm64);
    }

    for (uint64_t M : Movabs) {
        if (M == 0x100000001B3ULL) { R.FnvPrime = M; continue; }
        if (!R.BlockXor) R.BlockXor = M;
        else if (!R.FnvAdd && M != R.BlockXor) R.FnvAdd = M;
    }

    // The two 64-bit rotates that fold the FNV chain.
    std::vector<int> Big;
    for (const auto& In : Insns)
        if (In.type == INSN_ROL && In.hasImm8 && In.imm8 >= 32) Big.push_back(In.imm8);
    if (Big.size() >= 2) { R.FnvRol1 = Big[0]; R.FnvRol2 = Big[1]; }

    if (!R.PoolRva)      { R.Reject = "no .data pool lea";      return R; }
    if (!R.SeedOff)      { R.Reject = "no seed offset";         return R; }
    if (!R.BlockBase)    { R.Reject = "no block base";          return R; }
    if (!R.BlockMaskRva) { R.Reject = "no block mask";          return R; }
    if (!R.BlockXor)     { R.Reject = "no block xor";           return R; }
    if (!R.FnvPrime)     { R.Reject = "no FNV-64 prime";        return R; }
    if (!R.FnvAdd)       { R.Reject = "no FNV-64 addend";       return R; }
    if (!R.FnvRol1 || !R.FnvRol2) { R.Reject = "missing FNV rotates"; return R; }
    if (R.Hash.size() < 5) { R.Reject = "hash program too short"; return R; }
    if (!R.BlockRol16) R.BlockRol16 = 2;

    R.Valid = true;
    return R;
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolve the whole FName pipeline and prove it with plaintext.
//
// No candidate is accepted on structure alone. CompIndex 0 has been the name
// "None" in every build so far, which is four bytes of known plaintext — enough
// to pin the keystream by sweep and, in doing so, to confirm that the pool, the
// shard hash, the block decode and the FNV fold were all extracted correctly.
// If any one of them is wrong, no keystream in the image satisfies the
// constraint and the candidate is simply rejected.
// ─────────────────────────────────────────────────────────────────────────────
struct FNamePipelineInfo {
    bool              Valid = false;
    FNameResolverInfo Res;
    uint64_t          KeystreamWindowRva = 0;   // table + base*2, so indexing is idx*2
    uint64_t          EntryZero = 0;
    std::string       Second;                   // a second decoded name, for the log
};

using ReadFn = std::function<bool(uint64_t, void*, size_t)>;

namespace Detail {

inline uint64_t Rotl64R(uint64_t V, int N) {
    N &= 63; return N ? ((V << N) | (V >> (64 - N))) : V;
}
inline uint64_t Rol16x4R(uint64_t V, int N) {
    uint64_t R = 0;
    for (int I = 0; I < 4; ++I) {
        uint16_t W = (uint16_t)(V >> (16 * I));
        W = (uint16_t)((W << N) | (W >> (16 - N)));
        R |= (uint64_t)W << (16 * I);
    }
    return R;
}
inline uint64_t Pshufb8R(uint64_t V, const uint8_t* M) {
    uint8_t S[8], O[8];
    std::memcpy(S, &V, 8);
    for (int I = 0; I < 8; ++I) O[I] = (M[I] & 0x80) ? 0 : S[M[I] & 7];
    uint64_t R = 0; std::memcpy(&R, O, 8); return R;
}

} // namespace Detail

// Resolve one CompIndex with a candidate's constants.
inline uint64_t ResolveEntryWith(const FNameResolverInfo& R, const uint8_t* Mask,
                                 uint64_t ModuleBase, uint32_t Ci, const ReadFn& Read)
{
    uint32_t NameOff  = Ci & 0xFFFFu;
    uint32_t ChunkOff = (Ci >> 8) & 0xFFFF00u;
    uint64_t ChunkAddr = ModuleBase + R.PoolRva + ChunkOff;

    uint64_t Seed = ChunkAddr + R.SeedOff;
    uint32_t H = ArcDecrypt::RunHashProgram(R.Hash, (uint32_t)Seed, (uint32_t)(Seed >> 32));
    uint32_t S = H ^ (H >> 16);

    uint64_t BlockBase = ChunkAddr + R.BlockBase;
    uint64_t Raw1 = 0, Raw2 = 0;
    if (!Read(BlockBase + 32ULL * (S & 7u), &Raw1, 8)) return 0;
    if (!Read(BlockBase + 32ULL * ((S + 1u) & 7u), &Raw2, 8)) return 0;
    if (!Raw1 && !Raw2) return 0;

    uint64_t V13 = Detail::Rol16x4R(Detail::Pshufb8R(Raw1, Mask), R.BlockRol16) ^ R.BlockXor;
    uint64_t V15 = Detail::Rol16x4R(Detail::Pshufb8R(Raw2, Mask), R.BlockRol16) ^ R.BlockXor;

    uint64_t Fv = R.FnvPrime * Detail::Rotl64R(V13, R.FnvRol1) + R.FnvAdd;
    Fv = R.FnvPrime * Detail::Rotl64R(Fv, R.FnvRol2) + R.FnvAdd;

    uint64_t E = V13 + (V15 ^ Fv) + 2ULL * NameOff;
    if (E < 0x10000ULL || E >= 0x800000000000ULL) return 0;
    return E;
}

inline FNamePipelineInfo ResolveFNamePipeline(const SigScanV2::Scanner& Scanner,
                                              const AutoDiscovery::ModuleBounds& Bounds,
                                              uint64_t ModuleBase,
                                              const ReadFn& Read,
                                              uint32_t KeyInitAdd,
                                              int NarrowShift)
{
    FNamePipelineInfo Out;
    auto Cands = FindFnv64Sites(Scanner, Bounds);
    std::printf("[autoresolve] %zu functions carry the FNV-64 prime\n", Cands.size());

    std::unordered_map<std::string, int> Rejects;
    int NExtract = 0, NMask = 0, NEntry = 0, NLen = 0;

    for (uint64_t F : Cands) {
        FNameResolverInfo R = ExtractFNameResolver(Scanner, Bounds, F);
        if (getenv("FROST_AR_DEBUG") && F >= 0x23E000 && F < 0x240000)
            std::printf("[ar-dbg] fn 0x%llX valid=%d reject=%s pool=0x%llX seed=0x%llX "
                        "blk=0x%llX mask=0x%llX xor=0x%llX fnvadd=0x%llX rol=%d/%d ops=%zu\n",
                (unsigned long long)F, (int)R.Valid, R.Reject.c_str(),
                (unsigned long long)R.PoolRva, (unsigned long long)R.SeedOff,
                (unsigned long long)R.BlockBase, (unsigned long long)R.BlockMaskRva,
                (unsigned long long)R.BlockXor, (unsigned long long)R.FnvAdd,
                R.FnvRol1, R.FnvRol2, R.Hash.size());
        if (!R.Valid) { ++Rejects[R.Reject.empty() ? "?" : R.Reject]; continue; }
        ++NExtract;
        if (getenv("FROST_AR_DEBUG"))
            std::printf("[ar-dbg] extracted fn 0x%llX pool=0x%llX seed=0x%llX blk=0x%llX\n",
                (unsigned long long)F, (unsigned long long)R.PoolRva,
                (unsigned long long)R.SeedOff, (unsigned long long)R.BlockBase);

        const uint8_t* Mask = Scanner.GetLocalPtr(R.BlockMaskRva);
        if (!Mask) { ++Rejects["mask unreadable"]; continue; }
        ++NMask;

        uint64_t E0 = ResolveEntryWith(R, Mask, ModuleBase, 0, Read);
        if (!E0) { ++Rejects["CI=0 did not resolve"]; continue; }
        ++NEntry;

        uint16_t Hdr = 0;
        if (!Read(E0, &Hdr, 2) || !Hdr) { ++Rejects["entry header unreadable"]; continue; }
        int Len = (int)((((uint32_t)Hdr >> 6) & 0xFFFFFFC0u) | ((uint32_t)Hdr & 0x3Fu));
        if (Len != 4) { ++Rejects["CI=0 length != 4"]; continue; }
        ++NLen;

        uint8_t Cipher[4] = {};
        if (!Read(E0 + 2, Cipher, 4)) continue;

        // Sweep for the keystream window that turns those four bytes into
        // "None". One position settles it; there is no second solution.
        const char* Want = "None";
        uint32_t K = ((uint32_t)Len + KeyInitAdd);
        // Sweep LIVE memory, not the module cache. The keystream is decrypted
        // in place at load: a static read of the table yields bytes that share
        // not one value with the running one, and most of them never occur in
        // the at-rest form at all.
        uint64_t Lo = Bounds.RDataRva, Hi = Bounds.DataEnd();
        uint64_t FoundWin = 0;
        constexpr size_t Chunk = 1u << 20, Tail = 0x80;
        std::vector<uint8_t> Buf(Chunk + Tail);
        for (uint64_t Off = Lo; Off < Hi && !FoundWin; Off += Chunk) {
            size_t N = (size_t)std::min<uint64_t>(Chunk + Tail, Hi - Off);
            if (N <= Tail) break;
            if (!Read(ModuleBase + Off, Buf.data(), N)) continue;
            for (size_t W = 0; W + Tail <= N; W += 2) {
                bool Ok = true;
                for (int I = 0; I < 4 && Ok; ++I) {
                    uint16_t Ks = 0;
                    std::memcpy(&Ks, Buf.data() + W + (size_t)(((K + (uint32_t)I) & 0x3Fu) * 2), 2);
                    uint8_t Dec = (uint8_t)(Cipher[I] ^ (uint8_t)(Ks >> NarrowShift));
                    if (Dec != (uint8_t)Want[I]) Ok = false;
                }
                if (Ok) { FoundWin = Off + W; break; }
            }
        }
        if (!FoundWin) { ++Rejects["no keystream matched \"None\""]; continue; }

        Out.Res = R;
        Out.KeystreamWindowRva = FoundWin;
        Out.EntryZero = E0;

        // Decode a second, longer name so the log carries a real confirmation
        // rather than a four-byte coincidence.
        uint8_t WinBuf[128] = {};
        if (!Read(ModuleBase + FoundWin, WinBuf, sizeof(WinBuf))) continue;
        const uint8_t* Win = WinBuf;
        for (uint32_t Ci = 1; Ci < 512 && Out.Second.empty(); ++Ci) {
            uint64_t E = ResolveEntryWith(R, Mask, ModuleBase, Ci, Read);
            if (!E) continue;
            uint16_t H2 = 0;
            if (!Read(E, &H2, 2) || !H2) continue;
            int L2 = (int)((((uint32_t)H2 >> 6) & 0xFFFFFFC0u) | ((uint32_t)H2 & 0x3Fu));
            if (L2 < 4 || L2 > 40 || (H2 & 0x800)) continue;
            std::vector<uint8_t> B((size_t)L2);
            if (!Read(E + 2, B.data(), (size_t)L2)) continue;
            uint32_t K2 = (uint32_t)L2 + KeyInitAdd;
            std::string S2;
            bool Clean = true;
            for (int I = 0; I < L2; ++I) {
                uint16_t Ks = 0;
                std::memcpy(&Ks, Win + (size_t)(((K2 + (uint32_t)I) & 0x3Fu) * 2), 2);
                uint8_t C = (uint8_t)(B[(size_t)I] ^ (uint8_t)(Ks >> NarrowShift));
                if (!std::isalnum(C) && C != '_') { Clean = false; break; }
                S2.push_back((char)C);
            }
            if (Clean && S2.size() >= 4) Out.Second = S2;
        }

        // Four bytes of plaintext can be hit by accident, and a wrong
        // KEY_INIT_ADD would still let some window satisfy them. Requiring a
        // second, longer name to decode cleanly closes that off: no single
        // wrong constant survives both.
        if (Out.Second.empty()) {
            std::printf("[autoresolve]   candidate @ 0x%llX matched \"None\" but no second "
                        "name decoded — rejected as coincidence\n",
                (unsigned long long)R.Rva);
            Out.KeystreamWindowRva = 0;
            Out.EntryZero = 0;
            continue;
        }
        Out.Valid = true;

        std::printf("[autoresolve] FName pipeline @ 0x%llX — pool 0x%llX seed +0x%llX "
                    "block +0x%llX, keystream window 0x%llX\n",
            (unsigned long long)R.Rva, (unsigned long long)R.PoolRva,
            (unsigned long long)R.SeedOff, (unsigned long long)R.BlockBase,
            (unsigned long long)FoundWin);
        std::printf("[autoresolve]   %zu-op hash, block mask 0x%llX rol16 %d xor 0x%016llX, "
                    "FNV add 0x%016llX rol %d/%d\n",
            R.Hash.size(), (unsigned long long)R.BlockMaskRva, R.BlockRol16,
            (unsigned long long)R.BlockXor, (unsigned long long)R.FnvAdd,
            R.FnvRol1, R.FnvRol2);
        std::printf("[autoresolve]   CI=0 -> \"None\" ✓%s%s\n",
            Out.Second.empty() ? "" : "  2nd plaintext: ", Out.Second.c_str());
        return Out;
    }

    std::printf("[autoresolve] no FName pipeline candidate decoded CI=0 to \"None\" "
                "(%d extracted, %d with mask, %d resolved CI=0, %d gave length 4)\n",
        NExtract, NMask, NEntry, NLen);
    std::vector<std::pair<std::string, int>> Rk(Rejects.begin(), Rejects.end());
    std::sort(Rk.begin(), Rk.end(), [](const auto& A, const auto& B){ return A.second > B.second; });
    for (size_t I = 0; I < Rk.size() && I < 6; ++I)
        std::printf("[autoresolve]   %6d x %s\n", Rk[I].second, Rk[I].first.c_str());
    return Out;
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
        const std::function<uint64_t(uint64_t, uint32_t)>& ReadSlotDecrypted,
        const std::function<uint32_t(uint64_t)>& PredictIndex,
        int MaxSamples = 400)
{
    SlotScore S;
    for (uint64_t Obj : Objects) {
        if (S.Samples >= MaxSamples) break;

        int Found = -1, Count = 0;
        for (uint32_t I = 0; I < 4; ++I) {
            uint64_t V = ReadSlotDecrypted(Obj, I);
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
