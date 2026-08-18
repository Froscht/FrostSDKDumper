// =============================================================================
// auto_resolve818.h — patch-day extraction for the CL-1341255 pipeline shapes
//
// Written after CL-1341255 replaced primitives rather than moving constants:
// the UObject slot decode became PCLMULQDQ, the chunks_manager lost its vtable
// indirection, and the shard hash went back from SHR-form to ROL-form. The v811
// extractors in auto_resolve.h are written against the older instruction shapes
// and report honest failure here, which is correct but leaves the constants
// compile-time.
//
// The lesson from that is baked into this file: nothing is matched as a fixed
// op list. Both hash chains are COLLECTED as HashOp programs, so a form change
// between ROL and SHR costs nothing, and every extracted value is validated by
// plaintext or by an invariant rather than by looking plausible.
//
// Anchors, none of which Theia has ever moved:
//   FNV-32 prime  0x1000193        both hash chains
//   FNV-64 prime  0x100000001B3    the FName entry fold
//   `and r32, 0xFFFF00`            ChunkOff = (CI >> 8) & 0xFFFF00 — this is
//                                  the sharpest anchor in the whole image:
//                                  4 sites total on CL-1341255, all of them
//                                  the FName resolver family
//   FUObjectItem stride 20         the object-array index computation
//   CI = 0 decodes to "None"       validates the entire FName pipeline
// =============================================================================
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <functional>
#include <algorithm>
#include <unordered_map>
#include <cstdlib>

#include "arc_decrypt.h"
#include "insn_decoder.h"
#include "func_analyzer.h"
#include "sig_scanner_v2.h"
#include "auto_discovery.h"
#include "auto_resolve.h"

namespace AutoResolve818 {

using ArcDecrypt::HashOp;

constexpr uint32_t FNV32_PRIME = 0x01000193u;
constexpr uint64_t FNV64_PRIME = 0x100000001B3ULL;

// ─────────────────────────────────────────────────────────────────────────────
// Byte-level helpers for the forms the Zydis wrapper folds into INSN_UNKNOWN.
// ─────────────────────────────────────────────────────────────────────────────
namespace Detail {

// `xor r32, imm8` — 83 /6 ib, optionally REX-prefixed.
inline bool ReadXorImm8(const SigScanV2::Scanner& Scanner, uint64_t Rva, uint32_t& Out) {
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    int I = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
    if (P[I] != 0x83) return false;
    if (((P[I + 1] >> 3) & 7) != 6) return false;
    Out = P[I + 2];
    return true;
}

// `add r/m32, r32` (01 /r) or `add r32, r/m32` (03 /r) in register form. This
// is how the seed's high dword enters the hash, and the decoder has no type
// for it — only ADD_IMM.
inline bool IsAddRegReg(const SigScanV2::Scanner& Scanner, uint64_t Rva) {
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    int I = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
    if (P[I] != 0x01 && P[I] != 0x03) return false;
    return (P[I + 1] & 0xC0) == 0xC0;              // mod == 11, register form
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

// Displacement of any ModR/M memory operand, given the offset of the ModR/M
// byte inside the instruction. Returns false for the register form.
inline bool MemDisp(const uint8_t* P, int M, uint64_t& Out) {
    uint8_t Mod = (P[M] >> 6) & 3;
    uint8_t Rm  = P[M] & 7;
    if (Mod == 3) return false;
    int D = M + 1;
    if (Rm == 4) ++D;                              // SIB
    if (Mod == 0) {
        if (Rm == 5) return false;                 // rip-relative, not what we want
        Out = 0; return true;
    }
    if (Mod == 1) { Out = P[D]; return true; }
    uint32_t V = 0; std::memcpy(&V, P + D, 4); Out = V; return true;
}

// `movdqa xmm, [base(+index)+disp]` — displacement only.
inline bool ReadMovdqaDisp(const SigScanV2::Scanner& Scanner, uint64_t Rva,
                           uint8_t Len, uint64_t& Out)
{
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P || Len < 4) return false;
    int I = 0;
    while (I < Len && (P[I] == 0x66 || P[I] == 0xF3 || (P[I] & 0xF0) == 0x40)) ++I;
    if (I + 2 >= Len || P[I] != 0x0F || P[I + 1] != 0x6F) return false;
    return MemDisp(P, I + 2, Out);
}

// `xor r, [reg+disp]` — 33 /r. Returns the displacement.
inline bool ReadXorMemDisp(const SigScanV2::Scanner& Scanner, uint64_t Rva,
                           uint8_t Len, uint64_t& Out)
{
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P || Len < 2) return false;
    int I = 0;
    while (I < Len && (P[I] & 0xF0) == 0x40) ++I;
    if (I >= Len || P[I] != 0x33) return false;
    return MemDisp(P, I + 1, Out);
}

// `mov r32, imm32` — B8+r id, optionally REX-prefixed.
inline bool ReadMovImm32(const SigScanV2::Scanner& Scanner, uint64_t Rva, uint32_t& Out) {
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    int I = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
    if (P[I] < 0xB8 || P[I] > 0xBF) return false;
    std::memcpy(&Out, P + I + 1, 4);
    return true;
}

// `movabs r64, imm64` — REX.W B8+r io. The decoder does not reliably report
// the destination register for this form, and the destination is exactly what
// tells the two slot-decoder polynomials apart, so read it off the opcode.
inline bool ReadMovabs(const SigScanV2::Scanner& Scanner, uint64_t Rva,
                       uint8_t& Reg, uint64_t& Imm)
{
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    if ((P[0] & 0xF8) != 0x48) return false;          // REX.W, optional .B/.R
    if (P[1] < 0xB8 || P[1] > 0xBF) return false;
    Reg = (uint8_t)((P[1] - 0xB8) | ((P[0] & 1) ? 8 : 0));
    std::memcpy(&Imm, P + 2, 8);
    return true;
}

// `call rel32` — E8 cd. The decoder's INSN_CALL_RIP covers the indirect
// `call [rip+disp]` form, not this one, and the slot decoder is reached by a
// direct relative call. Missing it cost the whole GetFName extraction while
// every other field came out correct, which is the failure mode worth naming:
// a shape check that is *almost* right returns a fully populated record with
// one zero in it.
inline bool ReadCallRel32(const SigScanV2::Scanner& Scanner, uint64_t Rva,
                          uint8_t Len, uint64_t& Target)
{
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P || P[0] != 0xE8 || Len < 5) return false;
    int32_t Rel = 0;
    std::memcpy(&Rel, P + 1, 4);
    Target = Rva + 5 + (int64_t)Rel;
    return true;
}

// `bswap r32/r64` — 0F C8+r.
inline bool IsBswap(const SigScanV2::Scanner& Scanner, uint64_t Rva) {
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P) return false;
    int I = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
    return P[I] == 0x0F && P[I + 1] >= 0xC8 && P[I + 1] <= 0xCF;
}

// `lea r32/r64, [base + disp]` with a plain (non-rip) base.
inline bool ReadLeaRegDisp(const SigScanV2::Scanner& Scanner, uint64_t Rva,
                           uint8_t Len, uint64_t& Out)
{
    const uint8_t* P = Scanner.GetLocalPtr(Rva);
    if (!P || Len < 3) return false;
    int I = 0;
    while (I < Len && (P[I] & 0xF0) == 0x40) ++I;
    if (I >= Len || P[I] != 0x8D) return false;
    return MemDisp(P, I + 1, Out);
}

} // namespace Detail

// ─────────────────────────────────────────────────────────────────────────────
// Collect an FNV-32 chain as a HashOp program.
//
// This is the piece that makes the file survive the next shape change. The
// chain has been ROL-form (CL-1325322), SHR-form (build 24653108) and ROL-form
// again (CL-1341255); recording the ops as they appear costs nothing and
// removes the whole class of "the extractor expected a rotate" failures.
//
// Stops at the fold `S = H ^ (H >> 16)`. Running past it is the mistake that
// cost a debugging cycle on build 24653108: the collector swallowed the FNV-64
// rotates as hash steps, every constant still came out correct, and the only
// symptom was CI=0 resolving to garbage — which reads as a bad pool address.
// ─────────────────────────────────────────────────────────────────────────────
inline bool CollectHashProgram(const SigScanV2::Scanner& Scanner,
                               const std::vector<DecodedInsn>& Insns,
                               size_t Begin, size_t End,
                               std::vector<HashOp>& Out,
                               size_t* FoldIdx = nullptr)
{
    Out.clear();
    bool Started = false;                    // seen the first op on the seed
    int  Imuls   = 0;

    for (size_t I = Begin; I < End && I < Insns.size(); ++I) {
        const auto& In = Insns[I];

        // The fold ends the chain: `shr rX, 16` with an `xor rX, rY` close by.
        if (In.type == INSN_SHR && In.hasImm8 && In.imm8 == 16) {
            for (size_t K = I + 1; K < End && K <= I + 3; ++K) {
                if (Insns[K].type == INSN_XOR_REG) {
                    if (FoldIdx) *FoldIdx = K;
                    return Imuls >= 3 && !Out.empty();
                }
            }
        }

        if (In.type == INSN_ROL && In.hasImm8) {
            // A REX.W rotate is a 64-bit rotate and never part of the 32-bit
            // chain; the decoder's REX.W flag is unreliable, so gate on having
            // already multiplied instead — the final FName rotate always comes
            // after the fold and is therefore out of range anyway.
            Out.push_back({ Started ? HashOp::Rol : HashOp::SeedRol, In.imm8, 0 });
            Started = true;
            continue;
        }
        if (In.type == INSN_SHR && In.hasImm8) {
            // `shr rX, 0x20` in the prologue splits the seed and is not a step.
            if (In.imm8 == 32) continue;
            Out.push_back({ Started ? HashOp::Shr : HashOp::SeedShr, In.imm8, 0 });
            Started = true;
            continue;
        }
        if (In.type == INSN_IMUL && In.hasImm32 && In.imm32 == FNV32_PRIME) {
            Out.push_back({ HashOp::Imul, In.imm32, 0 });
            Started = true;
            ++Imuls;
            continue;
        }
        if (In.type == INSN_ADD_IMM && In.hasImm32 && Started) {
            Out.push_back({ HashOp::Add, In.imm32, 0 });
            continue;
        }
        if (Started && Detail::IsAddRegReg(Scanner, In.rva)) {
            Out.push_back({ HashOp::AddHi, 0, 0 });
            continue;
        }
        // Anything that leaves the chain entirely.
        if (In.type == INSN_RET || In.type == INSN_CALL_RIP) break;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// UObject::GetFName
//
// Shape on CL-1341255:
//   lea    rax, [rcx + SeedOff]
//   mov    rdx, rax ; shr rdx, 0x20            <- Hi
//   <FNV-32 chain on eax, Hi folded in by `add eax, edx`>
//   mov    edx, eax ; shr edx, 0x10 ; xor edx, eax
//   and    edx, 3 ; xor edx, 2 ; shl edx, 5
//   movdqa xmm0, [rcx + rdx + SlotBase]
//   movdqa [rsp+X], xmm0 ; lea rcx, [rsp+X]
//   movabs rdx, K2 ; movabs r8, K1 ; call <shared clmul decoder>
//   movq   rax, xmm0 ; rol rax, 0x20
//
// The three roles (Name / Class / Outer) share the chain and differ only in
// the slot adjustment, so they must be classified BEFORE consensus is taken.
// Averaging over all of them yields a slot xor of 0, because only the Name
// copies carry one.
// ─────────────────────────────────────────────────────────────────────────────
struct GetFNameInfo {
    enum class Role { Unknown, Name, Class, Outer };

    bool     Valid    = false;
    uint64_t Rva      = 0;
    Role     Which    = Role::Unknown;
    const char* Reject = nullptr;

    uint64_t SeedOff  = 0;
    std::vector<HashOp> Hash;

    uint32_t SlotXor  = 0;
    uint64_t SlotBase = 0;
    uint64_t SlotStride = 0;

    uint64_t DecoderRva = 0;
    uint64_t ClmulK1  = 0;          // the one passed in r8  (first product)
    uint64_t ClmulK2  = 0;          // the one passed in rdx (second product)
    int      FinalRol = 0;

    int Copies = 0;
};

inline const char* RoleName(GetFNameInfo::Role R) {
    switch (R) {
        case GetFNameInfo::Role::Name:  return "Name";
        case GetFNameInfo::Role::Class: return "Class";
        case GetFNameInfo::Role::Outer: return "Outer";
        default:                        return "?";
    }
}

inline GetFNameInfo ExtractGetFName(const SigScanV2::Scanner& Scanner, uint64_t FuncRva)
{
    GetFNameInfo Info;
    Info.Rva = FuncRva;

    auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, FuncRva, 256);
    if (Insns.size() < 16) { Info.Reject = "too short to decode"; return Info; }

    size_t End = Insns.size();
    for (size_t I = 0; I < Insns.size(); ++I)
        if (Insns[I].type == INSN_RET) { End = I + 1; break; }
    if (End == Insns.size()) { Info.Reject = "no ret within window"; return Info; }

    // The seed offset comes off the leading `lea rax, [rcx + off]`.
    for (size_t I = 0; I < End && I < 6; ++I) {
        if (Insns[I].type != INSN_LEA || Insns[I].hasRipRel) continue;
        uint64_t D = 0;
        if (Detail::ReadLeaRegDisp(Scanner, Insns[I].rva, Insns[I].length, D)) {
            Info.SeedOff = D;
            break;
        }
    }

    size_t Fold = 0;
    if (!CollectHashProgram(Scanner, Insns, 0, End, Info.Hash, &Fold)) {
        Info.Reject = "no FNV-32 chain ending in a 16-bit fold";
        return Info;
    }

    bool SawAnd3 = false;
    for (size_t I = Fold; I < End; ++I) {
        const auto& In = Insns[I];

        if (In.type == INSN_AND_IMM && In.imm32 == 3u) {
            SawAnd3 = true;
            uint32_t Xv = 0;
            bool HasXor = false;
            for (size_t K = I + 1; K < End && K <= I + 3; ++K)
                if (Detail::ReadXorImm8(Scanner, Insns[K].rva, Xv)) { HasXor = true; break; }
            bool PlusOne = false;
            for (size_t K = (I >= 3 ? I - 3 : 0); K < I; ++K)
                if (Detail::IsPlusOne(Scanner, Insns[K].rva)) { PlusOne = true; break; }

            if (HasXor)       { Info.SlotXor = Xv; Info.Which = GetFNameInfo::Role::Name;  }
            else if (PlusOne) {                    Info.Which = GetFNameInfo::Role::Outer; }
            else              {                    Info.Which = GetFNameInfo::Role::Class; }
            continue;
        }
        if (In.type == INSN_SHL && In.hasImm8 && SawAnd3 && !Info.SlotStride)
            Info.SlotStride = 1ULL << In.imm8;
        if (In.type == INSN_MOVDQA && !In.hasRipRel && SawAnd3 && !Info.SlotBase)
            Detail::ReadMovdqaDisp(Scanner, In.rva, In.length, Info.SlotBase);

        // The two polynomials are the last two movabs before the call, and the
        // destination register tells them apart: r8 feeds the first product,
        // rdx the second. Keying on order alone would swap them if the
        // compiler ever reorders the loads.
        // Evaluate the byte form FIRST and unconditionally. `||` short-circuits,
        // and the decoder already reports a relative call as INSN_CALL_RIP with
        // hasRipRel clear — so putting the type test first silently skipped the
        // only path that can produce a target, leaving a fully populated record
        // with one zero in it.
        uint64_t CallTarget = 0;
        bool ByteCall = Detail::ReadCallRel32(Scanner, In.rva, In.length, CallTarget);
        if (ByteCall || In.type == INSN_CALL_RIP) {
            Info.DecoderRva = CallTarget ? CallTarget : In.ResolveRipRVA();
            for (size_t K = (I >= 8 ? I - 8 : 0); K < I; ++K) {
                uint8_t Reg = 0; uint64_t Imm = 0;
                if (!Detail::ReadMovabs(Scanner, Insns[K].rva, Reg, Imm)) continue;
                if (Reg == 8) Info.ClmulK1 = Imm;      // r8  — the first product
                if (Reg == 2) Info.ClmulK2 = Imm;      // rdx — the second
            }
            continue;
        }
        if (In.type == INSN_ROL && In.hasImm8 && Info.DecoderRva)
            Info.FinalRol = In.imm8;
    }

    if (!Info.SeedOff)     { Info.Reject = "no seed lea";                     return Info; }
    if (!SawAnd3)          { Info.Reject = "no `and r32, 3` slot select";     return Info; }
    if (!Info.SlotStride)  { Info.Reject = "no slot stride";                  return Info; }
    if (!Info.SlotBase)    { Info.Reject = "no slot base displacement";       return Info; }
    if (!Info.DecoderRva)  { Info.Reject = "no call to the slot decoder";     return Info; }
    if (!Info.ClmulK1 || !Info.ClmulK2)
                           { Info.Reject = "decoder polynomials not both found"; return Info; }
    if (!Info.FinalRol)    { Info.Reject = "no final rotate";                 return Info; }

    Info.Valid = true;
    return Info;
}

inline GetFNameInfo FindGetFName(const SigScanV2::Scanner& Scanner,
                                 const AutoDiscovery::ModuleBounds& Bounds)
{
    GetFNameInfo Best;
    auto Sites  = AutoResolve::FindFnvImulSites(Scanner, Bounds);
    auto Groups = AutoResolve::GroupFnvSitesByFunction(Sites);
    std::printf("[ar818] %zu FNV-prime multiplies across %zu functions\n",
                Sites.size(), Groups.size());

    // Prefilter before decoding. 11583 functions carry 4+ FNV multiplies on
    // this build, and decoding all of them is what makes the pass unaffordable;
    // a slot accessor always reaches a `call` within its first 256 bytes and
    // always contains an `and r32,3`. Do NOT cap the candidate list instead:
    // on build 24653108 the real GetFName sat past a 2000-entry cap, which
    // produced "0 Name copies" and looked like a missing feature.
    auto LooksLikeAccessor = [&](uint64_t Func) {
        for (uint64_t K = 0; K + 3 < 256; ++K) {
            const uint8_t* P = Scanner.GetLocalPtr(Func + K);
            if (!P) return false;
            if (P[0] == 0xC3) return false;                     // ret — too early
            if (P[0] == 0x83 && (P[1] & 0xC0) == 0xC0 &&
                ((P[1] >> 3) & 7) == 4 && P[2] == 3) return true;  // and r32, 3
        }
        return false;
    };

    std::vector<GetFNameInfo> Names, Classes, Outers;
    std::unordered_map<std::string, int> Rejects;
    int Tried = 0;
    // FROST_AR818_DEBUG=<hex func rva> prints why one specific candidate was
    // rejected. Reject histograms tell you the shape of the failure; this
    // tells you whether the function you care about is even reaching the
    // extractor, which is a different question and usually the one that matters.
    uint64_t Dbg = 0;
    if (const char* E = getenv("FROST_AR818_DEBUG")) Dbg = strtoull(E, nullptr, 16);
    if (Dbg) {
        bool Seen = false;
        for (const auto& G : Groups) if (G.first == Dbg) { Seen = true; break; }
        std::printf("[ar818]   DEBUG target 0x%llX %s in the FNV group list\n",
            (unsigned long long)Dbg, Seen ? "IS" : "is NOT");
    }
    for (const auto& G : Groups) {
        if (G.second < 3) {
            if (Dbg) std::printf("[ar818]   DEBUG stopped at count %d before reaching "
                                 "the target\n", G.second);
            break;
        }
        if (!LooksLikeAccessor(G.first)) {
            if (G.first == Dbg)
                std::printf("[ar818]   DEBUG 0x%llX filtered out by the accessor prefilter\n",
                    (unsigned long long)Dbg);
            continue;
        }
        ++Tried;
        GetFNameInfo I = ExtractGetFName(Scanner, G.first);
        if (Dbg && G.first == Dbg)
            std::printf("[ar818]   DEBUG 0x%llX: %s (seed 0x%llX, hash %zu ops, "
                        "xor %u, base 0x%llX, stride 0x%llX, dec 0x%llX, "
                        "K1 0x%llX, K2 0x%llX, rol %d)\n",
                (unsigned long long)G.first, I.Valid ? "VALID" : (I.Reject ? I.Reject : "?"),
                (unsigned long long)I.SeedOff, I.Hash.size(), I.SlotXor,
                (unsigned long long)I.SlotBase, (unsigned long long)I.SlotStride,
                (unsigned long long)I.DecoderRva, (unsigned long long)I.ClmulK1,
                (unsigned long long)I.ClmulK2, I.FinalRol);
        if (!I.Valid) { ++Rejects[I.Reject ? I.Reject : "?"]; continue; }
        switch (I.Which) {
            case GetFNameInfo::Role::Name:  Names.push_back(I);   break;
            case GetFNameInfo::Role::Class: Classes.push_back(I); break;
            case GetFNameInfo::Role::Outer: Outers.push_back(I);  break;
            default: break;
        }
    }
    std::printf("[ar818] %d accessor-shaped functions decoded: %zu Name, %zu Class, %zu Outer\n",
                Tried, Names.size(), Classes.size(), Outers.size());
    if (Names.empty()) {
        std::vector<std::pair<std::string, int>> R(Rejects.begin(), Rejects.end());
        std::sort(R.begin(), R.end(),
                  [](const auto& A, const auto& B) { return A.second > B.second; });
        for (size_t I = 0; I < R.size() && I < 6; ++I)
            std::printf("[ar818]   %6d x %s\n", R[I].second, R[I].first.c_str());
        return Best;
    }

    // Theia's clones are free redundancy: take the per-field majority rather
    // than trusting whichever copy is found first. The RVA is deliberately not
    // compared — which clone wins carries no information.
    auto Majority64 = [](const std::vector<GetFNameInfo>& V,
                         uint64_t GetFNameInfo::* M) -> uint64_t {
        std::unordered_map<uint64_t, int> C;
        for (const auto& I : V) ++C[I.*M];
        uint64_t B = 0; int N = -1;
        for (const auto& [K, Cnt] : C) if (Cnt > N) { N = Cnt; B = K; }
        return B;
    };

    Best = Names.front();
    Best.SeedOff    = Majority64(Names, &GetFNameInfo::SeedOff);
    Best.SlotBase   = Majority64(Names, &GetFNameInfo::SlotBase);
    Best.SlotStride = Majority64(Names, &GetFNameInfo::SlotStride);
    Best.ClmulK1    = Majority64(Names, &GetFNameInfo::ClmulK1);
    Best.ClmulK2    = Majority64(Names, &GetFNameInfo::ClmulK2);
    {
        std::unordered_map<uint32_t, int> Cx;
        for (const auto& I : Names) ++Cx[I.SlotXor];
        int N = -1; for (const auto& [K, C] : Cx) if (C > N) { N = C; Best.SlotXor = K; }
        std::unordered_map<int, int> Cr;
        for (const auto& I : Names) ++Cr[I.FinalRol];
        N = -1; for (const auto& [K, C] : Cr) if (C > N) { N = C; Best.FinalRol = K; }
    }
    Best.Copies = (int)Names.size();
    Best.Valid  = true;

    // The Class and Outer adjustments come out of the role split for free —
    // they are the slot index relative to the raw hash, and the Name role is
    // the only one carrying an explicit xor.
    return Best;
}

// ─────────────────────────────────────────────────────────────────────────────
// The FName resolver.
//
// Anchored on `and r32, 0xFFFF00`, the ChunkOff computation. That mask occurs
// exactly four times in the whole CL-1341255 image and all four are this
// family — far sharper than any FNV-prime scan, which yields five figures.
// ─────────────────────────────────────────────────────────────────────────────
struct FNamePipelineInfo {
    bool     Valid = false;
    uint64_t Rva   = 0;
    const char* Reject = nullptr;

    uint64_t PoolRva     = 0;
    uint64_t SeedOff     = 0;
    uint64_t BlockBase   = 0;
    uint64_t BlockStride = 32;
    std::vector<HashOp> Hash;

    int      BlockRol64  = 0;
    int      BlockRol32  = 0;
    uint64_t BlockXorRva = 0;
    uint64_t BlockXor    = 0;

    uint64_t FnvPrime = FNV64_PRIME;
    uint64_t FnvAdd   = 0;
    int      FnvRol1  = 0;
    int      FnvRol2  = 0;

    uint64_t KeystreamRva    = 0;   // table base
    uint64_t KeystreamWindow = 0;   // table base + the +0xA0-style index bias
    uint32_t KeyInitAdd      = 0;

    uint16_t HdrLenMask = 0;
    uint16_t HdrWideBit = 0;
};

inline std::vector<uint64_t> FindChunkOffSites(const SigScanV2::Scanner& Scanner,
                                               const AutoDiscovery::ModuleBounds& Bounds)
{
    std::vector<uint64_t> Out;
    if (!Bounds.Valid || !Bounds.TextSize) return Out;
    const uint8_t Imm[4] = { 0x00, 0xFF, 0xFF, 0x00 };
    for (uint64_t R = Bounds.TextRva; R + 8 <= Bounds.TextEnd(); ++R) {
        const uint8_t* P = Scanner.GetLocalPtr(R);
        if (!P) continue;
        if (P[0] == 0x25 && std::memcmp(P + 1, Imm, 4) == 0) { Out.push_back(R); continue; }
        if (P[0] == 0x81 && P[1] >= 0xE0 && P[1] <= 0xE7 &&
            std::memcmp(P + 2, Imm, 4) == 0) { Out.push_back(R); continue; }
        if (P[0] == 0x41 && P[1] == 0x81 && P[2] >= 0xE0 && P[2] <= 0xE7 &&
            std::memcmp(P + 3, Imm, 4) == 0) { Out.push_back(R); continue; }
    }
    return Out;
}

inline FNamePipelineInfo ExtractFNameResolver(const SigScanV2::Scanner& Scanner,
                                              const AutoDiscovery::ModuleBounds& Bounds,
                                              uint64_t AndSite)
{
    FNamePipelineInfo Info;
    Info.Rva = AndSite;

    // Decode from the AND forward: the whole pipeline follows it. The block
    // XOR constant is the one exception — it is loaded into an xmm register in
    // the function prologue, so the register map is built from the function
    // start.
    uint64_t FuncRva = FuncAnalyze::FindFunctionStart(Scanner, AndSite);
    auto Pre = FuncAnalyze::DecodeWindowAt(Scanner, FuncRva,
                                           (size_t)(AndSite - FuncRva) + 16);
    uint64_t XmmConst[16] = {};
    uint64_t GprLea[16]   = {};
    auto TrackPrologue = [&](const std::vector<DecodedInsn>& V) {
        for (const auto& In : V) {
            if (In.type == INSN_MOVDQA && In.hasRipRel && In.reg1 < 16)
                XmmConst[In.reg1] = In.ResolveRipRVA();
            if (In.type == INSN_LEA && In.hasRipRel && In.reg1 < 16)
                GprLea[In.reg1] = In.ResolveRipRVA();
        }
    };
    TrackPrologue(Pre);

    auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, AndSite, 0x400);
    if (Insns.size() < 30) { Info.Reject = "window too short"; return Info; }

    // Pool: the first rip-relative lea into .data after the mask.
    size_t PoolIdx = 0;
    for (size_t I = 0; I < Insns.size(); ++I) {
        const auto& In = Insns[I];
        if (In.type != INSN_LEA || !In.hasRipRel) continue;
        uint64_t T = In.ResolveRipRVA();
        if (T < Bounds.DataRva || T >= Bounds.DataEnd()) continue;
        Info.PoolRva = T;
        if (In.reg1 < 16) GprLea[In.reg1] = T;
        PoolIdx = I;
        break;
    }
    if (!Info.PoolRva) { Info.Reject = "no .data pool lea"; return Info; }

    // Seed offset: the `add rdx, imm32` that turns ChunkAddr into SeedAddr.
    for (size_t I = PoolIdx; I < Insns.size() && I < PoolIdx + 12; ++I) {
        if (Insns[I].type == INSN_ADD_IMM && Insns[I].hasImm32 &&
            Insns[I].imm32 >= 0x100 && Insns[I].imm32 < 0x40000) {
            Info.SeedOff = Insns[I].imm32;
            break;
        }
    }
    if (!Info.SeedOff) { Info.Reject = "no seed offset"; return Info; }

    size_t Fold = 0;
    if (!CollectHashProgram(Scanner, Insns, PoolIdx, Insns.size(), Info.Hash, &Fold)) {
        Info.Reject = "no FNV-32 chain ending in a 16-bit fold";
        return Info;
    }

    // Blocks: `movdqa xmm, [idx + chunk + BlockBase]`, then the decode chain.
    // The `shl r32, N` right after `and r32, 7` gives the stride.
    for (size_t I = Fold; I < Insns.size(); ++I) {
        const auto& In = Insns[I];
        if (In.type == INSN_SHL && In.hasImm8 && !Info.BlockBase)
            Info.BlockStride = 1ULL << In.imm8;
        if (In.type == INSN_MOVDQA && !In.hasRipRel && !Info.BlockBase) {
            uint64_t D = 0;
            if (Detail::ReadMovdqaDisp(Scanner, In.rva, In.length, D) && D >= 0x100) {
                Info.BlockBase = D;
                // The decode chain runs from here to the movq that takes it
                // back into a GPR.
                for (size_t K = I + 1; K < Insns.size() && K < I + 24; ++K) {
                    const auto& B = Insns[K];
                    if (B.type == INSN_PSLLQ && B.hasImm8 && !Info.BlockRol64)
                        Info.BlockRol64 = B.imm8;
                    if (B.type == INSN_PSLLD && B.hasImm8 && !Info.BlockRol32)
                        Info.BlockRol32 = B.imm8;
                    if (B.type == INSN_PXOR && !Info.BlockXorRva) {
                        Info.BlockXorRva = B.hasRipRel ? B.ResolveRipRVA()
                                         : (B.reg2 < 16 ? XmmConst[B.reg2] : 0);
                    }
                    if (B.type == INSN_MOVQ) break;
                }
                break;
            }
        }
    }
    if (!Info.BlockBase)   { Info.Reject = "no block base";        return Info; }
    if (!Info.BlockRol64)  { Info.Reject = "no block ROL64";       return Info; }
    if (!Info.BlockXorRva) { Info.Reject = "no block xor constant"; return Info; }

    const uint8_t* Xp = Scanner.GetLocalPtr(Info.BlockXorRva);
    if (!Xp) { Info.Reject = "block xor constant unreadable"; return Info; }
    std::memcpy(&Info.BlockXor, Xp, 8);

    // FNV-64 fold. The immediate is B3 01 00 00 00 01 00 00 — the reversed
    // byte order finds zero sites and looks like the anchor does not exist.
    for (size_t I = Fold; I < Insns.size(); ++I) {
        if (Insns[I].imm64 == FNV64_PRIME) {
            for (size_t K = I; K < Insns.size() && K < I + 24; ++K) {
                const auto& B = Insns[K];
                if (B.type == INSN_ROL && B.hasImm8) {
                    if (!Info.FnvRol1)      Info.FnvRol1 = B.imm8;
                    else if (!Info.FnvRol2) Info.FnvRol2 = B.imm8;
                }
                if (B.imm64 && B.imm64 != FNV64_PRIME && !Info.FnvAdd)
                    Info.FnvAdd = B.imm64;
            }
            break;
        }
        // The rotate can precede the prime load; scan a little behind too.
        if (Insns[I].type == INSN_ROL && Insns[I].hasImm8 && !Info.FnvRol1) {
            for (size_t K = I; K < Insns.size() && K < I + 4; ++K)
                if (Insns[K].imm64 == FNV64_PRIME) { Info.FnvRol1 = Insns[I].imm8; break; }
        }
    }
    if (!Info.FnvRol1 || !Info.FnvRol2 || !Info.FnvAdd) {
        Info.Reject = "incomplete FNV-64 fold";
        return Info;
    }

    // Header masks and the keystream. The string decrypt indexes the table as
    // `[base + idx*2 + WindowOff]`, and the key seed is a `lea r32, [len + K]`.
    for (size_t I = Fold; I < Insns.size(); ++I) {
        const auto& In = Insns[I];
        if (In.type == INSN_AND_IMM && In.hasImm32 && !Info.HdrLenMask &&
            In.imm32 >= 0x3F && In.imm32 <= 0xFFFF)
            Info.HdrLenMask = (uint16_t)In.imm32;
        if (In.type == INSN_LEA && !In.hasRipRel && !Info.KeyInitAdd) {
            uint64_t D = 0;
            if (Detail::ReadLeaRegDisp(Scanner, In.rva, In.length, D) &&
                D >= 0x1000 && D <= 0xFFFF)
                Info.KeyInitAdd = (uint32_t)D;
        }
    }

    // The keystream base is whichever register the decrypt loop indexes; take
    // the rip-lea targets seen so far that are NOT the pool and sit in .data or
    // .rdata, and let the plaintext sweep settle the window offset.
    for (int R = 0; R < 16; ++R) {
        uint64_t T = GprLea[R];
        if (!T || T == Info.PoolRva) continue;
        if (T < Bounds.RDataRva || T >= Bounds.DataEnd()) continue;
        Info.KeystreamRva = T;
    }

    Info.HdrWideBit = 0x8000u;   // confirmed by the plaintext self-test below
    if (!Info.HdrLenMask) Info.HdrLenMask = 0x03FFu;
    Info.Valid = true;
    return Info;
}

// ─────────────────────────────────────────────────────────────────────────────
// Adopt a candidate into the sheet and decide it by plaintext.
//
// Nothing here is accepted because it looks right. The pipeline is installed,
// CI=0 must decode to "None", and a second, longer name must decode cleanly —
// no single wrong constant survives both. The keystream window is swept rather
// than extracted, because only its value mod 64 matters and a sweep absorbs
// that far more reliably than reading an index bias out of a SIB byte.
// ─────────────────────────────────────────────────────────────────────────────
struct FNameAdoption {
    bool     Valid = false;
    uint64_t WindowRva = 0;
};

inline FNameAdoption AdoptFNamePipeline(const AutoDiscovery::ModuleBounds& Bounds,
                                        const FNamePipelineInfo& P,
                                        const std::function<bool()>& TryPipeline)
{
    FNameAdoption Out;
    auto& Sh = ArcDecrypt::g_Sheet;
    const ArcDecrypt::LiveSheet Saved = Sh;

    Sh.Pool818Rva       = P.PoolRva;
    Sh.Seed818Off       = P.SeedOff;
    Sh.Block818Base     = P.BlockBase;
    Sh.Block818Stride   = P.BlockStride;
    Sh.Shard818Program  = P.Hash;
    Sh.Block818Rol64    = P.BlockRol64;
    Sh.Block818Rol32    = P.BlockRol32 ? P.BlockRol32 : Saved.Block818Rol32;
    Sh.BlockXor818      = P.BlockXor;
    Sh.Fnv818Prime      = P.FnvPrime;
    Sh.Fnv818Add        = P.FnvAdd;
    Sh.Fnv818Rol1       = P.FnvRol1;
    Sh.Fnv818Rol2       = P.FnvRol2;
    Sh.Hdr818LenMask    = P.HdrLenMask;
    Sh.Hdr818WideBit    = P.HdrWideBit;
    if (P.KeyInitAdd) Sh.KeyInitAdd818 = P.KeyInitAdd;

    // Sweep the keystream window rather than extracting it. Only its value
    // mod 64 matters, a sweep absorbs that far more reliably than reading an
    // index bias out of a SIB byte, and the plaintext test decides. The table
    // MUST be read live: the module image holds an at-rest form that shares no
    // value with the running table, so sweeping the cache finds nothing and
    // looks like the sweep itself is broken.
    std::vector<uint64_t> Cands;
    if (P.KeystreamRva)
        for (uint64_t B = 0; B <= 0x200; B += 0x10) Cands.push_back(P.KeystreamRva + B);
    Cands.push_back(Saved.Keystream818Rva);

    for (uint64_t W : Cands) {
        if (W < Bounds.RDataRva || W + 128 >= Bounds.DataEnd()) continue;
        Sh.Keystream818Rva = W;
        if (!TryPipeline()) continue;
        Out.Valid     = true;
        Out.WindowRva = W;
        return Out;
    }

    Sh = Saved;
    return Out;
}

// ─────────────────────────────────────────────────────────────────────────────
// chunks_manager.
//
// The 20-byte FUObjectItem stride forces a distinctive index computation
// (`lea r,[r+r*4]` with index == base, then `shl r32, 2`), and the containing
// function carries the whole decode inline. Reading it beats assuming it: on
// CL-1341255 the vote named the global correctly while the compiled v811
// decode rejected it, because the SHAPE had changed and only the shape check
// could tell.
// ─────────────────────────────────────────────────────────────────────────────
struct ChunkMgrInfo {
    bool     Valid = false;
    uint64_t GlobalRva = 0;
    uint64_t FuncRva   = 0;
    uint64_t PshufbRva = 0;
    uint8_t  Pshufb[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    int      Rol64 = 0;
    int      Rol32 = 0;
    uint64_t NumOff = 0;
    uint32_t NumXor = 0;
    uint64_t ArrOff = 0;
    uint64_t ArrXor = 0;
    int      Votes = 0;
};

inline bool ExtractChunkMgrFromFunc(const SigScanV2::Scanner& Scanner,
                                    const AutoDiscovery::ModuleBounds& Bounds,
                                    uint64_t FuncRva, ChunkMgrInfo& Out)
{
    auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, FuncRva, 0x300);
    if (Insns.size() < 12) return false;

    size_t GlobalIdx = 0;
    for (size_t I = 0; I < Insns.size(); ++I) {
        const auto& In = Insns[I];
        if (In.type != INSN_MOVDQA || !In.hasRipRel) continue;
        uint64_t T = In.ResolveRipRVA();
        if (T < Bounds.DataRva || T >= Bounds.DataEnd()) continue;
        Out.GlobalRva = T;
        GlobalIdx = I;
        break;
    }
    if (!Out.GlobalRva) return false;

    for (size_t I = GlobalIdx; I < Insns.size() && I < GlobalIdx + 24; ++I) {
        const auto& In = Insns[I];
        if (In.type == INSN_PSLLQ && In.hasImm8 && !Out.Rol64) Out.Rol64 = In.imm8;
        if (In.type == INSN_PSLLD && In.hasImm8 && !Out.Rol32) Out.Rol32 = In.imm8;
        if (In.type == INSN_PSHUFB && In.hasRipRel && !Out.PshufbRva) {
            Out.PshufbRva = In.ResolveRipRVA();
            const uint8_t* M = Scanner.GetLocalPtr(Out.PshufbRva);
            if (M) std::memcpy(Out.Pshufb, M, 8);
        }
        if (In.type == INSN_MOVQ) break;
    }
    if (!Out.Rol64 || !Out.Rol32) return false;

    // NumElements and the chunk array are both `mov r, imm ; xor r, [mgr+off] ;
    // bswap r`. The 64-bit one is the array, the 32-bit one the count.
    for (size_t I = GlobalIdx; I + 2 < Insns.size(); ++I) {
        if (!Detail::IsBswap(Scanner, Insns[I + 2].rva)) continue;
        uint64_t Disp = 0;
        if (!Detail::ReadXorMemDisp(Scanner, Insns[I + 1].rva, Insns[I + 1].length, Disp))
            continue;
        if (Insns[I].imm64 && !Out.ArrXor) {
            Out.ArrXor = Insns[I].imm64;
            Out.ArrOff = Disp;
            continue;
        }
        uint32_t Imm = 0;
        if (!Insns[I].imm64 && !Out.NumXor &&
            Detail::ReadMovImm32(Scanner, Insns[I].rva, Imm)) {
            Out.NumXor = Imm;
            Out.NumOff = Disp;
        }
    }
    if (!Out.ArrXor || !Out.NumXor) return false;

    Out.FuncRva = FuncRva;
    Out.Valid   = true;
    return true;
}

inline ChunkMgrInfo FindChunkMgr(const SigScanV2::Scanner& Scanner,
                                 const AutoDiscovery::ModuleBounds& Bounds,
                                 const std::function<bool(const ChunkMgrInfo&)>& Validate)
{
    ChunkMgrInfo Best;
    auto Sites = AutoResolve::FindStride20Sites(Scanner, Bounds);
    std::printf("[ar818] %zu FUObjectItem stride-20 index sites\n", Sites.size());

    std::unordered_map<uint64_t, int>      Votes;
    std::unordered_map<uint64_t, uint64_t> Owner;
    for (uint64_t S : Sites) {
        uint64_t F = FuncAnalyze::FindFunctionStart(Scanner, S);
        if (!F) continue;
        ChunkMgrInfo Tmp;
        if (!ExtractChunkMgrFromFunc(Scanner, Bounds, F, Tmp)) continue;
        ++Votes[Tmp.GlobalRva];
        Owner[Tmp.GlobalRva] = F;
    }

    std::vector<std::pair<uint64_t, int>> Ranked(Votes.begin(), Votes.end());
    std::sort(Ranked.begin(), Ranked.end(),
              [](const auto& A, const auto& B) { return A.second > B.second; });

    for (size_t I = 0; I < Ranked.size() && I < 8; ++I) {
        std::printf("[ar818]   candidate .data 0x%llX (%d site%s)%s\n",
            (unsigned long long)Ranked[I].first, Ranked[I].second,
            Ranked[I].second == 1 ? "" : "s", I == 0 ? "  <- highest" : "");
        ChunkMgrInfo C;
        if (!ExtractChunkMgrFromFunc(Scanner, Bounds, Owner[Ranked[I].first], C)) continue;
        C.Votes = Ranked[I].second;
        if (!Validate(C)) continue;
        std::printf("[ar818] chunks_manager = RVA 0x%llX (read from 0x%llX, validated)\n",
            (unsigned long long)C.GlobalRva, (unsigned long long)C.FuncRva);
        return C;
    }
    std::printf("[ar818] no chunks_manager candidate passed validation\n");
    return Best;
}

// ─────────────────────────────────────────────────────────────────────────────
// FProperty::SetupOffset — Offset_Internal and its XOR.
//
// The generic extractor needs two agreeing sites and finds only one here, so
// it declines. The single site is nonetheless unambiguous once the shape is
// pinned: `movzx r32, word [src+imm] ; xor r32, imm32 ; bswap r32 ;
// mov [dst+disp32], r32`. Nothing else in the image both encodes through
// bswap and stores to a large struct displacement.
// ─────────────────────────────────────────────────────────────────────────────
struct PropertyOffsetInfo {
    bool     Valid = false;
    uint64_t Rva = 0;
    uint64_t OffsetInternal = 0;
    uint32_t Xor = 0;
};

inline PropertyOffsetInfo ExtractPropertyOffset(const SigScanV2::Scanner& Scanner,
                                                const AutoDiscovery::ModuleBounds& Bounds)
{
    PropertyOffsetInfo Out;
    if (!Bounds.Valid || !Bounds.TextSize) return Out;

    struct Hit { uint64_t Rva, Disp; uint32_t Key; };
    std::vector<Hit> Hits;

    for (uint64_t R = Bounds.TextRva; R + 20 <= Bounds.TextEnd(); ++R) {
        const uint8_t* P = Scanner.GetLocalPtr(R);
        if (!P) continue;

        // xor eax, imm32 (35 id) or xor r32, imm32 (81 /6 id)
        int XLen = 0;
        uint32_t Key = 0;
        if (P[0] == 0x35) { std::memcpy(&Key, P + 1, 4); XLen = 5; }
        else if (P[0] == 0x81 && P[1] >= 0xF0 && P[1] <= 0xF7) {
            std::memcpy(&Key, P + 2, 4); XLen = 6;
        } else continue;
        if (!Key) continue;

        // bswap must follow immediately.
        const uint8_t* B = P + XLen;
        int BLen = 0;
        if (B[0] == 0x0F && B[1] >= 0xC8 && B[1] <= 0xCF) BLen = 2;
        else if ((B[0] & 0xF0) == 0x40 && B[1] == 0x0F && B[2] >= 0xC8 && B[2] <= 0xCF) BLen = 3;
        else continue;

        // then `mov [reg + disp32], r32` — 89 /r with mod == 10.
        const uint8_t* M = B + BLen;
        int I = ((M[0] & 0xF0) == 0x40) ? 1 : 0;
        if (M[I] != 0x89) continue;
        uint8_t Mod = (M[I + 1] >> 6) & 3;
        if (Mod != 2) continue;                       // disp32 store only
        int D = I + 2;
        if ((M[I + 1] & 7) == 4) ++D;                 // SIB
        uint32_t Disp = 0;
        std::memcpy(&Disp, M + D, 4);
        if (Disp < 0x40 || Disp > 0x400) continue;

        Hits.push_back({ R, Disp, Key });
    }

    std::printf("[ar818] %zu xor+bswap+mov[reg+disp32] encode sites\n", Hits.size());
    if (Hits.empty()) return Out;

    // Prefer the pair seen most often; a single site is accepted because the
    // shape is already this specific and the caller validates the decode
    // against live properties before it is used for anything.
    std::unordered_map<uint64_t, int> Pairs;
    for (const auto& H : Hits) ++Pairs[(H.Disp << 32) | H.Key];
    uint64_t BestKey = 0; int BestN = -1;
    for (const auto& [K, N] : Pairs) if (N > BestN) { BestN = N; BestKey = K; }

    Out.OffsetInternal = BestKey >> 32;
    Out.Xor            = (uint32_t)BestKey;
    for (const auto& H : Hits)
        if (H.Disp == Out.OffsetInternal && H.Key == Out.Xor) { Out.Rva = H.Rva; break; }
    Out.Valid = true;
    std::printf("[ar818] Offset_Internal +0x%llX xor 0x%08X (%d site%s, first @ 0x%llX)\n",
        (unsigned long long)Out.OffsetInternal, Out.Xor, BestN, BestN == 1 ? "" : "s",
        (unsigned long long)Out.Rva);
    return Out;
}


// ─────────────────────────────────────────────────────────────────────────────
// FField::NamePrivate and sizeof(FProperty), from the PropertyBool.cpp assert.
//
// The source-path strings in CoreUObject have survived every patch so far and
// name the exact function, which makes this the cheapest high-value anchor in
// the image. FBoolProperty::GetCPPType formats the field name for its "Unsupported
// FBoolProperty %s size %d." message, so its assert path carries the whole name
// decode inline — offset, both key constants and the rotate — and the same
// function tests FieldMask, which pins sizeof(FProperty) exactly rather than by
// probing.
// ─────────────────────────────────────────────────────────────────────────────
struct FFieldNameInfo {
    bool     Valid = false;
    uint64_t Rva = 0;
    uint64_t NameOff = 0;
    uint64_t K1Rva = 0, K2Rva = 0;
    uint64_t K1 = 0, K2 = 0;
    int      Rol32 = 0;
    int      Rol64 = 0;
    uint64_t FieldMaskOff = 0;      // sizeof(FProperty) == this - 3
};

// Every rip-relative reference in .text to one exact target RVA. The
// displacement is checked against the position, so no instruction-length
// assumption is needed; the three preceding bytes are then required to be a
// `lea r64, [rip+disp32]` so unrelated 4-byte matches cannot get in.
inline std::vector<uint64_t> FindRipRefs(const SigScanV2::Scanner& Scanner,
                                         const AutoDiscovery::ModuleBounds& Bounds,
                                         uint64_t Target)
{
    std::vector<uint64_t> Out;
    if (!Bounds.Valid || !Bounds.TextSize) return Out;
    for (uint64_t D = Bounds.TextRva + 3; D + 4 <= Bounds.TextEnd(); ++D) {
        const uint8_t* P = Scanner.GetLocalPtr(D);
        if (!P) continue;
        int32_t Rel = 0;
        std::memcpy(&Rel, P, 4);
        if ((uint64_t)((int64_t)D + 4 + Rel) != Target) continue;
        const uint8_t* Q = Scanner.GetLocalPtr(D - 3);
        if (!Q) continue;
        if ((Q[0] & 0xF8) != 0x48 || Q[1] != 0x8D) continue;   // REX.W lea
        if ((Q[2] & 0xC7) != 0x05) continue;                   // mod=00, rm=101
        Out.push_back(D - 3);
    }
    return Out;
}

// Locate an ASCII literal in .rdata and return the start of its printable run,
// which is what the code actually references.
inline uint64_t FindStringStart(const SigScanV2::Scanner& Scanner,
                                const AutoDiscovery::ModuleBounds& Bounds,
                                const char* Needle)
{
    size_t N = std::strlen(Needle);
    if (!Bounds.Valid || !Bounds.RDataSize || !N) return 0;
    for (uint64_t R = Bounds.RDataRva; R + N <= Bounds.RDataEnd(); ++R) {
        const uint8_t* P = Scanner.GetLocalPtr(R);
        if (!P || P[0] != (uint8_t)Needle[0]) continue;
        if (std::memcmp(P, Needle, N) != 0) continue;
        uint64_t S = R;
        while (S > Bounds.RDataRva) {
            const uint8_t* Q = Scanner.GetLocalPtr(S - 1);
            if (!Q || *Q < 0x20 || *Q > 0x7E) break;
            --S;
        }
        return S;
    }
    return 0;
}

inline FFieldNameInfo ExtractFFieldName(const SigScanV2::Scanner& Scanner,
                                        const AutoDiscovery::ModuleBounds& Bounds)
{
    FFieldNameInfo Best;
    uint64_t Str = FindStringStart(Scanner, Bounds, "PropertyBool.cpp");
    if (!Str) {
        std::printf("[ar818] PropertyBool.cpp not found in .rdata\n");
        return Best;
    }
    auto Refs = FindRipRefs(Scanner, Bounds, Str);
    std::printf("[ar818] PropertyBool.cpp @ 0x%llX, %zu rip references\n",
                (unsigned long long)Str, Refs.size());

    for (uint64_t R : Refs) {
        uint64_t Func = FuncAnalyze::FindFunctionStart(Scanner, R);
        if (!Func || R <= Func) continue;
        auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, Func,
                                                 (size_t)(R - Func) + 64);
        FFieldNameInfo I;
        I.Rva = Func;

        for (size_t K = 0; K + 1 < Insns.size(); ++K) {
            const auto& In = Insns[K];

            // The name load is the movdqa whose PXOR partner is a rip constant.
            if (In.type == INSN_MOVDQA && !In.hasRipRel && !I.NameOff) {
                uint64_t D = 0;
                if (!Detail::ReadMovdqaDisp(Scanner, In.rva, In.length, D)) continue;
                if (D < 0x20 || D > 0x300) continue;
                for (size_t J = K + 1; J < Insns.size() && J < K + 10; ++J) {
                    if (Insns[J].type == INSN_PXOR && Insns[J].hasRipRel) {
                        I.NameOff = D;
                        I.K1Rva   = Insns[J].ResolveRipRVA();
                        break;
                    }
                    if (Insns[J].type == INSN_MOVDQA) break;
                }
                continue;
            }
            if (I.NameOff) {
                if (In.type == INSN_PSLLD && In.hasImm8 && !I.Rol32) I.Rol32 = In.imm8;
                if (In.type == INSN_PADDD && In.hasRipRel && !I.K2Rva)
                    I.K2Rva = In.ResolveRipRVA();
                if (In.type == INSN_ROL && In.hasImm8 && !I.Rol64) I.Rol64 = In.imm8;
            }

            // `cmp byte [reg + disp], -1` is the FieldMask test, and FieldMask
            // is the last of FBoolProperty's four bytes.
            const uint8_t* P = Scanner.GetLocalPtr(In.rva);
            if (P && In.length >= 4) {
                int Q = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
                if (P[Q] == 0x80 && ((P[Q + 1] >> 3) & 7) == 7 &&
                    P[In.length - 1] == 0xFF)
                {
                    uint64_t D = 0;
                    if (Detail::MemDisp(P, Q + 1, D) && D >= 0x40 && D <= 0x400)
                        I.FieldMaskOff = D;
                }
            }
        }

        if (!I.NameOff || !I.K1Rva || !I.K2Rva || !I.Rol32) continue;
        const uint8_t* A = Scanner.GetLocalPtr(I.K1Rva);
        const uint8_t* B = Scanner.GetLocalPtr(I.K2Rva);
        if (!A || !B) continue;
        std::memcpy(&I.K1, A, 8);
        std::memcpy(&I.K2, B, 8);
        if (!I.Rol64) I.Rol64 = 32;
        I.Valid = true;

        // Prefer whichever copy also yielded the FieldMask test — that is the
        // one that pins sizeof(FProperty).
        if (!Best.Valid || (I.FieldMaskOff && !Best.FieldMaskOff)) Best = I;
        if (Best.FieldMaskOff) break;
    }
    return Best;
}

// ─────────────────────────────────────────────────────────────────────────────
// The remaining struct offsets, probed against the live object graph.
//
// Scored by DISTINCT names and by chain structure, never by hit count. Scoring
// "how many decode to a printable name" is what once gave a confident 80/80 for
// the wrong pair and cut the property count from 281k to 7k.
// ─────────────────────────────────────────────────────────────────────────────
struct LayoutProbe {
    bool     Valid = false;
    uint64_t ChildProps = 0;
    uint64_t Next       = 0;
    uint64_t Owner      = 0;
    uint64_t Super      = 0;
    uint64_t Children   = 0;
    int      ChainCount = 0;
    int      Distinct   = 0;
};

inline LayoutProbe ProbeLayout(IMemoryReader& Reader,
                               const std::vector<uint64_t>& Structs,
                               const std::function<std::string(uint64_t)>& FieldName,
                               const std::function<uint32_t(uint64_t)>& PropOffset,
                               const std::function<bool(uint64_t)>& IsTypeObject)
{
    LayoutProbe Out;
    auto Ptr = [&](uint64_t A) -> uint64_t {
        uint64_t V = 0;
        if (!Reader.Read(A, &V, 8)) return 0;
        return (V >= 0x10000ULL && V < 0x800000000000ULL) ? V : 0;
    };

    // ChildProperties: the head whose target carries a decodable field name on
    // the most structs, counted by distinct names.
    {
        int BestScore = -1;
        for (uint64_t Off = 0x80; Off <= 0x180; Off += 8) {
            std::vector<std::string> Seen;
            int Hits = 0;
            for (uint64_t S : Structs) {
                uint64_t H = Ptr(S + Off);
                if (!H) continue;
                std::string N = FieldName(H);
                if (N.size() < 2 || N.size() > 64) continue;
                bool Clean = true;
                for (unsigned char C : N) if (C < 32 || C > 126) { Clean = false; break; }
                if (!Clean) continue;
                ++Hits;
                Seen.push_back(N);
            }
            std::sort(Seen.begin(), Seen.end());
            Seen.erase(std::unique(Seen.begin(), Seen.end()), Seen.end());
            int Score = (int)Seen.size();
            if (Score > BestScore) { BestScore = Score; Out.ChildProps = Off; Out.Distinct = Score; }
        }
        if (BestScore < 8) return Out;
    }

    // Next: require at least three linked fields whose Offset_Internal ascends.
    // A structurally well-formed list is not enough — the UField list and the
    // property-link chains are all well-formed and all wrong.
    {
        int BestAsc = -1;
        for (uint64_t Off = 0x30; Off <= 0x100; Off += 8) {
            int Chains = 0, Asc = 0;
            for (uint64_t S : Structs) {
                uint64_t Cur = Ptr(S + Out.ChildProps);
                if (!Cur) continue;
                uint32_t Prev = 0;
                int Run = 0;
                bool Rising = true;
                for (int K = 0; K < 8 && Cur; ++K) {
                    std::string N = FieldName(Cur);
                    if (N.size() < 2) break;
                    uint32_t O = PropOffset(Cur);
                    if (O > 0x100000u) break;
                    if (Run && O < Prev) Rising = false;
                    Prev = O;
                    ++Run;
                    Cur = Ptr(Cur + Off);
                }
                if (Run >= 3) { ++Chains; if (Rising) ++Asc; }
            }
            if (Asc > BestAsc) { BestAsc = Asc; Out.Next = Off; Out.ChainCount = Chains; }
        }
        if (BestAsc < 4) return Out;
    }

    // Owner is the sharpest test and needs no names at all: it is a tagged
    // back-pointer, so for the right offset the field's owner IS the struct
    // walked from.
    {
        int BestHits = -1;
        for (uint64_t Off = 0x30; Off <= 0x100; Off += 8) {
            int Hits = 0;
            for (uint64_t S : Structs) {
                uint64_t F = Ptr(S + Out.ChildProps);
                if (!F) continue;
                uint64_t V = 0;
                if (!Reader.Read(F + Off, &V, 8)) continue;
                if ((V & ~1ULL) == S) ++Hits;
            }
            if (Hits > BestHits) { BestHits = Hits; Out.Owner = Off; }
        }
    }

    // SuperStruct: the offset that points at another type object on almost
    // every struct. UObject terminates the chain at zero, so a plain
    // "is it a pointer" test would also accept ClassWithin.
    {
        int BestHits = -1;
        for (uint64_t Off = 0x80; Off <= 0x140; Off += 8) {
            int Hits = 0, SelfLoops = 0;
            for (uint64_t S : Structs) {
                uint64_t V = Ptr(S + Off);
                if (!V) continue;
                if (V == S) { ++SelfLoops; continue; }
                if (IsTypeObject(V)) ++Hits;
            }
            Hits -= SelfLoops * 4;
            if (Hits > BestHits) { BestHits = Hits; Out.Super = Off; }
        }
    }

    Out.Valid = true;
    return Out;
}

} // namespace AutoResolve818
