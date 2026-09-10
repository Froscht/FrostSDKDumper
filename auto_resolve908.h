// =============================================================================
// auto_resolve908.h — patch-day extraction for the CL-1372005 (v20260908) shapes
//
// Same rule as auto_resolve818.h: nothing is matched as a fixed op list. Both
// hash chains are COLLECTED as HashOp programs, and every extracted value is
// validated by plaintext or by an invariant, never by looking plausible.
//
// Shape differences from v818 (things that MOVED, not just changed value):
//   - Block decode is per-dword ROL32 + PADDD (v818 was per-block ROL64 + XOR)
//   - FField NamePrivate is PSHUFB + XOR + ROL16 + ROL64 (v818 was XOR + PADDD)
//   - Slot decoder is a shared LEAF again, but with PSHUFLW/XOR/ROL64/PSHUFB
//     instead of CLMUL polynomials
//   - chunks_manager decrypt is PXOR + ROL16 + PSHUFLW (v818 was ROL64+PSHUFB+ROL32)
//   - FUObjectItem stride is 24 (v818 was 20), UObject at +8 (v818 at +0)
//   - UObject::InternalIndex sits at +0x90 (unchanged from v818)
//
// Anchors, none of which Theia has moved:
//   FNV-32 prime  0x1000193        both hash chains
//   FNV-64 prime  0x100000001B3    the FName entry fold
//   `and r32, 0xFFFF00`            ChunkOff = (CI >> 8) & 0xFFFF00 — the
//                                  sharpest anchor in the whole image
//   FUObjectItem stride 24         the object-array index computation
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
#include "auto_resolve818.h"

namespace AutoResolve908 {

using ArcDecrypt::HashOp;

constexpr uint32_t FNV32_PRIME = 0x01000193u;
constexpr uint64_t FNV64_PRIME = 0x100000001B3ULL;

// ─────────────────────────────────────────────────────────────────────────────
// The FName pipeline.
//
// Anchored on `and r32, 0xFFFF00` (reused from AutoResolve818::FindChunkOffSites,
// which handles all three encoding forms including REX-prefixed r8..r15). Each
// candidate is installed and decided by TryV908(false): CI=0 must decode to
// "None" plus a second longer plaintext identifier.
// ─────────────────────────────────────────────────────────────────────────────
struct FNamePipelineInfo908 {
    bool     Valid = false;
    uint64_t Rva   = 0;
    const char* Reject = nullptr;

    uint64_t PoolRva     = 0;
    uint64_t KeystreamRva = 0;
    uint64_t SeedOff     = 0;
    uint64_t BlockBase   = 0;
    uint64_t BlockStride = 32;

    int      BlockRol32  = 0;      // per-dword ROL32 in block decode
    uint64_t Block2Xor   = 0;      // pxor rip target constant
    uint64_t BlockAdd    = 0;      // paddd rip target constant

    uint64_t Fnv64Add    = 0;
    int      FnvRol1     = 0;
    int      FnvRol2     = 0;

    uint32_t KeyInitAdd  = 0;
    std::vector<HashOp> ShardProgram;
};

inline FNamePipelineInfo908 ExtractFNamePipeline908(const SigScanV2::Scanner& Scanner,
                                                    const AutoDiscovery::ModuleBounds& Bounds,
                                                    uint64_t AndSite)
{
    FNamePipelineInfo908 Info;
    Info.Rva = AndSite;

    // Track constants loaded into xmm/gpr registers from the function start.
    // The block xor / padd constants land in xmm regs by rip-relative movdqa
    // in the prologue and reach the block decode via `pxor xmm, xmmReg`.
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

    // Pool RVA: first rip-relative lea into .data after the mask.
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

    // Seed offset — `add r, imm32` between 0x100 and 0x40000 after the pool.
    for (size_t I = PoolIdx; I < Insns.size() && I < PoolIdx + 12; ++I) {
        if (Insns[I].type == INSN_ADD_IMM && Insns[I].hasImm32 &&
            Insns[I].imm32 >= 0x100 && Insns[I].imm32 < 0x40000) {
            Info.SeedOff = Insns[I].imm32;
            break;
        }
    }
    if (!Info.SeedOff) { Info.Reject = "no seed offset"; return Info; }

    // Shard hash — collect it as a program. The form has already flipped
    // between ROL and SHR between builds; recording the ops as they appear
    // costs nothing.
    size_t Fold = 0;
    if (!AutoResolve818::CollectHashProgram(Scanner, Insns, PoolIdx,
                                             Insns.size(), Info.ShardProgram, &Fold)) {
        Info.Reject = "no FNV-32 chain ending in a 16-bit fold";
        return Info;
    }

    // Block base — first non-rip movdqa with disp ≥ 0x100 after the fold.
    // The decode window then carries: pxor rip (Block2Xor), pslld imm8
    // (BlockRol32), paddd rip (BlockAdd). The pxor and paddd may reach
    // through a register loaded in the prologue, so consult XmmConst too.
    for (size_t I = Fold; I < Insns.size(); ++I) {
        const auto& In = Insns[I];
        if (In.type != INSN_MOVDQA || In.hasRipRel) continue;
        uint64_t D = 0;
        if (!AutoResolve818::Detail::ReadMovdqaDisp(Scanner, In.rva, In.length, D)) continue;
        if (D < 0x100) continue;
        Info.BlockBase = D;

        for (size_t K = I + 1; K < Insns.size() && K < I + 40; ++K) {
            const auto& B = Insns[K];
            if (B.type == INSN_PSLLD && B.hasImm8 && !Info.BlockRol32)
                Info.BlockRol32 = B.imm8;
            if (B.type == INSN_PXOR && !Info.Block2Xor) {
                uint64_t Rva = B.hasRipRel ? B.ResolveRipRVA()
                             : (B.reg2 < 16 ? XmmConst[B.reg2] : 0);
                if (Rva) {
                    const uint8_t* P = Scanner.GetLocalPtr(Rva);
                    if (P) std::memcpy(&Info.Block2Xor, P, 8);
                }
            }
            if (B.type == INSN_PADDD && !Info.BlockAdd) {
                uint64_t Rva = B.hasRipRel ? B.ResolveRipRVA()
                             : (B.reg2 < 16 ? XmmConst[B.reg2] : 0);
                if (Rva) {
                    const uint8_t* P = Scanner.GetLocalPtr(Rva);
                    if (P) std::memcpy(&Info.BlockAdd, P, 8);
                }
            }
            if (B.type == INSN_MOVQ) break;
        }
        break;
    }
    if (!Info.BlockBase)  { Info.Reject = "no block base";           return Info; }
    if (!Info.BlockRol32) { Info.Reject = "no per-dword ROL32";      return Info; }
    if (!Info.Block2Xor)  { Info.Reject = "no block XOR constant";   return Info; }
    if (!Info.BlockAdd)   { Info.Reject = "no PADDD add constant";   return Info; }

    // FNV-64 fold: two movabs (prime followed by add) + two rol imm8.
    // The immediate B3 01 00 00 00 01 00 00 — reversed byte order finds
    // nothing and looks like the anchor is missing.
    for (size_t I = Fold; I < Insns.size(); ++I) {
        if (Insns[I].imm64 == FNV64_PRIME) {
            for (size_t K = I; K < Insns.size() && K < I + 24; ++K) {
                const auto& B = Insns[K];
                if (B.type == INSN_ROL && B.hasImm8) {
                    if (!Info.FnvRol1)      Info.FnvRol1 = B.imm8;
                    else if (!Info.FnvRol2) Info.FnvRol2 = B.imm8;
                }
                if (B.imm64 && B.imm64 != FNV64_PRIME && !Info.Fnv64Add)
                    Info.Fnv64Add = B.imm64;
            }
            break;
        }
        if (Insns[I].type == INSN_ROL && Insns[I].hasImm8 && !Info.FnvRol1) {
            for (size_t K = I; K < Insns.size() && K < I + 4; ++K)
                if (Insns[K].imm64 == FNV64_PRIME) { Info.FnvRol1 = Insns[I].imm8; break; }
        }
    }
    if (!Info.FnvRol1 || !Info.FnvRol2 || !Info.Fnv64Add) {
        Info.Reject = "incomplete FNV-64 fold";
        return Info;
    }

    // Keystream RVA: any rip-lea target seen so far that lands in .rdata
    // (or .data) and is NOT the pool. The window offset is decided by the
    // plaintext sweep at adopt time; only the base matters here.
    for (int R = 0; R < 16; ++R) {
        uint64_t T = GprLea[R];
        if (!T || T == Info.PoolRva) continue;
        if (T < Bounds.RDataRva || T >= Bounds.DataEnd()) continue;
        Info.KeystreamRva = T;
    }
    // The Track loop above only saw the prologue; the actual keystream lea
    // often lives in the string-decrypt sub, called from this function.
    // Sweep the rest for a rip-lea into .rdata for completeness.
    if (!Info.KeystreamRva) {
        for (size_t I = Fold; I < Insns.size(); ++I) {
            const auto& In = Insns[I];
            if (In.type != INSN_LEA || !In.hasRipRel) continue;
            uint64_t T = In.ResolveRipRVA();
            if (!T || T == Info.PoolRva) continue;
            if (T < Bounds.RDataRva || T >= Bounds.DataEnd()) continue;
            Info.KeystreamRva = T;
            break;
        }
    }

    // KeyInitAdd — `lea r32, [base + imm]` after the fold, imm in a range
    // consistent with a short additive constant. On v908 KeyInitAdd is 0x2E0
    // (smaller than v818's 0xD917), so widen the lower bound.
    for (size_t I = Fold; I < Insns.size(); ++I) {
        const auto& In = Insns[I];
        if (In.type != INSN_LEA || In.hasRipRel) continue;
        uint64_t D = 0;
        if (AutoResolve818::Detail::ReadLeaRegDisp(Scanner, In.rva, In.length, D) &&
            D >= 0x100 && D <= 0xFFFF) {
            Info.KeyInitAdd = (uint32_t)D;
            break;
        }
    }

    Info.Valid = true;
    return Info;
}

// Adopt the pipeline into the sheet and decide it by plaintext. Nothing is
// accepted because it looks right — CI=0 must decode to "None" and a second
// longer plaintext must decode cleanly. The keystream window is swept because
// only its value mod 64 matters and a sweep absorbs that without an index
// bias extraction.
struct FNameAdoption908 {
    bool     Valid = false;
    uint64_t WindowRva = 0;
};

inline FNameAdoption908 AdoptFNamePipeline908(const AutoDiscovery::ModuleBounds& Bounds,
                                              const FNamePipelineInfo908& P,
                                              const std::function<bool()>& TryPipeline)
{
    FNameAdoption908 Out;
    auto& Sh = ArcDecrypt::g_Sheet;
    const ArcDecrypt::LiveSheet Saved = Sh;

    Sh.Pool908Rva      = P.PoolRva;
    Sh.Seed908Off      = P.SeedOff;
    Sh.Block908Base    = P.BlockBase;
    Sh.Block908Stride  = 32;
    Sh.BlockRol32_908  = P.BlockRol32 ? P.BlockRol32 : Saved.BlockRol32_908;
    Sh.Block2Xor908    = P.Block2Xor;
    Sh.BlockAdd908     = P.BlockAdd;
    Sh.Fnv908Prime     = FNV64_PRIME;
    Sh.Fnv908Add       = P.Fnv64Add;
    Sh.Fnv908Rol1      = P.FnvRol1;
    Sh.Fnv908Rol2      = P.FnvRol2;
    Sh.Shard908Program = P.ShardProgram;
    if (P.KeyInitAdd) Sh.KeyInitAdd908 = P.KeyInitAdd;

    // Sweep the window: only its value mod 64 matters. Must be read live
    // (the table is decrypted in place at load), so TryPipeline drives real
    // reads through IMemoryReader.
    std::vector<uint64_t> Cands;
    if (P.KeystreamRva)
        for (uint64_t B = 0; B <= 0x200; B += 0x10) Cands.push_back(P.KeystreamRva + B);
    Cands.push_back(Saved.Keystream908Rva);

    for (uint64_t W : Cands) {
        if (W < Bounds.RDataRva || W + 128 >= Bounds.DataEnd()) continue;
        Sh.Keystream908Rva = W;
        if (!TryPipeline()) continue;
        Out.Valid     = true;
        Out.WindowRva = W;
        return Out;
    }

    Sh = Saved;
    return Out;
}

// ─────────────────────────────────────────────────────────────────────────────
// chunks_manager (v908 shape).
//
// FUObjectItem's 24-byte stride forces a distinctive index computation:
//   lea r, [r + r*2]     ; *3    (SIB scale=×2, index==base)
//   shl r32, 3           ;       *3 << 3 = *24
// or:
//   imul r,r,24          ;       direct multiply
//
// Take the containing function; the first rip-relative movdqa from .data is
// the encrypted global, and the extraction of NumOff/NumXor plus ArrOff/ArrXor
// falls out of the `mov r,imm ; xor r,[mgr+off] ; bswap r` idiom.
// ─────────────────────────────────────────────────────────────────────────────
struct ChunkMgr908Info {
    bool     Valid = false;
    uint64_t GlobalRva = 0;
    uint64_t KeyRva    = 0;
    uint64_t FuncRva   = 0;
    uint8_t  Pshufb[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    int      Rol16       = 0;
    int      PshuflwImm  = 0;
    uint64_t NumOff = 0;
    uint32_t NumXor = 0;
    uint64_t ArrOff = 0;
    uint64_t ArrXor = 0;
    int      Votes  = 0;
};

inline std::vector<uint64_t> FindStride24Sites(const SigScanV2::Scanner& Scanner,
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
        if (((Sib >> 6) & 3) != 1) continue;                 // scale *2
        if (((Sib >> 3) & 7) != (Sib & 7)) continue;         // index == base
        // Within 8 bytes: either `shl r32, 3` (C1 /4 03) OR `imul r,r,24`
        // (48 6B ModR/M(mod=11) 18).
        bool Ok = false;
        for (int K = 4; K < 12 && !Ok; ++K) {
            const uint8_t* Q = Scanner.GetLocalPtr(R + K);
            if (!Q) break;
            int J = ((Q[0] & 0xF0) == 0x40) ? 1 : 0;
            if (Q[J] == 0xC1 && ((Q[J + 1] >> 3) & 7) == 4 && Q[J + 2] == 3) Ok = true;
            else if ((Q[0] & 0xF8) == 0x48 && Q[1] == 0x6B &&
                     (Q[2] & 0xC0) == 0xC0 && Q[3] == 0x18) Ok = true;
        }
        if (Ok) Out.push_back(R);
    }
    return Out;
}

inline bool ExtractChunkMgrFromFunc908(const SigScanV2::Scanner& Scanner,
                                       const AutoDiscovery::ModuleBounds& Bounds,
                                       uint64_t FuncRva, ChunkMgr908Info& Out)
{
    auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, FuncRva, 0x300);
    if (Insns.size() < 12) return false;

    // Global: first rip-relative movdqa from .data.
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

    // Decode chain: PXOR (rip key) + PSLLW imm8 (ROL16) + PSHUFLW imm8.
    // The key constant lives in .rdata and may reach the pxor via a rip
    // reference or via a register the prologue loaded — cover both by
    // tracking rip-loaded xmm constants across the window.
    uint64_t XmmConst[16] = {};
    for (size_t I = 0; I < GlobalIdx; ++I) {
        const auto& In = Insns[I];
        if (In.type == INSN_MOVDQA && In.hasRipRel && In.reg1 < 16)
            XmmConst[In.reg1] = In.ResolveRipRVA();
    }
    for (size_t I = GlobalIdx; I < Insns.size() && I < GlobalIdx + 24; ++I) {
        const auto& In = Insns[I];
        if (In.type == INSN_PXOR && !Out.KeyRva) {
            if (In.hasRipRel) Out.KeyRva = In.ResolveRipRVA();
            else if (In.reg2 < 16 && XmmConst[In.reg2]) Out.KeyRva = XmmConst[In.reg2];
        }
        if (In.type == INSN_PSLLW && In.hasImm8 && !Out.Rol16) Out.Rol16 = In.imm8;
        if (In.type == INSN_PSHUFLW && In.hasImm8 && !Out.PshuflwImm)
            Out.PshuflwImm = In.imm8;
        if (In.type == INSN_PSHUFB && In.hasRipRel) {
            uint64_t T = In.ResolveRipRVA();
            const uint8_t* M = Scanner.GetLocalPtr(T);
            if (M) std::memcpy(Out.Pshufb, M, 8);
        }
        if (In.type == INSN_MOVQ) break;
    }
    if (!Out.Rol16 || !Out.PshuflwImm || !Out.KeyRva) return false;

    // Field extraction — the encoded scalars are read by:
    //   mov r,imm            ; the negated xor key
    //   xor r,[mgr+disp]     ; combines with the stored ciphertext
    //   bswap r
    // 64-bit form addresses the chunk array; 32-bit form the count.
    for (size_t I = GlobalIdx; I + 2 < Insns.size(); ++I) {
        if (!AutoResolve818::Detail::IsBswap(Scanner, Insns[I + 2].rva)) continue;
        uint64_t Disp = 0;
        if (!AutoResolve818::Detail::ReadXorMemDisp(Scanner, Insns[I + 1].rva,
                                                    Insns[I + 1].length, Disp))
            continue;
        // 64-bit movabs → chunk array.
        uint8_t Reg = 0; uint64_t Imm64 = 0;
        if (AutoResolve818::Detail::ReadMovabs(Scanner, Insns[I].rva, Reg, Imm64) &&
            Imm64 && !Out.ArrXor) {
            Out.ArrXor = Imm64;
            Out.ArrOff = Disp;
            continue;
        }
        uint32_t Imm = 0;
        if (AutoResolve818::Detail::ReadMovImm32(Scanner, Insns[I].rva, Imm) &&
            Imm && !Out.NumXor) {
            Out.NumXor = Imm;
            Out.NumOff = Disp;
        }
    }
    if (!Out.ArrXor || !Out.NumXor) return false;

    Out.FuncRva = FuncRva;
    Out.Valid   = true;
    return true;
}

inline ChunkMgr908Info FindChunkMgr908(const SigScanV2::Scanner& Scanner,
                                       const AutoDiscovery::ModuleBounds& Bounds,
                                       const std::function<bool(const ChunkMgr908Info&)>& Validate)
{
    ChunkMgr908Info Best;
    auto Sites = FindStride24Sites(Scanner, Bounds);
    std::printf("[ar908] %zu FUObjectItem stride-24 index sites\n", Sites.size());

    std::unordered_map<uint64_t, int>      Votes;
    std::unordered_map<uint64_t, uint64_t> Owner;
    for (uint64_t S : Sites) {
        uint64_t F = FuncAnalyze::FindFunctionStart(Scanner, S);
        if (!F) continue;
        ChunkMgr908Info Tmp;
        if (!ExtractChunkMgrFromFunc908(Scanner, Bounds, F, Tmp)) continue;
        ++Votes[Tmp.GlobalRva];
        Owner[Tmp.GlobalRva] = F;
    }

    std::vector<std::pair<uint64_t, int>> Ranked(Votes.begin(), Votes.end());
    std::sort(Ranked.begin(), Ranked.end(),
              [](const auto& A, const auto& B) { return A.second > B.second; });

    for (size_t I = 0; I < Ranked.size() && I < 8; ++I) {
        std::printf("[ar908]   candidate .data 0x%llX (%d site%s)%s\n",
            (unsigned long long)Ranked[I].first, Ranked[I].second,
            Ranked[I].second == 1 ? "" : "s", I == 0 ? "  <- highest" : "");
        ChunkMgr908Info C;
        if (!ExtractChunkMgrFromFunc908(Scanner, Bounds, Owner[Ranked[I].first], C)) continue;
        C.Votes = Ranked[I].second;
        if (!Validate(C)) continue;
        std::printf("[ar908] chunks_manager = RVA 0x%llX (read from 0x%llX, validated)\n",
            (unsigned long long)C.GlobalRva, (unsigned long long)C.FuncRva);
        return C;
    }
    std::printf("[ar908] no chunks_manager candidate passed validation\n");
    return Best;
}

// ─────────────────────────────────────────────────────────────────────────────
// UObject::GetFName (v908 shape).
//
// The top-level function is a slot accessor (FNV-32 chain, then and-3 fold,
// then role adjustment) that calls a shared leaf decoder with the 16-byte
// slot as input. The leaf runs PSHUFLW → PXOR → ROL64 → PSHUFB → and returns
// the low 64 bits, which the caller finalises with ROL64.
//
// The three roles (Name / Class / Outer) share the chain and differ only in
// the slot adjustment, so they must be classified BEFORE consensus is taken.
// Averaging over all of them yields a slot xor of 0, because only the Name
// copies carry one.
// ─────────────────────────────────────────────────────────────────────────────
struct GetFNameInfo908 {
    enum class Role { Unknown, Name, Class, Outer };

    bool        Valid   = false;
    Role        Which   = Role::Unknown;
    const char* Reject  = nullptr;
    uint64_t    Rva     = 0;

    uint64_t    SeedOff    = 0;
    uint64_t    DecoderRva = 0;
    std::vector<HashOp> Hash;

    uint32_t    SlotXor    = 0;      // Name-role xor
    uint32_t    IdxAdd     = 0;      // add r32,imm32 between and-3 and >>16 fold
    uint64_t    SlotBase   = 0;
    uint64_t    SlotStride = 0;

    uint64_t    KeyLo64    = 0;      // pxor rip constant inside the leaf
    int         PshuflwImm = 0;
    int         Rol64Intra = 0;      // ROL64 inside the leaf
    int         FinalRol   = 0;      // ROL64 in the caller
    uint8_t     Pshufb[8]  = { 0, 1, 2, 3, 4, 5, 6, 7 };

    int         Copies = 0;
};

inline const char* RoleName908(GetFNameInfo908::Role R) {
    switch (R) {
        case GetFNameInfo908::Role::Name:  return "Name";
        case GetFNameInfo908::Role::Class: return "Class";
        case GetFNameInfo908::Role::Outer: return "Outer";
        default:                           return "?";
    }
}

// Decode the shared slot leaf and fill the SIMD fields on the caller info.
inline bool DecodeSlotLeaf908(const SigScanV2::Scanner& Scanner,
                              uint64_t LeafRva, GetFNameInfo908& Info)
{
    auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, LeafRva, 128);
    if (Insns.size() < 4) return false;

    uint64_t XmmConst[16] = {};
    for (const auto& In : Insns) {
        if (In.type == INSN_MOVDQA && In.hasRipRel && In.reg1 < 16)
            XmmConst[In.reg1] = In.ResolveRipRVA();
    }
    for (const auto& In : Insns) {
        if (In.type == INSN_PSHUFLW && In.hasImm8 && !Info.PshuflwImm)
            Info.PshuflwImm = In.imm8;
        if (In.type == INSN_PXOR && !Info.KeyLo64) {
            uint64_t T = In.hasRipRel ? In.ResolveRipRVA()
                       : (In.reg2 < 16 ? XmmConst[In.reg2] : 0);
            if (T) {
                const uint8_t* P = Scanner.GetLocalPtr(T);
                if (P) std::memcpy(&Info.KeyLo64, P, 8);
            }
        }
        if (In.type == INSN_ROL && In.hasImm8 && !Info.Rol64Intra)
            Info.Rol64Intra = In.imm8;
        if (In.type == INSN_PSHUFB && In.hasRipRel) {
            uint64_t T = In.ResolveRipRVA();
            const uint8_t* M = Scanner.GetLocalPtr(T);
            if (M) std::memcpy(Info.Pshufb, M, 8);
        }
        if (In.type == INSN_RET) break;
    }
    return Info.PshuflwImm && Info.KeyLo64 && Info.Rol64Intra;
}

inline GetFNameInfo908 ExtractGetFName908(const SigScanV2::Scanner& Scanner,
                                          uint64_t FuncRva)
{
    GetFNameInfo908 Info;
    Info.Rva = FuncRva;

    auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, FuncRva, 256);
    if (Insns.size() < 16) { Info.Reject = "too short to decode"; return Info; }

    size_t End = Insns.size();
    for (size_t I = 0; I < Insns.size(); ++I)
        if (Insns[I].type == INSN_RET) { End = I + 1; break; }
    if (End == Insns.size()) { Info.Reject = "no ret within window"; return Info; }

    // Seed offset — leading `lea rax, [rcx + X]`.
    for (size_t I = 0; I < End && I < 6; ++I) {
        if (Insns[I].type != INSN_LEA || Insns[I].hasRipRel) continue;
        uint64_t D = 0;
        if (AutoResolve818::Detail::ReadLeaRegDisp(Scanner, Insns[I].rva,
                                                    Insns[I].length, D)) {
            Info.SeedOff = D;
            break;
        }
    }

    // FNV-32 shard chain up to the fold.
    size_t Fold = 0;
    if (!AutoResolve818::CollectHashProgram(Scanner, Insns, 0, End,
                                             Info.Hash, &Fold)) {
        Info.Reject = "no FNV-32 chain ending in a 16-bit fold";
        return Info;
    }

    // Post-fold: `and r32, 3` classifies the role, `add r32, imm32` (before
    // the fold shift) is the IdxAdd, `shl r32, N` is the slot stride, and
    // the movdqa immediately after the mask picks up the base displacement.
    bool SawAnd3 = false;
    for (size_t I = Fold; I < End; ++I) {
        const auto& In = Insns[I];

        // `add r32, imm32` between and-3 and >>16&3 fold.
        if (!SawAnd3 && In.type == INSN_ADD_IMM && In.hasImm32 &&
            In.imm32 > 0xFF && In.imm32 < 0x1000000)
            Info.IdxAdd = In.imm32;

        if (In.type == INSN_AND_IMM && In.imm32 == 3u) {
            SawAnd3 = true;
            uint32_t Xv = 0;
            bool HasXor = false;
            for (size_t K = I + 1; K < End && K <= I + 3; ++K)
                if (AutoResolve818::Detail::ReadXorImm8(Scanner, Insns[K].rva, Xv)) {
                    HasXor = true; break;
                }
            bool PlusOne = false;
            for (size_t K = (I >= 3 ? I - 3 : 0); K < I; ++K)
                if (AutoResolve818::Detail::IsPlusOne(Scanner, Insns[K].rva)) {
                    PlusOne = true; break;
                }
            if (HasXor)       { Info.SlotXor = Xv; Info.Which = GetFNameInfo908::Role::Name;  }
            else if (PlusOne) {                    Info.Which = GetFNameInfo908::Role::Class; }
            else              {                    Info.Which = GetFNameInfo908::Role::Outer; }
            continue;
        }
        if (In.type == INSN_SHL && In.hasImm8 && SawAnd3 && !Info.SlotStride)
            Info.SlotStride = 1ULL << In.imm8;
        if (In.type == INSN_MOVDQA && !In.hasRipRel && SawAnd3 && !Info.SlotBase)
            AutoResolve818::Detail::ReadMovdqaDisp(Scanner, In.rva, In.length, Info.SlotBase);

        // Call to the shared leaf. Evaluate the BYTE form first and
        // unconditionally — `||` short-circuits, and the decoder already
        // reports a relative call as INSN_CALL_RIP with hasRipRel clear, so
        // putting the type test first silently skipped the only path that
        // could produce a target. This exact bug cost the whole GetFName
        // extraction on v818 while every other field came out correct.
        uint64_t CallTarget = 0;
        bool ByteCall = AutoResolve818::Detail::ReadCallRel32(
            Scanner, In.rva, In.length, CallTarget);
        if (ByteCall || In.type == INSN_CALL_RIP) {
            if (!Info.DecoderRva)
                Info.DecoderRva = CallTarget ? CallTarget : In.ResolveRipRVA();
            continue;
        }
        // Final rotate — last ROL64 in the top-level function.
        if (In.type == INSN_ROL && In.hasImm8 && Info.DecoderRva)
            Info.FinalRol = In.imm8;
    }

    if (!Info.SeedOff)    { Info.Reject = "no seed lea";                 return Info; }
    if (!SawAnd3)         { Info.Reject = "no `and r32, 3` slot select"; return Info; }
    if (!Info.SlotStride) { Info.Reject = "no slot stride";              return Info; }
    if (!Info.SlotBase)   { Info.Reject = "no slot base displacement";   return Info; }
    if (!Info.DecoderRva) { Info.Reject = "no call to the slot decoder"; return Info; }

    if (!DecodeSlotLeaf908(Scanner, Info.DecoderRva, Info))
        { Info.Reject = "shared leaf decoder did not decode"; return Info; }
    if (!Info.FinalRol) Info.FinalRol = 32;   // v908 default when the caller
                                              // inlines the final rotate

    Info.Valid = true;
    return Info;
}

inline GetFNameInfo908 FindGetFName908(const SigScanV2::Scanner& Scanner,
                                       const AutoDiscovery::ModuleBounds& Bounds)
{
    GetFNameInfo908 Best;
    auto Sites  = AutoResolve::FindFnvImulSites(Scanner, Bounds);
    auto Groups = AutoResolve::GroupFnvSitesByFunction(Sites);
    std::printf("[ar908] %zu FNV-prime multiplies across %zu functions\n",
                Sites.size(), Groups.size());

    // Prefilter — a slot accessor always reaches a `call` within its first
    // 256 bytes and always contains an `and r32, 3`. The byte-level check is
    // identical to v818's; reuse it as a lambda.
    auto LooksLikeAccessor = [&](uint64_t Func) {
        for (uint64_t K = 0; K + 3 < 256; ++K) {
            const uint8_t* P = Scanner.GetLocalPtr(Func + K);
            if (!P) return false;
            if (P[0] == 0xC3) return false;
            if (P[0] == 0x83 && (P[1] & 0xC0) == 0xC0 &&
                ((P[1] >> 3) & 7) == 4 && P[2] == 3) return true;
        }
        return false;
    };

    std::vector<GetFNameInfo908> Names, Classes, Outers;
    std::unordered_map<std::string, int> Rejects;
    int Tried = 0;
    uint64_t Dbg = 0;
    if (const char* E = getenv("FROST_AR908_DEBUG")) Dbg = strtoull(E, nullptr, 16);
    if (Dbg) {
        bool Seen = false;
        for (const auto& G : Groups) if (G.first == Dbg) { Seen = true; break; }
        std::printf("[ar908]   DEBUG target 0x%llX %s in the FNV group list\n",
            (unsigned long long)Dbg, Seen ? "IS" : "is NOT");
    }
    for (const auto& G : Groups) {
        if (G.second < 3) {
            if (Dbg) std::printf("[ar908]   DEBUG stopped at count %d before reaching "
                                 "the target\n", G.second);
            break;
        }
        if (!LooksLikeAccessor(G.first)) {
            if (G.first == Dbg)
                std::printf("[ar908]   DEBUG 0x%llX filtered out by the accessor prefilter\n",
                    (unsigned long long)Dbg);
            continue;
        }
        ++Tried;
        GetFNameInfo908 I = ExtractGetFName908(Scanner, G.first);
        if (Dbg && G.first == Dbg)
            std::printf("[ar908]   DEBUG 0x%llX: %s (seed 0x%llX, hash %zu ops, "
                        "xor %u, base 0x%llX, stride 0x%llX, dec 0x%llX, "
                        "key 0x%llX, pshuflw 0x%X, rol %d/%d)\n",
                (unsigned long long)G.first, I.Valid ? "VALID" : (I.Reject ? I.Reject : "?"),
                (unsigned long long)I.SeedOff, I.Hash.size(), I.SlotXor,
                (unsigned long long)I.SlotBase, (unsigned long long)I.SlotStride,
                (unsigned long long)I.DecoderRva, (unsigned long long)I.KeyLo64,
                I.PshuflwImm, I.Rol64Intra, I.FinalRol);
        if (!I.Valid) { ++Rejects[I.Reject ? I.Reject : "?"]; continue; }
        switch (I.Which) {
            case GetFNameInfo908::Role::Name:  Names.push_back(I);   break;
            case GetFNameInfo908::Role::Class: Classes.push_back(I); break;
            case GetFNameInfo908::Role::Outer: Outers.push_back(I);  break;
            default: break;
        }
    }
    std::printf("[ar908] %d accessor-shaped functions decoded: %zu Name, %zu Class, %zu Outer\n",
                Tried, Names.size(), Classes.size(), Outers.size());
    if (Names.empty()) {
        std::vector<std::pair<std::string, int>> R(Rejects.begin(), Rejects.end());
        std::sort(R.begin(), R.end(),
                  [](const auto& A, const auto& B) { return A.second > B.second; });
        for (size_t I = 0; I < R.size() && I < 6; ++I)
            std::printf("[ar908]   %6d x %s\n", R[I].second, R[I].first.c_str());
        return Best;
    }

    // Per-field majority across Name copies. Which copy is found first
    // carries no information; only the constants matter.
    auto Majority64 = [](const std::vector<GetFNameInfo908>& V,
                         uint64_t GetFNameInfo908::* M) -> uint64_t {
        std::unordered_map<uint64_t, int> C;
        for (const auto& I : V) ++C[I.*M];
        uint64_t B = 0; int N = -1;
        for (const auto& [K, Cnt] : C) if (Cnt > N) { N = Cnt; B = K; }
        return B;
    };
    auto Majority32 = [](const std::vector<GetFNameInfo908>& V,
                         uint32_t GetFNameInfo908::* M) -> uint32_t {
        std::unordered_map<uint32_t, int> C;
        for (const auto& I : V) ++C[I.*M];
        uint32_t B = 0; int N = -1;
        for (const auto& [K, Cnt] : C) if (Cnt > N) { N = Cnt; B = K; }
        return B;
    };
    auto MajorityInt = [](const std::vector<GetFNameInfo908>& V,
                          int GetFNameInfo908::* M) -> int {
        std::unordered_map<int, int> C;
        for (const auto& I : V) ++C[I.*M];
        int B = 0, N = -1;
        for (const auto& [K, Cnt] : C) if (Cnt > N) { N = Cnt; B = K; }
        return B;
    };

    Best = Names.front();
    Best.SeedOff    = Majority64(Names, &GetFNameInfo908::SeedOff);
    Best.SlotBase   = Majority64(Names, &GetFNameInfo908::SlotBase);
    Best.SlotStride = Majority64(Names, &GetFNameInfo908::SlotStride);
    Best.KeyLo64    = Majority64(Names, &GetFNameInfo908::KeyLo64);
    Best.SlotXor    = Majority32(Names, &GetFNameInfo908::SlotXor);
    Best.IdxAdd     = Majority32(Names, &GetFNameInfo908::IdxAdd);
    Best.PshuflwImm = MajorityInt(Names, &GetFNameInfo908::PshuflwImm);
    Best.Rol64Intra = MajorityInt(Names, &GetFNameInfo908::Rol64Intra);
    Best.FinalRol   = MajorityInt(Names, &GetFNameInfo908::FinalRol);
    // PSHUFB mask: pick the mode.
    {
        std::unordered_map<uint64_t, int> C;
        for (const auto& I : Names) {
            uint64_t Key = 0; std::memcpy(&Key, I.Pshufb, 8);
            ++C[Key];
        }
        uint64_t Mode = 0; int N = -1;
        for (const auto& [K, Cnt] : C) if (Cnt > N) { N = Cnt; Mode = K; }
        std::memcpy(Best.Pshufb, &Mode, 8);
    }
    Best.Copies = (int)Names.size();
    Best.Valid  = true;
    return Best;
}

// ─────────────────────────────────────────────────────────────────────────────
// FField::NamePrivate, from the PropertyBool.cpp assert path.
//
// Same anchor as v818 — the CoreUObject source-path strings are the cheapest
// high-value anchor in the image and Theia has not touched them. The decode
// SHAPE differs (v908 is PSHUFB → XOR → ROL16 → ROL64, v818 was XOR → PADDD),
// so extract fields individually rather than by op sequence.
//
// sizeof(FProperty) is NOT derived from the FieldMask offset on v908: the
// FBoolProperty extended slot starts at +0x118 while sizeof(FProperty) is
// 0x100. Keep FProp908Sizeof at its compiled default.
// ─────────────────────────────────────────────────────────────────────────────
struct FFieldNameInfo908 {
    bool     Valid = false;
    uint64_t Rva     = 0;
    uint64_t NameOff = 0;
    uint64_t KeyRva  = 0;
    uint64_t PshufRva = 0;
    uint64_t Key     = 0;
    uint8_t  Pshufb[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    int      Rol16   = 0;
    int      Rol64   = 0;
    uint64_t FieldMaskOff = 0;    // reported only; not used to derive sizeof
};

inline FFieldNameInfo908 ExtractFFieldName908(const SigScanV2::Scanner& Scanner,
                                              const AutoDiscovery::ModuleBounds& Bounds)
{
    FFieldNameInfo908 Best;
    uint64_t Str = AutoResolve818::FindStringStart(Scanner, Bounds, "PropertyBool.cpp");
    if (!Str) {
        std::printf("[ar908] PropertyBool.cpp not found in .rdata\n");
        return Best;
    }
    auto Refs = AutoResolve818::FindRipRefs(Scanner, Bounds, Str);
    std::printf("[ar908] PropertyBool.cpp @ 0x%llX, %zu rip references\n",
                (unsigned long long)Str, Refs.size());

    for (uint64_t R : Refs) {
        uint64_t Func = FuncAnalyze::FindFunctionStart(Scanner, R);
        if (!Func || R <= Func) continue;
        auto Insns = FuncAnalyze::DecodeWindowAt(Scanner, Func,
                                                 (size_t)(R - Func) + 64);
        FFieldNameInfo908 I;
        I.Rva = Func;

        // Track rip-loaded xmm constants; the pxor / pshufb often reach the
        // decode through a register loaded in the prologue.
        uint64_t XmmConst[16] = {};
        for (const auto& In : Insns) {
            if (In.type == INSN_MOVDQA && In.hasRipRel && In.reg1 < 16)
                XmmConst[In.reg1] = In.ResolveRipRVA();
        }

        for (size_t K = 0; K + 1 < Insns.size(); ++K) {
            const auto& In = Insns[K];

            // Name load — movdqa from a struct displacement in the FField.
            if (In.type == INSN_MOVDQA && !In.hasRipRel && !I.NameOff) {
                uint64_t D = 0;
                if (!AutoResolve818::Detail::ReadMovdqaDisp(Scanner, In.rva,
                                                             In.length, D)) continue;
                if (D < 0x20 || D > 0x300) continue;
                I.NameOff = D;
                continue;
            }
            if (!I.NameOff) continue;

            if (In.type == INSN_PXOR && !I.KeyRva) {
                uint64_t T = In.hasRipRel ? In.ResolveRipRVA()
                           : (In.reg2 < 16 ? XmmConst[In.reg2] : 0);
                if (T) I.KeyRva = T;
            }
            if (In.type == INSN_PSLLW && In.hasImm8 && !I.Rol16) I.Rol16 = In.imm8;
            if (In.type == INSN_PSHUFB && !I.PshufRva) {
                uint64_t T = In.hasRipRel ? In.ResolveRipRVA()
                           : (In.reg2 < 16 ? XmmConst[In.reg2] : 0);
                if (T) I.PshufRva = T;
            }
            if (In.type == INSN_ROL && In.hasImm8 && !I.Rol64) I.Rol64 = In.imm8;

            // Report the FieldMask offset if we see it — for diagnostics only.
            // On v908 sizeof(FProperty) is NOT FieldMask-3; the FBoolProperty
            // extended slot sits at +0x118 while sizeof is 0x100. Any code
            // that reads this must not derive sizeof from it.
            const uint8_t* P = Scanner.GetLocalPtr(In.rva);
            if (P && In.length >= 4) {
                int Q = ((P[0] & 0xF0) == 0x40) ? 1 : 0;
                if (P[Q] == 0x80 && ((P[Q + 1] >> 3) & 7) == 7 &&
                    P[In.length - 1] == 0xFF)
                {
                    uint64_t D = 0;
                    if (AutoResolve818::Detail::MemDisp(P, Q + 1, D) &&
                        D >= 0x40 && D <= 0x400)
                        I.FieldMaskOff = D;
                }
            }
        }

        if (!I.NameOff || !I.KeyRva || !I.Rol16) continue;
        const uint8_t* A = Scanner.GetLocalPtr(I.KeyRva);
        if (!A) continue;
        std::memcpy(&I.Key, A, 8);
        if (I.PshufRva) {
            const uint8_t* M = Scanner.GetLocalPtr(I.PshufRva);
            if (M) std::memcpy(I.Pshufb, M, 8);
        }
        if (!I.Rol64) I.Rol64 = 32;
        I.Valid = true;

        if (!Best.Valid || (I.FieldMaskOff && !Best.FieldMaskOff)) Best = I;
        if (Best.FieldMaskOff) break;
    }
    return Best;
}

// ─────────────────────────────────────────────────────────────────────────────
// FProperty::SetupOffset — reuse the v818 extractor verbatim. The
// `0F B7 ?? ?? 35 ?? ?? ?? ?? 0F C8 89 ?? ?? ?? ?? ??` idiom is 1-hit
// durable across all 13 builds surveyed on this project.
// ─────────────────────────────────────────────────────────────────────────────
using PropertyOffsetInfo908 = AutoResolve818::PropertyOffsetInfo;

inline PropertyOffsetInfo908 ExtractPropertyOffset908(const SigScanV2::Scanner& Scanner,
                                                     const AutoDiscovery::ModuleBounds& Bounds)
{
    return AutoResolve818::ExtractPropertyOffset(Scanner, Bounds);
}

// ─────────────────────────────────────────────────────────────────────────────
// Struct layout — reuse the v818 probe verbatim. Pipeline-agnostic: it uses
// live IMemoryReader + FieldName/PropOffset callbacks, and its scoring rules
// (DISTINCT names, ascending Offset_Internal, tagged Owner back-pointer) hold
// regardless of which decode is currently installed.
//
// This is only a stub in this namespace; the caller in main.cpp
// (ProbeAndAdopt908Layout) drives it after areas 4+5 have been adopted,
// because both the FField name decode and the Offset_Internal xor have to
// be in place before the probe can score candidates.
// ─────────────────────────────────────────────────────────────────────────────
using LayoutProbe908 = AutoResolve818::LayoutProbe;

inline LayoutProbe908 ProbeLayout908(IMemoryReader& Reader,
                                     const std::vector<uint64_t>& Structs,
                                     const std::function<std::string(uint64_t)>& FieldName,
                                     const std::function<uint32_t(uint64_t)>& PropOffset,
                                     const std::function<bool(uint64_t)>& IsTypeObject)
{
    return AutoResolve818::ProbeLayout(Reader, Structs, FieldName, PropOffset, IsTypeObject);
}

} // namespace AutoResolve908
