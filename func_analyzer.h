#pragma once

// =============================================================================
// func_analyzer.h — instruction-stream helpers built on Zydis + SigScanV2.
// Ported from ArcAutoDiscovery::auto_config_helpers.h.
//
// Useful primitives for autodiscovery phases:
//   - FindFunctionStart(scanner, code_rva)  — back-walk to CC padding
//   - FindFunctionEnd  (scanner, start_rva) — forward-walk to CC CC
//   - DecodeFunctionAt (scanner, code_rva)  — Zydis-decode whole fn
//   - DecodeWindowAt   (scanner, hit_rva, n) — decode N bytes at hit
//   - LeaTarget / FindLeaTargets — extract every LEA RIP-rel target in a fn
//   - VEX-aware PSHUFLW scanner   — covers both legacy + VEX encodings
//   - REX-aware SSE scanner       — covers `F2 0F ..` and `F2 4? 0F ..`
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include "insn_decoder.h"
#include "sig_scanner_v2.h"

namespace FuncAnalyze {

// ─────────────────────────────────────────────────────────────────────────────
// Function bounds — back-walk to CC padding (MSVC inserts INT3 between fns)
// ─────────────────────────────────────────────────────────────────────────────
inline uint64_t FindFunctionStart(const SigScanV2::Scanner& scanner, uint64_t codeRVA) {
    if (codeRVA < 16) return codeRVA;
    uint64_t limit = (codeRVA > 0x2000) ? codeRVA - 0x2000 : 0;
    for (uint64_t addr = codeRVA - 1; addr > limit; --addr) {
        if (!scanner.IsPageValid(addr)) {
            uint64_t pageStart = addr & ~(uint64_t)0xFFF;
            if (pageStart <= limit) break;
            addr = pageStart;
            continue;
        }
        const uint8_t* p = scanner.GetLocalPtr(addr);
        if (!p) continue;
        if (*p == 0xCC) {
            uint64_t start = addr + 1;
            const uint8_t* sp = scanner.GetLocalPtr(start);
            while (start < codeRVA && sp && *sp == 0xCC) { ++start; sp = scanner.GetLocalPtr(start); }
            return start;
        }
    }
    return codeRVA;
}

inline uint64_t FindFunctionEnd(const SigScanV2::Scanner& scanner,
                                uint64_t startRVA, uint64_t maxLen = 0x4000)
{
    uint64_t end = startRVA + maxLen;
    if (end > scanner.ModuleSize()) end = scanner.ModuleSize();
    for (uint64_t addr = startRVA; addr + 1 < end; ++addr) {
        const uint8_t* p = scanner.GetLocalPtr(addr);
        if (!p) continue;
        if (p[0] == 0xCC && (addr + 1 < end) && (scanner.GetLocalPtr(addr + 1) ?
            scanner.GetLocalPtr(addr + 1)[0] == 0xCC : false))
            return addr;
    }
    return end;
}

// Decode a function's instructions given an RVA inside it.
inline std::vector<DecodedInsn> DecodeFunctionAt(const SigScanV2::Scanner& scanner,
                                                  uint64_t codeRVA,
                                                  uint64_t maxLen = 0x1000)
{
    static thread_local FuncAnalyzer fa;
    uint64_t funcStart = FindFunctionStart(scanner, codeRVA);
    uint64_t funcEnd   = FindFunctionEnd(scanner, funcStart, maxLen);
    uint64_t funcLen   = funcEnd - funcStart;
    if (funcLen > maxLen) funcLen = maxLen;
    const uint8_t* buf = scanner.GetLocalPtr(funcStart);
    if (!buf) return {};
    return fa.DecodeAt(buf, (size_t)funcLen, funcStart);
}

// Decode a window of instructions around a hit RVA.
inline std::vector<DecodedInsn> DecodeWindowAt(const SigScanV2::Scanner& scanner,
                                                uint64_t hitRVA,
                                                size_t windowBytes = 256)
{
    static thread_local FuncAnalyzer fa;
    const uint8_t* buf = scanner.GetLocalPtr(hitRVA);
    if (!buf) return {};
    return fa.DecodeAt(buf, windowBytes, hitRVA);
}

// ─────────────────────────────────────────────────────────────────────────────
// Find every LEA r64,[rip+disp32] in a decoded fn whose target is in .data
// (or any section if wantData=false). Returns {idx, target_rva} pairs.
// ─────────────────────────────────────────────────────────────────────────────
struct LeaTarget {
    int      InsnIdx   = 0;
    uint64_t TargetRVA = 0;
};
inline std::vector<LeaTarget> FindLeaTargets(const std::vector<DecodedInsn>& insns,
                                             const SigScanV2::Scanner& scanner,
                                             bool wantData = true)
{
    std::vector<LeaTarget> out;
    for (int i = 0; i < (int)insns.size(); ++i) {
        const auto& ins = insns[i];
        if (ins.type != INSN_LEA || !ins.hasRipRel) continue;
        uint64_t t = ins.ResolveRipRVA();
        if (wantData) {
            if (scanner.IsDataRVA(t) || scanner.IsRDataRVA(t)) out.push_back({i, t});
        } else {
            out.push_back({i, t});
        }
    }
    return out;
}

// Find every PSHUFB / PXOR / PAND / PANDN / XORPS that has a RIP-rel operand,
// resolved to their target RVAs in .rdata (the SIMD constant tables).
struct SimdRipTarget {
    int        InsnIdx;
    InsnType   Type;
    uint64_t   TargetRVA;
};
inline std::vector<SimdRipTarget>
FindSimdRipTargets(const std::vector<DecodedInsn>& insns,
                   const SigScanV2::Scanner& scanner)
{
    std::vector<SimdRipTarget> out;
    for (int i = 0; i < (int)insns.size(); ++i) {
        const auto& ins = insns[i];
        if (!ins.hasRipRel) continue;
        switch (ins.type) {
            case INSN_PSHUFB:
            case INSN_PXOR:
            case INSN_XORPS:
            case INSN_PAND:
            case INSN_PANDN:
            case INSN_POR:
            case INSN_MOVDQA:
            case INSN_MOVAPS:
            case INSN_MOVQ:
            case INSN_LOADL_EPI64:
                out.push_back({i, ins.type, ins.ResolveRipRVA()});
                break;
            default: break;
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Extract a packed shift pair as a ROL32 (PSLLD imm + PSRLD imm where sum=32).
// Returns the SHL amount, or 0 if no matching pair found near startIdx.
// ─────────────────────────────────────────────────────────────────────────────
inline int FindRol32Pair(const std::vector<DecodedInsn>& insns, int startIdx,
                         int range = 6)
{
    int end = std::min((int)insns.size(), startIdx + range);
    for (int i = startIdx; i < end; ++i) {
        if (insns[i].type == INSN_PSLLD && insns[i].hasImm8) {
            int shl = insns[i].imm8;
            for (int j = i + 1; j < std::min((int)insns.size(), i + 4); ++j) {
                if (insns[j].type == INSN_PSRLD && insns[j].hasImm8) {
                    int shr = insns[j].imm8;
                    if (shl + shr == 32) return shl;
                }
            }
        }
        if (insns[i].type == INSN_PSRLD && insns[i].hasImm8) {
            int shr = insns[i].imm8;
            for (int j = i + 1; j < std::min((int)insns.size(), i + 4); ++j) {
                if (insns[j].type == INSN_PSLLD && insns[j].hasImm8) {
                    int shl = insns[j].imm8;
                    if (shl + shr == 32) return shl;
                }
            }
        }
    }
    return 0;
}

// Same for ROL16 (PSLLW + PSRLW) and ROL64 (PSLLQ + PSRLQ).
inline int FindRol16Pair(const std::vector<DecodedInsn>& insns, int startIdx,
                         int range = 6)
{
    int end = std::min((int)insns.size(), startIdx + range);
    for (int i = startIdx; i < end; ++i) {
        if (insns[i].type == INSN_PSLLW && insns[i].hasImm8) {
            int shl = insns[i].imm8;
            for (int j = i + 1; j < std::min((int)insns.size(), i + 4); ++j) {
                if (insns[j].type == INSN_PSRLW && insns[j].hasImm8 &&
                    shl + insns[j].imm8 == 16) return shl;
            }
        }
    }
    return 0;
}
inline int FindRol64Pair(const std::vector<DecodedInsn>& insns, int startIdx,
                         int range = 6)
{
    int end = std::min((int)insns.size(), startIdx + range);
    for (int i = startIdx; i < end; ++i) {
        if (insns[i].type == INSN_PSLLQ && insns[i].hasImm8) {
            int shl = insns[i].imm8;
            for (int j = i + 1; j < std::min((int)insns.size(), i + 4); ++j) {
                if (insns[j].type == INSN_PSRLQ && insns[j].hasImm8 &&
                    shl + insns[j].imm8 == 64) return shl;
            }
        }
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Collect all MOV r64, imm64 instructions in a function body — useful for
// extracting hardcoded scalar XOR keys (e.g. ENTRY_HANDLE_XOR, FNV64_OFFSET).
// ─────────────────────────────────────────────────────────────────────────────
struct MovImm64 {
    int      InsnIdx;
    uint64_t Value;
};
inline std::vector<MovImm64> FindMovImm64(const std::vector<DecodedInsn>& insns) {
    std::vector<MovImm64> out;
    for (int i = 0; i < (int)insns.size(); ++i) {
        if (insns[i].type == INSN_MOV_REG && insns[i].imm64 != 0 &&
            insns[i].length == 10 /* REX.W + B8+rd + imm64 */) {
            out.push_back({i, insns[i].imm64});
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// REX-aware SSE prefix scanner. Patterns starting with `F2 0F`, `F3 0F`, or
// `66 0F` may also appear as `F2 4X 0F`, `F3 4X 0F`, `66 4X 0F` (REX.B/R).
// ─────────────────────────────────────────────────────────────────────────────
inline std::vector<uint64_t> ScanWithRex(const SigScanV2::Scanner& scanner,
                                          const std::string& basePat,
                                          const char* section = ".text")
{
    auto results = scanner.ScanSection(basePat, section);
    size_t firstSpace = basePat.find(' ');
    if (firstSpace == 2) {
        bool ssePrefix =
            (basePat[0] == 'F' && (basePat[1] == '2' || basePat[1] == '3')) ||
            (basePat[0] == '6' && basePat[1] == '6');
        if (ssePrefix) {
            std::string prefix = basePat.substr(0, firstSpace);
            std::string rest   = basePat.substr(firstSpace);
            const uint8_t rexBytes[] = { 0x41, 0x44, 0x45 };
            for (uint8_t rex : rexBytes) {
                char rexStr[8];
                std::snprintf(rexStr, sizeof(rexStr), " %02X", rex);
                auto more = scanner.ScanSection(prefix + rexStr + rest, section);
                results.insert(results.end(), more.begin(), more.end());
            }
        }
    }
    std::sort(results.begin(), results.end());
    return results;
}

// VEX-encoded PSHUFLW with given immediate. Covers both 2-byte (C5) and
// 3-byte (C4) VEX prefixes; filters by checking pp=11, L=0.
inline std::vector<uint64_t> ScanVexPshuflw(const SigScanV2::Scanner& scanner,
                                             uint8_t imm,
                                             const char* section = ".text")
{
    std::vector<uint64_t> results;
    char pat[32];

    std::snprintf(pat, sizeof(pat), "C5 ?? 70 ?? %02X", imm);
    auto h2 = scanner.ScanSection(pat, section);
    for (auto rva : h2) {
        const uint8_t* p = scanner.GetLocalPtr(rva);
        if (!p) continue;
        // VEX byte1: bit2=L (must be 0), bits[1:0]=pp (must be 11)
        if ((p[1] & 0x07) == 0x03) results.push_back(rva);
    }

    std::snprintf(pat, sizeof(pat), "C4 ?? ?? 70 ?? %02X", imm);
    auto h3 = scanner.ScanSection(pat, section);
    for (auto rva : h3) {
        const uint8_t* p = scanner.GetLocalPtr(rva);
        if (!p) continue;
        if ((p[2] & 0x07) == 0x03) results.push_back(rva);
    }
    return results;
}

// All PSHUFLW encodings (legacy + REX + VEX) with a given immediate.
inline std::vector<uint64_t> ScanAllPshuflw(const SigScanV2::Scanner& scanner,
                                             uint8_t imm,
                                             const char* section = ".text")
{
    char pat[32];
    std::snprintf(pat, sizeof(pat), "F2 0F 70 ?? %02X", imm);
    auto base = ScanWithRex(scanner, pat, section);
    auto vex  = ScanVexPshuflw(scanner, imm, section);
    base.insert(base.end(), vex.begin(), vex.end());
    std::sort(base.begin(), base.end());
    return base;
}

}  // namespace FuncAnalyze
