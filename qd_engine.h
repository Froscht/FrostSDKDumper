#pragma once
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

#include "func_analyzer.h"

enum QDOp : uint8_t {
    QD_NOP = 0,
    QD_ROL64,
    QD_ROL32,
    QD_ROL16,
    QD_XOR64,
    QD_XOR128,
    QD_PSHUFLW,
    QD_PSHUFHW,
    QD_PSHUFB,
    QD_PSHUFD,
    QD_BSWAP64,
    QD_BSWAP32,
    QD_MOVQ,
    QD_PADDD,
    QD_PADDQ,
    QD_PSUBD,
    QD_PSUBQ,
    QD_PAND128,
    QD_POR128,
};

struct QDInstruction {
    QDOp Op = QD_NOP;
    uint8_t Imm8 = 0;
    uint64_t Imm64 = 0;
    uint64_t Imm64Hi = 0;
    uint8_t Mask[16] = {};
};

struct QDProgram {
    static constexpr int MAX_OPS = 48;
    QDInstruction Ops[MAX_OPS] = {};
    int OpCount = 0;
    bool Valid = false;
    uint64_t SourceRva = 0;
    int InputOffset = 0;
    int InputSize = 16;
};

struct QDResult {
    uint64_t Lo = 0, Hi = 0;
};


static inline uint32_t QDRotl32(uint32_t X, int N) { N &= 31; return (X << N) | (X >> (32 - N)); }
static inline uint64_t QDRotl64(uint64_t X, int N) { N &= 63; return (X << N) | (X >> (64 - N)); }

static inline uint64_t QDSoftPshuflw(uint64_t V, int Imm) {
    uint16_t W[4];
    std::memcpy(W, &V, 8);
    uint16_t R[4] = {
        W[(Imm >> 0) & 3], W[(Imm >> 2) & 3],
        W[(Imm >> 4) & 3], W[(Imm >> 6) & 3]
    };
    uint64_t Out;
    std::memcpy(&Out, R, 8);
    return Out;
}


static inline QDResult QDExecute(const QDProgram& Prog, const uint8_t Input[16]) {
    QDResult S;
    std::memcpy(&S.Lo, Input, 8);
    std::memcpy(&S.Hi, Input + 8, 8);

    for (int I = 0; I < Prog.OpCount; I++) {
        const auto& Op = Prog.Ops[I];
        switch (Op.Op) {
        case QD_ROL64:
            S.Lo = QDRotl64(S.Lo, Op.Imm8);
            S.Hi = QDRotl64(S.Hi, Op.Imm8);
            break;
        case QD_ROL32: {
            uint32_t D[4] = {
                QDRotl32((uint32_t)S.Lo, Op.Imm8),
                QDRotl32((uint32_t)(S.Lo >> 32), Op.Imm8),
                QDRotl32((uint32_t)S.Hi, Op.Imm8),
                QDRotl32((uint32_t)(S.Hi >> 32), Op.Imm8)
            };
            S.Lo = (uint64_t)D[0] | ((uint64_t)D[1] << 32);
            S.Hi = (uint64_t)D[2] | ((uint64_t)D[3] << 32);
            break;
        }
        case QD_ROL16: {
            uint16_t W[8];
            std::memcpy(W, &S.Lo, 8);
            std::memcpy(W + 4, &S.Hi, 8);
            int N = Op.Imm8 & 15;
            for (int J = 0; J < 8; J++)
                W[J] = (uint16_t)((W[J] << N) | (W[J] >> (16 - N)));
            std::memcpy(&S.Lo, W, 8);
            std::memcpy(&S.Hi, W + 4, 8);
            break;
        }
        case QD_XOR64:
            S.Lo ^= Op.Imm64;
            break;
        case QD_XOR128:
            S.Lo ^= Op.Imm64;
            S.Hi ^= Op.Imm64Hi;
            break;
        case QD_PSHUFLW:
            S.Lo = QDSoftPshuflw(S.Lo, Op.Imm8);
            break;
        case QD_PSHUFHW:
            S.Hi = QDSoftPshuflw(S.Hi, Op.Imm8);
            break;
        case QD_PSHUFB: {
            uint8_t In[16], Out[16];
            std::memcpy(In, &S.Lo, 8);
            std::memcpy(In + 8, &S.Hi, 8);
            for (int J = 0; J < 16; J++)
                Out[J] = (Op.Mask[J] & 0x80) ? 0 : In[Op.Mask[J] & 15];
            std::memcpy(&S.Lo, Out, 8);
            std::memcpy(&S.Hi, Out + 8, 8);
            break;
        }
        case QD_PSHUFD: {
            uint32_t D[4] = {
                (uint32_t)S.Lo, (uint32_t)(S.Lo >> 32),
                (uint32_t)S.Hi, (uint32_t)(S.Hi >> 32)
            };
            uint32_t R[4] = {
                D[(Op.Imm8 >> 0) & 3], D[(Op.Imm8 >> 2) & 3],
                D[(Op.Imm8 >> 4) & 3], D[(Op.Imm8 >> 6) & 3]
            };
            S.Lo = (uint64_t)R[0] | ((uint64_t)R[1] << 32);
            S.Hi = (uint64_t)R[2] | ((uint64_t)R[3] << 32);
            break;
        }
        case QD_BSWAP64:
            S.Lo = __builtin_bswap64(S.Lo);
            S.Hi = __builtin_bswap64(S.Hi);
            break;
        case QD_BSWAP32: {
            uint32_t D[4] = {
                __builtin_bswap32((uint32_t)S.Lo),
                __builtin_bswap32((uint32_t)(S.Lo >> 32)),
                __builtin_bswap32((uint32_t)S.Hi),
                __builtin_bswap32((uint32_t)(S.Hi >> 32))
            };
            S.Lo = (uint64_t)D[0] | ((uint64_t)D[1] << 32);
            S.Hi = (uint64_t)D[2] | ((uint64_t)D[3] << 32);
            break;
        }
        case QD_MOVQ:
            S.Hi = 0;
            break;
        case QD_PADDD: {
            uint32_t A[4] = {
                (uint32_t)S.Lo, (uint32_t)(S.Lo >> 32),
                (uint32_t)S.Hi, (uint32_t)(S.Hi >> 32)
            };
            uint32_t B[4] = {
                (uint32_t)Op.Imm64, (uint32_t)(Op.Imm64 >> 32),
                (uint32_t)Op.Imm64Hi, (uint32_t)(Op.Imm64Hi >> 32)
            };
            for (int J = 0; J < 4; J++) A[J] += B[J];
            S.Lo = (uint64_t)A[0] | ((uint64_t)A[1] << 32);
            S.Hi = (uint64_t)A[2] | ((uint64_t)A[3] << 32);
            break;
        }
        case QD_PADDQ:
            S.Lo += Op.Imm64;
            S.Hi += Op.Imm64Hi;
            break;
        case QD_PSUBD: {
            uint32_t A[4] = {
                (uint32_t)S.Lo, (uint32_t)(S.Lo >> 32),
                (uint32_t)S.Hi, (uint32_t)(S.Hi >> 32)
            };
            uint32_t B[4] = {
                (uint32_t)Op.Imm64, (uint32_t)(Op.Imm64 >> 32),
                (uint32_t)Op.Imm64Hi, (uint32_t)(Op.Imm64Hi >> 32)
            };
            for (int J = 0; J < 4; J++) A[J] -= B[J];
            S.Lo = (uint64_t)A[0] | ((uint64_t)A[1] << 32);
            S.Hi = (uint64_t)A[2] | ((uint64_t)A[3] << 32);
            break;
        }
        case QD_PSUBQ:
            S.Lo -= Op.Imm64;
            S.Hi -= Op.Imm64Hi;
            break;
        case QD_PAND128:
            S.Lo &= Op.Imm64;
            S.Hi &= Op.Imm64Hi;
            break;
        case QD_POR128:
            S.Lo |= Op.Imm64;
            S.Hi |= Op.Imm64Hi;
            break;
        case QD_NOP:
        default:
            break;
        }
    }
    return S;
}


static inline const char* QDOpName(QDOp Op) {
    switch (Op) {
    case QD_NOP:      return "NOP";
    case QD_ROL64:    return "ROL64";
    case QD_ROL32:    return "ROL32";
    case QD_ROL16:    return "ROL16";
    case QD_XOR64:    return "XOR64";
    case QD_XOR128:   return "XOR128";
    case QD_PSHUFLW:  return "PSHUFLW";
    case QD_PSHUFHW:  return "PSHUFHW";
    case QD_PSHUFB:   return "PSHUFB";
    case QD_PSHUFD:   return "PSHUFD";
    case QD_BSWAP64:  return "BSWAP64";
    case QD_BSWAP32:  return "BSWAP32";
    case QD_MOVQ:     return "MOVQ";
    case QD_PADDD:    return "PADDD";
    case QD_PADDQ:    return "PADDQ";
    case QD_PSUBD:    return "PSUBD";
    case QD_PSUBQ:    return "PSUBQ";
    case QD_PAND128:  return "PAND";
    case QD_POR128:   return "POR";
    default:          return "?";
    }
}

inline std::string QDProgramToString(const QDProgram& Prog) {
    std::string Out;
    for (int I = 0; I < Prog.OpCount; I++) {
        if (I > 0) Out += " -> ";
        const auto& Op = Prog.Ops[I];
        char Buf[256];
        switch (Op.Op) {
        case QD_ROL64: case QD_ROL32: case QD_ROL16:
            std::snprintf(Buf, sizeof(Buf), "%s(%d)", QDOpName(Op.Op), Op.Imm8);
            break;
        case QD_PSHUFLW: case QD_PSHUFHW: case QD_PSHUFD:
            std::snprintf(Buf, sizeof(Buf), "%s(0x%02X)", QDOpName(Op.Op), Op.Imm8);
            break;
        case QD_XOR64:
            std::snprintf(Buf, sizeof(Buf), "XOR64(0x%llX)", (unsigned long long)Op.Imm64);
            break;
        case QD_XOR128:
            std::snprintf(Buf, sizeof(Buf), "XOR128(0x%llX,0x%llX)",
                (unsigned long long)Op.Imm64, (unsigned long long)Op.Imm64Hi);
            break;
        case QD_PSHUFB:
            std::snprintf(Buf, sizeof(Buf),
                "PSHUFB([%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X])",
                Op.Mask[0],Op.Mask[1],Op.Mask[2],Op.Mask[3],
                Op.Mask[4],Op.Mask[5],Op.Mask[6],Op.Mask[7],
                Op.Mask[8],Op.Mask[9],Op.Mask[10],Op.Mask[11],
                Op.Mask[12],Op.Mask[13],Op.Mask[14],Op.Mask[15]);
            break;
        default:
            std::snprintf(Buf, sizeof(Buf), "%s", QDOpName(Op.Op));
            break;
        }
        Out += Buf;
    }
    return Out;
}


inline std::string QDProgramToC(const QDProgram& Prog, const char* FuncName) {
    std::string S;
    char Buf[512];

    std::snprintf(Buf, sizeof(Buf),
        "static inline uint64_t %s(const uint8_t Enc[16]) {\n"
        "    uint64_t Lo, Hi;\n"
        "    memcpy(&Lo, Enc, 8);\n"
        "    memcpy(&Hi, Enc + 8, 8);\n", FuncName);
    S += Buf;

    for (int I = 0; I < Prog.OpCount; I++) {
        const auto& Op = Prog.Ops[I];
        switch (Op.Op) {
        case QD_ROL64:
            std::snprintf(Buf, sizeof(Buf),
                "    Lo = Rotl64(Lo, %d); Hi = Rotl64(Hi, %d);\n", Op.Imm8, Op.Imm8);
            S += Buf;
            break;
        case QD_ROL32:
            std::snprintf(Buf, sizeof(Buf),
                "    { uint32_t D0=Rotl32((uint32_t)Lo,%d), D1=Rotl32((uint32_t)(Lo>>32),%d),\n"
                "               D2=Rotl32((uint32_t)Hi,%d), D3=Rotl32((uint32_t)(Hi>>32),%d);\n"
                "      Lo=(uint64_t)D0|((uint64_t)D1<<32); Hi=(uint64_t)D2|((uint64_t)D3<<32); }\n",
                Op.Imm8, Op.Imm8, Op.Imm8, Op.Imm8);
            S += Buf;
            break;
        case QD_ROL16:
            std::snprintf(Buf, sizeof(Buf),
                "    { uint16_t W[8]; memcpy(W,&Lo,8); memcpy(W+4,&Hi,8);\n"
                "      for(int i=0;i<8;i++) W[i]=(W[i]<<%d)|(W[i]>>%d);\n"
                "      memcpy(&Lo,W,8); memcpy(&Hi,W+4,8); }\n",
                Op.Imm8, 16 - Op.Imm8);
            S += Buf;
            break;
        case QD_XOR64:
            std::snprintf(Buf, sizeof(Buf),
                "    Lo ^= 0x%016llXULL;\n", (unsigned long long)Op.Imm64);
            S += Buf;
            break;
        case QD_XOR128:
            std::snprintf(Buf, sizeof(Buf),
                "    Lo ^= 0x%016llXULL; Hi ^= 0x%016llXULL;\n",
                (unsigned long long)Op.Imm64, (unsigned long long)Op.Imm64Hi);
            S += Buf;
            break;
        case QD_PSHUFLW:
            std::snprintf(Buf, sizeof(Buf),
                "    Lo = SoftPshuflw(Lo, 0x%02X);\n", Op.Imm8);
            S += Buf;
            break;
        case QD_PSHUFHW:
            std::snprintf(Buf, sizeof(Buf),
                "    Hi = SoftPshuflw(Hi, 0x%02X);\n", Op.Imm8);
            S += Buf;
            break;
        case QD_PSHUFB:
            std::snprintf(Buf, sizeof(Buf),
                "    { uint8_t M[16]={0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,"
                "0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X};\n"
                "      uint8_t In[16],Out[16]; memcpy(In,&Lo,8); memcpy(In+8,&Hi,8);\n"
                "      for(int i=0;i<16;i++) Out[i]=(M[i]&0x80)?0:In[M[i]&15];\n"
                "      memcpy(&Lo,Out,8); memcpy(&Hi,Out+8,8); }\n",
                Op.Mask[0],Op.Mask[1],Op.Mask[2],Op.Mask[3],
                Op.Mask[4],Op.Mask[5],Op.Mask[6],Op.Mask[7],
                Op.Mask[8],Op.Mask[9],Op.Mask[10],Op.Mask[11],
                Op.Mask[12],Op.Mask[13],Op.Mask[14],Op.Mask[15]);
            S += Buf;
            break;
        case QD_PSHUFD:
            std::snprintf(Buf, sizeof(Buf),
                "    { uint32_t D[4]={(uint32_t)Lo,(uint32_t)(Lo>>32),(uint32_t)Hi,(uint32_t)(Hi>>32)};\n"
                "      uint32_t R[4]={D[%d],D[%d],D[%d],D[%d]};\n"
                "      Lo=(uint64_t)R[0]|((uint64_t)R[1]<<32); Hi=(uint64_t)R[2]|((uint64_t)R[3]<<32); }\n",
                (Op.Imm8>>0)&3, (Op.Imm8>>2)&3, (Op.Imm8>>4)&3, (Op.Imm8>>6)&3);
            S += Buf;
            break;
        case QD_BSWAP64:
            S += "    Lo = Bswap64(Lo); Hi = Bswap64(Hi);\n";
            break;
        case QD_BSWAP32:
            S += "    { uint32_t D0=Bswap32((uint32_t)Lo),D1=Bswap32((uint32_t)(Lo>>32)),"
                 "D2=Bswap32((uint32_t)Hi),D3=Bswap32((uint32_t)(Hi>>32));\n"
                 "      Lo=(uint64_t)D0|((uint64_t)D1<<32); Hi=(uint64_t)D2|((uint64_t)D3<<32); }\n";
            break;
        case QD_MOVQ:
            break;
        case QD_PADDD:
            std::snprintf(Buf, sizeof(Buf),
                "    { uint32_t A[4]={(uint32_t)Lo,(uint32_t)(Lo>>32),(uint32_t)Hi,(uint32_t)(Hi>>32)};\n"
                "      uint32_t B[4]={0x%Xu,0x%Xu,0x%Xu,0x%Xu};\n"
                "      for(int i=0;i<4;i++) A[i]+=B[i];\n"
                "      Lo=(uint64_t)A[0]|((uint64_t)A[1]<<32); Hi=(uint64_t)A[2]|((uint64_t)A[3]<<32); }\n",
                (unsigned)(uint32_t)Op.Imm64, (unsigned)(uint32_t)(Op.Imm64>>32),
                (unsigned)(uint32_t)Op.Imm64Hi, (unsigned)(uint32_t)(Op.Imm64Hi>>32));
            S += Buf;
            break;
        case QD_PADDQ:
            std::snprintf(Buf, sizeof(Buf),
                "    Lo += 0x%016llXULL; Hi += 0x%016llXULL;\n",
                (unsigned long long)Op.Imm64, (unsigned long long)Op.Imm64Hi);
            S += Buf;
            break;
        case QD_PSUBD:
            std::snprintf(Buf, sizeof(Buf),
                "    { uint32_t A[4]={(uint32_t)Lo,(uint32_t)(Lo>>32),(uint32_t)Hi,(uint32_t)(Hi>>32)};\n"
                "      uint32_t B[4]={0x%Xu,0x%Xu,0x%Xu,0x%Xu};\n"
                "      for(int i=0;i<4;i++) A[i]-=B[i];\n"
                "      Lo=(uint64_t)A[0]|((uint64_t)A[1]<<32); Hi=(uint64_t)A[2]|((uint64_t)A[3]<<32); }\n",
                (unsigned)(uint32_t)Op.Imm64, (unsigned)(uint32_t)(Op.Imm64>>32),
                (unsigned)(uint32_t)Op.Imm64Hi, (unsigned)(uint32_t)(Op.Imm64Hi>>32));
            S += Buf;
            break;
        case QD_PSUBQ:
            std::snprintf(Buf, sizeof(Buf),
                "    Lo -= 0x%016llXULL; Hi -= 0x%016llXULL;\n",
                (unsigned long long)Op.Imm64, (unsigned long long)Op.Imm64Hi);
            S += Buf;
            break;
        case QD_PAND128:
            std::snprintf(Buf, sizeof(Buf),
                "    Lo &= 0x%016llXULL; Hi &= 0x%016llXULL;\n",
                (unsigned long long)Op.Imm64, (unsigned long long)Op.Imm64Hi);
            S += Buf;
            break;
        case QD_POR128:
            std::snprintf(Buf, sizeof(Buf),
                "    Lo |= 0x%016llXULL; Hi |= 0x%016llXULL;\n",
                (unsigned long long)Op.Imm64, (unsigned long long)Op.Imm64Hi);
            S += Buf;
            break;
        case QD_NOP:
        default:
            break;
        }
    }

    S += "    return Lo;\n}\n";
    return S;
}


namespace QDRecord {

struct XmmState {
    bool Hot = false;
    bool IsConst = false;
    uint64_t ConstLo = 0;
    uint64_t ConstHi = 0;
};

static inline bool ReadConst128(const SigScanV2::Scanner& Scanner, uint64_t Rva,
                                uint64_t& Lo, uint64_t& Hi)
{
    const uint8_t* Ptr = Scanner.GetLocalPtr(Rva);
    if (!Ptr) return false;
    std::memcpy(&Lo, Ptr, 8);
    std::memcpy(&Hi, Ptr + 8, 8);
    return true;
}

static inline void LoadXmmConst(XmmState& X, const SigScanV2::Scanner& Scanner, uint64_t Rva) {
    X.IsConst = true;
    ReadConst128(Scanner, Rva, X.ConstLo, X.ConstHi);
}

}  // namespace QDRecord

struct QDRecordResult {
    QDProgram Program;
    int InputLoadIdx = -1;
    int OutputExtractIdx = -1;
};

inline QDRecordResult QDRecordSIMDChain(
    const std::vector<DecodedInsn>& Insns,
    int AnchorIdx,
    const SigScanV2::Scanner& Scanner)
{
    using namespace QDRecord;
    QDRecordResult Result;

    int LoadIdx = -1;
    uint8_t DataReg = 255;

    for (int I = AnchorIdx; I >= 0 && I >= AnchorIdx - 30; --I) {
        const auto& In = Insns[I];
        if ((In.type == INSN_MOVDQA || In.type == INSN_MOVAPS) &&
            !In.hasRipRel && In.hasImm32) {
            LoadIdx = I;
            DataReg = In.reg1;
            Result.Program.InputOffset = (int)(int32_t)In.imm32;
            break;
        }
    }

    if (LoadIdx < 0) {
        for (int I = AnchorIdx; I >= 0 && I >= AnchorIdx - 30; --I) {
            const auto& In = Insns[I];
            if ((In.type == INSN_MOVDQA || In.type == INSN_MOVAPS) &&
                !In.hasRipRel) {
                LoadIdx = I;
                DataReg = In.reg1;
                break;
            }
        }
    }

    if (LoadIdx < 0 || DataReg == 255) return Result;
    Result.InputLoadIdx = LoadIdx;
    Result.Program.SourceRva = Insns[AnchorIdx].rva;

    XmmState Xmm[16] = {};
    Xmm[DataReg].Hot = true;

    uint8_t CopySource[16] = {};
    bool HasCopy[16] = {};
    for (int J = 0; J < 16; J++) CopySource[J] = (uint8_t)J;

    auto Emit = [&](QDOp Op, uint8_t Imm8 = 0, uint64_t Imm64 = 0, uint64_t Imm64Hi = 0) -> bool {
        if (Result.Program.OpCount >= QDProgram::MAX_OPS) return false;
        auto& Inst = Result.Program.Ops[Result.Program.OpCount++];
        Inst.Op = Op;
        Inst.Imm8 = Imm8;
        Inst.Imm64 = Imm64;
        Inst.Imm64Hi = Imm64Hi;
        return true;
    };

    auto EmitMask = [&](QDOp Op, const uint8_t Mask[16]) -> bool {
        if (Result.Program.OpCount >= QDProgram::MAX_OPS) return false;
        auto& Inst = Result.Program.Ops[Result.Program.OpCount++];
        Inst.Op = Op;
        std::memcpy(Inst.Mask, Mask, 16);
        return true;
    };

    for (int I = LoadIdx + 1; I < (int)Insns.size(); I++) {
        const auto& In = Insns[I];

        if (In.type == INSN_RET || In.type == INSN_INT3) break;
        if (In.type == INSN_JMP || In.type == INSN_CALL_RIP) break;

        if ((In.type == INSN_MOVQ || In.type == INSN_MOVD) && Xmm[In.reg2].Hot) {
            Emit(QD_MOVQ);
            Result.OutputExtractIdx = I;
            break;
        }

        if ((In.type == INSN_MOVDQA || In.type == INSN_MOVAPS) && !In.hasRipRel && !In.hasImm32) {
            if (Xmm[In.reg2].Hot && !Xmm[In.reg1].Hot) {
                Xmm[In.reg1].Hot = true;
                HasCopy[In.reg1] = true;
                CopySource[In.reg1] = In.reg2;
            } else if (Xmm[In.reg1].Hot && !Xmm[In.reg2].Hot) {
                HasCopy[In.reg1] = true;
                CopySource[In.reg1] = DataReg;
            } else if (Xmm[In.reg2].IsConst) {
                Xmm[In.reg1].IsConst = true;
                Xmm[In.reg1].ConstLo = Xmm[In.reg2].ConstLo;
                Xmm[In.reg1].ConstHi = Xmm[In.reg2].ConstHi;
            }
            continue;
        }

        if ((In.type == INSN_MOVDQA || In.type == INSN_MOVAPS) && In.hasRipRel) {
            uint64_t Rva = In.ResolveRipRVA();
            LoadXmmConst(Xmm[In.reg1], Scanner, Rva);
            continue;
        }

        bool IsShift = false;
        switch (In.type) {
        case INSN_PSLLW: case INSN_PSRLW: case INSN_PSLLD: case INSN_PSRLD:
        case INSN_PSLLQ: case INSN_PSRLQ:
        case INSN_PSLLI_EPI16: case INSN_PSRLI_EPI16:
        case INSN_PSLLI_EPI32: case INSN_PSRLI_EPI32:
        case INSN_PSLLI_EPI64: case INSN_PSRLI_EPI64:
            IsShift = true; break;
        default: break;
        }

        if (IsShift && In.hasImm8 && Xmm[In.reg1].Hot) {
            int Rol = 0;
            switch (In.type) {
            case INSN_PSLLQ: case INSN_PSRLQ:
            case INSN_PSLLI_EPI64: case INSN_PSRLI_EPI64:
                Rol = FuncAnalyze::FindRol64Pair(Insns, I, 6);
                if (Rol > 0) { Emit(QD_ROL64, (uint8_t)Rol); I += 2; }
                break;
            case INSN_PSLLD: case INSN_PSRLD:
            case INSN_PSLLI_EPI32: case INSN_PSRLI_EPI32:
                Rol = FuncAnalyze::FindRol32Pair(Insns, I, 6);
                if (Rol > 0) { Emit(QD_ROL32, (uint8_t)Rol); I += 2; }
                break;
            case INSN_PSLLW: case INSN_PSRLW:
            case INSN_PSLLI_EPI16: case INSN_PSRLI_EPI16:
                Rol = FuncAnalyze::FindRol16Pair(Insns, I, 6);
                if (Rol > 0) { Emit(QD_ROL16, (uint8_t)Rol); I += 2; }
                break;
            default: break;
            }
            continue;
        }

        if (In.type == INSN_POR && (Xmm[In.reg1].Hot || Xmm[In.reg2].Hot)) {
            uint8_t HotReg = Xmm[In.reg1].Hot ? In.reg1 : In.reg2;
            uint8_t OtherReg = (HotReg == In.reg1) ? In.reg2 : In.reg1;

            if (Xmm[OtherReg].Hot && HasCopy[OtherReg]) {
                int PrevI = I - 1;
                while (PrevI > LoadIdx) {
                    bool Found = false;
                    switch (Insns[PrevI].type) {
                    case INSN_PSLLQ: case INSN_PSRLQ: case INSN_PSLLD: case INSN_PSRLD:
                    case INSN_PSLLW: case INSN_PSRLW:
                    case INSN_PSLLI_EPI16: case INSN_PSRLI_EPI16:
                    case INSN_PSLLI_EPI32: case INSN_PSRLI_EPI32:
                    case INSN_PSLLI_EPI64: case INSN_PSRLI_EPI64:
                        Found = true; break;
                    default: break;
                    }
                    if (Found) break;
                    --PrevI;
                }
                if (PrevI > LoadIdx) {
                    int Rol = 0;
                    switch (Insns[PrevI].type) {
                    case INSN_PSLLQ: case INSN_PSRLQ:
                    case INSN_PSLLI_EPI64: case INSN_PSRLI_EPI64:
                        Rol = FuncAnalyze::FindRol64Pair(Insns, PrevI - 1, 4);
                        if (Rol > 0) Emit(QD_ROL64, (uint8_t)Rol);
                        break;
                    case INSN_PSLLD: case INSN_PSRLD:
                    case INSN_PSLLI_EPI32: case INSN_PSRLI_EPI32:
                        Rol = FuncAnalyze::FindRol32Pair(Insns, PrevI - 1, 4);
                        if (Rol > 0) Emit(QD_ROL32, (uint8_t)Rol);
                        break;
                    case INSN_PSLLW: case INSN_PSRLW:
                    case INSN_PSLLI_EPI16: case INSN_PSRLI_EPI16:
                        Rol = FuncAnalyze::FindRol16Pair(Insns, PrevI - 1, 4);
                        if (Rol > 0) Emit(QD_ROL16, (uint8_t)Rol);
                        break;
                    default: break;
                    }
                }
                Xmm[OtherReg].Hot = false;
                HasCopy[OtherReg] = false;
                DataReg = In.reg1;
                Xmm[In.reg1].Hot = true;
            } else if (Xmm[OtherReg].IsConst) {
                Emit(QD_POR128, 0, Xmm[OtherReg].ConstLo, Xmm[OtherReg].ConstHi);
                DataReg = In.reg1;
                Xmm[In.reg1].Hot = true;
            }
            continue;
        }

        if ((In.type == INSN_PXOR || In.type == INSN_XORPS) &&
            (Xmm[In.reg1].Hot || Xmm[In.reg2].Hot)) {
            uint8_t HotReg = Xmm[In.reg1].Hot ? In.reg1 : In.reg2;
            uint8_t OtherReg = (HotReg == In.reg1) ? In.reg2 : In.reg1;

            if (In.hasRipRel) {
                uint64_t Rva = In.ResolveRipRVA();
                uint64_t Lo = 0, Hi = 0;
                ReadConst128(Scanner, Rva, Lo, Hi);
                Emit(QD_XOR128, 0, Lo, Hi);
            } else if (Xmm[OtherReg].IsConst) {
                Emit(QD_XOR128, 0, Xmm[OtherReg].ConstLo, Xmm[OtherReg].ConstHi);
            } else if (HotReg == OtherReg) {
                Emit(QD_XOR128, 0, 0, 0);
            }
            DataReg = In.reg1;
            Xmm[In.reg1].Hot = true;
            continue;
        }

        if (In.type == INSN_PAND && (Xmm[In.reg1].Hot || Xmm[In.reg2].Hot)) {
            uint8_t OtherReg = Xmm[In.reg1].Hot ? In.reg2 : In.reg1;
            if (In.hasRipRel) {
                uint64_t Rva = In.ResolveRipRVA();
                uint64_t Lo = 0, Hi = 0;
                ReadConst128(Scanner, Rva, Lo, Hi);
                Emit(QD_PAND128, 0, Lo, Hi);
            } else if (Xmm[OtherReg].IsConst) {
                Emit(QD_PAND128, 0, Xmm[OtherReg].ConstLo, Xmm[OtherReg].ConstHi);
            }
            DataReg = In.reg1;
            Xmm[In.reg1].Hot = true;
            continue;
        }

        if (In.type == INSN_PSHUFLW && Xmm[In.reg2].Hot) {
            Emit(QD_PSHUFLW, In.imm8);
            DataReg = In.reg1;
            Xmm[In.reg1].Hot = true;
            continue;
        }

        if (In.type == INSN_PSHUFHW && Xmm[In.reg2].Hot) {
            Emit(QD_PSHUFHW, In.imm8);
            DataReg = In.reg1;
            Xmm[In.reg1].Hot = true;
            continue;
        }

        if (In.type == INSN_PSHUFD && Xmm[In.reg2].Hot) {
            Emit(QD_PSHUFD, In.imm8);
            DataReg = In.reg1;
            Xmm[In.reg1].Hot = true;
            continue;
        }

        if (In.type == INSN_PSHUFB && (Xmm[In.reg1].Hot || Xmm[In.reg2].Hot)) {
            uint8_t MaskReg = Xmm[In.reg1].Hot ? In.reg2 : In.reg1;
            uint8_t Mask[16] = {};
            if (In.hasRipRel) {
                uint64_t Rva = In.ResolveRipRVA();
                const uint8_t* MaskPtr = Scanner.GetLocalPtr(Rva);
                if (MaskPtr) std::memcpy(Mask, MaskPtr, 16);
            } else if (Xmm[MaskReg].IsConst) {
                std::memcpy(Mask, &Xmm[MaskReg].ConstLo, 8);
                std::memcpy(Mask + 8, &Xmm[MaskReg].ConstHi, 8);
            }
            EmitMask(QD_PSHUFB, Mask);
            DataReg = In.reg1;
            Xmm[In.reg1].Hot = true;
            continue;
        }

        if ((In.type == INSN_PADDD || In.type == INSN_PADDQ ||
             In.type == INSN_PSUBD || In.type == INSN_PSUBQ) &&
            (Xmm[In.reg1].Hot || Xmm[In.reg2].Hot)) {
            uint8_t OtherReg = Xmm[In.reg1].Hot ? In.reg2 : In.reg1;
            uint64_t Lo = 0, Hi = 0;
            if (In.hasRipRel) {
                uint64_t Rva = In.ResolveRipRVA();
                ReadConst128(Scanner, Rva, Lo, Hi);
            } else if (Xmm[OtherReg].IsConst) {
                Lo = Xmm[OtherReg].ConstLo;
                Hi = Xmm[OtherReg].ConstHi;
            }
            QDOp QOp = QD_NOP;
            switch (In.type) {
            case INSN_PADDD: QOp = QD_PADDD; break;
            case INSN_PADDQ: QOp = QD_PADDQ; break;
            case INSN_PSUBD: QOp = QD_PSUBD; break;
            case INSN_PSUBQ: QOp = QD_PSUBQ; break;
            default: break;
            }
            Emit(QOp, 0, Lo, Hi);
            DataReg = In.reg1;
            Xmm[In.reg1].Hot = true;
            continue;
        }
    }

    if (Result.Program.OpCount > 0)
        Result.Program.Valid = true;

    return Result;
}

inline QDRecordResult QDRecordFromRVA(
    const SigScanV2::Scanner& Scanner,
    uint64_t AnchorRva)
{
    auto Insns = FuncAnalyze::DecodeFunctionAt(Scanner, AnchorRva);
    int AnchorIdx = -1;
    for (int I = 0; I < (int)Insns.size(); I++) {
        if (Insns[I].rva <= AnchorRva && Insns[I].rva + Insns[I].length > AnchorRva) {
            AnchorIdx = I;
            break;
        }
        if (Insns[I].rva == AnchorRva) {
            AnchorIdx = I;
            break;
        }
    }
    if (AnchorIdx < 0 && !Insns.empty()) {
        uint64_t BestDist = UINT64_MAX;
        for (int I = 0; I < (int)Insns.size(); I++) {
            uint64_t D = (Insns[I].rva > AnchorRva) ? Insns[I].rva - AnchorRva : AnchorRva - Insns[I].rva;
            if (D < BestDist) { BestDist = D; AnchorIdx = I; }
        }
    }
    if (AnchorIdx < 0) { QDRecordResult Empty; return Empty; }
    return QDRecordSIMDChain(Insns, AnchorIdx, Scanner);
}

inline uint64_t QDProgramHash(const QDProgram& Prog) {
    uint64_t H = 0x9E3779B97F4A7C15ULL;
    for (int I = 0; I < Prog.OpCount; I++) {
        H ^= (uint64_t)Prog.Ops[I].Op;
        H = (H << 7) | (H >> 57);
        H ^= (uint64_t)Prog.Ops[I].Imm8;
        H = (H << 13) | (H >> 51);
    }
    return H;
}
