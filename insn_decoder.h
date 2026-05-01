#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdio>
#include "zydis/Zydis.h"

// =============================================================================
// INSN DECODER — Zydis-backed x86-64 instruction decoder for auto-discovery
//
// Layer 3 of the auto-discovery pipeline.
// Uses Zydis v4.1 amalgamated build for full x86-64 coverage including
// all VEX/EVEX/legacy SSE encodings. Maps Zydis decoded instructions to
// our simplified InsnType enum for pattern matching in auto_config.h.
//
// Previous hand-rolled decoder had issues with:
//   - Missing VEX/AVX prefix support (C4/C5)
//   - Instruction length desync on uncached pages
//   - Incomplete ModR/M parsing for rare encodings
// Zydis eliminates all of these classes of bugs.
// =============================================================================

enum InsnType : uint8_t {
    INSN_UNKNOWN = 0,
    INSN_PSHUFLW,      // pshuflw / vpshuflw
    INSN_PSHUFHW,      // pshufhw / vpshufhw
    INSN_PSHUFD,       // pshufd / vpshufd
    INSN_PSHUFB,       // pshufb / vpshufb
    INSN_PXOR,         // pxor / vpxor / vpxord / vpxorq
    INSN_XORPS,        // xorps / vxorps
    INSN_MOVDQA,       // movdqa / movdqu / vmovdqa / vmovdqu (all treated same)
    INSN_MOVAPS,       // movaps / vmovaps
    INSN_MOVD,         // movd / vmovd
    INSN_MOVQ,         // movq / vmovq
    INSN_LOADL_EPI64,  // movsd load / movq store
    INSN_LEA,          // lea
    INSN_MOV_REG,      // mov r64, r/m64 or mov r/m64, r64
    INSN_PSLLD,        // pslld / vpslld imm
    INSN_PSRLD,        // psrld / vpsrld imm
    INSN_PSLLW,        // psllw / vpsllw imm
    INSN_PSRLW,        // psrlw / vpsrlw imm
    INSN_PSLLQ,        // psllq / vpsllq imm
    INSN_PSRLQ,        // psrlq / vpsrlq imm
    INSN_PSLLDQ,       // pslldq / vpslldq (byte-granular left shift of entire xmm)
    INSN_PSRLDQ,       // psrldq / vpsrldq (byte-granular right shift of entire xmm)
    INSN_PSLLI_EPI16,  // alias: same as PSLLW
    INSN_PSRLI_EPI16,  // alias: same as PSRLW
    INSN_PSLLI_EPI32,  // alias: same as PSLLD
    INSN_PSRLI_EPI32,  // alias: same as PSRLD
    INSN_PSLLI_EPI64,  // alias: same as PSLLQ
    INSN_PSRLI_EPI64,  // alias: same as PSRLQ
    INSN_IMUL,         // imul with immediate
    INSN_XOR_EAX,      // xor eax/rax, imm32
    INSN_XOR_REG,      // xor r/m, r or xor r, r/m
    INSN_ROR,          // ror with immediate
    INSN_ROL,          // rol with immediate
    INSN_SHR,          // shr with immediate
    INSN_SHL,          // shl with immediate
    INSN_ADD_IMM,      // add reg, imm32
    INSN_SUB_IMM,      // sub reg, imm32
    INSN_AND_IMM,      // and reg, imm
    INSN_CALL_RIP,     // call near RIP-relative
    INSN_JMP,          // jmp
    INSN_JCC,          // jcc (conditional jump)
    INSN_RET,          // ret
    INSN_NOP,          // nop / multi-byte nop
    INSN_INT3,         // int3
    INSN_CMP_IMM,      // cmp reg, imm
    INSN_PAND,         // pand / vpand / vpandd / vpandq
    INSN_PANDN,        // pandn / vpandn / vpandnd / vpandnq
    INSN_POR,          // por / vpor / vpord / vporq
    INSN_BSWAP,        // bswap r32/r64
    INSN_SHLD,         // shld r64, r64, imm8 (double-precision left shift)
    INSN_SHRD,         // shrd r64, r64, imm8 (double-precision right shift)
    INSN_RORX,         // rorx r64, r/m64, imm8 (BMI2 rotate right)
    INSN_PADDB,        // paddb / vpaddb
    INSN_PADDW,        // paddw / vpaddw
    INSN_PADDD,        // paddd / vpaddd
    INSN_PADDQ,        // paddq / vpaddq
    INSN_PSUBB,        // psubb / vpsubb
    INSN_PSUBW,        // psubw / vpsubw
    INSN_PSUBD,        // psubd / vpsubd
    INSN_PSUBQ,        // psubq / vpsubq
};

struct DecodedInsn {
    InsnType  type     = INSN_UNKNOWN;
    uint64_t  rva      = 0;      // RVA of this instruction
    uint8_t   length   = 0;      // instruction byte count
    uint8_t   prefix   = 0;      // legacy prefix byte (0x66, 0xF2, 0xF3, or 0 for none)
    bool      hasREX_W = false;  // REX.W prefix present

    // Operands
    uint8_t   reg1     = 0;      // first register (ModR/M reg field)
    uint8_t   reg2     = 0;      // second register (ModR/M r/m field)
    uint8_t   imm8     = 0;      // 8-bit immediate (shuffle immediates, shift amounts)
    uint32_t  imm32    = 0;      // 32-bit immediate (XOR keys, FNV constants)
    uint64_t  imm64    = 0;      // 64-bit immediate (mov r64, imm64)
    int32_t   disp32   = 0;      // RIP-relative displacement
    bool      hasRipRel = false; // has RIP-relative operand
    bool      hasImm8   = false;
    bool      hasImm32  = false;

    // Resolve RIP-relative to absolute RVA
    uint64_t ResolveRipRVA() const {
        if (!hasRipRel) return 0;
        return rva + length + disp32;  // next_rip + disp
    }

    // Convenience: is this instruction a shuffle-type with an immediate?
    bool IsShuffleWithImm() const {
        return type == INSN_PSHUFLW || type == INSN_PSHUFHW || type == INSN_PSHUFD;
    }

    // Is this a shift instruction with an immediate?
    bool IsShiftImm() const {
        return type >= INSN_PSLLD && type <= INSN_PSRLI_EPI64;
    }

    // Get the shift/rotate amount (from imm8)
    uint8_t ShiftAmount() const { return imm8; }

    // Human-readable instruction type name for diagnostics
    const char* TypeName() const {
        switch (type) {
            case INSN_UNKNOWN:      return "UNKNOWN";
            case INSN_PSHUFLW:      return "PSHUFLW";
            case INSN_PSHUFHW:      return "PSHUFHW";
            case INSN_PSHUFD:       return "PSHUFD";
            case INSN_PSHUFB:       return "PSHUFB";
            case INSN_PXOR:         return "PXOR";
            case INSN_XORPS:        return "XORPS";
            case INSN_MOVDQA:       return "MOVDQA";
            case INSN_MOVAPS:       return "MOVAPS";
            case INSN_MOVD:         return "MOVD";
            case INSN_MOVQ:         return "MOVQ";
            case INSN_LOADL_EPI64:  return "LOADL_EPI64";
            case INSN_LEA:          return "LEA";
            case INSN_MOV_REG:      return "MOV_REG";
            case INSN_PSLLD:        return "PSLLD";
            case INSN_PSRLD:        return "PSRLD";
            case INSN_PSLLW:        return "PSLLW";
            case INSN_PSRLW:        return "PSRLW";
            case INSN_PSLLQ:        return "PSLLQ";
            case INSN_PSRLQ:        return "PSRLQ";
            case INSN_PSLLDQ:       return "PSLLDQ";
            case INSN_PSRLDQ:       return "PSRLDQ";
            case INSN_PAND:         return "PAND";
            case INSN_PANDN:        return "PANDN";
            case INSN_POR:          return "POR";
            case INSN_IMUL:         return "IMUL";
            case INSN_XOR_EAX:      return "XOR_EAX";
            case INSN_XOR_REG:      return "XOR_REG";
            case INSN_ROR:          return "ROR";
            case INSN_ROL:          return "ROL";
            case INSN_SHR:          return "SHR";
            case INSN_SHL:          return "SHL";
            case INSN_ADD_IMM:      return "ADD_IMM";
            case INSN_SUB_IMM:      return "SUB_IMM";
            case INSN_AND_IMM:      return "AND_IMM";
            case INSN_CALL_RIP:     return "CALL_RIP";
            case INSN_JMP:          return "JMP";
            case INSN_JCC:          return "JCC";
            case INSN_RET:          return "RET";
            case INSN_NOP:          return "NOP";
            case INSN_INT3:         return "INT3";
            case INSN_CMP_IMM:      return "CMP_IMM";
            case INSN_BSWAP:        return "BSWAP";
            case INSN_SHLD:         return "SHLD";
            case INSN_SHRD:         return "SHRD";
            case INSN_RORX:         return "RORX";
            case INSN_PADDB:        return "PADDB";
            case INSN_PADDW:        return "PADDW";
            case INSN_PADDD:        return "PADDD";
            case INSN_PADDQ:        return "PADDQ";
            case INSN_PSUBB:        return "PSUBB";
            case INSN_PSUBW:        return "PSUBW";
            case INSN_PSUBD:        return "PSUBD";
            case INSN_PSUBQ:        return "PSUBQ";
            default:                return "?";
        }
    }
};


// =============================================================================
// INSTRUCTION DECODER — Zydis-powered backend
// =============================================================================

class InsnDecoder {
public:
    InsnDecoder() {
        ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    }

    // Decode a buffer of instructions, returns list of decoded instructions
    std::vector<DecodedInsn> Decode(const uint8_t* buf, size_t len, uint64_t startRVA) const {
        std::vector<DecodedInsn> insns;
        insns.reserve(len / 4);

        size_t offset = 0;
        while (offset < len) {
            ZydisDecodedInstruction zinst;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            ZyanStatus status = ZydisDecoderDecodeFull(
                &m_decoder, buf + offset, len - offset,
                &zinst, operands);

            DecodedInsn insn;
            insn.rva = startRVA + offset;

            if (!ZYAN_SUCCESS(status)) {
                // Failed to decode — skip one byte
                insn.type   = INSN_UNKNOWN;
                insn.length = 1;
                insns.push_back(insn);
                offset++;
                continue;
            }

            insn.length = (uint8_t)zinst.length;
            MapInstruction(zinst, operands, insn);
            insns.push_back(insn); // DecodedInsn is a POD-like struct, push_back is fine
            offset += zinst.length;
        }

        return insns;
    }

private:
    ZydisDecoder m_decoder;

    // =========================================================================
    // Map a Zydis decoded instruction to our InsnType + extract operands
    // =========================================================================
    static void MapInstruction(const ZydisDecodedInstruction& zinst,
                               const ZydisDecodedOperand* ops,
                               DecodedInsn& out)
    {
        // Extract common operand info first
        ExtractOperands(zinst, ops, out);

        switch (zinst.mnemonic) {
        // --- Shuffles ---
        case ZYDIS_MNEMONIC_PSHUFLW:
        case ZYDIS_MNEMONIC_VPSHUFLW:   out.type = INSN_PSHUFLW; break;
        case ZYDIS_MNEMONIC_PSHUFHW:
        case ZYDIS_MNEMONIC_VPSHUFHW:   out.type = INSN_PSHUFHW; break;
        case ZYDIS_MNEMONIC_PSHUFD:
        case ZYDIS_MNEMONIC_VPSHUFD:    out.type = INSN_PSHUFD;  break;
        case ZYDIS_MNEMONIC_PSHUFB:
        case ZYDIS_MNEMONIC_VPSHUFB:    out.type = INSN_PSHUFB;  break;

        // --- Logical XOR ---
        case ZYDIS_MNEMONIC_PXOR:
        case ZYDIS_MNEMONIC_VPXOR:
        case ZYDIS_MNEMONIC_VPXORD:
        case ZYDIS_MNEMONIC_VPXORQ:     out.type = INSN_PXOR;    break;
        case ZYDIS_MNEMONIC_XORPS:
        case ZYDIS_MNEMONIC_VXORPS:
        case ZYDIS_MNEMONIC_XORPD:
        case ZYDIS_MNEMONIC_VXORPD:     out.type = INSN_XORPS;   break;

        // --- Logical AND ---
        case ZYDIS_MNEMONIC_PAND:
        case ZYDIS_MNEMONIC_VPAND:
        case ZYDIS_MNEMONIC_VPANDD:
        case ZYDIS_MNEMONIC_VPANDQ:
        case ZYDIS_MNEMONIC_ANDPS:
        case ZYDIS_MNEMONIC_VANDPS:     out.type = INSN_PAND;    break;
        case ZYDIS_MNEMONIC_PANDN:
        case ZYDIS_MNEMONIC_VPANDN:
        case ZYDIS_MNEMONIC_VPANDND:
        case ZYDIS_MNEMONIC_VPANDNQ:
        case ZYDIS_MNEMONIC_ANDNPS:
        case ZYDIS_MNEMONIC_VANDNPS:    out.type = INSN_PANDN;   break;

        // --- Logical OR ---
        case ZYDIS_MNEMONIC_POR:
        case ZYDIS_MNEMONIC_VPOR:
        case ZYDIS_MNEMONIC_VPORD:
        case ZYDIS_MNEMONIC_VPORQ:      out.type = INSN_POR;     break;

        // --- Packed integer add ---
        case ZYDIS_MNEMONIC_PADDB:
        case ZYDIS_MNEMONIC_VPADDB:     out.type = INSN_PADDB;   break;
        case ZYDIS_MNEMONIC_PADDW:
        case ZYDIS_MNEMONIC_VPADDW:     out.type = INSN_PADDW;   break;
        case ZYDIS_MNEMONIC_PADDD:
        case ZYDIS_MNEMONIC_VPADDD:     out.type = INSN_PADDD;   break;
        case ZYDIS_MNEMONIC_PADDQ:
        case ZYDIS_MNEMONIC_VPADDQ:     out.type = INSN_PADDQ;   break;

        // --- Packed integer subtract ---
        case ZYDIS_MNEMONIC_PSUBB:
        case ZYDIS_MNEMONIC_VPSUBB:     out.type = INSN_PSUBB;   break;
        case ZYDIS_MNEMONIC_PSUBW:
        case ZYDIS_MNEMONIC_VPSUBW:     out.type = INSN_PSUBW;   break;
        case ZYDIS_MNEMONIC_PSUBD:
        case ZYDIS_MNEMONIC_VPSUBD:     out.type = INSN_PSUBD;   break;
        case ZYDIS_MNEMONIC_PSUBQ:
        case ZYDIS_MNEMONIC_VPSUBQ:     out.type = INSN_PSUBQ;   break;

        // --- Moves (packed) ---
        case ZYDIS_MNEMONIC_MOVDQA:
        case ZYDIS_MNEMONIC_VMOVDQA:
        case ZYDIS_MNEMONIC_VMOVDQA32:
        case ZYDIS_MNEMONIC_VMOVDQA64:
        case ZYDIS_MNEMONIC_MOVDQU:
        case ZYDIS_MNEMONIC_VMOVDQU:
        case ZYDIS_MNEMONIC_VMOVDQU8:
        case ZYDIS_MNEMONIC_VMOVDQU16:
        case ZYDIS_MNEMONIC_VMOVDQU32:
        case ZYDIS_MNEMONIC_VMOVDQU64:  out.type = INSN_MOVDQA;  break;
        case ZYDIS_MNEMONIC_MOVAPS:
        case ZYDIS_MNEMONIC_VMOVAPS:
        case ZYDIS_MNEMONIC_MOVUPS:
        case ZYDIS_MNEMONIC_VMOVUPS:
        case ZYDIS_MNEMONIC_MOVAPD:
        case ZYDIS_MNEMONIC_VMOVAPD:
        case ZYDIS_MNEMONIC_MOVUPD:
        case ZYDIS_MNEMONIC_VMOVUPD:    out.type = INSN_MOVAPS;  break;
        case ZYDIS_MNEMONIC_MOVD:
        case ZYDIS_MNEMONIC_VMOVD:      out.type = INSN_MOVD;    break;
        case ZYDIS_MNEMONIC_MOVQ:
        case ZYDIS_MNEMONIC_VMOVQ:      out.type = INSN_MOVQ;    break;

        // --- LEA ---
        case ZYDIS_MNEMONIC_LEA:        out.type = INSN_LEA;     break;

        // --- MOV (general purpose) ---
        case ZYDIS_MNEMONIC_MOV:
            // Classify MOV reg, imm32 (opcode B8+rd) and MOV r64, r/m64
            if (out.hasImm32 || zinst.operand_width >= 32)
                out.type = INSN_MOV_REG;
            else
                out.type = INSN_UNKNOWN;
            break;

        // --- Packed shifts ---
        case ZYDIS_MNEMONIC_PSLLD:
        case ZYDIS_MNEMONIC_VPSLLD:     out.type = INSN_PSLLD;   break;
        case ZYDIS_MNEMONIC_PSRLD:
        case ZYDIS_MNEMONIC_VPSRLD:     out.type = INSN_PSRLD;   break;
        case ZYDIS_MNEMONIC_PSLLW:
        case ZYDIS_MNEMONIC_VPSLLW:     out.type = INSN_PSLLW;   break;
        case ZYDIS_MNEMONIC_PSRLW:
        case ZYDIS_MNEMONIC_VPSRLW:     out.type = INSN_PSRLW;   break;
        case ZYDIS_MNEMONIC_PSLLQ:
        case ZYDIS_MNEMONIC_VPSLLQ:     out.type = INSN_PSLLQ;   break;
        case ZYDIS_MNEMONIC_PSRLQ:
        case ZYDIS_MNEMONIC_VPSRLQ:     out.type = INSN_PSRLQ;   break;

        // PSLLDQ / PSRLDQ — byte-granular shifts (distinct from bit-granular PSLLQ/PSRLQ)
        case ZYDIS_MNEMONIC_PSLLDQ:
        case ZYDIS_MNEMONIC_VPSLLDQ:    out.type = INSN_PSLLDQ;  break;
        case ZYDIS_MNEMONIC_PSRLDQ:
        case ZYDIS_MNEMONIC_VPSRLDQ:    out.type = INSN_PSRLDQ;  break;

        // --- IMUL with immediate ---
        case ZYDIS_MNEMONIC_IMUL:       out.type = INSN_IMUL;    break;

        // --- Scalar XOR ---
        case ZYDIS_MNEMONIC_XOR:
            if (out.hasImm32 || out.hasImm8)
                out.type = INSN_XOR_EAX;
            else
                out.type = INSN_XOR_REG;
            break;

        // --- Rotate/Shift ---
        case ZYDIS_MNEMONIC_ROR:        out.type = INSN_ROR;     break;
        case ZYDIS_MNEMONIC_ROL:        out.type = INSN_ROL;     break;
        case ZYDIS_MNEMONIC_SHR:        out.type = INSN_SHR;     break;
        case ZYDIS_MNEMONIC_SHL:        out.type = INSN_SHL;     break;

        // --- Arithmetic ---
        case ZYDIS_MNEMONIC_ADD:
            out.type = (out.hasImm32 || out.hasImm8) ? INSN_ADD_IMM : INSN_UNKNOWN;
            break;
        case ZYDIS_MNEMONIC_SUB:
            out.type = (out.hasImm32 || out.hasImm8) ? INSN_SUB_IMM : INSN_UNKNOWN;
            break;
        case ZYDIS_MNEMONIC_AND:
            out.type = (out.hasImm32 || out.hasImm8) ? INSN_AND_IMM : INSN_UNKNOWN;
            break;
        case ZYDIS_MNEMONIC_CMP:
            out.type = (out.hasImm32 || out.hasImm8) ? INSN_CMP_IMM : INSN_UNKNOWN;
            break;

        // --- Control flow ---
        case ZYDIS_MNEMONIC_CALL:       out.type = INSN_CALL_RIP; break;
        case ZYDIS_MNEMONIC_JMP:        out.type = INSN_JMP;      break;
        case ZYDIS_MNEMONIC_RET:        out.type = INSN_RET;      break;
        case ZYDIS_MNEMONIC_INT3:       out.type = INSN_INT3;     break;
        case ZYDIS_MNEMONIC_NOP:        out.type = INSN_NOP;      break;

        // Conditional jumps
        case ZYDIS_MNEMONIC_JB:   case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JL:   case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNB:  case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JNL:  case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JNO:  case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JNS:  case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JO:   case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JS:   case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_JCXZ: case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JRCXZ:
            out.type = INSN_JCC;
            break;

        // --- MOVSD load (used for _mm_loadl_epi64) ---
        case ZYDIS_MNEMONIC_MOVSD:      out.type = INSN_LOADL_EPI64; break;

        // --- BSWAP ---
        case ZYDIS_MNEMONIC_BSWAP:      out.type = INSN_BSWAP; break;

        // --- Double-precision shift / BMI2 rotate ---
        case ZYDIS_MNEMONIC_SHLD:       out.type = INSN_SHLD; break;
        case ZYDIS_MNEMONIC_SHRD:       out.type = INSN_SHRD; break;
        case ZYDIS_MNEMONIC_RORX:       out.type = INSN_RORX; break;

        default:
            out.type = INSN_UNKNOWN;
            break;
        }
    }

    // =========================================================================
    // Extract operand info from Zydis decoded operands into DecodedInsn fields
    // =========================================================================
    static void ExtractOperands(const ZydisDecodedInstruction& zinst,
                                const ZydisDecodedOperand* ops,
                                DecodedInsn& out)
    {
        for (ZyanU8 i = 0; i < zinst.operand_count_visible; i++) {
            const auto& op = ops[i];

            switch (op.type) {
            case ZYDIS_OPERAND_TYPE_MEMORY:
                // Check for RIP-relative addressing (mod=00, rm=101 in x86-64)
                if (op.mem.base == ZYDIS_REGISTER_RIP && op.mem.index == ZYDIS_REGISTER_NONE) {
                    out.hasRipRel = true;
                    out.disp32 = (int32_t)op.mem.disp.value;
                }
                break;

            case ZYDIS_OPERAND_TYPE_REGISTER:
                if (i == 0)      out.reg1 = (uint8_t)(op.reg.value & 0xF);
                else if (i == 1) out.reg2 = (uint8_t)(op.reg.value & 0xF);
                break;

            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                if (op.size <= 8) {
                    out.imm8 = (uint8_t)op.imm.value.u;
                    out.hasImm8 = true;
                    // Also set imm32 with sign-extension for sign-extended imm8 ops
                    out.imm32 = (uint32_t)(int32_t)(int8_t)op.imm.value.s;
                    out.hasImm32 = true;
                } else if (op.size <= 32) {
                    out.imm32 = (uint32_t)op.imm.value.u;
                    out.hasImm32 = true;
                    out.imm8 = (uint8_t)op.imm.value.u;
                    out.hasImm8 = true;
                } else {
                    out.imm64 = op.imm.value.u;
                    out.imm32 = (uint32_t)op.imm.value.u;
                    out.hasImm32 = true;
                }
                break;

            default:
                break;
            }
        }

        // Extract prefix info
        if (zinst.attributes & ZYDIS_ATTRIB_HAS_OPERANDSIZE)  out.prefix = 0x66;
        else if (zinst.attributes & ZYDIS_ATTRIB_HAS_REPNE)   out.prefix = 0xF2;
        else if (zinst.attributes & ZYDIS_ATTRIB_HAS_REP)     out.prefix = 0xF3;

        // REX.W
        if ((zinst.attributes & ZYDIS_ATTRIB_HAS_REX) && zinst.raw.rex.W)
            out.hasREX_W = true;
    }
};


// =============================================================================
// FUNCTION ANALYZER — High-level helpers for extracting crypto parameters
// from decoded instruction sequences
// =============================================================================

class FuncAnalyzer {
public:
    FuncAnalyzer() = default;

    // Decode instructions from a local buffer
    std::vector<DecodedInsn> DecodeAt(const uint8_t* buf, size_t len, uint64_t rva) {
        return m_decoder.Decode(buf, len, rva);
    }

    // Find first instruction of a given type after startIdx
    static int FindInsn(const std::vector<DecodedInsn>& insns, InsnType type, int startIdx = 0) {
        for (int i = startIdx; i < (int)insns.size(); i++)
            if (insns[i].type == type) return i;
        return -1;
    }

    // Find all instructions of a given type
    static std::vector<int> FindAllInsn(const std::vector<DecodedInsn>& insns, InsnType type) {
        std::vector<int> result;
        for (int i = 0; i < (int)insns.size(); i++)
            if (insns[i].type == type) result.push_back(i);
        return result;
    }

    // Find PSHUFLW with specific immediate
    static int FindPSHUFLW(const std::vector<DecodedInsn>& insns, uint8_t imm, int startIdx = 0) {
        for (int i = startIdx; i < (int)insns.size(); i++)
            if (insns[i].type == INSN_PSHUFLW && insns[i].imm8 == imm) return i;
        return -1;
    }

    // Find PSHUFB with RIP-relative operand
    static int FindPSHUFB(const std::vector<DecodedInsn>& insns, int startIdx = 0) {
        for (int i = startIdx; i < (int)insns.size(); i++)
            if (insns[i].type == INSN_PSHUFB && insns[i].hasRipRel) return i;
        return -1;
    }

    // Find PXOR/XORPS with RIP-relative operand
    static int FindXorRip(const std::vector<DecodedInsn>& insns, int startIdx = 0) {
        for (int i = startIdx; i < (int)insns.size(); i++)
            if ((insns[i].type == INSN_PXOR || insns[i].type == INSN_XORPS) && insns[i].hasRipRel)
                return i;
        return -1;
    }

    // Find IMUL with specific constant
    static int FindIMUL(const std::vector<DecodedInsn>& insns, uint32_t constant, int startIdx = 0) {
        for (int i = startIdx; i < (int)insns.size(); i++)
            if (insns[i].type == INSN_IMUL && insns[i].imm32 == constant) return i;
        return -1;
    }

    // Find LEA with RIP-relative
    static int FindLEA(const std::vector<DecodedInsn>& insns, int startIdx = 0) {
        for (int i = startIdx; i < (int)insns.size(); i++)
            if (insns[i].type == INSN_LEA && insns[i].hasRipRel) return i;
        return -1;
    }

    // Find nearest shift instruction within range of an index
    static int FindShiftNear(const std::vector<DecodedInsn>& insns, int fromIdx, int range = 5) {
        int start = (std::max)(0, fromIdx - range);
        int end = (std::min)((int)insns.size(), fromIdx + range);
        for (int i = start; i < end; i++)
            if (insns[i].IsShiftImm()) return i;
        return -1;
    }

    // Find ROL or ROR instruction
    static int FindRolRor(const std::vector<DecodedInsn>& insns, int startIdx = 0) {
        for (int i = startIdx; i < (int)insns.size(); i++)
            if (insns[i].type == INSN_ROL || insns[i].type == INSN_ROR) return i;
        return -1;
    }

    // Match a sequence of instruction types starting at index
    static bool MatchSequence(const std::vector<DecodedInsn>& insns, int idx,
                              const std::vector<InsnType>& pattern) {
        if (idx < 0 || idx + (int)pattern.size() > (int)insns.size()) return false;
        for (size_t i = 0; i < pattern.size(); i++) {
            if (pattern[i] != INSN_UNKNOWN && insns[idx + i].type != pattern[i])
                return false;
        }
        return true;
    }

private:
    InsnDecoder m_decoder;
};
