#pragma once
// =============================================================================
// Capstone wrapper — semantic x86-64 disassembly for sig_scan.h.
// =============================================================================

#include <capstone/capstone.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

namespace SigScan {

class Decoder {
public:
    Decoder() {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_h) != CS_ERR_OK) { m_h = 0; return; }
        cs_option(m_h, CS_OPT_DETAIL, CS_OPT_ON);
    }
    ~Decoder() { if (m_h) cs_close(&m_h); }
    bool Ok() const { return m_h != 0; }

    struct MemHit {
        int      off;          // offset of insn within the scanned window
        uint64_t target_va;    // [rip+disp] resolves to this VA
        uint16_t insn_id;      // cs_insn.id (X86_INS_*)
        uint8_t  mem_size;     // operand size in bytes (4, 8, 16, …)
    };

    std::vector<MemHit> ScanRipLoads(const uint8_t* code, size_t len,
                                     uint64_t start_va, int max_insns = 256) {
        std::vector<MemHit> out;
        if (!m_h) return out;
        cs_insn* insn = nullptr;
        size_t n = cs_disasm(m_h, code, len, start_va, max_insns, &insn);
        for (size_t i = 0; i < n; ++i) {
            cs_x86& x = insn[i].detail->x86;
            for (int k = 0; k < x.op_count; ++k) {
                cs_x86_op& op = x.operands[k];
                if (op.type != X86_OP_MEM) continue;
                if (op.mem.base != X86_REG_RIP) continue;
                uint64_t target = insn[i].address + insn[i].size + (int64_t)op.mem.disp;
                out.push_back({int(insn[i].address - start_va), target,
                               (uint16_t)insn[i].id, op.size});
                break;
            }
        }
        if (insn) cs_free(insn, n);
        return out;
    }

private:
    csh m_h = 0;
};

} // namespace SigScan
