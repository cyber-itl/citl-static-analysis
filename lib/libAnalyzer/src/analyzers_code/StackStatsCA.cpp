#include <cstdlib>
#include <cstdint>
#include <string>
#include <algorithm>

#include "json.hpp"
#include "capstone/capstone.h"

#include "Block.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/StackStatsCA.hpp"

struct Symbol;

StackStatsCA::StackStatsCA(cs_arch arch, cs_mode mode) : BaseCodeAnalyzer("stack_stats", arch, mode) {};

int StackStatsCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    cs_detail *detail = insn.detail;
    int64_t adj_value = 0;

    if (block->start != block->func_addr) {
        return 0;
    }

    if (m_arch == cs_arch::CS_ARCH_X86) {
        if (insn.id == X86_INS_INVALID) {
            return 0;
        }

        if (insn.id != X86_INS_SUB) {
            return 0;
        }

        if (detail->x86.op_count != 2) {
            return 0;
        }

        cs_x86_op target = detail->x86.operands[0];
        cs_x86_op value = detail->x86.operands[1];

        if (target.reg == X86_REG_RSP || target.reg == X86_REG_ESP || target.reg == X86_REG_SP) {
            if (value.type == X86_OP_IMM) {
                adj_value = value.imm;
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        if (insn.id == ARM_INS_INVALID) {
            return 0;
        }

        if (insn.id != ARM_INS_SUB) {
            return 0;
        }

        if (detail->arm.op_count != 3) {
            return 0;
        }

        if (detail->arm.operands[0].reg != ARM_REG_SP && detail->arm.operands[1].reg != ARM_REG_SP) {
            return 0;
        }

        adj_value = detail->arm.operands[2].imm;
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        if (insn.id == ARM64_INS_INVALID) {
            return 0;
        }

        if (insn.id != ARM64_INS_STP) {
            return 0;
        }

        if (detail->arm64.op_count != 3) {
            return 0;
        }

        if (detail->arm64.operands[2].mem.base != ARM64_REG_SP) {
            return 0;
        }

        adj_value = detail->arm.operands[2].mem.disp;
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS) {
        if (insn.id == MIPS_INS_INVALID) {
            return 0;
        }

        if (insn.id != MIPS_INS_ADDIU) {
            return 0;
        }

        cs_mips mips = insn.detail->mips;
        if (mips.op_count < 3) {
            return 0;
        }

        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];
        cs_mips_op op2 = mips.operands[2];


        if (op0.type != MIPS_OP_REG ||
            op1.type != MIPS_OP_REG ||
            op2.type != MIPS_OP_IMM) {
            return 0;
        }

        if (op0.reg != MIPS_REG_SP ||
            op1.reg != MIPS_REG_SP) {
            return 0;
        }

        if (op2.imm < 0) {
            adj_value = std::abs(op2.imm);
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_PPC) {
        if (insn.id == PPC_INS_INVALID) {
            return 0;
        }

        if (insn.id != PPC_INS_STWU) {
            return 0;
        }

        cs_ppc ppc = insn.detail->ppc;
        if (ppc.op_count != 2) {
            return 0;
        }

        cs_ppc_op op0 = ppc.operands[0];
        cs_ppc_op op1 = ppc.operands[1];

        if (op0.type != PPC_OP_REG ||
            op1.type != PPC_OP_MEM) {
            return 0;
        }

        if (op0.reg != PPC_REG_R1 ||
            op1.mem.base != PPC_REG_R1) {
            return 0;
        }

        if (op1.mem.disp < 0) {
            adj_value = std::abs(op1.mem.disp);
        }
    }


    if (!adj_value) {
        return 0;
    }

    m_stack_adjs.emplace_back(adj_value);

    return 0;
}

int StackStatsCA::process_results() {
    m_results["stack_adjs"] = m_stack_adjs;

    return 0;
}
