#include <cstdint>
#include <algorithm>

#include "capstone/capstone.h"
#include "json.hpp"

#include "Block.hpp"
#include "analyzers_code/RetStatsCA.hpp"

struct Symbol;

#define MAX_BLOCK_COUNT_SIZE 0x1000

RetStatsCA::RetStatsCA(cs_arch arch, cs_mode mode) : BaseCodeAnalyzer("ret_stats", arch, mode) {};


int RetStatsCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    cs_detail *detail = insn.detail;

    std::string ret_mnemonic;

    if (m_arch == cs_arch::CS_ARCH_X86) {
        if (insn.id == X86_INS_INVALID) {
            return 0;
        }

        bool hit_ret = false;
        if (detail->groups_count > 0) {
            for (uint8_t i = 0; i < detail->groups_count; i++) {
                uint8_t grp = detail->groups[i];

                if (grp == CS_GRP_RET) {
                    hit_ret = true;
                    break;
                }
            }
        }

        switch (insn.id) {
        case X86_INS_IRET:
        case X86_INS_IRETD:
        case X86_INS_IRETQ:
        case X86_INS_SYSRET:
            hit_ret = true;
        }

        if (!hit_ret) {
            return 0;
        }

        ret_mnemonic = insn.mnemonic;
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        if (insn.id == ARM_INS_INVALID) {
            return 0;
        }

        if (insn.id == ARM_INS_POP) {
            for (uint8_t i = 0; i < detail->arm.op_count; i++) {
                cs_arm_op oper = detail->arm.operands[i];
                if (oper.reg == ARM_REG_PC) {
                    ret_mnemonic = insn.mnemonic;
                }
            }
        }
        else if (insn.id == ARM_INS_BL || insn.id == ARM_INS_BLX || insn.id == ARM_INS_BX) {
            if (detail->arm.op_count < 1) {
                return 0;
            }

            cs_arm_op branch_op = detail->arm.operands[0];

            if (branch_op.reg == ARM_REG_LR) {
                ret_mnemonic = insn.mnemonic;
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        if (insn.id == ARM64_INS_RET) {
            ret_mnemonic = insn.mnemonic;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS) {
        if (insn.id == MIPS_INS_JR) {
            cs_mips mips = insn.detail->mips;
            if (mips.op_count == 1) {
                if (mips.operands[0].type == MIPS_OP_REG || mips.operands[0].reg == MIPS_REG_RA) {
                    ret_mnemonic = insn.mnemonic;
                }
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_PPC) {
        switch (insn.id) {
        case PPC_INS_BLR:
            ret_mnemonic = insn.mnemonic;
            break;
        }
    }

    if (ret_mnemonic.empty()) {
        return 0;
    }

    if (m_ret_dict.count(ret_mnemonic)) {
        m_ret_dict[ret_mnemonic]++;
    }
    else {
        m_ret_dict.emplace(ret_mnemonic, 1);
    }

    uint64_t ret_dist = std::max(insn.address, block->func_addr) - std::min(insn.address, block->func_addr);
    m_ret_dists.emplace_back(ret_dist);

    return 0;
}

int RetStatsCA::process_results() {
    m_results["ret_dists"] = m_ret_dists;
    m_results["ret_counts"] = m_ret_dict;

    return 0;
}
