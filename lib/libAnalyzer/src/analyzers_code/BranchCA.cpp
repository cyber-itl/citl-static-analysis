#include <cstdint>

#include "capstone/capstone.h"
#include "json.hpp"

#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/BranchCA.hpp"

struct Block;
struct Symbol;

BranchCA::BranchCA(cs_arch arch, cs_mode mode) : BaseCodeAnalyzer("branch_stats", arch, mode) {};

int BranchCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    cs_detail *detail = insn.detail;
    uint8_t check_grp = CS_GRP_INVALID;

    if (m_arch == cs_arch::CS_ARCH_X86) {
        if (insn.id == X86_INS_INVALID) {
            return 0;
        }

        check_grp = X86_GRP_JUMP;
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        if (insn.id == ARM_INS_INVALID) {
            return 0;
        }

        check_grp = ARM_GRP_JUMP;
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        if (insn.id == ARM64_INS_INVALID) {
            return 0;
        }

        check_grp = ARM64_GRP_JUMP;
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS) {
        if (insn.id == MIPS_INS_INVALID) {
            return 0;
        }
        check_grp = MIPS_GRP_JUMP;
    }
    else if (m_arch == cs_arch::CS_ARCH_PPC) {
        switch (insn.id) {
        case PPC_INS_B:
        case PPC_INS_BA:
        case PPC_INS_BC:
        case PPC_INS_BCCTR:
        case PPC_INS_BCCTRL:
        case PPC_INS_BCL:
        case PPC_INS_BCLR:
        case PPC_INS_BCLRL:
        case PPC_INS_BCTR:
        case PPC_INS_BCTRL:
        case PPC_INS_BCT:
        case PPC_INS_BDNZ:
        case PPC_INS_BDNZA:
        case PPC_INS_BDNZL:
        case PPC_INS_BDNZLA:
        case PPC_INS_BDNZLR:
        case PPC_INS_BDNZLRL:
        case PPC_INS_BDZ:
        case PPC_INS_BDZA:
        case PPC_INS_BDZL:
        case PPC_INS_BDZLA:
        case PPC_INS_BDZLR:
        case PPC_INS_BDZLRL:
        case PPC_INS_BL:
        case PPC_INS_BLA:
        case PPC_INS_BLR:
        case PPC_INS_BLRL:
        case PPC_INS_BRINC:
        case PPC_INS_BCA:
        case PPC_INS_BCLA:
        case PPC_INS_BTA:
        case PPC_INS_BT:
        case PPC_INS_BF:
        case PPC_INS_BDNZT:
        case PPC_INS_BDNZF:
        case PPC_INS_BDZF:
        case PPC_INS_BDZT:
        case PPC_INS_BFA:
        case PPC_INS_BDNZTA:
        case PPC_INS_BDNZFA:
        case PPC_INS_BDZTA:
        case PPC_INS_BDZFA:
        case PPC_INS_BTCTR:
        case PPC_INS_BFCTR:
        case PPC_INS_BTCTRL:
        case PPC_INS_BFCTRL:
        case PPC_INS_BTL:
        case PPC_INS_BFL:
        case PPC_INS_BDNZTL:
        case PPC_INS_BDNZFL:
        case PPC_INS_BDZTL:
        case PPC_INS_BDZFL:
        case PPC_INS_BTLA:
        case PPC_INS_BFLA:
        case PPC_INS_BDNZTLA:
        case PPC_INS_BDNZFLA:
        case PPC_INS_BDZTLA:
        case PPC_INS_BDZFLA:
        case PPC_INS_BTLR:
        case PPC_INS_BFLR:
        case PPC_INS_BDNZTLR:
        case PPC_INS_BDZTLR:
        case PPC_INS_BDZFLR:
        case PPC_INS_BTLRL:
        case PPC_INS_BFLRL:
        case PPC_INS_BDNZTLRL:
        case PPC_INS_BDNZFLRL:
        case PPC_INS_BDZTLRL:
        case PPC_INS_BDZFLRL:
            if (m_branch_dict.count(insn.mnemonic)) {
                m_branch_dict[insn.mnemonic]++;
            }
            else {
                m_branch_dict.emplace(insn.mnemonic, 1);
            }

            return 0;
        }
    }

    if (check_grp != CS_GRP_INVALID && detail->groups_count > 0) {
        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];
            if (grp == check_grp) {
                if (m_branch_dict.count(insn.mnemonic)) {
                    m_branch_dict[insn.mnemonic]++;
                }
                else {
                    m_branch_dict.emplace(insn.mnemonic, 1);
                }

                break;
            }
        }
    }

    return 0;
}

int BranchCA::process_results() {
    m_results["branch_dict"] = m_branch_dict;

    return 0;
}
