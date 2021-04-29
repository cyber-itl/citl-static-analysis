#include <cstdint>
#include <string>

#include "glog/logging.h"
#include "capstone/capstone.h"
#include "json.hpp"

#include "Block.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/CorpusRankCfgCA.hpp"

struct Symbol;

CorpusRankCfgCA::CorpusRankCfgCA(cs_arch arch, cs_mode mode) : BaseCodeAnalyzer("corp_rank_cfg", arch, mode) {};

int CorpusRankCfgCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    cs_detail *detail = insn.detail;

    // Only process the last instruction in the block
    if ( !(insn.address + insn.size >= block->end) ) {
        return 0;
    }

    auto comp_id = block->start;
    auto b_type = branch_type::UNKNOWN;

    if (m_arch != cs_arch::CS_ARCH_X86) {
        LOG(FATAL) << "Corpus Rank CFG is only supported on x86 binaries";
    }

    for (uint8_t i = 0; i < detail->groups_count; i++) {
        uint8_t grp = detail->groups[i];

        switch (grp) {
        case X86_GRP_BRANCH_RELATIVE:
        case X86_GRP_JUMP:
            b_type = branch_type::CONDITIONAL;
            break;
        case X86_GRP_CALL:
            b_type = branch_type::LINKING;
            break;
        case X86_GRP_IRET:
        case X86_GRP_RET:
            b_type = branch_type::RET;
            break;
        case X86_GRP_INT:
            b_type = branch_type::SYSCALL;
            break;
        default:
            break;
        }
    }

    if (b_type == branch_type::UNKNOWN) {
        switch (insn.id) {
        case X86_INS_SYSCALL:
        case X86_INS_SYSENTER:
            b_type = branch_type::SYSCALL;
            break;
        case X86_INS_SYSEXIT:
        case X86_INS_SYSRET:
            b_type = branch_type::RET;
            break;
        default:
            break;
        }
    }

    // if (b_type == branch_type::UNKNOWN) {
    //     LOG(INFO) << "Unknown branch type for id: " << insn.mnemonic << " addr: 0x" << std::hex << insn.address;
    // }

    cs_x86 x86 = detail->x86;
    do {
        if (b_type == branch_type::LINKING || b_type == branch_type::UNCONDITIONAL) {
            if (x86.op_count < 1) {
                LOG(WARNING) << "Invalid branch instruction: 0x" << std::hex << insn.address;
                break;
            }

            cs_x86_op op0 = x86.operands[0];

            if (op0.type == X86_OP_MEM || op0.type == X86_OP_REG) {
                if (b_type == branch_type::LINKING) {
                    b_type = branch_type::INDIRECT_LINKING;
                }
                else if (b_type == branch_type::UNCONDITIONAL) {
                    b_type = branch_type::INDIRECT;
                }
                else {
                    LOG(FATAL) << "Invalid branch type state for indirect check";
                }
            }
        }
    }
    while (false);

    json block_res;
    block_res["b_type"] = b_type;
    block_res["followers"] = block->followers;

    m_serial_cfg.emplace(comp_id, block_res);

    return 0;
}

int CorpusRankCfgCA::process_results() {
    m_results = m_serial_cfg;
    return 0;
}
