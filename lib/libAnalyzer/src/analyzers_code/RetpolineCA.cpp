#include <cstdint>
#include <map>
#include <string>
#include <utility>

#include "capstone/capstone.h"
#include "glog/logging.h"
#include "json.hpp"

#include "Block.hpp"
#include "analyzers_code/RetpolineCA.hpp"

struct Symbol;


RetpolineCA::RetpolineCA(cs_arch arch, cs_mode mode) :
    BaseCodeAnalyzer("retpoline", arch, mode),
    m_has_pause(false),
    m_has_lfence(false),
    m_retpoline(false),
    m_block_addr(0x0) {};

int RetpolineCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    if (m_arch == cs_arch::CS_ARCH_X86) {
        switch (insn.id) {
        case X86_INS_PAUSE:
            m_block_addr = block->start;
            m_has_pause = true;

            break;
        case X86_INS_LFENCE:
            if (block->start == m_block_addr) {
                m_has_lfence = true;
            }
            break;
        case X86_INS_JMP:
            if (m_has_lfence && m_has_pause && block->start == m_block_addr) {
                cs_x86 x86 = insn.detail->x86;

                if (x86.op_count < 1) {
                    LOG(FATAL) << "Invalid jmp op count at: 0x" << std::hex << insn.address;
                }
                cs_x86_op op0 = x86.operands[0];

                if (op0.type == X86_OP_IMM) {
                    if (op0.imm == block->start) {
//                        LOG(INFO) << "FOUND RETPOLINE THUNK AT: 0x" << std::hex << block->start;
//                        LOG(INFO) << "Func addr: 0x" << std::hex << block->func_addr;
                        m_retpoline = true;

                        auto func_block = m_blocks->find(make_range(block->func_addr));
                        if (func_block == m_blocks->end()) {
                            LOG(FATAL) << "Mising func block for retpoline thunk, addr: 0x" << std::hex << block->func_addr;
                        }

                        m_call_sites.insert(m_call_sites.end(), func_block->second.callers.begin(), func_block->second.callers.end());
                    }
                }
            }
            break;
        default:
            break;
        }
    }

    return 0;
}

int RetpolineCA::process_results() {
    m_results["has_retpoline"] = m_retpoline;
    m_results["call_sites"] = m_call_sites;

    return 0;
}
