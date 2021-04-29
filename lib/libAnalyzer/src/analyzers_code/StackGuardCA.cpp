#include <set>
#include <memory>
#include <cstdint>
#include <map>
#include <utility>

#include "capstone/capstone.h"
#include "glog/logging.h"
#include "json.hpp"

#include "Block.hpp"
#include "SymResolver.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/FuncBaseCA.hpp"
#include "analyzers_code/StackGuardCA.hpp"


StackGuardCA::StackGuardCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver, bool is_pe) :
    FuncBaseCA("stack_guards", arch, mode, std::move(resolver)),
    m_is_pe(is_pe),
    m_found_guard_func(false) {

    m_stack_guard_syms = {
        "___stack_chk_fail",
        "__stack_chk_fail",
        "__dl___stack_chk_fail",
        "__stack_chk_fail_local",
        "__stack_smash_handler" // Openbsd
    };
};

int StackGuardCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    cs_detail *detail = insn.detail;

    if (block->jump_block) {
        return 0;
    }

    if (m_arch == cs_arch::CS_ARCH_X86) {
        if (insn.id == X86_INS_INVALID) {
            return 0;
        }

        if (m_is_pe) {
            if (insn.id != X86_INS_MOV) {
                return 0;
            }

            if (m_found_guard_func) {
                return 0;
            }

            if (detail->x86.op_count < 2) {
                return 0;
            }

            cs_x86_op target = detail->x86.operands[0];
            cs_x86_op src = detail->x86.operands[1];

            // TODO: Do deeper analysis to find if this block matches the GS failure function
            if (target.mem.disp != 0x0 && src.imm == 0xc0000409) {
                auto func_block = m_blocks->find(make_range(block->func_addr));
                if (func_block == m_blocks->end()) {
                    LOG(FATAL) << "Bad function block: 0x" << std::hex << block->func_addr << " for block: 0x" << block->start;
                }
                if (func_block->second.callers.size() != 0) {
                    for (const auto &caller_addr : func_block->second.callers) {
                        // Ensure the caller is in the map
                        if (m_blocks->count(make_range(caller_addr))) {
                            m_guard_chk_calls.insert(caller_addr);
                        }
                    }
                    m_found_guard_func = true;
                }
            }

            return 0;
        }

        if (insn.id != X86_INS_CALL && insn.id != X86_INS_JMP) {
            return 0;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        if (insn.id == ARM_INS_INVALID) {
            return 0;
        }

        bool found_jmp = false;

        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];

            if (grp == ARM_GRP_JUMP) {
                found_jmp = true;
            }
        }

        if (!found_jmp) {
            return 0;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        if (insn.id == ARM64_INS_INVALID) {
            return 0;
        }

        bool found_jmp = false;

        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];

            if (grp == ARM64_GRP_JUMP) {
                found_jmp = true;
            }
        }

        // Some cases AARCH64 instructions group counts fail to generate
        // Add some extra checks just incase, this is fixed in capstone "next"
        // capstone tag: 4be19c3cbbf708451e116fbf7026b737a9ce3407
        switch(insn.id) {
        case ARM64_INS_B:
        case ARM64_INS_BL:
        case ARM64_INS_BLR:
            found_jmp = true;
            break;
        default:
            break;
        }

        if (!found_jmp) {
            return 0;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS)  {
        bool found_jmp = false;

        if (insn.id == MIPS_INS_INVALID) {
            return 0;
        }

        switch(insn.id) {
        case MIPS_INS_BAL:
        case MIPS_INS_B:
        case MIPS_INS_BLTZAL:
        case MIPS_INS_BGEZAL:
        case MIPS_INS_J:
        case MIPS_INS_JAL:
        case MIPS_INS_JALR:
            found_jmp = true;
            break;
        default:
            return 0;
        }

        if (!found_jmp) {
            return 0;
        }
    }

    if (!call_sym) {
        return 0;
    }

    for (const auto &sym : m_stack_guard_syms) {
        if (call_sym->name == sym) {
            m_guard_chk_calls.insert(insn.address);
            break;
        }
    }

    return 0;
}

int StackGuardCA::process_results() {
    m_results["stack_guard_calls"] = m_guard_chk_calls;

    return 0;
}
