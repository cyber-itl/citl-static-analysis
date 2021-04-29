#include <cassert>
#include <cstdio>
#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

#include "glog/logging.h"
#include "json.hpp"
#include "capstone/capstone.h"

#include "analyzers/SpectreWidgetEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ObjectFile.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Error.h"

using namespace llvm;
using namespace object;

#define WIDGET_MAX_LEN 64

class Counts {
public:
    std::vector<uint64_t> m_insn_cnts; // instrunctions per widget
    std::vector<uint64_t> m_byte_cnts; // bytes per widget
    std::vector<uint64_t> m_reg_cnts; // register indexes used
    std::vector<uint64_t> m_arg_cnts; // number of ABI argument registers in widget for ABI arg only widgets
    std::vector<uint64_t> m_rsv_cnts; // number of ABI reserved registers in widget for ABI rsv only widgets
    std::vector<uint64_t> m_argrsv_cnts; // number of ABI arg + rsv registers in widget for ABI arg + rsv only widgets
    uint64_t m_arg_mask;
    uint64_t m_rsv_mask;
    uint64_t m_argrsv_mask;

    Counts() : m_arg_cnts(0), m_rsv_mask(0), m_argrsv_mask(0) {};
    Counts(size_t regs, uint64_t arg_mask, uint64_t rsv_mask)
        : m_insn_cnts(WIDGET_MAX_LEN + 1), m_byte_cnts(WIDGET_MAX_LEN + 1), m_reg_cnts(regs + 1),
          m_arg_mask(arg_mask), m_rsv_mask(rsv_mask), m_argrsv_mask(arg_mask | rsv_mask) {
        uint64_t mask;
        size_t arg_cnt = 0;
        size_t rsv_cnt = 0;
        size_t argrsv_cnt = 0;

        for(mask = 1; mask; mask <<= 1) {
            if(m_arg_mask & mask) {
                arg_cnt++;
            }
            if(m_rsv_mask & mask) {
                rsv_cnt++;
            }
            if(m_argrsv_mask & mask) {
                argrsv_cnt++;
            }
        }
        m_arg_cnts = std::vector<uint64_t>(arg_cnt + 1);
        m_rsv_cnts = std::vector<uint64_t>(rsv_cnt + 1);
        m_argrsv_cnts = std::vector<uint64_t>(argrsv_cnt + 1);
        return;
    }
};

#define RAX_INDEX       0
#define RCX_INDEX       1
#define RDX_INDEX       2
#define RBX_INDEX       3
#define RSP_INDEX       4
#define RBP_INDEX       5
#define RSI_INDEX       6
#define RDI_INDEX       7
#define R8_INDEX        8
#define R9_INDEX        9
#define R10_INDEX       10
#define R11_INDEX       11
#define R12_INDEX       12
#define R13_INDEX       13
#define R14_INDEX       14
#define R15_INDEX       15
#define REG_INVALID_INDEX   16

#define RAX_MASK        (1 << RAX_INDEX)
#define RCX_MASK        (1 << RCX_INDEX)
#define RDX_MASK        (1 << RDX_INDEX)
#define RBX_MASK        (1 << RBX_INDEX)
#define RSP_MASK        (1 << RSP_INDEX)
#define RBP_MASK        (1 << RBP_INDEX)
#define RSI_MASK        (1 << RSI_INDEX)
#define RDI_MASK        (1 << RDI_INDEX)
#define R8_MASK         (1 << R8_INDEX)
#define R9_MASK         (1 << R9_INDEX)
#define R10_MASK        (1 << R10_INDEX)
#define R11_MASK        (1 << R11_INDEX)
#define R12_MASK        (1 << R12_INDEX)
#define R13_MASK        (1 << R13_INDEX)
#define R14_MASK        (1 << R14_INDEX)
#define R15_MASK        (1 << R15_INDEX)
#define REG_INVALID_MASK    (1 << REG_INVALID_INDEX)

/* This shouldn't need to exist, and even so should be a table.  We'll only concern ourselves
 * with general purpose registers for now
 */
static inline uint8_t capstone_to_x86(uint8_t reg) {
    switch(reg) {
    case X86_REG_AH:
    case X86_REG_AL:
    case X86_REG_AX:
    case X86_REG_EAX:
    case X86_REG_RAX:
        return RAX_INDEX;
    case X86_REG_CL:
    case X86_REG_CH:
    case X86_REG_CX:
    case X86_REG_ECX:
    case X86_REG_RCX:
        return RCX_INDEX;
    case X86_REG_DL:
    case X86_REG_DH:
    case X86_REG_DX:
    case X86_REG_EDX:
    case X86_REG_RDX:
        return RDX_INDEX;
    case X86_REG_BL:
    case X86_REG_BH:
    case X86_REG_BX:
    case X86_REG_EBX:
    case X86_REG_RBX:
        return RBP_INDEX;
    case X86_REG_SPL:
    case X86_REG_SP:
    case X86_REG_ESP:
    case X86_REG_RSP:
        return RSP_INDEX;
    case X86_REG_BPL:
    case X86_REG_BP:
    case X86_REG_EBP:
    case X86_REG_RBP:
        return RBP_INDEX;
    case X86_REG_SIL:
    case X86_REG_SI:
    case X86_REG_ESI:
    case X86_REG_RSI:
        return RSI_INDEX;
    case X86_REG_DIL:
    case X86_REG_DI:
    case X86_REG_EDI:
    case X86_REG_RDI:
        return RDI_INDEX;
    case X86_REG_R8B:
    case X86_REG_R8W:
    case X86_REG_R8D:
    case X86_REG_R8:
        return R8_INDEX;
    case X86_REG_R9B:
    case X86_REG_R9W:
    case X86_REG_R9D:
    case X86_REG_R9:
        return R9_INDEX;
    case X86_REG_R10B:
    case X86_REG_R10W:
    case X86_REG_R10D:
    case X86_REG_R10:
        return R10_INDEX;
    case X86_REG_R11B:
    case X86_REG_R11W:
    case X86_REG_R11D:
    case X86_REG_R11:
        return R11_INDEX;
    case X86_REG_R12B:
    case X86_REG_R12W:
    case X86_REG_R12D:
    case X86_REG_R12:
        return R12_INDEX;
    case X86_REG_R13B:
    case X86_REG_R13W:
    case X86_REG_R13D:
    case X86_REG_R13:
        return R13_INDEX;
    case X86_REG_R14B:
    case X86_REG_R14W:
    case X86_REG_R14D:
    case X86_REG_R14:
        return R14_INDEX;
    case X86_REG_R15B:
    case X86_REG_R15W:
    case X86_REG_R15D:
    case X86_REG_R15:
        return R15_INDEX;
    default:
        return REG_INVALID_INDEX;
    }
}

enum ref_pattern_state {
    FIND_LOAD,
    FIND_LOAD_OR_STORE
};

static bool find_ref_pattern(csh cs_handle, cs_insn *insn, const uint8_t *ptr, size_t length, Counts *counts) {
    enum ref_pattern_state state;
    uint64_t addr;
    cs_detail *detail;
    cs_x86 *x86;
    cs_x86_op *op;
    uint8_t content_reg, op_idx;
    uint64_t used_regs;
    size_t remain, insn_cnt;

    state = FIND_LOAD;
    addr = 0;
    remain = length;
    insn_cnt = 0;
    used_regs = 0;

    while(remain) {
        if(!cs_disasm_iter(cs_handle, &ptr, &remain, &addr, insn)) {
            if(cs_errno(cs_handle) != 0)
            printf("ERROR: %d\n", cs_errno(cs_handle));
            return false;
        }
        /* check for bailout conditions */
        if(insn->id == X86_INS_INVALID) { /* should be caught by CS_GRP_INVALID... should be */
            return false;
        }

        detail = insn->detail;
        for(uint8_t i = 0; i < detail->groups_count; i++) {
            switch(detail->groups[i]) {
            case CS_GRP_INVALID:
            case CS_GRP_JUMP: // not necessarily true for conditional static branches
            case CS_GRP_CALL:
            case CS_GRP_RET: // not necessarily true, re: gcc padding wars of the late 90's
            case CS_GRP_INT:
            case CS_GRP_IRET:
            case X86_GRP_VM:
                return false;
                break;
            default:
                break;
            }
        }

        insn_cnt++;
        x86 = &detail->x86;

        switch(state) {
        case FIND_LOAD:
            /* Force first widget instruction to be our leak load.
             * This isn't true, as widgets can be found that generate
             * a usable known register value, but the scanner would
             * need semantic information.
             */

            /* Ignore destination argument as potential load.  This
             * isn't true, as exchange and even compare type operations
             * can be utilized to leak contents.  This however requires
             * a semantic model.
             *
             * We only search for op reg,[base (+ index)] where reg
             * must be a general purpose register and base or index must
             * be a general purpose register.
             */
            if(x86->op_count < 2) {
                return false;
            }
            op = &x86->operands[0];
            if(op->type != X86_OP_REG) {
                return false;
            }

            content_reg = capstone_to_x86(op->reg);
            if(content_reg >= 16) {
                return false;
            }

            for(op_idx = 1, op++; op_idx < x86->op_count; op_idx++, op++) {
                if(op->type == X86_OP_MEM) {
                    if(capstone_to_x86(op->mem.base) < 16 || capstone_to_x86(op->mem.index) < 16) {
                        uint8_t reg;
                        reg = capstone_to_x86(op->mem.base);
                        if (reg != REG_INVALID_INDEX) {
                            used_regs |= (1 << reg);
                        }
                        reg = capstone_to_x86(op->mem.index);
                        if (reg != REG_INVALID_INDEX) {
                            used_regs |= (1 << reg);
                        }
                        break;
                    }
                }
            }
            /* memory operand not found, bail on this block */
            if(op_idx >= x86->op_count) {
                return false;
            }
            state = FIND_LOAD_OR_STORE;
            break;
        case FIND_LOAD_OR_STORE:
            for(uint8_t op_idx = 0; op_idx < x86->op_count; op_idx++) {
                op = &x86->operands[op_idx];
                if(op->type == X86_OP_MEM) {
                    if(capstone_to_x86(op->mem.base) == content_reg || capstone_to_x86(op->mem.index) == content_reg) {
                        uint8_t reg;
                        reg = capstone_to_x86(op->mem.base);
                        if(reg != REG_INVALID_INDEX && reg != content_reg) {
                            used_regs |= (1 << reg);
                        }

                        reg = capstone_to_x86(op->mem.index);
                        if(reg != REG_INVALID_INDEX && reg != content_reg) {
                            used_regs |= (1 << reg);
                        }

                        /* update counts */
                        assert(length > remain);
                        assert((length - remain) < counts->m_byte_cnts.size());
                        assert(insn_cnt > 0);
                        assert(insn_cnt < counts->m_insn_cnts.size());
                        counts->m_byte_cnts[(length - remain)]++;
                        counts->m_insn_cnts[insn_cnt]++;

                        size_t reg_cnt;
                        uint64_t mask;

                        if((used_regs & counts->m_arg_mask) == used_regs) {
                            reg_cnt = 0;
                            for(mask = 1; mask; mask <<= 1) {
                                if(used_regs & mask) {
                                    reg_cnt++;
                                }
                            }
                            assert(reg_cnt < counts->m_arg_cnts.size());
                            counts->m_arg_cnts[reg_cnt]++;
                        }
                        if((used_regs & counts->m_rsv_mask) == used_regs) {
                            reg_cnt = 0;
                            for(mask = 1; mask; mask <<= 1) {
                                if(used_regs & mask) {
                                    reg_cnt++;
                                }
                            }
                            assert(reg_cnt < counts->m_rsv_cnts.size());
                            counts->m_rsv_cnts[reg_cnt]++;
                        }
                        if((used_regs & counts->m_argrsv_mask) == used_regs) {
                            reg_cnt = 0;
                            for(mask = 1; mask; mask <<= 1) {
                                if(used_regs & mask) {
                                    reg_cnt++;
                                }
                            }
                            assert(reg_cnt < counts->m_argrsv_cnts.size());
                            counts->m_argrsv_cnts[reg_cnt]++;
                        }

                        reg_cnt = 0;
                        for(mask = 1; mask; mask <<= 1) {
                            if(used_regs & mask) {
                                reg_cnt++;
                            }
                        }
                        assert(reg_cnt < counts->m_reg_cnts.size());
                        counts->m_reg_cnts[reg_cnt]++;
                        return true;
                    }
                }
            }
            break;
        default: /* should never happen */
            break;
        }
    } /* while(remain) */
    return false;
}

#define X86_32_REG_NUM          8
#define X86_32_SYSV_ARG_MASK    0 // all args on stack
#define X86_32_SYSV_RSV_MASK    (RBX_MASK | RSI_MASK | RDI_MASK | RBP_MASK | RSP_MASK)
// assume __stdcall
#define X86_32_WIN_ARG_MASK     0 // all args on stack
#define X86_32_WIN_RSV_MASK     (RBX_MASK | RSI_MASK | RDI_MASK | RBP_MASK | RSP_MASK)
#define X86_32_OSX_ARG_MASK     0 // all args on stack
#define X86_32_OSX_RSV_MASK     (RBX_MASK | RSI_MASK | RDI_MASK | RBP_MASK | RSP_MASK)


#define X86_64_REG_NUM          16
#define X86_64_SYSV_ARG_MASK    (RDI_MASK | RSI_MASK | RDX_MASK | RCX_MASK | R8_MASK | R9_MASK)
#define X86_64_SYSV_RSV_MASK    (RBX_MASK | RSP_MASK | RBP_MASK | R12_MASK | R13_MASK | R14_MASK | R15_MASK)
#define X86_64_WIN_ARG_MASK     (RCX_MASK | RDX_MASK | R8_MASK | R9_MASK)
#define X86_64_WIN_RSV_MASK     (RBX_MASK | RBP_MASK | RDI_MASK | RSI_MASK | RSP_MASK | R12_MASK | R13_MASK | R14_MASK | R15_MASK)
#define X86_64_OSX_ARG_MASK     (RDI_MASK | RSI_MASK | RDX_MASK | RCX_MASK | R8_MASK | R9_MASK)
#define X86_64_OSX_RSV_MASK     (RBX_MASK | RSP_MASK | RBP_MASK | R12_MASK | R13_MASK | R14_MASK | R15_MASK)

SpectreWidgetEA::SpectreWidgetEA(const ObjectFile *obj) : BaseEnvAnalyzer("spectrewidget"), m_obj(obj) {};

int SpectreWidgetEA::run() {
    csh cs_handle;
    cs_insn *insn;
    cs_arch arch;
    cs_mode mode;
    Counts counts;
    std::string objfmt;

    objfmt = m_obj->getFileFormatName().data();
    if(objfmt == "ELF64-x86-64") {
        arch = cs_arch::CS_ARCH_X86;
        mode = cs_mode::CS_MODE_64;
        counts = Counts(X86_64_REG_NUM, X86_64_SYSV_ARG_MASK, X86_64_SYSV_RSV_MASK);
    }
    else if(objfmt == "ELF32-i386") {
        arch = cs_arch::CS_ARCH_X86;
        mode = cs_mode::CS_MODE_32;
        counts = Counts(X86_32_REG_NUM, X86_32_SYSV_ARG_MASK, X86_32_SYSV_RSV_MASK);
    }
    else if(objfmt == "Mach-O 64-bit x86-64") {
        arch = cs_arch::CS_ARCH_X86;
        mode = cs_mode::CS_MODE_64;
        counts = Counts(X86_64_REG_NUM, X86_64_OSX_ARG_MASK, X86_64_OSX_RSV_MASK);
    }
    else if(objfmt == "Mach-O 32-bit i386") {
        arch = cs_arch::CS_ARCH_X86;
        mode = cs_mode::CS_MODE_32;
        counts = Counts(X86_32_REG_NUM, X86_32_OSX_ARG_MASK, X86_32_OSX_RSV_MASK);
    }
    else if(objfmt == "COFF-x86-64") {
        arch = cs_arch::CS_ARCH_X86;
        mode = cs_mode::CS_MODE_64;
        counts = Counts(X86_64_REG_NUM, X86_64_WIN_ARG_MASK, X86_64_WIN_RSV_MASK);
    }
    else if(objfmt == "COFF-i386") {
        arch = cs_arch::CS_ARCH_X86;
        mode = cs_mode::CS_MODE_32;
        counts = Counts(X86_32_REG_NUM, X86_32_WIN_ARG_MASK, X86_32_WIN_RSV_MASK);
    }
    else {
        return 0;
    }

    for(const SectionRef &section : m_obj->sections()) {
        if(!section.isText()) {
            continue;
        }

        Expected<StringRef> sectDataErr = section.getContents();
        if (!sectDataErr) {
            std::error_code EC = errorToErrorCode(sectDataErr.takeError());
            LOG(ERROR) << "Failed to get section contents, err: " << EC.message();
            continue;
        }
        auto contents = sectDataErr.get();

        if(cs_open(arch, mode, &cs_handle) != CS_ERR_OK) {
            return 0;
        }
        cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

        insn = cs_malloc(cs_handle);

        size_t contents_size = contents.size();
        const uint8_t *ptr = (const uint8_t *) contents.data();

        for(; contents_size; contents_size--, ptr++) {
            size_t remain = WIDGET_MAX_LEN;
            if(remain > contents_size) {
                remain = contents_size;
            }

            //printf("NEXT PTR: %p %lld\n", ptr, remain);
            find_ref_pattern(cs_handle, insn, ptr, remain, &counts);
        } /* contents loop */
        cs_free(insn, 1);
        cs_close(&cs_handle);
    } /* section loop */

    m_results["insn_cnts"] = counts.m_insn_cnts;
    m_results["byte_cnts"] = counts.m_byte_cnts;
    m_results["reg_cnts"] = counts.m_reg_cnts;
    m_results["arg_cnts"] = counts.m_arg_cnts;
    m_results["rsv_cnts"] = counts.m_rsv_cnts;
    m_results["argrsv_cnts"] = counts.m_argrsv_cnts;

    return 0;
}
