#include <map>
#include <string>
#include <cstdint>
#include <sstream>
#include <vector>
#include <tuple>

#include "glog/logging.h"

#include "capstone/capstone.h"

#include "Block.hpp"
#include "TraceDefs.hpp"
#include "LiftingAnalyzer.hpp"
#include "CapstoneHelper.hpp"


Lifter::Lifter() : m_arch(cs_arch::CS_ARCH_X86) {};
Lifter::Lifter(cs_arch arch) : m_arch(arch) {};

bool Lifter::check_mem_op_x86(cs_insn *insn, uint8_t load_op) {
    cs_x86 x86 = insn->detail->x86;

    if (load_op > x86.op_count) {
        LOG(FATAL) << "Invalid check_mem_op_x86 operand index: " << load_op;
    }

    cs_x86_op op = x86.operands[load_op];

    return op.type == X86_OP_MEM;
}

bool Lifter::check_stack(cs_insn *insn, uint8_t op_idx) {
    cs_x86 x86 = insn->detail->x86;

    if (op_idx > x86.op_count) {
        LOG(FATAL) << "Invalid check_stack operand index: " << op_idx;
    }

    cs_x86_op op = x86.operands[op_idx];

    if (op.type == X86_OP_MEM) {
        if (op.mem.base == X86_REG_RSP || op.mem.base == X86_REG_ESP) {
            return true;
        }
    }

    return false;
}

std::vector<Lifter::insn_class> Lifter::update_x86(cs_insn *insn) {
    std::vector<insn_class> ret;
    if (insn->id == X86_INS_INVALID || insn->id == X86_INS_NOP) {
        return ret;
    }
    cs_x86 x86 = insn->detail->x86;


    // Load and stores
    bool mem_op = false;
    if (x86.op_count > 0) {
        for (uint8_t i = 0; i < x86.op_count; i++) {
            cs_x86_op op = x86.operands[i];
            if (op.type == X86_OP_MEM) {
                mem_op = true;
                break;
            }
        }

    }

    if (mem_op) {
        switch (insn->id) {
            // reader / writer instructions
            case X86_INS_ADD:
            case X86_INS_AND:
            case X86_INS_ANDN:
            case X86_INS_OR:
            case X86_INS_XOR:
            case X86_INS_NOT:
            case X86_INS_SUB:
            case X86_INS_LEA:
            case X86_INS_MOV:
            case X86_INS_MOVABS:
            case X86_INS_MOVBE:
            case X86_INS_MOVD:
            case X86_INS_MOVSB:
            case X86_INS_MOVSD:
            case X86_INS_MOVSW:
            case X86_INS_MOVSX:
            case X86_INS_MOVSXD:
            case X86_INS_MOVZX:
            case X86_INS_MOVAPS:
            case X86_INS_MOVUPS:
            case X86_INS_MOVDQU:
            case X86_INS_MOVDQA:
                if (check_mem_op_x86(insn, 1)) {
                    ret.emplace_back(insn_class::LOAD);

                    if (check_stack(insn, 1)) {
                        ret.emplace_back(insn_class::STACK_OP);
                    }
                }
                else if (check_mem_op_x86(insn, 0)) {
                    ret.emplace_back(insn_class::STORE);

                    if (check_stack(insn, 0)) {
                        ret.emplace_back(insn_class::STACK_OP);
                    }
                }
                break;

            // Reader instructions
            case X86_INS_CMP:
            case X86_INS_TEST:
                ret.emplace_back(insn_class::LOAD);
                break;

            // Writer instructions:
            case X86_INS_SETAE:
            case X86_INS_SETA:
            case X86_INS_SETBE:
            case X86_INS_SETB:
            case X86_INS_SETE:
            case X86_INS_SETGE:
            case X86_INS_SETG:
            case X86_INS_SETLE:
            case X86_INS_SETL:
            case X86_INS_SETNE:
            case X86_INS_SETNO:
            case X86_INS_SETNP:
            case X86_INS_SETNS:
            case X86_INS_SETO:
            case X86_INS_SETP:
            case X86_INS_SETS:
                ret.emplace_back(insn_class::STORE);
                break;
            default:
                if (mem_op && (insn->id != X86_INS_CALL && insn->id != X86_INS_JMP)) {
                    LOG(INFO) << "Missing mem:   0x" << std::hex << insn->address << ": " << insn->mnemonic << " " << insn->op_str;
                }
                break;
        }
    }



    // Stack
    switch (insn->id) {
        case X86_INS_POP:
        case X86_INS_POPAL:
        case X86_INS_POPAW:
        case X86_INS_POPF:
        case X86_INS_POPFD:
        case X86_INS_POPFQ:
            ret.emplace_back(insn_class::LOAD);
            ret.emplace_back(insn_class::STACK_OP);
            break;

        case X86_INS_PUSH:
        case X86_INS_PUSHAL:
        case X86_INS_PUSHAW:
        case X86_INS_PUSHF:
        case X86_INS_PUSHFD:
        case X86_INS_PUSHFQ:
            ret.emplace_back(insn_class::STORE);
            ret.emplace_back(insn_class::STACK_OP);
            break;

        default:
            break;
    }

    // Arithmetic
    switch (insn->id) {
        case X86_INS_AAA:
        case X86_INS_XADD:
        case X86_INS_AAD:
        case X86_INS_AAM:
        case X86_INS_AAS:
        case X86_INS_DAA:
        case X86_INS_CWD:
        case X86_INS_CWDE:
        case X86_INS_CBW:
        case X86_INS_DIV:
        case X86_INS_IDIV:
        case X86_INS_NEG:
        case X86_INS_IMUL:
        case X86_INS_MUL:
        case X86_INS_MULX:
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_INC:
        case X86_INS_DEC: {
            ret.emplace_back(insn_class::ARITHMETIC);
            break;
        }
        default:
            break;
    }

    // Logical
    switch (insn->id) {
        case X86_INS_XOR:
        case X86_INS_AND:
        case X86_INS_ANDN:
        case X86_INS_NOT:
        case X86_INS_OR:
        case X86_INS_SHL:
        case X86_INS_SHLD:
        case X86_INS_SHLX:
        case X86_INS_SHR:
        case X86_INS_SHRD:
        case X86_INS_SHRX:
            ret.emplace_back(insn_class::LOGICAL);
            break;

        default:
            break;
    }

    // Comparative
    switch (insn->id) {
        case X86_INS_CMP:
        case X86_INS_CMPXCHG:
        case X86_INS_CMPXCHG16B:
        case X86_INS_CMPXCHG8B:
        case X86_INS_TEST:
            ret.emplace_back(insn_class::COMP);
            break;
        default:
            break;
    }

    // CALL vs COND termination insn
    bool is_jump_grp = false;
    for (uint8_t i = 0; i < insn->detail->groups_count; i++) {
        uint8_t grp = insn->detail->groups[i];
        if (grp == X86_GRP_JUMP) {
            is_jump_grp = true;
            break;
        }
    }
    switch (insn->id) {
        case X86_INS_JMP:
        case X86_INS_CALL:
        case X86_INS_LCALL:
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
        case X86_INS_LEAVE:
        case X86_INS_SYSCALL:
        case X86_INS_INT:
            ret.emplace_back(insn_class::CALL_TERM);
            break;

        default:
            if (is_jump_grp) {
                ret.emplace_back(insn_class::COND_TERM);
            }
            break;
    }

    // FPU
    switch (insn->id) {
        case X86_INS_FADD:
        case X86_INS_FIADD:
        case X86_INS_FADDP:
        case X86_INS_F2XM1:
        case X86_INS_FABS:
        case X86_INS_FBLD:
        case X86_INS_FBSTP:
        case X86_INS_FCOMPP:
        case X86_INS_FDECSTP:
        case X86_INS_FEMMS:
        case X86_INS_FFREE:
        case X86_INS_FICOM:
        case X86_INS_FICOMP:
        case X86_INS_FINCSTP:
        case X86_INS_FLDCW:
        case X86_INS_FLDENV:
        case X86_INS_FLDL2E:
        case X86_INS_FLDL2T:
        case X86_INS_FLDLG2:
        case X86_INS_FLDLN2:
        case X86_INS_FLDPI:
        case X86_INS_FNCLEX:
        case X86_INS_FNINIT:
        case X86_INS_FNOP:
        case X86_INS_FNSTCW:
        case X86_INS_FNSTSW:
        case X86_INS_FPATAN:
        case X86_INS_FPREM:
        case X86_INS_FPREM1:
        case X86_INS_FPTAN:
        case X86_INS_FRNDINT:
        case X86_INS_FRSTOR:
        case X86_INS_FNSAVE:
        case X86_INS_FSCALE:
        case X86_INS_FSETPM:
        case X86_INS_FSINCOS:
        case X86_INS_FNSTENV:
        case X86_INS_FXAM:
        case X86_INS_FXRSTOR:
        case X86_INS_FXRSTOR64:
        case X86_INS_FXSAVE:
        case X86_INS_FXSAVE64:
        case X86_INS_FXTRACT:
        case X86_INS_FYL2X:
        case X86_INS_FYL2XP1:
        case X86_INS_FILD:
        case X86_INS_FISTTP:
        case X86_INS_FIST:
        case X86_INS_FISTP:
        case X86_INS_FLDZ:
        case X86_INS_FLD1:
        case X86_INS_FLD:
        case X86_INS_FMUL:
        case X86_INS_FIMUL:
        case X86_INS_FMULP:
        case X86_INS_FSIN:
        case X86_INS_FSQRT:
        case X86_INS_FST:
        case X86_INS_FSTP:
        case X86_INS_FSTPNCE:
        case X86_INS_FSUBR:
        case X86_INS_FISUBR:
        case X86_INS_FSUBRP:
        case X86_INS_FSUB:
        case X86_INS_FISUB:
        case X86_INS_FSUBP:
        case X86_INS_FUCOMI:
        case X86_INS_FUCOMPP:
        case X86_INS_FUCOMP:
        case X86_INS_FUCOM:
            ret.emplace_back(insn_class::FPU);
            break;
        default:
            break;
    }

    return ret;
}

std::vector<Lifter::insn_class> Lifter::update(cs_insn *insn) {
    switch (m_arch) {
    case cs_arch::CS_ARCH_X86:
        return update_x86(insn);
        break;
    default:
        LOG(FATAL) << "Unsupported arch for classification";
    }

    return {};
}

std::string Lifter::class_to_str(Lifter::insn_class insn_class) {
    return std::string(insn_class_str[insn_class]);
}


LiftingAnalyzer::LiftingAnalyzer(std::map<uint64_t, Module> *mod_map) : TraceAnalyzer(mod_map, "lift") {};

void LiftingAnalyzer::output_header() {}
void LiftingAnalyzer::output_results() {}

bool LiftingAnalyzer::init() {
    if (inited) {
        return true;
    }

    // Assume the first module is representative of the process
    if (m_mod_map->empty()) {
        LOG(ERROR) << "Empty module map, could not init analyzer: " << m_name;
        return false;
    }

    auto mod = m_mod_map->cbegin();

    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(mod->second.obj->getArch());
    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    m_lifter = Lifter(arch);

    cs_err err;
    err = cs_open(arch, mode, &m_cs_handle);
    if (err != CS_ERR_OK) {
        LOG(ERROR) << "cs_open: " << cs_strerror(err);
        return false;
    }
    cs_option(m_cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    inited = true;

    return true;
}

bool LiftingAnalyzer::on_trace_elm(uint32_t modid, uint32_t offset, uint32_t pid, uint32_t tid, log_fault *fault) {
    auto module = m_mod_map->find(modid);
    if (module == m_mod_map->end()) {
        LOG(ERROR) << "Failed to find module: " << modid;
        return false;
    }

    auto block = module->second.block_map->find(make_range(offset));
    if (block == module->second.block_map->end()) {
        LOG(ERROR) << "Failed to find offset: 0x" << std::hex << offset << " in modid: " << modid;
        return false;
    }

    cs_insn *insn = cs_malloc(m_cs_handle);
    cs_option(m_cs_handle, CS_OPT_MODE, block->second.mode);

    const uint8_t *data_ptr = block->second.data;
    uint64_t tmp_block_addr = block->second.start;
    uint64_t block_size = block->second.end - block->second.start;

    while(cs_disasm_iter(m_cs_handle, &data_ptr, &block_size, &tmp_block_addr, insn)) {
        // LOG(INFO) << "  0x" << std::hex << insn->address << ": " << insn->mnemonic << " " << insn->op_str;

        auto lifted = m_lifter.update(insn);
        for (const auto &lift_insn : lifted) {
            // json row;
            // row["serial"] = m_tc->serial;
            // row["modid"] = modid;
            // row["pid"] = pid;
            // row["tid"] = tid;
            // row["offset"] = offset;
            // row["block_id"] = m_block_count;
            // row["lift"] = m_lifter.class_to_str(lift_insn);
            // row["signum"] = fault ? fault->signum : 0;

            // m_results.emplace_back(row);
        }
    }

    cs_free(insn, 1);

    return true;
}