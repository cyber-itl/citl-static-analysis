#include <tuple>
#include <cstdint>

#include "glog/logging.h"
#include "capstone/capstone.h"
#include "llvm/ADT/Triple.h"

#include "CapstoneHelper.hpp"

using namespace llvm;


std::tuple<cs_arch, cs_mode> map_triple_cs(uint32_t triple) {
    cs_arch arch;
    cs_mode mode;
    switch(triple) {
    case Triple::x86:
        arch = cs_arch::CS_ARCH_X86;
        mode = cs_mode::CS_MODE_32;
        break;
    case Triple::x86_64:
        arch = cs_arch::CS_ARCH_X86;
        mode = cs_mode::CS_MODE_64;
        break;

    case Triple::arm:
        arch = cs_arch::CS_ARCH_ARM;
        mode = cs_mode::CS_MODE_ARM;
        break;
    case Triple::aarch64:
        arch = cs_arch::CS_ARCH_ARM64;
        mode = cs_mode::CS_MODE_ARM;
        break;
    case Triple::aarch64_be:
        arch = cs_arch::CS_ARCH_ARM64;
        mode = static_cast<cs_mode>(cs_mode::CS_MODE_ARM + cs_mode::CS_MODE_BIG_ENDIAN);
        break;
    case Triple::mips:
        arch = cs_arch::CS_ARCH_MIPS;
        mode = static_cast<cs_mode>(cs_mode::CS_MODE_MIPS32 + cs_mode::CS_MODE_BIG_ENDIAN);
        break;
    case Triple::mipsel:
        arch = cs_arch::CS_ARCH_MIPS;
        mode = static_cast<cs_mode>(cs_mode::CS_MODE_MIPS32 + cs_mode::CS_MODE_LITTLE_ENDIAN);
        break;
    case Triple::mips64:
        arch = cs_arch::CS_ARCH_MIPS;
        mode = static_cast<cs_mode>(cs_mode::CS_MODE_MIPS64 + cs_mode::CS_MODE_BIG_ENDIAN);
        break;
    case Triple::mips64el:
        arch = cs_arch::CS_ARCH_MIPS;
        mode = static_cast<cs_mode>(cs_mode::CS_MODE_MIPS64 + cs_mode::CS_MODE_LITTLE_ENDIAN);
        break;
    case Triple::ppc:
        arch = cs_arch::CS_ARCH_PPC;
        mode = static_cast<cs_mode>(cs_mode::CS_MODE_32 + cs_mode::CS_MODE_BIG_ENDIAN);
        break;
    case Triple::ppc64:
        arch = cs_arch::CS_ARCH_PPC;
        mode = static_cast<cs_mode>(cs_mode::CS_MODE_64 + cs_mode::CS_MODE_BIG_ENDIAN);
        break;
    case Triple::ppc64le:
        arch = cs_arch::CS_ARCH_PPC;
        mode = static_cast<cs_mode>(cs_mode::CS_MODE_64);
        break;

    default:
        LOG(FATAL) << "Unsupported architecture: " << triple;
    }

    return std::make_tuple(arch, mode);
}


std::vector<uint64_t> get_imm_vals(const cs_insn &insn, cs_arch arch, uint32_t base_reg, uint64_t reg_val) {
    std::vector<uint64_t> ret = std::vector<uint64_t>();
    if (!insn.id) {
        return ret;
    }

    if (!insn.detail) {
        return ret;
    }

    if (arch == cs_arch::CS_ARCH_X86) {
        cs_x86 x86 = insn.detail->x86;
        for (uint8_t i = 0; i < x86.op_count; i++) {
            cs_x86_op op = x86.operands[i];

            switch(op.type) {
            case X86_OP_IMM:
                ret.push_back(op.imm);
                break;
            case X86_OP_MEM:
                if (op.mem.base == X86_REG_RIP) {
                    ret.push_back(insn.address + insn.size + op.mem.disp);
                }
                else if (op.mem.base == base_reg) {
                    ret.push_back(op.mem.disp + reg_val);
                }
                else if (op.mem.base == X86_REG_INVALID && op.mem.disp != X86_REG_INVALID) {
                    ret.push_back(op.mem.disp);
                }
                break;
            default:
                continue;
            }
        }
    }

    return ret;
}

bool is_nop(cs_arch arch, cs_insn *insn) {
    switch (arch) {
    case cs_arch::CS_ARCH_X86:
        switch (insn->id) {
        case X86_INS_NOP:
        case X86_INS_FNOP:
            return true;
        default:
            break;
        }
        break;
    case cs_arch::CS_ARCH_ARM:
        if (insn->id == ARM_INS_NOP) {
            return true;
        }
        else if (insn->id == ARM_INS_MOV) {
            if (insn->detail->arm.op_count == 2) {
                if (insn->detail->arm.operands[0].type == ARM_OP_REG && insn->detail->arm.operands[1].type == ARM_OP_REG) {
                    if (insn->detail->arm.operands[0].reg == insn->detail->arm.operands[1].reg) {
                        return true;
                    }
                }
            }
        }
        break;
    case cs_arch::CS_ARCH_ARM64:
        if (insn->id == ARM64_INS_NOP) {
            return true;
        }
        break;
    case cs_arch::CS_ARCH_MIPS:
        if (insn->id == MIPS_INS_NOP) {
            return true;
        }
        if (insn->id == MIPS_INS_MOVE) {
            cs_mips mips = insn->detail->mips;
            if (mips.op_count != 2) {
                break;
            }

            cs_mips_op op0 = mips.operands[0];
            cs_mips_op op1 = mips.operands[1];
            if (op0.type == MIPS_OP_REG && op1.type == MIPS_OP_REG) {
                if (op0.reg == MIPS_REG_ZERO && op1.reg == MIPS_REG_RA) {
                    return true;
                }
            }
        }
        break;
    case cs_arch::CS_ARCH_PPC:
        if (insn->id == PPC_INS_NOP) {
            return true;
        }
        break;
    default:
        break;
    }
    return false;
}

bool is_pc_in_arm_ops(cs_arm arm_details) {
    for (uint8_t i = 0; i < arm_details.op_count; i++) {
        cs_arm_op oper = arm_details.operands[i];
        if (oper.reg == ARM_REG_PC) {
            return true;
        }
    }

    return false;
}

bool is_lr_in_arm_ops(cs_arm arm_details) {
    for (uint8_t i = 0; i < arm_details.op_count; i++) {
        cs_arm_op oper = arm_details.operands[i];
        if (oper.reg == ARM_REG_LR) {
            return true;
        }
    }

    return false;
}

unsigned rotr32(unsigned val, unsigned amt) {
    return (val >> amt) | (val << ((32-amt)&31));
}


