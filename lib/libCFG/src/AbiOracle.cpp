#include <map>
#include <cstdint>
#include <utility>

#include "capstone/capstone.h"
#include "glog/logging.h"

#include "CfgRes.hpp"
#include "AbiOracle.hpp"
#include "Utils.hpp"
#include "CapstoneHelper.hpp"

void AbiOracle::setup_regs() {
    switch (m_type) {
    case bin_type::COFF:
        if (m_arch == cs_arch::CS_ARCH_X86) {
            if (m_mode == cs_mode::CS_MODE_32) {
                // https://msdn.microsoft.com/en-us/library/984x0h58.aspx
                m_abi_bucket.emplace(X86_REG_ESI, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_EDI, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_EBX, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_EBP, reg_state::INIT);
            }
            else if (m_mode == cs_mode::CS_MODE_64) {
                // https://msdn.microsoft.com/en-us/library/9z1stfyw.aspx
                m_abi_bucket.emplace(X86_REG_R12, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R13, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R14, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R15, reg_state::INIT);

                m_abi_bucket.emplace(X86_REG_RDI, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_RSI, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_RBX, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_RBP, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_RSP, reg_state::INIT);

                m_abi_bucket.emplace(X86_REG_XMM6, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM7, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM8, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM9, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM10, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM11, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM12, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM13, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM14, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_XMM15, reg_state::INIT);
            }
            else {
                LOG(FATAL) << "Invalid x86 bit mode: " << static_cast<int>(m_mode);
            }
        }
        else {
            LOG(FATAL) << "Invalid architecture for AbiOracle: " << static_cast<int>(m_arch);
        }
        break;
    case bin_type::ELF:
        if (m_arch == cs_arch::CS_ARCH_X86) {
            if (m_mode == cs_mode::CS_MODE_32) {
                // https://wiki.osdev.org/System_V_ABI
                m_abi_bucket.emplace(X86_REG_EBX, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_EBP, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_ESI, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_EDI, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_ESP, reg_state::INIT);
            }
            else if (m_mode == cs_mode::CS_MODE_64) {
                // https://wiki.osdev.org/System_V_ABI
                m_abi_bucket.emplace(X86_REG_RBX, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_RBP, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_RSP, reg_state::INIT);

                m_abi_bucket.emplace(X86_REG_R12, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R13, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R14, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R15, reg_state::INIT);

            }
            else {
                LOG(FATAL) << "Invalid x86 bit mode: " << static_cast<int>(m_mode);
            }
        }
        else if (m_arch == cs_arch::CS_ARCH_ARM) {
            // http://infocenter.arm.com/help/topic/com.arm.doc.ihi0042f/IHI0042F_aapcs.pdf
            // https://developer.apple.com/library/content/documentation/Xcode/Conceptual/iPhoneOSABIReference/Articles/ARMv6FunctionCallingConventions.html#//apple_ref/doc/uid/TP40009021-SW7
            if (m_mode == cs_mode::CS_MODE_ARM) {
                m_abi_bucket.emplace(ARM_REG_R4, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R5, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R6, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R7, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R8, reg_state::INIT);

                m_abi_bucket.emplace(ARM_REG_R10, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R11, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_LR, reg_state::INIT);
            }
            else if (m_mode == cs_mode::CS_MODE_THUMB) {
                m_abi_bucket.emplace(ARM_REG_R4, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R5, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R6, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R7, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R8, reg_state::INIT);

                m_abi_bucket.emplace(ARM_REG_R10, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_R11, reg_state::INIT);
                m_abi_bucket.emplace(ARM_REG_LR, reg_state::INIT);
            }
            else {
                LOG(FATAL) << "Invalid arm mode: " << static_cast<int>(m_mode);
            }
        }
        else if (m_arch == cs_arch::CS_ARCH_ARM64) {
            // http://infocenter.arm.com/help/topic/com.arm.doc.ihi0055b/IHI0055B_aapcs64.pdf
            m_abi_bucket.emplace(ARM64_REG_X19, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X20, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X21, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X22, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X23, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X24, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X25, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X26, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X27, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_X28, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_FP, reg_state::INIT);
            m_abi_bucket.emplace(ARM64_REG_SP, reg_state::INIT);
        }
        else if (m_arch == cs_arch::CS_ARCH_MIPS) {
            // https://en.wikipedia.org/wiki/Calling_convention#MIPS
            m_abi_bucket.emplace(MIPS_REG_S0, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_S1, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_S2, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_S3, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_S4, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_S5, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_S6, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_S7, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_FP, reg_state::INIT);
            m_abi_bucket.emplace(MIPS_REG_SP, reg_state::INIT);
        }
        else if (m_arch == cs_arch::CS_ARCH_PPC) {
            // https://www.ibm.com/support/knowledgecenter/en/ssw_aix_72/com.ibm.aix.alangref/idalangref_reg_use_conv.htm
            m_abi_bucket.emplace(PPC_REG_R1, reg_state::INIT); // Stack reg
            m_abi_bucket.emplace(PPC_REG_R2, reg_state::INIT); // TOC reg
            m_abi_bucket.emplace(PPC_REG_R13, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R14, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R15, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R16, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R17, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R18, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R19, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R20, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R21, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R22, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R23, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R24, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R25, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R26, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R27, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R28, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R29, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R30, reg_state::INIT);
            m_abi_bucket.emplace(PPC_REG_R31, reg_state::INIT);
        }
        else {
            LOG(FATAL) << "Invalid architecture for AbiOracle: " << static_cast<int>(m_arch);
        }

        break;
    case bin_type::MACHO:
        if (m_arch == cs_arch::CS_ARCH_X86) {
            if (m_mode == cs_mode::CS_MODE_32) {
                // https://developer.apple.com/library/content/documentation/DeveloperTools/Conceptual/LowLevelABI/130-IA-32_Function_Calling_Conventions/IA32.html
                m_abi_bucket.emplace(X86_REG_EBX, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_EBP, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_ESI, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_EDI, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_ESP, reg_state::INIT);
            }
            else if (m_mode == cs_mode::CS_MODE_64) {
                // https://developer.apple.com/library/content/documentation/DeveloperTools/Conceptual/LowLevelABI/140-x86-64_Function_Calling_Conventions/x86_64.html#//apple_ref/doc/uid/TP40005035-SW1
                // https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf
                m_abi_bucket.emplace(X86_REG_RBX, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_RBP, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_RSP, reg_state::INIT);

                m_abi_bucket.emplace(X86_REG_R12, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R13, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R14, reg_state::INIT);
                m_abi_bucket.emplace(X86_REG_R15, reg_state::INIT);

            }
            else {
                LOG(FATAL) << "Invalid x86 bit mode: " << static_cast<int>(m_mode);
            }
        }
        else {
            LOG(FATAL) << "Invalid architecture for AbiOracle: " << static_cast<int>(m_arch);
        }

        break;
    default:
        LOG(FATAL) << "Invalid bin_type: " << static_cast<int>(m_type);
        break;
    }

}

AbiOracle::AbiOracle(cs_arch arch, cs_mode mode, bin_type type) :
    m_arch(arch),
    m_mode(mode),
    m_type(type),
    m_start_addr(0) {
    this->setup_regs();
};

CfgRes<uint64_t> AbiOracle::get_reg(cs_x86 x86, uint8_t idx) const {
    if (idx > x86.op_count) {
        LOG(FATAL) << "Invalid operand index: " << idx;
    }
    cs_x86_op oper = x86.operands[idx];

    switch (oper.type) {
    case X86_OP_REG:
        return CfgRes<uint64_t>(oper.reg);
        break;
    case X86_OP_MEM:
        return CfgRes<uint64_t>(oper.mem.base);
        break;
    default:
        return CfgRes<uint64_t>(CfgErr::NO_REG);
    }
}

CfgRes<uint64_t> AbiOracle::get_reg(cs_arm arm, uint8_t idx) const {
    if (idx > arm.op_count) {
        LOG(FATAL) << "Invalid operand index: " << idx;
    }
    cs_arm_op oper = arm.operands[idx];

    switch (oper.type) {
    case ARM_OP_REG:
        return CfgRes<uint64_t>(oper.reg);
        break;
    default:
        return CfgRes<uint64_t>(CfgErr::NO_REG);
    }
}

CfgRes<uint64_t> AbiOracle::get_reg(cs_arm64 arm64, uint8_t idx) const {
    if (idx > arm64.op_count) {
        LOG(FATAL) << "Invalid operand index: " << idx;
    }
    cs_arm64_op oper = arm64.operands[idx];

    switch (oper.type) {
    case ARM64_OP_REG:
        return CfgRes<uint64_t>(oper.reg);
        break;
    default:
        return CfgRes<uint64_t>(CfgErr::NO_REG);
    }
}

CfgRes<uint64_t> AbiOracle::get_reg(cs_mips mips, uint8_t idx) const {
    if (idx > mips.op_count) {
        LOG(FATAL) << "Invalid operand index: " << idx;
    }
    cs_mips_op oper = mips.operands[idx];

    switch (oper.type) {
    case MIPS_OP_REG:
        return CfgRes<uint64_t>(oper.reg);
        break;
    default:
        return CfgRes<uint64_t>(CfgErr::NO_REG);
    }
}

CfgRes<uint64_t> AbiOracle::get_reg(cs_ppc ppc, uint8_t idx) const {
    if (idx > ppc.op_count) {
        LOG(FATAL) << "Invalid operand index: " << idx;
    }
    cs_ppc_op oper = ppc.operands[idx];

    switch (oper.type) {
    case PPC_OP_REG:
        return CfgRes<uint64_t>(oper.reg);
        break;
    default:
        return CfgRes<uint64_t>(CfgErr::NO_REG);
    }

}

abi_stat AbiOracle::update_x86_insn(cs_insn *insn) {
    cs_x86 x86 = insn->detail->x86;

    switch (insn->id) {
    case X86_INS_PUSH: {
        auto reg_stat = this->get_reg(x86, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;

        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        if (reg_state->second != reg_state::INIT) {
            return abi_stat::INVALID;
        }
        reg_state->second = reg_state::SAVED;

        return abi_stat::CONTINUE;
    }

    case X86_INS_LEA:
    case X86_INS_XOR:
    case X86_INS_POP:
    case X86_INS_MOV: {
        auto reg_stat = this->get_reg(x86, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;

        // Handle mov edi, edi as a valid case.
        if (insn->id == X86_INS_MOV && reg == X86_REG_EDI) {
            auto reg_2_stat = this->get_reg(x86, 1);
            if (reg_2_stat) {
                if (*reg_2_stat == X86_REG_EDI) {
                    break;
                }
            }

        }

        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        if (reg_state->second == reg_state::SAVED) {
            return abi_stat::FOUND;
        }
        else {
            return abi_stat::INVALID;
        }

        break;
    }

    // Cases to invalidate the register
    case X86_INS_INC:
    case X86_INS_DEC: {
        auto reg_stat = this->get_reg(x86, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;
        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        return abi_stat::INVALID;
    }


    default:
        return abi_stat::CONTINUE;
    }

    return abi_stat::CONTINUE;
}

abi_stat AbiOracle::update_x86_64_insn(cs_insn *insn) {
    cs_x86 x86 = insn->detail->x86;

    switch (insn->id) {
    case X86_INS_MOV: {
        auto reg_stat = this->get_reg(x86, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg1 = *reg_stat;

        reg_stat = this->get_reg(x86, 1);
        if (!reg_stat) {
            break;
        }
        uint64_t reg2 = *reg_stat;

        // only allow mov saves to RSP, to PE files
        if (reg1 == X86_REG_RSP && x86.operands[0].type == X86_OP_MEM && m_type == bin_type::COFF) {
            auto reg_state = m_abi_bucket.find(reg2);
            if (reg_state == m_abi_bucket.end()) {
                break;
            }

            if (reg_state->second != reg_state::INIT) {
                return abi_stat::INVALID;
            }
            reg_state->second = reg_state::SAVED;

            return abi_stat::CONTINUE;
        }
        else {
            auto reg_state = m_abi_bucket.find(reg1);
            if (reg_state == m_abi_bucket.end()) {
                break;
            }

            if (reg_state->second == reg_state::SAVED) {
                return abi_stat::FOUND;
            }
            else {
                return abi_stat::INVALID;
            }
        }

        break;
    }
    case X86_INS_LEA: {
        auto reg_stat = this->get_reg(x86, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;

        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        if (reg_state->second != reg_state::SAVED) {
            return abi_stat::INVALID;
        }
        else {
            return abi_stat::FOUND;
        }

        break;
    }
    case X86_INS_PUSH: {
        auto reg_stat = this->get_reg(x86, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;
        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        if (reg_state->second != reg_state::INIT) {
            return abi_stat::INVALID;
        }
        reg_state->second = reg_state::SAVED;

        break;
    }

    // Cases to invalidate the register
    case X86_INS_INC:
    case X86_INS_DEC: {
        auto reg_stat = this->get_reg(x86, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;
        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        return abi_stat::INVALID;
    }

    default:
        return abi_stat::CONTINUE;
    }

    return abi_stat::CONTINUE;
}

abi_stat AbiOracle::update_arm_insn(cs_insn *insn) {
    cs_arm arm = insn->detail->arm;

    switch (insn->id) {
    case ARM_INS_PUSH: {
        for (uint8_t i = 0; i < arm.op_count; i++) {
            cs_arm_op op = arm.operands[i];
            if (op.type == ARM_OP_REG) {
                auto reg_state = m_abi_bucket.find(op.reg);
                if (reg_state == m_abi_bucket.end()) {
//                    LOG(WARNING) << "Pushing odd arm register at: 0x" << std::hex << insn->address;
                    continue;
                }
                if (reg_state->second != reg_state::INIT) {
                    return abi_stat::INVALID;
                }

                reg_state->second = reg_state::SAVED;
            }
        }
        break;
    }
    case ARM_INS_STR: {
        auto reg_stat = this->get_reg(arm, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;
        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        // Check the second operand to see if its a stack memory addr:
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm STR instruction: 0x" << std::hex << insn->address;
        }
        if (arm.operands[1].type != ARM_OP_MEM) {
            break;
        }
        cs_arm_op op_2 = arm.operands[1];
        if (op_2.mem.base == ARM_REG_SP) {
            if (reg_state->second != reg_state::INIT) {
                return abi_stat::INVALID;
            }

            reg_state->second = reg_state::SAVED;
        }

        break;
    }
    case ARM_INS_SUB: {
        // Special case for functions that look like:
        // str lr, [sp, OFFSET]
        // sub sp, sp, OFFSET / sub sp, offset
        // ...
        // pop [pc]
        if (arm.op_count == 2) {
            auto op0 = this->get_reg(arm, 0);
            if (!op0) {
                break;
            }

            if (*op0 == ARM_REG_SP) {
                if (arm.operands[1].type == ARM_OP_IMM) {
                    auto lr_state = m_abi_bucket.find(ARM_REG_LR);
                    if (lr_state == m_abi_bucket.end()) {
                        break;
                    }

                    if (lr_state->second == reg_state::SAVED) {
                        return abi_stat::FOUND;
                    }
                }
            }

        }
        else if (arm.op_count == 3) {
            auto op0 = this->get_reg(arm, 0);
            if (!op0) {
                break;
            }

            auto op1 = this->get_reg(arm, 1);
            if (!op1) {
                break;
            }

            if (*op0 == ARM_REG_SP && *op1 == ARM_REG_SP) {
                auto lr_state = m_abi_bucket.find(ARM_REG_LR);
                if (lr_state == m_abi_bucket.end()) {
                    break;
                }

                if (lr_state->second == reg_state::SAVED) {
                    return abi_stat::FOUND;
                }
            }

        }

        break;
    }


    case ARM_INS_MOV:
    case ARM_INS_ADD:
    case ARM_INS_LDRD:
    case ARM_INS_LDR:
    case ARM_INS_LSR:
    case ARM_INS_LSL:{
        auto reg_stat = this->get_reg(arm, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;
        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        if (reg_state->second != reg_state::SAVED) {
            return abi_stat::INVALID;
        }
        else {
            return abi_stat::FOUND;
        }

        break;
    }

    // Sanity check that we are jumping to a valid branch location.
    case ARM_INS_B:
    case ARM_INS_BX:
    case ARM_INS_BLX:
        if (arm.op_count < 1) {
            LOG(FATAL) << "Invalid arm branch instruction: 0x" << std::hex << insn->address;
        }
        if (arm.operands[0].type == ARM_OP_IMM && (arm.operands[0].imm % 2) != 0) {
            return abi_stat::RESET;
        }

        if (is_lr_in_arm_ops(arm)) {
            return abi_stat::RESET;
        }

        break;

    case ARM_INS_POP:
        // Check if we pop a saved register, it's possible that a arm func
        // will save off the register then not use it, but still pop.
        for (uint8_t i = 0; i < arm.op_count; i++) {
            cs_arm_op op = arm.operands[i];
            if (op.type == ARM_OP_REG) {
                uint64_t reg = op.reg;

                auto reg_state = m_abi_bucket.find(reg);
                if (reg_state == m_abi_bucket.end()) {
                    continue;
                }

                if (reg_state->second == reg_state::SAVED) {
                    return abi_stat::FOUND;
                }
            }
        }

        if (is_pc_in_arm_ops(arm)) {
            return abi_stat::RESET;
        }

        break;
    default:
        return abi_stat::CONTINUE;
    }

    return  abi_stat::CONTINUE;
}

abi_stat AbiOracle::update_arm64_insn(cs_insn *insn) {
    cs_arm64 arm64 = insn->detail->arm64;

    switch (insn->id) {
    case ARM64_INS_STP: {
        // Check that we are saving to the stack:
        if (arm64.op_count < 3) {
            LOG(FATAL) << "Invalid arm64 STP instruction at: 0x" << std::hex << insn->address;
        }

        cs_arm64_op op_3 = arm64.operands[2];
        if (op_3.type != ARM64_OP_MEM) {
            break;
        }
        if (op_3.mem.base != ARM64_REG_SP) {
            break;
        }

        for (uint8_t i = 0; i < 2; i++) {
            auto reg_stat = this->get_reg(arm64, i);
            if (!reg_stat) {
                break;
            }
            uint64_t reg = *reg_stat;

            auto reg_state = m_abi_bucket.find(reg);
            if (reg_state == m_abi_bucket.end()) {
                break;
            }
            if (reg_state->second != reg_state::INIT) {
                return abi_stat::INVALID;
            }
            reg_state->second = reg_state::SAVED;
        }

        break;
    }

    case ARM64_INS_LDP: {
        // Check that we are saving to the stack:
        if (arm64.op_count < 3) {
            LOG(FATAL) << "Invalid arm64 STP instruction at: 0x" << std::hex << insn->address;
        }

        cs_arm64_op op_3 = arm64.operands[2];
        if (op_3.type != ARM64_OP_MEM) {
            break;
        }
        if (op_3.mem.base != ARM64_REG_SP) {
            break;
        }

        for (uint8_t i = 0; i < 2; i++) {
            auto reg_stat = this->get_reg(arm64, i);
            if (!reg_stat) {
                break;
            }
            uint64_t reg = *reg_stat;

            auto reg_state = m_abi_bucket.find(reg);
            if (reg_state == m_abi_bucket.end()) {
                break;
            }
            if (reg_state->second == reg_state::SAVED) {
                return abi_stat::FOUND;
            }
            else {
                return abi_stat::INVALID;
            }
        }

        break;
    }

    case ARM64_INS_SUB: {
        bool all_sp = true;
        for (uint8_t i = 0; i < 2; i++) {
            auto reg_stat = this->get_reg(arm64, 0);
            if (!reg_stat) {
                break;
            }
            if (*reg_stat != ARM64_REG_SP) {
                all_sp = false;
                break;
            }

        }

        if (!all_sp) {
            break;
        }

        auto sp_state = m_abi_bucket.find(ARM64_REG_SP);
        CHECK(sp_state != m_abi_bucket.end()) << "Invalid abi oracle state, ARM64 SP register missing";

        sp_state->second = reg_state::SAVED;

        break;
    }

    case ARM64_INS_ADD: {
        if (arm64.op_count < 2) {
            LOG(FATAL) << "Invalid arm64 ADD instruction at: 0x" << std::hex << insn->address;
        }

        // Special case a function if:
        // sub sp, sp, IMM
        // ....
        // add sp, sp, IMM
        // reg <- not checked.
        if (arm64.operands[0].type == ARM64_OP_REG && arm64.operands[0].reg == ARM64_REG_SP &&
            arm64.operands[1].type == ARM64_OP_REG && arm64.operands[1].reg == ARM64_REG_SP) {

            auto sp_state = m_abi_bucket.find(ARM64_REG_SP);
            CHECK(sp_state != m_abi_bucket.end()) << "Invalid abi oracle state, ARM64 SP register missing";

            if (sp_state->second == reg_state::SAVED) {
                return abi_stat::FOUND;
            }
            else {
                return abi_stat::INVALID;
            }
        }
        else {
            auto reg_stat = this->get_reg(arm64, 0);
            if (!reg_stat) {
                break;
            }
            uint64_t reg = *reg_stat;
            auto reg_state = m_abi_bucket.find(reg);
            if (reg_state == m_abi_bucket.end()) {
                break;
            }

            if (reg_state->second != reg_state::SAVED) {
                return abi_stat::INVALID;
            }
            else {
                return abi_stat::FOUND;
            }
        }

        break;
    }
    case ARM64_INS_MOV: {
        auto reg_stat = this->get_reg(arm64, 0);
        if (!reg_stat) {
            break;
        }
        uint64_t reg = *reg_stat;
        auto reg_state = m_abi_bucket.find(reg);
        if (reg_state == m_abi_bucket.end()) {
            break;
        }

        if (reg_state->second != reg_state::SAVED) {
            return abi_stat::INVALID;
        }
        else {
            return abi_stat::FOUND;
        }

        break;

    }

    case ARM64_INS_RET: {
        return abi_stat::RESET;
    }
    default:
        return abi_stat::CONTINUE;
    }

    return  abi_stat::CONTINUE;
}

abi_stat AbiOracle::update_mips_insn(cs_insn *insn) {
    cs_mips mips = insn->detail->mips;

    switch (insn->id) {
    case MIPS_INS_SW: {
        if (mips.op_count < 2) {
            LOG(FATAL) << "Invalid MIPS sw instruction at: 0x" << std::hex << insn->address;
        }
        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        if (op1.type != MIPS_OP_MEM) {
            break;
        }

        if (op1.mem.base != MIPS_REG_SP) {
            break;
        }

        auto op0_res = this->get_reg(mips, 0);
        if (!op0_res) {
            break;
        }

        auto op0_state = m_abi_bucket.find(*op0_res);
        if (op0_state == m_abi_bucket.end()) {
            break;
        }

        op0_state->second = reg_state::SAVED;
        break;
    }
    case MIPS_INS_ADDIU: {
        if (mips.op_count < 3) {
            LOG(FATAL) << "Invalid MIPS addiu instruction at: 0x" << std::hex << insn->address;
        }

        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        if (op0.type != MIPS_OP_REG || op1.type != MIPS_OP_REG) {
            break;
        }

        if (op0.reg == MIPS_REG_SP && op1.reg == MIPS_REG_SP) {
            auto sp_state = m_abi_bucket.find(MIPS_REG_SP);
            CHECK(sp_state != m_abi_bucket.end()) << "State error in ABI oracle, SP register missing from buckets";
            sp_state->second = reg_state::SAVED;
        }
        else {
            auto op0_state = m_abi_bucket.find(op0.reg);
            if (op0_state == m_abi_bucket.end()) {
                break;
            }

            if (op0_state->second != reg_state::SAVED) {
                return abi_stat::INVALID;
            }

            return abi_stat::FOUND;
        }

        break;
    }

    case MIPS_INS_LUI:
    case MIPS_INS_LW:
    case MIPS_INS_MOVE: {
        if (mips.op_count < 2) {
            LOG(FATAL) << "Invalid MIPS move/lw/lui instruction at: 0x" << std::hex << insn->address;
        }

        auto op0_res = this->get_reg(mips, 0);
        if (!op0_res) {
            break;
        }

        auto op0_state = m_abi_bucket.find(*op0_res);
        if (op0_state == m_abi_bucket.end()) {
            break;
        }

        if (op0_state->second != reg_state::SAVED) {
            return abi_stat::INVALID;
        }

        return abi_stat::FOUND;

        break;
    }

    case MIPS_INS_JR: {
        auto op_res = this->get_reg(mips, 0);
        if (!op_res) {
            break;
        }

        if (*op_res == MIPS_REG_RA) {
            return abi_stat::RESET;
        }
        // Assume that we won't make any standard calls before the
        // end of the prolog
        else if (*op_res == MIPS_REG_T9) {
            return abi_stat::RESET;
        }
        break;
    }
    case MIPS_INS_B: {
        // Assume any branch will not happen before the prolog completes
        return abi_stat::RESET;
    }
    default:
        return abi_stat::CONTINUE;
    }
    return  abi_stat::CONTINUE;
}

abi_stat AbiOracle::update_ppc_insn(cs_insn *insn) {
    cs_ppc ppc = insn->detail->ppc;

    switch (insn->id) {
    case PPC_INS_STWU:
    case PPC_INS_STW: {
        CHECK(ppc.op_count > 1) << "Invalid PPC stwu|stw instruction at: 0x" << std::hex << insn->address;

        cs_ppc_op op0 = ppc.operands[0];
        cs_ppc_op op1 = ppc.operands[1];

        if (op0.type != PPC_OP_REG) {
            break;
        }
        if (op1.type != PPC_OP_MEM && op1.mem.base != PPC_REG_R1) {
            break;
        }

        auto op0_res = this->get_reg(ppc, 0);
        if (!op0_res) {
            break;
        }

        auto op0_state = m_abi_bucket.find(*op0_res);
        if (op0_state == m_abi_bucket.end()) {
            break;
        }

        op0_state->second = reg_state::SAVED;
        break;
    }

    case PPC_INS_LWZ:
    case PPC_INS_MR:
    case PPC_INS_OR: {
        CHECK(ppc.op_count > 1) << "Invalid PPC or|mr instruction at: 0x" << std::hex << insn->address;

        cs_ppc_op op0 = ppc.operands[0];

        if (op0.type != PPC_OP_REG) {
            break;
        }

        auto op0_res = this->get_reg(ppc, 0);
        if (!op0_res) {
            break;
        }

        auto op0_state = m_abi_bucket.find(*op0_res);
        if (op0_state == m_abi_bucket.end()) {
            break;
        }

        if (op0_state->second != reg_state::SAVED) {
            return abi_stat::INVALID;
        }

        return abi_stat::FOUND;

        break;
    }

    case PPC_INS_BLR: {
        return abi_stat::RESET;
    }
    default:
        return  abi_stat::CONTINUE;
    }

    return  abi_stat::CONTINUE;
}

abi_stat AbiOracle::update_insn(cs_insn *insn) {
    if (is_nop(m_arch, insn)) {
        return abi_stat::RESET;
    }

    switch (m_arch) {
    case cs_arch::CS_ARCH_X86:
        switch(insn->id) {
        // Restart processing at rets
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
        case X86_INS_INT3: // windows only, need to re-adjust some of our oracle to get these features
            return abi_stat::RESET;
        }

        if (!m_start_addr) {
            m_start_addr = insn->address;
        }

        if (m_mode == cs_mode::CS_MODE_32) {
            return update_x86_insn(insn);
        }
        else if (m_mode == cs_mode::CS_MODE_64) {
            return update_x86_64_insn(insn);
        }

        break;
    case cs_arch::CS_ARCH_ARM:
        if (m_mode == cs_mode::CS_MODE_ARM || m_mode == cs_mode::CS_MODE_THUMB) {
            if (!m_start_addr) {
                m_start_addr = insn->address;
            }

            return update_arm_insn(insn);
        }
        break;
    case cs_arch::CS_ARCH_ARM64:
        if (!m_start_addr) {
            m_start_addr = insn->address;
        }

        return update_arm64_insn(insn);

    case cs_arch::CS_ARCH_MIPS:
        if (!m_start_addr) {
            m_start_addr = insn->address;
        }

        return update_mips_insn(insn);
    case cs_arch::CS_ARCH_PPC:
        if (!m_start_addr) {
            m_start_addr = insn->address;
        }
        return update_ppc_insn(insn);

    default:
        LOG(FATAL) << "Invalid arch for updating the AbiOracle: " << static_cast<int>(m_arch);
        break;
    }

    return abi_stat::CONTINUE;
}

uint64_t AbiOracle::get_start_addr() const {
    return m_start_addr;
}

void AbiOracle::change_mode(cs_mode mode) {
    m_mode = mode;
    m_abi_bucket.clear();
    m_start_addr = 0;
    this->setup_regs();
}

void AbiOracle::reset() {
    for (auto &kv : m_abi_bucket) {
        kv.second = reg_state::INIT;
    }
    m_start_addr = 0;
}
