#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "capstone/capstone.h"
#include "glog/logging.h"

#include "CfgRes.hpp"
#include "CpuState.hpp"
#include "MemoryMap.hpp"
#include "Block.hpp"
#include "CapstoneHelper.hpp"

CpuState::CpuState(cs_arch arch, std::shared_ptr<MemoryMap> memmap) :
    m_arch(arch),
    m_memmap(std::move(memmap)) {

    // Check for delay slot
    if (m_arch == cs_arch::CS_ARCH_MIPS) {
        m_has_delay_slot = true;
    }
    else {
        m_has_delay_slot = false;
    }
};

cs_arch CpuState::get_arch() const {
    return m_arch;
}
cs_mode CpuState::get_mode() const {
    return m_mode;
}


bool CpuState::is_big_endian() const {
    return m_big_endian;
}
bool CpuState::has_delay_slot() const {
    return m_has_delay_slot;
}

void CpuState::clear_reg_cache() {
    m_reg_32_cache.clear();
    m_reg_64_cache.clear();
}

void CpuState::clear_vstack() {
    m_virt_stack.clear();
}

void CpuState::at_func_start(Block *block) {
    // For mips we need to prime the $t9 register
    // This should only be for public functions but any other
    // usage would overwrite it.
    if (m_arch == cs_arch::CS_ARCH_MIPS) {
        m_reg_32_cache.set_reg(MIPS_REG_T9, block->start);
    }
}

void CpuState::at_func_end() {
    m_virt_stack.clear();
    m_func_reg_caches_32.clear();
}

void CpuState::at_block_start(Block *block) {
    // Just stub in mips for now, and only 32 bit caching.
    // Need to trail run and test other arches before using function level
    // reg files.
    if (m_arch == cs_arch::CS_ARCH_MIPS) {
        if (!block->leaders.empty()) {
            auto leader_regs = m_func_reg_caches_32.find(block->leaders.at(0));
            if (leader_regs != m_func_reg_caches_32.end()) {
                m_reg_32_cache = leader_regs->second;
            }
        }
    }

    this->change_mode(block->mode);
}

void CpuState::at_block_end(Block *block) {
    if (m_arch == cs_arch::CS_ARCH_MIPS) {
        m_func_reg_caches_32[block->start] = m_reg_32_cache;
    }

    this->clear_reg_cache();
}

void CpuState::at_insn(cs_insn *insn, Block *block) {
    this->update_reg_cache(insn, block);

    // adding metadata is called after the reg update so we can directly query registers written.
    this->add_block_metadata(insn, block);
}

void CpuState::change_mode(cs_mode mode) {
    // Check endian
    if (mode != m_mode) {
        if (mode & cs_mode::CS_MODE_BIG_ENDIAN) {
            m_big_endian = true;
        }
        else {
            m_big_endian = false;
        }
    }

    if (m_mode != mode) {
        m_mode = mode;
    }
}

std::shared_ptr<MemoryMap> CpuState::get_memmap() const {
    return m_memmap;
}

std::map<uint64_t, uint64_t> *CpuState::get_switch_tables() {
    return &m_switch_vtables;
}

CfgRes<uint64_t> CpuState::get_op_read_addr(cs_insn *insn, cs_x86_op op, cs_mode mode) const {
    if (op.type != X86_OP_MEM) {
        return CfgRes<uint64_t>(CfgErr::OTHER);
    }

    // Bail if we are in some random segment:
    // eg: mov eax, dword [fs:rbp]
    if (op.mem.segment != X86_REG_INVALID) {
        return CfgRes<uint64_t>(CfgErr::NO_REG);
    }

    if (op.mem.base == X86_REG_RIP) {
        return CfgRes<uint64_t>(insn->address + insn->size + op.mem.disp);
    }

    if (op.mem.base == X86_REG_INVALID) {
        if (op.mem.index == X86_REG_INVALID) {
            return CfgRes<uint64_t>(static_cast<uint64_t>(op.mem.disp));
        }
    }

    uint64_t target = 0;
    if (mode == cs_mode::CS_MODE_32) {
        CfgRes<int32_t> reg_res = m_reg_32_cache.get_reg(op.mem.base);
        if (!reg_res) {
            return CfgRes<uint64_t>(CfgErr::NO_REG);
        }
        int32_t base_val = *reg_res;

        if (op.mem.index != X86_REG_INVALID) {
            int32_t offset_val;
            CfgRes<int32_t> idx_res = m_reg_32_cache.get_reg(op.mem.index);
            if (!idx_res) {
                return CfgRes<uint64_t>(CfgErr::NO_REG);
            }
            offset_val = *idx_res * op.mem.scale;
            target = base_val + offset_val + op.mem.disp;
        }
        else {
            target = base_val + op.mem.disp;
        }
    }
    else if (mode == cs_mode::CS_MODE_64) {
        CfgRes<int64_t> reg_res = m_reg_64_cache.get_reg(op.mem.base);
        if (!reg_res) {
            return CfgRes<uint64_t>(CfgErr::NO_REG);
        }
        int64_t reg_val = *reg_res;
        if (op.mem.index != X86_REG_INVALID) {
            int64_t offset_val;
            CfgRes<int64_t> idx_res = m_reg_64_cache.get_reg(op.mem.index);
            if (!idx_res) {
                return CfgRes<uint64_t>(CfgErr::NO_REG);
            }
            offset_val = *idx_res * op.mem.scale;
            target = reg_val + offset_val + op.mem.disp;
        }
        else {
            target = reg_val + op.mem.disp;
        }
    }
    else {
        LOG(FATAL) << "Invalid cs_mode: " << mode;
    }

    return CfgRes<uint64_t>(target);
}

CfgRes<uint32_t> CpuState::get_op_read_addr(cs_insn *insn, cs_arm_op op, cs_mode mode) const {
    uint32_t read_addr = 0;
    if (op.mem.base == arm_reg::ARM_REG_PC) {
        read_addr = this->get_arm_pc_val(insn, op, mode);
    }
    // TODO: Implement more arm PC checks here:
    else if (op.mem.base != arm_reg::ARM_REG_INVALID && op.mem.index == arm_reg::ARM_REG_INVALID) {
        auto op_res = m_reg_32_cache.get_reg(op.mem.base);
        if (!op_res) {
            return CfgRes<uint32_t>(CfgErr::NO_REG);
        }

        read_addr = *op_res + op.mem.disp;
    }
    else if (op.mem.base != arm_reg::ARM_REG_INVALID && op.mem.index != arm_reg::ARM_REG_INVALID) {
        auto op_idx_res = m_reg_32_cache.get_reg(op.mem.index);
        auto op_base_res = m_reg_32_cache.get_reg(op.mem.base);
        if (!op_idx_res || !op_base_res) {
            return CfgRes<uint32_t>(CfgErr::NO_REG);
        }
        else {
            int32_t index_val = *op_idx_res;
            int32_t base_val = *op_base_res;
            VLOG(VLOG_REG) << "--base_val: 0x" << std::hex << base_val;
            VLOG(VLOG_REG) << "--idx_val:  0x" << std::hex << index_val;

            read_addr = static_cast<uint32_t>(base_val + index_val);
        }
    }
    else {
        LOG(FATAL) << "Invalid arm op config at: 0x" << std::hex << insn->address;
    }

    return CfgRes<uint32_t>(read_addr);
}

CfgRes<uint64_t> CpuState::get_op_read_addr(cs_insn *insn, cs_arm64_op op, cs_mode mode) const {
    uint64_t read_addr = 0;
    if (op.mem.base != ARM64_REG_INVALID && op.mem.index == ARM64_REG_INVALID) {
        auto op_res = m_reg_64_cache.get_reg(op.mem.base);
        if (!op_res) {
            return CfgRes<uint64_t>(CfgErr::NO_REG);
        }

        read_addr = *op_res + op.mem.disp;
    }
    else if (op.mem.base != ARM64_REG_INVALID && op.mem.index != ARM64_REG_INVALID) {
        auto op_idx_res = m_reg_64_cache.get_reg(op.mem.index);
        auto op_base_res = m_reg_64_cache.get_reg(op.mem.base);
        if (!op_idx_res || !op_base_res) {
            return CfgRes<uint64_t>(CfgErr::NO_REG);
        }
        else {
            int64_t index_val = *op_idx_res;
            int64_t base_val = *op_base_res;
            VLOG(VLOG_REG) << "--base_val: 0x" << std::hex << base_val;
            VLOG(VLOG_REG) << "--idx_val:  0x" << std::hex << index_val;

            read_addr = static_cast<uint64_t>(base_val + index_val);
        }
    }
    else {
        LOG(FATAL) << "Invalid arm op config at: 0x" << std::hex << insn->address;
    }

    return CfgRes<uint64_t>(read_addr);
}

CfgRes<uint32_t> CpuState::get_op_read_addr(cs_insn *insn, cs_mips_op op, Block *block) const {
    uint64_t read_addr = 0;

    if (op.type != MIPS_OP_MEM) {
        return CfgRes<uint32_t>(CfgErr::OTHER);
    }

    if (op.mem.base == MIPS_REG_SP) {
        // Attempt to pull the value out of the virtual stack
        auto func_stack = m_virt_stack.find(block->func_addr);
        if (func_stack == m_virt_stack.end()) {
            return CfgRes<uint32_t>(CfgErr::OTHER);
        }

        auto offset = func_stack->second.find(op.mem.disp);
        if (offset == func_stack->second.end()) {
            return CfgRes<uint32_t>(CfgErr::OTHER);
        }

        read_addr = offset->second;
        VLOG(VLOG_CFG) << "Fetched value from virtual stack at offset: 0x" << std::hex << op.mem.disp;

        return CfgRes<uint32_t>(read_addr);
    }
    else {
        auto op_base_res = m_reg_32_cache.get_reg(op.mem.base);
        if (!op_base_res) {
            return CfgRes<uint32_t>(CfgErr::NO_REG);
        }
        read_addr = *op_base_res + op.mem.disp;
    }

    return CfgRes<uint32_t>(read_addr);
}


CfgRes<uint32_t> CpuState::get_op_read_addr(cs_insn *insn, cs_ppc_op op) const {
    if (op.type != PPC_OP_MEM) {
        return CfgRes<uint32_t>(CfgErr::OTHER);
    }

    auto op_base_res = m_reg_32_cache.get_reg(op.mem.base);
    if (!op_base_res) {
        return CfgRes<uint32_t>(CfgErr::NO_REG);
    }

    return CfgRes<uint32_t>(*op_base_res + op.mem.disp);
}

CfgRes<uint64_t> CpuState::get_op_val(cs_insn *insn, cs_x86_op op, cs_mode mode) const {
    switch(op.type) {
    case X86_OP_IMM:
        return CfgRes<uint64_t>(op.imm);

    case X86_OP_REG:
        if (mode == cs_mode::CS_MODE_32) {
            auto op_res = m_reg_32_cache.get_reg(op.reg);
            if (!op_res) {
                return CfgRes<uint64_t>(CfgErr::NO_REG);
            }
            return CfgRes<uint64_t>(*op_res);
        }
        else if (mode == cs_mode::CS_MODE_64) {
            auto op_res = m_reg_64_cache.get_reg(op.reg);
            if (!op_res) {
                return CfgRes<uint64_t>(CfgErr::NO_REG);
            }
            return CfgRes<uint64_t>(*op_res);
        }
        else {
            LOG(FATAL) << "Invalid x86 mode: " << mode;
        }
        break;

    case X86_OP_MEM: {
        auto read_addr_res = this->get_op_read_addr(insn, op, mode);
        if (!read_addr_res) {
            return CfgRes<uint64_t>(read_addr_res);
        }

        uint64_t read_addr = *read_addr_res;
        uint64_t value = 0;

        if (mode == cs_mode::CS_MODE_32) {
            const auto *mem_ptr = reinterpret_cast<const uint32_t *>(m_memmap->addr_to_ptr(read_addr));
            if (!mem_ptr) {
                return CfgRes<uint64_t>(CfgErr::BAD_READ);
            }

            value = *mem_ptr;
        }
        else if (mode == cs_mode::CS_MODE_64) {
            const auto *mem_ptr = reinterpret_cast<const uint64_t *>(m_memmap->addr_to_ptr(read_addr));
            if (!mem_ptr) {
                return CfgRes<uint64_t>(CfgErr::BAD_READ);
            }

            value = *mem_ptr;
        }

        return CfgRes<uint64_t>(value);
    }
    default:
        break;
    }
    return CfgRes<uint64_t>(CfgErr::OTHER);
}

uint64_t CpuState::get_arm_pc_val(cs_insn *insn, cs_arm_op op, cs_mode mode) const {
    if (mode == cs_mode::CS_MODE_THUMB) {
        switch (insn->id) {
        case ARM_INS_B:
        case ARM_INS_BL:
        case ARM_INS_CBNZ:
        case ARM_INS_CBZ:
            return insn->address + 4 + op.mem.disp;
            break;
        default:
            if (op.type == ARM_OP_MEM) {
                return (0xfffffffd & (insn->address + 4)) + op.mem.disp;
            }
            else {
                return insn->address + 4;
            }
            break;
        }
    }
    else {
        return insn->address + 8 + op.mem.disp;
    }
}

CfgRes<int32_t> CpuState::get_op_val(cs_insn *insn, cs_arm_op op, cs_mode mode) const {
    switch(op.type) {
    case ARM_OP_IMM:
        return CfgRes<int32_t>(op.imm);
    case ARM_OP_REG: {
        if (op.reg == arm_reg::ARM_REG_PC) {
            return CfgRes<int32_t>(this->get_arm_pc_val(insn, op, mode));
        }
        auto op_res = m_reg_32_cache.get_reg(op.reg);
        if (!op_res) {
            return CfgRes<int32_t>(CfgErr::NO_REG);
        }
        return CfgRes<int32_t>(*op_res);
    }
    case ARM_OP_MEM: {
        auto read_addr_res = this->get_op_read_addr(insn, op, mode);
        if (!read_addr_res) {
            return CfgRes<int32_t>(read_addr_res.get_err());
        }

        VLOG(VLOG_CFG) << "Reading from addr: 0x" << std::hex << *read_addr_res;
        const auto *mem_ptr = reinterpret_cast<const int32_t *>(m_memmap->addr_to_ptr(*read_addr_res));
        if (!mem_ptr) {
            return CfgRes<int32_t>(CfgErr::BAD_READ);
        }

        return CfgRes<int32_t>(*mem_ptr);
    }
    default:
        break;
    }

    return CfgRes<int32_t>(CfgErr::OTHER);
}

CfgRes<uint64_t> CpuState::get_op_val(cs_insn *insn, cs_arm64_op op) const {
    switch(op.type) {
    case ARM64_OP_IMM:
        return CfgRes<uint64_t>(static_cast<uint64_t>(op.imm));

    case ARM64_OP_REG: {
        auto op_res = m_reg_64_cache.get_reg(op.reg);
        if (!op_res) {
            return CfgRes<uint64_t>(CfgErr::NO_REG);
        }
        return CfgRes<uint64_t>(*op_res);
    }

    case ARM64_OP_MEM: {
        auto op_base_res = m_reg_64_cache.get_reg(op.mem.base);
        if (!op_base_res) {
            return CfgRes<uint64_t>(CfgErr::NO_REG);
        }
        int64_t reg_val = *op_base_res;
        if (reg_val) {
            uint64_t read_addr = reg_val + op.mem.disp;
            VLOG(VLOG_CFG) << "Reading from addr: 0x" << std::hex << read_addr;
            const auto *mem_ptr = reinterpret_cast<const uint32_t *>(m_memmap->addr_to_ptr(read_addr));
            if (!mem_ptr) {
                return CfgRes<uint64_t>(CfgErr::BAD_READ);
            }

            return CfgRes<uint64_t>(*mem_ptr);
        }
        break;
    }
    default:
        break;
    }
    return CfgRes<uint64_t>(CfgErr::OTHER);
}

CfgRes<int32_t> CpuState::get_op_val(cs_insn *insn, cs_mips_op op, Block *block) const {
    switch(op.type) {
    case MIPS_OP_IMM:
        return CfgRes<int32_t>(op.imm);

    case MIPS_OP_REG: {
        if (op.reg == MIPS_REG_ZERO) {
            return CfgRes<int32_t>(0);
        }
        auto op_res = m_reg_32_cache.get_reg(op.reg);
        if (!op_res) {
            return CfgRes<int32_t>(CfgErr::NO_REG);
        }
        return CfgRes<int32_t>(*op_res);
    }

    case MIPS_OP_MEM: {
        // TODO: replace body of this with get_op_read_addr()
        int32_t reg_val = 0;

        if (op.mem.base == MIPS_REG_SP) {
            // Attempt to pull the value out of the virtual stack
            auto func_stack = m_virt_stack.find(block->func_addr);
            if (func_stack == m_virt_stack.end()) {
                break;
            }

            auto offset = func_stack->second.find(op.mem.disp);
            if (offset == func_stack->second.end()) {
                break;
            }

            reg_val = offset->second;
            VLOG(VLOG_CFG) << "Fetched value from virtual stack at offset: 0x" << std::hex << op.mem.disp;

            return CfgRes<int32_t>(reg_val);
        }
        else {
            auto op_base_res = m_reg_32_cache.get_reg(op.mem.base);
            if (!op_base_res) {
                return CfgRes<int32_t>(CfgErr::NO_REG);
            }
            reg_val = *op_base_res + op.mem.disp;
            if (reg_val) {
                VLOG(VLOG_CFG) << "Reading from addr: 0x" << std::hex << reg_val;
                const auto *mem_ptr = reinterpret_cast<const uint32_t *>(m_memmap->addr_to_ptr(reg_val));
                if (!mem_ptr) {
                    return CfgRes<int32_t>(CfgErr::BAD_READ);
                }
                int32_t value = *mem_ptr;
                if (m_big_endian) {
                    value = __builtin_bswap32(value);
                }
                return CfgRes<int32_t>(value);
            }
        }
        break;
    }
    default:
        break;
    }

    return CfgRes<int32_t>(CfgErr::OTHER);
}

CfgRes<uint32_t> CpuState::get_op_val(cs_insn *insn, cs_ppc_op op, Block *block) const {
    switch(op.type) {
    case PPC_OP_IMM:
        return CfgRes<uint32_t>(op.imm);

    case PPC_OP_REG: {
        auto op_res = m_reg_32_cache.get_reg(op.reg);
        if (!op_res) {
            return CfgRes<uint32_t>(CfgErr::NO_REG);
        }
        return CfgRes<uint32_t>(*op_res);
    }
    case PPC_OP_MEM: {
        // TODO: replace body of this with get_op_read_addr()

        uint32_t reg_val = 0;

        if (op.mem.base == PPC_REG_R1) {
            // Attempt to pull the value out of the virtual stack
            auto func_stack = m_virt_stack.find(block->func_addr);
            if (func_stack == m_virt_stack.end()) {
                break;
            }

            auto offset = func_stack->second.find(op.mem.disp);
            if (offset == func_stack->second.end()) {
                break;
            }

            reg_val = offset->second;
            VLOG(VLOG_CFG) << "Fetched value from virtual stack at offset: 0x" << std::hex << op.mem.disp;

            return CfgRes<uint32_t>(reg_val);
        }
        else {
            auto op_base_res = m_reg_32_cache.get_reg(op.mem.base);
            if (!op_base_res) {
                return CfgRes<uint32_t>(CfgErr::NO_REG);
            }
            reg_val = *op_base_res + op.mem.disp;
            if (reg_val) {
                VLOG(VLOG_CFG) << "Reading from addr: 0x" << std::hex << reg_val;
                const auto *mem_ptr = reinterpret_cast<const uint32_t *>(m_memmap->addr_to_ptr(reg_val));
                if (!mem_ptr) {
                    return CfgRes<uint32_t>(CfgErr::BAD_READ);
                }
                uint32_t value = *mem_ptr;
                if (m_big_endian) {
                    value = __builtin_bswap32(value);
                }
                return CfgRes<uint32_t>(value);
            }
        }
        break;
    }
    default:
        break;

    }

    return CfgRes<uint32_t>(CfgErr::OTHER);
}


bool CpuState::is_op_stack_based(cs_x86_op op) {
    if (op.type == X86_OP_MEM) {
        if (op.mem.base == X86_REG_ESP || op.mem.base == X86_REG_RSP) {
            return true;
        }
    }
    return false;
}

bool CpuState::is_op_stack_based(cs_arm_op op) {
    if (op.type == ARM_OP_MEM) {
        if  (op.mem.base == ARM_REG_SP) {
            return true;
        }
    }
    return false;
}

bool CpuState::is_op_stack_based(cs_arm64_op op) {
    if (op.type == ARM64_OP_MEM) {
        if  (op.mem.base == ARM64_REG_SP) {
            return true;
        }
    }
    return false;
}

CfgRes<int32_t> CpuState::get_reg_val(ppc_reg reg) const {
    auto reg_res = m_reg_32_cache.get_reg(reg);
    if (!reg_res) {
        return CfgRes<int32_t>(CfgErr::NO_REG);
    }
    return reg_res;
}


void CpuState::set_reg_val_32(uint32_t reg, int32_t val) {
    m_reg_32_cache.set_reg(reg, val);
}

void CpuState::set_reg_val_64(uint32_t reg, int64_t val) {
    m_reg_64_cache.set_reg(reg, val);
}


uint64_t CpuState::get_last_removed() {
    if (m_arch == cs_arch::CS_ARCH_ARM) {
        return *m_reg_32_cache.get_last_removed();
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        return *m_reg_64_cache.get_last_removed();
    }
    else {
        return 0;
    }
}

void CpuState::invalid_reg(cs_x86_op op, cs_mode mode) {
    if (op.type != X86_OP_REG) {
        return;
    }

    if (mode == cs_mode::CS_MODE_32) {
        m_reg_32_cache.remove_reg(op.reg);
    }
    else if (mode == cs_mode::CS_MODE_64) {
        m_reg_64_cache.remove_reg(op.reg);
    }
    else {
        LOG(FATAL) << "Invalid mode: " << mode << " for reg invalidation";
    }
}

void CpuState::invalid_reg(cs_arm_op op, cs_mode mode) {
    if (op.type != ARM_OP_REG) {
        return;
    }
    m_reg_32_cache.remove_reg(op.reg);
}

void CpuState::invalid_reg(cs_arm64_op op, cs_mode mode) {
    if (op.type != ARM64_OP_REG) {
        return;
    }
    m_reg_64_cache.remove_reg(op.reg);
}

void CpuState::invalid_reg(cs_mips_op op) {
    if (op.type != MIPS_OP_REG) {
        return;
    }
    m_reg_32_cache.remove_reg(op.reg);
}

void CpuState::invalid_reg(cs_ppc_op op) {
    if (op.type != PPC_OP_REG) {
        return;
    }
    m_reg_32_cache.remove_reg(op.reg);
}

void CpuState::update_reg_x86(cs_insn *insn, Block *block) {
    cs_x86 x86 = insn->detail->x86;

    switch (insn->id) {
    case X86_INS_LEA: {
        if (x86.op_count < 2) {
            LOG(FATAL) << "Invalid x86 LEA at: 0x" << std::hex << insn->address;
        }
        cs_x86_op op0 = x86.operands[0];
        cs_x86_op op1 = x86.operands[1];

        // Bail out of target addition if we are based off the stack
        if (this->is_op_stack_based(op1)) {
            break;
        }

        auto op1_res = this->get_op_read_addr(insn, op1, block->mode);
        if (!op1_res) {
            break;
        }
        uint64_t target = *op1_res;

        if (target && op0.type == X86_OP_REG) {
            if (block->mode == cs_mode::CS_MODE_32) {
                m_reg_32_cache.set_reg(op0.reg, target);
            }
            else if (block->mode == cs_mode::CS_MODE_64) {
                m_reg_64_cache.set_reg(op0.reg, target);
            }
            else {
                LOG(FATAL) << "Invalid x86 mode: " << block->mode;
            }
            VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << target;
        }


        break;
    }
    case X86_INS_MOV: {
        if (x86.op_count < 2) {
            LOG(FATAL) << "Invalid x86 MOV at: 0x" << std::hex << insn->address;
        }
        cs_x86_op op0 = x86.operands[0];
        cs_x86_op op1 = x86.operands[1];
        auto op1_res = this->get_op_val(insn, op1, block->mode);
        if (!op1_res) {
            this->invalid_reg(op0, block->mode);
            break;
        }

        if (op0.type == X86_OP_REG && !this->is_op_stack_based(op1)) {
            if (block->mode == cs_mode::CS_MODE_32) {
                m_reg_32_cache.set_reg(op0.reg, *op1_res);
            }
            else if (block->mode == cs_mode::CS_MODE_64) {
                m_reg_64_cache.set_reg(op0.reg, *op1_res);
            }
            else {
                LOG(FATAL) << "Invalid x86 mode: " << block->mode;
            }
            VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << *op1_res;
        }

        break;
    }
    default:
        break;
    }
}

void CpuState::update_reg_arm(cs_insn *insn, Block *block) {
    uint8_t pc_offset = 8;
    if (block->mode == cs_mode::CS_MODE_THUMB) {
        pc_offset = 4;
    }

    cs_arm arm = insn->detail->arm;
    cs_arm_op op0;
    cs_arm_op op1;
    cs_arm_op op2;

    switch (insn->id) {
    case ARM_INS_LDR: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm LDR instruction at: 0x" << std::hex << insn->address;
        }

        op0 = arm.operands[0];
        op1 = arm.operands[1];

        auto op1_res = this->get_op_val(insn, op1, block->mode);
        if (!op1_res) {
            this->invalid_reg(op0, block->mode);
            break;
        }
        int32_t op1_val = *op1_res;

        if (op0.type == ARM_OP_REG) {
            m_reg_32_cache.set_reg(op0.reg, op1_val);
            VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << op1_val;
        }

        break;
    }
    case ARM_INS_ADDW:
    case ARM_INS_ADD: {
        if (arm.op_count < 1) {
            LOG(FATAL) << "--Invalid arm ADD instruction at: 0x" << std::hex << insn->address;
        }
        op0 = arm.operands[0];

        if (op0.type != ARM_OP_REG) {
            break;
        }

        int32_t op1_val = 0;
        int32_t op2_val = 0;

        if (arm.op_count == 2) {
            auto op1_res = this->get_op_val(insn, arm.operands[1], block->mode);
            if (!op1_res) {
                this->invalid_reg(op0, block->mode);
                break;
            }
            op1_val = *op1_res;

            // Overload the op2_val from op0 here
            auto op0_res = this->get_op_val(insn, arm.operands[0], block->mode);
            if (!op0_res) {
                this->invalid_reg(op0, block->mode);
                break;
            }
            op2_val = *op0_res;

        }
        else if (arm.op_count == 3) {
            auto op1_res = this->get_op_val(insn, arm.operands[1], block->mode);
            if (!op1_res) {
                this->invalid_reg(op0, block->mode);
                break;
            }
            op1_val = *op1_res;

            auto op2_res = this->get_op_val(insn, arm.operands[2], block->mode);
            if (!op2_res) {
                this->invalid_reg(op0, block->mode);
                break;
            }
            op2_val = *op2_res;
        }
        else if (arm.op_count == 4) {
            auto op1_res = this->get_op_val(insn, arm.operands[1], block->mode);
            if (!op1_res) {
                this->invalid_reg(op0, block->mode);
                break;
            }
            op1_val = *op1_res;


            auto op2_res = this->get_op_val(insn, arm.operands[2], block->mode);
            if (!op2_res) {
                this->invalid_reg(op0, block->mode);
                break;
            }
            op2_val = *op2_res;

            auto op3_res = this->get_op_val(insn, arm.operands[3], block->mode);
            if (!op3_res) {
                this->invalid_reg(op0, block->mode);
                break;
            }
            op2_val = rotr32(op2_val, *op3_res);
        }
        else {
            LOG(FATAL) << "Invalid arm ADD instruction at: 0x" << std::hex << insn->address;
        }
        int32_t result = op1_val + op2_val;

        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << result;

        m_reg_32_cache.set_reg(op0.reg, result);

        break;
    }
    case ARM_INS_ADR: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm ADR instruction at: 0x" << std::hex << insn->address;
        }
        op0 = arm.operands[0];
        op1 = arm.operands[1];

        if (op0.type != ARM_OP_REG) {
            break;
        }

        int32_t reg_val = insn->address + pc_offset + op1.imm;
        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << reg_val;

        m_reg_32_cache.set_reg(op0.reg, reg_val);

        break;
    }

    case ARM_INS_MOVT: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm MOV instruction at: 0x" << std::hex << insn->address;
        }

        op0 = arm.operands[0];
        op1 = arm.operands[1];

        if (op0.type != ARM_OP_REG) {
            break;
        }

        auto op0_res = this->get_op_val(insn, op0, block->mode);
        if (!op0_res) {
            this->invalid_reg(op0, block->mode);
            break;
        }
        int32_t op0_val = *op0_res;

        auto op1_res = this->get_op_val(insn, op1, block->mode);
        if (!op1_res) {
            this->invalid_reg(op0, block->mode);
            break;
        }
        int32_t op1_val = *op1_res;

        op1_val = (op0_val & 0x0000ffff) + (op1_val << 16);

        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << op1_val;
        m_reg_32_cache.set_reg(op0.reg, op1_val);
        break;
    }

    case ARM_INS_MOVW:
    case ARM_INS_MOV: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm MOV instruction at: 0x" << std::hex << insn->address;
        }

        op0 = arm.operands[0];
        op1 = arm.operands[1];

        if (op0.type != ARM_OP_REG) {
            break;
        }

        auto op1_res = this->get_op_val(insn, op1, block->mode);
        if (!op1_res) {
            this->invalid_reg(op0, block->mode);
            break;
        }
        int32_t op1_val = *op1_res;

        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << op1_val;
        m_reg_32_cache.set_reg(op0.reg, op1_val);
        break;
    }
    }
}

void CpuState::update_reg_arm64(cs_insn *insn, Block *block) {
    cs_arm64 arm = insn->detail->arm64;

    switch (insn->id) {
    case ARM64_INS_ADRP: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm64 ADRP at: 0x" << std::hex << insn->address;
        }
        cs_arm64_op op0 = arm.operands[0];
        cs_arm64_op op1 = arm.operands[1];

        if (op0.type != ARM64_OP_REG || op1.type != ARM64_OP_IMM) {
            break;
        }

        auto op1_res = this->get_op_val(insn, op1);
        if (!op1_res) {
            this->invalid_reg(op0, block->mode);
            break;
        }
        uint64_t op1_val = *op1_res;

        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << op1_val;
        m_reg_64_cache.set_reg(op0.reg, op1_val);

        break;
    }
    case ARM64_INS_ADD: {
        if (arm.op_count < 3) {
            LOG(FATAL) << "--Invalid arm ADD instruction at: 0x" << std::hex << insn->address;
        }
        cs_arm64_op op0 = arm.operands[0];
        cs_arm64_op op1 = arm.operands[1];
        cs_arm64_op op2 = arm.operands[2];

        if (op0.type != ARM64_OP_REG) {
            break;
        }

        auto op1_res = this->get_op_val(insn, op1);
        auto op2_res = this->get_op_val(insn, op2);
        if (!op1_res || !op2_res) {
            this->invalid_reg(op0, block->mode);
            break;
        }
        uint64_t op1_val = *op1_res;
        uint64_t op2_val = *op2_res;

        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << op1_val + op2_val;
        m_reg_64_cache.set_reg(op0.reg, op1_val + op2_val);

        break;
    }
    case ARM64_INS_ADR: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm ADR instruction at: 0x" << std::hex << insn->address;
        }
        cs_arm64_op op0 = arm.operands[0];
        cs_arm64_op op1 = arm.operands[1];

        if (op0.type != ARM64_OP_REG) {
            break;
        }

        auto op1_res = this->get_op_val(insn, op1);
        if (!op1_res) {
            this->invalid_reg(op0, block->mode);
            break;
        }
        uint64_t op1_val = *op1_res;

        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << op1_val;
        m_reg_64_cache.set_reg(op0.reg, op1_val);

        break;
    }

    case ARM64_INS_LDR: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm64 LDR at: 0x" << std::hex << insn->address;
        }
        cs_arm64_op op0 = arm.operands[0];
        cs_arm64_op op1 = arm.operands[1];

        int64_t read_addr = 0;
        switch(op1.type) {
        case ARM64_OP_IMM:
            read_addr = op1.imm;
            break;
        case ARM64_OP_MEM:
            if (op1.mem.base != arm64_reg::ARM64_REG_INVALID && op1.mem.disp != 0) {
                auto op1_res = this->m_reg_64_cache.get_reg(op1.mem.base);
                if (!op1_res) {
                    read_addr = 0;
                    break;
                }
                uint64_t op1_val = *op1_res;
                read_addr = op1_val + op1.mem.disp;
            }
            else if (op1.mem.index != arm64_reg::ARM64_REG_INVALID) {
                auto op1_idx_res = m_reg_64_cache.get_reg(op1.mem.index);
                auto op1_base_res = m_reg_64_cache.get_reg(op1.mem.base);

                if (!op1_idx_res || !op1_base_res) {
                    read_addr = 0;
                    break;
                }

                int64_t index_val = *op1_idx_res;
                int64_t base_val = *op1_base_res;
                VLOG(VLOG_REG) << "--base_val: 0x" << std::hex << base_val;
                VLOG(VLOG_REG) << "--idx_val:  0x" << std::hex << index_val;

                read_addr = static_cast<int64_t>(base_val + index_val);
            }
            break;
        default:
            this->invalid_reg(op0, block->mode);
            break;
        }

        if (!read_addr || read_addr < 0) {
            this->invalid_reg(op0, block->mode);
            break;
        }

        VLOG(VLOG_REG) << "--Reading from: 0x" << std::hex << read_addr;
        const auto *mem_ptr = reinterpret_cast<const int64_t *>(m_memmap->addr_to_ptr(read_addr));
        if (!mem_ptr) {
            LOG(ERROR) << "Failed to find memory for addr: 0x" << std::hex << op1.imm;
            this->invalid_reg(op0, block->mode);
            break;
        }

        m_reg_64_cache.set_reg(op0.reg, *mem_ptr);
        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << *mem_ptr;


        break;
    }
    default:
        break;
    }
}

void CpuState::update_reg_mips(cs_insn *insn, Block *block) {
    cs_mips mips = insn->detail->mips;

    switch (insn->id) {
    case MIPS_INS_LI: {
        if (mips.op_count < 2) {
            LOG(FATAL) << "Invalid op count for MIPS li instruction at: 0x" << std::hex << insn->address;
        }
        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        if (op0.type != MIPS_OP_REG || op1.type != MIPS_OP_IMM) {
            VLOG(VLOG_REG) << "Odd MIPS li instruction at: 0x" << std::hex << insn->address;
            break;
        }

        auto op1_res = this->get_op_val(insn, op1, block);
        if (!op1_res) {
            VLOG(VLOG_REG) << "Failed to get LI op1 value at: 0x" << std::hex << insn->address;
            break;
        }
        uint32_t value = *op1_res;
        m_reg_32_cache.set_reg(op0.reg, value);
        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << value;

        break;
    }
    case MIPS_INS_LUI: {
        if (mips.op_count < 2) {
            LOG(FATAL) << "Invalid op count for MIPS lui instruction at: 0x" << std::hex << insn->address;
        }
        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        if (op0.type != MIPS_OP_REG || op1.type != MIPS_OP_IMM) {
            VLOG(VLOG_REG) << "Odd MIPS lui instruction at: 0x" << std::hex << insn->address;
            break;
        }

        uint64_t value = op1.imm << 16;
        m_reg_32_cache.set_reg(op0.reg, value);
        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << value;

        break;
    }

    case MIPS_INS_LW: {
        if (mips.op_count < 2) {
            LOG(FATAL) << "Invalid op count for MIPS lw instruction at: 0x" << std::hex << insn->address;
        }
        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        uint32_t value = 0;
        auto op1_res = this->get_op_val(insn, op1, block);
        if (!op1_res) {
            this->invalid_reg(op0);
            VLOG(VLOG_REG) << "Failed to get LW operand value";
            break;
        }
        value = *op1_res;

        m_reg_32_cache.set_reg(op0.reg, value);
        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << value;


        break;
    }

    case MIPS_INS_ADDIU: {
        if (mips.op_count < 3) {
            LOG(FATAL) << "Invalid op count for MIPS addiu instruction at: 0x" << std::hex << insn->address;
        }
        cs_mips_op write_op = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];
        cs_mips_op op2 = mips.operands[2];

        if (write_op.type != MIPS_OP_REG || op1.type != MIPS_OP_REG || op2.type != MIPS_OP_IMM) {
            VLOG(VLOG_REG) << "Odd MIPS addiu instruction at: 0x" << std::hex << insn->address;
            break;
        }

        auto op1_res = this->get_op_val(insn, op1, block);
        if (!op1_res) {
            VLOG(VLOG_REG) << "Failed to get ADDIU operand value";
            break;
        }

        int32_t value = *op1_res + op2.imm;
        m_reg_32_cache.set_reg(write_op.reg, value);
        VLOG(VLOG_REG) << "--updated reg: " << write_op.reg << " to : 0x" << std::hex << value;

        break;
    }

    case MIPS_INS_ADDU: {
        if (mips.op_count < 3) {
            LOG(FATAL) << "Invalid op count for MIPS addu instruction at: 0x" << std::hex << insn->address;
        }
        cs_mips_op write_op = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];
        cs_mips_op op2 = mips.operands[2];

        if (write_op.type != MIPS_OP_REG || op1.type != MIPS_OP_REG || op2.type != MIPS_OP_REG) {
            VLOG(VLOG_REG) << "Odd MIPS addu instruction at: 0x" << std::hex << insn->address;
            break;
        }

        auto op1_res = this->get_op_val(insn, op1, block);
        if (!op1_res) {
            VLOG(VLOG_REG) << "Failed to get addu operand 1 value";
            this->invalid_reg(op1);
            break;
        }
        auto op2_res = this->get_op_val(insn, op2, block);
        if (!op2_res) {
            VLOG(VLOG_REG) << "Failed to get addu operand 2 value";
            this->invalid_reg(op2);
            break;
        }

        int32_t value = *op1_res + *op2_res;
        m_reg_32_cache.set_reg(write_op.reg, value);
        VLOG(VLOG_REG) << "--updated reg: " << write_op.reg << " to : 0x" << std::hex << value;

        break;
    }

    case MIPS_INS_SW: {
        if (mips.op_count < 2) {
            LOG(FATAL) << "Invalid op count for MIPS sw instruction at: 0x" << std::hex << insn->address;
        }

        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        if (op0.type != MIPS_OP_REG || op1.type != MIPS_OP_MEM) {
            VLOG(VLOG_REG) << "Odd sw, invalid operand types at 0x" << std::hex << insn->address;
        }

        // Store to our virtual stack.
        if (op1.mem.base == MIPS_REG_SP) {
            auto op0_res = this->get_op_val(insn, op0, block);
            if (!op0_res) {
                break;
            }
            uint64_t offset = op1.mem.disp;

            auto func_stack = m_virt_stack.find(block->func_addr);
            if (func_stack == m_virt_stack.end()) {
                m_virt_stack[block->func_addr].emplace(offset, *op0_res);
            }
            else {
                func_stack->second[offset] = *op0_res;
            }

            VLOG(VLOG_REG) << "--storing register (" << op0.reg << ") val: 0x" << std::hex << *op0_res << " at offset: 0x" << offset << " on the virtual stack";
        }

        break;
    }

    default:
        break;
    }
}

void CpuState::update_reg_ppc(cs_insn *insn, Block *block) {
    cs_ppc ppc = insn->detail->ppc;

    switch (insn->id) {
    case PPC_INS_LIS: {
        if (ppc.op_count < 2) {
            LOG(FATAL) << "Invalid op count for PPC lis instruction at: 0x" << std::hex << insn->address;
        }

        cs_ppc_op op0 = ppc.operands[0];
        cs_ppc_op op1 = ppc.operands[1];

        if (op0.type != PPC_OP_REG || op1.type != PPC_OP_IMM) {
            LOG(FATAL) << "Invalid PPC lis instruction at: 0x" << std::hex << insn->address;
        }

        uint32_t value = op1.imm << 16;
        m_reg_32_cache.set_reg(op0.reg, value);
        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << value;

        break;
    }
    case PPC_INS_LWZ:
    case PPC_INS_LWZU: {
        if (ppc.op_count < 2) {
            LOG(FATAL) << "Invalid op count for PPC lwzu instruction at: 0x" << std::hex << insn->address;
        }

        cs_ppc_op op0 = ppc.operands[0];
        cs_ppc_op op1 = ppc.operands[1];

        if (op0.type != PPC_OP_REG || op1.type != PPC_OP_MEM) {
            LOG(FATAL) << "Invalid PPC lis instruction at: 0x" << std::hex << insn->address;
        }

        auto op1_res = this->get_op_val(insn, op1, block);
        if (!op1_res) {
            VLOG(VLOG_REG) << "Failed to get lwzu operand 1 value";
            this->invalid_reg(op0);
            break;
        }

        auto op1_read_add = this->get_op_read_addr(insn, op1);
        if (!op1_res) {
            VLOG(VLOG_REG) << "Failed to get lwzu operand 1 read addr";
            this->invalid_reg(op0);
            break;
        }

        uint32_t value = *op1_res;

        m_reg_32_cache.set_reg(op0.reg, value);
        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << value;
        m_reg_32_cache.set_reg(op1.mem.base, *op1_read_add);
        VLOG(VLOG_REG) << "--updated reg: " << op1.mem.base << " to : 0x" << std::hex << *op1_read_add;
        break;
    }
    case PPC_INS_ADDI: {
        CHECK(ppc.op_count == 3) << "Invalid PPC addi insn at: 0x" << std::hex << insn->address;

        cs_ppc_op op0 = ppc.operands[0];
        cs_ppc_op op1 = ppc.operands[1];
        cs_ppc_op op2 = ppc.operands[2];

        if (op0.type != PPC_OP_REG || op1.type != PPC_OP_REG || op2.type != PPC_OP_IMM) {
            LOG(FATAL) << "Invalid PPC addi insn at: 0x" << std::hex << insn->address;
        }

        auto op1_res = this->get_op_val(insn, op1, block);
        if (!op1_res) {
            this->invalid_reg(op0);
            break;
        }

        uint32_t value = *op1_res + static_cast<int16_t>(op2.imm);
        m_reg_32_cache.set_reg(op0.reg, value);
        VLOG(VLOG_REG) << "--updated reg: " << op0.reg << " to : 0x" << std::hex << value;
        break;
    }
    }
}

void CpuState::update_reg_cache(cs_insn *insn, Block *block) {
    if (m_arch == cs_arch::CS_ARCH_X86) {
        this->update_reg_x86(insn, block);
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        this->update_reg_arm(insn, block);
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        this->update_reg_arm64(insn, block);
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS) {
        this->update_reg_mips(insn, block);
    }
    else if (m_arch == cs_arch::CS_ARCH_PPC) {
        this->update_reg_ppc(insn, block);
    }
    else {
        LOG(FATAL) << "Invalid Arch for reg cache: " << m_arch;
    }
}


void CpuState::add_meta_x86(cs_insn *insn, Block *block) {
    cs_x86 x86 = insn->detail->x86;

    switch (insn->id) {
    case X86_INS_LEA: {
        if (x86.op_count < 2) {
            LOG(FATAL) << "Invalid x86 LEA at: 0x" << std::hex << insn->address;
        }
        cs_x86_op op0 = x86.operands[0];
        cs_x86_op op1 = x86.operands[1];

        auto op1_res = this->get_op_read_addr(insn, op1, block->mode);
        if (!op1_res) {
            break;
        }
        uint64_t target = *op1_res;

        if (op0.type != X86_OP_REG) {
            LOG(FATAL) << "Invalid x86 LEA at: 0x" << std::hex << insn->address;
        }

        block->metadata.emplace(bb_metadata::LOAD, MetaData(insn->address, op0.reg, target));

        break;
    }
    case X86_INS_MOV: {
        if (x86.op_count < 2) {
            LOG(FATAL) << "Invalid x86 MOV at: 0x" << std::hex << insn->address;
        }

        auto load_meta = block->metadata.find(bb_metadata::LOAD);
        if (load_meta == block->metadata.end()) {
            break;
        }

        cs_x86_op op1 = x86.operands[1];

        if (op1.type != X86_OP_MEM) {
            break;
        }

        int64_t disp = op1.mem.disp;
        if (!disp || disp < 0) {
            break;
        }

        if (op1.mem.base != load_meta->second.reg) {
            break;
        }

        // Update if it exists
        auto mov_meta = block->metadata.find(bb_metadata::MOV_OFFSET);
        if (mov_meta == block->metadata.end()) {
            block->metadata.emplace(bb_metadata::MOV_OFFSET, MetaData(insn->address, 0, disp));
            break;
        }

        break;
    }
    case X86_INS_ADD: {
        auto lea_meta = block->metadata.find(bb_metadata::LOAD);
        if (lea_meta == block->metadata.end()) {
            break;
        }

        if (x86.op_count < 2) {
            LOG(FATAL) << "Invalid x86 ADD at: 0x" << std::hex << insn->address;
        }

        cs_x86_op op0 = x86.operands[0];
        cs_x86_op op1 = x86.operands[1];

        if (op0.type != X86_OP_REG && op1.type != X86_OP_REG) {
            break;
        }

        if (op0.reg != lea_meta->second.reg && op1.reg != lea_meta->second.reg) {
            break;
        }

        block->metadata.emplace(bb_metadata::REG_ARITH, MetaData(insn->address, lea_meta->second.reg, 0));

        break;
    }
    case X86_INS_AND: {
        auto lea_meta = block->metadata.find(bb_metadata::LOAD);
        if (lea_meta == block->metadata.end()) {
            break;
        }

        if (x86.op_count < 2) {
            LOG(FATAL) << "Invalid x86 AND at: 0x" << std::hex << insn->address;
        }

        cs_x86_op op0 = x86.operands[0];
        cs_x86_op op1 = x86.operands[1];

        if (op0.type != X86_OP_REG && op1.type != X86_OP_IMM) {
            break;
        }

        block->metadata.emplace(bb_metadata::AND_OFFSET, MetaData(insn->address, op0.reg, op1.imm));

        break;
    }
    case X86_INS_JMP: {
        if (x86.op_count < 1) {
            LOG(FATAL) << "Invalid x86 JMP at: 0x" << std::hex << insn->address;
        }

        cs_x86_op op0 = x86.operands[0];

        if (op0.type == X86_OP_REG) {
            auto arith_meta = block->metadata.find(bb_metadata::REG_ARITH);
            if (arith_meta == block->metadata.end()) {
                break;
            }

            auto load_meta = block->metadata.find(bb_metadata::LOAD);
            if (load_meta == block->metadata.end()) {
                LOG(FATAL) << "Invalid block metadata, missing LOAD key";
            }

            uint64_t vtable_addr = load_meta->second.value;
            auto mov_meta = block->metadata.find(bb_metadata::MOV_OFFSET);
            if (mov_meta != block->metadata.end()) {
                vtable_addr += mov_meta->second.value;
            }

            VLOG(VLOG_CFG) << "Found possible switch vtable at: 0x"
                           << std::hex << vtable_addr << " at block: 0x" << block->start;

            m_switch_vtables.emplace(vtable_addr, block->start);
            block->metadata.emplace(bb_metadata::SWITCH_INDIRECT, MetaData(insn->address, op0.reg, 0));
        }
        else if (block->mode == cs_mode::CS_MODE_32 && op0.type == X86_OP_MEM) {
            if (op0.mem.base != X86_REG_INVALID) {
                break;
            }
            if (op0.mem.index == X86_REG_INVALID) {
                break;
            }

            m_switch_vtables.emplace(op0.mem.disp, block->start);
            block->metadata.emplace(bb_metadata::SWITCH_INDIRECT, MetaData(insn->address, X86_REG_INVALID, 0));
        }

        break;
    }
    case X86_INS_CMP: {
        if (x86.op_count < 2) {
            LOG(FATAL) << "Invalid x86 CMP at: 0x" << std::hex << insn->address;
        }

        cs_x86_op op0 = x86.operands[0];
        cs_x86_op op1 = x86.operands[1];

        if (op1.type != X86_OP_IMM) {
            break;
        }

        auto op1_res = this->get_op_val(insn, op1, block->mode);
        if (!op1_res) {
            break;
        }
        uint64_t cmp_val = *op1_res;


        // Optional op0 reg, on x86 some compilers will not store the index in a reg
        // but in a mem load location.
        uint32_t op0_reg = 0;
        if (op0.type == X86_OP_REG) {
            op0_reg = op0.reg;
        }

        block->metadata.emplace(bb_metadata::CMP_LENGTH, MetaData(insn->address, op0_reg, cmp_val));

        break;
    }
    }
}
void CpuState::add_meta_arm(cs_insn *insn, Block *block) {
    cs_arm arm = insn->detail->arm;

    switch (insn->id) {
    case ARM_INS_CMP: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm CMP at: 0x" << std::hex << insn->address;
        }
        cs_arm_op op0 = arm.operands[0];
        cs_arm_op op1 = arm.operands[1];

        auto op1_res = this->get_op_val(insn, op1, block->mode);
        if (!op1_res) {
            break;
        }
        uint64_t cmp_val = *op1_res;

        if (op0.type != ARM_OP_REG) {
            LOG(FATAL) << "Invalid arm CMP at: 0x" << std::hex << insn->address;
        }

        auto ret = block->metadata.emplace(bb_metadata::CMP_LENGTH, MetaData(insn->address, op0.reg, cmp_val));

        // if a compare exists, overwrite it with the current value.
        if (!ret.second) {
            block->metadata[bb_metadata::CMP_LENGTH] = MetaData(insn->address, op0.reg, cmp_val);
        }

        break;
    }
    case ARM_INS_LDR: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm LDR at: 0x" << std::hex << insn->address;
        }

        cs_arm_op op0 = arm.operands[0];
        cs_arm_op op1 = arm.operands[1];

        auto arm_cmp = block->metadata.find(bb_metadata::CMP_LENGTH);
        if (arm_cmp == block->metadata.end()) {
            // Add in addition data for direct switch branches with b/bx
            if (block->metadata.count(bb_metadata::LOAD)) {
                if (op1.type != ARM_OP_MEM) {
                    break;
                }

                if (op1.shift.type == ARM_SFT_LSL) {
                    uint32_t reg_numb = 0;
                    if (op1.type == ARM_OP_REG) {
                        reg_numb = op1.reg;
                    }

                    block->metadata.emplace(bb_metadata::ARM_LDR_SHIFT, MetaData(insn->address, reg_numb, 0));
                    break;
                }
            }
            break;
        }

        if (op0.type != ARM_OP_REG) {
            break;
        }
        if (op0.reg != ARM_REG_PC) {
            break;
        }

        // Common arm jump table for ldrls
        if (op1.type == ARM_OP_MEM && op1.mem.base == ARM_REG_PC) {
            if (op1.shift.type == ARM_SFT_LSL && op1.shift.value == 2) {
                uint64_t vtable_addr = insn->address + 8;

                VLOG(VLOG_CFG) << "Found possible switch vtable at: 0x"
                               << std::hex << vtable_addr << " at block: 0x" << block->start;

                m_switch_vtables.emplace(vtable_addr, block->start);
                block->metadata.emplace(bb_metadata::SWITCH_INDIRECT, MetaData(insn->address, ARM_REG_INVALID, 0));
            }
        }
        break;
    }
    case ARM_INS_TBH: {
        if (arm.op_count < 1) {
            LOG(FATAL) << "Invalid arm THB at: 0x" << std::hex << insn->address;
        }

        cs_arm_op op0 = arm.operands[0];

        if (op0.type != ARM_OP_MEM) {
            break;
        }

        if (op0.shift.type == ARM_SFT_LSL && op0.shift.value == 1) {
            uint64_t vtable_addr = 0;
            if (op0.mem.base == ARM_REG_PC) {
                vtable_addr = insn->address + 4;
            } else {
                auto reg_val = this->m_reg_32_cache.get_reg(op0.mem.base);
                if (!reg_val) {
                    break;
                }
                vtable_addr = *reg_val;
            }

            if (!vtable_addr) {
                break;
            }
            VLOG(VLOG_CFG) << "Found possible switch vtable at: 0x"
                           << std::hex << vtable_addr << " at block: 0x" << block->start;

            block->metadata.emplace(bb_metadata::TBH_INS, MetaData());
            m_switch_vtables.emplace(vtable_addr, block->start);
        }

        break;
    }
    case ARM_INS_TBB: {
        if (arm.op_count < 1) {
            LOG(FATAL) << "Invalid arm THB at: 0x" << std::hex << insn->address;
        }

        cs_arm_op op0 = arm.operands[0];

        if (op0.type != ARM_OP_MEM) {
            break;
        }
        if (op0.mem.base != ARM_REG_PC) {
            break;
        }

        uint64_t vtable_addr = insn->address + 4;
        VLOG(VLOG_CFG) << "Found possible switch vtable at: 0x"
                       << std::hex << vtable_addr << " at block: 0x" << block->start;

        block->metadata.emplace(bb_metadata::TBB_INS, MetaData());
        m_switch_vtables.emplace(vtable_addr, block->start);


        break;
    }
    // Alternative path a switch construction can take:
    case ARM_INS_ADR: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm ADR at: 0x" << std::hex << insn->address;
        }
        cs_arm_op op0 = arm.operands[0];
        cs_arm_op op1 = arm.operands[1];

        if (op0.type != ARM_OP_REG) {
            break;
        }
        // Grab the value right out of the register from the tracking code.
        auto op0_res = this->get_op_val(insn, op0, block->mode);
        if (!op0_res) {
            break;
        }
        uint64_t op0_val = *op0_res;

        block->metadata.emplace(bb_metadata::LOAD, MetaData(insn->address, op0.reg, op0_val));

        break;
    }
    case ARM_INS_B:
    case ARM_INS_BX: {
        if (arm.op_count < 1) {
            LOG(FATAL) << "Invalid arm BRANCH at: 0x" << std::hex << insn->address;
        }
        cs_arm_op op0 = arm.operands[0];

        auto adr_meta = block->metadata.find(bb_metadata::LOAD);
        if (adr_meta == block->metadata.end()) {
            break;
        }

        if (!block->metadata.count(bb_metadata::ARM_LDR_SHIFT)) {
            break;
        }

        if (op0.type != ARM_OP_REG) {
            break;
        }
        if (op0.reg != adr_meta->second.reg) {
            break;
        }

        uint64_t vtable_addr = adr_meta->second.value;

        VLOG(VLOG_CFG) << "Found possible switch vtable at: 0x"
                       << std::hex << vtable_addr << " at block: 0x" << block->start;

        m_switch_vtables.emplace(vtable_addr, block->start);
        block->metadata.emplace(bb_metadata::SWITCH_INDIRECT, MetaData(insn->address, op0.reg, 0));

        break;
    }
    }
}
void CpuState::add_meta_arm64(cs_insn *insn, Block *block) {
    cs_arm64 arm64 = insn->detail->arm64;

    switch (insn->id) {
    case ARM64_INS_SUB:
        if (arm64.op_count < 3) {
            LOG(FATAL) << "Invalid arm64 SUB at: 0x" << std::hex << insn->address;
        }

        if (arm64.operands[2].type == ARM64_OP_IMM && arm64.operands[0].type == ARM64_OP_REG) {
            if (block->metadata.count(bb_metadata::CMP_LENGTH)) {
                block->metadata.erase(bb_metadata::CMP_LENGTH);
                block->metadata.emplace(bb_metadata::CMP_LENGTH, MetaData(insn->address, arm64.operands[0].reg, arm64.operands[2].imm));
            }
        }

        break;
    case ARM64_INS_CMP: {
        if (arm64.op_count < 2) {
            LOG(FATAL) << "Invalid arm64 CMP at: 0x" << std::hex << insn->address;
        }
        cs_arm64_op op0 = arm64.operands[0];
        cs_arm64_op op1 = arm64.operands[1];

        auto op1_res = this->get_op_val(insn, op1);
        if (!op1_res) {
            break;
        }
        uint64_t cmp_val = *op1_res;

        if (op0.type != ARM64_OP_REG) {
            LOG(FATAL) << "Invalid arm64 CMP at: 0x" << std::hex << insn->address;
        }

        block->metadata.emplace(bb_metadata::CMP_LENGTH, MetaData(insn->address, op0.reg, cmp_val));

        break;
    }

    /*
        Special case for:
        adrp    x8, data_418000
        add     x8, x8, #0xf18  {jump_table_418f18}
        ldr     x9, [sp, #0x70 {var_100_1}]
        ldr     x8, [x8, x9, lsl #0x3] <-- trigger and save meta here
        br      x8
    */
    case ARM64_INS_LDR:
        if (arm64.op_count == 2) {
            cs_arm64_op op0 = arm64.operands[0];
            cs_arm64_op op1 = arm64.operands[1];

            if (op0.type != ARM64_OP_REG || op1.type != ARM64_OP_MEM) {
                break;
            }

            if (op0.reg != op1.mem.base) {
                break;
            }

            if (op1.shift.type == ARM64_SFT_LSL) {
                block->metadata.emplace(bb_metadata::ADD_OFFSET, MetaData(insn->address, op0.reg, 0x0, 0));
            }

            uint64_t base_val = 0;

            auto op1_base_res = this->get_op_val(insn, op0);
            if (!op1_base_res) {
                base_val = this->get_last_removed();
            }
            else {
                base_val = *op1_base_res;
            }

            if (base_val) {
                block->metadata.emplace(bb_metadata::LOAD, MetaData(insn->address, op1.mem.base, base_val, 8));
            }

            break;
        }
        break;

    // Fall through and then check scale inside the block.
    case ARM64_INS_LDRB:
    case ARM64_INS_LDRH: {
        if (arm64.op_count < 2) {
            LOG(FATAL) << "Invalid arm64 LDRH at: 0x" << std::hex << insn->address;
        }
        cs_arm64_op op0 = arm64.operands[0];
        cs_arm64_op op1 = arm64.operands[1];

        if (op0.type != ARM64_OP_REG) {
            break;
        }

        if (op1.type != ARM64_OP_MEM) {
            break;
        }

        // scale defined by instruction (H == half word)
        uint8_t scale = 0;
        if (insn->id == ARM64_INS_LDRB) {
            scale = 1;
        }
        else if (insn->id == ARM64_INS_LDRH) {
            scale = 2;
        }

        if (!scale) {
            LOG(FATAL) << "Invalid scale for LDR* ARM64 instruction";
        }

        // Should hold the vtable reg
        // this check blocks vtables that are loaded in previous blocks (UNSUPPORTED!)
        auto op1_base_res = m_reg_64_cache.get_reg(op1.mem.base);
        if (!op1_base_res) {
            break;
        }
        uint64_t base_val = *op1_base_res;

        block->metadata.emplace(bb_metadata::LOAD, MetaData(insn->address, op0.reg, base_val, scale));

        break;
    }

    case ARM64_INS_ADD: {
        if (arm64.op_count < 3) {
            LOG(FATAL) << "Invalid arm64 ADD at: 0x" << std::hex << insn->address;
        }

        // Make sure we have already seen the load we want.
        if (!block->metadata.count(bb_metadata::LOAD)) {
            break;
        }

        cs_arm64_op op0 = arm64.operands[0];
        cs_arm64_op op1 = arm64.operands[1];
        cs_arm64_op op2 = arm64.operands[2];

        if (op0.type != ARM64_OP_REG) {
            break;
        }
        if (op1.type != ARM64_OP_REG) {
            break;
        }

        uint64_t base_block_addr = 0;
        auto op1_res = m_reg_64_cache.get_reg(op1.reg);
        if (op1_res) {
            base_block_addr = *op1_res;
        }

        uint8_t shift_val = 0;
        // TODO: make it a modular if we need to shift right.
        if (op2.shift.type == ARM64_SFT_LSL) {
            shift_val = op2.shift.value;
        }

        block->metadata.emplace(bb_metadata::ADD_OFFSET, MetaData(insn->address, op0.reg, base_block_addr, shift_val));

        break;
    }
    case ARM64_INS_BR: {
        if (arm64.op_count < 1) {
            LOG(FATAL) << "Invalid arm64 BR at: 0x" << std::hex << insn->address;
        }

        cs_arm64_op op0 = arm64.operands[0];

        if (op0.type != ARM64_OP_REG) {
            break;
        }

        auto load_meta = block->metadata.find(bb_metadata::LOAD);
        if (load_meta == block->metadata.end()) {
            break;
        }

        auto add_meta = block->metadata.find(bb_metadata::ADD_OFFSET);
        if (add_meta == block->metadata.end()) {
            break;
        }

        // Make sure we are actually branching off the primed register
        if (add_meta->second.reg != op0.reg) {
            break;
        }

        uint64_t vtable_addr = load_meta->second.value;

        VLOG(VLOG_CFG) << "Found possible switch vtable at: 0x"
                       << std::hex << vtable_addr << " at block: 0x" << block->start;

        m_switch_vtables.emplace(vtable_addr, block->start);
        block->metadata.emplace(bb_metadata::SWITCH_INDIRECT, MetaData(insn->address, ARM64_REG_INVALID, 0));

        break;
    }

    // Add in metadata about branch linking
    case ARM64_INS_LDP: {
        if (arm64.op_count < 3) {
            LOG(FATAL) << "Invalid arm64 LDP at: 0x" << std::hex << insn->address;
        }
        // Some times arm64 binaries will emit a manual save of the link regiser
        // then use a b instruction instead of bl.  This can confuse the CFG engine
        // into thinking a target is a block in the current function vs an actual call

        // Example:
        // ldp     x29, x30, [sp {__saved_x29} {__saved_x30}], #0x90
        // b <TARGET>

        cs_arm64_op op0 = arm64.operands[0];
        cs_arm64_op op1 = arm64.operands[1];
        cs_arm64_op op2 = arm64.operands[2];

        if (op0.type != ARM64_OP_REG || op1.type != ARM64_OP_REG) {
            break;
        }

        if (op0.reg != ARM64_REG_FP && op0.reg != ARM64_REG_LR) {
            break;
        }
        if (op1.reg != ARM64_REG_FP && op1.reg != ARM64_REG_LR) {
            break;
        }

        if (op2.type == ARM64_OP_MEM) {
            if (op2.mem.base == ARM64_REG_SP) {
                block->metadata.emplace(bb_metadata::SAVE_LINK_REG, MetaData(insn->address, ARM64_REG_INVALID, 0));
            }
        }

        break;
    }
    }
}

void CpuState::add_meta_mips(cs_insn *insn, Block *block) {
    cs_mips mips = insn->detail->mips;

    switch (insn->id) {
    case MIPS_INS_SLTIU: {
        if (mips.op_count < 3) {
            LOG(FATAL) << "Invalid mips SLTIU at: 0x" << std::hex << insn->address;
        }
        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op2 = mips.operands[2];

        auto op2_res = this->get_op_val(insn, op2, block);
        if (!op2_res) {
            break;
        }
        uint64_t cmp_val = *op2_res - 1; // zero indexed.

        if (op0.type != MIPS_OP_REG) {
            LOG(FATAL) << "Invalid mips SLTIU at: 0x" << std::hex << insn->address;
        }

        block->metadata.emplace(bb_metadata::CMP_LENGTH, MetaData(insn->address, op0.reg, cmp_val));

        break;
    }

    /* First mips switch prolog:
     * lw      $at, 0x24($fp) {var_24}
     * sll     $v0, $at, 0x2 {indx << 2}
     * lui     $v1, 0x44  {0x440000}
     * addu    $v0, $v0, $v1
     * lw      $v0, -0x20c8($v0)
     * jr      $v0
     */
    case MIPS_INS_SLL: {
        if (mips.op_count < 3) {
            LOG(FATAL) << "Invalid mips SLL insn at: 0x" << std::hex << insn->address;
            break;
        }
        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op2 = mips.operands[2];

        if (op0.type != MIPS_OP_REG) {
            break;
        }
        if (op2.type != MIPS_OP_IMM) {
            break;
        }

        block->metadata.emplace(bb_metadata::SLL_VALUE, MetaData(insn->address, op0.reg, op2.imm));

        break;
    }

    case MIPS_INS_ADDIU: {
        if (mips.op_count < 3) {
            LOG(FATAL) << "Invalid MIPS addiu insn at: 0x" << std::hex << insn->address;
            break;
        }

        cs_mips_op op0 = mips.operands[0];

        if (op0.type != MIPS_OP_REG) {
            break;
        }

        auto op0_res = this->get_op_val(insn, op0, block);
        if (!op0_res) {
            break;
        }

        block->metadata.emplace(bb_metadata::ADDIU_VAL, MetaData(insn->address, op0.reg, *op0_res));

        break;
    }

    case MIPS_INS_ADDU: {
        if (mips.op_count < 3) {
            LOG(FATAL) << "Invalid MIPS addu insn at: 0x" << std::hex << insn->address;
            break;
        }

        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];
        cs_mips_op op2 = mips.operands[2];

        if (op0.type != MIPS_OP_REG || op1.type != MIPS_OP_REG || op2.type != MIPS_OP_REG) {
            break;
        }

        auto sll_meta = block->metadata.find(bb_metadata::SLL_VALUE);
        auto addiu_meta = block->metadata.find(bb_metadata::ADDIU_VAL);

        int32_t table_val = 0;
        if (sll_meta != block->metadata.end()) {
            if (sll_meta->second.reg == op2.reg) {
                // Special case here, since we already added the values
                // and basically doubled the value, we need to take the addiu val
                if (op0.reg == op1.reg && addiu_meta != block->metadata.end()) {
                    table_val = addiu_meta->second.value;
                }
                else {
                    auto op1_res = this->get_op_val(insn, op1, block);
                    if (!op1_res) {
                        break;
                    }
                    table_val = *op1_res;
                }
            }
            else if (sll_meta->second.reg == op0.reg) {
                auto op2_res = this->get_op_val(insn, op2, block);
                if (!op2_res) {
                    break;
                }
                table_val = *op2_res;
            }
        }
        else if (addiu_meta != block->metadata.end()) {
            table_val = addiu_meta->second.value;
        }

        block->metadata.emplace(bb_metadata::ADDU_VAL, MetaData(insn->address, op0.reg, table_val));

        break;
    }
    case MIPS_INS_LW: {
        if (mips.op_count < 2) {
            LOG(FATAL) << "Invalid MIPS lw insn at: 0x" << std::hex << insn->address;
            break;
        }
        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        if (op0.type != MIPS_OP_REG || op1.type != MIPS_OP_MEM) {
            break;
        }

        auto addu_meta = block->metadata.find(bb_metadata::ADDU_VAL);
        if (addu_meta == block->metadata.end()) {
            break;
        }

        // Skip the LW if we already got it.
        if (block->metadata.count(bb_metadata::LOAD)) {
            break;
        }

        uint32_t table_addr = op1.mem.disp + addu_meta->second.value;
        block->metadata.emplace(bb_metadata::LOAD, MetaData(insn->address, op0.reg, table_addr));

        break;
    }
    case MIPS_INS_JR: {
        if (mips.op_count < 1) {
            LOG(FATAL) << "Invalid mips JR insn at: 0x" << std::hex << insn->address;
            break;
        }

        cs_mips_op op0 = mips.operands[0];

        if (op0.type != MIPS_OP_REG || op0.reg == MIPS_REG_RA) {
            break;
        }

        bool has_addu = block->metadata.count(bb_metadata::ADDU_VAL);
        auto load_meta = block->metadata.find(bb_metadata::LOAD);

        if (!has_addu || load_meta == block->metadata.end()) {
            break;
        }

        uint64_t vtable_addr = load_meta->second.value;

        if (load_meta->second.reg == op0.reg) {
            VLOG(VLOG_CFG) << "Found possible switch vtable at: 0x"
                           << std::hex << vtable_addr << " at block: 0x" << block->start;

            m_switch_vtables.emplace(vtable_addr, block->start);
            block->metadata.emplace(bb_metadata::SWITCH_INDIRECT, MetaData(insn->address, MIPS_REG_INVALID, 0));
        }

        break;
    }
    }
}

void CpuState::add_meta_ppc(cs_insn *insn, Block *block) {
    cs_ppc ppc = insn->detail->ppc;

    /* Sample switch setup:
     *
     *  1000d63c  lis     r9, 0x1004  {jump_table_1003fe94[0x5b]}
     *  1000d640  slwi    r10, r14, 0x2
     *  1000d644  addi    r9, r9, -0x16c  {jump_table_1003fe94}
     *  1000d648  lwzx    r10, r9, r10
     *  1000d64c  add     r9, r10, r9
     *  1000d650  mtctr   r9
     *  1000d654  bctr
     */

    switch (insn->id) {
    case PPC_INS_ADDI: {
        CHECK (ppc.op_count > 0) << "Invalid PPC addi insn at: 0x" << std::hex << insn->address;
        cs_ppc_op op0 = ppc.operands[0];

        if (op0.type != PPC_OP_REG) {
            break;
        }

        if (block->metadata.count(bb_metadata::LOAD)) {
            break;
        }
        auto table_addr = this->m_reg_32_cache.get_reg(op0.reg);
        if (!table_addr) {
            break;
        }
        block->metadata.emplace(bb_metadata::LOAD, MetaData(insn->address, op0.reg, *table_addr));

        break;
    }
    case PPC_INS_LWZX: {
        CHECK(ppc.op_count > 2) << "Invalid PPC lwzx insn at: 0x" << std::hex << insn->address;

        cs_ppc_op op1 = ppc.operands[1];

        if (op1.type != PPC_OP_REG) {
            break;
        }

        auto load_meta = block->metadata.find(bb_metadata::LOAD);
        if (load_meta == block->metadata.end()) {
            break;
        }

        if (load_meta->second.reg != op1.reg) {
            break;
        }

        block->metadata.emplace(bb_metadata::LWZX_LOAD, MetaData(insn->address, op1.reg, 0));

        break;
    }
    case PPC_INS_MTCTR: {
        CHECK(ppc.op_count > 0) << "Invalid PPC mtctr insn at: 0x" << std::hex << insn->address;

        cs_ppc_op op0 = ppc.operands[0];

        if (op0.type != PPC_OP_REG) {
            break;
        }

        auto lwzx_meta = block->metadata.find(bb_metadata::LWZX_LOAD);
        if (lwzx_meta == block->metadata.end()) {
            break;
        }

        if (lwzx_meta->second.reg != op0.reg) {
            break;
        }

        block->metadata.emplace(bb_metadata::MTCTR_REG, MetaData(insn->address, op0.reg, 0));

        break;
    }
    case PPC_INS_BCTR: {
        auto mtctr_meta = block->metadata.find(bb_metadata::MTCTR_REG);
        if (mtctr_meta == block->metadata.end()) {
            break;
        }

        auto load_meta = block->metadata.find(bb_metadata::LOAD);
        if (load_meta == block->metadata.end()) {
            LOG(FATAL) << "Invalid PPC switch block metadata state at: 0x" << std::hex << insn->address;
        }

        auto vtable_addr = load_meta->second.value;

        VLOG(VLOG_CFG) << "Found possible switch vtable at: 0x"
                       << std::hex << vtable_addr << " at block: 0x" << block->start;

        m_switch_vtables.emplace(vtable_addr, block->start);
        block->metadata.emplace(bb_metadata::SWITCH_INDIRECT, MetaData(insn->address, PPC_REG_INVALID, 0));

        break;
    }

    case PPC_INS_CMPLWI: {
        CHECK(ppc.op_count > 1) << "Invalid PPC CMPLWI insn at: 0x" << std::hex << insn->address;

        if (ppc.op_count == 3) {
            cs_ppc_op op1 = ppc.operands[1];
            cs_ppc_op op2 = ppc.operands[2];

            if (op2.type != PPC_OP_IMM || op1.type != PPC_OP_REG) {
                break;
            }

            auto op2_res = this->get_op_val(insn, op2, block);
            if (!op2_res) {
                break;
            }

            block->metadata.emplace(bb_metadata::CMP_LENGTH, MetaData(insn->address, op1.reg, *op2_res));
        }
        else if (ppc.op_count == 2) {
            cs_ppc_op op0 = ppc.operands[0];
            cs_ppc_op op1 = ppc.operands[1];

            if (op1.type != PPC_OP_IMM || op0.type != PPC_OP_REG) {
                break;
            }

            auto op1_res = this->get_op_val(insn, op1, block);
            if (!op1_res) {
                break;
            }

            block->metadata.emplace(bb_metadata::CMP_LENGTH, MetaData(insn->address, op0.reg, *op1_res));
        }
    }
    }
}

void CpuState::add_block_metadata(cs_insn *insn, Block *block) {
    switch (m_arch) {
    case cs_arch::CS_ARCH_X86:
        this->add_meta_x86(insn, block);
        break;
    case cs_arch::CS_ARCH_ARM:
        this->add_meta_arm(insn, block);
        break;
    case cs_arch::CS_ARCH_ARM64:
        this->add_meta_arm64(insn, block);
        break;
    case cs_arch::CS_ARCH_MIPS:
        this->add_meta_mips(insn, block);
        break;
    case cs_arch::CS_ARCH_PPC:
        this->add_meta_ppc(insn, block);
        break;
    default:
        LOG(FATAL) << "Invalid arch for adding metadata";
        break;
    }
}
