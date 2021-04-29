#pragma once

#include <map>
#include <memory>
#include <cstdint>

#include "capstone/capstone.h"

#include "CfgRes.hpp"
#include "RegCache.hpp"

class MemoryMap;
struct Block;


class CpuState {
  public:
    CpuState(cs_arch arch, std::shared_ptr<MemoryMap> memmap);

    cs_arch get_arch() const;
    cs_mode get_mode() const;

    bool is_big_endian() const;
    bool has_delay_slot() const;

    void clear_reg_cache();
    void clear_vstack();

    void at_func_start(Block *block);
    void at_func_end();

    void at_block_start(Block *block);
    void at_block_end(Block *block);

    void at_insn(cs_insn *insn, Block *block);

    std::map<uint64_t, uint64_t> *get_switch_tables();

    uint64_t get_arm_pc_val(cs_insn *insn, cs_arm_op op, cs_mode mode) const;

    CfgRes<uint64_t> get_op_read_addr(cs_insn *insn, cs_x86_op op, cs_mode mode) const;
    CfgRes<uint32_t> get_op_read_addr(cs_insn *insn, cs_arm_op op, cs_mode mode) const;
    CfgRes<uint64_t> get_op_read_addr(cs_insn *insn, cs_arm64_op op, cs_mode mode) const;
    CfgRes<uint32_t> get_op_read_addr(cs_insn *insn, cs_mips_op op, Block *block) const;
    CfgRes<uint32_t> get_op_read_addr(cs_insn *insn, cs_ppc_op op) const;

    CfgRes<uint64_t> get_op_val(cs_insn *insn, cs_x86_op op, cs_mode mode) const;
    CfgRes<int32_t> get_op_val(cs_insn *insn, cs_arm_op op, cs_mode mode) const;
    CfgRes<uint64_t> get_op_val(cs_insn *insn, cs_arm64_op op) const;
    CfgRes<int32_t> get_op_val(cs_insn *insn, cs_mips_op op, Block *block) const;
    CfgRes<uint32_t> get_op_val(cs_insn *insn, cs_ppc_op op, Block *block) const;


    bool is_op_stack_based(cs_x86_op op);
    bool is_op_stack_based(cs_arm_op op);
    bool is_op_stack_based(cs_arm64_op op);

    std::shared_ptr<MemoryMap> get_memmap() const;

    // Setters / getters for registers
    CfgRes<int32_t> get_reg_val(ppc_reg reg) const;
    void set_reg_val_32(uint32_t reg, int32_t val);
    void set_reg_val_64(uint32_t reg, int64_t val);

  private:
    void change_mode(cs_mode mode);

    void add_meta_x86(cs_insn *insn, Block *block);
    void add_meta_arm(cs_insn *insn, Block *block);
    void add_meta_arm64(cs_insn *insn, Block *block);
    void add_meta_mips(cs_insn *insn, Block *block);
    void add_meta_ppc(cs_insn *insn, Block *block);

    void add_block_metadata(cs_insn *insn, Block *block);


    void invalid_reg(cs_x86_op op, cs_mode mode);
    void invalid_reg(cs_arm_op op, cs_mode mode);
    void invalid_reg(cs_arm64_op op, cs_mode mode);
    void invalid_reg(cs_mips_op op);
    void invalid_reg(cs_ppc_op op);

    uint64_t get_last_removed();

    void update_reg_x86(cs_insn *insn, Block *block);
    void update_reg_arm(cs_insn *insn, Block *block);
    void update_reg_arm64(cs_insn *insn, Block *block);
    void update_reg_mips(cs_insn *insn, Block *block);
    void update_reg_ppc(cs_insn *insn, Block *block);

    void update_reg_cache(cs_insn *insn, Block *block);


    const cs_arch m_arch;
    // the mode is able to change depending on the current block
    cs_mode m_mode;

    std::shared_ptr<MemoryMap> m_memmap;

    // cs_reg : cur_val
    RegCache<int32_t> m_reg_32_cache;
    RegCache<int64_t> m_reg_64_cache;

    // block_addr : RegCache
    // These are used to do a quick look up within a single function of the leader
    // blocks regcache to pre-populate the current register cache.
    std::map<uint64_t, RegCache<int32_t>> m_func_reg_caches_32;


    // Virtual stack used to save and store values within a single function.
    // indexing works like this:
    // func_addr : <offset : value>
    std::map<uint64_t, std::map<int32_t, uint64_t>> m_virt_stack;

    // Does the current arch has a delay slot
    bool m_has_delay_slot;

    // Is the current binary a bigE encoding.
    bool m_big_endian;

    // vtable_addr : block_addr, found in metadata parsing
    std::map<uint64_t, uint64_t> m_switch_vtables;
};
