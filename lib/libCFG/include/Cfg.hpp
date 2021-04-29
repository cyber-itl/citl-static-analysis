#pragma once

#include <map>
#include <vector>
#include <memory>
#include <cstdint>
#include <unordered_set>

#include "capstone/capstone.h"

#include "llvm/Object/ObjectFile.h"

#include "Block.hpp"
#include "BlockQueueUniq.hpp"
#include "CfgRes.hpp"
#include "Utils.hpp"

using namespace llvm;
using namespace object;

class CpuState;
class EventManager;
class MemBitMap;
class MemoryMap;
class SymResolver;
struct MemRange;


class Cfg {
  public:
    enum class branch_type {
        CONDITIONAL,
        UNCONDITIONAL,
        CALL,
        FALLTHRU,
        GUESS
    };

    enum class guess_type {
        UNKNOWN = 0,
        X86_MOV,
        X86_PUSH,
        X86_LEA,
        ARM_LDR,
        MIPS_LW,
        LIBC_START
    };

    enum class fixup_type {
        LEADER = 0,
        LEADER_REPLACE,
        FOLLOWER,
        CALLER,
        FUNC_ADDR
    };

    struct Fixup {
        Fixup(uint64_t block, uint64_t value, fixup_type type) :
            block(block),
            value(value),
            value_2(0),
            type(type) {};

        Fixup(uint64_t block, uint64_t value, uint64_t value_2, fixup_type type) :
            block(block),
            value(value),
            value_2(value_2),
            type(type) {};

        uint64_t block;
        uint64_t value;
        uint64_t value_2;
        fixup_type type;
    };

    struct Branch {
        Branch() :
            addr(0),
            type(branch_type::GUESS),
            g_type(guess_type::UNKNOWN) {};
        Branch(uint64_t addr, branch_type type, guess_type g_type) :
            addr(addr),
            type(type),
            g_type(g_type) {};

        bool operator==(const Branch &other) const {
            return this->addr == other.addr;
        }

        uint64_t addr;
        branch_type type;
        cs_mode mode;

        guess_type g_type;
    };

    Cfg(const ObjectFile *obj, std::shared_ptr<SymResolver> resolver, std::shared_ptr<MemoryMap> memmap, std::shared_ptr<EventManager> events);
    ~Cfg();

    int create_cfg(uint64_t ep);

    const std::map<block_range, Block, block_cmp> *get_cfg_map() const;

    const uint64_t get_switch_count() const;
    const uint64_t get_sweep_count() const;


    void print_cfg();


  private:
    void print_holes();

    void populate_func_tables();

    int process_func_queue();

    int process_block_queue(Block func_block, uint64_t func_addr);

    int process_block_queue();

    int process_block(Block *block);

    void split_block(uint64_t split_addr, Block *cur_block, bool call_target);

    void add_block(Branch target, Block *cur_block);

    void process_fixups(Block *block);

    void add_fixup(Fixup fixup);

    bool is_branch(cs_insn *insn) const;

    void find_guesses(cs_insn *insn, Block *block, std::vector<Branch> *targets);

    int process_guesses(std::vector<Branch> *guesses, Block *block);

    int find_branch_targets(cs_insn *insn, Block *block, Branch *targets);

    bool is_no_exit_sym(uint64_t sym_addr) const;

    uint64_t get_switch_bound(Block *cur_block, uint64_t switch_addr);

    template<typename ENTRY, typename VAL>
    VAL read_switch_entry(const ENTRY *entry, uint32_t idx, bool thumb_multi, uint8_t shift_val);

    template<typename ENTRY, typename VAL>
    int get_switch_table(uint64_t table_addr, Block *parent_block);

    void process_switches();

    uint64_t scan_and_queue(std::vector<MemRange> *holes, cs_mode mode);

    void do_linear_scan();

    int post_process_blocks();

    CfgRes<uint64_t> libc_start_main_helper(cs_insn *insn, Block *block) const;
    CfgRes<uint64_t> libc_start_main_ppc(cs_insn *insn, Block *block) const;

    const ObjectFile *m_obj;
    bin_type m_bin_type;
    std::shared_ptr<SymResolver> m_resolver;
    std::shared_ptr<MemoryMap> m_memmap;
    std::unique_ptr<MemBitMap> m_bitmap;

    CpuState *m_state;

    csh m_cs_handle;
    cs_arch m_arch;

    std::map<block_range, Block, block_cmp> m_blocks;

    BlockQueueUniq m_func_queue;

    BlockQueueUniq m_block_queue;
    uint64_t m_ep;

    std::unordered_set<uint64_t> m_exit_funcs;

    uint64_t m_switches_found;
    uint64_t m_sweep_funcs_found;

    // Used to queue up fixups for post processing.  For example, a call
    // target is found that is a duplicate, already in queue. In order to patch
    // up the callers's vector we can use fixups in a post processing pass.
    // block_addr : [Fixups]
    std::map<uint64_t, std::vector<Fixup>> m_fixups;

    std::shared_ptr<EventManager> m_events;
};
