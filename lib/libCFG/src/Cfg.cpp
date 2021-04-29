#include <cxxabi.h>
#include <cstdint>
#include <memory>
#include <vector>
#include <cstdlib>
#include <algorithm>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <functional>

#include "capstone/capstone.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "llvm/Object/ObjectFile.h"

#include "Cfg.hpp"
#include "CfgRes.hpp"
#include "MemRange.hpp"
#include "MemBitMap.hpp"
#include "AbiOracle.hpp"
#include "Utils.hpp"
#include "CapstoneHelper.hpp"
#include "Block.hpp"
#include "CpuState.hpp"
#include "PerfDefs.hpp"
#include "EventManager.hpp"
#include "MemoryMap.hpp"
#include "SymResolver.hpp"


#define MAX_BLOCK_SIZE 0x1000


DEFINE_bool(printholes, false, "Pretty prints the current holes in the text section after main analysis, before linear sweep");
DEFINE_bool(lin_sweep, true, "Toggle linear sweeps over the binary looking for funcs");

Cfg::Cfg(const ObjectFile *obj, std::shared_ptr<SymResolver> resolver, std::shared_ptr<MemoryMap> memmap, std::shared_ptr<EventManager> events) :
    m_obj(obj),
    m_resolver(std::move(resolver)),
    m_memmap(std::move(memmap)),
    m_ep(0),
    m_switches_found(0),
    m_sweep_funcs_found(0),
    m_bitmap(new MemBitMap()),
    m_bin_type(get_bin_type(obj)),
    m_state(nullptr),
    m_events(std::move(events)) {}

Cfg::~Cfg() {
    cs_close(&m_cs_handle);
    delete m_state;
}

const std::map<block_range, Block, block_cmp> *Cfg::get_cfg_map() const {
    return &m_blocks;
}

const uint64_t Cfg::get_switch_count() const {
    return m_switches_found;
}

const uint64_t Cfg::get_sweep_count() const {
    return m_sweep_funcs_found;
}


void Cfg::print_cfg() {
    csh cs_handle;

    unsigned int obj_arch = m_obj->getArch();
    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(obj_arch);
    m_arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    cs_err err;
    err = cs_open(m_arch, mode, &cs_handle);
    if (err != CS_ERR_OK) {
        LOG(ERROR) << "cs_open: " << cs_strerror(err);
        return;
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    for (const auto &kv : m_blocks) {
        Block block = kv.second;
        uint64_t block_size = block.end - block.start;
        uint64_t block_addr = block.start;

        LOG(INFO) << std::endl << "Block: 0x" << std::hex << block_addr << " size: 0x" << block_size;

        cs_insn *insn = cs_malloc(cs_handle);

        const uint8_t *data_ptr = block.data;

        cs_option(cs_handle, CS_OPT_MODE, block.mode);

        while(cs_disasm_iter(cs_handle, &data_ptr, &block_size, &block_addr, insn)) {
            cs_insn cur_insn = *insn;
            LOG(INFO) << "0x" << std::hex << insn->address << ": " << insn->mnemonic << " " << insn->op_str;
        }
        cs_free(insn, 1);

        LOG(INFO) << "Leaders:";
        for (const auto &leader : block.leaders) {
            LOG(INFO) << " 0x" << std::hex << leader;
        }
        LOG(INFO) << "Followers:";
        for (const auto &follower : block.followers) {
            LOG(INFO) << " 0x" << std::hex << follower;
        }
        if (block.is_func_head) {
            LOG(INFO) << "Callers:";
            for (const auto &follower : block.callers) {
                LOG(INFO) << " 0x" << std::hex << follower;
            }
        }
        if (block.branch_target) {
            LOG(INFO) << "Branch target: 0x" << std::hex << block.branch_target;
        }

        LOG(INFO) << "Call target: " << block.is_func_head;
        LOG(INFO) << "Function addr: 0x" << std::hex << block.func_addr;
        LOG(INFO) << "Splits insn: " << block.splits_insn;
    }

    cs_close(&cs_handle);
}

void Cfg::print_holes() {
    std::vector<MemRange> holes = this->m_bitmap->get_unset_ranges(m_memmap.get(), MapFlag::ANY);

    LOG(INFO) << "TEXT holes:";
    for (const auto &hole : holes) {
        LOG(INFO) << "  " << "0x" << std::hex << hole.addr << " : 0x" << hole.addr + hole.size << " | size: 0x" << hole.size;
    }
}

int Cfg::create_cfg(uint64_t ep) {
    unsigned int obj_arch = m_obj->getArch();

    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(obj_arch);
    m_arch = std::get<0>(arch_tup);

    cs_mode mode = std::get<1>(arch_tup);

    this->populate_func_tables();

    for (const auto &page : m_memmap->get_text_pages()) {
        if (!page.second) {
            continue;
        }
        m_bitmap->add_map(page.first, page.second);
    }

    m_state = new CpuState(m_arch, m_memmap);
    if (!m_state) {
        LOG(FATAL) << "Failed to create CpuState object";
    }

    cs_err err;
    err = cs_open(m_arch, mode, &m_cs_handle);
    if (err != CS_ERR_OK) {
        LOG(ERROR) << "cs_open: " << cs_strerror(err);
        return 1;
    }
    cs_option(m_cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Queue the entry point
    if (ep) {
        do {
            auto *ep_page = m_memmap->addr_to_page(ep);
            if (!ep_page) {
                LOG(WARNING) << "Invalid ep addr: 0x" << std::hex << ep;
                break;
            }

            if (ep_page->empty_page) {
                LOG(WARNING) << "Skipping ep addr due to virtual page: 0x" << std::hex << ep;
                break;
            }

            m_ep = ep;
            Block ep_block(m_ep);

            ep_block.mode = mode;
            if (m_arch == cs_arch::CS_ARCH_ARM) {
                if (ep_block.start % 2 != 0) {
                    ep_block.mode = cs_mode::CS_MODE_THUMB;
                    ep_block.start -= 1;
                    m_ep = ep_block.start;
                }
            }
            m_func_queue.push(ep_block);

            VLOG(VLOG_CFG) << "Pushing ep: 0x" << std::hex << ep_block.start;
        } while(false);
    }

    // Queue all exported symbols
    for (const auto &kv : m_resolver->get_syms_by_addr()) {
        Symbol sym = kv.second;

        if (sym.type != sym_type::EXPORT || sym.obj_type != sym_obj_type::FUNC) {
            continue;
        }

        if(!m_memmap->is_text_sec(kv.first)) {
            VLOG(VLOG_CFG) << "Skipping symbol function 0x" << std::hex << kv.first << " because its not a TEXT section";
            continue;
        }

        auto *sym_page = m_memmap->addr_to_page(kv.first);
        if (!sym_page) {
            LOG(WARNING) << "Invalid symbol addr, no page: 0x" << std::hex << kv.first;
            continue;
        }

        if (sym_page->empty_page) {
            VLOG(VLOG_CFG) << "Skipping symbol due to empty page: 0x" << std::hex << kv.first;
            continue;
        }

        Block sym_block(kv.first);
        sym_block.mode = mode;
        if (m_arch == cs_arch::CS_ARCH_ARM) {
            if (sym.is_thumb) {
                sym_block.mode = cs_mode::CS_MODE_THUMB;
            }
        }

        VLOG(VLOG_CFG) << "Pushing sym: 0x" << std::hex << sym_block.start;

        m_func_queue.push(sym_block);
    }

    // First process all normal functions, then process found functions.
    //  This helps reduce CFG false positives (for example CFI on windows includes both)
    //  functions and jump targets which can cause split functions.
    this->process_func_queue();

    // Queue all extra found functions (eg from CFG or eh_frame)
    for (const auto &kv : m_resolver->get_found_funcs()) {
        if(!m_memmap->is_text_sec(kv.first)) {
            VLOG(VLOG_CFG) << "Skipping found function 0x" << std::hex << kv.first << " because its not a TEXT section";
            continue;
        }
        auto *found_page = m_memmap->addr_to_page(kv.first);
        if (!found_page) {
            LOG(WARNING) << "Skipping invalid addr, no page: 0x" << std::hex << kv.first;
            continue;
        }

        if (found_page->empty_page) {
            VLOG(VLOG_CFG) << "Skipping found function, empty page: 0x" << std::hex << kv.first;
            continue;
        }

        if (m_blocks.count(make_range(kv.first))) {
            continue;
        }

        Block found_block(kv.first);
        found_block.mode = mode;
        if (m_arch == cs_arch::CS_ARCH_ARM) {
            if (found_block.start % 2 != 0) {
                found_block.mode = cs_mode::CS_MODE_THUMB;
                found_block.start -= 1;
            }
        }

        found_block.metadata.emplace(bb_metadata::FOUND_BLOCK, MetaData());

        VLOG(VLOG_CFG) << "Pushing found: 0x" << std::hex << found_block.start;

        m_func_queue.push(found_block);
    }

    // Process any newly added functions in the found queue.
    this->process_func_queue();

    m_state->clear_vstack();

    if (FLAGS_printholes) {
        this->print_holes();
    }
    if (FLAGS_lin_sweep) {
        this->do_linear_scan();
    }

    this->post_process_blocks();

    // Manually clean up our bitmap;
    this->m_bitmap.reset();

    CHECK(m_block_queue.empty() && m_func_queue.empty()) << "Failed to exhaust all blocks and functions";

    return 0;
}

void Cfg::populate_func_tables() {
    for (const auto &kv : m_resolver->get_syms_by_addr()) {
        // Populate any functions that exit with noreturn
        if (kv.second.name == "__stack_chk_fail") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "___stack_chk_fail") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "__dl___stack_chk_fail") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "exit") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "_exit") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "__cxa_bad_cast") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "__cxa_bad_typeid") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "__assert_fail") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "abort") {
            m_exit_funcs.emplace(kv.first);
        }
        if (kv.second.name == "__android_log_assert") {
            m_exit_funcs.emplace(kv.first);
        }

        std::string demangled_sym;
        int status;
        char *ret = abi::__cxa_demangle(kv.second.name.c_str(), 0, 0, &status);

        if (status == 0) {
            demangled_sym = std::string(ret);
        }
        else {
            continue;
        }
        free(ret);

        if (demangled_sym == "std::terminate()") {
            m_exit_funcs.emplace(kv.first);
        }
        if (demangled_sym == "__gnu_cxx::__throw_concurrence_lock_error()") {
            m_exit_funcs.emplace(kv.first);
        }
        if (demangled_sym.find("__throw_out_of_range_fmt") != std::string::npos) {
            m_exit_funcs.emplace(kv.first);
        }
        if (demangled_sym.find("std::__throw_length_error") != std::string::npos) {
            m_exit_funcs.emplace(kv.first);
        }

    }
}

int Cfg::process_func_queue() {
    while (!m_func_queue.empty()) {
        Block func_block = m_func_queue.pop();

        m_state->at_func_start(&func_block);

        VLOG(VLOG_CFG) << "Starting function at: 0x" << std::hex << func_block.start;
        if (this->process_block_queue(func_block, func_block.start)) {
            LOG(FATAL) << "Failed to process block: 0x" << std::hex << func_block.start;
        }

        // Exhaust all switches found in this function
        while (!m_state->get_switch_tables()->empty()) {
            this->process_switches();
        }

        m_state->at_func_end();
    }

    return 0;
}

int Cfg::process_block_queue(Block func_block, uint64_t func_addr) {
    if (func_addr) {
        func_block.is_func_head = true;
        func_block.func_addr = func_addr;
    }

    m_block_queue.push(func_block);

    return this->process_block_queue();
}

int Cfg::process_block_queue() {
    while (!m_block_queue.empty()) {
        Block cur_block = m_block_queue.pop();

        m_state->at_block_start(&cur_block);

        if (this->process_block(&cur_block)) {
            continue;
        }

        m_state->at_block_end(&cur_block);

        this->process_fixups(&cur_block);

        auto ret_pair = m_blocks.emplace(make_range(cur_block.start, cur_block.end - 1), cur_block);
        if (!ret_pair.second) {
            LOG(ERROR) << "Failed to emplace new block: 0x" << std::hex << cur_block.start;
            continue;
        }

//        LOG(INFO) << "block bit range: 0x" << std::hex << cur_block.start << " size: 0x" << (cur_block.end - cur_block.start);
        m_bitmap->set_bit_range(cur_block.start, (cur_block.end - cur_block.start), MapFlag::BLOCK);
    }

    return 0;
}

int Cfg::process_block(Block *block) {
    const uint8_t *data_ptr = m_memmap->addr_to_ptr(block->start);
    if (!data_ptr) {
        VLOG(VLOG_CFG) << "Failed to find memory for block: 0x" << std::hex << block->start;
        return 1;
    }

    // Check if we walked into a block that was in the queue at the time of branch checks
    // So we have to ensure it was not already processed here, check for the split then fix up
    // the old block and continue on with this new block.  This is a duplication of work slightly.
    auto start_it = m_blocks.find(make_range(block->start));
    if (start_it != m_blocks.end()) {
        if (start_it->first.first != block->start) {
            bool call_target = block->start == block->func_addr;

            // Skip found blocks that split our existing CFG's blocks
            if (call_target && block->metadata.count(bb_metadata::FOUND_BLOCK)) {
                return 1;
            }

            this->split_block(block->start, &start_it->second, call_target);
            return 1;
            // Continue on processing this block.
        }
        else if (start_it->first.first == block->start) {
            VLOG(VLOG_CFG) << "Attempted to double parse block: 0x" << std::hex << block->start;
            return 1;
        }
    }

    block->data = data_ptr;

    VLOG(VLOG_CFG) << "Processing block: 0x" << std::hex << block->start;

    Branch target;
    std::vector<Branch> guesses;

    uint64_t block_start = block->start;
    uint64_t max_block_size = MAX_BLOCK_SIZE;

    cs_insn *insn;
    insn = cs_malloc(m_cs_handle);

    cs_option(m_cs_handle, CS_OPT_MODE, block->mode);
    cs_option(m_cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    bool got_delay = false;
    while(cs_disasm_iter(m_cs_handle, &data_ptr, &max_block_size, &block_start, insn)) {
        VLOG(VLOG_CFG) << "0x" << std::hex << insn->address << ": " << insn->mnemonic << " " << insn->op_str;

        this->find_guesses(insn, block, &guesses);

        m_state->at_insn(insn, block);
        m_events->run_events(event_type::INSN, m_state, block, insn);

        // If we hit a block we already knew about fall through and mark it a follower.
        uint64_t next_insn_addr = insn->address + insn->size;

        if (m_bitmap->get_bit(next_insn_addr, MapFlag::BLOCK)) {
            break;
        }

        if (got_delay) {
            break;
        }

        if (!this->is_branch(insn)) {
            continue;
        }

        if (m_state->has_delay_slot()) {
            this->find_branch_targets(insn, block, &target);
            got_delay = true;
            continue;
        }

        break;
    }

    // Invalid block, we did not disassemble any instructions.
    if (block->data == data_ptr) {
        cs_free(insn, 1);
        return 1;
    }

    block->end = insn->address + insn->size;

    // Check that this block is not a failure, bail if it is
    if (m_blocks.count(make_range(block->start, block->end - 1))) {
//        LOG(ERROR) << "Invalid block of range: 0x" << std::hex << block->start << " : 0x" << block->end;
        cs_free(insn, 1);
        return 1;
    }

    if (!m_state->has_delay_slot()) {
        this->find_branch_targets(insn, block, &target);
    }

    cs_free(insn, 1);

    this->process_guesses(&guesses, block);

    // Check the Branch's target, determine if a fallthrough should be queued and if the branch target should.

    bool queue_branch = false;
    bool queue_fallthrough = false;

    do {
        switch (target.type) {
        case branch_type::GUESS:
            queue_branch = false;
            queue_fallthrough = false;
            break;
        case branch_type::CONDITIONAL:
            queue_branch = true;
            queue_fallthrough = true;
            break;
        case branch_type::UNCONDITIONAL:
            queue_branch = true;
            queue_fallthrough = false;
            break;
        case branch_type::CALL:
            queue_branch = true;
            queue_fallthrough = true;
            break;
        case branch_type::FALLTHRU:
            LOG(FATAL) << "Fallthrough should never be generated by process_guesses!";
            break;
        };

        if (!target.addr) {
            break;
        }

        if (queue_branch) {
            block->branch_target = target.addr;

            auto it = m_blocks.find(make_range(target.addr));
            if (it != m_blocks.end()) {
                if (it->first.first != target.addr) {
                    bool call_target = target.type == branch_type::CALL;
                    this->split_block(target.addr, &it->second, call_target);
                }
                else {
                    VLOG(VLOG_CFG) << "Skipping duplicate target 0x" << std::hex << target.addr;
                    if (target.type == branch_type::CALL) {
                        it->second.callers.emplace_back(block->start);
                    }
                    else if (target.type == branch_type::CONDITIONAL || target.type == branch_type::UNCONDITIONAL) {
                        it->second.leaders.emplace_back(block->start);
                    }

                    block->followers.emplace_back(target.addr);

                    if (this->is_no_exit_sym(target.addr)) {
                        queue_fallthrough = false;
                    }
                }

                break;
            }

            const Symbol *sym;
            if (m_resolver->resolve_sym(target.addr, &sym) && sym->type == sym_type::IMPORT) {
                VLOG(VLOG_CFG) << "Skipping target: 0x" << std::hex << target.addr << " : " << sym->name;

                m_events->run_events(event_type::SYM_BRANCH, m_state, block, insn, sym);

                if (this->is_no_exit_sym(target.addr)) {
                    VLOG(VLOG_CFG) << "Skipping fallthrough on symbol that does not return";
                    queue_fallthrough = false;
                }

                // Extra checks for special functions
                if (sym->name == "__libc_start_main") {
                    auto main_ptr_res = this->libc_start_main_helper(insn, block);
                    if (main_ptr_res) {
                        VLOG(VLOG_CFG) << "Found main ptr: 0x" << std::hex << *main_ptr_res;
                        auto main_branch = Branch(*main_ptr_res, branch_type::CALL, guess_type::LIBC_START);
                        main_branch.mode = block->mode;
                        this->add_block(main_branch, block);
                    }
                }
                break;
            }

            if(!m_memmap->is_text_sec(target.addr)) {
                VLOG(VLOG_CFG) << "Skipping target 0x" << std::hex << target.addr << " because its not a TEXT section";
                break;
            }

            this->add_block(target, block);
        }
    } while (false);

    do {
        if (queue_fallthrough) {
            uint64_t fallthru_start = block->end;

            auto it = m_blocks.find(make_range(fallthru_start));
            if (it != m_blocks.end()) {
                VLOG(VLOG_CFG) << "Skipping duplicate target 0x" << std::hex << fallthru_start;
                break;
            }

            block->followers.emplace_back(fallthru_start);

            auto fallbranch = Branch(fallthru_start, branch_type::FALLTHRU, guess_type::UNKNOWN);
            fallbranch.mode = block->mode;
            this->add_block(fallbranch, block);
        }
    } while (false);

    return 0;
}

void Cfg::split_block(uint64_t split_addr, Block *cur_block, bool call_target) {
    // Split the block into two new blocks
    VLOG(VLOG_CFG) << "Splitting block: 0x" << std::hex << cur_block->start << " : 0x" << cur_block->end << " at addr: 0x" << std::hex << split_addr;
    CHECK(cur_block) << "Invalid block pointer passed to split_block()";

    Block block_1 = std::move(*cur_block);
    m_blocks.erase(make_range(block_1.start));

    uint64_t original_end = block_1.end;
    std::vector<uint64_t> copy_followers;
    uint64_t orig_btarget = block_1.branch_target;


    if (block_1.followers.size()) {
        copy_followers = block_1.followers;
        block_1.followers.clear();
    }
    // If we are splitting a call target, discard the prior head of the block
    if (!call_target) {
        block_1.end = split_addr;
        block_1.followers.emplace_back(split_addr);

        auto ret_pair = m_blocks.emplace(make_range(block_1.start, block_1.end - 1), block_1);
        if (!ret_pair.second) {
            LOG(ERROR) << "Failed to emplace 1st splitted block: 0x" << std::hex << block_1.start;
        }
    }
    else {
        m_bitmap->clear_bit_range(block_1.start, (split_addr - block_1.start));
    }

    // Make the second block:
    auto block_2 = Block(split_addr);
    block_2.mode = block_1.mode;
    block_2.end = original_end;
    block_2.func_addr = block_1.func_addr; // if call target, this will be swapped in the lambda

    if (call_target) {
        block_2.is_func_head = true;
    }
    else {
        block_2.func_addr = block_1.func_addr;
        block_2.leaders.emplace_back(block_1.start);
    }
    CHECK( (split_addr - block_1.start) > 0 ) << "Invalid block being split, block_1.end less than split addr, end: 0x"
                                                        << std::hex << block_1.end << " split_addr: 0x" << split_addr;

    block_2.data = block_1.data + (split_addr - block_1.start);
    block_2.branch_target = orig_btarget;
    block_2.followers = copy_followers;

    auto block_1_meta = block_1.metadata;
    block_1.metadata.clear();

    for (const auto &meta : block_1_meta) {
        if (meta.second.addr >= split_addr) {
            block_2.metadata.emplace(meta);
        }
        else {
            block_1.metadata.emplace(meta);
        }
    }

    // Fix up the followers, leader addresses
    for (const auto &follower : block_2.followers) {
        auto follow_it = m_blocks.find(make_range(follower));
        if (follow_it == m_blocks.end()) {
            this->add_fixup({follower, block_1.start, block_2.start, fixup_type::LEADER_REPLACE});
            continue;
        }

        follow_it->second.leaders.erase(std::remove(follow_it->second.leaders.begin(), follow_it->second.leaders.end(), block_1.start), follow_it->second.leaders.end());
        follow_it->second.leaders.emplace_back(block_2.start);
    }

    auto ret_pair_2 = m_blocks.emplace(make_range(block_2.start, block_2.end - 1), block_2);
    if (!ret_pair_2.second) {
        LOG(ERROR) << "Failed to emplace 2nd splitted block: 0x" << std::hex << block_2.start;
    }
    else {
        if (call_target) {
            ret_pair_2.first->second.func_addr = block_2.start;
        }
    }

    // Since we are are creating a new function out of a split, we need to mark all
    // the existing blocks in the function as under this new function.
    if (call_target) {
        std::function<void(Block *, uint64_t, uint64_t)> change_func;
        // Use a recusing lambda to quickly mark all the blocks in the function
        change_func = [this, &change_func](Block *block, uint64_t func_addr, uint64_t old_addr)->void {
            if (block->func_addr != old_addr) {
                return;
            }
            block->func_addr = func_addr;
            VLOG(VLOG_CFG) << "Recursive change func_addr: 0x" << std::hex << old_addr << " -> 0x" << func_addr << " block: 0x" << block->start;
            for (const auto &follower : block->followers) {
                auto it = m_blocks.find(make_range(follower));
                if (it != m_blocks.end()) {
                    change_func(&it->second, func_addr, old_addr);
                }
            }
        };

        change_func(&block_2, block_2.start, block_1.func_addr);
    }

    // Fix up any switch tables linked to the split block
    auto switch_tables = m_state->get_switch_tables();
    CHECK(switch_tables) << "Invalid switch tables pointer";

    for (auto &kv : *switch_tables) {
        if (kv.second != block_1.start) {
            continue;
        }
        VLOG(VLOG_CFG) << "Replaced split block switch table entry: 0x" << std::hex << kv.first;
        kv.second = block_2.start;
        break;
    }
}

void Cfg::add_block(Cfg::Branch target, Block *cur_block) {
    Block new_block(target.addr);

    new_block.mode = target.mode;
    if (target.type == branch_type::CALL) {
        VLOG(VLOG_CFG) << "Pushing CALL into func queue: 0x" << std::hex << target.addr;
        new_block.callers.emplace_back(cur_block->start);

        // Check if we already have this new call block in the block queue and remove it.
        // functions should take priority.  TODO: this will break the linkages for the created block.
        if (m_block_queue.in_queue(new_block)) {
            m_block_queue.del_elm(new_block);
            VLOG(VLOG_CFG) << "Call branch 0x" << std::hex << cur_block->start << " already in block queue, deleted from block queue";
        }

        if (!m_func_queue.push(new_block)) {
            VLOG(VLOG_CFG) << "Tried to push duplicate CALL block: 0x" << std::hex << target.addr;
            this->add_fixup({target.addr, cur_block->start, fixup_type::CALLER});
        }
    }
    else if (target.type == branch_type::CONDITIONAL || target.type == branch_type::UNCONDITIONAL) {
        new_block.func_addr = cur_block->func_addr;
        new_block.leaders.emplace_back(cur_block->start);

        if (m_func_queue.in_queue(new_block)) {
            VLOG(VLOG_CFG) << "Unconditional branch 0x" << std::hex << new_block.start << " already in function queue";
            return;
        }

        VLOG(VLOG_CFG) << "Pushing COND/UNCOND branch: 0x" << std::hex << target.addr;
        if (!m_block_queue.push(new_block)) {
            VLOG(VLOG_CFG) << "Tried to push duplicate fallthru block: 0x" << std::hex << new_block.start;
            this->add_fixup({target.addr, cur_block->start, fixup_type::LEADER});
        }

        cur_block->followers.emplace_back(new_block.start);
    }
    else if (target.type == branch_type::FALLTHRU) {
        new_block.func_addr = cur_block->func_addr;
        new_block.leaders.emplace_back(cur_block->start);

        if (m_func_queue.in_queue(new_block)) {
            VLOG(VLOG_CFG) << "Fallthru branch 0x" << std::hex << new_block.start << " already in function queue";
            return;
        }

        VLOG(VLOG_CFG) << "Pushing fallthru: 0x" << std::hex << new_block.start;
        if (!m_block_queue.push(new_block)) {
            VLOG(VLOG_CFG) << "Tried to push duplicate fallthru block: 0x" << std::hex << new_block.start;
            this->add_fixup({new_block.start, cur_block->start, fixup_type::LEADER});
        }
    }
    else {
        LOG(FATAL) << "Invalid Branch type: " << static_cast<int>(target.type);
    }
}

void Cfg::add_fixup(Fixup fixup) {
    auto fix_it = m_fixups.find(fixup.block);
    if (fix_it == m_fixups.end()) {
        m_fixups[fixup.block] = {fixup};
    }
    else {
        fix_it->second.emplace_back(fixup);
    }
}

void Cfg::process_fixups(Block *block) {
    CHECK(block) << "Invalid block passed to process_fixups";
    auto fix_it = m_fixups.find(block->start);
    if (fix_it == m_fixups.end()) {
        return;
    }

    for (const auto &fixup : fix_it->second) {
        switch (fixup.type) {
        case fixup_type::CALLER:
            block->callers.emplace_back(fixup.value);
            VLOG(VLOG_CFG) << "Fixing up caller on block: 0x" << std::hex << block->start << " val: 0x" << fixup.value;
            break;
        case fixup_type::LEADER:
            block->leaders.emplace_back(fixup.value);
            VLOG(VLOG_CFG) << "Fixing up leader on block: 0x" << std::hex << block->start << " val: 0x" << fixup.value;
            break;
        case fixup_type::LEADER_REPLACE:
            std::replace(block->leaders.begin(), block->leaders.end(), fixup.value, fixup.value_2);
            break;
        case fixup_type::FOLLOWER:
            block->followers.emplace_back(fixup.value);
            VLOG(VLOG_CFG) << "Fixing up follower on block: 0x" << std::hex << block->start << " val: 0x" << fixup.value;
            break;
        default:
            LOG(WARNING) << "Unsupported fixup type: " << static_cast<uint32_t>(fixup.type);
            break;
        }

    }

    m_fixups.erase(fix_it);
}

void Cfg::find_guesses(cs_insn *insn, Block *block, std::vector<Branch> *targets) {
    guess_type g_type = guess_type::UNKNOWN;
    uint64_t target = 0;

    switch (m_arch) {
    case cs_arch::CS_ARCH_X86: {
        cs_x86 x86 = insn->detail->x86;

        switch (insn->id) {
        case X86_INS_LEA: {
            if (x86.op_count < 2) {
                LOG(FATAL) << "Invalid x86 LEA at: 0x" << std::hex << insn->address;
            }
            cs_x86_op op1 = x86.operands[1];
            auto op1_res = m_state->get_op_read_addr(insn, op1, block->mode);
            if (!op1_res) {
                break;
            }
            target = *op1_res;
            g_type = guess_type::X86_LEA;
            break;
        }
        case X86_INS_PUSH: {
            if (x86.op_count < 1) {
                LOG(FATAL) << "Invalid x86 PUSH at: 0x" << std::hex << insn->address;
            }
            cs_x86_op op0 = x86.operands[0];
            auto op0_res = m_state->get_op_val(insn, op0, block->mode);
            if (!op0_res) {
                break;
            }
            target = *op0_res;
            g_type = guess_type::X86_PUSH;

            break;
        }
        case X86_INS_MOV: {
            if (x86.op_count < 2) {
                LOG(FATAL) << "Invalid x86 MOV at: 0x" << std::hex << insn->address;
            }
            cs_x86_op op0 = x86.operands[0];
            cs_x86_op op1 = x86.operands[1];
            auto op1_res = m_state->get_op_val(insn, op1, block->mode);
            if (!op1_res) {
                break;
            }
            target = *op1_res;
            g_type = guess_type::X86_MOV;
            break;

        }
        }
        break;
    }
    case cs_arch::CS_ARCH_ARM: {
        cs_arm arm = insn->detail->arm;
        switch (insn->id) {
        case ARM_INS_LDR: {
            if (arm.op_count < 2) {
                LOG(FATAL) << "Invalid arm LDR instruction at: 0x" << std::hex << insn->address;
            }
            cs_arm_op op0 = arm.operands[0];
            cs_arm_op op1 = arm.operands[1];

            auto op1_res = m_state->get_op_val(insn, op1, block->mode);
            if (!op1_res) {
                break;
            }
            int32_t op1_val = *op1_res;

            // Check for relative loads and write off those to the bitmap.
            if (op1.type == ARM_OP_MEM && op1.mem.base == ARM_REG_PC) {
                uint32_t read_addr = m_state->get_arm_pc_val(insn, op1, block->mode);

                if (read_addr) {
                    if (block->mode == cs_mode::CS_MODE_THUMB && read_addr % 2 != 0) {
                        // Possible thumb function address, skip it.
                    }
                    else {
                        m_bitmap->set_bit_range(read_addr, 4, MapFlag::READ);
                    }
                }
            }

            if (op1_val > 0 && !m_state->is_op_stack_based(op1)) {
                target = op1_val;
                g_type = guess_type::ARM_LDR;
            }

            break;
        }
        }
        break;
    }
    case cs_arch::CS_ARCH_ARM64: {
        cs_arm64 arm = insn->detail->arm64;

        switch (insn->id) {
        case ARM64_INS_LDR: {
            if (arm.op_count < 2) {
                LOG(FATAL) << "Invalid arm64 LDR at: 0x" << std::hex << insn->address;
            }
            cs_arm64_op op0 = arm.operands[0];
            cs_arm64_op op1 = arm.operands[1];

            auto op1_res = m_state->get_op_val(insn, op1);
            if (!op1_res) {
                break;
            }

            if (*op1_res > 0 && !m_state->is_op_stack_based(op1)) {
                target = *op1_res;
                g_type = guess_type::ARM_LDR;
            }

        }
        }
        break;
    }
    case cs_arch::CS_ARCH_MIPS: {
        cs_mips mips = insn->detail->mips;

        switch (insn->id) {
        case MIPS_INS_LW: {
            if (mips.op_count < 2) {
                LOG(FATAL) << "Invalid op count for MIPS lw instruction at: 0x" << std::hex << insn->address;
            }
            cs_mips_op op0 = mips.operands[0];
            cs_mips_op op1 = mips.operands[1];
            auto op1_res = m_state->get_op_val(insn, op1, block);
            if (!op1_res) {
                break;
            }

            if (*op1_res) {
                target = *op1_res;
                g_type = guess_type::MIPS_LW;
            }

            break;
        }
        }
        break;
    }
    case cs_arch::CS_ARCH_PPC: {
        // TODO: PPC guesses
        break;
    }
    default:
        LOG(FATAL) << "Invalid CPU arch: " << m_arch;
        break;
    }

    if (target && g_type != guess_type::UNKNOWN) {
        VLOG(VLOG_REG) << "--target: 0x" << std::hex << target;
        targets->emplace_back(target, branch_type::GUESS, g_type);
    }
}

int Cfg::process_guesses(std::vector<Cfg::Branch> *guesses, Block *block) {
    // Check each found addr in the block body for being a possible function entry and push it.
    for (Branch &guess : *guesses) {
        // Check if the current block is the ep func, and we are ELF
        // Because most elf binaries start by calling a libc start function with the main as a arg
        // either LEA'd or MOV'd into a register in the block.

        bool allow_guess = false;

        if (guess.g_type == guess_type::X86_PUSH) {
            if (block->mode == cs_mode::CS_MODE_32) {
                allow_guess = true;
            }
        }

        if (m_obj->isELF()) {
            if (m_ep == block->func_addr) {
                switch (guess.g_type) {
                case guess_type::X86_MOV:
                case guess_type::X86_LEA:
                case guess_type::ARM_LDR:
                case guess_type::MIPS_LW:
                    allow_guess = true;
                    break;
                default:
                    break;
                }
            }
        }

        else if (m_obj->isCOFF() || m_obj->isMachO()) {
            switch (guess.g_type) {
            case guess_type::X86_PUSH:
                allow_guess = true;
                break;
            default:
                break;
            }
        }

        guess.mode = block->mode;
        // Fix up guess block addresses
        if (m_arch == cs_arch::CS_ARCH_ARM) {
            if (guess.addr % 2 != 0) {
                guess.addr -= 1;
                guess.mode = cs_mode::CS_MODE_THUMB;
            }
        }

        // Skip this guess
        if (!allow_guess) {
            continue;
        }

        // Avoid splitting our own block
        if (guess.addr >= block->start && guess.addr < block->end) {
            continue;
        }

        // Now that we found a valid guess, try and queue it.
        auto it = m_blocks.find(make_range(guess.addr));
        if (it != m_blocks.end()) {
            VLOG(VLOG_CFG) << "Skipping duplicate GUESS 0x" << std::hex << guess.addr;
            continue;
        }

        if(!m_memmap->is_text_sec(guess.addr)) {
            VLOG(VLOG_CFG) << "Skipping GUESS 0x" << std::hex << guess.addr << " because its not a TEXT section";
            continue;
        }

        const Symbol *sym;
        if (m_resolver->resolve_sym(guess.addr, &sym) && sym->type == sym_type::IMPORT) {
            VLOG(VLOG_CFG) << "Skipping GUESS: 0x" << std::hex << guess.addr << " : " << sym->name;
            continue;
        }

        if (block->metadata.count(bb_metadata::SWITCH_INDIRECT)) {
            auto lea_meta = block->metadata.find(bb_metadata::LOAD);
            if (lea_meta != block->metadata.end()) {
                if (lea_meta->second.value == guess.addr) {
                    VLOG(VLOG_CFG) << "Skipping GUESS: 0x" << std::hex << guess.addr << " because it is a switch vtable load";
                    continue;
                }
            }
        }

        VLOG(VLOG_CFG) << "Pushing GUESS into func queue: 0x" << std::hex << guess.addr;
        Block guess_block(guess.addr);
        guess_block.mode = guess.mode;

        if (!m_func_queue.push(guess_block)) {
            VLOG(VLOG_CFG) << "Tried to push duplicate GUESS block: 0x" << std::hex << guess.addr;
        }
    }

    return 0;
}

int Cfg::find_branch_targets(cs_insn *insn, Block *block, Branch *b_target) {
    cs_detail *detail = insn->detail;

    branch_type b_type = branch_type::UNCONDITIONAL;
    bool find_op = false;
    uint8_t op_idx = 0;
    uint64_t target = 0;

    cs_mode new_mode;
    bool switch_mode = false;

    if (m_arch == cs_arch::CS_ARCH_X86) {
        cs_x86 x86 = insn->detail->x86;

        new_mode = block->mode;

        switch (insn->id) {
        case X86_INS_CALL:
            b_type = branch_type::CALL;
            find_op = true;
            op_idx = 0;
            break;
        case X86_INS_SYSENTER:
        case X86_INS_SYSCALL:
        case X86_INS_INT:
            b_type = branch_type::CALL;
            break;
        case X86_INS_LOOP:
        case X86_INS_LOOPE:
        case X86_INS_LOOPNE:
            find_op = true;
            op_idx = 0;
            b_type = branch_type::CONDITIONAL;
        }

        if (!find_op) {
            for (uint8_t i = 0; i < detail->groups_count; i++) {
                uint8_t grp = detail->groups[i];
                if (grp == X86_GRP_JUMP) {
                    // Mark static jumps as targets.
                    // All dependent jumps should be fallthroughs
                    if (insn->id == X86_INS_JMP) {
                        b_type = branch_type::UNCONDITIONAL;
                    }
                    else {
                        b_type = branch_type::CONDITIONAL;
                    }
                    find_op = true;

                    break;
                }
            }
        }

        if (find_op) {
            if (op_idx >= x86.op_count) {
                LOG(FATAL) << "BAD instruction hit at: 0x" << std::hex << insn->address;
            }

            CfgRes<uint64_t> oper_res;

            do {
                cs_x86_op op = x86.operands[op_idx];
                // Special case for x86 because we need to symbolize the call target address, not the value
                if ( (insn->id == X86_INS_CALL || insn->id == X86_INS_JMP) && op.type == X86_OP_MEM) {
                    oper_res = m_state->get_op_read_addr(insn, op, new_mode);
                    break;
                }

                oper_res = m_state->get_op_val(insn, x86.operands[op_idx], new_mode);
                break;
            } while(false);

            if (oper_res) {
                target = *oper_res;
            }
        }

    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        cs_arm arm = insn->detail->arm;

        bool check_cc = false;

        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];
            if (grp == ARM_GRP_JUMP) {
                check_cc = true;
                find_op = true;
                op_idx = 0;
                break;
            }
        }

        switch (insn->id) {
        case ARM_INS_POP:
            if (is_pc_in_arm_ops(arm)) {
                check_cc = true;
            }
            break;
        case ARM_INS_TBH:
        case ARM_INS_TBB:
            // ignore switch table instructions.
            find_op = false;
            break;

        case ARM_INS_BX:
        case ARM_INS_BLX:
            // Check if we are on a switch branch and ignore the op.
            if (arm.op_count < 1) {
                LOG(FATAL) << "Invalid arm branch instruction at: 0x" << std::hex << insn->address;
            }
            if (arm.operands[0].type == ARM_OP_REG) {
                if (block->metadata.count(bb_metadata::SWITCH_INDIRECT)) {
                    find_op = false;
                }
            }
            switch_mode = true;
            break;
        case ARM_INS_ADD:
            // WARN: Special case bypass here, because we cannot directly query the PC register we calculate the
            // target value and then disable find_op to fall though.
            if (arm.op_count == 3 && arm.operands[0].type == ARM_OP_REG && arm.operands[0].reg == ARM_REG_PC) {
                find_op = false;
                b_type = branch_type::UNCONDITIONAL;

                auto op1_res = m_state->get_op_val(insn, arm.operands[1], block->mode);
                auto op2_res = m_state->get_op_val(insn, arm.operands[2], block->mode);
                if (op1_res && op2_res) {
                    target = *op1_res + *op2_res;
                }
            }
            break;
        }

        if (check_cc) {
            if (arm.cc == ARM_CC_AL || arm.cc == ARM_CC_INVALID) {
                if (insn->id == ARM_INS_BL) {
                    b_type = branch_type::CALL;
                }
                else if (insn->id == ARM_INS_BLX) {
                    b_type = branch_type::CALL;
                }
                else if (insn->id == ARM_INS_CBZ || insn->id == ARM_INS_CBNZ) {
                    b_type = branch_type::CONDITIONAL;
                    op_idx = 1;
                }
                else {
                    b_type = branch_type::UNCONDITIONAL;
                }
            }
            else {
                b_type = branch_type::CONDITIONAL;
            }
        }

        if (find_op) {
            if (op_idx >= arm.op_count) {
                LOG(FATAL) << "BAD instruction hit at: 0x" << std::hex << insn->address;
            }
            auto oper_res = m_state->get_op_val(insn, arm.operands[op_idx], block->mode);
            if (oper_res) {
                target = *oper_res;
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        cs_arm64 arm = insn->detail->arm64;

        bool check_cc = false;

        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];
            if (grp == ARM64_GRP_JUMP) {
                check_cc = true;
                find_op = true;
                op_idx = 0;
                break;
            }
        }

        switch (insn->id) {
        case ARM64_INS_BL:
        case ARM64_INS_BLR:
            check_cc = true;
            find_op = true;
            op_idx = 0;
            break;
        case ARM64_INS_SVC:
            b_type = branch_type::CALL;
            break;
        default:
            break;
        }

        if (check_cc) {
            if (arm.cc == ARM64_CC_AL || arm.cc == ARM64_CC_INVALID) {
                switch (insn->id) {
                case ARM64_INS_BL:
                case ARM64_INS_BLR:
                    b_type = branch_type::CALL;
                    break;
                case ARM64_INS_CBZ:
                case ARM64_INS_CBNZ:
                    b_type = branch_type::CONDITIONAL;
                    op_idx = 1;
                    break;
                case ARM64_INS_TBZ:
                case ARM64_INS_TBNZ:
                    b_type = branch_type::CONDITIONAL;
                    op_idx = 2;
                    break;
                case ARM64_INS_B:
                    // Check if this looks like a linking branch
                    if (block->metadata.count(bb_metadata::SAVE_LINK_REG)) {
                        b_type = branch_type::CALL;
                    }
                    break;
                default:
                    b_type = branch_type::UNCONDITIONAL;
                }
            }
            else {
                b_type = branch_type::CONDITIONAL;
            }
        }

        if (find_op) {
            if (op_idx >= arm.op_count) {
                LOG(FATAL) << "BAD instruction hit at: 0x" << std::hex << insn->address;
            }

            auto oper_res = m_state->get_op_val(insn, arm.operands[op_idx]);
            if (oper_res) {
                target = *oper_res;
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS) {
        cs_mips mips = insn->detail->mips;

        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];
            if (grp == MIPS_GRP_JUMP) {
                find_op = true;
                op_idx = 0;
                break;
            }
        }

        switch (insn->id) {
        case MIPS_INS_BAL:
        case MIPS_INS_JAL:
        case MIPS_INS_JALR:
            b_type = branch_type::CALL;
            op_idx = 0;
            find_op = true;
            break;
        case MIPS_INS_BLTZAL:
        case MIPS_INS_BGEZAL:
            b_type = branch_type::CALL;
            op_idx = 1;
            find_op = true;
            break;
        case MIPS_INS_SYSCALL:
            b_type = branch_type::CALL;
            find_op = false;
            break;
        case MIPS_INS_B:
        case MIPS_INS_J:
        case MIPS_INS_JR:
            b_type = branch_type::UNCONDITIONAL;
            op_idx = 0;
            find_op = true;
            break;
        case MIPS_INS_BC1F:
        case MIPS_INS_BC1T:
            b_type = branch_type::CONDITIONAL;
            op_idx = 0;
            find_op = true;
            break;
        case MIPS_INS_BEQZ:
        case MIPS_INS_BGEZ:
        case MIPS_INS_BGTZ:
        case MIPS_INS_BLEZ:
        case MIPS_INS_BLTZ:
        case MIPS_INS_BNEZ:
            b_type = branch_type::CONDITIONAL;
            op_idx = 1;
            find_op = true;
            break;
        case MIPS_INS_BEQ:
        case MIPS_INS_BNE:
            b_type = branch_type::CONDITIONAL;
            op_idx = 2;
            find_op = true;
            break;
        }

        if (find_op) {
            if (op_idx >= mips.op_count) {
                LOG(FATAL) << "BAD instruction hit at: 0x" << std::hex << insn->address;
            }
            auto oper_res = m_state->get_op_val(insn, mips.operands[op_idx], block);
            if (oper_res) {
                target = *oper_res;
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_PPC) {
        cs_ppc ppc = insn->detail->ppc;

        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];
            if (grp == PPC_GRP_JUMP) {
                find_op = true;
                op_idx = 0;
                break;
            }
        }

        switch (insn->id) {
        // Conditional / unsupported / B(uncond)
        case PPC_INS_B:
            // Special case for BEQ because capstone does not have BEQ instructions
            if (ppc.bc != ppc_bc::PPC_BC_INVALID) {
                b_type = branch_type::CONDITIONAL;
                if (ppc.op_count > 1) {
                    op_idx = 1;
                } else {
                    op_idx = 0;
                }
                find_op = true;
            }
            else {
                b_type = branch_type::UNCONDITIONAL;
                op_idx = 0;
                find_op = true;
            }
            break;

        // Linking branches (calls)
        case PPC_INS_BL:
        case PPC_INS_BLA:
            b_type = branch_type::CALL;
            op_idx = 0;
            find_op = true;
            break;

        case PPC_INS_BLR:
            if (ppc.bc != ppc_bc::PPC_BC_INVALID) {
                b_type = branch_type::CONDITIONAL;
                find_op = false;
            }
            break;

        case PPC_INS_BCL:
        case PPC_INS_BCLA:
        case PPC_INS_BCLR:
        case PPC_INS_BCLRL:
            b_type = branch_type::CALL;
            op_idx = 2;
            find_op = true;
            break;

        // Conditional jumps
        case PPC_INS_BC:
            b_type = branch_type::CONDITIONAL;
            op_idx = 2;
            find_op = true;
            break;

        case PPC_INS_BDZ:
        case PPC_INS_BDZA:
        case PPC_INS_BDZL:
        case PPC_INS_BDZLA:
        case PPC_INS_BDNZ:
        case PPC_INS_BDNZA:
        case PPC_INS_BDNZL:
        case PPC_INS_BDNZLA:
            b_type = branch_type::CONDITIONAL;
            op_idx = 0;
            find_op = true;
            break;


        // Conditional, no operand jumps
        case PPC_INS_BDZLR:
        case PPC_INS_BDZLRL:
        case PPC_INS_BDNZLR:
        case PPC_INS_BDNZLRL:
            b_type = branch_type::CONDITIONAL;
            find_op = false;
            break;

        // Special case indirect branches
        // TODO: Look up the CTR register for a possible indirect target
        case PPC_INS_BCCTR:
            b_type = branch_type::CONDITIONAL;
            find_op = false;
            break;
        case PPC_INS_BCTR:
            b_type = branch_type::UNCONDITIONAL;
            find_op = false;
            break;
        case PPC_INS_BCTRL:
            b_type = branch_type::CALL;
            find_op = false;
            break;
        }

        if (find_op) {
            CHECK(op_idx < ppc.op_count) << "BAD instruction hit at: 0x" << std::hex << insn->address;

            auto oper_res = m_state->get_op_val(insn, ppc.operands[op_idx], block);
            if (oper_res) {
                target = *oper_res;
            }

            // Skip branch forward by 1 instruction
            if (target == insn->address + 4) {
                target = 0x0;
            }
        }
    }
    else {
        LOG(FATAL) << "Unsupported arch: " << m_arch;
    }

    if (!target) {
        b_target->addr = 0;
    }

    // Prevent splitting our own block.
    if (target >= block->start && target < block->end) {
        b_target->addr = 0;
    }

    // Block targets that are the current block.
    else if (target == block->start) {
        b_target->addr = 0;
    }
    else {
        b_target->addr = target;
    }

    b_target->type = b_type;
    b_target->mode = block->mode;

    if (switch_mode) {
        VLOG(VLOG_CFG) << "trying to switch modes, addr: 0x" << std::hex << b_target->addr;
        if (block->mode == cs_mode::CS_MODE_ARM) {
            if (b_target->addr % 2 != 0) {
                b_target->addr -= 1;
            }
            b_target->mode = cs_mode::CS_MODE_THUMB;
        }
        else if (block->mode == cs_mode::CS_MODE_THUMB) {
            if (b_target->addr % 2 != 0) {
                b_target->addr -= 1;
                b_target->mode = cs_mode::CS_MODE_THUMB;
            }
            else {
                b_target->mode = cs_mode::CS_MODE_ARM;
            }
        }
    }

    return 0;
}

bool Cfg::is_branch(cs_insn *insn) const {
    cs_detail *detail = insn->detail;
    if (m_arch == cs_arch::CS_ARCH_X86) {
        if (detail->groups_count > 0) {
            for (uint8_t i = 0; i < detail->groups_count; i++) {
                uint8_t grp = detail->groups[i];

                switch (grp) {
                case X86_GRP_JUMP:
                case X86_GRP_INT:
                case X86_GRP_IRET:
                case X86_GRP_RET:
                case X86_GRP_BRANCH_RELATIVE:
                    return true;

                default:
                    continue;
                }
            }
        }

        switch (insn->id) {
        case X86_INS_CALL:
        case X86_INS_HLT:
        case X86_INS_SYSENTER:
        case X86_INS_SYSCALL:
        case X86_INS_LOOP:
        case X86_INS_LOOPE:
        case X86_INS_LOOPNE:
        case X86_INS_UD2:
            return true;
        default:
            break;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        if (detail->groups_count > 0) {
            for (uint8_t i = 0; i < detail->groups_count; i++) {
                uint8_t grp = detail->groups[i];

                switch (grp) {
                case ARM_GRP_JUMP:
                case ARM_GRP_CALL:
                case ARM_GRP_INT:
                case ARM_GRP_BRANCH_RELATIVE:
                    return true;
                default:
                    continue;
                }
            }
        }

        cs_arm arm = insn->detail->arm;

        switch (insn->id) {
        case ARM_INS_SVC:
            return true;
        case ARM_INS_LDMDB:
        case ARM_INS_POP:
        case ARM_INS_LDM:
            return is_pc_in_arm_ops(arm);
        case ARM_INS_LDR:
        case ARM_INS_MOV:
            if (arm.op_count > 0) {
                if (arm.operands[0].reg == ARM_REG_PC) {
                    return true;
                }
            }
            break;
        case ARM_INS_ADD:
            if (arm.op_count == 3) {
                if (arm.operands[0].type == ARM_OP_REG && arm.operands[0].reg == ARM_REG_PC) {
                    return true;
                }
            }
            break;
        default:
            break;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        if (detail->groups_count > 0) {
            for (uint8_t i = 0; i < detail->groups_count; i++) {
                uint8_t grp = detail->groups[i];

                switch (grp) {
                case ARM64_GRP_JUMP:
                case ARM64_GRP_CALL:
                case ARM64_GRP_INT:
                case ARM64_GRP_BRANCH_RELATIVE:
                    return true;
                default:
                    continue;
                }
            }
        }

        switch (insn->id) {
        case ARM64_INS_BLR:
        case ARM64_INS_BL:
        case ARM64_INS_SVC:
        case ARM64_INS_RET:
            return true;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS) {
        if (detail->groups_count > 0) {
            for (uint8_t i = 0; i < detail->groups_count; i++) {
                uint8_t grp = detail->groups[i];

                switch (grp) {
                case MIPS_GRP_JUMP:
                case MIPS_GRP_CALL:
                case MIPS_GRP_INT:
                case MIPS_GRP_BRANCH_RELATIVE:
                    return true;
                default:
                    continue;
                }
            }
        }

        switch (insn->id) {
        case MIPS_INS_JALR:
        case MIPS_INS_JAL:
        case MIPS_INS_J:
        case MIPS_INS_B:
        case MIPS_INS_BAL:
        case MIPS_INS_SYSCALL:
            return true;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_PPC) {
        if (detail->groups_count > 0) {
            for (uint8_t i = 0; i < detail->groups_count; i++) {
                uint8_t grp = detail->groups[i];

                switch (grp) {
                case PPC_GRP_JUMP:
                    return true;
                default:
                    continue;
                }
            }
        }

        switch (insn->id) {
        case PPC_INS_SC:
        case PPC_INS_B:
        case PPC_INS_BA:
        case PPC_INS_BC:
        case PPC_INS_BCCTR:
        case PPC_INS_BCCTRL:
        case PPC_INS_BCL:
        case PPC_INS_BCLR:
        case PPC_INS_BCLRL:
        case PPC_INS_BCTR:
        case PPC_INS_BCTRL:
        case PPC_INS_BCT:
        case PPC_INS_BDNZ:
        case PPC_INS_BDNZA:
        case PPC_INS_BDNZL:
        case PPC_INS_BDNZLA:
        case PPC_INS_BDNZLR:
        case PPC_INS_BDNZLRL:
        case PPC_INS_BDZ:
        case PPC_INS_BDZA:
        case PPC_INS_BDZL:
        case PPC_INS_BDZLA:
        case PPC_INS_BDZLR:
        case PPC_INS_BDZLRL:
        case PPC_INS_BL:
        case PPC_INS_BLA:
        case PPC_INS_BLR:
        case PPC_INS_BLRL:
        case PPC_INS_BRINC:
        case PPC_INS_BCA:
        case PPC_INS_BCLA:
        case PPC_INS_BTA:
        case PPC_INS_BT:
        case PPC_INS_BF:
        case PPC_INS_BDNZT:
        case PPC_INS_BDNZF:
        case PPC_INS_BDZF:
        case PPC_INS_BDZT:
        case PPC_INS_BFA:
        case PPC_INS_BDNZTA:
        case PPC_INS_BDNZFA:
        case PPC_INS_BDZTA:
        case PPC_INS_BDZFA:
        case PPC_INS_BTCTR:
        case PPC_INS_BFCTR:
        case PPC_INS_BTCTRL:
        case PPC_INS_BFCTRL:
        case PPC_INS_BTL:
        case PPC_INS_BFL:
        case PPC_INS_BDNZTL:
        case PPC_INS_BDNZFL:
        case PPC_INS_BDZTL:
        case PPC_INS_BDZFL:
        case PPC_INS_BTLA:
        case PPC_INS_BFLA:
        case PPC_INS_BDNZTLA:
        case PPC_INS_BDNZFLA:
        case PPC_INS_BDZTLA:
        case PPC_INS_BDZFLA:
        case PPC_INS_BTLR:
        case PPC_INS_BFLR:
        case PPC_INS_BDNZTLR:
        case PPC_INS_BDZTLR:
        case PPC_INS_BDZFLR:
        case PPC_INS_BTLRL:
        case PPC_INS_BFLRL:
        case PPC_INS_BDNZTLRL:
        case PPC_INS_BDNZFLRL:
        case PPC_INS_BDZTLRL:
        case PPC_INS_BDZFLRL:
        // case PPC_INS_TWLT:
        // case PPC_INS_TWEQ:
        // case PPC_INS_TWGT:
        // case PPC_INS_TWNE:
        // case PPC_INS_TWLLT:
        // case PPC_INS_TWLGT:
        // case PPC_INS_TWLTI:
        // case PPC_INS_TWEQI:
        // case PPC_INS_TWGTI:
        // case PPC_INS_TWNEI:
        // case PPC_INS_TWLLTI:
        // case PPC_INS_TWLGTI:
        // case PPC_INS_TDLT:
        // case PPC_INS_TDEQ:
        // case PPC_INS_TDGT:
        // case PPC_INS_TDNE:
        // case PPC_INS_TDLLT:
        // case PPC_INS_TDLGT:
        // case PPC_INS_TDLTI:
        // case PPC_INS_TDEQI:
        // case PPC_INS_TDGTI:
        // case PPC_INS_TDNEI:
        // case PPC_INS_TDLLTI:
        // case PPC_INS_TDLGTI:
            return true;
        }

        cs_ppc ppc = insn->detail->ppc;

        if (ppc.bc != ppc_bc::PPC_BC_INVALID) {
            LOG(WARNING) << "Hit a weird instruction with branch code that fell through, at: 0x" << std::hex << insn->address;
            return true;
        }
    }
    else {
        LOG(FATAL) << "Unsupported arch: " << m_arch;
    }

    return false;
}

bool Cfg::is_no_exit_sym(uint64_t sym_addr) const {
    if (m_exit_funcs.find(sym_addr) != m_exit_funcs.end()) {
        return true;
    }

    return false;
}

uint64_t Cfg::get_switch_bound(Block *cur_block, uint64_t switch_addr) {
    uint64_t bound = 0;

    if (!cur_block->leaders.size()) {
        LOG(ERROR) << "No leader blocks on switch table, failed to get switch bound";
        return bound;
    }
    for (const auto &leader_addr : cur_block->leaders) {
        auto leader_block = m_blocks.find(make_range(leader_addr));
        if (leader_block == m_blocks.end()) {
            LOG(FATAL) << "Invalid leader address 0x" << std::hex << leader_addr << " on block: 0x" << cur_block->start;
        }

        auto cmp_meta = leader_block->second.metadata.find(bb_metadata::CMP_LENGTH);
        if (cmp_meta == leader_block->second.metadata.end()) {
            continue;
        }
        if (!cmp_meta->second.value) {
            continue;
        }

        bound = cmp_meta->second.value;
        VLOG(VLOG_CFG) << "vtable bound val: 0x" << std::hex << bound;

        return bound;
    }

    if (!bound && m_arch == cs_arch::CS_ARCH_X86) {
        // Check for an and offset
        auto and_meta = cur_block->metadata.find(bb_metadata::AND_OFFSET);
        if (and_meta != cur_block->metadata.end()) {
            return and_meta->second.value;
        }
    }

    if (!bound && m_arch == cs_arch::CS_ARCH_ARM) {
        auto cmp_meta = cur_block->metadata.find(bb_metadata::CMP_LENGTH);
        if (cmp_meta != cur_block->metadata.end()) {
            return cmp_meta->second.value;
        }

        return bound;
    }
    else if (!bound && m_arch == cs_arch::CS_ARCH_MIPS) {
        do {
            // With mips we can walk up two blocks to try and find our CMP meta tag.
            if (!cur_block->leaders.size()) {
                break;
            }

            auto leader_addr = cur_block->leaders.at(0);
            auto leader_block = m_blocks.find(make_range(leader_addr));
            if (leader_block == m_blocks.end()) {
                break;
            }

            if (!leader_block->second.leaders.size()) {
                break;
            }
            auto next_leader_addr = leader_block->second.leaders.at(0);
            auto next_leader_block = m_blocks.find(make_range(next_leader_addr));
            if (next_leader_block == m_blocks.end()) {
                break;
            }

            auto cmp_meta = next_leader_block->second.metadata.find(bb_metadata::CMP_LENGTH);
            if (cmp_meta == next_leader_block->second.metadata.end()) {
                return bound;
            }
            return cmp_meta->second.value;

        }
        while (false);
    }
    else {
        LOG(WARNING) << "Failed to find backup architecture boundary for arch: " << static_cast<uint32_t>(m_arch);
    }

    return bound;
}

template<typename ENTRY, typename VAL>
VAL Cfg::read_switch_entry(const ENTRY *entry, uint32_t idx, bool thumb_multi, uint8_t shift_val) {
    ENTRY val = entry[idx];

    if (m_state->is_big_endian()) {
        if (sizeof(ENTRY) == 4) {
            val = __builtin_bswap32(val);
        }
        else if (sizeof(ENTRY) == 8) {
            val = __builtin_bswap64(val);
        }
    }

    VAL read_val = 0;

    if (thumb_multi) {
        // Spec defines a *2 of any value in the table
        read_val = val * 2;
    }
    else if (shift_val) {
        read_val = val << shift_val;
    }
    else {
        read_val = val;
    }

    return read_val;
}

template<typename ENTRY, typename VAL>
int Cfg::get_switch_table(uint64_t table_addr, Block *parent_block) {
    uint64_t cur_addr = table_addr;

    VLOG(VLOG_SWT) << "Inspecting switch table: 0x" << std::hex << table_addr << " linked to block: 0x" << parent_block->start;

    auto entry = reinterpret_cast<const ENTRY *>(m_memmap->addr_to_ptr(table_addr));
    if (!entry) {
        LOG(WARNING) << "Failed to find switch addr: 0x" << std::hex << table_addr;
        return 1;
    }

    const MemPage *table_page = m_memmap->addr_to_page(table_addr);
    CHECK(table_page) << "Failed to find table page: 0x" << std::hex << table_addr;


    // Only track unique entries in the table.
    uint32_t idx = 0;

    uint64_t base_addr = table_addr;

    // TODO: This needs to be much more modular
    //  In the future I would like to rip out this switch parser system and replace it with
    //  something that can be built ontop of the extracted metadata
    uint8_t shift_left = 0;
    bool thumb_mult = false;

    // Check if we need to perform a shift inline.
    if (m_arch == cs_arch::CS_ARCH_ARM64) {
        auto add_meta = parent_block->metadata.find(bb_metadata::ADD_OFFSET);
        if (add_meta == parent_block->metadata.end()) {
            LOG(FATAL) << "Missing ADD_OFFSET in AARCH64 switch metadata";
        }

        // in aarch64 tables:
        //  case block_addr = (addr_of_first_physical_case + (vtable_val << shift_val))

        shift_left = add_meta->second.scale;
        base_addr = add_meta->second.value;
    }
    else if (m_arch == cs_arch::CS_ARCH_X86) {
        if (parent_block->mode == cs_mode::CS_MODE_32) {
            base_addr = 0x0;
        }
        else {
            if (parent_block->metadata.count(bb_metadata::MOV_OFFSET)) {
                auto load_meta = parent_block->metadata.find(bb_metadata::LOAD);
                if (load_meta == parent_block->metadata.end()) {
                    LOG(FATAL) << "Failed to find vtable load value";
                }
                base_addr = load_meta->second.value;
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        if (parent_block->mode == cs_mode::CS_MODE_ARM) {
            base_addr = 0;
        }
        else if (parent_block->mode == cs_mode::CS_MODE_THUMB) {
            if (parent_block->metadata.count(bb_metadata::SWITCH_INDIRECT)) {
                thumb_mult = false;
            }
            else {
                // offsets are PC relative to the TBB/TBH insn, so block->end.
                base_addr = parent_block->end;
                thumb_mult = true;
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS) {
        base_addr = 0;
    }

    std::set<VAL, std::greater<VAL>> table;

    uint64_t table_bound = this->get_switch_bound(parent_block, table_addr);

    if (!table_bound) {
        LOG(WARNING) << "Failed to get switch table bound for block: 0x" << std::hex << parent_block->start;
        return 1;
    }

    VLOG(VLOG_SWT) << "Discovered switch table size: 0x" << std::hex << table_bound;

    while (true) {
        auto read_val = this->read_switch_entry<ENTRY, VAL>(entry, idx, thumb_mult, shift_left);

        auto cur_ptr = reinterpret_cast<const uint8_t *>(&entry[idx]);

        cs_insn *insn;
        uint32_t count = 0;

        count = cs_disasm(m_cs_handle, cur_ptr, 0, cur_addr, 1, &insn);
        if (count) {
            // Break if we walk into a NOP instruction
            if (is_nop(m_arch, insn)) {
                cs_free(insn, count);
                break;
            }
        }
        cs_free(insn, count);

        VLOG(VLOG_SWT) << "addr: 0x" << std::hex << cur_addr << " vtable value: " << read_val;
        table.insert(read_val);

        idx++;
        cur_addr += sizeof(ENTRY);
        auto next_val = this->read_switch_entry<ENTRY, VAL>(entry, idx, thumb_mult, shift_left);


        // Stop if we hit an explicit end, found via inspecting leader blocks
        if (table_bound && idx > table_bound) {
            break;
        }

        // Stop if we hit a block:
        if (m_blocks.count(make_range(cur_addr))) {
            break;
        }

        // Stop if we walk into another vtable addr
        if (m_state->get_switch_tables()->count(cur_addr)) {
            break;
        }

        // Stop if we walk off the current page
        if (cur_addr >= (table_page->address + table_page->size)) {
            break;
        }
        // stop if the next value is a windows padding
        if (sizeof(next_val == 4)) {
            if (next_val == 0xcccccccc) {
                break;
            }
        }
        // On ARM64 we base off the first case in memory so 0x0 is allowed.
        if (m_arch != cs_arch::CS_ARCH_ARM64) {
            // Stop if its just pointing back to the vtable itself
            if (next_val == 0x0) {
                break;
            }
        }
        // Simple check to see if we walked out of a table of negative offsets
        if (!table_bound) {
            if (read_val < 0) {
                if (next_val > 0) {
                    break;
                }
            }
            // Invert the previous if statement
            else {
                if (next_val < 0) {
                    break;
                }
            }
        }

        if (!m_memmap->is_text_sec(next_val + base_addr)) {
            break;
        }

        // Use this as a fall back if we don't have table bound
        if (!table_bound) {
            // Check everything that is not SCAN
            // LOG(INFO) << "Next addr: 0x" << std::hex << next_val + base_addr;
            if (m_bitmap->get_bit(next_val + base_addr, (MapFlag::SCAN ^ MapFlag::ANY))) {
                break;
            }
        }
    }

    uint64_t table_size = sizeof(entry[idx]) * idx;

    // VLOG(VLOG_CFG) << "vtable bit range: 0x" << std::hex << switch_addr << " size: 0x" << table_size;
    m_bitmap->set_bit_range(table_addr, table_size, MapFlag::SWITCH);

    for (const auto &offset : table) {
        uint64_t block_addr = offset + base_addr;

        if(!m_memmap->is_text_sec(block_addr)) {
            continue;
        }

        cs_mode new_mode = parent_block->mode;
        if (m_arch == cs_arch::CS_ARCH_ARM && new_mode == cs_mode::CS_MODE_THUMB) {
            if (block_addr % 2 != 0) {
                block_addr -= 1;
            }
        }

        auto check_addr_it = m_blocks.find(make_range(block_addr));
        if (check_addr_it != m_blocks.end()) {
            if (check_addr_it->first.first != block_addr) {
                LOG(WARNING) << "Switch block: 0x" << std::hex << block_addr << " splits and existing block, boundary most likely wrong";
                break;
            }
            else {
                continue;
            }
        }

        Block switch_block(block_addr);
        switch_block.mode = new_mode;

        if (m_arch == cs_arch::CS_ARCH_ARM) {
            if (switch_block.start % 2 != 0) {
                switch_block.mode = cs_mode::CS_MODE_THUMB;
            }
        }
        switch_block.callers.emplace_back(parent_block->start);
        switch_block.func_addr = parent_block->func_addr;
        VLOG(VLOG_SWT) << "Found switch block: 0x" << std::hex << switch_block.start << " from block: 0x" << parent_block->start;
        m_block_queue.push(switch_block);

        if(!m_block_queue.empty()) {
            this->process_block_queue();
        }
    }

    return 0;
}

void Cfg::process_switches() {
    VLOG(VLOG_SWT) << "Processing switch vtables";

    unsigned int obj_arch = m_obj->getArch();
    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(obj_arch);

    std::vector<uint64_t> tables_to_del;
    // Sanity check, make sure we remove any switch that exist in blocks due to switch metadata
    // failures.
    for (const auto &kv : *m_state->get_switch_tables()) {
        // Ignore bits outside of the text ranges.
        if (!m_bitmap->has_addr(kv.first)) {
            continue;
        }
        if (m_bitmap->get_bit(kv.first, MapFlag::BLOCK)) {
            LOG(ERROR) << "Switch table: 0x" << std::hex << kv.first << " exists in a block, flags: 0x" << static_cast<uint32_t>(m_bitmap->get_flag(kv.first));
            tables_to_del.emplace_back(kv.first);
        }
    }

    // Clean up bad tables.
    for (const auto &table : tables_to_del) {
        m_state->get_switch_tables()->erase(table);
    }

    for (const auto &kv : *m_state->get_switch_tables()) {
        uint64_t switch_addr = kv.first;

        auto parent_block_it = m_blocks.find(make_range(kv.second));
        if (parent_block_it == m_blocks.end()) {
            LOG(FATAL) << "Bad parent block for switch vtable at: 0x" << std::hex << switch_addr;
        }
        auto parent_block = parent_block_it->second;

        if (m_arch == cs_arch::CS_ARCH_X86) {
            this->get_switch_table<int32_t, int32_t>(switch_addr, &parent_block);
        }
        else if (m_arch == cs_arch::CS_ARCH_ARM) {
            if (parent_block.mode == cs_mode::CS_MODE_THUMB) {
                if (parent_block.metadata.count(bb_metadata::TBH_INS)) {
                    this->get_switch_table<uint16_t, uint32_t>(switch_addr, &parent_block);
                }
                else if (parent_block.metadata.count(bb_metadata::TBB_INS)){
                    this->get_switch_table<uint8_t, uint32_t>(switch_addr, &parent_block);
                }
                else if (parent_block.metadata.count(bb_metadata::SWITCH_INDIRECT)) {
                    this->get_switch_table<int32_t, int32_t>(switch_addr, &parent_block);
                }
                else {
                    LOG(FATAL) << "Bad arm switch block!";
                }
            }
            else {
                this->get_switch_table<int32_t, int32_t>(switch_addr, &parent_block);
            }
        }
        else if (m_arch == cs_arch::CS_ARCH_ARM64) {
            auto load_meta = parent_block.metadata.find(bb_metadata::LOAD);
            if (load_meta == parent_block.metadata.end()) {
                LOG(FATAL) << "Missing LOAD metadata on aarch64 switch table";
            }
            if (load_meta->second.scale == 2) {
                this->get_switch_table<int16_t, int32_t>(switch_addr, &parent_block);
            }
            else if (load_meta->second.scale == 1) {
                this->get_switch_table<int8_t, int32_t>(switch_addr, &parent_block);
            }
            else if (load_meta->second.scale == 8) {
                this->get_switch_table<int64_t, int32_t>(switch_addr, &parent_block);
            }
            else {
                LOG(FATAL) << "Unsupported load scale: " << load_meta->second.scale;
            }
        }
        else if (m_arch == cs_arch::CS_ARCH_MIPS) {
            this->get_switch_table<int32_t, int32_t>(switch_addr, &parent_block);
        }
        else if (m_arch == cs_arch::CS_ARCH_PPC) {
            if (parent_block.mode & cs_mode::CS_MODE_32) {
                this->get_switch_table<int32_t, int32_t>(switch_addr, &parent_block);
            }
            else {
                LOG(FATAL) << "PPC64 switch tables unsupported";
            }
        }
        else {
            LOG(FATAL) << "unsupported arch for switch processing: " << m_arch;
            return;
        }
    }

    m_switches_found += m_state->get_switch_tables()->size();
    m_state->get_switch_tables()->clear();
}

// 8 word sizes
#define ARM_SAMPLE_COUNT 8
#define ARM_SAMPLE_SIZE (0x4 * ARM_SAMPLE_COUNT)
uint64_t Cfg::scan_and_queue(std::vector<MemRange> *holes, cs_mode mode) {
    CHECK(holes) << "Invalid holes pointer passed to scan_and_queue";

    uint64_t found = 0;
    cs_err err;
    csh cs_handle;

    // Set a default mode
    cs_mode tmp_mode = mode;
    if (tmp_mode == cs_mode::CS_MODE_BIG_ENDIAN) {
        tmp_mode = cs_mode::CS_MODE_ARM;
    }

    err = cs_open(m_arch, tmp_mode, &cs_handle);
    if (err != CS_ERR_OK) {
        LOG(FATAL) << "cs_open: " << cs_strerror(err);
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(cs_handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    AbiOracle oracle(m_arch, tmp_mode, m_bin_type);

    cs_insn *insn = cs_malloc(cs_handle);
    CHECK(insn) << "Failed to cs_malloc";

    MapFlag not_scan = MapFlag::BLOCK | MapFlag::SWITCH | MapFlag::READ;

    bool exhusted_holes = true;
    for (auto &hole : *holes) {
        // Lets not bother checking tiny holes.
        if (hole.size <= 4) {
            continue;
        }
        if (unlikely(!hole.cur_addr)) {
            continue;
        }

        if ((hole.cur_addr > hole.addr) && (hole.size - hole.cur_addr) <= 4) {
            continue;
        }

        exhusted_holes = false;

        uint64_t start_offset;
        const uint8_t *data_ptr = nullptr;
        uint64_t hole_size;
        uint64_t cur_addr = hole.cur_addr;
        uint64_t end_addr = hole.addr + hole.size;

        // VLOG(VLOG_LIN) << "Started walk at: 0x" << std::hex << hole.cur_addr;
        // Walk forward over any blocks we discovered in a previous pass
        for (; cur_addr < end_addr; cur_addr++) {
            if (!this->m_bitmap->get_bit(cur_addr, not_scan)) {
                if (m_arch == cs_arch::CS_ARCH_ARM) {
                    // short aligned for thumb
                    if (cur_addr % 2 != 0) {
                        continue;
                    }
                }
                else if (m_arch == cs_arch::CS_ARCH_MIPS || m_arch == cs_arch::CS_ARCH_ARM64) {
                    if (cur_addr % 4 != 0) {
                        continue;
                    }
                }
                start_offset = cur_addr - hole.addr;
                data_ptr = hole.ptr + start_offset;
                hole_size = hole.size - start_offset;
                // VLOG(VLOG_LIN) << "Ended walk at: 0x" << std::hex << cur_addr;

                break;
            }
        }

        if (!data_ptr) {
            hole.cur_addr = 0;
            continue;
        }

        VLOG(VLOG_LIN) << "Hole addr: 0x" << std::hex << cur_addr << " size: 0x" << hole_size;

        cs_mode swap_mode = mode;
        // If we are in a arm bin and not able to determine the mode, we need to sample the hole
        // Looking for possible signs of arm / thumb code.
        if (m_arch == cs_arch::CS_ARCH_ARM && mode == cs_mode::CS_MODE_BIG_ENDIAN) {
            if (hole_size < ARM_SAMPLE_SIZE) {
                VLOG(VLOG_LIN) << "skipping hole of size: 0x" << std::hex << hole_size << " because it is too small to sample";
                hole.cur_addr = 0;
                continue;
            }

            auto hole_words = reinterpret_cast<const uint32_t *>(data_ptr);

            uint8_t always_exec_bits = 0;
            for (uint8_t i = 0; i < ARM_SAMPLE_COUNT; i++) {
                if ((hole_words[i] >> 28) == 0xe) {
                    always_exec_bits++;
                }
            }

            if (always_exec_bits >= 6) {
                if (cur_addr % 4 != 0) {
                    VLOG(VLOG_LIN) << "Possible arm instructions, but not word aligned. Picking thumb";
                    swap_mode = cs_mode::CS_MODE_THUMB;
                    CHECK(cur_addr % 2 == 0) << "Invalid THUMB address, not word aligned, addr: 0x" << std::hex << cur_addr;
                }
                else {
                    VLOG(VLOG_LIN) << "Possible arm instructions";
                    swap_mode = cs_mode::CS_MODE_ARM;
                }
            }
            else {
                VLOG(VLOG_LIN) << "Lack of arm instructions, picking thumb";
                swap_mode = cs_mode::CS_MODE_THUMB;
                CHECK(cur_addr % 2 == 0) << "Invalid THUMB address, not word aligned, addr: 0x" << std::hex << cur_addr;
            }

            cs_option(cs_handle, CS_OPT_MODE, swap_mode);
            oracle.change_mode(swap_mode);
        }

        // Use for arm starts of either str or push,
        // Kinda ugly way to handle it but with arm we need a defined starting point past and imm references
        bool arm_save_hit = false;
        bool skip_delay = false;

        while(cs_disasm_iter(cs_handle, &data_ptr, &hole_size, &cur_addr, insn)) {
            // Skip small end blocks
            if ((end_addr - insn->address) <= 4) {
                hole.cur_addr = 0; // exhausted
                break;
            }

            // when we walk into another block, bail out of disassembly loop,
            // Next time this function is called it will do a cheaper walk over all the blocks until is hits a new hole.
            if (this->m_bitmap->get_bit(insn->address, not_scan)) {
                hole.cur_addr = insn->address;
                break;
            }

            if (skip_delay) {
                skip_delay = false;
                continue;
            }


            abi_stat status = oracle.update_insn(insn);
            if (status == abi_stat::CONTINUE) {
                continue;
            }
            else if (status == abi_stat::RESET) {
                VLOG(VLOG_LIN) << "-- Oracle reset at: 0x" << std::hex << insn->address;
                oracle.reset();
                if (m_arch == cs_arch::CS_ARCH_MIPS) {
                    skip_delay = true;
                }
                continue;
            }
            else if (status == abi_stat::FOUND) {
                uint64_t start_addr = oracle.get_start_addr();
                VLOG(VLOG_LIN) << "Found possible block at: 0x" << std::hex << start_addr << " on addr: 0x" << insn->address;
                Block scan_block(start_addr);
                scan_block.mode = swap_mode;
                m_func_queue.push(scan_block);
                m_sweep_funcs_found += 1;

                found++;
                break;
            }
            else if (status == abi_stat::INVALID) {
                uint64_t start_addr = oracle.get_start_addr();
                VLOG(VLOG_LIN) << "Invalid function ABI at 0x" << std::hex << start_addr << " on addr: 0x" << insn->address;
                break;
            }
            else {
                LOG(FATAL) << "INVALID ORACLE STATUS: " << static_cast<int>(status);
            }
        }

        uint64_t next_addr = insn->address + insn->size;

        // Check if we are done with this hole.
        if (next_addr > (hole.addr + hole.size)) {
            hole.cur_addr = 0;
        }
        else {
            VLOG(VLOG_LIN) << "Next check address 0x" << std::hex << next_addr;
            hole.cur_addr = next_addr;
        }

        if (hole_size == 0) {
            hole.cur_addr = 0;
        }

        if (hole.cur_addr) {
            CHECK(hole.cur_addr >= hole.addr && hole.cur_addr < (hole.addr + hole.size)) << "Invalid hole skip addr: 0x" << std::hex << hole.cur_addr;
        }

        oracle.reset();
    }

    cs_free(insn, 1);
    cs_close(&cs_handle);

    if (exhusted_holes) {
        holes->clear();
    }

    return found;
}

void Cfg::do_linear_scan() {
    // Skip scanning on bins with no blocks created up to this point. PE files like COM or CLR's
    // will have a valid .text but will have no entries exposed. Sweeping through that can cause false positives.
    if (m_blocks.empty()) {
        LOG(WARNING) << "No blocks in CFG, skipping linear sweep";
        return;
    }

    LOG(INFO) << "Performing linear sweep";

    uint64_t scan_blocks = 0;

    unsigned int obj_arch = m_obj->getArch();
    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(obj_arch);
    cs_mode mode = std::get<1>(arch_tup);

    // Attempt to determine if the current binary is all ARM or all THUMB
    if (m_arch == cs_arch::CS_ARCH_ARM) {
        // This step could be done inline while creating blocks,
        // if the perf is needed lets perform the operations there.
        uint64_t arm_blocks = 0;
        uint64_t thumb_blocks = 0;
        for (const auto &block_kv : m_blocks) {
            if (block_kv.second.mode == cs_mode::CS_MODE_ARM) {
                arm_blocks++;
            }
            else if (block_kv.second.mode == cs_mode::CS_MODE_THUMB) {
                thumb_blocks++;
            }
            else {
                LOG(FATAL) << "Invalid block mode: 0x" << std::hex << block_kv.second.start << " mode: " << static_cast<int>(block_kv.second.mode);
            }
        }

        // All arm
        if (arm_blocks > 0 && thumb_blocks == 0) {
            VLOG(VLOG_LIN) << "All arm blocks, using arm mode for sweep";
            mode = cs_mode::CS_MODE_ARM;
        }
        // All thumb
        else if (arm_blocks == 0 && thumb_blocks > 0) {
            VLOG(VLOG_LIN) << "All thumb blocks, using thumb mode for sweep";
            mode = cs_mode::CS_MODE_THUMB;
        }
        // Mixed state
        else if (arm_blocks > 0 && thumb_blocks > 0) {
            LOG(WARNING) << "Mixed thumb / arm binary";
            mode = cs_mode::CS_MODE_BIG_ENDIAN; // default out.
        }
        else {
            LOG(FATAL) << "Invalid logic in thumb/arm block calc";
        }
    }

    std::vector<MemRange> holes = this->m_bitmap->get_unset_ranges(m_memmap.get(), MapFlag::ANY);

    if (holes.empty()) {
        VLOG(VLOG_LIN) << "Failed to find any code holes";
        return;
    }

    do {
        scan_blocks = this->scan_and_queue(&holes, mode);
        if (holes.empty()) {
            VLOG(VLOG_LIN) << "Exhusted all bitmap holes";
            break;
        }
        VLOG(VLOG_LIN) << "Found " << scan_blocks << " blocks from scanning holes" << " holes left: " << holes.size();

        this->process_func_queue();

        if(!m_block_queue.empty()) {
            this->process_block_queue();
        }
    } while(true);

    return;
}

int Cfg::post_process_blocks() {
    // Check for any split blocks within the block
    // Removes blocks that are standard splits, and kept all blocks that split instructions
    // Also mark the instruction splitting blocks for later analysis.
    //
    // TODO: This invalidates some leader/follower/callers, it might be required to make another follow up
    // pass to fix up those. Or make a generic lookup function that checks first the main blocks for a target
    // then the split targets map.

    for (auto it = m_blocks.begin(); it != m_blocks.end(); ++it) {
        auto &kv = *it;
        // clear out metadata used in the CFG
        kv.second.metadata.clear();

        // Find thumb bridges to the plt

        if (kv.second.mode == cs_mode::CS_MODE_THUMB) {
            // Check for the bx pc block,
            uint64_t block_size = kv.second.end - kv.second.start;
            if (block_size == 2) {
                cs_insn *insn;

                cs_option(m_cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
                cs_option(m_cs_handle, CS_OPT_MODE, kv.second.mode);

                uint32_t count = 0;
                count = cs_disasm(m_cs_handle, kv.second.data, block_size, kv.second.start, 1, &insn);

                if (!count) {
                    continue;
                }

                if (insn[0].id != ARM_INS_BX) {
                    cs_free(insn, count);
                    continue;
                }

                cs_arm arm = insn[0].detail->arm;
                if (arm.op_count != 1) {
                    cs_free(insn, count);
                    continue;
                }

                if (arm.operands[0].type != ARM_OP_REG || arm.operands[0].reg != ARM_REG_PC) {
                    cs_free(insn, count);
                    continue;
                }

                cs_free(insn, count);


                // Ok found bx pc, now check the follower block:
                if (kv.second.followers.size() != 1) {
                    // Non fatal error here because a 'bx pc' can be a tail call, indicated by a branch_target being filled in.
                    if (kv.second.branch_target) {
                        continue;
                    }
                    else {
                        LOG(FATAL) << "Invalid bx pc ARM block in post processing";
                    }
                }

                auto follow_block = m_blocks.find(make_range(kv.second.followers.at(0)));
                if (follow_block == m_blocks.end()) {
                    continue;
                }

                if (follow_block->second.mode != cs_mode::CS_MODE_ARM) {
                    LOG(FATAL) << "Invalid following block for a bx pc block";
                }

                const Symbol *sym;
                if (!m_resolver->resolve_sym(follow_block->second.branch_target, &sym)) {
                    continue;
                }

                // Ok we found a thumb bridge, now symbolize the current iterated block to be a valid symbol
                // Todo: invalidate the old symbol?
                m_resolver->add_symbol(kv.second.start, *sym);
                VLOG(VLOG_CFG) << "New thumb bridge symbol: 0x" << std::hex << kv.second.start << " : " << sym->name;
            }
        }
    }

    // Find any blocks that are just jmp to IAT entry blocks and symbolize them to match their targets.
    if (this->m_obj->isCOFF()) {
        unsigned int obj_arch = m_obj->getArch();
        std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(obj_arch);
        cs_mode mode = std::get<1>(arch_tup);

        cs_err err;
        csh cs_handle;

        err = cs_open(m_arch, mode, &cs_handle);
        if (err != CS_ERR_OK) {
            LOG(ERROR) << "cs_open: " << cs_strerror(err);
            return 1;
        }
        cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

        for (auto &kv : m_blocks) {
            uint64_t block_size = kv.second.end - kv.second.start;

            cs_insn *insn = cs_malloc(cs_handle);

            const uint8_t *data_ptr = kv.second.data;
            uint64_t tmp_block_addr = kv.second.start;

            // Only grab one instruction.
            while(cs_disasm_iter(cs_handle, &data_ptr, &block_size, &tmp_block_addr, insn)) {
                break;
            }

            if (!insn) {
                continue;
            }

            if (m_arch == cs_arch::CS_ARCH_X86) {
                if (insn->id != X86_INS_JMP) {
                    cs_free(insn, 1);
                    continue;
                }
            }

            // This is x86 only, TODO refactor with better get_op_val;
            std::vector<uint64_t> imms = get_imm_vals(*insn, m_arch, 0, 0);
            for (const auto &imm : imms) {
                const Symbol *sym;
                if (!m_resolver->resolve_sym(imm, &sym)) {
                    continue;
                }
                if (!sym) {
                    continue;
                }
                m_resolver->add_symbol(insn->address, *sym);
                kv.second.jump_block = true;
                VLOG(VLOG_CFG) << "New jump addr: 0x" << std::hex << insn->address << " : " << sym->name;

                // Only grab the first imm value, if there are more than one it's most likely a capstone issue.
                break;
            }

            cs_free(insn, 1);
        }

        cs_close(&cs_handle);
    }

    return 0;
}

CfgRes<uint64_t> Cfg::libc_start_main_helper(cs_insn *insn, Block *block) const {
    switch (m_arch) {
    case cs_arch::CS_ARCH_PPC:
        return libc_start_main_ppc(insn, block);
    default:
        break;
    }
    return CfgRes<uint64_t>(CfgErr::OTHER);
}
CfgRes<uint64_t> Cfg::libc_start_main_ppc(cs_insn *insn, Block *block) const {
    if (block->mode & cs_mode::CS_MODE_32) {
        auto startup_info_ptr_res = m_state->get_reg_val(ppc_reg::PPC_REG_R8); // Assume standard ABI and GLIBC start_main
        if (!startup_info_ptr_res) {
            VLOG(VLOG_CFG) << "Failed to get R13 register for startup_info arg at: 0x" << std::hex << insn->address;

            auto r3_res = m_state->get_reg_val(ppc_reg::PPC_REG_R3);
            if (r3_res) {
                VLOG(VLOG_CFG) << "Assuming r3, standard libc_start_main arg is main ptr";

                if (!m_memmap->is_text_sec(*r3_res)) {
                    LOG(WARNING) << "stinfo->main ptr not in text segment at: 0x" << std::hex << insn->address << " ptr: 0x" << *r3_res;
                    return CfgRes<uint64_t>(CfgErr::OTHER);
                }

                return CfgRes<uint64_t>(*r3_res);
            }

            return CfgRes<uint64_t>(CfgErr::NO_REG);
        }

//        VLOG(VLOG_CFG) << "stinfo ptr: 0x" << std::hex << *startup_info_ptr_res;

        auto stinfo_ptr = reinterpret_cast<const uint32_t *>(m_memmap->addr_to_ptr(*startup_info_ptr_res));
        if (!stinfo_ptr) {
            LOG(WARNING) << "Failed read stinfo ptr at: 0x" << std::hex << insn->address;
            return CfgRes<uint64_t>(CfgErr::BAD_READ);
        }
        auto main_val = stinfo_ptr[1];
        if (block->mode & cs_mode::CS_MODE_BIG_ENDIAN){
            main_val = __builtin_bswap32(main_val);
        }

        if (!m_memmap->is_text_sec(main_val)) {
            LOG(WARNING) << "stinfo->main ptr not in text segment at: 0x" << std::hex << insn->address << " ptr: 0x" << main_val;
            return CfgRes<uint64_t>(CfgErr::OTHER);
        }

        return CfgRes<uint64_t>(main_val);
    }
    else {
        LOG(WARNING) << "Skipping PPC64 libc_start_main inspection";
    }

    return CfgRes<uint64_t>(CfgErr::OTHER);
}

