#include <map>
#include <string>
#include <cstdint>
#include <iostream>
#include <memory>


#include "glog/logging.h"

#include "Block.hpp"
#include "TraceDefs.hpp"
#include "SymTraceAnalyzer.hpp"

SymTraceAnalyzer::SymTraceAnalyzer(std::map<uint64_t, Module> *mod_map) : TraceAnalyzer(mod_map, "symtrace") {};

void SymTraceAnalyzer::output_header() {
    std::cout << "serial,modid,pid,tid,addr_offset,block_id,signum,sym" << std::endl;
}

void SymTraceAnalyzer::output_results() {
    for (const auto &res : m_results) {
        std::cout <<
        res.serial << "," <<
        res.modid << "," <<
        res.pid << "," <<
        res.tid << "," <<
        res.addr_offset << "," <<
        res.block_id << "," <<
        res.signum << "," <<
        res.sym <<
        std::endl;
    }
    m_results.clear();
}

bool SymTraceAnalyzer::on_trace_elm(uint32_t modid, uint32_t offset, uint32_t pid, uint32_t tid, log_fault *fault) {
    auto module = m_mod_map->find(modid);
    if (module == m_mod_map->end()) {
        LOG(ERROR) << "Failed to find module: " << modid;
        return false;
    }

    auto block = module->second.block_map->find(make_range(offset));
    if (block == module->second.block_map->end()) {
        // LOG(ERROR) << "Failed to find offset: 0x" << std::hex << offset << " in modid: " << std::dec << modid;
        return false;
    }

    Result res = { m_tc->serial, modid, pid, tid, offset, m_block_count };
    std::string sym;
    uint32_t signum = 0;

    if (block->second.branch_target) {
        const Symbol *sym_out;
        if (module->second.resolver->resolve_sym(block->second.branch_target, &sym_out)) {
            sym = sym_out->name;
        }
    }
    if (fault) {
        signum = fault->signum;
    }

    if (signum || !sym.empty()) {
        res.signum = signum;
        res.sym = sym;
        m_results.push_back(res);
    }

    return true;
}
