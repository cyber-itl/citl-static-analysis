#include <string>
#include <cstdint>
#include <utility>

#include "json.hpp"
#include "capstone/capstone.h"

#include "Block.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/FuncInstrStatsCA.hpp"

struct Symbol;


FuncInstrStatsCA::FuncInstrStatsCA(cs_arch arch, cs_mode mode) : BaseCodeAnalyzer("func_insn_stats", arch, mode) {};

int FuncInstrStatsCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    auto func_stats = m_func_insn_stats.find(block->func_addr);
    if (func_stats != m_func_insn_stats.end()) {
        auto mnemonic_it = func_stats->second.find(insn.mnemonic);
        if (mnemonic_it != func_stats->second.end()){
            mnemonic_it->second++;
        }
        else {
            func_stats->second.emplace(insn.mnemonic, 1);
        }
    }
    else {
        std::map<std::string, uint64_t> new_map;
        new_map.emplace(insn.mnemonic, 1);
        m_func_insn_stats.emplace(block->func_addr, new_map);
    }

    return 0;
}

int FuncInstrStatsCA::process_results() {
    json final_data;
    for (const auto &kv : m_func_insn_stats) {
        final_data[std::to_string(kv.first)] = kv.second;
    }
    m_results["instruction_dict"] = final_data;

    return 0;
}
