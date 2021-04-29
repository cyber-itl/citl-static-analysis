#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "capstone/capstone.h"

#include "analyzers_code/BaseCodeAnalyzer.hpp"

struct Block;
struct Symbol;

class FuncInstrStatsCA : public BaseCodeAnalyzer {
  public:
    FuncInstrStatsCA(cs_arch arch, cs_mode mode);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    // func_addr : <insntruction mnonic : count>
    std::map<uint64_t, std::map<std::string, uint64_t>> m_func_insn_stats;
};
