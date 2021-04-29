#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "capstone/capstone.h"
#include "analyzers_code/BaseCodeAnalyzer.hpp"

struct Block;
struct Symbol;

class CallStatsCA : public BaseCodeAnalyzer {
  public:
    CallStatsCA(cs_arch arch, cs_mode mode);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    // mmemonic : found_count
    std::map<std::string, uint64_t> m_call_dict;
};
