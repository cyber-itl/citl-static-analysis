#pragma once

#include <cstdint>
#include <vector>

#include "capstone/capstone.h"

#include "analyzers_code/BaseCodeAnalyzer.hpp"

struct Block;
struct Symbol;


class StackStatsCA : public BaseCodeAnalyzer {
  public:
    StackStatsCA(cs_arch arch, cs_mode mode);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    std::vector<int64_t> m_stack_adjs;
};
