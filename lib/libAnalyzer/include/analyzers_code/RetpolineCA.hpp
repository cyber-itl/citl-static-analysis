#pragma once

#include <cstdint>
#include <vector>
#include "capstone/capstone.h"

#include "analyzers_code/BaseCodeAnalyzer.hpp"

struct Block;
struct Symbol;


class RetpolineCA : public BaseCodeAnalyzer {
  public:
    RetpolineCA(cs_arch arch, cs_mode mode);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    bool m_has_pause;
    bool m_has_lfence;
    bool m_retpoline;

    std::vector<uint64_t> m_call_sites;

    uint64_t m_block_addr;
};
