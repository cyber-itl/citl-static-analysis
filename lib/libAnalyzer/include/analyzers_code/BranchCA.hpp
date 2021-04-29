#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "capstone/capstone.h"

#include "analyzers_code/BaseCodeAnalyzer.hpp"

struct Block;
struct Symbol;

class BranchCA : public BaseCodeAnalyzer {
  public:
    BranchCA(cs_arch arch, cs_mode mode);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    // cs_insn.id : found_count
    std::map<std::string, uint64_t> m_branch_dict;
};
