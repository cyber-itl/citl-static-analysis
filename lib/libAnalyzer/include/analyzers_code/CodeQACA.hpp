#pragma once

#include <cstdint>
#include <map>
#include <memory>

#include "capstone/capstone.h"

#include "analyzers_code/BaseCodeAnalyzer.hpp"

class SymResolver;
struct Block;
struct Symbol;


class CodeQACA : public BaseCodeAnalyzer {
  public:
    CodeQACA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    std::shared_ptr<SymResolver> m_resolver;

    std::map<uint64_t, uint64_t> m_sym_calls;
    uint64_t m_sym_call_count;
};
