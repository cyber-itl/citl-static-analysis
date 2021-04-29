#pragma once

#include <cstdint>
#include <memory>
#include <map>
#include <string>
#include <vector>

#include "capstone/capstone.h"

#include "analyzers_code/FuncBaseCA.hpp"

class SymResolver;
struct Block;
struct Symbol;

class SandboxFuncCA : public FuncBaseCA {
  public:
    SandboxFuncCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    std::vector<std::string> m_sandbox_funcs;
    std::map<std::string, uint64_t> m_sandbox_calls;
};
