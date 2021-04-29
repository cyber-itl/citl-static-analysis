#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <memory>
#include <vector>

#include "capstone/capstone.h"

#include "analyzers_code/FuncBaseCA.hpp"

class SymResolver;
struct Block;
struct Symbol;


class DynLibLoadCA : public FuncBaseCA {
  public:
    DynLibLoadCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    std::vector<std::string> m_load_lib_funcs;
    std::map<std::string, uint64_t> m_load_lib_calls;
};
