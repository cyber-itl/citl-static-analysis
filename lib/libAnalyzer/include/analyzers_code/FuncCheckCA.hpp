#pragma once

#include <memory>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "capstone/capstone.h"

#include "analyzers_code/FuncBaseCA.hpp"

class SymResolver;
struct Block;
struct Symbol;

class FuncCheckCA : public FuncBaseCA {
  public:
    FuncCheckCA(cs_arch arch, cs_mode mode,
            std::shared_ptr<SymResolver> resolver,
            std::vector<std::string> good_funcs,
            std::vector<std::string> risky_funcs,
            std::vector<std::string> bad_funcs,
            std::vector<std::string> ick_funcs);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    std::map<std::string, uint64_t> m_good_hits;
    std::map<std::string, uint64_t> m_risky_hits;
    std::map<std::string, uint64_t> m_bad_hits;
    std::map<std::string, uint64_t> m_ick_hits;
};
