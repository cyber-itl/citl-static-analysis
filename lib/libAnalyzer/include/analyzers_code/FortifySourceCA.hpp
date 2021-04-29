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

class FortifySourceCA : public FuncBaseCA {
  public:
    FortifySourceCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver, bool is_macho = false);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    bool check_block(const Block *block, uint64_t stop_addr = 0);
    bool check_alt_fort(const Block *block, cs_insn insn);

    std::vector<std::string> m_fort_targets;
    std::map<std::string, uint64_t> m_fort_funcs;
    std::map<std::string, uint64_t> m_unfort_funcs;

    bool m_is_macho;
};
