#pragma once

#include <memory>
#include <set>
#include <cstdint>
#include <string>
#include <vector>

#include "capstone/capstone.h"

#include "analyzers_code/FuncBaseCA.hpp"

class SymResolver;
struct Block;
struct Symbol;


class StackGuardCA : public FuncBaseCA {
  public:
    StackGuardCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver, bool is_pe = false);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    bool m_is_pe;
    bool m_found_guard_func;

    std::set<uint64_t> m_guard_chk_calls;
    std::vector<std::string> m_stack_guard_syms;
};
