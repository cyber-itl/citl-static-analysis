#pragma once

#include <string>
#include <cstdint>
#include <unordered_map>

#include "capstone/capstone.h"

class CpuState;
struct Block;
struct Symbol;

#include "EventManager.hpp"

class FuzzImmEvent : public AnalyzerEvent {
  public:
    FuzzImmEvent();

    int run(CpuState *cpu, Block *block, cs_insn *insn, const Symbol *sym) override;

    json get_results() const override;

  private:
    void try_add_imm(CpuState *cpu, cs_insn *insn, uint64_t imm);
    void try_mem_read(CpuState *cpu, cs_insn *insn, uint64_t read_addr);

    std::unordered_map<std::string, uint64_t> m_strings;
    std::unordered_map<std::string, uint64_t> m_values;
};
