#pragma once

#include <cstdint>
#include <map>

#include "capstone/capstone.h"

#include "analyzers_code/BaseCodeAnalyzer.hpp"

struct Block;
struct Symbol;

class CorpusRankCfgCA : public BaseCodeAnalyzer {
  public:
    CorpusRankCfgCA(cs_arch arch, cs_mode mode);

    int run(cs_insn insn, const Block *block, const Symbol *call_sym) override;

    int process_results() override;

  private:
    enum class branch_type {
        CONDITIONAL = 0,  // jnz, je
        UNCONDITIONAL,    // jmp 0x1000,
        LINKING,          // call 0x1000
        INDIRECT,         // jmp rax
        INDIRECT_LINKING, // call [rax],
        RET,              // ret, retn
        SYSCALL,          // int 0x80, syscall
        UNKNOWN           // Everything else
    };

    std::map<uint64_t, json> m_serial_cfg;
};
