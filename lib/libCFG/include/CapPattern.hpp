#pragma once

#include <cstdint>
#include <vector>
#include <map>

#include "capstone/capstone.h"

enum class op_type {
    REG,
    SEG,
    MEM,
    IMM,
    REG_PLACEHOLDER,
    WILDCARD
};

enum class pat_type {
    ORDERED,
    UNORDERED
};

struct OperPat {
    OperPat(op_type op_type);
    OperPat(op_type op_type, uint64_t reg);
    OperPat(op_type op_type, const std::vector<uint32_t> &regs);
    uint64_t reg;
    const std::vector<uint32_t> regs;
    op_type type;
};

struct InsnPattern {
    InsnPattern(uint32_t id);
    InsnPattern(uint32_t id, const std::vector<OperPat> &opers);

    uint32_t m_id;
    uint8_t m_op_count;
    const std::vector<OperPat> m_opers;
};

struct Pattern {
    Pattern(const std::vector<InsnPattern> &pattern);
    Pattern(pat_type type, const std::vector<InsnPattern> &pattern);

    const std::vector<InsnPattern> insn_patterns;
    pat_type type;
};

class CapPattern {
  public:
    CapPattern(cs_insn *insns, uint64_t count, cs_arch arch, cs_mode mode);

    bool check_pattern(const Pattern &pat);

    bool check_insn(cs_insn insn, const InsnPattern &pat);

    bool check_x86_ops(cs_insn insn, const InsnPattern &pat);

  private:
    cs_insn *m_insns;
    uint64_t m_count;
    cs_arch m_arch;
    cs_mode m_mode;

    std::map<uint64_t, uint64_t> m_reg_placeholders;
};
