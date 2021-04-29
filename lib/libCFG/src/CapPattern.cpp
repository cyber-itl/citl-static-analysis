#include <cstdint>
#include <vector>
#include <algorithm>
#include <utility>

#include "capstone/capstone.h"
#include "glog/logging.h"
#include "CapPattern.hpp"

OperPat::OperPat(op_type op_type) :
    reg(0),
    type(op_type) {};

OperPat::OperPat(op_type op_type, uint64_t reg) :
    reg(reg),
    type(op_type) {};

OperPat::OperPat(op_type op_type, const std::vector<uint32_t> &regs) :
    reg(0),
    type(op_type),
    regs{regs} {};

InsnPattern::InsnPattern(uint32_t id) :
    m_id(id),
    m_op_count(0) {};

InsnPattern::InsnPattern(uint32_t id, const std::vector<OperPat> &opers) :
    m_id(id),
    m_op_count(opers.size()),
    m_opers(opers) {};

Pattern::Pattern(const std::vector<InsnPattern> &pattern) :
    type(pat_type::ORDERED),
    insn_patterns(pattern) {};

Pattern::Pattern(pat_type type, const std::vector<InsnPattern> &pattern) :
    type(type),
    insn_patterns(pattern) {};

CapPattern::CapPattern(cs_insn *insns, uint64_t count, cs_arch arch, cs_mode mode) :
    m_insns(insns),
    m_count(count),
    m_arch(arch),
    m_mode(mode) {};

bool CapPattern::check_pattern(const Pattern &pattern) {
    if (m_count < pattern.insn_patterns.size()) {
        return false;
    }

    bool unordered_match = false;
    std::vector<bool> matched_idxs;
    if (pattern.type == pat_type::UNORDERED) {
        unordered_match = true;
        matched_idxs.resize(pattern.insn_patterns.size(), false);
    }

    for (uint64_t idx = 0; idx < m_count; idx++) {
        cs_insn insn = m_insns[idx];

        if (idx >= pattern.insn_patterns.size()) {
            break;
        }

        if (unordered_match) {
            bool match_any = false;
            uint64_t pat_idx = 0;
            for (const auto &cur_pat : pattern.insn_patterns) {
                // Skip things we already matched.
                if (matched_idxs.at(pat_idx)) {
                    pat_idx++;
                    continue;
                }
                if (this->check_insn(insn, cur_pat)) {
                    match_any = true;
                    matched_idxs.at(pat_idx) = true;
                    break;
                }
                pat_idx++;
            }

            if (!match_any) {
                return false;
            }
        }
        else {
            InsnPattern cur_pat = pattern.insn_patterns.at(idx);

            if (!this->check_insn(insn, cur_pat)) {
                return false;
            }
        }
    }

    m_reg_placeholders.clear();

    return true;
}

bool CapPattern::check_insn(cs_insn insn, const InsnPattern &pat) {
    if (pat.m_id != insn.id) {
        return false;
    }

    if (pat.m_op_count != 0) {
        bool valid_ops = false;
        if (m_arch == cs_arch::CS_ARCH_X86) {
            valid_ops = this->check_x86_ops(insn, pat);
        }
        else if (m_arch == cs_arch::CS_ARCH_ARM) {

        }
        else if (m_arch == cs_arch::CS_ARCH_ARM64) {

        }
        else {

        }

        if (!valid_ops) {
            return false;
        }
    }

    return true;
}

bool CapPattern::check_x86_ops(cs_insn insn, const InsnPattern &pat) {
    cs_x86 detail = insn.detail->x86;

    if (detail.op_count < pat.m_op_count) {
        return false;
    }

    for(uint8_t idx = 0; idx < detail.op_count; idx++) {
        cs_x86_op op = detail.operands[idx];

        if (idx >= pat.m_op_count) {
            break;
        }

        OperPat op_pat = pat.m_opers.at(idx);

        switch (op_pat.type) {
        case op_type::WILDCARD:
            continue;
            break;

        case op_type::REG:
            if (op.type != X86_OP_REG) {
                return false;
            }

            // Allow * reg value's
            if (op_pat.reg != X86_REG_INVALID) {
                if (op_pat.reg != op.reg) {
                    return false;
                }
            }
            else {
                // Check for a list of optional regs
                if (op_pat.regs.size()) {
                    if (std::find(op_pat.regs.cbegin(), op_pat.regs.cend(), op.reg) == op_pat.regs.cend()) {
                        return false;
                    }
                }
            }
            break;

        case op_type::SEG:
            if (op.type != X86_OP_MEM) {
                return false;
            }
            if (op_pat.reg != op.mem.segment) {
                return false;
            }
            break;

        case op_type::MEM:
            if (op.type != X86_OP_MEM) {
                return false;
            }
            // Allow empty mem type without a reg.
            if (op_pat.reg != X86_REG_INVALID) {
                if (op.mem.base != op_pat.reg) {
                    return false;
                }
            }
            else {
                // Check for a list of optional regs
                if (op_pat.regs.size()) {
                    if (std::find(op_pat.regs.cbegin(), op_pat.regs.cend(), op.mem.base) == op_pat.regs.cend()) {
                        return false;
                    }
                }
            }
            break;

        case op_type::IMM:
            if (op.type != X86_OP_IMM) {
                return false;
            }
            break;
        case op_type::REG_PLACEHOLDER: {
            if (op.type != X86_OP_REG && op.type != X86_OP_MEM) {
                return false;
            }

            uint64_t reg_id = 0;
            if (op.type == X86_OP_REG) {
                reg_id = op.reg;
            }
            else if (op.type == X86_OP_MEM) {
                reg_id = op.mem.base;
            }
            else {
                LOG(FATAL) << "Invalid operand type for REG_PLACEHOLDER";
            }

            auto reg_id_kv = m_reg_placeholders.find(op_pat.reg);
            // if we don't have it in the place holders map, store the first seen value.
            if (reg_id_kv == m_reg_placeholders.end()) {
                m_reg_placeholders.emplace(op_pat.reg, reg_id);
            }
            else {
                // Grab from the cache, verify that the current reg value is the same.
                if (reg_id != reg_id_kv->second) {
                    return false;
                }
            }
            break;
        }
        default:
            LOG(FATAL) << "Invalid operand type: " << static_cast<uint32_t>(op_pat.type);
            break;
        }
    }

    return true;
}
