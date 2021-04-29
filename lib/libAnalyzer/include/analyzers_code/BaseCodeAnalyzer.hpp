#pragma once

#include "json.hpp"
#include "capstone/capstone.h"

#include "SymResolver.hpp"
#include "Block.hpp"

using json = nlohmann::json;

class BaseCodeAnalyzer {
  public:
    virtual ~BaseCodeAnalyzer() = default;

    virtual int run(cs_insn insn, const Block *block, const Symbol *call_sym) = 0;

    virtual int process_results() = 0;

    json get_results() const {
        return m_results;
    }

    std::string get_analyzer_name() const {
        return m_analyzer_name;
    }

    void set_blocks(const std::map<block_range, Block, block_cmp> *blocks)  {
        m_blocks = blocks;
    }

  protected:
    BaseCodeAnalyzer(std::string name, cs_arch arch, cs_mode mode) :
        m_analyzer_name(std::move(name)),
        m_blocks(nullptr),
        m_arch(arch),
        m_mode(mode) {};
    const std::string m_analyzer_name;
    const std::map<block_range, Block, block_cmp> *m_blocks;

    cs_arch m_arch;
    cs_mode m_mode;

    json m_results;
};
