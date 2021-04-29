#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include <utility>

#include "capstone/capstone.h"

#define VLOG_SWT 1
#define VLOG_LIN 2
#define VLOG_CFG 3
#define VLOG_REG 4


enum class bb_metadata {
    LOAD,
    MOV_OFFSET,
    REG_ARITH,
    AND_OFFSET,
    ADD_OFFSET,
    SWITCH_INDIRECT,
    CMP_LENGTH,
    TBH_INS,
    TBB_INS,
    ARM_LDR_SHIFT,

    // MIPS
    SLL_VALUE,
    ADDIU_VAL,
    ADDU_VAL,

    // PPC
    LWZX_LOAD,
    MTCTR_REG,

    // Related to RISC linking
    SAVE_LINK_REG,

    // General
    FOUND_BLOCK
};


struct MetaData {
    MetaData() = default;
    MetaData(uint64_t addr, uint32_t reg, uint64_t val) : addr(addr), reg(reg), value(val) {};
    MetaData(uint64_t addr, uint32_t reg, uint64_t val, uint8_t scale) : addr(addr), reg(reg), value(val), scale(scale) {};

    uint64_t addr {0};
    uint32_t reg {0};
    uint64_t value {0};
    uint8_t scale {0};
};

using block_range = std::pair<uint64_t, uint64_t>;
block_range make_range(uint64_t lower, uint64_t upper);
block_range make_range(uint64_t target);

struct block_cmp {
    bool operator()(const block_range &a, const block_range &b) const {
        return a.first < b.first && a.second < b.first;
    }
};

struct Block {
    explicit Block(uint64_t addr) :
        start(addr),
        end(0),
        data(nullptr),
        func_addr(0),
        mode(CS_MODE_LITTLE_ENDIAN),
        splits_insn(false),
        is_func_head(false),
        jump_block(false),
        branch_target(0) {};

    bool operator==(const Block &other) const {
        return this->start == other.start;
    }

    bool operator <(const Block &other) const {
        return this->start < other.start;
    }

    bool operator!=(const Block &other) const {
        return this->start != other.start;
    }

    cs_mode mode;

    uint64_t start;
    uint64_t end;
    const uint8_t *data;

    bool is_func_head;
    uint64_t func_addr;
    std::vector<uint64_t> callers;

    bool splits_insn;
    bool jump_block;

    std::vector<uint64_t> leaders;
    std::vector<uint64_t> followers;

    uint64_t branch_target;

    std::map<bb_metadata, MetaData> metadata;
};
