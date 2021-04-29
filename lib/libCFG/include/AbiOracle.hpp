#pragma once

#include <map>
#include <cstdint>

#include "capstone/capstone.h"
#include "CfgRes.hpp"
#include "Utils.hpp"

enum class abi_stat {
    CONTINUE,   // Found nothing of interest, continue walking
    INVALID,    // Hit an invalid abi state
    RESET,      // Need to reset the Oracle state state and continue walking
    FOUND       // Found a valid abi prolog
};

class AbiOracle {
  public:
    AbiOracle(cs_arch arch, cs_mode mode, bin_type type);

    abi_stat update_insn(cs_insn *insn);
    uint64_t get_start_addr() const;
    void change_mode(cs_mode mode);
    void reset();

  private:
    void setup_regs();
    abi_stat update_x86_insn(cs_insn *insn);
    abi_stat update_x86_64_insn(cs_insn *insn);
    abi_stat update_arm_insn(cs_insn *insn);
    abi_stat update_arm64_insn(cs_insn *insn);
    abi_stat update_mips_insn(cs_insn *insn);
    abi_stat update_ppc_insn(cs_insn *insn);

    CfgRes<uint64_t> get_reg(cs_x86 x86, uint8_t idx) const;
    CfgRes<uint64_t> get_reg(cs_arm arm, uint8_t idx) const;
    CfgRes<uint64_t> get_reg(cs_arm64 arm64, uint8_t idx) const;
    CfgRes<uint64_t> get_reg(cs_mips mips, uint8_t idx) const;
    CfgRes<uint64_t> get_reg(cs_ppc ppc, uint8_t idx) const;

    enum class reg_state {
        INIT,
        SAVED,
        USED
    };

    cs_arch m_arch;
    cs_mode m_mode;
    bin_type m_type;
    // cs_reg_id : valid|invalid
    std::map<uint64_t, reg_state> m_abi_bucket;
    uint64_t m_start_addr;
};
