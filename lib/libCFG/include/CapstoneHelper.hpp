#pragma once


#include <cstdint>
#include <tuple>
#include <vector>

#include "capstone/capstone.h"


std::tuple<cs_arch, cs_mode> map_triple_cs(uint32_t triple);

std::vector<uint64_t> get_imm_vals(const cs_insn &insn, cs_arch arch, uint32_t base_reg, uint64_t reg_val);

bool is_nop(cs_arch arch, cs_insn *insn);

bool is_pc_in_arm_ops(cs_arm arm_details);
bool is_lr_in_arm_ops(cs_arm arm_details);

unsigned rotr32(unsigned val, unsigned amt);
