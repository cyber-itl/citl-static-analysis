#include <cstdint>

#include "capstone/capstone.h"
#include "json.hpp"

#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/CallStatsCA.hpp"

struct Block;
struct Symbol;


CallStatsCA::CallStatsCA(cs_arch arch, cs_mode mode) : BaseCodeAnalyzer("call_stats", arch, mode) {};

int CallStatsCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    cs_detail *detail = insn.detail;
    std::string mnemonic;

    if (m_arch == cs_arch::CS_ARCH_X86) {
        if (insn.id == X86_INS_INVALID) {
            return 0;
        }

        if (detail->groups_count > 0) {
            for (uint8_t i = 0; i < detail->groups_count; i++) {
                uint8_t grp = detail->groups[i];

                if (grp == CS_GRP_CALL) {
                    mnemonic = insn.mnemonic;
                    break;
                }
            }
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM) {
        switch (insn.id) {
        case ARM_INS_BL:
        case ARM_INS_BLX:
        case ARM_INS_BXJ:
            mnemonic = insn.mnemonic;
            break;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_ARM64) {
        switch (insn.id) {
        case ARM64_INS_BL:
        case ARM64_INS_BLR:
            mnemonic = insn.mnemonic;
            break;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_MIPS) {
        switch (insn.id) {
        case MIPS_INS_BAL:
        case MIPS_INS_JAL:
        case MIPS_INS_JALR:
        case MIPS_INS_BGEZAL:
        case MIPS_INS_BLTZAL:
            mnemonic = insn.mnemonic;
            break;
        }
    }
    else if (m_arch == cs_arch::CS_ARCH_PPC) {
        switch(insn.id) {
        case PPC_INS_BL:
        case PPC_INS_BLA:
        case PPC_INS_BLRL:
        case PPC_INS_BCL:
        case PPC_INS_BCLA:
        case PPC_INS_BCLR:
        case PPC_INS_BCLRL:
        case PPC_INS_BCTRL:
            mnemonic = insn.mnemonic;
            break;
        }
    }

    if (!mnemonic.empty()) {
        if (m_call_dict.count(insn.mnemonic)) {
            m_call_dict[insn.mnemonic]++;
        }
        else {
            m_call_dict.emplace(insn.mnemonic, 1);
        }
    }

    return 0;
}

int CallStatsCA::process_results() {
    m_results["call_dict"] = m_call_dict;

    return 0;
}
