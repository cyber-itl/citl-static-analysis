#include <ctype.h>
#include <memory>

#include "capstone/capstone.h"
#include "glog/logging.h"
#include "json.hpp"

#include "CpuState.hpp"
#include "CfgRes.hpp"
#include "EventManager.hpp"
#include "MemoryMap.hpp"
#include "analyzers_event/FuzzImmEvent.hpp"

struct Block;
struct Symbol;

#define MAX_STR_LEN 0x1000

FuzzImmEvent::FuzzImmEvent() : AnalyzerEvent("fuzz_imm", event_type::INSN) {};

int FuzzImmEvent::run(CpuState *cpu, Block *block, cs_insn *insn, const Symbol *sym) {
    switch(cpu->get_arch()) {
    case cs_arch::CS_ARCH_X86: {
        if (insn->id == X86_INS_INVALID) {
            break;
        }

        cs_x86 x86 = insn->detail->x86;

        for (uint8_t i = 0; i < x86.op_count; i++) {
            cs_x86_op op = x86.operands[i];
            if (op.type == X86_OP_IMM) {
                this->try_add_imm(cpu, insn, op.imm);

                if (cpu->get_mode() == cs_mode::CS_MODE_32 && insn->id == X86_INS_PUSH) {
                    this->try_mem_read(cpu, insn, op.imm);
                }
            }
            else if (op.type == X86_OP_MEM) {
                auto read_addr_res = cpu->get_op_read_addr(insn, op, cpu->get_mode());
                if (!read_addr_res) {
                    continue;
                }
                this->try_mem_read(cpu, insn, *read_addr_res);
            }
        }

        break;
    }
    default:
        return 0;
    }

    return 0;
}

void FuzzImmEvent::try_add_imm(CpuState *cpu, cs_insn *insn, uint64_t imm) {
    auto memmap = cpu->get_memmap();
    CHECK(memmap) << "CPU MemoryMap invalid";

    if (memmap->is_text_sec(imm)) {
        return;
    }

    std::stringstream stream;
    stream << "0x" << std::hex << imm;

    m_values.emplace(stream.str(), insn->address);
}

void FuzzImmEvent::try_mem_read(CpuState *cpu, cs_insn *insn, uint64_t read_addr) {
    auto memmap = cpu->get_memmap();
    CHECK(memmap) << "CPU MemoryMap invalid";

    auto read_ptr = memmap->addr_to_ptr(read_addr);
    if (!read_ptr) {
        return;
    }
    auto start_ptr = read_ptr;

    uint64_t str_len = 0;
    bool is_str = true;

    while (*read_ptr != 0x0 && str_len < MAX_STR_LEN) {
        if ( !static_cast<bool>(std::isprint(*read_ptr)) && !static_cast<bool>(std::isspace(*read_ptr)) ) {
            is_str = false;
            break;
        }
        str_len++;
        read_ptr++;
    }

    if (str_len >= 4 && is_str) {
        m_strings.emplace(std::string(reinterpret_cast<const char *>(start_ptr), str_len), insn->address);
    }
}

json FuzzImmEvent::get_results() const {
    json results;
    results["values"] = m_values;
    results["strings"] = m_strings;

    return results;
}
