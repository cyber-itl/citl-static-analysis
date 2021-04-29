#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>

#include "capstone/capstone.h"

#include "TraceAnalyzer.hpp"

struct Module;
struct log_fault;


class Lifter {
  public:
    /*
        No. of stack operation instructions:          push, pop
        No. of arithmetic instructions:               add, sub
        No. of logical instructions:                  and, or
        No. of comparative instructions:              test
        bool. of function calls/unconditional jumps:  call printf, jmp 0x4141, jmp [eax]
        bool. of conditional jump instructions:       jne, jb
        No. of load operations:                       mov eax, [ebx]
        No. of store operations:                      mov [eax], ebx
        No. of FPU operations:                        FNOP
    */

    enum insn_class {
        STACK_OP    = 0,
        ARITHMETIC  = 1,
        LOGICAL     = 2,
        COMP        = 3,
        CALL_TERM   = 4,
        COND_TERM   = 5,
        LOAD        = 6,
        STORE       = 7,
        FPU         = 8,
        CLASS_MAX   = 9,
    };

    Lifter();
    Lifter(cs_arch arch);

    bool check_mem_op_x86(cs_insn *insn, uint8_t load_op);
    bool check_stack(cs_insn *insn, uint8_t op_idx);

    std::vector<insn_class> update_x86(cs_insn *insn);
    std::vector<insn_class> update(cs_insn *insn);


    std::string class_to_str(insn_class insn_class);

  private:
    const char *insn_class_str[CLASS_MAX] = {
        "STACK_OP",
        "ARITHMETIC",
        "LOGICAL",
        "COMP",
        "CALL_TERM",
        "COND_TERM",
        "LOAD",
        "STORE",
        "FPU"
    };

    cs_arch m_arch;
};


class LiftingAnalyzer : public TraceAnalyzer {
  public:
    LiftingAnalyzer(std::map<uint64_t, Module> *mod_map);
    bool init();
    void output_header();
    void output_results();

  private:
    bool on_trace_elm(uint32_t modid, uint32_t offset, uint32_t pid, uint32_t tid, log_fault *fault);

    csh m_cs_handle;
    Lifter m_lifter;
};
