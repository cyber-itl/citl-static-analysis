#pragma once

#include <cstdint>
#include <string>
#include <map>

#include "capstone/capstone.h"

#include "TraceAnalyzer.hpp"

struct Module;
struct log_fault;

class DisasmAnalyzer : public TraceAnalyzer {
  public:
    DisasmAnalyzer(std::map<uint64_t, Module> *mod_map, std::string name = "disasm");
    bool init();
    void output_header();
    void output_results();

  protected:
    bool on_trace_elm(uint32_t modid, uint32_t offset, uint32_t pid, uint32_t tid, log_fault *fault);

    csh m_cs_handle;
};
