#pragma once

#include <map>
#include <cstdint>
#include <vector>
#include <string>

#include "TraceAnalyzer.hpp"

struct Module;
struct log_fault;

class SymTraceAnalyzer : public TraceAnalyzer {
  public:
    SymTraceAnalyzer(std::map<uint64_t, Module> *mod_map);

    void output_header();
    void output_results();

  private:
    bool on_trace_elm(uint32_t modid, uint32_t offset, uint32_t pid, uint32_t tid, log_fault *fault);

    struct Result {
        uint64_t serial;
        uint32_t modid;
        uint32_t pid;
        uint32_t tid;
        uint32_t addr_offset;
        uint64_t block_id;
        uint32_t signum;
        std::string sym;
    };

    std::vector<Result> m_results;
};
