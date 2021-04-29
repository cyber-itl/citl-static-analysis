#pragma once

#include <map>
#include <string>
#include <cstdint>

struct Module;
struct TestCase;
struct log_fault;

class TraceAnalyzer {
  public:
    TraceAnalyzer(std::map<uint64_t, Module> *mod_map, std::string name);
    TraceAnalyzer(const TraceAnalyzer &other);
    virtual ~TraceAnalyzer() = default;

    bool run();
    void set_testcase(TestCase *tc);
    std::string m_name;

    virtual bool init() { return true; };
    virtual void output_header() = 0;
    virtual void output_results() = 0;

  protected:
    virtual bool on_trace_elm(uint32_t modid, uint32_t offset, uint32_t pid, uint32_t tid, log_fault *fault) = 0;

    std::map<uint64_t, Module> *m_mod_map;
    TestCase *m_tc;
    std::map<const uint64_t*, log_fault*> m_fault_locs;
    uint64_t m_block_count;
    bool inited = false;
};
