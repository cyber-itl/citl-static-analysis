#pragma once

#include <memory>
#include <map>
#include <cstdint>
#include <string>
#include <vector>

#include "llvm/Object/ObjectFile.h"
using namespace llvm;
using namespace object;

#include "Cfg.hpp"
#include "MemoryMap.hpp"
#include "SymResolver.hpp"

struct Module {
    OwningBinary<Binary> own_bin;
    const ObjectFile *obj;
    std::shared_ptr<MemoryMap> mem_map;
    std::shared_ptr<SymResolver> resolver;
    std::unique_ptr<Cfg> cfg;
    const std::map<block_range, Block, block_cmp> *block_map;
};

struct TestCase {
    uint64_t lastmutated;
    std::string lastmutator;
    uint64_t lastmut_offset;
    uint64_t serial;
    uint64_t parent_serial;
    std::vector<std::string> argv;
    std::vector<std::pair<std::string, std::string>> envp;
    std::string stdin_str;
    std::vector<std::pair<std::string, std::string>> files;
    bool hasrun;
    bool hascrash;
    uint64_t hitcnt;
    uint64_t msec_delta;
    uint64_t runs_total;
    std::vector<uint64_t> mod_ids;
    std::vector<std::string> getopt_strs;
    std::vector<std::string> unsat_envs;
    std::vector<std::string> unsat_files;
    bool uses_stdin;
    bool timed_out;
    bool bailed_out;
    void *trace_log;
    uint64_t trace_size;
    void *call_log;
    uint64_t call_size;
    void *fault_log;
    uint64_t fault_size;
};

// Taken from sfuzzer code....
#define NUM_BBTRACE_PER_BLOCK   127
#define LOGENT_GET_PID(x)       ((x) >> 32 & ((1ULL << 30) - 1))
#define LOGENT_GET_TID(x)       ((x) & ((1ULL << 32) - 1))

struct log_bbtrace {
    uint64_t pidtid;
    uint64_t comp_id[NUM_BBTRACE_PER_BLOCK];
} __attribute__((packed));

struct log_fault {
    uint64_t pidtid;
    uint32_t bbslab_off;
    uint32_t bbslab_idx;
    uint64_t addr;
    uint32_t signum;
} __attribute__((packed));

