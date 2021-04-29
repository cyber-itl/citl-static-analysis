#include <map>
#include <string>
#include <cstdint>
#include <iostream>

#include "glog/logging.h"

#include "TraceDefs.hpp"
#include "TraceAnalyzer.hpp"

TraceAnalyzer::TraceAnalyzer(std::map<uint64_t, Module> *mod_map, std::string name) :
    m_mod_map(mod_map),
    m_tc(nullptr),
    m_name(name),
    m_block_count(0) {};

bool TraceAnalyzer::run() {
    const uint8_t *ptr, *eptr = nullptr;

    if (m_tc->hascrash) {
        ptr = static_cast<const uint8_t *>(m_tc->fault_log);
        eptr = ptr + m_tc->fault_size;

        while(ptr < eptr)
        {
            log_fault *fault = (log_fault *)ptr;
            ptr += sizeof(log_fault);

            if (fault->bbslab_off > m_tc->trace_size) {
                LOG(ERROR) << "Invalid fault log offset";
                continue;
            }
            log_bbtrace *trace_block = (log_bbtrace *) (static_cast<const uint8_t *>(m_tc->trace_log) + fault->bbslab_off);

            if (fault->bbslab_idx > NUM_BBTRACE_PER_BLOCK) {
                LOG(ERROR) << "Invalid fault log index";
                continue;
            }

            m_fault_locs.emplace(&trace_block->comp_id[fault->bbslab_idx], fault);
        }
    }

    ptr = static_cast<const uint8_t *>(m_tc->trace_log);
    eptr = ptr + m_tc->trace_size;

    while (ptr < eptr) {
        const log_bbtrace *bb = reinterpret_cast<const log_bbtrace *>(ptr);
        ptr += sizeof(log_bbtrace);

        auto pid = LOGENT_GET_PID(bb->pidtid);
        auto tid = LOGENT_GET_TID(bb->pidtid);

        for (uint64_t i = 0; i < NUM_BBTRACE_PER_BLOCK && bb->comp_id[i]; i++) {
            uint32_t modid = bb->comp_id[i] >> 32;
            uint32_t offset = bb->comp_id[i] & ((1ULL << 32) - 1);

            log_fault *fault = nullptr;
            if (m_tc->hascrash) {
                auto fault_it = m_fault_locs.find(&bb->comp_id[i]);
                if (fault_it != m_fault_locs.end()) {
                    fault = fault_it->second;
                }
            }

            if (!this->on_trace_elm(modid, offset, pid, tid, fault)) {
                // LOG(WARNING) << "Failed to run on trace elm!";
            }
            m_block_count++;
        }
    }
    return true;
}

void TraceAnalyzer::set_testcase(TestCase *tc) {
    m_tc = tc;
    m_fault_locs.clear();
    m_block_count = 0;
}