#include <memory>
#include <cstdint>
#include <utility>

#include "capstone/capstone.h"
#include "json.hpp"

#include "SymResolver.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/FuncBaseCA.hpp"
#include "analyzers_code/FuncCheckCA.hpp"

struct Block;

FuncCheckCA::FuncCheckCA(cs_arch arch, cs_mode mode,
        std::shared_ptr<SymResolver> resolver,
        std::vector<std::string> good_funcs,
        std::vector<std::string> risky_funcs,
        std::vector<std::string> bad_funcs,
        std::vector<std::string> ick_funcs) :
    FuncBaseCA("func_calls", arch, mode, std::move(resolver)) {

    for (const auto &func : good_funcs) {
        m_good_hits.emplace(func, 0);
    }
    for (const auto &func : risky_funcs) {
        m_risky_hits.emplace(func, 0);
    }
    for (const auto &func : bad_funcs) {
        m_bad_hits.emplace(func, 0);
    }
    for (const auto &func : ick_funcs) {
        m_ick_hits.emplace(func, 0);
    }
};

int FuncCheckCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    if (!call_sym) {
        return 0;
    }

    if (m_good_hits.count(call_sym->name)) {
        m_good_hits[call_sym->name]++;
        return 0;
    }
    else if (m_risky_hits.count(call_sym->name)) {
        m_risky_hits[call_sym->name]++;
        return 0;
    }
    else if (m_bad_hits.count(call_sym->name)) {
        m_bad_hits[call_sym->name]++;
        return 0;
    }
    else if (m_ick_hits.count(call_sym->name)) {
        m_ick_hits[call_sym->name]++;
        return 0;
    }


    return 0;
}

int FuncCheckCA::process_results() {
    for (auto it = m_good_hits.begin(); it != m_good_hits.end();) {
        if (it->second == 0) {
            m_good_hits.erase(it++);
        }
        else {
            ++it;
        }
    }
    for (auto it = m_risky_hits.begin(); it != m_risky_hits.end();) {
        if (it->second == 0) {
            m_risky_hits.erase(it++);
        }
        else {
            ++it;
        }
    }
    for (auto it = m_bad_hits.begin(); it != m_bad_hits.end();) {
        if (it->second == 0) {
            m_bad_hits.erase(it++);
        }
        else {
            ++it;
        }
    }
    for (auto it = m_ick_hits.begin(); it != m_ick_hits.end();) {
        if (it->second == 0) {
            m_ick_hits.erase(it++);
        }
        else {
            ++it;
        }
    }


    m_results["good_funcs"] = m_good_hits;
    m_results["risky_funcs"] = m_risky_hits;
    m_results["bad_funcs"] = m_bad_hits;
    m_results["ick_funcs"] = m_ick_hits;

    return 0;
}
