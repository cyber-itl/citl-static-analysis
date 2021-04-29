#include <memory>
#include <cstdint>
#include <utility>

#include "capstone/capstone.h"
#include "json.hpp"

#include "SymResolver.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/FuncBaseCA.hpp"
#include "analyzers_code/SelectableFuncsCA.hpp"

struct Block;

SelectableFuncsCA::SelectableFuncsCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver, std::vector<std::string> funcs) :
    FuncBaseCA("selected_funcs", arch, mode, std::move(resolver)), m_load_lib_funcs(std::move(funcs)) {};

int SelectableFuncsCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    if (!call_sym) {
        return 0;
    }
    for (const auto &func_name : m_load_lib_funcs) {
        if (call_sym->name == func_name) {
            if (m_load_lib_calls.count(call_sym->name)) {
                m_load_lib_calls[call_sym->name]++;
                return 0;
            }
            else {
                m_load_lib_calls.emplace(call_sym->name, 1);
            }
            break;
        }
    }


    return 0;
}

int SelectableFuncsCA::process_results() {
    m_results["selected_funcs_dict"] = m_load_lib_calls;

    return 0;
}
