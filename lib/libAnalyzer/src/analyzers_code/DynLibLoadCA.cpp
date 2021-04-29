#include <memory>
#include <cstdint>
#include <utility>
#include <algorithm>

#include "capstone/capstone.h"
#include "json.hpp"

#include "SymResolver.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/FuncBaseCA.hpp"
#include "analyzers_code/DynLibLoadCA.hpp"

struct Block;

DynLibLoadCA::DynLibLoadCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver) :
    FuncBaseCA("load_lib", arch, mode, std::move(resolver))
{
    m_load_lib_funcs = {"LoadLibrary", "LoadLibraryA", "LoadLibraryW",
                        "LoadLibraryEx", "dlopen", "lt_dlopenext",
                        "lt_dlopen", "__interceptor_dlopen", "lt_dlopenadvise"};
};

int DynLibLoadCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
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

int DynLibLoadCA::process_results() {
    m_results["load_lib_dict"] = m_load_lib_calls;

    return 0;
}
