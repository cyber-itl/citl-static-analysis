#include <memory>
#include <cstdint>
#include <utility>

#include "capstone/capstone.h"
#include "json.hpp"

#include "SymResolver.hpp"
#include "analyzers_code/FuncBaseCA.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/SandboxFuncCA.hpp"

struct Block;



SandboxFuncCA::SandboxFuncCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver) : FuncBaseCA("sandbox_calls", arch, mode, std::move(resolver)) {
    m_sandbox_funcs = {"chroot", "scm_chroot", "posix_chroot",
                       "_sandbox_init", "_sandbox_init_with_parameters", "_sandbox_init_with_extensions"};
};

int SandboxFuncCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    if (!call_sym) {
        return 0;
    }
    for (const auto &func_name : m_sandbox_funcs) {
        if (call_sym->name == func_name) {
            if (m_sandbox_calls.count(call_sym->name)) {
                m_sandbox_calls[call_sym->name]++;
                return 0;
            }
            else {
                m_sandbox_calls.emplace(call_sym->name, 1);
            }
            break;
        }
    }


    return 0;
}

int SandboxFuncCA::process_results() {
    m_results["sandbox_func_dict"] = m_sandbox_calls;

    return 0;
}
