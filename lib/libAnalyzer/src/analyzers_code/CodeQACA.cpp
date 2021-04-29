#include <memory>
#include <cstdint>
#include <string>
#include <utility>

#include "json.hpp"
#include "capstone/capstone.h"
#include "glog/logging.h"

#include "SymResolver.hpp"

#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/CodeQACA.hpp"

struct Block;

CodeQACA::CodeQACA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver) :
    BaseCodeAnalyzer("code_qa", arch, mode),
    m_resolver(std::move(resolver)),
    m_sym_call_count(0) {

    for (const auto &sym : m_resolver->get_syms_by_addr()) {
        if (sym.second.type == sym_type::IMPORT && sym.second.obj_type == sym_obj_type::FUNC) {
            m_sym_calls.emplace(sym.first, 0);
        }
    }
};

int CodeQACA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    if (!call_sym) {
        return 0;
    }

    if (call_sym->type == sym_type::IMPORT && call_sym->obj_type == sym_obj_type::FUNC) {
        m_sym_call_count++;

        auto sym_count = m_sym_calls.find(call_sym->addr);
        if (sym_count != m_sym_calls.end()) {
            sym_count->second += 1;
        }
        else {
            LOG(FATAL) << "Called a symbol that was not in original internal map: " << call_sym->name << " 0x" << std::hex << call_sym->addr;
        }
    }

    return 0;
}

int CodeQACA::process_results() {
    uint64_t non_calls = 0;
    for (const auto &call : m_sym_calls) {
        if (call.second == 0) {
            non_calls += 1;
        }
    }

    m_results["imported_not_called"] = non_calls;
    m_results["imported_func_syms"] = m_sym_calls.size();
    m_results["imported_func_calls"] = m_sym_call_count;

    return 0;
}
