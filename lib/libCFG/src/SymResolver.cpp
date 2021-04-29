#include <sstream>
#include <cstdint>

#include "glog/logging.h"
#include "SymResolver.hpp"


void SymResolver::print_map() const {
    for (const auto &kv : m_syms_by_addr) {
        auto symbol = kv.second;

        std::stringstream ss;
        ss << "0x" << std::hex << kv.first;
        ss << " : ";
        if (symbol.type == sym_type::EXPORT) {
            ss << "(EXPORT: ";
        }
        else {
            ss << "(IMPORT: ";
        }
        switch (symbol.obj_type) {
        case sym_obj_type::FUNC:
            ss << "FUNC)";
            break;
        case sym_obj_type::NOTYPE:
            ss << "NOTYPE)";
            break;
        case sym_obj_type::OBJECT:
            ss << "OBJECT)";
            break;
        case sym_obj_type::DEBUG:
            ss << "DEBUG)";
            break;
        }

        ss << " ";

        if (symbol.module.empty()) {
            ss << symbol.name;
        }
        else {
            ss << symbol.module << ":" << symbol.name;
        }

        if (!symbol.alt_names.empty()) {
            ss << " | alt names: ";
            for (const auto &sym : symbol.alt_names) {
                ss << sym << ", ";
            }
        }
        LOG(INFO) << " " << ss.str();
    }
}

const std::map<uint64_t, Symbol> &SymResolver::get_syms_by_addr() const {
    return m_syms_by_addr;
}

const std::map<uint64_t, Symbol> &SymResolver::get_found_funcs() const {
    return m_found_funcs;
}

bool SymResolver::add_symbol(uint64_t addr, Symbol sym) {
    m_syms_by_addr.emplace(addr, sym);

    return true;
}

bool SymResolver::resolve_sym(uint64_t addr, const Symbol **sym_out) const {
    auto it = m_syms_by_addr.find(addr);
    if (it != m_syms_by_addr.end()) {
        *sym_out = &it->second;
        return true;
    }

    return false;
}