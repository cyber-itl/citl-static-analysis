#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include <map>

enum class sym_type {
    EXPORT = 0,
    IMPORT,
    HIDDEN
};

enum class sym_obj_type {
    NOTYPE = 0,
    OBJECT,
    FUNC,
    DEBUG
};

struct Symbol {
    Symbol() = default;
    Symbol(std::string name, uint64_t addr, sym_type type, sym_obj_type obj_type) :
        name(std::move(name)),
        addr(addr),
        type(type),
        obj_type(obj_type) {
        module = std::string();
    };
    Symbol(std::string name, uint64_t addr, std::string module, sym_type type, sym_obj_type obj_type, bool is_thumb = false) :
        name(std::move(name)),
        addr(addr),
        module(std::move(module)),
        type(type),
        obj_type(obj_type),
        is_thumb(is_thumb) {};

    std::string name;
    uint64_t addr;
    std::vector<std::string> alt_names;
    std::string module;
    bool is_thumb;
    sym_type type;
    sym_obj_type obj_type;
};

class SymResolver {
  public:
    virtual int generate_symbols() = 0;

    virtual int find_funcs() = 0;

    bool resolve_sym(uint64_t addr, const Symbol **sym_out) const;

    // Util
    void print_map() const;

    const std::map<uint64_t, Symbol> &get_syms_by_addr() const;

    const std::map<uint64_t, Symbol> &get_found_funcs() const;

    bool add_symbol(uint64_t addr, Symbol sym);

  protected:

    std::map<uint64_t, Symbol> m_syms_by_addr;
    std::map<uint64_t, Symbol> m_found_funcs;
};
