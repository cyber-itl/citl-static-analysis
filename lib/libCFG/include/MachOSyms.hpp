#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "SymResolver.hpp"

#include "llvm/Object/MachO.h"
#include "llvm/Support/Endian.h"


using namespace llvm;
using namespace object;

class MachOSyms : public SymResolver {
  public:
    explicit MachOSyms(const MachOObjectFile *obj);

    int generate_symbols() override;

    int find_funcs() override;

  private:
    struct IndexEntry {
        IndexEntry(uint32_t func_offset, uint32_t second_level, uint32_t lsda_start) :
            FunctionOffset(func_offset),
            SecondLevelPageStart(second_level),
            LSDAStart(lsda_start) {};
        uint32_t FunctionOffset;
        uint32_t SecondLevelPageStart;
        uint32_t LSDAStart;
    };

    const MachOObjectFile *m_macho_obj;

    // Helper function for reading macho unwind info.
    template <typename T>
    static uint64_t readNext(const char *&Buf) {
        uint64_t Val = support::endian::read<T, llvm::support::little, llvm::support::unaligned>(Buf);
        Buf += sizeof(T);
        return Val;
    }

    std::map<uint64_t, Symbol> m_plt_sym_map;

    int parse_macho_unwind(const SectionRef &sec);

    int parse_indirect_table(uint32_t n, uint32_t count, uint32_t stride, uint64_t addr);
    int parse_macho_indirect();

    std::string getMachoOrdinalName(int ordinal) const;

};
