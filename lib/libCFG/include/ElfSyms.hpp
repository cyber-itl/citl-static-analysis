#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <map>
#include <string>
#include <utility>

#include "capstone/capstone.h"
#include "glog/logging.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFObjectFile.h"

class CpuState;
class MemoryMap;
struct Block;

#include "SymResolver.hpp"


using namespace llvm;
using namespace object;

template <class ELFT>
class ElfSyms : public SymResolver {
  private:
    // Parsing helper structs
    struct SymTabSym {
        SymTabSym(uint64_t idx, uint64_t value, std::string sym, sym_obj_type type, bool undefined) :
            idx(idx),
            value(value),
            sym(sym),
            type(type),
            undefined(undefined) {};

        uint64_t idx;
        uint64_t value;
        std::string sym;
        sym_obj_type type;
        bool undefined;
    };

    struct Reloc {
        Reloc(std::string sym, sym_type type, uint32_t reloc_type, uint64_t value) :
            sym(std::move(sym)),
            type(type),
            reloc_type(reloc_type),
            value(value),
            symbolized(false) {};

        std::string sym;
        sym_type type;
        uint32_t reloc_type;
        uint64_t value;
        bool symbolized;
    };

    struct PltRange {
        PltRange(uint64_t start, uint64_t end, bool nobits) :
            start(start),
            end(end),
            nobits(nobits) {};
        uint64_t start;
        uint64_t end;
        bool nobits;
    };

    enum class insn_status {
        CONT = 0,
        SYMBOLIZE,
        FAILURE,
        STOP
    };

    struct StubState {
        void reset() {
            reloc_idx = 0;
            stub_addr = 0;
        }

        uint64_t reloc_idx {0};
        uint64_t stub_addr {0};
    };

    struct CIE {
        CIE(uint32_t fdee, uint32_t lsdae, uint32_t augment_len) : FDEencoding(fdee), LSDAEncoding(), hasAugmentationLength(augment_len == 0) {};
        uint32_t FDEencoding;
        uint32_t LSDAEncoding;
        bool hasAugmentationLength;
    };

  public:
    explicit ElfSyms(const ELFObjectFile<ELFT> *obj, const std::shared_ptr<MemoryMap> memmap);

    int generate_symbols() override;
    int find_funcs() override;

    struct DynTag {
        DynTag(uint64_t tag, uint64_t value) : tag(tag), value(value) {};
        uint64_t tag;
        uint64_t value;
    };
    const std::vector<DynTag> &get_dyn_tags() const;

  private:
    // Private members
    const ELFObjectFile<ELFT> *m_obj;
    const std::shared_ptr<MemoryMap> m_memmap;
    std::vector<DynTag> m_dyn_tags;
    std::vector<SymTabSym> m_symtab_syms;
    std::map<uint64_t, Reloc> m_relocs;

    unsigned int m_arch;
    bool m_is_stripped;

    // Arch specific saved data
    uint64_t m_mips_gp_reg;
    uint64_t m_x86_got_base;

    // Private parsing functions to be run ahead of symbolizing logic
    int parse_dynamic_tags();
    int parse_symtab();

    int parse_relocs();
    template <typename REL>
    void parse_plt_rels(const uint8_t *plt_rel_ptr, uint64_t plt_rel_size);

    std::vector<PltRange> parse_plts();

    int disasm_plt_iter(PltRange plt);

    insn_status plt_insn_x86(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block);
    insn_status plt_insn_arm(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block);
    insn_status plt_insn_arm64(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block);
    insn_status plt_insn_mips(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block);
    insn_status plt_insn_ppc(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block);

    int parse_section_syms();

    int parse_exports();

    // Arch specific handling
    int parse_mips_no_relocs();
    int find_ppc_plts(std::vector<PltRange> *plts);


    // function discovery parsing functions
    int parse_arm_unwind();
    int parse_init_fini();
    int parse_eh_data();
    std::vector<uint64_t> parse_eh_frame(uint64_t addr, uint64_t size, const char *data, uint64_t ehframe_val, uint64_t fde_count);

    // Utility functions mapping between our datatypes and the ELF types
    sym_obj_type map_elf_sym_type(uint8_t type);
    sym_obj_type map_elf_reloc_type(cs_arch arch, uint32_t type);
    sym_obj_type map_sym_type(uint8_t type);

    // Extra utility functions
    uint64_t read_word(uint64_t addr);

    // Templated code utils
    template <typename Type>
    ArrayRef<Type> static getAsArrayRef(const uint8_t *addr, uint64_t ent_size, uint64_t total_size) {
        const auto *start = reinterpret_cast<const Type *>(addr);

        if (!start) {
            return {start, start};
        }

        if (ent_size != sizeof(Type) || total_size % ent_size) {
            LOG(ERROR) << "Failed to create ArrayRef, invalid size: ent_size: 0x" << std::hex << ent_size << " total: 0x" << total_size;
            return {start, start};
        }
        return {start, start + (total_size / ent_size)};
    }

    template <typename T>
    std::vector<uint64_t> parse_array(const char *data, uint64_t size, bool byteswap = false) {
        std::vector<uint64_t> ret;
        if (!data) {
            return ret;
        }

        const auto *cast_data = reinterpret_cast<const T*>(data);
        if (!cast_data) {
            return ret;
        }

        for (uint64_t i = 0; i < (size / sizeof(T)); i++) {
            T value = cast_data[i];
            if (byteswap) {
                if (sizeof(T) == 8) {
                    value = __builtin_bswap64(value);
                }
                else if (sizeof(T) == 4) {
                    value = __builtin_bswap32(value);
                }
            }
            ret.emplace_back(value);
        }

        return ret;
    }

};
