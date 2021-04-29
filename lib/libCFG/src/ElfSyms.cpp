#include <algorithm>
#include <system_error>
#include <tuple>


#include "gflags/gflags.h"
#include "glog/logging.h"
#include "capstone/capstone.h"

#include "CfgRes.hpp"
#include "DwarfReader.hpp"
#include "MemoryMap.hpp"
#include "SymResolver.hpp"
#include "ElfSyms.hpp"
#include "CapstoneHelper.hpp"
#include "CpuState.hpp"
#include "Block.hpp"

#include "llvm/Object/ELF.h"
#include "llvm/Support/Endian.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Error.h"

using namespace llvm;


DEFINE_bool(print_dyn_tags, false, "Toggles printing of PT_DYNAMIC tags");
DEFINE_bool(print_symtab, false, "Toggles printing of PT_DYNAMIC symtab syms");
DEFINE_bool(print_relocs, false, "Toggles printing of PT_DYNAMIC relocs");
DEFINE_bool(print_plts, false, "Toggles printing of discovered PLT ranges");


template <class ELFT>
ElfSyms<ELFT>::ElfSyms(const ELFObjectFile<ELFT> *obj, const std::shared_ptr<MemoryMap> memmap) :
    m_obj(obj),
    m_memmap(memmap),
    m_arch(obj->getArch()),
    m_is_stripped(false),
    m_mips_gp_reg(0),
    m_x86_got_base(0) {};


template <class ELFT>
const std::vector<typename ElfSyms<ELFT>::DynTag> &ElfSyms<ELFT>::get_dyn_tags() const {
    return m_dyn_tags;
}

template <class ELFT>
int ElfSyms<ELFT>::generate_symbols() {
    if (m_obj->section_begin() == m_obj->section_end()) {
        this->m_is_stripped = true;
    }

    do {
        if (this->parse_dynamic_tags()) {
            LOG(ERROR) << "Failed to find dynamic tags, most likely a static elf file";
            break;
        }

        if (this->parse_symtab()) {
            LOG(ERROR) << "Failed to parse dynamic symtab";
            break;
        }

        if (this->parse_relocs()) {
            if (m_arch == Triple::mips || m_arch == Triple::mipsel || m_arch == Triple::mips64 || m_arch == Triple::mips64el) {
                if (this->parse_mips_no_relocs()) {
                    LOG(FATAL) << "Failed to parse mips missing relocs";
                }
            }
            else {
                LOG(ERROR) << "Failed to parse relocs without a backup for the arch";
                break;
            }
        }

        if (m_relocs.begin() != m_relocs.end()) {
            auto plts = this->parse_plts();

            if (plts.empty()) {
                // Default to using the direct .got / reloc entries as symbols
                LOG(INFO) << "No plts found, defaulting to reloc / .got entries as symbols";
                for (auto &kv : m_relocs) {
                    bool is_thumb = false;
                    auto addr = kv.second.value;
                    if (m_arch == Triple::arm || m_arch == Triple::armeb) {
                        is_thumb = ((kv.second.value & 1) == 1);
                        addr--;
                    }
                    m_syms_by_addr.emplace(addr, Symbol(kv.second.sym,
                                                        addr,
                                                        std::string(),
                                                        kv.second.type,
                                                        sym_obj_type::FUNC,
                                                        is_thumb));
                    kv.second.symbolized = true;
                }
            }
            else {
                LOG(INFO) << "Found PLTs, using disassembly iterators";
                for (const auto &plt : plts) {
                    // LOG(INFO) << "Starting plt at: 0x" << std::hex << plt.start;
                    this->disasm_plt_iter(plt);
                }
            }

            // TODO: pull out GLOB_DAT relocs and symbolize them? Old code only did it for RELA values

            // Do a final pass and any reloc not symbolized we will default the reloc address
            // to the symbol address.  This catches mixed plt / reloc binaries (commonly __libc_start_main)
            // NOTE:
            // Sometimes functions like lxstat* and xstat* will have a wrapper stub placed into the .text
            // this is because most *stat functions are just wrappers, these stubs are not true PLT's but
            // act like them.  We won't correctly get all the counts of those function calls but finding them
            // would require the CFG driven symbol discover and we can't support that at the moment.
            for (auto &kv : m_relocs) {
                if (kv.second.symbolized) {
                    continue;
                }
                if (kv.second.type != sym_type::IMPORT) {
                    continue;
                }

                bool is_thumb = false;
                if (m_arch == Triple::arm || m_arch == Triple::armeb) {
                    bool is_thumb = ((kv.second.value & 1) == 1);
                }
                m_syms_by_addr.emplace(kv.second.value, Symbol(kv.second.sym,
                                                    kv.second.value,
                                                    std::string(),
                                                    kv.second.type,
                                                    sym_obj_type::FUNC,
                                                    is_thumb));
                kv.second.symbolized = true;
            }
        }
    } while (false);

    if (this->parse_exports()) {
        LOG(ERROR) << "Failed to parse export functions out of symtab";
    }

    if (!m_is_stripped) {
        if (this->parse_section_syms()) {
            LOG(ERROR) << "Failed to parse symbol table from sections";
        }
    }
    // TODO: If not stripped, check the symbol table for syms with values and add them.

    this->find_funcs();

    // Clean up internal containers;
    this->m_symtab_syms.clear();
    this->m_relocs.clear();

    return 0;
}

template <class ELFT>
int ElfSyms<ELFT>::find_funcs() {
    if (this->parse_init_fini()) {
        LOG(WARNING) << "Failed to parse init/fini array's";
    }

    if (this->parse_arm_unwind()) {
        LOG(WARNING) << "Failed to parse arm unwinding info";
    }

    if (this->parse_eh_data()) {
        LOG(WARNING) << "Failed to parse EH frame data";
    }

    return 0;
}


template <class ELFT>
int ElfSyms<ELFT>::parse_dynamic_tags() {
    const ELFFile<ELFT> *elf_file = m_obj->getELFFile();
    if (!elf_file) {
        LOG(FATAL) << "ELFFile object missing from inside ELFObjectFile";
    }
    bool found_dynamic = false;

    if (!m_is_stripped) {
        for (const SectionRef &section: m_obj->sections()) {
            Expected<StringRef> nameOrErr = section.getName();
            if (!nameOrErr) {
                std::error_code EC = errorToErrorCode(nameOrErr.takeError());
                LOG(ERROR) << "Failed to get section name: " << EC.message();
                continue;
            }
            auto sect_name = *nameOrErr;

            if (sect_name != ".dynamic") {
                continue;
            }

            if (section.isVirtual()) {
                LOG(WARNING) << "Virtual .dynamic section, failed to get dyn tags";
                break;
            }

            auto data_ptr = m_memmap->addr_to_ptr(section.getAddress());
            if (!data_ptr) {
                LOG(ERROR) << "unable to get .dynamic section contents";
                break;
            }
            uint64_t sect_size = section.getSize();
            if (!sect_size) {
                LOG(WARNING) << ".dynamic section has zero size, failed to get dyn tags";
                break;
            }

            auto dyn_array = this->getAsArrayRef<typename ELFFile<ELFT>::Elf_Dyn>(data_ptr, sizeof(typename ELFFile<ELFT>::Elf_Dyn), sect_size);
            for (const auto &dyn : dyn_array) {
                if (dyn.getTag() == ELF::DT_NULL) {
                    break;
                }
                m_dyn_tags.emplace_back(dyn.getTag(), dyn.getVal());
            }
            found_dynamic = true;
        }
    }
    // Stripped binary
    else {
        auto ProgramHeaderOrError = elf_file->program_headers();
        if (!ProgramHeaderOrError) {
            LOG(ERROR) << "Failed to get program headers";
            return 1;
        }

        if (ProgramHeaderOrError->empty() || !ProgramHeaderOrError->data()) {
            LOG(ERROR) << "Bad Program headers in ELF file";
            return 1;
        }

        for (const typename ELFFile<ELFT>::Elf_Phdr &p_hdr : *ProgramHeaderOrError) {
            if (p_hdr.p_type == ELF::PT_DYNAMIC) {
                auto dyn_ptr = m_memmap->addr_to_ptr(p_hdr.p_vaddr);
                if (!dyn_ptr) {
                    LOG(ERROR) << "Invalid p_vaddr for PT_DYNAMIC in stripped binary: 0x" << std::hex << p_hdr.p_vaddr;
                    break;
                }

                auto dyn_page = m_memmap->addr_to_page(p_hdr.p_vaddr);
                if (!dyn_page) {
                    LOG(FATAL) << "Unable to get memmap page for vaddr: 0x" << std::hex << p_hdr.p_vaddr;
                }

                uint64_t dyn_size = p_hdr.p_memsz;

                if (dyn_size > dyn_page->size) {
                    LOG(FATAL) << "Invalid elf PT_DYNAMIC size: 0x" << std::hex << dyn_size;
                }

                const auto *dyn = reinterpret_cast<const typename ELFFile<ELFT>::Elf_Dyn *>(dyn_ptr);
                if (!dyn) {
                    LOG(FATAL) << "Invalid dynamic ptr";
                }

                while (dyn->getTag() != ELF::DT_NULL) {
                    m_dyn_tags.emplace_back(dyn->getTag(), dyn->getVal());
                    dyn++;
                }

                found_dynamic = true;
                break;
            }
        }
    }

    if (FLAGS_print_dyn_tags) {
        LOG(INFO) << "PT_DYNAMIC TAGS:";
        for (const auto &tag : m_dyn_tags) {
            LOG(INFO) << "tag: 0x" << std::hex << tag.tag << " : " << tag.value;
        }
    }

    if (!found_dynamic) {
        return 1;
    }

    return 0;
}

template <class ELFT>
int ElfSyms<ELFT>::parse_symtab() {
    const uint8_t *symtab_ptr = nullptr;
    const uint8_t *strtab_ptr = nullptr;
    const uint8_t *gnuhash_ptr = nullptr;
    uint64_t strtab_size = 0;

    if (!m_dyn_tags.size()) {
        LOG(FATAL) << "no dynamic tags found, unable to parse symtab";
    }

    for (const auto &dyn : m_dyn_tags) {
        switch (dyn.tag) {
        case ELF::DT_SYMTAB:
            symtab_ptr = m_memmap->addr_to_ptr(dyn.value);
            if (!symtab_ptr) {
                LOG(WARNING) << "Failed to get DT_SYMTAB pointer from addr: 0x" << std::hex << dyn.value;
            }
            break;
        case ELF::DT_STRTAB:
            strtab_ptr = m_memmap->addr_to_ptr(dyn.value);
            if (!strtab_ptr) {
                LOG(WARNING) << "Failed to get DT_STRTAB pointer from addr: 0x" << std::hex << dyn.value;
            }
            break;
        case ELF::DT_STRSZ:
            strtab_size = dyn.value;
            break;
        case ELF::DT_GNU_HASH:
            gnuhash_ptr = m_memmap->addr_to_ptr(dyn.value);
            break;
        default:
            continue;
        }
    }

    if (!symtab_ptr || !strtab_ptr) {
        LOG(FATAL) << "PT_DYNAMIC missing symtab or strtab";
    }
    if (!strtab_size) {
        LOG(FATAL) << "PT_DYNAMIC missing strtab_size";
    }

    uint64_t symtab_size = 0;
    if (gnuhash_ptr && ( ( (strtab_ptr < gnuhash_ptr) && (gnuhash_ptr < symtab_ptr) ) ||
            ( (strtab_ptr > gnuhash_ptr) && (gnuhash_ptr > symtab_ptr) ) ) ) {
        LOG(INFO) << "Gnu hash between symtab and strtab, resorting to checking sections";
        CHECK(!m_is_stripped) << "Unsupported, gnu hash between strtab and symtab, no way to find symtab size";

        for (const auto &section : m_obj->sections()) {
            Expected<StringRef> nameOrErr = section.getName();
            if (!nameOrErr) {
                std::error_code EC = errorToErrorCode(nameOrErr.takeError());
                LOG(ERROR) << "Failed to get section name: " << EC.message();
                continue;
            }
            auto sect_name = *nameOrErr;

            if (sect_name == ".dynsym") {
                symtab_size = section.getSize();
                break;
            }
        }
    }
    else {
        symtab_size = std::abs(strtab_ptr - symtab_ptr);
    }

    if (!symtab_size) {
        LOG(FATAL) << "Invalid symtab_size: 0x" << std::hex << symtab_size << "elm size: 0x" << std::hex << sizeof(typename ELFT::Sym);
    }

    symtab_size = symtab_size / sizeof(typename ELFT::Sym);

    const auto syms = reinterpret_cast<const typename ELFT::Sym *>(symtab_ptr);
    for (uint64_t i = 0; i < symtab_size; i++) {
        auto sym = syms[i];
        CHECK(sym.st_name < strtab_size) << "Invalid st_name value: 0x" << std::hex << sym.st_name << " strtab_size: 0x" << strtab_size;

        auto sym_str = std::string(reinterpret_cast<const char *>(strtab_ptr + sym.st_name));

        auto elf_type = sym.getType();
        auto sym_val = sym.getValue();
        auto type = this->map_elf_sym_type(elf_type);

        m_symtab_syms.emplace_back(i, sym.st_value, sym_str, type, sym.isUndefined());
    }

    if (FLAGS_print_symtab) {
        LOG(INFO) << "PT_DYNAMIC symtab syms:";
        for (const auto &sym : m_symtab_syms) {
            LOG(INFO) << sym.idx << " | "
                      << static_cast<uint32_t>(sym.type) << " | "
                      << sym.undefined << " | "
                      << std::hex << sym.value << " | "
                      << sym.sym;
        }
    }

    return 0;
}

template <class ELFT>
int ElfSyms<ELFT>::parse_relocs() {
    // Parse only the JUMP_SLOT relocs to find function relocations
    if (!m_dyn_tags.size()) {
        LOG(FATAL) << "no dynamic tags found, unable to parse symtab";
    }

    const uint8_t *rel_ptr = nullptr;
    uint64_t rel_size = 0;

    const uint8_t *rela_ptr = nullptr;
    uint64_t rela_size = 0;

    const uint8_t *plt_rel_ptr = nullptr;
    uint64_t plt_rel_size = 0;
    uint64_t plt_rel_type = ELF::DT_NULL;


    for (const auto &dyn : m_dyn_tags) {
        switch (dyn.tag) {
        // PLT REL/RELA
        case ELF::DT_JMPREL:
            plt_rel_ptr = m_memmap->addr_to_ptr(dyn.value);
            if (!plt_rel_ptr) {
                LOG(WARNING) << "Failed to get DT_JMPREL pointer from addr: 0x" << std::hex << dyn.value;
            }
            break;
        case ELF::DT_PLTREL:
            plt_rel_type = dyn.value;
            break;
        case ELF::DT_PLTRELSZ:
            plt_rel_size = dyn.value;
            break;

        // REL
        case ELF::DT_REL:
            if (!dyn.value) {
                break;
            }
            rel_ptr = m_memmap->addr_to_ptr(dyn.value);
            if (!rel_ptr) {
                LOG(WARNING) << "Failed to get DT_REL pointer from addr: 0x" << std::hex << dyn.value;
            }
            break;
        case ELF::DT_RELSZ:
            rel_size = dyn.value;
            break;

        // RELA
        case ELF::DT_RELA:
            if (!dyn.value) {
                break;
            }
            rela_ptr = m_memmap->addr_to_ptr(dyn.value);
            if (!rela_ptr) {
                LOG(WARNING) << "Failed to get DT_RELA pointer from addr: 0x" << std::hex << dyn.value;
            }
            break;
        case ELF::DT_RELASZ:
            rela_size = dyn.value;
            break;

        default:
            continue;
        }
    }

    bool parse_one = false;
    if (plt_rel_ptr && plt_rel_size && plt_rel_type != ELF::DT_NULL) {
        if (plt_rel_type == ELF::DT_REL) {
            this->parse_plt_rels<typename ELFT::Rel>(plt_rel_ptr, plt_rel_size);
        }
        else if (plt_rel_type == ELF::DT_RELA) {
            this->parse_plt_rels<typename ELFT::Rela>(plt_rel_ptr, plt_rel_size);
        }
        parse_one = true;
    }
    if (rela_ptr && rela_size) {
        this->parse_plt_rels<typename ELFT::Rela>(rela_ptr, rela_size);
        parse_one = true;
    }
    if (rel_ptr && rel_size) {
        this->parse_plt_rels<typename ELFT::Rel>(rel_ptr, rel_size);
        parse_one = true;
    }

    if (!parse_one || !m_relocs.size()) {
        return 1;
    }

    if (FLAGS_print_relocs) {
        LOG(INFO) << "DYNAMIC function relocs:";
        for (const auto &reloc : m_relocs) {
            LOG(INFO) << "0x" << std::hex << reloc.first
                      << " : " << reloc.second.sym
                      << " : val: 0x" << reloc.second.value
                      << " : type: " << static_cast<uint32_t>(reloc.second.type);
        }
    }

    return 0;
}

template <class ELFT>
template <typename REL>
void ElfSyms<ELFT>::parse_plt_rels(const uint8_t *plt_rel_ptr, uint64_t plt_rel_size) {
    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(m_arch);
    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    const ELFFile<ELFT> *elf_file = m_obj->getELFFile();
    if (!elf_file) {
        LOG(FATAL) << "ELFFile object missing from inside ELFObjectFile";
    }

    const auto rels = reinterpret_cast<const REL *>(plt_rel_ptr);
    uint64_t rels_size = plt_rel_size / sizeof(REL);
    for (uint64_t i = 0; i < rels_size; i++) {
        auto rel = rels[i];

        auto reloc_sym_idx = rel.getSymbol(elf_file->isMips64EL());
        if (reloc_sym_idx >= m_symtab_syms.size()) {
            LOG(WARNING) << "Invalid reloc index: 0x" << std::hex << reloc_sym_idx;
            continue;
        }
        auto symtab_sym = m_symtab_syms.at(reloc_sym_idx);
        auto reloc_type = rel.getType(elf_file->isMips64EL());

        auto type = sym_type::IMPORT;
        if (symtab_sym.value) {
            type = sym_type::EXPORT;
        }
        // Architecture specific parsing here,
        //  Different arch index into the relocs differently, some by idx and some by offset directly
        //  This is dependent on the plt stubs.  We make an assumption about the plt style here.
        //  In the future we might consider 'sampling' the stubs if possible to determine a format.

        if (this->map_elf_reloc_type(arch, reloc_type) == sym_obj_type::FUNC &&
                (symtab_sym.type == sym_obj_type::FUNC | symtab_sym.type == sym_obj_type::NOTYPE)) {
            if (arch == cs_arch::CS_ARCH_ARM || arch == cs_arch::CS_ARCH_ARM64) {
                m_relocs.emplace(rel.r_offset, Reloc(symtab_sym.sym, type, reloc_type, rel.r_offset));
            }
            else if (arch == cs_arch::CS_ARCH_X86) {
                m_relocs.emplace(rel.r_offset, Reloc(symtab_sym.sym, type, reloc_type, rel.r_offset));
            }
            else if (arch == cs_arch::CS_ARCH_PPC) {
                if (mode & cs_mode::CS_MODE_32) {
                    m_relocs.emplace(rel.r_offset, Reloc(symtab_sym.sym, type, reloc_type, rel.r_offset));
                }
                else {
                    LOG(FATAL) << "Invalid ppc mode: " << static_cast<int>(mode);
                }
            }
            else if (arch == cs_arch::CS_ARCH_MIPS) {
                if (mode & cs_mode::CS_MODE_32) {
                    m_relocs.emplace(rel.r_offset, Reloc(symtab_sym.sym, type, reloc_type, rel.r_offset));
                }
            }
            else {
                LOG(FATAL) << "Unsupported arch for reloc parsing";
            }
        }
    }
}

template <class ELFT>
std::vector<typename ElfSyms<ELFT>::PltRange> ElfSyms<ELFT>::parse_plts() {
    // plts: <start_addr, end_addr>
    std::vector<PltRange> plts;

    // x86-32 got specific values we are going to pull out
    uint64_t got_addr = 0;
    uint64_t got_plt_addr = 0;

    if (!m_is_stripped) {
        for (const auto &section : m_obj->sections()) {
            Expected<StringRef> nameOrErr = section.getName();
            if (!nameOrErr) {
                std::error_code EC = errorToErrorCode(nameOrErr.takeError());
                LOG(ERROR) << "Failed to get section name: " << EC.message();
                continue;
            }
            auto sect_name = *nameOrErr;

            if (sect_name == ".plt" ||
                sect_name == ".plt.got" ||
                sect_name == ".MIPS.stubs") {

                auto addr = section.getAddress();
                auto nobits = section.isVirtual();

                if (nobits) {
                    continue;
                }

                plts.emplace_back(addr, (addr + section.getSize()), nobits);
            }

            if (m_arch == Triple::x86) {
                if (sect_name == ".got") {
                    got_addr = section.getAddress();
                }
                if (sect_name == ".got.plt") {
                    got_plt_addr = section.getAddress();
                }
            }
        }
    }

    if (m_arch == Triple::x86) {
        if (!got_plt_addr) {
            if (!got_addr) {
                LOG(ERROR) << "Failed to find got address in sections for x86-32 binary";
            }
            else {
                m_x86_got_base = got_addr;
            }
        }
        else {
            m_x86_got_base = got_plt_addr;
        }
    }

    // PPC has a very odd setup for how it does its BSS plt's with -secure-plt,
    // we need to search the .text segment backwards looking for the plt stubs.
    if (m_arch == Triple::ppc && plts.size()) {
        plts.clear();
        if (this->find_ppc_plts(&plts)) {
            LOG(ERROR) << "Failed to discover plt ranges in ppc32 text segment";
            return plts;
        }
    }
    else {
        if (!plts.size()) {
            uint64_t possible_plt_addr = 0;

            if (!m_mips_gp_reg) {
                for (const auto &kv : m_relocs) {
                    auto reloc_val = kv.second.value;
                    auto read_val = this->read_word(reloc_val);

                    if (!read_val) {
                        continue;
                    }
                    // LOG(INFO) << "Found plt val: 0x" << std::hex << read_val << " at: 0x" << kv.second.value;
                    possible_plt_addr = read_val;
                    m_x86_got_base = reloc_val;
                    break;
                }
            }
            else {
                uint64_t cur_idx = -1;
                for (const auto &kv : m_relocs) {
                    if (kv.second.value < cur_idx) {
                        cur_idx = kv.second.value;
                    }
                }

                if (cur_idx != -1) {
                    possible_plt_addr = cur_idx;
                }
            }
            if (!possible_plt_addr) {
                LOG(ERROR) << "Unable to find any PLT, attempt scanning .text";
                return plts;
            }

            if (m_arch == Triple::ppc) {
                // If we are a PPC32 binary, the values at the address held in the reloc are: 0x4800 0x-OFFSET.
                // The offset is from the current address backwards which points to the PLT stub. Fetching the
                // first value and calculating:
                //  first_plt_addr = RELOC_VALUE_ADDR - ((LOWER_16_BITS + 4)  * 4)
                // Should give us the first plt address.
                do {
                    auto read_val = this->read_word(possible_plt_addr);
                    if (!read_val) {
                        LOG(WARNING) << "Invalid read value at 0x" << std::hex << possible_plt_addr << " while probing ppc32 reloc value";
                        break;
                    }


                    auto high_val = read_val >> 16;
                    auto low_val = read_val & 0xffff;

                    // Found the trigger
                    if (high_val == 0x4800) {
                        possible_plt_addr = possible_plt_addr - ((low_val + 4) * 4);
                        LOG(INFO) << "Probed PPC32 relocs and found PLT start addr: 0x" << std::hex << possible_plt_addr;
                    }
                } while (false);
            }
            // LOG(INFO) << "Found PLT addr: 0x" << std::hex << possible_plt_addr;
            auto plt_page = m_memmap->addr_to_page(possible_plt_addr);
            CHECK(plt_page) << "Failed to fetch PLT page at addr: 0x" << std::hex << possible_plt_addr;

            // In x86 the first entry in the relocs will point to the linker stub, and so just past the
            // actual first jmp instruction, we need to bump the address back by the width of a:
            //  or jmp [ADDR]
            if (m_arch == Triple::x86 || m_arch == Triple::x86_64) {
                auto new_plt_addr = possible_plt_addr - 6;
                if (new_plt_addr < plt_page->address) {
                    LOG(FATAL) << "Invalid x86-32 plt start correction, new plt addr: 0x" << std::hex << new_plt_addr;
                }
                possible_plt_addr = new_plt_addr;
            }

            plts.emplace_back(possible_plt_addr, possible_plt_addr + plt_page->size, plt_page->empty_page);
        }
    }

    if (FLAGS_print_plts) {
        LOG(INFO) << "PLT ranges:";
        for (const auto &plt : plts) {
            LOG(INFO) << "0x" << std::hex << plt.start << " : 0x" << plt.end << "  nobits: " << plt.nobits;
        }
        LOG(INFO) << "x86-32 got base: 0x" << std::hex << m_x86_got_base;
    }

    return plts;
}

template <class ELFT>
int ElfSyms<ELFT>::disasm_plt_iter(typename ElfSyms<ELFT>::PltRange plt) {
    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(m_arch);
    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    csh handle;

    cs_err err;
    err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        LOG(INFO) << "cs_open: " << cs_strerror(err);
        return 1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn *insn = cs_malloc(handle);
    if (!insn) {
        LOG(FATAL) << "Failed to alloc insn in ply disasm iterator";
    }

    auto plt_page = m_memmap->addr_to_page(plt.start);
    CHECK(plt_page) << "Failed to find PLT memory page for address: 0x" << std::hex << plt.start;

    auto plt_ptr = m_memmap->addr_to_ptr(plt.start);
    CHECK(plt_ptr) << "Failed to find ptr to plt addr: 0x" << std::hex << plt.start;

    uint64_t max_size = plt_page->size;

    auto state = StubState();
    auto cpu_state = CpuState(arch, m_memmap);

    if (m_arch == Triple::x86 && m_x86_got_base) {
        cpu_state.set_reg_val_32(X86_REG_EBX, m_x86_got_base);
    }

    auto tmp_block = Block(plt.start);
    tmp_block.mode = mode;

    while(cs_disasm_iter(handle, &plt_ptr, &max_size, &plt.start, insn)) {
        cs_insn cur_insn = *insn;
        // LOG(INFO) << " 0x" << std::hex << cur_insn.address << " : " << cur_insn.mnemonic << " " << cur_insn.op_str;

        insn_status status;
        switch (arch) {
        case cs_arch::CS_ARCH_X86:
            status = this->plt_insn_x86(&cur_insn, state, mode, &cpu_state, &tmp_block);
            break;
        case cs_arch::CS_ARCH_ARM:
            status = this->plt_insn_arm(&cur_insn, state, mode, &cpu_state, &tmp_block);
            break;
        case cs_arch::CS_ARCH_ARM64:
            status = this->plt_insn_arm64(&cur_insn, state, mode, &cpu_state, &tmp_block);
            break;
        case cs_arch::CS_ARCH_MIPS:
            status = this->plt_insn_mips(&cur_insn, state, mode, &cpu_state, &tmp_block);
            break;
        case cs_arch::CS_ARCH_PPC:
            status = this->plt_insn_ppc(&cur_insn, state, mode, &cpu_state, &tmp_block);
            break;
        default:
            LOG(FATAL) << "Unsupported strippped PLT walking architecture: " << static_cast<int>(arch);
        }

        bool break_loop = false;
        switch (status) {
        case insn_status::FAILURE:
            LOG(FATAL) << "plt walking instruction handler failed at: 0x" << std::hex << cur_insn.address;
            break;
        case insn_status::SYMBOLIZE: {
            CHECK(state.stub_addr) << "plt_insn_* returned a SYMBOLIZE status but with no strtab data";
            auto reloc_it = m_relocs.find(state.reloc_idx);
            if (reloc_it == m_relocs.end()) {
                LOG(WARNING) << "Failed to find reloc idx: 0x" << std::hex << state.reloc_idx << " at 0x" << insn->address;
                break;
            }

            // LOG(INFO) << "Found sub sym: 0x" << std::hex << state.stub_addr << " : " << reloc_it->second.sym;
            auto mapped_type = this->map_elf_reloc_type(arch, reloc_it->second.reloc_type);
            m_syms_by_addr.emplace(state.stub_addr, Symbol(reloc_it->second.sym, state.stub_addr, std::string(), sym_type::IMPORT, mapped_type, false));
            reloc_it->second.symbolized = true;

            state.reset();

            // stop if we hit the end of our relocs, this will break with out of order relocs
            // needed for ARM because there is not guaranteed a padding between then next major func
            // and the plt stubs
            if (m_arch == Triple::arm && m_arch == Triple::armeb) {
                if (reloc_it->first == m_relocs.rbegin()->first) {
                    break_loop = true;
                }
            }

            break;
        }
        case insn_status::STOP:
            break_loop = true;
            break;
        case insn_status::CONT:
            break;
        }


        if (break_loop) {
            break;
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);

    return 0;
}


template <class ELFT>
typename ElfSyms<ELFT>::insn_status ElfSyms<ELFT>::plt_insn_x86(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block) {
    cs_x86 x86 = insn->detail->x86;

    CHECK(cpu_state) << "Invalid CpuState object";
    cpu_state->at_insn(insn, block);

    switch (insn->id) {
    case X86_INS_JMP: {
        if (x86.op_count < 1) {
            LOG(FATAL) << "Invalid x86 jmp insn at: 0x" << std::hex << insn->address;
        }
        cs_x86_op op0 = x86.operands[0];

        if (op0.type == X86_OP_IMM) {
            break;
        }
        else if (op0.type == X86_OP_MEM) {
            state.reset();
            state.stub_addr = insn->address;

            auto op0_res = cpu_state->get_op_read_addr(insn, op0, block->mode);
            if (!op0_res) {
                LOG(FATAL) << "Failed to get op0 value at 0x" << std::hex << insn->address;
            }
            state.reloc_idx = *op0_res;
            return insn_status::SYMBOLIZE;
        }
        break;
    }
    case X86_INS_XOR:
    case X86_INS_MOV:
    case X86_INS_CALL:
        return insn_status::STOP;
    }

    return insn_status::CONT;
}

template <class ELFT>
typename ElfSyms<ELFT>::insn_status ElfSyms<ELFT>::plt_insn_arm(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block) {
    cs_arm arm = insn->detail->arm;

    CHECK(cpu_state) << "Invalid CpuState object";
    cpu_state->at_insn(insn, block);

    /*
     * 00005738  adr     r12, 0x5740
     * 0000573c  add     r12, r12, #0x22000
     * 00005740  ldr     pc, [r12,  #0x3f8]!  {__libc_start_main@GOT}  {__libc_start_main@GOT}
     */

    switch (insn->id) {
    case ARM_INS_ADD: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid ARM add at: 0x" << std::hex << insn->address;
        }
        cs_arm_op op0 = arm.operands[0];
        cs_arm_op op1 = arm.operands[1];
        cs_arm_op op2 = arm.operands[2];

        if (op0.type != ARM_OP_REG || op1.type != ARM_OP_REG) {
            break;
        }

        // Is pc relative adr
        if (op0.reg == arm_reg::ARM_REG_IP && op1.reg == arm_reg::ARM_REG_PC) {
            if (op2.type == ARM_OP_IMM) {
                state.reset();
                state.stub_addr = insn->address;
            }
        }

        break;
    }
    case ARM_INS_LDR: {
        if (arm.op_count < 2) {
            LOG(FATAL) << "Invalid arm ldr instruction at: 0x" << std::hex << insn->address;
        }

        cs_arm_op op1 = arm.operands[1];
        if (op1.type != ARM_OP_MEM) {
            break;
        }
        auto op1_res = cpu_state->get_op_read_addr(insn, op1, block->mode);
        if (!op1_res) {
            LOG(WARNING) << "unable to get op0 value in arm LDR at: 0x" << std::hex << insn->address;
            return insn_status::FAILURE;
        }
        if (state.stub_addr) {
            state.reloc_idx = *op1_res;
            return insn_status::SYMBOLIZE;
        }
        return insn_status::CONT;
    }
    case ARM_INS_PUSH:
    case ARM_INS_CMP:
    case ARM_INS_SUB:
    case ARM_INS_INVALID:
        return insn_status::STOP;

    default:
        break;
    }
    return insn_status::CONT;
}

template <class ELFT>
typename ElfSyms<ELFT>::insn_status ElfSyms<ELFT>::plt_insn_arm64(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block) {
    cs_arm64 arm64 = insn->detail->arm64;

    CHECK(cpu_state) << "Invalid CpuState object";
    cpu_state->at_insn(insn, block);

    /*
     * 12c0:       90 00 00 f0     adrp    x16, #77824
     * 12c4:       11 72 47 f9     ldr     x17, [x16, #3808]
     * 12c8:       10 82 3b 91     add     x16, x16, #3808
     * 12cc:       20 02 1f d6     br      x17
     */

    switch (insn->id) {
    case ARM64_INS_ADRP: {
        if (arm64.op_count != 2) {
            break;
        }
        cs_arm64_op op0 = arm64.operands[0];
        cs_arm64_op op1 = arm64.operands[1];

        if (op0.type != ARM64_OP_REG || op1.type != ARM64_OP_IMM) {
            break;
        }

        state.reset();
        state.stub_addr = insn->address;

        break;
    }
    case ARM64_INS_LDR: {
        if (arm64.op_count != 2) {
            break;
        }

        cs_arm64_op op0 = arm64.operands[0];
        cs_arm64_op op1 = arm64.operands[1];

        if (op0.type != ARM64_OP_REG || op1.type != ARM64_OP_MEM) {
            break;
        }

        auto op1_res = cpu_state->get_op_read_addr(insn, op1, block->mode);
        if (!op1_res) {
            LOG(WARNING) << "unable to get op0 value in arm LDR at: 0x" << std::hex << insn->address;
            return insn_status::FAILURE;
        }

        if (state.stub_addr && *op1_res) {
            state.reloc_idx = *op1_res;
            return insn_status::SYMBOLIZE;
        }
        break;
    }
    case ARM64_INS_MOV:
    case ARM64_INS_CBZ:
        return insn_status::STOP;
    default:
        break;
    }
    return insn_status::CONT;
}

template <class ELFT>
typename ElfSyms<ELFT>::insn_status ElfSyms<ELFT>::plt_insn_mips(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block) {
    cs_mips mips = insn->detail->mips;
    CHECK(cpu_state) << "Invalid CpuState object";

    cpu_state->at_insn(insn, block);
    switch (insn->id) {

    // Normal type:
    case MIPS_INS_LUI: {
        if (mips.op_count != 2) {
            break;
        }
        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        if (op0.type != MIPS_OP_REG || op1.type != MIPS_OP_IMM) {
            break;
        }

        state.reset();
        state.stub_addr = insn->address;

        break;
    }
    case MIPS_INS_LW: {
        if (mips.op_count != 2) {
            break;
        }

        cs_mips_op op0 = mips.operands[0];
        cs_mips_op op1 = mips.operands[1];

        if (op0.type != MIPS_OP_REG || op1.type != MIPS_OP_MEM) {
            break;
        }
        if (!state.stub_addr) {
            if (m_mips_gp_reg) {
                state.stub_addr = insn->address;
            }
            break;
        }

        auto op0_res = cpu_state->get_op_read_addr(insn, op1, block);
        if (!op0_res) {
            break;
        }

        state.reloc_idx = *op0_res;

        break;
    }

    case MIPS_INS_JR:
        if (!state.stub_addr || !state.reloc_idx) {
            break;
        }
        return insn_status::SYMBOLIZE;

    // MIPS direct GOT / non-relocs support
    case MIPS_INS_ADDIU: {
        if (mips.op_count != 3) {
            break;
        }
        if (!m_mips_gp_reg) {
            break;
        }

        cs_mips_op op2 = mips.operands[2];

        if (op2.type != MIPS_OP_IMM) {
            break;
        }

        state.reloc_idx = op2.imm;

        if (state.reloc_idx && state.stub_addr) {
            return insn_status::SYMBOLIZE;
        }

        break;
    }

    case MIPS_INS_NOP:
        return insn_status::STOP;
    default:
        break;
    }

    return insn_status::CONT;
}

template <class ELFT>
typename ElfSyms<ELFT>::insn_status ElfSyms<ELFT>::plt_insn_ppc(cs_insn *insn, StubState &state, cs_mode mode, CpuState *cpu_state, Block *block) {
    cs_ppc ppc = insn->detail->ppc;
    CHECK(cpu_state) << "Invalid CpuState object";

    cpu_state->at_insn(insn, block);
    switch (insn->id) {
    case PPC_INS_LIS: {
        CHECK(ppc.op_count == 2) << "Invalid PPC lis insn at: 0x" << std::hex << insn->address;

        cs_ppc_op op0 = ppc.operands[0];
        cs_ppc_op op1 = ppc.operands[1];

        if (op0.type != PPC_OP_REG || op1.type != PPC_OP_IMM) {
            break;
        }

        state.reset();
        state.stub_addr = insn->address;

        break;
    }
    case PPC_INS_MTCTR: {
        CHECK(ppc.op_count == 1) << "Invalid PPC mtctr insn at: 0x" << std::hex << insn->address;

        cs_ppc_op op0 = ppc.operands[0];

        if (op0.type != PPC_OP_REG) {
            break;
        }

        auto op0_res = cpu_state->get_op_val(insn, op0, block);
        if (!op0_res) {
            LOG(FATAL) << "Failed to ppc mtctr register value";
            break;
        }

        if (state.stub_addr) {
            state.reloc_idx = *op0_res;
            return insn_status::SYMBOLIZE;
        }

        break;
    }
    case PPC_INS_NOP:
        return insn_status::STOP;
    default:
        break;
    }

    return insn_status::CONT;
}

template<class ELFT>
int ElfSyms<ELFT>::parse_section_syms() {
    for (const SymbolRef &sym : m_obj->symbols()) {
        Expected<uint64_t> addrOrErr = sym.getAddress();
        if (!addrOrErr) {
            std::error_code EC = errorToErrorCode(addrOrErr.takeError());
            LOG(ERROR) << "Failed to get sym address: " << EC.message();
            continue;
        }
        uint64_t addr = *addrOrErr;

        Expected<SymbolRef::Type> typeOrError = sym.getType();
        if (!typeOrError) {
            std::error_code EC = errorToErrorCode(typeOrError.takeError());
            LOG(ERROR) << "Failed to get sym type: " << EC.message();
            continue;
        }
        SymbolRef::Type sym_type = *typeOrError;

        Expected<StringRef> nameOrError = sym.getName();
        if (!nameOrError) {
            std::error_code EC = errorToErrorCode(nameOrError.takeError());
            LOG(ERROR) << "Failed to get sym name: " << EC.message();
            continue;
        }
        StringRef sym_name = *nameOrError;

        Expected<section_iterator> sectOrErr = sym.getSection();
        if (!sectOrErr) {
            std::error_code EC = errorToErrorCode(sectOrErr.takeError());
            LOG(ERROR) << "Failed to get sym section: " << EC.message();
            continue;
        }
        section_iterator section = *sectOrErr;

        if (addr && section->isText() && sym_type == SymbolRef::ST_Function) {
            sym_obj_type mapped_type = this->map_sym_type(sym_type);
            bool is_thumb = sym.getFlags() & SymbolRef::SF_Thumb;

            m_syms_by_addr.emplace(addr, Symbol(sym_name.str(), addr, std::string(), sym_type::EXPORT, mapped_type, is_thumb));
        }
    }

    return 0;
}

template <class ELFT>
int ElfSyms<ELFT>::parse_exports() {
    for (const auto &sym : m_symtab_syms) {
        if (sym.undefined) {
            // Some MIPS binaries will have no relocs but a undefined symtab with a value, that value
            // points to the plt so we can symbolize that.
            if (m_arch == Triple::mips || m_arch == Triple::mipsel) {
                if (!sym.value) {
                    continue;
                }

                if (!m_relocs.empty()) {
                    continue;
                }

                if (sym.type == sym_obj_type::FUNC || sym.type == sym_obj_type::OBJECT) {
                    m_syms_by_addr.emplace(sym.value, Symbol(sym.sym, sym.value, std::string(), sym_type::IMPORT, sym.type, false));
                }
            }
            continue;
        }

        if (!sym.value) {
            continue;
        }

        if (sym.type == sym_obj_type::FUNC || sym.type == sym_obj_type::OBJECT) {
            bool is_thumb = false;
            auto addr = sym.value;
            if (m_arch == Triple::arm || m_arch == Triple::armeb) {
                is_thumb = ((addr & 1) == 1);
                if (is_thumb) {
                    addr--;
                }
            }

            // LOG(INFO) << "Found export sym: 0x" << std::hex << addr << " | " << sym.sym;
            m_syms_by_addr.emplace(addr, Symbol(sym.sym, addr, std::string(), sym_type::EXPORT, sym.type, is_thumb));
        }
    }

    return 0;
}

template<class ELFT>
int ElfSyms<ELFT>::parse_mips_no_relocs() {
    // Explanation:
    // older style non-reloc based MIPS symbols expose themselves as symtab entries that point to
    // the plt stubs, so they act like relocs but have slightly different meaning / plt stub style.
    // They are indexed via a ADDIU instruction in the PLT and points to the symtab index of the sym.
    // We hack in the relocs from the symtab, save off the GP registers as a flag for later in the code
    // Then use that flag to enable / disable some features in the disassembly walker and plt discovery
    // code.

    uint64_t idx = 0;
    for (const SymTabSym &sym : m_symtab_syms) {
        do {
            if (sym.type == sym_obj_type::NOTYPE && sym.value && sym.sym == "_gp") {
                m_mips_gp_reg = sym.value;
            }
            if (sym.type != sym_obj_type::FUNC) {
                break;
            }

            if (!sym.value) {
                break;
            }

            if (!sym.undefined) {
                break;
            }

            m_relocs.emplace(idx, Reloc(sym.sym, sym_type::IMPORT, ELF::R_MIPS_JUMP_SLOT, sym.value));
        }
        while (false);
        idx++;
    }

    if (!m_mips_gp_reg) {
        for (const auto &dt : m_dyn_tags) {
            if (dt.tag == ELF::DT_PLTGOT) {
                m_mips_gp_reg = dt.value;
            }
        }
    }

    return 0;
}

template<class ELFT>
int ElfSyms<ELFT>::find_ppc_plts(std::vector<PltRange> *plts) {
    CHECK(plts != nullptr) << "Invalid PLTS vector provided";

    LOG(INFO) << "Parsing PPC32 text segment looking for stubs";

    uint64_t text_addr = 0;
    uint64_t text_size = 0;

    if (!m_is_stripped) {
        for (const SectionRef &section : m_obj->sections()) {
            if (!section.isText()) {
                continue;
            }

            Expected<StringRef> nameOrErr = section.getName();
            if (!nameOrErr) {
                std::error_code EC = errorToErrorCode(nameOrErr.takeError());
                LOG(ERROR) << "Failed to get section name: " << EC.message();
                continue;
            }
            auto sect_name = *nameOrErr;

            if (sect_name == ".text") {
                text_addr = section.getAddress();
                text_size = section.getSize();
            }
        }
    } else {
        auto *text_page = this->m_memmap->text_page();
        CHECK(text_page != nullptr) << "No text page found in stripped binary";
        text_addr = text_page->address;
        text_size = text_page->size;
    }

    auto data = m_memmap->addr_to_ptr(text_addr);
    if (!data) {
        LOG(FATAL) << "Failed to get text_address for finding PPC plt stubs";
    }


    // Walk backwards 4 bytes (insn alignment) from the end of the page.
    // Stage machine:
    // 1. Walk until we find the first stub, eg:
    //    100031b0  3d601001   lis     r11, 0x1001
    //    100031b4  816b4114   lwz     r11, 16660(r11)  {memcmp@GOT}
    //    100031b8  7d6903a6   mtctr   r11
    //    100031bc  4e800420   bctr
    //
    // 2. Set the 'stubs_end_addr'
    // 3. Walk backwards until we hit a 0x00000000, or 0x60000000 (padding assumptions for ppc32)
    // 4. Mark the 'stubs_start_addr'

    enum class ppc_stub {
        LWZ = 0,
        MTCTR,
        BCTR,
        NONE
    };

    uint64_t stubs_end_addr = 0;
    uint64_t stubs_start_addr = 0;
    ppc_stub cur_state = ppc_stub::NONE;

    for (uint64_t i = (text_size - 4); i > 0; i -= 4) {
        auto cur_byte_ptr = reinterpret_cast<const uint32_t *>(&data[i]);
        uint32_t upper_bytes = *cur_byte_ptr;

        if (ELFT::TargetEndianness == endianness::big) {
            upper_bytes = __builtin_bswap32(upper_bytes) >> 16;
        }
        else {
            upper_bytes = upper_bytes >> 16;
        }

        switch (upper_bytes) {
        case 0x3d60:
            if (cur_state == ppc_stub::LWZ) {
                if (stubs_end_addr == 0) {
                    stubs_end_addr = text_addr + i + 16;
                }
            }
            break;
        case 0x816b:
            if (cur_state == ppc_stub::MTCTR) {
                cur_state = ppc_stub::LWZ;
            } else {
                cur_state = ppc_stub::NONE;
            }
            break;
        case 0x7d69:
            if (cur_state == ppc_stub::BCTR) {
                cur_state = ppc_stub::MTCTR;
            } else {
                cur_state = ppc_stub::NONE;
            }
            break;
        case 0x4e80:
            if (cur_state == ppc_stub::NONE) {
                cur_state = ppc_stub::BCTR;
            } else {
                cur_state = ppc_stub::NONE;
            }
            break;
        default:
            if (stubs_end_addr != 0) {
                stubs_start_addr = text_addr + i + 4;
            }
            cur_state = ppc_stub::NONE;
            break;
        }

        if (stubs_start_addr != 0) {
            break;
        }
    }

    if (!stubs_end_addr || ! stubs_start_addr) {
        return 1;
    }
    // LOG(INFO) << "Stub start: 0x" << std::hex << stubs_start_addr;
    // LOG(INFO) << "Stub end:   0x" << std::hex << stubs_end_addr;
    auto stub_offset = stubs_start_addr - text_addr;

    plts->clear();
    plts->emplace_back(stubs_start_addr, (stubs_end_addr - stubs_start_addr), false);

    return 0;
}

template <class ELFT>
int ElfSyms<ELFT>::parse_arm_unwind() {
    /* TODO: figure out how the correctly identify ARM exception functions being thumb or not

    // LLVM has limited support for parsing the arm ".ARM.exidx" section we can use.
    if (FLAGS_arm_unwind && (m_arch == cs_arch::CS_ARCH_ARM || m_arch == cs_arch::CS_ARCH_ARM64)) {
        const ELFFile<ELFT> *elf_file = m_elf_obj->getELFFile();
        if (!elf_file) {
            LOG(FATAL) << "ELFFile object missing from inside ELFObjectFile";
        }

        Expected<typename ELFT::ShdrRange> sectionsOrErr = elf_file->sections();
        if (!sectionsOrErr) {
            LOG(ERROR) << "Failed to get ELFFile sections";
            return 1;
        }

        auto sections = sectionsOrErr.get();
        for (const auto &section : sections) {
            if (section.sh_type != ELF::SHT_ARM_EXIDX) {
                continue;
            }

            Expected<ArrayRef<uint8_t>> data = elf_file->getSectionContents(&section);
            if (!data) {
                LOG(ERROR) << "Failed to get ARM_EXIDX data";
                return 1;
            }

            uint8_t index_table_ent_size = 8;
            const auto *Data = reinterpret_cast<const support::ulittle32_t *>(data->data());
            const unsigned Entries = section.sh_size / index_table_ent_size;

            for (unsigned Entry = 0; Entry < Entries; ++Entry) {
                const support::ulittle32_t Word0 = Data[Entry * (index_table_ent_size / sizeof(*Data)) + 0];
                const support::ulittle32_t Word1 = Data[Entry * (index_table_ent_size / sizeof(*Data)) + 1];

                if (Word0 & 0x80000000) {
                    continue;
                }

                if (Word1 == llvm::ARM::EHABI::EXIDX_CANTUNWIND) {
                    continue;
                }

                const uint64_t Offset = this->PREL31(Word0, section.sh_addr);

                m_found_funcs.emplace(Offset, Symbol(std::string(), Offset, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
            }
        }
    }
    */

    return 0;
}

template <class ELFT>
int ElfSyms<ELFT>::parse_init_fini() {
    if (!m_is_stripped) {
        for (const SectionRef &section : m_obj->sections()) {
            Expected<StringRef> nameOrErr = section.getName();
            if (!nameOrErr) {
                std::error_code EC = errorToErrorCode(nameOrErr.takeError());
                LOG(ERROR) << "Failed to get section name: " << EC.message();
                continue;
            }
            auto sect_name = *nameOrErr;

            if (section.isText()) {
                if (sect_name.str() == ".fini" || sect_name.str() == ".init") {
                    uint64_t addr = section.getAddress();
                    m_found_funcs.emplace(addr, Symbol(sect_name.str(), addr, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
                }
            }
            if (sect_name.str() == ".init_array" ||
                sect_name.str() == ".fini_array" ||
                sect_name.str() == ".ctors" ||
                sect_name.str() == ".dtors") {

                uint64_t sect_size = section.getSize();

                // Skip NOBITS
                if (section.isVirtual()) {
                    continue;
                }

                Expected<StringRef> sectDataErr = section.getContents();
                if (!sectDataErr) {
                    std::error_code EC = errorToErrorCode(sectDataErr.takeError());
                    LOG(ERROR) << "Failed to get " << sect_name.str() << " contents, err: " << EC.message();
                    continue;
                }
                auto sect_contents = sectDataErr.get();

                if (sect_size > sect_contents.size()) {
                    LOG(ERROR) << "Bad section data";
                    continue;
                }

                uint8_t dword_size = 0;
                std::vector<uint64_t> func_array;

                unsigned int arch = m_obj->getArch();

                switch (arch) {
                case Triple::x86:
                case Triple::arm:
                case Triple::armeb:
                case Triple::mipsel:
                    func_array = this->parse_array<uint32_t>(sect_contents.data(), sect_size);
                    break;
                case Triple::mips:
                    func_array = this->parse_array<uint32_t>(sect_contents.data(), sect_size, true);
                    break;
                case Triple::x86_64:
                case Triple::aarch64:
                case Triple::aarch64_be:
                case Triple::mips64el:
                    func_array = this->parse_array<uint64_t>(sect_contents.data(), sect_size);
                    break;
                case Triple::mips64:
                    func_array = this->parse_array<uint64_t>(sect_contents.data(), sect_size, true);
                    break;
                case Triple::ppc:
                    func_array = this->parse_array<uint32_t>(sect_contents.data(), sect_size, true);
                    break;

                default:
                    LOG(ERROR) << "unsupported arch for init/fini array parsing: " << std::hex << arch;
                    break;
                }

                for (const auto &func : func_array) {
                    if (!func || func == -1 || func == 0xffffffff) {
                        continue;
                    }

                    m_found_funcs.emplace(func, Symbol(std::string(), func, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
                }
            }
        }
    }
    else {
        uint64_t init_array_addr = 0;
        uint64_t init_size = 0;
        uint64_t fini_array_addr = 0;
        uint64_t fini_size = 0;

        for (const auto &dt : m_dyn_tags) {
            switch (dt.tag) {
            case ELF::DT_INIT:
            case ELF::DT_FINI:
                m_found_funcs.emplace(dt.value, Symbol(std::string(), dt.value, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
                break;
            }
        }
    }

    return 0;
}

template <class ELFT>
int ElfSyms<ELFT>::parse_eh_data() {
    uint64_t eh_frame_addr = 0;
    uint64_t eh_frame_size = 0;
    const char *eh_frame = nullptr;

    uint64_t eh_frame_hdr_addr = 0;
    uint64_t eh_frame_hdr_size = 0;
    const char *eh_frame_hdr = nullptr;

    for (const SectionRef &section : m_obj->sections()) {
        Expected<StringRef> nameOrErr = section.getName();
        if (!nameOrErr) {
            std::error_code EC = errorToErrorCode(nameOrErr.takeError());
            LOG(ERROR) << "Failed to get section name: " << EC.message();
            continue;
        }
        auto sect_name = *nameOrErr;

        if (sect_name.str() == ".eh_frame") {
            eh_frame_addr = section.getAddress();
            eh_frame_size = section.getSize();

            // Check if NOBITS
            if (section.isVirtual()) {
                LOG(WARNING) << "NOBITS eh_frame";
                eh_frame = nullptr;
                continue;
            }

            Expected<StringRef> sectDataErr = section.getContents();
            if (!sectDataErr) {
                std::error_code EC = errorToErrorCode(sectDataErr.takeError());
                LOG(ERROR) << "Failed to get .eh_frame contents, err: " << EC.message();
                eh_frame = nullptr;
                continue;
            }
            auto sect_contents = sectDataErr.get();

            eh_frame = sect_contents.data();
        }
        else if (sect_name.str() == ".eh_frame_hdr") {
            eh_frame_hdr_addr = section.getAddress();
            eh_frame_hdr_size = section.getSize();

            // Check if NOBITS
            if (section.isVirtual()) {
                LOG(WARNING) << "NOBITS eh_frame_hdr";
                eh_frame_hdr = nullptr;
                continue;
            }

            Expected<StringRef> sectDataErr = section.getContents();
            if (!sectDataErr) {
                std::error_code EC = errorToErrorCode(sectDataErr.takeError());
                LOG(ERROR) << "Failed to get .eh_frame_hdr contents, err: " << EC.message();
                eh_frame_hdr = nullptr;
                continue;
            }
            auto sect_contents = sectDataErr.get();

            eh_frame_hdr = sect_contents.data();
        }
    }


    if (eh_frame_hdr && eh_frame_hdr_addr && eh_frame_hdr_size) {
        auto dr = DwarfReader<ELFT::TargetEndianness, ELFT::Is64Bits>(eh_frame_hdr_addr, eh_frame_hdr_size, eh_frame_hdr);

        uint8_t version = dr.readU8();
        CHECK(version < 4) << "Invalid eh_frame_hdr version: " << static_cast<int>(version);

        uint64_t frame_encoding = dr.readU8();
        // FDEsCountEncoding
        uint8_t FDEsCountEncoding = dr.readU8();

        // skip byte
        dr.readU8();

        uint64_t ehFrameVal = dr.readPtr(frame_encoding);
        uint64_t fdeCount = dr.readPtr(FDEsCountEncoding);


        std::vector<uint64_t> eh_funcs = this->parse_eh_frame(eh_frame_addr, eh_frame_size, eh_frame, ehFrameVal, fdeCount);
        if (eh_funcs.empty()) {
            return 0;
        }

        for (const auto &func_addr : eh_funcs) {
            m_found_funcs.emplace(func_addr, Symbol(std::string(), func_addr, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
        }
    }

    return 0;
}

template <class ELFT>
std::vector<uint64_t> ElfSyms<ELFT>::parse_eh_frame(uint64_t addr, uint64_t size, const char *data, uint64_t ehframe_val, uint64_t fde_count) {
    std::vector<uint64_t> eh_funcs;

    if (!ehframe_val || !fde_count) {
        return eh_funcs;
    }

    auto dr = DwarfReader<ELFT::TargetEndianness, ELFT::Is64Bits>(addr, size, data);

    std::map<uint64_t, CIE> cie_map;
    uint32_t fde_idx = 0;
    while (!dr.eof() && ((fde_idx < fde_count) || (dr.offset() < size))) {
        uint64_t start_offset = dr.offset();

        // Read the length of the entry
        uint64_t length = dr.readU32();
        if (length == 0xffffffff) {
            length = dr.readU64();
        }
        // Compute the end offset of the entry
        uint64_t OffsetAfterLength = dr.offset();
        uint64_t end_offset = OffsetAfterLength + length;

        // Zero-sized entry, skip it
        if (length == 0) {
            if (dr.offset() == end_offset) {
                break;
            }
            else {
                continue;
            }
        }

        uint32_t entry_id = dr.readU32();
        if (entry_id == 0) {
            uint32_t version = dr.readU8();
            if (version > 4) {
                LOG(FATAL) << "Invalid CIE version: " << version;
            }

            std::vector<char> augment_vect;

            for (char ch = dr.readU8(); ch != 0 && augment_vect.size() <= 8; ch = dr.readU8()) {
                augment_vect.emplace_back(ch);
            }

            std::string augment_str = std::string(augment_vect.begin(), augment_vect.end());
            if (augment_str.find("eh") != std::string::npos) {
                dr.readU8();
            }

            // CodeAlignmentFactor
            dr.readULEB128();
            // DataAlignmentFactor
            dr.readULEB128();
            // ReturnAddressRegister
            dr.readU8();

            uint64_t augment_len = 0;
            uint32_t LSDAEncoding = 0;
            uint32_t PersonalityEncoding = 0;
            uint32_t FDEEncoding = 0;

            // LOG(INFO) << "Parsing augment str: " << augment_str;
            if (!augment_str.empty() && augment_str.front() == 'z') {
                augment_len = dr.readULEB128();

                uint32_t remaining;
                for (uint32_t i = 1, remaining = augment_str.size(); i != remaining; ++i) {
                    char ch = augment_str[i];
                    switch (ch) {
                    case 'e':
                        CHECK((i + 1) != remaining && augment_str[i+1] == 'h') << "Invalid augment str: " << augment_str;
                        break;
                    case 'L':
                        CHECK(!LSDAEncoding) << "Duplicate LSDAEncoding value";
                        LSDAEncoding = dr.readU8();
                        break;
                    case 'P': {
                        CHECK(!PersonalityEncoding) << "Duplicate PersonalityEncoding value";
                        PersonalityEncoding = dr.readU8();
                        uint64_t personality = dr.readPtr(PersonalityEncoding);
                        // LOG(INFO) << "Personality: 0x" << std::hex << personality;
                        break;
                    }
                    case 'R':
                        CHECK(!FDEEncoding) << "Duplicate FDEEncoding value";
                        FDEEncoding = dr.readU8();
                        break;
                    case 'z': {
                        LOG(FATAL) << "Invalid augment str (z expected at beginning): " << augment_str;
                        break;
                    }
                    }
                }
            }
            // LOG(INFO) << "Mapping: 0x" << std::hex << start_offset;
            // LOG(INFO) << " fde encoding:  0x" << std::hex << FDEEncoding;
            // LOG(INFO) << " lsda encoding: 0x" << std::hex << LSDAEncoding;
            // LOG(INFO) << " augment_len:   0x" << std::hex << augment_len;

            cie_map.emplace(start_offset, CIE(FDEEncoding, LSDAEncoding, augment_len));

        }
        else {
            fde_idx++;

            uint64_t CIE_offset = OffsetAfterLength - entry_id;

            auto CIE = cie_map.find(CIE_offset);
            if (CIE == cie_map.end()) {
                LOG(FATAL) << "Invalid CIE_offset, not in map: 0x" << std::hex << CIE_offset;
            }

            // CHECK(CIE->second.FDEencoding) << "CIE without FDE encoding: 0x" << std::hex << CIE_offset;

            uint64_t pc_begin = dr.readPtr(CIE->second.FDEencoding);
            // LOG(INFO) << "PC begin: 0x" << std::hex << pc_begin;

            eh_funcs.emplace_back(pc_begin);
        }

        dr.moveTo(end_offset);
    }

    return eh_funcs;
}


template <class ELFT>
sym_obj_type ElfSyms<ELFT>::map_elf_sym_type(uint8_t type) {
    switch (type) {
    case ELF::STT_OBJECT:
        return sym_obj_type::OBJECT;
    case ELF::STT_FUNC:
        return sym_obj_type::FUNC;
    case ELF::STT_NOTYPE:
        return sym_obj_type::NOTYPE;
    default:
        return sym_obj_type::NOTYPE;
    }

    return sym_obj_type::NOTYPE;
}

template<class ELFT>
sym_obj_type ElfSyms<ELFT>::map_sym_type(uint8_t type) {
    switch (type) {
    case SymbolRef::ST_Data:
        return sym_obj_type::OBJECT;
    case SymbolRef::ST_Debug:
        return sym_obj_type::DEBUG;
    case SymbolRef::ST_Function:
        return sym_obj_type::FUNC;
    default:
        return sym_obj_type::NOTYPE;
    }

    return sym_obj_type::NOTYPE;
}

// LLVM forgot some
#define R_PPC_COPY 19
#define R_PPC_GLOB_DAT 20

template <class ELFT>
sym_obj_type ElfSyms<ELFT>::map_elf_reloc_type(cs_arch arch, uint32_t type) {
    switch (arch) {
    case cs_arch::CS_ARCH_X86:
        switch (type) {
        case ELF::R_X86_64_COPY: // R_386_COPY equals the same thing in llvm.
            return sym_obj_type::OBJECT;
        case ELF::R_X86_64_GLOB_DAT:
        case ELF::R_X86_64_JUMP_SLOT:
            return sym_obj_type::FUNC;
        }
        break;

    case cs_arch::CS_ARCH_ARM:
        switch (type) {
        case ELF::R_ARM_COPY:
            return sym_obj_type::OBJECT;
        case ELF::R_ARM_GLOB_DAT:
        case ELF::R_ARM_JUMP_SLOT:
            return sym_obj_type::FUNC;
        }
        break;
    case cs_arch::CS_ARCH_ARM64:
        switch (type) {
        case ELF::R_AARCH64_COPY:
            return sym_obj_type::OBJECT;
        case ELF::R_AARCH64_GLOB_DAT:
        case ELF::R_AARCH64_JUMP_SLOT:
        case ELF::R_AARCH64_P32_ABS16:
            return sym_obj_type::FUNC;
        }
        break;
    case cs_arch::CS_ARCH_MIPS:
        switch (type) {
        case ELF::R_MIPS_COPY:
            return sym_obj_type::OBJECT;
        case ELF::R_MIPS_JUMP_SLOT:
        case ELF::R_MIPS_GLOB_DAT:
            return sym_obj_type::FUNC;
        }
        break;
    case cs_arch::CS_ARCH_PPC:
        switch (type) {
        case R_PPC_COPY:
            return sym_obj_type::OBJECT;
        case R_PPC_GLOB_DAT:
        case ELF::R_PPC_JMP_SLOT:
            return sym_obj_type::FUNC;
        }
        break;
    default:
        break;
    }

    return sym_obj_type::NOTYPE;
}

template <class ELFT>
uint64_t ElfSyms<ELFT>::read_word(uint64_t addr) {
    const uint8_t *ptr = m_memmap->addr_to_ptr(addr);
    uint64_t ret = 0;
    if (!ptr) {
        return ret;
    }

    if (ELFT::Is64Bits) {
        ret = *reinterpret_cast<const uint64_t *>(ptr);
        if (ELFT::TargetEndianness == endianness::big) {
            ret = __builtin_bswap64(ret);
        }
    }
    else {
        ret = *reinterpret_cast<const uint32_t *>(ptr);
        if (ELFT::TargetEndianness == endianness::big) {
            ret = __builtin_bswap32(ret);
        }
    }

    return ret;
}


template class ElfSyms<ELFType<support::little, false>>;
template class ElfSyms<ELFType<support::big, false>>;
template class ElfSyms<ELFType<support::little, true>>;
template class ElfSyms<ELFType<support::big, true>>;
