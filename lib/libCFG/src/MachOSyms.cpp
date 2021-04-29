#include <cstdint>
#include <map>
#include <string>
#include <algorithm>
#include <memory>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include "MachOSyms.hpp"
#include "CapstoneHelper.hpp"

#include "capstone/capstone.h"
#include "glog/logging.h"
#include "llvm/Object/MachO.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Error.h"

using namespace llvm;
using namespace object;


MachOSyms::MachOSyms(const MachOObjectFile *obj) : m_macho_obj(obj) {}

int MachOSyms::generate_symbols() {
    Error err = Error::success();

    // Removing the const here enables us to use the bind*() functions
    // because internally those functions are non-const safe.
    auto *vObj = const_cast<MachOObjectFile *>(m_macho_obj);

    for (const MachOBindEntry &entry : vObj->bindTable(err)) {
        std::string dylib_name = this->getMachoOrdinalName(entry.ordinal());
        auto addr = entry.address();
        m_plt_sym_map.emplace(addr, Symbol(entry.symbolName().str(), addr, dylib_name, sym_type::IMPORT, sym_obj_type::FUNC));
    }
    if (err) {
        LOG(ERROR) << "Failed to get bind table";
        return 1;
    }

    for (const MachOBindEntry &entry : vObj->lazyBindTable(err)) {
        std::string dylib_name = this->getMachoOrdinalName(entry.ordinal());
        uint64_t sym_addr = entry.address();
        std::string sym_name = entry.symbolName().str();

        auto old_sym_it = m_plt_sym_map.find(sym_addr);
        if (old_sym_it == m_plt_sym_map.end()) {
            uint64_t addr = entry.address();
            m_plt_sym_map.emplace(addr, Symbol(sym_name, addr, dylib_name, sym_type::IMPORT, sym_obj_type::FUNC));
        }
        else {
            if (old_sym_it->second.name != sym_name) {
                LOG(FATAL) << "Duplicate symbol entry at addr: 0x" << std::hex << sym_addr << " new symbol: " << sym_name << " old sym: " << old_sym_it->second.name;
            }
        }

    }
    if (err) {
        LOG(ERROR) << "Failed to get lazyBind table";
        return 1;
    }

    for (const MachOBindEntry &entry : vObj->weakBindTable(err)) {
        std::string dylib_name = this->getMachoOrdinalName(entry.ordinal());
        uint64_t sym_addr = entry.address();
        std::string sym_name = entry.symbolName().str();


        auto old_sym_it = m_plt_sym_map.find(sym_addr);
        // If we hit an existing definition for a symbol we can avoid erroring here because this is a weak bind.
        if (old_sym_it == m_plt_sym_map.end()) {
            uint64_t addr = entry.address();
            m_plt_sym_map.emplace(addr, Symbol(sym_name, addr, dylib_name, sym_type::IMPORT, sym_obj_type::FUNC));
        }
    }
    if (err) {
        LOG(ERROR) << "Failed to get weakBind table";
        return 1;
    }

    // Get the __stubs section and disassemble it
    uint64_t stub_addr = 0;
    uint64_t stub_size = 0;
    const uint8_t *stub_data = nullptr;

    uint64_t text_addr = 0;
    uint64_t text_size = 0;

    for (const SectionRef &section : m_macho_obj->sections()) {
        Expected<StringRef> nameOrErr = section.getName();
        if (!nameOrErr) {
            std::error_code EC = errorToErrorCode(nameOrErr.takeError());
            LOG(ERROR) << "Failed to get section name: " << EC.message();
            continue;
        }
        auto sect_name = *nameOrErr;

        if (sect_name == "__stubs") {
            stub_addr = section.getAddress();
            stub_size = section.getSize();

            Expected<StringRef> sectDataErr = section.getContents();
            if (!sectDataErr) {
                std::error_code EC = errorToErrorCode(sectDataErr.takeError());
                LOG(ERROR) << "Failed to get __stub contents, err: " << EC.message();
                continue;
            }
            auto stub_contents = sectDataErr.get();

            stub_data = reinterpret_cast<const uint8_t *>(stub_contents.data());
        }
        else if(sect_name == "__text") {
            text_addr = section.getAddress();
            text_size = section.getSize();
        }
    }

    if (!stub_addr || !stub_size || !stub_data) {
        m_syms_by_addr = m_plt_sym_map;
        m_plt_sym_map.clear();
        LOG(WARNING) << "Failed to find __stubs in binary";
    }

    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(m_macho_obj->getArch());

    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    csh handle;
    uint64_t count;
    cs_insn *insn;

    cs_err cserr;
    cserr = cs_open(arch, mode, &handle);
    if (cserr != CS_ERR_OK) {
        LOG(INFO) << "cs_open: " << cs_strerror(cserr);
        return 1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    count = cs_disasm(handle, stub_data, stub_size, stub_addr, 0, &insn);

    for (uint64_t idx = 0; idx < count; idx++) {
        cs_insn cur_insn = insn[idx];
        if (cur_insn.id == X86_INS_JMP) {
            std::vector<uint64_t> imms;
            imms = get_imm_vals(cur_insn, arch, X86_REG_INVALID, 0x0);

            for (const auto &imm : imms) {
                auto it = m_plt_sym_map.find(imm);
                if (it == m_plt_sym_map.end()) {
                    continue;
                }

                m_syms_by_addr.emplace(cur_insn.address, Symbol(it->second.name, cur_insn.address, it->second.module, it->second.type, it->second.obj_type));
            }
        }
    }

    if (count) {
        cs_free(insn, count);
    }
    cs_close(&handle);

    m_plt_sym_map.clear();

    for (const SymbolRef &sym : vObj->symbols())  {
        StringRef sym_name;
        Expected<StringRef> SymbolNameOrErr = sym.getName();
        if (!SymbolNameOrErr) {
            continue;
        }
        sym_name = SymbolNameOrErr.get();

        Expected<uint64_t> AddressOrError = sym.getAddress();
        if (!AddressOrError) {
            LOG(ERROR) << "Failed to get address for symbol: " << sym_name.str();
            continue;
        }
        uint64_t value = *AddressOrError;

        // Skip undefined symbols
        if (!value) {
            continue;
        }

        if (m_syms_by_addr.count(value)) {
            continue;
        }

        Expected<SymbolRef::Type> TypeOrError = sym.getType();
        if (!TypeOrError) {
            LOG(ERROR) << "Failed to get symbol type, sym: " << sym_name.str();
            continue;
        }

        SymbolRef::Type Type = *TypeOrError;

        if (Type == SymbolRef::ST_Function) {
            m_syms_by_addr.emplace(value, Symbol(sym_name.str(), value, sym_type::EXPORT, sym_obj_type::FUNC));
        }
        else if (Type == SymbolRef::ST_Data || Type == SymbolRef::ST_Debug) {
            // I would rather use .getSection on the symbol but llvm appears to have a assert bug there.
            if (value >= text_addr && value < text_addr + text_size) {
                m_syms_by_addr.emplace(value, Symbol(sym_name.str(), value, sym_type::EXPORT, sym_obj_type::FUNC));
            }
        }
    }

    this->parse_macho_indirect();

    this->find_funcs();

    return 0;
}

int MachOSyms::parse_indirect_table(uint32_t n, uint32_t count, uint32_t stride, uint64_t addr) {
    MachO::dysymtab_command dysymtab = m_macho_obj->getDysymtabLoadCommand();

    uint32_t nindirectsyms = dysymtab.nindirectsyms;

    if (n > nindirectsyms) {
        LOG(WARNING) << "Entries start past the end of the indirect table";
        return 1;
    }
    else if (n + count > nindirectsyms) {
        LOG(WARNING) << "entries extend past the end of the indirect table";
        return 1;
    }

    MachO::symtab_command symtab = m_macho_obj->getSymtabLoadCommand();

    for (uint32_t i = 0; i < count && n + i < nindirectsyms; i++) {
        uint64_t sym_addr = addr + i * stride;

        uint32_t indirect_symbol = m_macho_obj->getIndirectSymbolTableEntry(dysymtab, n + i);

        if (indirect_symbol == MachO::INDIRECT_SYMBOL_LOCAL||
            indirect_symbol == MachO::INDIRECT_SYMBOL_ABS) {
            continue;
        }

        if (indirect_symbol < symtab.nsyms) {
            symbol_iterator sym = m_macho_obj->getSymbolByIndex(indirect_symbol);
            SymbolRef symbol = *sym;
            Expected<StringRef> SymName = symbol.getName();
            if (!SymName) {
                LOG(ERROR) << "Failed to getName on symbol at index: " << indirect_symbol;
            }

            m_syms_by_addr.emplace(sym_addr, Symbol(SymName->str(), sym_addr, sym_type::IMPORT, sym_obj_type::FUNC));
        }
    }

    return 0;
}

int MachOSyms::parse_macho_indirect() {
    for (const auto &load : m_macho_obj->load_commands()) {
        if (load.C.cmd == MachO::LC_SEGMENT) {
            MachO::segment_command seg = m_macho_obj->getSegmentLoadCommand(load);

            for (uint32_t i = 0; i < seg.nsects; ++i) {
                MachO::section sec = m_macho_obj->getSection(load, i);

                uint32_t section_type = sec.flags & MachO::SECTION_TYPE;
                if (section_type == MachO::S_NON_LAZY_SYMBOL_POINTERS ||
                    section_type == MachO::S_LAZY_SYMBOL_POINTERS ||
                    section_type == MachO::S_LAZY_DYLIB_SYMBOL_POINTERS ||
                    section_type == MachO::S_THREAD_LOCAL_VARIABLE_POINTERS ||
                    section_type == MachO::S_SYMBOL_STUBS) {

                    uint32_t stride;
                    if (section_type == MachO::S_SYMBOL_STUBS) {
                        stride = sec.reserved2;
                    }
                    else {
                        stride = 8;
                    }
                    if (stride == 0) {
                        LOG(WARNING) << "Invalid indirect stride: " << stride;
                        continue;
                    }
                    uint32_t count = sec.size / stride;
                    uint32_t n = sec.reserved1;

                    if (this->parse_indirect_table(n, count, stride, sec.addr)) {
                        LOG(ERROR) << "Failed to parse indirect sym table";
                        continue;
                    }
                }
            }
        }
        else if (load.C.cmd == MachO::LC_SEGMENT_64) {
            MachO::segment_command_64 seg = m_macho_obj->getSegment64LoadCommand(load);

            for (uint32_t i = 0; i < seg.nsects; ++i) {
                MachO::section_64 sec = m_macho_obj->getSection64(load, i);


                uint32_t section_type = sec.flags & MachO::SECTION_TYPE;
                if (section_type == MachO::S_NON_LAZY_SYMBOL_POINTERS ||
                    section_type == MachO::S_LAZY_SYMBOL_POINTERS ||
                    section_type == MachO::S_LAZY_DYLIB_SYMBOL_POINTERS ||
                    section_type == MachO::S_THREAD_LOCAL_VARIABLE_POINTERS ||
                    section_type == MachO::S_SYMBOL_STUBS) {

                    uint32_t stride;
                    if (section_type == MachO::S_SYMBOL_STUBS) {
                        stride = sec.reserved2;
                    }
                    else {
                        stride = 4;
                    }
                    if (stride == 0) {
                        LOG(WARNING) << "Invalid indirect stride: " << stride;
                        continue;
                    }
                    uint32_t count = sec.size / stride;
                    uint32_t n = sec.reserved1;

                    if (this->parse_indirect_table(n, count, stride, sec.addr)) {
                        LOG(ERROR) << "Failed to parse indirect sym table";
                        continue;
                    }
                }
            }
        }
    }
    return 0;
}

int MachOSyms::find_funcs() {
    for (const SectionRef &section : m_macho_obj->sections()) {
        Expected<StringRef> nameOrErr = section.getName();
        if (!nameOrErr) {
            std::error_code EC = errorToErrorCode(nameOrErr.takeError());
            LOG(ERROR) << "Failed to get section name: " << EC.message();
            continue;
        }
        auto sect_name = *nameOrErr;

        if (sect_name == "__unwind_info") {
            this->parse_macho_unwind(section);
            break;
        }
    }

    SmallVector<uint64_t, 8> found_funcs;
    uint64_t text_base = 0;

    for (const auto &Command : m_macho_obj->load_commands()) {
        if (Command.C.cmd == MachO::LC_FUNCTION_STARTS) {
            MachO::linkedit_data_command LLC = m_macho_obj->getLinkeditDataLoadCommand(Command);
            m_macho_obj->ReadULEB128s(LLC.dataoff, found_funcs);
        }
        else if (Command.C.cmd == MachO::LC_SEGMENT && !text_base) {
            MachO::segment_command seg_lcmd = m_macho_obj->getSegmentLoadCommand(Command);
            if (std::string(seg_lcmd.segname) ==  "__TEXT" && (seg_lcmd.initprot & MachO::VM_PROT_EXECUTE)) {
                text_base = seg_lcmd.vmaddr;
            }
        }
        else if (Command.C.cmd == MachO::LC_SEGMENT_64 && !text_base) {
            MachO::segment_command_64 seg_lcmd = m_macho_obj->getSegment64LoadCommand(Command);
            if (std::string(seg_lcmd.segname) ==  "__TEXT" && (seg_lcmd.initprot & MachO::VM_PROT_EXECUTE)) {
                text_base = seg_lcmd.vmaddr;
            }

        }
    }
    if (!found_funcs.empty() && text_base) {
        for (const auto &func : found_funcs) {
            uint64_t func_addr = func + text_base;
            m_found_funcs.emplace(func_addr, Symbol(std::string(), func_addr, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
        }
    }
    else {
        LOG(WARNING) << "Failed to find an LC_FUNCTION_STARTS";
    }

    return 0;
}

int MachOSyms::parse_macho_unwind(const SectionRef &sec) {
    if (!m_macho_obj->isLittleEndian()) {
        return 1;
    }

    Expected<StringRef> sectDataErr = sec.getContents();
    if (!sectDataErr) {
        std::error_code EC = errorToErrorCode(sectDataErr.takeError());
        LOG(ERROR) << "Failed to get unwind section contents, err: " << EC.message();
        return 1;
    }
    auto sect_contents = sectDataErr.get();

    const char *Pos = sect_contents.data();

    uint64_t sec_size = sec.getSize();
    uint64_t sect_end = reinterpret_cast<std::uintptr_t>(Pos) + sec_size;

    // Check that the unwind header does not go off the end of the memory
    if (!sec_size || sec_size < 28) {
        return 1;
    }

    uint32_t Version = readNext<uint32_t>(Pos);
    if (Version != 1) {
        return 1;
    }

    readNext<uint32_t>(Pos); // CommonEncodingsStart
    readNext<uint32_t>(Pos); // NumCommonEncodings
    readNext<uint32_t>(Pos); // PersonalitiesStart
    readNext<uint32_t>(Pos); // NumPersonalities
    uint32_t IndicesStart = readNext<uint32_t>(Pos);
    uint32_t NumIndices = readNext<uint32_t>(Pos);

    std::vector<IndexEntry> index_entries;
    std::vector<uint64_t> func_offsets;

    Pos = sect_contents.data() + IndicesStart;

    // Check that our indices iterator will not run off the end of memory.
    if (reinterpret_cast<std::uintptr_t>(Pos) + (NumIndices * 12) >= sect_end) {
        return 1;
    }

    for (unsigned i = 0; i < NumIndices; ++i) {
        uint32_t func_offset = readNext<uint32_t>(Pos);
        uint32_t second_level_pstart = readNext<uint32_t>(Pos);
        uint32_t lsda_start = readNext<uint32_t>(Pos);

        index_entries.emplace_back(func_offset, second_level_pstart, lsda_start);
    }

    if (index_entries.empty()) {
        return 1;

    }
    Pos = sect_contents.data() + index_entries.at(0).LSDAStart;

    int NumLSDAs = (index_entries.back().LSDAStart - index_entries.at(0).LSDAStart) / (2 * sizeof(uint32_t));

    if (reinterpret_cast<std::uintptr_t>(Pos) + (NumLSDAs * 8) >= sect_end) {
        return 1;
    }

    for (int i = 0; i < NumLSDAs; ++i) {
        uint32_t FunctionOffset = readNext<uint32_t>(Pos);
        readNext<uint32_t>(Pos); // LSDAOffset

        func_offsets.emplace_back(FunctionOffset);
    }

    for (const auto &entry : index_entries) {
        if (entry.SecondLevelPageStart == 0) {
            break;
        }

        Pos = sect_contents.data() + entry.SecondLevelPageStart;
        if (reinterpret_cast<std::uintptr_t>(Pos) + 4 >= sect_end) {
            return 1;
        }

        uint32_t kind = *reinterpret_cast<const support::ulittle32_t *>(Pos);
        if (kind == 2) {
            readNext<uint32_t>(Pos); // inner_kind

            const char *level_pos = Pos;
            uint16_t EntriesStart = readNext<uint16_t>(level_pos);
            uint16_t NumEntries = readNext<uint16_t>(level_pos);

            level_pos = Pos + EntriesStart;
            if (reinterpret_cast<std::uintptr_t>(level_pos) + (NumEntries * 8) >= sect_end) {
                return 1;
            }
            for (unsigned i = 0; i < NumEntries; ++i) {
                uint32_t FunctionOffset = readNext<uint32_t>(level_pos);
                readNext<uint32_t>(level_pos); // Encoding
                func_offsets.emplace_back(FunctionOffset);
            }
        }
        else if (kind == 3) {
            readNext<uint32_t>(Pos); // inner_kind

            uint32_t func_offset = entry.FunctionOffset;
            const char *level_pos = Pos;

            if (reinterpret_cast<std::uintptr_t>(level_pos) + 8 >= sect_end) {
                return 1;
            }

            uint16_t EntriesStart = readNext<uint16_t>(level_pos);
            uint16_t NumEntries = readNext<uint16_t>(level_pos);

            readNext<uint16_t>(level_pos); // EncodingsStart
            readNext<uint16_t>(level_pos);

            level_pos = Pos + EntriesStart;

            if (reinterpret_cast<std::uintptr_t>(level_pos) + (NumEntries * 4) >= sect_end) {
                return 1;
            }

            for (unsigned i = 0; i < NumEntries; ++i) {
                uint32_t Entry = readNext<uint32_t>(level_pos);
                uint32_t FunctionOffset = func_offset + (Entry & 0xffffff);
                func_offsets.emplace_back(FunctionOffset);
            }
        }
    }

    for (const auto &func : func_offsets) {
        if (!func) {
            continue;
        }
        m_found_funcs.emplace(func, Symbol(std::string(), func, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
    }

    return 0;
}


//! Simple rewrite of ordinalName() in MachODump.cpp in LLVM.
std::string MachOSyms::getMachoOrdinalName(int ordinal) const {
    StringRef lib_name;
    switch (ordinal) {
    case MachO::BIND_SPECIAL_DYLIB_SELF:
        return "this-image";
    case MachO::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
        return "main-executable";
    case MachO::BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
        return "flat-namespace";
    default:
        if (ordinal > 0) {
            std::error_code EC = m_macho_obj->getLibraryShortNameByIndex(ordinal - 1, lib_name);
            if (EC) {
                LOG(ERROR) << "Failed to get name for ordinal: " << ordinal << " msg: " << EC.message();
                return "unknown";
            }
            return lib_name.str();
        }
    }
    return "unknown";
}
