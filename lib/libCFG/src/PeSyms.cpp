#include <string>
#include <algorithm>
#include <cstdint>
#include <map>
#include <system_error>
#include <utility>

#include "PeSyms.hpp"
#include "Utils.hpp"

#include "glog/logging.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Win64EH.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

using namespace llvm;
using namespace object;


PeSyms::PeSyms(const COFFObjectFile *obj) : m_pe_obj(obj) {}


int PeSyms::generate_symbols() {
    uint64_t img_base = m_pe_obj->getImageBase();

    for (const ImportDirectoryEntryRef &DirRef : m_pe_obj->import_directories()) {
        StringRef module_name;
        if (std::error_code EC = DirRef.getName(module_name)) {
            LOG(ERROR) << "Failed to get module name: " << EC.message();
            continue;
        }

        uint32_t IAT_addr = 0;
        uint64_t sym_base_addr = 0;

        if (std::error_code EC = DirRef.getImportAddressTableRVA(IAT_addr)) {
            LOG(ERROR) << "Failed to get IAT address: " << EC.message();
            continue;
        }
        sym_base_addr = IAT_addr + img_base;

        // Used for non-ordinal imports, seen with packed binaries.
        // In MOST cases the order of the IAT call targets appears to match
        // the ordering of the names list, so we can use simple indexing off
        // the IAT base addr.
        uint32_t idx = 0;
        for (const auto &sym : DirRef.imported_symbols()) {
            StringRef sym_name;
            if (std::error_code EC = sym.getSymbolName(sym_name)) {
                LOG(ERROR) << "Failed to look up symbol name: " << EC.message();
                continue;
            }

            uint64_t sym_addr = sym_base_addr + idx;
            if (m_syms_by_addr.find(sym_addr) != m_syms_by_addr.end() ) {
                LOG(FATAL) << "Duplicate symbol entry at addr: 0x" << std::hex << sym_addr << " new symbol: " << sym_name.str();
            }

            m_syms_by_addr.emplace(sym_addr, Symbol(sym_name.str(), sym_addr, module_name.str(), sym_type::IMPORT, sym_obj_type::FUNC));

            // Bump the index by the current dword size.
            if (m_pe_obj->is64()) {
                idx += 8;
            }
            else {
                idx += 4;
            }
        }
    }

//    TODO: implement support for delayed imports
//    for (const auto &DirRef : obj->delay_import_directories()) {
//        StringRef dll_name;
//        if (std::error_code EC = DirRef.getName(dll_name)) {
//            LOG(ERROR) << "Failed to get delayed import name: " << EC.message();
//            continue;
//        }
//        LOG(INFO) << "Delayed import name: " << dll_name.str();
//    }

    for (const ExportDirectoryEntryRef &DirRef : m_pe_obj->export_directories()) {
        StringRef exp_name;
        if (std::error_code EC = DirRef.getSymbolName(exp_name)) {
            LOG(ERROR) << "Failed to get export name: " << EC.message();
            continue;
        }

        uint32_t rva;
        if (std::error_code EC = DirRef.getExportRVA(rva)) {
            LOG(ERROR) << "Failed to get RVA for symbol: " << exp_name.str() << " err: " << EC.message();
            continue;
        }

        uint64_t sym_addr = img_base + rva;
        auto existing_sym = m_syms_by_addr.find(sym_addr);
        if ( existing_sym != m_syms_by_addr.end() ) {
            existing_sym->second.alt_names.emplace_back(exp_name.str());
        }

        m_syms_by_addr.emplace(sym_addr, Symbol(exp_name.str(), sym_addr, std::string(), sym_type::EXPORT, sym_obj_type::FUNC));
    }

    this->find_funcs();

    return 0;
}

int PeSyms::find_cfg_funcs() {
    uint16_t dll_chars = get_dllChars(m_pe_obj);
    if (!dll_chars) {
//        LOG(ERROR) << "No dll characteristics to find CFG blocks in";
        return 1;
    }

    if (!(dll_chars & COFF::IMAGE_DLL_CHARACTERISTICS_GUARD_CF)) {
        return 1;
    }

    const data_directory *DataEntry;
    // work around: https://bugs.llvm.org/show_bug.cgi?id=34108
    if (m_pe_obj->getDataDirectory(COFF::LOAD_CONFIG_TABLE, DataEntry)) {
        LOG(WARNING) << "Binary missing load config";
        return 1;
    }
    else if (DataEntry->RelativeVirtualAddress == 0x0) {
        LOG(WARNING) << "Null load address";
        return 1;
    }

    uint64_t guard_table_va = 0;
    uint64_t guard_table_cnt = 0;
    uint32_t guard_flags = 0;

    if (!m_pe_obj->is64()) {
        const coff_load_configuration32 *load_config = m_pe_obj->getLoadConfig32();
        if (load_config) {
            guard_table_va = load_config->GuardCFFunctionTable;
            guard_table_cnt = load_config->GuardCFFunctionCount;
            guard_flags = load_config->GuardFlags;
        }
        else {
            LOG(ERROR) << "Failed to get 32bit load config";
            return 1;
        }
    }
    else {
        const coff_load_configuration64 *load_config = m_pe_obj->getLoadConfig64();
        if (load_config) {
            guard_table_va = load_config->GuardCFFunctionTable;
            guard_table_cnt = load_config->GuardCFFunctionCount;
            guard_flags = load_config->GuardFlags;
        }
        else {
            LOG(ERROR) << "Failed to get 32bit load config";
            return 1;
        }
    }

    if (!guard_table_va || !guard_table_cnt) {
        LOG(ERROR) << "Empty / null guard table";
        return 1;
    }


    uint8_t entry_size = 0;
    if (guard_flags & uint32_t(coff_guard_flags::FidTableHasFlags)) {
        entry_size = 5;
    }
    else {
        entry_size = 6;
    }

    uintptr_t TableStart, TableEnd;
    if (std::error_code EC = m_pe_obj->getVaPtr(guard_table_va, TableStart)) {
        LOG(ERROR) << "Failed to get guard table start pointer, vaddr: 0x" << std::hex << guard_table_va;
        return 1;
    }
    if (std::error_code EC = m_pe_obj->getVaPtr(guard_table_va + guard_table_cnt * entry_size - 1, TableEnd)) {
        LOG(ERROR) << "Failed to get guard table end pointer";
        return 1;
    }
    TableEnd++;

    for (uintptr_t I = TableStart; I < TableEnd; I += entry_size) {
        uint32_t RVA = *reinterpret_cast<const support::ulittle32_t *>(I);
        uint64_t guard_func = m_pe_obj->getImageBase() + RVA;

        if (!m_syms_by_addr.count(guard_func)) {
//            LOG(INFO) << "CfgFunc addr: 0x" << std::hex << guard_func;
            m_found_funcs.emplace(guard_func, Symbol(std::string(), guard_func, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
        }
    }

    return 0;
}

bool PeSyms::get_pdata_section(std::vector<RelocationRef> *rels, const llvm::Win64EH::RuntimeFunction *&rfstart, uint32_t *num_rfs) {
    CHECK(rels) << "Invalid rels pointer passed";

    for (const SectionRef &section : m_pe_obj->sections()) {
        Expected<StringRef> nameOrErr = section.getName();
        if (!nameOrErr) {
            std::error_code EC = errorToErrorCode(nameOrErr.takeError());
            LOG(ERROR) << "Failed to get section name: " << EC.message();
            continue;
        }
        auto sect_name = *nameOrErr;

        if (sect_name != ".pdata") {
            continue;
        }

        for (const RelocationRef &reloc : section.relocations()) {
            rels->push_back(reloc);
        }


        Expected<StringRef> sectDataErr = section.getContents();
        if (!sectDataErr) {
            LOG(ERROR) << "Failed to get .pdata section contents";
            return false;
        }
        auto contents = sectDataErr.get();

        if (contents.empty() || !contents.data()) {
            continue;
        }

        rfstart = reinterpret_cast<const llvm::Win64EH::RuntimeFunction *>(contents.data());
        *num_rfs = contents.size() / sizeof(llvm::Win64EH::RuntimeFunction);
        return true;
    }

    return false;
}

int PeSyms::find_unwind_funcs() {
    std::vector<RelocationRef> rels;
    uint32_t num_rfs;
    const llvm::Win64EH::RuntimeFunction *rf_start;

    if (!this->get_pdata_section(&rels, rf_start, &num_rfs)) {
        LOG(ERROR) << "failed to get .pdata section for unwinding";
        return 1;
    }

    for (uint64_t i = 0; i < num_rfs; i++) {
        const auto run_func = rf_start[i];
        if (run_func.StartAddress) {
            uint64_t unwind_info_addr;
            if (std::error_code EC = m_pe_obj->getRvaPtr(run_func.UnwindInfoOffset, unwind_info_addr)) {
                LOG(ERROR) << "Failed to get unwinding info for offset: 0x" << std::hex << run_func.UnwindInfoOffset << " msg: " << EC.message();
                continue;
            }
            const auto *unwind_info = reinterpret_cast<const llvm::Win64EH::UnwindInfo *>(unwind_info_addr);

            // Skip any unwinding info that is contained in other functions.
            if (unwind_info->getFlags() == llvm::Win64EH::UNW_ChainInfo) {
                continue;
            }

            uint64_t func_addr = m_pe_obj->getImageBase() + run_func.StartAddress;
            if (!m_syms_by_addr.count(func_addr)) {
//                LOG(INFO) << "RunFunc addr: 0x" << std::hex << func_addr;
                m_found_funcs.emplace(func_addr, Symbol(std::string(), func_addr, std::string(), sym_type::HIDDEN, sym_obj_type::FUNC));
            }

        }
    }

    return 0;
}


int PeSyms::find_funcs() {
    this->find_cfg_funcs();

    if (m_pe_obj->getMachine() == COFF::IMAGE_FILE_MACHINE_AMD64) {
        this->find_unwind_funcs();
    }

    return 0;
}
