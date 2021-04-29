#include <algorithm>
#include <system_error>

#include "json.hpp"
#include "glog/logging.h"

#include "analyzers/LibraryEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

LibraryEA::LibraryEA() : BaseEnvAnalyzer("library_data") {};

template <class ELFT>
int LibraryElfEA<ELFT>::run() {
    auto elf_hdr = m_elf_file->getHeader();

    if (!elf_hdr) {
        LOG(ERROR) << "Failed to get elf header";
        return 1;
    }

    bool is_dso = false;
    switch (elf_hdr->e_type) {
    case llvm::ELF::ET_REL:
    case llvm::ELF::ET_DYN:
        is_dso = true;
        break;
    case llvm::ELF::ET_EXEC:
        is_dso = false;
    }

    auto ProgramHeaderOrError = m_elf_file->program_headers();
    if (!ProgramHeaderOrError) {
        LOG(ERROR) << "Failed to get program headers";
        return 1;
    }

    bool has_interp = false;
    for (const typename ELFFile<ELFT>::Elf_Phdr &p_hdr : ProgramHeaderOrError.get()) {
        if (p_hdr.p_type == ELF::PT_INTERP) {
            has_interp = true;
            break;
        }
    }

    m_results["soname"] = m_soname;
    m_results["is_dso"] = is_dso;
    m_results["has_interp"] = has_interp;

    bool is_library = false;
    if (is_dso) {
        if (!has_interp) {
            is_library = true;
        }
        else {
            // Here we have a special case for 'lib.so', this is because the JLI or java native launcher
            // has a bug that accidentally fills in this field.  So in readelf -d you might see:
            //  0x000000000000000e (SONAME)             Library soname: [lib.so]
            //  0x000000000000000f (RPATH)              Library rpath: [$ORIGIN/../lib/amd64/jli:$ORIGIN/../lib/amd64]
            if (!m_soname.empty() && m_soname != "lib.so") {
                is_library = true;
            }

        }
    }
    m_results["is_lib"] = is_library;

    m_results["library_deps"] = m_mods;

    return 0;
}

int LibraryPeEA::run() {
    if (m_pe_chars & llvm::COFF::IMAGE_FILE_DLL) {
        m_results["is_lib"] = true;
    }
    else {
        m_results["is_lib"] = false;
    }

    std::vector<std::string> modules;
    for (const ImportDirectoryEntryRef &DirRef : m_obj->import_directories()) {
        StringRef module_name;
        if (std::error_code EC = DirRef.getName(module_name)) {
            LOG(ERROR) << "Failed to get module name: " << EC.message();
            continue;
        }
        modules.emplace_back(module_name.str());
    }

    m_results["library_deps"] = modules;

    return 0;
}

int LibraryMachEA::run() {
    const MachO::mach_header hdr = m_obj->getHeader();
    if (hdr.filetype == MachO::MH_EXECUTE) {
        m_results["is_lib"] = false;
    }
    else {
        m_results["is_lib"] = true;
    }

    std::vector<std::string> modules;

    for (const auto &load_cmd : m_obj->load_commands()) {
        if (load_cmd.C.cmd == MachO::LC_ID_DYLIB ||
            load_cmd.C.cmd == MachO::LC_LOAD_DYLIB ||
            load_cmd.C.cmd == MachO::LC_LOAD_WEAK_DYLIB ||
            load_cmd.C.cmd == MachO::LC_REEXPORT_DYLIB ||
            load_cmd.C.cmd == MachO::LC_LAZY_LOAD_DYLIB ||
            load_cmd.C.cmd == MachO::LC_LOAD_UPWARD_DYLIB) {

            MachO::dylib_command dl = m_obj->getDylibIDLoadCommand(load_cmd);
            if (dl.dylib.name < dl.cmdsize) {
                const auto *char_name = static_cast<const char *>((load_cmd.Ptr) + dl.dylib.name);
                if (!char_name) {
                    continue;
                }
                std::string name(char_name);
                modules.emplace_back(name);
            }
        }
    }

    m_results["library_deps"] = modules;

    return 0;
}



template class LibraryElfEA<ELFType<support::little, false>>;
template class LibraryElfEA<ELFType<support::big, false>>;
template class LibraryElfEA<ELFType<support::little, true>>;
template class LibraryElfEA<ELFType<support::big, true>>;

