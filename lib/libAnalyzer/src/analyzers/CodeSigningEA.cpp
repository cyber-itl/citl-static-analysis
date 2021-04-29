#include <algorithm>
#include <string>
#include <vector>

#include "json.hpp"
#include "glog/logging.h"

#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers/CodeSigningEA.hpp"

#include "llvm/Object/MachO.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

CodeSigningEA::CodeSigningEA() : BaseEnvAnalyzer("code_signing") {};

template <class ELFT>
int CodeSigningElfEA<ELFT>::run() {
    std::vector<std::string> elf_sig_section;
    Expected<typename ELFT::ShdrRange> sectionsOrErr = m_elf_file->sections();
    if (!sectionsOrErr) {
        LOG(ERROR) << "Failed to get ELFFile sections";
        return 1;
    }
    auto sections = sectionsOrErr.get();

    for(const auto &section : sections) {
        Expected<StringRef> nameOrErr = m_elf_file->getSectionName(&section);
        if (!nameOrErr) {
            continue;
        }
        StringRef name = nameOrErr.get();
        if (name == ".sig") {
            elf_sig_section.emplace_back(name.str());
        }
        else if (name == ".signature") {
            elf_sig_section.emplace_back(name.str());
        }
        else if (name == ".pgptab") {
            elf_sig_section.emplace_back(name.str());
        }
    }

    if (!elf_sig_section.size()) {
        m_results["is_signed"] = false;
    }
    else {
        m_results["is_signed"] = true;
        m_results["elf_sig_section"] = elf_sig_section;
    }

    return 0;
}

int CodeSigningPeEA::run() {
    bool is_signed = false;
    if (m_dll_chars & COFF::IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY) {
        is_signed = true;
    }

    m_results["is_signed"] = is_signed;

    return 0;
}

int CodeSigningMachEA::run() {
    bool is_signed = false;
    for (const auto &load_cmd : m_obj->load_commands()) {
        if (load_cmd.C.cmd != MachO::LC_CODE_SIGNATURE) {
            is_signed = true;
            break;
        }
    }

    m_results["is_signed"] = is_signed;

    return 0;
}

template class CodeSigningElfEA<ELFType<support::little, false>>;
template class CodeSigningElfEA<ELFType<support::big, false>>;
template class CodeSigningElfEA<ELFType<support::little, true>>;
template class CodeSigningElfEA<ELFType<support::big, true>>;
