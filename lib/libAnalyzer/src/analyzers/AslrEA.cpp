#include <string>

#include "glog/logging.h"
#include "json.hpp"

#include "analyzers/AslrEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers/UtilsEA.hpp"

#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Support/Endian.h"


AslrEA::AslrEA() : BaseEnvAnalyzer("aslr") {};

template <class ELFT>
int AslrElfEA<ELFT>::run() {
    auto elf_hdr = m_elf_file->getHeader();

    if (!elf_hdr) {
        LOG(ERROR) << "Failed to get elf header";
        return 1;
    }

    bool is_dso = false;
    if (elf_hdr->e_type == llvm::ELF::ET_DYN) {
        is_dso = true;
    }

    if (elf_hdr->e_machine == llvm::ELF::EM_MIPS) {
        bool mips_pic = false;
        if (elf_hdr->e_flags & llvm::ELF::EF_MIPS_PIC) {
            mips_pic = true;
        }
        m_results["mips_pic"] = mips_pic;
    }

    m_results["is_dso"] = is_dso;

    return 0;
}

int AslrPeEA::run() {
    bool has_aslr = false;
    bool has_dyn_base = false;
    bool has_high_entropy = false;
    bool has_stripped_relocs = false;

    if (m_dll_chars & COFF::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE) {
        has_aslr = true;
        has_dyn_base = true;
        if (m_dll_chars & COFF::IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA) {
            has_high_entropy = true;
        }
    }

    uint16_t pe_chars = m_obj->getCharacteristics();
    if (pe_chars & COFF::IMAGE_FILE_RELOCS_STRIPPED) {
        has_stripped_relocs = true;
    }


    m_results["has_aslr"] = has_aslr;
    m_results["dyn_base"] = has_dyn_base;
    m_results["high_entropy_va"] = has_high_entropy;
    m_results["stripped_relocs"] = has_stripped_relocs;
    return 0;
}

int AslrMachEA::run() {
    bool has_aslr_flag = false;
    if (!m_obj->is64Bit()) {
        has_aslr_flag = check_flags(m_obj->getHeader(), MachO::MH_PIE);
    }
    else {
        has_aslr_flag = check_flags(m_obj->getHeader64(), MachO::MH_PIE);
    }

    m_results["has_aslr"] = has_aslr_flag;

    return 0;
}


template class AslrElfEA<ELFType<support::little, false>>;
template class AslrElfEA<ELFType<support::big, false>>;
template class AslrElfEA<ELFType<support::little, true>>;
template class AslrElfEA<ELFType<support::big, true>>;
