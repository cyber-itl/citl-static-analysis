#include <cstdint>
#include <string>

#include "json.hpp"
#include "glog/logging.h"

#include "analyzers/DriverEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"


DriverEA::DriverEA() : BaseEnvAnalyzer("driver") {};

template <class ELFT>
int DriverElfEA<ELFT>::run() {
    bool is_driver = false;
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
        if (name == ".modinfo") {
            // TODO: This is not adequte, the .modinfo is optional for kernel modules.
            // Using symbols and other factors should be used instead to create a few indicators.
            is_driver = true;
        }
    }

    m_results["is_driver"] = is_driver;

    return 0;
}

int DriverPeEA::run() {
    bool is_driver = false;

    const pe32plus_header *PEPlusHeader = m_obj->getPE32PlusHeader();

    if (PEPlusHeader) {
        if (PEPlusHeader->Subsystem == COFF::IMAGE_SUBSYSTEM_NATIVE) {
            is_driver = true;
        }
    } else {
        LOG(ERROR) << "Failed to get PE32 Plus header";
    }

    m_results["is_driver"] = is_driver;
    return 0;
}

int DriverMachEA::run() {
    bool is_driver = false;

    if (!m_obj->is64Bit()) {
        const MachO::mach_header hdr = m_obj->getHeader();

        if (hdr.filetype == MachO::MH_KEXT_BUNDLE) {
            is_driver = true;
        }
    }
    else {
        const MachO::mach_header_64 hdr = m_obj->getHeader64();
        if (hdr.filetype == MachO::MH_KEXT_BUNDLE) {
            is_driver = true;
        }
    }

    m_results["is_driver"] = is_driver;

    return 0;
}


template class DriverElfEA<ELFType<support::little, false>>;
template class DriverElfEA<ELFType<support::big, false>>;
template class DriverElfEA<ELFType<support::little, true>>;
template class DriverElfEA<ELFType<support::big, true>>;
