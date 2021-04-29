#include <cstdint>

#include "glog/logging.h"

#include "analyzers/DepEA.hpp"
#include "analyzers/AslrEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"


DepEA::DepEA() : BaseEnvAnalyzer("dep") {};

template <class ELFT>
int DepElfEA<ELFT>::run() {
    auto ProgramHeaderOrError = m_elf_file->program_headers();
    if (!ProgramHeaderOrError) {
        LOG(ERROR) << "Failed to get program headers";
        return 1;
    }

    bool allow_stack_exec = false;
    bool have_stack_seg = false;
    bool have_openbsd_randdat = false;

    for (const typename ELFFile<ELFT>::Elf_Phdr &p_hdr : ProgramHeaderOrError.get()) {
        if (p_hdr.p_type == ELF::PT_GNU_STACK) {
            if (p_hdr.p_flags & ELF::PF_X) {
                allow_stack_exec = true;
            }
            have_stack_seg = true;
            break;
        }
        if (p_hdr.p_type == ELF::PT_OPENBSD_RANDOMIZE) {
            have_openbsd_randdat = true;
        }
    }

    // Linux defaults to a RWX stack if the segment
    // header is not present on the following arch's
    // This code might need to be moved into the summary model so it can be easier to adjust.
    if (!have_stack_seg) {
        if (!have_openbsd_randdat) {
            unsigned int obj_arch = m_obj->getArch();
            switch(obj_arch) {
            case Triple::x86:
            case Triple::x86_64:
            case Triple::arm:
            case Triple::armeb:
            case Triple::aarch64:
            case Triple::aarch64_be:
            case Triple::mips:
            case Triple::mipsel:
            case Triple::mips64:
            case Triple::mips64el:
            case Triple::ppc:
            case Triple::ppc64:
            case Triple::ppc64le:
                allow_stack_exec = true;
                break;
            }
        }
        else {
            allow_stack_exec = false;
        }
    }


    m_results["have_gnu_stack"] = have_stack_seg;
    m_results["allow_stack_exec"] = allow_stack_exec;
    m_results["have_openbsd_rand_dat"] = have_openbsd_randdat;

    return 0;
}

int DepPeEA::run() {
    bool nx_compat = false;

    if (m_dll_chars & COFF::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT) {
        nx_compat = true;
    }

    m_results["nx_compat"] = nx_compat;
    return 0;
}

int DepMachEA::run() {
    bool allow_stack_exec = false;
    if (!m_obj->is64Bit()) {
        allow_stack_exec = check_flags(m_obj->getHeader(), MachO::MH_ALLOW_STACK_EXECUTION);
    }
    else {
        allow_stack_exec = check_flags(m_obj->getHeader64(), MachO::MH_ALLOW_STACK_EXECUTION);
    }

    m_results["allow_stack_exec"] = allow_stack_exec;

    return 0;
}


template class DepElfEA<ELFType<support::little, false>>;
template class DepElfEA<ELFType<support::big, false>>;
template class DepElfEA<ELFType<support::little, true>>;
template class DepElfEA<ELFType<support::big, true>>;
