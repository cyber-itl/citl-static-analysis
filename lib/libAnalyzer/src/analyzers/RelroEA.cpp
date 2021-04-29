#include <cstdint>

#include "json.hpp"
#include "glog/logging.h"

#include "analyzers/RelroEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

template <class ELFT>
int RelroElfEA<ELFT>::run() {
    auto ProgramHeaderOrError = m_elf_file->program_headers();
    if (!ProgramHeaderOrError) {
        LOG(ERROR) << "Failed to get program headers";
        return 1;
    }

    bool has_relro = false;
    bool has_bindnow = false;

    for (const typename ELFFile<ELFT>::Elf_Phdr &p_hdr : *ProgramHeaderOrError) {
        if (p_hdr.p_type == ELF::PT_GNU_RELRO) {
            has_relro = true;
            break;
        }
    }

    for (const auto &dyn : m_dyn_tags) {
        if (dyn.tag == ELF::DT_BIND_NOW) {
            has_bindnow = true;
            break;
        }
    }

    m_results["RELRO"] = has_relro;
    m_results["BINDNOW"] = has_bindnow;
    return 0;
}


template class RelroElfEA<ELFType<support::little, false>>;
template class RelroElfEA<ELFType<support::big, false>>;
template class RelroElfEA<ELFType<support::little, true>>;
template class RelroElfEA<ELFType<support::big, true>>;
