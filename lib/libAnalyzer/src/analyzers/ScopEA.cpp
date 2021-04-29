#include <cstdint>

#include "json.hpp"
#include "glog/logging.h"

#include "analyzers/ScopEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

template <class ELFT>
int ScopElfEA<ELFT>::run() {
    auto ProgramHeaderOrError = m_elf_file->program_headers();
    if (!ProgramHeaderOrError) {
        LOG(ERROR) << "Failed to get program headers";
        return 1;
    }

    uint64_t load_cnt = 0;

    for (const typename ELFFile<ELFT>::Elf_Phdr &p_hdr : *ProgramHeaderOrError) {
        if (p_hdr.p_type == ELF::PT_LOAD) {
            load_cnt += 1;
        }
    }

    m_results["load_count"] = load_cnt;
    return 0;
}


template class ScopElfEA<ELFType<support::little, false>>;
template class ScopElfEA<ELFType<support::big, false>>;
template class ScopElfEA<ELFType<support::little, true>>;
template class ScopElfEA<ELFType<support::big, true>>;
