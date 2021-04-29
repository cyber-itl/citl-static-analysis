#include <cstdint>
#include <string>

#include "json.hpp"
#include "analyzers/StrippedEA.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

StrippedEA::StrippedEA() : BaseEnvAnalyzer("stripped") {};

template <class ELFT>
int StrippedElfEA<ELFT>::run() {
    bool has_sections = true;
    if (m_obj->section_begin() == m_obj->section_end()) {
        has_sections = false;
    }

    bool has_dynamic = false;

    auto prog_hdrs = m_elf_file->program_headers();
    if (prog_hdrs) {
        for (const auto &hdr : *prog_hdrs) {
            if (hdr.p_type == ELF::PT_DYNAMIC) {
                has_dynamic = true;
                break;
            }
        }
    }

    m_results["has_sections"] = has_sections;
    m_results["has_dynamic_seg"] = has_dynamic;

    return 0;
}

template class StrippedElfEA<ELFType<support::little, false>>;
template class StrippedElfEA<ELFType<support::big, false>>;
template class StrippedElfEA<ELFType<support::little, true>>;
template class StrippedElfEA<ELFType<support::big, true>>;
