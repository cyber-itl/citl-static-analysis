#include <memory>
#include <algorithm>
#include <string>
#include <tuple>
#include <utility>

#include "gflags/gflags.h"
#include "glog/logging.h"
#include "capstone/capstone.h"

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

using namespace llvm;
using namespace object;

#include "ElfHandler.hpp"
#include "ElfSyms.hpp"
#include "SymResolver.hpp"

#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"

#include "analyzers/LibraryEA.hpp"
#include "analyzers/AslrEA.hpp"
#include "analyzers/DepEA.hpp"
#include "analyzers/SectionStatsEA.hpp"
#include "analyzers/CodeSigningEA.hpp"

#include "analyzers/RelroEA.hpp"
#include "analyzers/DriverEA.hpp"
#include "analyzers/StrippedEA.hpp"
#include "analyzers/ScopEA.hpp"
#include "analyzers/SpectreWidgetEA.hpp"

#include "analyzers_code/CallStatsCA.hpp"
#include "analyzers_code/BranchCA.hpp"
#include "analyzers_code/RetStatsCA.hpp"
#include "analyzers_code/StackStatsCA.hpp"
#include "analyzers_code/FuncCheckCA.hpp"
#include "analyzers_code/FunctionLists.hpp"
#include "analyzers_code/StackGuardCA.hpp"
#include "analyzers_code/SandboxFuncCA.hpp"
#include "analyzers_code/FortifySourceCA.hpp"
#include "analyzers_code/DynLibLoadCA.hpp"
#include "analyzers_code/SelectableFuncsCA.hpp"
#include "analyzers_code/CodeQACA.hpp"
#include "analyzers_code/FuncInstrStatsCA.hpp"
#include "analyzers_code/RetpolineCA.hpp"
#include "analyzers_code/CorpusRankCfgCA.hpp"

#include "CapstoneHelper.hpp"


DECLARE_bool(all_analyzers);
DECLARE_string(addition_funcs);
DECLARE_bool(spectre_analyzer);
DECLARE_bool(insn_stats_analyzer);
DECLARE_bool(corprank);

template <class ELFT>
ElfHandler<ELFT>::ElfHandler(const ELFObjectFile<ELFT> *elf_obj, const ObjectFile *obj) :
    m_elf_obj(elf_obj),
    m_elf_file(nullptr),
    ArchHandler(obj) {}

template <class ELFT>
int ElfHandler<ELFT>::analyze_format() {
    if (!m_elf_obj->isELF()) {
        LOG(FATAL) << "Bad cast, non-ELF file being processed by ELF analyzer";
    }

    m_elf_file = m_elf_obj->getELFFile();
    if (!m_elf_file) {
        LOG(FATAL) << "Failed to get elf file object";
    }

    auto header = m_elf_file->getHeader();
    if (!header) {
        LOG(FATAL) << "Failed to get elf header";
    }

    if (header->e_machine == ELF::EM_MIPS | header->e_machine == ELF::EM_MIPS_RS3_LE | header->e_machine == ELF::EM_MIPS_X) {
        if (header->e_flags & ELF::EF_MIPS_ARCH_ASE_M16) {
            LOG(FATAL) << "Invalid CPU architecture: MIPS16";
        }
    }

    m_resolver = std::make_shared<ElfSyms<ELFT>>(m_elf_obj, m_memmap);

    if (m_resolver->generate_symbols()) {
        LOG(ERROR) << "Failed to generate ELF symbols, most likely static binary";
    }

    auto ProgramHeaderOrError = m_elf_file->program_headers();
    if (!ProgramHeaderOrError) {
        LOG(ERROR) << "Failed to get program headers";
        return 1;
    }

    auto elf_resolver = std::dynamic_pointer_cast<ElfSyms<ELFT>>(m_resolver);
    auto dyn_tags = elf_resolver->get_dyn_tags();
    std::vector<const typename ELFT::Phdr *> loaded_segs;

    for (const typename ELFFile<ELFT>::Elf_Phdr &p_hdr : *ProgramHeaderOrError) {

        if (p_hdr.p_type != ELF::PT_LOAD || p_hdr.p_filesz == 0) {
            continue;
        }

        loaded_segs.emplace_back(&p_hdr);
    }

    const char *strtab_begin = nullptr;
    uint64_t strtab_size = 0;
    for (const auto &dyn : dyn_tags) {
        switch (dyn.tag) {
        case ELF::DT_STRTAB:
            strtab_begin = (const char *)this->to_mapped_addr(dyn.value, loaded_segs);
            break;
        case ELF::DT_STRSZ:
            strtab_size = dyn.value;
            break;
        }
    }

    std::vector<std::string> modules;
    std::string soname;

    if (strtab_begin && strtab_size) {
        for (const auto &dyn : dyn_tags) {
            if (dyn.tag == ELF::DT_NEEDED) {
                uint64_t value = dyn.value;
                if (value > strtab_size) {
                    LOG(WARNING) << "Bad DT_NEEDED str index: " << std::hex << value;
                    continue;
                }
                modules.emplace_back(strtab_begin + value);
            }
            else if (dyn.tag == ELF::DT_SONAME) {
                uint64_t value = dyn.value;
                if (value > strtab_size) {
                    LOG(WARNING) << "Bad DT_SONAME str index: " << std::hex << value;
                    continue;
                }
                soname = std::string(strtab_begin + value);
            }
        }
    }
    else {
        LOG(ERROR) << "No dynamic section found, most likely static binary";
    }



    // Construct analyzers
    m_env_analyzers.emplace_back(new AslrElfEA<ELFT>(m_elf_obj, m_elf_file));
    m_env_analyzers.emplace_back(new LibraryElfEA<ELFT>(m_elf_obj, m_elf_file, modules, soname));
    m_env_analyzers.emplace_back(new DepElfEA<ELFT>(m_elf_obj, m_elf_file));
    if (FLAGS_all_analyzers) {
        m_env_analyzers.emplace_back(new SectionStatsElfEA<ELFT>(m_elf_obj, m_elf_file));
    }
    if (FLAGS_spectre_analyzer) {
        m_env_analyzers.emplace_back(new SpectreWidgetEA(m_elf_obj));
    }

    m_env_analyzers.emplace_back(new CodeSigningElfEA<ELFT>(m_elf_obj, m_elf_file));

    m_env_analyzers.emplace_back(new RelroElfEA<ELFT>(m_elf_obj, m_elf_file, dyn_tags));
    m_env_analyzers.emplace_back(new DriverElfEA<ELFT>(m_elf_obj, m_elf_file));
    m_env_analyzers.emplace_back(new StrippedElfEA<ELFT>(m_elf_obj, m_elf_file));
    m_env_analyzers.emplace_back(new ScopElfEA<ELFT>(m_elf_obj, m_elf_file));

    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(m_elf_obj->getArch());
    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    // Construct code analyzers
    m_code_analyzers.emplace_back(new CallStatsCA(arch, mode));
    m_code_analyzers.emplace_back(new BranchCA(arch, mode));

    if (FLAGS_all_analyzers) {
        m_code_analyzers.emplace_back(new RetStatsCA(arch, mode));
        m_code_analyzers.emplace_back(new StackStatsCA(arch, mode));
        m_code_analyzers.emplace_back(new StackGuardCA(arch, mode, m_resolver));
        if (FLAGS_insn_stats_analyzer) {
            m_code_analyzers.emplace_back(new FuncInstrStatsCA(arch, mode));
        }
    }

    m_code_analyzers.emplace_back(new SandboxFuncCA(arch, mode, m_resolver));
    m_code_analyzers.emplace_back(new FortifySourceCA(arch, mode, m_resolver));
    m_code_analyzers.emplace_back(new DynLibLoadCA(arch, mode, m_resolver));

    if (!FLAGS_addition_funcs.empty()) {
        m_code_analyzers.emplace_back(new SelectableFuncsCA(arch, mode, m_resolver, m_selected_funcs));
    }

    if (FLAGS_corprank) {
        m_code_analyzers.emplace_back(new CorpusRankCfgCA(arch, mode));
    }

    m_code_analyzers.emplace_back(new CodeQACA(arch, mode, m_resolver));
    m_code_analyzers.emplace_back(new RetpolineCA(arch, mode));

    m_code_analyzers.emplace_back(new FuncCheckCA(arch, mode, m_resolver,
            elf_funcs::good_funcs,
            elf_funcs::risky_funcs,
            elf_funcs::bad_funcs,
            elf_funcs::ick_funcs));

    return 0;
}

template <class ELFT>
uint64_t ElfHandler<ELFT>::get_ep() {
    const typename ELFT::Ehdr *hdr = m_elf_file->getHeader();
    if (!hdr) {
        LOG(ERROR) << "Failed to get elf header";
        return 0;
    }

    return hdr->e_entry;
}

template <class ELFT>
bool compareAddr(uint64_t VAddr, const Elf_Phdr_Impl<ELFT> *Phdr) {
  return VAddr < Phdr->p_vaddr;
}

template <class ELFT>
const uint8_t *ElfHandler<ELFT>::to_mapped_addr(uint64_t addr, std::vector<const typename ELFT::Phdr *> pages) const {
    auto I = std::upper_bound(pages.begin(), pages.end(), addr, compareAddr<ELFT>);
    if (I == pages.begin()) {
        LOG(FATAL) << "Virtual address is not in any segment";
    }
    --I;
    const typename ELFT::Phdr &Phdr = **I;
    uint64_t Delta = addr - Phdr.p_vaddr;
    if (Phdr.p_offset + Delta >= (Phdr.p_filesz + Phdr.p_offset)) {
        LOG(FATAL) << "Virtual address is not in any segment";
    }

    return m_elf_file->base() + Phdr.p_offset + Delta;
}

template class ElfHandler<ELFType<support::little, false>>;
template class ElfHandler<ELFType<support::big, false>>;
template class ElfHandler<ELFType<support::little, true>>;
template class ElfHandler<ELFType<support::big, true>>;
