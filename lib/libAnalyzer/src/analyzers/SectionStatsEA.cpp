#include <algorithm>
#include <cstdint>
#include <map>
#include <system_error>

#include "json.hpp"
#include "glog/logging.h"

#include "analyzers/UtilsEA.hpp"
#include "analyzers/SectionStatsEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"


SectionStatsEA::SectionStatsEA() : BaseEnvAnalyzer("section_stats") {};

template <class ELFT>
int SectionStatsElfEA<ELFT>::run() {
    uint64_t text_size = 0;
    std::vector<std::string> text_flags;
    std::map<uint8_t, uint64_t> text_entropy;

    uint64_t data_size = 0;
    std::vector<std::string> data_flags;
    std::map<uint8_t, uint64_t> data_entropy;

    Expected<typename ELFT::ShdrRange> sectionsOrErr = m_elf_file->sections();
    if (!sectionsOrErr) {
        LOG(ERROR) << "Failed to get ELFFile sections";
        return 1;
    }
    auto sections = sectionsOrErr.get();

    if (sections.empty()) {
        LOG(WARNING) << "Falling back to program headers for section stats because a lack of sections";

        auto prog_hdrs = m_elf_file->program_headers();
        if (prog_hdrs) {
            for (const auto &hdr : *prog_hdrs) {
                if (hdr.p_flags & ELF::PF_X) {
                    text_size += hdr.p_filesz;
                    text_flags = this->map_pflags(hdr.p_flags);
                    // TODO: Add a iterative entropy_hist generator
                }
                else if (hdr.p_flags & ELF::PF_R) {
                    data_size += hdr.p_filesz;
                    data_flags = this->map_pflags(hdr.p_flags);

                }

            }
        }
    }
    else {
        for(const auto &section : sections) {
            Expected<StringRef> nameOrErr = m_elf_file->getSectionName(&section);
            if (!nameOrErr) {
                continue;
            }
            StringRef name = nameOrErr.get();
            if (name == ".text") {
                text_size = section.sh_size;
                text_flags = map_shflags(section.sh_flags);
                Expected<ArrayRef<uint8_t>>  text_data = m_elf_file->template getSectionContentsAsArray<uint8_t>(&section);
                if (!text_data) {
                    std::error_code EC = errorToErrorCode(text_data.takeError());
                    LOG(WARNING) << "Failed to get .text section data: " << EC.message();
                    continue;
                }
                text_entropy = make_entropy_hist(text_data.get().data(), text_size);
            }
            else if (name == ".data") {
                data_size = section.sh_size;
                data_flags = map_shflags(section.sh_flags);
                Expected<ArrayRef<uint8_t>> data_data = m_elf_file->template getSectionContentsAsArray<uint8_t>(&section);
                if (!data_data) {
                    std::error_code EC = errorToErrorCode(data_data.takeError());
                    LOG(WARNING) << "Failed to get .data section data: " << EC.message();
                    continue;
                }

                data_entropy = make_entropy_hist(data_data.get().data(), data_size);

            }
        }
    }

    m_results["text_size"] = text_size;
    m_results["text_flags"] = text_flags;
    m_results["text_entropy"] = text_entropy;

    m_results["data_size"] = data_size;
    m_results["data_flags"] = data_flags;
    m_results["data_entropy"] = data_entropy;

    return 0;
}

template <class ELFT>
std::vector<std::string> SectionStatsElfEA<ELFT>::map_shflags(uint32_t flags) {
    std::vector<std::string> str_flags;
    if (flags & ELF::SHF_WRITE) {
        str_flags.emplace_back("SHF_WRITE");
    }
    if (flags & ELF::SHF_ALLOC) {
        str_flags.emplace_back("SHF_ALLOC");
    }
    if (flags & ELF::SHF_EXECINSTR) {
        str_flags.emplace_back("SHF_EXECINSTR");
    }
    if (flags & ELF::SHF_MERGE) {
        str_flags.emplace_back("SHF_MERGE");
    }
    if (flags & ELF::SHF_STRINGS) {
        str_flags.emplace_back("SHF_STRINGS");
    }
    if (flags & ELF::SHF_INFO_LINK) {
        str_flags.emplace_back("SHF_INFO_LINK");
    }
    if (flags & ELF::SHF_OS_NONCONFORMING) {
        str_flags.emplace_back("SHF_OS_NONCONFORMING");
    }
    if (flags & ELF::SHF_TLS) {
        str_flags.emplace_back("SHF_TLS");
    }
    if (flags & ELF::SHF_COMPRESSED) {
        str_flags.emplace_back("SHF_COMPRESSED");
    }
    return str_flags;
}

template <class ELFT>
std::vector<std::string> SectionStatsElfEA<ELFT>::map_pflags(uint32_t flags) {
    std::vector<std::string> str_flags;
    if (flags & ELF::PF_R) {
        str_flags.emplace_back("PF_R");
    }
    if (flags & ELF::PF_W) {
        str_flags.emplace_back("PF_W");
    }
    if (flags & ELF::PF_X) {
        str_flags.emplace_back("PF_X");
    }
    return str_flags;
}



int SectionStatsPeEA::run() {
    uint64_t text_size = 0;
    std::vector<std::string> text_flags;
    std::map<uint8_t, uint64_t> text_entropy;

    uint64_t data_size = 0;
    std::vector<std::string> data_flags;
    std::map<uint8_t, uint64_t> data_entropy;

    uint32_t code_section_count = 0;
    std::vector<std::string> code_section_names;

    for (const SectionRef &section : m_obj->sections()) {
        Expected<StringRef> nameOrErr = section.getName();
        if (!nameOrErr) {
            std::error_code EC = errorToErrorCode(nameOrErr.takeError());
            LOG(ERROR) << "Failed to get section name: " << EC.message();
            continue;
        }
        auto sect_name = *nameOrErr;

        const coff_section *raw_sect = m_obj->getCOFFSection(section);

        if (raw_sect->Characteristics & COFF::IMAGE_SCN_CNT_CODE){
            code_section_count++;
            code_section_names.emplace_back(sect_name.str());
        }

        if (sect_name == ".text") {
            text_flags = this->map_flags(raw_sect->Characteristics);
            text_size = raw_sect->SizeOfRawData;

            Expected<StringRef> sectDataErr = section.getContents();
            if (!sectDataErr) {
                std::error_code EC = errorToErrorCode(sectDataErr.takeError());
                LOG(ERROR) << "Failed to get section: " << sect_name.str() << " err: " << EC.message();
                continue;
            }
            auto sect_data = sectDataErr.get();
            text_entropy = make_entropy_hist(sect_data.bytes_begin(), text_size);
        }
        else if (sect_name == ".data") {
            data_flags = this->map_flags(raw_sect->Characteristics);
            data_size = raw_sect->SizeOfRawData;

            Expected<StringRef> sectDataErr = section.getContents();
            if (!sectDataErr) {
                std::error_code EC = errorToErrorCode(sectDataErr.takeError());
                LOG(ERROR) << "Failed to get section: " << sect_name.str() << " err: " << EC.message();
                continue;
            }
            auto sect_data = sectDataErr.get();

            data_entropy = make_entropy_hist(sect_data.bytes_begin(), data_size);
        }
    }

    const pe32plus_header *hdrPlus = nullptr;
    const pe32_header *hdr = m_obj->getPE32Header();
    if (!hdr) {
        hdrPlus = m_obj->getPE32PlusHeader();
        if (!hdrPlus) {
            LOG(ERROR) << "Failed to get PE header";
            return 1;
        }
    }

    uint64_t size_of_code = 0;
    uint64_t size_of_init_data = 0;
    uint64_t stack_commit_size = 0;
    uint64_t stack_reserve_size = 0;
    uint64_t heap_commit_size = 0;
    uint64_t heap_reserve_size = 0;


    if (hdr) {
        size_of_code = hdr->SizeOfCode;
        size_of_init_data = hdr->SizeOfInitializedData;
        stack_commit_size = hdr->SizeOfStackCommit;
        stack_reserve_size = hdr->SizeOfStackReserve;
        heap_commit_size = hdr->SizeOfHeapCommit;
        heap_reserve_size = hdr->SizeOfHeapReserve;
    }
    else {
        size_of_code = hdrPlus->SizeOfCode;
        size_of_init_data = hdrPlus->SizeOfInitializedData;
        stack_commit_size = hdrPlus->SizeOfStackCommit;
        stack_reserve_size = hdrPlus->SizeOfStackReserve;
        heap_commit_size = hdrPlus->SizeOfHeapCommit;
        heap_reserve_size = hdrPlus->SizeOfHeapReserve;
    }

    m_results["code_section_count"] = code_section_count;
    m_results["code_section_names"] = code_section_names;

    m_results["text_size"] = text_size;
    m_results["text_flags"] = text_flags;
    m_results["text_entropy"] = text_entropy;

    m_results["data_size"] = data_size;
    m_results["data_flags"] = data_flags;
    m_results["data_entropy"] = data_entropy;

    m_results["size_of_code"] = size_of_code;
    m_results["size_of_init_data"] = size_of_init_data;
    m_results["stack_commit_size"] = stack_commit_size;
    m_results["stack_reserve_size"] = stack_reserve_size;
    m_results["heap_commit_size"] = heap_commit_size;
    m_results["heap_reserve_size"] = heap_reserve_size;

    return 0;
}

std::vector<std::string> SectionStatsPeEA::map_flags(uint32_t flags) {
    std::vector<std::string> str_flags;
    if (flags & COFF::IMAGE_SCN_MEM_SHARED) {
        str_flags.emplace_back("IMAGE_SCN_MEM_SHARED");
    }
    if (flags & COFF::IMAGE_SCN_MEM_EXECUTE) {
        str_flags.emplace_back("IMAGE_SCN_MEM_EXECUTE");
    }
    if (flags & COFF::IMAGE_SCN_MEM_READ) {
        str_flags.emplace_back("IMAGE_SCN_MEM_READ");
    }
    if (flags & COFF::IMAGE_SCN_MEM_WRITE) {
        str_flags.emplace_back("IMAGE_SCN_MEM_WRITE");
    }

    return str_flags;
}

int SectionStatsMachEA::run() {
    uint64_t text_size = 0;
    std::vector<std::string> text_initprot;
    std::vector<std::string> text_maxprot;

    uint64_t data_size = 0;
    std::vector<std::string> data_initprot;
    std::vector<std::string> data_maxprot;

    bool is_root_safe = false;
    bool is_setuid_safe = false;
    bool split_segments = false;

    if (!m_obj->is64Bit()) {
        is_root_safe = check_flags(m_obj->getHeader(), MachO::MH_ROOT_SAFE);
        is_setuid_safe = check_flags(m_obj->getHeader(), MachO::MH_SETUID_SAFE);
        split_segments = check_flags(m_obj->getHeader(), MachO::MH_SPLIT_SEGS);
    }
    else {
        is_root_safe = check_flags(m_obj->getHeader64(), MachO::MH_ROOT_SAFE);
        is_setuid_safe = check_flags(m_obj->getHeader(), MachO::MH_SETUID_SAFE);
        split_segments = check_flags(m_obj->getHeader(), MachO::MH_SPLIT_SEGS);
    }

    for (const auto &load_cmd : m_obj->load_commands()) {
        if (load_cmd.C.cmd != MachO::LC_SEGMENT && load_cmd.C.cmd != MachO::LC_SEGMENT_64) {
            continue;
        }
        std::string name;
        uint64_t size = 0;
        uint32_t init_prot = 0;
        uint32_t max_prot = 0;
        if (!m_obj->is64Bit()) {
            MachO::segment_command SC = m_obj->getSegmentLoadCommand(load_cmd);
            name = std::string(SC.segname);
            size = SC.filesize;
            max_prot = SC.maxprot;
            init_prot = SC.initprot;
        }
        else {
            MachO::segment_command_64 SC = m_obj->getSegment64LoadCommand(load_cmd);
            name = std::string(SC.segname);
            size = SC.filesize;
            max_prot = SC.maxprot;
            init_prot = SC.initprot;
        }

        if (name == "__TEXT") {
            text_size = size;
            text_maxprot = map_seg_flags(max_prot);
            text_initprot = map_seg_flags(init_prot);
        }
        else if (name == "__DATA") {
            data_size = size;
            data_maxprot = map_seg_flags(max_prot);
            data_initprot = map_seg_flags(init_prot);
        }
    }

    uint64_t text_section_size = 0;
    std::map<uint8_t, uint64_t> text_section_entropy;
    std::vector<std::string> text_section_flags;

    uint64_t data_section_size = 0;
    std::map<uint8_t, uint64_t> data_section_entropy;
    std::vector<std::string> data_section_flags;

    for (const auto &section : m_obj->sections()) {
        Expected<StringRef> nameOrErr = section.getName();
        if (!nameOrErr) {
            std::error_code EC = errorToErrorCode(nameOrErr.takeError());
            LOG(ERROR) << "Failed to get section name: " << EC.message();
            continue;
        }
        auto sect_name = *nameOrErr;

        uint64_t size = 0;
        uint32_t flags = 0;
        if (sect_name != "__text" && sect_name != "__data") {
            continue;
        }

        if (!m_obj->is64Bit()) {
            MachO::section Sect = m_obj->getSection(section.getRawDataRefImpl());
            size = Sect.size;
            flags = Sect.flags;
        }
        else {
            MachO::section_64 Sect = m_obj->getSection64(section.getRawDataRefImpl());
            size = Sect.size;
            flags = Sect.flags;
        }

        std::map<uint8_t, uint64_t> entropy;

        Expected<StringRef> sectDataErr = section.getContents();
        if (!sectDataErr) {
            std::error_code EC = errorToErrorCode(sectDataErr.takeError());
            LOG(ERROR) << "Failed to get mach section contents: " << EC.message();
        }
        else {
            auto sect_data = sectDataErr.get();
            entropy = make_entropy_hist(sect_data.bytes_begin(), size);
        }

        if (sect_name == "__text") {
            text_section_size = size;
            text_section_flags = map_sec_flags(flags);
            text_section_entropy = entropy;
        }
        else if (sect_name == "__data") {
            data_section_size = size;
            data_section_flags = map_sec_flags(flags);
            data_section_entropy = entropy;
        }

    }

    m_results["is_root_safe"] = is_root_safe;
    m_results["is_setuid_safe"] = is_setuid_safe;
    m_results["split_segments"] = split_segments;

    m_results["text_size"] = text_size;
    m_results["text_segment_maxprot"] = text_maxprot;
    m_results["text_segment_initprot"] = text_initprot;

    m_results["data_size"] = data_size;
    m_results["data_segment_maxprot"] = data_maxprot;
    m_results["data_segment_initprot"] = data_initprot;

    m_results["text_section_size"] = text_section_size;
    m_results["text_section_flags"] = text_section_flags;
    m_results["text_section_entropy"] = text_section_entropy;

    m_results["data_section_size"] = data_section_size;
    m_results["data_section_flags"] = data_section_flags;
    m_results["data_section_entropy"] = data_section_entropy;


    return 0;
}

std::vector<std::string> SectionStatsMachEA::map_seg_flags(uint32_t flags) {
    std::vector<std::string> str_flags;
    if (flags & MachO::VM_PROT_READ) {
        str_flags.emplace_back("VM_PROT_READ");
    }
    if (flags & MachO::VM_PROT_WRITE) {
        str_flags.emplace_back("VM_PROT_WRITE");
    }
    if (flags & MachO::VM_PROT_EXECUTE) {
        str_flags.emplace_back("VM_PROT_EXECUTE");
    }
    return str_flags;
}

std::vector<std::string> SectionStatsMachEA::map_sec_flags(uint32_t flags) {
    std::vector<std::string> str_flags;
    if (flags & MachO::S_ATTR_PURE_INSTRUCTIONS) {
        str_flags.emplace_back("S_ATTR_PURE_INSTRUCTIONS");
    }
    if (flags & MachO::S_ATTR_NO_TOC) {
        str_flags.emplace_back("S_ATTR_NO_TOC");
    }
    if (flags & MachO::S_ATTR_STRIP_STATIC_SYMS) {
        str_flags.emplace_back("S_ATTR_STRIP_STATIC_SYMS");
    }
    if (flags & MachO::S_ATTR_NO_DEAD_STRIP) {
        str_flags.emplace_back("S_ATTR_NO_DEAD_STRIP");
    }
    if (flags & MachO::S_ATTR_LIVE_SUPPORT) {
        str_flags.emplace_back("S_ATTR_LIVE_SUPPORT");
    }
    if (flags & MachO::S_ATTR_SELF_MODIFYING_CODE) {
        str_flags.emplace_back("S_ATTR_SELF_MODIFYING_CODE");
    }
    if (flags & MachO::S_ATTR_DEBUG) {
        str_flags.emplace_back("S_ATTR_DEBUG");
    }
    if (flags & MachO::S_ATTR_SOME_INSTRUCTIONS) {
        str_flags.emplace_back("S_ATTR_SOME_INSTRUCTIONS");
    }
    if (flags & MachO::S_ATTR_EXT_RELOC) {
        str_flags.emplace_back("S_ATTR_EXT_RELOC");
    }
    if (flags & MachO::S_ATTR_LOC_RELOC) {
        str_flags.emplace_back("S_ATTR_LOC_RELOC");
    }
    if (flags & MachO::INDIRECT_SYMBOL_LOCAL) {
        str_flags.emplace_back("INDIRECT_SYMBOL_LOCAL");
    }
    if (flags & MachO::INDIRECT_SYMBOL_ABS) {
        str_flags.emplace_back("INDIRECT_SYMBOL_ABS");
    }

    return str_flags;
}



template class SectionStatsElfEA<ELFType<support::little, false>>;
template class SectionStatsElfEA<ELFType<support::big, false>>;
template class SectionStatsElfEA<ELFType<support::little, true>>;
template class SectionStatsElfEA<ELFType<support::big, true>>;

