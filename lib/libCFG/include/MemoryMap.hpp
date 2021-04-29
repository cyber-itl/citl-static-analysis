#pragma once

#include <map>
#include <cstdint>
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "glog/logging.h"

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/ELF.h"

using namespace llvm;
using namespace object;

struct MemPage {
    MemPage(uint64_t address, uint64_t size, const std::string &name, const char *data, bool is_text, bool empty_page);
    MemPage(uint64_t address, uint64_t size, const std::string &name, const uint8_t *data, bool is_text);

    uint64_t address;
    uint64_t size;
    std::string name;
    std::size_t name_hash;
    const uint8_t *data;
    bool is_text;
    bool empty_page;
};

class MemoryMap {
  public:
    explicit MemoryMap(const ObjectFile *obj);

    template <class ELFT>
    int populate_elf_pages(const ELFObjectFile<ELFT> *elf_obj) {
        using ELFO = ELFFile<ELFT>;
        const ELFFile<ELFT> *elf_file = elf_obj->getELFFile();
        if (!elf_file) {
            LOG(FATAL) << "Failed to get elf file object";
        }

        auto ProgramHeaderOrError = elf_file->program_headers();
        if (!ProgramHeaderOrError) {
            LOG(WARNING) << "Failed to get program headers in elf file";
            return 1;
        }

        const uint8_t *base_ptr = elf_file->base();
        uint64_t max_size = elf_file->getBufSize();

        for (const typename ELFO::Elf_Phdr &phdr : *ProgramHeaderOrError) {
            uint64_t address = phdr.p_vaddr;
            uint64_t size = phdr.p_filesz;
            uint64_t offset = phdr.p_offset;

            bool is_text = phdr.p_flags & ELF::PF_X;

            if (phdr.p_type != ELF::PT_LOAD) {
                continue;
            }
            std::string name = "PT_LOAD";

            if (offset > max_size) {
                LOG(FATAL) << "program header: 0x" << std::hex << address << " is larger than the mapped file";
            }

            m_pages.emplace_back(address, size, name, base_ptr + offset, is_text);
        }

        return 1;
    }

    bool is_text_sec(uint64_t addr) const;

    const MemPage *text_page() const;

    bool is_valid_addr(uint64_t addr) const;

    const uint8_t *addr_to_ptr(uint64_t addr) const;
    uint64_t ptr_to_addr(const uint8_t *ptr) const;

    const MemPage *addr_to_page(uint64_t addr) const;

    void print_memmap() const;

    const std::vector<std::pair<uint64_t, uint64_t>> get_text_pages() const;

  private:

    const ObjectFile *m_obj;
    std::vector<std::size_t> m_stub_section_hashes;
    std::vector<MemPage> m_pages;
    std::map<uint64_t, bool> m_sections_nobits;

    const uint64_t m_null_stub;
};
