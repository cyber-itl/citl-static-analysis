#include <algorithm>
#include <system_error>

#include "glog/logging.h"

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Object/SymbolicFile.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

#include "MemoryMap.hpp"

using namespace llvm;
using namespace object;

MemPage::MemPage(uint64_t address, uint64_t size, const std::string &name, const char *data, bool is_text, bool empty_page) :
    address(address),
    size(size),
    name(name),
    name_hash(std::hash<std::string>{}(name)),
    data(reinterpret_cast<const uint8_t *>(data)),
    is_text(is_text),
    empty_page(empty_page) {};
MemPage::MemPage(uint64_t address, uint64_t size, const std::string &name, const uint8_t *data, bool is_text) :
    address(address),
    size(size),
    name(name),
    name_hash(std::hash<std::string>{}(name)),
    data(data),
    is_text(is_text),
    empty_page(false) {};


MemoryMap::MemoryMap(const ObjectFile *obj) : m_obj(obj), m_null_stub(0) {
    m_stub_section_hashes.emplace_back(std::hash<std::string>{}("__stubs"));
    m_stub_section_hashes.emplace_back(std::hash<std::string>{}("__stub_helper"));
    m_stub_section_hashes.emplace_back(std::hash<std::string>{}(".plt"));
    m_stub_section_hashes.emplace_back(std::hash<std::string>{}(".plt.got"));
    m_stub_section_hashes.emplace_back(std::hash<std::string>{}(".MIPS.stubs"));

    if (m_obj->section_begin() != m_obj->section_end()) {
        for (const SectionRef &section : m_obj->sections()) {
            uint64_t sect_addr = section.getAddress();
            uint64_t sect_size = section.getSize();

            Expected<StringRef> nameOrErr = section.getName();
            if (!nameOrErr) {
                std::error_code EC = errorToErrorCode(nameOrErr.takeError());
                LOG(ERROR) << "Failed to get section name: " << EC.message();
                continue;
            }
            auto sect_name = *nameOrErr;

            Expected<StringRef> sectDataErr = section.getContents();
            if (!sectDataErr) {
                std::error_code EC = errorToErrorCode(sectDataErr.takeError());
                LOG(WARNING) << "Skipping section: 0x" << std::hex << sect_addr << " err: " << EC.message();
                continue;
            }
            auto sect_data = sectDataErr.get();

            bool isText = section.isText();
            if (obj->isMachO() && sect_name == "__text") {
                isText = true;
            }

            if (m_obj->isELF()) {
                if (sect_addr == 0 || sect_size == 0) {
                    continue;
                }
            }

            // Here is 'fun' fact, PE files will have 'compressed' section, where
            // all trailing zero data in the .data will be trimmed off and marked in the virtual size
            // Found mostly in GO binaries
            if (m_obj->isCOFF()) {
                if (const auto *coff_obj = dyn_cast<COFFObjectFile>(m_obj)) {
                    const coff_section *pe_sec = coff_obj->getCOFFSection(section);

                    // Add in a 'empty' mapping for any over head size at the end of the map for the existing sect.
                    if (pe_sec->VirtualSize > sect_size) {
                        uint64_t virt_sec_addr = sect_addr + sect_size;

                        m_pages.emplace_back(virt_sec_addr , pe_sec->VirtualSize, sect_name.str() + "_VIRT", nullptr, isText, true);
                    }
                }
            }

            bool empty_page = false;
            if (section.isBSS()) {
//                LOG(WARNING) << "Creating empty page for: " << sect_name.str();
                empty_page = true;
            }

//            if (isText && empty_page) {
//                LOG(FATAL) << "text page is an empty page (bss / NOBITS), unsupported binary";
//            }

            auto existing_page = m_sections_nobits.find(sect_addr);
            if (existing_page != m_sections_nobits.end()) {
                if (empty_page && !existing_page->second) {
                    LOG(INFO) << "Skipping empty, overlaping section: 0x" << std::hex << sect_addr << " name: " << sect_name.str();
                    continue;
                }

                if (existing_page->second && !empty_page) {
                    m_pages.erase(std::remove_if(m_pages.begin(), m_pages.end(),
                            [sect_addr] (const MemPage& page) {
                                return page.address == sect_addr;
                                }), m_pages.end());
                    LOG(INFO) << "Removed existing page with addr: 0x" << std::hex << sect_addr;
                }
            }

            m_sections_nobits.emplace(sect_addr, empty_page);
            m_pages.emplace_back(sect_addr, sect_size, sect_name.str(), sect_data.data(), isText, empty_page);
        }
    }
    else { // Stripped binaries
        if (const auto *ELFObj = dyn_cast<ELF32LEObjectFile>(m_obj)) {
            this->populate_elf_pages<ELFType<support::little, false>>(ELFObj);
        }
        else if (const auto *ELFObj = dyn_cast<ELF32BEObjectFile>(m_obj)) {
            this->populate_elf_pages<ELFType<support::big, false>>(ELFObj);
        }
        else if (const auto *ELFObj = dyn_cast<ELF64LEObjectFile>(m_obj)) {
            this->populate_elf_pages<ELFType<support::little, true>>(ELFObj);
        }
        else if (const auto *ELFObj = dyn_cast<ELF64BEObjectFile>(m_obj)) {
            this->populate_elf_pages<ELFType<support::big, true>>(ELFObj);
        }
    }
};

bool MemoryMap::is_text_sec(uint64_t addr) const {
    for (const MemPage &page : m_pages) {
        if (addr >= page.address && addr < page.address + page.size) {
            if (page.is_text) {
                if (std::find(m_stub_section_hashes.cbegin(), m_stub_section_hashes.cend(), page.name_hash) == m_stub_section_hashes.cend()) {
                    return true;
                }
            }
        }
    }

    return false;
}

const MemPage *MemoryMap::text_page() const {
    for (const MemPage &page : m_pages) {
        if (page.is_text) {
            return &page;
        }
    }
    return nullptr;
}

bool MemoryMap::is_valid_addr(uint64_t addr) const {
    for (const MemPage &page : m_pages) {
        if (addr >= page.address && addr < page.address + page.size) {
            return true;
        }
    }
    return false;
}


const uint8_t *MemoryMap::addr_to_ptr(uint64_t addr) const {
    for (const MemPage &page : m_pages) {
        if (addr >= page.address && addr < page.address + page.size) {
            if (page.empty_page) {
                return reinterpret_cast<const uint8_t *>(&m_null_stub);
            }

            uint64_t offset = addr - page.address;
            return page.data + offset;
        }
    }
    return nullptr;
}

uint64_t MemoryMap::ptr_to_addr(const uint8_t *ptr) const {
    for (const MemPage &page : m_pages) {
        if (ptr >= page.data && ptr < page.data + page.size) {
            auto offset = reinterpret_cast<int64_t>(ptr - page.data);
            return page.address + offset;
        }
    }

    return 0;
}

const MemPage *MemoryMap::addr_to_page(uint64_t addr) const {
    for (const MemPage &page : m_pages) {
        if (addr >= page.address && addr < page.address + page.size) {
            return &page;
        }
    }
    return nullptr;
}

void MemoryMap::print_memmap() const {
    for (const MemPage &page : m_pages) {
        LOG(INFO) << "Page: name: " << page.name << " 0x" << std::hex << page.address << " size: 0x" << std::hex << page.size;
    }
}

const std::vector<std::pair<uint64_t, uint64_t>> MemoryMap::get_text_pages() const {
    std::vector<std::pair<uint64_t, uint64_t>> pages;
    for (const auto &page : m_pages) {
        if (page.is_text) {
            if (std::find(m_stub_section_hashes.cbegin(), m_stub_section_hashes.cend(), page.name_hash) == m_stub_section_hashes.cend()) {
                pages.emplace_back(std::make_pair(page.address, page.size));
            }
        }
    }

    return pages;
}
