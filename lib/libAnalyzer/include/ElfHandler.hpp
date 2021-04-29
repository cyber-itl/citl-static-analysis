#pragma once

#include <cstdint>
#include <vector>

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/ELFTypes.h"

using namespace llvm;
using namespace object;

#include "ArchHandler.hpp"

template <class ELFT>
class ElfHandler : public ArchHandler {
  public:
    ElfHandler<ELFT>(const ELFObjectFile<ELFT> *elf_obj, const ObjectFile *obj);

    int analyze_format() override;

    uint64_t get_ep() override;

  private:
    const uint8_t *to_mapped_addr(uint64_t, std::vector<const typename ELFT::Phdr *> pages) const;

    const ELFObjectFile<ELFT> *m_elf_obj;
    const ELFFile<ELFT> *m_elf_file;
};
