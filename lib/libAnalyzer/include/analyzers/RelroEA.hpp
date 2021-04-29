#pragma once

#include <string>
#include <utility>
#include <vector>

#include "analyzers/BaseEnvAnalyzer.hpp"
#include "ElfSyms.hpp"

#include "llvm/Object/ELFObjectFile.h"

using namespace llvm;
using namespace object;


template <class ELFT>
class RelroElfEA : public BaseEnvAnalyzer {
  public:
    RelroElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file, std::vector<typename ElfSyms<ELFT>::DynTag> dyn_tags) :
        BaseEnvAnalyzer("relro"),
        m_obj(obj),
        m_elf_file(elf_file),
        m_dyn_tags(std::move(dyn_tags)) {};

    int run() override;

  private:
    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
    const std::vector<typename ElfSyms<ELFT>::DynTag> m_dyn_tags;
};
