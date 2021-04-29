#pragma once

#include <string>

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"

using namespace llvm;
using namespace object;


template <class ELFT>
class ScopElfEA : public BaseEnvAnalyzer {
  public:
    ScopElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file) :
        BaseEnvAnalyzer("scop"),
        m_obj(obj),
        m_elf_file(elf_file) {};
    int run() override;

  private:
    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
};
