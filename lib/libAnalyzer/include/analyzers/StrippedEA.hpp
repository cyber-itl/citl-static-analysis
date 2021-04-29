#pragma once

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"

using namespace llvm;
using namespace object;


class StrippedEA : public BaseEnvAnalyzer {
  public:
    StrippedEA();
};

template <class ELFT>
class StrippedElfEA : public StrippedEA {
  public:
    StrippedElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file) :
        StrippedEA(),
        m_obj(obj),
        m_elf_file(elf_file) {};

    int run() override;

  private:
    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
};
