#pragma once

#include <cstdint>
#include <string>

#include "json.hpp"

#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers/UtilsEA.hpp"

#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"

using namespace llvm;
using namespace object;

class DepEA : public BaseEnvAnalyzer {
  public:
    DepEA();
};

template <class ELFT>
class DepElfEA : public DepEA {
  public:
    DepElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file) :
        DepEA(),
        m_obj(obj),
        m_elf_file(elf_file) {};

    int run() override;

  private:
    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
};

class DepPeEA : public DepEA {
  public:
    DepPeEA(const COFFObjectFile *obj, uint16_t dll_chars) :
        DepEA(),
        m_obj(obj),
        m_dll_chars(dll_chars) {};

    int run() override;

  private:
    const COFFObjectFile *m_obj;
    uint16_t m_dll_chars;
};

class DepMachEA : public DepEA {
  public:
    explicit DepMachEA(const MachOObjectFile *obj) :
        DepEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const MachOObjectFile *m_obj;
};
