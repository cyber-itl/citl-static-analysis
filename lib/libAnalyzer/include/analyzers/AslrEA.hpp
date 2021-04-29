#pragma once

#include <cstdint>

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"

using namespace llvm;
using namespace object;

class AslrEA : public BaseEnvAnalyzer {
  public:
    AslrEA();
};

template <class ELFT>
class AslrElfEA : public AslrEA {
  public:
    AslrElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file) :
        AslrEA(),
        m_obj(obj),
        m_elf_file(elf_file) {};

    int run() override;

  private:
    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
};

class AslrPeEA : public AslrEA {
  public:
    AslrPeEA(const COFFObjectFile *obj, uint16_t dll_chars) :
        AslrEA(),
        m_obj(obj),
        m_dll_chars(dll_chars) {};

    int run() override;

  private:
    const COFFObjectFile *m_obj;
    uint16_t m_dll_chars;
};

class AslrMachEA : public AslrEA {
  public:
    explicit AslrMachEA(const MachOObjectFile *obj) :
        AslrEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const MachOObjectFile *m_obj;
};
