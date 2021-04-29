#pragma once

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"

using namespace llvm;
using namespace object;

class DriverEA : public BaseEnvAnalyzer {
  public:
    DriverEA();
};

template <class ELFT>
class DriverElfEA : public DriverEA {
  public:
    DriverElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file) :
        DriverEA(),
        m_obj(obj),
        m_elf_file(elf_file) {};

    int run() override;

  private:
    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
};

class DriverPeEA : public DriverEA {
  public:
    explicit DriverPeEA(const COFFObjectFile *obj) :
        DriverEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const COFFObjectFile *m_obj;
};

class DriverMachEA : public DriverEA {
  public:
    explicit DriverMachEA(const MachOObjectFile *obj) :
        DriverEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const MachOObjectFile *m_obj;
};
