#pragma once

#include <cstdint>

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"

using namespace llvm;
using namespace object;

class CodeSigningEA : public BaseEnvAnalyzer {
  public:
    CodeSigningEA();
};

template <class ELFT>
class CodeSigningElfEA : public CodeSigningEA {
  public:
    CodeSigningElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file) :
        CodeSigningEA(),
        m_obj(obj),
        m_elf_file(elf_file) {};

    /*
     * Note, no of the below checks are expected to ever hit because of lack of adoption
     */
    int run() override;

  private:
    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
};

class CodeSigningPeEA : public CodeSigningEA {
  public:
    CodeSigningPeEA(const COFFObjectFile *obj, uint16_t dll_chars) :
        CodeSigningEA(),
        m_obj(obj),
        m_dll_chars(dll_chars) {};

    int run() override;

  private:
    const COFFObjectFile *m_obj;
    uint16_t m_dll_chars;
};

class CodeSigningMachEA : public CodeSigningEA {
  public:
    explicit CodeSigningMachEA(const MachOObjectFile *obj) :
        CodeSigningEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const MachOObjectFile *m_obj;
};
