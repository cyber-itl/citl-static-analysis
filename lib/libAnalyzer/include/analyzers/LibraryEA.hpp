#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"

using namespace llvm;
using namespace object;

class LibraryEA : public BaseEnvAnalyzer {
  public:
    LibraryEA();
};

template <class ELFT>
class LibraryElfEA : public LibraryEA {
  public:
    LibraryElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file, std::vector<std::string> mods, std::string soname) :
        LibraryEA(),
        m_obj(obj),
        m_elf_file(elf_file),
        m_mods(std::move(mods)),
        m_soname(soname) {};

    int run() override;

  private:
    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
    const std::vector<std::string> m_mods;
    std::string m_soname;
};

class LibraryPeEA : public LibraryEA {
  public:
    LibraryPeEA(const COFFObjectFile *obj, uint16_t pe_chars) :
        LibraryEA(),
        m_obj(obj),
        m_pe_chars(pe_chars) {};

    int run() override;

  private:
    const COFFObjectFile *m_obj;
    uint16_t m_pe_chars;
};

class LibraryMachEA : public LibraryEA {
  public:
    explicit LibraryMachEA(const MachOObjectFile *obj) :
        LibraryEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const MachOObjectFile *m_obj;
};
