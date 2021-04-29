#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"

using namespace llvm;
using namespace object;

class SectionStatsEA : public BaseEnvAnalyzer {
  public:
    SectionStatsEA();
};

template <class ELFT>
class SectionStatsElfEA : public SectionStatsEA {
  public:
    SectionStatsElfEA(const ELFObjectFile<ELFT> *obj, const ELFFile<ELFT> *elf_file) :
        SectionStatsEA(),
        m_obj(obj),
        m_elf_file(elf_file) {};

    int run() override;

  private:

    std::vector<std::string> map_shflags(uint32_t flags);
    std::vector<std::string> map_pflags(uint32_t flags);

    const ELFObjectFile<ELFT> *m_obj;
    const ELFFile<ELFT> *m_elf_file;
};

class SectionStatsPeEA : public SectionStatsEA {
  public:
    explicit SectionStatsPeEA(const COFFObjectFile *obj) :
        SectionStatsEA(),
        m_obj(obj) {};

    int run() override;

  private:
    std::vector<std::string> map_flags(uint32_t flags);

    const COFFObjectFile *m_obj;
};

class SectionStatsMachEA : public SectionStatsEA {
  public:
    explicit SectionStatsMachEA(const MachOObjectFile *obj) :
        SectionStatsEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const MachOObjectFile *m_obj;

    std::vector<std::string> map_seg_flags(uint32_t flags);
    std::vector<std::string> map_sec_flags(uint32_t flags);
};
