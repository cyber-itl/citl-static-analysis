#pragma once

#include <cstdint>

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/MachO.h"

#include "ArchHandler.hpp"


class MachOHandler : public ArchHandler {
  public:
    MachOHandler(const MachOObjectFile *macho_obj, const ObjectFile *obj) : m_macho_obj(macho_obj), ArchHandler(obj) {};

    int analyze_format() override;

    uint64_t get_ep() override;

  private:
    const MachOObjectFile *m_macho_obj;
};
