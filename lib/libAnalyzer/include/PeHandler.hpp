#pragma once

#include <cstdint>
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/COFF.h"

#include "ArchHandler.hpp"

class PeHandler : public ArchHandler {
  public:
    PeHandler(const COFFObjectFile *coff_obj, const ObjectFile *obj) : m_pe_obj(coff_obj),  ArchHandler(obj) {};

    int analyze_format() override;

    uint64_t get_ep() override;

  private:
    const COFFObjectFile *m_pe_obj;

    uint16_t get_dllChars() const;
};
