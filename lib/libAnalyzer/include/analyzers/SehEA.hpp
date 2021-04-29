#pragma once

#include <cstdint>

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/COFF.h"

using namespace llvm;
using namespace object;

class SehEA : public BaseEnvAnalyzer {
  public:
    SehEA();
};

class SehPeEA : public SehEA {
  public:
    SehPeEA(const COFFObjectFile *obj, uint16_t dll_chars) :
        SehEA(),
        m_obj(obj),
        m_dll_chars(dll_chars) {};

    int run() override;

  private:
    const COFFObjectFile *m_obj;
    uint16_t m_dll_chars;
};
