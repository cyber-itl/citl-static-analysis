#pragma once

#include <cstdint>

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"

using namespace llvm;
using namespace object;

class SandboxEA : public BaseEnvAnalyzer {
  public:
    SandboxEA();
};

class SandboxPeEA : public SandboxEA {
  public:
    SandboxPeEA(const COFFObjectFile *obj, uint16_t dll_chars) :
        SandboxEA(),
        m_obj(obj),
        m_dll_chars(dll_chars) {};

    int run() override;

  private:
    const COFFObjectFile *m_obj;
    uint16_t m_dll_chars;
};
