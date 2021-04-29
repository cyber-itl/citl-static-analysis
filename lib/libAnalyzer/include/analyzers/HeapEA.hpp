#pragma once

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/MachO.h"

using namespace llvm;
using namespace object;

class HeapEA : public BaseEnvAnalyzer {
  public:
    HeapEA();
};

class HeapMachEA : public HeapEA {
  public:
    explicit HeapMachEA(const MachOObjectFile *obj) :
        HeapEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const MachOObjectFile *m_obj;
};
