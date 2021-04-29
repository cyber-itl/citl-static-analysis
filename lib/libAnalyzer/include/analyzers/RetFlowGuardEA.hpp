#pragma once

#include "llvm/Object/COFF.h"

#include "analyzers/BaseEnvAnalyzer.hpp"

using namespace llvm;
using namespace object;

class RetFlowGuardEA : public BaseEnvAnalyzer {
  public:
    RetFlowGuardEA();
};

class RetFlowGuardPeEA : public RetFlowGuardEA {
  public:
    RetFlowGuardPeEA(const COFFObjectFile *obj) :
        RetFlowGuardEA(),
        m_obj(obj) {};

    int run() override;

  private:
    const COFFObjectFile *m_obj;
};
