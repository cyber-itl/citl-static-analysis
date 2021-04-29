#pragma once

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/ObjectFile.h"

using namespace llvm;
using namespace object;

class SpectreWidgetEA : public BaseEnvAnalyzer {
  public:
    explicit SpectreWidgetEA(const ObjectFile *obj);
    int run() override;
  private:
    const ObjectFile *m_obj;
};
