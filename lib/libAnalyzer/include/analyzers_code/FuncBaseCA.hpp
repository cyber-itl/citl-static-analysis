#pragma once

#include <memory>
#include <string>

#include "capstone/capstone.h"

#include "analyzers_code/BaseCodeAnalyzer.hpp"

class SymResolver;


class FuncBaseCA : public BaseCodeAnalyzer {
  public:
    FuncBaseCA(std::string name, cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver);

  protected:
    std::shared_ptr<SymResolver> m_resolver;
};
