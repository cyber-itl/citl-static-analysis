#include <memory>
#include <utility>

#include "capstone/capstone.h"

#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/FuncBaseCA.hpp"

class SymResolver;

FuncBaseCA::FuncBaseCA(std::string name, cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver) :
    BaseCodeAnalyzer(std::move(name), arch, mode),
    m_resolver(std::move(resolver)) {};
