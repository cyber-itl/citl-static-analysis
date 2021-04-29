#pragma once

#include <memory>
#include <cstdint>
#include <string>
#include <vector>

#include "json.hpp"
#include "capstone/capstone.h"
#include "llvm/Object/ObjectFile.h"

class Cfg;
class MemoryMap;
class SymResolver;
struct Block;
struct Symbol;

#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"

using json = nlohmann::json;
using namespace llvm;
using namespace object;

class ArchHandler {
  public:
    json analyze();

    virtual ~ArchHandler() = default;

  protected:
    std::vector<std::unique_ptr<BaseEnvAnalyzer>> m_env_analyzers;
    std::vector<std::unique_ptr<BaseCodeAnalyzer>> m_code_analyzers;
    json m_bin_results;
    std::shared_ptr<SymResolver> m_resolver;
    std::shared_ptr<MemoryMap> m_memmap;

    explicit ArchHandler(const ObjectFile *obj);

    // Analyze format specific fields that don't have universal examples
    virtual int analyze_format() = 0;

    virtual uint64_t get_ep() = 0;

    int run_code_analyzers(const Cfg *cfg);

    const Symbol *resolve_call_sym(cs_insn *insn, cs_arch arch, const Block *block);

    std::vector<std::string> m_selected_funcs;

  private:
    std::vector<std::string> split(const std::string &str, char delimiter) const;
    std::string arch_to_str(const unsigned int arch) const;

    const ObjectFile *m_obj;
};

std::unique_ptr<ArchHandler> handler_factory(const ObjectFile *obj);
