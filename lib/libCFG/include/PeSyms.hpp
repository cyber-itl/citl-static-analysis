#pragma once

#include <cstdint>
#include <vector>

#include "SymResolver.hpp"

#include "llvm/Object/COFF.h"
#include "llvm/Support/Win64EH.h"

using namespace llvm;
using namespace object;


class PeSyms : public SymResolver {
  public:
    explicit PeSyms(const COFFObjectFile *obj);

    int generate_symbols() override;

    int find_cfg_funcs();

    bool get_pdata_section(std::vector<RelocationRef> *rels, const llvm::Win64EH::RuntimeFunction *&rfstart, uint32_t *num_rfs);
    int find_unwind_funcs();

    int find_funcs() override;


  private:
    const COFFObjectFile *m_pe_obj;

};
