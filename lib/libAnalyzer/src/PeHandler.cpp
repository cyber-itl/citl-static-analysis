#include <algorithm>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "gflags/gflags.h"
#include "glog/logging.h"
#include "capstone/capstone.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Endian.h"

using namespace llvm;
using namespace object;

#include "PeSyms.hpp"
#include "PeHandler.hpp"
#include "CapstoneHelper.hpp"

#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"

#include "analyzers/AslrEA.hpp"
#include "analyzers/LibraryEA.hpp"
#include "analyzers/DepEA.hpp"
#include "analyzers/SectionStatsEA.hpp"
#include "analyzers/CodeSigningEA.hpp"
#include "analyzers/CfiEA.hpp"

#include "analyzers/SehEA.hpp"
#include "analyzers/SandboxEA.hpp"
#include "analyzers/DriverEA.hpp"
#include "analyzers/SpectreWidgetEA.hpp"
#include "analyzers/RetFlowGuardEA.hpp"

#include "analyzers_code/CallStatsCA.hpp"
#include "analyzers_code/BranchCA.hpp"
#include "analyzers_code/RetStatsCA.hpp"
#include "analyzers_code/StackStatsCA.hpp"
#include "analyzers_code/FuncCheckCA.hpp"
#include "analyzers_code/StackGuardCA.hpp"
#include "analyzers_code/FunctionLists.hpp"
#include "analyzers_code/DynLibLoadCA.hpp"
#include "analyzers_code/CodeQACA.hpp"
#include "analyzers_code/FuncInstrStatsCA.hpp"

DECLARE_bool(all_analyzers);
DECLARE_bool(spectre_analyzer);
DECLARE_bool(insn_stats_analyzer);

int PeHandler::analyze_format() {
    if (!m_pe_obj->isCOFF()) {
        LOG(FATAL) << "Bad cast, non-COFF file being processed by PE analyzer";
    }

    m_resolver = std::make_shared<PeSyms>(m_pe_obj);

    if (m_resolver->generate_symbols()) {
        LOG(ERROR) << "Failed to generate PE symbols";
        return 1;
    }

    uint16_t pe_chars = m_pe_obj->getCharacteristics();
    uint16_t dll_chars = get_dllChars();

    if (!dll_chars) {
        LOG(WARNING) << "Possible failure to get DllCharacteristics, null flags";
    }

    m_env_analyzers.emplace_back(new AslrPeEA(m_pe_obj, dll_chars));
    m_env_analyzers.emplace_back(new LibraryPeEA(m_pe_obj, pe_chars));
    m_env_analyzers.emplace_back(new DepPeEA(m_pe_obj, dll_chars));
    if (FLAGS_all_analyzers) {
        m_env_analyzers.emplace_back(new SectionStatsPeEA(m_pe_obj));
    }
    if (FLAGS_spectre_analyzer) {
        m_env_analyzers.emplace_back(new SpectreWidgetEA(m_pe_obj));
    }

    m_env_analyzers.emplace_back(new CodeSigningPeEA(m_pe_obj, dll_chars));

    m_env_analyzers.emplace_back(new SehPeEA(m_pe_obj, dll_chars));
    m_env_analyzers.emplace_back(new CfiPeEa(m_pe_obj, dll_chars));
    m_env_analyzers.emplace_back(new SandboxPeEA(m_pe_obj, dll_chars));
    m_env_analyzers.emplace_back(new DriverPeEA(m_pe_obj));
    m_env_analyzers.emplace_back(new RetFlowGuardPeEA(m_pe_obj));

    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(m_pe_obj->getArch());
    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    m_code_analyzers.emplace_back(new CallStatsCA(arch, mode));
    m_code_analyzers.emplace_back(new BranchCA(arch, mode));

    if (FLAGS_all_analyzers) {
        m_code_analyzers.emplace_back(new RetStatsCA(arch, mode));
        m_code_analyzers.emplace_back(new StackStatsCA(arch, mode));
        m_code_analyzers.emplace_back(new StackGuardCA(arch, mode, m_resolver, true));
        if (FLAGS_insn_stats_analyzer) {
            m_code_analyzers.emplace_back(new FuncInstrStatsCA(arch, mode));
        }
    }

    m_code_analyzers.emplace_back(new DynLibLoadCA(arch, mode, m_resolver));

    m_code_analyzers.emplace_back(new CodeQACA(arch, mode, m_resolver));

    m_code_analyzers.emplace_back(new FuncCheckCA(arch, mode, m_resolver,
            pe_funcs::good_funcs,
            pe_funcs::risky_funcs,
            pe_funcs::bad_funcs,
            pe_funcs::ick_funcs));


    return 0;
}

uint16_t PeHandler::get_dllChars() const {
    const pe32_header *hdr = m_pe_obj->getPE32Header();
    if (!hdr) {
        const pe32plus_header *hdrPlus = m_pe_obj->getPE32PlusHeader();
        if (!hdrPlus) {
            LOG(WARNING) << "Failed to get DllCharacteristics from header";
            return 0;
        }
        return hdrPlus->DLLCharacteristics;
    }
    else {
        return hdr->DLLCharacteristics;
    }

    return 0;
}

uint64_t PeHandler::get_ep() {
    uint64_t entry_point_offset = 0;
    uint64_t image_base = 0;

    const pe32_header *hdr = m_pe_obj->getPE32Header();
    if (!hdr) {
        const pe32plus_header *hdrPlus = m_pe_obj->getPE32PlusHeader();
        if (!hdrPlus) {
            LOG(ERROR) << "Failed to get DllCharacteristics from header";
            return 0;
        }
        entry_point_offset = hdrPlus->AddressOfEntryPoint;
        image_base = hdrPlus->ImageBase;
    }
    else {
        entry_point_offset = hdr->AddressOfEntryPoint;
        image_base = hdr->ImageBase;
    }

    if (!entry_point_offset) {
        return 0x0;
    }

    return entry_point_offset + image_base;
}
