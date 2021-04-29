#include <memory>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <istream>
#include <map>
#include <tuple>
#include <utility>

#include "gflags/gflags.h"
#include "glog/logging.h"
#include "json.hpp"
#include "capstone/capstone.h"

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/MachO.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Endian.h"

using namespace llvm;
using namespace object;

#include "Block.hpp"
#include "Cfg.hpp"
#include "MemoryMap.hpp"
#include "EventManager.hpp"
#include "CapstoneHelper.hpp"
#include "SymResolver.hpp"

#include "ArchHandler.hpp"
#include "ElfHandler.hpp"
#include "PeHandler.hpp"
#include "MachOHandler.hpp"

#include "analyzers/BaseEnvAnalyzer.hpp"

#include "analyzers_event/FuzzImmEvent.hpp"


DEFINE_bool(printsyms, false, "Pretty print the symbol table");
DEFINE_bool(printcfg, false, "Pretty print the CFG blocks");
DEFINE_bool(all_analyzers, false, "Toggle noisy analyzers that create large output");
DEFINE_bool(spectre_analyzer, false, "Toggles the collection of spectre data");
DEFINE_bool(insn_stats_analyzer, false, "Toggles the collection of function level instruction counts");
DEFINE_string(addition_funcs, "", "Toggles an analyzer to check for supplied function calls, format: func1,func2,ect");
DEFINE_bool(printmem, false, "Pretty print the constructed memory map");

DEFINE_bool(events, false, "Enable event based analyzers, such as the fuzzimm generator");
DEFINE_bool(corprank, false, "Enable corpus rank, serialized cfg generation");


ArchHandler::ArchHandler(const ObjectFile *obj) : m_obj(obj), m_memmap(std::make_shared<MemoryMap>(obj)) {
}

json ArchHandler::analyze() {
    m_bin_results["object_format"] = m_obj->getFileFormatName().str();
    if (m_obj->isLittleEndian()) {
        m_bin_results["endian"] = "little";
    }
    else {
        m_bin_results["endian"] = "big";
    }

    Triple::ObjectFormatType format_type = m_obj->getTripleObjectFormat();
    switch (format_type) {
    case Triple::COFF:
        m_bin_results["filetype"] = "PE";
        break;
    case Triple::ELF:
        m_bin_results["filetype"] = "ELF";
        break;
    case Triple::MachO:
        m_bin_results["filetype"] = "MACHO";
        break;
    default:
        LOG(ERROR) << "Failed to determine file type, unknown type: " << format_type;
        return json();
    }

    unsigned int arch = m_obj->getArch();
    switch(arch) {
    case Triple::arm:
        m_bin_results["architecture"] = "arm";
        m_bin_results["bitness"] = 32;
        break;
    case Triple::x86:
        m_bin_results["bitness"] = 32;
        m_bin_results["architecture"] = "x86";
        break;
    case Triple::x86_64:
        m_bin_results["bitness"] = 64;
        m_bin_results["architecture"] = "x86_64";
        break;
    case Triple::aarch64:
        m_bin_results["bitness"] = 64;

        m_bin_results["architecture"] = "aarch64";
        break;
    case Triple::aarch64_be:
        m_bin_results["bitness"] = 64;
        m_bin_results["architecture"] = "aarch64";
        break;
    case Triple::mips:
    case Triple::mipsel:
        m_bin_results["bitness"] = 32;
        m_bin_results["architecture"] = "mips";
        break;
//    case Triple::mips64:
//    case Triple::mips64el:
//        m_bin_results["bitness"] = 64;
//        m_bin_results["architecture"] = "mips64";
//        break;
    case Triple::ppc:
        m_bin_results["bitness"] = 32;
        m_bin_results["architecture"] = "ppc";
        break;
//    case Triple::ppc64:
//        m_bin_results["bitness"] = 64;
//        m_bin_results["architecture"] = "ppc64";
//        break;
    default:
        LOG(ERROR) << "Unsupported architecture: " << arch_to_str(arch);
        return json();
    }

    if (FLAGS_printmem) {
        m_memmap->print_memmap();
    }

    if (!FLAGS_addition_funcs.empty()) {
        m_selected_funcs = this->split(FLAGS_addition_funcs, ',');
    }

    if (this->analyze_format()) {
        LOG(ERROR) << "Failed to parse binary specific data";
        return json();
    }

    m_bin_results["symbols"]["count"] = m_resolver->get_syms_by_addr().size();


    if (FLAGS_printsyms) {
        m_resolver->print_map();
    }

    // Run all analyzers and add results
    for (std::unique_ptr<BaseEnvAnalyzer> &analyzer : m_env_analyzers) {
        std::string analyzer_name = analyzer->get_analyzer_name();
        if (analyzer->run()) {
            LOG(INFO) << "Failed to run analyzer: " << analyzer_name;
            continue;
        }
        m_bin_results[analyzer_name] = analyzer->get_results();
    }

    // Generate the CFG
    auto events = std::make_shared<EventManager>();
    if (!events) {
        LOG(FATAL) << "Failed to allocate EventManager shared_ptr";
    }

    if (FLAGS_events) {
        events->register_event(std::unique_ptr<FuzzImmEvent>(new FuzzImmEvent()));
    }

    Cfg cfg(m_obj, m_resolver, m_memmap, events);
    if (cfg.create_cfg(this->get_ep())) {
        LOG(FATAL) << "Failed to create CFG";
    }

    for (const auto &event : *events->get_events()) {
        m_bin_results[event->get_name()] = event->get_results();
    }

    if (FLAGS_printcfg) {
        cfg.print_cfg();
    }

    this->run_code_analyzers(&cfg);

    for (std::unique_ptr<BaseCodeAnalyzer> &analyzer : m_code_analyzers) {
        std::string analyzer_name = analyzer->get_analyzer_name();
        analyzer->process_results();
        m_bin_results[analyzer_name] = analyzer->get_results();
    }

    return m_bin_results;
}

int ArchHandler::run_code_analyzers(const Cfg *cfg) {
    const std::map<block_range, Block, block_cmp> *blocks = cfg->get_cfg_map();

    json cfg_data;
    for(const auto &analyzer : m_code_analyzers) {
        analyzer->set_blocks(blocks);
    }

    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(m_obj->getArch());
    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    csh cs_handle;

    cs_err err;
    err = cs_open(arch, mode, &cs_handle);
    if (err != CS_ERR_OK) {
        LOG(ERROR) << "cs_open: " << cs_strerror(err);
        return 1;
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    uint64_t func_cnt = 0;

    for (const auto &kv : *blocks) {
        Block block = kv.second;

        if (block.is_func_head) {
            func_cnt++;
        }

        uint64_t block_size = block.end - block.start;


        const uint8_t *data_ptr = block.data;
        uint64_t tmp_block_addr = block.start;
        cs_insn *insn = cs_malloc(cs_handle);

        cs_option(cs_handle, CS_OPT_MODE, block.mode);

        while(cs_disasm_iter(cs_handle, &data_ptr, &block_size, &tmp_block_addr, insn)) {
            cs_insn cur_insn = *insn;
            const Symbol *sym = this->resolve_call_sym(&cur_insn, arch, &block);
            for (const auto &analyzer : m_code_analyzers) {
                analyzer->run(cur_insn, &block, sym);
            }
        }
        cs_free(insn, 1);
    }
    cs_close(&cs_handle);

    cfg_data["blocks"] = blocks->size();
    cfg_data["functions"] = func_cnt;
    cfg_data["switch_tbl_count"] = cfg->get_switch_count();
    cfg_data["sweep_func_count"] = cfg->get_sweep_count();

    m_bin_results["cfg"] = cfg_data;

    return 0;
}

const Symbol *ArchHandler::resolve_call_sym(cs_insn *insn, cs_arch arch, const Block *block) {
    cs_detail *detail = insn->detail;
    uint64_t branch_target = 0;

    if (arch == cs_arch::CS_ARCH_X86) {
        if (insn->id != X86_INS_CALL && insn->id != X86_INS_JMP) {
            return nullptr;
        }

        if (block->jump_block) {
            return nullptr;
        }

        if (detail->x86.op_count < 1) {
            return nullptr;
        }

        branch_target = block->branch_target;
    }
    else if (arch == cs_arch::CS_ARCH_ARM) {
        if (insn->id == ARM_INS_INVALID) {
            return nullptr;
        }

        if (block->jump_block) {
            return nullptr;
        }

        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];

            if (grp == ARM_GRP_JUMP) {
                branch_target = block->branch_target;
                break;
            }
        }
    }
    else if (arch == cs_arch::CS_ARCH_ARM64) {
        if (insn->id == ARM64_INS_INVALID) {
            return nullptr;
        }

        if (block->jump_block) {
            return nullptr;
        }

        bool is_branch = false;

        for (uint8_t i = 0; i < detail->groups_count; i++) {
            uint8_t grp = detail->groups[i];

            if (grp == ARM64_GRP_JUMP) {
                is_branch = true;
                break;
            }
        }

        // Some cases AARCH64 instructions group counts fail to generate
        // Add some extra checks just incase, this is fixed in capstone "next"
        // capstone tag: 4be19c3cbbf708451e116fbf7026b737a9ce3407
        switch(insn->id) {
        case ARM64_INS_B:
        case ARM64_INS_BL:
        case ARM64_INS_BLR:
            is_branch = true;
            break;
        default:
            break;
        }

        if (is_branch) {
            branch_target = block->branch_target;
        }
    }
    else if (arch == cs_arch::CS_ARCH_MIPS) {
        if (insn->id == ARM64_INS_INVALID) {
            return nullptr;
        }
        bool is_branch = false;

        switch (insn->id) {
        case MIPS_INS_BAL:
        case MIPS_INS_B:
        case MIPS_INS_BLTZAL:
        case MIPS_INS_BGEZAL:
        case MIPS_INS_J:
        case MIPS_INS_JAL:
        case MIPS_INS_JALR:
            is_branch = true;
            break;
        case MIPS_INS_JR:
            cs_mips mips = insn->detail->mips;
            if (mips.op_count > 0) {
                if (mips.operands[0].type == MIPS_OP_REG && mips.operands[0].reg == MIPS_REG_RA) {
                    is_branch = false;
                    break;
                }
            }
            is_branch = true;
            break;
        }

        if (is_branch) {
            branch_target = block->branch_target;
        }
    }
    else if (arch == cs_arch::CS_ARCH_PPC) {
        if (insn->id == ARM64_INS_INVALID) {
            return nullptr;
        }
        bool is_branch = false;

        switch (insn->id) {
        case PPC_INS_B:
        case PPC_INS_BA:
        case PPC_INS_BC:
        case PPC_INS_BCCTR:
        case PPC_INS_BCCTRL:
        case PPC_INS_BCL:
        case PPC_INS_BCLR:
        case PPC_INS_BCLRL:
        case PPC_INS_BCTR:
        case PPC_INS_BCTRL:
        case PPC_INS_BCT:
        case PPC_INS_BDNZ:
        case PPC_INS_BDNZA:
        case PPC_INS_BDNZL:
        case PPC_INS_BDNZLA:
        case PPC_INS_BDNZLR:
        case PPC_INS_BDNZLRL:
        case PPC_INS_BDZ:
        case PPC_INS_BDZA:
        case PPC_INS_BDZL:
        case PPC_INS_BDZLA:
        case PPC_INS_BDZLR:
        case PPC_INS_BDZLRL:
        case PPC_INS_BL:
        case PPC_INS_BLA:
        case PPC_INS_BLR:
        case PPC_INS_BLRL:
        case PPC_INS_BRINC:
        case PPC_INS_BCA:
        case PPC_INS_BCLA:
        case PPC_INS_BTA:
        case PPC_INS_BT:
        case PPC_INS_BF:
        case PPC_INS_BDNZT:
        case PPC_INS_BDNZF:
        case PPC_INS_BDZF:
        case PPC_INS_BDZT:
        case PPC_INS_BFA:
        case PPC_INS_BDNZTA:
        case PPC_INS_BDNZFA:
        case PPC_INS_BDZTA:
        case PPC_INS_BDZFA:
        case PPC_INS_BTCTR:
        case PPC_INS_BFCTR:
        case PPC_INS_BTCTRL:
        case PPC_INS_BFCTRL:
        case PPC_INS_BTL:
        case PPC_INS_BFL:
        case PPC_INS_BDNZTL:
        case PPC_INS_BDNZFL:
        case PPC_INS_BDZTL:
        case PPC_INS_BDZFL:
        case PPC_INS_BTLA:
        case PPC_INS_BFLA:
        case PPC_INS_BDNZTLA:
        case PPC_INS_BDNZFLA:
        case PPC_INS_BDZTLA:
        case PPC_INS_BDZFLA:
        case PPC_INS_BTLR:
        case PPC_INS_BFLR:
        case PPC_INS_BDNZTLR:
        case PPC_INS_BDZTLR:
        case PPC_INS_BDZFLR:
        case PPC_INS_BTLRL:
        case PPC_INS_BFLRL:
        case PPC_INS_BDNZTLRL:
        case PPC_INS_BDNZFLRL:
        case PPC_INS_BDZTLRL:
        case PPC_INS_BDZFLRL:
            is_branch = true;
            break;
        }
        if (is_branch) {
            branch_target = block->branch_target;
        }
    }
    else {
        LOG(FATAL) << "Invalid architecture for getting call target symbol" << static_cast<uint32_t>(arch);
    }

    if (!branch_target) {
        return nullptr;
    }

    const Symbol *sym_out;
    if (!m_resolver->resolve_sym(block->branch_target, &sym_out)) {
        return nullptr;
    }

    return sym_out;
}

std::vector<std::string> ArchHandler::split(const std::string &str, char delimiter) const {
    std::vector<std::string> internal;
    std::stringstream ss(str);
    std::string tok;

    while(std::getline(ss, tok, delimiter)) {
        internal.push_back(tok);
    }

    return internal;
}

std::string ArchHandler::arch_to_str(const unsigned int arch) const {
    switch(arch) {
    case Triple::arm:
    case Triple::armeb:
        return std::string("arm");
    case Triple::aarch64:
    case Triple::aarch64_be:
        return std::string("arm64");
    case Triple::thumb:
    case Triple::thumbeb:
        return std::string("thumb");
    case Triple::mips:
    case Triple::mipsel:
        return std::string("mips");
    case Triple::mips64:
    case Triple::mips64el:
        return std::string("mips64");
    case Triple::x86:
        return std::string("x86-32");
    case Triple::x86_64:
        return std::string("x86-64");
    case Triple::sparc:
    case Triple::sparcv9:
    case Triple::sparcel:
        return std::string("sparc");
    case Triple::ppc:
        return std::string("ppc");
    case Triple::ppc64:
    case Triple::ppc64le:
        return std::string("ppc64");
    case Triple::riscv32:
        return std::string("riscv32");
    case Triple::riscv64:
        return std::string("riscv64");
    case Triple::wasm32:
        return std::string("wasm32");
    case Triple::wasm64:
        return std::string("wasm64");
    default:
        return std::string("unknown: 0x") + std::to_string(arch);
    }
}

std::unique_ptr<ArchHandler> handler_factory(const ObjectFile *obj) {
    if (const auto *coff = dyn_cast<COFFObjectFile>(obj)) {
        LOG(INFO) << "Processing COFF file";
        return std::unique_ptr<PeHandler>(new PeHandler(coff, obj));
    }
    else if (const auto *MachO = dyn_cast<MachOObjectFile>(obj)) {
        LOG(INFO) << "Processing macho file";
        return std::unique_ptr<MachOHandler>(new MachOHandler(MachO, obj));
    }
    else if (const auto *ELFObj = dyn_cast<ELF32LEObjectFile>(obj)) {
        LOG(INFO) << "Processing elf32LE file";
        return std::unique_ptr<ElfHandler<ELFType<support::little, false>>>(new ElfHandler<ELFType<support::little, false>>(ELFObj, obj));
    }
    else if (const auto *ELFObj = dyn_cast<ELF32BEObjectFile>(obj)) {
        LOG(INFO) << "Processing elf32BE file";
        return std::unique_ptr<ElfHandler<ELFType<support::big, false>>>(new ElfHandler<ELFType<support::big, false>>(ELFObj, obj));
    }
    else if (const auto *ELFObj = dyn_cast<ELF64LEObjectFile>(obj)) {
        LOG(INFO) << "Processing elf64LE file";
        return std::unique_ptr<ElfHandler<ELFType<support::little, true>>>(new ElfHandler<ELFType<support::little, true>>(ELFObj, obj));
    }
    else if (const auto *ELFObj = dyn_cast<ELF64BEObjectFile>(obj)) {
        LOG(INFO) << "Processing elf64BE file";
        return std::unique_ptr<ElfHandler<ELFType<support::big, true>>>(new ElfHandler<ELFType<support::big, true>>(ELFObj, obj));
    }
    else {
        LOG(ERROR) << "Failed to cast ObjectFile to implementation, type: " << obj->getType();
    }
    return nullptr;
}
