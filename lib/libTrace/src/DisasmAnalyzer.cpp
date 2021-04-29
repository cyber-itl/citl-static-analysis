#include <map>
#include <string>
#include <cstdint>
#include <sstream>
#include <tuple>

#include "glog/logging.h"
#include "capstone/capstone.h"

#include "Block.hpp"
#include "TraceDefs.hpp"
#include "DisasmAnalyzer.hpp"
#include "CapstoneHelper.hpp"


DisasmAnalyzer::DisasmAnalyzer(std::map<uint64_t, Module> *mod_map, std::string name) : TraceAnalyzer(mod_map, name) {};

void DisasmAnalyzer::output_header() {}
void DisasmAnalyzer::output_results() {}

bool DisasmAnalyzer::init() {
    if (inited) {
        return true;
    }
    // Assume the first module is representative of the process
    if (m_mod_map->empty()) {
        LOG(ERROR) << "Empty module map, could not init analyzer: " << m_name;
        return false;
    }

    auto mod = m_mod_map->cbegin();

    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(mod->second.obj->getArch());
    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    cs_err err;
    err = cs_open(arch, mode, &m_cs_handle);
    if (err != CS_ERR_OK) {
        LOG(ERROR) << "cs_open: " << cs_strerror(err);
        return false;
    }
    cs_option(m_cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    inited = true;

    return true;
}

bool DisasmAnalyzer::on_trace_elm(uint32_t modid, uint32_t offset, uint32_t pid, uint32_t tid, log_fault *fault) {
    auto module = m_mod_map->find(modid);
    if (module == m_mod_map->end()) {
        LOG(ERROR) << "Failed to find module: " << modid;
        return false;
    }

    auto block = module->second.block_map->find(make_range(offset));
    if (block == module->second.block_map->end()) {
        LOG(ERROR) << "Failed to find offset: 0x" << std::hex << offset << " in modid: " << modid;
        return false;
    }

    LOG(INFO) << "mod: " << modid << " pid: " << pid << " tid: " << tid << (fault ? " CRASHED" : "");

    cs_insn *insn = cs_malloc(m_cs_handle);
    cs_option(m_cs_handle, CS_OPT_MODE, block->second.mode);

    const uint8_t *data_ptr = block->second.data;
    uint64_t tmp_block_addr = block->second.start;
    uint64_t block_size = block->second.end - block->second.start;

    while(cs_disasm_iter(m_cs_handle, &data_ptr, &block_size, &tmp_block_addr, insn)) {
        LOG(INFO) << "  0x" << std::hex << insn->address << ": " << insn->mnemonic << " " << insn->op_str;
    }

    cs_free(insn, 1);

    return true;
}