#include <memory>
#include <stddef.h>
#include <string.h>
#include <tuple>
#include <algorithm>
#include <string>
#include <vector>

#include "gflags/gflags.h"
#include "glog/logging.h"
#include "capstone/capstone.h"

#include "llvm/Object/MachO.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Support/SwapByteOrder.h"

#include "SymResolver.hpp"
#include "MachOSyms.hpp"
#include "MachOHandler.hpp"
#include "CapstoneHelper.hpp"

#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"

#include "analyzers/AslrEA.hpp"
#include "analyzers/DepEA.hpp"
#include "analyzers/HeapEA.hpp"
#include "analyzers/LibraryEA.hpp"
#include "analyzers/SectionStatsEA.hpp"
#include "analyzers/CodeSigningEA.hpp"
#include "analyzers/DriverEA.hpp"
#include "analyzers/SpectreWidgetEA.hpp"

#include "analyzers_code/CallStatsCA.hpp"
#include "analyzers_code/BranchCA.hpp"
#include "analyzers_code/RetStatsCA.hpp"
#include "analyzers_code/StackStatsCA.hpp"
#include "analyzers_code/FuncCheckCA.hpp"
#include "analyzers_code/FunctionLists.hpp"
#include "analyzers_code/StackGuardCA.hpp"
#include "analyzers_code/SandboxFuncCA.hpp"
#include "analyzers_code/FortifySourceCA.hpp"
#include "analyzers_code/DynLibLoadCA.hpp"
#include "analyzers_code/CodeQACA.hpp"
#include "analyzers_code/FuncInstrStatsCA.hpp"

DECLARE_bool(all_analyzers);
DECLARE_bool(spectre_analyzer);
DECLARE_bool(insn_stats_analyzer);

int MachOHandler::analyze_format() {
    if (!m_macho_obj->isMachO()) {
        LOG(FATAL) << "Bad cast, non-MachO file being processed by MachO analyzer";
    }

    m_resolver = std::make_shared<MachOSyms>(m_macho_obj);


    if (m_resolver->generate_symbols()) {
        LOG(ERROR) << "Failed to generate MACHO symbols";
        return 1;
    }
    m_env_analyzers.emplace_back(new AslrMachEA(m_macho_obj));
    m_env_analyzers.emplace_back(new LibraryMachEA(m_macho_obj));
    m_env_analyzers.emplace_back(new DepMachEA(m_macho_obj));
    if (FLAGS_all_analyzers) {
        m_env_analyzers.emplace_back(new SectionStatsMachEA(m_macho_obj));
    }
    if (FLAGS_spectre_analyzer) {
        m_env_analyzers.emplace_back(new SpectreWidgetEA(m_macho_obj));
    }

    m_env_analyzers.emplace_back(new CodeSigningMachEA(m_macho_obj));

    m_env_analyzers.emplace_back(new HeapMachEA(m_macho_obj));
    m_env_analyzers.emplace_back(new DriverMachEA(m_macho_obj));

    std::tuple<cs_arch, cs_mode> arch_tup = map_triple_cs(m_macho_obj->getArch());
    cs_arch arch = std::get<0>(arch_tup);
    cs_mode mode = std::get<1>(arch_tup);

    m_code_analyzers.emplace_back(new CallStatsCA(arch, mode));
    m_code_analyzers.emplace_back(new BranchCA(arch, mode));

    if (FLAGS_all_analyzers) {
        m_code_analyzers.emplace_back(new RetStatsCA(arch, mode));
        m_code_analyzers.emplace_back(new StackStatsCA(arch, mode));
        m_code_analyzers.emplace_back(new StackGuardCA(arch, mode, m_resolver));
        if (FLAGS_insn_stats_analyzer) {
            m_code_analyzers.emplace_back(new FuncInstrStatsCA(arch, mode));
        }
    }
    m_code_analyzers.emplace_back(new SandboxFuncCA(arch, mode, m_resolver));
    m_code_analyzers.emplace_back(new FortifySourceCA(arch, mode, m_resolver, true));
    m_code_analyzers.emplace_back(new DynLibLoadCA(arch, mode, m_resolver));

    m_code_analyzers.emplace_back(new CodeQACA(arch, mode, m_resolver));

    m_code_analyzers.emplace_back(new FuncCheckCA(arch, mode, m_resolver,
            macho_funcs::good_funcs,
            macho_funcs::risky_funcs,
            macho_funcs::bad_funcs,
            macho_funcs::ick_funcs));

    return 0;
}

uint64_t MachOHandler::get_ep() {
    uint64_t image_base = 0;
    uint64_t entry_point = 0;

    // Intentionally return's in all thread states, they don't need the addition of the image_base.
    for (const auto &command : m_macho_obj->load_commands()) {
        if (command.C.cmd == MachO::LC_MAIN) {
            MachO::entry_point_command Ep = m_macho_obj->getEntryPointCommand(command);
            entry_point = Ep.entryoff;
        }
        else if (command.C.cmd == MachO::LC_UNIXTHREAD) {
            MachO::thread_command thread_cmd = m_macho_obj->getThreadCommand(command);
            uint32_t cputype;
            if (!m_macho_obj->is64Bit()) {
                cputype = m_macho_obj->getHeader().cputype;
            }
            else {
                cputype = m_macho_obj->getHeader64().cputype;
            }
            bool isLittle = m_macho_obj->isLittleEndian();

            // Parsing based off MachODump.cpp code.
            const char *begin = command.Ptr + sizeof(struct MachO::thread_command);
            const char *end = command.Ptr + thread_cmd.cmdsize;
            uint32_t flavor, count, left;

            if (cputype == MachO::CPU_TYPE_I386) {
                while (begin < end) {
                    if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
                        memcpy((char *)&flavor, begin, sizeof(uint32_t));
                        begin += sizeof(uint32_t);
                    }
                    else  {
                        flavor = 0;
                        begin = end;
                    }

                    if (isLittle != sys::IsLittleEndianHost) {
                        sys::swapByteOrder(flavor);
                    }
                    if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
                        memcpy((char *)&count, begin, sizeof(uint32_t));
                        begin += sizeof(uint32_t);
                    } else {
                        count = 0;
                        begin = end;
                    }
                    if (isLittle != sys::IsLittleEndianHost) {
                      sys::swapByteOrder(count);
                    }
                    if (flavor == MachO::x86_THREAD_STATE32) {
                        MachO::x86_thread_state32_t cpu32;
                        left = end - begin;
                        if (left >= sizeof(MachO::x86_thread_state32_t)) {
                            memcpy(&cpu32, begin, sizeof(MachO::x86_thread_state32_t));
                            begin += sizeof(MachO::x86_thread_state32_t);
                        } else {
                            memset(&cpu32, '\0', sizeof(MachO::x86_thread_state32_t));
                            memcpy(&cpu32, begin, left);
                            begin += left;
                        }
                        if (isLittle != sys::IsLittleEndianHost) {
                            swapStruct(cpu32);
                        }
                        return cpu32.eip;
                    }
                    else if (flavor == MachO::x86_THREAD_STATE) {
                        struct MachO::x86_thread_state_t ts;
                        left = end - begin;
                        if (left >= sizeof(MachO::x86_thread_state_t)) {
                            memcpy(&ts, begin, sizeof(MachO::x86_thread_state_t));
                            begin += sizeof(MachO::x86_thread_state_t);
                        } else {
                            memset(&ts, '\0', sizeof(MachO::x86_thread_state_t));
                            memcpy(&ts, begin, left);
                            begin += left;
                        }
                        if (isLittle != sys::IsLittleEndianHost) {
                            swapStruct(ts);
                        }

                        return ts.uts.ts32.eip;
                    }
                    else {
                        LOG(ERROR) << "Unknown cpu flavor: " << flavor;
                        return 0;
                    }
                }
            }
            else if (cputype == MachO::CPU_TYPE_X86_64) {
                while (begin < end) {
                    if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
                        memcpy((char *)&flavor, begin, sizeof(uint32_t));
                        begin += sizeof(uint32_t);
                    } else {
                        flavor = 0;
                        begin = end;
                    }
                    if (isLittle != sys::IsLittleEndianHost) {
                        sys::swapByteOrder(flavor);
                    }
                    if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
                        memcpy((char *)&count, begin, sizeof(uint32_t));
                        begin += sizeof(uint32_t);
                    } else {
                        count = 0;
                        begin = end;
                    }
                    if (isLittle != sys::IsLittleEndianHost) {
                        sys::swapByteOrder(count);
                    }
                    if (flavor == MachO::x86_THREAD_STATE64) {
                        MachO::x86_thread_state64_t cpu64;
                        left = end - begin;
                        if (left >= sizeof(MachO::x86_thread_state64_t)) {
                            memcpy(&cpu64, begin, sizeof(MachO::x86_thread_state64_t));
                            begin += sizeof(MachO::x86_thread_state64_t);
                        } else {
                            memset(&cpu64, '\0', sizeof(MachO::x86_thread_state64_t));
                            memcpy(&cpu64, begin, left);
                            begin += left;
                        }
                        if (isLittle != sys::IsLittleEndianHost) {
                            swapStruct(cpu64);
                        }

                        return cpu64.rip;
                    }
                    else {
                        LOG(ERROR) << "Unknown cpu flavor: " << flavor;
                        return 0;
                    }
                }
            }
            else {
                LOG(ERROR) << "Unknown cputype: " << cputype;
                return 0;
            }
        }
        else if (command.C.cmd == MachO::LC_SEGMENT) {
            std::string seg_name;
            uint64_t vm_addr;
            if (!m_macho_obj->is64Bit()) {
                MachO::segment_command seg_cmd = m_macho_obj->getSegmentLoadCommand(command);
                seg_name = std::string(seg_cmd.segname);
                vm_addr = seg_cmd.vmaddr;
            }
            else {
                MachO::segment_command_64 seg_cmd = m_macho_obj->getSegment64LoadCommand(command);
                seg_name = std::string(seg_cmd.segname);
                vm_addr = seg_cmd.vmaddr;
            }

            if (seg_name == "__TEXT") {
                image_base = vm_addr;
            }
        }
        else if (command.C.cmd == MachO::LC_SEGMENT_64) {
            std::string seg_name;
            uint64_t vm_addr;
            if (!m_macho_obj->is64Bit()) {
                MachO::segment_command seg_cmd = m_macho_obj->getSegmentLoadCommand(command);
                seg_name = std::string(seg_cmd.segname);
                vm_addr = seg_cmd.vmaddr;
            }
            else {
                MachO::segment_command_64 seg_cmd = m_macho_obj->getSegment64LoadCommand(command);
                seg_name = std::string(seg_cmd.segname);
                vm_addr = seg_cmd.vmaddr;
            }

            if (seg_name == "__TEXT") {
                image_base = vm_addr;
            }
        }

    }

    return image_base + entry_point;
}
