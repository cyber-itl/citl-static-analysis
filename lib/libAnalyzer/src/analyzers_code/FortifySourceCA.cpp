#include <memory>
#include <utility>
#include <cstdint>

#include "capstone/capstone.h"
#include "glog/logging.h"
#include "json.hpp"

#include "Block.hpp"
#include "SymResolver.hpp"
#include "analyzers_code/BaseCodeAnalyzer.hpp"
#include "analyzers_code/FuncBaseCA.hpp"
#include "analyzers_code/FortifySourceCA.hpp"


FortifySourceCA::FortifySourceCA(cs_arch arch, cs_mode mode, std::shared_ptr<SymResolver> resolver, bool is_macho) : FuncBaseCA("fortify_src", arch, mode, std::move(resolver)), m_is_macho(is_macho) {
    m_fort_targets = {
        "asprintf",
        "confstr",
        "dprint",
        "dprintf",
        "fdelt",
        "fgets",
        "fgets_unlocked",
        "fgetws",
        "fgetws_unlocked",
        "fprintf",
        "fread",
        "fread_u",
        "fread_unlocked",
        "fwprintf",
        "getcwd",
        "getdomainname",
        "getgroups",
        "gethostname",
        "getlogin_r",
        "gets",
        "getwd",
        "longjmp",
        "mbsnrtowcs",
        "mbsrtowcs",
        "mbstowcs",
        "memccpy",
        "memcpy",
        "memmove",
        "mempcpy",
        "memset",
        "obstack_printf",
        "obstack_vprintf",
        "poll",
        "ppoll",
        "pread",
        "pread64",
        "printf",
        "ptsname_r",
        "read",
        "readlink",
        "readlinkati",
        "realpath",
        "recv",
        "snprintf",
        "sprintf",
        "stpcpy",
        "stpncpy",
        "strcat",
        "strcpy",
        "strlcat",
        "strlcpy",
        "strncat",
        "strncpy",
        "swprintf",
        "syslog",
        "ttyname_r",
        "vasprintf",
        "vdprintf",
        "vfprintf",
        "vfwprintf",
        "vprintf",
        "vsnprintf",
        "vsprintf",
        "vswprintf",
        "vsyslog",
        "vwprintf",
        "wcpcpy",
        "wcpncpy",
        "wcrtomb",
        "wcscat",
        "wcscpy",
        "wcsncat",
        "wcsncpy",
        "wcsnrtombs",
        "wcsrtombs",
        "wcstombs",
        "wctomb",
        "wmemcpy",
        "wmemmove",
        "wmempcpy",
        "wmemset",
        "wprintf"
    };

    if (m_is_macho) {
        for (auto &func_name : m_fort_targets) {
            func_name.insert(0, "_");
        }
    }
};

/*
*  The openwrt project uses an alternative fortification project:
*  https://git.2f30.org/fortify-headers/
*  The code injects the checks inline around the call site,
*  then jumps to a ud2 or arch specific __builtin_trap()
*/

bool FortifySourceCA::check_block(const Block *block, uint64_t stop_addr) {
    bool ret = false;

    csh handle;
    uint64_t count;
    cs_insn *insn;

    cs_err cserr;
    cserr = cs_open(m_arch, block->mode, &handle);
    if (cserr != CS_ERR_OK) {
        LOG(ERROR) << "cs_open: " << cs_strerror(cserr);
        return false;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    uint64_t block_size = 0;
    if (stop_addr) {
        CHECK(stop_addr > block->start) << "Invalid stop address passed to check_block at addr: 0x" << std::hex << stop_addr;
        block_size = stop_addr - block->start;
    } else {
        block_size = block->end - block->start;
    }

    count = cs_disasm(handle, block->data, block_size, block->start, 0, &insn);

    for (uint64_t idx = 0; idx < count; idx++) {
        if (m_arch == cs_arch::CS_ARCH_X86) {
            if (insn[idx].id == X86_INS_UD2) {
                ret = true;
                break;
            }
        }
        else if (m_arch == cs_arch::CS_ARCH_ARM) {
            if (insn[idx].id == ARM_INS_UDF || insn[idx].id == ARM_INS_BKPT) {
                ret = true;
                break;
            }
        }
        else if (m_arch == cs_arch::CS_ARCH_ARM64) {
            if (insn[idx].id == ARM64_INS_BRK) {
                ret = true;
                break;
            }
        }
        else if (m_arch == cs_arch::CS_ARCH_MIPS) {
            switch (insn[idx].id) {
            case MIPS_INS_TEQ:
            case MIPS_INS_TEQI:
            case MIPS_INS_TGE:
            case MIPS_INS_TGEI:
            case MIPS_INS_TGEIU:
            case MIPS_INS_TGEU:
            case MIPS_INS_TLT:
            case MIPS_INS_TLTI:
            case MIPS_INS_TLTIU:
            case MIPS_INS_TLTU:
            case MIPS_INS_TNE:
            case MIPS_INS_TNEI:
                ret = true;
                break;
            default:
                break;
            }

            if (ret) {
                break;
            }
        }
        else if (m_arch == cs_arch::CS_ARCH_PPC) {
            switch (insn[idx].id) {
            case PPC_INS_TWLT:
            case PPC_INS_TWEQ:
            case PPC_INS_TWGT:
            case PPC_INS_TWNE:
            case PPC_INS_TWLLT:
            case PPC_INS_TWLGT:
            case PPC_INS_TWLTI:
            case PPC_INS_TWEQI:
            case PPC_INS_TWGTI:
            case PPC_INS_TWNEI:
            case PPC_INS_TWLLTI:
            case PPC_INS_TWLGTI:
            case PPC_INS_TDLT:
            case PPC_INS_TDEQ:
            case PPC_INS_TDGT:
            case PPC_INS_TDNE:
            case PPC_INS_TDLLT:
            case PPC_INS_TDLGT:
            case PPC_INS_TDLTI:
            case PPC_INS_TDEQI:
            case PPC_INS_TDGTI:
            case PPC_INS_TDNEI:
            case PPC_INS_TDLLTI:
            case PPC_INS_TDLGTI:
                ret = true;
                break;
            default:
                break;
            }

            if (ret) {
                break;
            }
        }
    }

    if (count) {
        cs_free(insn, count);
    }
    cs_close(&handle);

    return ret;
}

bool FortifySourceCA::check_alt_fort(const Block *block, cs_insn insn) {
    bool ret = false;

    // MIPS/ppc will have the trap instruction some times in the current branch.
    if ((m_arch == cs_arch::CS_ARCH_MIPS || m_arch == cs_arch::CS_ARCH_PPC) && insn.address != block->start) {
        ret = check_block(block, insn.address);
    }

    if (ret) {
        return ret;
    }

    for (const auto &leader : block->leaders) {
        auto leader_block = m_blocks->find(make_range(leader));
        if (leader_block == m_blocks->end()) {
            continue;
        }

        // Mips will place a tltu/etc instruction in the leader block before the call
        if (m_arch == cs_arch::CS_ARCH_MIPS || m_arch == cs_arch::CS_ARCH_PPC) {
            ret = check_block(&leader_block->second);
        }

        if (m_arch != cs_arch::CS_ARCH_MIPS) {
            // Other archs will have a compare and branch before the call.
            for (const auto &parent_out_edge : leader_block->second.followers) {
                if (parent_out_edge == block->start) {
                    continue;
                }

                auto alt_block = m_blocks->find(make_range(parent_out_edge));
                if (alt_block == m_blocks->end()) {
                    continue;
                }

                ret = check_block(&alt_block->second);

                if (ret) {
                    break;
                }
            }
        }

        if (ret) {
            break;
        }
    }

    return ret;
}

int FortifySourceCA::run(cs_insn insn, const Block *block, const Symbol *call_sym) {
    if (!call_sym) {
        return 0;
    }
    for (const auto &func_name : m_fort_targets) {
        std::string chk_str = "__" + func_name + "_chk";
        if (func_name == call_sym->name) {
            if (check_alt_fort(block, insn)) {
                // LOG(INFO) << "found alt fortification call at: 0x" << std::hex << insn.address << " sym: " << func_name;
                if (m_fort_funcs.count(chk_str)) {
                    m_fort_funcs[chk_str]++;
                }
                else {
                    m_fort_funcs.emplace(chk_str, 1);
                }
            }
            else {
                if (m_unfort_funcs.count(func_name)) {
                    m_unfort_funcs[func_name]++;
                }
                else {
                    m_unfort_funcs.emplace(func_name, 1);
                }
            }
            break;
        }
        else if (chk_str == call_sym->name) {
            if (m_fort_funcs.count(chk_str)) {
                m_fort_funcs[chk_str]++;
            }
            else {
                m_fort_funcs.emplace(chk_str, 1);
            }
            break;
        }
    }

    return 0;
}

int FortifySourceCA::process_results() {
    m_results["fort_dict"] = m_fort_funcs;
    m_results["unfort_dict"] = m_unfort_funcs;

    return 0;
}
