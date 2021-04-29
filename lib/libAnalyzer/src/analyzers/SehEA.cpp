#include <cstdint>
#include <string>
#include <system_error>

#include "json.hpp"
#include "glog/logging.h"

#include "analyzers/SehEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/Object/COFF.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/Support/Endian.h"


SehEA::SehEA() : BaseEnvAnalyzer("seh") {};

int SehPeEA::run() {
    bool seh = true;
    bool safe_seh = true;

    uint64_t safe_seh_count = 0;
    const data_directory *DataEntry;

    if (m_dll_chars & COFF::IMAGE_DLL_CHARACTERISTICS_NO_SEH) {
        seh = false;
    }
    // work around: https://bugs.llvm.org/show_bug.cgi?id=34108
    else if (m_obj->getDataDirectory(COFF::LOAD_CONFIG_TABLE, DataEntry)) {
        LOG(WARNING) << "Binary missing load config";
    }
    else if (DataEntry->RelativeVirtualAddress == 0x0) {
        LOG(WARNING) << "Null load address";
    }
    else {
        if (!m_obj->is64()) {
            const coff_load_configuration32 *load_config = m_obj->getLoadConfig32();
            if (load_config) {
                safe_seh_count = load_config->SEHandlerCount;
            }
            else {
                LOG(ERROR) << "Failed to get 32bit load config";
            }
        }
        else {
            const coff_load_configuration64 *load_config = m_obj->getLoadConfig64();
            if (load_config) {
                safe_seh_count = load_config->SEHandlerCount;
            }
            else {
                LOG(ERROR) << "Failed to get 32bit load config";
            }
        }
    }

    if (safe_seh_count) {
        safe_seh = true;
    }
    else {
        safe_seh = false;
    }

    m_results["seh_compatible"] = seh;
    m_results["safe_seh"] = safe_seh;
    m_results["safe_seh_count"] = safe_seh_count;

    return 0;
}
