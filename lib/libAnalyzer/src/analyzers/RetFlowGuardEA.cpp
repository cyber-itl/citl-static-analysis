#include <cstdint>
#include <string>
#include <system_error>

#include "json.hpp"
#include "glog/logging.h"

#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers/RetFlowGuardEA.hpp"

#include "llvm/BinaryFormat/COFF.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Endian.h"


RetFlowGuardEA::RetFlowGuardEA() : BaseEnvAnalyzer("rfg") {};

#define IMAGE_GUARD_RF_INSTRUMENTED 0x00020000
#define IMAGE_GUARD_RF_ENABLE       0x00040000
#define IMAGE_GUARD_RF_STRICT       0x00080000


int RetFlowGuardPeEA::run() {
    const data_directory *DataEntry;

    bool rfg_enabled = false;

    do {
        if (m_obj->getDataDirectory(COFF::LOAD_CONFIG_TABLE, DataEntry)) {
            LOG(WARNING) << "Binary missing load config";
            break;
        }
        if (DataEntry->RelativeVirtualAddress == 0x0) {
            LOG(WARNING) << "Null load address";
            break;
        }
        if (!m_obj->is64()) {
            const coff_load_configuration32 *load_config = m_obj->getLoadConfig32();
            if (!load_config) {
                LOG(ERROR) << "Failed to get 32bit load config";
                break;
            }
            if (load_config->Size < 72) {
                break;
            }

            if ( (load_config->GuardFlags & IMAGE_GUARD_RF_INSTRUMENTED) &&
                 ((load_config->GuardFlags & IMAGE_GUARD_RF_ENABLE) || (load_config->GuardFlags & IMAGE_GUARD_RF_STRICT)) ) {
                rfg_enabled = true;
            }
        }
        else {
            const coff_load_configuration64 *load_config = m_obj->getLoadConfig64();
            if (!load_config) {
                LOG(ERROR) << "Failed to get 64bit load config";
                break;
            }
            if (load_config->Size < 148) {
                break;
            }

            if ( (load_config->GuardFlags & IMAGE_GUARD_RF_INSTRUMENTED) &&
                 ((load_config->GuardFlags & IMAGE_GUARD_RF_ENABLE) || (load_config->GuardFlags & IMAGE_GUARD_RF_STRICT)) ) {
                rfg_enabled = true;
            }
        }
    } while(false);


    m_results["rfg_enabled"] = rfg_enabled;

    return 0;
}
