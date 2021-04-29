#include <string>

#include "json.hpp"

#include "analyzers/SandboxEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/BinaryFormat/COFF.h"

SandboxEA::SandboxEA() : BaseEnvAnalyzer("sandbox") {};

int SandboxPeEA::run() {
    bool app_container = false;

    if (m_dll_chars & COFF::IMAGE_DLL_CHARACTERISTICS_APPCONTAINER) {
        app_container = true;
    }

    m_results["app_container"] = app_container;

    return 0;
}
