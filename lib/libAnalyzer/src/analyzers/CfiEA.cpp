#include <string>

#include "json.hpp"

#include "analyzers/CfiEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"

#include "llvm/BinaryFormat/COFF.h"

CfiEA::CfiEA() : BaseEnvAnalyzer("cfi") {};

int CfiPeEa::run() {
    bool cfi = false;
    if (m_dll_chars & COFF::IMAGE_DLL_CHARACTERISTICS_GUARD_CF) {
        cfi = true;
    }

    m_results["guard_cf"] = cfi;

    return 0;
}
