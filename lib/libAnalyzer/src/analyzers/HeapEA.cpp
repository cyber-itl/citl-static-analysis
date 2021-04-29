#include <cstdint>
#include <string>

#include "json.hpp"

#include "analyzers/HeapEA.hpp"
#include "analyzers/BaseEnvAnalyzer.hpp"
#include "analyzers/UtilsEA.hpp"

#include "llvm/Object/MachO.h"
#include "llvm/BinaryFormat/MachO.h"

HeapEA::HeapEA() : BaseEnvAnalyzer("heap") {};

int HeapMachEA::run() {
    bool has_no_heap_exec = false;
    if (!m_obj->is64Bit()) {
        has_no_heap_exec = check_flags(m_obj->getHeader(), MachO::MH_NO_HEAP_EXECUTION);
    }
    else {
        has_no_heap_exec = check_flags(m_obj->getHeader64(), MachO::MH_NO_HEAP_EXECUTION);
    }

    m_results["no_heap_exec"] = has_no_heap_exec;

    return 0;
}
