project(Analyzer)

add_library(Analyzer
    src/Driver.cpp
    src/ArchHandler.cpp
    src/ElfHandler.cpp
    src/MachOHandler.cpp
    src/PeHandler.cpp

    src/analyzers/AslrEA.cpp
    src/analyzers/CfiEA.cpp
    src/analyzers/CodeSigningEA.cpp
    src/analyzers/DepEA.cpp
    src/analyzers/HeapEA.cpp
    src/analyzers/LibraryEA.cpp
    src/analyzers/RelroEA.cpp
    src/analyzers/SandboxEA.cpp
    src/analyzers/SectionStatsEA.cpp
    src/analyzers/SpectreWidgetEA.cpp
    src/analyzers/SehEA.cpp
    src/analyzers/DriverEA.cpp
    src/analyzers/StrippedEA.cpp
    src/analyzers/ScopEA.cpp
    src/analyzers/RetFlowGuardEA.cpp

    src/analyzers_code/CallStatsCA.cpp
    src/analyzers_code/BranchCA.cpp
    src/analyzers_code/RetStatsCA.cpp
    src/analyzers_code/StackStatsCA.cpp
    src/analyzers_code/FuncBaseCA.cpp
    src/analyzers_code/FuncCheckCA.cpp
    src/analyzers_code/FunctionLists.cpp
    src/analyzers_code/StackGuardCA.cpp
    src/analyzers_code/SandboxFuncCA.cpp
    src/analyzers_code/FortifySourceCA.cpp
    src/analyzers_code/DynLibLoadCA.cpp
    src/analyzers_code/SelectableFuncsCA.cpp
    src/analyzers_code/CodeQACA.cpp
    src/analyzers_code/FuncInstrStatsCA.cpp
    src/analyzers_code/RetpolineCA.cpp
    src/analyzers_code/CorpusRankCfgCA.cpp

    src/analyzers_event/FuzzImmEvent.cpp
)

target_link_libraries(Analyzer CFG Utils ${llvm_libs} ${GFLAGS_LIBRARIES} ${GLOG_LIBRARIES} nlohmann_json ssl crypto capstone-static)
add_dependencies(Analyzer gflags-extern glog-extern)
target_include_directories(Analyzer PUBLIC ${LLVM_INCLUDE_DIRS} ${GFLAGS_INCLUDE_DIRS} ${GLOG_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/include)
