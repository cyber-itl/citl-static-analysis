project(CFG)

add_library(CFG
    src/SymResolver.cpp
    src/ElfSyms.cpp
    src/PeSyms.cpp
    src/MachOSyms.cpp
    src/MemoryMap.cpp
    src/Cfg.cpp
    src/CapstoneHelper.cpp
    src/MemBitMap.cpp
    src/CapPattern.cpp
    src/AbiOracle.cpp
    src/CpuState.cpp
    src/Block.cpp
    src/EventManager.cpp
    src/BlockQueueUniq.cpp
)

target_link_libraries(CFG Utils LLVMSupport LLVMCore LLVMObject ${GLOG_LIBRARIES} ${GFLAGS_LIBRARIES} capstone-static nlohmann_json)
add_dependencies(CFG gflags-extern glog-extern)
target_include_directories(CFG PUBLIC ${LLVM_INCLUDE_DIRS} ${GLOG_INCLUDE_DIRS} ${CAPSTONE_INCLUDES} ${CMAKE_CURRENT_SOURCE_DIR}/include)
