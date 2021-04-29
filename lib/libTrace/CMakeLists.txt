project(Trace)

add_library(Trace
    src/TraceManager.cpp
    src/TraceAnalyzer.cpp

    src/DisasmAnalyzer.cpp
    src/SymTraceAnalyzer.cpp
    src/LiftingAnalyzer.cpp
)

target_link_libraries(Trace CFG ${llvm_libs} ${GLOG_LIBRARIES} ${GFLAGS_LIBRARIES} capstone-static)
add_dependencies(Trace gflags-extern glog-extern)
target_include_directories(Trace PUBLIC ${LLVM_INCLUDE_DIRS} ${GFLAGS_INCLUDE_DIRS} ${GLOG_INCLUDE_DIRS} ${CAPSTONE_INCLUDES} ${CMAKE_CURRENT_SOURCE_DIR}/include)
