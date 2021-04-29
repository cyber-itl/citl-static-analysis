project(Utils)

add_library(Utils
    src/Utils.cpp
    src/SecComp.cpp
    src/meta.cpp
)

execute_process(COMMAND
  "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=40
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_SHA1
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE retcode)

if(NOT "${retcode}" STREQUAL "0")
  set(GIT_SHA1 "NONE")
endif()

target_compile_definitions(Utils PRIVATE GIT_SHA1="${GIT_SHA1}")
target_link_libraries(Utils ${llvm_libs} ${GLOG_LIBRARIES})
add_dependencies(Utils gflags-extern glog-extern)
target_include_directories(Utils PUBLIC ${LLVM_INCLUDE_DIRS} ${GFLAGS_INCLUDE_DIRS} ${GLOG_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/include)
