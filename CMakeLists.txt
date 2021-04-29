cmake_minimum_required(VERSION 3.11)
project(citl-static-analysis)

set(CITL_STATIC_ANALYSIS_VERSION "0.1.2")

find_package(OpenSSL REQUIRED)

include(ProcessorCount)
include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

# BUILD_TYPE options:
#  'Debug'   - Adds debug info to builds
#  'Release' - full release builds

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif(NOT CMAKE_BUILD_TYPE)

option(ASAN "Add AddressSanitizer flags to build." OFF)

set(CXX_STD "c++14")
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcolor-diagnostics")
endif()

# Set major CXX flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=${CXX_STD} -fstack-protector -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector -fPIC")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,now -Wl,-z,relro -pie")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -D_FORTIFY_SOURCE=2")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -D_FORTIFY_SOURCE=2")
endif(CMAKE_BUILD_TYPE STREQUAL "Release")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSECCOMP_TRAP")
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

if(ASAN)
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
endif(ASAN)

# External deps
include(ExternalProject)
include(FetchContent)

function(remove_from_all prject)
    if(IS_DIRECTORY "${prject_SOURCE_DIR}")
        set_property(DIRECTORY ${prject_SOURCE_DIR} PROPERTY EXCLUDE_FROM_ALL YES)
    endif()
endfunction()

# gflags
set(GFLAGS_INSTALL_DIR ${CMAKE_BINARY_DIR}/contrib/gflags)
set(GFLAGS_LIBRARY_INSTALL_DIR ${GFLAGS_INSTALL_DIR})
set(GFLAGS_LIBRARIES ${GFLAGS_INSTALL_DIR}/lib/libgflags_nothreads.a)

ExternalProject_Add(
    gflags-extern
    PREFIX ${CMAKE_BINARY_DIR}/staging/gflags
    GIT_REPOSITORY "https://github.com/gflags/gflags.git"
    GIT_TAG "46f73f88b18aee341538c0dfc22b1710a6abedef" # tag v2.2.1
    INSTALL_DIR ${GFLAGS_INSTALL_DIR}
    CMAKE_ARGS
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
    -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    -DBUILD_SHARED_LIBS=OFF
    -DBUILD_STATIC_LIBS=ON
    -DBUILD_PACKAGING=OFF
    -DBUILD_TESTING=OFF
    -DBUILD_NC_TESTS=OFF
    -DBUILD_CONFIG_TESTS=OFF
    -DINSTALL_HEADERS=ON
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DCMAKE_INSTALL_PREFIX:STRING=${GFLAGS_INSTALL_DIR}
    -DCMAKE_EXE_LINKER_FLAGS:STRING=${CMAKE_EXE_LINKER_FLAGS}
    BUILD_BYPRODUCTS ${GFLAGS_LIBRARIES}
    LOG_CONFIGURE 1
    LOG_BUILD 1
    LOG_INSTALL 1)

set(GFLAGS_INCLUDE_DIRS ${GFLAGS_INSTALL_DIR}/include)
set(GFLAGS_LIBRARY_DIRS ${GFLAGS_INSTALL_DIR}/lib)

set(GFLAGS_NAMESPACE "google")

# glog
set(GLOG_INSTALL_DIR ${CMAKE_BINARY_DIR}/contrib/glog)
set(GLOG_LIBRARIES ${GLOG_INSTALL_DIR}/lib/libglog.a)

ExternalProject_Add(
    glog-extern
    DEPENDS gflags-extern
    PREFIX ${CMAKE_BINARY_DIR}/staging/glog
    GIT_REPOSITORY "https://github.com/google/glog.git"
    GIT_TAG "a6a166db069520dbbd653c97c2e5b12e08a8bb26" # tag v0.3.5
    INSTALL_DIR ${GLOG_INSTALL_DIR}
    CMAKE_ARGS
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
    -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DCMAKE_INSTALL_PREFIX:STRING=${GLOG_INSTALL_DIR}
    -DGFLAGS_NAMESPACE:STRING=${GFLAGS_NAMESPACE}
    -DCMAKE_EXE_LINKER_FLAGS:STRING=${CMAKE_EXE_LINKER_FLAGS}
    -Dgflags_DIR=${GFLAGS_INSTALL_DIR}
    -DBUILD_TESTING=OFF
    BUILD_BYPRODUCTS ${GLOG_LIBRARIES}
    LOG_CONFIGURE 1
    LOG_BUILD 1
    LOG_INSTALL 1)

set(GLOG_INCLUDE_DIRS ${GLOG_INSTALL_DIR}/include)
set(GLOG_LIBRARY_DIRS ${GLOG_INSTALL_DIR}/lib)

# llvm
message("Fetching llvm ...")
FetchContent_Declare(
    llvm_project
    GIT_REPOSITORY https://github.com/llvm/llvm-project.git
    GIT_TAG        llvmorg-10.0.0
    SOURCE_SUBDIR llvm/
)

option(LLVM_TOOLS "Toggle the LLVM varible: LLVM_BUILD_TOOLS in contrib builds." OFF)
set(LLVM_ENABLE_PIC ON)
set(LLVM_REQUIRES_RTTI TRUE)
set(LLVM_BUILD_TOOLS ${LLVM_TOOLS})
set(LLVM_INCLUDE_TOOLS OFF)
set(LLVM_INCLUDE_UTILS OFF)
set(LLVM_INCLUDE_EXAMPLES OFF)
set(LLVM_INCLUDE_TESTS OFF)
set(LLVM_INCLUDE_GO_TESTS OFF)
set(LLVM_INCLUDE_DOCS OFF)
set(LLVM_ENABLE_OCAMLDOC OFF)
set(LLVM_BUILD_RUNTIMES OFF)
set(LLVM_TARGETS_TO_BUILD X86)
set(LLVM_ABI_BREAKING_CHECKS FORCE_OFF)
FetchContent_MakeAvailable(llvm_project)

set(LLVM_INCLUDE_DIRS ${llvm_project_SOURCE_DIR}/llvm/include/ ${llvm_project_BINARY_DIR}/include/)

# nlohmann json
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        4414f94cd5b6f1f5d46677b96f4bee7096b64f59
)
set(JSON_BuildTests OFF CACHE BOOL "Disable JSON tests")
FetchContent_MakeAvailable(nlohmann_json)

# Capstone
FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/aquynh/capstone.git
    GIT_TAG        0f1674223452827493357dd7258145fe9f51cd05
)

set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Disable shared builds of capstone" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Disable capstone tests" FORCE)
set(CAPSTONE_X86_ATT_DISABLE ON CACHE BOOL "Disble ATT syntax" FORCE)
FetchContent_MakeAvailable(capstone)
set(CAPSTONE_INCLUDES ${capstone_SOURCE_DIR}/include/)


# Catch2
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v2.13.1)
FetchContent_MakeAvailable(Catch2)

# When we build the citl-static-analysis target, we don't want to re-build
# these packages. Also, when we install citl-static-analysis, we don't want
# these to also be installed.
set_target_properties(gflags-extern PROPERTIES EXCLUDE_FROM_ALL TRUE)
set_target_properties(glog-extern PROPERTIES EXCLUDE_FROM_ALL TRUE)
remove_from_all(llvm_project)
remove_from_all(nlohmann_json)
remove_from_all(capstone)
remove_from_all(Catch2)



# Our libs
add_subdirectory(lib/)

add_executable(citl-static-analysis ${PROJECT_SOURCE_DIR}/src/main.cpp)
add_dependencies(citl-static-analysis gflags-extern glog-extern)
target_link_libraries(citl-static-analysis LLVMSupport Analyzer Utils ${GFLAGS_LIBRARIES} ${GLOG_LIBRARIES})

add_executable(trace-walker ${PROJECT_SOURCE_DIR}/src/trace-walker.cpp)
add_dependencies(trace-walker gflags-extern glog-extern)
target_link_libraries(trace-walker Trace ${GFLAGS_LIBRARIES} ${GLOG_LIBRARIES})

# Testing
enable_testing()
add_subdirectory(test/)

# Packaging
install(TARGETS citl-static-analysis DESTINATION bin)
install(PROGRAMS utils/citl-run-directory.py DESTINATION bin)

set(CPACK_PACKAGE_VENDOR "Cyber Independent Testing Lab")
set(CPACK_PACKAGE_CONTACT "${CPACK_PACKAGE_VENDOR}")
set(CPACK_PACKAGE_NAME "citl-static-analysis")
set(CPACK_PACKAGE_VERSION "${CITL_STATIC_ANALYSIS_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "CITL static analysis tools")

set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl (>= 1.0.1), python (>= 2.7)")

set(CPACK_RPM_PACKAGE_REQUIRES "openssl >= 1.0.1, python >= 2.7")


include(CPack)

