include(define-test.cmake)

FetchContent_Declare(
    TestBins
    GIT_REPOSITORY git@github.com:cyber-itl/static-test-bins.git
    GIT_TAG        2481c24fcd508e84f45015bdcdf274b318dc1346)
FetchContent_MakeAvailable(TestBins)
FetchContent_GetProperties(TestBins SOURCE_DIR testbin_src_dir)

# checksec for hardening tests
set(CHECKSEC_INSTALL_DIR ${CMAKE_BINARY_DIR}/staging/checksec)
ExternalProject_Add(
    checksec-extern
    PREFIX ${CMAKE_BINARY_DIR}/staging/checksec
    GIT_REPOSITORY "https://github.com/slimm609/checksec.sh.git"
    GIT_TAG "8a4c4da5ab8e103f971b0dff4746f60cd20d442d"
    INSTALL_DIR ${CHECKSEC_INSTALL_DIR}
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ""
    LOG_CONFIGURE 1
    LOG_BUILD 1
    LOG_INSTALL 1)

add_library(catch_main OBJECT
    "src/unit.cpp"
)
target_link_libraries(catch_main PRIVATE Catch2::Catch2)

define_unit(unit-bitmap "src/unit-bitmap.cpp" CFG "")
define_unit(unit-regcache "src/unit-regcache.cpp" CFG "")
define_unit(unit-cfgres "src/unit-cfgres.cpp" CFG "")
define_unit(unit-unique-queue "src/unit-block-queue.cpp" CFG "")
define_unit(unit-cappattern "src/unit-cappattern.cpp" CFG "")

define_unit(unit-driver "src/unit-driver.cpp" Analyzer "${testbin_src_dir}/elf/x86/tree")

# Main based -test tests

set(refresh_targets "")

define_test(TestElf "elf/x86/tree")
define_test(TestElfSample "elf/x86/sample-app")
define_test(TestElfSampleFort "elf/x86/sample-app-fort")
define_test(TestElfRelocArchReadelf "elf/x86/readelf")
define_test(TestElfGo "elf/x86/hello-go")
define_test(TestElfRust "elf/x86/hello-rust")
define_test(TestElf32 "elf/x86/gcc_findutils_32_O3_code_stripped")
define_test(TestElfStripWithPlt "elf/x86/xfce4-about-strip")
define_test(TestElfStripGlobDat "elf/x86/readelf-strip")
define_test(TestElfSoname "elf/x86/jinfo-soname")
define_test(TestElfSCOP "elf/x86/scop-test")
define_test(TestElfOpenBsd "elf/x86/openbsd-nslookup")
define_test(TestElf32Stripped "elf/x86/dd-wrt-http-stripped")
define_test(TestElfRetpoline "elf/x86/retpoline-test-clang")
define_test(TestElf32GotSyms "elf/x86/x86-32-got-syms")
define_test(TestElfSectionOverlap "elf/x86/overlapping-sections")
define_test(TestElfFortHdr64 "elf/x86/partx-forthdr-64")

define_test(TestElfArm "elf/arm/dlink-proxyd")
define_test(TestElfArmUnwind "elf/arm/s62xd")
define_test(TestElfArmThumb "elf/arm/e2fsck")
define_test(TestElfThumbBridge "elf/arm/libcrypto_utils_android_8_1.so")
define_test(TestElfArmStripped "elf/arm/s62xd-strip")
define_test(TestElfArmTailCall "elf/arm/tail-call-bug")
define_test(TestElfArmSwitch "elf/arm/libpcre2-and10.so")
define_test(TestElfArmFortHdr "elf/arm/dropbear-forthdr")

define_test(TestElfArm64Bin "elf/arm64/6620_wmt_lpbk")
define_test(TestElfArm64Lib "elf/arm64/libcjson.so")
define_test(TestElfArm64NoDyn "elf/arm64/linker64")
define_test(TestElfArm64Android10Symtab "elf/arm64/android-10-symtab-specialcase")
define_test(TestElfArm64FortHdr "elf/arm64/dropbear-forthdr")

define_test(TestElfMips32elGcc "elf/mips/readelf")
define_test(TestElfMips32elClang "elf/mips/nl")
define_test(TestElfMips32Clang "elf/mips/nl-be")
define_test(TestElfMipsStripped "elf/mips/wlanconfig-strip")
define_test(TestElfMipsNoPLT "elf/mips/acos_service")
define_test(TestElfMipsSymtabUND "elf/mips/symtab-und-plts")
define_test(TestElfMipsFallbackGPSym "elf/mips/fallback-mips-gp-sym")
define_test(TestElfMipsFortHdr "elf/mips/dropbear-forthdr")

define_test(TestElfPPC32Bin "elf/ppc32/readelf")
define_test(TestElfPPC32Norelro "elf/ppc32/telnet")
define_test(TestElfPPC32Stripped "elf/ppc32/mtd-openwrt-stripped")

# fuzzing data tests
define_test_raw(TesstElfFuzzing "elf/x86/tree-fuzzdat" ${TestBins_SOURCE_DIR} "-events")

define_test(TestPeLib "pe/ntdll.dll")
define_test(TestPeExe "pe/Tcpview.exe")
define_test(TestPeGo "pe/hello-go.exe")
define_test(TestPeGS "pe/StackExample.exe")

define_test(TestMacho "macho/bnepd")
define_test(TestMachoGo "macho/hello-world-go")

# run 'make refresh_test_json' to update all test outputs
# please git diff and verify before commiting.
add_custom_target(refresh_test_json DEPENDS ${refresh_targets})

# Hardening tests
# get_property(STATIC_MAIN_PATH TARGET $<TARGET_FILE:citl-static-analysis> PROPERTY LOCATION)
add_test(NAME HardeningTest
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/checksec-wrapper.sh ${CHECKSEC_INSTALL_DIR}/src/checksec-extern/checksec ${CMAKE_BINARY_DIR}/citl-static-analysis)

add_custom_target(unit-tests DEPENDS ${unit_targets} checksec-extern)
