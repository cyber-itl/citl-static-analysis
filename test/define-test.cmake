macro(define_test_raw test_name input_bin extra_args)
    set(OUTPUT_JSON_DIR ${PROJECT_SOURCE_DIR}/test/json/${input_bin}.json)
    set(BASE_CMD ${CMAKE_BINARY_DIR}/citl-static-analysis -spectre-analyzer -insn_stats_analyzer -omit_git -nolog_prefix -all_analyzers -logtostderr ${extra_args} -binfile ${testbin_src_dir}/${input_bin})
    set(TEST_CMD ${BASE_CMD} -test ${OUTPUT_JSON_DIR})

    add_test(NAME ${test_name} COMMAND ${TEST_CMD})

    add_custom_target(refresh_test_${test_name} COMMAND ${BASE_CMD} > ${OUTPUT_JSON_DIR})
    list(APPEND refresh_targets refresh_test_${test_name})
endmacro()

macro(define_test test_name input_bin)
    define_test_raw(${test_name} ${input_bin} "")
endmacro()

macro(define_unit testname srcfile srcdeps input_file)
    add_executable(${testname} $<TARGET_OBJECTS:catch_main> ${srcfile})

    target_compile_definitions(${testname} PRIVATE CATCH_CONFIG_PREFIX_ALL CATCH_CONFIG_FAST_COMPILE)

    # If we have a input file, assign it to the preproc definition
    string(COMPARE EQUAL input_file "" result)
    if (NOT ${result})
        target_compile_definitions(${testname} PRIVATE CATCH_INPUT_BIN="${input_file}")
    endif(NOT ${result})

    target_link_libraries(${testname} ${srcdeps} Catch2::Catch2)
    target_include_directories(${testname} PRIVATE ${GFLAGS_INCLUDE_DIRS})
    list(APPEND unit_targets ${testname})

    add_test(NAME "${testname}"
        COMMAND ${testname}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
endmacro()
