cmake_minimum_required(VERSION 3.20)
project(QuickJS)

set(CMAKE_C_STANDARD        17)
set(CMAKE_CXX_STANDARD      17)
set(CMAKE_VERBOSE_MAKEFILE  on)

file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/VERSION" QJS_VERSION)

message(STATUS "${PROJECT_NAME} v${QJS_VERSION}")

function(print_list)
    set(prefix ARG)

    set(flags FLAGS)
    set(labelValue LABEL)
    set(filepathValues SOURCES LIST)

    cmake_parse_arguments(${prefix} "${flags}" "${labelValue}" "${filepathValues}" ${ARGN})

    message("${ARG_LABEL}:")
    foreach(list_item ${ARG_LIST})
        message("\t${list_item}")
    endforeach()
endfunction()

set(QJS_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/lib)
set(QJS_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(QJS_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

set(QJS_GENERATED_DIR ${CMAKE_CURRENT_LIST_DIR}/generated)

set(QJS_TESTS_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/tests)

set(QJS_TEST262_SOURCE_DIR ${QJS_TESTS_SOURCE_DIR}/test262)
set(QJS_TEST_EXP_SOURCE_DIR ${QJS_TESTS_SOURCE_DIR}/experimental)

file(GLOB_RECURSE QJS_CORE_HEADERS
    ${QJS_INCLUDE_DIR}/quickjs/*.h
    ${QJS_INCLUDE_DIR}/quickjs/*.hpp
)

file(GLOB_RECURSE QJS_CORE_SOURCES
    ${QJS_SOURCE_DIR}/quickjs/*.c
    ${QJS_SOURCE_DIR}/quickjs/*.cpp
)

set(QJS_CORE_TARGET qjs-core)

add_library(${QJS_CORE_TARGET} STATIC ${QJS_CORE_HEADERS} ${QJS_CORE_SOURCES})

target_include_directories(${QJS_CORE_TARGET} PUBLIC ${QJS_INCLUDE_DIR})

target_compile_options(${QJS_CORE_TARGET} PRIVATE
    -Os -s
    -MMD -MF
    -Wno-sign-compare
    -Wno-missing-field-initializers
    -Wunused -Wno-unused-parameter
    -Wundef -Wuninitialized -Wwrite-strings
    -Wchar-subscripts -funsigned-char
)

target_compile_definitions(${QJS_CORE_TARGET} PUBLIC
    CONFIG_VERSION="${QJS_VERSION}"
    CONFIG_BIGNUM
#    USE_WORKER  # win32 needs fixes
    _GNU_SOURCE
    "$<IF:$<BOOL:${WIN32}>,__USE_MINGW_ANSI_STDIO,>"
)

if (UNIX)
    target_link_libraries(${QJS_CORE_TARGET} PRIVATE m dl pthread)
else()
    set(LIB_WIN_PTHREAD_STATIC -static winpthread)
    target_link_libraries(${QJS_CORE_TARGET} PRIVATE ${LIB_WIN_PTHREAD_STATIC} ws2_32)
endif()

# QuickJS compiler.
set(QJS_COMPILER_TARGET qjsc)
add_executable(${QJS_COMPILER_TARGET} ${QJS_SOURCE_DIR}/qjsc.c)
target_link_libraries(${QJS_COMPILER_TARGET} PRIVATE ${QJS_CORE_TARGET})

set(QJSC_GENERATED_DIR ${QJS_GENERATED_DIR}/qjsc)

add_custom_command(
    OUTPUT ${QJSC_GENERATED_DIR}/repl.c ${QJSC_GENERATED_DIR}/calc.c ${QJSC_GENERATED_DIR}/test.c
    # Compile repl.js into repl.c as a module
    COMMAND qjsc -c -o ${QJSC_GENERATED_DIR}/repl.c -m ${QJS_LIB_DIR}/repl.js

    # Compile calc.js into calc.c not as a module with bignum
    COMMAND qjsc -fbignum -c -o ${QJSC_GENERATED_DIR}/calc.c ${QJS_LIB_DIR}/calc.js

    # Compile test.js into test.c as a module
    COMMAND qjsc -c -o ${QJSC_GENERATED_DIR}/test.c -m ${QJS_LIB_DIR}/test.js
    DEPENDS ${QJS_COMPILER_TARGET}
)

set(QJSC_GENERATED_SOURCES
    ${QJSC_GENERATED_DIR}/repl.c
    ${QJSC_GENERATED_DIR}/calc.c
    ${QJSC_GENERATED_DIR}/test.c
)

print_list(LABEL "QJsc Generated Sources:" LIST ${QJSC_GENERATED_SOURCES})

# QuickJS interpreter.
set(QJS_INTERPRETER_TARGET qjs)
add_executable(${QJS_INTERPRETER_TARGET} ${QJS_SOURCE_DIR}/qjs.c ${QJSC_GENERATED_SOURCES})
target_link_libraries(${QJS_INTERPRETER_TARGET} PRIVATE ${QJS_CORE_TARGET})

# QuickJS Embedded. (TestExample)
set(QJS_EMBEDDED_TARGET qjse)
add_executable(${QJS_EMBEDDED_TARGET} ${QJS_SOURCE_DIR}/qjse.c ${QJSC_GENERATED_SOURCES})
target_link_libraries(${QJS_EMBEDDED_TARGET} PRIVATE ${QJS_CORE_TARGET})

# QuickJS ECMA Test 262 Runner.
set(QJS_ECMA_TEST262_RUNNER_TARGET qjs_test262)
add_executable(${QJS_ECMA_TEST262_RUNNER_TARGET} ${QJS_TEST262_SOURCE_DIR}/run-test262.c)
target_link_libraries(${QJS_ECMA_TEST262_RUNNER_TARGET} PRIVATE ${QJS_CORE_TARGET})

# QuickJS BSON (Test).
set(QJS_TEST_BJSON_TARGET qjs_test_bjson)
add_library(${QJS_TEST_BJSON_TARGET} SHARED ${QJS_TESTS_SOURCE_DIR}/bjson.c)
target_link_libraries(${QJS_TEST_BJSON_TARGET} PRIVATE ${QJS_CORE_TARGET})

# QuickJS Experimental (Test).
set(QJS_TEST_EXP_TARGET qjs_test_exp)
add_executable(${QJS_TEST_EXP_TARGET} ${QJS_TEST_EXP_SOURCE_DIR}/test.c)
target_link_libraries(${QJS_TEST_EXP_TARGET} PRIVATE ${QJS_CORE_TARGET})

# tests
enable_testing()

# test
set(QJS_TEST_TARGET qjs_test)
add_custom_target(
    ${QJS_TEST_TARGET}

    COMMENT "Running test..."

    WORKING_DIRECTORY ${QJS_TESTS_SOURCE_DIR}

    COMMAND echo Running: test_closure.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_closure.js

    COMMAND echo Running: test_language.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_language.js

    COMMAND echo Running: test_builtin.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_builtin.js

    COMMAND echo Running: test_loop.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_loop.js

    COMMAND echo Running: test_std.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_std.js

    COMMAND echo Running: test_worker.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_worker.js

    DEPENDS ${QJS_INTERPRETER_TARGET}
)
add_test(
    NAME ${QJS_TEST_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TEST_TARGET}
)

# stats
set(QJS_STATS_TARGET qjs_stats)
add_custom_target(${QJS_STATS_TARGET}
    COMMENT "Running stats..."

    WORKING_DIRECTORY ${QJS_TESTS_SOURCE_DIR}

    COMMAND ${QJS_INTERPRETER_TARGET} -qd

    DEPENDS ${QJS_INTERPRETER_TARGET}
)
add_test(
    NAME ${QJS_STATS_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_STATS_TARGET}
)

# microbench
set(QJS_MICROBENCH_TARGET qjs_microbench)
add_custom_target(${QJS_MICROBENCH_TARGET}
    COMMENT "Running microbench..."

    WORKING_DIRECTORY ${QJS_TESTS_SOURCE_DIR}

    COMMAND ${QJS_INTERPRETER_TARGET} microbench.js

    DEPENDS ${QJS_INTERPRETER_TARGET}
)
add_test(
    NAME ${QJS_MICROBENCH_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_MICROBENCH_TARGET}
)

# ES5 tests (obsolete)
set(TEST262O_CONF_FILE ${QJS_TEST262_SOURCE_DIR}/test262o.conf)

# test2o
set(QJS_TEST2O_TARGET qjs_test2o)
add_custom_target(${QJS_TEST2O_TARGET}
    COMMENT "Running test2o..."

    WORKING_DIRECTORY ${QJS_TEST262_SOURCE_DIR}

    COMMAND ${QJS_ECMA_TEST262_RUNNER_TARGET} -m -c ${TEST262O_CONF_FILE}

    DEPENDS ${QJS_ECMA_TEST262_RUNNER_TARGET}
)
add_test(
    NAME ${QJS_TEST2O_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TEST2O_TARGET}
)

# test2o-update
set(QJS_TEST2O_UPDATE_TARGET qjs_test2o-update)
add_custom_target(${QJS_TEST2O_UPDATE_TARGET}
    COMMENT "Running test2o-update..."

    WORKING_DIRECTORY ${QJS_TEST262_SOURCE_DIR}

    COMMAND ${QJS_ECMA_TEST262_RUNNER_TARGET} -u -c ${TEST262O_CONF_FILE}

    DEPENDS ${QJS_ECMA_TEST262_RUNNER_TARGET}
)
add_test(
    NAME ${QJS_TEST2O_UPDATE_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TEST2O_UPDATE_TARGET}
)

# Test262 tests
set(TEST262_CONF_FILE ${QJS_TEST262_SOURCE_DIR}/test262.conf)

# test2-default
set(QJS_TEST2_DEFAULT_TARGET qjs_test2-default)
add_custom_target(${QJS_TEST2_DEFAULT_TARGET}
    COMMENT "Running test2-default..."

    WORKING_DIRECTORY ${QJS_TEST262_SOURCE_DIR}

    COMMAND ${QJS_ECMA_TEST262_RUNNER_TARGET} -m -c ${TEST262_CONF_FILE}

    DEPENDS ${QJS_ECMA_TEST262_RUNNER_TARGET}
)
add_test(
    NAME ${QJS_TEST2_DEFAULT_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TEST2_DEFAULT_TARGET}
)

# test2
set(QJS_TEST2_TARGET qjs_test2)
add_custom_target(${QJS_TEST2_TARGET}
    COMMENT "Running test2..."

    WORKING_DIRECTORY ${QJS_TEST262_SOURCE_DIR}

    COMMAND ${QJS_ECMA_TEST262_RUNNER_TARGET} -m -c ${TEST262_CONF_FILE} -a

    DEPENDS ${QJS_ECMA_TEST262_RUNNER_TARGET}
)
add_test(
    NAME ${QJS_TEST2_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TEST2_TARGET}
)

# test2-update
set(QJS_TEST2_UPDATE_TARGET qjs_test2-update)
add_custom_target(${QJS_TEST2_UPDATE_TARGET}
    COMMENT "Running test2-update..."

    WORKING_DIRECTORY ${QJS_TEST262_SOURCE_DIR}

    COMMAND ${QJS_ECMA_TEST262_RUNNER_TARGET} -u -c ${TEST262_CONF_FILE} -a

    DEPENDS ${QJS_ECMA_TEST262_RUNNER_TARGET}
)
add_test(
    NAME ${QJS_TEST2_UPDATE_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TEST2_UPDATE_TARGET}
)

# test2-check
set(QJS_TEST2_CHECK_TARGET qjs_test2-check)
add_custom_target(${QJS_TEST2_CHECK_TARGET}
    COMMENT "Running test2-check..."

    WORKING_DIRECTORY ${QJS_TEST262_SOURCE_DIR}

    COMMAND ${QJS_ECMA_TEST262_RUNNER_TARGET} -m -c ${TEST262_CONF_FILE} -E -a

    DEPENDS ${QJS_ECMA_TEST262_RUNNER_TARGET}
)
add_test(
    NAME ${QJS_TEST2_CHECK_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TEST2_CHECK_TARGET}
)

# testall
set(QJS_TESTALL_TARGET qjs_testall)
add_custom_target(${QJS_TESTALL_TARGET}
    COMMENT "Running testall..."

    WORKING_DIRECTORY ${QJS_TESTS_SOURCE_DIR}

    COMMAND echo "Running all tests..."

    DEPENDS ${QJS_MICROBENCH_TARGET} ${QJS_TEST2O_TARGET} ${QJS_TEST2_TARGET}
)
add_test(
    NAME ${QJS_TESTALL_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TESTALL_TARGET}
)
