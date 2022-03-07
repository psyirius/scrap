cmake_minimum_required(VERSION 3.20)
project(QuickJS)

set(CMAKE_C_STANDARD        17)
set(CMAKE_CXX_STANDARD      17)
set(CMAKE_VERBOSE_MAKEFILE  on)

file(STRINGS "VERSION" QJS_VERSION)

message("${PROJECT_NAME} v${QJS_VERSION}")

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
    target_link_libraries(${QJS_CORE_TARGET} PRIVATE ${LIB_WIN_PTHREAD_STATIC})
endif()

# QuickJS compiler.
set(QJS_COMPILER_TARGET qjsc)
add_executable(${QJS_COMPILER_TARGET} ${QJS_SOURCE_DIR}/qjsc.c)
target_link_libraries(${QJS_COMPILER_TARGET} PRIVATE ${QJS_CORE_TARGET})

set(QJSC_GENERATED_DIR ${QJS_GENERATED_DIR}/qjsc)

add_custom_command(
    OUTPUT ${QJSC_GENERATED_DIR}/repl.c ${QJSC_GENERATED_DIR}/calc.c
    # Compile repl.js into repl.c
    COMMAND qjsc -c -o ${QJSC_GENERATED_DIR}/repl.c -m ${QJS_LIB_DIR}/repl.js
    # Compile calc.js into calc.c
    COMMAND qjsc -c -o ${QJSC_GENERATED_DIR}/calc.c -m ${QJS_LIB_DIR}/calc.js
    DEPENDS ${QJS_COMPILER_TARGET}
)

set(QJSC_GENERATED_SOURCES
    ${QJSC_GENERATED_DIR}/repl.c
    ${QJSC_GENERATED_DIR}/calc.c
)

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
add_custom_target(${QJS_TEST_TARGET}
    COMMENT "Running test..."

    WORKING_DIRECTORY ${QJS_TESTS_SOURCE_DIR}

    COMMAND ${QJS_INTERPRETER_TARGET} test_closure.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_language.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_builtin.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_loop.js
    COMMAND ${QJS_INTERPRETER_TARGET} test_std.js
#    COMMAND ${QJS_INTERPRETER_TARGET} test_worker.js

    DEPENDS ${QJS_TEST_BJSON_TARGET}
)
add_dependencies(${QJS_TEST_TARGET} ${QJS_INTERPRETER_TARGET})

add_test(
    NAME ${QJS_TEST_TARGET}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${QJS_TEST_TARGET}
)

