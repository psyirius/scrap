cmake_minimum_required(VERSION 3.21)
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
    #    USE_WORKER  # needs fix for win32
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
