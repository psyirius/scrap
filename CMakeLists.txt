cmake_minimum_required(VERSION 3.21)
project(QuickJS)

set(CMAKE_C_STANDARD        17)
set(CMAKE_CXX_STANDARD      17)
set(CMAKE_VERBOSE_MAKEFILE  on)

file(STRINGS "VERSION" QJS_VERSION)

message("${PROJECT_NAME} v${QJS_VERSION}")

set(QJS_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(QJS_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

file(GLOB QJS_CORE_HEADERS
    ${QJS_SOURCE_DIR}/quickjs/*.h
    ${QJS_SOURCE_DIR}/quickjs/*.hpp
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

# QuickJS Main. (for testing) (using MINGW-w64 v9.0 for now which has POSIX threads)
set(QJS_EMBEDDED_TARGET qjx)
set(LIB_WIN_PTHREAD_STATIC -static winpthread)
add_executable(${QJS_EMBEDDED_TARGET} ${QJS_SOURCE_DIR} ${QJS_SOURCE_DIR}/main.c)
target_link_libraries(${QJS_EMBEDDED_TARGET} PRIVATE ${QJS_CORE_TARGET} ${LIB_WIN_PTHREAD_STATIC})
