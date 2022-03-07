#pragma once

#include "ctypi.h"

// Macros
#define DEF_CString_METHOD(method, return_type, ...) \
    DEF_METHOD(CString, const char*, method, return_type, ##__VA_ARGS__)

#define DECL_CString_METHOD(method, return_type, ...) \
    DECL_METHOD(CString, const char*, method, return_type, ##__VA_ARGS__)

#define IMPL_CString_METHOD(method, return_type, ...) \
    IMPL_METHOD(CString, const char*, method, return_type, ##__VA_ARGS__)


// Declarations
DECL_CString_METHOD(length, size_t);

struct {
    DEF_CString_METHOD(length, size_t);
} CString = {
    REF_METHOD(CString, length),
};


// Implementations
IMPL_CString_METHOD(length, size_t) {
    size_t len = 0;

    while (self[len]) { len++; }

    return len;
}
