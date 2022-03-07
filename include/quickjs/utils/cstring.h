#pragma once

#include "ctypi.h"

// Define Macros
#define CString_METHOD(method) \
    REF_METHOD(CString, method)

#define DEF_CString_METHOD(method, return_type, ...) \
    DEF_METHOD(CString, const char*, method, return_type, ##__VA_ARGS__)

#define DECL_CString_METHOD(method, return_type, ...) \
    DECL_METHOD(CString, const char*, method, return_type, ##__VA_ARGS__)

#define IMPL_CString_METHOD(method, return_type, ...) \
    IMPL_METHOD(CString, const char*, method, return_type, ##__VA_ARGS__)


// Declarations
DECL_CString_METHOD(length, size_t);
DECL_CString_METHOD(cmp, int, const char* other);
DECL_CString_METHOD(equals, bool, const char* other);

struct {
    DEF_CString_METHOD(length, size_t);
    DEF_CString_METHOD(cmp, int, const char* other);
    DEF_CString_METHOD(equals, bool, const char* other);
} CString = {
    CString_METHOD(length),
    CString_METHOD(cmp),
    CString_METHOD(equals),
};


// Implementations
IMPL_CString_METHOD(length, size_t) {
    size_t len = 0;

    while (self[len]) { len++; }

    return len;
}

IMPL_CString_METHOD(cmp, int, const char* other) {
    const char *a = self, *b = other;

    while ((a[0] && b[0]) && (a[0] == b[0])) {
        a++, b++;
    }

    return (*(const unsigned char*)a) - (*(const unsigned char*)b);
}

IMPL_CString_METHOD(equals, bool, const char* other) {
    return CString_METHOD(cmp)(self, other) == 0;
}

// Un-define Macros
#undef CString_METHOD
#undef DEF_CString_METHOD
#undef DECL_CString_METHOD
#undef IMPL_CString_METHOD
