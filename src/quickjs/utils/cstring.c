#include "quickjs/utils/cstring.h"

#include <assert.h>

// Init in-type scope
#define CT_NAME CString
#define CT_TYPE const char*
#include "quickjs/macros/ctypi.h"

// Declarations
DECL_METHOD(length, size_t);
DECL_METHOD(cmp, int, const char* other);
DECL_METHOD(equals, bool, const char* other);

// Namespace model setup
CStringPrototype CString = {
    REF_METHOD(length),
    REF_METHOD(cmp),
    REF_METHOD(equals),
};

// Implementations
IMPL_METHOD(length, size_t) {
    size_t len = 0;

    while (self[len]) { len++; }

    return len;
}

IMPL_METHOD(cmp, int, const char* other) {
    const char *a = self, *b = other;

    while ((a[0] && b[0]) && (a[0] == b[0])) {
        a++, b++;
    }

    return (*(unsigned const char*)a) - (*(unsigned const char*)b);
}

IMPL_METHOD(equals, bool, const char* other) {
    return REF_METHOD(cmp)(self, other) == 0;
}
