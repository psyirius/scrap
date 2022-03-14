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
DECL_METHOD(is_digits, bool);
DECL_METHOD(find, const char*, char find);
DECL_METHOD(replace_char, size_t, char find, char replace);

// Namespace model setup
CStringPrototype CString = {
    REF_METHOD(length),
    REF_METHOD(cmp),
    REF_METHOD(equals),
    REF_METHOD(is_digits),
    REF_METHOD(find),
    REF_METHOD(replace_char),
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

IMPL_METHOD(is_digits, bool) {
    char *s = (char *) self;
    while (*s != '\0') {
        if ((*s < '0') || (*s > '9')) {
            return false;
        }
    }

    return true;
}

IMPL_METHOD(find, const char*, char find) {
    char *s = (char *) self;
    while (*s != '\0') {
        if (*s == find) {
            return s;
        }
        s++;
    }

    return nullptr;
}

IMPL_METHOD(replace_char, size_t, char find, char replace) {
    char *ps = (char *) self;
    size_t o = 0;

    while((ps = (char *) REF_METHOD(find)(ps, find)) != nullptr) {
        *ps++ = replace;
        o++;
    }

    return o;
}
