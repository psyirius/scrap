/*
 * CString utilities
 */
#pragma once

#include "quickjs/config.h"

#include "quickjs/macros/struct.h"
#include "quickjs/macros/types.h"
#include "quickjs/macros/function.h"

#define CT_NAME CString
#define CT_TYPE const char*
#include "quickjs/macros/ctypi.h"

// Namespace model
DECL_STRUCT(CStringPrototype) {
    DEF_METHOD(length, size_t);
    DEF_METHOD(cmp, int, const char* other);
    DEF_METHOD(equals, bool, const char* other);
    DEF_METHOD(is_empty, bool);
    DEF_METHOD(is_digits, bool);
    DEF_METHOD(find, const char*, char find);
    DEF_METHOD(replace_char, size_t, char find, char replace);
};

extern CStringPrototype CString;

#if !defined(INCLUDE_FROM_IMPL_C)
#include "quickjs/macros/ctypi.h"
#endif
