/*
 * CString implementation
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
DEF_STRUCT(CStringPrototype) {
    DEF_METHOD(length, size_t);
    DEF_METHOD(cmp, int, const char* other);
    DEF_METHOD(equals, bool, const char* other);
    DEF_METHOD(is_numbers, bool);
    DEF_METHOD(replace_char, size_t, char find, char replace);
};

extern CStringPrototype CString;

#include "quickjs/macros/ctypi.h"
