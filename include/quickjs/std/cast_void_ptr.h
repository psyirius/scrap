/*
 * Type casting utilities (void * as ---)
 */
#pragma once

#include "quickjs/config.h"

#include "quickjs/macros/struct.h"
#include "quickjs/macros/types.h"

#define CT_NAME CastVoidPtr
#define CT_TYPE void*
#include "quickjs/macros/ctypi.h"

// Namespace model
DECL_STRUCT(CastVoidPtrPrototype) {
    DEF_METHOD(as_i8p, int8_t*);
    DEF_METHOD(as_u8p, uint8_t*);
    DEF_METHOD(as_i16p, int16_t*);
    DEF_METHOD(as_u16p, uint16_t*);
    DEF_METHOD(as_i32p, int32_t*);
    DEF_METHOD(as_u32p, uint32_t*);
    DEF_METHOD(as_i64p, int64_t*);
    DEF_METHOD(as_u64p, uint64_t*);
    DEF_METHOD(as_f32p, float32_t*);
    DEF_METHOD(as_f64p, float64_t*);
    DEF_METHOD(as_iptr, intptr_t);
    DEF_METHOD(as_uiptr, uintptr_t);
};

extern CastVoidPtrPrototype CastVoidPtr;

#if !defined(INCLUDE_FROM_CVP_IMPL_C)
#include "quickjs/macros/ctypi.h"
#endif
