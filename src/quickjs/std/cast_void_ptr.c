#define INCLUDE_FROM_CVP_IMPL_C
#include "quickjs/std/cast_void_ptr.h"
#undef INCLUDE_FROM_CVP_IMPL_C

// Declarations
DECL_METHOD(as_i8p, int8_t*);
DECL_METHOD(as_u8p, uint8_t*);
DECL_METHOD(as_i16p, int16_t*);
DECL_METHOD(as_u16p, uint16_t*);
DECL_METHOD(as_i32p, int32_t*);
DECL_METHOD(as_u32p, uint32_t*);
DECL_METHOD(as_i64p, int64_t*);
DECL_METHOD(as_u64p, uint64_t*);
DECL_METHOD(as_f32p, float32_t*);
DECL_METHOD(as_f64p, float64_t*);
DECL_METHOD(as_iptr, intptr_t);
DECL_METHOD(as_uiptr, uintptr_t);

// Namespace model setup
CastVoidPtrPrototype CastVoidPtr = {
    REF_METHOD(as_i8p),
    REF_METHOD(as_u8p),
    REF_METHOD(as_i16p),
    REF_METHOD(as_u16p),
    REF_METHOD(as_i32p),
    REF_METHOD(as_u32p),
    REF_METHOD(as_i64p),
    REF_METHOD(as_u64p),
    REF_METHOD(as_f32p),
    REF_METHOD(as_f64p),
    REF_METHOD(as_iptr),
    REF_METHOD(as_uiptr),
};

// Macros
#define cast_as(value, type) \
    ((type*) &self)[0]


// Implementations
IMPL_METHOD(as_i8p, int8_t*) {
    return cast_as(self, int8_t*);
}

IMPL_METHOD(as_u8p, uint8_t*) {
    return cast_as(self, uint8_t*);
}

IMPL_METHOD(as_i16p, int16_t*) {
    return cast_as(self, int16_t*);
}

IMPL_METHOD(as_u16p, uint16_t*) {
    return cast_as(self, uint16_t*);
}

IMPL_METHOD(as_i32p, int32_t*) {
    return cast_as(self, int32_t*);
}

IMPL_METHOD(as_u32p, uint32_t*) {
    return cast_as(self, uint32_t*);
}

IMPL_METHOD(as_i64p, int64_t*) {
    return cast_as(self, int64_t*);
}

IMPL_METHOD(as_u64p, uint64_t*) {
    return cast_as(self, uint64_t*);
}

IMPL_METHOD(as_f32p, float32_t*) {
    return cast_as(self, float32_t*);
}

IMPL_METHOD(as_f64p, float64_t*) {
    return cast_as(self, float64_t*);
}

IMPL_METHOD(as_iptr, intptr_t) {
    return cast_as(self, intptr_t);
}

IMPL_METHOD(as_uiptr, uintptr_t) {
    return cast_as(self, uintptr_t);
}
