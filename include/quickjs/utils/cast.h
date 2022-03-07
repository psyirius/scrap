#pragma once

#include "ctypi.h"

// Macros
#define DEF_Cast_METHOD(method, return_type, ...) \
    DEF_METHOD(Cast, void*, method, return_type, ##__VA_ARGS__)

#define DECL_Cast_METHOD(method, return_type, ...) \
    DECL_METHOD(Cast, void*, method, return_type, ##__VA_ARGS__)

#define IMPL_Cast_METHOD(method, return_type, ...) \
    IMPL_METHOD(Cast, void*, method, return_type, ##__VA_ARGS__)


// Declarations
DECL_Cast_METHOD(voidp_as_u8p, uint8_t*);

DECL_Cast_METHOD(voidp_as_u16p, uint16_t*);
DECL_Cast_METHOD(voidp_as_u32p, uint32_t*);
DECL_Cast_METHOD(voidp_as_u64p, uint64_t*);

DECL_Cast_METHOD(voidp_as_f32p, float*);
DECL_Cast_METHOD(voidp_as_f64p, double*);

struct {
    DEF_Cast_METHOD(voidp_as_u8p, uint8_t*);

    DEF_Cast_METHOD(voidp_as_u16p, uint16_t*);
    DEF_Cast_METHOD(voidp_as_u32p, uint32_t*);
    DEF_Cast_METHOD(voidp_as_u64p, uint64_t*);

    DEF_Cast_METHOD(voidp_as_f32p, float*);
    DEF_Cast_METHOD(voidp_as_f64p, double*);
} Cast = {
    REF_METHOD(Cast, voidp_as_u8p),

    REF_METHOD(Cast, voidp_as_u16p),
    REF_METHOD(Cast, voidp_as_u32p),
    REF_METHOD(Cast, voidp_as_u64p),

    REF_METHOD(Cast, voidp_as_f32p),
    REF_METHOD(Cast, voidp_as_f64p),
};


// Implementations
IMPL_Cast_METHOD(voidp_as_u8p, uint8_t*) {
    return (uint8_t*) ((void**) &self)[0];
}

IMPL_Cast_METHOD(voidp_as_u16p, uint16_t*) {
    return (uint16_t*) ((void**) &self)[0];
}

IMPL_Cast_METHOD(voidp_as_u32p, uint32_t*) {
    return (uint32_t*) ((void**) &self)[0];
}

IMPL_Cast_METHOD(voidp_as_u64p, uint64_t*) {
    return (uint64_t*) ((void**) &self)[0];
}

IMPL_Cast_METHOD(voidp_as_f32p, float*) {
    return (float*) ((void**) &self)[0];
}

IMPL_Cast_METHOD(voidp_as_f64p, double*) {
    return (double*) ((void**) &self)[0];
}
