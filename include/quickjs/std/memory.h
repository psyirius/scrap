/*
 * Memory utilities
 */
#pragma once

#include "quickjs/config.h"

#include "quickjs/macros/struct.h"
#include "quickjs/macros/types.h"

#define CT_NAME Memory
#define CT_TYPE void*
#include "quickjs/macros/ctypi.h"

// Namespace model
DECL_STRUCT(MemoryPrototype) {
    DEF_STATIC_METHOD(alloc, void*, size_t size);
    DEF_STATIC_METHOD(release, void, void* mem);
    DEF_METHOD(copy, size_t, const void* from, size_t size);
    DEF_METHOD(clone, void*, size_t size);
    DEF_METHOD(reverse, void, size_t size);
};

extern MemoryPrototype Memory;

#if !defined(INCLUDE_FROM_MEM_IMPL_C)
#include "quickjs/macros/ctypi.h"
#endif
