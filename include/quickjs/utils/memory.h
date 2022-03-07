#pragma once

#include <stdlib.h>
#include "ctypi.h"

// Macros
#define Memory_METHOD(method) \
    REF_METHOD(Memory, method)

#define Memory_METHOD_STATIC(method) \
    Memory_METHOD(method)

#define DEF_Memory_METHOD(method, return_type, ...) \
    DEF_METHOD(Memory, void*, method, return_type, ##__VA_ARGS__)

#define DECL_Memory_METHOD(method, return_type, ...) \
    DECL_METHOD(Memory, void*, method, return_type, ##__VA_ARGS__)

#define IMPL_Memory_METHOD(method, return_type, ...) \
    IMPL_METHOD(Memory, void*, method, return_type, ##__VA_ARGS__)

#define DEF_Memory_METHOD_STATIC(method, return_type, ...) \
    DEF_METHOD_STATIC(Memory, method, return_type, ##__VA_ARGS__)

#define DECL_Memory_METHOD_STATIC(method, return_type, ...) \
    DECL_METHOD_STATIC(Memory, method, return_type, ##__VA_ARGS__)

#define IMPL_Memory_METHOD_STATIC(method, return_type, ...) \
    IMPL_METHOD_STATIC(Memory, method, return_type, ##__VA_ARGS__)

// Declarations
DECL_Memory_METHOD_STATIC(new, void*, size_t size);
DECL_Memory_METHOD_STATIC(free, void, void* mem);

DECL_Memory_METHOD(copy, size_t, const void* from, size_t size);
DECL_Memory_METHOD(reverseCopy, size_t, const void* from, size_t size);
DECL_Memory_METHOD(reverse, void, size_t size);

// Implementation
#include "quickjs/utils/cast.h"

IMPL_Memory_METHOD_STATIC(new, void*, size_t size) {
    return malloc(size);
}

IMPL_Memory_METHOD_STATIC(free, void, void* mem) {
    return free(mem);
}

IMPL_Memory_METHOD(copy, size_t, const void* from, size_t size) {
    size_t i = 0;

    while (i++ < size) {
        Cast.voidp_as_u8p(self)[i] = Cast.voidp_as_u8p((void*) from)[i];
    }

    return i;
}

IMPL_Memory_METHOD(reverseCopy, size_t, const void* from, size_t size) {
    size_t i = 0;

    while (i++ < size) {
        Cast.voidp_as_u8p(self)[i] = Cast.voidp_as_u8p((void*) from)[size - 1 - i];
    }

    return i;
}

IMPL_Memory_METHOD(reverse, void, size_t size) {
    size_t l = 0, r;
    uint8_t* buff = Cast.voidp_as_u8p(self);

    for (;r = size - (l + 1), l < (size / 2); ++l) {
        // swap values
        buff[r] ^= buff[l];
        buff[l] ^= buff[r];
        buff[r] ^= buff[l];
    }
}

// Namespace model
struct {
    DEF_Memory_METHOD_STATIC(new, void*, size_t size);
    DEF_Memory_METHOD_STATIC(free, void, void* mem);
    DEF_Memory_METHOD(copy, size_t, const void* from, size_t size);
    DEF_Memory_METHOD(reverseCopy, size_t, const void* from, size_t size);
    DEF_Memory_METHOD(reverse, void, size_t size);
} Memory = {
    Memory_METHOD_STATIC(new),
    Memory_METHOD_STATIC(free),
    Memory_METHOD(copy),
    Memory_METHOD(reverseCopy),
    Memory_METHOD(reverse),
};

