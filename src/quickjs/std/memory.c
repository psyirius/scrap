#define INCLUDE_FROM_MEM_IMPL_C
#include "quickjs/std/memory.h"
#undef INCLUDE_FROM_MEM_IMPL_C

#include <stdlib.h>

// Declarations
DECL_STATIC_METHOD(alloc, void*, size_t size);
DECL_STATIC_METHOD(release, void, void* mem);
DECL_METHOD(copy, size_t, const void* from, size_t size);
DECL_METHOD(clone, void*, size_t size);
DECL_METHOD(reverse, void, size_t size);

// Namespace model setup
MemoryPrototype Memory = {
    REF_METHOD(alloc),
    REF_METHOD(release),
    REF_METHOD(copy),
    REF_METHOD(clone),
    REF_METHOD(reverse),
};

// Implementations
IMPL_STATIC_METHOD(alloc, void*, size_t size) {
    return malloc(size);
}

IMPL_STATIC_METHOD(release, void, void* mem) {
    return free(mem);
}

IMPL_METHOD(copy, size_t, const void* from, size_t size) {
    size_t i = 0;

    while (i++ < size) {
        cast_as(self, uint8_t*)[i] = cast_as(from, uint8_t*)[i];
    }

    return i;
}

IMPL_METHOD(clone, void*, size_t size) {
    void* clone = REF_STATIC_METHOD(alloc)(size);

    REF_METHOD(copy)(clone, self, size);

    return clone;
}

IMPL_METHOD(reverse, void, size_t size) {
    uint8_t *buff = cast_as(self, uint8_t*);

    for (size_t l = 0, r; r = size - (l + 1), l < (size / 2); ++l) {
        // swap values
        buff[r] ^= buff[l];
        buff[l] ^= buff[r];
        buff[r] ^= buff[l];
    }
}

