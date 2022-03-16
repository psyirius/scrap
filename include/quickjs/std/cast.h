/*
 * Type casting utilities (--- as ---)
 */
#pragma once

#include "quickjs/config.h"

#include "quickjs/macros/struct.h"

#include "quickjs/std/cast_void_ptr.h"

// Namespace model
DECL_STRUCT(CastPrototype) {
    CastVoidPtrPrototype *VoidPtr;
};

extern CastPrototype Cast;
