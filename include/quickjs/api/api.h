/* QuickJs Engine - Internal API */
#pragma once

#include "quickjs/macros/types.h"
#include "quickjs/macros/struct.h"

DECL_STRUCT(JSAtom);
DECL_STRUCT(JSClass);
DECL_STRUCT(JSValue);
DECL_STRUCT(JSString);
DECL_STRUCT(JSObject);
DECL_STRUCT(JSRuntime);
DECL_STRUCT(JSContext);
DECL_STRUCT(JSClassDef);
DECL_STRUCT(JSModuleDef);
DECL_STRUCT(JSAtomStruct);
DECL_STRUCT(JSValueUnion);
DECL_STRUCT(JSMallocState);
DECL_STRUCT(JSMemoryUsage);
DECL_STRUCT(JSPropertyEnum);
DECL_STRUCT(JSRefCountHeader);
DECL_STRUCT(JSGCObjectHeader);
DECL_STRUCT(JSMallocFunctions);
DECL_STRUCT(JSCFunctionListEntry);
DECL_STRUCT(JSPropertyDescriptor);
DECL_STRUCT(JSRuntimeThreadState);
DECL_STRUCT(JSClassExoticMethods);
DECL_STRUCT(JSGlobalAccessFunctions);
DECL_STRUCT(JSSharedArrayBufferFunctions);

DECL_UNION(JSCFunctionCall);

DECL_ENUM(JSAtomKind);
DECL_ENUM(JSAtomType);
DECL_ENUM(JSCFunctionType);

DECL_STRUCT(JSValue) {
    int64_t _tag;
    union {
        int32_t   _i32;
        float64_t _f64;
        void     *_ptr;
    };
};

#define JSValue_MAKE_I32(tag, val) (JSValue){ ._tag = (tag), ._i32 = (val) }
#define JSValue_MAKE_F64(tag, val) (JSValue){ ._tag = (tag), ._f64 = (val) }
#define JSValue_MAKE_PTR(tag, val) (JSValue){ ._tag = (tag), ._ptr = (val) }

void JS_Context_SetGlobalAccessFunctions(JSContext *ctx, const JSGlobalAccessFunctions *af);

void JS_Runtime_SetMaxStackSize(JSRuntime *rt, size_t stack_size);

void JS_Runtime_DumpString(JSRuntime *rt, const JSString *str);

int JS_Runtime_InitAtoms(JSRuntime *rt);

void JS_Runtime_DumpAtoms(JSRuntime *rt);

JSAtom JS_Runtime_DupAtom(JSRuntime *rt, JSAtom v);

JSAtom JS_Context_DupAtom(JSContext *ctx, JSAtom v);

JSAtom JS_Context_NewAtomLen(JSContext *ctx, const char *str, size_t len);

JSAtom JS_Context_NewAtom(JSContext *ctx, const char *str);

JSAtom JS_Context_NewAtomUInt32(JSContext *ctx, uint32_t n);

JSAtom JS_Context_NewAtomInt64(JSContext *ctx, int64_t n);

JSAtom JS_Context_NewAtomStr(JSContext *ctx, JSString *str);

JSAtom JS_Runtime_FindAtom(JSRuntime *rt, const char *str, size_t len, JSAtomType type);

JSAtom JS_Runtime_NewAtomInit(JSRuntime *rt, const char *str, int len, JSAtomType type);

int JS_Runtime_AtomHashResize(JSRuntime *rt, size_t new_size);

void JS_Runtime_FreeAtomStruct(JSRuntime *rt, JSAtomStruct *p);

void JS_Runtime_FreeAtom(JSRuntime *rt, size_t index);

JSValue JS_Runtime_DupValue(JSRuntime *rt, JSValue value);

JSValue JS_Context_DupValue(JSContext *ctx, JSValue value);

void JS_Runtime_FreeValue(JSRuntime *rt, JSValue value);

void JS_Context_FreeValue(JSContext *ctx, JSValue value);

JSValue JS_Context_NewSymbol(JSContext *ctx, JSString *str, JSAtomType type);

JSValue JS_Context_NewSymbolFromAtom(JSContext *ctx, JSAtom desc, JSAtomType type);

JSAtomKind JS_Context_AtomGetKind(JSContext *ctx, JSAtom v);

bool JS_Context_AtomIsString(JSContext *ctx, JSAtom v);

const char* JS_Context_AtomToCString(JSContext *ctx, JSAtom atom);

