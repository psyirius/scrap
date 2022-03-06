/*
 * QuickJS C library
 */
#pragma once

#include <stdio.h>
#include <stdlib.h>

#include "quickjs.h"

#ifdef __cplusplus
extern "C" {
#endif

JSModuleDef *js_init_module_std(JSContext *ctx, const char *module_name);

JSModuleDef *js_init_module_os(JSContext *ctx, const char *module_name);

void js_std_add_helpers(JSContext *ctx, int argc, char **argv);

void js_std_loop(JSContext *ctx);

void js_std_init_handlers(JSRuntime *rt);

void js_std_free_handlers(JSRuntime *rt);

void js_std_dump_error(JSContext *ctx);

uint8_t *js_load_file(JSContext *ctx, size_t *pbuf_len, const char *filename);

int js_module_set_import_meta(JSContext *ctx, JSValueConst func_val,
                              JS_BOOL use_realpath, JS_BOOL is_main);

JSModuleDef *js_module_loader(JSContext *ctx,
                              const char *module_name, void *opaque);

void js_std_eval_binary(JSContext *ctx, const uint8_t *buf, size_t buf_len,
                        int flags);

void js_std_promise_rejection_tracker(JSContext *ctx, JSValueConst promise,
                                      JSValueConst reason,
                                      JS_BOOL is_handled, void *opaque);

void js_std_set_worker_new_context_func(JSContext *(*func)(JSRuntime *rt));

#ifdef __cplusplus
} /* extern "C" { */
#endif
