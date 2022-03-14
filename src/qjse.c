/*
 * QuickJS Embedded Example (with REPL) (C)
 */
#include <stdio.h>
#include <stdbool.h>

#include "quickjs/quickjs.h"
#include "quickjs/libc.h"
#include "quickjs/utils/cstring.h"

// repl.js compiled
#include "lib/repl.h"

// calc.js compiled
#include "lib/calc.h"

// test.js compiled
#include "lib/test.h"

/* extra modules */
#include "quickjs/modules/example.h"

/* Also used to initialize the worker context */
static
JSContext* JS_NewCustomContext(JSRuntime *rt) {
    JSContext *ctx = JS_NewContext(rt);

    if (!ctx) return NULL;

#ifdef CONFIG_BIGNUM
    JS_AddIntrinsicBigFloat(ctx);
    JS_AddIntrinsicBigDecimal(ctx);
    JS_AddIntrinsicOperators(ctx);
    JS_EnableBignumExt(ctx, true);
#endif

    /* stdlib modules */
    js_init_module_std(ctx, "std");
    js_init_module_os(ctx, "os");

    /* extra modules */
    js_init_module_example(ctx, "example");

    return ctx;
}

static
int js_import_globals(JSContext *ctx) {
#define IMPORT_GLOBAL_TO_GLOBAL_JS(name) \
    "globalThis."#name" = globalThis;"

#define IMPORT_MOD_TO_GLOBAL_JS(name) \
    "import * as "#name" from '"#name"';" \
    "globalThis."#name" = "#name";"

    const char *js_src = (
        IMPORT_GLOBAL_TO_GLOBAL_JS(global)

        IMPORT_MOD_TO_GLOBAL_JS(std)
        IMPORT_MOD_TO_GLOBAL_JS(os)

        IMPORT_MOD_TO_GLOBAL_JS(example)
    );

    const char *filename = "<input>";
    int eval_flags = JS_EVAL_TYPE_MODULE;

    JSValue val;
    if ((eval_flags & JS_EVAL_TYPE_MASK) == JS_EVAL_TYPE_MODULE) {
        /* for the modules, we compile then run to be able to set import.meta */
        val = JS_Eval(ctx, js_src, CString.length(js_src), filename, eval_flags | JS_EVAL_FLAG_COMPILE_ONLY);
        if (!JS_IsException(val)) {
            js_module_set_import_meta(ctx, val, true, true);
            val = JS_EvalFunction(ctx, val);
        }
    } else {
        val = JS_Eval(ctx, js_src, CString.length(js_src), filename, eval_flags);
    }

    int ret;
    if (JS_IsException(val)) {
        js_std_dump_error(ctx);
        ret = -1;
    } else {
        ret = 0;
    }

    JS_FreeValue(ctx, val);

    return ret;
}

int main(int argc, char* argv[], char* envp[]) {
    printf("%s\n", "Welcome to QuickJS Embedded!");

    JSRuntime *rt = JS_NewRuntime();

    if (!rt) {
        fprintf(stderr, "qjs: cannot allocate JS runtime\n");
        exit(2);
    }

    js_std_set_worker_new_context_func(JS_NewCustomContext);
    js_std_init_handlers(rt);

    JSContext* ctx = JS_NewCustomContext(rt);

    if (!ctx) {
        fprintf(stderr, "qjs: cannot allocate JS context\n");
        js_std_free_handlers(rt);
        JS_FreeRuntime(rt);
        exit(2);
    }

    /* Loader for ES6 modules */
    JS_SetModuleLoaderFunc(rt, NULL, js_module_loader, NULL);

    js_std_add_helpers(ctx, 0, NULL);
    js_import_globals(ctx);

    // run test script
    js_std_eval_binary(ctx, qjsc_test, qjsc_test_size, 0);

#ifdef CONFIG_BIGNUM
    // Preload math-calc stuff
    js_std_eval_binary(ctx, qjsc_calc, qjsc_calc_size, 0);
#endif

    // Init REPL
    js_std_eval_binary(ctx, qjsc_repl, qjsc_repl_size, 0);

    js_std_loop(ctx);

    js_std_free_handlers(rt);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    return 0;
}
