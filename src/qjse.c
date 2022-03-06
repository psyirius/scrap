/*
 * QuickJS Embedded Example (with REPL) (C)
 */

#include <stdio.h>
#include <stdbool.h>

#include "quickjs/quickjs.h"
#include "quickjs/libc/quickjs-libc.h"

#include "lib/repl.h"

#ifdef CONFIG_BIGNUM

#include "lib/calc.h"

#endif

size_t cstr_len(const char *str) {
    size_t len = 0;

    while (str[len]) {
        len++;
    }

    return len;
}

/* Also used to initialize the worker context */
static JSContext *JS_NewCustomContext(JSRuntime *rt) {
    JSContext *ctx = JS_NewContext(rt);

    if (!ctx) return NULL;

#ifdef CONFIG_BIGNUM
    JS_AddIntrinsicBigFloat(ctx);
    JS_AddIntrinsicBigDecimal(ctx);
    JS_AddIntrinsicOperators(ctx);
    JS_EnableBignumExt(ctx, true);
#endif

    /* system modules */
    js_init_module_std(ctx, "std");
    js_init_module_os(ctx, "os");

    /* stdlib modules */
//    js_init_module_re(ctx, "re");

    return ctx;
}

static int js_eval_string(JSContext *ctx, const char *js_src, const char *filename, int eval_flags) {
    JSValue val;
    int ret;

    if ((eval_flags & JS_EVAL_TYPE_MASK) == JS_EVAL_TYPE_MODULE) {
        /* for the modules, we compile then run to be able to set import.meta */
        val = JS_Eval(ctx, js_src, cstr_len(js_src), filename, eval_flags | JS_EVAL_FLAG_COMPILE_ONLY);
        if (!JS_IsException(val)) {
            js_module_set_import_meta(ctx, val, true, true);
            val = JS_EvalFunction(ctx, val);
        }
    } else {
        val = JS_Eval(ctx, js_src, cstr_len(js_src), filename, eval_flags);
    }
    if (JS_IsException(val)) {
        js_std_dump_error(ctx);
        ret = -1;
    } else {
        ret = 0;
    }
    JS_FreeValue(ctx, val);
    return ret;
}

int main(int argc, char *argv[], char *envp[]) {
    printf("%s\n", "Welcome to QuickJS Embedded!");

    JSRuntime *rt = JS_NewRuntime();
    if (!rt) {
        fprintf(stderr, "qjs: cannot allocate JS runtime\n");
        exit(2);
    }

    js_std_set_worker_new_context_func(JS_NewCustomContext);
    js_std_init_handlers(rt);

    JSContext *ctx = JS_NewCustomContext(rt);
    if (!ctx) {
        fprintf(stderr, "qjs: cannot allocate JS context\n");
        js_std_free_handlers(rt);
        JS_FreeRuntime(rt);
        exit(2);
    }

    /* Loader for ES6 modules */
    JS_SetModuleLoaderFunc(rt, NULL, js_module_loader, NULL);

#ifdef CONFIG_BIGNUM
    // Preload math-calc stuff
    js_std_eval_binary(ctx, qjsc_calc, qjsc_calc_size, 0);
#endif

    js_std_add_helpers(ctx, 0, NULL);

    const char *str = "import * as std from 'std'; globalThis.std = std;"
                      "import * as os from 'os'; globalThis.os = os;";

    js_eval_string(ctx, str, "<input>", JS_EVAL_TYPE_MODULE);

    // Init REPL
    js_std_eval_binary(ctx, qjsc_repl, qjsc_repl_size, 0);

    js_std_loop(ctx);

    js_std_free_handlers(rt);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    return 0;
}
