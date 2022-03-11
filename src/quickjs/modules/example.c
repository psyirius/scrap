#include "quickjs/modules/example.h"

#define countof(x) (sizeof(x) / sizeof((x)[0]))

static
int64_t fib(int64_t n) {
    switch (n) {
        case -1:
        case 0: return 0;
        case 1: return n;
        default:
            return fib(n - 1) + fib(n - 2);
    }
}

static
JSValue js_fib(JSContext* ctx, JSValueConst self, int argc, JSValueConst* argv) {
    int64_t n, res;
    if (JS_ToInt64(ctx, &n, argv[0]))
        return JS_EXCEPTION;
    res = fib(n);
    return JS_NewInt64(ctx, res);
}

static
const JSCFunctionListEntry js_fib_funcs[] = {
    JS_CFUNC_DEF("fib", 1, js_fib),
};

static
int js_fib_init(JSContext *ctx, JSModuleDef *m) {
    return JS_SetModuleExportList(ctx, m, js_fib_funcs, countof(js_fib_funcs));
}

JSModuleDef *js_init_module_example(JSContext *ctx, const char *module_name) {
    JSModuleDef *m = JS_NewCModule(ctx, module_name, js_fib_init);
    if (!m) return NULL;
    JS_AddModuleExportList(ctx, m, js_fib_funcs, countof(js_fib_funcs));
    return m;
}
