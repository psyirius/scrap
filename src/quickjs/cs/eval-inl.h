static
JSValue JS_EvalFunctionInternal(JSContext *ctx, JSValue fun_obj, JSValueConst this_obj,
                                JSVarRef **var_refs, JSStackFrame *sf) {
    JSValue ret_val;
    uint32_t tag = JS_VALUE_GET_TAG(fun_obj);
    if (tag == JS_TAG_FUNCTION_BYTECODE) {
        fun_obj = js_closure(ctx, fun_obj, var_refs, sf);
        ret_val = JS_CallFree(ctx, fun_obj, this_obj, 0, NULL);
    } else if (tag == JS_TAG_MODULE) {
        JSModuleDef *m;
        m = JS_VALUE_GET_PTR(fun_obj);
        /* the module refcount should be >= 2 */
        JS_FreeValue(ctx, fun_obj);
        if (js_create_module_function(ctx, m) < 0)
            goto fail;
        if (js_link_module(ctx, m) < 0)
            goto fail;
        ret_val = js_evaluate_module(ctx, m);
        if (JS_IsException(ret_val)) {
            fail:
            js_free_modules(ctx, JS_FREE_MODULE_NOT_EVALUATED);
            return JS_EXCEPTION;
        }
    } else {
        JS_FreeValue(ctx, fun_obj);
        ret_val = JS_ThrowTypeError(ctx, "bytecode function expected");
    }

    return ret_val;
}

JSValue JS_EvalFunction(JSContext *ctx, JSValue fun_obj) {
    return JS_EvalFunctionInternal(ctx, fun_obj, ctx->global_obj, NULL, NULL);
}

/* 'input' must be zero terminated i.e. input[input_len] = '\0'. */
static
JSValue cb_JS_EvalInternal(JSContext *ctx, JSValueConst this_obj, const char *input, size_t input_len,
                          const char *filename, int flags, int scope_idx) {
    JSParseState s1, *s = &s1;
    int err, js_mode, eval_type;
    JSValue fun_obj, ret_val;
    JSStackFrame *sf;
    JSVarRef **var_refs;
    JSFunctionBytecode *b;
    JSFunctionDef *fd;
    JSModuleDef *m;

    js_parse_init(ctx, s, input, input_len, filename);
    skip_shebang(s);

    eval_type = flags & JS_EVAL_TYPE_MASK;
    m = NULL;
    if (eval_type == JS_EVAL_TYPE_DIRECT) {
        JSObject *p;
        sf = ctx->rt->current_stack_frame;
        assert(sf != NULL);
        assert(JS_VALUE_GET_TAG(sf->cur_func) == JS_TAG_OBJECT);
        p = JS_VALUE_GET_OBJ(sf->cur_func);
        assert(js_class_has_bytecode(p->class_id));
        b = p->u.func.function_bytecode;
        var_refs = p->u.func.var_refs;
        js_mode = b->js_mode;
    } else {
        sf = NULL;
        b = NULL;
        var_refs = NULL;
        js_mode = 0;
        if (flags & JS_EVAL_FLAG_STRICT)
            js_mode |= JS_MODE_STRICT;
        if (flags & JS_EVAL_FLAG_STRIP)
            js_mode |= JS_MODE_STRIP;
        if (eval_type == JS_EVAL_TYPE_MODULE) {
            JSAtom module_name = JS_NewAtom(ctx, filename);
            if (module_name == JS_ATOM_NULL)
                return JS_EXCEPTION;
            m = js_new_module_def(ctx, module_name);
            if (!m)
                return JS_EXCEPTION;
            js_mode |= JS_MODE_STRICT;
        }
    }

    fd = js_new_function_def(ctx, NULL, TRUE, FALSE, filename, 1);
    if (!fd) goto fail1;
    s->cur_func = fd;
    fd->eval_type = eval_type;
    fd->has_this_binding = (eval_type != JS_EVAL_TYPE_DIRECT);
    fd->backtrace_barrier = ((flags & JS_EVAL_FLAG_BACKTRACE_BARRIER) != 0);
    if (eval_type == JS_EVAL_TYPE_DIRECT) {
        fd->new_target_allowed = b->new_target_allowed;
        fd->super_call_allowed = b->super_call_allowed;
        fd->super_allowed = b->super_allowed;
        fd->arguments_allowed = b->arguments_allowed;
    } else {
        fd->new_target_allowed = FALSE;
        fd->super_call_allowed = FALSE;
        fd->super_allowed = FALSE;
        fd->arguments_allowed = TRUE;
    }
    fd->js_mode = js_mode;
    fd->func_name = JS_DupAtom(ctx, JS_ATOM__eval_);
    if (b) {
        if (add_closure_variables(ctx, fd, b, scope_idx)) {
            goto fail;
        }
    }
    fd->module = m;
    s->is_module = (m != NULL);
    s->allow_html_comments = !s->is_module;

    push_scope(s); /* body scope */
    fd->body_scope = fd->scope_level;

    err = js_parse_program(s);
    if (err) {
fail:
        free_token(s, &s->token);
        js_free_function_def(ctx, fd);
        goto fail1;
    }

    /* create the function object and all the enclosed functions */
    fun_obj = js_create_function(ctx, fd);
    if (JS_IsException(fun_obj))
        goto fail1;
    /* Could add a flag to avoid resolution if necessary */
    if (m) {
        m->func_obj = fun_obj;
        if (js_resolve_module(ctx, m) < 0)
            goto fail1;
        fun_obj = JS_DupValue(ctx, JS_MKPTR(JS_TAG_MODULE, m));
    }
    if (flags & JS_EVAL_FLAG_COMPILE_ONLY) {
        ret_val = fun_obj;
    } else {
        ret_val = JS_EvalFunctionInternal(ctx, fun_obj, this_obj, var_refs, sf);
    }

    return ret_val;

fail1:
    /* XXX: should free all the unresolved dependencies */
    if (m) js_free_module_def(ctx, m);

    return JS_EXCEPTION;
}

void JS_AddIntrinsicEval(JSContext *ctx) {
    ctx->eval_internal = cb_JS_EvalInternal;
}

/* the indirection is needed to make 'eval' optional */
static
JSValue JS_EvalInternal(JSContext *ctx, JSValueConst this_obj, const char *input, size_t input_len,
                        const char *filename, int flags, int scope_idx) {
    if (unlikely(!ctx->eval_internal)) {
        return JS_ThrowTypeError(ctx, "eval is not supported");
    }

    return ctx->eval_internal(ctx, this_obj, input, input_len, filename, flags, scope_idx);
}

static
JSValue JS_EvalObject(JSContext *ctx, JSValueConst this_obj, JSValueConst val, int flags, int scope_idx) {
    if (!JS_IsString(val))
        return JS_DupValue(ctx, val);

    size_t len;
    const char *str = JS_ToCStringLen(ctx, &len, val);
    if (!str)
        return JS_EXCEPTION;
    JSValue ret = JS_EvalInternal(ctx, this_obj, str, len, "<input>", flags, scope_idx);
    JS_FreeCString(ctx, str);
    return ret;

}

JSValue JS_EvalThis(JSContext *ctx, JSValueConst this_obj, const char *input, size_t input_len,
                    const char *filename, int eval_flags) {

    DBG_EXPR(int eval_type = eval_flags & JS_EVAL_TYPE_MASK);

    assert((eval_type == JS_EVAL_TYPE_GLOBAL) || (eval_type == JS_EVAL_TYPE_MODULE));

    return JS_EvalInternal(ctx, this_obj, input, input_len, filename, eval_flags, -1);
}

JSValue JS_Eval(JSContext *ctx, const char *input, size_t input_len, const char *filename, int eval_flags) {
    return JS_EvalThis(ctx, ctx->global_obj, input, input_len, filename, eval_flags);
}
