JSDebuggerLocation js_debugger_current_location(JSContext *ctx, const uint8_t *cur_pc) {
    JSDebuggerLocation location = {.filename = 0};
    JSStackFrame *sf = ctx->rt->current_stack_frame;

    if (!sf)
        return location;

    JSObject *p = JS_VALUE_GET_OBJ(sf->cur_func);
    if (!p)
        return location;

    JSFunctionBytecode *b = p->u.func.function_bytecode;
    if (!b || !b->has_debug)
        return location;

    location.line = find_line_num(ctx, b, (cur_pc ? cur_pc : sf->cur_pc) - b->byte_code_buf - 1);
    location.filename = b->debug.filename;

    // quickjs has no column info.
    location.column = 0;
    return location;
}

JSDebuggerInfo *js_debugger_info(JSRuntime *rt) {
    return &(rt->debugger_info);
}

uint32_t js_debugger_stack_depth(JSContext *ctx) {
    uint32_t stack_index = 0;
    JSStackFrame *sf = ctx->rt->current_stack_frame;
    while (sf != NULL) {
        sf = sf->prev_frame;
        stack_index++;
    }
    return stack_index;
}

JSValue js_debugger_build_backtrace(JSContext *ctx, const uint8_t *cur_pc) {
    const char *func_name_str;
    JSValue ret = JS_NewArray(ctx);
    uint32_t stack_index = 0;

    for (JSStackFrame *sf = ctx->rt->current_stack_frame; sf != NULL; sf = sf->prev_frame) {
        JSValue current_frame = JS_NewObject(ctx);

        uint32_t id = stack_index++;
        JS_SetPropertyStr(ctx, current_frame, "id", JS_NewUint32(ctx, id));

        func_name_str = get_func_name(ctx, sf->cur_func);
        if (!func_name_str || func_name_str[0] == '\0')
            JS_SetPropertyStr(ctx, current_frame, "name", JS_NewString(ctx, "<anonymous>"));
        else
            JS_SetPropertyStr(ctx, current_frame, "name", JS_NewString(ctx, func_name_str));
        JS_FreeCString(ctx, func_name_str);

        JSObject *p = JS_VALUE_GET_OBJ(sf->cur_func);
        if (p && js_class_has_bytecode(p->class_id)) {
            JSFunctionBytecode *b;
            int line_num1;

            b = p->u.func.function_bytecode;
            if (b->has_debug) {
                const uint8_t *pc = sf != ctx->rt->current_stack_frame || !cur_pc ? sf->cur_pc : cur_pc;
                line_num1 = find_line_num(ctx, b, pc - b->byte_code_buf - 1);
                JS_SetPropertyStr(ctx, current_frame, "filename", JS_AtomToString(ctx, b->debug.filename));
                if (line_num1 != -1)
                    JS_SetPropertyStr(ctx, current_frame, "line", JS_NewUint32(ctx, line_num1));
            }
        } else {
            JS_SetPropertyStr(ctx, current_frame, "name", JS_NewString(ctx, "(native)"));
        }

        JS_SetPropertyUint32(ctx, ret, id, current_frame);
    }
    return ret;
}

int js_debugger_check_breakpoint(JSContext *ctx, uint32_t current_dirty, const uint8_t *cur_pc) {
    JSValue path_data = JS_UNDEFINED;
    if (!ctx->rt->current_stack_frame)
        return 0;
    JSObject *f = JS_VALUE_GET_OBJ(ctx->rt->current_stack_frame->cur_func);
    if (!f || !js_class_has_bytecode(f->class_id))
        return 0;
    JSFunctionBytecode *b = f->u.func.function_bytecode;
    if (!b->has_debug || !b->debug.filename)
        return 0;

    // check if up to date
    if (b->debugger.dirty == current_dirty)
        goto done;

    // note the dirty value and mark as up to date
    uint32_t dirty = b->debugger.dirty;
    b->debugger.dirty = current_dirty;

    const char *filename = JS_AtomToCString(ctx, b->debug.filename);
    path_data = js_debugger_file_breakpoints(ctx, filename);
    JS_FreeCString(ctx, filename);
    if (JS_IsUndefined(path_data))
        goto done;

    JSValue path_dirty_value = JS_GetPropertyStr(ctx, path_data, "dirty");
    uint32_t path_dirty;
    JS_ToUint32(ctx, &path_dirty, path_dirty_value);
    JS_FreeValue(ctx, path_dirty_value);
    // check the dirty value on this source file specifically
    if (path_dirty == dirty)
        goto done;

    // todo: bit field?
    // clear/alloc breakpoints
    if (!b->debugger.breakpoints)
        b->debugger.breakpoints = js_malloc_rt(ctx->rt, b->byte_code_len);
    memset(b->debugger.breakpoints, 0, b->byte_code_len);

    JSValue breakpoints = JS_GetPropertyStr(ctx, path_data, "breakpoints");

    JSValue breakpoints_length_property = JS_GetPropertyStr(ctx, breakpoints, "length");
    uint32_t breakpoints_length;
    JS_ToUint32(ctx, &breakpoints_length, breakpoints_length_property);
    JS_FreeValue(ctx, breakpoints_length_property);

    const uint8_t *p_end, *p;
    int new_line_num, line_num, pc, v, ret;
    unsigned int op;

    p = b->debug.pc2line_buf;
    p_end = p + b->debug.pc2line_len;
    pc = 0;
    line_num = b->debug.line_num;

    for (uint32_t i = 0; i < breakpoints_length; i++) {
        JSValue breakpoint = JS_GetPropertyUint32(ctx, breakpoints, i);
        JSValue breakpoint_line_prop = JS_GetPropertyStr(ctx, breakpoint, "line");
        uint32_t breakpoint_line;
        JS_ToUint32(ctx, &breakpoint_line, breakpoint_line_prop);
        JS_FreeValue(ctx, breakpoint_line_prop);
        JS_FreeValue(ctx, breakpoint);

        // breakpoint is before the current line.
        // todo: this may be an invalid breakpoint if it's inside the function, but got
        // skipped over.
        if (breakpoint_line < line_num)
            continue;
        // breakpoint is after function end. can stop, as breakpoints are in sorted order.
        if (b->debugger.last_line_num && breakpoint_line > b->debugger.last_line_num)
            break;

        int last_line_num = line_num;
        int line_pc = pc;

        // scan until we find the start pc for the breakpoint
        while (p < p_end && line_num <= breakpoint_line) {

            // scan line by line
            while (p < p_end && line_num == last_line_num) {
                op = *p++;
                if (op == 0) {
                    uint32_t val;
                    ret = get_leb128(&val, p, p_end);
                    if (ret < 0)
                        goto fail;
                    pc += val;
                    p += ret;
                    ret = get_sleb128(&v, p, p_end);
                    if (ret < 0)
                        goto fail;
                    p += ret;
                    new_line_num = line_num + v;
                } else {
                    op -= PC2LINE_OP_FIRST;
                    pc += (op / PC2LINE_RANGE);
                    new_line_num = line_num + (op % PC2LINE_RANGE) + PC2LINE_BASE;
                }
                line_num = new_line_num;
            }

            if (line_num != last_line_num) {
                // new line found, check if it is the one with breakpoint.
                if (last_line_num == breakpoint_line && line_num > last_line_num)
                    memset(b->debugger.breakpoints + line_pc, 1, pc - line_pc);

                // update the line trackers
                line_pc = pc;
                last_line_num = line_num;
            }
        }

        if (p >= p_end)
            b->debugger.last_line_num = line_num;
    }

fail:
    JS_FreeValue(ctx, breakpoints);

done:
    JS_FreeValue(ctx, path_data);

    if (!b->debugger.breakpoints)
        return 0;

    pc = (cur_pc ? cur_pc : ctx->rt->current_stack_frame->cur_pc) - b->byte_code_buf - 1;
    if (pc < 0 || pc > b->byte_code_len)
        return 0;
    return b->debugger.breakpoints[pc];
}

JSValue js_debugger_local_variables(JSContext *ctx, int stack_index) {
    JSValue ret = JS_NewObject(ctx);

    // put exceptions on the top stack frame
    if (stack_index == 0 && !JS_IsNull(ctx->rt->current_exception) && !JS_IsUndefined(ctx->rt->current_exception))
        JS_SetPropertyStr(ctx, ret, "<exception>", JS_DupValue(ctx, ctx->rt->current_exception));

    JSStackFrame *sf;
    int cur_index = 0;

    for(sf = ctx->rt->current_stack_frame; sf != NULL; sf = sf->prev_frame) {
        // this val is one frame up
        if (cur_index == stack_index - 1) {
            JSObject *f = JS_VALUE_GET_OBJ(sf->cur_func);
            if (f && js_class_has_bytecode(f->class_id)) {
                JSFunctionBytecode *b = f->u.func.function_bytecode;

                JSValue this_obj = sf->var_buf[b->var_count];
                // only provide a this if it is not the global object.
                if (JS_VALUE_GET_OBJ(this_obj) != JS_VALUE_GET_OBJ(ctx->global_obj))
                    JS_SetPropertyStr(ctx, ret, "this", JS_DupValue(ctx, this_obj));
            }
        }

        if (cur_index < stack_index) {
            cur_index++;
            continue;
        }

        JSObject *f = JS_VALUE_GET_OBJ(sf->cur_func);
        if (!f || !js_class_has_bytecode(f->class_id))
            goto done;
        JSFunctionBytecode *b = f->u.func.function_bytecode;

        for (uint32_t i = 0; i < b->arg_count + b->var_count; i++) {
            JSValue var_val;
            if (i < b->arg_count)
                var_val = sf->arg_buf[i];
            else
                var_val = sf->var_buf[i - b->arg_count];

            if (JS_IsUninitialized(var_val))
                continue;

            JSVarDef *vd = b->vardefs + i;
            JS_SetProperty(ctx, ret, vd->var_name, JS_DupValue(ctx, var_val));
        }

        break;
    }

    done:
    return ret;
}

JSValue js_debugger_closure_variables(JSContext *ctx, int stack_index) {
    JSValue ret = JS_NewObject(ctx);

    JSStackFrame *sf;
    int cur_index = 0;
    for(sf = ctx->rt->current_stack_frame; sf != NULL; sf = sf->prev_frame) {
        if (cur_index < stack_index) {
            cur_index++;
            continue;
        }

        JSObject *f = JS_VALUE_GET_OBJ(sf->cur_func);
        if (!f || !js_class_has_bytecode(f->class_id))
            goto done;

        JSFunctionBytecode *b = f->u.func.function_bytecode;

        for (uint32_t i = 0; i < b->closure_var_count; i++) {
            JSClosureVar *cvar = b->closure_var + i;
            JSValue var_val;
            JSVarRef *var_ref = NULL;
            if (f->u.func.var_refs)
                var_ref = f->u.func.var_refs[i];
            if (!var_ref || !var_ref->pvalue)
                continue;
            var_val = *var_ref->pvalue;

            if (JS_IsUninitialized(var_val))
                continue;

            JS_SetProperty(ctx, ret, cvar->var_name, JS_DupValue(ctx, var_val));
        }

        break;
    }

    done:
    return ret;
}

/* debugger needs ability to eval at any stack frame */
static
JSValue js_debugger_eval(JSContext *ctx, JSValueConst this_obj, JSStackFrame *sf,
                         const char *input, size_t input_len, const char *filename, int flags, int scope_idx)
{
    JSParseState s1, *s = &s1;
    int err, js_mode;
    JSValue fun_obj, ret_val;
    JSVarRef **var_refs;
    JSFunctionBytecode *b;
    JSFunctionDef *fd;

    js_parse_init(ctx, s, input, input_len, filename);
    skip_shebang(s);

    JSObject *p;
    assert(sf != NULL);
    assert(JS_VALUE_GET_TAG(sf->cur_func) == JS_TAG_OBJECT);
    p = JS_VALUE_GET_OBJ(sf->cur_func);
    assert(js_class_has_bytecode(p->class_id));
    b = p->u.func.function_bytecode;
    var_refs = p->u.func.var_refs;
    js_mode = b->js_mode;

    fd = js_new_function_def(ctx, NULL, TRUE, FALSE, filename, 1);
    if (!fd)
        goto fail1;
    s->cur_func = fd;
    fd->eval_type = JS_EVAL_TYPE_DIRECT;
    fd->has_this_binding = 0;
    fd->new_target_allowed = b->new_target_allowed;
    fd->super_call_allowed = b->super_call_allowed;
    fd->super_allowed = b->super_allowed;
    fd->arguments_allowed = b->arguments_allowed;
    fd->js_mode = js_mode;
    fd->func_name = JS_DupAtom(ctx, JS_ATOM__eval_);
    if (b) {
        int idx;
        if (!b->var_count)
            idx = -1;
        else
            // use DEBUG_SCOP_INDEX to add all lexical variables to debug eval closure.
            idx = DEBUG_SCOP_INDEX;
        if (add_closure_variables(ctx, fd, b, idx))
            goto fail;
    }
    fd->module = NULL;
    s->is_module = 0;
    s->allow_html_comments = !s->is_module;

    push_scope(s); /* body scope */

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
    if (flags & JS_EVAL_FLAG_COMPILE_ONLY) {
        ret_val = fun_obj;
    } else {
        ret_val = JS_EvalFunctionInternal(ctx, fun_obj, this_obj, var_refs, sf);
    }
    return ret_val;
    fail1:
    return JS_EXCEPTION;
}

JSValue js_debugger_evaluate(JSContext *ctx, int stack_index, JSValue expression) {
    JSStackFrame *sf;
    int cur_index = 0;

    for(sf = ctx->rt->current_stack_frame; sf != NULL; sf = sf->prev_frame) {
        if (cur_index < stack_index) {
            cur_index++;
            continue;
        }

        JSObject *f = JS_VALUE_GET_OBJ(sf->cur_func);
        if (!f || !js_class_has_bytecode(f->class_id))
            return JS_UNDEFINED;
        JSFunctionBytecode *b = f->u.func.function_bytecode;

        int scope_idx = b->vardefs ? 0 : -1;
        size_t len;
        const char* str = JS_ToCStringLen(ctx, &len, expression);
        JSValue ret = js_debugger_eval(ctx, sf->var_buf[b->var_count], sf, str, len, "<debugger>", JS_EVAL_TYPE_DIRECT, scope_idx);
        JS_FreeCString(ctx, str);
        return ret;
    }
    return JS_UNDEFINED;
}
