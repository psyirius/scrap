#ifdef CONFIG_BIGNUM

/* Operators */
static void js_operator_set_finalizer(JSRuntime *rt, JSValue val) {
    JSOperatorSetData *opset = JS_GetOpaque(val, JS_CLASS_OPERATOR_SET);

    if (opset) {
        for (int i = 0; i < JS_OVOP_COUNT; i++) {
            if (opset->self_ops[i])
                JS_FreeValueRT(rt, JS_MKPTR(JS_TAG_OBJECT, opset->self_ops[i]));
        }

        for (int j = 0; j < opset->left.count; j++) {
            JSBinaryOperatorDefEntry *ent = &opset->left.tab[j];
            for (int i = 0; i < JS_OVOP_BINARY_COUNT; i++) {
                if (ent->ops[i])
                    JS_FreeValueRT(rt, JS_MKPTR(JS_TAG_OBJECT, ent->ops[i]));
            }
        }
        js_free_rt(rt, opset->left.tab);
        for (int j = 0; j < opset->right.count; j++) {
            JSBinaryOperatorDefEntry *ent = &opset->right.tab[j];
            for (int i = 0; i < JS_OVOP_BINARY_COUNT; i++) {
                if (ent->ops[i])
                    JS_FreeValueRT(rt, JS_MKPTR(JS_TAG_OBJECT, ent->ops[i]));
            }
        }
        js_free_rt(rt, opset->right.tab);
        js_free_rt(rt, opset);
    }
}

static void js_operator_set_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    JSOperatorSetData *opset = JS_GetOpaque(val, JS_CLASS_OPERATOR_SET);
    int i, j;
    JSBinaryOperatorDefEntry *ent;

    if (opset) {
        for (i = 0; i < JS_OVOP_COUNT; i++) {
            if (opset->self_ops[i])
                JS_MarkValue(rt, JS_MKPTR(JS_TAG_OBJECT, opset->self_ops[i]),
                             mark_func);
        }
        for (j = 0; j < opset->left.count; j++) {
            ent = &opset->left.tab[j];
            for (i = 0; i < JS_OVOP_BINARY_COUNT; i++) {
                if (ent->ops[i])
                    JS_MarkValue(rt, JS_MKPTR(JS_TAG_OBJECT, ent->ops[i]),
                                 mark_func);
            }
        }
        for (j = 0; j < opset->right.count; j++) {
            ent = &opset->right.tab[j];
            for (i = 0; i < JS_OVOP_BINARY_COUNT; i++) {
                if (ent->ops[i])
                    JS_MarkValue(rt, JS_MKPTR(JS_TAG_OBJECT, ent->ops[i]),
                                 mark_func);
            }
        }
    }
}


/* create an OperatorSet object */
static JSValue js_operators_create_internal(JSContext *ctx, int argc, JSValueConst *argv, BOOL is_primitive) {
    JSValue opset_obj, prop, obj;
    JSOperatorSetData *opset, *opset1;
    JSBinaryOperatorDef *def;
    JSValueConst arg;
    int i, j;
    JSBinaryOperatorDefEntry *new_tab;
    JSBinaryOperatorDefEntry *ent;
    uint32_t op_count;

    if (ctx->rt->operator_count == UINT32_MAX) {
        return JS_ThrowTypeError(ctx, "too many operators");
    }
    opset_obj = JS_NewObjectProtoClass(ctx, JS_NULL, JS_CLASS_OPERATOR_SET);
    if (JS_IsException(opset_obj))
        goto fail;
    opset = js_mallocz(ctx, sizeof(*opset));
    if (!opset)
        goto fail;
    JS_SetOpaque(opset_obj, opset);
    if (argc >= 1) {
        arg = argv[0];
        /* self operators */
        for (i = 0; i < JS_OVOP_COUNT; i++) {
            prop = JS_GetPropertyStr(ctx, arg, js_overloadable_operator_names[i]);
            if (JS_IsException(prop))
                goto fail;
            if (!JS_IsUndefined(prop)) {
                if (check_function(ctx, prop)) {
                    JS_FreeValue(ctx, prop);
                    goto fail;
                }
                opset->self_ops[i] = JS_VALUE_GET_OBJ(prop);
            }
        }
    }
    /* left & right operators */
    for (j = 1; j < argc; j++) {
        arg = argv[j];
        prop = JS_GetPropertyStr(ctx, arg, "left");
        if (JS_IsException(prop))
            goto fail;
        def = &opset->right;
        if (JS_IsUndefined(prop)) {
            prop = JS_GetPropertyStr(ctx, arg, "right");
            if (JS_IsException(prop))
                goto fail;
            if (JS_IsUndefined(prop)) {
                JS_ThrowTypeError(ctx, "left or right property must be present");
                goto fail;
            }
            def = &opset->left;
        }
        /* get the operator set */
        obj = JS_GetProperty(ctx, prop, JS_ATOM_prototype);
        JS_FreeValue(ctx, prop);
        if (JS_IsException(obj))
            goto fail;
        prop = JS_GetProperty(ctx, obj, JS_ATOM_Symbol_operatorSet);
        JS_FreeValue(ctx, obj);
        if (JS_IsException(prop))
            goto fail;
        opset1 = JS_GetOpaque2(ctx, prop, JS_CLASS_OPERATOR_SET);
        if (!opset1) {
            JS_FreeValue(ctx, prop);
            goto fail;
        }
        op_count = opset1->operator_counter;
        JS_FreeValue(ctx, prop);

        /* we assume there are few entries */
        new_tab = js_realloc(ctx, def->tab,
                             (def->count + 1) * sizeof(def->tab[0]));
        if (!new_tab)
            goto fail;
        def->tab = new_tab;
        def->count++;
        ent = def->tab + def->count - 1;
        memset(ent, 0, sizeof(def->tab[0]));
        ent->operator_index = op_count;

        for (i = 0; i < JS_OVOP_BINARY_COUNT; i++) {
            prop = JS_GetPropertyStr(ctx, arg,
                                     js_overloadable_operator_names[i]);
            if (JS_IsException(prop))
                goto fail;
            if (!JS_IsUndefined(prop)) {
                if (check_function(ctx, prop)) {
                    JS_FreeValue(ctx, prop);
                    goto fail;
                }
                ent->ops[i] = JS_VALUE_GET_OBJ(prop);
            }
        }
    }
    opset->is_primitive = is_primitive;
    opset->operator_counter = ctx->rt->operator_count++;
    return opset_obj;
    fail:
    JS_FreeValue(ctx, opset_obj);
    return JS_EXCEPTION;
}

static JSValue js_operators_create(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    return js_operators_create_internal(ctx, argc, argv, FALSE);
}

static JSValue js_operators_updateBigIntOperators(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue opset_obj, prop;
    JSOperatorSetData *opset;
    const JSOverloadableOperatorEnum ops[2] = {JS_OVOP_DIV, JS_OVOP_POW};
    JSOverloadableOperatorEnum op;
    int i;

    opset_obj = JS_GetProperty(ctx, ctx->class_proto[JS_CLASS_BIG_INT],
                               JS_ATOM_Symbol_operatorSet);
    if (JS_IsException(opset_obj))
        goto fail;
    opset = JS_GetOpaque2(ctx, opset_obj, JS_CLASS_OPERATOR_SET);
    if (!opset)
        goto fail;
    for (i = 0; i < countof(ops); i++) {
        op = ops[i];
        prop = JS_GetPropertyStr(ctx, argv[0],
                                 js_overloadable_operator_names[op]);
        if (JS_IsException(prop))
            goto fail;
        if (!JS_IsUndefined(prop)) {
            if (!JS_IsNull(prop) && check_function(ctx, prop)) {
                JS_FreeValue(ctx, prop);
                goto fail;
            }
            if (opset->self_ops[op])
                JS_FreeValue(ctx, JS_MKPTR(JS_TAG_OBJECT, opset->self_ops[op]));
            if (JS_IsNull(prop)) {
                opset->self_ops[op] = NULL;
            } else {
                opset->self_ops[op] = JS_VALUE_GET_PTR(prop);
            }
        }
    }
    JS_FreeValue(ctx, opset_obj);
    return JS_UNDEFINED;
    fail:
    JS_FreeValue(ctx, opset_obj);
    return JS_EXCEPTION;
}

static int js_operators_set_default(JSContext *ctx, JSValueConst obj) {
    JSValue opset_obj;

    if (!JS_IsObject(obj)) /* in case the prototype is not defined */
        return 0;
    opset_obj = js_operators_create_internal(ctx, 0, NULL, TRUE);
    if (JS_IsException(opset_obj))
        return -1;
    /* cannot be modified by the user */
    JS_DefinePropertyValue(ctx, obj, JS_ATOM_Symbol_operatorSet,
                           opset_obj, 0);
    return 0;
}

static JSValue js_dummy_operators_ctor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    return js_create_from_ctor(ctx, new_target, JS_CLASS_OBJECT);
}

static JSValue js_global_operators(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue func_obj, proto, opset_obj;

    func_obj = JS_UNDEFINED;
    proto = JS_NewObject(ctx);
    if (JS_IsException(proto))
        return JS_EXCEPTION;
    opset_obj = js_operators_create_internal(ctx, argc, argv, FALSE);
    if (JS_IsException(opset_obj))
        goto fail;
    JS_DefinePropertyValue(ctx, proto, JS_ATOM_Symbol_operatorSet,
                           opset_obj, JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    func_obj = JS_NewCFunction2(ctx, js_dummy_operators_ctor, "Operators",
                                0, JS_CFUNC_constructor, 0);
    if (JS_IsException(func_obj))
        goto fail;
    JS_SetConstructor2(ctx, func_obj, proto,
                       0, JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_FreeValue(ctx, proto);
    return func_obj;
    fail:
    JS_FreeValue(ctx, proto);
    JS_FreeValue(ctx, func_obj);
    return JS_EXCEPTION;
}

static
const JSCFunctionListEntry js_operators_funcs[] = {
    JS_CFUNC_DEF("create", 1, js_operators_create),
    JS_CFUNC_DEF("updateBigIntOperators", 2, js_operators_updateBigIntOperators),
};

/* must be called after all overload-able base types are initialized */
void JS_AddIntrinsicOperators(JSContext *ctx) {
    JSValue obj;

    ctx->allow_operator_overloading = TRUE;
    obj = JS_NewCFunction(ctx, js_global_operators, "Operators", 1);
    JS_SetPropertyFunctionList(ctx, obj, js_operators_funcs, countof(js_operators_funcs));
    JS_DefinePropertyValue(ctx, ctx->global_obj, JS_ATOM_Operators, obj, JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    /* add default operatorSets */
    js_operators_set_default(ctx, ctx->class_proto[JS_CLASS_BOOLEAN]);
    js_operators_set_default(ctx, ctx->class_proto[JS_CLASS_NUMBER]);
    js_operators_set_default(ctx, ctx->class_proto[JS_CLASS_STRING]);
    js_operators_set_default(ctx, ctx->class_proto[JS_CLASS_BIG_INT]);
    js_operators_set_default(ctx, ctx->class_proto[JS_CLASS_BIG_FLOAT]);
    js_operators_set_default(ctx, ctx->class_proto[JS_CLASS_BIG_DECIMAL]);
}

#endif /* CONFIG_BIGNUM */
