static const JSCFunctionListEntry js_generator_function_proto_funcs[] = {
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "GeneratorFunction", JS_PROP_CONFIGURABLE),
};

static const JSCFunctionListEntry js_generator_proto_funcs[] = {
    JS_ITERATOR_NEXT_DEF("next", 1, js_generator_next, GEN_MAGIC_NEXT),
    JS_ITERATOR_NEXT_DEF("return", 1, js_generator_next, GEN_MAGIC_RETURN),
    JS_ITERATOR_NEXT_DEF("throw", 1, js_generator_next, GEN_MAGIC_THROW),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Generator", JS_PROP_CONFIGURABLE),
};
