#if defined(CT_NAME) && defined(CT_TYPE)

#if !defined(CT_DEFINED)

#define CT_DEFINED

#define GLUE(x,y)  x##_##y
#define EVAL(x,y)  GLUE(x,y)

#define REF_METHOD(method) EVAL(CT_NAME, method)

#define REF_STATIC_METHOD(method) REF_METHOD(method)

#define DECL_METHOD(method, return_type, ...) \
    static return_type REF_METHOD(method)(CT_TYPE self, ##__VA_ARGS__);

#define DECL_STATIC_METHOD(method, return_type, ...) \
    static return_type REF_METHOD(method)(__VA_ARGS__);

#define DEF_METHOD(method, return_type, ...) \
    return_type (*method)(CT_TYPE self, ##__VA_ARGS__);

#define DEF_STATIC_METHOD(method, return_type, ...) \
    return_type (*method)(__VA_ARGS__);

#define IMPL_METHOD(method, return_type, ...) \
    static return_type REF_METHOD(method)(CT_TYPE self, ##__VA_ARGS__)

#define IMPL_STATIC_METHOD(method, return_type, ...) \
    static return_type REF_METHOD(method)(__VA_ARGS__)


#else /* !defined(CT_DEFINED) */

// Undef all (on second include)

#undef CT_DEFINED

#undef GLUE
#undef EVAL

#undef REF_METHOD
#undef REF_STATIC_METHOD
#undef DECL_METHOD
#undef DECL_STATIC_METHOD
#undef DEF_METHOD
#undef DEF_STATIC_METHOD
#undef IMPL_METHOD
#undef IMPL_STATIC_METHOD

#undef CT_NAME
#undef CT_TYPE

#endif /* !defined(CT_DEFINED) */

#endif /* defined(CT_NAME) && defined(CT_TYPE) */


