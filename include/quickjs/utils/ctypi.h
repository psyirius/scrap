/* A cpp like namespaced functions interface */
#pragma once

#include <stdint.h>

#define REF_METHOD(type_name, method) \
    type_name##_##method

#define DECL_METHOD(type_name, type, method, return_type, ...) \
    static return_type REF_METHOD(type_name, method)(type self, ##__VA_ARGS__);

#define DECL_METHOD_STATIC(type_name, method, return_type, ...) \
    static return_type REF_METHOD(type_name, method)(__VA_ARGS__);

#define IMPL_METHOD(type_name, type, method, return_type, ...) \
    static return_type REF_METHOD(type_name, method)(type self, ##__VA_ARGS__)

#define IMPL_METHOD_STATIC(type_name, method, return_type, ...) \
    static return_type REF_METHOD(type_name, method)(__VA_ARGS__)

#define DEF_METHOD(type_name, type, method, return_type, ...) \
    return_type (*method)(type self, ##__VA_ARGS__);

#define DEF_METHOD_STATIC(type_name, method, return_type, ...) \
    return_type (*method)(__VA_ARGS__);

