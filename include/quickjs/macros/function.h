#pragma once

#define DEF_FUNC_TYPE(name, return_type, ...) \
    typedef return_type (*name)(__VA_ARGS__);
