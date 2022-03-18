#pragma once

#define DECL_STRUCT(name) \
    typedef struct name name; struct name

#define DECL_UNION(name) \
    typedef union name name; union name

#define DECL_ENUM(name) \
    typedef enum name name; enum name
