#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if !defined(nullptr)
#define nullptr  ((void *)0)
#endif

#if !defined(bool)
typedef unsigned char bool;
#endif

typedef float       float32_t;
typedef double      float64_t;

#ifndef YES
#define YES  1
#endif

#ifndef NO
#define NO   0
#endif

#ifndef true
#define true  1
#endif

#ifndef false
#define false 0
#endif

#define cast_as(value, type) ((type*) &self)[0]
