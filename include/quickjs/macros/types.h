#pragma once

#include <stdint.h>
#include <stdbool.h>

#if !defined(nullptr)
#define nullptr  ((void *)0)
#endif

#if !defined(bool)
typedef unsigned char bool;
#endif

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