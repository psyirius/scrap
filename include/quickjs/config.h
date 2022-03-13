#pragma once

#if !defined(CONFIG_VERSION)
#define CONFIG_VERSION "0.0.0"
#endif

#ifdef NDEBUG
#define DBG_EXPR(expr)
#else /* !defined (NDEBUG) */
#define DBG_EXPR(expr) expr
#endif

#if defined(_WIN32) && !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0600
#endif
