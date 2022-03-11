#pragma once

#if !defined(CONFIG_VERSION)
#define CONFIG_VERSION "0.0.0"
#endif

#ifdef NDEBUG
#define DBG_EXPR(expr)
#else /* !defined (NDEBUG) */
#define DBG_EXPR(expr) expr
#endif
