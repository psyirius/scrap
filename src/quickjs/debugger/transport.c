#include "quickjs/debugger/debugger.h"

typedef struct {
    int handle;
} JS_DebuggerTransportData;

#ifdef _WIN32
#include "./transport-win-inl.h"
#else
#include "./transport-unix-inl.h"
#endif
