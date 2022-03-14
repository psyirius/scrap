#ifdef CONFIG_DEBUGGER

#ifdef __MSYS__
#define __INSIDE_CYGWIN_NET__ 1
#endif

#include "quickjs/debugger/debugger.h"

#include <winsock2.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef struct {
  int handle;
} JS_DebuggerTransportData;

static
size_t js_transport_read(void* udata, char* buffer, size_t length) {
    JS_DebuggerTransportData* data = (JS_DebuggerTransportData*) udata;
    if(data->handle <= 0)
        return -1;

    if(length == 0)
        return -2;

    if(buffer == NULL)
        return -3;

    ssize_t ret = recv(data->handle, (void*)buffer, (int)length, 0);
    if(ret < 0)
        return -4;

    if(ret == 0)
        return -5;

    if(ret > length)
        return -6;

    return ret;
}

static
size_t js_transport_write(void* udata, const char* buffer, size_t length) {
  JS_DebuggerTransportData* data = (JS_DebuggerTransportData*)udata;
  if(data->handle <= 0)
    return -1;

  if(length == 0)
    return -2;

  if(buffer == NULL)
    return -3;

  size_t ret = send(data->handle, (const void*)buffer, (int)length, 0);
  if(ret <= 0 || ret > (ssize_t)length)
    return -4;

  return ret;
}

static
size_t js_transport_peek(void* udata) {
  fd_set fds;

  int select_rc;

  JS_DebuggerTransportData* data = (JS_DebuggerTransportData*)udata;
  if(data->handle <= 0)
    return -1;

  FD_ZERO(&fds);
  FD_SET(data->handle, &fds);

  select_rc = select(data->handle + 1, &fds, NULL, NULL, 0);
  if(select_rc < 0)
    return -2;
  if(select_rc > 1)
    return -3;
  // no data
  if(select_rc == 0)
    return 0;
  // has data
  return 1;
}

static
void js_transport_close(JSRuntime* rt, void* udata) {
  JS_DebuggerTransportData* data = (JS_DebuggerTransportData*)udata;
  if(data->handle <= 0)
    return;
  closesocket(data->handle);
  data->handle = 0;
  free(udata);
}

// todo: fixup asserts to return errors.
static
struct sockaddr_in js_debugger_parse_sockaddr(const char* address) {
  char* port_string = strstr(address, ":");
  assert(port_string);

  int port = atoi(port_string + 1);
  assert(port);

  char host_string[256];
  strcpy(host_string, address);
  host_string[port_string - address] = 0;

  struct hostent* host = gethostbyname(host_string);
  assert(host);
  struct sockaddr_in addr;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  memcpy((char*)&addr.sin_addr.s_addr, (char*)host->h_addr, host->h_length);
  addr.sin_port = htons(port);

  return addr;
}

void js_debugger_connect(JSContext* ctx, const char* address) {
  struct sockaddr_in addr = js_debugger_parse_sockaddr(address);

  int client = socket(AF_INET, SOCK_STREAM, 0);
  assert(client > 0);

  assert(!connect(client, (const struct sockaddr*)&addr, sizeof(addr)));

  JS_DebuggerTransportData* data = (JS_DebuggerTransportData*) malloc(sizeof(JS_DebuggerTransportData));
  memset(data, 0, sizeof(JS_DebuggerTransportData));
  data->handle = client;
  js_debugger_attach(ctx, js_transport_read, js_transport_write, js_transport_peek, js_transport_close, data);
}

void
js_debugger_wait_connection(JSContext* ctx, const char* address) {
  struct sockaddr_in addr = js_debugger_parse_sockaddr(address);

  int server = socket(AF_INET, SOCK_STREAM, 0);
  assert(server >= 0);

  int reuseAddress = 1;
  assert(setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuseAddress, sizeof(reuseAddress)) >= 0);

  assert(bind(server, (struct sockaddr*)&addr, sizeof(addr)) >= 0);

  listen(server, 1);

  struct sockaddr_in client_addr;
  int client_addr_size = sizeof(addr);
  int client = accept(server, (struct sockaddr*)&client_addr, &client_addr_size);
  closesocket(server);
  assert(client >= 0);

  JS_DebuggerTransportData* data = (JS_DebuggerTransportData*)malloc(sizeof(JS_DebuggerTransportData));
  memset(data, 0, sizeof(JS_DebuggerTransportData));
  data->handle = client;
  js_debugger_attach(ctx, js_transport_read, js_transport_write, js_transport_peek, js_transport_close, data);
}

#endif /* defined(CONFIG_DEBUGGER) */
