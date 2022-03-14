#ifdef CONFIG_DEBUGGER

#include "quickjs/debugger/debugger.h"

#include <winsock2.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static
size_t js_transport_read(void* udata, char* buffer, size_t length) {
    JS_DebuggerTransportData* data = (JS_DebuggerTransportData*) udata;

    if (data->handle <= 0)
        return -1;

    if (length == 0)
        return -2;

    if (buffer == NULL)
        return -3;

    ssize_t ret = recv(data->handle, (void*)buffer, (int)length, 0);

    if (ret < 0)
        return -4;

    if (ret == 0)
        return -5;

    if (ret > length)
        return -6;

    return ret;
}

static
size_t js_transport_write(void* udata, const char* buffer, size_t length) {
    JS_DebuggerTransportData* data = (JS_DebuggerTransportData*)udata;

    if (data->handle <= 0)
        return -1;

    if (length == 0)
        return -2;

    if (buffer == 0)
        return -3;

    size_t ret = send(data->handle, (const void*)buffer, (int)length, 0);

    if (ret <= 0 || ret > (ssize_t)length)
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
  if (select_rc < 0)
    return -2;
  if (select_rc > 1)
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

static
long str_to_int(char* str, int base) {
    char *end_ptr = 0;
    return strtol(str, &end_ptr, base);
}

static
int win_sock_init() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(1, 1), &wsaData);
}

// TODO: fixup asserts to return errors.
static
struct sockaddr_in js_debugger_parse_sockaddr(const char* address) {
    // you really shouldn't be calling WSAStartup() here.
    // Call it at app startup instead...
    int err = win_sock_init();

    if (err != 0) {
        fprintf(stderr, "Error %d in win_sock_init\n", err);
        fflush(stderr);
        exit(100);
    }

    char* port_string = strstr(address, ":");
    assert(port_string);

    int port = str_to_int(port_string + 1, 10);
    assert(port);

    char host_string[256];
    strcpy(host_string, address);
    host_string[port_string - address] = 0;

    struct hostent* host = gethostbyname(host_string);
    assert(host != 0);
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy((char*)&addr.sin_addr.s_addr, (char*)host->h_addr, host->h_length);
    addr.sin_port = htons(port);

    return addr;
}

static
void close_sock(SOCKET *sock) {
    // preserve current error code
    int err = WSAGetLastError();
    closesocket(*sock);
    *sock = INVALID_SOCKET;
    WSASetLastError(err);
}

void js_debugger_connect(JSContext* ctx, const char* address) {
  struct sockaddr_in addr = js_debugger_parse_sockaddr(address);

  SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

  assert(client != INVALID_SOCKET);

  int cer = connect(client, (const struct sockaddr*)&addr, sizeof(addr));

  assert(cer == 0);

  if (cer == SOCKET_ERROR) {
    // connection failed
    close_sock(&client);
    return;
  }

  JS_DebuggerTransportData* data = (JS_DebuggerTransportData*) malloc(sizeof(JS_DebuggerTransportData));
  memset(data, 0, sizeof(JS_DebuggerTransportData));
  data->handle = (int) client;
  js_debugger_attach(ctx, js_transport_read, js_transport_write, js_transport_peek, js_transport_close, data);
}

void js_debugger_wait_connection(JSContext* ctx, const char* address) {
  struct sockaddr_in addr = js_debugger_parse_sockaddr(address);

  SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  assert(server >= 0);

  int reuseAddress = 1;
  assert(setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuseAddress, sizeof(reuseAddress)) >= 0);

  assert(bind(server, (struct sockaddr*)&addr, sizeof(addr)) >= 0);

  listen(server, 1);

  struct sockaddr_in client_addr;
  int client_addr_size = sizeof(addr);
  SOCKET client = accept(server, (struct sockaddr*)&client_addr, &client_addr_size);
  closesocket(server);
  assert(client >= 0);

  JS_DebuggerTransportData* data = (JS_DebuggerTransportData*)malloc(sizeof(JS_DebuggerTransportData));
  memset(data, 0, sizeof(JS_DebuggerTransportData));
  data->handle = (int) client;
  js_debugger_attach(ctx, js_transport_read, js_transport_write, js_transport_peek, js_transport_close, data);
}

#endif /* defined(CONFIG_DEBUGGER) */
