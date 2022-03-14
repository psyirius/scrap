#if !defined(_WIN32) && defined(CONFIG_DEBUGGER)

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <poll.h>
#include <arpa/inet.h>

static size_t js_transport_read(void *udata, char *buffer, size_t length) {
    JS_DebuggerTransportData* data = (JS_DebuggerTransportData *)udata;
    if (data->handle <= 0)
        return -1;

    if (length == 0)
        return -2;

    if (buffer == NULL)
        return -3;

    ssize_t ret = read(data->handle, (void *)buffer, length);
    if (ret < 0)
        return -4;

    if (ret == 0)
        return -5;

    if (ret > length)
        return -6;

    return ret;
}

static size_t js_transport_write(void *udata, const char *buffer, size_t length) {
    JS_DebuggerTransportData* data = (JS_DebuggerTransportData *)udata;
    if (data->handle <= 0)
        return -1;

    if (length == 0)
        return -2;

    if (buffer == NULL)
        return -3;

    size_t ret = write(data->handle, (const void *) buffer, length);
    if (ret <= 0 || ret > (ssize_t) length)
        return -4;

    return ret;
}

static size_t js_transport_peek(void *udata) {
    struct pollfd fds[1];
    int poll_rc;

    JS_DebuggerTransportData* data = (JS_DebuggerTransportData *)udata;
    if (data->handle <= 0)
        return -1;

    fds[0].fd = data->handle;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    poll_rc = poll(fds, 1, 0);
    if (poll_rc < 0)
        return -2;
    if (poll_rc > 1)
        return -3;
    // no data
    if (poll_rc == 0)
        return 0;
    // has data
    return 1;
}

static void js_transport_close(JSRuntime* rt, void *udata) {
    JS_DebuggerTransportData* data = (JS_DebuggerTransportData *)udata;
    if (data->handle <= 0)
        return;
    close(data->handle);
    data->handle = 0;
    free(udata);
}

static
long str_to_int(char* str, int base) {
    char *end_ptr = 0;
    return strtol(str, &end_ptr, base);
}

// todo: fixup asserts to return errors.
static struct sockaddr_in js_debugger_parse_sockaddr(const char* address) {
    char* port_string = strstr(address, ":");
    assert(port_string);

    int port = str_to_int(port_string + 1, 10);
    assert(port);

    char host_string[256];
    strcpy(host_string, address);
    host_string[port_string - address] = 0;

    struct hostent *host = gethostbyname(host_string);
    assert(host);
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy((char *)&addr.sin_addr.s_addr, (char *)host->h_addr, host->h_length);
    addr.sin_port = htons(port);

    return addr;
}

void js_debugger_connect(JSContext *ctx, const char *address) {
    struct sockaddr_in addr = js_debugger_parse_sockaddr(address);

    int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client > 0);

    assert(connect(client, (const struct sockaddr *)&addr, sizeof(addr)) == 0);

    JS_DebuggerTransportData *data = (JS_DebuggerTransportData *)malloc(sizeof(JS_DebuggerTransportData));
    memset(data, 0, sizeof(js_transport_data));
    data->handle = client;
    js_debugger_attach(ctx, js_transport_read, js_transport_write, js_transport_peek, js_transport_close, data);
}

void js_debugger_wait_connection(JSContext *ctx, const char* address) {
    struct sockaddr_in addr = js_debugger_parse_sockaddr(address);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    assert(server >= 0);

    int reuseAddress = 1;
    assert(setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuseAddress, sizeof(reuseAddress)) >= 0);

    assert(bind(server, (struct sockaddr *) &addr, sizeof(addr)) >= 0);

    listen(server, 1);

    struct sockaddr_in client_addr;
    socklen_t client_addr_size = (socklen_t) sizeof(addr);
    int client = accept(server, (struct sockaddr *) &client_addr, &client_addr_size);
    close(server);
    assert(client >= 0);

    JS_DebuggerTransportData *data = (JS_DebuggerTransportData *)malloc(sizeof(JS_DebuggerTransportData));
    memset(data, 0, sizeof(js_transport_data));
    data->handle = client;
    js_debugger_attach(ctx, js_transport_read, js_transport_write, js_transport_peek, js_transport_close, data);
}

#endif /* defined(CONFIG_DEBUGGER) */
