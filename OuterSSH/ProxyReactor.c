#include "platform/OTSocket.h"
#include "SSHProxyErrorInternal.h"
#include "ProxyReactor.h"
#include "ProxyReactorInternal.h"
#include "SSHProxyAddress.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include "platform/SecureRandom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void listener_socket_readable(void *opaque_context);
static OuterSSHError open_listener_socket(ProxyReactor *reactor, ProxyReactorListenerHandle handle,
    ListenerSlot *listener, int preferred_port, int *bound_port);
static bool reserve_listener_slots(
    ProxyReactor *reactor,
    size_t minimum_capacity);
static void remove_listener(ProxyReactor *reactor, size_t index);
static void destroy_reactor_on_queue(void *opaque_context);
static void invalidate_on_queue(ProxyReactor *reactor);
static ProxyConnectionRoute tcp_connection_route(
    ProxyConnectRequest request,
    const char *host,
    size_t host_length,
    uint16_t port);
static ProxyConnectionRoute unix_socket_connection_route(
    ProxyConnectRequest request,
    const char *path,
    size_t path_length);
static ProxyConnectionRoute rejected_connection_route(
    ProxyConnectRequest request);
static bool proxy_host_is_synthetic(const char *host, size_t host_length);
static bool host_ends_in_number(const char *host, size_t host_length);
static bool parse_ipv4(const char *text, size_t length, unsigned char address[4]);
static bool host_is_loopback(const char *host, size_t host_length);
static bool has_suffix(const char *text, size_t text_length, const char *suffix, size_t suffix_length);

#pragma mark - Create the Reactor

ProxyReactor *outersshpriv_proxy_reactor_create(otqueue_t queue)
{
    if (queue == NULL) {
        return NULL;
    }
    ProxyReactor *reactor = calloc(1, sizeof(*reactor));
    if (reactor == NULL) {
        return NULL;
    }
    otqueue_retain(queue);
    reactor->queue = queue;
    otqueue_set_specific(reactor->queue, reactor, reactor);
    return reactor;
}

#pragma mark - Create Listeners and Accept Connections

OuterSSHError outersshpriv_proxy_reactor_create_listener(
    ProxyReactor *reactor,
    ProxyReactorListenerHandle *handle,
    int preferred_port,
    int *bound_port,
    const char *username,
    size_t username_length,
    const char *password,
    size_t password_length,
    bool requires_authentication,
    uint64_t timeout_milliseconds)
{
    static const char creation_error_message[] = "Failed to create the SOCKS proxy listener.";
    if (handle != NULL) {
        *handle = (ProxyReactorListenerHandle){0};
    }
    if (bound_port != NULL) {
        *bound_port = 0;
    }
    if (reactor == NULL || handle == NULL || username == NULL ||
        password == NULL || reactor->server == NULL ||
        timeout_milliseconds == 0 ||
        timeout_milliseconds > INT64_MAX / NSEC_PER_MSEC) {
        return outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_LISTEN_SOCKET_CREATION_FAILED,
            creation_error_message, sizeof(creation_error_message) - 1, EINVAL);
    }
    otqueue_assert(reactor->queue);
    if (reactor->invalidated) {
        return outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_LISTEN_SOCKET_CREATION_FAILED,
            creation_error_message, sizeof(creation_error_message) - 1, ECANCELED);
    }
    if (bound_port == NULL || preferred_port < 0 || preferred_port > UINT16_MAX) {
        return outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_LISTEN_SOCKET_CREATION_FAILED,
            creation_error_message, sizeof(creation_error_message) - 1, EINVAL);
    }
    if (username_length > UINT8_MAX || password_length > UINT8_MAX) {
        return outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_LISTEN_SOCKET_CREATION_FAILED,
            creation_error_message, sizeof(creation_error_message) - 1, EINVAL);
    }

    unsigned char *username_copy = NULL;
    unsigned char *password_copy = NULL;
    OuterSSHError error = outersshpriv_proxy_error(
        OUTERSSH_PROXY_ERROR_LISTEN_SOCKET_CREATION_FAILED,
        creation_error_message, sizeof(creation_error_message) - 1, ENOMEM);
    size_t index;
    if (reactor->available_listener_index_count != 0) {
        index = reactor->available_listener_indices[
            reactor->available_listener_index_count - 1];
    } else {
        index = reactor->listener_slot_count;
        if (index == SIZE_MAX || !reserve_listener_slots(reactor, index + 1)) {
            goto failed;
        }
    }
    username_copy = malloc(username_length == 0 ? 1 : username_length);
    if (username_copy == NULL) {
        goto failed;
    }
    memcpy(username_copy, username, username_length);
    password_copy = malloc(password_length == 0 ? 1 : password_length);
    if (password_copy == NULL) {
        goto failed;
    }
    memcpy(password_copy, password, password_length);
    ListenerSlot *listener = &reactor->listener_slots[index];
    uint64_t generation = listener->generation + 1;
    if (generation == 0) generation = 1;
    *listener = (ListenerSlot){
        .generation = generation, .socket = -1,
        .requires_authentication = requires_authentication,
        .username = username_copy, .username_length = username_length,
        .password = password_copy, .password_length = password_length,
        .pending_connection_timeout_milliseconds = timeout_milliseconds,
        .is_active = true
    };
    ProxyReactorListenerHandle current_handle = {.index = index, .generation = generation};
    error = open_listener_socket(reactor, current_handle, listener, preferred_port, bound_port);
    if (error.domain != OUTERSSH_ERROR_NONE) {
        *listener = (ListenerSlot){.generation = generation, .socket = -1};
        goto failed;
    }
    if (reactor->available_listener_index_count != 0) reactor->available_listener_index_count--;
    else reactor->listener_slot_count++;
    *handle = current_handle;
    return (OuterSSHError){0};

failed:
    free(username_copy);
    free(password_copy);
    return error;
}

OuterSSHError outersshpriv_proxy_reactor_reopen_listener(
    ProxyReactor *reactor, ProxyReactorListenerHandle handle, int port)
{
    ListenerSlot *listener = outersshpriv_proxy_reactor_listener_for_handle(reactor, handle);
    assert(listener != NULL && listener->socket == -1);
    return open_listener_socket(reactor, handle, listener, port, &port);
}

static OuterSSHError open_listener_socket(ProxyReactor *reactor, ProxyReactorListenerHandle handle,
    ListenerSlot *listener, int preferred_port, int *bound_port)
{
    static const char message[] = "Failed to create the SOCKS proxy listener.";
    OuterSSHError error = outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_LISTEN_SOCKET_CREATION_FAILED,
        message, sizeof(message) - 1, ENOMEM);
    otsocket_t socket_fd = -1;
    ProxySourceContext *source_context = NULL;
    int port = preferred_port;
    otsource_t source = NULL;
    source_context = outersshpriv_proxy_reactor_create_source_context(reactor, NULL);
    if (source_context == NULL) {
        goto failed;
    }

    socket_fd = otsocket_create(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        error.system_error_code = errno;
        goto failed;
    }
    error.system_error_code = otsocket_prevent_inheritance(socket_fd) == 0 ? 0 : errno;
    if (error.system_error_code != 0) {
        goto failed;
    }
    error.system_error_code = otsocket_configure_sigpipe(socket_fd);
    if (error.system_error_code != 0) {
        goto failed;
    }
    int one = 1;
#if defined(_WIN32)
    int address_option = SO_EXCLUSIVEADDRUSE;
#else
    int address_option = SO_REUSEADDR;
#endif
    if (otsocket_setsockopt(socket_fd, SOL_SOCKET, address_option, &one, sizeof(one)) != 0) {
        error.system_error_code = errno;
        goto failed;
    }
    if (otsocket_set_nonblocking(socket_fd, true) != 0) {
        error.system_error_code = errno;
        goto failed;
    }

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)preferred_port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    if (otsocket_bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        static const char error_message[] = "Failed to bind the SOCKS proxy listener.";
        error = outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_BIND_FAILED,
            error_message, sizeof(error_message) - 1, errno);
        goto failed;
    }
    if (otsocket_listen(socket_fd, 128) != 0) {
        static const char error_message[] = "Failed to listen on the SOCKS proxy socket.";
        error = outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_LISTEN_FAILED,
            error_message, sizeof(error_message) - 1, errno);
        goto failed;
    }
    if (preferred_port == 0) {
        socklen_t address_length = sizeof(address);
        if (otsocket_getsockname(socket_fd, (struct sockaddr *)&address, &address_length) != 0) {
            static const char error_message[] = "Failed to resolve the SOCKS proxy listener address.";
            error = outersshpriv_proxy_error(
                OUTERSSH_PROXY_ERROR_LISTENER_ADDRESS_LOOKUP_FAILED,
                error_message, sizeof(error_message) - 1, errno);
            goto failed;
        }
        port = ntohs(address.sin_port);
    }

    source = otsource_create(
        OTSOURCE_TYPE_READ, (uintptr_t)socket_fd, reactor->queue);
    if (source == NULL) {
        error.system_error_code = ENOMEM;
        goto failed;
    }

    listener->socket = socket_fd;
    listener->accept_source = source;
    listener->accept_context = source_context;
    // From activation onward, only the cancel handler closes the descriptor.
    // Its context owns the descriptor independently of this reusable slot.
    if (source != NULL) {
        source_context->source = source;
        source_context->listener = handle;
        source_context->socket_to_close = socket_fd;
        otsource_set_context(source, source_context);
        otsource_set_event_handler(source, listener_socket_readable);
        otsource_set_cancel_handler(source, outersshpriv_proxy_reactor_source_cancelled);
        otsource_activate(source);
    }
    *bound_port = port;
    return (OuterSSHError){0};

failed:
    if (socket_fd >= 0) otsocket_close(socket_fd);
    if (source_context) outersshpriv_proxy_reactor_source_cancelled(source_context);
    return error;
}

void outersshpriv_proxy_reactor_close_listener_socket(ProxyReactor *reactor,
    ProxyReactorListenerHandle handle, void (*closed)(void *), void *context)
{
    otqueue_assert(reactor->queue);
    ListenerSlot *listener = outersshpriv_proxy_reactor_listener_for_handle(reactor, handle);
    assert(listener != NULL && listener->accept_context != NULL);
    listener->accept_context->closed = closed;
    listener->accept_context->closed_context = context;
    outersshpriv_proxy_reactor_cancel_source(&listener->accept_source);
    listener->socket = -1;
    listener->accept_context = NULL;
}

static void listener_socket_readable(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    outersshpriv_proxy_reactor_accept_connections(context->reactor, context->listener);
}

ListenerSlot *outersshpriv_proxy_reactor_listener_for_handle(
    ProxyReactor *reactor,
    ProxyReactorListenerHandle handle)
{
    if (handle.generation == 0 ||
        handle.index >= reactor->listener_slot_count) {
        return NULL;
    }
    ListenerSlot *listener = &reactor->listener_slots[handle.index];
    if (!listener->is_active ||
        listener->generation != handle.generation) {
        return NULL;
    }
    return listener;
}

static bool reserve_listener_slots(
    ProxyReactor *reactor,
    size_t minimum_capacity)
{
    if (reactor->listener_slot_capacity >= minimum_capacity) {
        return true;
    }

    size_t capacity = reactor->listener_slot_capacity == 0
        ? 4
        : reactor->listener_slot_capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*reactor->listener_slots)) {
        return false;
    }

    ListenerSlot *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL) {
        return false;
    }
    size_t *available_indices = malloc(
        capacity * sizeof(*available_indices));
    if (available_indices == NULL) {
        free(slots);
        return false;
    }

    if (reactor->listener_slot_count != 0) {
        memcpy(slots, reactor->listener_slots, reactor->listener_slot_count * sizeof(*slots));
    }
    if (reactor->available_listener_index_count > 0) {
        memcpy(
            available_indices,
            reactor->available_listener_indices,
            reactor->available_listener_index_count *
                sizeof(*available_indices));
    }

    free(reactor->listener_slots);
    free(reactor->available_listener_indices);
    reactor->listener_slots = slots;
    reactor->available_listener_indices = available_indices;
    reactor->listener_slot_capacity = capacity;
    return true;
}

#pragma mark - Remove Listeners

bool outersshpriv_proxy_reactor_remove_listener(
    ProxyReactor *reactor,
    ProxyReactorListenerHandle handle)
{
    if (reactor == NULL) {
        return false;
    }
    otqueue_assert(reactor->queue);
    if (outersshpriv_proxy_reactor_listener_for_handle(reactor, handle) == NULL) {
        return false;
    }
    // Stop accepting before cancellation can complete pending transfers.
    remove_listener(reactor, handle.index);
    outersshpriv_proxy_reactor_cancel_pending_connections_for_listener(reactor, handle);
    return true;
}

void outersshpriv_proxy_reactor_remove_all_listeners(ProxyReactor *reactor)
{
    otqueue_assert(reactor->queue);
    for (size_t index = 0; index < reactor->listener_slot_count; index++) {
        if (reactor->listener_slots[index].is_active) {
            remove_listener(reactor, index);
        }
    }
}

static void remove_listener(ProxyReactor *reactor, size_t index)
{
    ListenerSlot *listener = &reactor->listener_slots[index];
    outersshpriv_proxy_reactor_cancel_source(&listener->accept_source);
    free(listener->username);
    free(listener->password);
    *listener = (ListenerSlot){
        .generation = listener->generation,
        .socket = -1
    };
    reactor->available_listener_indices[
        reactor->available_listener_index_count++] = index;
}

#pragma mark - Invalidate and Destroy the Reactor

void outersshpriv_proxy_reactor_invalidate(ProxyReactor *reactor)
{
    if (reactor == NULL) {
        return;
    }
    otqueue_assert(reactor->queue);
    invalidate_on_queue(reactor);
}

void outersshpriv_proxy_reactor_destroy(ProxyReactor *reactor, void (*completion)(void *), void *context)
{
    assert(reactor != NULL);
    reactor->destruction_completion = completion;
    reactor->destruction_context = context;

    otqueue_t queue = reactor->queue;
    otqueue_retain(queue);
    otqueue_async(queue, reactor, destroy_reactor_on_queue);
    otqueue_release(queue);
}

static void destroy_reactor_on_queue(void *opaque_context)
{
    ProxyReactor *reactor = opaque_context;
    if (!reactor->destroy_started) {
        reactor->destroy_started = true;
        invalidate_on_queue(reactor);
    }
    outersshpriv_proxy_reactor_finish_destroy(reactor);
}

static void invalidate_on_queue(ProxyReactor *reactor)
{
    if (reactor->invalidated) {
        return;
    }
    reactor->invalidated = true;
    outersshpriv_proxy_reactor_remove_all_listeners(reactor);
    outersshpriv_proxy_reactor_cancel_all_tcp_connects(reactor);
    outersshpriv_proxy_reactor_cancel_all_pending_connections(reactor);

    free(reactor->listener_slots);
    reactor->listener_slots = NULL;
    reactor->listener_slot_count = 0;
    reactor->listener_slot_capacity = 0;
    free(reactor->available_listener_indices);
    reactor->available_listener_indices = NULL;
    reactor->available_listener_index_count = 0;

}

void outersshpriv_proxy_reactor_finish_destroy(ProxyReactor *reactor)
{
    otqueue_assert(reactor->queue);
    if (!reactor->destroy_started || reactor->pending_source_cancellations != 0 ||
        reactor->pending_tcp_resolutions != 0) return;
    otqueue_t queue = reactor->queue;
    reactor->queue = NULL;
    // Connection slots outlive invalidation while socket watches are cancelling.
    free(reactor->pending_connections);
    free(reactor->available_pending_connection_indices);
    free(reactor->connect_slots);
    free(reactor->available_connect_indices);
    void (*completion)(void *) = reactor->destruction_completion;
    void *context = reactor->destruction_context;
    free(reactor);
    if (completion != NULL) completion(context);
    otqueue_release(queue);
}

#pragma mark - Track Dispatch Source Cancellation

ProxySourceContext *outersshpriv_proxy_reactor_create_source_context(
    ProxyReactor *reactor,
    otsource_t socket_source)
{
    ProxySourceContext *context = calloc(1, sizeof(*context));
    if (context == NULL) {
        return NULL;
    }
    otqueue_assert(reactor->queue);
    reactor->pending_source_cancellations++;
    context->reactor = reactor;
    context->source = socket_source;
    context->socket_to_close = -1;
    return context;
}

void outersshpriv_proxy_reactor_cancel_source(otsource_t *socket_source)
{
    if (*socket_source == NULL) {
        return;
    }
    otsource_cancel(*socket_source);
    otsource_release(*socket_source);
    *socket_source = NULL;
}

void outersshpriv_proxy_reactor_source_cancelled(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    if (context->socket_to_close >= 0) {
        otsocket_close(context->socket_to_close);
    }
    ProxyReactor *reactor = context->reactor;
    void (*closed)(void *) = context->closed;
    void *closed_context = context->closed_context;
    free(context);
    otqueue_assert(reactor->queue);
    assert(reactor->pending_source_cancellations != 0);
    reactor->pending_source_cancellations--;
    if (closed) closed(closed_context);
    outersshpriv_proxy_reactor_finish_destroy(reactor);
}

#pragma mark - Create Credentials

char *outersshpriv_proxy_reactor_create_credential(
    size_t byte_count,
    int32_t *status)
{
    if (status != NULL) {
        *status = 0;
    }
    if (byte_count == 0 || byte_count > (SIZE_MAX - 1) / 2) {
        if (status != NULL) {
            *status = EINVAL;
        }
        return NULL;
    }

    unsigned char *bytes = malloc(byte_count);
    if (bytes == NULL) {
        if (status != NULL) {
            *status = ENOMEM;
        }
        return NULL;
    }
    int result = secure_random_bytes(bytes, byte_count);
    if (result != 0) {
        free(bytes);
        if (status != NULL) {
            *status = result;
        }
        return NULL;
    }

    static const char hexadecimal[] = "0123456789abcdef";
    char *credential = malloc(byte_count * 2 + 1);
    if (credential == NULL) {
        free(bytes);
        if (status != NULL) {
            *status = ENOMEM;
        }
        return NULL;
    }
    for (size_t index = 0; index < byte_count; index++) {
        credential[index * 2] = hexadecimal[bytes[index] >> 4];
        credential[index * 2 + 1] = hexadecimal[bytes[index] & 0x0f];
    }
    credential[byte_count * 2] = '\0';
    free(bytes);
    return credential;
}

#pragma mark - Resolve Proxy Requests

ProxyConnectionRoute outersshpriv_proxy_resolve_request(
    ProxyConnectRequest request)
{
    static const char unix_host_suffix[] = ".unix.outerssh.localhost";
    char normalized_host[PROXY_HOST_CAPACITY];
    size_t normalized_host_byte_count = 0;
    if (!outersshpriv_proxy_normalize_host(request.host, request.host_length, normalized_host, &normalized_host_byte_count)) {
        return rejected_connection_route(request);
    }
    if (has_suffix(normalized_host, normalized_host_byte_count, unix_host_suffix, sizeof(unix_host_suffix) - 1) ||
        has_suffix(normalized_host, normalized_host_byte_count, ".pipe.outerssh.localhost", sizeof(".pipe.outerssh.localhost") - 1)) {
        char path[PROXY_UNIX_SOCKET_PATH_CAPACITY];
        size_t path_byte_count = 0;
        OuterSSHProxySocketKind kind;
        if (request.port != 80 || !outerssh_proxy_decode_socket_host(normalized_host, normalized_host_byte_count, &kind, path, sizeof(path), &path_byte_count)) {
            return rejected_connection_route(request);
        }
        return unix_socket_connection_route(request, path, path_byte_count);
    }
    char loopback_host[OUTERSSH_PROXY_TCP_HOST_CAPACITY];
    size_t loopback_host_length = 0;
    if (outerssh_proxy_decode_tcp_host(
            request.host, request.host_length, loopback_host, sizeof(loopback_host), &loopback_host_length)) {
        if (request.port == 0) {
            return rejected_connection_route(request);
        }
        const char *connect_host = loopback_host;
        if (loopback_host[0] == '[') {
            connect_host++;
            loopback_host_length -= 2;
        }
        ProxyConnectionRoute route = tcp_connection_route(request, connect_host, loopback_host_length, request.port);
        route.tcp.loopback = true;
        return route;
    }
    unsigned char address[4];
    if (proxy_host_is_synthetic(normalized_host, normalized_host_byte_count) ||
        (host_ends_in_number(normalized_host, normalized_host_byte_count) &&
            !parse_ipv4(normalized_host, normalized_host_byte_count, address))) {
        return rejected_connection_route(request);
    }
    ProxyConnectionRoute route = tcp_connection_route(request, request.host, request.host_length, request.port);
    route.tcp.loopback = host_is_loopback(normalized_host, normalized_host_byte_count);
    return route;
}

bool outersshpriv_proxy_parse_origin(const char *origin, size_t origin_length,
    char normalized[PROXY_ORIGIN_CAPACITY], size_t *normalized_length, ProxyConnectionRoute *route)
{
    *normalized_length = 0;
    normalized[0] = '\0';
    bool secure;
    size_t scheme_length;
    if (origin_length > 7 && strncasecmp(origin, "http://", 7) == 0) {
        secure = false;
        scheme_length = 7;
    } else if (origin_length > 8 && strncasecmp(origin, "https://", 8) == 0) {
        secure = true;
        scheme_length = 8;
    } else {
        return false;
    }
    const char *host = origin + scheme_length, *end = origin + origin_length, *host_end = end, *port = NULL;
    bool bracketed = *host == '[';
    if (bracketed) {
        host++;
        host_end = memchr(host, ']', (size_t)(end - host));
        if (host_end == NULL || (host_end + 1 < end && host_end[1] != ':')) return false;
        if (host_end + 1 < end) port = host_end + 2;
    } else {
        const char *colon = memchr(host, ':', (size_t)(end - host));
        if (colon != NULL) {
            host_end = colon;
            port = colon + 1;
        }
    }
    ProxyConnectRequest request = {.port = secure ? 443 : 80};
    size_t host_length = (size_t)(host_end - host);
    if (host_length == 0 || host_length >= sizeof(request.host)) return false;
    for (size_t i = 0; i < host_length; i++) {
        unsigned char ch = (unsigned char)host[i];
        if (!isalnum(ch) && ch != '-' && ch != '.' && ch != '_' && (ch != ':' || !bracketed)) {
            return false;
        }
        request.host[i] = (char)tolower(ch);
    }
    request.host[host_length] = '\0';
    request.host_length = host_length;
    if (port != NULL) {
        unsigned value = 0;
        if (port == end || *port == '0') return false;
        for (; port < end; port++) {
            if (*port < '0' || *port > '9') return false;
            value = value * 10 + (unsigned)(*port - '0');
            if (value > 65535) return false;
        }
        request.port = (uint16_t)value;
    }
    *route = outersshpriv_proxy_resolve_request(request);
    if (route->kind == PROXY_CONNECTION_ROUTE_REJECTED ||
        (route->kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET && secure)) {
        return false;
    }
    char port_text[8] = "";
    if (request.port != (secure ? 443 : 80)) snprintf(port_text, sizeof(port_text), ":%u", request.port);
    int length = snprintf(normalized, PROXY_ORIGIN_CAPACITY, "%s%s%s%s%s", secure ? "https://" : "http://",
        bracketed ? "[" : "", request.host, bracketed ? "]" : "", port_text);
    if (length < 0 || length >= PROXY_ORIGIN_CAPACITY) {
        normalized[0] = '\0';
        return false;
    }
    *normalized_length = (size_t)length;
    return true;
}

static ProxyConnectionRoute tcp_connection_route(
    ProxyConnectRequest request,
    const char *host,
    size_t host_length,
    uint16_t port)
{
    ProxyConnectionRoute route = {
        .kind = PROXY_CONNECTION_ROUTE_TCP,
        .request = request,
        .tcp = {.port = port}
    };
    size_t length = host_length;
    if (length >= sizeof(route.tcp.host)) {
        return rejected_connection_route(request);
    }
    route.tcp.host_length = length;
    memcpy(route.tcp.host, host, length);
    route.tcp.host[length] = '\0';
    return route;
}

static ProxyConnectionRoute unix_socket_connection_route(
    ProxyConnectRequest request,
    const char *path,
    size_t path_length)
{
    ProxyConnectionRoute route = {
        .kind = PROXY_CONNECTION_ROUTE_UNIX_SOCKET,
        .request = request
    };
    size_t length = path_length;
    if (length >= sizeof(route.unix_socket.path)) {
        return rejected_connection_route(request);
    }
    memcpy(route.unix_socket.path, path, length);
    route.unix_socket.path[length] = '\0';
    route.unix_socket.path_length = length;
    return route;
}

static ProxyConnectionRoute rejected_connection_route(
    ProxyConnectRequest request)
{
    return (ProxyConnectionRoute){
        .kind = PROXY_CONNECTION_ROUTE_REJECTED,
        .request = request
    };
}

#pragma mark - Host Normalization

bool outersshpriv_proxy_normalize_host(
    const char *host,
    size_t host_length,
    char output[PROXY_HOST_CAPACITY], size_t *output_length)
{
    if (host == NULL || output == NULL || host_length >= PROXY_HOST_CAPACITY ||
        memchr(host, '\0', host_length) != NULL) {
        return false;
    }
    const char *start = host;
    const char *end = host + host_length;
    while (start < end && (*start == '[' || *start == ']')) {
        start++;
    }
    while (end > start && (end[-1] == '[' || end[-1] == ']')) {
        end--;
    }
    while (start < end && isspace((unsigned char)*start)) {
        start++;
    }
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }
    while (start < end && *start == '.') {
        start++;
    }
    while (end > start && end[-1] == '.') {
        end--;
    }
    const char *zone = memchr(start, '%', (size_t)(end - start));
    if (zone != NULL) {
        end = zone;
    }
    size_t length = (size_t)(end - start);
    if (length >= PROXY_HOST_CAPACITY) {
        output[0] = '\0';
        return false;
    }
    for (size_t index = 0; index < length; index++) {
        output[index] = (char)tolower((unsigned char)start[index]);
    }
    output[length] = '\0';
    *output_length = length;
    return true;
}

#pragma mark - Classify Hostnames and Addresses

static bool proxy_host_is_synthetic(const char *host, size_t host_length)
{
    static const char outerssh_suffix[] = ".outerssh.localhost";
    return (host_length == sizeof(outerssh_suffix) - 2 && memcmp(host, outerssh_suffix + 1, host_length) == 0) ||
        has_suffix(host, host_length, outerssh_suffix, sizeof(outerssh_suffix) - 1);
}

/* As in the URL standard, a host whose last label is a decimal or 0x number
 * is an IPv4 address. Resolvers also accept shortened, octal and hexadecimal
 * forms such as 127.1 or 0x7f000001, so only the dotted-quad spelling is
 * routed and the zone of every IPv4 destination follows from its spelling. */
static bool host_ends_in_number(const char *host, size_t host_length)
{
    if (memchr(host, ':', host_length) != NULL) {
        return false;
    }
    size_t start = host_length;
    while (start > 0 && host[start - 1] != '.') {
        start--;
    }
    const char *label = host + start;
    size_t length = host_length - start;
    if (length >= 2 && label[0] == '0' && label[1] == 'x') {
        for (size_t i = 2; i < length; i++) {
            if (!isxdigit((unsigned char)label[i])) return false;
        }
        return true;
    }
    if (length == 0) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        if (!isdigit((unsigned char)label[i])) return false;
    }
    return true;
}

static bool parse_ipv4(const char *text, size_t length, unsigned char address[4])
{
    size_t index = 0;
    for (size_t part = 0; part < 4; part++) {
        if (part > 0) {
            if (index >= length || text[index] != '.') return false;
            index++;
        }
        size_t start = index;
        unsigned value = 0;
        while (index < length && isdigit((unsigned char)text[index]) && index - start < 3) {
            value = value * 10 + (unsigned)(text[index] - '0');
            index++;
        }
        if (index == start || value > 255 || (index - start > 1 && text[start] == '0')) return false;
        address[part] = (unsigned char)value;
    }
    return index == length;
}

static int hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool parse_ipv6(const char *text, size_t length, unsigned char address[16])
{
    unsigned groups[8];
    size_t count = 0, gap = SIZE_MAX, index = 0;
    if (length >= 2 && text[0] == ':' && text[1] == ':') {
        gap = 0;
        index = 2;
    } else if (length > 0 && text[0] == ':') {
        return false;
    }
    while (index < length) {
        size_t end = index;
        while (end < length && text[end] != ':') {
            end++;
        }
        if (memchr(text + index, '.', end - index) != NULL) {
            unsigned char ipv4[4];
            if (end != length || count > 6 || !parse_ipv4(text + index, end - index, ipv4)) return false;
            groups[count++] = (unsigned)ipv4[0] << 8 | ipv4[1];
            groups[count++] = (unsigned)ipv4[2] << 8 | ipv4[3];
            break;
        }
        if (count == 8 || end == index || end - index > 4) return false;
        unsigned value = 0;
        for (size_t i = index; i < end; i++) {
            int digit = hex_digit(text[i]);
            if (digit < 0) return false;
            value = value * 16 + (unsigned)digit;
        }
        groups[count++] = value;
        index = end;
        if (index < length) {
            index++;
            if (index == length) return false;
            if (text[index] == ':') {
                if (gap != SIZE_MAX) return false;
                gap = count;
                index++;
            }
        }
    }
    if (gap == SIZE_MAX ? count != 8 : count > 7) return false;
    memset(address, 0, 16);
    for (size_t group = 0; group < count; group++) {
        size_t position = gap != SIZE_MAX && group >= gap ? 8 - (count - gap) + (group - gap) : group;
        address[position * 2] = (unsigned char)(groups[group] >> 8);
        address[position * 2 + 1] = (unsigned char)groups[group];
    }
    return true;
}

static bool ipv4_is_loopback(const unsigned char address[4])
{
    return address[0] == 127 || (!address[0] && !address[1] && !address[2] && !address[3]);
}

static bool host_is_loopback(const char *host, size_t host_length)
{
    static const char localhost[] = "localhost";
    if ((host_length == sizeof(localhost) - 1 && memcmp(host, localhost, host_length) == 0) ||
        has_suffix(host, host_length, ".localhost", sizeof(".localhost") - 1)) {
        return true;
    }
    unsigned char address[16];
    if (parse_ipv4(host, host_length, address)) {
        return ipv4_is_loopback(address);
    }
    if (!parse_ipv6(host, host_length, address)) {
        return false;
    }
    for (size_t i = 0; i < 10; i++) {
        if (address[i] != 0) return false;
    }
    bool compatible = address[10] == 0 && address[11] == 0;
    bool mapped = address[10] == 0xff && address[11] == 0xff;
    bool one = !address[12] && !address[13] && !address[14] && address[15] == 1;
    return (compatible && one) || ((compatible || mapped) && ipv4_is_loopback(address + 12));
}

static bool has_suffix(const char *text, size_t text_length, const char *suffix, size_t suffix_length)
{
    return text_length >= suffix_length &&
        memcmp(
            text + text_length - suffix_length,
            suffix,
            suffix_length) == 0;
}
