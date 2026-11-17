#include "platform/OTSocket.h"
#include "ProxyReactorInternal.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include "platform/SSHLogging.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(__APPLE__)
// Fresh builds installed into /Applications can report EHOSTUNREACH/ENETUNREACH on the first
// local-network connection, then succeed immediately on retry.
#define ENABLE_LOCAL_NETWORK_CONNECT_RETRY 1
#else
#define ENABLE_LOCAL_NETWORK_CONNECT_RETRY 0
#endif


static int set_close_on_exec(otsocket_t socket);

typedef ProxyReactorTCPConnectHandle TCPConnectHandle;

typedef enum {
    PROXY_TCP_CONNECTION_RESOLUTION_FAILED,
    PROXY_TCP_CONNECTION_FAILED,
    PROXY_TCP_CONNECTION_CANCELLED
} ProxyTCPConnectionErrorCode;

typedef struct {
    ProxyTCPConnectionErrorCode code;
    int detail;
} TCPConnectError;

struct TCPConnectSlot {
    uint64_t generation;
    char *host;
    size_t host_length;
    int32_t port;
    SSHSessionCreationOperation *operation;
    struct addrinfo *addresses;
    struct addrinfo *current_address;
    otsocket_t socket;
    otsource_t write_socket_source;
    otsource_t timeout_timer;
    char last_address[NI_MAXHOST + NI_MAXSERV + 2];
    int last_error;
    uint64_t attempt_generation;
    bool is_active;
    bool cancelling_write_source;
    void (*after_socket_watch)(ProxyReactor *reactor, TCPConnectSlot *connection);
    TCPConnectError completion_error;
#if ENABLE_LOCAL_NETWORK_CONNECT_RETRY
    otsource_t retry_timer;
    bool saw_local_network_address;
    bool has_initial_route_error;
    TCPConnectError initial_route_error;
    TCPConnectError latest_route_error;
    size_t next_retry_index;
#endif
};

typedef struct {
    ProxyReactor *reactor;
    TCPConnectHandle connection;
    char *host_c_string;
    int32_t port;
    int result;
    struct addrinfo *addresses;
} TCPResolutionContext;

static void start_tcp_resolution(
    ProxyReactor *reactor,
    TCPConnectHandle handle,
    TCPConnectSlot *connection);
static void resolve_tcp_address(void *opaque_context);
static void apply_tcp_resolution(void *opaque_context);
static void try_next_tcp_address(
    ProxyReactor *reactor,
    TCPConnectHandle handle,
    TCPConnectSlot *connection);
static bool start_tcp_connect_wait(
    ProxyReactor *reactor,
    TCPConnectHandle handle);
static void tcp_connect_socket_writable(void *opaque_context);
static void tcp_connect_timed_out(void *opaque_context);
static void finish_current_tcp_address(
    ProxyReactor *reactor,
    TCPConnectHandle handle,
    int error_code);
static void complete_tcp_connect_with_socket(
    ProxyReactor *reactor,
    TCPConnectSlot *connection);
static void complete_tcp_connect_with_error(
    ProxyReactor *reactor,
    TCPConnectSlot *connection,
    TCPConnectError error);
static void finish_tcp_socket_use(
    ProxyReactor *reactor,
    TCPConnectSlot *connection,
    void (*continuation)(ProxyReactor *reactor, TCPConnectSlot *connection));
static void tcp_connect_write_source_cancelled(void *opaque_context);
static void try_next_address_after_socket_watch(
    ProxyReactor *reactor,
    TCPConnectSlot *connection);
static void hand_off_connected_socket(
    ProxyReactor *reactor,
    TCPConnectSlot *connection);
static void report_tcp_connect_error(
    ProxyReactor *reactor,
    TCPConnectSlot *connection);
#if ENABLE_LOCAL_NETWORK_CONNECT_RETRY
static bool is_local_network_address(const struct addrinfo *address_info);
static void finish_tcp_connect_attempt(
    ProxyReactor *reactor,
    TCPConnectHandle handle,
    TCPConnectSlot *connection,
    TCPConnectError error,
    bool is_retryable_route_error);
static void retry_tcp_connect(void *opaque_context);
#endif
static bool reserve_connect_slots(
    ProxyReactor *reactor,
    size_t minimum_capacity);
static TCPConnectSlot *connect_for_handle(
    ProxyReactor *reactor,
    TCPConnectHandle handle);
static void close_connect_socket(TCPConnectSlot *connection);
static void clear_connect_addresses(TCPConnectSlot *connection);
static void release_connect(
    ProxyReactor *reactor,
    TCPConnectSlot *connection);

#pragma mark - Connect and Resolve

ProxyReactorTCPConnectHandle outersshpriv_proxy_reactor_connect_tcp(
    ProxyReactor *reactor,
    const char *host,
    size_t host_length,
    int32_t port,
    SSHSessionCreationOperation *operation)
{
    otqueue_assert(reactor->queue);
    if (reactor->invalidated) {
        static const char cancelled_message[] = "The SSH operation was cancelled.";
        outersshpriv_session_pool_tcp_connect_failed(operation, outerssh_session_error(OUTERSSH_SESSION_ERROR_CANCELLED,
            cancelled_message, sizeof(cancelled_message) - 1));
        ProxyReactorTCPConnectHandle invalid_handle = {0};
        return invalid_handle;
    }
    if (host == NULL || host_length == 0 ||
        host_length > INT_MAX || memchr(host, 0, host_length) != NULL ||
        port <= 0 || port > UINT16_MAX) {
        static const char invalid_address_message[] = "Invalid TCP connection address or port.";
        OuterSSHError error = outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
            invalid_address_message, sizeof(invalid_address_message) - 1);
        error.system_error_code = EINVAL;
        outersshpriv_session_pool_tcp_connect_failed(operation, error);
        ProxyReactorTCPConnectHandle invalid_handle = {0};
        return invalid_handle;
    }

    size_t index = 0;
    if (reactor->available_connect_index_count > 0) {
        reactor->available_connect_index_count -= 1;
        index = reactor->available_connect_indices[
            reactor->available_connect_index_count];
    } else {
        if (reactor->connect_slot_count == SIZE_MAX ||
            !reserve_connect_slots(
                reactor,
                reactor->connect_slot_count + 1)) {
            static const char allocation_message[] = "Failed to allocate TCP connection state.";
            OuterSSHError error = outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
                allocation_message, sizeof(allocation_message) - 1);
            error.system_error_code = ENOMEM;
            outersshpriv_session_pool_tcp_connect_failed(operation, error);
            ProxyReactorTCPConnectHandle invalid_handle = {0};
            return invalid_handle;
        }
        index = reactor->connect_slot_count;
        reactor->connect_slot_count += 1;
    }

    TCPConnectSlot *connection = &reactor->connect_slots[index];
    connection->generation += 1;
    if (connection->generation == 0) {
        connection->generation = 1;
    }
    TCPConnectHandle handle = {
        .index = index,
        .generation = connection->generation
    };
    connection->host = malloc(host_length);
    connection->host_length = host_length;
    if (connection->host == NULL) {
        static const char allocation_message[] = "Failed to allocate TCP connection state.";
        reactor->available_connect_indices[
            reactor->available_connect_index_count++] = index;
        OuterSSHError error = outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
            allocation_message, sizeof(allocation_message) - 1);
        error.system_error_code = ENOMEM;
        outersshpriv_session_pool_tcp_connect_failed(operation, error);
        ProxyReactorTCPConnectHandle invalid_handle = {0};
        return invalid_handle;
    }
    memcpy(connection->host, host, host_length);
    connection->port = port;
    connection->operation = operation;
    connection->socket = -1;
    connection->is_active = true;
    start_tcp_resolution(reactor, handle, connection);
    return handle;
}

static void start_tcp_resolution(
    ProxyReactor *reactor,
    TCPConnectHandle handle,
    TCPConnectSlot *connection)
{
    char *host = malloc(connection->host_length + 1);
    if (host == NULL) {
        complete_tcp_connect_with_error(
            reactor,
            connection,
            (TCPConnectError){
                .code = PROXY_TCP_CONNECTION_FAILED,
                .detail = ENOMEM,
            });
        return;
    }
    memcpy(host, connection->host, connection->host_length);
    host[connection->host_length] = '\0';
    TCPResolutionContext *context = calloc(1, sizeof(*context));
    if (context == NULL) {
        free(host);
        complete_tcp_connect_with_error(
            reactor,
            connection,
            (TCPConnectError){
                .code = PROXY_TCP_CONNECTION_FAILED,
                .detail = ENOMEM,
            });
        return;
    }
    reactor->pending_tcp_resolutions++;
    *context = (TCPResolutionContext){
        .reactor = reactor,
        .connection = handle,
        .host_c_string = host,
        .port = connection->port
    };
    otqueue_async_background(context, resolve_tcp_address);
}

static void resolve_tcp_address(void *opaque_context)
{
    TCPResolutionContext *context = opaque_context;
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char service[16] = {0};
    snprintf(service, sizeof(service), "%d", context->port);
    context->result = getaddrinfo(
        context->host_c_string,
        service,
        &hints,
        &context->addresses);
    otqueue_async(
        context->reactor->queue,
        context,
        apply_tcp_resolution);
}

static void apply_tcp_resolution(void *opaque_context)
{
    TCPResolutionContext *context = opaque_context;
    ProxyReactor *reactor = context->reactor;
    TCPConnectHandle handle = context->connection;
    int result = context->result;
    struct addrinfo *addresses = context->addresses;
    TCPConnectSlot *connection = connect_for_handle(
        reactor,
        handle);
    if (connection == NULL) {
        if (addresses != NULL) {
            freeaddrinfo(addresses);
        }
    } else {
        if (result != 0 || addresses == NULL) {
            if (addresses != NULL) {
                freeaddrinfo(addresses);
            }
            TCPConnectError error = {
                .code = PROXY_TCP_CONNECTION_RESOLUTION_FAILED,
                .detail = result,
            };
            complete_tcp_connect_with_error(reactor, connection, error);
        } else {
            connection->addresses = addresses;
            connection->current_address = addresses;
            try_next_tcp_address(reactor, handle, connection);
        }
    }

    free(context->host_c_string);
    free(context);
    assert(reactor->pending_tcp_resolutions != 0);
    reactor->pending_tcp_resolutions--;
    outersshpriv_proxy_reactor_finish_destroy(reactor);
}

#pragma mark - Try Addresses

static void try_next_tcp_address(
    ProxyReactor *reactor,
    TCPConnectHandle handle,
    TCPConnectSlot *connection)
{
    while (true) {
        const struct addrinfo *address_info = connection->current_address;
        if (address_info == NULL) {
            TCPConnectError error = {
                .code = PROXY_TCP_CONNECTION_FAILED,
                .detail = connection->last_error,
            };
#if ENABLE_LOCAL_NETWORK_CONNECT_RETRY
            bool should_retry = connection->saw_local_network_address &&
                (connection->last_error == EHOSTUNREACH
                 || connection->last_error == ENETUNREACH);
            finish_tcp_connect_attempt(
                reactor,
                handle,
                connection,
                error,
                should_retry);
#else
            complete_tcp_connect_with_error(reactor, connection, error);
#endif
            return;
        }

        int address_error = 0;
        if (address_info->ai_addr == NULL ||
            (address_info->ai_family == AF_INET &&
             (size_t)address_info->ai_addrlen < sizeof(struct sockaddr_in)) ||
            (address_info->ai_family == AF_INET6 &&
             (size_t)address_info->ai_addrlen < sizeof(struct sockaddr_in6))) {
            address_error = EINVAL;
        } else if (address_info->ai_family != AF_INET &&
                   address_info->ai_family != AF_INET6) {
            address_error = EAFNOSUPPORT;
        }
        if (address_error != 0) {
            connection->last_error = address_error;
            connection->current_address = address_info->ai_next;
            continue;
        }

        {
            char host[NI_MAXHOST];
            char service[NI_MAXSERV];
            int result = getnameinfo(address_info->ai_addr,
                                     (socklen_t)address_info->ai_addrlen,
                                     host,
                                     sizeof(host),
                                     service,
                                     sizeof(service),
                                     NI_NUMERICHOST | NI_NUMERICSERV);
            if (result != 0) {
                connection->last_address[0] = '\0';
            } else {
                snprintf(connection->last_address, sizeof(connection->last_address), "%s:%s", host, service);
            }
        }

#if ENABLE_LOCAL_NETWORK_CONNECT_RETRY
        if (is_local_network_address(address_info)) {
            connection->saw_local_network_address = true;
        }
#endif

        connection->attempt_generation += 1;
        if (connection->attempt_generation == 0) {
            connection->attempt_generation = 1;
        }

        connection->socket = otsocket_create(
            address_info->ai_family,
            address_info->ai_socktype,
            address_info->ai_protocol);
        if (connection->socket < 0) {
            connection->last_error = errno;
            connection->current_address = address_info->ai_next;
            continue;
        }

        int one = 1;
        int configuration_error = set_close_on_exec(connection->socket);
        if (configuration_error == 0) {
            configuration_error = otsocket_configure_sigpipe(connection->socket);
        }
        if (configuration_error == 0 &&
            otsocket_setsockopt(
                connection->socket,
                IPPROTO_TCP,
                TCP_NODELAY,
                &one,
                sizeof(one)) != 0) {
            configuration_error = errno;
        }
        if (configuration_error != 0) {
            close_connect_socket(connection);
            connection->last_error = configuration_error;
            connection->current_address = address_info->ai_next;
            continue;
        }
        if (otsocket_set_nonblocking(connection->socket, true) != 0) {
            int error_code = errno;
            close_connect_socket(connection);
            connection->last_error = error_code;
            connection->current_address = address_info->ai_next;
            continue;
        }

        int result = otsocket_connect(
            connection->socket,
            address_info->ai_addr,
            (socklen_t)address_info->ai_addrlen);
        if (result != 0) {
            int error_code = errno;
            if (error_code == EINPROGRESS) {
                (void)start_tcp_connect_wait(reactor, handle);
                return;
            }
            close_connect_socket(connection);
            connection->last_error = error_code;
            connection->current_address = address_info->ai_next;
            continue;
        }

        complete_tcp_connect_with_socket(reactor, connection);
        return;
    }
}

static bool start_tcp_connect_wait(
    ProxyReactor *reactor,
    TCPConnectHandle handle)
{
    TCPConnectSlot *connection = connect_for_handle(reactor, handle);
    if (connection == NULL) {
        return false;
    }
    uint64_t attempt_generation = connection->attempt_generation;
    ProxySourceContext *write_context =
        outersshpriv_proxy_reactor_create_source_context(reactor, NULL);
    if (write_context == NULL) {
        finish_current_tcp_address(reactor, handle, ENOMEM);
        return false;
    }
    connection->write_socket_source = otsource_create(
        OTSOURCE_TYPE_WRITE, (uintptr_t)connection->socket, reactor->queue);
    if (connection->write_socket_source == NULL) {
        outersshpriv_proxy_reactor_source_cancelled(write_context);
        finish_current_tcp_address(reactor, handle, ENOMEM);
        return false;
    }
    write_context->source = connection->write_socket_source;
    write_context->connection = handle;
    write_context->attempt_generation = attempt_generation;
    otsource_set_context(connection->write_socket_source, write_context);
    otsource_set_cancel_handler(
        connection->write_socket_source, tcp_connect_write_source_cancelled);
    otsource_set_event_handler(
        connection->write_socket_source, tcp_connect_socket_writable);
    otsource_activate(connection->write_socket_source);

    connection->timeout_timer = otsource_create(
        OTSOURCE_TYPE_TIMER, 0, reactor->queue);
    if (connection->timeout_timer == NULL) {
        finish_current_tcp_address(reactor, handle, ENOMEM);
        return false;
    }
    ProxySourceContext *timeout_context =
        outersshpriv_proxy_reactor_create_source_context(reactor, connection->timeout_timer);
    if (timeout_context == NULL) {
        otsource_activate(connection->timeout_timer);
        finish_current_tcp_address(reactor, handle, ENOMEM);
        return false;
    }
    timeout_context->connection = handle;
    timeout_context->attempt_generation = attempt_generation;
    otsource_set_context(connection->timeout_timer, timeout_context);
    otsource_set_cancel_handler(
        connection->timeout_timer, outersshpriv_proxy_reactor_source_cancelled);
    otsource_set_event_handler(
        connection->timeout_timer,
        tcp_connect_timed_out);
    otsource_set_timer(
        connection->timeout_timer,
        ottime(OTTIME_NOW, 10 * NSEC_PER_SEC),
        OTTIME_FOREVER,
        0);
    otsource_activate(connection->timeout_timer);
    return true;
}

static void tcp_connect_socket_writable(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;

    ProxyReactor *reactor = context->reactor;
    TCPConnectHandle handle = context->connection;

    TCPConnectSlot *connection = connect_for_handle(reactor, handle);
    if (connection == NULL || connection->cancelling_write_source ||
        connection->attempt_generation != context->attempt_generation) {
        return;
    }
    int socket_error = 0;
    socklen_t socket_error_length = sizeof(socket_error);
    if (otsocket_getsockopt(
            connection->socket,
            SOL_SOCKET,
            SO_ERROR,
            &socket_error,
            &socket_error_length) != 0) {
        socket_error = errno;
    }
    if (socket_error == 0) {
        complete_tcp_connect_with_socket(reactor, connection);
        return;
    }
    finish_current_tcp_address(reactor, handle, socket_error);
}

static void tcp_connect_timed_out(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    TCPConnectSlot *connection = connect_for_handle(
        context->reactor,
        context->connection);
    if (connection == NULL || connection->cancelling_write_source ||
        connection->attempt_generation != context->attempt_generation) {
        return;
    }
    finish_current_tcp_address(
        context->reactor,
        context->connection,
        ETIMEDOUT);
}

static void finish_current_tcp_address(
    ProxyReactor *reactor,
    TCPConnectHandle handle,
    int error_code)
{
    TCPConnectSlot *connection = connect_for_handle(reactor, handle);
    if (connection == NULL) {
        return;
    }
    connection->attempt_generation += 1;
    if (connection->attempt_generation == 0) {
        connection->attempt_generation = 1;
    }
    connection->last_error = error_code;
    finish_tcp_socket_use(reactor, connection, try_next_address_after_socket_watch);
}

#pragma mark - Cancel the Socket Watch and Complete the Attempt

static void complete_tcp_connect_with_socket(
    ProxyReactor *reactor,
    TCPConnectSlot *connection)
{
    finish_tcp_socket_use(reactor, connection, hand_off_connected_socket);
}

static void complete_tcp_connect_with_error(
    ProxyReactor *reactor,
    TCPConnectSlot *connection,
    TCPConnectError error)
{
    connection->completion_error = error;
    finish_tcp_socket_use(reactor, connection, report_tcp_connect_error);
}

static void finish_tcp_socket_use(
    ProxyReactor *reactor,
    TCPConnectSlot *connection,
    void (*continuation)(ProxyReactor *reactor, TCPConnectSlot *connection))
{
    connection->after_socket_watch = continuation;
    outersshpriv_proxy_reactor_cancel_source(&connection->timeout_timer);
#if ENABLE_LOCAL_NETWORK_CONNECT_RETRY
    outersshpriv_proxy_reactor_cancel_source(&connection->retry_timer);
#endif
    if (connection->cancelling_write_source) {
        return;
    }
    if (connection->write_socket_source != NULL) {
        // Keep the slot and descriptor until Dispatch has removed its socket watch.
        connection->cancelling_write_source = true;
        outersshpriv_proxy_reactor_cancel_source(&connection->write_socket_source);
        return;
    }
    connection->after_socket_watch = NULL;
    continuation(reactor, connection);
}

static void tcp_connect_write_source_cancelled(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    ProxyReactor *reactor = context->reactor;
    TCPConnectSlot *connection = &reactor->connect_slots[context->connection.index];
    assert(connection->generation == context->connection.generation);
    assert(connection->cancelling_write_source);
    void (*continuation)(ProxyReactor *, TCPConnectSlot *) = connection->after_socket_watch;
    connection->after_socket_watch = NULL;
    connection->cancelling_write_source = false;
    continuation(reactor, connection);
    outersshpriv_proxy_reactor_source_cancelled(context);
}

static void try_next_address_after_socket_watch(
    ProxyReactor *reactor,
    TCPConnectSlot *connection)
{
    TCPConnectHandle handle = {
        .index = (size_t)(connection - reactor->connect_slots),
        .generation = connection->generation
    };
    close_connect_socket(connection);
    if (connection->current_address != NULL) {
        connection->current_address = connection->current_address->ai_next;
    }
    try_next_tcp_address(reactor, handle, connection);
}

static void hand_off_connected_socket(
    ProxyReactor *reactor,
    TCPConnectSlot *connection)
{
    otsocket_t socket = connection->socket;
    if (otsocket_set_nonblocking(socket, false) != 0) {
        int error = errno;
        complete_tcp_connect_with_error(reactor, connection, (TCPConnectError){
            .code = PROXY_TCP_CONNECTION_FAILED,
            .detail = error,
        });
        return;
    }
    connection->socket = -1;
    SSHSessionCreationOperation *operation = connection->operation;
    release_connect(reactor, connection);
    outersshpriv_session_pool_tcp_connected(operation, socket);
}

static void report_tcp_connect_error(
    ProxyReactor *reactor,
    TCPConnectSlot *connection)
{
    static const char cancelled_message[] = "The SSH operation was cancelled.";

    SSHSessionCreationOperation *operation = connection->operation;
    TCPConnectError failure = connection->completion_error;
    OuterSSHError error;
    char *error_storage = NULL;
    switch (failure.code) {
    case PROXY_TCP_CONNECTION_CANCELLED:
        error = outerssh_session_error(OUTERSSH_SESSION_ERROR_CANCELLED,
            cancelled_message, sizeof(cancelled_message) - 1);
        break;
    case PROXY_TCP_CONNECTION_RESOLUTION_FAILED: {
        const char *reason = gai_strerror(failure.detail);
        error = outerssh_session_error_format(&error_storage,
            OUTERSSH_SESSION_ERROR_UNAVAILABLE,
            "Failed to resolve %.*s:%d: %s (%d).",
            (int)connection->host_length, connection->host,
            connection->port,
            reason == NULL ? "Unknown address resolution error" : reason,
            failure.detail);
        break;
    }
    case PROXY_TCP_CONNECTION_FAILED:
        error = outerssh_session_error_format(&error_storage,
            OUTERSSH_SESSION_ERROR_UNAVAILABLE,
            "Failed to connect to %.*s:%d via %.*s: %s (errno %d).",
            (int)connection->host_length, connection->host,
            connection->port,
            connection->last_address[0] == '\0'
                ? (int)connection->host_length : (int)strlen(connection->last_address),
            connection->last_address[0] == '\0' ? connection->host : connection->last_address,
            failure.detail == 0 ? "Unknown socket error" : strerror(failure.detail),
            failure.detail);
        error.system_error_code = failure.detail;
        break;
    default:
        abort();
    }
    release_connect(reactor, connection);
    outersshpriv_session_pool_tcp_connect_failed(operation, error);
    free(error_storage);
}

#if ENABLE_LOCAL_NETWORK_CONNECT_RETRY
#pragma mark - Retry Local Network Failures

static bool is_local_network_address(const struct addrinfo *address_info)
{
    switch (address_info->ai_family) {
    case AF_INET: {
        const struct sockaddr_in *address =
            (const struct sockaddr_in *)address_info->ai_addr;
        uint32_t host_order = ntohl(address->sin_addr.s_addr);
        uint8_t first = (uint8_t)((host_order >> 24) & 0xff);
        uint8_t second = (uint8_t)((host_order >> 16) & 0xff);
        return first == 10 ||
            (first == 172 && second >= 16 && second <= 31) ||
            (first == 192 && second == 168) ||
            (first == 169 && second == 254);
    }
    case AF_INET6: {
        const struct sockaddr_in6 *address =
            (const struct sockaddr_in6 *)address_info->ai_addr;
        const uint8_t *bytes = address->sin6_addr.s6_addr;
        return (bytes[0] & 0xfe) == 0xfc ||
            (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80);
    }
    default:
        return false;
    }
}

static void finish_tcp_connect_attempt(
    ProxyReactor *reactor,
    TCPConnectHandle handle,
    TCPConnectSlot *connection,
    TCPConnectError error,
    bool is_retryable_route_error)
{
    static const uint64_t retry_delays_nanoseconds[] = {
        500 * NSEC_PER_MSEC,
        1500 * NSEC_PER_MSEC
    };

    clear_connect_addresses(connection);
    if (!is_retryable_route_error) {
        TCPConnectError reported_error =
            connection->has_initial_route_error
            ? connection->initial_route_error
            : error;
        complete_tcp_connect_with_error(reactor, connection, reported_error);
        return;
    }

    if (!connection->has_initial_route_error) {
        connection->initial_route_error = error;
        connection->has_initial_route_error = true;
    }
    connection->latest_route_error = error;
    if (connection->next_retry_index >=
        sizeof(retry_delays_nanoseconds) /
            sizeof(retry_delays_nanoseconds[0])) {
        complete_tcp_connect_with_error(
            reactor,
            connection,
            connection->latest_route_error);
        return;
    }

    size_t retry_index = connection->next_retry_index;
    connection->next_retry_index += 1;
    SSH_LOG_NOTICE(
        SSH_LOG_CATEGORY_SESSION,
        "SSH local network connect to %{public}.*s:%d failed with a route error; retrying attempt %zu of %zu",
        (int)connection->host_length, connection->host,
        connection->port,
        retry_index + 1,
        sizeof(retry_delays_nanoseconds) /
            sizeof(retry_delays_nanoseconds[0]));

    connection->retry_timer = otsource_create(
        OTSOURCE_TYPE_TIMER,
        0,
        reactor->queue);
    if (connection->retry_timer == NULL) {
        complete_tcp_connect_with_error(
            reactor,
            connection,
            connection->latest_route_error);
        return;
    }
    ProxySourceContext *timer_context =
        outersshpriv_proxy_reactor_create_source_context(reactor, connection->retry_timer);
    if (timer_context == NULL) {
        otsource_activate(connection->retry_timer);
        outersshpriv_proxy_reactor_cancel_source(&connection->retry_timer);
        complete_tcp_connect_with_error(
            reactor,
            connection,
            connection->latest_route_error);
        return;
    }
    timer_context->connection = handle;
    otsource_set_context(connection->retry_timer, timer_context);
    otsource_set_cancel_handler(
        connection->retry_timer,
        outersshpriv_proxy_reactor_source_cancelled);
    otsource_set_event_handler(
        connection->retry_timer,
        retry_tcp_connect);
    otsource_set_timer(
        connection->retry_timer,
        ottime(OTTIME_NOW, (int64_t)retry_delays_nanoseconds[retry_index]),
        OTTIME_FOREVER,
        0);
    otsource_activate(connection->retry_timer);
}

static void retry_tcp_connect(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    TCPConnectSlot *connection = connect_for_handle(
        context->reactor,
        context->connection);
    if (connection == NULL) {
        return;
    }
    outersshpriv_proxy_reactor_cancel_source(&connection->retry_timer);
    clear_connect_addresses(connection);
    connection->last_address[0] = '\0';
    connection->last_error = 0;
    connection->saw_local_network_address = false;

    start_tcp_resolution(context->reactor, context->connection, connection);
}

#endif

#pragma mark - Cancel Connections

bool outersshpriv_proxy_reactor_cancel_tcp_connect(
    ProxyReactor *reactor,
    ProxyReactorTCPConnectHandle handle)
{
    otqueue_assert(reactor->queue);
    TCPConnectSlot *connection = connect_for_handle(reactor, handle);
    if (connection == NULL) {
        return false;
    }
    if (connection->cancelling_write_source &&
        connection->after_socket_watch == report_tcp_connect_error &&
        connection->completion_error.code == PROXY_TCP_CONNECTION_CANCELLED) {
        return false;
    }
    complete_tcp_connect_with_error(reactor, connection, (TCPConnectError){
        .code = PROXY_TCP_CONNECTION_CANCELLED,
    });
    return true;
}

void outersshpriv_proxy_reactor_cancel_all_tcp_connects(ProxyReactor *reactor)
{
    for (size_t index = 0; index < reactor->connect_slot_count; index++) {
        TCPConnectSlot *connection = &reactor->connect_slots[index];
        if (!connection->is_active) {
            continue;
        }
        (void)outersshpriv_proxy_reactor_cancel_tcp_connect(reactor, (TCPConnectHandle){
            .index = index,
            .generation = connection->generation
        });
    }
}

#pragma mark - Connection Storage and Address Details

static bool reserve_connect_slots(
    ProxyReactor *reactor,
    size_t minimum_capacity)
{
    if (reactor->connect_slot_capacity >= minimum_capacity) {
        return true;
    }

    size_t capacity = reactor->connect_slot_capacity == 0
        ? 4
        : reactor->connect_slot_capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*reactor->connect_slots)) {
        return false;
    }

    TCPConnectSlot *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL) {
        return false;
    }
    size_t *available_indices = malloc(
        capacity * sizeof(*available_indices));
    if (available_indices == NULL) {
        free(slots);
        return false;
    }

    if (reactor->connect_slot_count != 0) {
        memcpy(slots, reactor->connect_slots, reactor->connect_slot_count * sizeof(*slots));
    }
    if (reactor->available_connect_index_count > 0) {
        memcpy(
            available_indices,
            reactor->available_connect_indices,
            reactor->available_connect_index_count *
                sizeof(*available_indices));
    }

    free(reactor->connect_slots);
    free(reactor->available_connect_indices);
    reactor->connect_slots = slots;
    reactor->available_connect_indices = available_indices;
    reactor->connect_slot_capacity = capacity;
    return true;
}

static TCPConnectSlot *connect_for_handle(
    ProxyReactor *reactor,
    TCPConnectHandle handle)
{
    if (handle.generation == 0 ||
        handle.index >= reactor->connect_slot_count) {
        return NULL;
    }
    TCPConnectSlot *connection = &reactor->connect_slots[handle.index];
    if (!connection->is_active ||
        connection->generation != handle.generation) {
        return NULL;
    }
    return connection;
}

static int set_close_on_exec(otsocket_t socket)
{
    return otsocket_prevent_inheritance(socket) == 0 ? 0 : errno;
}

static void close_connect_socket(TCPConnectSlot *connection)
{
    if (connection->socket < 0) {
        return;
    }
    otsocket_close(connection->socket);
    connection->socket = -1;
}

static void clear_connect_addresses(TCPConnectSlot *connection)
{
    if (connection->addresses != NULL) {
        freeaddrinfo(connection->addresses);
        connection->addresses = NULL;
    }
    connection->current_address = NULL;
}

static void release_connect(
    ProxyReactor *reactor,
    TCPConnectSlot *connection)
{
    size_t index = (size_t)(connection - reactor->connect_slots);
    assert(!connection->cancelling_write_source && connection->write_socket_source == NULL);
    close_connect_socket(connection);
    clear_connect_addresses(connection);
    free(connection->host);
    *connection = (TCPConnectSlot){
        .generation = connection->generation,
        .socket = -1,
    };
    reactor->available_connect_indices[
        reactor->available_connect_index_count] = index;
    reactor->available_connect_index_count += 1;
}
