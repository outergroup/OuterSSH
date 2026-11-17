#ifndef PROXY_REACTOR_H
#define PROXY_REACTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "platform/OTQueue.h"

typedef struct {
    size_t index;
    uint64_t generation;
} ProxyReactorListenerHandle;

typedef struct {
    size_t index;
    uint64_t generation;
} ProxyReactorPendingConnectionHandle;

typedef struct {
    size_t index;
    uint64_t generation;
} ProxyReactorTCPConnectHandle;

typedef enum {
    PROXY_SOCKS_REPLY_SUCCEEDED = 0x00,
    PROXY_SOCKS_REPLY_GENERAL_FAILURE = 0x01,
    PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED = 0x02,
    PROXY_SOCKS_REPLY_NETWORK_UNREACHABLE = 0x03,
    PROXY_SOCKS_REPLY_HOST_UNREACHABLE = 0x04,
    PROXY_SOCKS_REPLY_CONNECTION_REFUSED = 0x05
} ProxySOCKSReplyStatus;

enum {
    PROXY_HOST_CAPACITY = UINT8_MAX + 1,
    PROXY_UNIX_SOCKET_PATH_CAPACITY = 4097,
    PROXY_ORIGIN_CAPACITY = 280
};

typedef struct {
    char host[PROXY_HOST_CAPACITY];
    size_t host_length;
    uint16_t port;
} ProxyConnectRequest;

/* Reports how a direct connection ended: PROXY_SOCKS_REPLY_SUCCEEDED once its
 * socket is connected, otherwise the SOCKS status a client would get.
 * forwarding_denied is set when the SSH server refused forwarding to a TCP
 * destination. */
typedef void (*ProxyDirectConnectionCompletion)(void *context, ProxySOCKSReplyStatus status,
    bool forwarding_denied);

typedef enum {
    PROXY_CONNECTION_ROUTE_TCP,
    PROXY_CONNECTION_ROUTE_UNIX_SOCKET,
    PROXY_CONNECTION_ROUTE_REJECTED
} ProxyConnectionRouteKind;

typedef struct ProxyConnectionRoute {
    ProxyConnectionRouteKind kind;
    ProxyConnectRequest request;
    union {
        struct {
            char host[PROXY_HOST_CAPACITY];
            size_t host_length;
            uint16_t port;
            /* The SSH server itself, by its spelling: localhost or a name
             * under it, 127.0.0.0/8, 0.0.0.0, ::1, ::, or those IPv4
             * addresses mapped into IPv6. Other hosts rank lower. */
            bool loopback;
        } tcp;
        struct {
            char path[PROXY_UNIX_SOCKET_PATH_CAPACITY];
            size_t path_length;
        } unix_socket;
    };
} ProxyConnectionRoute;

typedef enum {
    PROXY_SOCKS_HANDSHAKE_READ_FAILED,
    PROXY_SOCKS_HANDSHAKE_WRITE_FAILED,
    PROXY_SOCKS_HANDSHAKE_TIMED_OUT,
    PROXY_SOCKS_HANDSHAKE_CLIENT_CLOSED,
    PROXY_SOCKS_HANDSHAKE_INVALID_GREETING,
    PROXY_SOCKS_HANDSHAKE_AUTHENTICATION_METHOD_UNAVAILABLE,
    PROXY_SOCKS_HANDSHAKE_AUTHENTICATION_FAILED,
    PROXY_SOCKS_HANDSHAKE_INVALID_REQUEST,
    PROXY_SOCKS_HANDSHAKE_UNSUPPORTED_COMMAND,
    PROXY_SOCKS_HANDSHAKE_UNSUPPORTED_ADDRESS_TYPE
} ProxySOCKSHandshakeErrorCode;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ProxyReactor ProxyReactor;

/*
 * Stateful operations run on the queue passed to outersshpriv_proxy_reactor_create.
 * Asynchronous callbacks also use that queue. Destroy may be called from any
 * queue; reactor storage is released after all Dispatch sources finish
 * cancelling and outstanding DNS lookups return. Pure host and credential
 * helpers have no queue requirement.
 */


ProxyReactor *outersshpriv_proxy_reactor_create(otqueue_t queue);
// Transfers caller ownership to the reactor queue. Final deallocation waits
// for outstanding DNS lookups and dispatch source cancellation handlers. Completion,
// if supplied, runs once on that queue after deallocation.
void outersshpriv_proxy_reactor_destroy(ProxyReactor *reactor, void (*completion)(void *), void *context);

// Cancels a live connection and completes it exactly once with
// OUTERSSH_SESSION_ERROR_CANCELLED. If a write source watches the socket,
// closure and completion wait for its cancellation handler. Otherwise
// completion is synchronous. Stale or already-cancelled handles return false.
bool outersshpriv_proxy_reactor_cancel_tcp_connect(
    ProxyReactor *reactor,
    ProxyReactorTCPConnectHandle handle);

bool outersshpriv_proxy_reactor_remove_listener(
    ProxyReactor *reactor,
    ProxyReactorListenerHandle handle);

void outersshpriv_proxy_reactor_invalidate(ProxyReactor *reactor);

char *outersshpriv_proxy_reactor_create_credential(
    size_t byte_count,
    int32_t *status);

bool outersshpriv_proxy_normalize_host(
    const char *host,
    size_t host_length,
    char output[PROXY_HOST_CAPACITY], size_t *output_length);

// Queues the requested SOCKS failure reply and closes the socket after it has
// drained. Returning false means the handle was stale or already completed.
bool outersshpriv_proxy_reactor_fail_pending_connection(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection,
    ProxySOCKSReplyStatus status);

#ifdef __cplusplus
}
#endif

#endif
