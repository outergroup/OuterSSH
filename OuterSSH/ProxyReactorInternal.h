#ifndef PROXY_REACTOR_INTERNAL_H
#define PROXY_REACTOR_INTERNAL_H

#include "platform/OTSocket.h"

#include "ProxyReactor.h"
#include "SSHProxyError.h"

typedef struct SSHSessionCreationOperation SSHSessionCreationOperation;
typedef void (*ProxySocketTransferHandler)(void *context, otsocket_t socket);

typedef struct ProxySourceContext ProxySourceContext;

typedef struct ListenerSlot {
    uint64_t generation;
    otsocket_t socket;
    otsource_t accept_source;
    ProxySourceContext *accept_context;
    unsigned char *username;
    size_t username_length;
    unsigned char *password;
    size_t password_length;
    uint64_t pending_connection_timeout_milliseconds;
    ProxyConnectionRoute forward_route;
    bool requires_authentication;
    bool is_active;
} ListenerSlot;

typedef struct ProxyPendingConnection ProxyPendingConnection;
typedef struct TCPConnectSlot TCPConnectSlot;

typedef struct SSHForwarder SSHForwarder;
typedef struct OuterSSHSessionPool OuterSSHSessionPool;

struct ProxyReactor {
    SSHForwarder *server;
    size_t pending_source_cancellations;
    size_t pending_tcp_resolutions;
    otqueue_t queue;
    ListenerSlot *listener_slots;
    size_t listener_slot_count;
    size_t listener_slot_capacity;
    size_t *available_listener_indices;
    size_t available_listener_index_count;
    ProxyPendingConnection *pending_connections;
    size_t pending_connection_count;
    size_t pending_connection_capacity;
    size_t *available_pending_connection_indices;
    size_t available_pending_connection_index_count;
    TCPConnectSlot *connect_slots;
    size_t connect_slot_count;
    size_t connect_slot_capacity;
    size_t *available_connect_indices;
    size_t available_connect_index_count;
    bool invalidated;
    bool destroy_started;
    void (*destruction_completion)(void *);
    void *destruction_context;
};

struct ProxySourceContext {
    ProxyReactor *reactor;
    otsource_t source;
    ProxyReactorListenerHandle listener;
    ProxyReactorPendingConnectionHandle pending_connection;
    ProxyReactorTCPConnectHandle connection;
    uint64_t attempt_generation;
    otsocket_t socket_to_close;
    void (*closed)(void *);
    void *closed_context;
};

void outersshpriv_proxy_reactor_start_direct_connection(ProxyReactor *reactor, otsocket_t socket,
    ProxyConnectionRoute route, ProxyDirectConnectionCompletion completion, void *context);

void outersshpriv_proxy_server_pending_connection(SSHForwarder *server,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route);
/* Reactor queue only. Returns true when the credentials are one of the
 * server's origin credentials, with a malloc'd, NUL-terminated copy of their
 * normalized web origin in *origin that the caller frees. */
bool outersshpriv_proxy_server_origin_for_credentials(SSHForwarder *server,
    const unsigned char *username, size_t username_length, const unsigned char *password, size_t password_length,
    char **origin, size_t *origin_length);
/* Like outersshpriv_proxy_server_origin_for_credentials, for the base64
 * credentials of a Basic Proxy-Authorization header. */
bool outersshpriv_proxy_server_origin_for_basic_authorization(SSHForwarder *server, const char *encoded,
    char **origin, size_t *origin_length);
/* Exactly once, including immediate rejection. A valid socket transfers ownership;
 * -1 reports failure. Completion runs on the reactor queue, possibly inline. */
void outersshpriv_proxy_reactor_transfer_pending_connection(ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection,
    ProxySocketTransferHandler finished, void *context);
void outersshpriv_proxy_reactor_set_connection_pool(ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection, OuterSSHSessionPool *pool, uint64_t proxy_generation);
void outersshpriv_proxy_reactor_cancel_pool_pending_connections(ProxyReactor *reactor, OuterSSHSessionPool *pool, uint64_t proxy_generation);

/* Reactor queue only. Destruction waits for socket sources and DNS work. */
void outersshpriv_proxy_reactor_finish_destroy(ProxyReactor *reactor);
void outersshpriv_proxy_reactor_cancel_source(otsource_t *source);
ProxySourceContext *outersshpriv_proxy_reactor_create_source_context(
    ProxyReactor *reactor, otsource_t source);
void outersshpriv_proxy_reactor_source_cancelled(void *context);
void outersshpriv_proxy_reactor_cancel_all_tcp_connects(ProxyReactor *reactor);
ListenerSlot *outersshpriv_proxy_reactor_listener_for_handle(
    ProxyReactor *reactor, ProxyReactorListenerHandle handle);
ProxyConnectionRoute outersshpriv_proxy_resolve_request(
    ProxyConnectRequest request);
/* Parses a serialized web origin, scheme://host[:port] with an http or https
 * scheme, and writes its normalized form: lowercase, without a default port.
 * Sets *route to where the origin's host resolves; socket hosts must use http.
 * Returns false for malformed origins and hosts the proxy rejects. */
bool outersshpriv_proxy_parse_origin(const char *origin, size_t origin_length,
    char normalized[PROXY_ORIGIN_CAPACITY], size_t *normalized_length, ProxyConnectionRoute *route);
void outersshpriv_proxy_reactor_accept_connections(
    ProxyReactor *reactor, ProxyReactorListenerHandle handle);
void outersshpriv_proxy_reactor_cancel_pending_connections_for_listener(
    ProxyReactor *reactor, ProxyReactorListenerHandle handle);
void outersshpriv_proxy_reactor_cancel_all_pending_connections(ProxyReactor *reactor);
void outersshpriv_proxy_reactor_remove_all_listeners(ProxyReactor *reactor);

void outersshpriv_session_pool_tcp_connected(
    SSHSessionCreationOperation *operation,
    otsocket_t socket);
void outersshpriv_session_pool_tcp_connect_failed(
    SSHSessionCreationOperation *operation,
    OuterSSHError error);

// A successful completion transfers ownership of its nonnegative socket to
// the session creation operation. Every started operation completes exactly
// once. A zero-generation handle means no cancellable operation was installed.
ProxyReactorTCPConnectHandle outersshpriv_proxy_reactor_connect_tcp(
    ProxyReactor *reactor,
    const char *host,
    size_t host_length,
    int32_t port,
    SSHSessionCreationOperation *operation);


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
    uint64_t pending_connection_timeout_milliseconds);

OuterSSHError outersshpriv_proxy_reactor_reopen_listener(
    ProxyReactor *reactor, ProxyReactorListenerHandle handle, int port);
/* Keeps the listener handle and accepted connections alive. Calls closed on the
 * control queue after source cancellation has closed the listening socket. */
void outersshpriv_proxy_reactor_close_listener_socket(ProxyReactor *reactor,
    ProxyReactorListenerHandle handle, void (*closed)(void *), void *context);

/* For SOCKS connections, sends success before transferring. The socket stays in
 * the reactor until any reply drains and all socket sources cancel. Calls finished
 * exactly once, including immediate rejection; a nonnegative socket transfers ownership and
 * -1 reports failure or cancellation. */
void outersshpriv_proxy_reactor_complete_pending_connection(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection,
    ProxySocketTransferHandler finished, void *context);

bool outersshpriv_proxy_reactor_pending_connection_is_active(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection);

#endif
