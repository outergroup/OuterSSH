#ifndef PROXY_PENDING_CONNECTIONS_INTERNAL_H
#define PROXY_PENDING_CONNECTIONS_INTERNAL_H

#include "ProxyReactorInternal.h"

typedef struct SOCKSHandshake SOCKSHandshake;
typedef enum {
    PROXY_PENDING_NEGOTIATING,
    PROXY_PENDING_AWAITING_TARGET,
    PROXY_PENDING_REPLYING,
    PROXY_PENDING_CLOSING,
    PROXY_PENDING_TRANSFERRING
} ProxyPendingConnectionPhase;

struct ProxyPendingConnection {
    uint64_t generation;
    OuterSSHSessionPool *pool;
    uint64_t proxy_generation;
    otsocket_t socket;
    ProxyReactorListenerHandle listener;
    otsource_t read_socket_source, write_socket_source, timeout_timer;
    ProxyConnectionRoute route;
    ProxySocketTransferHandler transfer_finished;
    void *transfer_context;
    ProxyPendingConnectionPhase phase;
    size_t uncancelled_socket_source_count;
    ProxyDirectConnectionCompletion direct_completion;
    void *direct_context;
    SOCKSHandshake *socks;
    bool is_active;
    bool forwarding_denied;
    ProxySOCKSReplyStatus failure_status;
};

ProxyReactorPendingConnectionHandle outersshpriv_proxy_pending_connection_allocate(ProxyReactor *reactor, otsocket_t socket);
ProxyPendingConnection *outersshpriv_proxy_pending_connection_for_handle(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle);
bool outersshpriv_proxy_pending_connection_reserve(ProxyReactor *reactor, size_t capacity);
bool outersshpriv_proxy_pending_connection_watch_read(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle, void (*readable)(void *));
void outersshpriv_proxy_pending_connection_monitor(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle, ProxyPendingConnection *connection);
void outersshpriv_proxy_pending_connection_transfer(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle);
void outersshpriv_proxy_pending_connection_close(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle);
void outersshpriv_proxy_pending_connection_source_cancelled(void *context);
void outersshpriv_proxy_reactor_start_forwarded_connection(ProxyReactor *reactor,
    ProxyReactorListenerHandle listener, otsocket_t socket, ProxyConnectionRoute route);

void outersshpriv_socks_handshake_destroy(SOCKSHandshake *socks, otsocket_t socket);
/* Returns true when the client authenticated with origin credentials, setting
 * their normalized, NUL-terminated web origin. */
bool outersshpriv_socks_handshake_origin(const SOCKSHandshake *socks, const char **origin, size_t *origin_length);
void outersshpriv_socks_pending_connection_ready(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle);
bool outersshpriv_socks_pending_connection_failed(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle, ProxySOCKSReplyStatus status);
void outersshpriv_socks_pending_connection_read_failed(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle, bool closed, int error);

#endif
