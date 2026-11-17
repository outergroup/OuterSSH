#ifndef SSH_FORWARDER_H
#define SSH_FORWARDER_H
#include "SSHContinuations.h"
#include "include/OuterSSH/ProxyTypes.h"
#include "ProxyTypes.h"
typedef struct SSHForwarder SSHForwarder;
typedef struct SSHForwarderStartContext SSHForwarderStartContext;
typedef struct SSHOriginCredentials SSHOriginCredentials;
#include "SSHProxyState.h"

OT_ASSUME_NONNULL_BEGIN

struct SSHForwarder {
    otqueue_t queue;
    ProxyReactor *reactor;
    ProxyReactorListenerHandle listener;
    OuterSSHSessionPool *pool;
    /* The public object that owns this forwarder, reported in events. */
    const void *frontend;
    struct SSHForwarder *next_in_pool;
    uint64_t generation;
    char *username;
    size_t username_length;
    char *password;
    size_t password_length;
    int32_t port;
    ProxyConnectionRoute forward_route;
    bool requires_authentication;
    bool direct;
    void (*accept_tunnel)(void *, ProxyReactorPendingConnectionHandle, ProxyConnectionRoute);
    void *tunnel_context;
    bool running;
    bool listener_repair_pending;
    SSHForwarderStartContext *start_head, *start_tail;
    bool destroy_requested;
    void (*destruction_completion)(void *);
    void *destruction_context;
    size_t pending_work;
    SSHOriginCredentials *origin_credentials;
    size_t origin_credential_count;
};

void outersshpriv_proxy_connection_begin_work(SSHProxyConnection connection);
void outersshpriv_proxy_connection_end_work(SSHProxyConnection connection);
SSHProxyConnection outersshpriv_proxy_active_connection(SSHProxyConnection connection);
bool outersshpriv_proxy_connection_is_active(SSHProxyConnection connection);
void outersshpriv_proxy_server_begin_work(SSHForwarder *server);
void outersshpriv_proxy_server_end_work(SSHForwarder *server);
bool outersshpriv_proxy_pool_has_generation(OuterSSHSessionPool *pool, uint64_t generation);
SSHForwarder * OT_NULLABLE outersshpriv_forwarder_create(
    OuterSSHSessionPool *pool,
    bool requires_authentication, const OuterSSHProxyCredentials * OT_NULLABLE credentials,
    OuterSSHError * OT_NULLABLE error);
/* A forwarder whose listener relays every connection to host:port through the pool. */
SSHForwarder * OT_NULLABLE outersshpriv_tcp_forwarder_create(OuterSSHSessionPool *pool,
    const char *host, size_t host_length, uint16_t port, OuterSSHError * OT_NULLABLE error);
/* Control queue only. Starts or resumes forwarding through the fixed pool. */
OuterSSHError outersshpriv_forwarder_listen(SSHForwarder *server, int32_t port);
/* Control queue only. Starts forwarding connections passed to
 * outersshpriv_forwarder_connect, without a listener. */
void outersshpriv_forwarder_activate(SSHForwarder *server);

/* Operations behind the frontends' start and stop requests. Each sends the
 * reply its frontend reserved: OUTERSSH_EVENT_PROXY_STARTED for start,
 * OUTERSSH_EVENT_OPERATION_COMPLETED for stop. Stop closes this frontend's
 * streams; it can restart. */
void outersshpriv_forwarder_start(SSHForwarder *server, int32_t preferred_port, SSHPoolEvent *reply);
void outersshpriv_forwarder_stop(SSHForwarder *server, SSHPoolEvent *reply);
/* Queues shutdown after previously submitted operations, then frees the server
 * once all asynchronous forwarding stages and recovery callbacks have finished.
 * If supplied, completion runs exactly once on the control queue, asynchronously
 * after the server is freed, owned-context destructors have run, and its reactor
 * has closed its sockets, cancelled its sources, and finished DNS lookups.
 * The pool remains independently owned; destroying the server does not destroy it.
 * No further calls may use the server after destroy is called, including from
 * pending completions. Finish submitting calls on other queues before destroy. */
void outersshpriv_forwarder_destroy(SSHForwarder *server,
    SSHDestroyHandler OT_NULLABLE completion, void * OT_NULLABLE context);
/* Control queue only. Adds or replaces credentials for content loaded from a
 * web origin normalized by outersshpriv_proxy_parse_origin, or removes them
 * when password is NULL. */
/* Validates and copies origin credentials, then sets them on the control queue
 * and completes with OUTERSSH_EVENT_OPERATION_COMPLETED. A NULL password
 * removes them. Returns false without an event for invalid input. */
bool outersshpriv_forwarder_submit_origin_credentials(SSHForwarder *forwarder,
    const char *username, size_t username_length, const char * OT_NULLABLE password, size_t password_length,
    const char * OT_NULLABLE origin, size_t origin_length, uint64_t tag);
OuterSSHError outersshpriv_forwarder_set_origin_credentials(SSHForwarder *server,
    const char *username, size_t username_length, const char * OT_NULLABLE password, size_t password_length,
    const char * OT_NULLABLE origin, size_t origin_length);


struct OuterSSHSOCKSProxyServer;
SSHForwarder *outersshpriv_socks_proxy_server_forwarder(struct OuterSSHSOCKSProxyServer *server);

struct OuterSSHHTTPProxyServer;
struct OuterSSHHTTPProxyServer *outersshpriv_inspected_socks_create(
    OuterSSHSessionPool *pool, const OuterSSHProxyCredentials * OT_NULLABLE credentials,
    OuterSSHProxyAuthentication authentication, bool rewrite_loopback_addresses,
    OuterSSHError * OT_NULLABLE error);
SSHForwarder *outersshpriv_inspected_socks_forwarder(struct OuterSSHHTTPProxyServer *server);
/* The HTTP server's operations, also used by the inspected SOCKS frontend. Each
 * sends the reply the frontend reserved. */
void outersshpriv_http_proxy_start(struct OuterSSHHTTPProxyServer *server, int32_t preferred_port,
    SSHPoolEvent *reply);
void outersshpriv_http_proxy_stop(struct OuterSSHHTTPProxyServer *server, SSHPoolEvent *reply);
void outersshpriv_http_proxy_destroy(struct OuterSSHHTTPProxyServer *server, SSHPoolEvent *reply);

/* Control queue only. HTTP owns its listener and shares forwarding state. */
void outersshpriv_forwarder_stop_on_queue(SSHForwarder *server);
void outersshpriv_forwarder_destroy_on_queue(SSHForwarder *server,
    SSHDestroyHandler OT_NULLABLE completion, void * OT_NULLABLE context);
typedef struct {
    ProxySOCKSReplyStatus status;
    bool forwarding_denied;
    /* The sender may not reach the destination, or may not through sudo. */
    bool refused;
} SSHForwarderConnectionResult;

typedef void (*SSHForwarderConnectionCompletion)(void *context, SSHForwarderConnectionResult result);

/* Control queue only; completion may run inline on allocation failure. The
 * sender is judged once the destination socket's owner is known and before
 * the connection uses sudo; a refused connection fails without posting
 * OUTERSSH_EVENT_CONNECTION_FAILED. */
void outersshpriv_forwarder_connect(SSHForwarder *server, otsocket_t socket, const char *host, size_t host_length, uint16_t port,
    SSHSocketSender sender, SSHForwarderConnectionCompletion completion, void *context);
/* Control queue only. Whether the sender of a connection started by
 * outersshpriv_forwarder_connect may reach a socket with this owner, through
 * sudo when uses_sudo is set; other connections have no sender to judge. A
 * refusal is reported to the connection's completion, which the caller
 * triggers by failing the pending connection. */
bool outersshpriv_forwarder_connection_permits(SSHForwarder *server,
    ProxyReactorPendingConnectionHandle connection, const SSHSocketOwner *destination, bool uses_sudo);

OT_ASSUME_NONNULL_END
#endif
