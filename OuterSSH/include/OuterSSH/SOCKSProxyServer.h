#ifndef OUTERSSH_SOCKS_PROXY_SERVER_H
#define OUTERSSH_SOCKS_PROXY_SERVER_H

#include "ProxyTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

typedef struct OuterSSHSOCKSProxyServer OuterSSHSOCKSProxyServer;
typedef struct {
    const OuterSSHProxyCredentials * OT_NULLABLE credentials;
    OuterSSHProxyAuthentication authentication;
    /* Every SOCKS server inspects streams made with its own credentials.
     * Streams to Unix sockets, named pipes and the SSH server's loopback ports
     * are parsed as HTTP/1.1 so the zone rule HTTP listeners apply to pages
     * governs each request; streams to other hosts stay byte-transparent
     * unless rewrite_loopback_addresses is set, which parses HTTP/1.1 on them
     * too and applies the same rewriting as HTTP CONNECT. Upgrades pass through
     * once allowed. Streams made with origin credentials are neither parsed nor
     * rewritten; see below. */
    bool rewrite_loopback_addresses;
} OuterSSHSOCKSProxyServerConfiguration;

/* Creates a SOCKS server forwarding through pool. Password authentication is the default: NULL
 * credentials are generated; supplied ones are copied.
 * Supplied usernames and passwords must each contain 1-255 bytes.
 * No authentication requires NULL credentials and returns empty ones.
 * The listening port is supplied to start.
 * The pool must remain alive until the server is destroyed.
 * Returned error text remains valid for the process lifetime. */
OuterSSHSOCKSProxyServer * OT_NULLABLE outerssh_socks_proxy_server_create(
    OuterSSHSessionPool *pool,
    const OuterSSHSOCKSProxyServerConfiguration * OT_NULLABLE configuration,
    OuterSSHError * OT_NULLABLE error);
/* Start completes with OUTERSSH_EVENT_PROXY_STARTED; stop with
 * OUTERSSH_EVENT_OPERATION_COMPLETED. Operations are serialized in submission
 * order.
 * Start is idempotent for the current port (or port 0). It repairs an invalidated
 * listening socket without closing existing streams. A stop during repair
 * cancels the pending starts. Failed starts can be retried.
 * Stop closes the listener, cancels pending connections, and schedules closure
 * of this server's streams.
 * The pool remains usable and the server can restart. */
bool outerssh_socks_proxy_server_start(OuterSSHSOCKSProxyServer *server, uint16_t preferred_port, uint64_t tag);
bool outerssh_socks_proxy_server_stop(OuterSSHSOCKSProxyServer *server, uint64_t tag);
/* Queues shutdown after previously submitted operations, then frees the server
 * once all asynchronous forwarding stages and recovery work have finished.
 * OUTERSSH_EVENT_DESTROYED follows after the server is freed and its reactor
 * has closed its sockets, cancelled its sources, and finished DNS lookups.
 * Pools remain independently owned; destroying the server does not destroy them.
 * No further calls may use the server after destroy is called. Finish
 * submitting calls on other queues before destroy. */
bool outerssh_socks_proxy_server_destroy(OuterSSHSOCKSProxyServer *server, uint64_t tag);

/* Origin credentials identify content that is not a web page, such as an
 * Outerframe, by the web origin it was loaded from: a serialized origin,
 * scheme://host[:port] with an http or https scheme, such as
 * http://<encoded>.unix.outerssh.localhost for a socket. Connections made
 * with them are decided when they open, by that origin and the destination,
 * never by anything else the client sends: content from the SSH server reaches every
 * TCP destination, its own socket, and sockets with its socket's owner;
 * content from root's sockets reaches every socket, and content from a
 * loopback port has no owner, so it reaches no socket. Content from another
 * host reaches only that host and port. Other destinations are refused at the
 * SOCKS level with
 * "connection not allowed". An allowed connection's bytes are relayed
 * untouched, without HTTP parsing or rewriting. Usernames and passwords contain 1-255 bytes,
 * and a username must differ from the server's own. Adding a username again
 * replaces it. Requires password authentication; returns false otherwise or
 * for a malformed origin. Copies its arguments and completes with
 * OUTERSSH_EVENT_OPERATION_COMPLETED. */
bool outerssh_socks_proxy_server_add_origin_credentials(OuterSSHSOCKSProxyServer *server,
    const char *username, size_t username_length, const char *password, size_t password_length,
    const char *origin, size_t origin_length, uint64_t tag);
/* Removes origin credentials. Connections already made with them continue.
 * Unknown usernames do nothing. Completes with OUTERSSH_EVENT_OPERATION_COMPLETED. */
bool outerssh_socks_proxy_server_remove_origin_credentials(OuterSSHSOCKSProxyServer *server,
    const char *username, size_t username_length, uint64_t tag);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif
#endif
