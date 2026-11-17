#ifndef OUTERSSH_HTTP_PROXY_SERVER_H
#define OUTERSSH_HTTP_PROXY_SERVER_H

#include "ProxyTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

typedef struct OuterSSHHTTPProxyServer OuterSSHHTTPProxyServer;
typedef struct {
    const OuterSSHProxyCredentials * OT_NULLABLE credentials;
    OuterSSHProxyAuthentication authentication;
    const char * OT_NULLABLE realm;
    size_t realm_length;
    /* Translates TCP aliases to their destinations in
     * Host/Origin/Referer/Sec-WebSocket-Origin headers, restoring matching
     * Access-Control-Allow-Origin values to the original Origin. Socket hosts
     * pass through. Also rewrites literal loopback URLs in eligible HTML
     * responses from encoded endpoints to their aliases. When false, response
     * bodies stream without rewrite inspection or buffering. */
    bool rewrite_loopback_addresses;
} OuterSSHHTTPProxyServerConfiguration;

/* Creates an HTTP server forwarding through pool. Password authentication is the default: NULL
 * credentials are generated; supplied ones are copied.
 * Supplied usernames and passwords must each contain 1-255 bytes.
 * No authentication requires NULL credentials and returns empty ones.
 * The listening port is supplied to start.
 * The pool must remain alive until the server is destroyed.
 * Returned error text remains valid for the process lifetime.
 * HTTP usernames cannot contain ':'. Realm is copied using realm_length bytes;
 * no terminator is required. NULL with length 0 uses "OuterSSH". An explicit
 * realm must be shorter than 256 bytes and contain no controls, '"', or '\\'.
 * HTTP/1.1 exchanges are framed independently; 101 becomes a raw tunnel.
 * With rewriting enabled, plaintext HTTP/1.1 inside CONNECT is framed too.
 * HTTPS inside CONNECT is not inspected. */
OuterSSHHTTPProxyServer * OT_NULLABLE outerssh_http_proxy_server_create(
    OuterSSHSessionPool *pool,
    const OuterSSHHTTPProxyServerConfiguration * OT_NULLABLE configuration,
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
bool outerssh_http_proxy_server_start(OuterSSHHTTPProxyServer *server, uint16_t preferred_port, uint64_t tag);
bool outerssh_http_proxy_server_stop(OuterSSHHTTPProxyServer *server, uint64_t tag);
/* Queues shutdown after previously submitted operations, then frees the server
 * once all asynchronous forwarding stages and recovery work have finished.
 * OUTERSSH_EVENT_DESTROYED follows after the server is freed and its reactor
 * has closed its sockets, cancelled its sources, and finished DNS lookups.
 * Pools remain independently owned; destroying the server does not destroy them.
 * No further calls may use the server after destroy is called. Finish
 * submitting calls on other queues before destroy. */
bool outerssh_http_proxy_server_destroy(OuterSSHHTTPProxyServer *server, uint64_t tag);

/* Origin credentials identify content that is not a web page, as for
 * outerssh_socks_proxy_server_add_origin_credentials, which describes what
 * each origin may reach. Each request made with them is decided by that
 * origin and the request's destination, never by anything else the client
 * sends: a CONNECT tunnel when it opens, then relayed untouched; any other
 * request on its own, with its own Proxy-Authorization, and without HTTP
 * rewriting. Other destinations get 403 Forbidden. Usernames cannot contain
 * ':'. Copies its arguments and completes with
 * OUTERSSH_EVENT_OPERATION_COMPLETED. */
bool outerssh_http_proxy_server_add_origin_credentials(OuterSSHHTTPProxyServer *server,
    const char *username, size_t username_length, const char *password, size_t password_length,
    const char *origin, size_t origin_length, uint64_t tag);
/* Removes origin credentials. Tunnels already opened with them continue;
 * later requests made with them are refused. Unknown usernames do nothing.
 * Completes with OUTERSSH_EVENT_OPERATION_COMPLETED. */
bool outerssh_http_proxy_server_remove_origin_credentials(OuterSSHHTTPProxyServer *server,
    const char *username, size_t username_length, uint64_t tag);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif
#endif
