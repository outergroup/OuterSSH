#include "platform/OTSocket.h"
#include "SSHProxyErrorInternal.h"
#include "platform/OTSocketPair.h"
#include "SSHForwarder.h"
#include "SSHEventsInternal.h"
#include "platform/OTQueue.h"
#include "include/OuterSSH/HTTPProxyServer.h"
#include "HTTPProxyRewriter.h"
#include "ProxyReactorInternal.h"
#include "ProxyPendingConnectionsInternal.h"
#include "SSHProxyAddress.h"
#include "llhttp/llhttp.h"
#include "platform/Base64.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define HEADER_LIMIT (64 * 1024)
#define WATERMARK (256 * 1024)
#define BUFFER_LIMIT (9 * 1024 * 1024)

typedef struct {
    char *data;
    size_t size, capacity;
} HTTPBuffer;
typedef struct HTTPClient HTTPClient;
typedef struct HTTPPeer HTTPPeer;

typedef struct {
    HTTPBuffer name, value;
} HTTPHeaderField;

typedef struct {
    llhttp_t parser;
    HTTPHeaderField fields[256];
    size_t count, header_size;
    HTTPBuffer target;
    HTTPClient *client;
    bool response, complete, headers, chunked, keepalive;
} HTTPMessage;

typedef struct HTTPServerStartContext {
    OuterSSHHTTPProxyServer *server;
    int32_t port;
    SSHPoolEvent *reply;
    struct HTTPServerStartContext *next;
} HTTPServerStartContext;

typedef struct {
    OuterSSHHTTPProxyServer *server;
    otsocket_t socket;
    otsource_t source;
} HTTPListener;

struct OuterSSHHTTPProxyServer {
    otqueue_t queue;
    SSHForwarder *forwarder;
    HTTPListener *listener;
    HTTPListener *closing_listener;
    HTTPServerStartContext *start_head, *start_tail;
    HTTPClient *clients;
    size_t references, client_count;
    bool rewrite_loopback_addresses;
    bool socks;
    char *authorization, *realm;
    size_t realm_length;
    SSHPoolEvent *destroyed_reply;
};

struct HTTPPeer {
    HTTPClient *client;
    otsocket_t socket;
    otsource_t read, write;
    HTTPBuffer input, output;
    unsigned sources;
    int index;
    bool reading, writing, eof, half_closed, cancelled;
};

typedef enum {
    HTTP_IDLE,
    HTTP_CONNECTING,
    HTTP_RELAY,
    HTTP_DETECT,
    HTTP_TUNNEL,
    HTTP_REJECT
} HTTPClientPhase;

struct HTTPClient {
    OuterSSHHTTPProxyServer *server;
    HTTPClient *next, *previous;
    HTTPPeer *peers[2];
    HTTPMessage request, response;
    HTTPBuffer pending;
    HTTPProxyRewriter *rewriter;
    otsource_t timer;
    size_t references;
    HTTPClientPhase phase;
    ProxyConnectRequest destination, upstream;
    SSHForwarderConnectionResult connection_result;
    bool socks_reply_pending;
    bool closed, busy, request_close, connect, upgrade, head, response_body, tunneled;
    bool response_started, response_done, upstream_keepalive;
    bool ownership_pending;
    SSHSocketSender sender;
    bool origin_credentials;
    char *origin_socket_path;
    size_t origin_socket_path_length;
    bool origin_elsewhere;
    ProxyConnectRequest origin_host;
};

typedef enum {
    CREDENTIAL_ACCESS_ALLOWED,
    CREDENTIAL_ACCESS_PENDING,
    CREDENTIAL_ACCESS_REFUSED
} CredentialAccess;


typedef struct {
    OuterSSHHTTPProxyServer *server;
    SSHPoolEvent *reply;
} HTTPServerDestroyContext;

typedef struct {
    OuterSSHHTTPProxyServer *server;
    SSHPoolEvent *reply;
} HTTPServerStopContext;

static void initialize_server(void *context);
static void free_server(void *context);
static OuterSSHError http_error(const char *message);
static void start_server(void *context);
static OuterSSHError start_listener(OuterSSHHTTPProxyServer *server, int32_t port);
static void accept_clients(void *context);
static HTTPClient *create_client(OuterSSHHTTPProxyServer *server, otsocket_t socket);
static void accept_socks_tunnel(void *context, ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route);
static HTTPPeer *peer_create(HTTPClient *client, int index, otsocket_t socket, bool tcp);
static void initialize_message(HTTPMessage *message, HTTPClient *client, bool response);
static void peer_became_readable(void *context);
static void peer_became_writable(void *context);
static void update_downstream_sources(HTTPClient *client);
static void update_upstream_sources(HTTPClient *client);
static void half_close_drained_tunnel_peers(HTTPClient *client);
static bool close_client_if_finished(HTTPClient *client);
static void process_client_input(HTTPClient *client);
static void parse_message(HTTPClient *client, HTTPMessage *message, HTTPBuffer *input);
static int on_target(llhttp_t *parser, const char *bytes, size_t size);
static int on_field(llhttp_t *parser, const char *bytes, size_t size);
static int on_value(llhttp_t *parser, const char *bytes, size_t size);
static int on_value_complete(llhttp_t *parser);
static int on_headers(llhttp_t *parser);
static bool valid_framing(HTTPMessage *message);
static bool parse_destination(HTTPClient *client, const char *target, const char **path);
static bool same_destination(const ProxyConnectRequest *a, const ProxyConnectRequest *b);
static bool create_exchange_rewriter(HTTPClient *client);
static bool serialize_headers(
    HTTPMessage *message, HTTPBuffer *output, HTTPProxyRewriter *rewriter, bool has_body);
static bool serialize_header(void *context, const char *name, const char *value);
static int on_body(llhttp_t *parser, const char *bytes, size_t size);
static void upstream_output(void *context, const void *bytes, size_t size);
static void downstream_body(void *context, const void *bytes, size_t size);
static bool append_body_chunk(HTTPBuffer *buffer, const void *bytes, size_t size);
static int on_complete(llhttp_t *parser);
static void finish_exchange(HTTPClient *client);
static bool connect_upstream(HTTPClient *client);
static SSHSocketSender upstream_sender(HTTPClient *client);
static void upstream_connection_finished(void *context, SSHForwarderConnectionResult result);
static void apply_upstream_connection_result(void *context);
static void await_first_request(HTTPClient *client);
static void reply_to_socks_request(HTTPClient *client, ProxySOCKSReplyStatus status);
static void reject_request(HTTPClient *client, int status, const char *reason);
static bool destination_is_socket(HTTPClient *client);
static bool destination_is_loopback(HTTPClient *client);
static bool destination_is_session_owned(HTTPClient *client);
static bool ownership_allows(HTTPClient *client);
static int ownership_verdict(HTTPClient *client, HTTPMessage *message, llhttp_method_t method,
    const ProxyConnectionRoute *route);
static bool use_origin_credentials(HTTPClient *client, const char *origin, size_t origin_length);
static void forget_origin_credentials(HTTPClient *client);
static bool authorize_request(HTTPClient *client, HTTPMessage *message);
static CredentialAccess credential_access(HTTPClient *client);
static SSHSocketSender origin_sender(HTTPClient *client);
static void reset_deadline(HTTPClient *client);
static void timeout_client(void *context);
static void stop_server(void *context);
static void stop_listening(OuterSSHHTTPProxyServer *server);
static void destroy_server(void *context);
static void listener_cancelled(void *context);
static void client_close(HTTPClient *client);
static void peer_cancel(HTTPPeer *peer);
static void peer_cancelled(void *context);
static void timer_cancelled(void *context);
static void client_release(HTTPClient *client);
static void server_release(OuterSSHHTTPProxyServer *server);
static void clear_message_fields(HTTPMessage *message);
static const char *header_value(HTTPMessage *message, const char *name);
static bool is_hop_by_hop_header(HTTPMessage *message, const char *name);
static bool connection_has_token(HTTPMessage *message, const char *name);
static bool header_has_token(const char *list, const char *name);
static void queue_bytes(HTTPClient *client, HTTPBuffer *buffer, const void *bytes, size_t size);
static bool append_bytes(HTTPBuffer *buffer, const void *data, size_t size);
static bool append_text(HTTPBuffer *buffer, const char *text);
static void consume_bytes(HTTPBuffer *buffer, size_t n);
static void clear_buffer(HTTPBuffer *buffer);
static void destroy_buffer(HTTPBuffer *buffer);
static void set_source_enabled(otsource_t source, bool *enabled, bool wanted);

#pragma mark - Create and Configure the HTTP Proxy

static OuterSSHHTTPProxyServer *create_server(OuterSSHSessionPool *pool,
    const OuterSSHHTTPProxyServerConfiguration *configuration, bool socks, OuterSSHError *error)
{
    if (error) {
        *error = (OuterSSHError){0};
    }
    if (!configuration || !pool) {
        if (error) {
            *error = http_error("An SSH session pool is required.");
        }
        return NULL;
    }
    OuterSSHHTTPProxyServer *server = calloc(1, sizeof(*server));
    if (!server) {
        if (error) {
            *error = http_error("Could not allocate HTTP proxy.");
        }
        return NULL;
    }
    server->references = 1;
    server->socks = socks;
    server->rewrite_loopback_addresses = configuration->rewrite_loopback_addresses;
    static const char default_realm[] = "OuterSSH";
    const char *realm = configuration->realm;
    size_t realm_length = configuration->realm_length;
    bool valid = realm != NULL || realm_length == 0;
    if (realm == NULL && realm_length == 0) {
        realm = default_realm;
        realm_length = sizeof(default_realm) - 1;
    }
    valid = valid && realm_length < 256;
    if (valid) {
        for (size_t i = 0; i < realm_length; i++) {
            unsigned char byte = (unsigned char)realm[i];
            if (byte < 32 || byte == 127 || byte == '"' || byte == '\\') {
                valid = false;
                break;
            }
        }
    }
    if (valid) {
        server->realm = malloc(realm_length == 0 ? 1 : realm_length);
        valid = server->realm != NULL;
        if (valid) {
            if (realm_length) memcpy(server->realm, realm, realm_length);
            server->realm_length = realm_length;
        }
    }
    const OuterSSHProxyCredentials *credentials = configuration->credentials;
    bool authenticated = configuration->authentication == OUTERSSH_PROXY_AUTHENTICATION_PASSWORD;
    valid = valid && (authenticated || configuration->authentication == OUTERSSH_PROXY_AUTHENTICATION_NONE);
    if (!socks && credentials && credentials->username && credentials->username_length <= UINT8_MAX &&
        memchr(credentials->username, ':', credentials->username_length)) {
        valid = false;
    }
    if (authenticated) {
        /* Credentials are at most 255 bytes each; base64 includes a final NUL. */
        server->authorization = malloc(7 + 4 * ((255 + 1 + 255 + 2) / 3));
        valid = valid && server->authorization != NULL;
    }
    if (!valid) {
        if (error) *error = http_error("Invalid HTTP proxy configuration or allocation failure.");
        free_server(server);
        return NULL;
    }
    server->forwarder = outersshpriv_forwarder_create(pool, authenticated, credentials, error);
    if (!server->forwarder) {
        free_server(server);
        return NULL;
    }
    SSHForwarder *forwarder = server->forwarder;
    server->queue = forwarder->queue;
    otqueue_retain(server->queue);
    forwarder->direct = !socks;
    if (socks) {
        forwarder->accept_tunnel = accept_socks_tunnel;
        forwarder->tunnel_context = server;
    }
    if (authenticated) {
        unsigned char plain[255 + 1 + 255];
        memcpy(plain, forwarder->username, forwarder->username_length);
        plain[forwarder->username_length] = ':';
        memcpy(plain + forwarder->username_length + 1, forwarder->password, forwarder->password_length);
        memcpy(server->authorization, "Basic ", 6);
        outerssh_base64_encode((unsigned char *)server->authorization + 6, plain,
            (int)(forwarder->username_length + 1 + forwarder->password_length));
    }
    otqueue_async(server->queue, server, initialize_server);
    return server;
}

OuterSSHHTTPProxyServer *outerssh_http_proxy_server_create(OuterSSHSessionPool *pool,
    const OuterSSHHTTPProxyServerConfiguration *configuration, OuterSSHError *error)
{
    OuterSSHHTTPProxyServer *server = create_server(pool, configuration, false, error);
    if (server != NULL) server->forwarder->frontend = server;
    return server;
}

OuterSSHHTTPProxyServer *outersshpriv_inspected_socks_create(OuterSSHSessionPool *pool,
    const OuterSSHProxyCredentials *credentials, OuterSSHProxyAuthentication authentication,
    bool rewrite_loopback_addresses, OuterSSHError *error)
{
    OuterSSHHTTPProxyServerConfiguration configuration = {.credentials = credentials,
        .authentication = authentication, .rewrite_loopback_addresses = rewrite_loopback_addresses};
    return create_server(pool, &configuration, true, error);
}

SSHForwarder *outersshpriv_inspected_socks_forwarder(OuterSSHHTTPProxyServer *server)
{
    return server->forwarder;
}

static void initialize_server(void *context)
{
    OuterSSHHTTPProxyServer *server = context;
    /* Keep the forwarder and pool alive until every HTTP client/source has drained. */
    outersshpriv_proxy_server_begin_work(server->forwarder);
}

static OuterSSHError http_error(const char *message)
{
    return outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION, message, strlen(message), errno);
}

#pragma mark - Start Listening and Accept Clients

static SSHPoolEvent *reserve(OuterSSHHTTPProxyServer *server, OuterSSHEventType type, uint64_t tag)
{
    return outersshpriv_reply_reserve(server->forwarder->pool, type, tag);
}

bool outerssh_http_proxy_server_start(OuterSSHHTTPProxyServer *server, uint16_t port, uint64_t tag)
{
    SSHPoolEvent *reply = reserve(server, OUTERSSH_EVENT_PROXY_STARTED, tag);
    if (reply == NULL) return false;
    outersshpriv_http_proxy_start(server, port, reply);
    return true;
}

void outersshpriv_http_proxy_start(OuterSSHHTTPProxyServer *server, int32_t port, SSHPoolEvent *reply)
{
    HTTPServerStartContext *request = malloc(sizeof(*request));
    if (!request) {
        outersshpriv_reply_proxy_started(reply, 0, NULL, 0, NULL, 0, http_error("Could not allocate HTTP start operation."));
        return;
    }
    *request = (HTTPServerStartContext){.server = server, .port = port, .reply = reply};
    otqueue_async(server->queue, request, start_server);
}

static void start_server(void *context)
{
    HTTPServerStartContext *request = context;
    OuterSSHHTTPProxyServer *server = request->server;
    SSHForwarder *forwarder = server->forwarder;
    if (server->socks) {
        outersshpriv_forwarder_start(forwarder, request->port, request->reply);
        free(request);
        return;
    }
    if (server->closing_listener ||
        (forwarder->running && server->listener &&
         (request->port == 0 || request->port == forwarder->port) &&
         !otsocket_is_listening(server->listener->socket))) {
        if (server->start_tail) server->start_tail->next = request;
        else server->start_head = request;
        server->start_tail = request;
        if (!server->closing_listener) {
            server->closing_listener = server->listener;
            server->listener = NULL;
            otsource_cancel(server->closing_listener->source);
            otsource_release(server->closing_listener->source);
        }
        return;
    }
    OuterSSHError error = start_listener(server, request->port);
    outersshpriv_reply_proxy_started(request->reply, forwarder->port, forwarder->username, forwarder->username_length,
        forwarder->password, forwarder->password_length, error);
    free(request);
}

static OuterSSHError start_listener(OuterSSHHTTPProxyServer *server, int32_t port)
{
    SSHForwarder *forwarder = server->forwarder;
    if (forwarder->pool->shutdown_requested) return outerssh_proxy_closing_error();
    if (port < 0 || port > 65535) return http_error("Invalid HTTP proxy port.");
    if (forwarder->running) {
        if (port != 0 && port != forwarder->port)
            return http_error("The proxy server is already active on another port.");
        if (server->listener) return (OuterSSHError){0};
        port = forwarder->port;
    }
    HTTPListener *listener = calloc(1, sizeof(*listener));
    if (!listener) return http_error("Could not allocate HTTP listener.");
    listener->server = server;
    listener->socket = otsocket_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    socklen_t size = sizeof(address);
    int one = 1;
#if defined(_WIN32)
    int address_option = SO_EXCLUSIVEADDRUSE;
#else
    int address_option = SO_REUSEADDR;
#endif
    if (listener->socket == -1 || otsocket_set_nonblocking(listener->socket, true) ||
        otsocket_prevent_inheritance(listener->socket) ||
        otsocket_setsockopt(listener->socket, SOL_SOCKET, address_option, &one, sizeof(one)) ||
        otsocket_bind(listener->socket, (struct sockaddr *)&address, sizeof(address)) ||
        otsocket_listen(listener->socket, 128) ||
        otsocket_getsockname(listener->socket, (struct sockaddr *)&address, &size)) {
        OuterSSHError error = http_error("Could not listen for HTTP proxy connections.");
        if (listener->socket != -1) otsocket_close(listener->socket);
        free(listener);
        return error;
    }
    listener->source = otsource_create(
        OTSOURCE_TYPE_READ, (uintptr_t)listener->socket, server->queue);
    if (!listener->source) {
        otsocket_close(listener->socket);
        free(listener);
        return http_error("Could not create HTTP listener source.");
    }
    server->listener = listener;
    server->references++;
    forwarder->port = ntohs(address.sin_port);
    outersshpriv_forwarder_activate(forwarder);
    otsource_set_context(listener->source, listener);
    otsource_set_event_handler(listener->source, accept_clients);
    otsource_set_cancel_handler(listener->source, listener_cancelled);
    otsource_activate(listener->source);
    return (OuterSSHError){0};
}

static void accept_clients(void *context)
{
    HTTPListener *listener = context;
    OuterSSHHTTPProxyServer *server = listener->server;
    for (int i = 0; i < 32 && server->listener == listener; i++) {
        otsocket_t socket = otsocket_accept(listener->socket, NULL, NULL);
        if (socket == -1) {
            break;
        }
        create_client(server, socket);
    }
}

static HTTPClient *create_client(OuterSSHHTTPProxyServer *server, otsocket_t socket)
{
    if (server->client_count >= 512) {
        otsocket_close(socket);
        return NULL;
    }
    HTTPClient *client = calloc(1, sizeof(*client));
    if (!client) {
        otsocket_close(socket);
        return NULL;
    }
    client->server = server;
    client->references = 1;
    server->references++;
    server->client_count++;
    client->next = server->clients;
    if (client->next) {
        client->next->previous = client;
    }
    server->clients = client;
    initialize_message(&client->request, client, false);
    initialize_message(&client->response, client, true);
    if (!peer_create(client, 0, socket, true)) {
        client_close(client);
        return NULL;
    }
    client->timer = otsource_create(OTSOURCE_TYPE_TIMER, 0, server->queue);
    if (!client->timer) {
        client_close(client);
        return NULL;
    }
    client->references++;
    otsource_set_context(client->timer, client);
    otsource_set_event_handler(client->timer, timeout_client);
    otsource_set_cancel_handler(client->timer, timer_cancelled);
    reset_deadline(client);
    otsource_activate(client->timer);
    set_source_enabled(client->peers[0]->write, &client->peers[0]->writing, false);
    return client;
}

typedef struct {
    OuterSSHHTTPProxyServer *server;
    ProxyConnectRequest request;
    uint64_t generation;
    char *origin;
    size_t origin_length;
} SOCKSTunnelTransfer;

static void socks_socket_transferred(void *context, otsocket_t socket)
{
    SOCKSTunnelTransfer *transfer = context;
    OuterSSHHTTPProxyServer *server = transfer->server;
    if (socket >= 0) {
        if (!server->forwarder->running || server->forwarder->generation != transfer->generation) {
            otsocket_close(socket);
        } else {
            HTTPClient *client = create_client(server, socket);
            if (client) {
                client->destination = transfer->request;
                client->connect = true;
                client->socks_reply_pending = true;
                if (transfer->origin != NULL &&
                    !use_origin_credentials(client, transfer->origin, transfer->origin_length)) {
                    client_close(client);
                } else if (client->origin_credentials && credential_access(client) == CREDENTIAL_ACCESS_REFUSED) {
                    reply_to_socks_request(client, PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
                    update_downstream_sources(client);
                } else if (!connect_upstream(client)) {
                    client_close(client);
                }
            }
        }
    }
    free(transfer->origin);
    free(transfer);
    server_release(server);
}

static void accept_socks_tunnel(void *context, ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route)
{
    OuterSSHHTTPProxyServer *server = context;
    SOCKSTunnelTransfer *transfer = malloc(sizeof(*transfer));
    ProxyPendingConnection *pending =
        outersshpriv_proxy_pending_connection_for_handle(server->forwarder->reactor, connection);
    const char *origin = NULL;
    size_t origin_length = 0;
    bool has_origin = pending != NULL && pending->socks != NULL &&
        outersshpriv_socks_handshake_origin(pending->socks, &origin, &origin_length);
    char *origin_copy = has_origin ? malloc(origin_length + 1) : NULL;
    if (!transfer || (has_origin && (origin == NULL || origin_copy == NULL))) {
        free(transfer);
        free(origin_copy);
        outersshpriv_proxy_reactor_fail_pending_connection(server->forwarder->reactor,
            connection, PROXY_SOCKS_REPLY_GENERAL_FAILURE);
        return;
    }
    if (has_origin) {
        memcpy(origin_copy, origin, origin_length);
        origin_copy[origin_length] = '\0';
    }
    *transfer = (SOCKSTunnelTransfer){server, route.request, server->forwarder->generation,
        origin_copy, origin_length};
    server->references++;
    outersshpriv_proxy_reactor_transfer_pending_connection(server->forwarder->reactor,
        connection, socks_socket_transferred, transfer);
}

static HTTPPeer *peer_create(HTTPClient *client, int index, otsocket_t socket, bool tcp)
{
    HTTPPeer *peer = calloc(1, sizeof(*peer));
    if (!peer) {
        otsocket_close(socket);
        return NULL;
    }
    peer->client = client;
    peer->index = index;
    peer->socket = socket;
    peer->reading = peer->writing = true;
    client->references++;
    client->peers[index] = peer;
    int no_delay = 1;
    if (otsocket_set_nonblocking(socket, true) || otsocket_prevent_inheritance(socket) ||
        otsocket_configure_sigpipe(socket) ||
        (tcp && otsocket_setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay)))) {
        peer_cancel(peer);
        return NULL;
    }
    peer->read =
        otsource_create(OTSOURCE_TYPE_READ, (uintptr_t)socket, client->server->queue);
    peer->write =
        otsource_create(OTSOURCE_TYPE_WRITE, (uintptr_t)socket, client->server->queue);
    otsource_t sources[] = {peer->read, peer->write};
    for (int i = 0; i < 2; i++) {
        if (sources[i]) {
            peer->sources++;
            otsource_set_context(sources[i], peer);
            otsource_set_event_handler(sources[i], i ? peer_became_writable : peer_became_readable);
            otsource_set_cancel_handler(sources[i], peer_cancelled);
            otsource_activate(sources[i]);
        }
    }
    if (!peer->read || !peer->write) {
        peer_cancel(peer);
        return NULL;
    }
    return peer;
}

static const llhttp_settings_t settings = {.on_url = on_target,
    .on_status = on_target,
    .on_header_field = on_field,
    .on_header_value = on_value,
    .on_header_value_complete = on_value_complete,
    .on_headers_complete = on_headers,
    .on_body = on_body,
    .on_message_complete = on_complete};

static void initialize_message(HTTPMessage *message, HTTPClient *client, bool response)
{
    clear_message_fields(message);
    *message = (HTTPMessage){.client = client, .response = response};
    llhttp_init(&message->parser, response ? HTTP_RESPONSE : HTTP_REQUEST, &settings);
    message->parser.data = message;
}

#pragma mark - Process Socket Readiness

static void peer_became_readable(void *context)
{
    HTTPPeer *peer = context;
    HTTPClient *client = peer->client;
    if (client->closed || peer->cancelled) {
        return;
    }
    for (;;) {
        char bytes[16384];
        ssize_t n = otsocket_recv(peer->socket, bytes, sizeof(bytes), 0);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                client_close(client);
            }
            return;
        }
        if (n == 0) {
            peer->eof = true;
            if (peer->index == 1 && client->phase == HTTP_IDLE) {
                peer_cancel(peer);
            } else if (peer->index == 1 && client->phase < HTTP_RELAY) {
                reject_request(client, 502, "Upstream Connection Closed");
            } else if (peer->index == 0 && !client->request.complete && client->phase != HTTP_TUNNEL) {
                if (client->busy || peer->input.size) {
                    reject_request(client, 400, "Truncated HTTP Request");
                }
            }
        } else {
            if (peer->index == 1 && !client->busy && client->phase == HTTP_IDLE) {
                peer_cancel(peer);
                process_client_input(client);
                half_close_drained_tunnel_peers(client);
                if (!close_client_if_finished(client)) {
                    update_downstream_sources(client);
                    update_upstream_sources(client);
                }
                return;
            }
            queue_bytes(client, &peer->input, bytes, (size_t)n);
            reset_deadline(client);
        }
        process_client_input(client);
        half_close_drained_tunnel_peers(client);
        if (close_client_if_finished(client)) {
            return;
        }
        update_downstream_sources(client);
        update_upstream_sources(client);
        if (peer->cancelled || !peer->reading || peer->eof) {
            return;
        }
    }
}

static void peer_became_writable(void *context)
{
    HTTPPeer *peer = context;
    HTTPClient *client = peer->client;
    if (client->closed || peer->cancelled) {
        return;
    }
    for (;;) {
        bool blocked = false;
        while (!client->closed && peer->output.size) {
            size_t count = peer->output.size < 65536 ? peer->output.size : 65536;
            ssize_t n = otsocket_send(peer->socket, peer->output.data, count, OTSOCKET_SEND_FLAGS);
            if (n > 0) {
                consume_bytes(&peer->output, (size_t)n);
                reset_deadline(client);
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                blocked = true;
                break;
            } else {
                client_close(client);
                return;
            }
        }
        process_client_input(client);
        half_close_drained_tunnel_peers(client);
        if (close_client_if_finished(client)) {
            return;
        }
        update_downstream_sources(client);
        update_upstream_sources(client);
        if (peer->cancelled || blocked || !peer->output.size) {
            return;
        }
    }
}

static void update_downstream_sources(HTTPClient *client)
{
    HTTPPeer *downstream = client->peers[0], *upstream = client->peers[1];
    bool reading = !downstream->eof && downstream->input.size < WATERMARK && client->phase != HTTP_REJECT;
    if (client->phase == HTTP_TUNNEL) {
        reading = reading && upstream && upstream->output.size < WATERMARK;
    } else if (client->phase != HTTP_DETECT) {
        reading = reading && !client->request.complete && client->pending.size < WATERMARK &&
            downstream->output.size < WATERMARK && (!upstream || upstream->output.size < WATERMARK);
    } else {
        reading = reading && downstream->output.size < WATERMARK;
    }
    set_source_enabled(downstream->read, &downstream->reading, reading);
    set_source_enabled(downstream->write, &downstream->writing, downstream->output.size != 0);
}

static void update_upstream_sources(HTTPClient *client)
{
    HTTPPeer *upstream = client->peers[1], *downstream = client->peers[0];
    if (!upstream) {
        return;
    }
    bool reading = !upstream->eof && upstream->input.size < WATERMARK && client->phase != HTTP_REJECT;
    if (client->phase == HTTP_TUNNEL) {
        reading = reading && downstream->output.size < WATERMARK;
    } else {
        reading = reading && client->phase != HTTP_CONNECTING &&
            downstream->output.size < WATERMARK;
    }
    set_source_enabled(upstream->read, &upstream->reading, reading);
    set_source_enabled(upstream->write, &upstream->writing,
        upstream->output.size != 0);
}

static void half_close_drained_tunnel_peers(HTTPClient *client)
{
    if (client->closed || client->phase != HTTP_TUNNEL) {
        return;
    }
    for (int i = 0; i < 2; i++) {
        HTTPPeer *peer = client->peers[i], *other = client->peers[1 - i];
        if (peer && other && other->eof && !other->input.size && !peer->output.size && !peer->half_closed) {
            otsocket_shutdown(peer->socket, SHUT_WR);
            peer->half_closed = true;
        }
    }
}

static bool close_client_if_finished(HTTPClient *client)
{
    if (client->closed) {
        return true;
    }
    HTTPPeer *downstream = client->peers[0], *upstream = client->peers[1];
    if ((client->phase == HTTP_REJECT && !downstream->output.size) ||
        (client->phase == HTTP_TUNNEL && upstream && downstream->eof && upstream->eof &&
         !downstream->output.size && !upstream->output.size) ||
        (client->phase != HTTP_TUNNEL && downstream->eof && !client->busy && !downstream->output.size)) {
        client_close(client);
        return true;
    }
    return false;
}

static void process_client_input(HTTPClient *client)
{
    if (client->closed || client->phase == HTTP_REJECT || client->socks_reply_pending) {
        return;
    }
    HTTPPeer *downstream = client->peers[0], *upstream = client->peers[1];
    if (client->phase == HTTP_DETECT) {
        const char *methods[] = {"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE "};
        bool possible = false;
        for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
            size_t n = strlen(methods[i]);
            if (n > downstream->input.size) {
                n = downstream->input.size;
            }
            if (!n || memcmp(downstream->input.data, methods[i], n) == 0) {
                possible = true;
            }
        }
        char *line = downstream->input.data ? strstr(downstream->input.data, "\r\n") : NULL;
        if (possible && line && line - downstream->input.data >= 9 && memcmp(line - 9, " HTTP/1.1", 9) == 0) {
            client->tunneled = true;
            client->connect = false;
            client->busy = false;
            initialize_message(&client->request, client, false);
            initialize_message(&client->response, client, true);
            client->phase = upstream ? HTTP_RELAY : HTTP_IDLE;
        } else if (!possible || line || downstream->input.size >= HEADER_LIMIT ||
                   (upstream && (upstream->input.size || upstream->eof)) || downstream->eof) {
            if (!upstream || (destination_is_socket(client) && !destination_is_session_owned(client))) {
                peer_cancel(client->peers[1]);
                client->phase = HTTP_REJECT;
                return;
            }
            client->phase = HTTP_TUNNEL;
        } else {
            return;
        }
        reset_deadline(client);
    }
    if (client->phase == HTTP_TUNNEL) {
        if (upstream) {
            queue_bytes(client, &upstream->output, downstream->input.data, downstream->input.size);
            clear_buffer(&downstream->input);
            if (!client->closed) {
                queue_bytes(client, &downstream->output, upstream->input.data, upstream->input.size);
                clear_buffer(&upstream->input);
            }
        }
        return;
    }
    if (!client->request.complete && client->pending.size < WATERMARK &&
        (!upstream || upstream->output.size < WATERMARK) && downstream->output.size < WATERMARK) {
        parse_message(client, &client->request, &downstream->input);
    }
    if (client->closed || client->phase == HTTP_REJECT) {
        return;
    }
    upstream = client->peers[1];
    if (client->phase == HTTP_RELAY && upstream && client->busy && downstream->output.size < WATERMARK) {
        parse_message(client, &client->response, &upstream->input);
        if (!client->closed && upstream->eof && !upstream->input.size && !client->response.complete &&
            client->phase != HTTP_TUNNEL) {
            llhttp_errno_t result = llhttp_finish(&client->response.parser);
            if ((result != HPE_OK && result != HPE_PAUSED) || !client->response.complete) {
                reject_request(client, 502, "Truncated HTTP Response");
            }
        }
    }
    if (client->closed) {
        return;
    }
    if (client->phase == HTTP_TUNNEL) {
        process_client_input(client);
        return;
    }
    finish_exchange(client);
    if (!client->closed && client->phase == HTTP_IDLE && downstream->input.size &&
        downstream->output.size < WATERMARK) {
        process_client_input(client);
    }
}

#pragma mark - Parse and Forward HTTP Messages

static void parse_message(HTTPClient *client, HTTPMessage *message, HTTPBuffer *input)
{
    if (!input->size || message->complete || client->closed) {
        return;
    }
    llhttp_errno_t result = llhttp_execute(&message->parser, input->data, input->size);
    size_t used =
        result == HPE_OK ? input->size : (size_t)(llhttp_get_error_pos(&message->parser) - input->data);
    consume_bytes(input, used);
    if (result == HPE_PAUSED_UPGRADE) {
        message->complete = true;
    } else if (result != HPE_OK && result != HPE_PAUSED) {
        reject_request(client, message->response ? 502 : 400, "Invalid HTTP Message");
    }
}

static int on_target(llhttp_t *parser, const char *bytes, size_t size)
{
    HTTPMessage *message = parser->data;
    if (size > HEADER_LIMIT - message->header_size) {
        return -1;
    }
    message->header_size += size;
    return append_bytes(&message->target, bytes, size) ? 0 : -1;
}

static int on_field(llhttp_t *parser, const char *bytes, size_t size)
{
    HTTPMessage *message = parser->data;
    if (message->count >= 256 || size > HEADER_LIMIT - message->header_size) {
        return -1;
    }
    message->header_size += size;
    return append_bytes(&message->fields[message->count].name, bytes, size) ? 0 : -1;
}

static int on_value(llhttp_t *parser, const char *bytes, size_t size)
{
    HTTPMessage *message = parser->data;
    if (message->count >= 256 || size > HEADER_LIMIT - message->header_size) {
        return -1;
    }
    message->header_size += size;
    return append_bytes(&message->fields[message->count].value, bytes, size) ? 0 : -1;
}

static int on_value_complete(llhttp_t *parser)
{
    HTTPMessage *message = parser->data;
    if (message->count >= 256 || !append_bytes(&message->fields[message->count].value, "", 0)) {
        return -1;
    }
    HTTPBuffer *value = &message->fields[message->count].value;
    while (value->size && (value->data[value->size - 1] == ' ' || value->data[value->size - 1] == '\t')) {
        value->data[--value->size] = 0;
    }
    if (message->headers) {
        const char *name = message->fields[message->count].name.data;
        if (!strcasecmp(name, "content-length") || !strcasecmp(name, "transfer-encoding") ||
            !strcasecmp(name, "connection") || !strcasecmp(name, "host") || !strcasecmp(name, "upgrade") ||
            !strcasecmp(name, "proxy-authorization")) {
            return -1;
        }
    }
    message->count++;
    return 0;
}

static int on_headers(llhttp_t *parser)
{
    HTTPMessage *message = parser->data;
    HTTPClient *client = message->client;
    if (parser->http_major != 1 ||
        (!message->response && parser->http_minor != 1 && parser->method != HTTP_CONNECT) ||
        !valid_framing(message)) {
        return -1;
    }
    message->headers = true;
    message->chunked = (parser->flags & F_CHUNKED) != 0;
    message->keepalive = llhttp_should_keep_alive(parser) != 0;
    HTTPBuffer header = {0};
    bool ok = true;
    if (!message->response) {
        client->busy = true;
        client->request_close = !message->keepalive;
        if (!client->tunneled && client->server->authorization && !authorize_request(client, message)) {
            if (client->closed) {
                return -1;
            }
            reject_request(client, 407, "Proxy Authentication Required");
            return HPE_PAUSED;
        }
        if (client->tunneled && parser->method == HTTP_CONNECT) {
            return -1;
        }
        client->connect = parser->method == HTTP_CONNECT;
        client->head = parser->method == HTTP_HEAD;
        client->upgrade =
            connection_has_token(message, "upgrade") && header_value(message, "upgrade") != NULL;
        const char *path = "";
        ProxyConnectionRoute route;
        if (!message->target.data || !parse_destination(client, message->target.data, &path) ||
            (route = outersshpriv_proxy_resolve_request(client->destination)).kind == PROXY_CONNECTION_ROUTE_REJECTED) {
            return -1;
        }
        if (client->connect && (message->chunked || parser->content_length)) {
            return -1;
        }
        bool reconnects = !client->peers[1] || client->connect ||
            !same_destination(&client->upstream, &client->destination);
        client->ownership_pending = false;
        if (client->origin_credentials) {
            CredentialAccess access = credential_access(client);
            if (access == CREDENTIAL_ACCESS_REFUSED) {
                reject_request(client, 403, "Forbidden");
                return HPE_PAUSED;
            }
            reconnects = reconnects || access == CREDENTIAL_ACCESS_PENDING;
        } else if (!client->connect && (route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET || route.tcp.loopback)) {
            int verdict = ownership_verdict(client, message, (llhttp_method_t)parser->method, &route);
            if (verdict < 0 || (verdict > 0 && !reconnects)) {
                reject_request(client, 403, "Forbidden");
                return HPE_PAUSED;
            }
            client->ownership_pending = verdict > 0;
        }
        if (client->peers[1] && reconnects) {
            peer_cancel(client->peers[1]);
        }
        if (!client->peers[1]) {
            if (!connect_upstream(client)) {
                return -1;
            }
        } else {
            client->phase = HTTP_RELAY;
        }
        reset_deadline(client);
        if (client->connect) {
            return 2;
        }
        if (!create_exchange_rewriter(client)) {
            return -1;
        }
        ok = append_text(&header, llhttp_method_name((llhttp_method_t)parser->method)) &&
             append_text(&header, " ") && append_text(&header, *path == '/' ? "" : "/") &&
             append_text(&header, path) && append_text(&header, " HTTP/1.1\r\n");
        ok = ok && serialize_headers(message, &header, client->rewriter, false);
        if (message->chunked) {
            ok = ok && append_text(&header, "Transfer-Encoding: chunked\r\n");
        }
        if (client->upgrade && ok) {
            char upgrade[1024];
            int length = snprintf(upgrade, sizeof(upgrade), "Connection: Upgrade\r\nUpgrade: %s\r\n",
                header_value(message, "upgrade"));
            ok = length >= 0 && (size_t)length < sizeof(upgrade) &&
                 append_bytes(&header, upgrade, (size_t)length);
        }
        ok = ok && append_text(&header, "\r\n");
        if (ok) {
            upstream_output(client, header.data, header.size);
        }
    } else {
        unsigned status = parser->status_code;
        bool interim = status < 200 && status != 101;
        bool final = !interim && status != 101;
        if (status == 101 && (!client->upgrade || !connection_has_token(message, "upgrade") ||
                                 !header_value(message, "upgrade"))) {
            return -1;
        }
        if (final) {
            client->response_body = !client->head && status != 204 && status != 304;
            client->upstream_keepalive = message->keepalive;
            if (!client->request.complete || client->peers[1]->output.size) {
                client->request_close = true;
            }
        }
        char status_line[1024];
        int length = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %u ", status);
        ok = length >= 0 && (size_t)length < sizeof(status_line) &&
             append_bytes(&header, status_line, (size_t)length) &&
             append_text(&header, message->target.data ? message->target.data : "") &&
             append_text(&header, "\r\n") &&
             serialize_headers(
                 message, &header, final ? client->rewriter : NULL, final && client->response_body);
        if (final) {
            client->response_started = true;
        }
        if (status == 101 && ok) {
            char upgrade[1024];
            int upgrade_length = snprintf(upgrade, sizeof(upgrade), "Connection: Upgrade\r\nUpgrade: %s\r\n",
                header_value(message, "upgrade"));
            ok = upgrade_length >= 0 && (size_t)upgrade_length < sizeof(upgrade) &&
                 append_bytes(&header, upgrade, (size_t)upgrade_length);
        }
        if (final && client->response_body) {
            ok = ok && append_text(&header, "Transfer-Encoding: chunked\r\n");
        }
        if (final && client->request_close) {
            ok = ok && append_text(&header, "Connection: close\r\n");
        }
        ok = ok && append_text(&header, "\r\n");
        if (ok) {
            queue_bytes(client, &client->peers[0]->output, header.data, header.size);
        }
        if (status == 101) {
            client->phase = HTTP_TUNNEL;
            reset_deadline(client);
        }
    }
    destroy_buffer(&header);
    if (!ok || client->closed) {
        return -1;
    }
    if (message->response && parser->status_code == 101) {
        return 2;
    }
    return message->response && client->head && parser->status_code >= 200 ? 1 : 0;
}

static bool valid_framing(HTTPMessage *message)
{
    const char *transfer = header_value(message, "transfer-encoding");
    if (transfer && strcasecmp(transfer, "chunked")) {
        return false;
    }
    return !connection_has_token(message, "content-length") &&
           !connection_has_token(message, "transfer-encoding") && !connection_has_token(message, "host");
}

static bool same_destination(const ProxyConnectRequest *a, const ProxyConnectRequest *b)
{
    return a->port == b->port && a->host_length == b->host_length && !memcmp(a->host, b->host, a->host_length);
}

static bool parse_destination(HTTPClient *client, const char *target, const char **path)
{
    if (client->tunneled) {
        if (target[0] != '/' || strchr(target, '#')) {
            return false;
        }
        *path = target;
        return true;
    }
    const char *authority = target;
    if (!client->connect) {
        if (!strncasecmp(target, "http://", 7)) {
            authority += 7;
        } else if (client->upgrade && !strncasecmp(target, "ws://", 5)) {
            authority += 5;
        } else {
            return false;
        }
    }
    const char *end = authority + strcspn(authority, "/?#");
    if (client->connect && *end) {
        return false;
    }
    const char *host = authority, *host_end = end, *port = NULL;
    if (host < end && *host == '[') {
        host++;
        host_end = memchr(host, ']', (size_t)(end - host));
        if (!host_end) {
            return false;
        }
        if (host_end + 1 < end) {
            if (host_end[1] != ':') {
                return false;
            }
            port = host_end + 2;
        }
    } else {
        const char *colon = memchr(host, ':', (size_t)(end - host));
        if (colon) {
            host_end = colon;
            port = colon + 1;
        }
    }
    size_t size = (size_t)(host_end - host);
    if (!size || size > 255 || (client->connect && !port)) {
        return false;
    }
    for (size_t i = 0; i < size; i++) {
        unsigned char ch = (unsigned char)host[i];
        if (ch <= 32 || ch >= 127 || ch == '@' || ch == '\\' || ch == '%' || ch == '[' || ch == ']') {
            return false;
        }
        client->destination.host[i] = (char)tolower(ch);
    }
    client->destination.host[size] = 0;
    client->destination.host_length = size;
    unsigned value = 80;
    if (port) {
        value = 0;
        if (port == end) {
            return false;
        }
        for (; port < end; port++) {
            if (*port < '0' || *port > '9') {
                return false;
            }
            value = value * 10 + (unsigned)(*port - '0');
            if (value > 65535) {
                return false;
            }
        }
    }
    if (!value || strchr(end, '#')) {
        return false;
    }
    client->destination.port = (uint16_t)value;
    *path = end;
    return true;
}

static bool create_exchange_rewriter(HTTPClient *client)
{
    if (!client->server->rewrite_loopback_addresses || client->origin_credentials) {
        return true;
    }
    ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(client->destination);
    client->rewriter = outersshpriv_http_proxy_rewriter_create(&route,
        client->server->rewrite_loopback_addresses, client->server->rewrite_loopback_addresses);
    return client->rewriter != NULL;
}

static bool serialize_headers(
    HTTPMessage *message, HTTPBuffer *output, HTTPProxyRewriter *rewriter, bool has_body)
{
    HTTPProxyHeader headers[258];
    size_t count = 0;
    char authority[280];
    HTTPClient *client = message->client;
    if (!message->response) {
        size_t authority_length = 0;
        if (!outersshpriv_http_proxy_format_authority(
                client->destination.host, client->destination.host_length, client->destination.port, authority,
                sizeof(authority), &authority_length)) {
            return false;
        }
        if (client->destination.port == 80) {
            authority[authority_length - 3] = '\0';
        }
        headers[count++] = (HTTPProxyHeader){"Host", authority};
    }
    for (size_t i = 0; i < message->count; i++) {
        const char *name = message->fields[i].name.data;
        if (is_hop_by_hop_header(message, name) || (!message->response && !strcasecmp(name, "host")) ||
            (message->response && has_body && !strcasecmp(name, "content-length"))) {
            continue;
        }
        headers[count++] = (HTTPProxyHeader){name, message->fields[i].value.data};
    }
    if (rewriter != NULL) {
        return message->response
                   ? outersshpriv_http_proxy_rewrite_response_headers(
                         rewriter, headers, count, has_body, serialize_header, output)
                   : outersshpriv_http_proxy_rewrite_request_headers(rewriter, headers, count, serialize_header, output);
    }
    for (size_t i = 0; i < count; i++) {
        if (!serialize_header(output, headers[i].name, headers[i].value)) {
            return false;
        }
    }
    return true;
}

static bool serialize_header(void *context, const char *name, const char *value)
{
    HTTPBuffer *output = context;
    return append_text(output, name) && append_text(output, ": ") && append_text(output, value) &&
           append_text(output, "\r\n");
}

static int on_body(llhttp_t *parser, const char *bytes, size_t size)
{
    HTTPMessage *message = parser->data;
    HTTPClient *client = message->client;
    if (message->response) {
        if (client->rewriter) {
            outersshpriv_http_proxy_rewrite_body(client->rewriter, bytes, size, downstream_body, client);
        } else {
            downstream_body(client, bytes, size);
        }
    } else if (message->chunked) {
        HTTPBuffer buffer = {0};
        if (!append_body_chunk(&buffer, bytes, size)) {
            destroy_buffer(&buffer);
            return -1;
        }
        upstream_output(client, buffer.data, buffer.size);
        destroy_buffer(&buffer);
    } else {
        upstream_output(client, bytes, size);
    }
    return client->closed ? -1 : 0;
}

static void upstream_output(void *context, const void *bytes, size_t size)
{
    HTTPClient *client = context;
    if (client->closed) {
        return;
    }
    HTTPBuffer *buffer = client->phase == HTTP_RELAY ? &client->peers[1]->output : &client->pending;
    queue_bytes(client, buffer, bytes, size);
}

static void downstream_body(void *context, const void *bytes, size_t size)
{
    HTTPClient *client = context;
    if (!client->closed && client->response_body &&
        !append_body_chunk(&client->peers[0]->output, bytes, size)) {
        client_close(client);
    }
}

static bool append_body_chunk(HTTPBuffer *buffer, const void *bytes, size_t size)
{
    if (size == 0) {
        return true;
    }
    char header[1024];
    int length = snprintf(header, sizeof(header), "%zx\r\n", size);
    return length >= 0 && (size_t)length < sizeof(header) && append_bytes(buffer, header, (size_t)length) &&
           append_bytes(buffer, bytes, size) && append_text(buffer, "\r\n");
}

static int on_complete(llhttp_t *parser)
{
    HTTPMessage *message = parser->data;
    HTTPClient *client = message->client;
    if (message->response && parser->status_code == 101) {
        message->complete = true;
        return 0;
    }
    if (message->response && parser->status_code < 200 && parser->status_code != 101) {
        clear_message_fields(message);
        message->headers = false;
        return 0;
    }
    message->complete = true;
    if (message->response) {
        if (client->rewriter) {
            outersshpriv_http_proxy_rewrite_body_finish(client->rewriter, downstream_body, client);
        }
        if (!client->closed && client->response_body) {
            queue_bytes(client, &client->peers[0]->output, "0\r\n\r\n", 5);
        }
        client->response_done = true;
    } else {
        if (message->chunked) {
            upstream_output(client, "0\r\n\r\n", 5);
        }
    }
    return HPE_PAUSED;
}

static void finish_exchange(HTTPClient *client)
{
    if (!client->response_done || client->closed) {
        return;
    }
    if (client->request_close || client->peers[0]->eof) {
        peer_cancel(client->peers[1]);
        client->phase = HTTP_REJECT;
        return;
    }
    HTTPPeer *upstream = client->peers[1];
    if (upstream && (!client->upstream_keepalive || upstream->eof)) {
        peer_cancel(upstream);
    } else if (upstream && upstream->input.size) {
        client_close(client);
        return;
    }
    outersshpriv_http_proxy_rewriter_destroy(client->rewriter);
    client->rewriter = NULL;
    initialize_message(&client->request, client, false);
    initialize_message(&client->response, client, true);
    client->busy = client->response_started = client->response_done = client->response_body = false;
    client->phase = HTTP_IDLE;
    reset_deadline(client);
}

#pragma mark - Connect to the Upstream

static bool connect_upstream(HTTPClient *client)
{
    otsocket_t pair[2];
    if (otsocket_pair(pair)) {
        return false;
    }
#if defined(_WIN32)
    bool tcp = true;
#else
    bool tcp = false;
#endif
    if (!peer_create(client, 1, pair[0], tcp)) {
        otsocket_close(pair[1]);
        return false;
    }
    client->upstream = client->destination;
    client->phase = HTTP_CONNECTING;
    client->references++;
    outersshpriv_forwarder_connect(client->server->forwarder, pair[1], client->destination.host,
        client->destination.host_length, client->destination.port, upstream_sender(client),
        upstream_connection_finished, client);
    return true;
}

/* The pool judges this sender once the destination's owner is known, before
 * the connection uses sudo. A SOCKS or CONNECT tunnel has not sent a request
 * yet, so it may reach a socket only without sudo; a refused tunnel opens
 * without a connection and waits for its first request. */
static SSHSocketSender upstream_sender(HTTPClient *client)
{
    if (client->origin_credentials) {
        return credential_access(client) == CREDENTIAL_ACCESS_PENDING
            ? origin_sender(client) : (SSHSocketSender){.kind = SSH_SOCKET_SENDER_UNCHECKED};
    }
    if (client->connect) {
        return (SSHSocketSender){.kind = SSH_SOCKET_SENDER_UNDECIDED};
    }
    return client->ownership_pending ? client->sender : (SSHSocketSender){.kind = SSH_SOCKET_SENDER_UNCHECKED};
}

static void upstream_connection_finished(void *context, SSHForwarderConnectionResult result)
{
    HTTPClient *client = context;
    client->connection_result = result;
    /* Allocation failures can complete inline while the HTTP parser is still running. */
    otqueue_async(client->server->queue, client, apply_upstream_connection_result);
}

static void apply_upstream_connection_result(void *context)
{
    HTTPClient *client = context;
    if (!client->closed && client->phase == HTTP_CONNECTING && client->peers[1]) {
        SSHForwarderConnectionResult result = client->connection_result;
        if (result.refused && client->connect && !client->origin_credentials) {
            await_first_request(client);
        } else if (result.refused && !client->socks_reply_pending) {
            reject_request(client, 403, "Forbidden");
        } else if (result.status != PROXY_SOCKS_REPLY_SUCCEEDED) {
            if (client->socks_reply_pending) {
                reply_to_socks_request(client, result.status);
            } else {
                reject_request(client, 502, result.forwarding_denied
                    ? "SSH Server Denied Port Forwarding" : "SSH Connection Failed");
            }
        } else if (client->origin_credentials) {
            bool allowed = credential_access(client) == CREDENTIAL_ACCESS_ALLOWED;
            if (!allowed) {
                if (client->socks_reply_pending) {
                    reply_to_socks_request(client, PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
                } else {
                    reject_request(client, 403, "Forbidden");
                }
            } else if (client->connect) {
                client->phase = HTTP_TUNNEL;
                if (client->socks_reply_pending) {
                    reply_to_socks_request(client, PROXY_SOCKS_REPLY_SUCCEEDED);
                } else {
                    queue_bytes(client, &client->peers[0]->output,
                        "HTTP/1.1 200 Connection Established\r\n\r\n", 39);
                }
            } else {
                client->phase = HTTP_RELAY;
                queue_bytes(client, &client->peers[1]->output, client->pending.data, client->pending.size);
            }
            clear_buffer(&client->pending);
            reset_deadline(client);
        } else {
            client->phase = HTTP_RELAY;
            if (client->connect) {
                client->phase = client->server->rewrite_loopback_addresses || destination_is_socket(client) ||
                        destination_is_loopback(client)
                    ? HTTP_DETECT : HTTP_TUNNEL;
                if (client->socks_reply_pending) {
                    reply_to_socks_request(client, PROXY_SOCKS_REPLY_SUCCEEDED);
                } else {
                    queue_bytes(client, &client->peers[0]->output,
                        "HTTP/1.1 200 Connection Established\r\n\r\n", 39);
                }
            } else if (client->ownership_pending && !ownership_allows(client)) {
                reject_request(client, 403, "Forbidden");
            } else {
                queue_bytes(client, &client->peers[1]->output, client->pending.data, client->pending.size);
            }
            clear_buffer(&client->pending);
            reset_deadline(client);
        }
        process_client_input(client);
        half_close_drained_tunnel_peers(client);
        if (!close_client_if_finished(client)) {
            update_downstream_sources(client);
            update_upstream_sources(client);
        }
    }
    client_release(client);
}

/* Opens the tunnel without an upstream connection, which its first request
 * makes once that request has been judged. Only HTTP crosses it. */
static void await_first_request(HTTPClient *client)
{
    peer_cancel(client->peers[1]);
    client->phase = HTTP_DETECT;
    if (client->socks_reply_pending) {
        reply_to_socks_request(client, PROXY_SOCKS_REPLY_SUCCEEDED);
    } else {
        queue_bytes(client, &client->peers[0]->output, "HTTP/1.1 200 Connection Established\r\n\r\n", 39);
    }
    reset_deadline(client);
}

static void reply_to_socks_request(HTTPClient *client, ProxySOCKSReplyStatus status)
{
    const unsigned char reply[] = {5, (unsigned char)status, 0, 1, 0, 0, 0, 0, 0, 0};
    queue_bytes(client, &client->peers[0]->output, reply, sizeof(reply));
    client->socks_reply_pending = false;
    if (status != PROXY_SOCKS_REPLY_SUCCEEDED) {
        peer_cancel(client->peers[1]);
        client->phase = HTTP_REJECT;
    }
}

#pragma mark - Prevent Privilege Escalation

static bool destination_is_socket(HTTPClient *client)
{
    return outersshpriv_proxy_resolve_request(client->destination).kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET;
}

static bool destination_is_loopback(HTTPClient *client)
{
    ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(client->destination);
    return route.kind == PROXY_CONNECTION_ROUTE_TCP && route.tcp.loopback;
}

static bool destination_is_session_owned(HTTPClient *client)
{
    ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(client->destination);
    SSHSocketOwner owner = outersshpriv_proxy_socket_owner(client->server->forwarder->pool,
        route.unix_socket.path, route.unix_socket.path_length);
    return owner.known && owner.session_owned;
}

static bool origin_socket_path(const char *origin, char *path, size_t capacity, size_t *path_length)
{
    if (strncasecmp(origin, "http://", 7) != 0) {
        return false;
    }
    const char *host = origin + 7;
    size_t host_length = strlen(host);
    const char *colon = memchr(host, ':', host_length);
    if (colon != NULL) {
        if (strcmp(colon, ":80") != 0) {
            return false;
        }
        host_length = (size_t)(colon - host);
    }
    OuterSSHProxySocketKind kind;
    return outerssh_proxy_decode_socket_host(host, host_length, &kind, path, capacity, path_length);
}

static bool referer_origin(const char *referer, char origin[PROXY_ORIGIN_CAPACITY])
{
    size_t scheme_length = !strncasecmp(referer, "http://", 7) ? 7 : !strncasecmp(referer, "https://", 8) ? 8 : 0;
    if (scheme_length == 0) {
        return false;
    }
    size_t origin_length = scheme_length + strcspn(referer + scheme_length, "/?#");
    if (origin_length >= PROXY_ORIGIN_CAPACITY) {
        return false;
    }
    memcpy(origin, referer, origin_length);
    origin[origin_length] = '\0';
    return true;
}

static bool referer_socket_path(const char *referer, char *path, size_t capacity, size_t *path_length)
{
    char origin[PROXY_ORIGIN_CAPACITY];
    return referer_origin(referer, origin) && origin_socket_path(origin, path, capacity, path_length);
}

/* Whether a page origin is on the SSH server: one of its sockets, or a
 * loopback port. */
static bool origin_is_on_server(const char *origin)
{
    char normalized[PROXY_ORIGIN_CAPACITY];
    size_t normalized_length;
    ProxyConnectionRoute route;
    return outersshpriv_proxy_parse_origin(origin, strlen(origin), normalized, &normalized_length, &route) &&
        (route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET || route.tcp.loopback);
}

/* Endpoints form zones: other hosts the SSH server can reach are the lowest,
 * then the server's loopback ports, then each account's sockets, and root's
 * sockets are the highest; a socket whose owner is unknown ranks with the
 * ports. A request reaches a loopback port or a socket in its sender's zone or
 * below; the sender is the endpoint named by Origin, or else by the origin of
 * Referer, and browsers set these headers so pages cannot forge them. Other
 * hosts are not judged. From a lower zone only the
 * socket's own pages pass (Sec-Fetch-Site: same-origin), along with GET and
 * HEAD requests without an upgrade that are top-level navigations
 * (Sec-Fetch-Mode: navigate and Sec-Fetch-Dest: document), that the user typed
 * (Sec-Fetch-Site: none), or that have neither Origin nor Sec-Fetch-Site.
 * Browsers always send fetch metadata to these hosts and Origin with every
 * write, so a request with neither comes from the application's own code or
 * the CLI user, who act as the SSH user: it also reaches the SSH user's own
 * sockets, or every socket when the SSH user is root. A repeated Origin,
 * Referer or Sec-Fetch header is refused. Returns -1
 * to reject, 1 when the destination's owner is not yet known, keeping the
 * sender for ownership_allows, and 0 to allow. */
static int ownership_verdict(HTTPClient *client, HTTPMessage *message, llhttp_method_t method,
    const ProxyConnectionRoute *route)
{
    enum { ORIGIN, REFERER, FETCH_SITE, FETCH_MODE, FETCH_DEST, FIELD_COUNT };
    static const char *const names[FIELD_COUNT] = {
        "origin", "referer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"};
    const char *values[FIELD_COUNT] = {0};
    size_t counts[FIELD_COUNT] = {0};
    for (size_t i = 0; i < message->count; i++) {
        for (size_t field = 0; field < FIELD_COUNT; field++) {
            if (!strcasecmp(message->fields[i].name.data, names[field])) {
                values[field] = message->fields[i].value.data;
                counts[field]++;
            }
        }
    }
    for (size_t field = 0; field < FIELD_COUNT; field++) {
        if (counts[field] > 1) {
            return -1;
        }
    }
    bool reads = (method == HTTP_GET || method == HTTP_HEAD) && !client->upgrade;
    bool navigates = counts[FETCH_MODE] && !strcmp(values[FETCH_MODE], "navigate") &&
        counts[FETCH_DEST] && !strcmp(values[FETCH_DEST], "document");
    if ((counts[FETCH_SITE] && !strcmp(values[FETCH_SITE], "same-origin")) ||
        (reads && (navigates || (counts[FETCH_SITE] ? !strcmp(values[FETCH_SITE], "none") : !counts[ORIGIN])))) {
        return 0;
    }
    if (route->kind == PROXY_CONNECTION_ROUTE_TCP) {
        char origin[PROXY_ORIGIN_CAPACITY];
        bool on_server = counts[ORIGIN] ? origin_is_on_server(values[ORIGIN])
            : !counts[FETCH_SITE] ||
                (counts[REFERER] && referer_origin(values[REFERER], origin) && origin_is_on_server(origin));
        return on_server ? 0 : -1;
    }
    OuterSSHSessionPool *pool = client->server->forwarder->pool;
    char sender[PROXY_UNIX_SOCKET_PATH_CAPACITY];
    size_t sender_length = 0;
    client->sender = (SSHSocketSender){.kind = SSH_SOCKET_SENDER_OWNER};
    if (!counts[ORIGIN] && !counts[FETCH_SITE]) {
        client->sender.kind = SSH_SOCKET_SENDER_SSH_USER;
        return ownership_allows(client) ? 0 : client->ownership_pending ? 1 : -1;
    }
    if (counts[ORIGIN] ? origin_socket_path(values[ORIGIN], sender, sizeof(sender), &sender_length)
                       : counts[REFERER] && referer_socket_path(values[REFERER], sender, sizeof(sender), &sender_length)) {
        if (sender_length == route->unix_socket.path_length &&
            memcmp(sender, route->unix_socket.path, sender_length) == 0) {
            return 0;
        }
        client->sender.owner = outersshpriv_proxy_socket_owner(pool, sender, sender_length);
    }
    return ownership_allows(client) ? 0 : client->ownership_pending ? 1 : -1;
}

/* Decides for the sender kept by ownership_verdict once the destination's
 * owner is known; sets ownership_pending while it is not. */
static bool ownership_allows(HTTPClient *client)
{
    ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(client->destination);
    SSHSocketOwner destination = outersshpriv_proxy_socket_owner(client->server->forwarder->pool,
        route.unix_socket.path, route.unix_socket.path_length);
    client->ownership_pending = !destination.known;
    return outersshpriv_socket_sender_permits(&client->sender, &destination,
        client->server->forwarder->pool->_remoteUserIsRoot == 1, false);
}

/* Content that is not a web page, such as an Outerframe, authenticates with
 * origin credentials naming the origin it was loaded from. Its connections
 * are decided by that origin and their destination when they open, and their
 * bytes are relayed untouched. */
static bool use_origin_credentials(HTTPClient *client, const char *origin, size_t origin_length)
{
    char normalized[PROXY_ORIGIN_CAPACITY];
    size_t normalized_length;
    ProxyConnectionRoute route;
    if (!outersshpriv_proxy_parse_origin(origin, origin_length, normalized, &normalized_length, &route)) {
        return false;
    }
    client->origin_credentials = true;
    if (route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET) {
        client->origin_socket_path = malloc(route.unix_socket.path_length + 1);
        if (client->origin_socket_path == NULL) return false;
        memcpy(client->origin_socket_path, route.unix_socket.path, route.unix_socket.path_length + 1);
        client->origin_socket_path_length = route.unix_socket.path_length;
    } else if (!route.tcp.loopback) {
        client->origin_elsewhere = true;
        client->origin_host = route.request;
    }
    return true;
}

static void forget_origin_credentials(HTTPClient *client)
{
    free(client->origin_socket_path);
    client->origin_socket_path = NULL;
    client->origin_socket_path_length = 0;
    client->origin_elsewhere = false;
    client->origin_host = (ProxyConnectRequest){0};
    client->origin_credentials = false;
}

/* A request through the HTTP proxy carries its own Proxy-Authorization: the
 * proxy's credentials, for pages, or origin credentials, for content loaded
 * from that origin. Each request is judged by the credentials it carries. */
static bool authorize_request(HTTPClient *client, HTTPMessage *message)
{
    const char *auth = header_value(message, "proxy-authorization");
    size_t auth_count = 0;
    for (size_t i = 0; i < message->count; i++) {
        if (!strcasecmp(message->fields[i].name.data, "proxy-authorization")) {
            auth_count++;
        }
    }
    if (auth_count != 1 || !auth || strncasecmp(auth, "Basic ", 6)) {
        return false;
    }
    forget_origin_credentials(client);
    if (!strcmp(auth + 6, client->server->authorization + 6)) {
        return true;
    }
    char *origin;
    size_t origin_length;
    if (client->server->socks || !outersshpriv_proxy_server_origin_for_basic_authorization(
            client->server->forwarder, auth + 6, &origin, &origin_length)) {
        return false;
    }
    bool used = use_origin_credentials(client, origin, origin_length);
    free(origin);
    if (!used) {
        client_close(client);
    }
    return used;
}

static bool is_origin_host(HTTPClient *client)
{
    char origin[PROXY_HOST_CAPACITY], destination[PROXY_HOST_CAPACITY];
    size_t origin_length, destination_length;
    return client->destination.port == client->origin_host.port &&
        outersshpriv_proxy_normalize_host(client->origin_host.host, client->origin_host.host_length,
            origin, &origin_length) &&
        outersshpriv_proxy_normalize_host(client->destination.host, client->destination.host_length,
            destination, &destination_length) &&
        origin_length == destination_length && memcmp(origin, destination, origin_length) == 0;
}

/* Content from the SSH server reaches TCP destinations, its own socket, and
 * sockets whose owner its socket's owner may send to; content from a loopback
 * port has no owner. Content from another host reaches only that host and
 * port. The destination's owner is known once connecting to it has authorized
 * it. */
static CredentialAccess credential_access(HTTPClient *client)
{
    ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(client->destination);
    if (route.kind != PROXY_CONNECTION_ROUTE_UNIX_SOCKET) {
        return !client->origin_elsewhere || is_origin_host(client)
            ? CREDENTIAL_ACCESS_ALLOWED : CREDENTIAL_ACCESS_REFUSED;
    }
    if (client->origin_socket_path && client->origin_socket_path_length == route.unix_socket.path_length &&
        memcmp(client->origin_socket_path, route.unix_socket.path, route.unix_socket.path_length) == 0) {
        return CREDENTIAL_ACCESS_ALLOWED;
    }
    if (client->origin_socket_path == NULL) {
        return CREDENTIAL_ACCESS_REFUSED;
    }
    SSHSocketOwner destination = outersshpriv_proxy_socket_owner(client->server->forwarder->pool,
        route.unix_socket.path, route.unix_socket.path_length);
    if (!destination.known) {
        return CREDENTIAL_ACCESS_PENDING;
    }
    SSHSocketSender sender = origin_sender(client);
    return outersshpriv_socket_sender_permits(&sender, &destination, false, false)
        ? CREDENTIAL_ACCESS_ALLOWED : CREDENTIAL_ACCESS_REFUSED;
}

/* Content from a socket sends as that socket's owner. */
static SSHSocketSender origin_sender(HTTPClient *client)
{
    return (SSHSocketSender){
        .kind = SSH_SOCKET_SENDER_OWNER,
        .owner = outersshpriv_proxy_socket_owner(client->server->forwarder->pool,
            client->origin_socket_path, client->origin_socket_path_length),
    };
}

#pragma mark - Reject Requests and Enforce Deadlines

static void reject_request(HTTPClient *client, int status, const char *reason)
{
    if (client->closed || client->phase == HTTP_REJECT) {
        return;
    }
    if (client->response_started) {
        client_close(client);
        return;
    }
    peer_cancel(client->peers[1]);
    client->phase = HTTP_REJECT;
    HTTPBuffer *output = &client->peers[0]->output;
    char header[1024];
    int length = snprintf(header, sizeof(header), "HTTP/1.1 %d %s\r\n", status, reason);
    bool ok = length >= 0 && (size_t)length < sizeof(header) && append_bytes(output, header, (size_t)length);
    if (status == 407 && ok) {
        length = snprintf(
            header, sizeof(header), "Proxy-Authenticate: Basic realm=\"%.*s\"\r\n",
            (int)client->server->realm_length, client->server->realm);
        ok = length >= 0 && (size_t)length < sizeof(header) && append_bytes(output, header, (size_t)length);
    }
    if (status == 502 && (strcmp(reason, "SSH Connection Failed") == 0 ||
                          strcmp(reason, "Upstream Connection Closed") == 0)) {
        ok = ok && append_text(output, "OuterSSH-Proxy-Error: connection-failed\r\n");
    }
    char body[1024] = "";
    if (status == 403) {
        snprintf(body, sizeof(body), "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>Request Blocked</title></head><body><h1>Request Blocked</h1>"
            "<p>This socket belongs to another account. Only content served from that account's sockets, "
            "or from root's, can send it requests; other pages can only link to it.</p></body></html>");
    } else if (status == 502 && client->connection_result.forwarding_denied) {
        snprintf(body, sizeof(body), "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>SSH Server Denied Port Forwarding</title></head><body>"
            "<h1>SSH Server Denied Port Forwarding</h1>"
            "<p>Your SSH connection succeeded, but the server refused forwarding to port %u. "
            "The server's SSH policy does not allow this connection.</p></body></html>", client->destination.port);
    }
    length = snprintf(header, sizeof(header), "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n", strlen(body));
    if (!ok || length < 0 || (size_t)length >= sizeof(header) ||
        !append_bytes(output, header, (size_t)length) ||
        (client->request.parser.method != HTTP_HEAD && !append_text(output, body))) {
        client_close(client);
    }
}

static void reset_deadline(HTTPClient *client)
{
    if (client->timer) {
        otsource_set_timer(client->timer,
            (client->phase == HTTP_TUNNEL || client->phase == HTTP_RELAY)
                ? OTTIME_FOREVER
                : ottime(OTTIME_NOW, 60 * NSEC_PER_SEC),
            OTTIME_FOREVER, NSEC_PER_SEC);
    }
}

static void timeout_client(void *context)
{
    client_close(context);
}

#pragma mark - Stop Listening

bool outerssh_http_proxy_server_stop(OuterSSHHTTPProxyServer *server, uint64_t tag)
{
    SSHPoolEvent *reply = reserve(server, OUTERSSH_EVENT_OPERATION_COMPLETED, tag);
    if (reply == NULL) return false;
    outersshpriv_http_proxy_stop(server, reply);
    return true;
}

void outersshpriv_http_proxy_stop(OuterSSHHTTPProxyServer *server, SSHPoolEvent *reply)
{
    HTTPServerStopContext *request = malloc(sizeof(*request));
    if (!request) {
        outersshpriv_reply(reply, http_error("Could not allocate HTTP stop operation."));
        return;
    }
    *request = (HTTPServerStopContext){.server = server, .reply = reply};
    otqueue_async(server->queue, request, stop_server);
}

static void stop_server(void *context)
{
    HTTPServerStopContext *request = context;
    OuterSSHHTTPProxyServer *server = request->server;
    stop_listening(server);
    outersshpriv_forwarder_stop_on_queue(server->forwarder);
    outersshpriv_reply(request->reply, (OuterSSHError){0});
    free(request);
}

static void stop_listening(OuterSSHHTTPProxyServer *server)
{
    while (server->start_head) {
        HTTPServerStartContext *request = server->start_head;
        server->start_head = request->next;
        outersshpriv_reply_proxy_started(request->reply, 0, NULL, 0, NULL, 0, outerssh_proxy_closing_error());
        free(request);
    }
    server->start_tail = NULL;
    if (server->listener) {
        otsource_cancel(server->listener->source);
        otsource_release(server->listener->source);
        server->listener = NULL;
    }
    while (server->clients) client_close(server->clients);
}

#pragma mark - Identify Content by Its Origin

bool outerssh_http_proxy_server_add_origin_credentials(OuterSSHHTTPProxyServer *server,
    const char *username, size_t username_length, const char *password, size_t password_length,
    const char *origin, size_t origin_length, uint64_t tag)
{
    return password != NULL && outersshpriv_forwarder_submit_origin_credentials(server->forwarder,
        username, username_length, password, password_length, origin, origin_length, tag);
}

bool outerssh_http_proxy_server_remove_origin_credentials(OuterSSHHTTPProxyServer *server,
    const char *username, size_t username_length, uint64_t tag)
{
    return outersshpriv_forwarder_submit_origin_credentials(server->forwarder, username, username_length,
        NULL, 0, NULL, 0, tag);
}

#pragma mark - Destroy the Server and Close Clients

bool outerssh_http_proxy_server_destroy(OuterSSHHTTPProxyServer *server, uint64_t tag)
{
    SSHPoolEvent *reply = reserve(server, OUTERSSH_EVENT_DESTROYED, tag);
    if (reply == NULL) return false;
    outersshpriv_http_proxy_destroy(server, reply);
    return true;
}

void outersshpriv_http_proxy_destroy(OuterSSHHTTPProxyServer *server, SSHPoolEvent *reply)
{
    HTTPServerDestroyContext *request = malloc(sizeof(*request));
    if (!request) abort();
    *request = (HTTPServerDestroyContext){server, reply};
    otqueue_async(server->queue, request, destroy_server);
}

static void destroy_server(void *context)
{
    HTTPServerDestroyContext *request = context;
    OuterSSHHTTPProxyServer *server = request->server;
    server->destroyed_reply = request->reply;
    free(request);
    stop_listening(server);
    outersshpriv_forwarder_destroy_on_queue(server->forwarder, free_server, server);
    server_release(server);
}

static void listener_cancelled(void *context)
{
    HTTPListener *listener = context;
    OuterSSHHTTPProxyServer *server = listener->server;
    otsocket_close(listener->socket);
    if (server->closing_listener == listener) {
        server->closing_listener = NULL;
        HTTPServerStartContext *request = server->start_head;
        server->start_head = server->start_tail = NULL;
        while (request) {
            HTTPServerStartContext *next = request->next;
            request->next = NULL;
            start_server(request);
            request = next;
        }
    }
    free(listener);
    server_release(server);
}

static void client_close(HTTPClient *client)
{
    if (client->closed) {
        return;
    }
    client->closed = true;
    peer_cancel(client->peers[0]);
    peer_cancel(client->peers[1]);
    if (client->timer) {
        otsource_cancel(client->timer);
        otsource_release(client->timer);
        client->timer = NULL;
    }
    if (client->previous) {
        client->previous->next = client->next;
    } else {
        client->server->clients = client->next;
    }
    if (client->next) {
        client->next->previous = client->previous;
    }
    client->server->client_count--;
    client_release(client);
}

static void peer_cancel(HTTPPeer *peer)
{
    if (!peer || peer->cancelled) {
        return;
    }
    peer->cancelled = true;
    if (peer->client->peers[peer->index] == peer) {
        peer->client->peers[peer->index] = NULL;
    }
    if (peer->read) {
        set_source_enabled(peer->read, &peer->reading, true);
        otsource_cancel(peer->read);
        otsource_release(peer->read);
    }
    if (peer->write) {
        set_source_enabled(peer->write, &peer->writing, true);
        otsource_cancel(peer->write);
        otsource_release(peer->write);
    }
    if (!peer->sources) {
        peer->sources = 1;
        peer_cancelled(peer);
    }
}

static void peer_cancelled(void *context)
{
    HTTPPeer *peer = context;
    if (--peer->sources) {
        return;
    }
    otsocket_close(peer->socket);
    destroy_buffer(&peer->input);
    destroy_buffer(&peer->output);
    HTTPClient *client = peer->client;
    free(peer);
    client_release(client);
}

static void timer_cancelled(void *context)
{
    client_release(context);
}

static void client_release(HTTPClient *client)
{
    if (--client->references) {
        return;
    }
    OuterSSHHTTPProxyServer *server = client->server;
    clear_message_fields(&client->request);
    clear_message_fields(&client->response);
    destroy_buffer(&client->pending);
    outersshpriv_http_proxy_rewriter_destroy(client->rewriter);
    free(client->origin_socket_path);
    free(client);
    server_release(server);
}

static void server_release(OuterSSHHTTPProxyServer *server)
{
    if (--server->references) {
        return;
    }
    outersshpriv_proxy_server_end_work(server->forwarder);
}

static void free_server(void *context)
{
    OuterSSHHTTPProxyServer *server = context;
    SSHPoolEvent *destroyed_reply = server->destroyed_reply;
    free(server->authorization);
    free(server->realm);
    if (server->queue) otqueue_release(server->queue);
    free(server);
    if (destroyed_reply != NULL) outersshpriv_reply(destroyed_reply, (OuterSSHError){0});
}

static void clear_message_fields(HTTPMessage *message)
{
    for (size_t i = 0; i < 256; i++) {
        destroy_buffer(&message->fields[i].name);
        destroy_buffer(&message->fields[i].value);
    }
    destroy_buffer(&message->target);
    message->count = message->header_size = 0;
}

#pragma mark - Header Fields and Tokens

static const char *header_value(HTTPMessage *message, const char *name)
{
    for (size_t i = 0; i < message->count; i++) {
        if (!strcasecmp(message->fields[i].name.data, name)) {
            return message->fields[i].value.data;
        }
    }
    return NULL;
}

static bool is_hop_by_hop_header(HTTPMessage *message, const char *name)
{
    return !strcasecmp(name, "connection") || !strcasecmp(name, "proxy-connection") ||
           !strcasecmp(name, "proxy-authorization") || !strcasecmp(name, "proxy-authenticate") ||
           !strcasecmp(name, "keep-alive") || !strcasecmp(name, "te") || !strcasecmp(name, "trailer") ||
           !strcasecmp(name, "transfer-encoding") || !strcasecmp(name, "upgrade") ||
           connection_has_token(message, name);
}

static bool connection_has_token(HTTPMessage *message, const char *name)
{
    for (size_t i = 0; i < message->count; i++) {
        if (!strcasecmp(message->fields[i].name.data, "connection") &&
            header_has_token(message->fields[i].value.data, name)) {
            return true;
        }
    }
    return false;
}

static bool header_has_token(const char *list, const char *name)
{
    while (list && *list) {
        while (*list == ' ' || *list == '\t' || *list == ',') {
            list++;
        }
        const char *start = list;
        while (*list && *list != ',') {
            list++;
        }
        const char *end = list;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        if ((size_t)(end - start) == strlen(name) && !strncasecmp(start, name, (size_t)(end - start))) {
            return true;
        }
    }
    return false;
}

#pragma mark - Buffers and Dispatch Sources

static void queue_bytes(HTTPClient *client, HTTPBuffer *buffer, const void *bytes, size_t size)
{
    if (!client->closed && !append_bytes(buffer, bytes, size)) {
        client_close(client);
    }
}

static bool append_bytes(HTTPBuffer *buffer, const void *data, size_t size)
{
    if (size > BUFFER_LIMIT || buffer->size > BUFFER_LIMIT - size) {
        return false;
    }
    size_t needed = buffer->size + size + 1;
    if (needed > buffer->capacity) {
        size_t capacity = needed < 1024 ? 1024 : needed * 2;
        char *replacement = realloc(buffer->data, capacity);
        if (!replacement) {
            return false;
        }
        buffer->data = replacement;
        buffer->capacity = capacity;
    }
    if (size) {
        memcpy(buffer->data + buffer->size, data, size);
    }
    buffer->size += size;
    buffer->data[buffer->size] = 0;
    return true;
}

static bool append_text(HTTPBuffer *buffer, const char *text)
{
    return append_bytes(buffer, text, strlen(text));
}

static void consume_bytes(HTTPBuffer *buffer, size_t n)
{
    if (n > buffer->size) {
        n = buffer->size;
    }
    buffer->size -= n;
    if (buffer->data) {
        memmove(buffer->data, buffer->data + n, buffer->size);
        buffer->data[buffer->size] = 0;
    }
}

static void clear_buffer(HTTPBuffer *buffer)
{
    consume_bytes(buffer, buffer->size);
}

static void destroy_buffer(HTTPBuffer *buffer)
{
    free(buffer->data);
    *buffer = (HTTPBuffer){0};
}

static void set_source_enabled(otsource_t source, bool *enabled, bool wanted)
{
    if (source && *enabled != wanted) {
        *enabled = wanted;
        if (wanted) {
            otsource_resume(source);
        } else {
            otsource_suspend(source);
        }
    }
}

