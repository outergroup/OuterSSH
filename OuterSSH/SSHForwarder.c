#include "OuterSSH.h"
#include "SSHProxyErrorInternal.h"
#include "SSHSocketBridgeInternal.h"
#include "SSHEventsInternal.h"
#include "ProxyReactorInternal.h"
#include "ProxyPendingConnectionsInternal.h"
#include "SSHProxyAddress.h"
#include "platform/Base64.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    SSHForwarder *server;
    otsocket_t socket;
    ProxyConnectionRoute route;
    SSHSocketSender sender;
    bool refused;
    SSHForwarderConnectionCompletion completion;
    void *context;
} DirectConnectionContext;

static OuterSSHError server_error(const char *message);
static void initialize_forwarder(void *context);

static void start_server(void *context);
static void listener_closed_for_repair(void *context);
static void direct_connection_completed(void *context, ProxySOCKSReplyStatus status, bool forwarding_denied);
static void stop_server(void *context);
static void destroy_server(void *context);
static void free_server(void *context);

#pragma mark - Create the Shared Forwarder

SSHForwarder *outersshpriv_forwarder_create(OuterSSHSessionPool *pool,
    bool requires_authentication, const OuterSSHProxyCredentials *credentials, OuterSSHError *error)
{
    if (pool == NULL) {
        if (error != NULL) *error = server_error("An SSH session pool is required.");
        return NULL;
    }
    if (!outerssh_initialize(error)) {
        return NULL;
    }
    if ((!requires_authentication && credentials != NULL) ||
        (credentials != NULL &&
            (credentials->username == NULL || credentials->password == NULL ||
                credentials->username_length == 0 || credentials->password_length == 0 ||
                credentials->username_length > UINT8_MAX || credentials->password_length > UINT8_MAX))) {
        if (error != NULL) {
            *error = server_error("Invalid forwarding credentials.");
        }
        return NULL;
    }
    SSHForwarder *server = calloc(1, sizeof(*server));
    if (server == NULL) {
        goto allocation_failed;
    }
    server->queue = pool->_queue;
    otqueue_retain(server->queue);
    server->reactor = outersshpriv_proxy_reactor_create(server->queue);
    server->requires_authentication = requires_authentication;
    const OuterSSHProxyCredentials empty_credentials = {.username = "", .password = ""};
    if (!server->requires_authentication) {
        credentials = &empty_credentials;
    }
    int32_t status = 0;
    server->username_length = credentials == NULL ? 32 : credentials->username_length;
    server->password_length = credentials == NULL ? 32 : credentials->password_length;
    server->username = credentials == NULL ? outersshpriv_proxy_reactor_create_credential(16, &status)
                                        : malloc(server->username_length == 0 ? 1 : server->username_length);
    server->password = credentials == NULL ? outersshpriv_proxy_reactor_create_credential(16, &status)
                                        : malloc(server->password_length == 0 ? 1 : server->password_length);
    if (server->reactor == NULL || server->username == NULL || server->password == NULL) {
        goto allocation_failed;
    }
    if (credentials != NULL) {
        memcpy(server->username, credentials->username, server->username_length);
        memcpy(server->password, credentials->password, server->password_length);
    }
    server->reactor->server = server;
    server->pool = pool;
    otqueue_async(server->queue, server, initialize_forwarder);
    return server;
allocation_failed:
    if (error != NULL) {
        *error = server_error("Failed to allocate the SSH forwarder.");
    }
    if (server != NULL) {
        if (server->reactor != NULL) {
            outersshpriv_proxy_reactor_destroy(server->reactor, NULL, NULL);
        }
        free_server(server);
    }
    return NULL;
}

static OuterSSHError server_error(const char *message)
{
    return outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION, message, strlen(message), 0);
}

SSHForwarder *outersshpriv_tcp_forwarder_create(OuterSSHSessionPool *pool,
    const char *host, size_t host_length, uint16_t port, OuterSSHError *error)
{
    if (host_length == 0 || host_length >= PROXY_HOST_CAPACITY || memchr(host, 0, host_length) != NULL || port == 0) {
        if (error != NULL) *error = server_error("Invalid port forwarding destination.");
        return NULL;
    }
    SSHForwarder *forwarder = outersshpriv_forwarder_create(pool, false, NULL, error);
    if (forwarder == NULL) return NULL;
    ProxyConnectionRoute *route = &forwarder->forward_route;
    *route = (ProxyConnectionRoute){.kind = PROXY_CONNECTION_ROUTE_TCP};
    memcpy(route->request.host, host, host_length);
    route->request.host_length = host_length;
    route->request.port = port;
    memcpy(route->tcp.host, host, host_length);
    route->tcp.host_length = host_length;
    route->tcp.port = port;
    return forwarder;
}

static void initialize_forwarder(void *context)
{
    SSHForwarder *server = context;
    OuterSSHSessionPool *pool = server->pool;
    otqueue_assert(pool->_queue);
    assert(!pool->destroy_requested);
    outersshpriv_session_pool_begin_operation(pool);
    server->next_in_pool = pool->proxy_servers;
    pool->proxy_servers = server;
    if (++pool->proxy_generation == 0) ++pool->proxy_generation;
    server->generation = pool->proxy_generation;
}

#pragma mark - Start Listening

struct SSHForwarderStartContext {
    SSHForwarder *server;
    int32_t port;
    SSHPoolEvent *reply;
    SSHForwarderStartContext *next;
};

void outersshpriv_forwarder_start(SSHForwarder *server, int32_t port, SSHPoolEvent *reply)
{
    SSHForwarderStartContext *operation = calloc(1, sizeof(*operation));
    if (operation == NULL) {
        outersshpriv_reply_proxy_started(reply, 0, NULL, 0, NULL, 0, server_error("Failed to allocate proxy startup."));
        return;
    }
    *operation = (SSHForwarderStartContext){.server = server, .port = port, .reply = reply};
    otqueue_async(server->queue, operation, start_server);
}

static void start_server(void *context)
{
    SSHForwarderStartContext *operation = context;
    SSHForwarder *server = operation->server;
    ListenerSlot *listener = outersshpriv_proxy_reactor_listener_for_handle(server->reactor, server->listener);
    if (server->listener_repair_pending ||
        (server->running && listener && listener->socket != -1 &&
         (operation->port == 0 || operation->port == server->port) &&
         !otsocket_is_listening(listener->socket))) {
        if (server->start_tail) server->start_tail->next = operation;
        else server->start_head = operation;
        server->start_tail = operation;
        if (!server->listener_repair_pending) {
            server->listener_repair_pending = true;
            outersshpriv_proxy_server_begin_work(server);
            outersshpriv_proxy_reactor_close_listener_socket(server->reactor, server->listener,
                listener_closed_for_repair, server);
        }
        return;
    }
    OuterSSHError error = outersshpriv_forwarder_listen(server, operation->port);
    outersshpriv_reply_proxy_started(operation->reply, server->port, server->username, server->username_length,
        server->password, server->password_length, error);
    free(operation);
}

static void listener_closed_for_repair(void *context)
{
    SSHForwarder *server = context;
    server->listener_repair_pending = false;
    SSHForwarderStartContext *operation = server->start_head;
    server->start_head = server->start_tail = NULL;
    while (operation) {
        SSHForwarderStartContext *next = operation->next;
        operation->next = NULL;
        start_server(operation);
        operation = next;
    }
    outersshpriv_proxy_server_end_work(server);
}

OuterSSHError outersshpriv_forwarder_listen(SSHForwarder *server, int32_t port)
{
    otqueue_assert(server->queue);
    OuterSSHError error = {0};
    if (server->pool->shutdown_requested) return outerssh_proxy_closing_error();
    if (server->running) {
        if (port != 0 && port != server->port) {
            error = server_error("The proxy server is already active on another port.");
        } else {
            ListenerSlot *listener = outersshpriv_proxy_reactor_listener_for_handle(server->reactor, server->listener);
            if (listener && listener->socket == -1) {
                error = outersshpriv_proxy_reactor_reopen_listener(server->reactor, server->listener, server->port);
            }
        }
    } else {
        error = outersshpriv_proxy_reactor_create_listener(server->reactor, &server->listener, port,
            &server->port, server->username, server->username_length, server->password,
            server->password_length, server->requires_authentication, 120000);
        server->running = error.domain == OUTERSSH_ERROR_NONE;
        if (server->running) {
            if (++server->pool->proxy_generation == 0) ++server->pool->proxy_generation;
            server->generation = server->pool->proxy_generation;
            outersshpriv_proxy_reactor_listener_for_handle(server->reactor, server->listener)->forward_route = server->forward_route;
        }
    }
    return error;
}

void outersshpriv_forwarder_activate(SSHForwarder *server)
{
    otqueue_assert(server->queue);
    if (server->running) return;
    if (++server->pool->proxy_generation == 0) ++server->pool->proxy_generation;
    server->generation = server->pool->proxy_generation;
    server->running = true;
}

#pragma mark - Connect an HTTP Client

void outersshpriv_forwarder_connect(SSHForwarder *server, otsocket_t socket, const char *host, size_t host_length, uint16_t port,
    SSHSocketSender sender, SSHForwarderConnectionCompletion completion, void *context)
{
    otqueue_assert(server->queue);
    DirectConnectionContext *connection = calloc(1, sizeof(*connection));
    if (!connection) {
        otsocket_close(socket);
        completion(context, (SSHForwarderConnectionResult){.status = PROXY_SOCKS_REPLY_GENERAL_FAILURE});
        return;
    }
    *connection = (DirectConnectionContext){
        .server = server, .socket = socket, .sender = sender, .completion = completion, .context = context};
    ProxyConnectRequest request = {0};
    request.host_length = host_length;
    if (host_length == 0 || host_length >= sizeof(request.host) || memchr(host, 0, host_length)) {
        otsocket_close(socket);
        free(connection);
        completion(context, (SSHForwarderConnectionResult){.status = PROXY_SOCKS_REPLY_GENERAL_FAILURE});
        return;
    }
    memcpy(request.host, host, request.host_length);
    request.port = port;
    connection->route = outersshpriv_proxy_resolve_request(request);
    outersshpriv_proxy_server_begin_work(server);
    if (!server->running || server->destroy_requested || otsocket_set_nonblocking(connection->socket, true) ||
        otsocket_prevent_inheritance(connection->socket) || otsocket_configure_sigpipe(connection->socket)) {
        otsocket_close(connection->socket);
        direct_connection_completed(connection, PROXY_SOCKS_REPLY_GENERAL_FAILURE, false);
        return;
    }
    outersshpriv_proxy_reactor_start_direct_connection(
        server->reactor, connection->socket, connection->route, direct_connection_completed, connection);
}

static void direct_connection_completed(void *context, ProxySOCKSReplyStatus status, bool forwarding_denied)
{
    DirectConnectionContext *connection = context;
    connection->completion(connection->context, (SSHForwarderConnectionResult){
        .status = status,
        .forwarding_denied = forwarding_denied,
        .refused = connection->refused && status != PROXY_SOCKS_REPLY_SUCCEEDED,
    });
    outersshpriv_proxy_server_end_work(connection->server);
    free(connection);
}

bool outersshpriv_forwarder_connection_permits(SSHForwarder *server,
    ProxyReactorPendingConnectionHandle connection, const SSHSocketOwner *destination, bool uses_sudo)
{
    otqueue_assert(server->queue);
    ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(server->reactor, connection);
    if (pending == NULL || pending->direct_completion != direct_connection_completed) return true;
    DirectConnectionContext *context = pending->direct_context;
    if (outersshpriv_socket_sender_permits(&context->sender, destination,
            server->pool->_remoteUserIsRoot == 1, uses_sudo)) return true;
    context->refused = true;
    return false;
}

#pragma mark - Identify Content by Its Origin

struct SSHOriginCredentials {
    unsigned char username[UINT8_MAX];
    size_t username_length;
    unsigned char password[UINT8_MAX];
    size_t password_length;
    char *origin;
    size_t origin_length;
};

static void clear_origin_credentials(SSHOriginCredentials *credentials)
{
    volatile unsigned char *password = credentials->password;
    for (size_t i = 0; i < sizeof(credentials->password); i++) password[i] = 0;
    free(credentials->origin);
}

OuterSSHError outersshpriv_forwarder_set_origin_credentials(SSHForwarder *server,
    const char *username, size_t username_length, const char *password, size_t password_length,
    const char *origin, size_t origin_length)
{
    otqueue_assert(server->queue);
    size_t index = 0;
    while (index < server->origin_credential_count &&
           (server->origin_credentials[index].username_length != username_length ||
            memcmp(server->origin_credentials[index].username, username, username_length) != 0)) {
        index++;
    }
    if (password == NULL) {
        if (index < server->origin_credential_count) {
            clear_origin_credentials(&server->origin_credentials[index]);
            server->origin_credentials[index] = server->origin_credentials[--server->origin_credential_count];
        }
        return (OuterSSHError){0};
    }
    char *copy = malloc(origin_length + 1);
    if (copy == NULL) {
        static const char message[] = "Failed to allocate origin credentials.";
        return outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION, message, sizeof(message) - 1, ENOMEM);
    }
    memcpy(copy, origin, origin_length);
    copy[origin_length] = '\0';
    if (index == server->origin_credential_count) {
        SSHOriginCredentials *grown = realloc(server->origin_credentials,
            (server->origin_credential_count + 1) * sizeof(*grown));
        if (grown == NULL) {
            free(copy);
            static const char message[] = "Failed to allocate origin credentials.";
            return outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION, message, sizeof(message) - 1, ENOMEM);
        }
        server->origin_credentials = grown;
        server->origin_credential_count++;
    } else {
        clear_origin_credentials(&server->origin_credentials[index]);
    }
    SSHOriginCredentials *credentials = &server->origin_credentials[index];
    *credentials = (SSHOriginCredentials){
        .username_length = username_length,
        .password_length = password_length,
        .origin = copy,
        .origin_length = origin_length,
    };
    memcpy(credentials->username, username, username_length);
    memcpy(credentials->password, password, password_length);
    return (OuterSSHError){0};
}

bool outersshpriv_proxy_server_origin_for_credentials(SSHForwarder *server,
    const unsigned char *username, size_t username_length, const unsigned char *password, size_t password_length,
    char **origin, size_t *origin_length)
{
    *origin = NULL;
    *origin_length = 0;
    for (size_t index = 0; index < server->origin_credential_count; index++) {
        const SSHOriginCredentials *credentials = &server->origin_credentials[index];
        if (credentials->username_length != username_length || credentials->password_length != password_length ||
            memcmp(credentials->username, username, username_length) != 0 ||
            memcmp(credentials->password, password, password_length) != 0) {
            continue;
        }
        *origin = malloc(credentials->origin_length + 1);
        if (*origin == NULL) return false;
        memcpy(*origin, credentials->origin, credentials->origin_length + 1);
        *origin_length = credentials->origin_length;
        return true;
    }
    return false;
}

bool outersshpriv_proxy_server_origin_for_basic_authorization(SSHForwarder *server, const char *encoded,
    char **origin, size_t *origin_length)
{
    *origin = NULL;
    *origin_length = 0;
    for (size_t index = 0; index < server->origin_credential_count; index++) {
        const SSHOriginCredentials *credentials = &server->origin_credentials[index];
        unsigned char plain[UINT8_MAX + 1 + UINT8_MAX];
        unsigned char expected[4 * ((sizeof(plain) + 2) / 3) + 1];
        memcpy(plain, credentials->username, credentials->username_length);
        plain[credentials->username_length] = ':';
        memcpy(plain + credentials->username_length + 1, credentials->password, credentials->password_length);
        outerssh_base64_encode(expected, plain, credentials->username_length + 1 + credentials->password_length);
        volatile unsigned char *secret = plain;
        for (size_t i = 0; i < sizeof(plain); i++) secret[i] = 0;
        if (strcmp((const char *)expected, encoded) != 0) continue;
        *origin = malloc(credentials->origin_length + 1);
        if (*origin == NULL) return false;
        memcpy(*origin, credentials->origin, credentials->origin_length + 1);
        *origin_length = credentials->origin_length;
        return true;
    }
    return false;
}

typedef struct {
    SSHForwarder *forwarder;
    SSHPoolEvent *reply;
    size_t username_length;
    size_t password_length;
    size_t origin_length;
    bool removes;
    char bytes[];
} OriginCredentialsOperation;

static void apply_origin_credentials(void *context)
{
    OriginCredentialsOperation *operation = context;
    const char *username = operation->bytes;
    const char *password = username + operation->username_length;
    const char *origin = password + operation->password_length;
    OuterSSHError error = outersshpriv_forwarder_set_origin_credentials(operation->forwarder,
        username, operation->username_length, operation->removes ? NULL : password, operation->password_length,
        origin, operation->origin_length);
    outersshpriv_reply(operation->reply, error);
    volatile char *bytes = operation->bytes;
    for (size_t i = 0; i < operation->username_length + operation->password_length; i++) bytes[i] = 0;
    free(operation);
}

bool outersshpriv_forwarder_submit_origin_credentials(SSHForwarder *forwarder,
    const char *username, size_t username_length, const char *password, size_t password_length,
    const char *origin, size_t origin_length, uint64_t tag)
{
    bool removes = password == NULL;
    char normalized[PROXY_ORIGIN_CAPACITY];
    size_t normalized_length = 0;
    if (!forwarder->requires_authentication || username == NULL ||
        username_length == 0 || username_length > UINT8_MAX ||
        (forwarder->direct && memchr(username, ':', username_length) != NULL) ||
        (!removes && (password_length == 0 || password_length > UINT8_MAX)) ||
        (username_length == forwarder->username_length &&
         memcmp(username, forwarder->username, username_length) == 0)) {
        return false;
    }
    if (!removes) {
        ProxyConnectionRoute route;
        if (origin == NULL || !outersshpriv_proxy_parse_origin(origin, origin_length, normalized,
                &normalized_length, &route)) {
            return false;
        }
        origin = normalized;
        origin_length = normalized_length;
    }
    OriginCredentialsOperation *operation = malloc(sizeof(*operation) + username_length + password_length + origin_length);
    SSHPoolEvent *reply = operation == NULL ? NULL
        : outersshpriv_reply_reserve(forwarder->pool, OUTERSSH_EVENT_OPERATION_COMPLETED, tag);
    if (reply == NULL) {
        free(operation);
        return false;
    }
    *operation = (OriginCredentialsOperation){
        .forwarder = forwarder,
        .reply = reply,
        .username_length = username_length,
        .password_length = password_length,
        .origin_length = origin_length,
        .removes = removes,
    };
    memcpy(operation->bytes, username, username_length);
    if (password_length != 0) memcpy(operation->bytes + username_length, password, password_length);
    if (origin_length != 0) memcpy(operation->bytes + username_length + password_length, origin, origin_length);
    otqueue_async(forwarder->queue, operation, apply_origin_credentials);
    return true;
}

#pragma mark - Route Pending Connections to a Session Pool

void outersshpriv_proxy_server_pending_connection(
    SSHForwarder *server, ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route)
{
    if (server->running && !server->pool->shutdown_requested) {
        outersshpriv_proxy_reactor_set_connection_pool(
            server->reactor, connection, server->pool, server->generation);
        ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(server->reactor, connection);
        if (server->accept_tunnel && pending && pending->socks) {
            server->accept_tunnel(server->tunnel_context, connection, route);
            return;
        }
        outersshpriv_proxy_start_connection(
            (SSHProxyConnection){server, server->pool, server->generation}, connection, route);
    } else {
        outersshpriv_proxy_reactor_fail_pending_connection(
            server->reactor, connection, PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
    }
}

SSHProxyConnection outersshpriv_proxy_active_connection(SSHProxyConnection connection)
{
    if (!outersshpriv_proxy_connection_is_active(connection)) {
        connection.pool = NULL;
    }
    return connection;
}

bool outersshpriv_proxy_connection_is_active(SSHProxyConnection connection)
{
    otqueue_assert(connection.server->queue);
    return connection.server->running && !connection.pool->shutdown_requested &&
        connection.server->generation == connection.proxy_generation;
}

bool outersshpriv_proxy_pool_has_generation(OuterSSHSessionPool *pool, uint64_t generation)
{
    for (SSHForwarder *server = pool->proxy_servers; server != NULL; server = server->next_in_pool) {
        if (server->running && server->generation == generation) return true;
    }
    return false;
}

#pragma mark - Track Connection Work

void outersshpriv_proxy_connection_begin_work(SSHProxyConnection connection)
{
    outersshpriv_proxy_server_begin_work(connection.server);
    outersshpriv_session_pool_begin_operation(connection.pool);
}

void outersshpriv_proxy_connection_end_work(SSHProxyConnection connection)
{
    otqueue_assert(connection.server->queue);
    outersshpriv_session_pool_end_operation(connection.pool);
    outersshpriv_proxy_server_end_work(connection.server);
}

void outersshpriv_proxy_server_begin_work(SSHForwarder *server)
{
    otqueue_assert(server->queue);
    server->pending_work++;
}

void outersshpriv_proxy_server_end_work(SSHForwarder *server)
{
    otqueue_assert(server->queue);
    assert(server->pending_work != 0);
    server->pending_work--;
    if (server->destroy_requested && server->pending_work == 0) {
        outersshpriv_proxy_reactor_destroy(server->reactor, free_server, server);
    }
}

#pragma mark - Stop Listening and Destroy the Forwarder

typedef struct {
    SSHForwarder *server;
    SSHPoolEvent *reply;
} StopServerContext;

void outersshpriv_forwarder_stop(SSHForwarder *server, SSHPoolEvent *reply)
{
    StopServerContext *operation = malloc(sizeof(*operation));
    if (operation == NULL) {
        outersshpriv_reply(reply, server_error("Failed to allocate proxy shutdown."));
        return;
    }
    *operation = (StopServerContext){.server = server, .reply = reply};
    otqueue_async(server->queue, operation, stop_server);
}

static void stop_server(void *context)
{
    StopServerContext *operation = context;
    SSHForwarder *server = operation->server;
    outersshpriv_forwarder_stop_on_queue(server);
    outersshpriv_reply(operation->reply, (OuterSSHError){0});
    free(operation);
}

void outersshpriv_forwarder_stop_on_queue(SSHForwarder *server)
{
    otqueue_assert(server->queue);
    while (server->start_head) {
        SSHForwarderStartContext *operation = server->start_head;
        server->start_head = operation->next;
        outersshpriv_reply_proxy_started(operation->reply, 0, NULL, 0, NULL, 0, outerssh_proxy_closing_error());
        free(operation);
    }
    server->start_tail = NULL;
    if (server->running && !server->direct) {
        outersshpriv_proxy_reactor_remove_listener(server->reactor, server->listener);
    }
    server->running = false;
    outersshpriv_proxy_reactor_cancel_pool_pending_connections(server->reactor, server->pool, server->generation);
    outersshpriv_session_pool_close_proxy_connections(server->pool, server->generation);
}

void outersshpriv_forwarder_destroy(SSHForwarder *server, void (*completion)(void *), void *context)
{
    server->destruction_completion = completion;
    server->destruction_context = context;
    otqueue_async(server->queue, server, destroy_server);
}

static void destroy_server(void *context)
{
    SSHForwarder *server = context;
    outersshpriv_forwarder_destroy_on_queue(server, server->destruction_completion, server->destruction_context);
}

void outersshpriv_forwarder_destroy_on_queue(SSHForwarder *server,
    SSHDestroyHandler completion, void *context)
{
    otqueue_assert(server->queue);
    server->destruction_completion = completion;
    server->destruction_context = context;
    outersshpriv_forwarder_stop_on_queue(server);
    SSHForwarder **link = &server->pool->proxy_servers;
    while (*link != server) link = &(*link)->next_in_pool;
    *link = server->next_in_pool;
    server->destroy_requested = true;
    outersshpriv_session_pool_cancel_questions(server->pool, server);
    if (server->pending_work == 0) {
        outersshpriv_proxy_reactor_destroy(server->reactor, free_server, server);
    }
}

static void free_server(void *context)
{
    SSHForwarder *server = context;
    assert(server->pending_work == 0);
    if (server->pool != NULL) outersshpriv_session_pool_end_operation(server->pool);
    free(server->username);
    free(server->password);
    for (size_t index = 0; index < server->origin_credential_count; index++)
        clear_origin_credentials(&server->origin_credentials[index]);
    free(server->origin_credentials);
    otqueue_t queue = server->queue;
    void (*completion)(void *) = server->destruction_completion;
    void *completion_context = server->destruction_context;
    free(server);
    if (completion != NULL) {
        completion(completion_context);
    }
    if (queue != NULL) {
        otqueue_release(queue);
    }
}
