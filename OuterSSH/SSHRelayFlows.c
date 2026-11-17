#include "platform/OTSocket.h"
#include "SSHProxyErrorInternal.h"
#include "SSHSocketService.h"
#include "SocketBridgeCommands.h"
#include "SSHSocketBridgeInternal.h"
#include "SSHSessionPoolInternal.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ProxyReactorInternal.h"
#include "ProxyPendingConnectionsInternal.h"
#include "SSHFlows.h"
#include "platform/SSHLogging.h"

static const uint64_t relay_open_timeout_milliseconds = 10000;
static const uint32_t unknown_channel_type_reason = 3;
static const uint32_t administratively_prohibited_reason = 1;
static const uint32_t connect_failed_reason = 2;

#pragma mark - Forward an Incoming Connection

static void assign_tcp_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route);
static void assign_socket_connection_if_allowed(SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route);
static void assign_unix_connection(SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route);
static void prepare_relay(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route,
    SSHRelayTarget target);
void outersshpriv_proxy_fail_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route,
    OuterSSHError error);

void outersshpriv_proxy_start_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route)
{
    otqueue_assert(source.server->queue);
    switch (route.kind) {
    case PROXY_CONNECTION_ROUTE_TCP:
        assign_tcp_connection(source, connection, route);
        return;
    case PROXY_CONNECTION_ROUTE_UNIX_SOCKET:
        assign_socket_connection_if_allowed(source, connection, route);
        return;
    case PROXY_CONNECTION_ROUTE_REJECTED:
        outersshpriv_proxy_reactor_fail_pending_connection(
            source.server->reactor,
            connection,
            PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        return;
    }
}

static void assign_tcp_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route)
{
    SSHRelayTarget target = {.kind = SSHRelayTargetTCP, .port = route.tcp.port};
    if (route.tcp.host_length <= sizeof(target.destination)) {
        memcpy(target.destination, route.tcp.host, route.tcp.host_length);
        target.destination_length = route.tcp.host_length;
    }
    prepare_relay(source, connection, route, target);
}

#pragma mark - Prepare an Incoming Unix Socket Connection

typedef struct {
    SSHProxyConnection source;
    ProxyReactorPendingConnectionHandle connection;
    ProxyConnectionRoute route;
    union {
        struct {
            SocketAuthorizationRequest request;
        } authorization;
        struct {
            SSHSocketBridgeOperation operation;
            SSHSocketBridgeWaiter waiter;
        } bridge;
    };
    SSHWaiter waiter;
} PrepareRemoteSocketContext;

static void lookup_remote_user(OuterSSHSessionPool *pool,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context);
static void prepare_root_socket_connection(SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route);
static void root_socket_user_received(void *context, OuterSSHError error);
static void root_socket_bridge_ready(void *context, SSHBridgeResult result);
static void socket_connection_prepared(void *context, OuterSSHError error);
static void socket_connection_ready(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route,
    OuterSSHError error);

SSHSocketOwner outersshpriv_proxy_socket_owner(OuterSSHSessionPool *pool,
    const char *path, size_t path_length)
{
    otqueue_assert(pool->_queue);
    SSHSocketOwner owner = {0};
    SocketAuthorization *authorization = outersshpriv_socket_service_find_authorization(pool, path, path_length);
    if (authorization != NULL && authorization->pending == NULL) {
        owner.known = true;
        owner.session_owned = authorization->session_owned;
        owner.root = authorization->root_owned;
        owner.owner_length = authorization->owner_length;
        memcpy(owner.owner, authorization->owner, owner.owner_length);
        return owner;
    }
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_path(pool, path, path_length, NULL);
    if (bridge != NULL) {
        owner.known = true;
        owner.session_owned = !bridge->uses_sudo && pool->_remoteUserIsRoot != 1;
    }
    return owner;
}

/* Fails the connection, without a connection failure event, when its sender
 * may not reach the socket, or may not through sudo. */
static bool sender_permits(SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route, bool uses_sudo)
{
    SSHSocketOwner destination = outersshpriv_proxy_socket_owner(source.pool,
        route.unix_socket.path, route.unix_socket.path_length);
    if (outersshpriv_forwarder_connection_permits(source.server, connection, &destination, uses_sudo)) return true;
    outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor, connection,
        PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
    return false;
}

static void socket_authorized(SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route, OuterSSHError error)
{
    SocketAuthorization *authorization = error.domain == OUTERSSH_ERROR_NONE
        ? outersshpriv_socket_service_find_authorization(source.pool, route.unix_socket.path, route.unix_socket.path_length)
        : NULL;
    bool uses_sudo = authorization != NULL && authorization->connection_mode == HELPER_CONNECTION_PRIVILEGED &&
        source.pool->_remoteUserIsRoot != 1;
    if (authorization != NULL && !sender_permits(source, connection, route, uses_sudo)) return;
    if (uses_sudo && outersshpriv_proxy_active_connection(source).pool != NULL &&
        outersshpriv_proxy_reactor_pending_connection_is_active(source.server->reactor, connection)) {
        prepare_root_socket_connection(source, connection, route);
    } else {
        socket_connection_ready(source, connection, route, error);
    }
}

static void socket_authorization_completed(void *context, OuterSSHError error)
{
    PrepareRemoteSocketContext *preparation = context;
    socket_authorized(preparation->source, preparation->connection, preparation->route, error);
    outersshpriv_proxy_connection_end_work(preparation->source);
    free(preparation);
}

static void assign_socket_connection_if_allowed(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route)
{
    if (outersshpriv_proxy_active_connection(source).pool == NULL) {
        outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor, connection,
                                              PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        return;
    }
    if (!outersshpriv_proxy_socket_path_is_valid(route.unix_socket.path, route.unix_socket.path_length)) {
        static const char message[] = "The remote Unix socket path is invalid.";
        socket_connection_ready(source, connection, route, outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_UNIX_SOCKET_PATH, message, sizeof(message) - 1, 0));
        return;
    }
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_path(source.pool,
        route.unix_socket.path, route.unix_socket.path_length, NULL);
    if (bridge != NULL) {
        if (sender_permits(source, connection, route, bridge->uses_sudo))
            socket_connection_ready(source, connection, route, (OuterSSHError){0});
        return;
    }
    SocketAuthorization *authorization = outersshpriv_socket_service_find_authorization(source.pool, route.unix_socket.path, route.unix_socket.path_length);
    if (authorization != NULL && authorization->pending == NULL) {
        socket_authorized(source, connection, route, (OuterSSHError){0});
        return;
    }

    PrepareRemoteSocketContext *prep_context = malloc(sizeof(*prep_context));
    if (prep_context == NULL) {
        outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor, connection,
                                              PROXY_SOCKS_REPLY_GENERAL_FAILURE);
        return;
    }

    outersshpriv_proxy_connection_begin_work(source);
    *prep_context = (PrepareRemoteSocketContext){.source = source, .connection = connection, .route = route};
    if (authorization != NULL) {
        outersshpriv_socket_service_wait_for_authorization(authorization,
            &prep_context->waiter, socket_authorization_completed, prep_context);
    } else {
        outersshpriv_socket_service_authorize(source.pool, route.unix_socket.path,
            route.unix_socket.path_length, &prep_context->authorization.request,
            &prep_context->waiter, socket_authorization_completed, prep_context);
    }
}

static void socket_connection_ready(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route,
    OuterSSHError error)
{
    if (error.domain == OUTERSSH_ERROR_NONE) {
        SSHProxyConnection active_source = outersshpriv_proxy_active_connection(source);
        if (active_source.pool == NULL || !outersshpriv_proxy_reactor_pending_connection_is_active(source.server->reactor, connection)) {
            outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor, connection,
                PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
            return;
        }
        assign_unix_connection(source, connection, route);
    } else if (error.domain == OUTERSSH_ERROR_PROXY &&
               error.code == OUTERSSH_PROXY_ERROR_SUDO_PASSWORD_REQUIRED) {
        outersshpriv_proxy_request_sudo_for_connection(source, connection, route,
            route.unix_socket.path, route.unix_socket.path_length, error);
    } else {
        outersshpriv_proxy_fail_connection(source, connection, route, error);
    }
}

static void assign_unix_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route)
{
    const char *path = route.unix_socket.path;
    size_t path_length = route.unix_socket.path_length;
    if (path_length == 0) {
        outersshpriv_proxy_reactor_fail_pending_connection(
            source.server->reactor,
            connection,
            PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        return;
    }
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_path(source.pool, path, path_length, NULL);
    SocketAuthorization *authorization = outersshpriv_socket_service_find_authorization(source.pool, path, path_length);
    bool requires_bridge = authorization != NULL && authorization->connection_mode != HELPER_CONNECTION_DIRECT;
    if (bridge != NULL || source.pool->_directStreamLocalUnsupported || requires_bridge) {
        outersshpriv_proxy_assign_bridge_connection(source, connection, route,
            path, path_length, bridge != NULL && bridge->uses_sudo);
        return;
    }
    SSHRelayTarget target = {.kind = SSHRelayTargetUnixSocket};
    if (path_length <= sizeof(target.destination)) {
        memcpy(target.destination, path, path_length);
        target.destination_length = path_length;
    }
    prepare_relay(source, connection, route, target);
}

void outersshpriv_proxy_fail_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route,
    OuterSSHError error)
{
    ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(source.server->reactor, connection);
    if (pending) {
        pending->forwarding_denied = route.kind == PROXY_CONNECTION_ROUTE_TCP &&
            error.domain == OUTERSSH_ERROR_SESSION &&
            error.ssh_channel_open_reason == administratively_prohibited_reason;
    }
    SSHProxyConnection active_source = outersshpriv_proxy_active_connection(source);
    if (active_source.pool != NULL &&
        outersshpriv_proxy_reactor_pending_connection_is_active(source.server->reactor, connection)) {
        outersshpriv_session_pool_post_connection_failure(source.pool,
            active_source.server->frontend, route.request.host, route.request.host_length, route.request.port,
            route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET ? route.unix_socket.path : "",
            route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET ? route.unix_socket.path_length : 0,
            error);
    }
    if (active_source.pool != NULL && route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET &&
        error.domain == OUTERSSH_ERROR_SESSION && error.code == OUTERSSH_SESSION_ERROR_NOT_LISTENING) {
        outersshpriv_socket_service_found_nothing_listening(active_source.pool,
            route.unix_socket.path, route.unix_socket.path_length);
    }
    outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor, connection,
        outersshpriv_proxy_reply_status_for_error(error));
}

static void prepare_root_socket_connection(SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route)
{
    PrepareRemoteSocketContext *prep_context = malloc(sizeof(*prep_context));
    if (prep_context == NULL) {
        outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor, connection,
            PROXY_SOCKS_REPLY_GENERAL_FAILURE);
        return;
    }
    outersshpriv_proxy_connection_begin_work(source);
    *prep_context = (PrepareRemoteSocketContext){.source = source, .connection = connection, .route = route};
    lookup_remote_user(source.pool, &prep_context->waiter, root_socket_user_received, prep_context);
}

static void root_socket_user_received(void *context, OuterSSHError error)
{
    PrepareRemoteSocketContext *prep_context = context;
    if (error.domain == OUTERSSH_ERROR_NONE &&
        (outersshpriv_proxy_active_connection(prep_context->source).pool == NULL ||
         outersshpriv_session_pool_active(prep_context->source.pool) == NULL))
        error = outerssh_proxy_closing_error();
    if (error.domain != OUTERSSH_ERROR_NONE) {
        socket_connection_prepared(prep_context, error);
        return;
    }

    OuterSSHSessionPool *pool = prep_context->source.pool;
    if (pool->_remoteUserIsRoot == 1) {
        SocketAuthorization *authorization = outersshpriv_socket_service_find_authorization(
            pool, prep_context->route.unix_socket.path, prep_context->route.unix_socket.path_length);
        if (authorization != NULL) {
            if (authorization->pending == NULL) {
                socket_connection_prepared(prep_context, (OuterSSHError){0});
            } else {
                outersshpriv_socket_service_wait_for_authorization(authorization,
                    &prep_context->waiter, socket_connection_prepared, prep_context);
            }
        } else {
            outersshpriv_socket_service_authorize(pool, prep_context->route.unix_socket.path,
                prep_context->route.unix_socket.path_length, &prep_context->authorization.request,
                &prep_context->waiter, socket_connection_prepared, prep_context);
        }
        return;
    }

    outersshpriv_proxy_ensure_bridge(pool, (SSHBridgeRequest){
        .path = prep_context->route.unix_socket.path,
        .path_length = prep_context->route.unix_socket.path_length,
        .uses_sudo = true,
    }, &prep_context->bridge.operation, &prep_context->bridge.waiter, root_socket_bridge_ready, prep_context);
}

static void root_socket_bridge_ready(void *context, SSHBridgeResult result)
{
    socket_connection_prepared(context, result.error);
}

static void socket_connection_prepared(void *context, OuterSSHError error)
{
    PrepareRemoteSocketContext *prep_context = context;
    if (error.domain == OUTERSSH_ERROR_NONE && outersshpriv_session_pool_active(prep_context->source.pool) == NULL)
        error = outerssh_proxy_closing_error();
    socket_connection_ready(prep_context->source, prep_context->connection, prep_context->route, error);
    outersshpriv_proxy_connection_end_work(prep_context->source);
    free(prep_context);
}

#pragma mark - Look Up the Remote User Once Per Pool

static void remote_user_id_received(void *context,
    const SSHCommandOutput *result, OuterSSHError error);

/* Resumes once pool->_remoteUserIsRoot is known or cannot be. */
static void lookup_remote_user(OuterSSHSessionPool *pool,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    otqueue_assert(pool->_queue);
    if (outersshpriv_session_pool_active(pool) == NULL) {
        resume(context, outerssh_proxy_closing_error());
        return;
    }
    if (pool->_remoteUserIsRoot >= 0) {
        resume(context, (OuterSSHError){0});
        return;
    }
    if (!outersshpriv_wait(&pool->_remoteUserWaiters, waiter, resume, context)) return;
    static const char command[] = "id -u";
    outersshpriv_execute_command(pool, (SSHCommandRequest){
        .command = command, .command_byte_count = sizeof(command) - 1,
    }, remote_user_id_received, pool);
}

static void remote_user_id_received(void *context,
    const SSHCommandOutput *result, OuterSSHError error)
{
    OuterSSHSessionPool *pool = context;
    otqueue_assert(pool->_queue);
    if (error.domain == OUTERSSH_ERROR_NONE && outersshpriv_session_pool_active(pool) == NULL)
        error = outerssh_proxy_closing_error();
    if (error.domain == OUTERSSH_ERROR_NONE) {
        static const char lookup_failure_message[] = "Could not determine the remote user ID.";
        const unsigned char *bytes = result == NULL ? NULL : result->stdout_bytes;
        size_t start = 0, end = bytes == NULL ? 0 : result->stdout_byte_count;
        while (start < end && isspace(bytes[start])) start++;
        while (end > start && isspace(bytes[end - 1])) end--;
        bool valid = result != NULL && result->exit_status == 0 && start < end;
        bool is_root = true;
        for (size_t i = start; i < end; i++) {
            if (bytes[i] < '0' || bytes[i] > '9') valid = false;
            if (bytes[i] != '0') is_root = false;
        }
        if (valid) pool->_remoteUserIsRoot = is_root ? 1 : 0;
        else error = outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
            lookup_failure_message, sizeof(lookup_failure_message) - 1);
    }
    outersshpriv_wake(&pool->_remoteUserWaiters, error);
}

#pragma mark - Open and Attach a Relay

struct ConnectRelayContext {
    SSHProxyConnection source;
    ProxyReactorPendingConnectionHandle connection;

    ProxyConnectionRoute route;
    SSHSessionPoolSessionHandle session;
    SSHReactorRelayHandle relay_handle;
    SSHReactor *starting_reactor;
    SSHRelayTarget target;
    bool may_retry;
    OuterSSHError completed_error;
    char *error_storage;
    otsocket_t socket;
    uint64_t relay_identifier;
    uint64_t proxy_generation;
    SSHWaiter waiter;
};

static void ssh_relay_session_request_finished(void *context, OuterSSHError error);
static void start_prepared_relay_on_reactor(void *opaque_context);
static void finish_prepared_relay_on_pool(void *opaque_context);
static void relay_preparation_failed(ConnectRelayContext *relay_context, OuterSSHError error);
static void cancel_prepared_relay(const ConnectRelayContext *relay_context);
static void prepared_relay_socket_transferred(void *context, otsocket_t socket);
static void attach_prepared_relay_socket(void *opaque_context);
static void destroy_relay_context(void *context);

static void prepare_relay(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route,
    SSHRelayTarget target)
{
    ConnectRelayContext *relay_context = calloc(1, sizeof(*relay_context));
    if (relay_context == NULL) {
        outersshpriv_proxy_reactor_fail_pending_connection(
            source.server->reactor,
            connection,
            PROXY_SOCKS_REPLY_GENERAL_FAILURE);
        return;
    }
    outersshpriv_proxy_connection_begin_work(source);
    relay_context->source = source;
    relay_context->connection = connection;

    relay_context->route = route;
    relay_context->target = target;
    relay_context->may_retry = true;
    relay_context->socket = -1;
    outersshpriv_session_pool_run_when_ready(relay_context->source.pool, &relay_context->waiter,
        ssh_relay_session_request_finished, relay_context);
}

static void ssh_relay_session_request_finished(void *context, OuterSSHError error)
{
    ConnectRelayContext *relay_context = context;
    otqueue_assert(relay_context->source.pool->_queue);
    SSHSessionPoolSessionHandle session;
    SSHReactor *reactor = outersshpriv_session_pool_ready_reactor(relay_context->source.pool, &session, &error);
    if (error.domain != OUTERSSH_ERROR_NONE) {
        relay_preparation_failed(relay_context, error);
        return;
    }
    // While waiting for a session, the browser connection may close,
    // the proxy may stop, or the pool may be removed from the proxy.
    if (!outersshpriv_proxy_reactor_pending_connection_is_active(
            relay_context->source.server->reactor, relay_context->connection) ||
        !outersshpriv_proxy_connection_is_active(relay_context->source)) {
        outersshpriv_proxy_reactor_fail_pending_connection(
            relay_context->source.server->reactor,
            relay_context->connection,
            PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        destroy_relay_context(relay_context);
        return;
    }
    relay_context->session = session;
    relay_context->starting_reactor = reactor;
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        relay_context,
        start_prepared_relay_on_reactor);
}

static void start_prepared_relay_on_reactor(void *context)
{
    ConnectRelayContext *relay_context = context;
    SSHReactor *reactor = relay_context->starting_reactor;
    relay_context->starting_reactor = NULL;
    SSHReactorRelayHandle handle = {0};
    static const char loopback_host[] = "127.0.0.1";
    // Calls `outersshpriv_session_pool_prepared_relay_completed` on completion.
    int result = outersshpriv_reactor_prepare_relay(
        reactor,
        &handle,
        relay_context,
        &relay_context->target,
        loopback_host, sizeof(loopback_host) - 1,
        0,
        relay_open_timeout_milliseconds);
    if (result != 0) {
        relay_context->completed_error = outerssh_session_error_format(&relay_context->error_storage,
            OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_START_FAILED,
            "Failed to start opening an SSH channel (code %d).",
            result);
        otqueue_async(
            relay_context->source.pool->_queue,
            relay_context,
            finish_prepared_relay_on_pool);
    }
}

void outersshpriv_session_pool_prepared_relay_completed(
    ConnectRelayContext *relay_context,
    SSHReactorRelayHandle handle,
    SSHReactorRelayOpenResult result,
    uint32_t reason)
{
    relay_context->relay_handle = handle;
    switch (result) {
    case SSH_REACTOR_RELAY_OPEN_SUCCEEDED:
        relay_context->completed_error = (OuterSSHError){0};
        break;
    case SSH_REACTOR_RELAY_OPEN_CHANNEL_FAILED: {
        /* The server could not connect to its own socket or loopback port:
         * nothing is listening there. */
        bool not_listening = reason == connect_failed_reason &&
            (relay_context->target.kind == SSHRelayTargetUnixSocket ||
             (relay_context->route.kind == PROXY_CONNECTION_ROUTE_TCP && relay_context->route.tcp.loopback));
        relay_context->completed_error = not_listening
            ? outerssh_session_error_format(&relay_context->error_storage, OUTERSSH_SESSION_ERROR_NOT_LISTENING,
                "Nothing is listening at the destination (reason %u).", reason)
            : outerssh_session_error_format(&relay_context->error_storage, OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE,
                "The SSH server rejected the channel (reason %u).", reason);
        relay_context->completed_error.ssh_channel_open_reason = reason;
        break;
    }
    case SSH_REACTOR_RELAY_OPEN_TIMED_OUT: {
        static const char message[] = "The remote server took too long to open the channel.";
        relay_context->completed_error = outerssh_session_error(OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_TIMED_OUT,
            message, sizeof(message) - 1);
        break;
    }
    case SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED: {
        static const char message[] = "The SSH session is no longer available.";
        relay_context->completed_error = outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
            message, sizeof(message) - 1);
        break;
    }
    case SSH_REACTOR_RELAY_OPEN_CANCELLED: {
        static const char message[] = "The SSH operation was cancelled.";
        relay_context->completed_error = outerssh_session_error(OUTERSSH_SESSION_ERROR_CANCELLED,
            message, sizeof(message) - 1);
        break;
    }
    default:
        abort();
    }
    otqueue_async(
        relay_context->source.pool->_queue,
        relay_context,
        finish_prepared_relay_on_pool);
}

static void finish_prepared_relay_on_pool(void *opaque_context)
{
    ConnectRelayContext *relay_context = opaque_context;
    SSHProxyConnection source = relay_context->source;
    SSHSessionPoolSessionHandle session = relay_context->session;
    otqueue_assert(source.pool->_queue);
    OuterSSHError error = relay_context->completed_error;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        if (relay_context->may_retry &&
            (error.code == OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_START_FAILED ||
             error.code == OUTERSSH_SESSION_ERROR_UNAVAILABLE ||
             error.code == OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_TIMED_OUT)) {
            outersshpriv_remove_session(source.pool, session);
            relay_context->may_retry = false;
            free(relay_context->error_storage);
            relay_context->error_storage = NULL;
            relay_context->completed_error = (OuterSSHError){0};
            outersshpriv_session_pool_run_when_ready(source.pool, &relay_context->waiter,
                ssh_relay_session_request_finished, relay_context);
            return;
        }

        relay_preparation_failed(relay_context, error);
        return;
    }

    ProxyReactorPendingConnectionHandle connection = relay_context->connection;
    // While preparing the relay, the browser connection may close,
    // the proxy may stop, or the pool may be removed from the proxy.
    if (!outersshpriv_proxy_reactor_pending_connection_is_active(
            source.server->reactor, connection) ||
        !outersshpriv_proxy_connection_is_active(source)) {
        cancel_prepared_relay(relay_context);
        outersshpriv_proxy_reactor_fail_pending_connection(
            source.server->reactor,
            connection,
            PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        destroy_relay_context(relay_context);
        return;
    }

    outersshpriv_proxy_reactor_complete_pending_connection(source.server->reactor, connection,
        prepared_relay_socket_transferred, relay_context);
}

static void relay_preparation_failed(ConnectRelayContext *relay_context, OuterSSHError error)
{
    SSHProxyConnection source = relay_context->source;
    ProxyReactorPendingConnectionHandle connection = relay_context->connection;
    ProxyConnectionRoute route = relay_context->route;
    if (relay_context->target.kind == SSHRelayTargetUnixSocket &&
        error.code == OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE &&
        error.ssh_channel_open_reason == unknown_channel_type_reason) {
        source.pool->_directStreamLocalUnsupported = true;
        outersshpriv_proxy_assign_bridge_connection(
            source,
            connection,
            route,
            route.unix_socket.path, route.unix_socket.path_length, false);
    } else {
        outersshpriv_proxy_fail_connection(source, connection, route, error);
    }
    destroy_relay_context(relay_context);
}

static void prepared_relay_socket_transferred(void *context, otsocket_t socket)
{
    ConnectRelayContext *relay_context = context;
    SSHProxyConnection source = relay_context->source;
    SSHProxyConnection active_source = outersshpriv_proxy_active_connection(source);
    if (socket < 0 || active_source.pool == NULL) {
        if (socket >= 0) {
            otsocket_close(socket);
        }
        cancel_prepared_relay(relay_context);
        destroy_relay_context(relay_context);
        return;
    }
    SSHReactor *reactor = outersshpriv_session_pool_reactor_for_session(
        source.pool,
        relay_context->session);
    if (reactor == NULL) {
        otsocket_close(socket);
        cancel_prepared_relay(relay_context);
        destroy_relay_context(relay_context);
        return;
    }
    uint64_t identifier = source.pool->_nextRelayIdentifier++;
    if (source.pool->_nextRelayIdentifier == 0) {
        source.pool->_nextRelayIdentifier = 1;
    }
    relay_context->starting_reactor = reactor;
    relay_context->socket = socket;
    relay_context->relay_identifier = identifier;
    relay_context->proxy_generation = active_source.proxy_generation;
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        relay_context,
        attach_prepared_relay_socket);
}

static void attach_prepared_relay_socket(void *opaque_context)
{
    ConnectRelayContext *relay_context = opaque_context;
    SSHReactor *reactor = relay_context->starting_reactor;
    otsocket_t socket = relay_context->socket;
    relay_context->socket = -1;
    SSHRelayTarget target = relay_context->target;
    int result = outersshpriv_reactor_attach_prepared_relay(
        reactor,
        relay_context->relay_handle,
        socket,
        relay_context->relay_identifier,
        relay_context->proxy_generation,
        target.kind == SSHRelayTargetTCP
            ? SSH_RELAY_TARGET_TCP
            : SSH_RELAY_TARGET_STREAMLOCAL,
        target.destination,
        target.destination_length,
        target.port);
    if (result != 0) {
        SSH_LOG_ERROR(
            SSH_LOG_CATEGORY_RELAY,
            "Failed to attach an SSH proxy relay (code %{public}d)",
            result);
    }
    otqueue_async(relay_context->source.server->queue, relay_context, destroy_relay_context);
}

static void destroy_relay_context(void *context)
{
    ConnectRelayContext *relay_context = context;
    SSHProxyConnection source = relay_context->source;
    free(relay_context->error_storage);
    free(relay_context);
    outersshpriv_proxy_connection_end_work(source);
}

#pragma mark - Cancel a Prepared Relay

typedef struct {
    SSHReactor *reactor;
    SSHReactorRelayHandle handle;
} CancelPreparedRelayContext;

static void cancel_prepared_relay_on_reactor(void *opaque_context);

static void cancel_prepared_relay(const ConnectRelayContext *relay_context)
{
    OuterSSHSessionPool *pool = relay_context->source.pool;
    otqueue_assert(pool->_queue);
    SSHReactor *reactor = outersshpriv_session_pool_reactor_for_session(
        pool,
        relay_context->session);
    if (reactor == NULL) {
        return;
    }
    CancelPreparedRelayContext *context = malloc(sizeof(*context));
    if (context == NULL) {
        outersshpriv_remove_session(pool, relay_context->session);
        return;
    }
    *context = (CancelPreparedRelayContext){
        .reactor = reactor,
        .handle = relay_context->relay_handle
    };
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        context,
        cancel_prepared_relay_on_reactor);
}

static void cancel_prepared_relay_on_reactor(void *opaque_context)
{
    CancelPreparedRelayContext *context = opaque_context;
    (void)outersshpriv_reactor_cancel_prepared_relay(
        context->reactor,
        context->handle);
    free(context);
}

#pragma mark - Report Forwarding Errors

ProxySOCKSReplyStatus outersshpriv_proxy_reply_status_for_error(OuterSSHError error)
{
    if (error.domain == OUTERSSH_ERROR_SESSION) {
        switch ((OuterSSHSessionErrorCode)error.code) {
            case OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE:
                if (error.ssh_channel_open_reason == administratively_prohibited_reason)
                    return PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED;
                return PROXY_SOCKS_REPLY_CONNECTION_REFUSED;
            case OUTERSSH_SESSION_ERROR_NOT_LISTENING:
                return PROXY_SOCKS_REPLY_CONNECTION_REFUSED;
            case OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_TIMED_OUT:
                return PROXY_SOCKS_REPLY_HOST_UNREACHABLE;
            default:
                break;
        }
    }
    return PROXY_SOCKS_REPLY_GENERAL_FAILURE;
}
