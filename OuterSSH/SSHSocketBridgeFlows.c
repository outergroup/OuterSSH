#include "SSHSocketBridgeInternal.h"
#include "SSHProxyErrorInternal.h"
#include "SSHSocketService.h"
#include "ProxyReactorInternal.h"
#include "SSHEventsInternal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <limits.h>

#include "SSHFlows.h"
#include "SocketBridgeCommands.h"

static const uint64_t bridge_channel_open_timeout_milliseconds = 5000;
static const uint64_t bridge_ready_timeout_milliseconds = 10000;
static const uint64_t bridge_stream_timeout_milliseconds = 30000;

struct SSHSocketBridgeContext {
    OuterSSHSessionPool *pool;
    SSHSessionPoolSessionHandle session;
    SSHProxyBridgeHandle bridge;
    SSHSocketBridgeOperation *setup;
    bool reported_ready;
    bool exited_before_ready;
    SSHReactorSocketBridgeHandle completed_handle;
};

static void handle_bridge_failure(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route,
    SSHProxyBridgeHandle bridge_handle,
    bool did_retry,
    bool is_recovery,
    OuterSSHError error);
static void finish_bridge_ended(void *opaque_context);
static void destroy_bridge_context(SSHSocketBridgeContext *context);
static OuterSSHError bridge_unavailable_error(void);
static OuterSSHError socket_bridge_result_error(
    char **storage,
    bool uses_sudo,
    SSHReactorSocketBridgeResult result,
    uint32_t reason,
    const void *detail,
    size_t detail_length);
static bool session_handles_equal(
    SSHSessionPoolSessionHandle left,
    SSHSessionPoolSessionHandle right);

#pragma mark - Start or Reuse a Socket Bridge

static void bridge_executable_ready(void *context, OuterSSHError error);
static void ssh_bridge_session_request_finished(void *opaque_operation, OuterSSHError error);
static void start_bridge_on_reactor(void *opaque_context);
static void finish_bridge_ready(void *opaque_context);
static void finish_bridge_failed(void *opaque_context);
static void bridge_start_failed(
    SSHSocketBridgeOperation *operation,
    OuterSSHError error);
static void complete_bridge_setup(
    SSHSocketBridgeOperation *operation,
    SSHProxyBridgeHandle bridge,
    OuterSSHError error);

static void deliver_bridge_result(void *context, OuterSSHError error)
{
    (void)error;
    SSHSocketBridgeWaiter *waiter = context;
    waiter->finished(waiter->context, waiter->result);
}

void outersshpriv_proxy_ensure_bridge(
    OuterSSHSessionPool *pool,
    SSHBridgeRequest request, SSHSocketBridgeOperation *operation,
    SSHSocketBridgeWaiter *waiter, SSHProxyBridgeHandler finished,
    void *context)
{
    otqueue_assert(pool->_queue);
    SSHProxyBridgeHandle existing_handle;
    SSHProxyBridgeState *existing = outersshpriv_proxy_bridge_for_path(
        pool, request.path, request.path_length, &existing_handle);
    SSHProxyBridgeHandle failed_bridge = request.failed_bridge;
    if (existing != NULL) {
        if (existing->uses_sudo != request.uses_sudo) {
            static const char error_message[] = "The remote Unix socket path is already bridged with a different privilege mode.";
            finished(context, (SSHBridgeResult){
                .failed_bridge = failed_bridge,
                .error = outersshpriv_proxy_error(
                    OUTERSSH_PROXY_ERROR_BRIDGE_PRIVILEGE_CONFLICT,
                    error_message, sizeof(error_message) - 1, 0),
            });
            return;
        }
        if (!existing->stopped) {
            finished(context, (SSHBridgeResult){.bridge = existing_handle});
            return;
        }
        if (failed_bridge.generation == 0) {
            failed_bridge = existing_handle;
        }
    }

    SSHSocketBridgeOperation *setup = pool->_bridgeSetupHead;
    for (; setup != NULL; setup = setup->next_setup) {
        if (setup->request.path_length != request.path_length ||
            memcmp(setup->request.path, request.path, request.path_length) != 0) {
            continue;
        }
        if (setup->request.uses_sudo != request.uses_sudo) {
            static const char error_message[] = "The remote Unix socket path is already being bridged with a different privilege mode.";
            finished(context, (SSHBridgeResult){
                .failed_bridge = failed_bridge,
                .error = outersshpriv_proxy_error(
                    OUTERSSH_PROXY_ERROR_BRIDGE_PRIVILEGE_CONFLICT,
                    error_message,
                    sizeof(error_message) - 1, 0),
            });
            return;
        }
        if (failed_bridge.generation == 0) {
            failed_bridge = setup->failed_bridge;
        }
        break;
    }

    *waiter = (SSHSocketBridgeWaiter){.finished = finished, .context = context,
        .failed_bridge = failed_bridge};
    if (setup != NULL) {
        outersshpriv_wait(&setup->requesters, &waiter->waiter, deliver_bridge_result, waiter);
        return;
    }

    *operation = (SSHSocketBridgeOperation){
        .retry_cached_executable = request.uses_sudo
            ? pool->_sudoBridgeExecutablePath != NULL
            : pool->_userBridgeExecutablePath != NULL,
        .request = request,
        .pool = pool,
        .failed_bridge = failed_bridge,
    };
    outersshpriv_wait(&operation->requesters, &waiter->waiter, deliver_bridge_result, waiter);
    if (existing != NULL) {
        outersshpriv_proxy_stop_bridge(pool, existing_handle);
        existing->is_current = false;
    }
    operation->next_setup = pool->_bridgeSetupHead;
    pool->_bridgeSetupHead = operation;
    outersshpriv_session_pool_begin_operation(pool);

    if (operation->request.uses_sudo) {
        outersshpriv_proxy_ensure_sudo_bridge_executable(
            pool, operation->request.sudo_password, operation->request.sudo_password_length,
            &operation->waiter, bridge_executable_ready, operation);
    } else {
        outersshpriv_proxy_ensure_user_bridge_executable(
            pool, &operation->waiter, bridge_executable_ready, operation);
    }
}

static void bridge_executable_ready(void *context, OuterSSHError error)
{
    SSHSocketBridgeOperation *operation = context;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        complete_bridge_setup(operation, (SSHProxyBridgeHandle){0}, error);
        return;
    }
    OuterSSHSessionPool *pool = operation->pool;
    OuterSSHSessionPool *active_pool = outersshpriv_session_pool_active(
        pool);
    if (active_pool == NULL) {
        complete_bridge_setup(
            operation,
            (SSHProxyBridgeHandle){0},
            outerssh_proxy_closing_error());
        return;
    }
    char *command = operation->request.uses_sudo
        ? outersshpriv_socket_bridge_launch_command(
            operation->request.path, operation->request.path_length,
            pool->_sudoBridgeExecutablePath, pool->_sudoBridgeExecutablePath_length, pool->socket_allowlist_arguments,
            operation->request.sudo_password != NULL, &operation->command_byte_count)
        : outersshpriv_socket_bridge_launch_user_command(
            operation->request.path, operation->request.path_length,
            pool->_userBridgeExecutablePath, pool->_userBridgeExecutablePath_length,
            pool->socket_allowlist_arguments, &operation->command_byte_count);
    size_t initial_input_byte_count = operation->request.sudo_password == NULL
        ? 0
        : operation->request.sudo_password_length + 1;
    char *initial_input = initial_input_byte_count == 0
        ? NULL
        : malloc(initial_input_byte_count);
    if (initial_input != NULL) {
        memcpy(
            initial_input,
            operation->request.sudo_password,
            initial_input_byte_count - 1);
        initial_input[initial_input_byte_count - 1] = '\n';
    }
    if (command == NULL ||
        (initial_input_byte_count != 0 && initial_input == NULL)) {
        static const char error_message[] = "Failed to allocate the socket bridge command.";
        free(command);
        free(initial_input);
        complete_bridge_setup(
            operation,
            (SSHProxyBridgeHandle){0},
            outersshpriv_proxy_error(
                OUTERSSH_PROXY_ERROR_REACTOR_CREATION_FAILED,
                error_message, sizeof(error_message) - 1,
                0));
        return;
    }
    SSHProxyBridgeHandle bridge;
    SSHProxyBridgeState *state = outersshpriv_proxy_append_bridge_state(
        active_pool,
        operation->request.path, operation->request.path_length,
        operation->request.uses_sudo,
        &bridge);
    if (state == NULL) {
        static const char error_message[] = "Failed to allocate socket bridge state.";
        free(command);
        free(initial_input);
        complete_bridge_setup(
            operation,
            (SSHProxyBridgeHandle){0},
            outersshpriv_proxy_error(
                OUTERSSH_PROXY_ERROR_REACTOR_CREATION_FAILED,
                error_message, sizeof(error_message) - 1,
                0));
        return;
    }
    operation->bridge = bridge;
    operation->command = command;
    operation->initial_input = initial_input;
    operation->initial_input_byte_count = initial_input_byte_count;
    outersshpriv_session_pool_run_when_ready(operation->pool, &operation->waiter,
        ssh_bridge_session_request_finished, operation);
}

/* Detach before callbacks, which may synchronously request another bridge. */
static void complete_bridge_setup(
    SSHSocketBridgeOperation *operation,
    SSHProxyBridgeHandle bridge,
    OuterSSHError error)
{
    OuterSSHSessionPool *pool = operation->pool;
    SSHSocketBridgeOperation **link = &pool->_bridgeSetupHead;
    while (*link != NULL && *link != operation) {
        link = &(*link)->next_setup;
    }
    if (*link == operation) {
        *link = operation->next_setup;
    }
    SSHProxyBridgeHandle attempted_bridge = operation->bridge;
    /* The first requester owns operation and may free it when resumed. */
    SSHWaitList requesters = operation->requesters;
    char *error_storage = operation->error_storage;
    free(operation->command);
    free(operation->initial_input);
    for (SSHWaiter *entry = requesters.head; entry != NULL; entry = entry->next) {
        SSHSocketBridgeWaiter *waiter = entry->context;
        waiter->result = (SSHBridgeResult){.bridge = bridge, .error = error};
        if (error.domain != OUTERSSH_ERROR_NONE) {
            waiter->result.failed_bridge = attempted_bridge.generation != 0
                ? attempted_bridge : waiter->failed_bridge;
        }
    }
    outersshpriv_wake(&requesters, error);
    free(error_storage);
    outersshpriv_session_pool_end_operation(pool);
}

static void ssh_bridge_session_request_finished(void *opaque_operation, OuterSSHError error)
{
    SSHSocketBridgeOperation *operation = opaque_operation;
    OuterSSHSessionPool *pool = operation->pool;
    otqueue_assert(pool->_queue);
    SSHSessionPoolSessionHandle session;
    SSHReactor *reactor = outersshpriv_session_pool_ready_reactor(pool, &session, &error);
    if (error.domain != OUTERSSH_ERROR_NONE) {
        bridge_start_failed(
            operation,
            error);
        return;
    }
    SSHSocketBridgeContext *context = calloc(1, sizeof(*context));
    if (context == NULL) {
        static const char allocation_message[] = "Failed to allocate the socket bridge context.";
        bridge_start_failed(operation, outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
            allocation_message, sizeof(allocation_message) - 1));
        return;
    }
    context->pool = pool;
    outersshpriv_session_pool_begin_operation(pool);
    context->session = session;

    context->bridge = operation->bridge;
    context->setup = operation;
    operation->starting_reactor = reactor;
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        context,
        start_bridge_on_reactor);
}

static void start_bridge_on_reactor(void *opaque_context)
{
    SSHSocketBridgeContext *context = opaque_context;
    SSHSocketBridgeOperation *operation = context->setup;
    SSHReactor *reactor = operation->starting_reactor;
    operation->starting_reactor = NULL;
    SSHReactorSocketBridgeHandle handle = {0};
    int result = outersshpriv_reactor_start_socket_channel(
        reactor,
        &handle,
        (SSHSocketChannelCallbacks){.context = context, .completed = outersshpriv_session_pool_socket_bridge_completed},
        operation->command,
        operation->command_byte_count,
        operation->initial_input,
        operation->initial_input_byte_count,
        bridge_channel_open_timeout_milliseconds,
        bridge_ready_timeout_milliseconds);
    if (result != 0) {
        operation->completed_error = outerssh_session_error_format(&operation->error_storage,
            OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_START_FAILED,
            "Failed to start the remote socket bridge (code %d).",
            result);
        otqueue_async(
            operation->pool->_queue,
            context,
            finish_bridge_failed);
    }
}

void outersshpriv_session_pool_socket_bridge_completed(
    void *opaque_context,
    SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result,
    uint32_t reason,
    const void *detail,
    size_t detail_length)
{
    SSHSocketBridgeContext *context = opaque_context;
    OuterSSHSessionPool *pool = context->pool;
    if (result == SSH_REACTOR_SOCKET_BRIDGE_READY) {
        if (context->reported_ready) {
            return;
        }
        context->reported_ready = true;
        context->completed_handle = handle;
        otqueue_async(pool->_queue, context, finish_bridge_ready);
        return;
    }
    if (context->reported_ready) {
        otqueue_async(pool->_queue, context, finish_bridge_ended);
        return;
    }
    context->exited_before_ready = result == SSH_REACTOR_SOCKET_BRIDGE_EXITED;
    context->setup->completed_error = socket_bridge_result_error(
        &context->setup->error_storage,
        context->setup->request.uses_sudo,
        result,
        reason,
        detail,
        detail_length);
    otqueue_async(pool->_queue, context, finish_bridge_failed);
}

static void finish_bridge_ready(void *opaque_context)
{
    SSHSocketBridgeContext *context = opaque_context;
    SSHSocketBridgeOperation *operation = context->setup;
    context->setup = NULL;
    otqueue_assert(operation->pool->_queue);
    SSHSocketBridge socket_bridge = {
        .handle = context->completed_handle,
        .pool = operation->pool,
        .session = context->session
    };
    OuterSSHSessionPool *pool = operation->pool;

    SSHProxyBridgeHandle bridge_handle = operation->bridge;
    OuterSSHSessionPool *active_pool = outersshpriv_session_pool_active(
        pool);
    if (active_pool == NULL) {
        outersshpriv_socket_bridge_stop(socket_bridge);
        complete_bridge_setup(
            operation,
            (SSHProxyBridgeHandle){0},
            outerssh_proxy_closing_error());
        return;
    }
    SSHProxyBridgeState *state = outersshpriv_proxy_bridge_for_handle(
        active_pool,
        bridge_handle);
    if (state == NULL) {
        outersshpriv_socket_bridge_stop(socket_bridge);
        complete_bridge_setup(
            operation,
            (SSHProxyBridgeHandle){0},
            outerssh_proxy_closing_error());
        return;
    }
    state->bridge = socket_bridge;
    state->is_current = true;
    complete_bridge_setup(
        operation,
        bridge_handle,
        (OuterSSHError){0});
}

static void finish_bridge_failed(void *opaque_context)
{
    SSHSocketBridgeContext *context = opaque_context;
    SSHSocketBridgeOperation *operation = context->setup;
    context->setup = NULL;
    otqueue_assert(operation->pool->_queue);
    OuterSSHError error = operation->completed_error;
    OuterSSHSessionPool *pool = operation->pool;
    bool password_required = error.domain == OUTERSSH_ERROR_PROXY &&
        error.code == OUTERSSH_PROXY_ERROR_SUDO_PASSWORD_REQUIRED;
    if (context->exited_before_ready && operation->retry_cached_executable &&
        !password_required && outersshpriv_session_pool_active(pool) != NULL) {
        operation->retry_cached_executable = false;
        SSHProxyBridgeState *state = outersshpriv_proxy_bridge_for_handle(pool, operation->bridge);
        if (state != NULL) {
            state->stopped = true;
            state->is_current = false;
        }
        free(operation->command);
        operation->command = NULL;
        free(operation->initial_input);
        operation->initial_input = NULL;
        free(operation->error_storage);
        operation->error_storage = NULL;
        operation->completed_error = (OuterSSHError){0};
        destroy_bridge_context(context);
        if (operation->request.uses_sudo) {
            free(pool->_sudoBridgeExecutablePath);
            pool->_sudoBridgeExecutablePath = NULL;
            pool->_sudoBridgeExecutablePath_length = 0;
            outersshpriv_proxy_ensure_sudo_bridge_executable(pool,
                operation->request.sudo_password, operation->request.sudo_password_length,
                &operation->waiter, bridge_executable_ready, operation);
        } else {
            free(pool->_userBridgeExecutablePath);
            pool->_userBridgeExecutablePath = NULL;
            pool->_userBridgeExecutablePath_length = 0;
            outersshpriv_proxy_ensure_user_bridge_executable(pool, &operation->waiter, bridge_executable_ready, operation);
        }
        return;
    }
    bridge_start_failed(operation, error);
    destroy_bridge_context(context);
}

static void bridge_start_failed(
    SSHSocketBridgeOperation *operation,
    OuterSSHError error)
{
    OuterSSHSessionPool *pool = operation->pool;
    OuterSSHSessionPool *active_pool = outersshpriv_session_pool_active(
        pool);
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_handle(
        active_pool,
        operation->bridge);
    if (bridge != NULL) {
        bridge->stopped = true;
    }
    complete_bridge_setup(
        operation,
        (SSHProxyBridgeHandle){0},
        error);
}

#pragma mark - Connect a Socket Bridge Stream

struct ConnectBridgeStreamContext {
    SSHSocketBridgeOperation bridge_setup;
    SSHSocketBridgeWaiter bridge_waiter;
    SSHProxyConnection source;
    ProxyReactorPendingConnectionHandle connection;
    ProxyConnectionRoute route;
    SSHProxyBridgeHandle bridge;
    SSHSocketBridge socket_bridge;
    SSHSocketBridgeStream stream;
    otsocket_t socket;
    bool did_retry;
    SSHReactor *starting_reactor;
    SSHReactorSocketBridgeHandle completed_bridge_handle;
    SSHReactorSocketBridgeStreamHandle completed_stream_handle;
    SSHReactorSocketBridgeStreamResult completed_result;
    OuterSSHError completed_error;
    char *error_storage;
    char path[];
};

static void bridge_ready_for_connection(void *context, SSHBridgeResult result);
static void replacement_bridge_ready(void *context, SSHBridgeResult result);
static void prepare_bridge_stream(ConnectBridgeStreamContext *stream_context,
    SSHProxyBridgeHandle bridge_handle, bool did_retry);
static void start_stream_preparation(ConnectBridgeStreamContext *stream_context);
static void start_stream_on_reactor(void *opaque_context);
static void finish_stream_preparation(void *opaque_context);
static void complete_bridge_stream(
    ConnectBridgeStreamContext *stream_context,
    SSHSocketBridgeStream stream,
    OuterSSHError error);
static void bridge_stream_socket_transferred(void *context, otsocket_t socket);
static void attach_bridge_stream_socket(void *opaque_context);
static void destroy_stream_context(void *context);

void outersshpriv_proxy_assign_bridge_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route,
    const char *path,
    size_t path_length,
    bool uses_sudo)
{
    SSHProxyConnection active_source =
        outersshpriv_proxy_active_connection(source);
    if (active_source.pool == NULL) {
        outersshpriv_proxy_reactor_fail_pending_connection(
            source.server->reactor,
            connection,
            PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        return;
    }
    ConnectBridgeStreamContext *stream_context = path_length > SIZE_MAX - sizeof(*stream_context)
        ? NULL : malloc(sizeof(*stream_context) + path_length);
    if (stream_context == NULL) {
        outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor,
            connection, PROXY_SOCKS_REPLY_GENERAL_FAILURE);
        return;
    }
    outersshpriv_proxy_connection_begin_work(source);
    *stream_context = (ConnectBridgeStreamContext){
        .source = source,
        .connection = connection,
        .route = route,
        .socket = -1,
    };
    memcpy(stream_context->path, path, path_length);
    outersshpriv_proxy_ensure_bridge(source.pool, (SSHBridgeRequest){
        .path = stream_context->path,
        .path_length = path_length,
        .uses_sudo = uses_sudo,
    }, &stream_context->bridge_setup, &stream_context->bridge_waiter, bridge_ready_for_connection, stream_context);
}

static void bridge_ready_for_connection(void *context, SSHBridgeResult result)
{
    ConnectBridgeStreamContext *stream_context = context;
    SSHProxyConnection source = stream_context->source;
    SSHProxyConnection active_source = outersshpriv_proxy_active_connection(source);
    if (result.error.domain != OUTERSSH_ERROR_NONE) {
        handle_bridge_failure(source, stream_context->connection, stream_context->route,
            result.failed_bridge, false, false, result.error);
    } else if (!outersshpriv_proxy_reactor_pending_connection_is_active(
                   source.server->reactor, stream_context->connection) || active_source.pool == NULL) {
        outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor,
            stream_context->connection, PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
    } else {
        prepare_bridge_stream(stream_context, result.bridge, false);
        return;
    }
    destroy_stream_context(stream_context);
}

static void replacement_bridge_ready(void *context, SSHBridgeResult result)
{
    ConnectBridgeStreamContext *stream_context = context;
    SSHProxyConnection source = stream_context->source;
    if (result.error.domain == OUTERSSH_ERROR_NONE) {
        prepare_bridge_stream(stream_context, result.bridge, true);
        return;
    }
    handle_bridge_failure(source, stream_context->connection, stream_context->route,
        stream_context->bridge, stream_context->did_retry, true, result.error);
    destroy_stream_context(stream_context);
}

static void prepare_bridge_stream(ConnectBridgeStreamContext *stream_context,
    SSHProxyBridgeHandle bridge_handle, bool did_retry)
{
    SSHProxyConnection source = stream_context->source;
    SSHProxyConnection active_source = outersshpriv_proxy_active_connection(source);
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_handle(active_source.pool, bridge_handle);
    if (bridge == NULL) {
        outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor,
            stream_context->connection, PROXY_SOCKS_REPLY_GENERAL_FAILURE);
        destroy_stream_context(stream_context);
        return;
    }
    free(stream_context->error_storage);
    stream_context->error_storage = NULL;
    stream_context->completed_error = (OuterSSHError){0};
    stream_context->completed_result = SSH_REACTOR_SOCKET_BRIDGE_STREAM_READY;
    stream_context->completed_bridge_handle = (SSHReactorSocketBridgeHandle){0};
    stream_context->completed_stream_handle = (SSHReactorSocketBridgeStreamHandle){0};
    stream_context->bridge = bridge_handle;
    stream_context->socket_bridge = bridge->bridge;
    stream_context->did_retry = did_retry;
    start_stream_preparation(stream_context);
}

static void start_stream_preparation(ConnectBridgeStreamContext *stream_context)
{
    SSHSocketBridge bridge = stream_context->socket_bridge;
    if (bridge.pool == NULL ||
        bridge.session.generation == 0 ||
        bridge.handle.generation == 0) {
        complete_bridge_stream(
            stream_context,
            (SSHSocketBridgeStream){0},
            bridge_unavailable_error());
        return;
    }
    otqueue_assert(bridge.pool->_queue);
    SSHReactor *reactor = outersshpriv_session_pool_reactor_for_session(
        bridge.pool,
        bridge.session);
    if (reactor == NULL) {
        complete_bridge_stream(
            stream_context,
            (SSHSocketBridgeStream){0},
            bridge_unavailable_error());
        return;
    }
    stream_context->starting_reactor = reactor;
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        stream_context,
        start_stream_on_reactor);
}

static void start_stream_on_reactor(void *opaque_context)
{
    ConnectBridgeStreamContext *stream_context = opaque_context;
    SSHReactor *reactor = stream_context->starting_reactor;
    stream_context->starting_reactor = NULL;
    SSHReactorSocketBridgeStreamHandle stream_handle = {0};
    int result = outersshpriv_reactor_socket_bridge_prepare_stream(
        reactor,
        stream_context->socket_bridge.handle,
        &stream_handle,
        stream_context,
        bridge_stream_timeout_milliseconds);
    if (result != 0) {
        stream_context->completed_error = outerssh_session_error_format(&stream_context->error_storage,
            OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_START_FAILED,
            "Failed to prepare a remote socket bridge stream (code %d).",
            result);
        otqueue_async(
            stream_context->socket_bridge.pool->_queue,
            stream_context,
            finish_stream_preparation);
    }
}

void outersshpriv_session_pool_socket_bridge_stream_completed(
    ConnectBridgeStreamContext *stream_context,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle,
    SSHReactorSocketBridgeStreamResult result,
    const void *detail,
    size_t detail_length)
{
    stream_context->completed_bridge_handle = bridge_handle;
    stream_context->completed_stream_handle = stream_handle;
    if (result != SSH_REACTOR_SOCKET_BRIDGE_STREAM_READY) {
        static const char stream_failure_message[] = "The remote socket bridge could not open the stream.";
        OuterSSHSessionErrorCode code;
        switch (result) {
        case SSH_REACTOR_SOCKET_BRIDGE_STREAM_CANCELLED:
            code = OUTERSSH_SESSION_ERROR_CANCELLED;
            break;
        case SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_FAILED:
            code = OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE;
            break;
        case SSH_REACTOR_SOCKET_BRIDGE_STREAM_NOT_LISTENING:
            code = OUTERSSH_SESSION_ERROR_NOT_LISTENING;
            break;
        case SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_TIMED_OUT:
            code = OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_TIMED_OUT;
            break;
        case SSH_REACTOR_SOCKET_BRIDGE_STREAM_READY:
        case SSH_REACTOR_SOCKET_BRIDGE_STREAM_SESSION_CLOSED:
        case SSH_REACTOR_SOCKET_BRIDGE_STREAM_BRIDGE_CLOSED:
            code = OUTERSSH_SESSION_ERROR_UNAVAILABLE;
            break;
        default:
            abort();
        }
        stream_context->completed_error = detail == NULL || detail_length == 0
            ? outerssh_session_error(code,
                stream_failure_message, sizeof(stream_failure_message) - 1)
            : outerssh_error_copy(outerssh_session_error(code, detail, detail_length),
                &stream_context->error_storage);
        stream_context->completed_result = result;
    }
    otqueue_async(
        stream_context->socket_bridge.pool->_queue,
        stream_context,
        finish_stream_preparation);
}

static void finish_stream_preparation(void *opaque_context)
{
    ConnectBridgeStreamContext *stream_context = opaque_context;
    otqueue_assert(stream_context->socket_bridge.pool->_queue);
    SSHSocketBridge bridge = stream_context->socket_bridge;
    SSHSocketBridgeStream stream = stream_context->completed_error.domain != OUTERSSH_ERROR_NONE
        ? (SSHSocketBridgeStream){0}
        : (SSHSocketBridgeStream){
            .bridge_handle = stream_context->completed_bridge_handle,
            .handle = stream_context->completed_stream_handle,
            .pool = bridge.pool,
            .session = bridge.session
        };
    OuterSSHError error = stream_context->completed_error;
    complete_bridge_stream(
        stream_context,
        stream,
        error);
}

static void complete_bridge_stream(
    ConnectBridgeStreamContext *stream_context,
    SSHSocketBridgeStream stream,
    OuterSSHError error)
{
    SSHProxyConnection source = stream_context->source;
    ProxyReactorPendingConnectionHandle connection = stream_context->connection;

    ProxyConnectionRoute route = stream_context->route;
    SSHProxyBridgeHandle bridge_handle = stream_context->bridge;
    SSHSocketBridge socket_bridge = stream_context->socket_bridge;
    SSHProxyConnection active_source = outersshpriv_proxy_active_connection(
        source);
    if (active_source.pool == NULL) {
        outersshpriv_socket_bridge_cancel_stream(socket_bridge, stream);
        outersshpriv_proxy_reactor_fail_pending_connection(
            source.server->reactor,
            connection,
            PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        destroy_stream_context(stream_context);
        return;
    }
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_handle(
        active_source.pool,
        bridge_handle);
    if (bridge == NULL) {
        outersshpriv_socket_bridge_cancel_stream(socket_bridge, stream);
        outersshpriv_proxy_reactor_fail_pending_connection(
            source.server->reactor,
            connection,
            PROXY_SOCKS_REPLY_GENERAL_FAILURE);
        destroy_stream_context(stream_context);
        return;
    }
    if (error.domain != OUTERSSH_ERROR_NONE) {
        if (!bridge->explicitly_closed && !stream_context->did_retry &&
            (bridge->stopped ||
             stream_context->completed_result ==
                SSH_REACTOR_SOCKET_BRIDGE_STREAM_SESSION_CLOSED ||
             stream_context->completed_result ==
                SSH_REACTOR_SOCKET_BRIDGE_STREAM_BRIDGE_CLOSED)) {
            SSHProxyBridgeHandle current_handle;
            SSHProxyBridgeState *current =
                outersshpriv_proxy_bridge_for_path(
                    active_source.pool,
                    bridge->path, bridge->path_length,
                    &current_handle);
            if (current != NULL &&
                (current_handle.index != bridge_handle.index ||
                 current_handle.generation != bridge_handle.generation) &&
                !current->stopped &&
                current->uses_sudo == bridge->uses_sudo) {
                prepare_bridge_stream(stream_context, current_handle, true);
                return;
            }
            SSHBridgeRequest request = {
                .path = bridge->path,
                .path_length = bridge->path_length,
                .uses_sudo = bridge->uses_sudo,
                .failed_bridge = bridge_handle,
            };
            outersshpriv_proxy_stop_bridge(source.pool, bridge_handle);
            bridge->is_current = false;
            outersshpriv_proxy_ensure_bridge(source.pool, request, &stream_context->bridge_setup,
                &stream_context->bridge_waiter, replacement_bridge_ready, stream_context);
            return;
        }
        handle_bridge_failure(
            source,
            connection,
            route,
            bridge_handle,
            stream_context->did_retry,
            true,
            error);
        destroy_stream_context(stream_context);
        return;
    }
    if (!outersshpriv_proxy_reactor_pending_connection_is_active(
            source.server->reactor,
            connection) ||
        !bridge->is_current ||
        route.kind != PROXY_CONNECTION_ROUTE_UNIX_SOCKET ||
        route.unix_socket.path_length != bridge->path_length ||
        memcmp(route.unix_socket.path, bridge->path, bridge->path_length) != 0) {
        outersshpriv_socket_bridge_cancel_stream(bridge->bridge, stream);
        outersshpriv_proxy_reactor_fail_pending_connection(
            source.server->reactor,
            connection,
            PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        destroy_stream_context(stream_context);
        return;
    }
    stream_context->stream = stream;
    outersshpriv_proxy_reactor_complete_pending_connection(source.server->reactor, connection,
        bridge_stream_socket_transferred, stream_context);
}

static void bridge_stream_socket_transferred(void *context, otsocket_t socket)
{
    ConnectBridgeStreamContext *stream_context = context;
    SSHProxyConnection source = stream_context->source;
    SSHProxyConnection active_source = outersshpriv_proxy_active_connection(
        source);
    SSHProxyBridgeState *bridge = active_source.pool == NULL
        ? NULL
        : outersshpriv_proxy_bridge_for_handle(active_source.pool, stream_context->bridge);
    if (socket < 0 || active_source.pool == NULL || bridge == NULL ||
        !bridge->is_current || bridge->stopped ||
        stream_context->socket_bridge.pool != source.pool ||
        stream_context->stream.pool != source.pool ||
        stream_context->socket_bridge.session.index !=
            stream_context->stream.session.index ||
        stream_context->socket_bridge.session.generation !=
            stream_context->stream.session.generation) {
        if (socket >= 0) {
            otsocket_close(socket);
        }
        outersshpriv_socket_bridge_cancel_stream(
            stream_context->socket_bridge,
            stream_context->stream);
        destroy_stream_context(stream_context);
        return;
    }
    SSHReactor *reactor = outersshpriv_session_pool_reactor_for_session(
        source.pool,
        stream_context->socket_bridge.session);
    if (reactor == NULL) {
        otsocket_close(socket);
        outersshpriv_socket_bridge_cancel_stream(
            stream_context->socket_bridge,
            stream_context->stream);
        destroy_stream_context(stream_context);
        return;
    }
    stream_context->starting_reactor = reactor;
    stream_context->socket = socket;
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        stream_context,
        attach_bridge_stream_socket);
}

static void attach_bridge_stream_socket(void *opaque_context)
{
    ConnectBridgeStreamContext *stream_context = opaque_context;
    SSHReactor *reactor = stream_context->starting_reactor;
    otsocket_t socket = stream_context->socket;
    stream_context->socket = -1;
    (void)outersshpriv_reactor_socket_bridge_attach_stream(
        reactor,
        stream_context->stream.bridge_handle,
        stream_context->stream.handle,
        socket, stream_context->source.proxy_generation);
    otqueue_async(stream_context->source.server->queue, stream_context, destroy_stream_context);
}

static void destroy_stream_context(void *context)
{
    ConnectBridgeStreamContext *stream_context = context;
    SSHProxyConnection source = stream_context->source;
    free(stream_context->error_storage);
    free(stream_context);
    outersshpriv_proxy_connection_end_work(source);
}

#pragma mark - Recover a Failed Socket Bridge

static void handle_bridge_failure(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route,
    SSHProxyBridgeHandle bridge_handle,
    bool did_retry,
    bool is_recovery,
    OuterSSHError error)
{
    SSHProxyConnection active_source =
        outersshpriv_proxy_active_connection(source);
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_handle(active_source.pool, bridge_handle);
    if (is_recovery && bridge != NULL && bridge->explicitly_closed) {
        outersshpriv_proxy_fail_connection(source, connection, route, outerssh_proxy_closing_error());
        return;
    }
    if (!did_retry && route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET &&
        error.domain == OUTERSSH_ERROR_PROXY &&
        error.code == OUTERSSH_PROXY_ERROR_SUDO_PASSWORD_REQUIRED) {
        outersshpriv_proxy_request_sudo_for_connection(source, connection, route,
            route.unix_socket.path, route.unix_socket.path_length, error);
        return;
    }
    outersshpriv_proxy_fail_connection(source, connection, route, error);
}

#pragma mark - Ask for a Sudo Password

/* A pending proxy connection waiting for a sudo password. It holds one unit of
 * its source's work until it is connected or failed. */
typedef struct SudoPasswordWaiter {
    struct SudoPasswordWaiter *next;
    SSHProxyConnection source;
    ProxyReactorPendingConnectionHandle connection;
    ProxyConnectionRoute route;
} SudoPasswordWaiter;

/* Connections from one proxy to one socket share a question and each password
 * attempt. Linked from the pool on the control queue until finished. */
struct SSHSudoPasswordRequest {
    SSHSudoPasswordRequest *next;
    OuterSSHSessionPool *pool;
    SSHForwarder *server;
    const void *frontend;
    SudoPasswordWaiter *waiters;
    uint32_t attempt;
    SSHQuestionAnswer answer;
    char *password;
    size_t password_length;
    OuterSSHError attempt_error;
    char *attempt_error_storage;
    SSHSocketBridgeOperation bridge_operation;
    SSHSocketBridgeWaiter bridge_waiter;
    size_t path_length;
    char path[];
};

static void ask_for_sudo_password(SSHSudoPasswordRequest *request);
static void sudo_password_answered(void *context, SSHQuestionAnswer answer, char *password, size_t password_length);
static void use_sudo_password(void *context);
static void sudo_password_bridge_ready(void *context, SSHBridgeResult result);

static void clear_password(SSHSudoPasswordRequest *request)
{
    if (request->password == NULL) return;
    volatile char *bytes = request->password;
    for (size_t i = 0; i < request->password_length; i++) bytes[i] = 0;
    free(request->password);
    request->password = NULL;
    request->password_length = 0;
}

static void remove_sudo_password_request(SSHSudoPasswordRequest *request)
{
    for (SSHSudoPasswordRequest **link = &request->pool->_sudoPasswordRequests; *link != NULL; link = &(*link)->next) {
        if (*link == request) {
            *link = request->next;
            break;
        }
    }
    clear_password(request);
    free(request->attempt_error_storage);
    free(request);
}

static void fail_sudo_password_waiters(SSHSudoPasswordRequest *request, OuterSSHError error)
{
    while (request->waiters != NULL) {
        SudoPasswordWaiter *waiter = request->waiters;
        request->waiters = waiter->next;
        outersshpriv_proxy_fail_connection(waiter->source, waiter->connection, waiter->route, error);
        outersshpriv_proxy_connection_end_work(waiter->source);
        free(waiter);
    }
}

static bool sudo_password_waiter_is_active(const SudoPasswordWaiter *waiter)
{
    return outersshpriv_proxy_active_connection(waiter->source).pool != NULL &&
        outersshpriv_proxy_reactor_pending_connection_is_active(waiter->source.server->reactor, waiter->connection);
}

static void connect_sudo_password_waiters(SSHSudoPasswordRequest *request, SSHProxyBridgeHandle bridge)
{
    while (request->waiters != NULL) {
        SudoPasswordWaiter *waiter = request->waiters;
        request->waiters = waiter->next;
        ConnectBridgeStreamContext *stream_context = sudo_password_waiter_is_active(waiter)
            ? calloc(1, sizeof(*stream_context)) : NULL;
        if (stream_context == NULL) {
            outersshpriv_proxy_reactor_fail_pending_connection(waiter->source.server->reactor, waiter->connection,
                sudo_password_waiter_is_active(waiter) ? PROXY_SOCKS_REPLY_GENERAL_FAILURE
                    : PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
            outersshpriv_proxy_connection_end_work(waiter->source);
        } else {
            *stream_context = (ConnectBridgeStreamContext){
                .source = waiter->source,
                .connection = waiter->connection,
                .route = waiter->route,
                .socket = -1,
            };
            prepare_bridge_stream(stream_context, bridge, true);
        }
        free(waiter);
    }
}

static void drop_inactive_sudo_password_waiters(SSHSudoPasswordRequest *request)
{
    for (SudoPasswordWaiter **link = &request->waiters; *link != NULL;) {
        SudoPasswordWaiter *waiter = *link;
        if (sudo_password_waiter_is_active(waiter)) {
            link = &waiter->next;
            continue;
        }
        *link = waiter->next;
        outersshpriv_proxy_reactor_fail_pending_connection(waiter->source.server->reactor, waiter->connection,
            PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
        outersshpriv_proxy_connection_end_work(waiter->source);
        free(waiter);
    }
}

void outersshpriv_proxy_request_sudo_for_connection(
    SSHProxyConnection source, ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route,
    const char *path,
    size_t path_length, OuterSSHError error)
{
    SSHProxyConnection active_source = outersshpriv_proxy_active_connection(source);
    if (active_source.pool == NULL ||
        !outersshpriv_proxy_reactor_pending_connection_is_active(source.server->reactor, connection)) {
        outersshpriv_proxy_fail_connection(source, connection, route, error);
        return;
    }
    SSHSudoPasswordRequest *request = source.pool->_sudoPasswordRequests;
    while (request != NULL && (request->server != source.server || request->path_length != path_length ||
           memcmp(request->path, path, path_length) != 0)) {
        request = request->next;
    }
    bool created = request == NULL;
    if (created) {
        request = path_length > SIZE_MAX - sizeof(*request) ? NULL : malloc(sizeof(*request) + path_length);
        if (request != NULL) {
            *request = (SSHSudoPasswordRequest){
                .next = source.pool->_sudoPasswordRequests,
                .pool = source.pool,
                .server = source.server,
                .frontend = active_source.server->frontend,
                .attempt = 1,
                .path_length = path_length,
            };
            memcpy(request->path, path, path_length);
            source.pool->_sudoPasswordRequests = request;
        }
    }
    SudoPasswordWaiter *waiter = request == NULL ? NULL : malloc(sizeof(*waiter));
    if (waiter == NULL) {
        if (created && request != NULL) remove_sudo_password_request(request);
        outersshpriv_proxy_reactor_fail_pending_connection(source.server->reactor, connection,
            outersshpriv_proxy_reply_status_for_error(error));
        return;
    }
    outersshpriv_proxy_connection_begin_work(source);
    *waiter = (SudoPasswordWaiter){.next = request->waiters, .source = source, .connection = connection, .route = route};
    request->waiters = waiter;
    if (created) ask_for_sudo_password(request);
}

static void ask_for_sudo_password(SSHSudoPasswordRequest *request)
{
    drop_inactive_sudo_password_waiters(request);
    if (request->waiters == NULL) {
        remove_sudo_password_request(request);
        return;
    }
    outersshpriv_session_pool_ask_sudo_password(request->pool, request->server, request->frontend,
        request->path, request->path_length, request->attempt, request->attempt_error,
        sudo_password_answered, request);
}

static void sudo_password_answered(void *context, SSHQuestionAnswer answer, char *password, size_t password_length)
{
    SSHSudoPasswordRequest *request = context;
    request->answer = answer;
    request->password = password;
    request->password_length = password_length;
    otqueue_async(request->pool->_queue, request, use_sudo_password);
}

static void use_sudo_password(void *context)
{
    SSHSudoPasswordRequest *request = context;
    if (request->answer == SSH_QUESTION_DECLINED) {
        static const char message[] = "A sudo password is required to start the socket bridge.";
        fail_sudo_password_waiters(request, outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_SUDO_PASSWORD_REQUIRED,
            message, sizeof(message) - 1, 0));
        remove_sudo_password_request(request);
        return;
    }
    if (request->answer != SSH_QUESTION_ACCEPTED || outersshpriv_session_pool_active(request->pool) == NULL) {
        fail_sudo_password_waiters(request, outerssh_proxy_closing_error());
        remove_sudo_password_request(request);
        return;
    }
    outersshpriv_proxy_ensure_bridge(request->pool, (SSHBridgeRequest){
        .path = request->path,
        .path_length = request->path_length,
        .uses_sudo = true,
        .sudo_password = request->password,
        .sudo_password_length = request->password_length,
    }, &request->bridge_operation, &request->bridge_waiter, sudo_password_bridge_ready, request);
}

static bool sudo_password_error_is_final(OuterSSHError error)
{
    return (error.domain == OUTERSSH_ERROR_PROXY && error.code == OUTERSSH_PROXY_ERROR_CONNECTION_CLOSING) ||
        (error.domain == OUTERSSH_ERROR_SESSION && error.code == OUTERSSH_SESSION_ERROR_CANCELLED);
}

static void sudo_password_bridge_ready(void *context, SSHBridgeResult result)
{
    SSHSudoPasswordRequest *request = context;
    clear_password(request);
    if (result.error.domain == OUTERSSH_ERROR_NONE) {
        connect_sudo_password_waiters(request, result.bridge);
        remove_sudo_password_request(request);
        return;
    }
    if (sudo_password_error_is_final(result.error) || outersshpriv_session_pool_active(request->pool) == NULL) {
        fail_sudo_password_waiters(request, result.error);
        remove_sudo_password_request(request);
        return;
    }
    free(request->attempt_error_storage);
    request->attempt_error = outerssh_error_copy(result.error, &request->attempt_error_storage);
    request->attempt++;
    ask_for_sudo_password(request);
}

#pragma mark - Cancel a Prepared Socket Bridge Stream

typedef struct {
    SSHReactor *reactor;
    SSHReactorSocketBridgeHandle bridge_handle;
    SSHReactorSocketBridgeStreamHandle stream_handle;
} CancelBridgeStreamContext;

static void cancel_stream_on_reactor(void *opaque_context);

void outersshpriv_socket_bridge_cancel_stream(
    SSHSocketBridge bridge,
    SSHSocketBridgeStream stream)
{
    if (bridge.pool == NULL ||
        stream.pool != bridge.pool ||
        !session_handles_equal(bridge.session, stream.session)) {
        return;
    }
    otqueue_assert(bridge.pool->_queue);
    SSHReactor *reactor = outersshpriv_session_pool_reactor_for_session(
        bridge.pool,
        bridge.session);
    if (reactor == NULL) {
        return;
    }
    CancelBridgeStreamContext *context = malloc(sizeof(*context));
    if (context == NULL) {
        outersshpriv_remove_session(bridge.pool, bridge.session);
        return;
    }
    *context = (CancelBridgeStreamContext){
        .reactor = reactor,
        .bridge_handle = stream.bridge_handle,
        .stream_handle = stream.handle
    };
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        context,
        cancel_stream_on_reactor);
}

static void cancel_stream_on_reactor(void *opaque_context)
{
    CancelBridgeStreamContext *context = opaque_context;
    (void)outersshpriv_reactor_socket_bridge_cancel_stream(
        context->reactor,
        context->bridge_handle,
        context->stream_handle);
    free(context);
}

#pragma mark - Stop a Socket Bridge

typedef struct {
    SSHReactor *reactor;
    SSHReactorSocketBridgeHandle handle;
} StopSocketBridgeContext;

static void stop_bridge_on_reactor(void *opaque_context);

void outersshpriv_proxy_stop_bridge(
    OuterSSHSessionPool *pool,
    SSHProxyBridgeHandle bridge_handle)
{
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_handle(pool, bridge_handle);
    if (bridge == NULL || bridge->stopped) {
        return;
    }
    bridge->stopped = true;
    outersshpriv_socket_bridge_stop(bridge->bridge);
}

void outersshpriv_socket_bridge_stop(SSHSocketBridge bridge)
{
    if (bridge.pool == NULL ||
        bridge.session.generation == 0 ||
        bridge.handle.generation == 0) {
        return;
    }
    otqueue_assert(bridge.pool->_queue);
    SSHReactor *reactor = outersshpriv_session_pool_reactor_for_session(
        bridge.pool,
        bridge.session);
    if (reactor == NULL) {
        return;
    }
    StopSocketBridgeContext *context = malloc(sizeof(*context));
    if (context == NULL) {
        outersshpriv_remove_session(bridge.pool, bridge.session);
        return;
    }
    *context = (StopSocketBridgeContext){
        .reactor = reactor,
        .handle = bridge.handle
    };
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        context,
        stop_bridge_on_reactor);
}

static void stop_bridge_on_reactor(void *opaque_context)
{
    StopSocketBridgeContext *context = opaque_context;
    outersshpriv_reactor_stop_socket_bridge(
        context->reactor,
        context->handle,
        true);
    free(context);
}

static void finish_bridge_ended(void *opaque_context)
{
    SSHSocketBridgeContext *context = opaque_context;
    assert(context->setup == NULL);
    otqueue_assert(context->pool->_queue);
    OuterSSHSessionPool *pool = context->pool;
    OuterSSHSessionPool *active_pool = outersshpriv_session_pool_active(
        pool);
    SSHProxyBridgeState *bridge = outersshpriv_proxy_bridge_for_handle(
        active_pool,
        context->bridge);
    if (bridge != NULL) {
        bridge->stopped = true;
    }
    destroy_bridge_context(context);
}

#pragma mark - Operation Storage and Error Details

static void destroy_bridge_context(SSHSocketBridgeContext *context)
{
    OuterSSHSessionPool *pool = context->pool;
    assert(context->setup == NULL);
    free(context);
    outersshpriv_session_pool_end_operation(pool);
}

static OuterSSHError bridge_unavailable_error(void)
{
    static const char session_unavailable_message[] = "No active SSH session is available.";

    return outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
        session_unavailable_message, sizeof(session_unavailable_message) - 1);
}

static bool detail_contains(const void *detail, size_t detail_length, const char *text)
{
    size_t length = strlen(text);
    for (size_t offset = 0; detail_length >= length && offset <= detail_length - length; offset++) {
        if (memcmp((const char *)detail + offset, text, length) == 0) return true;
    }
    return false;
}

static OuterSSHError socket_bridge_result_error(
    char **storage,
    bool uses_sudo,
    SSHReactorSocketBridgeResult result,
    uint32_t reason,
    const void *detail,
    size_t detail_length)
{
    static const char bridge_timeout_message[] = "The remote socket bridge took too long to start.";
    static const char cancelled_message[] = "The SSH operation was cancelled.";

    switch (result) {
    case SSH_REACTOR_SOCKET_BRIDGE_CANCELLED:
        return outerssh_session_error(OUTERSSH_SESSION_ERROR_CANCELLED,
            cancelled_message, sizeof(cancelled_message) - 1);
    case SSH_REACTOR_SOCKET_BRIDGE_CHANNEL_OPEN_FAILED: {
        OuterSSHError error = outerssh_session_error_format(storage,
            OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE,
            "The SSH server rejected the socket bridge channel (reason %u).",
            reason);
        error.ssh_channel_open_reason = reason;
        return error;
    }
    case SSH_REACTOR_SOCKET_BRIDGE_CHANNEL_OPEN_TIMED_OUT:
    case SSH_REACTOR_SOCKET_BRIDGE_READY_TIMED_OUT:
        return outerssh_session_error(OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_TIMED_OUT,
            bridge_timeout_message, sizeof(bridge_timeout_message) - 1);
    default:
        if (detail == NULL || detail_length == 0) {
            static const char bridge_failure_message[] = "The remote socket bridge failed.";
            return outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
                bridge_failure_message, sizeof(bridge_failure_message) - 1);
        }
        static const char password_required[] = "A sudo password is required to start the socket bridge.";
        if (uses_sudo && result == SSH_REACTOR_SOCKET_BRIDGE_EXITED &&
            detail_contains(detail, detail_length, password_required)) {
            return outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_SUDO_PASSWORD_REQUIRED,
                password_required, sizeof(password_required) - 1, 0);
        }
        OuterSSHSessionErrorCode code = result == SSH_REACTOR_SOCKET_BRIDGE_EXITED &&
            detail_contains(detail, detail_length, HELPER_NOT_LISTENING_MESSAGE)
            ? OUTERSSH_SESSION_ERROR_NOT_LISTENING : OUTERSSH_SESSION_ERROR_UNAVAILABLE;
        return outerssh_error_copy(outerssh_session_error(code, detail, detail_length), storage);
    }
}

static bool session_handles_equal(
    SSHSessionPoolSessionHandle left,
    SSHSessionPoolSessionHandle right)
{
    return left.index == right.index &&
        left.generation == right.generation;
}

#pragma mark - Bridge Storage

static bool reserve_bridge_states(OuterSSHSessionPool *pool, size_t minimum_capacity);

SSHProxyBridgeState *outersshpriv_proxy_bridge_for_handle(
    OuterSSHSessionPool *pool,
    SSHProxyBridgeHandle handle)
{
    if (pool == NULL || handle.generation == 0 ||
        handle.index >= pool->bridge_state_count) {
        return NULL;
    }
    SSHProxyBridgeState *bridge = &pool->bridge_states[handle.index];
    return bridge->generation == handle.generation ? bridge : NULL;
}

SSHProxyBridgeState *outersshpriv_proxy_bridge_for_path(
    OuterSSHSessionPool *pool,
    const char *path,
    size_t path_length,
    SSHProxyBridgeHandle *handle)
{
    if (pool == NULL) {
        if (handle != NULL) {
            *handle = (SSHProxyBridgeHandle){0};
        }
        return NULL;
    }
    for (size_t index = 0; index < pool->bridge_state_count; index++) {
        SSHProxyBridgeState *bridge = &pool->bridge_states[index];
        if (!bridge->is_current || !(bridge->path_length == path_length && memcmp(bridge->path, path, bridge->path_length) == 0)) {
            continue;
        }
        if (handle != NULL) {
            *handle = (SSHProxyBridgeHandle){
                .index = index,
                .generation = bridge->generation
            };
        }
        return bridge;
    }
    if (handle != NULL) {
        *handle = (SSHProxyBridgeHandle){0};
    }
    return NULL;
}

SSHProxyBridgeState *outersshpriv_proxy_append_bridge_state(
    OuterSSHSessionPool *pool,
    const char *path,
    size_t path_length,
    bool uses_sudo,
    SSHProxyBridgeHandle *handle)
{
    char *path_copy = malloc(path_length + 1);
    if (path_copy != NULL) {
        memcpy(path_copy, path, path_length);
        path_copy[path_length] = '\0';
    }
    if (path_copy == NULL) return NULL;
    if (pool->bridge_state_count == SIZE_MAX ||
        !reserve_bridge_states(pool, pool->bridge_state_count + 1)) {
        free(path_copy);
        return NULL;
    }
    size_t index = pool->bridge_state_count++;
    SSHProxyBridgeState *bridge = &pool->bridge_states[index];
    bridge->generation = 1;
    bridge->path = path_copy;
    bridge->path_length = path_length;
    bridge->uses_sudo = uses_sudo;
    *handle = (SSHProxyBridgeHandle){
        .index = index,
        .generation = bridge->generation
    };
    return bridge;
}

static bool reserve_bridge_states(
    OuterSSHSessionPool *pool,
    size_t minimum_capacity)
{
    if (pool->bridge_state_capacity >= minimum_capacity) {
        return true;
    }
    size_t capacity = pool->bridge_state_capacity == 0
        ? 4
        : pool->bridge_state_capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    SSHProxyBridgeState *states = calloc(capacity, sizeof(*states));
    if (states == NULL) {
        return false;
    }
    if (pool->bridge_state_count != 0) {
        memcpy(
            states,
            pool->bridge_states,
            pool->bridge_state_count * sizeof(*states));
    }
    free(pool->bridge_states);
    pool->bridge_states = states;
    pool->bridge_state_capacity = capacity;
    return true;
}

typedef struct {
    OuterSSHSessionPool *pool;
    SSHPoolEvent *reply;
} SocketBridgeListRequest;

static void list_socket_bridges(void *context)
{
    SocketBridgeListRequest *request = context;
    OuterSSHSessionPool *pool = request->pool;
    size_t count = 0;
    for (size_t i = 0; i < pool->bridge_state_count; ++i) {
        SSHProxyBridgeState *bridge = &pool->bridge_states[i];
        if (bridge->is_current && !bridge->stopped) ++count;
    }
    OuterSSHBridgeInfo *items = count ? calloc(count, sizeof(*items)) : NULL;
    if (count && !items) {
        outersshpriv_reply_socket_bridges(request->reply, NULL, 0, outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_REACTOR_CREATION_FAILED, "Could not list socket bridges.", sizeof("Could not list socket bridges.") - 1, 0));
    } else {
        size_t next = 0;
        for (size_t i = 0; i < pool->bridge_state_count; ++i) {
            SSHProxyBridgeState *bridge = &pool->bridge_states[i];
            if (bridge->is_current && !bridge->stopped)
                items[next++] = (OuterSSHBridgeInfo){.identifier = i + 1,
                    .path = bridge->path, .path_length = bridge->path_length, .privileged = bridge->uses_sudo};
        }
        outersshpriv_reply_socket_bridges(request->reply, items, count, (OuterSSHError){0});
    }
    free(items);
    free(request);
}

bool outerssh_session_pool_get_bridges(OuterSSHSessionPool *pool, uint64_t tag)
{
    SocketBridgeListRequest *request = malloc(sizeof(*request));
    SSHPoolEvent *reply = request == NULL ? NULL
        : outersshpriv_reply_reserve(pool, OUTERSSH_EVENT_BRIDGES_RECEIVED, tag);
    if (reply == NULL) {
        free(request);
        return false;
    }
    *request = (SocketBridgeListRequest){pool, reply};
    otqueue_async(pool->_queue, request, list_socket_bridges);
    return true;
}

typedef struct {
    OuterSSHSessionPool *pool;
    uint64_t identifier;
    SSHPoolEvent *reply;
} SocketBridgeCloseRequest;

static void close_socket_bridge(void *context)
{
    SocketBridgeCloseRequest *request = context;
    OuterSSHSessionPool *pool = request->pool;
    if (request->identifier > 0 && request->identifier <= pool->bridge_state_count) {
        size_t index = (size_t)(request->identifier - 1);
        SSHProxyBridgeState *bridge = &pool->bridge_states[index];
        bridge->explicitly_closed = true;
        outersshpriv_proxy_stop_bridge(pool, (SSHProxyBridgeHandle){index, bridge->generation});
    }
    outersshpriv_reply(request->reply, (OuterSSHError){0});
    free(request);
}

bool outerssh_session_pool_close_bridge(OuterSSHSessionPool *pool, uint64_t identifier, uint64_t tag)
{
    SocketBridgeCloseRequest *request = malloc(sizeof(*request));
    SSHPoolEvent *reply = request == NULL ? NULL
        : outersshpriv_reply_reserve(pool, OUTERSSH_EVENT_OPERATION_COMPLETED, tag);
    if (reply == NULL) {
        free(request);
        return false;
    }
    *request = (SocketBridgeCloseRequest){pool, identifier, reply};
    otqueue_async(pool->_queue, request, close_socket_bridge);
    return true;
}
