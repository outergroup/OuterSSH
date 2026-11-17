#include "platform/OTSocket.h"
#include "SSHProxyErrorInternal.h"
#include "platform/OTSocketPair.h"
#include "SSHFlows.h"
#include "SSHForwarder.h"
#include "SSHEventsInternal.h"
#include "SSHReactorInternal.h"
#include "ProxyReactorInternal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint64_t authentication_timeout_milliseconds = 60000;
static const uint64_t validation_timeout_milliseconds = 5000;

static void reactor_created(void *context, SSHReactor *reactor);
static void handshake_finished(void *context, int error);
static void authentication_finished(void *context, OuterSSHError error);
static void finish_starting_session(void *opaque_operation);
static void finish_session_creation(
    OuterSSHSessionPool *pool,
    OuterSSHError error);
static void destroy_session_creation(void *context);
static void unused_session_reactor_destroyed(void *context);

#pragma mark - Obtain an SSH Session

typedef struct {
    OuterSSHSessionPool *pool;
    SSHPoolEvent *reply;
    SSHWaiter waiter;
} EnsureSessionOperation;

static void ensure_session_on_pool(void *context);
static void finish_ensuring_session(void *context, OuterSSHError error);

bool outerssh_session_pool_ensure_session(OuterSSHSessionPool *pool, uint64_t tag)
{
    EnsureSessionOperation *operation = malloc(sizeof(*operation));
    SSHPoolEvent *reply = operation == NULL ? NULL
        : outersshpriv_reply_reserve(pool, OUTERSSH_EVENT_OPERATION_COMPLETED, tag);
    if (reply == NULL) {
        free(operation);
        return false;
    }
    *operation = (EnsureSessionOperation){.pool = pool, .reply = reply};
    otqueue_async(pool->_queue, operation, ensure_session_on_pool);
    return true;
}

static void ensure_session_on_pool(void *context)
{
    EnsureSessionOperation *operation = context;
    outersshpriv_session_pool_begin_operation(operation->pool);
    if (operation->pool->shutdown_requested) {
        finish_ensuring_session(operation, outerssh_proxy_closing_error());
        return;
    }
    outersshpriv_session_pool_run_when_ready(operation->pool, &operation->waiter,
        finish_ensuring_session, operation);
}

static void finish_ensuring_session(void *context, OuterSSHError error)
{
    EnsureSessionOperation *operation = context;
    OuterSSHSessionPool *pool = operation->pool;
    otqueue_assert(pool->_queue);
    SSHSessionPoolSessionHandle session;
    outersshpriv_session_pool_ready_reactor(pool, &session, &error);
    outersshpriv_reply(operation->reply, error);
    free(operation);
    outersshpriv_session_pool_end_operation(pool);
}

/* The target session's transport is one end of an in-process socket pair; the
 * jump host's forwarder relays the other end through a direct-tcpip channel. */
typedef struct {
    SSHSessionCreationOperation *operation;
    SSHForwarder *forwarder;
    otsocket_t transport;
    otsocket_t relay;
    bool connected;
    bool denied;
} JumpConnection;

static void jump_transport_finished(void *context)
{
    JumpConnection *connection = context;
    SSHSessionCreationOperation *operation = connection->operation;
    OuterSSHSessionPool *pool = operation->pool;
    otsocket_t transport = connection->transport;
    bool connected = connection->connected, denied = connection->denied;
    free(connection);
    if (connected) {
        outersshpriv_session_pool_tcp_connected(operation, transport);
        return;
    }
    otsocket_close(transport);
    char *error_storage = NULL;
    OuterSSHError error = pool->shutdown_requested ? outerssh_proxy_closing_error()
        : outerssh_session_error_format(&error_storage, OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
            denied ? "The jump host refused forwarding to %.*s:%d." : "The jump host could not connect to %.*s:%d.",
            (int)pool->_hostnameLength, pool->_hostname, (int)pool->_port);
    outersshpriv_session_pool_tcp_connect_failed(operation, error);
    free(error_storage);
}

static void jump_relay_connected(void *context, SSHForwarderConnectionResult result)
{
    JumpConnection *connection = context;
    connection->connected = result.status == PROXY_SOCKS_REPLY_SUCCEEDED;
    connection->denied = result.forwarding_denied;
    otqueue_async(connection->operation->pool->_queue, connection, jump_transport_finished);
}

/* Runs on the upstream pool's control queue. */
static void connect_jump_transport(void *context)
{
    JumpConnection *connection = context;
    OuterSSHSessionPool *pool = connection->operation->pool;
    outersshpriv_forwarder_activate(connection->forwarder);
    outersshpriv_forwarder_connect(connection->forwarder, connection->relay,
        pool->_hostname, pool->_hostnameLength, (uint16_t)pool->_port,
        (SSHSocketSender){.kind = SSH_SOCKET_SENDER_UNCHECKED}, jump_relay_connected, connection);
}

void outersshpriv_session_pool_run_when_ready(
    OuterSSHSessionPool *pool,
    SSHWaiter *waiter,
    SSHCompletionHandler resume,
    void *context)
{
    otqueue_assert(pool->_queue);
    SSHSessionPoolSessionHandle session;
    if (pool->_disconnecting || pool->_disconnected ||
        outersshpriv_session_pool_available_reactor(pool, &session) != NULL) {
        resume(context, (OuterSSHError){0});
        return;
    }
    outersshpriv_wait(&pool->_sessionWaiters, waiter, resume, context);
    if (pool->_sessionCreation != NULL) {
        return;
    }

    otqueue_assert(pool->_queue);
    SSHSessionCreationOperation *operation = calloc(1, sizeof(*operation));
    if (operation == NULL) {
        static const char allocation_message[] = "Failed to allocate an SSH session creation operation.";
        finish_session_creation(pool, outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
            allocation_message, sizeof(allocation_message) - 1));
        return;
    }
    operation->pool = pool;
    outersshpriv_session_pool_begin_operation(pool);
    pool->_sessionCreation = operation;
    if (pool->jump_host != NULL) {
        OuterSSHError error = {0};
        if (pool->jump_forward == NULL) {
            pool->jump_forward = outersshpriv_tcp_forwarder_create(pool->jump_host,
                pool->_hostname, pool->_hostnameLength, (uint16_t)pool->_port, &error);
        }
        JumpConnection *connection = calloc(1, sizeof(*connection));
        otsocket_t pair[2] = {-1, -1};
        if (pool->jump_forward == NULL || connection == NULL || otsocket_pair(pair)) {
            free(connection);
            static const char message[] = "Failed to create the SSH jump transport.";
            if (error.domain == OUTERSSH_ERROR_NONE) error = outerssh_session_error(
                OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED, message, sizeof(message) - 1);
            outersshpriv_session_pool_tcp_connect_failed(operation, error);
            return;
        }
        *connection = (JumpConnection){.operation = operation, .forwarder = pool->jump_forward,
            .transport = pair[0], .relay = pair[1]};
        otqueue_async(pool->jump_forward->queue, connection, connect_jump_transport);
        return;
    }
    pool->_connectHandle = outersshpriv_proxy_reactor_connect_tcp(
        pool->_connectorReactor,
        pool->_hostname,
        pool->_hostnameLength,
        pool->_port,
        operation);
}

void outersshpriv_session_pool_tcp_connect_failed(
    SSHSessionCreationOperation *operation,
    OuterSSHError error)
{
    OuterSSHSessionPool *pool = operation->pool;
    otqueue_assert(pool->_queue);
    pool->_connectHandle = (ProxyReactorTCPConnectHandle){0};
    finish_session_creation(pool, error);
    destroy_session_creation(operation);
}

void outersshpriv_session_pool_tcp_connected(
    SSHSessionCreationOperation *operation,
    otsocket_t socket)
{
    OuterSSHSessionPool *pool = operation->pool;
    otqueue_assert(pool->_queue);
    pool->_connectHandle = (ProxyReactorTCPConnectHandle){0};
    if (pool->_disconnecting || pool->_disconnected) {
        static const char closing_message[] = "The SSH connection is closing.";
        otsocket_close(socket);
        finish_session_creation(pool, outerssh_session_error(OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING,
            closing_message, sizeof(closing_message) - 1));
        destroy_session_creation(operation);
        return;
    }
    SSHSessionStartResult result = {0};
    operation->session = outersshpriv_session_create(socket, &result);
    if (operation->session == NULL) {
        otsocket_close(socket);
        finish_session_creation(pool, result.error);
        outersshpriv_session_start_result_dispose(&result);
        destroy_session_creation(operation);
        return;
    }
    if (!outersshpriv_reactor_create(pool->_queue, socket, operation->session, reactor_created, operation))
        reactor_created(operation, NULL);
}

static void reactor_created(void *context, SSHReactor *reactor)
{
    SSHSessionCreationOperation *operation = context;
    OuterSSHSessionPool *pool = operation->pool;
    otqueue_assert(pool->_queue);
    if (reactor == NULL) {
        static const char message[] = "Failed to create the SSH reactor.";
        olibssh_session_free(operation->session);
        finish_session_creation(pool, outerssh_session_error(
            OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED, message, sizeof(message) - 1));
        destroy_session_creation(operation);
        return;
    }
    operation->reactor = reactor;
    outersshpriv_reactor_handshake(operation->reactor,
        handshake_finished, operation);
}

static void handshake_finished(void *context, int error)
{
    SSHSessionCreationOperation *operation = context;

    if (error != 0) {
        char *session_message = NULL;
        int message_length = 0;
        int reported_error = libssh2_session_last_error(
            operation->session, &session_message, &message_length, 0);
        const char *message = session_message;
        if (message == NULL || reported_error != error) {
            static const char failed[] = "Could not complete the SSH handshake";
            static const char timed_out[] = "Timed out waiting for the SSH server";
            if (error == LIBSSH2_ERROR_TIMEOUT) {
                message = timed_out;
                message_length = sizeof(timed_out) - 1;
            } else {
                message = failed;
                message_length = sizeof(failed) - 1;
            }
        }
        operation->completed_error = outersshpriv_error_format(&operation->error_storage,
            (OuterSSHError){
                .domain = OUTERSSH_ERROR_SESSION,
                .code = OUTERSSH_SESSION_ERROR_HANDSHAKE_FAILED,
                .ssh_error_code = error,
                .ssh_error_message = message,
                .ssh_error_message_length = (size_t)message_length
            }, "SSH handshake failed with code %d (%.*s).", error, message_length, message);
        otqueue_async(operation->pool->_queue, operation, finish_starting_session);
        return;
    }

    OuterSSHSessionPool *pool = operation->pool;
    operation->windows_banner = operation->reactor->windows_banner;
    outersshpriv_reactor_authenticate(operation->reactor,
        (SSHAuthenticationRequest){
            .username = pool->_username, .username_length = pool->_usernameLength,
            .credentials = pool->_authentication,
            .agent_path = pool->_sshAgentSocketPath,
            .agent_path_length = pool->_sshAgentSocketPathLength,
            .timeout_milliseconds = authentication_timeout_milliseconds,
            .host_key_pool = pool
        }, authentication_finished, operation);
}

static void authentication_finished(void *context, OuterSSHError error)
{
    SSHSessionCreationOperation *operation = context;
    operation->completed_error = outerssh_error_copy(error, &operation->error_storage);
    otqueue_async(operation->pool->_queue, operation, finish_starting_session);
}

static void finish_starting_session(void *opaque_operation)
{
    SSHSessionCreationOperation *operation = opaque_operation;
    OuterSSHSessionPool *pool = operation->pool;
    otqueue_assert(pool->_queue);
    SSHReactor *reactor = operation->reactor;
    OuterSSHError error = operation->completed_error;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        outersshpriv_reactor_destroy(reactor, unused_session_reactor_destroyed, operation);
        finish_session_creation(pool, error);
        return;
    }
    if (pool->_disconnecting || pool->_disconnected) {
        static const char closing_message[] = "The SSH connection is closing.";
        outersshpriv_reactor_destroy(reactor, unused_session_reactor_destroyed, operation);
        finish_session_creation(pool, outerssh_session_error(OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING,
            closing_message, sizeof(closing_message) - 1));
        return;
    }
    SSHSessionPoolSessionHandle session =
        outersshpriv_session_pool_allocate_session(pool, reactor);
    if (session.generation == 0) {
        static const char slot_allocation_message[] = "Failed to allocate an SSH session slot.";
        outersshpriv_reactor_destroy(reactor, unused_session_reactor_destroyed, operation);
        finish_session_creation(pool, outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
            slot_allocation_message, sizeof(slot_allocation_message) - 1));
        return;
    }
    if (operation->windows_banner) {
        atomic_store(&pool->_commandDialect, OUTERSSH_COMMAND_DIALECT_WINDOWS);
    } else {
        int unknown = OUTERSSH_COMMAND_DIALECT_UNKNOWN;
        atomic_compare_exchange_strong(&pool->_commandDialect, &unknown, OUTERSSH_COMMAND_DIALECT_POSIX);
    }
    outersshpriv_reactor_set_session_pool(reactor, pool, session);
    outersshpriv_reactor_start(reactor);
    finish_session_creation(
        pool,
        (OuterSSHError){0});
    destroy_session_creation(operation);
}

static void finish_session_creation(
    OuterSSHSessionPool *pool,
    OuterSSHError error)
{
    pool->_sessionCreation = NULL;
    outersshpriv_session_pool_wake_session_waiters(pool, error);
}

void outersshpriv_session_pool_wake_session_waiters(
    OuterSSHSessionPool *pool,
    OuterSSHError error)
{
    otqueue_assert(pool->_queue);
    outersshpriv_wake(&pool->_sessionWaiters, error);
}

SSHReactor *outersshpriv_session_pool_ready_reactor(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle *session,
    OuterSSHError *error)
{
    *session = (SSHSessionPoolSessionHandle){0};
    if (error->domain != OUTERSSH_ERROR_NONE) return NULL;
    if (pool->_disconnecting || pool->_disconnected) {
        static const char closing_message[] = "The SSH connection is closing.";
        *error = outerssh_session_error(OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING,
            closing_message, sizeof(closing_message) - 1);
        return NULL;
    }
    SSHReactor *reactor = outersshpriv_session_pool_available_reactor(pool, session);
    if (reactor == NULL) {
        static const char session_unavailable_message[] = "The SSH session is no longer available.";
        *error = outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
            session_unavailable_message, sizeof(session_unavailable_message) - 1);
    }
    return reactor;
}

#pragma mark - Cancel Session Startup

bool outersshpriv_cancel_session_startup(SSHSessionCreationOperation *operation)
{
    otqueue_assert(operation->pool->_queue);
    if (operation->cancellation_requested || operation->reactor == NULL) {
        return false;
    }
    operation->cancellation_requested = true;
    outersshpriv_reactor_cancel_startup(operation->reactor);
    return true;
}

#pragma mark - Poke Existing Sessions

static void perform_poke(void *context);
static void send_keepalive_on_reactor(void *context);

void outerssh_session_pool_poke(OuterSSHSessionPool *pool)
{
    otqueue_async(pool->_queue, pool, perform_poke);
}

static void perform_poke(void *context)
{
    OuterSSHSessionPool *pool = context;
    otqueue_assert(pool->_queue);
    if (pool->_disconnecting || pool->_disconnected) return;
    for (size_t index = 0; index < pool->_sessions.count; index++) {
        SSHSessionSlot *session = &pool->_sessions.slots[index];
        if (session->reactor != NULL &&
            !outersshpriv_reactor_session_has_failed(session->reactor)) {
            otqueue_async(outersshpriv_reactor_queue(session->reactor), session->reactor,
                send_keepalive_on_reactor);
        }
    }
}

static void send_keepalive_on_reactor(void *context)
{
    static const char reason[] = "application poke";
    (void)outersshpriv_reactor_send_keepalive(context, reason, sizeof(reason) - 1,
        validation_timeout_milliseconds);
}

static void unused_session_reactor_destroyed(void *context)
{
    SSHSessionCreationOperation *operation = context;
    otqueue_async(operation->pool->_queue, operation, destroy_session_creation);
}

static void destroy_session_creation(void *context)
{
    SSHSessionCreationOperation *operation = context;
    OuterSSHSessionPool *pool = operation->pool;
    operation->pool = NULL;
    free(operation->error_storage);
    free(operation);
    outersshpriv_session_pool_end_operation(pool);
}
