#include "SSHFlows.h"

#include <assert.h>
#include <stdlib.h>

#include "ProxyReactorInternal.h"
#include "platform/SSHLogging.h"
#include "SSHSocketBridgeInternal.h"
#include "SSHSessionPoolInternal.h"

static const uint64_t relay_open_timeout_milliseconds = 10000;

#pragma mark - Recover After Session Failure

typedef struct {
    OuterSSHSessionPool *pool;
    SSHSessionPoolSessionHandle session;
    SSHRelayRecoveryOperation **operations;
    size_t operation_count;
} SSHSessionRecovery;

static void finish_recovering_after_session_failure(void *opaque_recovery);
static void finish_removing_failed_sessions(void *opaque_pool);
static void resume_relay_recovery(SSHRelayRecoveryOperation *operation);
static void ssh_relay_recovery_session_request_finished(void *context, OuterSSHError error);
static void start_recovered_relay_on_reactor(void *opaque_operation);
static void finish_relay_recovery_attempt(void *opaque_operation);
static bool relay_recovery_is_allowed(SSHRelayRecoveryOperation *operation);
static void destroy_relay_recovery(SSHRelayRecoveryOperation *operation);

void outersshpriv_recover_after_session_failure(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle session,
    SSHReactor *reactor)
{
    assert(outersshpriv_reactor_is_current_queue(reactor));
    SSHRelayRecoveryOperation **operations = NULL;
    size_t operation_count = 0;
    size_t operation_capacity = 0;
    size_t next_index = 0;
    SSHRelay *relay;
    while ((relay = outersshpriv_reactor_detach_next_recoverable_relay(
                reactor,
                &next_index)) != NULL) {
        SSHRelayRecoveryOperation *operation = calloc(1, sizeof(*operation));
        if (operation == NULL) {
            outersshpriv_relay_close(relay);
            outersshpriv_relay_release(relay);
            continue;
        }
        operation->relay = relay;
        operation->pool = pool;
        operation->may_retry = true;
        if (operation_count == operation_capacity) {
            size_t capacity = operation_capacity == 0 ? 4 : operation_capacity * 2;
            SSHRelayRecoveryOperation **resized = realloc(
                operations, capacity * sizeof(*resized));
            if (resized == NULL) {
                free(operation);
                outersshpriv_relay_close(relay);
                outersshpriv_relay_release(relay);
                continue;
            }
            operations = resized;
            operation_capacity = capacity;
        }
        operations[operation_count++] = operation;
    }
    SSHSessionRecovery *recovery = malloc(sizeof(*recovery));
    if (recovery == NULL) {
        for (size_t index = 0; index < operation_count; index++) {
            outersshpriv_relay_close(operations[index]->relay);
            outersshpriv_relay_release(operations[index]->relay);
            free(operations[index]);
        }
        free(operations);
        otqueue_async(pool->_queue, pool, finish_removing_failed_sessions);
        return;
    }
    *recovery = (SSHSessionRecovery){
        .pool = pool,
        .session = session,
        .operations = operations,
        .operation_count = operation_count
    };
    otqueue_async(pool->_queue, recovery, finish_recovering_after_session_failure);
}

static void finish_recovering_after_session_failure(void *opaque_recovery)
{
    SSHSessionRecovery *recovery = opaque_recovery;
    OuterSSHSessionPool *pool = recovery->pool;
    otqueue_assert(pool->_queue);
    outersshpriv_remove_session(pool, recovery->session);
    for (size_t index = 0; index < recovery->operation_count; index++) {
        outersshpriv_session_pool_begin_operation(pool);
        resume_relay_recovery(recovery->operations[index]);
    }
    free(recovery->operations);
    free(recovery);
}

static void finish_removing_failed_sessions(void *opaque_pool)
{
    OuterSSHSessionPool *pool = opaque_pool;
    otqueue_assert(pool->_queue);
    for (size_t index = 0; index < pool->_sessions.count; index++) {
        SSHSessionSlot *session = &pool->_sessions.slots[index];
        if (session->reactor == NULL ||
            !outersshpriv_reactor_session_has_failed(session->reactor)) {
            continue;
        }
        outersshpriv_remove_session(pool, (SSHSessionPoolSessionHandle){
            .index = index,
            .generation = session->generation
        });
    }
}


static void resume_relay_recovery(SSHRelayRecoveryOperation *operation)
{
    OuterSSHSessionPool *pool = operation->pool;
    otqueue_assert(pool->_queue);
    SSHRelay *relay = operation->relay;
    if (!relay_recovery_is_allowed(operation)) {
        SSH_LOG_INFO(
            SSH_LOG_CATEGORY_RELAY,
            "Closing SSH relay %{public}llu because its proxy state or route is no longer available",
            (unsigned long long)relay->identifier);
        destroy_relay_recovery(operation);
        return;
    }
    SSH_LOG_INFO(
        SSH_LOG_CATEGORY_RELAY,
        "Reopening SSH relay %{public}llu socket=%{public}lld buffered=%{public}zu bytes",
        (unsigned long long)relay->identifier,
        (long long)atomic_load_explicit(&relay->socket, memory_order_acquire),
        outersshpriv_relay_buffer_pending(&relay->to_ssh));
    outersshpriv_session_pool_run_when_ready(pool, &operation->waiter,
        ssh_relay_recovery_session_request_finished, operation);
}

static void ssh_relay_recovery_session_request_finished(void *context, OuterSSHError error)
{
    SSHRelayRecoveryOperation *operation = context;
    otqueue_assert(operation->pool->_queue);
    SSHSessionPoolSessionHandle session;
    SSHReactor *reactor = outersshpriv_session_pool_ready_reactor(operation->pool, &session, &error);
    // Session acquisition can outlive the state or a change in streamlocal support.
    if (error.domain != OUTERSSH_ERROR_NONE || !relay_recovery_is_allowed(operation)) {
        destroy_relay_recovery(operation);
        return;
    }
    operation->session = session;
    operation->reactor = reactor;
    otqueue_async(outersshpriv_reactor_queue(reactor), operation, start_recovered_relay_on_reactor);
}

static void start_recovered_relay_on_reactor(void *opaque_operation)
{
    SSHRelayRecoveryOperation *operation = opaque_operation;
    SSHReactor *reactor = operation->reactor;
    assert(outersshpriv_reactor_is_current_queue(reactor));
    SSHRelay *relay = operation->relay;
    operation->reactor = NULL;
    // Relinquish before opening: a successful start may complete synchronously.
    operation->relay = NULL;
    int result;
    static const char loopback_host[] = "127.0.0.1";
    switch (relay->route.type) {
    case SSH_RELAY_TARGET_TCP:
        result = outersshpriv_reactor_open_tcp_relay(
            reactor, relay, operation, relay->route.destination, relay->route.destination_length, relay->route.port,
            loopback_host, sizeof(loopback_host) - 1, 0, relay_open_timeout_milliseconds);
        break;
    case SSH_RELAY_TARGET_STREAMLOCAL:
        result = outersshpriv_reactor_open_streamlocal_relay(
            reactor, relay, operation, relay->route.destination, relay->route.destination_length,
            loopback_host, sizeof(loopback_host) - 1, 0, relay_open_timeout_milliseconds);
        break;
    default:
        abort();
    }
    if (result != 0) {
        outersshpriv_relay_recovery_open_completed(
            operation, SSH_REACTOR_RELAY_OPEN_START_FAILED, relay);
    }
}

void outersshpriv_relay_recovery_open_completed(
    SSHRelayRecoveryOperation *operation,
    SSHReactorRelayOpenResult result,
    SSHRelay *detached_relay)
{
    operation->relay = detached_relay;
    operation->result = result;
    otqueue_async(operation->pool->_queue, operation, finish_relay_recovery_attempt);
}

static void finish_relay_recovery_attempt(void *opaque_operation)
{
    SSHRelayRecoveryOperation *operation = opaque_operation;
    OuterSSHSessionPool *pool = operation->pool;
    otqueue_assert(pool->_queue);
    switch (operation->result) {
    case SSH_REACTOR_RELAY_OPEN_START_FAILED:
    case SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED:
    case SSH_REACTOR_RELAY_OPEN_TIMED_OUT:
        if (operation->may_retry && operation->relay != NULL &&
            atomic_load_explicit(&operation->relay->socket, memory_order_acquire) >= 0) {
            outersshpriv_remove_session(pool, operation->session);
            operation->may_retry = false;
            resume_relay_recovery(operation);
            return;
        }
        break;
    case SSH_REACTOR_RELAY_OPEN_SUCCEEDED:
    case SSH_REACTOR_RELAY_OPEN_CHANNEL_FAILED:
    case SSH_REACTOR_RELAY_OPEN_ATTACHMENT_FAILED:
    case SSH_REACTOR_RELAY_OPEN_CANCELLED:
        break;
    }
    destroy_relay_recovery(operation);
}

#pragma mark - Recovery Eligibility and Cleanup

static bool relay_recovery_is_allowed(SSHRelayRecoveryOperation *operation)
{
    SSHRelay *relay = operation->relay;
    if (operation->pool->shutdown_requested || operation->pool->_disconnecting ||
        operation->pool->_disconnected) return false;
    return outersshpriv_proxy_pool_has_generation(operation->pool, relay->proxy_generation) &&
        !(relay->route.type == SSH_RELAY_TARGET_STREAMLOCAL && operation->pool->_directStreamLocalUnsupported);
}

static void destroy_relay_recovery(SSHRelayRecoveryOperation *operation)
{
    if (operation->relay != NULL) {
        outersshpriv_relay_close(operation->relay);
        outersshpriv_relay_release(operation->relay);
    }
    OuterSSHSessionPool *pool = operation->pool;
    free(operation);
    outersshpriv_session_pool_end_operation(pool);
}
