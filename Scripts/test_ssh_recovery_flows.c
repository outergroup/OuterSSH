#include "SSHTestSupport.h"
#include "platform/OTSocket.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool fail_operation_allocation;
static bool fail_array_allocation;
static bool fail_batch_allocation;
static void *recovery_calloc(size_t count, size_t size)
{
    return fail_operation_allocation ? NULL : calloc(count, size);
}
static void *recovery_realloc(void *pointer, size_t size)
{
    return fail_array_allocation ? NULL : realloc(pointer, size);
}
static void *recovery_malloc(size_t size)
{
    return fail_batch_allocation ? NULL : malloc(size);
}

#define calloc recovery_calloc
#define realloc recovery_realloc
#define malloc recovery_malloc
#include "SSHRecoveryFlows.c"
#undef calloc
#undef realloc
#undef malloc

enum {
    TCP_SUCCESS,
    UNIX_SUCCESS,
    SYNCHRONOUS_SUCCESS,
    START_FAILURE_THEN_SUCCESS,
    START_FAILURE_TWICE,
    TIMEOUT_THEN_SUCCESS,
    SESSION_CLOSED_THEN_SUCCESS,
    CHANNEL_FAILURE,
    ATTACHMENT_FAILURE,
    START_FAILURE_WITH_CLOSED_SOCKET,
    ACQUISITION_FAILURE,
    LISTENER_REMOVED_DURING_ACQUISITION,
    PROXY_REPLACED_DURING_ACQUISITION,
    DISCONNECT_DURING_ACQUISITION,
    SHUTDOWN_DURING_OPEN,
    STREAMLOCAL_DISABLED_DURING_ACQUISITION,
    STALE_PROXY_GENERATION,
    CONTROLLER_DESTROYED,
    OPERATION_ALLOCATION_FAILURE,
    ARRAY_ALLOCATION_FAILURE,
    BATCH_ALLOCATION_FAILURE,
    SCENARIO_COUNT
};

struct SSHReactor {
    otqueue_t queue;
};
static OuterSSHSessionPool pool;
static bool proxy_running;
static SSHSessionSlot source_slot;
static SSHReactor source_reactor;
static SSHReactor target_reactor;
static SSHRelay *detached_relay;
static SSHRelay *attached_relay;
static SSHRelay *opening_relay;
static SSHRelayRecoveryOperation *opening_operation;
static SSHRelayRecoveryOperation *first_operation;
static ssh_test_semaphore_t finished;
static unsigned scenario;
static unsigned acquisitions;
static unsigned attempts;
static unsigned removals;
static unsigned closes;
static unsigned releases;
static otsocket_t peer_socket;

static void run_scenario(void *context);
static void verify_scenario(void *context);
static void finish_open(void *context);

static void verification_barrier(void *context)
{
    otqueue_async(pool._queue, context, verify_scenario);
}

static void verify_if_recovery_finished(void);
static bool verification_scheduled;

void outersshpriv_session_pool_begin_operation(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    pool->pending_operations++;
}

void outersshpriv_session_pool_end_operation(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    assert(pool->pending_operations != 0);
    pool->pending_operations--;
    verify_if_recovery_finished();
}

void outersshpriv_session_pool_finish_destroy_if_ready(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
}


bool outersshpriv_relay_close(SSHRelay *relay)
{
    otsocket_t socket = atomic_exchange(&relay->socket, -1);
    if (socket >= 0) {
        assert(otsocket_close(socket) == 0);
        closes++;
    }
    return socket >= 0;
}

void outersshpriv_relay_release(SSHRelay *relay)
{
    assert(atomic_fetch_sub(&relay->reference_count, 1) == 1);
    releases++;
    free(relay->route.destination);
    free(relay->to_ssh.bytes);
    free(relay);
}

bool outersshpriv_reactor_is_current_queue(SSHReactor *reactor)
{
    otqueue_assert(reactor->queue);
    return true;
}

otqueue_t outersshpriv_reactor_queue(SSHReactor *reactor)
{
    return reactor->queue;
}

SSHRelay *outersshpriv_reactor_detach_next_recoverable_relay(SSHReactor *reactor, size_t *index)
{
    assert(reactor == &source_reactor);
    otqueue_assert(reactor->queue);
    (*index)++;
    SSHRelay *relay = detached_relay;
    detached_relay = NULL;
    return relay;
}

bool outersshpriv_reactor_session_has_failed(SSHReactor *reactor)
{
    assert(reactor == &source_reactor);
    return true;
}

void outersshpriv_remove_session(OuterSSHSessionPool *value, SSHSessionPoolSessionHandle session)
{
    assert(value == &pool && session.generation != 0);
    otqueue_assert(pool._queue);
    removals++;
    if (session.generation == 1) {
        source_slot.reactor = NULL;
    }
}

static SSHCompletionHandler pending_session_resume;

static void session_available(void *context)
{
    SSHRelayRecoveryOperation *operation = context;
    OuterSSHError error = {0};
    if (scenario == ACQUISITION_FAILURE) {
        error.domain = OUTERSSH_ERROR_SESSION;
        error.code = OUTERSSH_SESSION_ERROR_UNAVAILABLE;
    }
    pending_session_resume(operation, error);
}

SSHReactor *outersshpriv_session_pool_ready_reactor(OuterSSHSessionPool *value,
    SSHSessionPoolSessionHandle *session, OuterSSHError *error)
{
    assert(value == &pool);
    *session = (SSHSessionPoolSessionHandle){0};
    if (error->domain != OUTERSSH_ERROR_NONE) return NULL;
    *session = (SSHSessionPoolSessionHandle){.generation = acquisitions + 1};
    return &target_reactor;
}

void outersshpriv_session_pool_run_when_ready(OuterSSHSessionPool *value, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context)
{
    assert(value == &pool && resume == ssh_relay_recovery_session_request_finished);
    assert(waiter == &((SSHRelayRecoveryOperation *)context)->waiter);
    pending_session_resume = resume;
    otqueue_assert(pool._queue);
    SSHRelayRecoveryOperation *operation = context;
    assert(operation->pool == &pool && operation->relay != NULL);
    if (first_operation == NULL) {
        first_operation = operation;
    }
    assert(first_operation == operation);
    acquisitions++;
    if (scenario == LISTENER_REMOVED_DURING_ACQUISITION) {
        proxy_running = false;
    } else if (scenario == PROXY_REPLACED_DURING_ACQUISITION) {
        pool.proxy_generation++;
    } else if (scenario == DISCONNECT_DURING_ACQUISITION) {
        pool.shutdown_requested = true;
    } else if (scenario == STREAMLOCAL_DISABLED_DURING_ACQUISITION) {
        pool._directStreamLocalUnsupported = true;
    }
    otqueue_async(pool._queue, operation, session_available);
}

static void shutdown_before_open_completion(void *context)
{
    (void)context;
    pool._disconnecting = true;
    otqueue_async(target_reactor.queue, NULL, finish_open);
}

static int start_open(SSHReactor *reactor, SSHRelay *relay, SSHRelayRecoveryOperation *operation)
{
    assert(reactor == &target_reactor);
    otqueue_assert(reactor->queue);
    assert(operation->relay == NULL && operation->reactor == NULL);
    assert(relay->identifier == 27 && relay->proxy_generation == 9);
    size_t readable;
    const unsigned char *payload = outersshpriv_relay_buffer_readable(&relay->to_ssh, &readable);
    assert(outersshpriv_relay_buffer_pending(&relay->to_ssh) == 7 && readable == 7);
    assert(memcmp(payload, "payload", 7) == 0);
    attempts++;
    if (scenario == START_FAILURE_TWICE ||
        (scenario == START_FAILURE_THEN_SUCCESS && attempts == 1) ||
        scenario == START_FAILURE_WITH_CLOSED_SOCKET) {
        if (scenario == START_FAILURE_WITH_CLOSED_SOCKET) {
            outersshpriv_relay_close(relay);
        }
        return -1;
    }
    opening_operation = operation;
    opening_relay = relay;
    if (scenario == SYNCHRONOUS_SUCCESS) {
        finish_open(NULL);
    } else if (scenario == SHUTDOWN_DURING_OPEN) {
        otqueue_async(pool._queue, NULL, shutdown_before_open_completion);
    } else {
        otqueue_async(reactor->queue, NULL, finish_open);
    }
    return 0;
}

int outersshpriv_reactor_open_tcp_relay(
    SSHReactor *reactor, SSHRelay *relay, SSHRelayRecoveryOperation *operation,
    const char *host, size_t host_length, int port, const char *source_host, size_t source_host_length, int source_port, uint64_t timeout)
{
    (void)source_host_length;
    assert(relay->route.type == SSH_RELAY_TARGET_TCP);
    assert(host == relay->route.destination && host_length == sizeof("localhost") - 1 && memcmp(host, "localhost", host_length) == 0 && port == 8080);
    assert(strcmp(source_host, "127.0.0.1") == 0 && source_port == 0 && timeout == 10000);
    return start_open(reactor, relay, operation);
}

int outersshpriv_reactor_open_streamlocal_relay(
    SSHReactor *reactor, SSHRelay *relay, SSHRelayRecoveryOperation *operation,
    const char *path, size_t path_length, const char *source_host, size_t source_host_length, int source_port, uint64_t timeout)
{
    (void)source_host_length;
    assert(relay->route.type == SSH_RELAY_TARGET_STREAMLOCAL);
    assert(path == relay->route.destination && path_length == sizeof("/run/test.sock") - 1 && memcmp(path, "/run/test.sock", path_length) == 0);
    assert(strcmp(source_host, "127.0.0.1") == 0 && source_port == 0 && timeout == 10000);
    return start_open(reactor, relay, operation);
}

static void finish_open(void *context)
{
    (void)context;
    SSHRelayRecoveryOperation *operation = opening_operation;
    SSHRelay *relay = opening_relay;
    opening_operation = NULL;
    opening_relay = NULL;
    SSHReactorRelayOpenResult result = SSH_REACTOR_RELAY_OPEN_SUCCEEDED;
    if (scenario == TIMEOUT_THEN_SUCCESS && attempts == 1) {
        result = SSH_REACTOR_RELAY_OPEN_TIMED_OUT;
    } else if ((scenario == SESSION_CLOSED_THEN_SUCCESS && attempts == 1) ||
               scenario == SHUTDOWN_DURING_OPEN) {
        result = SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED;
    } else if (scenario == CHANNEL_FAILURE) {
        result = SSH_REACTOR_RELAY_OPEN_CHANNEL_FAILED;
    } else if (scenario == ATTACHMENT_FAILURE) {
        result = SSH_REACTOR_RELAY_OPEN_ATTACHMENT_FAILED;
        outersshpriv_relay_close(relay);
    }
    if (result == SSH_REACTOR_RELAY_OPEN_SUCCEEDED) {
        attached_relay = relay;
        relay = NULL;
    }
    outersshpriv_relay_recovery_open_completed(operation, result, relay);
}

static void verify_if_recovery_finished(void)
{
    otqueue_assert(pool._queue);
    if (pool.pending_operations == 0 && !verification_scheduled) {
        verification_scheduled = true;
        otqueue_async(target_reactor.queue, NULL, verification_barrier);
    }
}

static void collection_finished(void *context)
{
    (void)context;
    verify_if_recovery_finished();
}

static void collect_relays(void *context)
{
    (void)context;
    outersshpriv_recover_after_session_failure(&pool,
        (SSHSessionPoolSessionHandle){.generation = 1}, &source_reactor);
    otqueue_async(pool._queue, NULL, collection_finished);
}

static void run_scenario(void *context)
{
    (void)context;
    assert(pool.pending_operations == 0);
    assert(opening_operation == NULL && detached_relay == NULL && attached_relay == NULL);
    verification_scheduled = false;
    acquisitions = attempts = removals = closes = releases = 0;
    first_operation = NULL;
    pool._directStreamLocalUnsupported = false;
    proxy_running = scenario != CONTROLLER_DESTROYED;
    pool.shutdown_requested = pool._disconnecting = pool._disconnected = false;
    source_slot.reactor = &source_reactor;
    pool.proxy_generation = scenario == STALE_PROXY_GENERATION ? 10 : 9;
    fail_operation_allocation = scenario == OPERATION_ALLOCATION_FAILURE;
    fail_array_allocation = scenario == ARRAY_ALLOCATION_FAILURE;
    fail_batch_allocation = scenario == BATCH_ALLOCATION_FAILURE;
    otsocket_t sockets[2];
    assert(ssh_test_socket_pair(sockets) == 0);
    peer_socket = sockets[1];
    detached_relay = calloc(1, sizeof(*detached_relay));
    atomic_init(&detached_relay->reference_count, 1);
    atomic_init(&detached_relay->socket, sockets[0]);
    detached_relay->identifier = 27;
    detached_relay->proxy_generation = 9;
    bool streamlocal = scenario == UNIX_SUCCESS || scenario == STREAMLOCAL_DISABLED_DURING_ACQUISITION;
    detached_relay->route = (SSHRelayRoute){
        .type = streamlocal ? SSH_RELAY_TARGET_STREAMLOCAL : SSH_RELAY_TARGET_TCP,
        .destination_length = streamlocal ? sizeof("/run/test.sock") - 1 : sizeof("localhost") - 1,
        .port = 8080
    };
    detached_relay->route.destination = malloc(detached_relay->route.destination_length);
    assert(detached_relay->route.destination != NULL);
    memcpy(detached_relay->route.destination, streamlocal ? "/run/test.sock" : "localhost",
        detached_relay->route.destination_length);
    detached_relay->to_ssh = (SSHRelayBuffer){
        .bytes = (unsigned char *)strdup("XXpayload"), .capacity = 10, .start = 2, .count = 7
    };
    otqueue_async(source_reactor.queue, NULL, collect_relays);
}

static void verify_scenario(void *context)
{
    (void)context;
    assert(pool.pending_operations == 0);
    bool succeeds = scenario == TCP_SUCCESS || scenario == UNIX_SUCCESS ||
        scenario == SYNCHRONOUS_SUCCESS || scenario == START_FAILURE_THEN_SUCCESS ||
        scenario == TIMEOUT_THEN_SUCCESS || scenario == SESSION_CLOSED_THEN_SUCCESS;
    bool retries = scenario == START_FAILURE_THEN_SUCCESS || scenario == START_FAILURE_TWICE ||
        scenario == TIMEOUT_THEN_SUCCESS || scenario == SESSION_CLOSED_THEN_SUCCESS;
    bool starts = scenario <= START_FAILURE_WITH_CLOSED_SOCKET || scenario == SHUTDOWN_DURING_OPEN;
    assert(attempts == (retries ? 2u : starts ? 1u : 0u));
    assert(removals == 1u + (unsigned)(retries || scenario == SHUTDOWN_DURING_OPEN));
    assert((attached_relay != NULL) == succeeds);
    if (succeeds) {
        assert(closes == 0 && releases == 0);
        assert(otsocket_write(atomic_load(&attached_relay->socket), "x", 1) == 1);
        char byte;
        assert(otsocket_read(peer_socket, &byte, 1) == 1 && byte == 'x');
        outersshpriv_relay_close(attached_relay);
        outersshpriv_relay_release(attached_relay);
        attached_relay = NULL;
    }
    assert(closes == 1 && releases == 1);
    char byte;
    assert(otsocket_read(peer_socket, &byte, 1) == 0);
    otsocket_close(peer_socket);
    if (++scenario < SCENARIO_COUNT) {
        otqueue_async(pool._queue, NULL, run_scenario);
    } else {
        ssh_test_semaphore_signal(finished);
    }
}

int main(void)
{
    pool.pending_operations = 0;
    pool._queue = ssh_test_control_queue_create("recovery-pool-test");
    source_reactor.queue = ssh_test_control_queue_create("recovery-source-test");
    // Collection and opens are serialized in the test so its counters also cover allocation failures.
    target_reactor.queue = source_reactor.queue;
    pool._sessions.slots = &source_slot;
    pool._sessions.count = 1;
    source_slot.generation = 1;
    finished = ssh_test_semaphore_create(0);
    otqueue_async(pool._queue, NULL, run_scenario);
    assert(ssh_test_semaphore_wait(finished, 10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(finished);
    otqueue_release(source_reactor.queue);
    otqueue_release(pool._queue);
    puts("PASS: recovery handoffs, retry limits, synchronous completion, shutdown, and allocation cleanup");
    return 0;
}

bool outersshpriv_proxy_pool_has_generation(OuterSSHSessionPool *value, uint64_t generation)
{
    return proxy_running && value->proxy_generation == generation;
}
