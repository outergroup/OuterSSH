#include "SSHTestSupport.h"
#include "platform/OTSocket.h"
#include <assert.h>

#include <errno.h>
#include <stdlib.h>
#include "SSHSessionPoolInternal.h"
#include "SSHSocketBridgeInternal.h"

static bool fail_operation_allocation;
static otsocket_t reactor_socket = -1;
static void *session_test_calloc(size_t count, size_t size)
{
    return fail_operation_allocation && size == sizeof(SSHSessionCreationOperation)
        ? NULL : calloc(count, size);
}
static int session_test_close(otsocket_t socket);
#define calloc session_test_calloc
#define otsocket_close session_test_close
#include "SSHSessionFlows.c"
#undef calloc
#undef otsocket_close

SSHForwarder *outersshpriv_tcp_forwarder_create(OuterSSHSessionPool *pool,
    const char *host, size_t length, uint16_t port, OuterSSHError *error)
{
    (void)pool; (void)host; (void)length; (void)port; (void)error;
    abort();
}
void outersshpriv_forwarder_activate(SSHForwarder *forwarder)
{
    (void)forwarder;
    abort();
}
void outersshpriv_forwarder_connect(SSHForwarder *forwarder, otsocket_t socket, const char *host, size_t host_length,
    uint16_t port, SSHSocketSender sender, SSHForwarderConnectionCompletion completion, void *context)
{
    (void)forwarder; (void)socket; (void)host; (void)host_length; (void)port; (void)sender; (void)completion; (void)context;
    abort();
}

static void ensured(void *context, OuterSSHError error);
static int controller;

SSHPoolEvent *outersshpriv_reply_reserve(OuterSSHSessionPool *reply_pool, OuterSSHEventType type, uint64_t tag)
{
    assert(type == OUTERSSH_EVENT_OPERATION_COMPLETED);
    SSHPoolEvent *reply = calloc(1, sizeof(*reply));
    assert(reply != NULL);
    reply->event = (OuterSSHEvent){.type = type, .pool = reply_pool, .tag = tag};
    return reply;
}

/* The ensure-session reply, checked as the application would receive it. */
void outersshpriv_reply(SSHPoolEvent *reply, OuterSSHError error)
{
    assert(reply->event.tag == (uint64_t)(uintptr_t)&controller);
    free(reply);
    ensured(&controller, error);
}

enum {
    SESSION_CREATE_FAILURE = 5,
    AUTHENTICATION_FAILURE,
    REACTOR_ALLOCATION_FAILURE,
    CANCEL_DURING_AUTHENTICATION,
    CANCEL_AFTER_AUTHENTICATION,
    OPERATION_ALLOCATION_FAILURE,
    SESSION_SLOT_ALLOCATION_FAILURE,
    LATE_AUTHENTICATION_FAILURE,
    HANDSHAKE_FAILURE,
    STAGE_COUNT
};

static OuterSSHSessionPool pool;
static SSHSessionSlot slot;
static otqueue_t reactor_queue;
static ssh_test_semaphore_t finished;
static unsigned stage;
static unsigned completions;
static unsigned connections;
static unsigned authentications;
static unsigned destroyed_reactors;
static unsigned freed_sessions;
static bool advancement_scheduled;
static otsocket_t peer_socket = -1;
static ssh_test_semaphore_t pool_action_finished;
static unsigned keepalives;
static bool available;
static bool entering_api;
static unsigned selections;
static unsigned continuations;
static bool invalidate_after_continuation;
static bool disconnect_after_continuation;
static OuterSSHSessionErrorCode expected_work_error;

static int session_test_close(otsocket_t socket)
{
    otqueue_assert(pool._queue);
    return otsocket_close(socket);
}

static void run_stage(void *context);
static void advance_if_finished(void);

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
    advance_if_finished();
}

void outersshpriv_session_pool_finish_destroy_if_ready(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
}


SSHReactor *outersshpriv_session_pool_available_reactor(
    OuterSSHSessionPool *value, SSHSessionPoolSessionHandle *session)
{
    otqueue_assert(value->_queue);
    selections++;
    *session = (SSHSessionPoolSessionHandle){.generation = available ? 1 : 0};
    return available ? (SSHReactor *)&slot : NULL;
}

static void complete_connect(void *context)
{
    static const char session_error_message_1[] = "Test TCP resolution failure.";

    SSHSessionCreationOperation *operation = context;
    assert(pool._sessionWaiters.head != NULL && pool._sessionWaiters.head->next == pool._sessionWaiters.tail);
    if (stage == 0) {
        OuterSSHError error = outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE, session_error_message_1, sizeof(session_error_message_1) - 1);
        error.system_error_code = EHOSTUNREACH;
        outersshpriv_session_pool_tcp_connect_failed(operation, error);
        return;
    }
    otsocket_t sockets[2];
    assert(ssh_test_socket_pair(sockets) == 0);
    peer_socket = sockets[1];
    if (stage == 4) {
        pool._disconnecting = true;
    }
    outersshpriv_session_pool_tcp_connected(operation, sockets[0]);
}

ProxyReactorTCPConnectHandle outersshpriv_proxy_reactor_connect_tcp(
    ProxyReactor *reactor, const char *host, size_t host_length, int32_t port,
    SSHSessionCreationOperation *operation)
{
    assert(reactor == pool._connectorReactor);
    assert(host_length == 9 && memcmp(host, "test-host", host_length) == 0 && port == 22);
    connections++;
    otqueue_async(pool._queue, operation, complete_connect);
    return (ProxyReactorTCPConnectHandle){.generation = connections};
}

static void interrupt_authentication(void *context)
{
    static const char session_error_message_2[] = "closing";

    (void)context;
    otqueue_assert(pool._queue);
    pool._disconnecting = true;
    if (stage == CANCEL_DURING_AUTHENTICATION || stage == CANCEL_AFTER_AUTHENTICATION) {
        assert(ssh_test_socket_is_open(reactor_socket));
        assert(outersshpriv_cancel_session_startup(pool._sessionCreation));
        assert(!outersshpriv_cancel_session_startup(pool._sessionCreation));
    }
    if (stage == CANCEL_DURING_AUTHENTICATION) {
        outersshpriv_session_pool_wake_session_waiters(&pool, outerssh_session_error(OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING, session_error_message_2, sizeof(session_error_message_2) - 1));
    }
    ssh_test_semaphore_signal(pool_action_finished);
}

LIBSSH2_SESSION *outersshpriv_session_create(otsocket_t socket, SSHSessionStartResult *result)
{
    if (stage == SESSION_CREATE_FAILURE) {
        result->error = (OuterSSHError){
            .domain = OUTERSSH_ERROR_SESSION,
            .code = OUTERSSH_SESSION_ERROR_SOCKET_CONFIGURATION_FAILED,
            .ssh_error_code = EMFILE,
            .ssh_error_message = strerror(EMFILE),
            .ssh_error_message_length = strlen(strerror(EMFILE))
        };
        return NULL;
    }
    reactor_socket = socket;
    return (LIBSSH2_SESSION *)&slot;
}

static void deliver_handshake(void *opaque)
{
    SSHHandshakeContext *context = opaque;
    context->finished(context->context, stage == HANDSHAKE_FAILURE ? LIBSSH2_ERROR_PROTO : 0);
}

void outersshpriv_reactor_handshake(SSHReactor *reactor,
    void (*finished)(void *, int), void *completion_context)
{
    assert(reactor == (SSHReactor *)&slot);
    static SSHHandshakeContext storage;
    SSHHandshakeContext *context = &storage;
    *context = (SSHHandshakeContext){.finished = finished, .context = completion_context};
    otqueue_async(reactor_queue, context, deliver_handshake);
}

static void cancel_startup(void *context)
{
    (void)context;
    otsocket_shutdown(reactor_socket, SHUT_RDWR);
}

void outersshpriv_reactor_cancel_startup(SSHReactor *reactor)
{
    otqueue_async(reactor_queue, reactor, cancel_startup);
}

int libssh2_session_last_error(LIBSSH2_SESSION *session, char **message, int *length, int copy)
{
    (void)session; (void)copy;
    *message = NULL;
    *length = 0;
    return LIBSSH2_ERROR_PROTO;
}

static void simulate_authentication(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    SSHAuthenticationRequest request = context->request;
    const char *username = request.username;
    size_t username_length = request.username_length;
    OuterSSHSessionAuthentication authentication = request.credentials;
    const char *agent_path = request.agent_path;
    size_t agent_path_length = request.agent_path_length;
    uint64_t timeout = request.timeout_milliseconds;
    SSHSessionStartResult result_value = {0};
    SSHSessionStartResult *result = &result_value;
    static const char session_error_message_3[] = "Authentication test failure.";

    assert(otqueue_get_specific(&pool) == NULL);
    assert(username == pool._username && username_length == pool._usernameLength && timeout == 60000);
    assert(authentication.password == pool._authentication.password);
    assert(authentication.password_length == pool._authentication.password_length);
    assert(authentication.public_key == pool._authentication.public_key);
    assert(authentication.private_key == pool._authentication.private_key);
    assert(authentication.passphrase == pool._authentication.passphrase);
    assert(authentication.passphrase_length == pool._authentication.passphrase_length);
    assert(agent_path == pool._sshAgentSocketPath && agent_path_length == pool._sshAgentSocketPathLength);
    assert(request.host_key_pool == &pool);
    assert(pool.pending_operations == (stage == 2 ? 2u : 3u));
    authentications++;
    if (stage == 3 || stage == CANCEL_DURING_AUTHENTICATION || stage == LATE_AUTHENTICATION_FAILURE) {
        otqueue_async(pool._queue, NULL, interrupt_authentication);
        assert(ssh_test_semaphore_wait(pool_action_finished,
            2 * NSEC_PER_SEC) == 0);
    }
    if (stage == AUTHENTICATION_FAILURE || stage == CANCEL_DURING_AUTHENTICATION ||
        stage == LATE_AUTHENTICATION_FAILURE) {
        if (stage == CANCEL_DURING_AUTHENTICATION) {
            char byte;
            ssize_t count = otsocket_read(reactor_socket, &byte, 1);
            assert(count == 0 || (count < 0 && errno == EPIPE));
        }
        result->error = outerssh_session_error(OUTERSSH_SESSION_ERROR_AUTHENTICATION_FAILED, session_error_message_3, sizeof(session_error_message_3) - 1);
        result->error.ssh_error_code = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
        static const char detail[] = "rejected";
        result->error.ssh_error_message = detail;
        result->error.ssh_error_message_length = sizeof(detail) - 1;
    }
    if (stage == CANCEL_AFTER_AUTHENTICATION) {
        otqueue_async(pool._queue, NULL, interrupt_authentication);
        assert(ssh_test_semaphore_wait(pool_action_finished, 2 * NSEC_PER_SEC) == 0);
    }
    context->finished(context->completion_context, result->error);
}

void outersshpriv_reactor_authenticate(SSHReactor *reactor,
    SSHAuthenticationRequest request,
    void (*finished_handler)(void *, OuterSSHError), void *completion_context)
{
    assert(reactor == (SSHReactor *)&slot);
    static SSHAuthenticationContext storage;
    SSHAuthenticationContext *context = &storage;
    *context = (SSHAuthenticationContext){.request = request,
        .finished = finished_handler, .completion_context = completion_context};
    otqueue_async_background(context, simulate_authentication);
}

static struct {
    void (*created)(void *context, SSHReactor *reactor);
    void *context;
} reactor_creation;

static void deliver_created_reactor(void *context)
{
    (void)context;
    reactor_creation.created(reactor_creation.context, (SSHReactor *)&slot);
}

bool outersshpriv_reactor_create(otqueue_t queue, otsocket_t socket, LIBSSH2_SESSION *session,
    void (*created)(void *context, SSHReactor *reactor), void *context)
{
    assert(queue == pool._queue);
    assert(session == (LIBSSH2_SESSION *)&slot);
    if (stage == REACTOR_ALLOCATION_FAILURE) {
        otsocket_close(socket);
        reactor_socket = -1;
        return false;
    }
    reactor_socket = socket;
    reactor_creation.created = created;
    reactor_creation.context = context;
    otqueue_async(queue, NULL, deliver_created_reactor);
    return true;
}

int olibssh_session_free(LIBSSH2_SESSION *session)
{
    assert(session == (LIBSSH2_SESSION *)&slot);
    freed_sessions++;
    return 0;
}

void outersshpriv_session_start_result_dispose(SSHSessionStartResult *result)
{
    free(result->error_storage);
}

SSHSessionPoolSessionHandle outersshpriv_session_pool_allocate_session(
    OuterSSHSessionPool *value, SSHReactor *reactor)
{
    assert(value == &pool && reactor == (SSHReactor *)&slot);
    if (stage == SESSION_SLOT_ALLOCATION_FAILURE) {
        return (SSHSessionPoolSessionHandle){0};
    }
    available = true;
    return (SSHSessionPoolSessionHandle){.generation = 1};
}

void outersshpriv_reactor_set_session_pool(
    SSHReactor *reactor, OuterSSHSessionPool *value, SSHSessionPoolSessionHandle session)
{
    assert(reactor == (SSHReactor *)&slot && value == &pool && session.generation == 1);
}

void outersshpriv_reactor_start(SSHReactor *reactor)
{
    assert(reactor == (SSHReactor *)&slot);
    otsocket_close(reactor_socket);
    reactor_socket = -1;
}

void outersshpriv_reactor_destroy(SSHReactor *reactor, void (*completion)(void *), void *context)
{
    assert(reactor == (SSHReactor *)&slot);
    destroyed_reactors++;
    otsocket_close(reactor_socket);
    reactor_socket = -1;
    olibssh_session_free((LIBSSH2_SESSION *)&slot);
    if (completion != NULL) otqueue_async(reactor_queue, context, completion);
}

otqueue_t outersshpriv_reactor_queue(SSHReactor *reactor)
{
    assert(reactor == (SSHReactor *)&slot);
    return reactor_queue;
}

bool outersshpriv_reactor_session_has_failed(SSHReactor *reactor)
{
    assert(reactor == (SSHReactor *)&slot);
    return false;
}

int outersshpriv_reactor_send_keepalive(SSHReactor *reactor, const char *reason, size_t reason_length, uint64_t timeout)
{
    otqueue_assert(reactor_queue);
    assert(reactor == (SSHReactor *)&slot && timeout == 5000);
    assert(reason_length == sizeof("application poke") - 1);
    assert(memcmp(reason, "application poke", reason_length) == 0);
    keepalives++;
    return 0;
}

static void work_continued(void *operation, OuterSSHError error)
{
    otqueue_assert(pool._queue);
    SSHSessionPoolSessionHandle session;
    SSHReactor *reactor = outersshpriv_session_pool_ready_reactor(&pool, &session, &error);
    assert(*(unsigned *)operation == continuations);
    if (expected_work_error != 0) {
        assert(error.domain != OUTERSSH_ERROR_NONE && error.code == (int32_t)expected_work_error);
        assert(reactor == NULL && session.generation == 0);
    } else {
        assert(error.domain == OUTERSSH_ERROR_NONE && reactor == (SSHReactor *)&slot);
        assert(session.generation == 1);
    }
    continuations++;
    if (invalidate_after_continuation) {
        available = false;
        expected_work_error = OUTERSSH_SESSION_ERROR_UNAVAILABLE;
    }
    if (disconnect_after_continuation) {
        pool._disconnecting = true;
        expected_work_error = OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING;
    }
}

static void even_work_finished(void *context, OuterSSHError error)
{
    assert(*(unsigned *)context % 2 == 0);
    work_continued(context, error);
}

static void odd_work_finished(void *context, OuterSSHError error)
{
    assert(*(unsigned *)context % 2 == 1);
    work_continued(context, error);
}

static void ensured(void *context, OuterSSHError error)
{
    assert(context == &controller && !entering_api);
    otqueue_assert(pool._queue);
    assert((error.domain == OUTERSSH_ERROR_NONE) == (stage == 1 || stage == 2));
    switch (stage) {
    case 0:
        assert(error.code == OUTERSSH_SESSION_ERROR_UNAVAILABLE);
        assert(error.system_error_code == EHOSTUNREACH);
        assert(strcmp(error.message, "Test TCP resolution failure.") == 0);
        break;
    case SESSION_CREATE_FAILURE:
        assert(error.code == OUTERSSH_SESSION_ERROR_SOCKET_CONFIGURATION_FAILED);
        assert(error.ssh_error_code == EMFILE);
        assert(strcmp(error.ssh_error_message, strerror(EMFILE)) == 0);
        break;
    case HANDSHAKE_FAILURE:
        assert(error.code == OUTERSSH_SESSION_ERROR_HANDSHAKE_FAILED);
        assert(error.ssh_error_code == LIBSSH2_ERROR_PROTO);
        break;
    case AUTHENTICATION_FAILURE:
    case LATE_AUTHENTICATION_FAILURE:
        assert(error.code == OUTERSSH_SESSION_ERROR_AUTHENTICATION_FAILED);
        assert(error.ssh_error_code == LIBSSH2_ERROR_AUTHENTICATION_FAILED);
        assert(strcmp(error.ssh_error_message, "rejected") == 0);
        assert(strcmp(error.message, "Authentication test failure.") == 0);
        break;
    case REACTOR_ALLOCATION_FAILURE:
        assert(error.code == OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED);
        break;
    case OPERATION_ALLOCATION_FAILURE:
    case SESSION_SLOT_ALLOCATION_FAILURE:
        assert(error.code == OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED);
        break;
    case CANCEL_DURING_AUTHENTICATION:
    case CANCEL_AFTER_AUTHENTICATION:
        assert(error.code == OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING);
        break;
    default:
        break;
    }
    assert(!outersshpriv_is_waiting(&pool._sessionWaiters));
    completions++;
    advance_if_finished();
}

static void advance_stage(void *context)
{
    (void)context;
    if (peer_socket >= 0) {
        char byte;
        assert(otsocket_read(peer_socket, &byte, 1) == 0);
        otsocket_close(peer_socket);
        peer_socket = -1;
    }
    stage++;
    run_stage(NULL);
}

static void advance_if_finished(void)
{
    if (!advancement_scheduled && completions == (stage == 2 ? 1u : 2u) &&
        pool._sessionCreation == NULL && pool.pending_operations == 0) {
        advancement_scheduled = true;
        otqueue_async(pool._queue, NULL, advance_stage);
    }
}

static void finish_destroyed_pool_poke(void *context)
{
    (void)context;
    assert(keepalives == 1 && connections == STAGE_COUNT - 2);
    ssh_test_semaphore_signal(finished);
}

static void finish_poke_test(void *context)
{
    (void)context;
    assert(keepalives == 1 && connections == STAGE_COUNT - 2);
    unsigned work_indices[] = {0, 1, 2, 3};
    SSHCompletionHandler resumes[] = {even_work_finished, odd_work_finished, even_work_finished, odd_work_finished};
    SSHWaiter waiters[4];
    available = true;
    selections = 0;
    for (size_t index = 0; index < 4; index++) {
        outersshpriv_session_pool_run_when_ready(&pool, &waiters[index], resumes[index], &work_indices[index]);
    }
    /* Each finds a session ready, then selects it when it resumes. */
    assert(continuations == 4 && selections == 8);
    for (unsigned scenario = 0; scenario < 3; scenario++) {
        available = true;
        pool._disconnecting = false;
        expected_work_error = 0;
        invalidate_after_continuation = scenario == 1;
        disconnect_after_continuation = scenario == 2;
        selections = continuations = 0;
        for (size_t index = 0; index < 4; index++) {
            outersshpriv_wait(&pool._sessionWaiters, &waiters[index], resumes[index], &work_indices[index]);
        }
        outersshpriv_session_pool_wake_session_waiters(&pool, (OuterSSHError){0});
        assert(continuations == 4 && selections == (scenario == 2 ? 1u : 4u));
    }
    outerssh_session_pool_poke(&pool);
    pool._disconnected = true;
    slot.reactor = NULL;
    otqueue_async(pool._queue, NULL, finish_destroyed_pool_poke);
}

static void after_keepalive(void *context)
{
    otqueue_async(pool._queue, context, finish_poke_test);
}

static void check_active_poke(void *context)
{
    otqueue_async(reactor_queue, context, after_keepalive);
}

static void check_idle_poke(void *context)
{
    (void)context;
    assert(keepalives == 0 && connections == STAGE_COUNT - 2);
    slot.reactor = (SSHReactor *)&slot;
    pool._sessions.slots = &slot;
    pool._sessions.count = 1;
    outerssh_session_pool_poke(&pool);
    otqueue_async(pool._queue, NULL, check_active_poke);
}

static void run_stage(void *context)
{
    (void)context;
    assert(pool.pending_operations == 0);
    assert(pool._sessionCreation == NULL && !outersshpriv_is_waiting(&pool._sessionWaiters));
    assert(pool._connectHandle.generation == 0);
    pool._disconnecting = false;
    completions = 0;
    advancement_scheduled = false;
    fail_operation_allocation = stage == OPERATION_ALLOCATION_FAILURE;
    if (stage == STAGE_COUNT) {
        assert(authentications == 7 && destroyed_reactors == 7 && freed_sessions == 8);
        outerssh_session_pool_poke(&pool);
        otqueue_async(pool._queue, NULL, check_idle_poke);
        return;
    }
    available = stage == 2;
    entering_api = true;
    assert(outerssh_session_pool_ensure_session(&pool, (uint64_t)(uintptr_t)&controller));
    if (stage != 2) {
        assert(outerssh_session_pool_ensure_session(&pool, (uint64_t)(uintptr_t)&controller));
    }
    assert(completions == 0);
    entering_api = false;
}

int main(void)
{
    pool.pending_operations = 0;
    pool._queue = ssh_test_control_queue_create("session-flow-test");
    otqueue_set_specific(pool._queue, &pool, &pool);
    pool._hostname = "test-host"; pool._hostnameLength = 9;
    pool._username = "user"; pool._usernameLength = 4;
    pool._port = 22;
    pool._authentication = (OuterSSHSessionAuthentication){
        .password = "password", .password_length = 8,
        .passphrase = "passphrase", .passphrase_length = 10,
        .public_key = "public",
        .public_key_length = 6,
        .private_key = "private",
        .private_key_length = 7
    };
    pool._sshAgentSocketPath = "/tmp/test-agent"; pool._sshAgentSocketPathLength = 15;
    pool_action_finished = ssh_test_semaphore_create(0);
    reactor_queue = ssh_test_control_queue_create("auth-flow-test");
    finished = ssh_test_semaphore_create(0);
    otqueue_async(pool._queue, NULL, run_stage);
    assert(ssh_test_semaphore_wait(finished,
        10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(pool_action_finished);
    ssh_test_semaphore_destroy(finished);
    otqueue_release(reactor_queue);
    otqueue_release(pool._queue);
    puts("PASS: session acquisition, borrowed credentials, authentication cancellation, failure cleanup, and gentle pokes");
    return 0;
}
