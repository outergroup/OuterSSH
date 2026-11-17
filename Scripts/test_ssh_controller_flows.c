#include "SSHTestFakeEventQueue.h"
#include "platform/OTSocket.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool fail_command_operation_allocation;
static unsigned fail_command_allocation_number;
static void *command_test_calloc(size_t count, size_t size)
{
    return fail_command_operation_allocation ? NULL : calloc(count, size);
}
static void *command_test_malloc(size_t size)
{
    if (fail_command_allocation_number != 0 && --fail_command_allocation_number == 0) {
        return NULL;
    }
    return malloc(size);
}
#define calloc command_test_calloc
#define malloc command_test_malloc
#include "SSHCommandFlows.c"
#undef malloc
#undef calloc
#include <errno.h>

static otsocket_t listener_test_socket(int domain, int type, int protocol);
static int listener_test_bind(otsocket_t socket, const struct sockaddr *address, socklen_t length);
static int listener_test_listen(otsocket_t socket, int backlog);
#define otsocket_create(...) listener_test_socket(__VA_ARGS__)
#define otsocket_bind listener_test_bind
#define otsocket_listen listener_test_listen
#include "ProxyReactor.c"
#undef otsocket_create
#undef otsocket_bind
#undef otsocket_listen
#include "SSHSessionPool.c"

void outersshpriv_forwarder_destroy(SSHForwarder *forwarder, SSHDestroyHandler completion, void *context)
{
    (void)forwarder; (void)completion; (void)context; abort();
}
void outersshpriv_proxy_ensure_user_bridge_executable(OuterSSHSessionPool *pool,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    (void)pool; (void)waiter; (void)resume; (void)context; abort();
}
bool outersshpriv_proxy_bridge_installs_busy(const OuterSSHSessionPool *pool)
{
    return pool->_userBridgeInstall != SSH_BRIDGE_INSTALL_IDLE;
}
void outersshpriv_proxy_advance_bridge_installs(OuterSSHSessionPool *pool)
{
    outersshpriv_proxy_continue_disconnect_if_requested(pool);
}

static OuterSSHSessionPool test_pool;
static SSHSessionSlot session_slot;
static size_t available_session_indices[1];
static otqueue_t reactor_queue;
static ssh_test_semaphore_t finished;
static unsigned test_index;
static unsigned attempts;
static unsigned removed_sessions;
static ExecuteCommandContext *first_operation;
static const void *first_input;
static bool entering_public_api;
static bool internal_completed;
static bool testing_owned_input;
static bool defer_session_request;
static bool testing_windows_hold;
static ExecuteCommandContext *held_starts[8];
static size_t held_start_count;
static unsigned held_completions;
typedef struct {
    char bytes[4];
    unsigned releases;
} TestInput;
static TestInput owned_input;
static char owned_command[sizeof("test command") - 1];
static unsigned command_releases;

static void release_test_command(void *context)
{
    otqueue_assert(test_pool._queue);
    assert(context == owned_command);
    assert(++command_releases == 1);
    memset(owned_command, 0, sizeof(owned_command));
}

static void release_test_input(void *context)
{
    TestInput *input = context;
    otqueue_assert(test_pool._queue);
    assert(++input->releases == 1);
    memset(input->bytes, 0, sizeof(input->bytes));
}

static void resume_command_session(void *context)
{
    outersshpriv_session_pool_run_when_ready(&test_pool, &((ExecuteCommandContext *)context)->waiter,
        ssh_command_session_request_finished, context);
}
static unsigned cleanups;
static unsigned cancelled_connections;
static unsigned cancelled_authentications;
static bool fail_listener_creation;
static otsocket_t listener_peers[8];
static size_t listener_peer_count;
static bool defer_cleanup;
static bool cleanup_pending;
static SSHDestroyHandler pending_cleanup_completion;
static void *pending_cleanup_context;

static void next_command_test(void *context);
static void next_lifecycle_test(void *context);
static void start_destruction_test(void *context);
static void continue_destruction_test(void *context);
static void verify_destruction_test(void *context);

static void advance_command_test(void *context)
{
    otqueue_async(test_pool._queue, context, next_command_test);
}

static SSHSessionPoolSessionHandle ready_session;
static SSHReactor *ready_reactor;

SSHReactor *outersshpriv_session_pool_ready_reactor(OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle *session, OuterSSHError *error)
{
    assert(pool == &test_pool);
    *session = error->domain == OUTERSSH_ERROR_NONE ? ready_session : (SSHSessionPoolSessionHandle){0};
    return error->domain == OUTERSSH_ERROR_NONE ? ready_reactor : NULL;
}

void outersshpriv_session_pool_run_when_ready(
    OuterSSHSessionPool *pool, SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    otqueue_assert(pool->_queue);
    assert(resume == ssh_command_session_request_finished);
    assert(waiter == &((ExecuteCommandContext *)context)->waiter);
    if (testing_windows_hold) {
        ready_session = (SSHSessionPoolSessionHandle){.generation = 1};
        ready_reactor = (SSHReactor *)&test_pool;
        resume(context, (OuterSSHError){0});
        return;
    }
    if (testing_owned_input || test_index == 5) {
        assert(command_releases == 0 && owned_input.releases == 0);
        assert(((ExecuteCommandContext *)context)->request.command == owned_command);
        assert(((ExecuteCommandContext *)context)->request.standard_input == owned_input.bytes);
    }
    if (defer_session_request) {
        defer_session_request = false;
        otqueue_async(pool->_queue, context, resume_command_session);
        return;
    }
    removed_sessions = (unsigned)pool->_sessions.available_index_count;
    ExecuteCommandContext *operation = context;
    assert(operation->request.command_byte_count == sizeof("test command") - 1);
    assert(memcmp(operation->request.command, "test command", operation->request.command_byte_count) == 0);
    assert(operation->request.standard_input_byte_count == 4);
    assert(memcmp(operation->request.standard_input, "data", 4) == 0);
    if (first_operation == NULL) {
        first_operation = operation;
        first_input = operation->request.standard_input;
    } else {
        assert(first_operation == operation);
        assert(first_input == operation->request.standard_input);
    }
    OuterSSHError error = {0};
    if (test_index == 3 || (test_index == 6 && removed_sessions != 0)) {
        error.domain = OUTERSSH_ERROR_SESSION;
        error.code = OUTERSSH_SESSION_ERROR_UNAVAILABLE;
    }
    SSHSessionPoolSessionHandle session = {0};
    SSHReactor *reactor = NULL;
    if (error.domain == OUTERSSH_ERROR_NONE) {
        session = (SSHSessionPoolSessionHandle){.generation = 1};
        session_slot.generation = 1;
        if (session_slot.reactor == NULL) pool->live_sessions++;
        session_slot.reactor = (SSHReactor *)&test_pool;
        reactor = test_index == 4 ? NULL : session_slot.reactor;
        if (reactor == NULL) {
            error.domain = OUTERSSH_ERROR_SESSION;
            error.code = OUTERSSH_SESSION_ERROR_UNAVAILABLE;
        }
    }
    ready_session = session;
    ready_reactor = reactor;
    resume(context, error);
}

otqueue_t outersshpriv_reactor_queue(SSHReactor *reactor)
{
    assert(reactor == (SSHReactor *)&test_pool);
    return reactor_queue;
}

void outersshpriv_reactor_execute_command(
    SSHReactor *reactor,
    const void *command, size_t command_count,
    const void *input_prefix, size_t input_prefix_count,
    const void *input, size_t input_count,
    uint64_t open_timeout, uint64_t execution_timeout,
    ExecuteCommandContext *operation)
{
    otqueue_assert(reactor_queue);
    assert(reactor == (SSHReactor *)&test_pool);
    if (testing_windows_hold) {
        assert(held_start_count < sizeof(held_starts) / sizeof(held_starts[0]));
        held_starts[held_start_count++] = operation;
        return;
    }
    assert(command_count == strlen("test command"));
    assert(memcmp(command, "test command", command_count) == 0);
    assert(input_prefix == NULL && input_prefix_count == 0);
    assert(input_count == 4 && input == first_input);
    assert(memcmp(input, "data", 4) == 0);
    if (testing_owned_input || test_index == 5) {
        assert(command == owned_command && command_releases == 0);
        assert(owned_input.releases == 0);
    }
    assert(open_timeout == 5000 && execution_timeout == 300000);
    attempts++;
    SSHReactorCommandResult result = SSH_REACTOR_COMMAND_COMPLETED;
    if ((test_index == 1 && attempts == 1) || test_index == 2 || test_index == 6) {
        result = SSH_REACTOR_COMMAND_CHANNEL_OPEN_SESSION_CLOSED;
    } else if (test_index == 7) {
        result = SSH_REACTOR_COMMAND_REQUEST_FAILED;
    }
    char *output = strdup("output");
    char *errors = strdup("stderr");
    assert(output != NULL && errors != NULL);
    outersshpriv_session_pool_command_completed(
        operation, result, output, 6, errors, 6, 17, 0, 0);
    return;
}



bool outersshpriv_reactor_is_current_queue(SSHReactor *reactor)
{
    assert(reactor == (SSHReactor *)&test_pool);
    otqueue_assert(reactor_queue);
    return true;
}

OuterSSHSessionPool *outersshpriv_detach_reactor_from_session_pool(SSHReactor *reactor)
{
    assert(reactor == (SSHReactor *)&test_pool);
    return &test_pool;
}

int outersshpriv_reactor_teardown(SSHReactor *reactor, size_t *created, size_t *freed)
{
    assert(reactor == (SSHReactor *)&test_pool);
    *created = 1;
    *freed = 1;
    return 0;
}

void outersshpriv_reactor_destroy(SSHReactor *reactor, void (*completion)(void *), void *context)
{
    assert(reactor == (SSHReactor *)&test_pool);
    if (completion != NULL) otqueue_async(reactor_queue, context, completion);
}

static void command_completed(
    void *context, const SSHCommandOutput *result, OuterSSHError error)
{
    assert(context == &test_pool);
    otqueue_assert(test_pool._queue);
    assert(!entering_public_api);
    if (testing_owned_input || test_index == 5) {
        assert(command_releases == 1 && owned_input.releases == 1);
    }
    if (test_index == 7) assert(strstr(error.message, "test command") != NULL);
    bool succeeds = test_index == 0 || test_index == 1 || test_index == 5;
    assert((error.domain == OUTERSSH_ERROR_NONE) == succeeds);
    if (succeeds) {
        assert(result != NULL && result->exit_status == 17);
        assert(result->stdout_byte_count == 6 && result->stderr_byte_count == 6);
        assert(memcmp(result->stdout_bytes, "output", 6) == 0);
        assert(memcmp(result->stderr_bytes, "stderr", 6) == 0);
    } else {
        assert(result == NULL);
    }
    assert(removed_sessions ==
           (unsigned)(test_index == 1 || test_index == 2 || test_index == 6));
    unsigned expected_attempts = test_index == 3 || test_index == 4 ? 0 :
        test_index == 1 || test_index == 2 ? 2 : 1;
    assert(attempts == expected_attempts);
    test_index++;
    otqueue_async(reactor_queue, NULL, advance_command_test);
}

static void internal_command_completed(
    void *context, const SSHCommandOutput *result, OuterSSHError error)
{
    internal_completed = true;
    command_completed(context, result, error);
}

typedef struct {
    unsigned completions;
    unsigned expected_releases;
} CommandRejection;

static void rejected_command_completed(
    void *context, const SSHCommandOutput *result, OuterSSHError error)
{
    CommandRejection *test = context;
    assert(++test->completions == 1);
    assert(result == NULL && error.domain != OUTERSSH_ERROR_NONE);
    assert(owned_input.releases == test->expected_releases);
    assert(command_releases == test->expected_releases);
}

static void held_command_completed(void *context, const SSHCommandOutput *result, OuterSSHError error)
{
    assert(context == &test_pool);
    otqueue_assert(test_pool._queue);
    assert(error.domain == OUTERSSH_ERROR_NONE && result != NULL);
    held_completions++;
}

static void execute_held_command(void *context)
{
    static const char command[] = "test command";
    bool with_input = context != NULL;
    outersshpriv_execute_command(&test_pool, (SSHCommandRequest){
        .command = command,
        .command_byte_count = sizeof(command) - 1,
        .standard_input = with_input ? "data" : NULL,
        .standard_input_byte_count = with_input ? 4 : 0,
    }, held_command_completed, &test_pool);
}

static void complete_held_command(void *context)
{
    char *output = strdup("output");
    assert(output != NULL);
    outersshpriv_session_pool_command_completed(context, SSH_REACTOR_COMMAND_COMPLETED,
        output, 6, NULL, 0, 0, 0, 0);
}

static void drain_nothing(void *context)
{
    (void)context;
}

static void settle_held_commands(void)
{
    for (unsigned round = 0; round < 3; round++) {
        ssh_test_sync(test_pool._queue, NULL, drain_nothing);
        ssh_test_sync(reactor_queue, NULL, drain_nothing);
    }
}

static void finish_held_command(size_t index)
{
    ssh_test_sync(reactor_queue, held_starts[index], complete_held_command);
    settle_held_commands();
}

static void test_windows_input_hold(void)
{
    static int with_input;
    testing_windows_hold = true;
    atomic_store(&test_pool._commandDialect, OUTERSSH_COMMAND_DIALECT_WINDOWS);
    ssh_test_sync(test_pool._queue, &with_input, execute_held_command);
    ssh_test_sync(test_pool._queue, NULL, execute_held_command);
    ssh_test_sync(test_pool._queue, &with_input, execute_held_command);
    settle_held_commands();
    assert(held_start_count == 1 && held_starts[0]->request.standard_input_byte_count == 4);
    finish_held_command(0);
    assert(held_completions == 1 && held_start_count == 2);
    assert(held_starts[1]->request.standard_input_byte_count == 0);
    ssh_test_sync(test_pool._queue, NULL, execute_held_command);
    settle_held_commands();
    assert(held_start_count == 2);
    finish_held_command(1);
    assert(held_completions == 2 && held_start_count == 3);
    assert(held_starts[2]->request.standard_input_byte_count == 4);
    finish_held_command(2);
    assert(held_completions == 3 && held_start_count == 4);
    assert(held_starts[3]->request.standard_input_byte_count == 0);
    finish_held_command(3);
    assert(held_completions == 4 && test_pool._windowsInputCommand == NULL && test_pool._heldCommands == NULL);
    assert(test_pool._windowsRunningCommands == 0);
    atomic_store(&test_pool._commandDialect, OUTERSSH_COMMAND_DIALECT_UNKNOWN);
    ssh_test_sync(test_pool._queue, &with_input, execute_held_command);
    ssh_test_sync(test_pool._queue, &with_input, execute_held_command);
    settle_held_commands();
    assert(held_start_count == 6);
    finish_held_command(4);
    finish_held_command(5);
    assert(held_completions == 6 && test_pool.pending_operations == 0);
    testing_windows_hold = false;
}

static void test_immediate_command_failures(void)
{
    for (unsigned scenario = 0; scenario < 6; scenario++) {
        CommandRejection test = {.expected_releases = scenario != 5};
        owned_input = (TestInput){.bytes = {'d', 'a', 't', 'a'}};
        memcpy(owned_command, "test command", sizeof(owned_command));
        command_releases = 0;
        fail_command_operation_allocation = scenario == 3 || scenario == 4;
        fail_command_allocation_number = 0;
        outersshpriv_execute_command(&test_pool, (SSHCommandRequest){
            .command = scenario == 0 || scenario == 5 ? NULL : owned_command,
            .command_byte_count = scenario == 1 ? (size_t)INT_MAX + 1 : sizeof(owned_command),
            .release_command = scenario == 5 ? NULL : release_test_command,
            .release_command_context = scenario == 5 ? NULL : owned_command,
            .standard_input = scenario == 2 || scenario == 4 ? NULL : owned_input.bytes,
            .standard_input_byte_count = scenario == 4 ? 0 : sizeof(owned_input.bytes),
            .release_input = scenario == 5 ? NULL : release_test_input,
            .release_input_context = scenario == 5 ? NULL : &owned_input,
        }, rejected_command_completed, &test);
        assert(test.completions == 1);
        assert(test_pool.pending_operations == 0);
    }
    for (unsigned scenario = 0; scenario < 3; scenario++) {
        CommandRejection test = {0};
        owned_input = (TestInput){.bytes = {'d', 'a', 't', 'a'}};
        memcpy(owned_command, "test command", sizeof(owned_command));
        command_releases = 0;
        fail_command_operation_allocation = false;
        fail_command_allocation_number = scenario == 0 ? 1 : 0;
        assert(!outerssh_session_pool_execute_command(
            &test_pool, scenario == 1 ? NULL : "test command", sizeof("test command") - 1,
            owned_input.bytes, scenario == 2 ? SIZE_MAX : sizeof(owned_input.bytes), 1));
        assert(test.completions == 0);
        assert(memcmp(owned_input.bytes, "data", sizeof(owned_input.bytes)) == 0);
        assert(test_pool.pending_operations == 0);
    }
    fail_command_operation_allocation = false;
    fail_command_allocation_number = 0;
}

static void next_command_test(void *context)
{
    (void)context;
    assert(test_pool.pending_operations == 0);
    if (test_index == 8) {
        assert(internal_completed);
        if (!testing_owned_input) {
            testing_owned_input = true;
            test_index = 0;
            next_command_test(NULL);
            return;
        }
        test_immediate_command_failures();
        test_pool._sessions.count = 0;
        test_index = 0;
        next_lifecycle_test(NULL);
        return;
    }
    attempts = 0;
    removed_sessions = 0;
    test_pool._sessions.available_index_count = 0;
    first_operation = NULL;
    first_input = NULL;
    char command[sizeof("test command") - 1];
    memcpy(command, "test command", sizeof(command));
    char input[] = "data";
    if (testing_owned_input || test_index == 5) {
        owned_input = (TestInput){.bytes = {'d', 'a', 't', 'a'}};
        memcpy(owned_command, command, sizeof(owned_command));
        command_releases = 0;
        defer_session_request = testing_owned_input;
        outersshpriv_execute_command(&test_pool, (SSHCommandRequest){
            .command = owned_command,
            .command_byte_count = sizeof(owned_command),
            .release_command = release_test_command,
            .release_command_context = owned_command,
            .standard_input = owned_input.bytes,
            .standard_input_byte_count = sizeof(owned_input.bytes),
            .release_input = release_test_input,
            .release_input_context = &owned_input,
        }, internal_command_completed, &test_pool);
        if (testing_owned_input) {
            assert(first_operation == NULL && command_releases == 0 && owned_input.releases == 0);
        } else {
            assert(first_operation != NULL);
        }
    } else {
        entering_public_api = true;
        assert(outerssh_session_pool_execute_command(&test_pool, command, sizeof(command), input, 4, 1));
        assert(first_operation == NULL);
        entering_public_api = false;
    }
    memset(command, 0, sizeof(command));
    memset(input, 0, sizeof(input));
}

static otsocket_t listener_test_socket(int domain, int type, int protocol)
{
    assert(domain == AF_INET && type == SOCK_STREAM && protocol == 0);
    otsocket_t pair[2];
    assert(ssh_test_socket_pair(pair) == 0);
    assert(listener_peer_count < sizeof(listener_peers) / sizeof(*listener_peers));
    listener_peers[listener_peer_count++] = pair[1];
    return pair[0];
}

static int listener_test_bind(otsocket_t socket, const struct sockaddr *address, socklen_t length)
{
    (void)socket;
    assert(address->sa_family == AF_INET && length == sizeof(struct sockaddr_in));
    otqueue_assert(test_pool._queue);
    if (fail_listener_creation) {
        errno = EADDRINUSE;
        return -1;
    }
    return 0;
}

static int listener_test_listen(otsocket_t socket, int backlog)
{
    (void)socket;
    assert(backlog == 128);
    return 0;
}

void outersshpriv_proxy_reactor_accept_connections(ProxyReactor *reactor, ProxyReactorListenerHandle handle)
{
    (void)reactor; (void)handle;
    assert(false);
}

void outersshpriv_proxy_reactor_cancel_pending_connections_for_listener(
    ProxyReactor *reactor, ProxyReactorListenerHandle handle)
{
    assert(reactor == test_pool._connectorReactor && handle.generation != 0);
    assert(outersshpriv_proxy_reactor_listener_for_handle(reactor, handle) == NULL);
}

void outersshpriv_proxy_reactor_cancel_all_pending_connections(ProxyReactor *reactor)
{
    assert(reactor == test_pool._connectorReactor);
}

void outersshpriv_proxy_reactor_cancel_all_tcp_connects(ProxyReactor *reactor)
{
    assert(reactor == test_pool._connectorReactor);
}

void outersshpriv_proxy_stop_bridge(
    OuterSSHSessionPool *controller, SSHProxyBridgeHandle bridge)
{
    (void)controller;
    (void)bridge;

    assert(false);
}

void outersshpriv_reactor_close_proxy_connections(SSHReactor *reactor, uint64_t proxy_generation)
{
    assert(reactor == (SSHReactor *)&test_pool && proxy_generation != 0);
}

void outersshpriv_proxy_cleanup_bridge_executables(
    OuterSSHSessionPool *controller, SSHDestroyHandler completion,
    void *context)
{
    otqueue_assert(controller->_queue);
    cleanups++;
    if (defer_cleanup) {
        assert(completion == disconnect_after_bridge_cleanup && context == controller);
        assert(!cleanup_pending);
        cleanup_pending = true;
        pending_cleanup_completion = completion;
        pending_cleanup_context = context;
        return;
    }
    assert(completion != NULL);
    completion(context);
}

bool outersshpriv_proxy_reactor_cancel_tcp_connect(
    ProxyReactor *reactor, ProxyReactorTCPConnectHandle handle)
{
    assert(reactor == test_pool._connectorReactor);
    assert(handle.generation == 19 && test_pool._disconnecting);
    cancelled_connections++;
    return true;
}

bool outersshpriv_cancel_session_startup(SSHSessionCreationOperation *creation)
{
    assert(creation == (SSHSessionCreationOperation *)&session_slot);
    assert(test_pool._disconnecting);
    cancelled_authentications++;
    return true;
}

void outersshpriv_session_pool_wake_session_waiters(OuterSSHSessionPool *pool, OuterSSHError error)
{
    assert(pool == &test_pool);
    assert(!outersshpriv_is_waiting(&pool->_sessionWaiters));
    assert(error.code == OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING);
}

static void next_lifecycle_test(void *context)
{
    (void)context;
    for (unsigned scenario = 0; scenario < 3; scenario++) {
        assert(test_pool.pending_operations == 0);
        test_pool.shutdown_requested = test_pool._disconnecting = test_pool._disconnected = false;
        test_pool._disconnectFinalizationStarted = false;
        test_pool._userBridgeInstall = scenario == 1 ? SSH_BRIDGE_INSTALL_INSTALLING : SSH_BRIDGE_INSTALL_IDLE;
        test_pool._connectHandle = (ProxyReactorTCPConnectHandle){.generation = 19};
        test_pool._sessionCreation = (SSHSessionCreationOperation *)&session_slot;
        cleanups = cancelled_connections = cancelled_authentications = 0;
        defer_cleanup = scenario != 0;
        outersshpriv_disconnect_session_pool(&test_pool);
        outersshpriv_disconnect_session_pool(&test_pool);
        assert(test_pool.shutdown_requested);
        if (scenario == 1) {
            assert(cleanups == 0 && !test_pool._disconnected);
            test_pool._userBridgeInstall = SSH_BRIDGE_INSTALL_IDLE;
            outersshpriv_proxy_continue_disconnect_if_requested(&test_pool);
        }
        if (defer_cleanup) {
            assert(cleanup_pending && cleanups == 1 && !test_pool._disconnected);
            assert(test_pool.pending_operations == 0);
            cleanup_pending = false;
            pending_cleanup_completion(pending_cleanup_context);
            pending_cleanup_completion = NULL;
            pending_cleanup_context = NULL;
        }
        assert(test_pool.pending_operations == 0 && test_pool._disconnected);
        assert(cleanups == 1 && cancelled_connections == 1 && cancelled_authentications == 1);
        outersshpriv_disconnect_session_pool(&test_pool);
        assert(cleanups == 1);
    }
    ssh_test_semaphore_signal(finished);
}

static OuterSSHEventQueue test_event_queue;

/* Delivers public command replies to command_completed on the control queue. */
static void drain_test_event_queue(void *context)
{
    (void)context;
    OuterSSHEvent event;
    while (outerssh_event_queue_poll(&test_event_queue, &event, 1) == 1) {
        assert(event.type == OUTERSSH_EVENT_COMMAND_COMPLETED && event.tag == 1 && event.pool == &test_pool);
        SSHCommandOutput output = {
            .stdout_bytes = event.command_completed.standard_output,
            .stdout_byte_count = event.command_completed.standard_output_length,
            .stderr_bytes = event.command_completed.standard_error,
            .stderr_byte_count = event.command_completed.standard_error_length,
            .exit_status = event.command_completed.exit_status,
        };
        bool succeeded = event.command_completed.error.domain == OUTERSSH_ERROR_NONE;
        command_completed(&test_pool, succeeded ? &output : NULL, event.command_completed.error);
    }
}

int main(void)
{
    test_pool.pending_operations = 0;
    test_pool._queue = ssh_test_control_queue_create("controller-test");
    test_pool._event_queue = &test_event_queue;
    ssh_test_event_queue_observe(&test_event_queue, test_pool._queue, drain_test_event_queue, NULL);
    test_pool._sessions.slots = &session_slot;
    test_pool._sessions.count = 1;
    test_pool._sessions.available_indices = available_session_indices;
    test_pool._connectorReactor = outersshpriv_proxy_reactor_create(test_pool._queue);
    reactor_queue = ssh_test_control_queue_create("reactor-test");
    finished = ssh_test_semaphore_create(0);
    test_windows_input_hold();
    otqueue_async(test_pool._queue, NULL, next_command_test);
    assert(ssh_test_semaphore_wait(finished,
        10 * NSEC_PER_SEC) == 0);
    outersshpriv_proxy_reactor_destroy(test_pool._connectorReactor, NULL, NULL);
    ssh_test_sync(test_pool._queue, NULL, drain_test_event_queue);
    for (size_t index = 0; index < listener_peer_count; index++) {
        otsocket_close(listener_peers[index]);
    }
    ssh_test_semaphore_destroy(finished);
    otqueue_release(reactor_queue);
    otqueue_release(test_pool._queue);
    puts("PASS: command ownership, Windows input holds, retries, explicit queue hops, pool bridge cleanup, and shutdown");
    return 0;
}

void outersshpriv_socket_service_stop(OuterSSHSessionPool *pool)
{
    assert(pool->socket_service == NULL);
}

void outersshpriv_socket_service_dispose(OuterSSHSessionPool *pool)
{
    assert(pool->socket_service == NULL);
}
