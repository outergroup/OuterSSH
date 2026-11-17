#include "SSHTestSupport.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static unsigned fail_path_allocation_number;
static bool testing_assignment_failure;
static unsigned assignment_failures;
static bool counting_connection_failures;
static unsigned connection_failures;
static void *bridge_test_malloc(size_t size)
{
    if (fail_path_allocation_number != 0 && --fail_path_allocation_number == 0) {
        return NULL;
    }
    return malloc(size);
}

static bool fail_bridge_context_allocation;
static bool forbid_bridge_allocations;
static unsigned bridge_allocations;
static void *bridge_test_calloc(size_t count, size_t size);

#define calloc bridge_test_calloc
#define malloc bridge_test_malloc
#include "SSHSocketBridgeFlows.c"
#undef malloc
#undef calloc

static void *bridge_test_calloc(size_t count, size_t size)
{
    assert(!forbid_bridge_allocations);
    bridge_allocations++;
    if (fail_bridge_context_allocation && size == sizeof(SSHSocketBridgeContext)) {
        return NULL;
    }
    return calloc(count, size);
}

typedef struct {
    SSHSocketBridgeOperation operation;
    SSHSocketBridgeWaiter waiter;
} TestBridgePreparation;

#include "SocketBridgeCommands.h"

static bool fail_installation_allocation;
static bool fail_user_command_allocation;
static bool fail_second_command_allocation;
static bool fail_user_install_command;
static unsigned command_allocations;
static void *command_test_calloc(size_t count, size_t size);
static char *installation_test_sudo_command(
    const char *install_id, size_t install_id_length, bool requires_password,
    size_t *command_length);

static char *installation_test_install_command(const char *install_id, size_t install_id_length, size_t *command_length)
{
    return fail_user_install_command ? NULL : outersshpriv_socket_bridge_install_user_command(install_id, install_id_length, command_length);
}
static void *installation_test_calloc(size_t count, size_t size)
{
    if (fail_installation_allocation) return NULL;
    return calloc(count, size);
}

static bool fail_installation_malloc;
static void *installation_test_malloc(size_t size)
{
    if (fail_installation_malloc) return NULL;
    return malloc(size);
}

#define malloc installation_test_malloc
#define calloc installation_test_calloc
#define outersshpriv_socket_bridge_install_user_command installation_test_install_command
#define outersshpriv_socket_bridge_install_command installation_test_sudo_command
#include "SSHBridgeInstallationFlows.c"
#undef outersshpriv_socket_bridge_install_command
#undef outersshpriv_socket_bridge_install_user_command
#undef calloc
#undef malloc

#if defined(_WIN32)
static BOOL installation_test_unmap(const void *address);
#define UnmapViewOfFile installation_test_unmap
#include "SSHBridgeBinary.c"
#undef UnmapViewOfFile
#else
#include <sys/mman.h>
static int installation_test_munmap(void *address, size_t length);
#define munmap installation_test_munmap
#include "SSHBridgeBinary.c"
#undef munmap
#endif

#define calloc command_test_calloc
#include "SSHCommandFlows.c"
#undef calloc

static void *command_test_calloc(size_t count, size_t size)
{
    assert(size == sizeof(ExecuteCommandContext));
    if (fail_user_command_allocation || fail_installation_allocation ||
        (fail_second_command_allocation && command_allocations == 1)) return NULL;
    void *operation = calloc(count, size);
    if (operation != NULL) command_allocations++;
    return operation;
}

static OuterSSHSessionPool test_pool;
static SSHForwarder test_server;
static SSHProxyConnection test_connection;
static OuterSSHSessionPool *test_listener;
static otqueue_t reactor_queue;
static ssh_test_semaphore_t finished;
static SSHSocketBridgeContext *live_bridge;
static ConnectBridgeStreamContext *first_stream_context;
enum {
    ASYNC_BRIDGE_OPEN_FAILURE = 15,
    STREAM_START_FAILURE,
    STREAM_TIMEOUT,
    CONTEXT_ALLOCATION_FAILURE,
    READY_THEN_EVENTS,
    BRIDGE_REPLACEMENT_SUCCESS,
    MISSING_CACHED_BRIDGE,
    MISSING_CACHED_SUDO_BRIDGE,
    REINSTALLED_BRIDGE_FAILURE,
    FRESH_BRIDGE_FAILURE,
    CACHED_SUDO_PASSWORD_REQUIRED,
    USER_OPERATION_ALLOCATION_FAILURE,
    USER_LOADER_FAILURE,
    USER_INSTALL_COMMAND_FAILURE,
    USER_INSTALL_FAILURE,
    USER_INVALID_INSTALL_PATH,
    USER_INSTALL_SESSION_FAILURE,
    USER_INSTALL_ALLOCATION_FAILURE,
    STAGE_COUNT
};
static unsigned stage;
static unsigned expected_setup_completions(void)
{
    return stage == 0 || stage == 2 || stage == 4 ||
        stage == READY_THEN_EVENTS || stage == ASYNC_BRIDGE_OPEN_FAILURE ||
        stage == MISSING_CACHED_BRIDGE || stage == MISSING_CACHED_SUDO_BRIDGE ||
        stage == REINSTALLED_BRIDGE_FAILURE ? 2u : 1u;
}
static unsigned route_completions;
static SSHProxyBridgeHandle first_ready_handle;
static unsigned privilege_conflicts;
static unsigned starts;
static unsigned streams;
static unsigned cancellations;
typedef enum {
    TEST_COMMAND_BRIDGE_PLATFORM,
    TEST_COMMAND_USER_BRIDGE_INSTALL,
    TEST_COMMAND_SUDO_CREDENTIALS,
    TEST_COMMAND_SUDO_BRIDGE_INSTALL,
    TEST_COMMAND_CLEANUP
} TestCommandKind;

static TestCommandKind command_kind(ExecuteCommandContext *operation)
{
    if (operation->completion == unix_platform_received || operation->completion == remote_platform_received) return TEST_COMMAND_BRIDGE_PLATFORM;
    if (operation->completion == user_bridge_install_finished) return TEST_COMMAND_USER_BRIDGE_INSTALL;
    if (operation->completion == sudo_credentials_checked) return TEST_COMMAND_SUDO_CREDENTIALS;
    if (operation->completion == sudo_install_finished) return TEST_COMMAND_SUDO_BRIDGE_INSTALL;
    assert(operation->completion == cleanup_command_finished);
    return TEST_COMMAND_CLEANUP;
}

static unsigned commands[TEST_COMMAND_CLEANUP + 1];
static bool listener_active;
static unsigned cleanup_completions;
static unsigned cleanup_requests;
static ExecuteCommandContext *deferred_cleanup;
static bool testing_platform_cache;
static ExecuteCommandContext *deferred_platform;
static unsigned platform_requests;

static void run_stage(void *context);
static void verify_stage(void *context);
static void invalidate_listener(void *context);

static void return_to_controller(void *context)
{
    otqueue_async(test_pool._queue, context, verify_stage);
}

static void schedule_verification(void)
{
    otqueue_async(reactor_queue, NULL, return_to_controller);
}

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
}

void outersshpriv_session_pool_finish_destroy_if_ready(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
}


ProxySOCKSReplyStatus outersshpriv_proxy_reply_status_for_error(OuterSSHError error)
{
    (void)error;
    return PROXY_SOCKS_REPLY_GENERAL_FAILURE;
}

OuterSSHSessionPool *outersshpriv_session_pool_active(
    OuterSSHSessionPool *controller)
{
    assert(controller == &test_pool);
    return listener_active ? test_listener : NULL;
}

void outersshpriv_proxy_continue_disconnect_if_requested(OuterSSHSessionPool *controller)
{
    assert(controller == &test_pool);
}

SSHReactor *outersshpriv_session_pool_ready_reactor(OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle *session, OuterSSHError *error)
{
    assert(pool == &test_pool);
    *session = (SSHSessionPoolSessionHandle){.generation = error->domain == OUTERSSH_ERROR_NONE ? 1 : 0};
    return error->domain == OUTERSSH_ERROR_NONE ? (SSHReactor *)&test_pool : NULL;
}

void outersshpriv_session_pool_run_when_ready(OuterSSHSessionPool *pool, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context)
{
    otqueue_assert(pool->_queue);
    (void)waiter;
    if (testing_platform_cache) {
        assert(resume == ssh_command_session_request_finished);
        ExecuteCommandContext *operation = context;
        assert(operation->completion == unix_platform_received || operation->completion == remote_platform_received);
        assert(deferred_platform == NULL);
        deferred_platform = operation;
        platform_requests++;
        return;
    }
    if (resume == ssh_command_session_request_finished) {
        ExecuteCommandContext *operation = context;
        assert(operation->completed_stdout == NULL);
        assert(operation->completed_stderr == NULL);
        if (command_kind(operation) == TEST_COMMAND_CLEANUP &&
            stage == 10 && cleanup_requests++ == 0) {
            resume(context, outerssh_proxy_closing_error());
            return;
        }
        if (stage == USER_INSTALL_SESSION_FAILURE &&
            command_kind(operation) == TEST_COMMAND_USER_BRIDGE_INSTALL) {
            resume(context, outerssh_proxy_closing_error());
            return;
        }
        resume(context, (OuterSSHError){0});
        return;
    }
    assert(resume == ssh_bridge_session_request_finished);
    fail_bridge_context_allocation = stage == CONTEXT_ALLOCATION_FAILURE;
    resume(context, (OuterSSHError){0});
    fail_bridge_context_allocation = false;
}

SSHReactor *outersshpriv_session_pool_reactor_for_session(
    OuterSSHSessionPool *pool, SSHSessionPoolSessionHandle session)
{
    assert(pool == &test_pool && session.generation == 1);
    return (SSHReactor *)&test_pool;
}

otqueue_t outersshpriv_reactor_queue(SSHReactor *reactor)
{
    assert(reactor == (SSHReactor *)&test_pool);
    return reactor_queue;
}

void outersshpriv_remove_session(OuterSSHSessionPool *pool, SSHSessionPoolSessionHandle session)
{
    assert(pool == &test_pool && session.generation == 1 && stage == READY_THEN_EVENTS);
}

static const char packaged_binary_bytes[] = "BIN";
static unsigned binary_releases;
static unsigned expected_binary_releases;

static char *installation_test_sudo_command(
    const char *install_id, size_t install_id_length, bool requires_password,
    size_t *command_length)
{
    assert(binary_releases + 1 == expected_binary_releases);
    return outersshpriv_socket_bridge_install_command(
        install_id, install_id_length, requires_password, command_length);
}

#if defined(_WIN32)
static BOOL installation_test_unmap(const void *address)
{
    otqueue_assert(test_pool._queue);
    assert(address == packaged_binary_bytes);
    assert(++binary_releases <= expected_binary_releases);
    return TRUE;
}
#else
static int installation_test_munmap(void *address, size_t length)
{
    otqueue_assert(test_pool._queue);
    assert(address == packaged_binary_bytes && length == 3);
    assert(++binary_releases <= expected_binary_releases);
    return 0;
}
#endif

static unsigned binary_questions;
static bool decline_bridge_binaries;

void outersshpriv_session_pool_ask_bridge_binary(OuterSSHSessionPool *pool,
    const char *name, size_t name_length,
    SSHBridgeBinaryContinuation continuation, void *context)
{
    static const char test_error_text_1[] = "Test binary could not be loaded.";

    otqueue_assert(test_pool._queue);
    assert(pool == &test_pool);
    binary_questions++;
    if (decline_bridge_binaries || stage == USER_LOADER_FAILURE) {
        continuation(context, SSH_QUESTION_DECLINED, NULL, (OuterSSHError){
            .domain = OUTERSSH_ERROR_HELPER_INSTALLER,
            .code = OUTERSSH_HELPER_INSTALLER_ERROR_MISSING_PACKAGED_BINARY,
            .message = test_error_text_1, .message_length = sizeof(test_error_text_1) - 1
        });
        return;
    }
    const char expected[] = "linux-aarch64-glibc";
    assert(name_length == sizeof(expected) - 1);
    assert(memcmp(name, expected, name_length) == 0);
    SSHBridgeBinary *binary = calloc(1, sizeof(*binary));
    assert(binary != NULL);
    atomic_init(&binary->references, 1);
    binary->view = (void *)packaged_binary_bytes;
    binary->view_length = 3;
    binary->bytes = (const unsigned char *)packaged_binary_bytes;
    binary->length = 3;
    expected_binary_releases++;
    continuation(context, SSH_QUESTION_ACCEPTED, binary, (OuterSSHError){0});
}

static void complete_command(void *context)
{
    ExecuteCommandContext *command = context;
    SSHCommandOutput result = {0};
    OuterSSHError error = {0};
    const char *output = "";
    switch (command_kind(command)) {
    case TEST_COMMAND_BRIDGE_PLATFORM:
        output = "aarch64 glibc";
        if (stage == 0) {
            error = outerssh_proxy_closing_error();
        }
        break;
    case TEST_COMMAND_USER_BRIDGE_INSTALL:
        output = stage == USER_INVALID_INSTALL_PATH ? "invalid" :
            "OUTERSSH_HELPER_EXECUTABLE=/tmp/user-id/outerssh-helper\n";
        result.exit_status = stage == USER_INSTALL_FAILURE ? 1 : 0;
        break;
    case TEST_COMMAND_SUDO_BRIDGE_INSTALL:
        output = "OUTERSSH_HELPER_EXECUTABLE=/var/tmp/outerssh-helper/sudo-id/outerssh-helper\n";
        break;
    case TEST_COMMAND_SUDO_CREDENTIALS:
        result.exit_status = stage == 8 || stage == MISSING_CACHED_SUDO_BRIDGE ? 0 : 1;
        break;
    case TEST_COMMAND_CLEANUP:
        result.exit_status = 1;
        break;
    default:
        assert(false);
    }
    result.stdout_bytes = output;
    result.stdout_byte_count = strlen(output);
    char *bytes = strdup(output);
    assert(bytes != NULL);
    bool retry = stage == READY_THEN_EVENTS && commands[command_kind(command)] == 1 &&
        (command_kind(command) == TEST_COMMAND_BRIDGE_PLATFORM || command_kind(command) == TEST_COMMAND_USER_BRIDGE_INSTALL);
    outersshpriv_session_pool_command_completed(command,
        retry ? SSH_REACTOR_COMMAND_CHANNEL_OPEN_SESSION_CLOSED :
        error.domain == OUTERSSH_ERROR_NONE ? SSH_REACTOR_COMMAND_COMPLETED : SSH_REACTOR_COMMAND_SESSION_CLOSED,
        bytes, strlen(bytes), NULL, 0, result.exit_status, 0, 0);
}

void outersshpriv_reactor_execute_command(
    SSHReactor *reactor, const void *command, size_t command_count,
    const void *input_prefix, size_t input_prefix_count,
    const void *input, size_t input_count, uint64_t open_timeout,
    uint64_t execution_timeout, ExecuteCommandContext *operation)
{
    assert(reactor == (SSHReactor *)&test_pool);
    otqueue_assert(reactor_queue);
    assert(command != NULL && command_count > 0);
    assert(memchr(command, '\0', command_count) == NULL);
    TestCommandKind purpose = command_kind(operation);
    bool installs = purpose == TEST_COMMAND_USER_BRIDGE_INSTALL || purpose == TEST_COMMAND_SUDO_BRIDGE_INSTALL;
    assert(open_timeout == 5000 && execution_timeout == (installs ? 60000 : 300000));
    commands[purpose]++;
    if (purpose == TEST_COMMAND_CLEANUP && stage == 9) {
        if (deferred_cleanup == NULL) {
            deferred_cleanup = operation;
            return;
        }
        assert(commands[purpose] == 2);
        ExecuteCommandContext *first = deferred_cleanup;
        deferred_cleanup = NULL;
        complete_command(operation);
        complete_command(first);
        return;
    }
    if (purpose == TEST_COMMAND_USER_BRIDGE_INSTALL) {
        assert(input_prefix_count == 0);
        assert(input == packaged_binary_bytes);
        assert(binary_releases + 1 == expected_binary_releases);
        assert(input_count == 3 && memcmp(input, "BIN", 3) == 0);
    }
    if (purpose == TEST_COMMAND_SUDO_BRIDGE_INSTALL) {
        if (stage == 8 || stage == MISSING_CACHED_SUDO_BRIDGE) {
            assert(strstr(command, "sudo -n sh -c ") != NULL);
            assert(input_prefix_count == 0);
        } else {
            assert(strstr(command, "sudo -S -p '' sh -c ") != NULL);
            assert(input_prefix_count == 7 && memcmp(input_prefix, "secret\n", 7) == 0);
        }
        assert(input == packaged_binary_bytes);
        assert(binary_releases + 1 == expected_binary_releases);
        assert(input_count == 3 && memcmp(input, "BIN", 3) == 0);
    }
    complete_command(operation);
    return;
}



static void finish_bridge_on_reactor(void *context)
{
    (void)context;
    assert(live_bridge != NULL);
    outersshpriv_session_pool_socket_bridge_completed(live_bridge,
        (SSHReactorSocketBridgeHandle){.generation = 1}, SSH_REACTOR_SOCKET_BRIDGE_EXITED, 0, NULL, 0);
    live_bridge = NULL;
    if (stage != 7 && !(stage == BRIDGE_REPLACEMENT_SUCCESS && streams == 1)) {
        schedule_verification();
    }
}

static void reject_bridge_open(void *context)
{
    outersshpriv_session_pool_socket_bridge_completed(context,
        (SSHReactorSocketBridgeHandle){.generation = 1},
        SSH_REACTOR_SOCKET_BRIDGE_CHANNEL_OPEN_FAILED, 1, NULL, 0);
}

int outersshpriv_reactor_start_socket_channel(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle *handle, SSHSocketChannelCallbacks callbacks,
    const char *command, size_t command_count, const void *input, size_t input_count,
    uint64_t open_timeout, uint64_t ready_timeout)
{
    SSHSocketBridgeContext *context = callbacks.context;
    SSHSocketBridgeOperation *operation = context->setup;
    otqueue_assert(reactor_queue);
    assert(reactor == (SSHReactor *)&test_pool);
    assert(command == operation->command && command_count == strlen(command));
    assert(input == operation->initial_input && input_count == operation->initial_input_byte_count);
    assert(open_timeout == 5000 && ready_timeout == 10000);
    starts++;
    if (stage == CACHED_SUDO_PASSWORD_REQUIRED) {
        static const char password[] = "A sudo password is required to start the socket bridge.";
        outersshpriv_session_pool_socket_bridge_completed(context,
            (SSHReactorSocketBridgeHandle){.generation = 1},
            SSH_REACTOR_SOCKET_BRIDGE_EXITED, 0, password, sizeof(password) - 1);
        return 0;
    }
    if (((stage == MISSING_CACHED_BRIDGE || stage == MISSING_CACHED_SUDO_BRIDGE) && starts == 1) ||
        stage == REINSTALLED_BRIDGE_FAILURE || stage == FRESH_BRIDGE_FAILURE) {
        static const char missing[] = "bash: outerssh-helper: No such file or directory";
        outersshpriv_session_pool_socket_bridge_completed(context,
            (SSHReactorSocketBridgeHandle){.generation = 1},
            SSH_REACTOR_SOCKET_BRIDGE_EXITED, 0, missing, sizeof(missing) - 1);
        return 0;
    }
    if (stage == ASYNC_BRIDGE_OPEN_FAILURE) {
        otqueue_async(reactor_queue, context, reject_bridge_open);
        return 0;
    }
    if (stage == 3) {
        assert(input_count == 7 && memcmp(input, "secret\n", 7) == 0);
        return -1;
    }
    if (stage == 8) {
        assert(input == NULL && input_count == 0);
        return -1;
    }
    if (stage == 7 && starts == 2) {
        return -1;
    }
    *handle = (SSHReactorSocketBridgeHandle){.generation = 1};
    live_bridge = context;
    if (stage == 4) {
        otqueue_async(test_pool._queue, NULL, invalidate_listener);
    }
    outersshpriv_session_pool_socket_bridge_completed(context, *handle, SSH_REACTOR_SOCKET_BRIDGE_READY, 0, NULL, 0);
    return 0;
}

void outersshpriv_reactor_stop_socket_bridge(SSHReactor *reactor, SSHReactorSocketBridgeHandle handle, bool eof)
{
    assert(reactor == (SSHReactor *)&test_pool && handle.generation == 1 && eof);
    finish_bridge_on_reactor(NULL);
}

int outersshpriv_reactor_socket_bridge_prepare_stream(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle bridge, SSHReactorSocketBridgeStreamHandle *handle,
    ConnectBridgeStreamContext *operation, uint64_t timeout)
{
    otqueue_assert(reactor_queue);
    assert(reactor == (SSHReactor *)&test_pool && bridge.generation == 1);
    assert(timeout == 30000);
    streams++;
    if (first_stream_context == NULL) first_stream_context = operation;
    assert(first_stream_context == operation);
    if (streams > 1) {
        assert(operation->completed_error.domain == OUTERSSH_ERROR_NONE);
        assert(operation->error_storage == NULL);
    }
    if (stage == STREAM_START_FAILURE) {
        return -1;
    }
    *handle = (SSHReactorSocketBridgeStreamHandle){.generation = 1};
    outersshpriv_session_pool_socket_bridge_stream_completed(operation, bridge, *handle,
        stage == STREAM_TIMEOUT ? SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_TIMED_OUT :
        stage == 5 ? SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_FAILED :
        (stage == 7 || (stage == BRIDGE_REPLACEMENT_SUCCESS && streams == 1)) ? SSH_REACTOR_SOCKET_BRIDGE_STREAM_SESSION_CLOSED : SSH_REACTOR_SOCKET_BRIDGE_STREAM_READY,
        NULL, 0);
    return 0;
}

bool outersshpriv_reactor_socket_bridge_cancel_stream(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle bridge, SSHReactorSocketBridgeStreamHandle stream)
{
    assert(reactor == (SSHReactor *)&test_pool && bridge.generation == 1 && stream.generation == 1);
    cancellations++;
    finish_bridge_on_reactor(NULL);
    return true;
}

bool outersshpriv_proxy_reactor_pending_connection_is_active(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle connection)
{
    (void)reactor; (void)connection;
    return true;
}

bool outersshpriv_reactor_socket_bridge_attach_stream(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle bridge,
    SSHReactorSocketBridgeStreamHandle stream, otsocket_t socket, uint64_t proxy_generation)
{
    (void)reactor; (void)bridge; (void)stream; (void)socket; (void)proxy_generation;
    abort();
}

void outersshpriv_proxy_reactor_complete_pending_connection(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle connection,
    ProxySocketTransferHandler finished, void *context)
{
    (void)reactor; (void)connection;
    assert(stage == 1 || stage == BRIDGE_REPLACEMENT_SUCCESS);
    assert(context == first_stream_context);
    finished(context, -1);
}

void outersshpriv_proxy_fail_connection(
    SSHProxyConnection value,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route,
    OuterSSHError error)
{
    (void)route;
    outersshpriv_proxy_reactor_fail_pending_connection(value.server->reactor, connection,
        outersshpriv_proxy_reply_status_for_error(error));
}

bool outersshpriv_proxy_reactor_fail_pending_connection(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle connection, ProxySOCKSReplyStatus status)
{
    (void)reactor; (void)connection; (void)status;
    if (counting_connection_failures) {
        connection_failures++;
        return true;
    }
    if (testing_assignment_failure) {
        assert(status == PROXY_SOCKS_REPLY_GENERAL_FAILURE);
        assignment_failures++;
        return true;
    }
    assert(stage == 5 || stage == 6 || stage == 7 || stage == STREAM_START_FAILURE || stage == STREAM_TIMEOUT);
    if (stage == 5 || stage == STREAM_START_FAILURE || stage == STREAM_TIMEOUT) {
        otqueue_async(reactor_queue, NULL, finish_bridge_on_reactor);
    } else if (stage == 7) {
        schedule_verification();
    }
    return true;
}

static void verify_setup_finished(void *opaque_context)
{
    (void)opaque_context;
    assert(live_bridge != NULL && live_bridge->setup == NULL);
    assert(test_pool.pending_operations == 1);
    otqueue_async(reactor_queue, NULL, finish_bridge_on_reactor);
}

static void route_finished(SSHProxyBridgeHandle bridge, OuterSSHError error)
{
    otqueue_assert(test_pool._queue);
    route_completions++;
    if (stage == ASYNC_BRIDGE_OPEN_FAILURE) {
        static const char message[] = "The SSH server rejected the socket bridge channel (reason 1).";
        assert(error.message_length == sizeof(message) - 1);
        assert(memcmp(error.message, message, sizeof(message) - 1) == 0);
    }
    if (stage == USER_LOADER_FAILURE) {
        assert(error.domain == OUTERSSH_ERROR_HELPER_INSTALLER);
        assert(error.code == OUTERSSH_HELPER_INSTALLER_ERROR_MISSING_PACKAGED_BINARY);
        assert(strcmp(error.message, "Test binary could not be loaded.") == 0);
    }
    if (stage == 0 || stage == 2 || stage == 3 || stage == 4 || stage == 8 ||
        stage == ASYNC_BRIDGE_OPEN_FAILURE || stage == CONTEXT_ALLOCATION_FAILURE ||
        stage == REINSTALLED_BRIDGE_FAILURE || stage == FRESH_BRIDGE_FAILURE ||
        stage == CACHED_SUDO_PASSWORD_REQUIRED ||
        stage >= USER_OPERATION_ALLOCATION_FAILURE) {
        assert(error.domain != OUTERSSH_ERROR_NONE);
        if (stage != 4 && route_completions == expected_setup_completions()) {
            schedule_verification();
        }
        return;
    }
    assert(error.domain == OUTERSSH_ERROR_NONE && live_bridge != NULL && live_bridge->setup == NULL);
    assert(test_pool.pending_operations > 0);
    if (stage == READY_THEN_EVENTS || stage == MISSING_CACHED_BRIDGE ||
        stage == MISSING_CACHED_SUDO_BRIDGE) {
        if (route_completions != expected_setup_completions()) return;
        otqueue_async(test_pool._queue, NULL, verify_setup_finished);
        return;
    }
    ProxyConnectionRoute route = {.kind = PROXY_CONNECTION_ROUTE_UNIX_SOCKET,
        .request = {.host = "outer.test", .host_length = sizeof("outer.test") - 1, .port = 80}};
    strcpy(route.unix_socket.path, stage == 6 ? "/changed.sock" : "/run/test.sock");
    route.unix_socket.path_length = strlen(route.unix_socket.path);
    SSHProxyBridgeState *state = outersshpriv_proxy_bridge_for_handle(&test_pool, bridge);
    assert(state != NULL);
    outersshpriv_proxy_assign_bridge_connection(test_connection,
        (ProxyReactorPendingConnectionHandle){.generation = 1}, route,
        state->path, state->path_length, state->uses_sudo);
}

static void route_bridge_ready(void *context, SSHBridgeResult result)
{
    TestBridgePreparation *preparation = context;
    assert(preparation->waiter.waiter.next == NULL);
    free(preparation);
    SSHProxyBridgeHandle bridge = result.bridge;
    if (stage == 0) assert(result.failed_bridge.generation == 77);
    if (result.error.domain == OUTERSSH_ERROR_NONE) {
        if (first_ready_handle.generation == 0) first_ready_handle = bridge;
        assert(bridge.index == first_ready_handle.index && bridge.generation == first_ready_handle.generation);
    }
    route_finished(bridge, result.error);
}

static void invalidate_listener(void *context)
{
    (void)context;
    listener_active = false;
}

static void verify_stage(void *context)
{
    (void)context;
    assert(binary_releases == expected_binary_releases);
    assert(test_pool.pending_operations == 0);
    assert(live_bridge == NULL);
    assert(route_completions == expected_setup_completions());
    assert(starts == (stage == 7 || stage == BRIDGE_REPLACEMENT_SUCCESS ||
        stage == MISSING_CACHED_BRIDGE || stage == MISSING_CACHED_SUDO_BRIDGE ||
        stage == REINSTALLED_BRIDGE_FAILURE ? 2u : (unsigned)(stage != 0 && stage != 2 && stage != CONTEXT_ALLOCATION_FAILURE && stage < USER_OPERATION_ALLOCATION_FAILURE)));
    assert(streams == (stage == BRIDGE_REPLACEMENT_SUCCESS ? 2u : (unsigned)(stage == 1 || stage == 5 || stage == 6 || stage == 7 ||
        stage == STREAM_START_FAILURE || stage == STREAM_TIMEOUT)));
    assert(cancellations == (unsigned)(stage == 1 || stage == 6 || stage == BRIDGE_REPLACEMENT_SUCCESS));
    unsigned platform_commands = stage == READY_THEN_EVENTS ? 2u :
        (unsigned)(stage != 2 && stage != USER_OPERATION_ALLOCATION_FAILURE && stage != CACHED_SUDO_PASSWORD_REQUIRED);
    assert(commands[TEST_COMMAND_BRIDGE_PLATFORM] == platform_commands);
    if (stage != 2 && stage != 3 && stage != 8) {
        unsigned expected_allocations = stage == MISSING_CACHED_SUDO_BRIDGE ? 3u :
            stage == USER_OPERATION_ALLOCATION_FAILURE || stage == CACHED_SUDO_PASSWORD_REQUIRED ? 0u :
            (stage == 0 || stage == USER_LOADER_FAILURE || stage == USER_INSTALL_COMMAND_FAILURE ||
             stage == USER_INSTALL_ALLOCATION_FAILURE) ? 1u : 2u;
        assert(command_allocations == expected_allocations);
    }
    if (stage == READY_THEN_EVENTS) assert(commands[TEST_COMMAND_USER_BRIDGE_INSTALL] == 2);
    if (stage == MISSING_CACHED_BRIDGE || stage == REINSTALLED_BRIDGE_FAILURE || stage == FRESH_BRIDGE_FAILURE)
        assert(commands[TEST_COMMAND_USER_BRIDGE_INSTALL] == 1);
    if (stage == MISSING_CACHED_SUDO_BRIDGE) assert(commands[TEST_COMMAND_SUDO_BRIDGE_INSTALL] == 1);
    assert(commands[TEST_COMMAND_SUDO_CREDENTIALS] == (unsigned)(stage == 2 || stage == 3 || stage == 8 || stage == MISSING_CACHED_SUDO_BRIDGE));
    if (stage == CACHED_SUDO_PASSWORD_REQUIRED) {
        assert(commands[TEST_COMMAND_SUDO_BRIDGE_INSTALL] == 0);
        assert(strcmp(test_pool._sudoBridgeExecutablePath, "/var/tmp/vanished/outerssh-helper") == 0);
    }
    assert(test_pool._bridgeSetupHead == NULL);
    assert(!outersshpriv_is_waiting(&test_pool._userBridgeWaiters));
    assert(!outersshpriv_is_waiting(&test_pool._sudoBridgeWaiters));
    for (size_t i = 0; i < test_pool.bridge_state_count; i++) {
        free(test_pool.bridge_states[i].path);
        }
    free(test_pool.bridge_states);
    test_pool.bridge_states = NULL;
    test_pool.bridge_state_count = 0;
    test_pool.bridge_state_capacity = 0;
    free(test_pool._userBridgeExecutablePath);
    free(test_pool._sudoBridgeExecutablePath);
    test_pool._userBridgeExecutablePath = NULL;
    test_pool._sudoBridgeExecutablePath = NULL;
    test_server.port = 0;
    if (++stage == STAGE_COUNT) {
        free(test_pool._remotePlatform);
        test_pool._remotePlatform = NULL;
        test_pool._remotePlatformLength = 0;
        ssh_test_semaphore_signal(finished);
    } else {
        run_stage(NULL);
    }
}

static void cleanup_finished(void *context)
{
    (void)context;
    assert(commands[TEST_COMMAND_CLEANUP] == (stage == 9 ? 2u : stage == 10 ? 1u : 0u));
    assert(deferred_cleanup == NULL);
    assert(cleanup_completions == 1);
    assert(test_pool._userBridgeExecutablePath == NULL);
    assert(test_pool._sudoBridgeExecutablePath == NULL);
    assert(test_pool.pending_operations == 0);
    stage++;
    otqueue_async(test_pool._queue, NULL, run_stage);
}

static void cleanup_attempts_finished(void *context)
{
    unsigned *requested_stage = context;
    assert(*requested_stage == stage && stage >= 9);
    free(requested_stage);
    assert(++cleanup_completions == 1);
    unsigned expected_commands = stage == 9 || stage == 10 ? 1 : 0;
    assert(test_pool.pending_operations == expected_commands);
    otqueue_async(test_pool._queue, NULL, cleanup_finished);
}

static void conflicting_bridge_ready(void *context, SSHBridgeResult result)
{
    (void)context;
    assert(result.bridge.generation == 0);
    assert(result.error.domain == OUTERSSH_ERROR_PROXY && result.error.code == OUTERSSH_PROXY_ERROR_BRIDGE_PRIVILEGE_CONFLICT);
    assert(test_pool._bridgeSetupHead != NULL);
    privilege_conflicts++;
}

static void run_stage(void *context)
{
    (void)context;
    route_completions = starts = streams = cancellations = 0;
    first_stream_context = NULL;
    first_ready_handle = (SSHProxyBridgeHandle){0};
    privilege_conflicts = 0;
    memset(commands, 0, sizeof(commands));
    command_allocations = 0;
    assert(!test_pool._remotePlatformLookupRunning);
    free(test_pool._remotePlatform);
    test_pool._remotePlatform = NULL;
    test_pool._remotePlatformLength = 0;
    fail_user_command_allocation = stage == USER_OPERATION_ALLOCATION_FAILURE;
    fail_user_install_command = stage == USER_INSTALL_COMMAND_FAILURE;
    fail_second_command_allocation = stage == USER_INSTALL_ALLOCATION_FAILURE;
    if (stage >= 9 && stage < ASYNC_BRIDGE_OPEN_FAILURE) {
        cleanup_completions = cleanup_requests = 0;
        fail_installation_allocation = stage == 12 || stage == 14;
        fail_user_command_allocation = stage == 13;
        if (stage % 3 != 2) {
            test_pool._userBridgeExecutablePath = strdup("/tmp/user-id/outerssh-helper");
            test_pool._userBridgeExecutablePath_length = strlen(test_pool._userBridgeExecutablePath);
            test_pool._sudoBridgeExecutablePath = strdup("/var/tmp/outerssh-helper/sudo-id/outerssh-helper");
            test_pool._sudoBridgeExecutablePath_length = strlen(test_pool._sudoBridgeExecutablePath);
        }
        unsigned *requested_stage = malloc(sizeof(*requested_stage));
        assert(requested_stage != NULL);
        *requested_stage = stage;
        outersshpriv_proxy_cleanup_bridge_executables(&test_pool, cleanup_attempts_finished, requested_stage);
        assert(test_pool._userBridgeExecutablePath == NULL);
        assert(test_pool._userBridgeExecutablePath_length == 0);
        assert(test_pool._sudoBridgeExecutablePath == NULL);
        assert(test_pool._sudoBridgeExecutablePath_length == 0);
        assert(cleanup_completions == (unsigned)(stage >= 12 || stage % 3 == 2));
        return;
    }
    fail_installation_allocation = false;
    listener_active = true;
    test_listener = &test_pool;

    test_server.port = 12345;
    if (stage == MISSING_CACHED_BRIDGE || stage == REINSTALLED_BRIDGE_FAILURE) {
        test_pool._userBridgeExecutablePath = strdup("/run/user/1000/vanished/outerssh-helper");
        test_pool._userBridgeExecutablePath_length = strlen(test_pool._userBridgeExecutablePath);
    }
    if (stage == MISSING_CACHED_SUDO_BRIDGE || stage == CACHED_SUDO_PASSWORD_REQUIRED) {
        test_pool._sudoBridgeExecutablePath = strdup("/var/tmp/vanished/outerssh-helper");
        test_pool._sudoBridgeExecutablePath_length = strlen(test_pool._sudoBridgeExecutablePath);
    }
    if (stage == 0) {
        testing_assignment_failure = true;
        fail_path_allocation_number = 1;
        outersshpriv_proxy_assign_bridge_connection(test_connection,
            (ProxyReactorPendingConnectionHandle){.generation = 1},
            (ProxyConnectionRoute){.kind = PROXY_CONNECTION_ROUTE_UNIX_SOCKET}, "/run/test.sock", sizeof("/run/test.sock") - 1, false);
        assert(assignment_failures == 1 && fail_path_allocation_number == 0);
        assert(test_pool.pending_operations == 0);
        testing_assignment_failure = false;
    }
    for (unsigned index = 0; index < expected_setup_completions(); index++) {
        TestBridgePreparation *preparation = malloc(sizeof(*preparation));
        assert(preparation != NULL);
        memset(&preparation->operation, 0xa5, sizeof(preparation->operation));
        bool joining = test_pool._bridgeSetupHead != NULL;
        unsigned allocations = bridge_allocations;
        forbid_bridge_allocations = joining;
        outersshpriv_proxy_ensure_bridge(&test_pool, (SSHBridgeRequest){
            .path = "/run/test.sock",
            .path_length = sizeof("/run/test.sock") - 1,
            .uses_sudo = stage == 2 || stage == 3 || stage == 8 ||
                stage == MISSING_CACHED_SUDO_BRIDGE || stage == CACHED_SUDO_PASSWORD_REQUIRED,
            .sudo_password = stage == 3 ? "secret" : NULL,
            .sudo_password_length = stage == 3 ? sizeof("secret") - 1 : 0,
            .failed_bridge = {.generation = stage == 0 && index == 0 ? 77 : 0},
        }, &preparation->operation, &preparation->waiter, route_bridge_ready, preparation);
        if (joining) {
            assert(bridge_allocations == allocations);
            unsigned char untouched[sizeof(preparation->operation)];
            memset(untouched, 0xa5, sizeof(untouched));
            assert(memcmp(&preparation->operation, untouched, sizeof(untouched)) == 0);
        } else if (test_pool._bridgeSetupHead != NULL) {
            assert(test_pool._bridgeSetupHead == &preparation->operation);
        }
        forbid_bridge_allocations = false;
    }
    if (stage == READY_THEN_EVENTS) {
        unsigned allocations = bridge_allocations;
        forbid_bridge_allocations = true;
        TestBridgePreparation preparation;
        outersshpriv_proxy_ensure_bridge(&test_pool, (SSHBridgeRequest){
            .path = "/run/test.sock",
            .path_length = sizeof("/run/test.sock") - 1,
            .uses_sudo = true,
        }, &preparation.operation, &preparation.waiter, conflicting_bridge_ready, NULL);
        assert(privilege_conflicts == 1 && bridge_allocations == allocations);
        forbid_bridge_allocations = false;
    }
}

static unsigned installation_callbacks;
static OuterSSHError installation_callback_error;
static bool testing_sudo_installation;
static bool joining_installation;

static unsigned reentrant_installation_callbacks;

typedef struct {
    SSHWaiter waiter;
    unsigned order;
} InstallationRequest;

static InstallationRequest *installation_request(unsigned order)
{
    InstallationRequest *request = malloc(sizeof(*request));
    assert(request != NULL);
    request->order = order;
    return request;
}

static SSHBridgeInstallStep tested_installation_step(void)
{
    return testing_sudo_installation ? test_pool._sudoBridgeInstall : test_pool._userBridgeInstall;
}

static void reentrant_installation_ready(void *context, OuterSSHError error)
{
    free(context);
    assert(error.domain != OUTERSSH_ERROR_NONE);
    assert(tested_installation_step() == SSH_BRIDGE_INSTALL_IDLE);
    reentrant_installation_callbacks++;
}

static void installation_ready(void *context, OuterSSHError error)
{
    InstallationRequest *request = context;
    unsigned callback_order = request->order;
    assert(installation_callbacks++ == callback_order);
    free(request);
    assert(tested_installation_step() == SSH_BRIDGE_INSTALL_IDLE);
    assert(error.domain == installation_callback_error.domain);
    assert(error.code == installation_callback_error.code);
    assert(test_pool._bridgeSetupHead == NULL);
    assert(!outersshpriv_is_waiting(&test_pool._userBridgeWaiters));
    assert(!outersshpriv_is_waiting(&test_pool._sudoBridgeWaiters));
    const char *path = testing_sudo_installation ? test_pool._sudoBridgeExecutablePath
        : test_pool._userBridgeExecutablePath;
    assert((path != NULL) == (error.domain == OUTERSSH_ERROR_NONE));
    if (callback_order == 0 && joining_installation &&
        error.domain != OUTERSSH_ERROR_NONE) {
        fail_user_command_allocation = true;
        InstallationRequest *nested = installation_request(0);
        unsigned callbacks = reentrant_installation_callbacks;
        if (testing_sudo_installation) {
            outersshpriv_proxy_ensure_sudo_bridge_executable(&test_pool, NULL, 0,
                &nested->waiter, reentrant_installation_ready, nested);
        } else {
            outersshpriv_proxy_ensure_user_bridge_executable(&test_pool,
                &nested->waiter, reentrant_installation_ready, nested);
        }
        assert(reentrant_installation_callbacks == callbacks + 1);
        fail_user_command_allocation = false;
    }
}


static unsigned setup_callbacks;
static SSHProxyBridgeHandle expected_setup_bridge;
static SSHProxyBridgeHandle expected_failed_bridge;
static bool expects_setup_error;

static void setup_checked(void *context, SSHBridgeResult result)
{
    (void)context;
    assert(++setup_callbacks == 1);
    assert((result.error.domain != OUTERSSH_ERROR_NONE) == expects_setup_error);
    assert(result.bridge.generation == expected_setup_bridge.generation);
    assert(result.failed_bridge.generation == expected_failed_bridge.generation);
}

static unsigned borrowed_request_completions;
static void borrowed_request_finished(void *context, SSHBridgeResult result)
{
    free(context);
    borrowed_request_completions++;
    assert(result.error.domain == OUTERSSH_ERROR_NONE);
    assert(result.bridge.generation != 0);
}

static unsigned reentrant_setup_completions;
static void reentrant_setup_finished(void *context, SSHBridgeResult result)
{
    TestBridgePreparation *preparation = context;
    assert(result.error.domain != OUTERSSH_ERROR_NONE);
    assert(test_pool._bridgeSetupHead == NULL && preparation->waiter.waiter.next == NULL);
    if (++reentrant_setup_completions == 1) {
        outersshpriv_proxy_ensure_bridge(&test_pool, (SSHBridgeRequest){
            .path = "/run/reenter.sock", .path_length = sizeof("/run/reenter.sock") - 1,
        }, &preparation->operation, &preparation->waiter, reentrant_setup_finished, preparation);
    } else {
        assert(reentrant_setup_completions == 2);
        free(preparation);
    }
}

static void test_immediate_bridge_setup(void)
{
    test_listener = &test_pool;
    assert(test_listener != NULL);

    test_server.port = 12345;
    SSHProxyBridgeHandle existing_handle;
    SSHProxyBridgeState *existing = outersshpriv_proxy_append_bridge_state(
        test_listener, "/run/test.sock", sizeof("/run/test.sock") - 1, false, &existing_handle);
    assert(existing != NULL);
    for (unsigned privileged = 0; privileged < 2; privileged++) {
        existing->uses_sudo = privileged != 0;
        for (unsigned scenario = 0; scenario < 4; scenario++) {
            setup_callbacks = 0;
            expects_setup_error = scenario != 0;
            expected_setup_bridge = scenario == 0 ? existing_handle : (SSHProxyBridgeHandle){0};
            expected_failed_bridge = scenario == 2 ? existing_handle :
                scenario == 3 ? (SSHProxyBridgeHandle){.generation = 999} : (SSHProxyBridgeHandle){0};
            listener_active = true;
            existing->is_current = true;
            existing->stopped = scenario >= 2;
            fail_installation_allocation = scenario >= 2;
            forbid_bridge_allocations = scenario < 2;
            unsigned allocations = bridge_allocations;
            TestBridgePreparation preparation;
            unsigned char untouched[sizeof(preparation)];
            memset(&preparation, 0xa5, sizeof(preparation));
            memcpy(untouched, &preparation, sizeof(untouched));
            outersshpriv_proxy_ensure_bridge(&test_pool, (SSHBridgeRequest){
                .path = "/run/test.sock",
                .path_length = sizeof("/run/test.sock") - 1,
                .uses_sudo = (scenario == 1) != (privileged != 0),
                .failed_bridge = scenario == 3 ? expected_failed_bridge : (SSHProxyBridgeHandle){0},
            }, &preparation.operation, &preparation.waiter, setup_checked, NULL);
            assert(setup_callbacks == 1);
            if (scenario < 2) assert(memcmp(&preparation, untouched, sizeof(untouched)) == 0);
            assert(bridge_allocations == allocations);
            forbid_bridge_allocations = false;
            assert(test_pool.pending_operations == 0);
            if (scenario >= 2) assert(!existing->is_current);
            else assert(existing->is_current && !existing->stopped);
        }
    }
    fail_installation_allocation = false;
    existing->is_current = true;
    existing->stopped = false;
    TestBridgePreparation *borrowed = malloc(sizeof(*borrowed) + sizeof("/run/test.sock") - 1);
    assert(borrowed != NULL);
    char *path = (char *)(borrowed + 1);
    memcpy(path, "/run/test.sock", sizeof("/run/test.sock") - 1);
    existing->is_current = true;
    outersshpriv_proxy_ensure_bridge(&test_pool, (SSHBridgeRequest){
        .path = path,
        .path_length = sizeof("/run/test.sock") - 1,
        .uses_sudo = true,
    }, &borrowed->operation, &borrowed->waiter, borrowed_request_finished, borrowed);
    assert(borrowed_request_completions == 1);
    assert(test_pool.pending_operations == 0);

    TestBridgePreparation *preparation = malloc(sizeof(*preparation));
    assert(preparation != NULL);
    fail_user_command_allocation = true;
    outersshpriv_proxy_ensure_bridge(&test_pool, (SSHBridgeRequest){
        .path = "/run/reenter.sock", .path_length = sizeof("/run/reenter.sock") - 1,
    }, &preparation->operation, &preparation->waiter, reentrant_setup_finished, preparation);
    fail_user_command_allocation = false;
    assert(reentrant_setup_completions == 2 && test_pool.pending_operations == 0);

    for (size_t i = 0; i < test_pool.bridge_state_count; i++) {
        free(test_pool.bridge_states[i].path);
        }
    free(test_pool.bridge_states);
    test_pool.bridge_states = NULL;
    test_pool.bridge_state_count = 0;
    test_pool.bridge_state_capacity = 0;
    test_listener = NULL;
    test_server.port = 0;
}

typedef struct {
    SSHWaiter waiter;
    bool success;
    bool reenter;
} PlatformCallbackContext;

static unsigned platform_callbacks;

/* Binary questions are declined here, so an installation whose platform is
 * known ends at the binary step. */
static void platform_checked(void *context, OuterSSHError error)
{
    PlatformCallbackContext *request = context;
    bool reenter = request->reenter;
    bool success = request->success;
    free(request);
    bool reached_binary = error.domain == OUTERSSH_ERROR_HELPER_INSTALLER &&
        error.code == OUTERSSH_HELPER_INSTALLER_ERROR_MISSING_PACKAGED_BINARY;
    assert(reached_binary == success);
    platform_callbacks++;
    if (success) {
        assert(test_pool._remotePlatformLength == sizeof("aarch64 glibc") - 1);
        assert(memcmp(test_pool._remotePlatform, "aarch64 glibc", test_pool._remotePlatformLength) == 0);
    }
    if (reenter) {
        PlatformCallbackContext *next = malloc(sizeof(*next));
        assert(next != NULL);
        *next = (PlatformCallbackContext){.success = true};
        outersshpriv_proxy_ensure_user_bridge_executable(&test_pool, &next->waiter, platform_checked, next);
    }
}

static void request_test_platform(bool success, bool reenter)
{
    PlatformCallbackContext *context = malloc(sizeof(*context));
    assert(context != NULL);
    *context = (PlatformCallbackContext){.success = success, .reenter = reenter};
    outersshpriv_proxy_ensure_user_bridge_executable(&test_pool, &context->waiter, platform_checked, context);
}

static void complete_test_platform(int exit_status, const char *output, OuterSSHError error)
{
    ExecuteCommandContext *operation = deferred_platform;
    assert(operation != NULL);
    deferred_platform = NULL;
    operation->completed_result = SSH_REACTOR_COMMAND_COMPLETED;
    operation->completed_exit_status = exit_status;
    if (output != NULL) {
        operation->completed_stdout = strdup(output);
        assert(operation->completed_stdout != NULL);
        operation->completed_stdout_byte_count = strlen(output);
    }
    finish_command(operation, error);
}

static void test_platform_cache(void)
{
    testing_platform_cache = true;
    decline_bridge_binaries = true;
    for (unsigned failure = 1; failure < 5; failure++) {
        platform_callbacks = platform_requests = 0;
        request_test_platform(false, false);
        request_test_platform(false, false);
        assert(platform_callbacks == 0 && platform_requests == 1);
        fail_installation_malloc = failure == 4;
        complete_test_platform(failure == 2 ? 1 : 0,
            failure == 3 ? "" : "aarch64 glibc",
            failure == 1 ? outerssh_proxy_closing_error() : (OuterSSHError){0});
        if (failure == 2) complete_test_platform(1, "", (OuterSSHError){0});
        fail_installation_malloc = false;
        assert(platform_callbacks == 2);
        assert(test_pool._remotePlatform == NULL);
        assert(test_pool.pending_operations == 0);
        // A failed attempt does not prevent the next request from detecting the platform.
        request_test_platform(true, true);
        request_test_platform(true, false);
        unsigned before = platform_callbacks;
        unsigned probes = platform_requests;
        complete_test_platform(0, "aarch64 glibc", (OuterSSHError){0});
        assert(platform_callbacks == before + 3 && platform_requests == probes);
        assert(test_pool.pending_operations == 0);
        /* A known platform resumes at once without probing again. */
        request_test_platform(true, false);
        assert(platform_callbacks == before + 4 && platform_requests == probes);
        free(test_pool._remotePlatform);
        test_pool._remotePlatform = NULL;
        test_pool._remotePlatformLength = 0;
    }
    platform_callbacks = platform_requests = 0;
    request_test_platform(false, true);
    complete_test_platform(1, "", (OuterSSHError){0});
    assert(platform_callbacks == 0 && platform_requests == 2 && deferred_platform != NULL);
    complete_test_platform(1, "", (OuterSSHError){0});
    assert(platform_callbacks == 1 && platform_requests == 3 && deferred_platform != NULL);
    complete_test_platform(0, "aarch64 glibc", (OuterSSHError){0});
    assert(platform_callbacks == 2 && test_pool._remotePlatform != NULL);
    free(test_pool._remotePlatform);
    test_pool._remotePlatform = NULL;
    test_pool._remotePlatformLength = 0;
    request_test_platform(false, false);
    test_pool.shutdown_requested = true;
    test_pool._disconnecting = true;
    complete_test_platform(0, "aarch64 glibc", (OuterSSHError){0});
    assert(test_pool._remotePlatform == NULL && test_pool.pending_operations == 0);
    unsigned probes = platform_requests;
    unsigned callbacks = platform_callbacks;
    request_test_platform(false, false);
    assert(platform_requests == probes && platform_callbacks == callbacks + 1);
    assert(test_pool._userBridgeInstall == SSH_BRIDGE_INSTALL_IDLE);
    test_pool.shutdown_requested = false;
    test_pool._disconnecting = false;

    /* Shutdown fails an installation still waiting for the platform at once,
     * without waiting for the probe; a running install command finishes. */
    request_test_platform(false, false);
    assert(deferred_platform != NULL && test_pool._userBridgeInstall == SSH_BRIDGE_INSTALL_NEEDS_PLATFORM);
    test_pool._sudoBridgeInstall = SSH_BRIDGE_INSTALL_INSTALLING;
    callbacks = platform_callbacks;
    test_pool.shutdown_requested = true;
    outersshpriv_proxy_advance_bridge_installs(&test_pool);
    assert(platform_callbacks == callbacks + 1 && test_pool._userBridgeInstall == SSH_BRIDGE_INSTALL_IDLE);
    assert(test_pool._sudoBridgeInstall == SSH_BRIDGE_INSTALL_INSTALLING && outersshpriv_proxy_bridge_installs_busy(&test_pool));
    test_pool._sudoBridgeInstall = SSH_BRIDGE_INSTALL_IDLE;
    assert(!outersshpriv_proxy_bridge_installs_busy(&test_pool));
    complete_test_platform(0, "aarch64 glibc", (OuterSSHError){0});
    assert(platform_callbacks == callbacks + 1 && !test_pool._remotePlatformLookupRunning);
    assert(test_pool.pending_operations == 0);
    free(test_pool._remotePlatform);
    test_pool._remotePlatform = NULL;
    test_pool._remotePlatformLength = 0;
    test_pool.shutdown_requested = false;
    decline_bridge_binaries = false;
    binary_questions = 0;
    testing_platform_cache = false;
}

static unsigned sudo_password_questions;
static uint32_t last_sudo_attempt;
static char last_sudo_error[64];

void outersshpriv_session_pool_ask_sudo_password(OuterSSHSessionPool *pool, const void *owner,
    const void *frontend, const char *path, size_t path_length, uint32_t attempt, OuterSSHError error,
    SSHSudoPasswordContinuation continuation, void *context)
{
    (void)frontend; (void)continuation; (void)context;
    assert(pool == &test_pool && owner == &test_server);
    assert(path_length == sizeof("/run/expired.sock") - 1);
    assert(memcmp(path, "/run/expired.sock", path_length) == 0);
    sudo_password_questions++;
    last_sudo_attempt = attempt;
    assert(error.message_length < sizeof(last_sudo_error));
    memcpy(last_sudo_error, error.message ? error.message : "", error.message_length);
    last_sudo_error[error.message_length] = 0;
}

static bool explicit_close_completed;
enum { BRIDGE_LIST_TAG = 43, BRIDGE_CLOSE_TAG };
static uint64_t expected_bridge_identifier;

SSHPoolEvent *outersshpriv_reply_reserve(OuterSSHSessionPool *pool, OuterSSHEventType type, uint64_t tag)
{
    SSHPoolEvent *reply = calloc(1, sizeof(*reply));
    assert(reply != NULL);
    reply->event = (OuterSSHEvent){.type = type, .pool = pool, .tag = tag};
    return reply;
}

/* Replies are checked as the application would receive them. */
void outersshpriv_reply(SSHPoolEvent *reply, OuterSSHError error)
{
    uint64_t tag = reply->event.tag;
    assert(reply->event.type == OUTERSSH_EVENT_OPERATION_COMPLETED && reply->event.pool == &test_pool);
    free(reply);
    assert(tag == BRIDGE_CLOSE_TAG && error.domain == OUTERSSH_ERROR_NONE);
    explicit_close_completed = true;
}

void outersshpriv_reply_command(SSHPoolEvent *reply, const SSHCommandOutput *output, OuterSSHError error)
{
    (void)reply; (void)output; (void)error;
    abort();
}

void outersshpriv_reply_socket_bridges(SSHPoolEvent *reply, const OuterSSHBridgeInfo *items, size_t count,
    OuterSSHError error)
{
    assert(reply->event.tag == BRIDGE_LIST_TAG);
    free(reply);
    assert(error.domain == OUTERSSH_ERROR_NONE);
    assert(count == 1 && items[0].identifier == expected_bridge_identifier && items[0].privileged);
    assert(items[0].path_length == strlen("/run/expired.sock"));
}

static void request_sudo_password_twice(ProxyConnectionRoute route, OuterSSHError error)
{
    for (unsigned i = 0; i < 2; i++) {
        handle_bridge_failure(test_connection, (ProxyReactorPendingConnectionHandle){0},
            route, (SSHProxyBridgeHandle){0}, false, false, error);
    }
}

static void test_sudo_password_requests(void)
{
    listener_active = true;
    ProxyConnectionRoute route = {.kind = PROXY_CONNECTION_ROUTE_UNIX_SOCKET};
    static const char path[] = "/run/expired.sock";
    memcpy(route.unix_socket.path, path, sizeof(path) - 1);
    route.unix_socket.path_length = sizeof(path) - 1;
    static const char detail[] = "A sudo password is required to start the socket bridge.\n";
    char *storage = NULL;
    OuterSSHError error = socket_bridge_result_error(&storage, true,
        SSH_REACTOR_SOCKET_BRIDGE_EXITED, 0, detail, sizeof(detail) - 1);
    assert(error.domain == OUTERSSH_ERROR_PROXY && error.code == OUTERSSH_PROXY_ERROR_SUDO_PASSWORD_REQUIRED);
    assert(storage == NULL);
    OuterSSHError ordinary = socket_bridge_result_error(&storage, false,
        SSH_REACTOR_SOCKET_BRIDGE_EXITED, 0, detail, sizeof(detail) - 1);
    assert(ordinary.domain == OUTERSSH_ERROR_SESSION);
    free(storage);
    storage = NULL;
    ordinary = socket_bridge_result_error(&storage, true,
        SSH_REACTOR_SOCKET_BRIDGE_EXITED, 0, "Permission denied", sizeof("Permission denied") - 1);
    assert(ordinary.domain == OUTERSSH_ERROR_SESSION);
    free(storage);
    size_t pending = test_pool.pending_operations;

    /* Connections to one socket share a question, and a rejected password asks again with the failure. */
    request_sudo_password_twice(route, error);
    SSHSudoPasswordRequest *request = test_pool._sudoPasswordRequests;
    assert(sudo_password_questions == 1 && last_sudo_attempt == 1 && last_sudo_error[0] == 0);
    assert(request && request->waiters && request->waiters->next && !request->waiters->next->next);
    assert(test_pool.pending_operations == pending + 2);
    static const char rejected[] = "Sorry, try again.";
    OuterSSHError rejection = outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE, rejected, sizeof(rejected) - 1);
    for (uint32_t attempt = 2; attempt <= 5; attempt++) {
        request->password = strdup("wrong");
        request->password_length = 5;
        sudo_password_bridge_ready(request, (SSHBridgeResult){.error = rejection});
        assert(request->password == NULL && test_pool._sudoPasswordRequests == request);
        assert(sudo_password_questions == attempt && last_sudo_attempt == attempt);
        assert(strcmp(last_sudo_error, rejected) == 0);
    }

    /* Declining fails every waiting connection. */
    counting_connection_failures = true;
    request->answer = SSH_QUESTION_DECLINED;
    use_sudo_password(request);
    assert(connection_failures == 2 && test_pool._sudoPasswordRequests == NULL);
    assert(test_pool.pending_operations == pending);

    /* A closing connection fails the waiting connections without asking again. */
    request_sudo_password_twice(route, error);
    request = test_pool._sudoPasswordRequests;
    assert(sudo_password_questions == 6 && last_sudo_attempt == 1);
    request->password = strdup("right");
    request->password_length = 5;
    sudo_password_bridge_ready(request, (SSHBridgeResult){.error = outerssh_proxy_closing_error()});
    assert(sudo_password_questions == 6 && connection_failures == 4 && test_pool._sudoPasswordRequests == NULL);
    assert(test_pool.pending_operations == pending);
    counting_connection_failures = false;

    /* A working bridge hands every waiting connection to stream preparation. */
    request_sudo_password_twice(route, error);
    request = test_pool._sudoPasswordRequests;
    testing_assignment_failure = true;
    unsigned failures = assignment_failures;
    sudo_password_bridge_ready(request, (SSHBridgeResult){0});
    assert(assignment_failures == failures + 2 && test_pool._sudoPasswordRequests == NULL);
    assert(test_pool.pending_operations == pending);

    SSHProxyBridgeHandle handle;
    SSHProxyBridgeState *bridge = outersshpriv_proxy_append_bridge_state(&test_pool, path, sizeof(path) - 1, true, &handle);
    assert(bridge);
    bridge->is_current = true;
    uint64_t identifier = handle.index + 1;
    expected_bridge_identifier = identifier;
    /* Already on the control queue: run the operations' queue steps directly. */
    SocketBridgeListRequest *list = malloc(sizeof(*list));
    *list = (SocketBridgeListRequest){&test_pool,
        outersshpriv_reply_reserve(&test_pool, OUTERSSH_EVENT_BRIDGES_RECEIVED, BRIDGE_LIST_TAG)};
    list_socket_bridges(list);
    SocketBridgeCloseRequest *close = malloc(sizeof(*close));
    *close = (SocketBridgeCloseRequest){&test_pool, identifier,
        outersshpriv_reply_reserve(&test_pool, OUTERSSH_EVENT_OPERATION_COMPLETED, BRIDGE_CLOSE_TAG)};
    close_socket_bridge(close);
    assert(explicit_close_completed && bridge->stopped && bridge->explicitly_closed);
    unsigned questions = sudo_password_questions;
    handle_bridge_failure(test_connection, (ProxyReactorPendingConnectionHandle){0}, route, handle, false, true, error);
    assert(sudo_password_questions == questions && assignment_failures == failures + 3);

    /* A stopped sudo bridge that fails for another reason fails without asking. */
    bridge->explicitly_closed = false;
    counting_connection_failures = true;
    handle_bridge_failure(test_connection, (ProxyReactorPendingConnectionHandle){0}, route, handle, false, true, ordinary);
    assert(sudo_password_questions == questions && connection_failures == 5);
    counting_connection_failures = false;
    free(bridge->path);
    memset(bridge, 0, sizeof(*bridge));
    test_pool.bridge_state_count--;
    assignment_failures = failures;
    testing_assignment_failure = false;
    assert(test_pool.pending_operations == pending);
}

static void test_installation_waiters(void *context)
{
    (void)context;
    test_platform_cache();
    test_sudo_password_requests();
    test_immediate_bridge_setup();
    for (unsigned sudo = 0; sudo < 2; sudo++) {
        testing_sudo_installation = sudo != 0;
        char **installed_path = sudo ? &test_pool._sudoBridgeExecutablePath
            : &test_pool._userBridgeExecutablePath;
        size_t *installed_length = sudo ? &test_pool._sudoBridgeExecutablePath_length
            : &test_pool._userBridgeExecutablePath_length;
        SSHWaitList *waiters = sudo ? &test_pool._sudoBridgeWaiters : &test_pool._userBridgeWaiters;
        SSHBridgeInstallStep *step = sudo ? &test_pool._sudoBridgeInstall : &test_pool._userBridgeInstall;
        for (unsigned failure = 0; failure < 2; failure++) {
            installation_callbacks = 0;
            joining_installation = true;
            installation_callback_error = failure ? outerssh_proxy_closing_error() : (OuterSSHError){0};
            /* An installation is already in progress for the first request. */
            InstallationRequest *first = installation_request(0);
            *step = SSH_BRIDGE_INSTALL_INSTALLING;
            outersshpriv_wait(waiters, &first->waiter, installation_ready, first);
            const char password[] = {'s', 'e', 'c', 'r', 'e', 't'};
            InstallationRequest *second = installation_request(1);
            if (sudo) {
                outersshpriv_proxy_ensure_sudo_bridge_executable(&test_pool, password, sizeof(password),
                    &second->waiter, installation_ready, second);
                /* Joining an installation does not replace the first requester's password. */
                assert(test_pool._sudoBridgeInstallPassword != password);
            } else {
                outersshpriv_proxy_ensure_user_bridge_executable(&test_pool,
                    &second->waiter, installation_ready, second);
            }
            assert(waiters->head == &first->waiter && waiters->tail == &second->waiter);
            assert(installation_callbacks == 0);
            if (!failure) {
                *installed_path = strdup("/tmp/installed-executable");
                assert(*installed_path != NULL);
                *installed_length = strlen(*installed_path);
            }
            if (sudo) finish_sudo_bridge_install(&test_pool, installation_callback_error);
            else finish_user_bridge_install(&test_pool, installation_callback_error);
            assert(installation_callbacks == 2 && *step == SSH_BRIDGE_INSTALL_IDLE);
            assert(test_pool.pending_operations == 0);
            free(*installed_path);
            *installed_path = NULL;
            *installed_length = 0;
        }
        // Both entry points resume at once without waiting when already installed.
        *installed_path = strdup("/tmp/installed-executable");
        assert(*installed_path != NULL);
        *installed_length = strlen(*installed_path);
        installation_callbacks = 0;
        joining_installation = false;
        installation_callback_error = (OuterSSHError){0};
        InstallationRequest *installed = installation_request(0);
        if (sudo) outersshpriv_proxy_ensure_sudo_bridge_executable(&test_pool, NULL, 0,
            &installed->waiter, installation_ready, installed);
        else outersshpriv_proxy_ensure_user_bridge_executable(&test_pool,
            &installed->waiter, installation_ready, installed);
        assert(installation_callbacks == 1 && !outersshpriv_is_waiting(waiters));
        free(*installed_path);
        *installed_path = NULL;
        *installed_length = 0;
        assert(test_pool.pending_operations == 0);
    }
    for (unsigned failure = 0; failure < 2; failure++) {
        fail_installation_allocation = failure != 0;
        outersshpriv_proxy_cleanup_bridge_executables(&test_pool, NULL, NULL);
        assert(test_pool.pending_operations == 0);
    }
    fail_installation_allocation = false;
    run_stage(NULL);
}

static unsigned windows_completions;
static void windows_bridge_missing(void *context, OuterSSHError error)
{
    (void)context;
    assert(error.domain != OUTERSSH_ERROR_NONE && test_pool._userBridgeExecutablePath == NULL);
    windows_completions++;
}
static unsigned unsupported_platform_completions;
static void unsupported_platform_rejected(void *context, OuterSSHError error)
{
    (void)context;
    assert(error.domain == OUTERSSH_ERROR_HELPER_INSTALLER);
    assert(error.code == OUTERSSH_HELPER_INSTALLER_ERROR_UNSUPPORTED_PLATFORM);
    assert(error.message_length != 0);
    unsupported_platform_completions++;
}

static void test_unsupported_platforms(void)
{
    const char *unsupported[] = {"armv6l glibc", "i686 glibc", "aarch64 unknown", "aarch64 glibc extra", ""};
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
        SSHWaiter waiter;
        test_pool._remotePlatform = (char *)unsupported[i];
        test_pool._remotePlatformLength = strlen(unsupported[i]);
        outersshpriv_proxy_ensure_user_bridge_executable(&test_pool, &waiter, unsupported_platform_rejected, NULL);
        assert(unsupported_platform_completions == i + 1 && binary_questions == 0);
        assert(test_pool._userBridgeInstall == SSH_BRIDGE_INSTALL_IDLE && !test_pool._bridgeBinaryRequested);
    }
    test_pool._remotePlatform = NULL;
    test_pool._remotePlatformLength = 0;
}

static void test_synced_windows_bridge(void *context)
{
    test_unsupported_platforms();
    atomic_store(&test_pool._commandDialect, OUTERSSH_COMMAND_DIALECT_WINDOWS);
    SSHWaiter waiter;
    test_pool._remotePlatform = strdup("amd64 windows");
    test_pool._remotePlatformLength = strlen(test_pool._remotePlatform);
    decline_bridge_binaries = true;
    outersshpriv_proxy_ensure_user_bridge_executable(&test_pool, &waiter, windows_bridge_missing, NULL);
    assert(windows_completions == 1 && test_pool._userBridgeExecutablePath == NULL);
    assert(binary_questions == 1);
    assert(!test_pool._userBridgeIsPreinstalled && test_pool._userBridgeInstall == SSH_BRIDGE_INSTALL_IDLE);
    decline_bridge_binaries = false;
    binary_questions = 0;
    free(test_pool._remotePlatform);
    test_pool._remotePlatform = NULL;
    test_pool._remotePlatformLength = 0;
    atomic_store(&test_pool._commandDialect, OUTERSSH_COMMAND_DIALECT_UNKNOWN);
    (void)context;
    listener_active = true;
    test_listener = &test_pool;
    test_pool._remoteUserIsRoot = 1;
    otqueue_async(test_pool._queue, NULL, test_installation_waiters);
}

int main(void)
{
    test_connection = (SSHProxyConnection){&test_server, &test_pool, 1};
    test_pool.pending_operations = 0;
    test_pool._queue = ssh_test_control_queue_create("bridge-flow-test");
    test_pool._connectorReactor = (ProxyReactor *)&test_pool;
    test_server.reactor = test_pool._connectorReactor;
    test_server.queue = test_pool._queue;
    test_pool._userBridgeInstallID = "user-id";
    test_pool._userBridgeInstallID_length = sizeof("user-id") - 1;
    test_pool._sudoBridgeInstallID = "sudo-id";
    test_pool._sudoBridgeInstallID_length = sizeof("sudo-id") - 1;
    reactor_queue = ssh_test_control_queue_create("bridge-reactor-test");
    finished = ssh_test_semaphore_create(0);
    otqueue_async(test_pool._queue, NULL, test_synced_windows_bridge);
    assert(ssh_test_semaphore_wait(finished, 10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(finished);
    otqueue_release(reactor_queue);
    otqueue_release(test_pool._queue);
    puts("PASS: bridge executable installation, bridge lifetime, stream ownership, endpoint validation, and allocation cleanup");
    return 0;
}

void outersshpriv_proxy_connection_begin_work(SSHProxyConnection connection)
{
    outersshpriv_session_pool_begin_operation(connection.pool);
}
void outersshpriv_proxy_connection_end_work(SSHProxyConnection connection)
{
    outersshpriv_session_pool_end_operation(connection.pool);
}
SSHProxyConnection outersshpriv_proxy_active_connection(SSHProxyConnection connection)
{
    if (outersshpriv_session_pool_active(connection.pool) == NULL) connection.pool = NULL;
    return connection;
}
bool outersshpriv_proxy_connection_is_active(SSHProxyConnection connection)
{
    return outersshpriv_proxy_active_connection(connection).pool != NULL;
}
