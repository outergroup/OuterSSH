#include "SSHEventsInternal.h"
#include "SSHProxyErrorInternal.h"

#include <assert.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SSHFlows.h"
#include "SSHSocketBridgeInternal.h"
#include "SocketBridgeCommands.h"

#pragma mark - Execute a Command

/* A command reports either to its reply (a public request) or to the engine
 * step that started it. */
struct ExecuteCommandContext {
    SSHPoolEvent *reply;
    SSHWaiter waiter;
    SSHCommandHandler completion;
    void *completion_context;
    SSHCommandRequest request;
    OuterSSHSessionPool *pool;
    SSHSessionPoolSessionHandle session;
    SSHReactor *starting_reactor;
    ExecuteCommandContext *next_held;
    bool windows_admitted;
    bool may_retry;
    SSHReactorCommandResult completed_result;
    void *completed_stdout;
    size_t completed_stdout_byte_count;
    void *completed_stderr;
    size_t completed_stderr_byte_count;
    int32_t completed_exit_status;
    uint32_t completed_reason;
    unsigned char bytes[];
};

static const uint64_t channel_open_timeout_milliseconds = 5000;
static const uint64_t execution_timeout_milliseconds = 300000;

static void ssh_command_session_request_finished(void *context, OuterSSHError error);
static bool hold_for_windows_input(ExecuteCommandContext *command_context);
static void release_windows_admission(ExecuteCommandContext *command_context);
static void start_command_on_pool(void *opaque_context);
static void continue_command_on_pool(ExecuteCommandContext *command_context);
static void start_command_on_reactor(void *opaque_context);
static void finish_command_on_pool(void *opaque_context);
static void finish_command(
    ExecuteCommandContext *command_context,
    OuterSSHError error);
static void destroy_command_context(ExecuteCommandContext *command_context);
static OuterSSHError command_error(
    char **storage,
    SSHReactorCommandResult result,
    const char *command,
    size_t command_byte_count,
    uint32_t reason);

bool outerssh_session_pool_execute_command(
    OuterSSHSessionPool *pool,
    const char *command,
    size_t command_byte_count,
    const void *standard_input,
    size_t standard_input_byte_count,
    uint64_t tag)
{
    if (command == NULL || command_byte_count > INT_MAX ||
        (standard_input == NULL && standard_input_byte_count != 0) ||
        standard_input_byte_count > SIZE_MAX - sizeof(ExecuteCommandContext) - command_byte_count) return false;
    ExecuteCommandContext *command_context = malloc(
        sizeof(*command_context) + command_byte_count + standard_input_byte_count);
    SSHPoolEvent *reply = command_context == NULL ? NULL
        : outersshpriv_reply_reserve(pool, OUTERSSH_EVENT_COMMAND_COMPLETED, tag);
    if (reply == NULL) {
        free(command_context);
        return false;
    }
    *command_context = (ExecuteCommandContext){
        .pool = pool,
        .reply = reply,
        .request = {
            .command = (const char *)command_context->bytes,
            .command_byte_count = command_byte_count,
            .standard_input = standard_input_byte_count == 0
                ? NULL : command_context->bytes + command_byte_count,
            .standard_input_byte_count = standard_input_byte_count,
        },
    };
    memcpy(command_context->bytes, command, command_byte_count);
    if (standard_input_byte_count != 0)
        memcpy(command_context->bytes + command_byte_count, standard_input, standard_input_byte_count);
    otqueue_async(pool->_queue, command_context, start_command_on_pool);
    return true;
}

void outersshpriv_execute_command(
    OuterSSHSessionPool *pool,
    SSHCommandRequest request,
    SSHCommandHandler completion,
    void *context)
{
    otqueue_assert(pool->_queue);
    outersshpriv_session_pool_begin_operation(pool);
    if (request.command == NULL || request.command_byte_count > INT_MAX ||
        (request.standard_input_prefix == NULL && request.standard_input_prefix_byte_count != 0) ||
        (request.standard_input == NULL && request.standard_input_byte_count != 0)) {
        static const char invalid_input_message[] = "Invalid SSH command input.";
        OuterSSHError error = outerssh_session_error(OUTERSSH_SESSION_ERROR_COMMAND_REQUEST_DENIED,
            invalid_input_message, sizeof(invalid_input_message) - 1);
        if (request.release_command != NULL) {
            request.release_command(request.release_command_context);
        }
        if (request.release_input != NULL) {
            request.release_input(request.release_input_context);
        }
        completion(context, NULL, error);
        outersshpriv_session_pool_end_operation(pool);
        return;
    }
    ExecuteCommandContext *command_context = calloc(1, sizeof(*command_context));
    if (command_context == NULL) {
        static const char error_message[] = "Failed to allocate an SSH command context.";
        if (request.release_command != NULL) {
            request.release_command(request.release_command_context);
        }
        if (request.release_input != NULL) {
            request.release_input(request.release_input_context);
        }
        completion(
            context,
            NULL,
            outersshpriv_proxy_error(
                OUTERSSH_PROXY_ERROR_REACTOR_CREATION_FAILED,
                error_message, sizeof(error_message) - 1,
                0));
        outersshpriv_session_pool_end_operation(pool);
        return;
    }
    *command_context = (ExecuteCommandContext){
        .pool = pool,
        .request = request,
        .completion = completion,
        .completion_context = context,
    };
    continue_command_on_pool(command_context);
}

static void start_command_on_pool(void *opaque_context)
{
    ExecuteCommandContext *command_context = opaque_context;
    outersshpriv_session_pool_begin_operation(command_context->pool);
    continue_command_on_pool(command_context);
}

static void continue_command_on_pool(ExecuteCommandContext *command_context)
{
    otqueue_assert(command_context->pool->_queue);
    command_context->may_retry = true;
    if (command_context->pool->shutdown_requested && !command_context->request.during_shutdown) {
        finish_command(command_context, outerssh_proxy_closing_error());
        return;
    }
    outersshpriv_session_pool_run_when_ready(command_context->pool, &command_context->waiter,
        ssh_command_session_request_finished, command_context);
}

static void ssh_command_session_request_finished(void *context, OuterSSHError error)
{
    ExecuteCommandContext *command_context = context;
    otqueue_assert(command_context->pool->_queue);
    if (error.domain == OUTERSSH_ERROR_NONE && hold_for_windows_input(command_context)) return;
    SSHSessionPoolSessionHandle session;
    SSHReactor *reactor = outersshpriv_session_pool_ready_reactor(command_context->pool, &session, &error);
    if (error.domain != OUTERSSH_ERROR_NONE) {
        finish_command(command_context, error);
        return;
    }
    command_context->session = session;
    command_context->starting_reactor = reactor;
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        command_context,
        start_command_on_reactor);
}

/* Windows OpenSSH stalls a command's standard input when another command
 * starts or exits on the same connection while that input is being delivered.
 * On Windows servers a command with standard input therefore runs alone: it
 * waits for running commands to finish, and later commands wait for it. Held
 * commands start in order. */
static bool has_standard_input(const ExecuteCommandContext *command_context)
{
    return command_context->request.standard_input_byte_count ||
        command_context->request.standard_input_prefix_byte_count;
}

static bool windows_admits(const OuterSSHSessionPool *pool, const ExecuteCommandContext *command_context)
{
    return pool->_windowsInputCommand == NULL &&
        (!has_standard_input(command_context) || pool->_windowsRunningCommands == 0);
}

static void admit_windows_command(ExecuteCommandContext *command_context)
{
    OuterSSHSessionPool *pool = command_context->pool;
    command_context->windows_admitted = true;
    pool->_windowsRunningCommands++;
    if (has_standard_input(command_context)) pool->_windowsInputCommand = command_context;
}

static bool hold_for_windows_input(ExecuteCommandContext *command_context)
{
    OuterSSHSessionPool *pool = command_context->pool;
    if (command_context->windows_admitted || atomic_load(&pool->_commandDialect) != OUTERSSH_COMMAND_DIALECT_WINDOWS) return false;
    if (pool->_heldCommands == NULL && windows_admits(pool, command_context)) {
        admit_windows_command(command_context);
        return false;
    }
    command_context->next_held = NULL;
    ExecuteCommandContext **tail = &pool->_heldCommands;
    while (*tail != NULL) tail = &(*tail)->next_held;
    *tail = command_context;
    return true;
}

static void release_windows_admission(ExecuteCommandContext *command_context)
{
    OuterSSHSessionPool *pool = command_context->pool;
    if (!command_context->windows_admitted) return;
    command_context->windows_admitted = false;
    pool->_windowsRunningCommands--;
    if (pool->_windowsInputCommand == command_context) pool->_windowsInputCommand = NULL;
    while (pool->_heldCommands != NULL && windows_admits(pool, pool->_heldCommands)) {
        ExecuteCommandContext *held = pool->_heldCommands;
        pool->_heldCommands = held->next_held;
        held->next_held = NULL;
        admit_windows_command(held);
        outersshpriv_session_pool_run_when_ready(pool, &held->waiter,
            ssh_command_session_request_finished, held);
    }
}

static void start_command_on_reactor(void *opaque_context)
{
    ExecuteCommandContext *command_context = opaque_context;
    SSHReactor *reactor = command_context->starting_reactor;
    command_context->starting_reactor = NULL;
    outersshpriv_reactor_execute_command(
        reactor,
        command_context->request.command,
        command_context->request.command_byte_count,
        command_context->request.standard_input_prefix,
        command_context->request.standard_input_prefix_byte_count,
        command_context->request.standard_input,
        command_context->request.standard_input_byte_count,
        channel_open_timeout_milliseconds,
        command_context->request.execution_timeout_milliseconds
            ? command_context->request.execution_timeout_milliseconds : execution_timeout_milliseconds,
        command_context);
}

void outersshpriv_session_pool_command_completed(
    ExecuteCommandContext *command_context,
    SSHReactorCommandResult result,
    void *stdout_bytes,
    size_t stdout_byte_count,
    void *stderr_bytes,
    size_t stderr_byte_count,
    int32_t exit_status,
    int32_t error_code,
    uint32_t channel_open_reason)
{
    (void)error_code;
    command_context->completed_result = result;
    command_context->completed_stdout = stdout_bytes;
    command_context->completed_stdout_byte_count = stdout_byte_count;
    command_context->completed_stderr = stderr_bytes;
    command_context->completed_stderr_byte_count = stderr_byte_count;
    command_context->completed_exit_status = exit_status;
    command_context->completed_reason = channel_open_reason;
    otqueue_async(
        command_context->pool->_queue,
        command_context,
        finish_command_on_pool);
}

static void finish_command_on_pool(void *opaque_context)
{
    ExecuteCommandContext *command_context = opaque_context;
    OuterSSHSessionPool *pool = command_context->pool;
    otqueue_assert(pool->_queue);
    SSHReactorCommandResult result = command_context->completed_result;
    if (result == SSH_REACTOR_COMMAND_COMPLETED) {
        finish_command(command_context, (OuterSSHError){0});
        return;
    }
    if (command_context->may_retry &&
        (result == SSH_REACTOR_COMMAND_CHANNEL_OPEN_SESSION_CLOSED ||
         result == SSH_REACTOR_COMMAND_CHANNEL_OPEN_START_FAILED ||
         result == SSH_REACTOR_COMMAND_CHANNEL_OPEN_TIMED_OUT)) {
        outersshpriv_remove_session(pool, command_context->session);
        command_context->session = (SSHSessionPoolSessionHandle){0};
        command_context->may_retry = false;
        free(command_context->completed_stdout);
        free(command_context->completed_stderr);
        command_context->completed_stdout = NULL;
        command_context->completed_stdout_byte_count = 0;
        command_context->completed_stderr = NULL;
        command_context->completed_stderr_byte_count = 0;
        outersshpriv_session_pool_run_when_ready(pool, &command_context->waiter,
            ssh_command_session_request_finished, command_context);
        return;
    }
    char *error_storage = NULL;
    OuterSSHError error = command_error(&error_storage,
        result, command_context->request.command, command_context->request.command_byte_count, command_context->completed_reason);
    finish_command(command_context, error);
    free(error_storage);
}

static void finish_command(
    ExecuteCommandContext *command_context,
    OuterSSHError error)
{
    release_windows_admission(command_context);
    SSHCommandOutput command_result = {0};
    const SSHCommandOutput *result_value = NULL;
    if (error.domain == OUTERSSH_ERROR_NONE &&
        command_context->completed_result == SSH_REACTOR_COMMAND_COMPLETED) {
        command_result = (SSHCommandOutput){
            .stdout_bytes = command_context->completed_stdout,
            .stdout_byte_count = command_context->completed_stdout_byte_count,
            .stderr_bytes = command_context->completed_stderr,
            .stderr_byte_count = command_context->completed_stderr_byte_count,
            .exit_status = command_context->completed_exit_status
        };
        result_value = &command_result;
    }
    if (command_context->request.release_command != NULL) {
        command_context->request.release_command(command_context->request.release_command_context);
    }
    if (command_context->request.release_input != NULL) {
        command_context->request.release_input(command_context->request.release_input_context);
    }
    if (command_context->reply != NULL) outersshpriv_reply_command(command_context->reply, result_value, error);
    else command_context->completion(command_context->completion_context, result_value, error);
    destroy_command_context(command_context);
}

static void destroy_command_context(ExecuteCommandContext *command_context)
{
    OuterSSHSessionPool *pool = command_context->pool;
    free(command_context->completed_stdout);
    free(command_context->completed_stderr);
    free(command_context);
    outersshpriv_session_pool_end_operation(pool);
}

#pragma mark - Command Errors

static OuterSSHError command_error(
    char **storage,
    SSHReactorCommandResult result,
    const char *command,
    size_t command_byte_count,
    uint32_t reason)
{
    static const char session_unavailable_message[] = "The SSH session is no longer available.";
    static const char command_timeout_message[] = "The SSH command timed out.";
    static const char output_allocation_message[] = "Failed to allocate memory for SSH command output.";
    static const char output_limit_message[] = "The SSH command produced more output than the allowed limit.";
    static const char channel_start_message[] = "Failed to start opening an SSH channel.";
    static const char channel_timeout_message[] = "The remote server took too long to open the channel.";

    switch (result) {
    case SSH_REACTOR_COMMAND_CHANNEL_OPEN_FAILED: {
        OuterSSHError error = outerssh_session_error_format(storage,
            OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE,
            "The SSH server rejected the channel (reason %u).",
            reason);
        error.ssh_channel_open_reason = reason;
        return error;
    }
    case SSH_REACTOR_COMMAND_CHANNEL_OPEN_TIMED_OUT:
        return outerssh_session_error(OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_TIMED_OUT,
            channel_timeout_message, sizeof(channel_timeout_message) - 1);
    case SSH_REACTOR_COMMAND_CHANNEL_OPEN_START_FAILED:
        return outerssh_session_error(OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_START_FAILED,
            channel_start_message, sizeof(channel_start_message) - 1);
    case SSH_REACTOR_COMMAND_REQUEST_FAILED:
    case SSH_REACTOR_COMMAND_EXEC_START_FAILED:
        return outerssh_session_error_format(storage,
            OUTERSSH_SESSION_ERROR_COMMAND_REQUEST_DENIED,
            "The SSH server denied request for command '%.*s'.",
            (int)command_byte_count, command);
    case SSH_REACTOR_COMMAND_OUTPUT_LIMIT_EXCEEDED:
        return outerssh_session_error(OUTERSSH_SESSION_ERROR_COMMAND_OUTPUT_LIMIT_EXCEEDED,
            output_limit_message, sizeof(output_limit_message) - 1);
    case SSH_REACTOR_COMMAND_OUTPUT_ALLOCATION_FAILED:
        return outerssh_session_error(OUTERSSH_SESSION_ERROR_COMMAND_OUTPUT_ALLOCATION_FAILED,
            output_allocation_message, sizeof(output_allocation_message) - 1);
    case SSH_REACTOR_COMMAND_TIMED_OUT:
        return outerssh_session_error(OUTERSSH_SESSION_ERROR_COMMAND_TIMED_OUT,
            command_timeout_message, sizeof(command_timeout_message) - 1);
    default:
        return outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE,
            session_unavailable_message, sizeof(session_unavailable_message) - 1);
    }
}
