#include "SSHReactor.h"
#include "SSHReactorCommandInternal.h"
#include "SSHFlows.h"

#include <libssh2.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef SSHReactorCommand SSHCommand;
typedef SSHReactorCommandResult SSHCommandResult;

typedef struct {
    unsigned char *bytes;
    size_t byte_count;
    size_t capacity;
} SSHCommandBuffer;

typedef enum {
    SSH_COMMAND_PHASE_OPENING_CHANNEL,
    SSH_COMMAND_PHASE_EXECUTING,
    SSH_COMMAND_PHASE_AWAITING_REMOTE_CLOSE,
    SSH_COMMAND_PHASE_TERMINAL
} SSHCommandPhase;

struct SSHReactorCommand {
    size_t reference_count;
    SSHReactor *reactor;
    otqueue_t queue;
    const unsigned char *command;
    size_t command_byte_count;
    const unsigned char *input_prefix;
    size_t input_prefix_byte_count;
    const unsigned char *input;
    size_t input_byte_count;
    SSHCommandBuffer standard_output;
    SSHCommandBuffer standard_error;
    size_t output_byte_count;
    ExecuteCommandContext *operation;
    otsource_t execution_timeout_timer;
    uint64_t execution_timeout_milliseconds;
    uint64_t execution_timeout_generation;
    SSHReactorChannelToken channel_token;
    int32_t exit_status;
    int32_t request_error_code;
    SSHCommandResult pending_result;
    SSHCommandPhase phase;
    bool channel_open_started;
    bool request_succeeded;
    bool has_pending_result;
    bool did_complete;
    bool channel_reference_held;
};

typedef enum {
    SSH_COMMAND_BUFFER_APPEND_SUCCEEDED,
    SSH_COMMAND_BUFFER_APPEND_LIMIT_EXCEEDED,
    SSH_COMMAND_BUFFER_APPEND_ALLOCATION_FAILED
} SSHCommandBufferAppendResult;

typedef struct {
    SSHCommand *command;
    otsource_t timer;
    uint64_t generation;
} SSHCommandExecutionTimerContext;

static SSHCommand *create_command(
    SSHReactor *reactor,
    const void *command_bytes,
    size_t command_byte_count,
    const void *input_prefix_bytes,
    size_t input_prefix_byte_count,
    const void *input_bytes,
    size_t input_byte_count,
    uint64_t execution_timeout_milliseconds,
    ExecuteCommandContext *operation);
static void finish_command_channel_open(
    SSHCommand *command,
    SSHReactorChannelOpenResult result,
    uint32_t reason);
static void start_command_exec(
    SSHCommand *command);
static SSHCommandBufferAppendResult command_buffer_append(
    SSHCommand *command,
    SSHCommandBuffer *buffer,
    const void *bytes,
    size_t byte_count);
static void finish_command_after_remote_close(SSHCommand *command);
static void finish_command_after_session_close(SSHCommand *command);
static void record_command_terminal_failure(
    SSHCommand *command,
    SSHCommandResult result,
    int32_t error_code);
static void finish_command_execution(
    SSHCommand *command,
    SSHCommandResult result,
    int32_t error_code,
    uint32_t reason,
    bool close_remote_channel);
static void release_channel_reference(SSHCommand *command);
static bool start_execution_timeout(
    SSHCommand *command);
static void execution_timeout_timer_fired(void *context);
static void cancel_execution_timeout(SSHCommand *command);
static void advance_timeout_generation(SSHCommand *command);
static void execution_timeout_timer_cancelled(void *context);
static void destroy_command(SSHCommand *command);
static SSHCommand *retain_command(SSHCommand *command);
static void release_command(SSHCommand *command);

#pragma mark - Execute a Command

void outersshpriv_reactor_execute_command(
    SSHReactor *reactor,
    const void *command_bytes,
    size_t command_byte_count,
    const void *input_prefix_bytes,
    size_t input_prefix_byte_count,
    const void *input_bytes,
    size_t input_byte_count,
    uint64_t channel_open_timeout_milliseconds,
    uint64_t execution_timeout_milliseconds,
    ExecuteCommandContext *operation)
{
    if (operation == NULL) {
        return;
    }
    if (reactor == NULL ||
        (command_byte_count != 0 && command_bytes == NULL) ||
        (input_prefix_byte_count != 0 && input_prefix_bytes == NULL) ||
        (input_byte_count != 0 && input_bytes == NULL) ||
        channel_open_timeout_milliseconds == 0 ||
        execution_timeout_milliseconds == 0 ||
        channel_open_timeout_milliseconds >
            INT64_MAX / NSEC_PER_MSEC ||
        execution_timeout_milliseconds >
            INT64_MAX / NSEC_PER_MSEC) {
        outersshpriv_session_pool_command_completed(
            operation,
            SSH_REACTOR_COMMAND_CHANNEL_OPEN_START_FAILED,
            NULL,
            0,
            NULL,
            0,
            -1,
            LIBSSH2_ERROR_INVAL,
            0);
        return;
    }

    otqueue_assert(outersshpriv_reactor_queue(reactor));
    SSHCommand *command = create_command(
        reactor,
        command_bytes,
        command_byte_count,
        input_prefix_bytes,
        input_prefix_byte_count,
        input_bytes,
        input_byte_count,
        execution_timeout_milliseconds,
        operation);
    if (command == NULL) {
        outersshpriv_session_pool_command_completed(
            operation,
            SSH_REACTOR_COMMAND_CHANNEL_OPEN_START_FAILED,
            NULL,
            0,
            NULL,
            0,
            -1,
            LIBSSH2_ERROR_ALLOC,
            0);
        return;
    }

    retain_command(command);
    command->channel_reference_held = true;
    command->channel_open_started = true;
    int result = outersshpriv_reactor_open_command_session(
        reactor,
        &command->channel_token,
        channel_open_timeout_milliseconds,
        command);
    if (result != 0) {
        command->channel_open_started = false;
        finish_command_execution(
            command,
            SSH_REACTOR_COMMAND_CHANNEL_OPEN_START_FAILED,
            result,
            0,
            false);
        release_channel_reference(command);
    }
    release_command(command);
}

static SSHCommand *create_command(
    SSHReactor *reactor,
    const void *command_bytes,
    size_t command_byte_count,
    const void *input_prefix_bytes,
    size_t input_prefix_byte_count,
    const void *input_bytes,
    size_t input_byte_count,
    uint64_t execution_timeout_milliseconds,
    ExecuteCommandContext *operation)
{
    SSHCommand *command = calloc(1, sizeof(*command));
    if (command == NULL) {
        return NULL;
    }
    command->reference_count = 1;
    command->reactor = reactor;
    command->queue = outersshpriv_reactor_queue(reactor);
    if (command->queue != NULL) {
        otqueue_retain(command->queue);
    }
    command->exit_status = -1;
    command->request_error_code = LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED;
    command->execution_timeout_milliseconds =
        execution_timeout_milliseconds;
    command->phase = SSH_COMMAND_PHASE_OPENING_CHANNEL;
    command->command_byte_count = command_byte_count;
    command->command = command_bytes;
    command->input_prefix = input_prefix_bytes;
    command->input_prefix_byte_count = input_prefix_byte_count;
    command->input = input_bytes;
    command->input_byte_count = input_byte_count;
    if (command->queue == NULL) {
        release_command(command);
        return NULL;
    }
    command->operation = operation;
    return command;
}

void outersshpriv_reactor_command_handle_channel_open(
    SSHReactorCommand *command,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason)
{
    command->channel_token = channel_token;
    finish_command_channel_open(command, result, reason);
}

static void finish_command_channel_open(
    SSHCommand *command,
    SSHReactorChannelOpenResult result,
    uint32_t reason)
{
    if (command->did_complete) {
        return;
    }
    switch (result) {
    case SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED:
        start_command_exec(command);
        break;
    case SSH_REACTOR_CHANNEL_OPEN_FAILED:
        finish_command_execution(
            command,
            SSH_REACTOR_COMMAND_CHANNEL_OPEN_FAILED,
            0,
            reason,
            false);
        release_channel_reference(command);
        break;
    case SSH_REACTOR_CHANNEL_OPEN_TIMED_OUT:
        finish_command_execution(
            command,
            SSH_REACTOR_COMMAND_CHANNEL_OPEN_TIMED_OUT,
            0,
            reason,
            false);
        release_channel_reference(command);
        break;
    case SSH_REACTOR_CHANNEL_OPEN_SESSION_CLOSED:
        finish_command_execution(
            command,
            SSH_REACTOR_COMMAND_CHANNEL_OPEN_SESSION_CLOSED,
            0,
            reason,
            false);
        release_channel_reference(command);
        break;
    }
}

static void start_command_exec(
    SSHCommand *command)
{
    int result = outersshpriv_reactor_start_command(
        command->reactor,
        command->channel_token,
        (const char *)command->command,
        command->command_byte_count,
        command->input_prefix,
        command->input_prefix_byte_count,
        command->input,
        command->input_byte_count,
        true,
        command);
    if (result != 0) {
        finish_command_execution(
            command,
            SSH_REACTOR_COMMAND_EXEC_START_FAILED,
            result,
            0,
            true);
        release_channel_reference(command);
        return;
    }
    if (command->did_complete) {
        return;
    }
    if (!command->has_pending_result) {
        command->phase = SSH_COMMAND_PHASE_EXECUTING;
    }
    if (!start_execution_timeout(command)) {
        finish_command_execution(
            command,
            SSH_REACTOR_COMMAND_EXEC_START_FAILED,
            LIBSSH2_ERROR_ALLOC,
            0,
            true);
    }
}

#pragma mark - Receive Command Results

void outersshpriv_reactor_command_request_succeeded(SSHReactorCommand *command)
{
    if (!command->did_complete && !command->has_pending_result) {
        command->request_succeeded = true;
    }
}

void outersshpriv_reactor_command_request_failed(SSHReactorCommand *command, int error_code)
{
    record_command_terminal_failure(
        command,
        SSH_REACTOR_COMMAND_REQUEST_FAILED,
        error_code);
}

void outersshpriv_reactor_command_received_data(SSHReactorCommand *command, uint32_t stream_id,
    const void *data, size_t data_length)
{
    if (command->did_complete || data_length == 0 ||
        command->has_pending_result) {
        return;
    }
    SSHCommandBuffer *buffer = stream_id == 0
        ? &command->standard_output
        : &command->standard_error;
    SSHCommandBufferAppendResult append_result = command_buffer_append(
        command,
        buffer,
        data,
        data_length);
    if (append_result == SSH_COMMAND_BUFFER_APPEND_LIMIT_EXCEEDED) {
        record_command_terminal_failure(
            command,
            SSH_REACTOR_COMMAND_OUTPUT_LIMIT_EXCEEDED,
            LIBSSH2_ERROR_OUT_OF_BOUNDARY);
    } else if (append_result ==
               SSH_COMMAND_BUFFER_APPEND_ALLOCATION_FAILED) {
        record_command_terminal_failure(
            command,
            SSH_REACTOR_COMMAND_OUTPUT_ALLOCATION_FAILED,
            LIBSSH2_ERROR_ALLOC);
    }
}

static SSHCommandBufferAppendResult command_buffer_append(
    SSHCommand *command,
    SSHCommandBuffer *buffer,
    const void *bytes,
    size_t byte_count)
{
    if (byte_count == 0) {
        return SSH_COMMAND_BUFFER_APPEND_SUCCEEDED;
    }
    if (bytes == NULL ||
        byte_count > SSH_REACTOR_COMMAND_MAXIMUM_OUTPUT_BYTE_COUNT ||
        command->output_byte_count >
            SSH_REACTOR_COMMAND_MAXIMUM_OUTPUT_BYTE_COUNT - byte_count) {
        return SSH_COMMAND_BUFFER_APPEND_LIMIT_EXCEEDED;
    }
    if (buffer->byte_count > SIZE_MAX - byte_count) {
        return SSH_COMMAND_BUFFER_APPEND_ALLOCATION_FAILED;
    }
    size_t required_capacity = buffer->byte_count + byte_count;
    if (required_capacity > buffer->capacity) {
        size_t capacity = buffer->capacity == 0 ? 4096 : buffer->capacity;
        while (capacity < required_capacity) {
            if (capacity > SIZE_MAX / 2) {
                capacity = required_capacity;
                break;
            }
            capacity *= 2;
        }
        unsigned char *new_bytes = realloc(buffer->bytes, capacity);
        if (new_bytes == NULL) {
            return SSH_COMMAND_BUFFER_APPEND_ALLOCATION_FAILED;
        }
        buffer->bytes = new_bytes;
        buffer->capacity = capacity;
    }
    memcpy(buffer->bytes + buffer->byte_count, bytes, byte_count);
    buffer->byte_count = required_capacity;
    command->output_byte_count += byte_count;
    return SSH_COMMAND_BUFFER_APPEND_SUCCEEDED;
}

void outersshpriv_reactor_command_received_exit_status(SSHReactorCommand *command, int32_t exit_status)
{
    if (!command->did_complete) {
        command->exit_status = exit_status;
    }
}

void outersshpriv_reactor_command_channel_closed(SSHReactorCommand *command)
{
    finish_command_after_remote_close(command);
}

static void finish_command_after_remote_close(SSHCommand *command)
{
    if (command->did_complete) {
        release_channel_reference(command);
        return;
    }
    if (command->has_pending_result) {
        finish_command_execution(
            command,
            command->pending_result,
            command->request_error_code,
            0,
            false);
        release_channel_reference(command);
        return;
    }
    SSHCommandResult result = command->request_succeeded
        ? SSH_REACTOR_COMMAND_COMPLETED
        : SSH_REACTOR_COMMAND_REQUEST_FAILED;
    int32_t error_code = command->request_succeeded
        ? 0
        : command->request_error_code;
    finish_command_execution(
        command,
        result,
        error_code,
        0,
        false);
    release_channel_reference(command);
}

void outersshpriv_reactor_command_handle_session_closed(SSHReactorCommand *command)
{
    finish_command_after_session_close(command);
}

static void finish_command_after_session_close(SSHCommand *command)
{
    if (command->did_complete) {
        release_channel_reference(command);
        return;
    }
    if (command->has_pending_result) {
        finish_command_execution(
            command,
            command->pending_result,
            command->request_error_code,
            0,
            false);
        release_channel_reference(command);
        return;
    }
    finish_command_execution(
        command,
        SSH_REACTOR_COMMAND_SESSION_CLOSED,
        0,
        0,
        false);
    release_channel_reference(command);
}

static void record_command_terminal_failure(
    SSHCommand *command,
    SSHCommandResult result,
    int32_t error_code)
{
    if (command->did_complete || command->has_pending_result) {
        return;
    }
    command->has_pending_result = true;
    command->pending_result = result;
    command->request_error_code = error_code;
    command->phase = SSH_COMMAND_PHASE_AWAITING_REMOTE_CLOSE;
    outersshpriv_reactor_close_command(
        command->reactor,
        command->channel_token,
        false);
}

#pragma mark - Complete the Command

static void finish_command_execution(
    SSHCommand *command,
    SSHCommandResult result,
    int32_t error_code,
    uint32_t reason,
    bool close_remote_channel)
{
    if (command->did_complete) {
        return;
    }

    retain_command(command);
    SSHCommandPhase previous_phase = command->phase;
    command->did_complete = true;
    command->phase = SSH_COMMAND_PHASE_TERMINAL;
    cancel_execution_timeout(command);
    ExecuteCommandContext *operation = command->operation;
    command->operation = NULL;

    if (close_remote_channel && command->channel_open_started &&
        previous_phase != SSH_COMMAND_PHASE_AWAITING_REMOTE_CLOSE) {
        if (previous_phase == SSH_COMMAND_PHASE_OPENING_CHANNEL) {
            outersshpriv_reactor_close_channel(
                command->reactor,
                command->channel_token,
                false);
        } else {
            outersshpriv_reactor_close_command(
                command->reactor,
                command->channel_token,
                false);
        }
    }

    SSHCommandBuffer standard_output = command->standard_output;
    SSHCommandBuffer standard_error = command->standard_error;
    command->standard_output = (SSHCommandBuffer){0};
    command->standard_error = (SSHCommandBuffer){0};
    command->output_byte_count = 0;
    // Completion can free the operation's input or start another attempt on its queue.
    if (command->channel_open_started) {
        outersshpriv_reactor_forget_command_input(command->reactor, command->channel_token, command);
    }
    command->command = NULL;
    command->command_byte_count = 0;
    command->input_prefix = NULL;
    command->input_prefix_byte_count = 0;
    command->input = NULL;
    command->input_byte_count = 0;
    outersshpriv_session_pool_command_completed(
        operation,
        result,
        standard_output.bytes,
        standard_output.byte_count,
        standard_error.bytes,
        standard_error.byte_count,
        command->exit_status,
        error_code,
        reason);
    release_command(command);
}

static void release_channel_reference(SSHCommand *command)
{
    if (!command->channel_reference_held) {
        return;
    }
    command->channel_reference_held = false;
    release_command(command);
}

#pragma mark - Enforce Execution Deadlines

static bool start_execution_timeout(
    SSHCommand *command)
{
    otsource_t timer = otsource_create(
        OTSOURCE_TYPE_TIMER,
        0,
        command->queue);
    if (timer == NULL) {
        return false;
    }
    SSHCommandExecutionTimerContext *timer_context = malloc(
        sizeof(*timer_context));
    if (timer_context == NULL) {
        otsource_release(timer);
        return false;
    }
    advance_timeout_generation(command);
    command->execution_timeout_timer = timer;
    *timer_context = (SSHCommandExecutionTimerContext){
        .command = retain_command(command),
        .timer = timer,
        .generation = command->execution_timeout_generation
    };
    otsource_set_context(timer, timer_context);
    otsource_set_cancel_handler(
        timer,
        execution_timeout_timer_cancelled);
    otsource_set_event_handler(timer, execution_timeout_timer_fired);
    otsource_set_timer(
        timer,
        ottime(
            OTTIME_NOW,
            (int64_t)(command->execution_timeout_milliseconds *
                NSEC_PER_MSEC)),
        OTTIME_FOREVER,
        100 * NSEC_PER_MSEC);
    otsource_activate(timer);
    return true;
}

static void execution_timeout_timer_fired(void *context)
{
    SSHCommandExecutionTimerContext *timer_context = context;
    SSHCommand *command = timer_context->command;
    if (command->did_complete ||
        command->execution_timeout_timer != timer_context->timer ||
        command->execution_timeout_generation != timer_context->generation) {
        return;
    }
    command->execution_timeout_timer = NULL;
    advance_timeout_generation(command);
    otsource_cancel(timer_context->timer);
    otsource_release(timer_context->timer);
    finish_command_execution(
        command,
        SSH_REACTOR_COMMAND_TIMED_OUT,
        LIBSSH2_ERROR_TIMEOUT,
        0,
        true);
}

static void cancel_execution_timeout(SSHCommand *command)
{
    otsource_t timer = command->execution_timeout_timer;
    if (timer == NULL) {
        return;
    }
    command->execution_timeout_timer = NULL;
    advance_timeout_generation(command);
    otsource_cancel(timer);
    otsource_release(timer);
}

static void advance_timeout_generation(SSHCommand *command)
{
    command->execution_timeout_generation += 1;
    if (command->execution_timeout_generation == 0) {
        command->execution_timeout_generation = 1;
    }
}

static void execution_timeout_timer_cancelled(void *context)
{
    SSHCommandExecutionTimerContext *timer_context = context;
    release_command(timer_context->command);
    free(timer_context);
}

#pragma mark - Command Lifetime

static void release_command(SSHCommand *command)
{
    if (command == NULL) {
        return;
    }
    if (command->queue != NULL) {
        otqueue_assert(command->queue);
    }
    assert(command->reference_count != 0);
    if (--command->reference_count == 0) {
        destroy_command(command);
    }
}

static void destroy_command(SSHCommand *command)
{
    if (command->execution_timeout_timer != NULL) {
        otsource_cancel(command->execution_timeout_timer);
        otsource_release(command->execution_timeout_timer);
        command->execution_timeout_timer = NULL;
    }
    command->operation = NULL;
    free(command->standard_output.bytes);
    free(command->standard_error.bytes);
    if (command->queue != NULL) {
        otqueue_release(command->queue);
        command->queue = NULL;
    }
    free(command);
}

static SSHCommand *retain_command(SSHCommand *command)
{
    otqueue_assert(command->queue);
    assert(command->reference_count != 0 && command->reference_count != SIZE_MAX);
    command->reference_count++;
    return command;
}
