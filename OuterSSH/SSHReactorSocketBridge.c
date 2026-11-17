#include "SSHReactorInternal.h"
#include "SSHSessionPoolInternal.h"
#include "platform/SSHLogging.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const size_t SocketBridgeBufferLimit = 4 * 1024 * 1024;
static const size_t SocketBridgeReadChunkSize = 64 * 1024;
static const uint64_t SocketBridgePingIntervalNanoseconds = 15 * NSEC_PER_SEC;
static const uint64_t SocketBridgePingLeewayNanoseconds = 2 * NSEC_PER_SEC;

// Forward declarations for steps shared by the flows below.
static void socket_bridge_stream_socket_ready(void *opaque_context);
static bool socket_bridge_forward_remote_to_local(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SocketBridgeStream *stream,
    const void *bytes,
    size_t byte_count);
static bool socket_bridge_send_frame(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    HelperFrameType type,
    uint32_t stream_id,
    const void *payload,
    size_t payload_length);
static void release_socket_bridge_window_credit_for_handle(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle);
static size_t socket_bridge_buffered_remote_byte_count(
    SocketBridge *bridge);
static bool reserve_byte_buffer(
    unsigned char **bytes,
    size_t *capacity,
    size_t minimum_capacity);
static bool remove_socket_bridge_stream(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SocketBridgeStream *stream);
static void socket_bridge_stream_source_cancelled_context(
    void *opaque_context);
static bool remove_socket_bridge_stream_by_id(
    SocketBridge *bridge,
    SocketBridgeStream *stream);
static void close_socket_bridge(SSHReactor *reactor, SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result, const void *detail, size_t detail_length);
static void close_socket_bridge_channel(SSHReactor *reactor,
    SSHReactorChannelToken channel_token, bool send_eof);
static void finish_socket_bridge(SSHReactor *reactor, SocketBridge *bridge,
    SSHReactorSocketBridgeResult result, uint32_t reason,
    const void *detail, size_t detail_length);
static void cancel_socket_bridge_timer(otsource_t timer);
static bool detach_socket_bridge(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    SocketBridge *detached_bridge);
static void deinitialize_detached_socket_bridge(SocketBridge *bridge);
static void securely_clear_memory(void *bytes, size_t byte_count);
static void recycle_socket_bridge_slot(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle);
static SocketBridgeSlot *socket_bridge_slot_for_handle(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle);
static SocketBridgeStream *socket_bridge_stream_for_handle(
    SocketBridge *bridge,
    SSHReactorSocketBridgeStreamHandle handle);
static SocketBridgeStreamSlot *socket_bridge_stream_slot_for_handle(
    SocketBridge *bridge,
    SSHReactorSocketBridgeStreamHandle handle);
static SocketBridgeStream *socket_bridge_stream_for_id(
    SocketBridge *bridge,
    uint32_t stream_id);
static size_t socket_bridge_stream_id_lower_bound(
    SocketBridge *bridge,
    uint32_t stream_id);
static SocketBridgeStream *socket_bridge_stream_for_slot(
    SocketBridge *bridge,
    size_t index,
    uint64_t generation);
static SSHReactorSocketBridgeStreamHandle socket_bridge_stream_handle(
    SocketBridge *bridge,
    SocketBridgeStream *stream);

#pragma mark - Start the Socket Bridge

static bool reserve_socket_bridge_slots(
    SSHReactor *reactor,
    size_t minimum_capacity);
static void handle_socket_bridge_channel_open(
    SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason);
static int start_socket_bridge_exec(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle);
static int start_socket_bridge_ready_timer(
    SSHReactor *reactor,
    SocketBridge *bridge);
static void socket_bridge_ready_timed_out(void *opaque_context);
static void start_socket_bridge_ping_timer(
    SSHReactor *reactor,
    SocketBridge *bridge);
static void socket_bridge_ping_timer_fired(void *opaque_context);

int outersshpriv_reactor_start_socket_channel(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle *handle,
    SSHSocketChannelCallbacks callbacks,
    const char *command,
    size_t command_length,
    const void *initial_input,
    size_t initial_input_length,
    uint64_t channel_open_timeout_milliseconds,
    uint64_t ready_timeout_milliseconds)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (handle != NULL) {
        *handle = (SSHReactorSocketBridgeHandle){0};
    }
    if (!outersshpriv_reactor_accepts_work(reactor) ||
        handle == NULL || callbacks.completed == NULL ||
        command == NULL || command_length == 0 ||
        initial_input_length > SocketBridgeBufferLimit ||
        (initial_input == NULL && initial_input_length != 0) ||
        channel_open_timeout_milliseconds == 0 ||
        ready_timeout_milliseconds == 0 ||
        channel_open_timeout_milliseconds > INT64_MAX / NSEC_PER_MSEC ||
        ready_timeout_milliseconds > INT64_MAX / NSEC_PER_MSEC ||
        reactor->socket_bridge_slot_count == SIZE_MAX ||
        !reserve_socket_bridge_slots(
            reactor,
            reactor->socket_bridge_slot_count + 1)) {
        return LIBSSH2_ERROR_INVAL;
    }

    size_t index;
    if (reactor->available_socket_bridge_index_count != 0) {
        reactor->available_socket_bridge_index_count -= 1;
        index = reactor->available_socket_bridge_indices[
            reactor->available_socket_bridge_index_count];
    } else {
        index = reactor->socket_bridge_slot_count;
        reactor->socket_bridge_slot_count += 1;
    }
    SocketBridgeSlot *slot = &reactor->socket_bridge_slots[index];
    slot->generation += 1;
    if (slot->generation == 0) {
        slot->generation = 1;
    }
    SSHReactorSocketBridgeHandle current_handle = {
        .index = index,
        .generation = slot->generation
    };

    SocketBridge *bridge = &slot->bridge;
    slot->phase = SOCKET_BRIDGE_SLOT_ACTIVE;
    bridge->handle = current_handle;
    bridge->command = malloc(command_length);
    if (bridge->command != NULL) {
        memcpy(bridge->command, command, command_length);
    }
    if (initial_input_length != 0) {
        bridge->initial_input = malloc(initial_input_length);
        if (bridge->initial_input != NULL) {
            memcpy(
                bridge->initial_input,
                initial_input,
                initial_input_length);
        }
    }
    bridge->command_length = command_length;
    bridge->initial_input_length = initial_input_length;
    bridge->next_stream_id = 1;
    bridge->callbacks = callbacks;
    bridge->ready_timeout_milliseconds = ready_timeout_milliseconds;
    if (bridge->command == NULL ||
        (initial_input_length != 0 && bridge->initial_input == NULL)) {
        SocketBridge detached_bridge = {0};
        if (detach_socket_bridge(
                reactor,
                current_handle,
                &detached_bridge)) {
            deinitialize_detached_socket_bridge(&detached_bridge);
        }
        return LIBSSH2_ERROR_ALLOC;
    }

    SSHReactorChannelToken channel_token = 0;
    int open_result = outersshpriv_reactor_open_session_channel(
        reactor,
        &channel_token,
        channel_open_timeout_milliseconds,
        (SSHReactorPendingChannelOpen){
            .finished = handle_socket_bridge_channel_open,
            .target.socket_bridge_handle = current_handle
        });
    if (open_result != 0) {
        SocketBridge detached_bridge = {0};
        if (detach_socket_bridge(
                reactor,
                current_handle,
                &detached_bridge)) {
            deinitialize_detached_socket_bridge(&detached_bridge);
        }
        return open_result;
    }
    bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, current_handle);
    if (bridge == NULL) {
        outersshpriv_reactor_close_channel(reactor, channel_token, false);
        return LIBSSH2_ERROR_PROTO;
    }
    bridge->channel_token = channel_token;
    *handle = current_handle;
    return 0;
}


static void handle_socket_bridge_channel_open(
    SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason)
{
    SSHReactorSocketBridgeHandle handle = pending->target.socket_bridge_handle;
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        if (result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED) {
            outersshpriv_reactor_close_channel(reactor, channel_token, false);
        }
        return;
    }
    if (result != SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED) {
        SSHReactorSocketBridgeResult bridge_result;
        switch (result) {
        case SSH_REACTOR_CHANNEL_OPEN_FAILED:
            bridge_result = SSH_REACTOR_SOCKET_BRIDGE_CHANNEL_OPEN_FAILED;
            break;
        case SSH_REACTOR_CHANNEL_OPEN_TIMED_OUT:
            bridge_result = SSH_REACTOR_SOCKET_BRIDGE_CHANNEL_OPEN_TIMED_OUT;
            break;
        case SSH_REACTOR_CHANNEL_OPEN_SESSION_CLOSED:
        case SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED:
            bridge_result = SSH_REACTOR_SOCKET_BRIDGE_SESSION_CLOSED;
            break;
        default:
            abort();
        }
        finish_socket_bridge(reactor, bridge, bridge_result, reason, NULL, 0);
        return;
    }
    bridge->channel_token = channel_token;
    int exec_result = start_socket_bridge_exec(reactor, handle);
    if (exec_result != 0) {
        close_socket_bridge(
            reactor,
            handle,
            SSH_REACTOR_SOCKET_BRIDGE_REQUEST_DENIED,
            NULL,
            0);
    }
}

static int start_socket_bridge_exec(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return LIBSSH2_ERROR_INVAL;
    }
    int timer_result = start_socket_bridge_ready_timer(reactor, bridge);
    if (timer_result != 0) {
        return timer_result;
    }

    SSHReactorChannelToken channel_token = bridge->channel_token;
    assert(channel_token < reactor->channel_capacity);
    SSHReactorChannelOwner *owner =
        &reactor->channels[channel_token].owner;
    if (!outersshpriv_reactor_accepts_work(reactor)) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (owner->type != SSH_REACTOR_CHANNEL_OWNER_NONE) {
        return LIBSSH2_ERROR_BAD_USE;
    }
    int exec_result = outersshpriv_reactor_start_channel_exec(
        reactor,
        channel_token,
        bridge->command,
        bridge->command_length,
        bridge->initial_input,
        bridge->initial_input_length,
        false);
    if (exec_result != 0) {
        return exec_result;
    }
    owner->type = SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE;
    owner->socket_bridge_handle = handle;
    free(bridge->command);
    bridge->command = NULL;
    bridge->command_length = 0;
    if (bridge->initial_input != NULL) {
        securely_clear_memory(
            bridge->initial_input,
            bridge->initial_input_length);
    }
    free(bridge->initial_input);
    bridge->initial_input = NULL;
    bridge->initial_input_length = 0;
    outersshpriv_reactor_update_channel_write_source(reactor);
    return 0;
}

static int start_socket_bridge_ready_timer(
    SSHReactor *reactor,
    SocketBridge *bridge)
{
    otsource_t timer = otsource_create(
        OTSOURCE_TYPE_TIMER,
        0,
        reactor->queue);
    if (timer == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    SSHReactorSourceContext *timer_context =
        outersshpriv_reactor_create_source_context(reactor, timer);
    if (timer_context == NULL) {
        otsource_activate(timer);
        outersshpriv_reactor_cancel_source(timer);
        return LIBSSH2_ERROR_ALLOC;
    }
    bridge->ready_timer = timer;
    timer_context->bridge = bridge->handle;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(timer, timer_context);
    otsource_set_cancel_handler(timer, outersshpriv_reactor_timer_cancelled);
    otsource_set_event_handler(timer, socket_bridge_ready_timed_out);
    otsource_set_timer(
        timer,
        ottime(
            OTTIME_NOW,
            (int64_t)(bridge->ready_timeout_milliseconds *
                NSEC_PER_MSEC)),
        OTTIME_FOREVER,
        0);
    otsource_activate(timer);
    return 0;
}

static void socket_bridge_ready_timed_out(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    close_socket_bridge(
        context->reactor,
        context->bridge,
        SSH_REACTOR_SOCKET_BRIDGE_READY_TIMED_OUT,
        NULL,
        0);
}

static void start_socket_bridge_ping_timer(
    SSHReactor *reactor,
    SocketBridge *bridge)
{
    if (bridge->ping_timer != NULL) {
        return;
    }
    otsource_t timer = otsource_create(
        OTSOURCE_TYPE_TIMER,
        0,
        reactor->queue);
    if (timer == NULL) {
        return;
    }
    SSHReactorSourceContext *timer_context =
        outersshpriv_reactor_create_source_context(reactor, timer);
    if (timer_context == NULL) {
        otsource_activate(timer);
        outersshpriv_reactor_cancel_source(timer);
        return;
    }
    timer_context->bridge = bridge->handle;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(timer, timer_context);
    otsource_set_cancel_handler(timer, outersshpriv_reactor_timer_cancelled);
    otsource_set_event_handler(
        timer,
        socket_bridge_ping_timer_fired);
    otsource_set_timer(
        timer,
        ottime(
            OTTIME_NOW,
            (int64_t)SocketBridgePingIntervalNanoseconds),
        SocketBridgePingIntervalNanoseconds,
        SocketBridgePingLeewayNanoseconds);
    bridge->ping_timer = timer;
    otsource_activate(timer);
}

static void socket_bridge_ping_timer_fired(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(
        context->reactor,
        context->bridge);
    if (bridge == NULL) {
        return;
    }
    socket_bridge_send_frame(
        context->reactor,
        context->bridge,
        HELPER_FRAME_PING,
        0,
        NULL,
        0);
}

#pragma mark - Receive Bridge Frames

static bool append_socket_bridge_stderr(
    SocketBridge *bridge,
    const void *bytes,
    size_t byte_count);
static void socket_bridge_receive_stdout(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    const void *bytes,
    size_t byte_count);
static const char *socket_bridge_parse_error_message(
    HelperParseResult result);
static bool socket_bridge_handle_frame(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    HelperFrame frame);
static void complete_socket_bridge_stream_preparation(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SocketBridgeStream *stream,
    SSHReactorSocketBridgeStreamResult result,
    const void *detail,
    size_t detail_length,
    bool notify_remote);

void outersshpriv_reactor_socket_bridge_receive_channel_data(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    uint32_t stream_id,
    const void *bytes,
    size_t byte_count)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return;
    }
    if (stream_id == 0) {
        socket_bridge_receive_stdout(
            reactor,
            handle,
            bytes,
            byte_count);
        return;
    }
    if (!append_socket_bridge_stderr(bridge, bytes, byte_count)) {
        static const char message[] =
            "Failed to buffer outerssh-helper stderr";
        close_socket_bridge(
            reactor,
            handle,
            SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
            message,
            sizeof(message) - 1);
    }
}

static bool append_socket_bridge_stderr(
    SocketBridge *bridge,
    const void *bytes,
    size_t byte_count)
{
    if (byte_count == 0) {
        return true;
    }
    if (bytes == NULL || byte_count > SocketBridgeBufferLimit ||
        bridge->stderr_byte_count > SocketBridgeBufferLimit - byte_count) {
        return false;
    }
    size_t required_capacity =
        bridge->stderr_byte_count + byte_count + 1;
    if (!reserve_byte_buffer(
            &bridge->stderr_bytes,
            &bridge->stderr_capacity,
            required_capacity)) {
        return false;
    }
    memcpy(bridge->stderr_bytes + bridge->stderr_byte_count,
           bytes,
           byte_count);
    bridge->stderr_byte_count += byte_count;
    bridge->stderr_bytes[bridge->stderr_byte_count] = '\0';
    return true;
}

static void socket_bridge_receive_stdout(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    const void *bytes,
    size_t byte_count)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return;
    }
    size_t buffered_byte_count =
        socket_bridge_buffered_remote_byte_count(bridge);
    if (byte_count > SocketBridgeBufferLimit ||
        buffered_byte_count > SocketBridgeBufferLimit - byte_count ||
        !outersshpriv_helper_frame_parser_append(
            &bridge->parser,
            bytes,
            byte_count)) {
        static const char message[] =
            "Failed to buffer outerssh-helper output";
        close_socket_bridge(
            reactor,
            handle,
            SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
            message,
            sizeof(message) - 1);
        return;
    }

    while (true) {
        HelperFrame frame = {0};
        uint32_t invalid_value = 0;
        HelperParseResult result =
            outersshpriv_helper_frame_parser_peek(
                &bridge->parser,
                &frame,
                &invalid_value);
        if (result == HELPER_PARSE_NEEDS_DATA) {
            return;
        }
        if (result != HELPER_PARSE_FRAME_AVAILABLE) {
            const char *message = socket_bridge_parse_error_message(result);
            close_socket_bridge(
                reactor,
                handle,
                SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
                message,
                strlen(message));
            return;
        }
        if (!socket_bridge_handle_frame(reactor, handle, frame)) {
            static const char message[] = "Invalid socket channel frame.";
            close_socket_bridge(reactor, handle, SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
                message, sizeof(message) - 1);
            return;
        }
        bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
        if (bridge == NULL) {
            return;
        }
        outersshpriv_helper_frame_parser_consume(&bridge->parser);
    }
}

static const char *socket_bridge_parse_error_message(
    HelperParseResult result)
{
    switch (result) {
    case HELPER_PARSE_INVALID_MAGIC:
        return "outerssh-helper sent invalid frame magic";
    case HELPER_PARSE_UNSUPPORTED_VERSION:
        return "outerssh-helper sent an unsupported protocol version";
    case HELPER_PARSE_PAYLOAD_TOO_LARGE:
        return "outerssh-helper sent an oversized frame";
    case HELPER_PARSE_ALLOCATION_FAILED:
        return "Failed to buffer outerssh-helper output";
    case HELPER_PARSE_FRAME_AVAILABLE:
    case HELPER_PARSE_NEEDS_DATA:
        return "outerssh-helper protocol error";
    }
    return "outerssh-helper protocol error";
}

static bool socket_bridge_handle_frame(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    HelperFrame frame)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return false;
    }

    if (bridge->callbacks.received != NULL &&
        frame.type != HELPER_FRAME_HELLO &&
        frame.type != HELPER_FRAME_PING && frame.type != HELPER_FRAME_PONG) {
        return bridge->is_ready && bridge->callbacks.received(bridge->callbacks.context, frame);
    }

    switch (frame.type) {
    case HELPER_FRAME_HELLO: {
        if (bridge->is_ready || frame.stream_id != 0 || frame.payload_length != 0) return false;
        cancel_socket_bridge_timer(bridge->ready_timer);
        bridge->ready_timer = NULL;
        bridge->is_ready = true;
        start_socket_bridge_ping_timer(reactor, bridge);
        SSHSocketChannelCallbacks callbacks = bridge->callbacks;
        if (callbacks.completed != NULL) {
            callbacks.completed(
                callbacks.context,
                handle,
                SSH_REACTOR_SOCKET_BRIDGE_READY,
                0,
                NULL,
                0);
        }
        return outersshpriv_reactor_socket_bridge_for_handle(reactor, handle) != NULL;
    }

    case HELPER_FRAME_OPEN_OK: {
        if (frame.payload_length > 4096) return false;
        SocketBridgeStream *stream = socket_bridge_stream_for_id(
            bridge,
            frame.stream_id);
        if (stream == NULL) {
            return socket_bridge_send_frame(
                reactor,
                handle,
                HELPER_FRAME_CLOSE,
                frame.stream_id,
                NULL,
                0);
        }
        if (stream->open_operation != NULL) {
            complete_socket_bridge_stream_preparation(
                reactor,
                bridge,
                stream,
                SSH_REACTOR_SOCKET_BRIDGE_STREAM_READY,
                frame.payload,
                frame.payload_length,
                false);
        }
        return outersshpriv_reactor_socket_bridge_for_handle(reactor, handle) != NULL;
    }

    case HELPER_FRAME_OPEN_ERROR:
    case HELPER_FRAME_OPEN_NOT_LISTENING: {
        SocketBridgeStream *stream = socket_bridge_stream_for_id(
            bridge,
            frame.stream_id);
        if (stream == NULL) {
            return true;
        }
        if (stream->open_operation != NULL) {
            complete_socket_bridge_stream_preparation(
                reactor,
                bridge,
                stream,
                frame.type == HELPER_FRAME_OPEN_NOT_LISTENING
                    ? SSH_REACTOR_SOCKET_BRIDGE_STREAM_NOT_LISTENING : SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_FAILED,
                frame.payload,
                frame.payload_length,
                false);
        } else {
            outersshpriv_reactor_socket_bridge_close_stream(
                reactor,
                handle,
                frame.stream_id,
                false);
        }
        return outersshpriv_reactor_socket_bridge_for_handle(reactor, handle) != NULL;
    }

    case HELPER_FRAME_DATA: {
        SocketBridgeStream *stream = socket_bridge_stream_for_id(
            bridge,
            frame.stream_id);
        if (stream == NULL) {
            return socket_bridge_send_frame(
                reactor,
                handle,
                HELPER_FRAME_CLOSE,
                frame.stream_id,
                NULL,
                0);
        }
        size_t stream_index = stream->slot_index;
        uint64_t stream_generation =
            bridge->stream_slots[stream_index].generation;
        if (!socket_bridge_forward_remote_to_local(
                reactor,
                bridge,
                stream,
                frame.payload,
                frame.payload_length)) {
            return false;
        }
        bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
        if (bridge == NULL) {
            return false;
        }
        stream = socket_bridge_stream_for_slot(
            bridge,
            stream_index,
            stream_generation);
        if (stream != NULL && stream->write_socket_source != NULL &&
            stream->to_local_offset < stream->to_local_byte_count) {
            outersshpriv_reactor_safely_set_source_resumed(
                reactor,
                stream->write_socket_source,
                true,
                &stream->write_socket_source_is_resumed);
        }
        return true;
    }

    case HELPER_FRAME_EOF: {
        SocketBridgeStream *stream = socket_bridge_stream_for_id(
            bridge,
            frame.stream_id);
        if (stream == NULL) {
            return socket_bridge_send_frame(
                reactor,
                handle,
                HELPER_FRAME_CLOSE,
                frame.stream_id,
                NULL,
                0);
        }
        stream->remote_read_is_open = false;
        if (stream->write_socket_source != NULL &&
            stream->to_local_offset < stream->to_local_byte_count) {
            outersshpriv_reactor_safely_set_source_resumed(
                reactor,
                stream->write_socket_source,
                true,
                &stream->write_socket_source_is_resumed);
        } else if (stream->socket >= 0 &&
                   stream->to_local_offset == stream->to_local_byte_count) {
            otsocket_shutdown(stream->socket, SHUT_WR);
        }
        if (!stream->local_read_is_open &&
            stream->to_local_offset == stream->to_local_byte_count) {
            remove_socket_bridge_stream(reactor, bridge, stream);
        }
        return true;
    }

    case HELPER_FRAME_CLOSE: {
        SocketBridgeStream *stream = socket_bridge_stream_for_id(
            bridge,
            frame.stream_id);
        if (stream == NULL) {
            return true;
        }
        if (stream->open_operation != NULL) {
            complete_socket_bridge_stream_preparation(
                reactor,
                bridge,
                stream,
                SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_FAILED,
                frame.payload,
                frame.payload_length,
                false);
            return outersshpriv_reactor_socket_bridge_for_handle(reactor, handle) != NULL;
        }
        stream->remote_read_is_open = false;
        stream->local_read_is_open = false;
        if (stream->read_socket_source != NULL) {
            outersshpriv_reactor_safely_set_source_resumed(
                reactor,
                stream->read_socket_source,
                false,
                &stream->read_socket_source_is_resumed);
        }
        if (stream->to_local_offset == stream->to_local_byte_count) {
            remove_socket_bridge_stream(reactor, bridge, stream);
        } else if (stream->write_socket_source != NULL) {
            outersshpriv_reactor_safely_set_source_resumed(
                reactor,
                stream->write_socket_source,
                true,
                &stream->write_socket_source_is_resumed);
        }
        return true;
    }

    case HELPER_FRAME_PING:
        return socket_bridge_send_frame(
            reactor,
            handle,
            HELPER_FRAME_PONG,
            frame.stream_id,
            frame.payload,
            frame.payload_length);

    case HELPER_FRAME_SOCKET_STATE:
    case HELPER_FRAME_AUTHORIZE:
    case HELPER_FRAME_ENDPOINT_NAMES:
    case HELPER_FRAME_GET_ENDPOINT_NAMES:
    case HELPER_FRAME_ENDPOINT_NAMES_CHANGED:
    case HELPER_FRAME_STORE_ENDPOINT_ICON:
    case HELPER_FRAME_GET_ENDPOINT_ICON:
    case HELPER_FRAME_ENDPOINT_ICON:
    case HELPER_FRAME_APP_REQUEST:
    case HELPER_FRAME_APP_RESPONSE:
    case HELPER_FRAME_PREPARED:
    case HELPER_FRAME_RESULT:
    case HELPER_FRAME_WATCH:
    case HELPER_FRAME_UNWATCH:
        return false;

    case HELPER_FRAME_PONG:
        return bridge->callbacks.received == NULL ||
            bridge->callbacks.received(bridge->callbacks.context, frame);
    case HELPER_FRAME_OPEN:
        return true;
    }
    return false;
}


#pragma mark - Open and Attach a Stream

static int socket_bridge_prepare_stream(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SSHReactorSocketBridgeStreamHandle *handle,
    ConnectBridgeStreamContext *operation,
    uint64_t timeout_milliseconds);
static bool reserve_socket_bridge_stream_slots(
    SocketBridge *bridge,
    size_t minimum_capacity);
static bool reserve_socket_bridge_streams_by_id(
    SocketBridge *bridge,
    size_t minimum_capacity);
static bool insert_socket_bridge_stream_by_id(
    SocketBridge *bridge,
    SocketBridgeStream *stream);
static void socket_bridge_stream_open_timed_out(void *opaque_context);
static bool socket_bridge_attach_stream(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SocketBridgeStream *stream,
    otsocket_t socket);

int outersshpriv_reactor_socket_bridge_prepare_stream(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle *stream_handle,
    ConnectBridgeStreamContext *operation,
    uint64_t timeout_milliseconds)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (stream_handle != NULL) {
        *stream_handle = (SSHReactorSocketBridgeStreamHandle){0};
    }
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(
        reactor,
        bridge_handle);
    if (!outersshpriv_reactor_accepts_work(reactor) || bridge == NULL ||
        !bridge->is_ready || stream_handle == NULL || operation == NULL ||
        timeout_milliseconds == 0 ||
        timeout_milliseconds > INT64_MAX / NSEC_PER_MSEC) {
        return LIBSSH2_ERROR_INVAL;
    }
    return socket_bridge_prepare_stream(
        reactor,
        bridge,
        stream_handle,
        operation,
        timeout_milliseconds);
}

static int socket_bridge_prepare_stream(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SSHReactorSocketBridgeStreamHandle *handle,
    ConnectBridgeStreamContext *operation,
    uint64_t timeout_milliseconds)
{
    *handle = (SSHReactorSocketBridgeStreamHandle){0};
    if (bridge->stream_by_id_count >= UINT32_MAX ||
        !reserve_socket_bridge_streams_by_id(
            bridge,
            bridge->stream_by_id_count + 1)) {
        return LIBSSH2_ERROR_ALLOC;
    }
    size_t index;
    if (bridge->available_stream_index_count != 0) {
        bridge->available_stream_index_count -= 1;
        index = bridge->available_stream_indices[
            bridge->available_stream_index_count];
    } else {
        if (bridge->stream_slot_count == SIZE_MAX ||
            !reserve_socket_bridge_stream_slots(
                bridge,
                bridge->stream_slot_count + 1)) {
            return LIBSSH2_ERROR_ALLOC;
        }
        index = bridge->stream_slot_count;
        bridge->stream_slot_count += 1;
    }
    SocketBridgeStreamSlot *slot = &bridge->stream_slots[index];
    slot->generation += 1;
    if (slot->generation == 0) {
        slot->generation = 1;
    }
    SocketBridgeStream *stream = &slot->stream;

    uint32_t stream_id;
    do {
        stream_id = bridge->next_stream_id;
        bridge->next_stream_id += 1;
        if (bridge->next_stream_id == 0) {
            bridge->next_stream_id = 1;
        }
    } while (socket_bridge_stream_for_id(bridge, stream_id) != NULL);

    stream->slot_index = index;
    stream->stream_id = stream_id;
    stream->socket = -1;
    stream->open_operation = operation;
    stream->local_read_is_open = true;
    stream->remote_read_is_open = true;
    stream->phase = SOCKET_BRIDGE_STREAM_ACTIVE;
    stream->open_timer = otsource_create(
        OTSOURCE_TYPE_TIMER,
        0,
        reactor->queue);
    if (stream->open_timer == NULL) {
        stream->open_operation = NULL;
        *stream = (SocketBridgeStream){.socket = -1};
        assert(bridge->available_stream_index_count <
               bridge->stream_slot_capacity);
        bridge->available_stream_indices[
            bridge->available_stream_index_count] = index;
        bridge->available_stream_index_count += 1;
        return LIBSSH2_ERROR_ALLOC;
    }
    if (!insert_socket_bridge_stream_by_id(bridge, stream)) {
        stream->phase = SOCKET_BRIDGE_STREAM_FREE;
        stream->open_operation = NULL;
        otsource_activate(stream->open_timer);
        outersshpriv_reactor_cancel_source(stream->open_timer);
        stream->open_timer = NULL;
        *stream = (SocketBridgeStream){.socket = -1};
        assert(bridge->available_stream_index_count <
               bridge->stream_slot_capacity);
        bridge->available_stream_indices[
            bridge->available_stream_index_count] = index;
        bridge->available_stream_index_count += 1;
        return LIBSSH2_ERROR_PROTO;
    }
    SSHReactorSocketBridgeHandle bridge_handle = bridge->handle;
    SSHReactorSocketBridgeStreamHandle stream_handle =
        socket_bridge_stream_handle(bridge, stream);
    SSHReactorSourceContext *timer_context =
        outersshpriv_reactor_create_source_context(reactor, stream->open_timer);
    if (timer_context == NULL) {
        remove_socket_bridge_stream_by_id(bridge, stream);
        stream->phase = SOCKET_BRIDGE_STREAM_FREE;
        stream->open_operation = NULL;
        otsource_activate(stream->open_timer);
        outersshpriv_reactor_cancel_source(stream->open_timer);
        stream->open_timer = NULL;
        *stream = (SocketBridgeStream){.socket = -1};
        assert(bridge->available_stream_index_count <
               bridge->stream_slot_capacity);
        bridge->available_stream_indices[
            bridge->available_stream_index_count++] = index;
        return LIBSSH2_ERROR_ALLOC;
    }
    timer_context->bridge = bridge_handle;
    timer_context->stream = stream_handle;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(stream->open_timer, timer_context);
    otsource_set_cancel_handler(
        stream->open_timer,
        outersshpriv_reactor_timer_cancelled);
    otsource_set_event_handler(
        stream->open_timer,
        socket_bridge_stream_open_timed_out);
    otsource_set_timer(
        stream->open_timer,
        ottime(
            OTTIME_NOW,
            (int64_t)(timeout_milliseconds * NSEC_PER_MSEC)),
        OTTIME_FOREVER,
        0);
    otsource_activate(stream->open_timer);
    *handle = stream_handle;

    if (!socket_bridge_send_frame(
            reactor,
            bridge_handle,
            HELPER_FRAME_OPEN,
            stream_id,
            NULL,
            0)) {
        SocketBridge *current = outersshpriv_reactor_socket_bridge_for_handle(
            reactor,
            bridge_handle);
        if (current != NULL) {
            SocketBridgeStream *current_stream =
                socket_bridge_stream_for_handle(
                    current,
                    stream_handle);
            complete_socket_bridge_stream_preparation(
                reactor,
                current,
                current_stream,
                SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_FAILED,
                NULL,
                0,
                false);
        }
    }
    return 0;
}

static void complete_socket_bridge_stream_preparation(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SocketBridgeStream *stream,
    SSHReactorSocketBridgeStreamResult result,
    const void *detail,
    size_t detail_length,
    bool notify_remote)
{
    if (stream == NULL) {
        return;
    }
    SSHReactorSocketBridgeHandle bridge_handle = bridge->handle;
    SSHReactorSocketBridgeStreamHandle stream_handle =
        socket_bridge_stream_handle(bridge, stream);
    ConnectBridgeStreamContext *operation = stream->open_operation;
    assert(operation != NULL);
    stream->open_operation = NULL;
    if (stream->open_timer != NULL) {
        outersshpriv_reactor_cancel_source(stream->open_timer);
        stream->open_timer = NULL;
    }
    if (result != SSH_REACTOR_SOCKET_BRIDGE_STREAM_READY) {
        uint32_t stream_id = stream->stream_id;
        remove_socket_bridge_stream(reactor, bridge, stream);
        if (notify_remote &&
            outersshpriv_reactor_socket_bridge_for_handle(reactor, bridge_handle) != NULL) {
            socket_bridge_send_frame(
                reactor,
                bridge_handle,
                HELPER_FRAME_CLOSE,
                stream_id,
                NULL,
                0);
        }
        SocketBridge *current_bridge = outersshpriv_reactor_socket_bridge_for_handle(
            reactor,
            bridge_handle);
        if (current_bridge != NULL) {
            outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(
                reactor,
                current_bridge);
        }
    }
    outersshpriv_session_pool_socket_bridge_stream_completed(
        operation,
        bridge_handle,
        stream_handle,
        result,
        detail,
        detail_length);
}


static bool reserve_socket_bridge_stream_slots(
    SocketBridge *bridge,
    size_t minimum_capacity)
{
    if (bridge->stream_slot_capacity >= minimum_capacity) {
        return true;
    }
    size_t capacity = bridge->stream_slot_capacity == 0
        ? 4
        : bridge->stream_slot_capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*bridge->stream_slots) ||
        capacity > SIZE_MAX / sizeof(*bridge->available_stream_indices)) {
        return false;
    }

    SocketBridgeStreamSlot *slots = calloc(capacity, sizeof(*slots));
    size_t *available_indices = malloc(
        capacity * sizeof(*available_indices));
    if (slots == NULL || available_indices == NULL) {
        free(slots);
        free(available_indices);
        return false;
    }
    for (size_t index = 0; index < bridge->stream_slot_count; index++) {
        SocketBridgeStreamSlot *source_slot =
            &bridge->stream_slots[index];
        SocketBridgeStreamSlot *destination_slot = &slots[index];
        destination_slot->generation = source_slot->generation;
        if (source_slot->stream.phase == SOCKET_BRIDGE_STREAM_FREE) {
            continue;
        }
        destination_slot->stream = source_slot->stream;
        source_slot->stream = (SocketBridgeStream){.socket = -1};
    }
    if (bridge->available_stream_index_count != 0) {
        memcpy(available_indices,
               bridge->available_stream_indices,
               bridge->available_stream_index_count *
                   sizeof(*available_indices));
    }
    free(bridge->stream_slots);
    free(bridge->available_stream_indices);
    bridge->stream_slots = slots;
    bridge->available_stream_indices = available_indices;
    bridge->stream_slot_capacity = capacity;
    return true;
}

static bool reserve_socket_bridge_streams_by_id(
    SocketBridge *bridge,
    size_t minimum_capacity)
{
    if (bridge->stream_by_id_capacity >= minimum_capacity) {
        return true;
    }
    size_t capacity = bridge->stream_by_id_capacity == 0
        ? 4
        : bridge->stream_by_id_capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*bridge->stream_indices_by_id)) {
        return false;
    }
    size_t *indices = realloc(
        bridge->stream_indices_by_id,
        capacity * sizeof(*indices));
    if (indices == NULL) {
        return false;
    }
    bridge->stream_indices_by_id = indices;
    bridge->stream_by_id_capacity = capacity;
    return true;
}

static bool insert_socket_bridge_stream_by_id(
    SocketBridge *bridge,
    SocketBridgeStream *stream)
{
    assert(bridge->stream_by_id_count < bridge->stream_by_id_capacity);
    if (bridge->stream_by_id_count >= bridge->stream_by_id_capacity) {
        return false;
    }
    size_t index = socket_bridge_stream_id_lower_bound(
        bridge,
        stream->stream_id);
    if (index < bridge->stream_by_id_count) {
        size_t existing_stream_index =
            bridge->stream_indices_by_id[index];
        if (bridge->stream_slots[existing_stream_index].stream.stream_id ==
            stream->stream_id) {
            return false;
        }
    }
    size_t shifted_count = bridge->stream_by_id_count - index;
    if (shifted_count != 0) {
        memmove(
            bridge->stream_indices_by_id + index + 1,
            bridge->stream_indices_by_id + index,
            shifted_count * sizeof(*bridge->stream_indices_by_id));
    }
    bridge->stream_indices_by_id[index] = stream->slot_index;
    bridge->stream_by_id_count += 1;
    return true;
}

static void socket_bridge_stream_open_timed_out(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(
        context->reactor,
        context->bridge);
    if (bridge == NULL) {
        return;
    }
    SocketBridgeStream *stream = socket_bridge_stream_for_handle(
        bridge,
        context->stream);
    if (stream == NULL || stream->open_operation == NULL) {
        return;
    }
    complete_socket_bridge_stream_preparation(
        context->reactor,
        bridge,
        stream,
        SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_TIMED_OUT,
        NULL,
        0,
        true);
}

bool outersshpriv_reactor_socket_bridge_attach_stream(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle,
    otsocket_t socket, uint64_t proxy_generation)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (socket < 0) {
        return false;
    }
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(
        reactor,
        bridge_handle);
    SocketBridgeStream *stream = bridge == NULL
        ? NULL
        : socket_bridge_stream_for_handle(bridge, stream_handle);
    if (!outersshpriv_reactor_accepts_work(reactor) || bridge == NULL ||
        stream == NULL) {
        otsocket_close(socket);
        return false;
    }
    stream->proxy_generation = proxy_generation;
    bool attached = socket_bridge_attach_stream(
        reactor,
        bridge,
        stream,
        socket);
    if (!attached) {
        bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, bridge_handle);
        stream = bridge == NULL
            ? NULL
            : socket_bridge_stream_for_handle(bridge, stream_handle);
        if (stream != NULL) {
            outersshpriv_reactor_socket_bridge_close_stream(
                reactor,
                bridge_handle,
                stream->stream_id,
                true);
            release_socket_bridge_window_credit_for_handle(
                reactor,
                bridge_handle);
        }
    }
    return attached;
}

static bool socket_bridge_attach_stream(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SocketBridgeStream *stream,
    otsocket_t socket)
{
    if (stream->open_operation != NULL ||
        stream->socket >= 0 || stream->read_socket_source != NULL ||
        stream->write_socket_source != NULL ||
        !outersshpriv_reactor_configure_nonblocking_stream_socket(socket)) {
        otsocket_close(socket);
        return false;
    }

    SSHReactorSocketBridgeHandle bridge_handle = bridge->handle;
    SSHReactorSocketBridgeStreamHandle stream_handle =
        socket_bridge_stream_handle(bridge, stream);
    assert(socket_bridge_stream_slot_for_handle(bridge, stream_handle) != NULL);
    SSHReactorSourceContext *read_context =
        outersshpriv_reactor_create_source_context(reactor, NULL);
    SSHReactorSourceContext *write_context =
        outersshpriv_reactor_create_source_context(reactor, NULL);
    if (read_context == NULL || write_context == NULL) {
        free(read_context);
        free(write_context);
        otsocket_close(socket);
        return false;
    }
    read_context->bridge = bridge_handle;
    read_context->stream = stream_handle;
    write_context->bridge = bridge_handle;
    write_context->stream = stream_handle;
    write_context->writes = true;
    stream->socket = socket;
    stream->read_socket_source = otsource_create(
        OTSOURCE_TYPE_READ,
        (uintptr_t)socket,
        reactor->queue);
    stream->write_socket_source = otsource_create(
        OTSOURCE_TYPE_WRITE,
        (uintptr_t)socket,
        reactor->queue);
    size_t socket_source_count =
        (stream->read_socket_source != NULL ? 1 : 0) +
        (stream->write_socket_source != NULL ? 1 : 0);
    stream->uncancelled_socket_source_count = socket_source_count;
    if (stream->read_socket_source != NULL) {
        read_context->source = stream->read_socket_source;
        outersshpriv_reactor_source_created(reactor);
        otsource_set_context(stream->read_socket_source, read_context);
        otsource_set_cancel_handler(
            stream->read_socket_source,
            socket_bridge_stream_source_cancelled_context);
    } else {
        free(read_context);
    }
    if (stream->write_socket_source != NULL) {
        write_context->source = stream->write_socket_source;
        outersshpriv_reactor_source_created(reactor);
        otsource_set_context(stream->write_socket_source, write_context);
        otsource_set_cancel_handler(
            stream->write_socket_source,
            socket_bridge_stream_source_cancelled_context);
    } else {
        free(write_context);
    }
    if (socket_source_count != 2) {
        if (stream->read_socket_source != NULL) {
            otsource_activate(stream->read_socket_source);
            stream->read_socket_source_is_resumed = true;
        }
        if (stream->write_socket_source != NULL) {
            otsource_activate(stream->write_socket_source);
            stream->write_socket_source_is_resumed = true;
        }
        if (socket_source_count == 0) {
            otsocket_close(socket);
            stream->socket = -1;
        }
        return false;
    }

    otsource_set_event_handler(
        stream->read_socket_source,
        socket_bridge_stream_socket_ready);
    otsource_set_event_handler(
        stream->write_socket_source,
        socket_bridge_stream_socket_ready);
    if (stream->local_read_is_open) {
        outersshpriv_reactor_safely_set_source_resumed(
            reactor,
            stream->read_socket_source,
            true,
            &stream->read_socket_source_is_resumed);
    }
    if (stream->to_local_offset < stream->to_local_byte_count) {
        outersshpriv_reactor_safely_set_source_resumed(
            reactor,
            stream->write_socket_source,
            true,
            &stream->write_socket_source_is_resumed);
    } else if (!stream->remote_read_is_open) {
        otsocket_shutdown(socket, SHUT_WR);
    }
    return true;
}

#pragma mark - Forward Stream Data

static void socket_bridge_handle_local_read(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    size_t stream_index,
    uint64_t stream_generation);
static void socket_bridge_handle_local_write(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    size_t stream_index,
    uint64_t stream_generation);
static bool append_socket_bridge_local_output(
    SocketBridge *bridge,
    SocketBridgeStream *stream,
    const void *bytes,
    size_t byte_count);

static void socket_bridge_stream_socket_ready(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    if (context->writes) {
        socket_bridge_handle_local_write(
            context->reactor,
            context->bridge,
            context->stream.index,
            context->stream.generation);
    } else {
        socket_bridge_handle_local_read(
            context->reactor,
            context->bridge,
            context->stream.index,
            context->stream.generation);
    }
}

static void socket_bridge_handle_local_read(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    size_t stream_index,
    uint64_t stream_generation)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(
        reactor,
        bridge_handle);
    if (bridge == NULL) {
        return;
    }
    SocketBridgeStream *stream = socket_bridge_stream_for_slot(
        bridge,
        stream_index,
        stream_generation);
    if (stream == NULL || !stream->local_read_is_open) {
        return;
    }
    if (reactor->socket_bridge_read_buffer == NULL) {
        reactor->socket_bridge_read_buffer = malloc(
            SocketBridgeReadChunkSize);
        if (reactor->socket_bridge_read_buffer == NULL) {
            static const char message[] =
                "Failed to allocate socket bridge read buffer";
            close_socket_bridge(
                reactor,
                bridge_handle,
                SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
                message,
                sizeof(message) - 1);
            return;
        }
    }

    while (true) {
        size_t pending_byte_count =
            outersshpriv_reactor_pending_exec_input_byte_count(
                reactor,
                bridge->channel_token);
        if (pending_byte_count >= SocketBridgeBufferLimit ||
            SocketBridgeBufferLimit - pending_byte_count <=
                HELPER_FRAME_HEADER_LENGTH) {
            break;
        }
        size_t read_capacity = SocketBridgeBufferLimit -
            pending_byte_count - HELPER_FRAME_HEADER_LENGTH;
        if (read_capacity > SocketBridgeReadChunkSize) {
            read_capacity = SocketBridgeReadChunkSize;
        }
        ssize_t byte_count = otsocket_recv(
            stream->socket,
            reactor->socket_bridge_read_buffer,
            read_capacity,
            0);
        if (byte_count > 0) {
            if (!socket_bridge_send_frame(
                    reactor,
                    bridge_handle,
                    HELPER_FRAME_DATA,
                    stream->stream_id,
                    reactor->socket_bridge_read_buffer,
                    (size_t)byte_count)) {
                return;
            }
            bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, bridge_handle);
            if (bridge == NULL) {
                return;
            }
            stream = socket_bridge_stream_for_slot(
                bridge,
                stream_index,
                stream_generation);
            if (stream == NULL) {
                return;
            }
            continue;
        }

        if (byte_count == 0) {
            stream->local_read_is_open = false;
            outersshpriv_reactor_safely_set_source_resumed(
                reactor,
                stream->read_socket_source,
                false,
                &stream->read_socket_source_is_resumed);
            uint32_t stream_id = stream->stream_id;
            if (!socket_bridge_send_frame(
                    reactor,
                    bridge_handle,
                    HELPER_FRAME_EOF,
                    stream_id,
                    NULL,
                    0)) {
                return;
            }
            bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, bridge_handle);
            if (bridge == NULL) {
                return;
            }
            stream = socket_bridge_stream_for_slot(
                bridge,
                stream_index,
                stream_generation);
            if (stream != NULL && !stream->remote_read_is_open &&
                stream->to_local_offset == stream->to_local_byte_count) {
                outersshpriv_reactor_socket_bridge_close_stream(
                    reactor,
                    bridge_handle,
                    stream_id,
                    true);
                release_socket_bridge_window_credit_for_handle(
                    reactor,
                    bridge_handle);
            }
            return;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        outersshpriv_reactor_socket_bridge_close_stream(
            reactor,
            bridge_handle,
            stream->stream_id,
            true);
        release_socket_bridge_window_credit_for_handle(
            reactor,
            bridge_handle);
        return;
    }

    outersshpriv_reactor_safely_set_source_resumed(
        reactor,
        stream->read_socket_source,
        false,
        &stream->read_socket_source_is_resumed);
}

static void socket_bridge_handle_local_write(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    size_t stream_index,
    uint64_t stream_generation)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(
        reactor,
        bridge_handle);
    if (bridge == NULL) {
        return;
    }
    SocketBridgeStream *stream = socket_bridge_stream_for_slot(
        bridge,
        stream_index,
        stream_generation);
    if (stream == NULL) {
        return;
    }

    while (stream->to_local_offset < stream->to_local_byte_count) {
        size_t remaining =
            stream->to_local_byte_count - stream->to_local_offset;
        ssize_t written = otsocket_send(
            stream->socket,
            stream->to_local + stream->to_local_offset,
            remaining,
            OTSOCKET_SEND_FLAGS);
        if (written > 0) {
            size_t written_byte_count = (size_t)written;
            assert(written_byte_count <=
                   bridge->pending_local_output_byte_count);
            if (written_byte_count <=
                bridge->pending_local_output_byte_count) {
                bridge->pending_local_output_byte_count -=
                    written_byte_count;
            } else {
                bridge->pending_local_output_byte_count = 0;
            }
            stream->to_local_offset += written_byte_count;
            continue;
        }
        if (written == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
            release_socket_bridge_window_credit_for_handle(
                reactor,
                bridge_handle);
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        outersshpriv_reactor_socket_bridge_close_stream(
            reactor,
            bridge_handle,
            stream->stream_id,
            true);
        release_socket_bridge_window_credit_for_handle(
            reactor,
            bridge_handle);
        return;
    }

    stream->to_local_byte_count = 0;
    stream->to_local_offset = 0;
    outersshpriv_reactor_safely_set_source_resumed(
        reactor,
        stream->write_socket_source,
        false,
        &stream->write_socket_source_is_resumed);
    if (!outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(
            reactor,
            bridge)) {
        return;
    }
    bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, bridge_handle);
    if (bridge == NULL) {
        return;
    }
    stream = socket_bridge_stream_for_slot(
        bridge,
        stream_index,
        stream_generation);
    if (stream == NULL) {
        return;
    }
    if (!stream->remote_read_is_open) {
        otsocket_shutdown(stream->socket, SHUT_WR);
    }
    if (!stream->remote_read_is_open &&
        !stream->local_read_is_open) {
        outersshpriv_reactor_socket_bridge_close_stream(
            reactor,
            bridge_handle,
            stream->stream_id,
            true);
    }
}

static bool socket_bridge_forward_remote_to_local(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SocketBridgeStream *stream,
    const void *bytes,
    size_t byte_count)
{
    size_t frame_length = HELPER_FRAME_HEADER_LENGTH + byte_count;
    size_t buffered_byte_count =
        socket_bridge_buffered_remote_byte_count(bridge);
    bool result = buffered_byte_count >= frame_length &&
        buffered_byte_count - frame_length <= SocketBridgeBufferLimit &&
        byte_count <= SocketBridgeBufferLimit - (buffered_byte_count - frame_length) &&
        append_socket_bridge_local_output(
            bridge,
            stream,
            bytes,
            byte_count);
    if (!result) {
        static const char message[] =
            "Failed to buffer socket bridge data";
        close_socket_bridge(
            reactor,
            bridge->handle,
            SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
            message,
            sizeof(message) - 1);
    }
    return result;
}

static bool append_socket_bridge_local_output(
    SocketBridge *bridge,
    SocketBridgeStream *stream,
    const void *bytes,
    size_t byte_count)
{
    if (byte_count == 0) {
        return true;
    }
    size_t pending_byte_count =
        stream->to_local_byte_count - stream->to_local_offset;
    if (bytes == NULL || byte_count > SocketBridgeBufferLimit ||
        pending_byte_count > SocketBridgeBufferLimit - byte_count ||
        bridge->pending_local_output_byte_count >
            SocketBridgeBufferLimit - byte_count) {
        return false;
    }
    if (stream->to_local_offset != 0 && pending_byte_count != 0) {
        memmove(stream->to_local,
                stream->to_local + stream->to_local_offset,
                pending_byte_count);
    }
    stream->to_local_offset = 0;
    stream->to_local_byte_count = pending_byte_count;
    size_t required_capacity = pending_byte_count + byte_count;
    if (!reserve_byte_buffer(
            &stream->to_local,
            &stream->to_local_capacity,
            required_capacity)) {
        return false;
    }
    memcpy(stream->to_local + stream->to_local_byte_count,
           bytes,
           byte_count);
    stream->to_local_byte_count += byte_count;
    bridge->pending_local_output_byte_count += byte_count;
    return true;
}

bool outersshpriv_reactor_socket_channel_send(SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle, HelperFrame frame)
{
    outersshpriv_reactor_assert_queue(reactor);
    return socket_bridge_send_frame(reactor, handle, frame.type,
        frame.stream_id, frame.payload, frame.payload_length);
}

static bool socket_bridge_send_frame(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    HelperFrameType type,
    uint32_t stream_id,
    const void *payload,
    size_t payload_length)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (!outersshpriv_reactor_accepts_work(reactor) || bridge == NULL ||
        (payload == NULL && payload_length != 0) ||
        payload_length > SIZE_MAX - HELPER_FRAME_HEADER_LENGTH) {
        return false;
    }
    size_t frame_length =
        HELPER_FRAME_HEADER_LENGTH + payload_length;
    size_t pending_byte_count =
        outersshpriv_reactor_pending_exec_input_byte_count(
            reactor,
            bridge->channel_token);
    if (frame_length > SocketBridgeBufferLimit ||
        pending_byte_count > SocketBridgeBufferLimit - frame_length) {
        static const char message[] =
            "outerssh-helper output exceeded its buffer limit";
        close_socket_bridge(
            reactor,
            handle,
            SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
            message,
            sizeof(message) - 1);
        return false;
    }
    unsigned char *frame_bytes = malloc(frame_length);
    if (frame_bytes == NULL ||
        !outersshpriv_helper_encode_header(
            type,
            stream_id,
            payload_length,
            frame_bytes)) {
        free(frame_bytes);
        static const char message[] =
            "Failed to encode outerssh-helper frame";
        close_socket_bridge(
            reactor,
            handle,
            SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
            message,
            sizeof(message) - 1);
        return false;
    }
    if (payload_length != 0) {
        memcpy(frame_bytes + HELPER_FRAME_HEADER_LENGTH,
               payload,
               payload_length);
    }
    int result = LIBSSH2_ERROR_INVAL;
    SSHChannelState *channel =
        &reactor->channels[bridge->channel_token];
    if (channel->in_use &&
        channel->purpose == SSH_CHANNEL_PURPOSE_EXEC &&
        !channel->is_closing) {
        result = outersshpriv_reactor_output_buffer_append(
            &channel->exec_input,
            frame_bytes,
            frame_length);
        if (result == 0 && frame_length > 0) {
            result = outersshpriv_reactor_enqueue_channel_data(
                reactor,
                bridge->channel_token);
        }
    }
    free(frame_bytes);
    if (result != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, result);
        return false;
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
    return true;
}

void outersshpriv_reactor_socket_bridge_channel_became_writable(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return;
    }
    for (size_t index = 0; index < bridge->stream_slot_count; index++) {
        SocketBridgeStreamSlot *slot = &bridge->stream_slots[index];
        SocketBridgeStream *stream = &slot->stream;
        if (stream->phase == SOCKET_BRIDGE_STREAM_ACTIVE &&
            stream->read_socket_source != NULL &&
            stream->local_read_is_open) {
            outersshpriv_reactor_safely_set_source_resumed(
                reactor,
                stream->read_socket_source,
                true,
                &stream->read_socket_source_is_resumed);
        }
    }
}


bool outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(
    SSHReactor *reactor,
    SocketBridge *bridge)
{
    size_t buffered = socket_bridge_buffered_remote_byte_count(bridge);
    if (bridge->uncredited_byte_count <= buffered) {
        return true;
    }
    size_t credit = bridge->uncredited_byte_count - buffered;
    bridge->uncredited_byte_count -= credit;
    int result = outersshpriv_reactor_consume_channel_bytes(
        reactor,
        &reactor->channels[bridge->channel_token],
        bridge->channel_token,
        credit);
    if (result != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, result);
        return false;
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
    return true;
}

static void release_socket_bridge_window_credit_for_handle(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge != NULL) {
        outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(reactor, bridge);
    }
}


static size_t socket_bridge_buffered_remote_byte_count(
    SocketBridge *bridge)
{
    size_t parser_byte_count =
        outersshpriv_helper_frame_parser_byte_count(&bridge->parser);
    if (bridge->pending_local_output_byte_count >
        SIZE_MAX - parser_byte_count) {
        return SIZE_MAX;
    }
    return parser_byte_count + bridge->pending_local_output_byte_count;
}

static bool reserve_byte_buffer(
    unsigned char **bytes,
    size_t *capacity,
    size_t minimum_capacity)
{
    if (*capacity >= minimum_capacity) {
        return true;
    }
    size_t new_capacity = *capacity == 0 ? 4096 : *capacity;
    while (new_capacity < minimum_capacity) {
        if (new_capacity > SIZE_MAX / 2) {
            return false;
        }
        new_capacity *= 2;
    }
    unsigned char *new_bytes = realloc(*bytes, new_capacity);
    if (new_bytes == NULL) {
        return false;
    }
    *bytes = new_bytes;
    *capacity = new_capacity;
    return true;
}

#pragma mark - Close Streams and Recycle Their Slots

static void socket_bridge_stream_source_cancelled(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle);
static void recycle_socket_bridge_stream_slot(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle);

bool outersshpriv_reactor_socket_bridge_cancel_stream(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle)
{
    outersshpriv_reactor_assert_queue(reactor);
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(
        reactor,
        bridge_handle);
    SocketBridgeStream *stream = bridge == NULL
        ? NULL
        : socket_bridge_stream_for_handle(bridge, stream_handle);
    if (stream == NULL) {
        return false;
    }
    if (stream->open_operation != NULL) {
        complete_socket_bridge_stream_preparation(
            reactor,
            bridge,
            stream,
            SSH_REACTOR_SOCKET_BRIDGE_STREAM_CANCELLED,
            NULL,
            0,
            true);
        return true;
    }
    return outersshpriv_reactor_socket_bridge_close_stream(
        reactor,
        bridge_handle,
        stream->stream_id,
        true);
}

bool outersshpriv_reactor_socket_bridge_close_stream(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    uint32_t stream_id,
    bool notify_remote)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(
        reactor,
        bridge_handle);
    if (bridge == NULL) {
        return false;
    }
    SocketBridgeStream *stream = socket_bridge_stream_for_id(
        bridge,
        stream_id);
    if (stream == NULL) {
        return false;
    }
    size_t stream_index = stream->slot_index;
    uint64_t stream_generation =
        bridge->stream_slots[stream_index].generation;
    if (notify_remote &&
        !socket_bridge_send_frame(
            reactor,
            bridge_handle,
            HELPER_FRAME_CLOSE,
            stream_id,
            NULL,
            0)) {
        return false;
    }
    bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, bridge_handle);
    if (bridge == NULL) {
        return false;
    }
    stream = socket_bridge_stream_for_slot(
        bridge,
        stream_index,
        stream_generation);
    return remove_socket_bridge_stream(reactor, bridge, stream);
}

static bool remove_socket_bridge_stream(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SocketBridgeStream *stream)
{
    if (stream == NULL ||
        stream->slot_index >= bridge->stream_slot_count) {
        return false;
    }
    SocketBridgeStreamSlot *slot =
        &bridge->stream_slots[stream->slot_index];
    if (slot->stream.phase != SOCKET_BRIDGE_STREAM_ACTIVE ||
        &slot->stream != stream) {
        return false;
    }
    if (!remove_socket_bridge_stream_by_id(bridge, stream)) {
        return false;
    }
    assert(bridge->available_stream_index_count <
           bridge->stream_slot_capacity);
    size_t pending_byte_count =
        stream->to_local_byte_count - stream->to_local_offset;
    assert(pending_byte_count <= bridge->pending_local_output_byte_count);
    if (pending_byte_count <= bridge->pending_local_output_byte_count) {
        bridge->pending_local_output_byte_count -= pending_byte_count;
    } else {
        bridge->pending_local_output_byte_count = 0;
    }
    SSHReactorSocketBridgeHandle bridge_handle = bridge->handle;
    SSHReactorSocketBridgeStreamHandle stream_handle =
        socket_bridge_stream_handle(bridge, stream);
    size_t socket_source_count =
        (stream->read_socket_source != NULL ? 1 : 0) +
        (stream->write_socket_source != NULL ? 1 : 0);
    if (stream->open_timer != NULL) {
        outersshpriv_reactor_cancel_source(stream->open_timer);
        stream->open_timer = NULL;
    }
    if (stream->read_socket_source != NULL) {
        outersshpriv_reactor_safely_cancel_source(
            reactor,
            stream->read_socket_source,
            &stream->read_socket_source_is_resumed);
        stream->read_socket_source = NULL;
    }
    if (stream->write_socket_source != NULL) {
        outersshpriv_reactor_safely_cancel_source(
            reactor,
            stream->write_socket_source,
            &stream->write_socket_source_is_resumed);
        stream->write_socket_source = NULL;
    }
    bridge->cancelling_stream_count += 1;
    stream->open_operation = NULL;
    free(stream->to_local);
    otsocket_t socket = stream->socket;
    *stream = (SocketBridgeStream){
        .socket = socket,
        .uncancelled_socket_source_count = socket_source_count,
        .phase = SOCKET_BRIDGE_STREAM_CANCELLING
    };
    if (socket_source_count == 0) {
        recycle_socket_bridge_stream_slot(
            reactor,
            bridge_handle,
            stream_handle);
    }
    return true;
}

static void socket_bridge_stream_source_cancelled_context(
    void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    socket_bridge_stream_source_cancelled(
        context->reactor,
        context->bridge,
        context->stream);
    outersshpriv_reactor_source_cancelled(context->reactor);
    free(context);
}

static void socket_bridge_stream_source_cancelled(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle)
{
    SocketBridgeSlot *bridge_slot = socket_bridge_slot_for_handle(
        reactor,
        bridge_handle);
    assert(bridge_slot != NULL);
    SocketBridge *bridge = &bridge_slot->bridge;
    SocketBridgeStreamSlot *slot = socket_bridge_stream_slot_for_handle(
        bridge,
        stream_handle);
    assert(slot != NULL);
    assert(slot->stream.phase == SOCKET_BRIDGE_STREAM_ACTIVE ||
           slot->stream.phase == SOCKET_BRIDGE_STREAM_CANCELLING);
    assert(slot->stream.uncancelled_socket_source_count > 0);
    slot->stream.uncancelled_socket_source_count -= 1;
    if (slot->stream.uncancelled_socket_source_count != 0) {
        return;
    }
    assert(slot->stream.socket >= 0);
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_RELAY,
        "Socket bridge stream dispatch sources cancelled; closing local socket %{public}lld",
        (long long)slot->stream.socket);
    otsocket_close(slot->stream.socket);
    slot->stream.socket = -1;
    if (slot->stream.phase == SOCKET_BRIDGE_STREAM_CANCELLING) {
        recycle_socket_bridge_stream_slot(
            reactor,
            bridge_handle,
            stream_handle);
    }
}

static void recycle_socket_bridge_stream_slot(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle)
{
    SocketBridgeSlot *bridge_slot = socket_bridge_slot_for_handle(
        reactor,
        bridge_handle);
    assert(bridge_slot != NULL);
    SocketBridge *bridge = &bridge_slot->bridge;
    SocketBridgeStreamSlot *slot = socket_bridge_stream_slot_for_handle(
        bridge,
        stream_handle);
    assert(slot != NULL);
    assert(slot->stream.phase == SOCKET_BRIDGE_STREAM_CANCELLING);
    assert(slot->stream.uncancelled_socket_source_count == 0);
    assert(slot->stream.socket < 0);
    slot->stream = (SocketBridgeStream){.socket = -1};
    slot->generation += 1;
    if (slot->generation == 0) {
        slot->generation = 1;
    }
    slot->stream.phase = SOCKET_BRIDGE_STREAM_FREE;
    bridge->available_stream_indices[
        bridge->available_stream_index_count] = stream_handle.index;
    bridge->available_stream_index_count += 1;
    assert(bridge->cancelling_stream_count > 0);
    bridge->cancelling_stream_count -= 1;
    if (bridge_slot->phase == SOCKET_BRIDGE_SLOT_CANCELLING &&
        bridge->cancelling_stream_count == 0) {
        recycle_socket_bridge_slot(reactor, bridge_handle);
    }
}

static bool remove_socket_bridge_stream_by_id(
    SocketBridge *bridge,
    SocketBridgeStream *stream)
{
    size_t index = socket_bridge_stream_id_lower_bound(
        bridge,
        stream->stream_id);
    if (index >= bridge->stream_by_id_count ||
        bridge->stream_indices_by_id[index] != stream->slot_index) {
        return false;
    }
    size_t shifted_count = bridge->stream_by_id_count - index - 1;
    if (shifted_count != 0) {
        memmove(
            bridge->stream_indices_by_id + index,
            bridge->stream_indices_by_id + index + 1,
            shifted_count * sizeof(*bridge->stream_indices_by_id));
    }
    bridge->stream_by_id_count -= 1;
    return true;
}

#pragma mark - Stop or Fail the Socket Bridge

static void fail_pending_socket_bridge_streams(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SSHReactorSocketBridgeStreamResult result,
    const void *detail,
    size_t detail_length);
static void begin_cancelling_socket_bridge(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle);

void outersshpriv_reactor_stop_socket_bridge(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    bool send_eof)
{
    outersshpriv_reactor_assert_queue(reactor);
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return;
    }
    SSHReactorChannelToken channel_token = bridge->channel_token;
    finish_socket_bridge(reactor, bridge, SSH_REACTOR_SOCKET_BRIDGE_CANCELLED, 0, NULL, 0);
    close_socket_bridge_channel(reactor, channel_token, send_eof);
}

void outersshpriv_reactor_fail_all_socket_bridges(
    SSHReactor *reactor,
    SSHReactorSocketBridgeResult result)
{
    for (size_t index = 0; index < reactor->socket_bridge_slot_count; index++) {
        SocketBridgeSlot *slot = &reactor->socket_bridge_slots[index];
        if (slot->phase == SOCKET_BRIDGE_SLOT_ACTIVE) {
            finish_socket_bridge(reactor, &slot->bridge, result, 0, NULL, 0);
        }
    }
}

void outersshpriv_reactor_fail_socket_bridge_channel(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return;
    }
    close_socket_bridge(reactor, handle, result,
        result == SSH_REACTOR_SOCKET_BRIDGE_EXITED ? bridge->stderr_bytes : NULL,
        result == SSH_REACTOR_SOCKET_BRIDGE_EXITED ? bridge->stderr_byte_count : 0);
}

void outersshpriv_reactor_socket_bridge_channel_closed(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle handle)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return;
    }
    finish_socket_bridge(reactor, bridge, SSH_REACTOR_SOCKET_BRIDGE_EXITED, 0,
        bridge->stderr_bytes, bridge->stderr_byte_count);
}

static void close_socket_bridge(SSHReactor *reactor, SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result, const void *detail, size_t detail_length)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return;
    }
    SSHReactorChannelToken channel_token = bridge->channel_token;
    finish_socket_bridge(reactor, bridge, result, 0, detail, detail_length);
    close_socket_bridge_channel(reactor, channel_token, false);
}

static void close_socket_bridge_channel(SSHReactor *reactor,
    SSHReactorChannelToken channel_token, bool send_eof)
{
    if (!outersshpriv_reactor_accepts_work(reactor) || channel_token >= reactor->channel_capacity) {
        return;
    }
    SSHChannelState *channel = &reactor->channels[channel_token];
    switch (channel->owner.type) {
    case SSH_REACTOR_CHANNEL_OWNER_NONE:
        outersshpriv_reactor_close_channel(reactor, channel_token, false);
        break;
    case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE: {
        int error = outersshpriv_reactor_begin_channel_close(reactor, channel, channel_token, send_eof);
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
            return;
        }
        break;
    }
    case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
    case SSH_REACTOR_CHANNEL_OWNER_RELAY:
    case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
        return;
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
}

static void finish_socket_bridge(SSHReactor *reactor, SocketBridge *bridge,
    SSHReactorSocketBridgeResult result, uint32_t reason,
    const void *detail, size_t detail_length)
{
    SSHReactorSocketBridgeHandle handle = bridge->handle;
    SSHSocketChannelCallbacks callbacks = bridge->callbacks;
    void *ready_detail = NULL;
    size_t ready_detail_length = 0;
    if (callbacks.completed != NULL && detail != NULL && detail_length != 0) {
        ready_detail = malloc(detail_length);
        if (ready_detail != NULL) {
            memcpy(ready_detail, detail, detail_length);
            ready_detail_length = detail_length;
        }
    }
    SSHReactorSocketBridgeStreamResult stream_result =
        result == SSH_REACTOR_SOCKET_BRIDGE_SESSION_CLOSED
            ? SSH_REACTOR_SOCKET_BRIDGE_STREAM_SESSION_CLOSED
            : SSH_REACTOR_SOCKET_BRIDGE_STREAM_BRIDGE_CLOSED;
    fail_pending_socket_bridge_streams(reactor, bridge, stream_result, detail, detail_length);
    begin_cancelling_socket_bridge(reactor, handle);
    if (callbacks.completed != NULL) {
        callbacks.completed(callbacks.context, handle, result, reason, ready_detail, ready_detail_length);
    }
    free(ready_detail);
}

static void fail_pending_socket_bridge_streams(
    SSHReactor *reactor,
    SocketBridge *bridge,
    SSHReactorSocketBridgeStreamResult result,
    const void *detail,
    size_t detail_length)
{
    for (size_t index = 0; index < bridge->stream_slot_count; index++) {
        SocketBridgeStream *stream = &bridge->stream_slots[index].stream;
        if (stream->phase != SOCKET_BRIDGE_STREAM_ACTIVE || stream->open_operation == NULL) {
            continue;
        }
        ConnectBridgeStreamContext *operation = stream->open_operation;
        stream->open_operation = NULL;
        SSHReactorSocketBridgeStreamHandle handle = socket_bridge_stream_handle(bridge, stream);
        remove_socket_bridge_stream(reactor, bridge, stream);
        outersshpriv_session_pool_socket_bridge_stream_completed(
            operation, bridge->handle, handle, result, detail, detail_length);
    }
}

static void begin_cancelling_socket_bridge(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle)
{
    SocketBridgeSlot *slot = socket_bridge_slot_for_handle(reactor, handle);
    assert(slot != NULL);
    assert(slot->phase == SOCKET_BRIDGE_SLOT_ACTIVE);
    SocketBridge *bridge = &slot->bridge;
    cancel_socket_bridge_timer(bridge->ready_timer);
    bridge->ready_timer = NULL;
    cancel_socket_bridge_timer(bridge->ping_timer);
    bridge->ping_timer = NULL;
    for (size_t index = 0; index < bridge->stream_slot_count; index++) {
        SocketBridgeStreamSlot *stream_slot = &bridge->stream_slots[index];
        if (stream_slot->stream.phase == SOCKET_BRIDGE_STREAM_ACTIVE) {
            remove_socket_bridge_stream(
                reactor,
                bridge,
                &stream_slot->stream);
        }
    }
    assert(bridge->stream_by_id_count == 0);
    assert(bridge->pending_local_output_byte_count == 0);
    outersshpriv_helper_frame_parser_deinitialize(&bridge->parser);
    free(bridge->stderr_bytes);
    bridge->stderr_bytes = NULL;
    free(bridge->command);
    bridge->command = NULL;
    if (bridge->initial_input != NULL) {
        securely_clear_memory(
            bridge->initial_input,
            bridge->initial_input_length);
    }
    free(bridge->initial_input);
    bridge->initial_input = NULL;
    bridge->callbacks = (SSHSocketChannelCallbacks){0};
    slot->phase = SOCKET_BRIDGE_SLOT_CANCELLING;
    if (bridge->cancelling_stream_count == 0) {
        recycle_socket_bridge_slot(reactor, handle);
    }
}

static void cancel_socket_bridge_timer(otsource_t timer)
{
    if (timer == NULL) {
        return;
    }
    outersshpriv_reactor_cancel_source(timer);
}

static bool detach_socket_bridge(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    SocketBridge *detached_bridge)
{
    SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
    if (bridge == NULL) {
        return false;
    }
    SocketBridgeSlot *slot = &reactor->socket_bridge_slots[handle.index];
    *detached_bridge = slot->bridge;
    slot->bridge = (SocketBridge){0};
    slot->phase = SOCKET_BRIDGE_SLOT_FREE;
    reactor->available_socket_bridge_indices[
        reactor->available_socket_bridge_index_count] = handle.index;
    reactor->available_socket_bridge_index_count += 1;
    return true;
}

static void deinitialize_detached_socket_bridge(SocketBridge *bridge)
{
    cancel_socket_bridge_timer(bridge->ready_timer);
    bridge->ready_timer = NULL;
    cancel_socket_bridge_timer(bridge->ping_timer);
    bridge->ping_timer = NULL;
    for (size_t index = 0; index < bridge->stream_slot_count; index++) {
        assert(bridge->stream_slots[index].stream.phase ==
               SOCKET_BRIDGE_STREAM_FREE);
    }
    assert(bridge->stream_by_id_count == 0);
    assert(bridge->pending_local_output_byte_count == 0);
    free(bridge->stream_slots);
    free(bridge->available_stream_indices);
    free(bridge->stream_indices_by_id);
    outersshpriv_helper_frame_parser_deinitialize(&bridge->parser);
    free(bridge->stderr_bytes);
    free(bridge->command);
    if (bridge->initial_input != NULL) {
        securely_clear_memory(
            bridge->initial_input,
            bridge->initial_input_length);
    }
    free(bridge->initial_input);
    bridge->callbacks = (SSHSocketChannelCallbacks){0};
    *bridge = (SocketBridge){0};
}

static void securely_clear_memory(void *bytes, size_t byte_count)
{
    volatile unsigned char *cursor = bytes;
    while (byte_count > 0) {
        *cursor = 0;
        cursor += 1;
        byte_count -= 1;
    }
}

static void recycle_socket_bridge_slot(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle)
{
    SocketBridgeSlot *slot = socket_bridge_slot_for_handle(
        reactor,
        handle);
    assert(slot != NULL);
    assert(slot->phase == SOCKET_BRIDGE_SLOT_CANCELLING);
    SocketBridge *bridge = &slot->bridge;
    assert(bridge->cancelling_stream_count == 0);
    for (size_t index = 0; index < bridge->stream_slot_count; index++) {
        assert(bridge->stream_slots[index].stream.phase ==
               SOCKET_BRIDGE_STREAM_FREE);
    }
    free(bridge->stream_slots);
    free(bridge->available_stream_indices);
    free(bridge->stream_indices_by_id);
    *bridge = (SocketBridge){0};
    slot->generation += 1;
    if (slot->generation == 0) {
        slot->generation = 1;
    }
    slot->phase = SOCKET_BRIDGE_SLOT_FREE;
    reactor->available_socket_bridge_indices[
        reactor->available_socket_bridge_index_count] = handle.index;
    reactor->available_socket_bridge_index_count += 1;
}

#pragma mark - Look Up Bridges and Streams

SocketBridge *outersshpriv_reactor_socket_bridge_for_handle(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle)
{
    SocketBridgeSlot *slot = socket_bridge_slot_for_handle(
        reactor,
        handle);
    if (slot == NULL || slot->phase != SOCKET_BRIDGE_SLOT_ACTIVE) {
        return NULL;
    }
    return &slot->bridge;
}

static bool reserve_socket_bridge_slots(
    SSHReactor *reactor,
    size_t minimum_capacity)
{
    if (reactor->socket_bridge_slot_capacity >= minimum_capacity) {
        return true;
    }
    size_t capacity = reactor->socket_bridge_slot_capacity == 0
        ? 2
        : reactor->socket_bridge_slot_capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*reactor->socket_bridge_slots) ||
        capacity > SIZE_MAX / sizeof(*reactor->available_socket_bridge_indices)) {
        return false;
    }

    SocketBridgeSlot *slots = calloc(capacity, sizeof(*slots));
    size_t *available_indices = malloc(
        capacity * sizeof(*available_indices));
    if (slots == NULL || available_indices == NULL) {
        free(slots);
        free(available_indices);
        return false;
    }
    for (size_t index = 0;
         index < reactor->socket_bridge_slot_count;
         index++) {
        SocketBridgeSlot *source_slot =
            &reactor->socket_bridge_slots[index];
        SocketBridgeSlot *destination_slot = &slots[index];
        destination_slot->generation = source_slot->generation;
        destination_slot->phase = source_slot->phase;
        if (source_slot->phase == SOCKET_BRIDGE_SLOT_FREE) {
            continue;
        }
        destination_slot->bridge = source_slot->bridge;
        source_slot->bridge = (SocketBridge){0};
    }
    if (reactor->available_socket_bridge_index_count != 0) {
        memcpy(available_indices,
               reactor->available_socket_bridge_indices,
               reactor->available_socket_bridge_index_count *
                   sizeof(*available_indices));
    }
    free(reactor->socket_bridge_slots);
    free(reactor->available_socket_bridge_indices);
    reactor->socket_bridge_slots = slots;
    reactor->available_socket_bridge_indices = available_indices;
    reactor->socket_bridge_slot_capacity = capacity;
    return true;
}

static SocketBridgeSlot *socket_bridge_slot_for_handle(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle)
{
    if (handle.generation == 0 ||
        handle.index >= reactor->socket_bridge_slot_count) {
        return NULL;
    }
    SocketBridgeSlot *slot = &reactor->socket_bridge_slots[handle.index];
    if (slot->generation != handle.generation ||
        slot->phase == SOCKET_BRIDGE_SLOT_FREE) {
        return NULL;
    }
    return slot;
}

static SocketBridgeStream *socket_bridge_stream_for_handle(
    SocketBridge *bridge,
    SSHReactorSocketBridgeStreamHandle handle)
{
    return socket_bridge_stream_for_slot(
        bridge,
        handle.index,
        handle.generation);
}

static SocketBridgeStreamSlot *socket_bridge_stream_slot_for_handle(
    SocketBridge *bridge,
    SSHReactorSocketBridgeStreamHandle handle)
{
    if (handle.generation == 0 ||
        handle.index >= bridge->stream_slot_count) {
        return NULL;
    }
    SocketBridgeStreamSlot *slot = &bridge->stream_slots[handle.index];
    return slot->generation == handle.generation &&
            slot->stream.phase != SOCKET_BRIDGE_STREAM_FREE
        ? slot
        : NULL;
}

static SocketBridgeStream *socket_bridge_stream_for_id(
    SocketBridge *bridge,
    uint32_t stream_id)
{
    size_t index = socket_bridge_stream_id_lower_bound(bridge, stream_id);
    if (index >= bridge->stream_by_id_count) {
        return NULL;
    }
    size_t stream_index = bridge->stream_indices_by_id[index];
    SocketBridgeStreamSlot *slot = &bridge->stream_slots[stream_index];
    if (slot->stream.phase != SOCKET_BRIDGE_STREAM_ACTIVE ||
        slot->stream.stream_id != stream_id) {
        return NULL;
    }
    return &slot->stream;
}

static size_t socket_bridge_stream_id_lower_bound(
    SocketBridge *bridge,
    uint32_t stream_id)
{
    size_t lower = 0;
    size_t upper = bridge->stream_by_id_count;
    while (lower < upper) {
        size_t middle = lower + (upper - lower) / 2;
        size_t stream_index = bridge->stream_indices_by_id[middle];
        if (bridge->stream_slots[stream_index].stream.stream_id < stream_id) {
            lower = middle + 1;
        } else {
            upper = middle;
        }
    }
    return lower;
}

static SocketBridgeStream *socket_bridge_stream_for_slot(
    SocketBridge *bridge,
    size_t index,
    uint64_t generation)
{
    if (generation == 0 || index >= bridge->stream_slot_count) {
        return NULL;
    }
    SocketBridgeStreamSlot *slot = &bridge->stream_slots[index];
    if (slot->generation != generation ||
        slot->stream.phase != SOCKET_BRIDGE_STREAM_ACTIVE) {
        return NULL;
    }
    return &slot->stream;
}

static SSHReactorSocketBridgeStreamHandle socket_bridge_stream_handle(
    SocketBridge *bridge,
    SocketBridgeStream *stream)
{
    if (stream == NULL || stream->slot_index >= bridge->stream_slot_count) {
        return (SSHReactorSocketBridgeStreamHandle){0};
    }
    return (SSHReactorSocketBridgeStreamHandle){
        .index = stream->slot_index,
        .generation = bridge->stream_slots[stream->slot_index].generation
    };
}
