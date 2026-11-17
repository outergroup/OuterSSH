#include "SSHReactorInternal.h"
#include "platform/SSHLogging.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#pragma mark - Queue SSH Writes

static size_t
write_action_index(const SSHReactor *reactor, size_t offset);

int outersshpriv_reactor_enqueue_channel_data(
    SSHReactor *reactor,
    SSHReactorChannelToken token)
{
    if (reactor->channels[token].is_waiting_for_window) {
        return 0;
    }
    if (outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_DATA, token)) {
        return 0;
    }
    SSHWriteAction action = {
        .type = SSH_WRITE_CHANNEL_DATA,
        .token = token
    };
    return outersshpriv_reactor_append_write_action(reactor, action, false);
}

int
outersshpriv_reactor_enqueue_channel_eof(SSHReactor *reactor,
                    SSHChannelState *state,
                    SSHReactorChannelToken token)
{
    if (state->is_closing) {
        return 0;
    }
    if (state->sent_eof) {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Channel EOF was already sent; received_eof=%{public}s token=%{public}llu pointer=%{public}p",
            state->received_eof ? "true" : "false",
            (unsigned long long)token,
            state);
        return state->received_eof
            ? outersshpriv_reactor_enqueue_channel_close(reactor, token)
            : 0;
    }
    size_t pending_byte_count;
    switch (state->purpose) {
    case SSH_CHANNEL_PURPOSE_RELAY:
        pending_byte_count = outersshpriv_relay_buffer_pending(&state->relay->to_ssh);
        break;
    case SSH_CHANNEL_PURPOSE_EXEC:
        pending_byte_count = outersshpriv_reactor_buffer_pending_byte_count(
            &state->exec_input);
        break;
    default:
        abort();
    }
    if (pending_byte_count > 0) {
        state->send_eof_after_output_drains = true;
        return 0;
    }
    state->send_eof_after_output_drains = false;
    if (outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_EOF, token)) {
        return 0;
    }
    SSHWriteAction action = {
        .type = SSH_WRITE_CHANNEL_EOF,
        .token = token
    };
    return outersshpriv_reactor_append_write_action(reactor, action, false);
}

int
outersshpriv_reactor_enqueue_channel_close(SSHReactor *reactor,
                      SSHReactorChannelToken token)
{
    if (reactor->channels[token].close_sent ||
        outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_CLOSE, token)) {
        return 0;
    }
    SSHWriteAction action = {
        .type = SSH_WRITE_CHANNEL_CLOSE,
        .token = token
    };
    return outersshpriv_reactor_append_write_action(reactor, action, false);
}

int
outersshpriv_reactor_enqueue_protocol_response(SSHReactor *reactor,
                          const unsigned char *packet,
                          size_t packet_length)
{
    if (!reactor || !packet || packet_length == 0) {
        return LIBSSH2_ERROR_INVAL;
    }
    SSHWriteAction action = {
        .type = SSH_WRITE_PROTOCOL_RESPONSE,
        .payload.packet.length = packet_length
    };
    action.payload.packet.bytes = malloc(packet_length);
    if (!action.payload.packet.bytes) {
        return LIBSSH2_ERROR_ALLOC;
    }
    memcpy(action.payload.packet.bytes, packet, packet_length);

    int result = outersshpriv_reactor_append_write_action(reactor, action, false);
    if (result) {
        outersshpriv_reactor_destroy_write_action(&action);
    }
    return result;
}

int
outersshpriv_reactor_append_write_action(SSHReactor *reactor,
                    SSHWriteAction action,
                    bool at_front)
{
    if (!reactor || reactor->write_action_count == SIZE_MAX) {
        return reactor ? LIBSSH2_ERROR_ALLOC : LIBSSH2_ERROR_INVAL;
    }
    int reserve_result = outersshpriv_reactor_reserve_write_actions(
        reactor,
        reactor->write_action_count + 1);
    if (reserve_result) {
        return reserve_result;
    }
    outersshpriv_reactor_append_reserved_write_action(reactor, action, at_front);
    return 0;
}

int
outersshpriv_reactor_reserve_write_actions(SSHReactor *reactor, size_t minimum_capacity)
{
    if (reactor->write_action_capacity >= minimum_capacity) {
        return 0;
    }

    size_t capacity = reactor->write_action_capacity
        ? reactor->write_action_capacity
        : 8;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return LIBSSH2_ERROR_ALLOC;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*reactor->write_actions)) {
        return LIBSSH2_ERROR_ALLOC;
    }

    SSHWriteAction *actions = calloc(capacity, sizeof(*actions));
    if (!actions) {
        return LIBSSH2_ERROR_ALLOC;
    }
    for (size_t offset = 0; offset < reactor->write_action_count; offset++) {
        actions[offset] = *outersshpriv_reactor_write_action_at(reactor, offset);
    }
    free(reactor->write_actions);
    reactor->write_actions = actions;
    reactor->write_action_head = 0;
    reactor->write_action_capacity = capacity;
    return 0;
}

/// Only use this if you manually call `outersshpriv_reactor_reserve_write_actions`.
/// Otherwise, use `outersshpriv_reactor_append_write_action`.
void
outersshpriv_reactor_append_reserved_write_action(SSHReactor *reactor,
                             SSHWriteAction action,
                             bool at_front)
{
    size_t index;
    if (at_front) {
        reactor->write_action_head = reactor->write_action_head == 0
            ? reactor->write_action_capacity - 1
            : reactor->write_action_head - 1;
        index = reactor->write_action_head;
    }
    else {
        index = write_action_index(reactor, reactor->write_action_count);
    }
    reactor->write_actions[index] = action;
    reactor->write_action_count += 1;
}

SSHWriteAction *
outersshpriv_reactor_write_action_at(SSHReactor *reactor, size_t offset)
{
    if (!reactor || offset >= reactor->write_action_count) {
        return NULL;
    }
    return &reactor->write_actions[write_action_index(reactor, offset)];
}

const SSHWriteAction *
outersshpriv_reactor_const_write_action_at(const SSHReactor *reactor, size_t offset)
{
    if (!reactor || offset >= reactor->write_action_count) {
        return NULL;
    }
    return &reactor->write_actions[write_action_index(reactor, offset)];
}

static size_t
write_action_index(const SSHReactor *reactor, size_t offset)
{
    size_t space_after_head =
        reactor->write_action_capacity - reactor->write_action_head;
    return offset < space_after_head
        ? reactor->write_action_head + offset
        : offset - space_after_head;
}

bool
outersshpriv_reactor_has_write_action(SSHReactor *reactor,
                 SSHWriteActionType type,
                 SSHReactorChannelToken token)
{
    for (size_t offset = 0; offset < reactor->write_action_count; offset++) {
        SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, offset);
        if (action->type == type && action->token == token) {
            return true;
        }
    }
    return false;
}

void
outersshpriv_reactor_move_write_action_to_front(SSHReactor *reactor, size_t offset)
{
    SSHWriteAction selected = *outersshpriv_reactor_write_action_at(reactor, offset);
    for (size_t position = offset; position > 0; position--) {
        *outersshpriv_reactor_write_action_at(reactor, position) =
            *outersshpriv_reactor_write_action_at(reactor, position - 1);
    }
    *outersshpriv_reactor_write_action_at(reactor, 0) = selected;
}

void
outersshpriv_reactor_pop_write_action(SSHReactor *reactor)
{
    SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, 0);
    outersshpriv_reactor_destroy_write_action(action);
    reactor->write_action_count -= 1;
    if (reactor->write_action_count == 0) {
        reactor->write_action_head = 0;
    }
    else {
        reactor->write_action_head =
            (reactor->write_action_head + 1) % reactor->write_action_capacity;
    }
}

void
outersshpriv_reactor_destroy_write_action(SSHWriteAction *action)
{
    if (!action) {
        return;
    }
    switch (action->type) {
    case SSH_WRITE_CHANNEL_EXEC:
        free(action->payload.exec.command);
        break;
    case SSH_WRITE_CHANNEL_OPEN:
    case SSH_WRITE_KEEPALIVE:
    case SSH_WRITE_PROTOCOL_RESPONSE:
        free(action->payload.packet.bytes);
        break;
    case SSH_WRITE_CHANNEL_DATA:
    case SSH_WRITE_CHANNEL_WINDOW_ADJUST:
    case SSH_WRITE_CHANNEL_EOF:
    case SSH_WRITE_CHANNEL_CLOSE:
        break;
    }
    memset(action, 0, sizeof(*action));
}

void
outersshpriv_reactor_remove_channel_actions_for_close(SSHReactor *reactor,
                                 SSHReactorChannelToken token)
{
    size_t kept_count = 0;
    size_t original_count = reactor->write_action_count;
    for (size_t offset = 0; offset < original_count; offset++) {
        SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, offset);
        if (outersshpriv_reactor_write_action_is_removed_for_channel_close(action, token)) {
            outersshpriv_reactor_destroy_write_action(action);
            continue;
        }
        if (kept_count != offset) {
            SSHWriteAction *destination = outersshpriv_reactor_write_action_at(
                reactor,
                kept_count);
            *destination = *action;
            memset(action, 0, sizeof(*action));
        }
        kept_count += 1;
    }
    reactor->write_action_count = kept_count;
    if (kept_count == 0) {
        reactor->write_action_head = 0;
    }
}

bool
outersshpriv_reactor_write_action_is_removed_for_channel_close(
    const SSHWriteAction *action,
    SSHReactorChannelToken token)
{
    return !action->must_resume && action->token == token &&
        (action->type == SSH_WRITE_CHANNEL_DATA ||
         action->type == SSH_WRITE_CHANNEL_WINDOW_ADJUST ||
         action->type == SSH_WRITE_CHANNEL_EOF ||
         action->type == SSH_WRITE_CHANNEL_CLOSE ||
         action->type == SSH_WRITE_CHANNEL_EXEC);
}

#pragma mark - Relay Buffers

int outersshpriv_relay_buffer_initialize(SSHRelayBuffer *buffer, size_t capacity)
{
    *buffer = (SSHRelayBuffer){0};
    buffer->bytes = malloc(capacity);
    if (!buffer->bytes) {
        return LIBSSH2_ERROR_ALLOC;
    }
    buffer->capacity = capacity;
    return 0;
}

void outersshpriv_relay_buffer_deinitialize(SSHRelayBuffer *buffer)
{
    free(buffer->bytes);
    *buffer = (SSHRelayBuffer){0};
}

int outersshpriv_relay_buffer_append(SSHRelayBuffer *buffer, const void *bytes, size_t byte_count)
{
    if (!bytes && byte_count > 0) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (byte_count > outersshpriv_relay_buffer_space(buffer)) {
        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
    }
    const unsigned char *source = bytes;
    while (byte_count > 0) {
        size_t span;
        unsigned char *destination = outersshpriv_relay_buffer_writable(buffer, &span);
        if (span > byte_count) {
            span = byte_count;
        }
        memcpy(destination, source, span);
        outersshpriv_relay_buffer_commit(buffer, span);
        source += span;
        byte_count -= span;
    }
    return 0;
}

#pragma mark - Channel Output Buffers

int
outersshpriv_reactor_output_buffer_initialize(SSHChannelOutputBuffer *buffer,
                         size_t initial_capacity)
{
    memset(buffer, 0, sizeof(*buffer));
    if (initial_capacity == 0) {
        return 0;
    }
    buffer->bytes = malloc(initial_capacity);
    if (!buffer->bytes) {
        return LIBSSH2_ERROR_ALLOC;
    }
    buffer->capacity = initial_capacity;
    return 0;
}

int outersshpriv_reactor_output_buffer_append(
    SSHChannelOutputBuffer *buffer,
    const void *bytes,
    size_t byte_count)
{
    if (!bytes && byte_count > 0) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (byte_count == 0) {
        return 0;
    }

    size_t pending_byte_count = buffer->byte_count - buffer->offset;
    if (byte_count > SIZE_MAX - pending_byte_count) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (buffer->offset != 0) {
        if (pending_byte_count != 0) {
            memmove(buffer->bytes,
                    buffer->bytes + buffer->offset,
                    pending_byte_count);
        }
        buffer->offset = 0;
        buffer->byte_count = pending_byte_count;
    }

    size_t required_capacity = buffer->byte_count + byte_count;
    if (required_capacity > buffer->capacity) {
        size_t new_capacity = buffer->capacity ? buffer->capacity : 4096;
        while (new_capacity < required_capacity) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = required_capacity;
                break;
            }
            new_capacity *= 2;
        }
        unsigned char *resized_bytes = realloc(buffer->bytes, new_capacity);
        if (!resized_bytes) {
            return LIBSSH2_ERROR_ALLOC;
        }
        buffer->bytes = resized_bytes;
        buffer->capacity = new_capacity;
    }

    memcpy(buffer->bytes + buffer->byte_count, bytes, byte_count);
    buffer->byte_count += byte_count;
    return 0;
}

size_t
outersshpriv_reactor_buffer_pending_byte_count(
    const SSHChannelOutputBuffer *buffer)
{
    return buffer->byte_count - buffer->offset;
}

void
outersshpriv_reactor_output_buffer_clear(SSHChannelOutputBuffer *buffer,
                                    bool keeping_capacity)
{
    buffer->byte_count = 0;
    buffer->offset = 0;
    if (!keeping_capacity) {
        free(buffer->bytes);
        buffer->bytes = NULL;
        buffer->capacity = 0;
    }
}

void
outersshpriv_reactor_output_buffer_deinitialize(SSHChannelOutputBuffer *buffer)
{
    free(buffer->bytes);
    memset(buffer, 0, sizeof(*buffer));
}
