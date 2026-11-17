#include "platform/OTSocket.h"
#include "SSHReactorInternal.h"
#include "SSHReactorReadInternal.h"
#include "SSHReactorCommandInternal.h"
#include "SSHFlows.h"
#include "SSHSessionPoolInternal.h"
#include "platform/SSHLogging.h"
#include "HelperProtocol.h"
#include "olibssh/read_dispatch.h"
#include "olibssh/key_exchange.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static void relay_socket_ready(void *opaque_context);
static void relay_attachment_failed(SSHRelay *relay);
static void begin_closing_relay_socket(
    SSHReactor *reactor,
    RelaySlot *relay);
static void relay_source_cancelled(void *opaque_context);
static void maybe_recycle_relay_slot(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);
static void mark_relay_closed(SSHRelay *relay);
static SSHRelay *
retain_relay(SSHRelay *relay);
static bool reserve_relays(
    SSHReactor *reactor,
    size_t minimum_capacity);

#pragma mark - Prepare and Attach a Relay

static void handle_prepared_relay_channel_open(
    SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason);
static SSHRelay *ssh_relay_create(
    otsocket_t socket,
    uint64_t identifier,
    uint64_t proxy_generation,
    SSHRelayTargetType target_type,
    const char *target_destination,
    size_t target_destination_length,
    int target_port);
static int add_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle *handle,
    SSHReactorRelayHandle existing_handle,
    SSHReactorChannelToken channel_token,
    SSHRelay *owned_relay,
    SSHRelayOwnershipState expected_state);
static bool relay_begin_attachment(
    SSHRelay *relay,
    SSHRelayOwnershipState expected_state);
static int
attach_relay_to_channel(SSHReactor *reactor,
                        SSHChannelState *channel,
                        SSHReactorChannelToken token,
                        SSHRelay *relay);
static int
transfer_unattached_remote_data(
    SSHChannelState *state,
    SSHRelay *relay,
    size_t byte_count);
static bool
channel_allows_initial_relay_assignment(SSHReactor *reactor,
                                        SSHChannelState *state,
                                        SSHReactorChannelToken token);
static bool
channel_allows_initial_assignment(SSHReactor *reactor,
                                  SSHChannelState *state,
                                  SSHReactorChannelToken token);

#if !defined(SSH_REACTOR_TESTS)

int outersshpriv_reactor_prepare_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle *handle,
    ConnectRelayContext *operation,
    const SSHRelayTarget *target,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (handle != NULL) {
        *handle = (SSHReactorRelayHandle){0};
    }
    if (!outersshpriv_reactor_accepts_work(reactor) || handle == NULL || operation == NULL ||
        target == NULL || source_host == NULL) {
        return LIBSSH2_ERROR_INVAL;
    }

    if (reactor->available_relay_index_count == 0 &&
        (reactor->relay_slot_count == SIZE_MAX ||
         !reserve_relays(reactor, reactor->relay_slot_count + 1))) {
        return LIBSSH2_ERROR_ALLOC;
    }
    size_t index;
    if (reactor->available_relay_index_count > 0) {
        reactor->available_relay_index_count -= 1;
        index = reactor->available_relay_indices[
            reactor->available_relay_index_count];
    } else {
        index = reactor->relay_slot_count;
        reactor->relay_slot_count += 1;
    }
    RelaySlot *relay = &reactor->relay_slots[index];
    relay->generation += 1;
    if (relay->generation == 0) {
        relay->generation = 1;
    }
    relay->state = (SSHReactorRelayState){.socket = -1};
    relay->state.channel_token = 0;
    relay->state.channel_phase = SSH_RELAY_CHANNEL_OPENING;
    relay->state.socket_phase = SSH_RELAY_SOCKET_UNATTACHED;
    *handle = (SSHReactorRelayHandle){
        .index = index,
        .generation = relay->generation
    };

    SSHReactorRelayHandle current_handle = *handle;
    SSHReactorChannelToken channel_token = 0;
    SSHReactorPendingChannelOpen pending_open = {
        .finished = handle_prepared_relay_channel_open,
        .prepared_relay_operation = operation,
        .target.prepared_relay_handle = current_handle
    };
    int result;
    switch (target->kind) {
    case SSHRelayTargetTCP:
        result = outersshpriv_reactor_open_tcp_channel(
            reactor,
            &channel_token,
            target->destination,
            target->destination_length,
            target->port,
            source_host, source_host_length,
            source_port,
            timeout_milliseconds,
            pending_open);
        break;
    case SSHRelayTargetUnixSocket:
        result = outersshpriv_reactor_open_streamlocal_channel(
            reactor,
            &channel_token,
            target->destination,
            target->destination_length,
            source_host, source_host_length,
            source_port,
            timeout_milliseconds,
            pending_open);
        break;
    default:
        abort();
    }
    if (result != 0) {
        outersshpriv_reactor_remove_prepared_relay(reactor, current_handle);
        *handle = (SSHReactorRelayHandle){0};
        return result;
    }
    relay = outersshpriv_reactor_slot_for_handle(reactor, current_handle);
    if (relay == NULL) {
        return LIBSSH2_ERROR_PROTO;
    }
    relay->state.channel_token = channel_token;
    return 0;
}

static void handle_prepared_relay_channel_open(
    SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason)
{
    ConnectRelayContext *operation = pending->prepared_relay_operation;
    SSHReactorRelayHandle handle = pending->target.prepared_relay_handle;
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(
        reactor,
        handle);
    if (relay == NULL) {
        if (result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED &&
            outersshpriv_reactor_accepts_work(reactor)) {
            int close_result = outersshpriv_reactor_begin_channel_close(
                reactor,
                &reactor->channels[channel_token],
                channel_token,
                false);
            if (close_result != 0) {
                outersshpriv_reactor_fail(
                    reactor,
                    SSH_REACTOR_OPERATION_WRITE,
                    close_result);
            } else {
                outersshpriv_reactor_update_channel_write_source(reactor);
            }
        }
    } else if (relay->state.channel_token != channel_token) {
        outersshpriv_reactor_fail(
            reactor,
            SSH_REACTOR_OPERATION_READ,
            LIBSSH2_ERROR_PROTO);
        outersshpriv_session_pool_prepared_relay_completed(
            operation,
            handle,
            SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED, 0);
        return;
    }

    if (relay != NULL) {
        assert(relay->state.channel_phase == SSH_RELAY_CHANNEL_OPENING);
        assert(relay->state.socket_phase == SSH_RELAY_SOCKET_UNATTACHED);
        if (result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED) {
            relay->state.channel_phase = SSH_RELAY_CHANNEL_OPEN;
            outersshpriv_session_pool_prepared_relay_completed(operation, handle, SSH_REACTOR_RELAY_OPEN_SUCCEEDED, 0);
            return;
        }
        outersshpriv_reactor_remove_prepared_relay(reactor, handle);
    }

    SSHReactorRelayOpenResult relay_result;
    switch (result) {
    case SSH_REACTOR_CHANNEL_OPEN_FAILED:
        relay_result = SSH_REACTOR_RELAY_OPEN_CHANNEL_FAILED;
        break;
    case SSH_REACTOR_CHANNEL_OPEN_TIMED_OUT:
        relay_result = SSH_REACTOR_RELAY_OPEN_TIMED_OUT;
        break;
    case SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED:
    case SSH_REACTOR_CHANNEL_OPEN_SESSION_CLOSED:
        relay_result = SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED;
        break;
    default:
        abort();
    }
    outersshpriv_session_pool_prepared_relay_completed(operation, handle, relay_result, reason);
}

int outersshpriv_reactor_attach_prepared_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle,
    otsocket_t socket,
    uint64_t identifier,
    uint64_t proxy_generation,
    SSHRelayTargetType target_type,
    const char *target_destination,
    size_t target_destination_length,
    int target_port)
{
    outersshpriv_reactor_assert_queue(reactor);
    RelaySlot *prepared = outersshpriv_reactor_slot_for_handle(
        reactor,
        handle);
    if (socket < 0 || !outersshpriv_reactor_accepts_work(reactor) || prepared == NULL ||
        prepared->state.channel_phase != SSH_RELAY_CHANNEL_OPEN ||
        prepared->state.socket_phase != SSH_RELAY_SOCKET_UNATTACHED) {
        if (socket >= 0) {
            otsocket_close(socket);
        }
        return LIBSSH2_ERROR_INVAL;
    }

    SSHReactorChannelToken current_channel_token = prepared->state.channel_token;
    SSHRelay *owned_relay = ssh_relay_create(
        socket,
        identifier,
        proxy_generation,
        target_type,
        target_destination,
        target_destination_length,
        target_port);
    if (owned_relay == NULL) {
        otsocket_close(socket);
        outersshpriv_reactor_remove_prepared_relay(reactor, handle);
        int close_result = outersshpriv_reactor_begin_channel_close(
            reactor,
            &reactor->channels[current_channel_token],
            current_channel_token,
            false);
        if (close_result == 0) {
            outersshpriv_reactor_update_channel_write_source(reactor);
        }
        return close_result == 0 ? LIBSSH2_ERROR_ALLOC : close_result;
    }

    SSHReactorRelayHandle attached_handle = {0};
    int result = add_relay(
        reactor,
        &attached_handle,
        handle,
        current_channel_token,
        owned_relay,
        SSH_RELAY_DETACHED);
    if (result != 0) {
        outersshpriv_relay_release(owned_relay);
        RelaySlot *failed_relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
        if (failed_relay != NULL &&
            failed_relay->state.channel_phase == SSH_RELAY_CHANNEL_OPEN &&
            failed_relay->state.socket_phase ==
                SSH_RELAY_SOCKET_UNATTACHED) {
            outersshpriv_reactor_remove_prepared_relay(reactor, handle);
        }
        int close_result = outersshpriv_reactor_begin_channel_close(
            reactor,
            &reactor->channels[current_channel_token],
            current_channel_token,
            false);
        if (close_result == 0) {
            outersshpriv_reactor_update_channel_write_source(reactor);
        }
        return result;
    }

    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, attached_handle);
    if (relay != NULL && !outersshpriv_reactor_close_finished_relay(reactor, relay)) {
        outersshpriv_reactor_update_relay_read_source(reactor, relay);
        outersshpriv_reactor_update_relay_write_source(reactor, relay);
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
    return 0;
}

#endif

static SSHRelay *ssh_relay_create(
    otsocket_t socket,
    uint64_t identifier,
    uint64_t proxy_generation,
    SSHRelayTargetType target_type,
    const char *target_destination,
    size_t target_destination_length,
    int target_port)
{
    if (socket < 0 || target_destination == NULL || target_destination_length == 0) {
        return NULL;
    }
    SSHRelay *relay = calloc(1, sizeof(*relay));
    if (relay == NULL) {
        return NULL;
    }
    if (outersshpriv_relay_buffer_initialize(&relay->to_ssh, SSH_READ_BUFFER_CAPACITY) != 0 ||
        outersshpriv_relay_buffer_initialize(&relay->to_socket, SSH_READ_BUFFER_CAPACITY) != 0) {
        outersshpriv_relay_buffer_deinitialize(&relay->to_ssh);
        outersshpriv_relay_buffer_deinitialize(&relay->to_socket);
        free(relay);
        return NULL;
    }
    relay->socket_read_open = true;
    relay->channel_read_open = true;
    relay->identifier = identifier;
    relay->proxy_generation = proxy_generation;
    relay->route.type = target_type;
    relay->route.destination = malloc(target_destination_length);
    relay->route.destination_length = target_destination_length;
    relay->route.port = target_port;
    if (relay->route.destination == NULL) {
        outersshpriv_relay_buffer_deinitialize(&relay->to_ssh);
        outersshpriv_relay_buffer_deinitialize(&relay->to_socket);
        free(relay);
        return NULL;
    }
    memcpy(relay->route.destination, target_destination, target_destination_length);
    atomic_init(&relay->reference_count, 1);
    atomic_init(&relay->socket, socket);
    atomic_init(&relay->ownership_state, SSH_RELAY_DETACHED);
    return relay;
}

#if !defined(SSH_REACTOR_TESTS)

static int add_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle *handle,
    SSHReactorRelayHandle existing_handle,
    SSHReactorChannelToken channel_token,
    SSHRelay *owned_relay,
    SSHRelayOwnershipState expected_state)
{
    if (!outersshpriv_reactor_accepts_work(reactor) || handle == NULL || owned_relay == NULL) {
        return LIBSSH2_ERROR_INVAL;
    }
    otsocket_t socket = atomic_load_explicit(
        &owned_relay->socket,
        memory_order_acquire);
    if (socket < 0) {
        return LIBSSH2_ERROR_INVAL;
    }
    *handle = (SSHReactorRelayHandle){0};
    SSHChannelState *channel = &reactor->channels[channel_token];
    SSHReactorChannelOwner *owner = &channel->owner;
    if (!channel->in_use ||
        owner->type != SSH_REACTOR_CHANNEL_OWNER_NONE ||
        !relay_begin_attachment(owned_relay, expected_state)) {
        return LIBSSH2_ERROR_BAD_USE;
    }
    if (!outersshpriv_reactor_configure_nonblocking_stream_socket(socket)) {
        relay_attachment_failed(owned_relay);
        return LIBSSH2_ERROR_SOCKET_SEND;
    }

    bool reusing_prepared_relay = existing_handle.generation != 0;
    size_t index;
    RelaySlot *relay;
    if (reusing_prepared_relay) {
        relay = outersshpriv_reactor_slot_for_handle(reactor, existing_handle);
        if (relay == NULL ||
            relay->state.channel_phase != SSH_RELAY_CHANNEL_OPEN ||
            relay->state.socket_phase != SSH_RELAY_SOCKET_UNATTACHED ||
            relay->state.channel_token != channel_token) {
            relay_attachment_failed(owned_relay);
            return LIBSSH2_ERROR_BAD_USE;
        }
        index = existing_handle.index;
    } else {
        if (reactor->available_relay_index_count > 0) {
            reactor->available_relay_index_count -= 1;
            index = reactor->available_relay_indices[
                reactor->available_relay_index_count];
        } else {
            if (reactor->relay_slot_count == SIZE_MAX ||
                !reserve_relays(reactor, reactor->relay_slot_count + 1)) {
                relay_attachment_failed(owned_relay);
                return LIBSSH2_ERROR_ALLOC;
            }
            index = reactor->relay_slot_count;
            reactor->relay_slot_count += 1;
        }
        relay = &reactor->relay_slots[index];
        relay->generation += 1;
        if (relay->generation == 0) {
            relay->generation = 1;
        }
    }
    SSHReactorRelayHandle current_handle = {
        .index = index,
        .generation = relay->generation
    };
    if (!reusing_prepared_relay) {
        relay->state = (SSHReactorRelayState){.socket = -1};
        relay->state.channel_token = channel_token;
        relay->state.channel_phase = SSH_RELAY_CHANNEL_OPEN;
        relay->state.socket_phase = SSH_RELAY_SOCKET_UNATTACHED;
    }
    SSHReactorSourceContext *read_context =
        outersshpriv_reactor_create_source_context(reactor, NULL);
    SSHReactorSourceContext *write_context =
        outersshpriv_reactor_create_source_context(reactor, NULL);
    if (read_context == NULL || write_context == NULL) {
        free(read_context);
        free(write_context);
        if (!reusing_prepared_relay) {
            relay->state = (SSHReactorRelayState){.socket = -1};
            relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSED;
            maybe_recycle_relay_slot(reactor, current_handle);
        }
        relay_attachment_failed(owned_relay);
        return LIBSSH2_ERROR_ALLOC;
    }
    read_context->relay = current_handle;
    write_context->relay = current_handle;
    write_context->writes = true;
    relay->state.read_socket_source = otsource_create(
        OTSOURCE_TYPE_READ,
        (uintptr_t)socket,
        reactor->queue);
    if (relay->state.read_socket_source == NULL) {
        free(read_context);
        free(write_context);
        if (!reusing_prepared_relay) {
            relay->state = (SSHReactorRelayState){.socket = -1};
            relay->relay = NULL;
            relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSED;
            maybe_recycle_relay_slot(reactor, current_handle);
        }
        relay_attachment_failed(owned_relay);
        return LIBSSH2_ERROR_ALLOC;
    }
    read_context->source = relay->state.read_socket_source;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(relay->state.read_socket_source, read_context);
    otsource_set_cancel_handler(
        relay->state.read_socket_source,
        relay_source_cancelled);
    otsource_set_event_handler(
        relay->state.read_socket_source,
        relay_socket_ready);

    relay->state.write_socket_source = otsource_create(
        OTSOURCE_TYPE_WRITE,
        (uintptr_t)socket,
        reactor->queue);
    if (relay->state.write_socket_source == NULL) {
        free(write_context);
        relay->relay = NULL;
        relay->state.socket = socket;
        relay->state.uncancelled_socket_source_count = 1;
        relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSED;
        relay->state.socket_phase = SSH_RELAY_SOCKET_CANCELLING;
        mark_relay_closed(owned_relay);
        otsource_activate(relay->state.read_socket_source);
        outersshpriv_reactor_cancel_source(relay->state.read_socket_source);
        return LIBSSH2_ERROR_ALLOC;
    }
    write_context->source = relay->state.write_socket_source;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(relay->state.write_socket_source, write_context);
    otsource_set_cancel_handler(
        relay->state.write_socket_source,
        relay_source_cancelled);
    otsource_set_event_handler(
        relay->state.write_socket_source,
        relay_socket_ready);

    relay->state.channel_token = channel_token;
    relay->state.socket = socket;
    relay->relay = owned_relay;
    relay->state.uncancelled_socket_source_count = 2;
    relay->state.read_socket_source_is_resumed = false;
    relay->state.write_socket_source_is_resumed = false;
    relay->state.remote_output_finished = false;
    relay->state.channel_phase = SSH_RELAY_CHANNEL_OPEN;
    relay->state.socket_phase = SSH_RELAY_SOCKET_ACTIVE;

    int attach_result = attach_relay_to_channel(
        reactor,
        channel,
        channel_token,
        owned_relay);
    if (attach_result != 0) {
        begin_closing_relay_socket(reactor, relay);
        relay->state.channel_token = 0;
        relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSED;
        relay->relay = NULL;
        maybe_recycle_relay_slot(reactor, current_handle);
        return attach_result;
    }
    relay->state.remote_output_finished =
        !owned_relay->channel_read_open;

    atomic_store_explicit(
        &owned_relay->ownership_state,
        SSH_RELAY_ATTACHED,
        memory_order_release);
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_RELAY,
        "Attached local socket %{public}lld to SSH channel; relay index=%{public}zu generation=%{public}llu channel=%{public}llu",
        (long long)socket,
        current_handle.index,
        (unsigned long long)current_handle.generation,
        (unsigned long long)channel_token);
    owner->type = SSH_REACTOR_CHANNEL_OWNER_RELAY;
    owner->relay_handle = current_handle;
    *handle = current_handle;
    return 0;
}

static bool relay_begin_attachment(
    SSHRelay *relay,
    SSHRelayOwnershipState expected_state)
{
    int expected = expected_state;
    return relay != NULL && atomic_compare_exchange_strong_explicit(
        &relay->ownership_state,
        &expected,
        SSH_RELAY_ATTACHING,
        memory_order_acq_rel,
        memory_order_acquire);
}

#endif

static int
attach_relay_to_channel(SSHReactor *reactor,
                        SSHChannelState *channel,
                        SSHReactorChannelToken token,
                        SSHRelay *relay)
{
    if (!channel_allows_initial_relay_assignment(
            reactor,
            channel,
            token)) {
        return LIBSSH2_ERROR_BAD_USE;
    }

    bool has_pending_data = outersshpriv_relay_buffer_pending(&relay->to_ssh) > 0;
    size_t unattached_byte_count = outersshpriv_reactor_buffer_pending_byte_count(
        &channel->unattached_remote_buffer);
    bool may_enqueue_window_adjust =
        unattached_byte_count >= SSH_READ_BUFFER_CAPACITY / 2;
    bool sends_eof_immediately =
        !relay->socket_read_open && !has_pending_data;
    size_t action_count =
        (has_pending_data ? 1 : 0) +
        (sends_eof_immediately ? 1 : 0) +
        (may_enqueue_window_adjust ? 1 : 0);
    if (reactor->write_action_count > SIZE_MAX - action_count) {
        return LIBSSH2_ERROR_ALLOC;
    }
    int result = outersshpriv_reactor_reserve_write_actions(
        reactor,
        reactor->write_action_count + action_count);
    if (result != 0) {
        return result;
    }
    result = transfer_unattached_remote_data(
        channel,
        relay,
        unattached_byte_count);
    if (result != 0) {
        return result;
    }

    channel->relay = retain_relay(relay);
    relay->channel_read_open =
        relay->channel_read_open && !channel->received_eof;
    outersshpriv_reactor_output_buffer_deinitialize(&channel->unattached_remote_buffer);
    if (has_pending_data) {
        SSHWriteAction data_action = {
            .type = SSH_WRITE_CHANNEL_DATA,
            .token = token
        };
        outersshpriv_reactor_append_reserved_write_action(reactor, data_action, false);
    }
    channel->send_eof_after_output_drains =
        !relay->socket_read_open && has_pending_data;
    if (sends_eof_immediately) {
        SSHWriteAction eof_action = {
            .type = SSH_WRITE_CHANNEL_EOF,
            .token = token
        };
        outersshpriv_reactor_append_reserved_write_action(reactor, eof_action, false);
    }
    if (unattached_byte_count > 0 &&
        outersshpriv_relay_buffer_pending(&relay->to_socket) == 0) {
        size_t credit = relay->pending_window_credit;
        relay->pending_window_credit = 0;
        return outersshpriv_reactor_consume_channel_bytes(
            reactor,
            channel,
            token,
            credit);
    }
    return 0;
}

static int
transfer_unattached_remote_data(
    SSHChannelState *state,
    SSHRelay *relay,
    size_t byte_count)
{
    if (byte_count > SIZE_MAX - relay->pending_window_credit) {
        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
    }
    if (byte_count == 0) {
        return 0;
    }
    int result = outersshpriv_relay_buffer_append(
        &relay->to_socket,
        state->unattached_remote_buffer.bytes + state->unattached_remote_buffer.offset,
        byte_count);
    if (result == 0) {
        relay->pending_window_credit += byte_count;
    }
    return result;
}

static bool
channel_allows_initial_relay_assignment(SSHReactor *reactor,
                                        SSHChannelState *state,
                                        SSHReactorChannelToken token)
{
    return state->purpose == SSH_CHANNEL_PURPOSE_RELAY &&
        channel_allows_initial_assignment(reactor, state, token);
}

bool
outersshpriv_reactor_channel_allows_initial_exec_assignment(SSHReactor *reactor,
                                       SSHChannelState *state,
                                       SSHReactorChannelToken token)
{
    return state->purpose == SSH_CHANNEL_PURPOSE_EXEC &&
        channel_allows_initial_assignment(reactor, state, token) &&
        !state->has_transmitted_data &&
        !state->received_eof &&
        outersshpriv_reactor_buffer_pending_byte_count(
            &state->unattached_remote_buffer) == 0;
}

static bool
channel_allows_initial_assignment(SSHReactor *reactor,
                                  SSHChannelState *state,
                                  SSHReactorChannelToken token)
{
    return state &&
        !state->is_closing &&
        !state->sent_eof &&
        !state->remote_closed &&
        !state->close_sent &&
        !state->relay &&
        !outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_DATA, token) &&
        !outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_EOF, token) &&
        !outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_CLOSE, token) &&
        !outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_EXEC, token);
}

#pragma mark - Forward Relay Data

static void process_relay_read(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);
static int commit_local_input(
    SSHReactor *reactor,
    RelaySlot *relay,
    size_t byte_count);
static int finish_local_input(
    SSHReactor *reactor,
    RelaySlot *relay);
static void process_relay_write(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);
static size_t
relay_socket_read_capacity(const SSHRelay *relay);

#if !defined(SSH_REACTOR_TESTS)

static void relay_socket_ready(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    if (!context->writes) {
        process_relay_read(context->reactor, context->relay);
        return;
    }
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(context->reactor, context->relay);
    if (relay == NULL) {
        return;
    }
    outersshpriv_reactor_safely_set_source_resumed(
        context->reactor,
        relay->state.write_socket_source,
        false,
        &relay->state.write_socket_source_is_resumed);
    process_relay_write(context->reactor, context->relay);
}

static void process_relay_read(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay == NULL || relay->relay == NULL ||
        relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE ||
        !outersshpriv_reactor_accepts_work(reactor)) {
        return;
    }
    SSHRelay *owned_relay = relay->relay;

    while (true) {
        if (relay_socket_read_capacity(owned_relay) == 0) {
            break;
        }
        size_t capacity;
        unsigned char *destination = outersshpriv_relay_buffer_writable(
            &owned_relay->to_ssh,
            &capacity);

        ssize_t byte_count = otsocket_recv(
            relay->state.socket,
            destination,
            capacity,
            0);
        if (byte_count > 0) {
            int result = commit_local_input(
                reactor,
                relay,
                (size_t)byte_count);
            if (result != 0) {
                outersshpriv_reactor_fail(
                    reactor,
                    SSH_REACTOR_OPERATION_WRITE,
                    result);
                return;
            }
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_RELAY,
                "Read %{public}zd bytes from local socket for relay index=%{public}zu generation=%{public}llu channel=%{public}llu",
                byte_count,
                handle.index,
                (unsigned long long)handle.generation,
                (unsigned long long)relay->state.channel_token);
            continue;
        }

        int error_code = errno;
        if (byte_count < 0 && error_code == EINTR) {
            continue;
        }
        bool input_ended = byte_count == 0 ||
            (error_code != EAGAIN && error_code != EWOULDBLOCK);
        if (input_ended) {
            if (byte_count == 0) {
                SSH_LOG_DEBUG(
                    SSH_LOG_CATEGORY_RELAY,
                    "Local socket EOF for relay index=%{public}zu generation=%{public}llu channel=%{public}llu",
                    handle.index,
                    (unsigned long long)handle.generation,
                    (unsigned long long)relay->state.channel_token);
            } else {
                SSH_LOG_ERROR(
                    SSH_LOG_CATEGORY_RELAY,
                    "Local socket read failed for relay index=%{public}zu generation=%{public}llu channel=%{public}llu errno=%{public}d (%{public}s)",
                    handle.index,
                    (unsigned long long)handle.generation,
                    (unsigned long long)relay->state.channel_token,
                    error_code,
                    strerror(error_code));
            }
            int result = finish_local_input(reactor, relay);
            if (result != 0) {
                outersshpriv_reactor_fail(
                    reactor,
                    SSH_REACTOR_OPERATION_WRITE,
                    result);
                return;
            }
        }
        break;
    }

    outersshpriv_reactor_update_channel_write_source(reactor);
    if (!outersshpriv_reactor_close_finished_relay(reactor, relay)) {
        outersshpriv_reactor_update_relay_read_source(reactor, relay);
    }
}

static int commit_local_input(
    SSHReactor *reactor,
    RelaySlot *relay,
    size_t byte_count)
{
    SSHRelay *owned_relay = relay->relay;
    if (owned_relay == NULL ||
        relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE ||
        relay->state.channel_token >= reactor->channel_capacity) {
        return LIBSSH2_ERROR_INVAL;
    }
    SSHChannelState *channel =
        &reactor->channels[relay->state.channel_token];
    if (!channel->in_use || channel->relay != owned_relay ||
        channel->is_closing) {
        return LIBSSH2_ERROR_INVAL;
    }
    outersshpriv_relay_buffer_commit(&owned_relay->to_ssh, byte_count);
    return outersshpriv_reactor_enqueue_channel_data(
        reactor,
        relay->state.channel_token);
}

static int finish_local_input(
    SSHReactor *reactor,
    RelaySlot *relay)
{
    SSHRelay *owned_relay = relay->relay;
    if (owned_relay == NULL ||
        relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE ||
        relay->state.channel_token >= reactor->channel_capacity) {
        return LIBSSH2_ERROR_INVAL;
    }
    SSHChannelState *channel =
        &reactor->channels[relay->state.channel_token];
    if (!channel->in_use || channel->relay != owned_relay) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (channel->is_closing) {
        return 0;
    }
    owned_relay->socket_read_open = false;
    return outersshpriv_reactor_enqueue_channel_eof(
        reactor,
        channel,
        relay->state.channel_token);
}

static void process_relay_write(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay == NULL || relay->relay == NULL ||
        relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE ||
        !outersshpriv_reactor_accepts_work(reactor)) {
        return;
    }
    SSHRelay *owned_relay = relay->relay;

    size_t byte_count;
    const unsigned char *bytes = outersshpriv_relay_buffer_readable(
        &owned_relay->to_socket,
        &byte_count);
    if (byte_count > 0) {
        ssize_t sent = otsocket_send(relay->state.socket, bytes, byte_count, OTSOCKET_SEND_FLAGS);
        if (sent > 0) {
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_RELAY,
                "Wrote %{public}zd bytes to local socket for relay index=%{public}zu generation=%{public}llu channel=%{public}llu",
                sent,
                handle.index,
                (unsigned long long)handle.generation,
                (unsigned long long)relay->state.channel_token);
            int result = 0;
            outersshpriv_relay_buffer_consume(&owned_relay->to_socket, (size_t)sent);
            if (outersshpriv_relay_buffer_pending(&owned_relay->to_socket) == 0) {
                size_t credit = owned_relay->pending_window_credit;
                owned_relay->pending_window_credit = 0;
                if (credit > 0 && owned_relay->channel_read_open &&
                    relay->state.channel_token < reactor->channel_capacity) {
                    SSHChannelState *channel =
                        &reactor->channels[relay->state.channel_token];
                    if (channel->relay == owned_relay) {
                        result = outersshpriv_reactor_consume_channel_bytes(
                            reactor,
                            channel,
                            relay->state.channel_token,
                            credit);
                    }
                }
            }
            if (result != 0) {
                outersshpriv_reactor_fail(
                    reactor,
                    SSH_REACTOR_OPERATION_READ,
                    result);
                return;
            }
        } else if (sent < 0) {
            int error_code = errno;
            if (error_code != EAGAIN && error_code != EWOULDBLOCK &&
                error_code != EINTR) {
                SSH_LOG_ERROR(
                    SSH_LOG_CATEGORY_RELAY,
                    "Local socket write failed for relay index=%{public}zu generation=%{public}llu channel=%{public}llu errno=%{public}d (%{public}s)",
                    handle.index,
                    (unsigned long long)handle.generation,
                    (unsigned long long)relay->state.channel_token,
                    error_code,
                    strerror(error_code));
                owned_relay->socket_read_open = false;
                owned_relay->socket_write_closed = true;
                owned_relay->pending_window_credit = 0;
                outersshpriv_relay_buffer_clear(&owned_relay->to_socket);
                int result = relay->state.channel_phase == SSH_RELAY_CHANNEL_CLOSED
                    ? 0 : LIBSSH2_ERROR_INVAL;
                if (relay->state.channel_phase != SSH_RELAY_CHANNEL_CLOSED &&
                    relay->state.channel_token < reactor->channel_capacity) {
                    SSHChannelState *channel =
                        &reactor->channels[relay->state.channel_token];
                    if (channel->in_use &&
                        channel->relay == owned_relay) {
                        result = outersshpriv_reactor_begin_channel_close(
                            reactor,
                            channel,
                            relay->state.channel_token,
                            false);
                    }
                }
                if (result != 0) {
                    outersshpriv_reactor_fail(
                        reactor,
                        SSH_REACTOR_OPERATION_READ,
                        result);
                    return;
                }
            }
        }
    }

    if (!owned_relay->channel_read_open &&
        outersshpriv_relay_buffer_pending(&owned_relay->to_socket) == 0) {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_RELAY,
            "Remote output ended and buffered data drained; shutting down local socket write for relay index=%{public}zu generation=%{public}llu channel=%{public}llu",
            handle.index,
            (unsigned long long)handle.generation,
            (unsigned long long)relay->state.channel_token);
        otsocket_shutdown(relay->state.socket, SHUT_WR);
        owned_relay->socket_write_closed = true;
    }

    outersshpriv_reactor_update_channel_write_source(reactor);
    if (!outersshpriv_reactor_close_finished_relay(reactor, relay)) {
        outersshpriv_reactor_update_relay_write_source(reactor, relay);
    }
}

int outersshpriv_reactor_apply_relay_data(
    SSHReactor *reactor,
    RelaySlot *relay,
    const unsigned char *bytes,
    size_t byte_count)
{
    SSHRelay *owned_relay = relay->relay;
    if (owned_relay == NULL ||
        relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE ||
        (bytes == NULL && byte_count > 0)) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (relay->state.channel_token >= reactor->channel_capacity ||
        !reactor->channels[relay->state.channel_token].in_use) {
        return outersshpriv_relay_buffer_append(
            &owned_relay->to_socket,
            bytes,
            byte_count);
    }
    SSHChannelState *channel =
        &reactor->channels[relay->state.channel_token];
    if (channel->relay != owned_relay ||
        byte_count > SIZE_MAX - owned_relay->pending_window_credit) {
        return LIBSSH2_ERROR_INVAL;
    }
    int result = outersshpriv_relay_buffer_append(
        &owned_relay->to_socket,
        bytes,
        byte_count);
    if (result != 0) {
        return result;
    }
    owned_relay->pending_window_credit += byte_count;
    if (outersshpriv_relay_buffer_pending(&owned_relay->to_socket) != 0 ||
        owned_relay->pending_window_credit == 0) {
        return 0;
    }
    size_t credit = owned_relay->pending_window_credit;
    owned_relay->pending_window_credit = 0;
    return outersshpriv_reactor_consume_channel_bytes(
        reactor,
        channel,
        relay->state.channel_token,
        credit);
}

int outersshpriv_reactor_receive_relay_eof(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle,
    SSHReactorChannelToken channel_token)
{
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay == NULL) {
        return LIBSSH2_ERROR_PROTO;
    }
    if (relay->relay != NULL &&
        relay->state.socket_phase == SSH_RELAY_SOCKET_ACTIVE &&
        !relay->state.remote_output_finished) {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_RELAY,
            "EOF received from SSH channel for relay index=%{public}zu generation=%{public}llu channel=%{public}llu",
            handle.index,
            (unsigned long long)handle.generation,
            (unsigned long long)channel_token);
        relay->state.remote_output_finished = true;
    }
    if (!outersshpriv_reactor_close_finished_relay(reactor, relay)) {
        outersshpriv_reactor_update_relay_write_source(reactor, relay);
    }
    return 0;
}

bool outersshpriv_reactor_close_finished_relay(SSHReactor *reactor, RelaySlot *relay)
{
    if (relay->relay == NULL) {
        return false;
    }
    SSHReactorRelayHandle handle = {
        .index = (size_t)(relay - reactor->relay_slots), .generation = relay->generation
    };
    if (relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE) {
        if (relay->state.channel_phase == SSH_RELAY_CHANNEL_CLOSED) {
            outersshpriv_reactor_remove_relay(reactor, handle);
        }
        return true;
    }
    if (relay->relay->socket_read_open || !relay->relay->socket_write_closed) {
        return false;
    }
    if (relay->state.channel_phase == SSH_RELAY_CHANNEL_CLOSED) {
        outersshpriv_reactor_remove_relay(reactor, handle);
    } else {
        begin_closing_relay_socket(reactor, relay);
    }
    return true;
}

void outersshpriv_reactor_update_relay_read_source(SSHReactor *reactor, RelaySlot *relay)
{
    if (relay->relay == NULL || relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE) {
        return;
    }
    bool resumed = reactor->started && outersshpriv_reactor_accepts_work(reactor) &&
        relay_socket_read_capacity(relay->relay) > 0;
    outersshpriv_reactor_safely_set_source_resumed(
        reactor, relay->state.read_socket_source, resumed,
        &relay->state.read_socket_source_is_resumed);
}

void outersshpriv_reactor_update_relay_write_source(SSHReactor *reactor, RelaySlot *relay)
{
    if (relay->relay == NULL || relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE) {
        return;
    }
    SSHRelay *owned_relay = relay->relay;
    bool resumed = reactor->started && outersshpriv_reactor_accepts_work(reactor) &&
        (outersshpriv_relay_buffer_pending(&owned_relay->to_socket) > 0 ||
         (!owned_relay->channel_read_open && !owned_relay->socket_write_closed));
    outersshpriv_reactor_safely_set_source_resumed(
        reactor, relay->state.write_socket_source, resumed,
        &relay->state.write_socket_source_is_resumed);
}

#endif

static size_t
relay_socket_read_capacity(const SSHRelay *relay)
{
    if (!relay->socket_read_open) {
        return 0;
    }
    return outersshpriv_relay_buffer_space(&relay->to_ssh);
}

#pragma mark - Recover a Relay

static SSHReactorRelayReleaseResult
detach_relay_for_session_recovery(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle,
    SSHRelay **detached_relay);
static bool relay_begin_channel_open(SSHRelay *relay);
static void handle_relay_channel_open(
    SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason);

#if !defined(SSH_REACTOR_TESTS)

SSHRelay *outersshpriv_reactor_detach_next_recoverable_relay(
    SSHReactor *reactor,
    size_t *next_index)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (next_index == NULL) {
        return NULL;
    }
    for (size_t index = *next_index;
         index < reactor->relay_slot_count;
         index++) {
        *next_index = index + 1;
        RelaySlot *relay = &reactor->relay_slots[index];
        if (relay->relay == NULL ||
            relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE) {
            continue;
        }
        SSHReactorRelayHandle handle = {
            .index = index,
            .generation = relay->generation
        };
        SSHRelay *detached_relay = NULL;
        if (detach_relay_for_session_recovery(
                reactor,
                handle,
                &detached_relay) == SSH_REACTOR_RELAY_RELEASE_DETACHED) {
            return detached_relay;
        }
    }
    return NULL;
}

static SSHReactorRelayReleaseResult
detach_relay_for_session_recovery(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle,
    SSHRelay **detached_relay)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (detached_relay != NULL) {
        *detached_relay = NULL;
    }
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    SSHChannelState *channel = relay == NULL ||
        relay->state.channel_phase != SSH_RELAY_CHANNEL_OPEN ||
        relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE
        ? NULL
        : &reactor->channels[relay->state.channel_token];
    bool channel_can_be_reassigned = channel != NULL &&
        channel->in_use &&
        channel->purpose == SSH_CHANNEL_PURPOSE_RELAY &&
        outersshpriv_reactor_channel_lifecycle_allows_reassignment(channel);
    if (relay == NULL ||
        relay->state.channel_phase != SSH_RELAY_CHANNEL_OPEN ||
        relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE ||
        relay->relay == NULL || detached_relay == NULL ||
        reactor->session == NULL ||
        !channel_can_be_reassigned) {
        return SSH_REACTOR_RELAY_RELEASE_UNAVAILABLE;
    }

    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_RELAY,
        "Detaching relay for session recovery index=%{public}zu generation=%{public}llu channel=%{public}llu",
        handle.index,
        (unsigned long long)handle.generation,
        (unsigned long long)relay->state.channel_token);

    SSHRelay *owned_relay = relay->relay;
    relay->state.socket_phase = SSH_RELAY_SOCKET_CANCELLING;
    outersshpriv_reactor_safely_cancel_source(
        reactor,
        relay->state.read_socket_source,
        &relay->state.read_socket_source_is_resumed);
    outersshpriv_reactor_safely_cancel_source(
        reactor,
        relay->state.write_socket_source,
        &relay->state.write_socket_source_is_resumed);
    // The recovered SSHRelay retains the socket. Prevent the old
    // Dispatch sources' final cancellation handler from closing it.
    relay->state.socket = -1;
    relay->state.read_socket_source = NULL;
    relay->state.write_socket_source = NULL;
    relay->state.read_socket_source_is_resumed = false;
    relay->state.write_socket_source_is_resumed = false;
    atomic_store_explicit(
        &owned_relay->ownership_state,
        SSH_RELAY_DETACHED,
        memory_order_release);

    SSHReactorChannelOwner *owner =
        &reactor->channels[relay->state.channel_token].owner;
    switch (owner->type) {
        case SSH_REACTOR_CHANNEL_OWNER_RELAY: {
            SSHReactorRelayHandle mapped_handle = owner->relay_handle;
            if (mapped_handle.index == handle.index &&
                mapped_handle.generation == handle.generation) {
                owner->relay_handle = (SSHReactorRelayHandle){0};
                owner->type = SSH_REACTOR_CHANNEL_OWNER_NONE;
            }
            break;
        }
        case SSH_REACTOR_CHANNEL_OWNER_NONE:
        case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
        case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
        case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
            break;
    }

    relay->state.channel_token = 0;
    relay->state.remote_output_finished = false;
    relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSED;
    relay->relay = NULL;
    *detached_relay = owned_relay;
    maybe_recycle_relay_slot(reactor, handle);
    return SSH_REACTOR_RELAY_RELEASE_DETACHED;
}

#endif

bool
outersshpriv_reactor_channel_lifecycle_allows_reassignment(const SSHChannelState *state)
{
    // Any transmitted or consumed data, EOF, or close transition commits the
    // relay's byte stream to this channel and prevents session reassignment.
    return state &&
        !state->is_closing &&
        !state->has_transmitted_data &&
        state->consumed_byte_count == 0 &&
        !state->sent_eof &&
        !state->received_eof &&
        !state->remote_closed &&
        !state->close_sent;
}

#if !defined(SSH_REACTOR_TESTS)

int outersshpriv_reactor_open_tcp_relay(
    SSHReactor *reactor,
    SSHRelay *relay,
    SSHRelayRecoveryOperation *recovery_operation,
    const char *host,
    size_t host_length,
    int port,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (recovery_operation == NULL || !relay_begin_channel_open(relay)) {
        return LIBSSH2_ERROR_INVAL;
    }
    SSHReactorChannelToken channel_token = 0;
    int result = outersshpriv_reactor_open_tcp_channel(
        reactor,
        &channel_token,
        host,
        host_length,
        port,
        source_host, source_host_length,
        source_port,
        timeout_milliseconds,
        (SSHReactorPendingChannelOpen){
            .finished = handle_relay_channel_open,
            .recovery_operation = recovery_operation,
            .target.relay = relay
        });
    if (result != 0) {
        relay_attachment_failed(relay);
    }
    return result;
}

int outersshpriv_reactor_open_streamlocal_relay(
    SSHReactor *reactor,
    SSHRelay *relay,
    SSHRelayRecoveryOperation *recovery_operation,
    const char *socket_path,
    size_t socket_path_length,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (recovery_operation == NULL || !relay_begin_channel_open(relay)) {
        return LIBSSH2_ERROR_INVAL;
    }
    SSHReactorChannelToken channel_token = 0;
    int result = outersshpriv_reactor_open_streamlocal_channel(
        reactor,
        &channel_token,
        socket_path,
        socket_path_length,
        source_host, source_host_length,
        source_port,
        timeout_milliseconds,
        (SSHReactorPendingChannelOpen){
            .finished = handle_relay_channel_open,
            .recovery_operation = recovery_operation,
            .target.relay = relay
        });
    if (result != 0) {
        relay_attachment_failed(relay);
    }
    return result;
}

static bool relay_begin_channel_open(SSHRelay *relay)
{
    if (relay == NULL ||
        atomic_load_explicit(&relay->socket, memory_order_acquire) < 0) {
        return false;
    }
    int expected = SSH_RELAY_DETACHED;
    return atomic_compare_exchange_strong_explicit(
        &relay->ownership_state,
        &expected,
        SSH_RELAY_PENDING_CHANNEL,
        memory_order_acq_rel,
        memory_order_acquire);
}

static void handle_relay_channel_open(
    SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason)
{
    (void)reason;
    SSHRelay *owned_relay = pending->target.relay;
    SSHRelayRecoveryOperation *recovery_operation = pending->recovery_operation;
    if (result != SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED) {
        relay_attachment_failed(owned_relay);
        SSHReactorRelayOpenResult open_result;
        switch (result) {
        case SSH_REACTOR_CHANNEL_OPEN_FAILED:
            open_result = SSH_REACTOR_RELAY_OPEN_CHANNEL_FAILED;
            break;
        case SSH_REACTOR_CHANNEL_OPEN_TIMED_OUT:
            open_result = SSH_REACTOR_RELAY_OPEN_TIMED_OUT;
            break;
        case SSH_REACTOR_CHANNEL_OPEN_SESSION_CLOSED:
        case SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED:
            open_result = SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED;
            break;
        default:
            abort();
        }
        outersshpriv_relay_recovery_open_completed(
            recovery_operation,
            open_result,
            owned_relay);
        return;
    }

    SSHReactorRelayHandle handle = {0};
    if (add_relay(
            reactor,
            &handle,
            (SSHReactorRelayHandle){0},
            channel_token,
            owned_relay,
            SSH_RELAY_PENDING_CHANNEL) != 0) {
        outersshpriv_reactor_close_channel(reactor, channel_token, false);
        outersshpriv_relay_recovery_open_completed(
            recovery_operation,
            SSH_REACTOR_RELAY_OPEN_ATTACHMENT_FAILED,
            owned_relay);
        return;
    }

    outersshpriv_relay_recovery_open_completed(
        recovery_operation,
        SSH_REACTOR_RELAY_OPEN_SUCCEEDED,
        NULL);
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay != NULL && !outersshpriv_reactor_close_finished_relay(reactor, relay)) {
        outersshpriv_reactor_update_relay_read_source(reactor, relay);
        outersshpriv_reactor_update_relay_write_source(reactor, relay);
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
}

static void relay_attachment_failed(SSHRelay *relay)
{
    atomic_store_explicit(
        &relay->ownership_state,
        SSH_RELAY_DETACHED,
        memory_order_release);
}

#endif

#pragma mark - Close Relays and Recycle Their Slots

static SSHReactorRelayReleaseResult close_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);
static void relay_socket_source_cancelled(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);

#if !defined(SSH_REACTOR_TESTS)

void outersshpriv_reactor_close_proxy_connections(
    SSHReactor *reactor,
    uint64_t proxy_generation)
{
    outersshpriv_reactor_assert_queue(reactor);
    for (size_t index = 0; index < reactor->relay_slot_count; index++) {
        RelaySlot *relay = &reactor->relay_slots[index];
        if (relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE ||
            relay->relay == NULL ||
            relay->relay->proxy_generation != proxy_generation) {
            continue;
        }
        SSHReactorRelayHandle handle = {
            .index = index,
            .generation = relay->generation
        };
        (void)close_relay(reactor, handle);
    }
    for (size_t i = 0; i < reactor->socket_bridge_slot_count; i++) {
        SocketBridgeSlot *slot = &reactor->socket_bridge_slots[i];
        if (slot->phase != SOCKET_BRIDGE_SLOT_ACTIVE) continue;
        SSHReactorSocketBridgeHandle handle = slot->bridge.handle;
        for (size_t j = 0;; j++) {
            SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
            if (bridge == NULL || j >= bridge->stream_slot_count) break;
            SocketBridgeStream *stream = &bridge->stream_slots[j].stream;
            if (stream->phase == SOCKET_BRIDGE_STREAM_ACTIVE && stream->proxy_generation == proxy_generation)
                outersshpriv_reactor_socket_bridge_close_stream(reactor, bridge->handle, stream->stream_id, true);
        }
    }

}

static SSHReactorRelayReleaseResult close_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    outersshpriv_reactor_assert_queue(reactor);
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay == NULL || relay->relay == NULL) {
        return SSH_REACTOR_RELAY_RELEASE_UNAVAILABLE;
    }
    if (relay->state.channel_phase == SSH_RELAY_CHANNEL_CLOSED) {
        outersshpriv_reactor_remove_relay(reactor, handle);
        return SSH_REACTOR_RELAY_RELEASE_CLOSED;
    }
    int close_result = reactor->session != NULL &&
            relay->state.channel_token < reactor->channel_capacity &&
            reactor->channels[relay->state.channel_token].in_use
        ? outersshpriv_reactor_begin_channel_close(
            reactor,
            &reactor->channels[relay->state.channel_token],
            relay->state.channel_token,
            false)
        : LIBSSH2_ERROR_INVAL;
    if (relay->state.socket_phase == SSH_RELAY_SOCKET_ACTIVE) {
        begin_closing_relay_socket(reactor, relay);
    }
    if (close_result != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, close_result);
    } else {
        outersshpriv_reactor_update_channel_write_source(reactor);
    }
    return SSH_REACTOR_RELAY_RELEASE_CLOSED;
}

bool outersshpriv_reactor_cancel_prepared_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    outersshpriv_reactor_assert_queue(reactor);
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay == NULL ||
        relay->state.socket_phase != SSH_RELAY_SOCKET_UNATTACHED ||
        (relay->state.channel_phase != SSH_RELAY_CHANNEL_OPENING &&
         relay->state.channel_phase != SSH_RELAY_CHANNEL_OPEN)) {
        return false;
    }
    bool was_ready =
        relay->state.channel_phase == SSH_RELAY_CHANNEL_OPEN;
    SSHReactorChannelToken channel_token = relay->state.channel_token;
    ConnectRelayContext *operation = NULL;
    if (!was_ready) {
        SSHReactorChannelOwner *owner =
            &reactor->channels[channel_token].owner;
        if (owner->type != SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN ||
            owner->pending_open.finished !=
                handle_prepared_relay_channel_open ||
            owner->pending_open.target.prepared_relay_handle.index !=
                handle.index ||
            owner->pending_open.target.prepared_relay_handle.generation !=
                handle.generation) {
            return false;
        }
        operation = owner->pending_open.prepared_relay_operation;
        owner->pending_open.prepared_relay_operation = NULL;
        owner->pending_open.finished = NULL;
        owner->pending_open.result_delivered = true;
        if (owner->pending_open.timeout_timer != NULL) {
            outersshpriv_reactor_cancel_source(owner->pending_open.timeout_timer);
            owner->pending_open.timeout_timer = NULL;
        }
    }
    outersshpriv_reactor_remove_prepared_relay(reactor, handle);
    if (was_ready && outersshpriv_reactor_accepts_work(reactor)) {
        int result = outersshpriv_reactor_begin_channel_close(
            reactor,
            &reactor->channels[channel_token],
            channel_token,
            false);
        if (result != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, result);
        } else {
            outersshpriv_reactor_update_channel_write_source(reactor);
        }
    }
    if (operation != NULL) {
        outersshpriv_session_pool_prepared_relay_completed(
            operation,
            handle,
            SSH_REACTOR_RELAY_OPEN_CANCELLED, 0);
    }
    return true;
}

void outersshpriv_reactor_remove_prepared_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay == NULL) {
        return;
    }
    relay->state.channel_token = 0;
    relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSED;
    maybe_recycle_relay_slot(reactor, handle);
}

bool outersshpriv_reactor_remove_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay == NULL || relay->relay == NULL ||
        relay->state.socket_phase == SSH_RELAY_SOCKET_UNATTACHED) {
        return false;
    }

    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_RELAY,
        "Removing relay index=%{public}zu generation=%{public}llu channel=%{public}llu channel_phase=%{public}d socket_phase=%{public}d",
        handle.index,
        (unsigned long long)handle.generation,
        (unsigned long long)relay->state.channel_token,
        relay->state.channel_phase,
        relay->state.socket_phase);

    SSHRelay *owned_relay = relay->relay;
    if (relay->state.socket_phase == SSH_RELAY_SOCKET_ACTIVE) {
        begin_closing_relay_socket(reactor, relay);
    }

    if (relay->state.channel_token < reactor->channel_capacity) {
        SSHReactorChannelOwner *owner =
            &reactor->channels[relay->state.channel_token].owner;
        switch (owner->type) {
            case SSH_REACTOR_CHANNEL_OWNER_RELAY: {
                SSHReactorRelayHandle mapped_handle =
                    owner->relay_handle;
                if (mapped_handle.index == handle.index &&
                    mapped_handle.generation == handle.generation) {
                    owner->relay_handle = (SSHReactorRelayHandle){0};
                    owner->type = SSH_REACTOR_CHANNEL_OWNER_NONE;
                }
                break;
            }
            case SSH_REACTOR_CHANNEL_OWNER_NONE:
            case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
            case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
            case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
                break;
        }
    }

    relay->state.channel_token = 0;
    relay->state.remote_output_finished = false;
    relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSED;
    relay->relay = NULL;
    outersshpriv_relay_release(owned_relay);
    maybe_recycle_relay_slot(reactor, handle);
    return true;
}

static void begin_closing_relay_socket(
    SSHReactor *reactor,
    RelaySlot *relay)
{
    assert(relay->state.socket_phase == SSH_RELAY_SOCKET_ACTIVE);
    assert(relay->state.read_socket_source != NULL);
    assert(relay->state.write_socket_source != NULL);
    relay->state.socket_phase = SSH_RELAY_SOCKET_CANCELLING;
    outersshpriv_reactor_safely_cancel_source(
        reactor,
        relay->state.read_socket_source,
        &relay->state.read_socket_source_is_resumed);
    outersshpriv_reactor_safely_cancel_source(
        reactor,
        relay->state.write_socket_source,
        &relay->state.write_socket_source_is_resumed);
    relay->state.read_socket_source = NULL;
    relay->state.write_socket_source = NULL;
    relay->state.read_socket_source_is_resumed = false;
    relay->state.write_socket_source_is_resumed = false;
    mark_relay_closed(relay->relay);
}

static void relay_source_cancelled(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    relay_socket_source_cancelled(context->reactor, context->relay);
    outersshpriv_reactor_source_cancelled(context->reactor);
    free(context);
}

static void relay_socket_source_cancelled(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    assert(relay != NULL);
    assert(relay->state.socket_phase == SSH_RELAY_SOCKET_CANCELLING);
    assert(relay->state.uncancelled_socket_source_count > 0);
    relay->state.uncancelled_socket_source_count -= 1;
    if (relay->state.uncancelled_socket_source_count != 0) {
        return;
    }
    if (relay->state.socket >= 0) {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_RELAY,
            "Relay dispatch sources cancelled; closing local socket %{public}lld",
            (long long)relay->state.socket);
        otsocket_close(relay->state.socket);
        relay->state.socket = -1;
    }
    relay->state.socket_phase = SSH_RELAY_SOCKET_CLOSED;
    maybe_recycle_relay_slot(reactor, handle);
}

static void maybe_recycle_relay_slot(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
    if (relay->state.channel_phase == SSH_RELAY_CHANNEL_CLOSED &&
        (relay->state.socket_phase == SSH_RELAY_SOCKET_UNATTACHED ||
         relay->state.socket_phase == SSH_RELAY_SOCKET_CLOSED)) {

        assert(relay->state.uncancelled_socket_source_count == 0);
        assert(relay->state.socket < 0);
        assert(relay->relay == NULL);
        relay->state = (SSHReactorRelayState){.socket = -1};
        relay->generation += 1;
        if (relay->generation == 0) {
            relay->generation = 1;
        }
        reactor->available_relay_indices[
            reactor->available_relay_index_count] = handle.index;
        reactor->available_relay_index_count += 1;
    }
}

bool outersshpriv_relay_close(SSHRelay *relay)
{
    if (relay == NULL) {
        return false;
    }
    int expected = SSH_RELAY_DETACHED;
    if (!atomic_compare_exchange_strong_explicit(
            &relay->ownership_state,
            &expected,
            SSH_RELAY_CLOSED,
            memory_order_acq_rel,
            memory_order_acquire)) {
        return false;
    }
    otsocket_t socket = atomic_exchange_explicit(
        &relay->socket,
        -1,
        memory_order_acq_rel);
    if (socket >= 0) {
        otsocket_close(socket);
    }
    return true;
}

static void mark_relay_closed(SSHRelay *relay)
{
    if (relay == NULL) {
        return;
    }
    atomic_store_explicit(
        &relay->ownership_state,
        SSH_RELAY_CLOSED,
        memory_order_release);
    atomic_store_explicit(&relay->socket, -1, memory_order_release);
}

#endif

void outersshpriv_relay_release(SSHRelay *relay)
{
    if (relay == NULL ||
        atomic_fetch_sub_explicit(
            &relay->reference_count,
            1,
            memory_order_acq_rel) != 1) {
        return;
    }
    otsocket_t socket = atomic_exchange_explicit(
        &relay->socket,
        -1,
        memory_order_acq_rel);
    if (socket >= 0) {
        otsocket_close(socket);
    }
    free(relay->route.destination);
    outersshpriv_relay_buffer_deinitialize(&relay->to_ssh);
    outersshpriv_relay_buffer_deinitialize(&relay->to_socket);
    free(relay);
}

static SSHRelay *
retain_relay(SSHRelay *relay)
{
    if (relay) {
        atomic_fetch_add_explicit(&relay->reference_count,
                                  1,
                                  memory_order_relaxed);
    }
    return relay;
}

#if !defined(SSH_REACTOR_TESTS)

// The browser socket and the SSH channel can close in either order.
// When both are closed, the relay is freed and the slot is recycled.
// Closing the browser socket first requires cancelling its dispatch
// sources, then waiting for both of their cancel handlers to run,
// then finally calling close on the socket. Until all of this
// completes, we continue holding the slot.
RelaySlot *outersshpriv_reactor_slot_for_handle(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle)
{
    assert(handle.generation != 0);
    assert(handle.index < reactor->relay_slot_count);
    RelaySlot *slot = &reactor->relay_slots[handle.index];
    return slot->generation == handle.generation ? slot : NULL;
}

static bool reserve_relays(
    SSHReactor *reactor,
    size_t minimum_capacity)
{
    if (reactor->relay_capacity >= minimum_capacity) {
        return true;
    }

    size_t capacity = reactor->relay_capacity == 0
        ? 4
        : reactor->relay_capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*reactor->relay_slots)) {
        return false;
    }

    RelaySlot *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL) {
        return false;
    }
    size_t *available_indices = malloc(
        capacity * sizeof(*available_indices));
    if (available_indices == NULL) {
        free(slots);
        return false;
    }
    for (size_t index = 0; index < reactor->relay_slot_count; index++) {
        slots[index].generation = reactor->relay_slots[index].generation;
        slots[index].state = reactor->relay_slots[index].state;
        slots[index].relay = reactor->relay_slots[index].relay;
        reactor->relay_slots[index].state = (SSHReactorRelayState){0};
        reactor->relay_slots[index].relay = NULL;
    }
    if (reactor->available_relay_index_count > 0) {
        memcpy(
            available_indices,
            reactor->available_relay_indices,
            reactor->available_relay_index_count * sizeof(*available_indices));
    }
    free(reactor->relay_slots);
    free(reactor->available_relay_indices);
    reactor->relay_slots = slots;
    reactor->available_relay_indices = available_indices;
    reactor->relay_capacity = capacity;
    return true;
}

#endif
