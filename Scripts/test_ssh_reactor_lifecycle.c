#include "SSHTestSupport.h"
#include "platform/OTSocket.h"
#include "SSHReactor.h"
#include "SSHReactorCommandInternal.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static bool fail_all_allocations;
static unsigned bridge_stream_completions, bridge_completions;
static bool fail_channel_creation, fail_timer_creation, fail_timer_context;
static SSHReactor *completion_reactor;
static size_t command_close_count, command_open_count;
static SSHReactorChannelOpenResult expected_open_result;
static bool invalidate_on_completion;
static void *test_calloc(size_t count, size_t size);
static void *test_malloc(size_t size);
static otsource_t test_source_create(otsource_type_t type,
    uintptr_t handle, otqueue_t queue);

#define malloc test_malloc
#define calloc test_calloc
#define otsource_create test_source_create
#include "SSHReactor.c"
#include "SSHReactorRelay.c"
#include "SSHReactorOutput.c"
#include "SSHReactorKeyExchange.c"
#include "SSHReactorSocketBridge.c"
#undef malloc
#undef calloc
#undef otsource_create

static void *test_malloc(size_t size)
{
    return fail_all_allocations || fail_channel_creation ? NULL : malloc(size);
}

static void *test_calloc(size_t count, size_t size)
{
    if (fail_all_allocations || (fail_timer_context && size == sizeof(SSHReactorSourceContext))) {
        return NULL;
    }
    return calloc(count, size);
}

static otsource_t test_source_create(otsource_type_t type,
    uintptr_t handle, otqueue_t queue)
{
    if (fail_timer_creation && type == OTSOURCE_TYPE_TIMER) {
        return NULL;
    }
    return otsource_create(type, handle, queue);
}

void outersshpriv_reactor_command_channel_closed(SSHReactorCommand *command)
{
    assert(completion_reactor != NULL);
    assert(command == (SSHReactorCommand *)(uintptr_t)3);
    SSHChannelState *channel = &completion_reactor->channels[0];
    assert(!channel->in_use);
    assert(channel->owner.type == SSH_REACTOR_CHANNEL_OWNER_NONE);
    assert(channel->exec_input.bytes == NULL);
    assert(channel->unattached_remote_buffer.bytes == NULL);
    assert(!channel->sent_eof && !channel->remote_closed && !channel->is_closing);
    command_close_count++;
    assert(ensure_channel_capacity(completion_reactor,
        completion_reactor->channel_capacity) == 0);
    if (invalidate_on_completion) {
        completion_reactor->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    }
}

void outersshpriv_reactor_command_handle_channel_open(SSHReactorCommand *command,
    SSHReactorChannelToken token, SSHReactorChannelOpenResult result, uint32_t reason)
{
    assert(completion_reactor != NULL);
    assert(command == (SSHReactorCommand *)(uintptr_t)3);
    assert(token < completion_reactor->channel_capacity && result == expected_open_result);
    assert(reason == (result == SSH_REACTOR_CHANNEL_OPEN_FAILED ? 42u : 0u));
    SSHChannelState *channel = &completion_reactor->channels[token];
    assert(channel->owner.type == SSH_REACTOR_CHANNEL_OWNER_NONE);
    assert((!channel->in_use) == (result == SSH_REACTOR_CHANNEL_OPEN_FAILED));
    command_open_count++;
    assert(ensure_channel_capacity(completion_reactor,
        completion_reactor->channel_capacity) == 0);
    if (invalidate_on_completion) {
        completion_reactor->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    }
}

void outersshpriv_recover_after_session_failure(OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle session, SSHReactor *reactor)
{
    abort();
}

void outersshpriv_relay_recovery_open_completed(SSHRelayRecoveryOperation *operation,
    SSHReactorRelayOpenResult result, SSHRelay *relay)
{
    abort();
}

static unsigned prepared_completions;
static SSHReactorRelayOpenResult prepared_result;
static uint32_t prepared_reason;
static SSHReactorRelayHandle prepared_handle;

void outersshpriv_session_pool_prepared_relay_completed(ConnectRelayContext *operation,
    SSHReactorRelayHandle handle, SSHReactorRelayOpenResult result, uint32_t reason)
{
    assert(operation == (ConnectRelayContext *)(uintptr_t)4);
    prepared_completions++;
    prepared_result = result;
    prepared_reason = reason;
    prepared_handle = handle;
}

void outersshpriv_session_pool_socket_bridge_completed(void *operation,
    SSHReactorSocketBridgeHandle handle, SSHReactorSocketBridgeResult result,
    uint32_t reason, const void *detail, size_t detail_length)
{
    (void)detail_length;
    abort();
}

void outersshpriv_session_pool_socket_bridge_stream_completed(
    ConnectBridgeStreamContext *operation, SSHReactorSocketBridgeHandle bridge,
    SSHReactorSocketBridgeStreamHandle stream, SSHReactorSocketBridgeStreamResult result,
    const void *detail, size_t detail_length)
{
    assert(fail_all_allocations);
    assert(operation == (ConnectBridgeStreamContext *)(uintptr_t)(stream.index + 1));
    assert(bridge.index == 0 && bridge.generation == 1);
    assert(result == SSH_REACTOR_SOCKET_BRIDGE_STREAM_SESSION_CLOSED);
    assert(detail_length == 6 && memcmp(detail, "closed", 6) == 0);
    bridge_stream_completions++;
}

static void test_channel_open_failure(SSHReactor *reactor, int channel_type)
{
    SSHReactorPendingChannelOpen pending = {
        .finished = handle_command_channel_open,
        .target.command = (SSHReactorCommand *)(uintptr_t)3
    };
    SSHReactorChannelToken token = UINT64_MAX;
    int result;
    switch (channel_type) {
    case 0:
        result = outersshpriv_reactor_open_session_channel(reactor, &token, 1000, pending);
        break;
    case 1:
        result = outersshpriv_reactor_open_tcp_channel(reactor, &token, "localhost", sizeof("localhost") - 1, 80,
            "127.0.0.1", sizeof("127.0.0.1") - 1, 1234, 1000, pending);
        break;
    default:
        result = outersshpriv_reactor_open_streamlocal_channel(reactor, &token, "/tmp/test.sock", sizeof("/tmp/test.sock") - 1,
            "127.0.0.1", sizeof("127.0.0.1") - 1, 1234, 1000, pending);
        break;
    }
    assert(result == LIBSSH2_ERROR_ALLOC);
    assert(token == UINT64_MAX);
    assert(reactor->write_action_count == 0);
    assert(!reactor->channels[0].in_use);
    assert(reactor->channels[0].owner.type == SSH_REACTOR_CHANNEL_OWNER_NONE);
    assert(reactor->socket_source_count == 0);
    assert(reactor->created_channel_count == 0);
    assert(outersshpriv_reactor_accepts_work(reactor));
}

static void test_relay_write_failure(SSHReactor *reactor, bool channel_closed)
{
    otsocket_t sockets[2];
    assert(ssh_test_socket_pair(sockets) == 0);
    SSHRelay *relay = ssh_relay_create(sockets[0], 1, 1,
        SSH_RELAY_TARGET_TCP, "localhost", sizeof("localhost") - 1, 80);
    assert(relay != NULL);
    assert(register_channel(reactor, 0,
        SSH_CHANNEL_PURPOSE_RELAY) == 0);
    reactor->created_channel_count++;
    SSHReactorRelayHandle handle;
    assert(add_relay(reactor, &handle, (SSHReactorRelayHandle){0}, 0,
        relay, SSH_RELAY_DETACHED) == 0);
    assert(outersshpriv_relay_buffer_append(&relay->to_socket, "hello", 5) == 0);
    relay->pending_window_credit = 5;
    if (channel_closed) {
        relay->channel_read_open = false;
        relay->socket_read_open = false;
        assert(complete_channel_close(reactor, 0) == 0);
    }
    retain_relay(relay);
    assert(otsocket_shutdown(sockets[0], SHUT_WR) == 0);
    otsocket_close(sockets[1]);

    process_relay_write(reactor, handle);

    assert(outersshpriv_reactor_accepts_work(reactor));
    assert(!outersshpriv_reactor_session_has_failed(reactor));
    assert(!relay->socket_read_open && relay->socket_write_closed);
    assert(outersshpriv_relay_buffer_pending(&relay->to_socket) == 0);
    assert(relay->pending_window_credit == 0);
    assert(outersshpriv_reactor_slot_for_handle(reactor, handle)->state.socket_phase ==
        SSH_RELAY_SOCKET_CANCELLING);
    if (channel_closed) {
        assert(reactor->write_action_count == 0);
        assert(outersshpriv_reactor_slot_for_handle(reactor, handle)->relay == NULL);
    } else {
        assert(outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_CLOSE, 0));
        assert(reactor->channels[0].is_closing);
        assert(complete_channel_close(reactor, 0) == 0);
        while (reactor->write_action_count > 0) {
            outersshpriv_reactor_pop_write_action(reactor);
        }
    }
    outersshpriv_relay_release(relay);
}

static void test_close_relay_after_channel_closed(SSHReactor *reactor)
{
    otsocket_t sockets[2];
    assert(ssh_test_socket_pair(sockets) == 0);
    SSHRelay *relay = ssh_relay_create(sockets[0], 1, 1,
        SSH_RELAY_TARGET_TCP, "localhost", sizeof("localhost") - 1, 80);
    assert(relay != NULL);
    assert(register_channel(reactor, 0, SSH_CHANNEL_PURPOSE_RELAY) == 0);
    reactor->created_channel_count++;
    SSHReactorRelayHandle handle;
    assert(add_relay(reactor, &handle, (SSHReactorRelayHandle){0}, 0,
        relay, SSH_RELAY_DETACHED) == 0);
    assert(outersshpriv_relay_buffer_append(&relay->to_socket, "hello", 5) == 0);
    relay->channel_read_open = false;
    relay->socket_read_open = false;
    assert(complete_channel_close(reactor, 0) == 0);
    assert(outersshpriv_reactor_slot_for_handle(reactor, handle)->state.socket_phase == SSH_RELAY_SOCKET_ACTIVE);

    assert(close_relay(reactor, handle) == SSH_REACTOR_RELAY_RELEASE_CLOSED);
    assert(outersshpriv_reactor_accepts_work(reactor));
    assert(!outersshpriv_reactor_session_has_failed(reactor));
    assert(outersshpriv_reactor_slot_for_handle(reactor, handle)->relay == NULL);
    assert(outersshpriv_reactor_slot_for_handle(reactor, handle)->state.socket_phase == SSH_RELAY_SOCKET_CANCELLING);
    assert(reactor->write_action_count == 0);
    otsocket_close(sockets[1]);
}

static void test_channel_open_packet(SSHReactor *reactor, bool streamlocal)
{
    char host[] = {'h', 'o', 's', 't'};
    char path[] = {'/', 't', 'm', 'p', '/', 's'};
    char source[] = {'1', '2', '7', '.', '0', '.', '0', '.', '1'};
    SSHReactorChannelToken token;
    int result = streamlocal
        ? outersshpriv_reactor_open_streamlocal_channel(reactor, &token, path, sizeof(path),
            source, sizeof(source), 1234, 0, (SSHReactorPendingChannelOpen){0})
        : outersshpriv_reactor_open_tcp_channel(reactor, &token, host, sizeof(host), 8080,
            source, sizeof(source), 1234, 0, (SSHReactorPendingChannelOpen){0});
    assert(result == 0);
    memset(host, 'x', sizeof(host));
    memset(path, 'x', sizeof(path));
    memset(source, 'x', sizeof(source));
    SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, 0);
    const unsigned char *packet = action->payload.packet.bytes;
    assert(packet[0] == SSH_PACKET_CHANNEL_OPEN);
    uint32_t length;
    memcpy(&length, packet + 1, 4);
    const char *type = streamlocal ? "direct-streamlocal@openssh.com" : "direct-tcpip";
    assert(ntohl(length) == strlen(type));
    assert(memcmp(packet + 5, type, strlen(type)) == 0);
    const unsigned char *cursor = packet + 5 + strlen(type);
    uint32_t fields[3];
    memcpy(fields, cursor, sizeof(fields));
    assert(ntohl(fields[0]) == token);
    assert(ntohl(fields[1]) == SSH_READ_BUFFER_CAPACITY);
    assert(ntohl(fields[2]) == LIBSSH2_CHANNEL_PACKET_DEFAULT);
    cursor += sizeof(fields);
    memcpy(&length, cursor, 4); cursor += 4;
    size_t destination_length = streamlocal ? sizeof(path) : sizeof(host);
    assert(ntohl(length) == destination_length);
    assert(memcmp(cursor, streamlocal ? "/tmp/s" : "host", destination_length) == 0);
    cursor += destination_length;
    if (!streamlocal) {
        memcpy(&length, cursor, 4); cursor += 4;
        assert(ntohl(length) == 8080);
    }
    memcpy(&length, cursor, 4); cursor += 4;
    assert(ntohl(length) == sizeof(source));
    assert(memcmp(cursor, "127.0.0.1", sizeof(source)) == 0);
    cursor += sizeof(source);
    memcpy(&length, cursor, 4); cursor += 4;
    assert(ntohl(length) == 1234);
    assert(cursor == packet + action->payload.packet.length);
    clear_channel(reactor, token);
    outersshpriv_reactor_pop_write_action(reactor);
    reactor->freed_channel_count++;
}

static void test_open_timer_success(SSHReactor *reactor, uint64_t timeout_milliseconds)
{
    SSHReactorChannelToken token = UINT64_MAX;
    SSHReactorCommand *command = (SSHReactorCommand *)(uintptr_t)3;
    assert(outersshpriv_reactor_open_session_channel(reactor, &token, timeout_milliseconds,
        (SSHReactorPendingChannelOpen){
            .finished = handle_command_channel_open,
            .target.command = command
        }) == 0);
    assert(token + 1 == reactor->next_channel_id);
    SSHReactorChannelOwner *owner = &reactor->channels[token].owner;
    assert(owner->type == SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN);
    assert(owner->pending_open.target.command == command);
    assert((owner->pending_open.timeout_timer != NULL) == (timeout_milliseconds != 0));
    assert(reactor->write_action_count == 1);
    SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, 0);
    assert(action->type == SSH_WRITE_CHANNEL_OPEN && action->token == token);
    if (owner->pending_open.timeout_timer != NULL) {
        outersshpriv_reactor_cancel_source(owner->pending_open.timeout_timer);
    }
    *owner = (SSHReactorChannelOwner){0};
    clear_channel(reactor, token);
    outersshpriv_reactor_pop_write_action(reactor);
    reactor->freed_channel_count++;
}

static void test_command_channel_close(SSHReactor *reactor)
{
    assert(register_channel(reactor, 0,
        SSH_CHANNEL_PURPOSE_EXEC) == 0);
    reactor->created_channel_count++;
    SSHChannelState *channel = &reactor->channels[0];
    channel->owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND;
    channel->owner.command.command = (SSHReactorCommand *)(uintptr_t)3;
    channel->sent_eof = true;
    channel->remote_closed = true;
    channel->is_closing = true;
    assert(outersshpriv_reactor_output_buffer_append(&channel->exec_input, "input", 5) == 0);
    assert(outersshpriv_reactor_output_buffer_append(&channel->unattached_remote_buffer, "output", 6) == 0);
    assert(schedule_command_exit_close(reactor, 0) == 0);
    assert(channel->owner.command.exit_close_timer != NULL);
    size_t freed_before = reactor->freed_channel_count;
    size_t closed_before = command_close_count;
    completion_reactor = reactor;
    invalidate_on_completion = true;

    assert(complete_channel_close(reactor, 0) == 0);

    assert(reactor->freed_channel_count == freed_before + 1);
    assert(command_close_count == closed_before + 1);
    assert(reactor->lifecycle == SSH_REACTOR_LIFECYCLE_INVALIDATED);
    reactor->lifecycle = SSH_REACTOR_LIFECYCLE_ACTIVE;
    invalidate_on_completion = false;
    completion_reactor = NULL;
}

static void test_channel_open_completion(SSHReactor *reactor,
    SSHReactorChannelOpenResult result, bool already_timed_out)
{
    SSHReactorChannelToken token;
    assert(outersshpriv_reactor_open_session_channel(reactor, &token, 10000,
        (SSHReactorPendingChannelOpen){
            .finished = handle_command_channel_open,
            .target.command = (SSHReactorCommand *)(uintptr_t)3,
            .result_delivered = already_timed_out
        }) == 0);
    outersshpriv_reactor_pop_write_action(reactor);
    size_t freed_before = reactor->freed_channel_count;
    size_t completed_before = command_open_count;
    completion_reactor = reactor;
    expected_open_result = result;
    invalidate_on_completion = result == SSH_REACTOR_CHANNEL_OPEN_FAILED;

    assert(complete_pending_channel_open(reactor, token, result,
        result == SSH_REACTOR_CHANNEL_OPEN_FAILED ? 42 : 0) == 0);

    assert(command_open_count == completed_before + (already_timed_out ? 0 : 1));
    assert(reactor->freed_channel_count == freed_before +
        (result == SSH_REACTOR_CHANNEL_OPEN_FAILED ? 1 : 0));
    assert(reactor->channels[token].owner.type == SSH_REACTOR_CHANNEL_OWNER_NONE);
    if (result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED) {
        assert(reactor->channels[token].is_closing == already_timed_out);
        assert(outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_CLOSE, token) == already_timed_out);
        while (reactor->write_action_count > 0) {
            outersshpriv_reactor_pop_write_action(reactor);
        }
        assert(complete_channel_close(reactor, token) == 0);
    }
    reactor->lifecycle = SSH_REACTOR_LIFECYCLE_ACTIVE;
    invalidate_on_completion = false;
    completion_reactor = NULL;
}

static void test_prepared_relay_completion(SSHReactor *reactor,
    SSHReactorChannelOpenResult result, bool removed)
{
    size_t index = reactor->relay_slot_count;
    assert(reserve_relays(reactor, index + 1));
    reactor->relay_slot_count++;
    SSHReactorRelayHandle handle = {.index = index, .generation = 1};
    reactor->relay_slots[index] = (RelaySlot){
        .generation = 1,
        .state = {
            .socket = -1,
            .socket_phase = SSH_RELAY_SOCKET_UNATTACHED,
            .channel_phase = SSH_RELAY_CHANNEL_OPENING,
            .channel_token = 0
        }
    };
    if (removed) {
        outersshpriv_reactor_remove_prepared_relay(reactor, handle);
        reactor->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    }
    unsigned before = prepared_completions;
    SSHReactorPendingChannelOpen pending = {
        .finished = handle_prepared_relay_channel_open,
        .prepared_relay_operation = (ConnectRelayContext *)(uintptr_t)4,
        .target.prepared_relay_handle = handle
    };
    pending.finished(reactor, &pending, 0, result, 3);
    assert(prepared_completions == before + 1);
    assert(prepared_handle.index == handle.index && prepared_handle.generation == handle.generation);
    if (result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED && !removed) {
        assert(prepared_result == SSH_REACTOR_RELAY_OPEN_SUCCEEDED);
        assert(reactor->relay_slots[index].state.channel_phase == SSH_RELAY_CHANNEL_OPEN);
        outersshpriv_reactor_remove_prepared_relay(reactor, handle);
    } else {
        if (result == SSH_REACTOR_CHANNEL_OPEN_FAILED) {
            assert(prepared_result == SSH_REACTOR_RELAY_OPEN_CHANNEL_FAILED);
            assert(prepared_reason == 3);
        } else if (result == SSH_REACTOR_CHANNEL_OPEN_TIMED_OUT) {
            assert(prepared_result == SSH_REACTOR_RELAY_OPEN_TIMED_OUT);
        } else {
            assert(prepared_result == SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED);
        }
    }
    assert(outersshpriv_reactor_slot_for_handle(reactor, handle) == NULL);
    reactor->lifecycle = SSH_REACTOR_LIFECYCLE_ACTIVE;
}

static void test_prepared_relay_cancel_or_timeout(
    SSHReactor *reactor, bool cancel, SSHReactorChannelOpenResult late_result)
{
    SSHReactorRelayHandle handle;
    SSHRelayTarget target = {
        .kind = SSHRelayTargetTCP, .destination = "localhost",
        .destination_length = sizeof("localhost") - 1, .port = 80
    };
    assert(outersshpriv_reactor_prepare_relay(reactor, &handle, (ConnectRelayContext *)(uintptr_t)4,
        &target, "127.0.0.1", sizeof("127.0.0.1") - 1, 1234, 10000) == 0);
    outersshpriv_reactor_pop_write_action(reactor);
    SSHReactorChannelToken token = reactor->relay_slots[handle.index].state.channel_token;
    SSHReactorPendingChannelOpen *pending = &reactor->channels[token].owner.pending_open;
    unsigned before = prepared_completions;
    if (cancel) {
        assert(outersshpriv_reactor_cancel_prepared_relay(reactor, handle));
    } else {
        SSHReactorSourceContext timeout = {
            .reactor = reactor, .channel_token = token, .source = pending->timeout_timer
        };
        pending_channel_open_timed_out(&timeout);
    }
    assert(prepared_completions == before + 1);
    assert(prepared_result == (cancel ? SSH_REACTOR_RELAY_OPEN_CANCELLED : SSH_REACTOR_RELAY_OPEN_TIMED_OUT));
    assert(!outersshpriv_reactor_cancel_prepared_relay(reactor, handle));
    assert(complete_pending_channel_open(reactor, token, late_result, 0) == 0);
    assert(prepared_completions == before + 1);
    if (late_result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED) {
        assert(reactor->channels[token].is_closing);
        assert(outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_CLOSE, token));
        outersshpriv_reactor_pop_write_action(reactor);
        assert(complete_channel_close(reactor, token) == 0);
    }
    assert(!reactor->channels[token].in_use);
}

static void bridge_closed_without_allocating(void *context,
    SSHReactorSocketBridgeHandle handle, SSHReactorSocketBridgeResult result,
    uint32_t reason, const void *detail, size_t detail_length)
{
    SSHReactor *reactor = context;
    assert(fail_all_allocations && bridge_stream_completions == 2);
    assert(outersshpriv_reactor_socket_bridge_for_handle(reactor, handle) == NULL);
    assert(result == SSH_REACTOR_SOCKET_BRIDGE_SESSION_CLOSED && reason == 0);
    assert(detail == NULL && detail_length == 0);
    bridge_completions++;
}

static void test_bridge_failure_without_allocating(SSHReactor *reactor)
{
    assert(reserve_socket_bridge_slots(reactor, 1));
    reactor->socket_bridge_slot_count = 1;
    SocketBridgeSlot *slot = &reactor->socket_bridge_slots[0];
    *slot = (SocketBridgeSlot){.generation = 1, .phase = SOCKET_BRIDGE_SLOT_ACTIVE};
    SocketBridge *bridge = &slot->bridge;
    bridge->handle = (SSHReactorSocketBridgeHandle){.index = 0, .generation = 1};
    bridge->callbacks = (SSHSocketChannelCallbacks){
        .context = reactor, .completed = bridge_closed_without_allocating
    };
    assert(reserve_socket_bridge_stream_slots(bridge, 2));
    assert(reserve_socket_bridge_streams_by_id(bridge, 2));
    bridge->stream_slot_count = 2;
    for (size_t i = 0; i < 2; i++) {
        bridge->stream_slots[i] = (SocketBridgeStreamSlot){
            .generation = 1,
            .stream = {
                .slot_index = i, .stream_id = (uint32_t)i + 1, .socket = -1,
                .phase = SOCKET_BRIDGE_STREAM_ACTIVE,
                .open_operation = (ConnectBridgeStreamContext *)(uintptr_t)(i + 1)
            }
        };
        assert(insert_socket_bridge_stream_by_id(bridge, &bridge->stream_slots[i].stream));
    }
    fail_all_allocations = true;
    finish_socket_bridge(reactor, bridge, SSH_REACTOR_SOCKET_BRIDGE_SESSION_CLOSED,
        0, "closed", 6);
    fail_all_allocations = false;
    assert(bridge_stream_completions == 2 && bridge_completions == 1);
    assert(slot->phase == SOCKET_BRIDGE_SLOT_FREE);
    assert(outersshpriv_reactor_accepts_work(reactor));
    assert(!outersshpriv_reactor_session_has_failed(reactor));
}

static void test_validation_timeout(SSHReactor *reactor)
{
    reactor->lifecycle = SSH_REACTOR_LIFECYCLE_ACTIVE;
    reactor->phase = SSH_REACTOR_PHASE_CHANNELS;
    reactor->keepalive_pending = true;
    reactor->has_pending_global_request = true;
    assert(outersshpriv_reactor_start_keepalive_timeout(reactor) == 0);
    SSHReactorSourceContext context = {
        .reactor = reactor,
        .source = reactor->keepalive_timeout_timer,
        .generation = reactor->keepalive_timeout_generation
    };
    keepalive_timeout_fired(&context);
    assert(reactor->lifecycle == SSH_REACTOR_LIFECYCLE_FAILED);
    assert(outersshpriv_reactor_session_has_failed(reactor));
    assert(!reactor->keepalive_pending);
    assert(reactor->keepalive_timeout_timer == NULL);
}

static void run_lifecycle_tests(void *context)
{
    SSHReactor *value = context;
    test_bridge_failure_without_allocating(value);
    for (int removed = 0; removed < 2; removed++) {
        test_prepared_relay_completion(value, SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED, removed);
        test_prepared_relay_completion(value, SSH_REACTOR_CHANNEL_OPEN_FAILED, removed);
        test_prepared_relay_completion(value, SSH_REACTOR_CHANNEL_OPEN_TIMED_OUT, removed);
        test_prepared_relay_completion(value, SSH_REACTOR_CHANNEL_OPEN_SESSION_CLOSED, removed);
    }
    for (int channel_type = 0; channel_type < 3; channel_type++) {
        fail_timer_creation = true;
        test_channel_open_failure(value, channel_type);
        fail_timer_creation = false;
        fail_timer_context = true;
        test_channel_open_failure(value, channel_type);
        fail_timer_context = false;
        fail_channel_creation = true;
        test_channel_open_failure(value, channel_type);
        fail_channel_creation = false;
    }
    test_prepared_relay_cancel_or_timeout(value, true, SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED);
    test_prepared_relay_cancel_or_timeout(value, true, SSH_REACTOR_CHANNEL_OPEN_FAILED);
    test_prepared_relay_cancel_or_timeout(value, false, SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED);
    test_prepared_relay_cancel_or_timeout(value, false, SSH_REACTOR_CHANNEL_OPEN_FAILED);
    test_channel_open_packet(value, false);
    test_channel_open_packet(value, true);
    test_open_timer_success(value, 10000);
    test_open_timer_success(value, 0);
    test_close_relay_after_channel_closed(value);
    test_relay_write_failure(value, true);
    test_relay_write_failure(value, false);
    test_command_channel_close(value);
    test_channel_open_completion(value, SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED, false);
    test_channel_open_completion(value, SSH_REACTOR_CHANNEL_OPEN_FAILED, false);
    test_channel_open_completion(value, SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED, true);
    test_channel_open_completion(value, SSH_REACTOR_CHANNEL_OPEN_FAILED, true);
    test_validation_timeout(value);
}

static void finish_lifecycle_tests(void *context)
{
    SSHReactor *value = context;
    assert(value->socket_source_count == 0);
    assert(value->available_relay_index_count == value->relay_slot_count);
    free(value->channels);
    free(value->write_actions);
    free(value->relay_slots);
    free(value->available_relay_indices);
    free(value->socket_bridge_slots);
    free(value->available_socket_bridge_indices);
}

static void read_source_count(void *context)
{
    void **query = context;
    *(size_t *)query[1] = ((SSHReactor *)query[0])->socket_source_count;
}

void outersshpriv_handshake_keys_exchanged(SSHReactor *reactor) { (void)reactor; abort(); }
int outersshpriv_authentication_resume_write(SSHReactor *reactor) { (void)reactor; abort(); }
void outersshpriv_authentication_keys_exchanged(SSHReactor *reactor) { (void)reactor; abort(); }
void outersshpriv_handshake_failed(SSHReactor *reactor, int error) { (void)reactor; (void)error; abort(); }

int main(void)
{
    otqueue_t queue = ssh_test_queue_create("ssh-reactor-lifecycle-test");
    SSHReactor reactor = {
        .session = (LIBSSH2_SESSION *)(uintptr_t)1,
        .queue = queue,
        .socket = -1
    };
    atomic_init(&reactor.session_failed, false);
    ssh_test_sync(queue, &reactor, run_lifecycle_tests);
    for (size_t attempt = 0; attempt < 1000; attempt++) {
        size_t source_count;
        void *query[] = {&reactor, &source_count};
        ssh_test_sync(queue, query, read_source_count);
        if (source_count == 0) break;
        ssh_test_sleep_milliseconds(1);
    }
    ssh_test_sync(queue, &reactor, finish_lifecycle_tests);
    otqueue_release(queue);
    return 0;
}

int outersshpriv_authentication_write(SSHReactor *reactor) { (void)reactor; abort(); }
void outersshpriv_authentication_failed(SSHReactor *reactor, int error) { (void)reactor; (void)error; abort(); }
