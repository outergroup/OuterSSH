#include "SSHTestSupport.h"
#include "platform/OTSocket.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libssh2.h>

#include "olibssh/key_exchange.h"
#include "olibssh/read_dispatch.h"
#include "SSHReactorReadInternal.h"

typedef enum {
    TEST_PACKET_NONE = 0,
    TEST_PACKET_CHANNEL_DATA,
    TEST_PACKET_CHANNEL_EOF,
    TEST_PACKET_CHANNEL_WINDOW_ADJUST,
    TEST_PACKET_CHANNEL_CLOSE,
    TEST_PACKET_CHANNEL_OPEN_CONFIRMATION,
    TEST_PACKET_CHANNEL_OPEN_FAILURE,
    TEST_PACKET_CHANNEL_REQUEST_SUCCESS,
    TEST_PACKET_CHANNEL_REQUEST_FAILURE,
    TEST_PACKET_CHANNEL_EXIT_STATUS,
    TEST_PACKET_GLOBAL_REQUEST_RESPONSE,
    TEST_PACKET_KEY_EXCHANGE
} TestPacketType;

typedef struct {
    TestPacketType type;
    uint32_t channel_id, stream_id, value;
} TestPacket;

#include "SSHReactorCommandInternal.h"

typedef struct {
    int result;
} ScriptedResult;

static ScriptedResult read_results[8];
static size_t read_result_count;
static size_t read_result_index;
static ScriptedResult write_results[8];
static size_t write_result_count;
static size_t write_result_index;
static const unsigned char *blocked_write_packet;
static size_t blocked_write_packet_length;
static size_t channel_close_call_count;
static int channel_close_result = LIBSSH2_ERROR_EAGAIN;
static size_t channel_send_eof_call_count;
static size_t channel_open_call_count, channel_exec_call_count;
static int channel_exec_result;
static size_t window_adjust_call_count, ping_write_call_count;
static int window_adjust_result;
static uint32_t window_adjust_amount;
static const unsigned char *scripted_read_response;
static size_t scripted_read_response_length;
static TestPacket scripted_read_events[8];
static ssize_t channel_write_results[4];
static size_t channel_write_result_count;
static size_t channel_write_result_index;
static const char *channel_write_buffers[4];
static uint32_t channel_write_channels[4];
static size_t channel_write_buffer_lengths[4];
static unsigned char channel_write_buffer_contents[4][16];
static ssize_t channel_read_result = LIBSSH2_ERROR_BAD_USE;
static const unsigned char *channel_read_bytes;

static unsigned char pending_header[32], pending_body[16];
static size_t pending_header_length, pending_body_length;

static int simulate_transport_write(LIBSSH2_SESSION *session,
    const unsigned char *packet, size_t packet_length,
    const unsigned char *bytes, size_t byte_count)
{
    (void)session;
    unsigned type = packet_length ? packet[0] : 90;
    int result = 0;
    switch (type) {
    case 94: {
        assert(packet_length == 9);
        uint32_t remote_id, length;
        memcpy(&remote_id, packet + 1, 4);
        memcpy(&length, packet + 5, 4);
        assert(ntohl(length) == byte_count);
        assert(channel_write_result_index < channel_write_result_count);
        assert(byte_count <= sizeof(channel_write_buffer_contents[0]));
        size_t index = channel_write_result_index++;
        channel_write_channels[index] = ntohl(remote_id);
        channel_write_buffers[index] = (const char *)bytes;
        channel_write_buffer_lengths[index] = byte_count;
        memcpy(channel_write_buffer_contents[index], bytes, byte_count);
        ssize_t scripted = channel_write_results[index];
        assert(scripted < 0 || (size_t)scripted == byte_count);
        result = scripted < 0 ? (int)scripted : 0;
        break;
    }
    case 93: {
        assert(packet_length == 9);
        uint32_t amount;
        memcpy(&amount, packet + 5, 4);
        window_adjust_amount = ntohl(amount);
        window_adjust_call_count++;
        result = window_adjust_result;
        break;
    }
    case 96: channel_send_eof_call_count++; break;
    case 97: channel_close_call_count++; result = channel_close_result; break;
    case 98: channel_exec_call_count++; result = channel_exec_result; break;
    case 90: channel_open_call_count++; break;
    default: {
        if (type == 80) {
            static const unsigned char expected[] =
                "\x50\x00\x00\x00\x16" "keepalive@outerssh.org" "\x01";
            assert(packet_length == sizeof(expected) - 1);
            assert(memcmp(packet, expected, packet_length) == 0);
            ping_write_call_count++;
        }
        assert(write_result_index < write_result_count);
        result = write_results[write_result_index++].result;
        if (result == LIBSSH2_ERROR_EAGAIN) {
            if (blocked_write_packet == NULL) {
                blocked_write_packet = packet;
                blocked_write_packet_length = packet_length;
            }
        } else {
            blocked_write_packet = NULL;
            blocked_write_packet_length = 0;
        }
        break;
    }
    }
    if (result == LIBSSH2_ERROR_EAGAIN) {
        assert(packet_length <= sizeof(pending_header));
        assert(byte_count <= sizeof(pending_body));
        if (packet != pending_header) memcpy(pending_header, packet, packet_length);
        if (byte_count && bytes != pending_body) memcpy(pending_body, bytes, byte_count);
        pending_header_length = packet_length;
        pending_body_length = byte_count;
    }
    return result;
}

static size_t transport_start_count, transport_resume_count;

int olibssh_transport_write(LIBSSH2_SESSION *session,
    const unsigned char *packet, size_t packet_length,
    const unsigned char *bytes, size_t byte_count)
{
    assert(blocked_write_packet == NULL);
    transport_start_count++;
    return simulate_transport_write(session, packet, packet_length, bytes, byte_count);
}

int olibssh_transport_resume_write(LIBSSH2_SESSION *session)
{
    transport_resume_count++;
    return simulate_transport_write(session, pending_header, pending_header_length,
        pending_body, pending_body_length);
}

int olibssh_transport_read(LIBSSH2_SESSION *session, SSHReactor *reactor)
{
    (void)session;
    if (read_result_index == read_result_count) {
        return LIBSSH2_ERROR_EAGAIN;
    }
    TestPacket packet = scripted_read_events[read_result_index];
    scripted_read_events[read_result_index] = (TestPacket){0};
    ScriptedResult step = read_results[read_result_index++];
    if (scripted_read_response_length > 0) {
        bool queued = outersshpriv_reactor_queue_protocol_response(reactor,
            scripted_read_response, scripted_read_response_length);
        scripted_read_response = NULL;
        scripted_read_response_length = 0;
        if (!queued) {
            return step.result;
        }
    }
    switch (packet.type) {
    case TEST_PACKET_NONE:
        break;
    case TEST_PACKET_CHANNEL_DATA:
        outersshpriv_reactor_received_channel_data(reactor, packet.channel_id,
            packet.stream_id, channel_read_bytes, channel_read_result > 0 ? (size_t)channel_read_result : 0);
        break;
    case TEST_PACKET_CHANNEL_EOF:
        outersshpriv_reactor_received_channel_eof(reactor, packet.channel_id);
        break;
    case TEST_PACKET_CHANNEL_CLOSE:
        outersshpriv_reactor_received_channel_close(reactor, packet.channel_id);
        break;
    case TEST_PACKET_CHANNEL_WINDOW_ADJUST:
        outersshpriv_reactor_received_channel_window_adjust(reactor, packet.channel_id, packet.value ? packet.value : 1);
        break;
    case TEST_PACKET_CHANNEL_OPEN_CONFIRMATION:
        outersshpriv_reactor_received_channel_open_confirmation(reactor, packet.channel_id, 2, 2097152, 32768);
        break;
    case TEST_PACKET_CHANNEL_OPEN_FAILURE:
        outersshpriv_reactor_received_channel_open_failure(reactor, packet.channel_id, packet.value);
        break;
    case TEST_PACKET_CHANNEL_REQUEST_SUCCESS:
        outersshpriv_reactor_received_channel_request_success(reactor, packet.channel_id);
        break;
    case TEST_PACKET_CHANNEL_REQUEST_FAILURE:
        outersshpriv_reactor_received_channel_request_failure(reactor, packet.channel_id);
        break;
    case TEST_PACKET_CHANNEL_EXIT_STATUS:
        outersshpriv_reactor_received_channel_exit_status(reactor, packet.channel_id, packet.value);
        break;
    case TEST_PACKET_GLOBAL_REQUEST_RESPONSE:
        outersshpriv_reactor_received_global_response(reactor, packet.value != 0);
        break;
    case TEST_PACKET_KEY_EXCHANGE: {
        unsigned char *bytes = malloc(1);
        assert(bytes != NULL);
        bytes[0] = 20;
        outersshpriv_reactor_received_key_exchange_packet(reactor, bytes, 1);
        break;
    }
    }
    return step.result;
}

// The read and write loops run unchanged; these replace their reactor-side effects.
bool outersshpriv_reactor_accepts_work(SSHReactor *reactor);
void outersshpriv_reactor_fail(SSHReactor *reactor, SSHReactorOperation operation, int error_code);
static void clear_keepalive(SSHReactor *reactor);
int outersshpriv_reactor_begin_key_exchange(SSHReactor *reactor);
int outersshpriv_reactor_advance_key_exchange(SSHReactor *reactor);
static int complete_channel_close(SSHReactor *reactor, SSHReactorChannelToken token);
static int complete_pending_channel_open(
    SSHReactor *reactor, SSHReactorChannelToken token,
    SSHReactorChannelOpenResult result, uint32_t reason);
static int deliver_channel_data(
    SSHReactor *reactor, SSHReactorChannelToken token, uint32_t stream_id,
    const unsigned char *bytes, size_t byte_count);
static int outersshpriv_reactor_receive_relay_eof(
    SSHReactor *reactor, SSHReactorRelayHandle handle, SSHReactorChannelToken token);
void outersshpriv_reactor_fail_socket_bridge_channel(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result);
static int schedule_command_exit_close(
    SSHReactor *reactor, SSHReactorChannelToken token);

struct RelaySlot;
static struct RelaySlot *outersshpriv_reactor_slot_for_handle(
    SSHReactor *reactor, SSHReactorRelayHandle handle);
static void outersshpriv_reactor_update_relay_read_source(SSHReactor *reactor, struct RelaySlot *relay);
void outersshpriv_reactor_socket_bridge_channel_became_writable(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle handle);
int outersshpriv_reactor_start_keepalive_timeout(SSHReactor *reactor);

// Tests advance this clock when they need an idle session.
static uint64_t test_time_seconds = 10;
#if defined(_WIN32)
static ottime_t test_ottime(ottime_t base, int64_t delta)
{
    assert(base == OTTIME_NOW && delta == 0);
    return test_time_seconds * NSEC_PER_SEC;
}
#define ottime test_ottime
#else
static int test_clock_gettime(clockid_t clock, struct timespec *now)
{
    assert(clock == CLOCK_MONOTONIC);
    *now = (struct timespec){.tv_sec = (time_t)test_time_seconds};
    return 0;
}
#define clock_gettime test_clock_gettime
#endif
#define SSH_REACTOR_TESTS 1
#include "SSHReactor.c"
#include "SSHReactorRelay.c"
#include "SSHReactorOutput.c"
#include "SSHReactorKeyExchange.c"
#if defined(_WIN32)
#undef ottime
#else
#undef clock_gettime
#endif

static int read_failure;
static SSHReactorOperation failure_operation;
static size_t relay_update_count, bridge_writable_count, keepalive_timeout_count;
static bool stop_after_relay_update, stop_after_bridge_writable;
static bool relocate_on_bridge_writable;
static SSHReactor *stop_on_command_event;
static int keepalive_timeout_result;
static int exchange_write_result = LIBSSH2_ERROR_EAGAIN;

static size_t delivered_byte_count, delivered_stream_id;
static unsigned char delivered_bytes[32];
static size_t freed_notification_count, open_completion_count;
static SSHReactorChannelOpenResult open_completion_result;
static uint32_t open_completion_reason;
static bool stop_after_delivery, stop_after_free;
static size_t source_update_count, exchange_start_count;
static TestPacketType command_event_type;
static int32_t command_event_value;
static size_t command_exit_timer_count, relay_eof_count, bridge_failure_count;

bool outersshpriv_reactor_accepts_work(SSHReactor *reactor)
{
    return reactor->lifecycle == SSH_REACTOR_LIFECYCLE_ACTIVE &&
        reactor->session != NULL;
}

void outersshpriv_reactor_fail(SSHReactor *reactor, SSHReactorOperation operation, int error_code)
{
    failure_operation = operation;
    read_failure = error_code;
    reactor->lifecycle = SSH_REACTOR_LIFECYCLE_FAILED;
}

void outersshpriv_reactor_safely_set_source_resumed(
    SSHReactor *reactor, otsource_t source, bool resumed, bool *is_resumed)
{
    (void)reactor;
    (void)source;
    *is_resumed = resumed;
    source_update_count++;
}

static void clear_keepalive(SSHReactor *reactor)
{
    reactor->keepalive_pending = false;
    free(reactor->keepalive_reason);
    reactor->keepalive_reason = NULL;
}

static unsigned exchange_finish_count;
static void finish_key_exchange(SSHReactor *reactor)
{
    reactor->key_exchange.step = OLIBSSH_KEY_EXCHANGE_IDLE;
    reactor->key_exchange_in_progress = false;
    exchange_finish_count++;
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
    outersshpriv_reactor_update_channel_write_source(reactor);
}

static int authentication_resume_result;
static unsigned authentication_resume_count;
int outersshpriv_authentication_resume_write(SSHReactor *reactor)
{
    authentication_resume_count++;
    if (authentication_resume_result == 0) {
        reactor->startup.authentication.packet_write_pending = false;
        reactor->startup.authentication.packet = NULL;
    }
    return authentication_resume_result;
}

int outersshpriv_reactor_begin_key_exchange(SSHReactor *reactor)
{
    exchange_start_count++;
    reactor->key_exchange_in_progress = true;
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    const SSHWriteAction *head = outersshpriv_reactor_const_write_action_at(reactor, 0);
    if (head && head->must_resume) {
        reactor->key_exchange_waiting_for_write = true;
    } else {
        reactor->key_exchange.step = OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT;
    }
    return 0;
}

int outersshpriv_reactor_advance_key_exchange(SSHReactor *reactor)
{
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    reactor->key_exchange.step = OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT;
    return 0;
}

static int complete_channel_close(SSHReactor *reactor, SSHReactorChannelToken token)
{
    free_channel(reactor, token);
    freed_notification_count++;
    if (stop_after_free) {
        reactor->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    }
    return 0;
}

static int complete_pending_channel_open(
    SSHReactor *reactor, SSHReactorChannelToken token,
    SSHReactorChannelOpenResult result, uint32_t reason)
{
    assert(reactor->channels[token].owner.type == SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN);
    assert(reactor->channels[token].in_use);
    if (result == SSH_REACTOR_CHANNEL_OPEN_FAILED) {
        free_channel(reactor, token);
        freed_notification_count++;
    }
    open_completion_count++;
    open_completion_result = result;
    open_completion_reason = reason;
    return 0;
}

static int deliver_channel_data(
    SSHReactor *reactor, SSHReactorChannelToken token, uint32_t stream_id,
    const unsigned char *bytes, size_t byte_count)
{
    assert(reactor->channels[token].in_use);
    assert(byte_count <= sizeof(delivered_bytes));
    memcpy(delivered_bytes, bytes, byte_count);
    delivered_byte_count = byte_count;
    delivered_stream_id = stream_id;
    if (stop_after_delivery) {
        reactor->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    }
    return 0;
}

static int outersshpriv_reactor_receive_relay_eof(
    SSHReactor *reactor, SSHReactorRelayHandle handle, SSHReactorChannelToken token)
{
    (void)handle;
    assert(reactor->channels[token].received_eof);
    relay_eof_count++;
    return 0;
}

void outersshpriv_reactor_fail_socket_bridge_channel(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result)
{
    (void)reactor;
    (void)handle;
    (void)result;
    bridge_failure_count++;
}

static int schedule_command_exit_close(
    SSHReactor *reactor, SSHReactorChannelToken token)
{
    (void)reactor;
    (void)token;
    command_exit_timer_count++;
    return 0;
}

static void record_command_event(
    SSHReactorCommand *command, TestPacketType type, uint32_t stream_id,
    const void *data, size_t data_length, int32_t value)
{
    assert(command != NULL);
    (void)stream_id;
    (void)data;
    (void)data_length;
    command_event_type = type;
    command_event_value = value;
    if (stop_on_command_event != NULL) {
        assert(outersshpriv_reactor_write_action_at(stop_on_command_event, 0)->type != SSH_WRITE_CHANNEL_EXEC);
        stop_on_command_event->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    }
}

void outersshpriv_reactor_command_request_succeeded(SSHReactorCommand *command)
{
    record_command_event(command, TEST_PACKET_CHANNEL_REQUEST_SUCCESS, 0, NULL, 0, 0);
}

void outersshpriv_reactor_command_request_failed(SSHReactorCommand *command, int error_code)
{
    record_command_event(command, TEST_PACKET_CHANNEL_REQUEST_FAILURE, 0, NULL, 0, error_code);
}

void outersshpriv_reactor_command_received_data(SSHReactorCommand *command, uint32_t stream_id,
    const void *data, size_t data_length)
{
    record_command_event(command, TEST_PACKET_CHANNEL_DATA, stream_id, data, data_length, 0);
}

void outersshpriv_reactor_command_channel_closed(SSHReactorCommand *command)
{
    record_command_event(command, TEST_PACKET_CHANNEL_CLOSE, 0, NULL, 0, 0);
}

void outersshpriv_reactor_command_received_exit_status(SSHReactorCommand *command, int32_t exit_status)
{
    record_command_event(command, TEST_PACKET_CHANNEL_EXIT_STATUS, 0, NULL, 0, exit_status);
}


static RelaySlot *outersshpriv_reactor_slot_for_handle(
    SSHReactor *reactor, SSHReactorRelayHandle handle)
{
    assert(handle.index < reactor->relay_slot_count);
    RelaySlot *slot = &reactor->relay_slots[handle.index];
    return slot->generation == handle.generation ? slot : NULL;
}

static void outersshpriv_reactor_update_relay_read_source(SSHReactor *reactor, RelaySlot *relay)
{
    assert(relay != NULL);
    relay_update_count++;
    if (stop_after_relay_update) {
        reactor->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    }
}

void outersshpriv_reactor_socket_bridge_channel_became_writable(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle handle)
{
    (void)handle;
    bridge_writable_count++;
    if (relocate_on_bridge_writable) {
        relocate_on_bridge_writable = false;
        SSHChannelState *channels = malloc(reactor->channel_capacity * sizeof(*channels));
        assert(channels != NULL);
        memcpy(channels, reactor->channels, reactor->channel_capacity * sizeof(*channels));
        free(reactor->channels);
        reactor->channels = channels;
        assert(outersshpriv_reactor_reserve_write_actions(reactor, reactor->write_action_capacity + 1) == 0);
        assert(outersshpriv_reactor_output_buffer_append(&channels[0].exec_input, "def", 3) == 0);
        assert(outersshpriv_reactor_enqueue_channel_data(reactor, 0) == 0);
    }
    if (stop_after_bridge_writable) {
        reactor->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    }
}

int outersshpriv_reactor_start_keepalive_timeout(SSHReactor *reactor)
{
    assert(reactor->has_pending_global_request);
    assert(reactor->keepalive_pending);
    keepalive_timeout_count++;
    return keepalive_timeout_result;
}

int olibssh_key_exchange_receive(LIBSSH2_SESSION *session,
    OLIBSSHKeyExchange *exchange, unsigned char *packet, size_t length)
{
    (void)session;
    (void)exchange;
    assert(length == 1 && packet[0] == 20);
    free(packet);
    return 0;
}

int olibssh_key_exchange_write(LIBSSH2_SESSION *session, OLIBSSHKeyExchange *exchange)
{
    (void)session;
    assert(exchange->step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    return exchange_write_result;
}

int olibssh_transport_has_buffered_input(LIBSSH2_SESSION *session)
{
    (void)session;
    return 0;
}

static void run_read_event(
    SSHReactor *reactor, TestPacket event, int transport_result)
{
    reactor->started = true;
    reactor->read_socket_source_is_resumed = true;
    scripted_read_events[0] = event;
    read_results[0] = (ScriptedResult){transport_result};
    read_result_count = 1;
    read_result_index = 0;
    read_failure = 0;
    ssh_socket_became_readable(reactor);
    assert(read_result_index == 1);
}

static void test_read_data_delivery(LIBSSH2_SESSION *session)
{
    static const unsigned char bytes[] = "abc";
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner = {
            .type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
            .command.command = (SSHReactorCommand *)(uintptr_t)3
        }
    };
    SSHReactor reactor = {
        .session = session,
        .channels = &state,
        .channel_capacity = 1
    };
    TestPacket event = {
        .type = TEST_PACKET_CHANNEL_DATA,
        .stream_id = 1
    };
    channel_read_result = 3;
    channel_read_bytes = bytes;
    delivered_byte_count = 0;
    run_read_event(&reactor, event, LIBSSH2_ERROR_EAGAIN);
    assert(read_failure == 0 && delivered_byte_count == 3);
    assert(delivered_stream_id == 1);
    assert(memcmp(delivered_bytes, bytes, 3) == 0);
    assert(state.has_transmitted_data);
    assert(reactor.last_server_activity_nanoseconds != 0);

    state.is_closing = true;
    delivered_byte_count = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && delivered_byte_count == 0);
    assert(state.consumed_byte_count == 0);
    state.is_closing = false;

    channel_read_result = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && delivered_byte_count == 0);
    size_t updates = source_update_count;
    run_read_event(&reactor, event, LIBSSH2_ERROR_EAGAIN);
    assert(read_failure == 0 && outersshpriv_reactor_accepts_work(&reactor));
    assert(source_update_count == updates + 1);

    channel_read_result = 3;
    stop_after_delivery = true;
    updates = source_update_count;
    run_read_event(&reactor, event, 0);
    assert(reactor.lifecycle == SSH_REACTOR_LIFECYCLE_INVALIDATED);
    assert(source_update_count == updates);
    stop_after_delivery = false;
    reactor.lifecycle = SSH_REACTOR_LIFECYCLE_ACTIVE;

    event.type = TEST_PACKET_NONE;
    run_read_event(&reactor, event, LIBSSH2_ERROR_BAD_USE);
    assert(read_failure == LIBSSH2_ERROR_BAD_USE);
    assert(reactor.lifecycle == SSH_REACTOR_LIFECYCLE_FAILED);
}

static void test_unattached_read_data(LIBSSH2_SESSION *session)
{
    static const unsigned char bytes[] = "abc";
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_RELAY
    };
    SSHReactor reactor = {
        .session = session,
        .channels = &state,
        .channel_capacity = 1
    };
    TestPacket event = {.type = TEST_PACKET_CHANNEL_DATA};
    assert(outersshpriv_reactor_output_buffer_append(&state.unattached_remote_buffer, "hi", 2) == 0);
    channel_read_bytes = bytes;
    channel_read_result = 3;
    delivered_byte_count = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && delivered_byte_count == 0);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&state.unattached_remote_buffer) == 5);
    assert(memcmp(state.unattached_remote_buffer.bytes, "hiabc", 5) == 0);
    assert(state.consumed_byte_count == 0);

    event.stream_id = 1;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && delivered_byte_count == 0);
    assert(state.consumed_byte_count == 3);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&state.unattached_remote_buffer) == 5);
    outersshpriv_reactor_output_buffer_deinitialize(&state.unattached_remote_buffer);

    state.unattached_remote_buffer.byte_count = SSH_READ_BUFFER_CAPACITY;
    event.stream_id = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == LIBSSH2_ERROR_OUT_OF_BOUNDARY);
    state.unattached_remote_buffer.byte_count = 0;
    channel_read_result = LIBSSH2_ERROR_BAD_USE;
}

static void test_read_channel_lifecycle(LIBSSH2_SESSION *session)
{
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN
    };
    SSHReactor reactor = {.session = session, .channels = &state, .channel_capacity = 1};
    TestPacket event = {
        .type = TEST_PACKET_CHANNEL_OPEN_CONFIRMATION
    };
    open_completion_count = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && open_completion_count == 1);
    assert(open_completion_result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED);

    event.type = TEST_PACKET_CHANNEL_OPEN_FAILURE;
    event.value = 42;
    freed_notification_count = 0;
    run_read_event(&reactor, event, LIBSSH2_ERROR_EAGAIN);
    assert(read_failure == 0 && !state.in_use);
    assert(freed_notification_count == 1);
    assert(open_completion_count == 2);
    assert(open_completion_result == SSH_REACTOR_CHANNEL_OPEN_FAILED);
    assert(open_completion_reason == 42);

    state.in_use = true;
    state.owner.type = SSH_REACTOR_CHANNEL_OWNER_NONE;
    state.close_sent = true;
    state.sent_eof = true;
    event.type = TEST_PACKET_CHANNEL_EOF;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && reactor.write_action_count == 0);
    event.type = TEST_PACKET_CHANNEL_CLOSE;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && !state.in_use);
    assert(freed_notification_count == 2);

    event.type = TEST_PACKET_CHANNEL_DATA;
    event.channel_id = 1;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0);
    event.channel_id = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0);
    event.type = TEST_PACKET_CHANNEL_OPEN_CONFIRMATION;
    run_read_event(&reactor, event, 0);
    assert(read_failure == LIBSSH2_ERROR_PROTO);
}

static void test_read_open_confirmations_and_buffered_data(LIBSSH2_SESSION *session)
{
    static const unsigned char bytes[] = "hello";
    SSHChannelState channels[] = {
        {
            .in_use = true,
            .remote_id = 2,
            .send_window = 2097152,
            .send_packet_size = 32768,
            .receive_window = 2097152,
            .receive_packet_size = 32768,
            .purpose = SSH_CHANNEL_PURPOSE_RELAY,
            .owner.type = SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN
        },
        {
            .in_use = true,
            .remote_id = 3,
            .send_window = 2097152,
            .send_packet_size = 32768,
            .receive_window = 2097152,
            .receive_packet_size = 32768,
            .purpose = SSH_CHANNEL_PURPOSE_RELAY,
            .owner.type = SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN
        }
    };
    SSHReactor reactor = {
        .session = session,
        .channels = channels,
        .channel_capacity = 2
    };
    scripted_read_events[0] = (TestPacket){
        .type = TEST_PACKET_CHANNEL_OPEN_CONFIRMATION,
        .channel_id = 0
    };
    scripted_read_events[1] = (TestPacket){
        .type = TEST_PACKET_CHANNEL_OPEN_CONFIRMATION,
        .channel_id = 1
    };
    scripted_read_events[2] = (TestPacket){
        .type = TEST_PACKET_CHANNEL_DATA,
        .channel_id = 0
    };
    read_result_count = 3;
    read_result_index = 0;
    for (size_t index = 0; index < read_result_count; index++) {
        read_results[index] = (ScriptedResult){0};
    }
    channel_read_bytes = bytes;
    channel_read_result = sizeof(bytes) - 1;
    open_completion_count = 0;
    read_failure = 0;

    reactor.started = true;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    ssh_socket_became_readable(&reactor);

    assert(read_failure == 0 && outersshpriv_reactor_accepts_work(&reactor));
    assert(open_completion_count == 2);
    assert(read_result_index == read_result_count);
    SSHChannelOutputBuffer *buffer = &channels[0].unattached_remote_buffer;
    assert(outersshpriv_reactor_buffer_pending_byte_count(buffer) == sizeof(bytes) - 1);
    assert(memcmp(buffer->bytes + buffer->offset, bytes, sizeof(bytes) - 1) == 0);
    outersshpriv_reactor_output_buffer_deinitialize(buffer);
    channel_read_bytes = NULL;
    channel_read_result = LIBSSH2_ERROR_BAD_USE;
}

static void test_read_command_and_eof(LIBSSH2_SESSION *session)
{
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner = {
            .type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
            .command.command = (SSHReactorCommand *)(uintptr_t)3
        }
    };
    SSHReactor reactor = {.session = session, .channels = &state, .channel_capacity = 1};
    TestPacket event = {.type = TEST_PACKET_CHANNEL_REQUEST_SUCCESS};
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && command_event_type == event.type);

    event.type = TEST_PACKET_CHANNEL_EXIT_STATUS;
    event.value = 17;
    command_exit_timer_count = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && command_event_type == event.type && command_event_value == 17);
    assert(command_exit_timer_count == 1);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->type == SSH_WRITE_CHANNEL_EOF);

    event.type = TEST_PACKET_CHANNEL_REQUEST_FAILURE;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && command_event_type == event.type);
    assert(command_event_value == LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED);
    assert(state.is_closing);
    while (reactor.write_action_count != 0) {
        outersshpriv_reactor_pop_write_action(&reactor);
    }
    free(reactor.write_actions);
    reactor.write_actions = NULL;
    reactor.write_action_capacity = 0;

    state.is_closing = false;
    state.owner.type = SSH_REACTOR_CHANNEL_OWNER_RELAY;
    event.type = TEST_PACKET_CHANNEL_EOF;
    relay_eof_count = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && state.received_eof && relay_eof_count == 1);

    state.owner.type = SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE;
    bridge_failure_count = 0;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && bridge_failure_count == 1);
    state.is_closing = true;
    run_read_event(&reactor, event, 0);
    assert(read_failure == 0 && bridge_failure_count == 1);
}


static void test_write_drain_notifications(
    LIBSSH2_SESSION *session, SSHReactorChannelOwnerType owner_type)
{
    SSHRelay relay_data = {0};
    RelaySlot slot = {.generation = 1, .relay = &relay_data};
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = owner_type == SSH_REACTOR_CHANNEL_OWNER_RELAY
            ? SSH_CHANNEL_PURPOSE_RELAY : SSH_CHANNEL_PURPOSE_EXEC,
        .has_transmitted_data = true,
        .owner.type = owner_type
    };
    bool relays = owner_type == SSH_REACTOR_CHANNEL_OWNER_RELAY;
    if (relays) {
        state.relay = &relay_data;
        state.owner.relay_handle = (SSHReactorRelayHandle){.generation = 1};
        assert(outersshpriv_relay_buffer_initialize(&relay_data.to_ssh, 16) == 0);
        assert(outersshpriv_relay_buffer_append(&relay_data.to_ssh, "abc", 3) == 0);
    } else {
        assert(outersshpriv_reactor_output_buffer_append(&state.exec_input, "abc", 3) == 0);
    }
    SSHReactor reactor = {
        .session = session, .channels = &state, .channel_capacity = 1,
        .relay_slots = &slot, .relay_slot_count = 1
    };
    assert(outersshpriv_reactor_enqueue_channel_data(&reactor, 0) == 0);
    const unsigned char response = 0xaa;
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    channel_write_results[0] = 3;
    channel_write_result_count = 1;
    channel_write_result_index = 0;
    write_result_index = 0;
    write_result_count = 1;
    write_results[0] = (ScriptedResult){0};
    blocked_write_packet = NULL;
    relay_update_count = bridge_writable_count = 0;
    stop_after_relay_update = stop_after_bridge_writable = true;
    process_writes(&reactor);
    assert(reactor.lifecycle == SSH_REACTOR_LIFECYCLE_INVALIDATED);
    assert(channel_output_pending(&state) == 0);
    assert(reactor.write_action_count == 1 && write_result_index == 0);
    assert(relay_update_count == (owner_type == SSH_REACTOR_CHANNEL_OWNER_RELAY ? 1 : 0));
    assert(bridge_writable_count == (owner_type == SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE ? 1 : 0));
    stop_after_relay_update = stop_after_bridge_writable = false;
    reactor.lifecycle = SSH_REACTOR_LIFECYCLE_ACTIVE;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor) && reactor.write_action_count == 0);
    if (relays) {
        outersshpriv_relay_buffer_deinitialize(&relay_data.to_ssh);
    } else {
        outersshpriv_reactor_output_buffer_deinitialize(&state.exec_input);
    }
    free(reactor.write_actions);
}

static void test_bridge_write_notification_relocates_arrays(LIBSSH2_SESSION *session)
{
    SSHReactor reactor = {
        .session = session,
        .channels = calloc(1, sizeof(*reactor.channels)),
        .channel_capacity = 1
    };
    assert(reactor.channels != NULL);
    reactor.channels[0] = (SSHChannelState){
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE,
        .has_transmitted_data = true
    };
    assert(outersshpriv_reactor_output_buffer_append(&reactor.channels[0].exec_input, "abc", 3) == 0);
    assert(outersshpriv_reactor_enqueue_channel_data(&reactor, 0) == 0);
    channel_write_results[0] = channel_write_results[1] = 3;
    channel_write_result_count = 2;
    channel_write_result_index = 0;
    bridge_writable_count = 0;
    relocate_on_bridge_writable = true;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(!relocate_on_bridge_writable && bridge_writable_count == 2);
    assert(channel_write_result_index == 2);
    assert(memcmp(channel_write_buffer_contents[0], "abc", 3) == 0);
    assert(memcmp(channel_write_buffer_contents[1], "def", 3) == 0);
    assert(reactor.write_action_count == 0);
    outersshpriv_reactor_output_buffer_deinitialize(&reactor.channels[0].exec_input);
    free(reactor.channels);
    free(reactor.write_actions);
}

static void test_write_exec_notifications(LIBSSH2_SESSION *session, int exec_result, bool rekey)
{
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner = {
            .type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
            .command.command = (SSHReactorCommand *)(uintptr_t)3
        }
    };
    SSHReactor reactor = {
        .session = session, .channels = &state, .channel_capacity = 1,
        .last_server_activity_nanoseconds = outersshpriv_reactor_monotonic_time_nanoseconds()
    };
    char *command = strdup("cat");
    assert(command != NULL);
    assert(outersshpriv_reactor_append_write_action(&reactor, (SSHWriteAction){
        .type = SSH_WRITE_CHANNEL_EXEC,
        .payload.exec = {.command = command, .command_length = 3}
    }, false) == 0);
    const unsigned char response = 0xaa;
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    channel_exec_result = LIBSSH2_ERROR_EAGAIN;
    command_event_type = TEST_PACKET_NONE;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor) && outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);
    assert(command_event_type == TEST_PACKET_NONE);
    channel_exec_result = exec_result;
    stop_on_command_event = &reactor;
    write_result_index = 0;
    if (rekey) {
        reactor.started = true;
        assert(outersshpriv_reactor_begin_key_exchange(&reactor) == 0);
        key_exchange_socket_became_writable(&reactor);
        assert(reactor.key_exchange_waiting_for_write);
        assert(reactor.key_exchange.step == OLIBSSH_KEY_EXCHANGE_IDLE);
    } else {
        process_writes(&reactor);
    }
    assert(reactor.lifecycle == SSH_REACTOR_LIFECYCLE_INVALIDATED);
    assert(command_event_type == (exec_result < 0
        ? TEST_PACKET_CHANNEL_REQUEST_FAILURE : TEST_PACKET_CHANNEL_REQUEST_SUCCESS));
    assert(command_event_value == exec_result);
    assert(state.is_closing == (exec_result < 0));
    assert(write_result_index == 0);
    assert(reactor.write_action_count == (exec_result < 0 ? 2 : 1));
    stop_on_command_event = NULL;
    channel_exec_result = 0;
    while (reactor.write_action_count != 0) {
        outersshpriv_reactor_pop_write_action(&reactor);
    }
    free(reactor.write_actions);
}

static void test_write_close_notification_stops_reactor(LIBSSH2_SESSION *session)
{
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .remote_closed = true
    };
    SSHReactor reactor = {.session = session, .channels = &state, .channel_capacity = 1};
    assert(outersshpriv_reactor_append_write_action(&reactor,
        (SSHWriteAction){.type = SSH_WRITE_CHANNEL_CLOSE}, false) == 0);
    const unsigned char response = 0xaa;
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    channel_close_result = 0;
    freed_notification_count = 0;
    stop_after_free = true;
    write_result_index = 0;
    process_writes(&reactor);
    assert(reactor.lifecycle == SSH_REACTOR_LIFECYCLE_INVALIDATED);
    assert(!state.in_use);
    assert(freed_notification_count == 1 && write_result_index == 0);
    assert(reactor.write_action_count == 1);
    stop_after_free = false;
    channel_close_result = LIBSSH2_ERROR_EAGAIN;
    outersshpriv_reactor_pop_write_action(&reactor);
    free(reactor.write_actions);
}

static void test_keepalive_write_notification(LIBSSH2_SESSION *session, bool rekey)
{
    SSHReactor reactor = {.session = session};
    assert(enqueue_keepalive(&reactor) == 0);
    blocked_write_packet = NULL;
    write_result_index = 0;
    write_result_count = 2;
    write_results[0] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    write_results[1] = (ScriptedResult){0};
    keepalive_timeout_count = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor) && outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);
    assert(!reactor.has_pending_global_request && keepalive_timeout_count == 0);
    if (rekey) {
        reactor.started = true;
        outersshpriv_reactor_begin_key_exchange(&reactor);
        key_exchange_socket_became_writable(&reactor);
    } else {
        process_writes(&reactor);
    }
    assert(outersshpriv_reactor_accepts_work(&reactor) && reactor.write_action_count == 0);
    assert(reactor.has_pending_global_request && reactor.keepalive_pending);
    assert(keepalive_timeout_count == (rekey ? 0 : 1));
    assert(reactor.keepalive_timeout_milliseconds == DefaultKeepaliveTimeoutMilliseconds);
    assert(strcmp(reactor.keepalive_reason, "automatic SSH validation") == 0);
    if (rekey) {
        assert(!reactor.key_exchange_waiting_for_write);
        assert(reactor.key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    }
    clear_keepalive(&reactor);
    free(reactor.write_actions);
}

static void test_write_failure_classification(LIBSSH2_SESSION *session, bool timer_failure)
{
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
        .has_transmitted_data = true
    };
    SSHReactor reactor = {.session = session, .channels = &state, .channel_capacity = 1};
    assert(outersshpriv_reactor_output_buffer_append(&state.exec_input, "abc", 3) == 0);
    assert(outersshpriv_reactor_enqueue_channel_data(&reactor, 0) == 0);
    assert(enqueue_keepalive(&reactor) == 0);
    blocked_write_packet = NULL;
    write_result_index = 0;
    write_result_count = 1;
    write_results[0] = (ScriptedResult){0};
    channel_write_result_index = 0;
    channel_write_result_count = 1;
    channel_write_results[0] = LIBSSH2_ERROR_SOCKET_SEND;
    keepalive_timeout_result = timer_failure ? LIBSSH2_ERROR_ALLOC : 0;
    process_writes(&reactor);
    assert(reactor.lifecycle == SSH_REACTOR_LIFECYCLE_FAILED);
    assert(read_failure == (timer_failure ? LIBSSH2_ERROR_ALLOC : LIBSSH2_ERROR_SOCKET_SEND));
    assert(failure_operation == (timer_failure
        ? SSH_REACTOR_OPERATION_KEEPALIVE : SSH_REACTOR_OPERATION_WRITE));
    assert(channel_write_result_index == (timer_failure ? 0 : 1));
    keepalive_timeout_result = 0;
    outersshpriv_reactor_pop_write_action(&reactor);
    outersshpriv_reactor_output_buffer_deinitialize(&state.exec_input);
    clear_keepalive(&reactor);
    free(reactor.write_actions);
}

static void test_socket_source_state(LIBSSH2_SESSION *session)
{
    SSHReactor reactor = {.started = true, .session = session};
    for (unsigned mask = 0; mask < 4; mask++) {
        bool readable = (mask & 1) != 0;
        bool writable = (mask & 2) != 0;
        outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, readable);
        outersshpriv_reactor_set_ssh_write_source_resumed(&reactor, writable);
        assert(reactor.read_socket_source_is_resumed == readable);
        assert(reactor.write_socket_source_is_resumed == writable);
    }

    size_t updates = source_update_count;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, false);
    assert(source_update_count == updates + 1);
    assert(!reactor.read_socket_source_is_resumed);
    assert(reactor.write_socket_source_is_resumed);
    outersshpriv_reactor_set_ssh_write_source_resumed(&reactor, false);
    assert(source_update_count == updates + 2);
    assert(!reactor.read_socket_source_is_resumed);
    assert(!reactor.write_socket_source_is_resumed);
    outersshpriv_reactor_set_ssh_write_source_resumed(&reactor, true);

    // Notifications queued before a transition must not perform unwanted I/O.
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(&reactor, false);
    size_t reads = read_result_index;
    size_t writes = write_result_index;
    ssh_socket_became_readable(&reactor);
    ssh_socket_became_writable(&reactor);
    ssh_socket_became_readable(&reactor);
    assert(read_result_index == reads && write_result_index == writes);

    for (size_t i = 0; i < 3; i++) {
        reactor.started = i != 0;
        reactor.session = i == 1 ? NULL : session;
        reactor.lifecycle = i == 2
            ? SSH_REACTOR_LIFECYCLE_FAILED : SSH_REACTOR_LIFECYCLE_ACTIVE;
        outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
        outersshpriv_reactor_set_ssh_write_source_resumed(&reactor, true);
        assert(!reactor.read_socket_source_is_resumed);
        assert(!reactor.write_socket_source_is_resumed);
    }
}

static void test_writable_source_validation(LIBSSH2_SESSION *session)
{
    SSHWriteAction action = {.type = SSH_WRITE_CHANNEL_OPEN};
    SSHReactor reactor = {
        .started = true,
        .session = session,
        .has_pending_global_request = true,
        .write_actions = &action,
        .write_action_count = 1,
        .write_action_capacity = 1,
        .read_socket_source_is_resumed = true,
        .write_socket_source_is_resumed = true,
    };
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(!reactor.write_socket_source_is_resumed);
    assert(reactor.read_socket_source_is_resumed);

    action.must_resume = true;
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.write_socket_source_is_resumed);
    assert(reactor.read_socket_source_is_resumed);

    action.must_resume = false;
    action.type = SSH_WRITE_PROTOCOL_RESPONSE;
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.write_socket_source_is_resumed);
    assert(reactor.read_socket_source_is_resumed);

    action.type = SSH_WRITE_CHANNEL_OPEN;
    reactor.has_pending_global_request = false;
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.write_socket_source_is_resumed);
    assert(reactor.read_socket_source_is_resumed);
}

static void test_read_eagain_does_not_block_writes(LIBSSH2_SESSION *session)
{
    SSHReactor reactor = {.started = true, .session = session};
    read_results[0] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    read_result_count = 1;
    read_result_index = 0;
    reactor.started = true;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    ssh_socket_became_readable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.read_socket_source_is_resumed);

    static const unsigned char response = 0xaa;
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    write_results[0] = (ScriptedResult){0};
    write_result_count = 1;
    write_result_index = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(write_result_index == 1);
    assert(reactor.write_action_count == 0);
    free(reactor.write_actions);
}

static void test_explicit_key_exchange_readiness(LIBSSH2_SESSION *session)
{
    SSHReactor reactor = {.started = true, .session = session};
    scripted_read_events[0] = (TestPacket){
        .type = TEST_PACKET_KEY_EXCHANGE
    };
    read_results[0] = (ScriptedResult){20};
    read_result_count = 1;
    read_result_index = 0;
    reactor.started = true;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    ssh_socket_became_readable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(exchange_start_count == 1);
    assert(reactor.key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);

    static const unsigned char response = 0xaa;
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    reactor.key_exchange.step = OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    outersshpriv_reactor_set_ssh_write_source_resumed(&reactor, false);
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.read_socket_source_is_resumed);
    assert(!reactor.write_socket_source_is_resumed);
    key_exchange_socket_became_writable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(reactor.write_action_count == 1);

    reactor.key_exchange.step = OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(&reactor, true);
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(!reactor.read_socket_source_is_resumed);
    assert(reactor.write_socket_source_is_resumed);
    key_exchange_socket_became_writable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(reactor.write_action_count == 1);
    assert(reactor.write_socket_source_is_resumed);
    assert(!reactor.read_socket_source_is_resumed);

    unsigned finished = exchange_finish_count;
    reactor.key_exchange.step = OLIBSSH_KEY_EXCHANGE_COMPLETE;
    key_exchange_socket_became_writable(&reactor);
    assert(exchange_finish_count == finished + 1);
    assert(!reactor.key_exchange_in_progress);
    assert(reactor.write_action_count == 1);
    write_results[0] = (ScriptedResult){0};
    write_result_count = 1;
    write_result_index = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(reactor.write_action_count == 0);
    free(reactor.write_actions);
}

static void test_write_owner(LIBSSH2_SESSION *session)
{
    SSHReactor reactor = {
        .started = true, .session = session
    };
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    transport_start_count = transport_resume_count = 0;
    write_results[0] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    write_results[1] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    write_results[2] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    write_results[3] = (ScriptedResult){0};
    write_results[4] = (ScriptedResult){0};
    write_result_count = 5;
    write_result_index = 0;
    blocked_write_packet = NULL;
    blocked_write_packet_length = 0;

    static const unsigned char first_response = 0xaa;
    assert(outersshpriv_reactor_enqueue_protocol_response(
               &reactor,
               &first_response,
               1) == 0);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.read_socket_source_is_resumed);
    assert(reactor.write_socket_source_is_resumed);

    read_results[0] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    read_result_count = 1;
    read_result_index = 0;
    reactor.started = true;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    ssh_socket_became_readable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(read_result_index == 1);

    const unsigned char *first_packet = blocked_write_packet;
    static const unsigned char second_response = 0xbb;
    assert(outersshpriv_reactor_enqueue_protocol_response(
               &reactor,
               &second_response,
               1) == 0);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->payload.packet.bytes ==
           first_packet);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);

    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(write_result_index == write_result_count);
    assert(transport_start_count == 2);
    assert(transport_resume_count == 3);
    assert(reactor.write_action_count == 0);
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.read_socket_source_is_resumed);
    assert(!reactor.write_socket_source_is_resumed);
    free(reactor.write_actions);
}

static void test_server_channel_open_rejection(LIBSSH2_SESSION *session)
{
    SSHReactor reactor = {
        .session = session
    };
    static const unsigned char response[] = {
        92,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    read_results[0] = (ScriptedResult){0};
    read_result_count = 1;
    read_result_index = 0;
    scripted_read_response = response;
    scripted_read_response_length = sizeof(response);
    reactor.started = true;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    ssh_socket_became_readable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(reactor.write_action_count == 1);
    SSHWriteAction *action = outersshpriv_reactor_write_action_at(&reactor, 0);
    assert(action != NULL);
    assert(action->type == SSH_WRITE_PROTOCOL_RESPONSE);
    assert(action->payload.packet.length == sizeof(response));
    assert(memcmp(action->payload.packet.bytes,
                  response,
                  sizeof(response)) == 0);

    write_results[0] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    write_results[1] = (ScriptedResult){0};
    write_result_count = 2;
    write_result_index = 0;
    blocked_write_packet = NULL;
    blocked_write_packet_length = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(blocked_write_packet_length == sizeof(response));
    assert(memcmp(blocked_write_packet, response, sizeof(response)) == 0);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(reactor.write_action_count == 0);
    free(reactor.write_actions);
}

static void test_channel_write_retry_survives_output_buffer_relocation(void)
{
    static const unsigned char first[] = "abc";
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 3,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
        .has_transmitted_data = true
    };
    assert(outersshpriv_reactor_output_buffer_append(
               &state.exec_input,
               first,
               sizeof(first) - 1) == 0);
    SSHWriteAction action = {
        .type = SSH_WRITE_CHANNEL_DATA
    };
    SSHReactor reactor = {
        .session = (LIBSSH2_SESSION *)(uintptr_t)1,
        .channels = &state,
        .channel_capacity = 1,
        .write_actions = &action,
        .write_action_capacity = 1,
        .write_action_count = 1
    };
    channel_write_results[0] = LIBSSH2_ERROR_EAGAIN;
    channel_write_results[1] = sizeof(first) - 1;
    channel_write_result_count = 2;
    channel_write_result_index = 0;

    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(action.payload.channel_data.byte_count == sizeof(first) - 1);
    assert(channel_write_buffer_lengths[0] == sizeof(first) - 1);
    assert(memcmp(channel_write_buffer_contents[0],
                  first,
                  sizeof(first) - 1) == 0);

    assert(state.send_window == 3);
    outersshpriv_reactor_received_channel_window_adjust(&reactor, 0, 7);
    assert(state.send_window == 10);

    unsigned char *original_bytes = state.exec_input.bytes;
    unsigned char *relocated_bytes = malloc(state.exec_input.capacity);
    assert(relocated_bytes != NULL);
    assert(relocated_bytes != original_bytes);
    memcpy(relocated_bytes,
           state.exec_input.bytes,
           state.exec_input.byte_count);
    state.exec_input.bytes = relocated_bytes;
    free(original_bytes);

    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_write_result_index == channel_write_result_count);
    assert(channel_write_buffers[1] == (const char *)pending_body);
    assert(channel_write_buffer_lengths[1] == sizeof(first) - 1);
    assert(memcmp(channel_write_buffer_contents[1],
                  first,
                  sizeof(first) - 1) == 0);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&state.exec_input) == 0);
    assert(state.send_window == 7);
    outersshpriv_reactor_output_buffer_deinitialize(&state.exec_input);
}

static void test_channel_write_respects_packet_and_window_limits(void)
{
    static const unsigned char input[] = "abcdef";
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 7,
        .send_window = 5,
        .send_packet_size = 2,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
        .has_transmitted_data = true
    };
    assert(outersshpriv_reactor_output_buffer_append(&state.exec_input, input, sizeof(input) - 1) == 0);
    SSHWriteAction action = {.type = SSH_WRITE_CHANNEL_DATA};
    SSHReactor reactor = {
        .session = (LIBSSH2_SESSION *)(uintptr_t)1,
        .channels = &state,
        .channel_capacity = 1,
        .write_actions = &action,
        .write_action_capacity = 1,
        .write_action_count = 1
    };
    channel_write_results[0] = 2;
    channel_write_results[1] = 2;
    channel_write_results[2] = 1;
    channel_write_results[3] = 1;
    channel_write_result_count = 4;
    channel_write_result_index = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_write_result_index == 3);
    assert(memcmp(channel_write_buffer_contents[0], "ab", 2) == 0);
    assert(memcmp(channel_write_buffer_contents[1], "cd", 2) == 0);
    assert(memcmp(channel_write_buffer_contents[2], "e", 1) == 0);
    assert(state.send_window == 0 && state.is_waiting_for_window);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&state.exec_input) == 1);
    assert(reactor.write_action_count == 0);

    outersshpriv_reactor_received_channel_window_adjust(&reactor, 0, 1);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_write_result_index == 4);
    assert(memcmp(channel_write_buffer_contents[3], "f", 1) == 0);
    assert(state.send_window == 0 && !state.is_waiting_for_window);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&state.exec_input) == 0);
    assert(reactor.write_action_count == 0);
    outersshpriv_reactor_output_buffer_deinitialize(&state.exec_input);
}

static void test_borrowed_exec_input_sends_both_segments_in_place(void)
{
    static const unsigned char prefix[] = "ab";
    static const unsigned char tail[] = "cdef";
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 7,
        .send_window = 100,
        .send_packet_size = 3,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
        .has_transmitted_data = true,
        .exec_input = {.bytes = (unsigned char *)prefix, .byte_count = 2, .capacity = 2},
        .exec_input_tail = tail,
        .exec_input_tail_length = 4,
        .exec_input_is_borrowed = true
    };
    SSHWriteAction action = {.type = SSH_WRITE_CHANNEL_DATA};
    SSHReactor reactor = {
        .session = (LIBSSH2_SESSION *)(uintptr_t)1,
        .channels = &state,
        .channel_capacity = 1,
        .write_actions = &action,
        .write_action_capacity = 1,
        .write_action_count = 1
    };
    channel_write_results[0] = 2;
    channel_write_results[1] = 3;
    channel_write_results[2] = 1;
    channel_write_result_count = 3;
    channel_write_result_index = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_write_result_index == 3);
    assert(channel_write_buffers[0] == (const char *)prefix);
    assert(channel_write_buffers[1] == (const char *)tail);
    assert(channel_write_buffers[2] == (const char *)tail + 3);
    assert(memcmp(channel_write_buffer_contents[0], "ab", 2) == 0);
    assert(memcmp(channel_write_buffer_contents[1], "cde", 3) == 0);
    assert(memcmp(channel_write_buffer_contents[2], "f", 1) == 0);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&state.exec_input) == 0);
    assert(state.exec_input_tail == NULL && state.exec_input_tail_length == 0);
    assert(reactor.write_action_count == 0);
}

static void test_receive_window_credit_during_partial_write(void)
{
    uint32_t initial_credit = SSH_READ_BUFFER_CAPACITY / 2;
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 7,
        .receive_window = SSH_READ_BUFFER_CAPACITY - initial_credit,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND
    };
    SSHWriteAction action = {0};
    SSHReactor reactor = {
        .session = (LIBSSH2_SESSION *)(uintptr_t)1,
        .channels = &state,
        .channel_capacity = 1,
        .write_actions = &action,
        .write_action_capacity = 1
    };
    assert(outersshpriv_reactor_consume_channel_bytes(&reactor, &state, 0, initial_credit) == 0);
    window_adjust_call_count = 0;
    window_adjust_result = LIBSSH2_ERROR_EAGAIN;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(action.must_resume);
    assert(window_adjust_call_count == 1 && window_adjust_amount == initial_credit);
    assert(state.receive_window == SSH_READ_BUFFER_CAPACITY - initial_credit);
    assert(state.consumed_byte_count == initial_credit);

    static const unsigned char bytes[] = "abc";
    outersshpriv_reactor_received_channel_data(&reactor, 0, 0, bytes, sizeof(bytes) - 1);
    assert(outersshpriv_reactor_consume_channel_bytes(&reactor, &state, 0, sizeof(bytes) - 1) == 0);
    assert(state.receive_window == SSH_READ_BUFFER_CAPACITY - initial_credit - 3);
    assert(state.consumed_byte_count == initial_credit + 3);
    assert(reactor.write_action_count == 1);

    window_adjust_result = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(window_adjust_call_count == 2 && window_adjust_amount == initial_credit);
    assert(state.receive_window == SSH_READ_BUFFER_CAPACITY - 3);
    assert(state.consumed_byte_count == 3);
    assert(reactor.write_action_count == 0);
}

static void test_window_blocked_channel_yields_and_resumes(void)
{
    static const unsigned char first[] = "a";
    static const unsigned char second[] = "b";
    SSHChannelState states[2] = {
        {
            .in_use = true,
            .remote_id = 2,
            .send_window = 2097152,
            .send_packet_size = 32768,
            .receive_window = 2097152,
            .receive_packet_size = 32768,
            .purpose = SSH_CHANNEL_PURPOSE_EXEC,
            .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
            .has_transmitted_data = true
        },
        {
            .in_use = true,
            .remote_id = 3,
            .send_window = 2097152,
            .send_packet_size = 32768,
            .receive_window = 2097152,
            .receive_packet_size = 32768,
            .purpose = SSH_CHANNEL_PURPOSE_EXEC,
            .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
            .has_transmitted_data = true
        }
    };
    assert(outersshpriv_reactor_output_buffer_append(
               &states[0].exec_input,
               first,
               sizeof(first) - 1) == 0);
    assert(outersshpriv_reactor_output_buffer_append(
               &states[1].exec_input,
               second,
               sizeof(second) - 1) == 0);
    SSHWriteAction actions[2] = {
        {
            .type = SSH_WRITE_CHANNEL_DATA,
            .token = 0
        },
        {
            .type = SSH_WRITE_CHANNEL_DATA,
            .token = 1
        }
    };
    SSHReactor reactor = {
        .session = (LIBSSH2_SESSION *)(uintptr_t)1,
        .channels = states,
        .channel_capacity = 2,
        .write_actions = actions,
        .write_action_capacity = 2,
        .write_action_count = 2
    };
    assert(outersshpriv_reactor_enqueue_channel_eof(&reactor, &states[0], 0) == 0);
    assert(states[0].send_eof_after_output_drains);
    assert(reactor.write_action_count == 2);

    states[0].send_window = 0;
    channel_write_results[0] = sizeof(second) - 1;
    channel_write_result_count = 1;
    channel_write_result_index = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(states[0].is_waiting_for_window);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&states[0].exec_input) == 1);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&states[1].exec_input) == 0);
    assert(reactor.write_action_count == 0);

    read_results[0] = (ScriptedResult){0};
    read_result_count = 1;
    read_result_index = 0;
    scripted_read_events[0] = (TestPacket){
        .type = TEST_PACKET_CHANNEL_WINDOW_ADJUST,
        .channel_id = 0
    };
    reactor.started = true;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    ssh_socket_became_readable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(!states[0].is_waiting_for_window);
    assert(reactor.write_action_count == 1);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->type == SSH_WRITE_CHANNEL_DATA);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->token == 0);

    channel_send_eof_call_count = 0;
    channel_write_results[0] = sizeof(first) - 1;
    channel_write_result_count = 1;
    channel_write_result_index = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(outersshpriv_reactor_buffer_pending_byte_count(&states[0].exec_input) == 0);
    assert(!states[0].send_eof_after_output_drains);
    assert(channel_send_eof_call_count == 1);
    assert(states[0].sent_eof);
    assert(reactor.write_action_count == 0);
    outersshpriv_reactor_output_buffer_deinitialize(&states[0].exec_input);
    outersshpriv_reactor_output_buffer_deinitialize(&states[1].exec_input);
}

static void test_relay_buffer_wraps(void)
{
    SSHRelayBuffer buffer;
    assert(outersshpriv_relay_buffer_initialize(&buffer, 8) == 0);
    assert(outersshpriv_relay_buffer_append(&buffer, "abcdef", 6) == 0);
    outersshpriv_relay_buffer_consume(&buffer, 4);
    assert(outersshpriv_relay_buffer_append(&buffer, "ghijkl", 6) == 0);
    assert(outersshpriv_relay_buffer_pending(&buffer) == 8);
    assert(outersshpriv_relay_buffer_space(&buffer) == 0);
    assert(outersshpriv_relay_buffer_append(&buffer, "m", 1) == LIBSSH2_ERROR_OUT_OF_BOUNDARY);

    size_t length;
    const unsigned char *span = outersshpriv_relay_buffer_readable(&buffer, &length);
    assert(length == 4 && memcmp(span, "efgh", 4) == 0);
    outersshpriv_relay_buffer_consume(&buffer, 4);
    span = outersshpriv_relay_buffer_readable(&buffer, &length);
    assert(length == 4 && memcmp(span, "ijkl", 4) == 0);

    unsigned char *free_span = outersshpriv_relay_buffer_writable(&buffer, &length);
    assert(free_span == buffer.bytes + 4 && length == 4);
    outersshpriv_relay_buffer_consume(&buffer, 4);
    assert(outersshpriv_relay_buffer_pending(&buffer) == 0 && buffer.start == 0);
    free_span = outersshpriv_relay_buffer_writable(&buffer, &length);
    assert(free_span == buffer.bytes && length == 8);
    outersshpriv_relay_buffer_deinitialize(&buffer);
}

static void test_unattached_data_transfer(LIBSSH2_SESSION *session)
{
    SSHChannelState *channels = calloc(1, sizeof(*channels));
    assert(channels != NULL);
    channels[0].in_use = true;
    channels[0].remote_id = 2;
    channels[0].send_window = 2097152;
    channels[0].send_packet_size = 32768;
    channels[0].receive_window = 2097152;
    channels[0].receive_packet_size = 32768;
    channels[0].purpose = SSH_CHANNEL_PURPOSE_RELAY;
    channels[0].has_transmitted_data = true;
    channels[0].received_eof = true;
    static const unsigned char greeting[] = "hello";
    assert(outersshpriv_reactor_output_buffer_append(
               &channels[0].unattached_remote_buffer,
               greeting,
               sizeof(greeting) - 1) == 0);

    SSHReactor reactor = {
        .session = session,
        .channels = channels,
        .channel_capacity = 1
    };
    assert(channel_allows_initial_relay_assignment(
        &reactor,
        &channels[0],
        0));
    otsocket_t relay_sockets[2];
    assert(ssh_test_socket_pair(relay_sockets) == 0);
    char destination[sizeof("example.com") - 1];
    memcpy(destination, "example.com", sizeof(destination));
    SSHRelay *relay = ssh_relay_create(
        relay_sockets[0],
        1,
        1,
        SSH_RELAY_TARGET_TCP,
        destination,
        sizeof(destination),
        443);
    otsocket_close(relay_sockets[1]);
    assert(relay != NULL);
    assert(relay->route.destination_length == sizeof(destination));
    assert(memcmp(relay->route.destination, destination, sizeof(destination)) == 0);
    assert(attach_relay_to_channel(
               &reactor,
               &channels[0],
               0,
               relay) == 0);
    assert(channels[0].purpose == SSH_CHANNEL_PURPOSE_RELAY);
    assert(outersshpriv_reactor_buffer_pending_byte_count(
               &channels[0].unattached_remote_buffer) == 0);
    assert(!relay->channel_read_open);
    assert(relay->pending_window_credit == sizeof(greeting) - 1);
    size_t readable;
    const unsigned char *received = outersshpriv_relay_buffer_readable(&relay->to_socket, &readable);
    assert(outersshpriv_relay_buffer_pending(&relay->to_socket) == sizeof(greeting) - 1);
    assert(readable == sizeof(greeting) - 1);
    assert(memcmp(received, greeting, sizeof(greeting) - 1) == 0);
    assert(!outersshpriv_reactor_channel_lifecycle_allows_reassignment(&channels[0]));

    outersshpriv_relay_release(channels[0].relay);
    channels[0].relay = NULL;
    outersshpriv_relay_release(relay);
    free(channels);
}

static void test_rekey_waits_for_only_the_incomplete_packet(LIBSSH2_SESSION *session)
{
    SSHChannelState state = {
        .in_use = true,
        .remote_id = 2,
        .send_window = 2097152,
        .send_packet_size = 32768,
        .receive_window = 2097152,
        .receive_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
        .has_transmitted_data = true
    };
    assert(outersshpriv_reactor_output_buffer_append(&state.exec_input, "abc", 3) == 0);
    SSHWriteAction action = {.type = SSH_WRITE_CHANNEL_DATA};
    SSHReactor reactor = {
        .started = true, .session = session,
        .channels = &state,
        .channel_capacity = 1,
        .write_actions = &action,
        .write_action_capacity = 1,
        .write_action_count = 1
    };
    channel_write_results[0] = LIBSSH2_ERROR_EAGAIN;
    channel_write_results[1] = LIBSSH2_ERROR_EAGAIN;
    channel_write_results[2] = 3;
    channel_write_results[3] = 3;
    channel_write_result_count = 4;
    channel_write_result_index = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(outersshpriv_reactor_output_buffer_append(&state.exec_input, "def", 3) == 0);

    assert(outersshpriv_reactor_begin_key_exchange(&reactor) == 0);
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(!reactor.read_socket_source_is_resumed);
    assert(reactor.write_socket_source_is_resumed);
    key_exchange_socket_became_writable(&reactor);
    assert(channel_write_result_index == 2 && action.must_resume);
    assert(reactor.key_exchange_waiting_for_write);
    assert(reactor.write_socket_source_is_resumed);
    assert(!reactor.read_socket_source_is_resumed);
    key_exchange_socket_became_writable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_write_result_index == 3);
    assert(!action.must_resume);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&state.exec_input) == 3);
    key_exchange_socket_became_writable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_write_result_index == 3);

    assert(!reactor.key_exchange_waiting_for_write);
    assert(reactor.key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    reactor.key_exchange.step = OLIBSSH_KEY_EXCHANGE_COMPLETE;
    key_exchange_socket_became_writable(&reactor);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_write_result_index == 4);
    outersshpriv_reactor_output_buffer_deinitialize(&state.exec_input);
}

static void test_rekey_pending_protocol_response(LIBSSH2_SESSION *session, int result)
{
    SSHReactor reactor = {.started = true, .session = session};
    const unsigned char response = 0xaa;
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    blocked_write_packet = NULL;
    transport_start_count = transport_resume_count = 0;
    write_result_index = 0;
    write_result_count = 3;
    write_results[0] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    write_results[1] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    write_results[2] = (ScriptedResult){result};
    process_writes(&reactor);
    assert(reactor.write_action_count == 2 && outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);
    assert(outersshpriv_reactor_begin_key_exchange(&reactor) == 0);
    key_exchange_socket_became_writable(&reactor);
    assert(reactor.key_exchange_waiting_for_write && reactor.write_socket_source_is_resumed);
    assert(write_result_index == 2 && reactor.write_action_count == 2);
    key_exchange_socket_became_writable(&reactor);
    assert(transport_start_count == 1 && transport_resume_count == 2);
    assert(write_result_index == 3);
    if (result == 0) {
        assert(outersshpriv_reactor_accepts_work(&reactor));
        assert(!reactor.key_exchange_waiting_for_write);
        assert(reactor.key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
        assert(reactor.write_action_count == 1);
        assert(!outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);
    } else {
        assert(reactor.lifecycle == SSH_REACTOR_LIFECYCLE_FAILED);
        assert(read_failure == result && failure_operation == SSH_REACTOR_OPERATION_WRITE);
        assert(reactor.key_exchange.step == OLIBSSH_KEY_EXCHANGE_IDLE);
    }
    while (reactor.write_action_count != 0) {
        outersshpriv_reactor_pop_write_action(&reactor);
    }
    free(reactor.write_actions);
}

static void test_remote_close_during_write(
    LIBSSH2_SESSION *session, SSHWriteActionType type)
{
    SSHReactor reactor = {
        .session = session,
        .channels = calloc(1, sizeof(*reactor.channels)),
        .channel_capacity = 1
    };
    assert(reactor.channels);
    SSHChannelState *state = &reactor.channels[0];
    state->in_use = true; state->remote_id = 2; state->send_window = 2097152; state->send_packet_size = 32768; state->receive_window = 2097152; state->receive_packet_size = 32768;
    state->purpose = SSH_CHANNEL_PURPOSE_EXEC;
    state->owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND;
    state->has_transmitted_data = true;
    assert(outersshpriv_reactor_output_buffer_append(&state->exec_input, "abc", 3) == 0);
    assert(outersshpriv_reactor_append_write_action(&reactor,
        (SSHWriteAction){.type = type}, false) == 0);
    channel_write_results[0] = LIBSSH2_ERROR_EAGAIN;
    channel_write_results[1] = 3;
    channel_write_result_count = 2;
    channel_write_result_index = 0;
    channel_close_result = LIBSSH2_ERROR_EAGAIN;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);

    read_results[0] = (ScriptedResult){0};
    read_result_count = 1;
    read_result_index = 0;
    scripted_read_events[0] = (TestPacket){
        .type = TEST_PACKET_CHANNEL_CLOSE,
        .channel_id = 0
    };
    reactor.started = true;
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    ssh_socket_became_readable(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(state->remote_closed && state->is_closing);
    assert(state->in_use);
    assert(outersshpriv_reactor_buffer_pending_byte_count(&state->exec_input) == 3);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->type == type);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);
    assert(reactor.write_action_count == (type == SSH_WRITE_CHANNEL_DATA ? 2 : 1));

    if(type == SSH_WRITE_CHANNEL_DATA) {
        process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
        assert(channel_write_result_index == 2);
        assert(memcmp(channel_write_buffer_contents[1], "abc", 3) == 0);
        assert(state->in_use);
    }
    channel_close_result = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(!state->in_use);
    assert(reactor.write_action_count == 0);
    channel_close_result = LIBSSH2_ERROR_EAGAIN;
    free(reactor.channels);
    free(reactor.write_actions);
}

static void test_validation_policy(void)
{
    SSHChannelState state = {0};
    SSHReactor reactor = {.channels = &state, .channel_capacity = 1};
    const struct {
        SSHWriteActionType type;
        bool needs_validation;
    } cases[] = {
        {SSH_WRITE_CHANNEL_DATA, true},
        {SSH_WRITE_CHANNEL_WINDOW_ADJUST, false},
        {SSH_WRITE_CHANNEL_EOF, true},
        {SSH_WRITE_CHANNEL_CLOSE, false},
        {SSH_WRITE_CHANNEL_OPEN, true},
        {SSH_WRITE_CHANNEL_EXEC, true},
        {SSH_WRITE_KEEPALIVE, false},
        {SSH_WRITE_PROTOCOL_RESPONSE, false}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        SSHWriteAction action = {.type = cases[i].type};
        assert(write_action_starts_channel_activity(&reactor, &action) == cases[i].needs_validation);
        action.must_resume = true;
        assert(!write_action_starts_channel_activity(&reactor, &action));
    }
    SSHWriteAction data = {.type = SSH_WRITE_CHANNEL_DATA};
    state.has_transmitted_data = true;
    assert(!write_action_starts_channel_activity(&reactor, &data));
    state.has_transmitted_data = false;
    state.received_eof = true;
    assert(!write_action_starts_channel_activity(&reactor, &data));
    state.received_eof = false;
    state.is_closing = true;
    assert(!write_action_starts_channel_activity(&reactor, &data));
}

static void receive_validation_reply(SSHReactor *reactor)
{
    scripted_read_events[0] = (TestPacket){.type = TEST_PACKET_GLOBAL_REQUEST_RESPONSE};
    read_results[0] = (ScriptedResult){0};
    read_result_count = 1;
    read_result_index = 0;
    ssh_socket_became_readable(reactor);
    assert(outersshpriv_reactor_accepts_work(reactor));
    assert(!reactor->has_pending_global_request);
}

static void test_established_channel_validation(LIBSSH2_SESSION *session)
{
    SSHChannelState state = {
        .in_use = true, .remote_id = 2,
        .send_window = 2097152, .send_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND,
        .has_transmitted_data = true, .consumed_byte_count = 64
    };
    SSHReactor reactor = {
        .started = true, .session = session,
        .channels = &state, .channel_capacity = 1,
        .last_server_activity_nanoseconds = outersshpriv_reactor_monotonic_time_nanoseconds()
    };
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    channel_write_result_count = 4;
    channel_write_result_index = 0;
    for (size_t i = 0; i < 4; i++) channel_write_results[i] = 3;
    write_results[0] = (ScriptedResult){0};
    write_result_count = 1;
    write_result_index = 0;
    ping_write_call_count = keepalive_timeout_count = 0;

    for (size_t i = 0; i < 4; i++) {
        if (i == 1) test_time_seconds += 61;
        if (i == 3) receive_validation_reply(&reactor);
        size_t previous_ping_count = ping_write_call_count;
        process_writes(&reactor);
        assert(ping_write_call_count == previous_ping_count);
        assert(!reactor.write_socket_source_is_resumed);

        assert(outersshpriv_reactor_output_buffer_append(&state.exec_input, "abc", 3) == 0);
        assert(outersshpriv_reactor_enqueue_channel_data(&reactor, 0) == 0);
        process_writes(&reactor);
        assert(outersshpriv_reactor_accepts_work(&reactor));
        assert(channel_write_result_index == i + 1);
        assert(memcmp(channel_write_buffer_contents[i], "abc", 3) == 0);
        assert(reactor.write_action_count == 0);
        assert(ping_write_call_count == (i == 0 ? 0 : 1));
        assert(keepalive_timeout_count == (i == 0 ? 0 : 1));
        assert(reactor.keepalive_pending == (i == 1 || i == 2));
        assert(!outersshpriv_reactor_channel_lifecycle_allows_reassignment(&state));
    }
    outersshpriv_reactor_output_buffer_deinitialize(&state.exec_input);
    free(reactor.write_actions);
    test_time_seconds = 10;
}

static void test_interrupted_write_after_inactivity(LIBSSH2_SESSION *session)
{
    SSHChannelState state = {
        .in_use = true, .remote_id = 2,
        .send_window = 2097152, .send_packet_size = 32768,
        .purpose = SSH_CHANNEL_PURPOSE_EXEC, .has_transmitted_data = true,
        .owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND
    };
    SSHReactor reactor = {
        .session = session, .channels = &state, .channel_capacity = 1,
        .last_server_activity_nanoseconds = outersshpriv_reactor_monotonic_time_nanoseconds()
    };
    assert(outersshpriv_reactor_output_buffer_append(&state.exec_input, "abc", 3) == 0);
    assert(outersshpriv_reactor_enqueue_channel_data(&reactor, 0) == 0);
    channel_write_results[0] = LIBSSH2_ERROR_EAGAIN;
    channel_write_results[1] = 3;
    channel_write_result_count = 2;
    channel_write_result_index = 0;
    ping_write_call_count = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);
    test_time_seconds += 61;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(reactor.write_action_count == 0);
    assert(channel_write_result_index == 2);
    assert(ping_write_call_count == 0);
    outersshpriv_reactor_output_buffer_deinitialize(&state.exec_input);
    free(reactor.write_actions);
    test_time_seconds = 10;
}

static void test_validation_allows_other_channels(LIBSSH2_SESSION *session)
{
    SSHReactor reactor = {
        .started = true, .session = session,
        .channels = calloc(4, sizeof(*reactor.channels)),
        .channel_capacity = 4,
        .write_actions = calloc(16, sizeof(*reactor.write_actions)),
        .write_action_capacity = 16,
        .write_action_head = 13,
        .has_pending_global_request = true
    };
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    assert(reactor.channels && reactor.write_actions);
    for (size_t i = 0; i < 4; i++) {
        reactor.channels[i].in_use = true;
        reactor.channels[i].remote_id = (uint32_t)i + 2;
        reactor.channels[i].send_window = 2097152;
        reactor.channels[i].send_packet_size = 32768;
        reactor.channels[i].receive_window = 2097152;
        reactor.channels[i].receive_packet_size = 32768;
        reactor.channels[i].purpose = SSH_CHANNEL_PURPOSE_EXEC;
        reactor.channels[i].owner.type = SSH_REACTOR_CHANNEL_OWNER_COMMAND;
        reactor.channels[i].owner.command.command = (SSHReactorCommand *)(uintptr_t)3;
    }
    reactor.channels[1].has_transmitted_data = true;
    reactor.channels[1].consumed_byte_count = 64;
    reactor.channels[2].is_closing = true;
    assert(outersshpriv_reactor_output_buffer_append(&reactor.channels[0].exec_input, "new", 3) == 0);
    assert(outersshpriv_reactor_output_buffer_append(&reactor.channels[1].exec_input, "old", 3) == 0);
    SSHWriteAction actions[] = {
        {.type = SSH_WRITE_CHANNEL_EXEC, .token = 0,
         .payload.exec = {.command = strdup("cat"), .command_length = 3}},
        {.type = SSH_WRITE_CHANNEL_DATA, .token = 0},
        {.type = SSH_WRITE_CHANNEL_EOF, .token = 0},
        {.type = SSH_WRITE_CHANNEL_OPEN, .token = 3},
        {.type = SSH_WRITE_CHANNEL_CLOSE, .token = 3},
        {.type = SSH_WRITE_CHANNEL_DATA, .token = 1},
        {.type = SSH_WRITE_CHANNEL_WINDOW_ADJUST, .token = 1},
        {.type = SSH_WRITE_CHANNEL_EOF, .token = 1},
        {.type = SSH_WRITE_CHANNEL_CLOSE, .token = 2}
    };
    assert(actions[0].payload.exec.command);
    for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
        outersshpriv_reactor_append_reserved_write_action(&reactor, actions[i], false);
    }
    const unsigned char response = 0xbb;
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    channel_write_results[0] = LIBSSH2_ERROR_EAGAIN;
    channel_write_results[1] = 3;
    channel_write_results[2] = 3;
    channel_write_result_count = 3;
    channel_write_result_index = 0;
    write_results[0] = (ScriptedResult){0};
    write_result_count = 1;
    write_result_index = 0;
    blocked_write_packet = NULL;
    channel_close_result = 0;
    channel_close_call_count = channel_send_eof_call_count = 0;
    channel_open_call_count = channel_exec_call_count = window_adjust_call_count = 0;
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.write_socket_source_is_resumed);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->token == 1);
    assert(outersshpriv_reactor_write_action_at(&reactor, 0)->must_resume);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(reactor.has_pending_global_request);
    assert(channel_write_result_index == 2);
    assert(channel_write_channels[0] == reactor.channels[1].remote_id);
    assert(channel_write_channels[1] == reactor.channels[1].remote_id);
    assert(window_adjust_call_count == 1 && channel_send_eof_call_count == 1);
    assert(channel_close_call_count == 1);
    assert(channel_open_call_count == 0 && channel_exec_call_count == 0);
    assert(write_result_index == 1);
    assert(reactor.write_action_count == 5);
    for (size_t i = 0; i < 5; i++) {
        assert(outersshpriv_reactor_write_action_at(&reactor, i)->type == actions[i].type);
        assert(outersshpriv_reactor_write_action_at(&reactor, i)->token == actions[i].token);
    }
    assert(outersshpriv_reactor_buffer_pending_byte_count(&reactor.channels[0].exec_input) == 3);
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(!reactor.write_socket_source_is_resumed);
    assert(reactor.read_socket_source_is_resumed);

    receive_validation_reply(&reactor);
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(reactor.write_socket_source_is_resumed);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(reactor.write_action_count == 0);
    assert(channel_write_result_index == 3);
    assert(channel_write_channels[2] == reactor.channels[0].remote_id);
    assert(channel_open_call_count == 1 && channel_exec_call_count == 1);
    assert(channel_send_eof_call_count == 2 && channel_close_call_count == 2);
    assert(teardown_ssh_channels(&reactor, NULL) == 0);
    channel_close_result = LIBSSH2_ERROR_EAGAIN;
    free(reactor.channels);
    free(reactor.write_actions);
}

static void test_validation_reuses_queued_ping(LIBSSH2_SESSION *session)
{
    test_time_seconds = 120;
    SSHReactor reactor = {.started = true, .session = session};
    outersshpriv_reactor_set_ssh_read_source_resumed(&reactor, true);
    const unsigned char response = 0xaa;
    assert(outersshpriv_reactor_enqueue_protocol_response(&reactor, &response, 1) == 0);
    assert(outersshpriv_reactor_append_write_action(&reactor,
        (SSHWriteAction){.type = SSH_WRITE_CHANNEL_OPEN}, false) == 0);
    write_results[0] = (ScriptedResult){LIBSSH2_ERROR_EAGAIN};
    write_results[1] = (ScriptedResult){0};
    write_results[2] = (ScriptedResult){0};
    write_result_count = 3;
    write_result_index = 0;
    blocked_write_packet = NULL;
    ping_write_call_count = 0;
    channel_open_call_count = 0;
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(enqueue_keepalive(&reactor) == 0);
    assert(outersshpriv_reactor_write_action_at(&reactor, 2)->type == SSH_WRITE_KEEPALIVE);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_open_call_count == 0 && ping_write_call_count == 1);
    assert(reactor.has_pending_global_request);
    assert(reactor.write_action_count == 1);
    assert(enqueue_keepalive(&reactor) == 0);
    assert(ping_write_call_count == 1);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    outersshpriv_reactor_update_channel_write_source(&reactor);
    assert(!reactor.write_socket_source_is_resumed);
    receive_validation_reply(&reactor);
    process_writes(&reactor);
    assert(outersshpriv_reactor_accepts_work(&reactor));
    assert(channel_open_call_count == 1 && reactor.write_action_count == 0);
    free(reactor.write_actions);
    test_time_seconds = 10;
}

static void test_teardown_does_not_send(LIBSSH2_SESSION *session)
{
    SSHReactor reactor = {
        .session = session,
        .channels = calloc(1, sizeof(*reactor.channels)),
        .channel_capacity = 1,
        .write_actions = calloc(1, sizeof(*reactor.write_actions)),
        .write_action_capacity = 1,
        .write_action_count = 1
    };
    assert(reactor.channels != NULL);
    assert(reactor.write_actions != NULL);
    reactor.channels[0].in_use = true;
    reactor.channels[0].remote_id = 4;
    reactor.channels[0].send_window = 2097152;
    reactor.channels[0].send_packet_size = 32768;
    reactor.channels[0].receive_window = 2097152;
    reactor.channels[0].receive_packet_size = 32768;
    reactor.write_actions[0].type = SSH_WRITE_PROTOCOL_RESPONSE;
    reactor.write_actions[0].payload.packet.bytes = malloc(1);
    assert(reactor.write_actions[0].payload.packet.bytes != NULL);
    reactor.write_actions[0].payload.packet.length = 1;
    reactor.write_actions[0].must_resume = true;

    channel_close_call_count = 0;
    size_t freed_channel_count = 0;
    assert(teardown_ssh_channels(
               &reactor,
               &freed_channel_count) == 0);
    assert(channel_close_call_count == 0);
    assert(freed_channel_count == 1);
    assert(reactor.write_action_count == 0);
    assert(outersshpriv_reactor_const_write_action_at(&reactor, 0) == NULL);
    free(reactor.channels);
    free(reactor.write_actions);
}

void outersshpriv_handshake_keys_exchanged(SSHReactor *reactor) { (void)reactor; abort(); }
void outersshpriv_handshake_failed(SSHReactor *reactor, int error) { (void)reactor; (void)error; abort(); }

void outersshpriv_authentication_failed(SSHReactor *reactor, int error) { (void)reactor; (void)error; abort(); }

static void test_authentication_packet_before_key_exchange(LIBSSH2_SESSION *session)
{
    unsigned char packet = 50;
    SSHReactor reactor = {.started = true, .session = session,
        .phase = SSH_REACTOR_PHASE_AUTHENTICATION,
        .startup.authentication = {.packet = &packet, .packet_write_pending = true},
        .key_exchange_waiting_for_write = true,
        .key_exchange_in_progress = true, .write_socket_source_is_resumed = true};
    authentication_resume_count = 0;
    authentication_resume_result = LIBSSH2_ERROR_EAGAIN;
    key_exchange_socket_became_writable(&reactor);
    assert(authentication_resume_count == 1 && reactor.key_exchange_waiting_for_write);
    assert(reactor.write_socket_source_is_resumed && !reactor.read_socket_source_is_resumed);
    authentication_resume_result = 0;
    key_exchange_socket_became_writable(&reactor);
    assert(authentication_resume_count == 2 && !reactor.key_exchange_waiting_for_write);
    assert(reactor.startup.authentication.packet == NULL);
    assert(reactor.key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
}

int main(void)
{
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION *)(uintptr_t)1;
    test_authentication_packet_before_key_exchange(session);
    test_socket_source_state(session);
    test_writable_source_validation(session);
    test_read_eagain_does_not_block_writes(session);
    test_explicit_key_exchange_readiness(session);
    test_write_owner(session);
    test_server_channel_open_rejection(session);
    test_channel_write_retry_survives_output_buffer_relocation();
    test_channel_write_respects_packet_and_window_limits();
    test_borrowed_exec_input_sends_both_segments_in_place();
    test_receive_window_credit_during_partial_write();
    test_window_blocked_channel_yields_and_resumes();
    test_relay_buffer_wraps();
    test_unattached_data_transfer(session);
    test_rekey_waits_for_only_the_incomplete_packet(session);
    test_rekey_pending_protocol_response(session, 0);
    test_rekey_pending_protocol_response(session, LIBSSH2_ERROR_SOCKET_SEND);
    test_remote_close_during_write(session, SSH_WRITE_CHANNEL_DATA);
    test_remote_close_during_write(session, SSH_WRITE_CHANNEL_CLOSE);
    test_validation_policy();
    test_established_channel_validation(session);
    test_interrupted_write_after_inactivity(session);
    test_validation_allows_other_channels(session);
    test_validation_reuses_queued_ping(session);
    test_teardown_does_not_send(session);
    test_read_data_delivery(session);
    test_unattached_read_data(session);
    test_read_channel_lifecycle(session);
    test_read_open_confirmations_and_buffered_data(session);
    test_read_command_and_eof(session);
    test_write_drain_notifications(session, SSH_REACTOR_CHANNEL_OWNER_RELAY);
    test_write_drain_notifications(session, SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE);
    test_bridge_write_notification_relocates_arrays(session);
    test_write_exec_notifications(session, 0, false);
    test_write_exec_notifications(session, LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED, false);
    test_write_exec_notifications(session, 0, true);
    test_write_exec_notifications(session, LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED, true);
    test_write_close_notification_stops_reactor(session);
    test_keepalive_write_notification(session, false);
    test_keepalive_write_notification(session, true);
    test_write_failure_classification(session, false);
    test_write_failure_classification(session, true);
    return 0;
}
