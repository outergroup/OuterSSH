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

static const uint64_t ValidationIntervalNanoseconds = 60 * NSEC_PER_SEC;
static const uint64_t DefaultKeepaliveTimeoutMilliseconds = 5000;
static const uint64_t ExecExitCloseGraceMilliseconds = 5000;

#define SSH_CHANNEL_WRITE_CHUNK_CAPACITY 32700

enum {
    SSH_PACKET_GLOBAL_REQUEST = 80,
    SSH_PACKET_CHANNEL_OPEN = 90,
    SSH_PACKET_CHANNEL_WINDOW_ADJUST = 93,
    SSH_PACKET_CHANNEL_DATA = 94,
    SSH_PACKET_CHANNEL_EOF = 96,
    SSH_PACKET_CHANNEL_CLOSE = 97,
    SSH_PACKET_CHANNEL_REQUEST = 98,
    SSH_PACKET_CHANNEL_FAILURE = 100
};

static void ssh_socket_became_readable(void *context);
static void ssh_socket_became_writable(void *context);
static int
enqueue_keepalive(SSHReactor *reactor);
static void clear_keepalive(
    SSHReactor *reactor);
static int complete_pending_channel_open(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason);
static int schedule_command_exit_close(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token);
static int complete_channel_close(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token);
static void free_channel(SSHReactor *reactor, SSHReactorChannelToken token);
static void
clear_channel(SSHReactor *reactor, SSHReactorChannelToken token);
static void ssh_socket_source_cancelled_context(void *context);
static void
dispose_ssh_transport(SSHReactor *reactor);

#pragma mark - Create and Start the Reactor

static void start_reactor_on_queue(void *context);

#if !defined(SSH_REACTOR_TESTS)

typedef struct {
    otqueue_t reply_queue;
    otqueue_t reactor_queue;
    otsocket_t socket;
    LIBSSH2_SESSION *session;
    void (*created)(void *context, SSHReactor *reactor);
    void *context;
    SSHReactor *reactor;
} SSHReactorCreation;

static void construct_reactor_on_queue(void *context);
static void deliver_created_reactor(void *context);
static SSHReactor *construct_reactor(otqueue_t queue, otsocket_t socket, LIBSSH2_SESSION *session);

bool outersshpriv_reactor_create(otqueue_t queue, otsocket_t socket, LIBSSH2_SESSION *session,
    void (*created)(void *context, SSHReactor *reactor), void *context)
{
    SSHReactorCreation *creation = malloc(sizeof(*creation));
    otqueue_t reactor_queue = creation == NULL ? NULL : otqueue_create(queue, "org.outerssh.SSHReactor");
    if (reactor_queue == NULL) {
        free(creation);
        otsocket_close(socket);
        return false;
    }
    otqueue_retain(queue);
    *creation = (SSHReactorCreation){
        .reply_queue = queue, .reactor_queue = reactor_queue, .socket = socket, .session = session,
        .created = created, .context = context,
    };
    otqueue_async(reactor_queue, creation, construct_reactor_on_queue);
    return true;
}

/* Sources are created from work on their own queue, so the reactor is built there. */
static void construct_reactor_on_queue(void *context)
{
    SSHReactorCreation *creation = context;
    creation->reactor = construct_reactor(creation->reactor_queue, creation->socket, creation->session);
    otqueue_async(creation->reply_queue, creation, deliver_created_reactor);
}

static void deliver_created_reactor(void *context)
{
    SSHReactorCreation *creation = context;
    otqueue_t reply_queue = creation->reply_queue;
    creation->created(creation->context, creation->reactor);
    free(creation);
    otqueue_release(reply_queue);
}

/* Takes ownership of queue's reference, including on failure. */
static SSHReactor *construct_reactor(otqueue_t queue, otsocket_t socket, LIBSSH2_SESSION *session)
{
    SSHReactor *reactor = calloc(1, sizeof(*reactor));
    if (reactor == NULL) {
        otqueue_release(queue);
        otsocket_close(socket);
        return NULL;
    }
    reactor->socket = -1;
    atomic_init(&reactor->session_failed, false);

    reactor->session = session;
    reactor->last_server_activity_nanoseconds = outersshpriv_reactor_monotonic_time_nanoseconds();
    reactor->queue = queue;
    otqueue_set_specific(reactor->queue, reactor, reactor);

    reactor->read_socket_source = otsource_create(
        OTSOURCE_TYPE_READ,
        (uintptr_t)socket,
        reactor->queue);
    if (reactor->read_socket_source == NULL) {
        otqueue_release(reactor->queue);
        reactor->queue = NULL;
        dispose_ssh_transport(reactor);
        reactor->session = NULL;
        otsocket_close(socket);
        free(reactor);
        return NULL;
    }
    reactor->socket = socket;
    reactor->uncancelled_socket_source_count = 1;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(reactor->read_socket_source, reactor);
    otsource_set_cancel_handler(
        reactor->read_socket_source,
        ssh_socket_source_cancelled_context);

    reactor->write_socket_source = otsource_create(
        OTSOURCE_TYPE_WRITE,
        (uintptr_t)socket,
        reactor->queue);
    if (reactor->write_socket_source == NULL) {
        dispose_ssh_transport(reactor);
        reactor->session = NULL;
        reactor->lifecycle = SSH_REACTOR_LIFECYCLE_DESTROY_WAITING;
        otsource_t read_socket_source =
            reactor->read_socket_source;
        reactor->read_socket_source = NULL;
        otsource_activate(read_socket_source);
        outersshpriv_reactor_cancel_source(read_socket_source);
        return NULL;
    }
    reactor->uncancelled_socket_source_count += 1;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(reactor->write_socket_source, reactor);
    otsource_set_cancel_handler(
        reactor->write_socket_source,
        ssh_socket_source_cancelled_context);

    return reactor;
}

void outersshpriv_reactor_start(SSHReactor *reactor)
{
    otqueue_async(reactor->queue, reactor, start_reactor_on_queue);
}

static void start_reactor_on_queue(void *context)
{
    SSHReactor *reactor = context;
    if (reactor->started ||
        reactor->lifecycle >= SSH_REACTOR_LIFECYCLE_INVALIDATED) {
        return;
    }
    reactor->phase = SSH_REACTOR_PHASE_CHANNELS;
    reactor->started = true;
    SSH_LOG_INFO(SSH_LOG_CATEGORY_SESSION, "Started SSH reactor");
    if (reactor->key_exchange_in_progress) {
        outersshpriv_reactor_resume_key_exchange(reactor);
        return;
    }
    outersshpriv_reactor_resume_channels_after_key_exchange(reactor);
}

void outersshpriv_reactor_set_session_pool(
    SSHReactor *reactor,
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle session)
{
    reactor->session_pool = pool;
    reactor->session_pool_handle = session;
}

OuterSSHSessionPool *outersshpriv_detach_reactor_from_session_pool(
    SSHReactor *reactor)
{
    outersshpriv_reactor_assert_queue(reactor);
    OuterSSHSessionPool *pool = reactor->session_pool;
    reactor->session_pool = NULL;
    reactor->session_pool_handle = (SSHSessionPoolSessionHandle){0};
    return pool;
}

otqueue_t outersshpriv_reactor_queue(SSHReactor *reactor)
{
    return reactor != NULL ? reactor->queue : NULL;
}

bool outersshpriv_reactor_is_current_queue(SSHReactor *reactor)
{
    return reactor != NULL && otqueue_get_specific(reactor) == reactor;
}

bool outersshpriv_reactor_session_has_failed(SSHReactor *reactor)
{
    return atomic_load_explicit(
        &reactor->session_failed,
        memory_order_acquire);
}

void outersshpriv_reactor_assert_queue(SSHReactor *reactor)
{
    otqueue_assert(reactor->queue);
}

bool outersshpriv_reactor_accepts_work(SSHReactor *reactor)
{
    return reactor->lifecycle == SSH_REACTOR_LIFECYCLE_ACTIVE &&
        reactor->session != NULL;
}

bool outersshpriv_reactor_configure_nonblocking_stream_socket(otsocket_t socket)
{
    if (otsocket_set_nonblocking(socket, true) != 0) {
        return false;
    }
    if (otsocket_prevent_inheritance(socket) != 0) {
        return false;
    }
#ifdef SO_NOSIGPIPE
    int no_sigpipe = 1;
    (void)otsocket_setsockopt(socket,
                     SOL_SOCKET,
                     SO_NOSIGPIPE,
                     &no_sigpipe,
                     sizeof(no_sigpipe));
#endif
    return true;
}

#endif

#pragma mark - Process SSH Socket Readiness

static int deliver_channel_data(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    uint32_t stream_id,
    const unsigned char *bytes,
    size_t byte_count);
static int
append_unattached_remote_bytes(SSHChannelState *state,
                               const void *bytes,
                               size_t byte_count);
static void process_writes(SSHReactor *reactor);
static bool complete_packet_write(SSHReactor *reactor, SSHWriteAction *action, int result);
static size_t
next_safely_runnable_write_offset(const SSHReactor *reactor);
static bool
write_action_starts_channel_activity(
    const SSHReactor *reactor,
    const SSHWriteAction *action);

#if !defined(SSH_REACTOR_TESTS)

void outersshpriv_reactor_resume_channels_after_key_exchange(SSHReactor *reactor)
{
    otsource_set_event_handler(reactor->read_socket_source,
        ssh_socket_became_readable);
    otsource_set_event_handler(reactor->write_socket_source,
        ssh_socket_became_writable);
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
    outersshpriv_reactor_update_channel_write_source(reactor);
    ssh_socket_became_readable(reactor);
}

#endif

static void ssh_socket_became_readable(void *context)
{
    SSHReactor *reactor = context;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_SESSION,
        "SSH socket became readable");

    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor)) {
        return;
    }

    if (!reactor->read_socket_source_is_resumed) {
        return;
    }

    outersshpriv_reactor_read_packets(reactor);
    if (reactor->started && outersshpriv_reactor_accepts_work(reactor)) {
        outersshpriv_reactor_update_channel_write_source(reactor);
    }
}

static void ssh_socket_became_writable(void *context)
{
    SSHReactor *reactor = context;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_SESSION,
        "SSH socket became writable");
    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor) ||
        !reactor->write_socket_source_is_resumed) {
        return;
    }

    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
    process_writes(reactor);
}

void outersshpriv_reactor_read_packets(SSHReactor *reactor)
{
    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor) ||
        !reactor->read_socket_source_is_resumed) {
        return;
    }
    while (true) {
        int transport_result = olibssh_transport_read(reactor->session, reactor);
        if (!outersshpriv_reactor_accepts_work(reactor) ||
            !reactor->started) {
            return;
        }
        if (transport_result < 0 && transport_result != LIBSSH2_ERROR_EAGAIN) {
            SSH_LOG_ERROR(
                SSH_LOG_CATEGORY_SESSION,
                "SSH transport read failed with code %{public}d", transport_result);
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, transport_result);
            return;
        }
        if (transport_result >= 0 &&
            reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT) {
            int error = outersshpriv_reactor_advance_key_exchange(reactor);
            if (error != 0) {
                outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
                return;
            }
        }
        if (!reactor->read_socket_source_is_resumed || transport_result == LIBSSH2_ERROR_EAGAIN) {
            return;
        }
    }
}

static SSHChannelState *channel_for_received_packet(
    SSHReactor *reactor, uint32_t channel_id, bool required)
{
    if (channel_id < reactor->channel_capacity && reactor->channels[channel_id].in_use) {
        return &reactor->channels[channel_id];
    }
    if (required) {
        SSH_LOG_ERROR(SSH_LOG_CATEGORY_CHANNEL,
            "Received packet for unknown channel token=%{public}u", channel_id);
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_PROTO);
    }
    return NULL;
}

void outersshpriv_reactor_received_channel_data(SSHReactor *reactor,
    uint32_t channel_id, uint32_t stream_id,
    const unsigned char *bytes, size_t byte_count)
{
    reactor->last_server_activity_nanoseconds = outersshpriv_reactor_monotonic_time_nanoseconds();
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, false);
    if (channel_state == NULL) {
        return;
    }
    if (byte_count > channel_state->receive_packet_size) {
        byte_count = channel_state->receive_packet_size;
    }
    if (byte_count > channel_state->receive_window) {
        byte_count = channel_state->receive_window;
    }
    channel_state->receive_window -= (uint32_t)byte_count;
    bool has_data_consumer;
    switch (channel_state->purpose) {
    case SSH_CHANNEL_PURPOSE_RELAY:
        has_data_consumer = channel_state->relay != NULL;
        break;
    case SSH_CHANNEL_PURPOSE_EXEC:
        has_data_consumer = channel_state->owner.type == SSH_REACTOR_CHANNEL_OWNER_COMMAND ||
            channel_state->owner.type == SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE;
        break;
    default:
        abort();
    }
    if (byte_count == 0) {
        return;
    }
    SSH_LOG_DEBUG(SSH_LOG_CATEGORY_CHANNEL,
        "Received %{public}zu bytes from SSH channel token=%{public}u stream=%{public}u",
        byte_count, channel_id, stream_id);
    channel_state->has_transmitted_data = true;
    bool buffers_unattached_data = !has_data_consumer && stream_id == 0 &&
        !channel_state->is_closing;
    bool discard_data = !buffers_unattached_data &&
        (!has_data_consumer || channel_state->is_closing ||
         (channel_state->purpose == SSH_CHANNEL_PURPOSE_RELAY && stream_id != 0));
    int error;
    if (buffers_unattached_data) {
        error = append_unattached_remote_bytes(channel_state, bytes, byte_count);
    } else if (discard_data) {
        SSH_LOG_DEBUG(SSH_LOG_CATEGORY_CHANNEL,
            "Discarding %{public}zu bytes from unattached or closing channel token=%{public}u stream=%{public}u",
            byte_count, channel_id, stream_id);
        error = outersshpriv_reactor_consume_channel_bytes(reactor, channel_state, channel_id, byte_count);
    } else {
        error = deliver_channel_data(reactor, channel_id, stream_id, bytes, byte_count);
    }
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

void outersshpriv_reactor_received_channel_eof(SSHReactor *reactor,
    uint32_t channel_id)
{
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, false);
    if (channel_state == NULL) {
        return;
    }
    int error = 0;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Received channel EOF; sent_eof=%{public}s closing=%{public}s token=%{public}llu pointer=%{public}p",
        channel_state->sent_eof ? "true" : "false",
        channel_state->is_closing ? "true" : "false",
        (unsigned long long)channel_id,
        channel_state);
    channel_state->received_eof = true;
    if (channel_state->relay) {
        channel_state->relay->channel_read_open = false;
    }
    if (channel_state->sent_eof) {
        error = outersshpriv_reactor_enqueue_channel_close(
            reactor,
            channel_id);
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
            return;
        }
    }
    if (channel_state->is_closing) {
        return;
    }
    switch (channel_state->owner.type) {
    case SSH_REACTOR_CHANNEL_OWNER_RELAY:
        error = outersshpriv_reactor_receive_relay_eof(
            reactor, channel_state->owner.relay_handle, channel_id);
        break;
    case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
        if (channel_state->owner.command.command == NULL) {
            error = LIBSSH2_ERROR_PROTO;
            break;
        }
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Received EOF from command channel token=%{public}llu",
            (unsigned long long)channel_id);
        break;
    case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
        SSH_LOG_ERROR(
            SSH_LOG_CATEGORY_CHANNEL,
            "outerssh-helper channel reached EOF token=%{public}llu",
            (unsigned long long)channel_id);
        outersshpriv_reactor_fail_socket_bridge_channel(
            reactor,
            channel_state->owner.socket_bridge_handle,
            SSH_REACTOR_SOCKET_BRIDGE_EXITED);
        break;
    case SSH_REACTOR_CHANNEL_OWNER_NONE:
    case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
        break;
    }
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

void outersshpriv_reactor_received_channel_close(SSHReactor *reactor,
    uint32_t channel_id)
{
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, false);
    if (channel_state == NULL) {
        return;
    }
    int error = 0;
    channel_state->remote_closed = true;
    channel_state->received_eof = true;
    if (channel_state->relay) {
        channel_state->relay->channel_read_open = false;
        channel_state->relay->socket_read_open = false;
    }
    if (channel_state->close_sent) {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Remote close received after local close; freeing channel token=%{public}llu pointer=%{public}p",
            (unsigned long long)channel_id,
            channel_state);
        error = complete_channel_close(reactor, channel_id);
    }
    else {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Remote close received before local close; scheduling local close token=%{public}llu pointer=%{public}p",
            (unsigned long long)channel_id,
            channel_state);
        error = outersshpriv_reactor_begin_channel_close(
            reactor,
            channel_state,
            channel_id,
            false);
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
            return;
        }
    }
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

void outersshpriv_reactor_received_channel_window_adjust(SSHReactor *reactor,
    uint32_t channel_id, uint32_t adjustment)
{
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, false);
    if (channel_state == NULL) {
        return;
    }
    if (adjustment > UINT32_MAX - channel_state->send_window) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_PROTO);
        return;
    }
    channel_state->send_window += adjustment;
    int error = 0;
    if (channel_state->is_waiting_for_window) {
        channel_state->is_waiting_for_window = false;

        if (!outersshpriv_reactor_has_write_action(reactor, SSH_WRITE_CHANNEL_DATA,
             channel_id)) {
            SSHWriteAction action = {
                .type = SSH_WRITE_CHANNEL_DATA,
                .token = channel_id
            };
            error = outersshpriv_reactor_append_write_action(reactor, action, false);
        }
    }
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

void outersshpriv_reactor_received_channel_open_confirmation(SSHReactor *reactor,
    uint32_t channel_id, uint32_t remote_id, uint32_t window_size, uint32_t packet_size)
{
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, true);
    if (channel_state == NULL) {
        return;
    }
    if (packet_size == 0 || channel_state->owner.type != SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_PROTO);
        return;
    }
    channel_state->remote_id = remote_id;
    channel_state->send_window = window_size;
    channel_state->send_packet_size = packet_size;
    int error = 0;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Channel open confirmed token=%{public}llu pointer=%{public}p",
        (unsigned long long)channel_id,
        channel_state);
    error = complete_pending_channel_open(
        reactor, channel_id, SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED, 0);
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

void outersshpriv_reactor_received_channel_open_failure(SSHReactor *reactor,
    uint32_t channel_id, uint32_t reason_code)
{
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, true);
    if (channel_state == NULL) {
        return;
    }
    int error = 0;
    SSH_LOG_ERROR(
        SSH_LOG_CATEGORY_CHANNEL,
        "Channel open failed with code %{public}u; freeing token=%{public}llu pointer=%{public}p",
        reason_code,
        (unsigned long long)channel_id,
        channel_state);
    error = complete_pending_channel_open(
        reactor, channel_id, SSH_REACTOR_CHANNEL_OPEN_FAILED,
        reason_code);
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

void outersshpriv_reactor_received_channel_request_success(SSHReactor *reactor,
    uint32_t channel_id)
{
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, true);
    if (channel_state == NULL) {
        return;
    }
    int error = 0;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Channel request succeeded token=%{public}llu pointer=%{public}p",
        (unsigned long long)channel_id,
        channel_state);
    switch (channel_state->owner.type) {
    case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
        if (channel_state->owner.command.command == NULL) {
            error = LIBSSH2_ERROR_PROTO;
            break;
        }
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Command exec request succeeded token=%{public}llu",
            (unsigned long long)channel_id);
        outersshpriv_reactor_command_request_succeeded(channel_state->owner.command.command);
        break;
    case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "outerssh-helper exec request succeeded token=%{public}llu",
            (unsigned long long)channel_id);
        break;
    default:
        error = LIBSSH2_ERROR_PROTO;
        break;
    }
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

void outersshpriv_reactor_received_channel_request_failure(SSHReactor *reactor,
    uint32_t channel_id)
{
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, true);
    if (channel_state == NULL) {
        return;
    }
    int error = 0;
    SSH_LOG_ERROR(
        SSH_LOG_CATEGORY_CHANNEL,
        "Channel request failed token=%{public}llu pointer=%{public}p",
        (unsigned long long)channel_id,
        channel_state);
    if (channel_state->purpose == SSH_CHANNEL_PURPOSE_EXEC) {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Exec request failed; closing channel token=%{public}llu pointer=%{public}p",
            (unsigned long long)channel_id,
            channel_state);
        error = outersshpriv_reactor_begin_channel_close(
            reactor, channel_state, channel_id, false);
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
            return;
        }
    }
    switch (channel_state->owner.type) {
    case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
        if (channel_state->owner.command.command == NULL) {
            error = LIBSSH2_ERROR_PROTO;
            break;
        }
        SSH_LOG_ERROR(
            SSH_LOG_CATEGORY_CHANNEL,
            "Command exec request failed token=%{public}llu",
            (unsigned long long)channel_id);
        outersshpriv_reactor_command_request_failed(channel_state->owner.command.command, LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED);
        break;
    case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
        SSH_LOG_ERROR(
            SSH_LOG_CATEGORY_CHANNEL,
            "outerssh-helper exec request failed token=%{public}llu",
            (unsigned long long)channel_id);
        outersshpriv_reactor_fail_socket_bridge_channel(
            reactor, channel_state->owner.socket_bridge_handle,
            SSH_REACTOR_SOCKET_BRIDGE_REQUEST_DENIED);
        break;
    default:
        error = LIBSSH2_ERROR_PROTO;
        break;
    }
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

void outersshpriv_reactor_received_channel_exit_status(SSHReactor *reactor,
    uint32_t channel_id, uint32_t exit_status)
{
    SSHChannelState *channel_state = channel_for_received_packet(reactor, channel_id, false);
    if (channel_state == NULL) {
        return;
    }
    int error = 0;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Channel reported exit status %{public}u token=%{public}llu pointer=%{public}p",
        exit_status,
        (unsigned long long)channel_id,
        channel_state);
    switch (channel_state->owner.type) {
    case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
        if (channel_state->owner.command.command == NULL) {
            error = LIBSSH2_ERROR_PROTO;
            break;
        }
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Command channel reported exit status %{public}u token=%{public}llu; sending EOF",
            exit_status,
            (unsigned long long)channel_id);
        outersshpriv_reactor_command_received_exit_status(channel_state->owner.command.command, (int32_t)exit_status);
        if (!outersshpriv_reactor_accepts_work(reactor)) {
            return;
        }
        error = outersshpriv_reactor_enqueue_channel_eof(
            reactor, &reactor->channels[channel_id],
            channel_id);
        if (error == 0) {
            error = schedule_command_exit_close(
                reactor, channel_id);
        }
        break;
    case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
        SSH_LOG_ERROR(
            SSH_LOG_CATEGORY_CHANNEL,
            "outerssh-helper exited with status %{public}u token=%{public}llu",
            exit_status,
            (unsigned long long)channel_id);
        outersshpriv_reactor_fail_socket_bridge_channel(
            reactor, channel_state->owner.socket_bridge_handle,
            SSH_REACTOR_SOCKET_BRIDGE_EXITED);
        break;
    default:
        error = LIBSSH2_ERROR_PROTO;
        break;
    }
    if (outersshpriv_reactor_accepts_work(reactor) && error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
    }
}

bool outersshpriv_reactor_reject_channel_request(SSHReactor *reactor, uint32_t channel_id)
{
    SSHChannelState *channel = channel_for_received_packet(reactor, channel_id, false);
    if (channel == NULL) {
        return true;
    }
    unsigned char packet[5] = {SSH_PACKET_CHANNEL_FAILURE};
    uint32_t remote_id = htonl(channel->remote_id);
    memcpy(packet + 1, &remote_id, sizeof(remote_id));
    return outersshpriv_reactor_queue_protocol_response(reactor, packet, sizeof(packet));
}

bool outersshpriv_reactor_queue_protocol_response(SSHReactor *reactor,
    const void *bytes, size_t byte_count)
{
    int error = outersshpriv_reactor_enqueue_protocol_response(reactor, bytes, byte_count);
    if (error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
        return false;
    }
    return true;
}

void outersshpriv_reactor_received_global_response(SSHReactor *reactor, bool succeeded)
{
    reactor->last_server_activity_nanoseconds = outersshpriv_reactor_monotonic_time_nanoseconds();
    SSH_LOG_DEBUG(SSH_LOG_CATEGORY_KEEPALIVE,
        "Received global request response success=%{public}s", succeeded ? "true" : "false");
    reactor->has_pending_global_request = false;
    SSH_LOG_DEBUG(SSH_LOG_CATEGORY_KEEPALIVE,
        "SSH validation succeeded for %{public}s",
        reactor->keepalive_reason != NULL ? reactor->keepalive_reason : "automatic SSH validation");
    clear_keepalive(reactor);
}

#if !defined(SSH_REACTOR_TESTS)

static int deliver_channel_data(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    uint32_t stream_id,
    const unsigned char *bytes,
    size_t byte_count)
{
    SSHReactorChannelOwner *owner = &reactor->channels[channel_token].owner;
    switch (owner->type) {
    case SSH_REACTOR_CHANNEL_OWNER_RELAY: {
        SSHReactorRelayHandle handle = owner->relay_handle;
        RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
        if (relay == NULL || relay->relay == NULL ||
            relay->state.socket_phase != SSH_RELAY_SOCKET_ACTIVE) {
            return LIBSSH2_ERROR_PROTO;
        }
        int result = outersshpriv_reactor_apply_relay_data(reactor, relay, bytes, byte_count);
        if (result == 0) {
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_RELAY,
                "Received %{public}zu bytes from SSH channel for relay index=%{public}zu generation=%{public}llu channel=%{public}llu",
                byte_count,
                handle.index,
                (unsigned long long)handle.generation,
                (unsigned long long)channel_token);
            outersshpriv_reactor_update_relay_write_source(reactor, relay);
        }
        return result;
    }
    case SSH_REACTOR_CHANNEL_OWNER_COMMAND: {
        SSHReactorCommand *command = owner->command.command;
        if (command == NULL) {
            return LIBSSH2_ERROR_PROTO;
        }
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Delivering %{public}zu bytes from command channel token=%{public}llu stream=%{public}u",
            byte_count,
            (unsigned long long)channel_token,
            stream_id);
        outersshpriv_reactor_command_received_data(command, stream_id, bytes, byte_count);
        if (!outersshpriv_reactor_accepts_work(reactor)) {
            return 0;
        }
        return outersshpriv_reactor_consume_channel_bytes(
            reactor,
            &reactor->channels[channel_token],
            channel_token,
            byte_count);
    }
    case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE: {
        SSHReactorSocketBridgeHandle handle = owner->socket_bridge_handle;
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Delivering %{public}zu bytes from outerssh-helper channel token=%{public}llu stream=%{public}u",
            byte_count,
            (unsigned long long)channel_token,
            stream_id);
        outersshpriv_reactor_socket_bridge_receive_channel_data(reactor,
                                           handle,
                                           stream_id,
                                           bytes,
                                           byte_count);
        if (!outersshpriv_reactor_accepts_work(reactor)) {
            return 0;
        }
        SocketBridge *bridge = outersshpriv_reactor_socket_bridge_for_handle(reactor, handle);
        if (stream_id == 0 && bridge != NULL) {
            if (byte_count >
                SIZE_MAX - bridge->uncredited_byte_count) {
                return LIBSSH2_ERROR_ALLOC;
            }
            bridge->uncredited_byte_count += byte_count;
            (void)outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(
                reactor,
                bridge);
            return 0;
        }
        return outersshpriv_reactor_consume_channel_bytes(
            reactor,
            &reactor->channels[channel_token],
            channel_token,
            byte_count);
    }
    case SSH_REACTOR_CHANNEL_OWNER_NONE:
    case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
        return LIBSSH2_ERROR_PROTO;
    }
    abort();
}

#endif

static int
append_unattached_remote_bytes(SSHChannelState *state,
                               const void *bytes,
                               size_t byte_count)
{
    size_t buffered_byte_count = outersshpriv_reactor_buffer_pending_byte_count(
        &state->unattached_remote_buffer);
    if (buffered_byte_count > SSH_READ_BUFFER_CAPACITY ||
       byte_count > SSH_READ_BUFFER_CAPACITY - buffered_byte_count) {
        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
    }
    return outersshpriv_reactor_output_buffer_append(&state->unattached_remote_buffer,
                                bytes,
                                byte_count);
}

int outersshpriv_reactor_consume_channel_bytes(
    SSHReactor *reactor,
    SSHChannelState *state,
    SSHReactorChannelToken token,
    size_t byte_count)
{
    if (byte_count > SIZE_MAX - state->consumed_byte_count) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (state->is_closing) {
        return 0;
    }
    state->consumed_byte_count += byte_count;
    if (state->consumed_byte_count < SSH_READ_BUFFER_CAPACITY / 2) {
        return 0;
    }
    if (outersshpriv_reactor_has_write_action(reactor,
                        SSH_WRITE_CHANNEL_WINDOW_ADJUST,
                        token)) {
        return 0;
    }
    SSHWriteAction action = {
        .type = SSH_WRITE_CHANNEL_WINDOW_ADJUST,
        .token = token
    };
    return outersshpriv_reactor_append_write_action(reactor, action, false);
}

static size_t channel_output_pending(const SSHChannelState *state)
{
    switch (state->purpose) {
    case SSH_CHANNEL_PURPOSE_RELAY:
        return outersshpriv_relay_buffer_pending(&state->relay->to_ssh);
    case SSH_CHANNEL_PURPOSE_EXEC:
        return outersshpriv_reactor_buffer_pending_byte_count(&state->exec_input);
    default:
        abort();
    }
}

static const unsigned char *channel_output_span(const SSHChannelState *state, size_t *length)
{
    switch (state->purpose) {
    case SSH_CHANNEL_PURPOSE_RELAY:
        return outersshpriv_relay_buffer_readable(&state->relay->to_ssh, length);
    case SSH_CHANNEL_PURPOSE_EXEC:
        *length = outersshpriv_reactor_buffer_pending_byte_count(&state->exec_input);
        return state->exec_input.bytes + state->exec_input.offset;
    default:
        abort();
    }
}

static void consume_channel_output(SSHChannelState *state, size_t byte_count)
{
    if (state->purpose == SSH_CHANNEL_PURPOSE_RELAY) {
        outersshpriv_relay_buffer_consume(&state->relay->to_ssh, byte_count);
        return;
    }
    SSHChannelOutputBuffer *input = &state->exec_input;
    input->offset += byte_count;
    if (input->offset != input->byte_count) {
        return;
    }
    input->offset = 0;
    input->byte_count = 0;
    if (state->exec_input_tail_length != 0) {
        state->exec_input = (SSHChannelOutputBuffer){
            .bytes = (unsigned char *)state->exec_input_tail,
            .byte_count = state->exec_input_tail_length,
            .capacity = state->exec_input_tail_length,
        };
        state->exec_input_tail = NULL;
        state->exec_input_tail_length = 0;
    }
}

static void process_writes(SSHReactor *reactor)
{
    if (!outersshpriv_reactor_write_queued_packets(reactor)) {
        return;
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
}

bool outersshpriv_reactor_write_queued_packets(SSHReactor *reactor)
{
    if (!outersshpriv_reactor_accepts_work(reactor)) {
        return false;
    }

    while (reactor->write_action_count != 0) {
        SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, 0);
        if (reactor->has_pending_global_request) {
            size_t offset = next_safely_runnable_write_offset(reactor);
            if (offset == reactor->write_action_count) {
                break;
            }
            if (offset != 0) {
                // An interrupted write must remain at the head of the queue.
                outersshpriv_reactor_move_write_action_to_front(reactor, offset);
            }
        } else if (write_action_starts_channel_activity(reactor, action) ||
                   (action->type == SSH_WRITE_CHANNEL_DATA && !action->must_resume)) {
            uint64_t t = outersshpriv_reactor_monotonic_time_nanoseconds();
            if (t >= reactor->last_server_activity_nanoseconds &&
                t - reactor->last_server_activity_nanoseconds > ValidationIntervalNanoseconds) {
                int error = enqueue_keepalive(reactor);
                if (error != 0) {
                    outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
                    return false;
                }
                SSH_LOG_NOTICE(SSH_LOG_CATEGORY_KEEPALIVE,
                    "Queued automatic SSH validation for outgoing channel activity after inactivity");
                continue;
            }
        }

        int result;
        if (action->must_resume) {
            result = olibssh_transport_resume_write(reactor->session);
        } else {
            switch (action->type) {
            case SSH_WRITE_CHANNEL_DATA: {
                SSHChannelState *state = &reactor->channels[action->token];
                size_t byte_count;
                const unsigned char *bytes = channel_output_span(state, &byte_count);
                if (state->send_window == 0) {
                    state->is_waiting_for_window = true;
                    outersshpriv_reactor_pop_write_action(reactor);
                    continue;
                }
                if (state->sent_eof || state->close_sent || state->send_packet_size == 0) {
                    outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, LIBSSH2_ERROR_PROTO);
                    return false;
                }
                if (byte_count > SSH_CHANNEL_WRITE_CHUNK_CAPACITY) byte_count = SSH_CHANNEL_WRITE_CHUNK_CAPACITY;
                if (byte_count > state->send_window) byte_count = state->send_window;
                if (byte_count > state->send_packet_size) byte_count = state->send_packet_size;
                action->payload.channel_data.byte_count = byte_count;
                unsigned char packet[9] = {SSH_PACKET_CHANNEL_DATA};
                uint32_t fields[] = {htonl(state->remote_id), htonl((uint32_t)byte_count)};
                memcpy(packet + 1, fields, sizeof(fields));
                result = olibssh_transport_write(reactor->session, packet, sizeof(packet),
                    bytes, byte_count);
                break;
            }
            case SSH_WRITE_CHANNEL_WINDOW_ADJUST: {
                SSHChannelState *state = &reactor->channels[action->token];
                size_t byte_count = state->consumed_byte_count < UINT32_MAX
                    ? state->consumed_byte_count : UINT32_MAX;
                if (byte_count == 0 || byte_count > UINT32_MAX - state->receive_window) {
                    outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, LIBSSH2_ERROR_PROTO);
                    return false;
                }
                action->payload.window_adjust.byte_count = byte_count;
                unsigned char packet[9] = {SSH_PACKET_CHANNEL_WINDOW_ADJUST};
                uint32_t fields[] = {htonl(state->remote_id), htonl((uint32_t)byte_count)};
                memcpy(packet + 1, fields, sizeof(fields));
                result = olibssh_transport_write(reactor->session, packet, sizeof(packet), NULL, 0);
                break;
            }
            case SSH_WRITE_CHANNEL_EOF: {
                SSHChannelState *state = &reactor->channels[action->token];
                unsigned char packet[5] = {SSH_PACKET_CHANNEL_EOF};
                uint32_t remote_id = htonl(state->remote_id);
                memcpy(packet + 1, &remote_id, sizeof(remote_id));
                result = olibssh_transport_write(reactor->session, packet, sizeof(packet), NULL, 0);
                break;
            }
            case SSH_WRITE_CHANNEL_CLOSE: {
                SSHChannelState *state = &reactor->channels[action->token];
                unsigned char packet[5] = {SSH_PACKET_CHANNEL_CLOSE};
                uint32_t remote_id = htonl(state->remote_id);
                memcpy(packet + 1, &remote_id, sizeof(remote_id));
                result = olibssh_transport_write(reactor->session, packet, sizeof(packet), NULL, 0);
                break;
            }
            case SSH_WRITE_CHANNEL_OPEN:
            case SSH_WRITE_KEEPALIVE:
            case SSH_WRITE_PROTOCOL_RESPONSE:
                result = olibssh_transport_write(reactor->session, action->payload.packet.bytes,
                    action->payload.packet.length, NULL, 0);
                break;
            case SSH_WRITE_CHANNEL_EXEC: {
                SSHChannelState *state = &reactor->channels[action->token];
                unsigned char packet[18] = {SSH_PACKET_CHANNEL_REQUEST};
                uint32_t fields[] = {htonl(state->remote_id), htonl(4)};
                memcpy(packet + 1, fields, sizeof(fields));
                memcpy(packet + 9, "exec", 4);
                packet[13] = 0; // No reply; command completion arrives through exit-status and close.
                uint32_t command_length = htonl((uint32_t)action->payload.exec.command_length);
                memcpy(packet + 14, &command_length, sizeof(command_length));
                result = olibssh_transport_write(reactor->session, packet, sizeof(packet),
                    (const unsigned char *)action->payload.exec.command, action->payload.exec.command_length);
                break;
            }
            default:
                abort();
            }
        }
        if (result == LIBSSH2_ERROR_EAGAIN) {
            action->must_resume = true;
            if (action->type == SSH_WRITE_CHANNEL_DATA) {
                reactor->channels[action->token].has_transmitted_data = true;
            }
            outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
            return false;
        }
        SSHWriteActionType type = action->type;
        if (!complete_packet_write(reactor, action, result) ||
            !outersshpriv_reactor_accepts_work(reactor)) {
            return false;
        }
        if (type == SSH_WRITE_KEEPALIVE) {
            int error = outersshpriv_reactor_start_keepalive_timeout(reactor);
            if (error != 0) {
                outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_KEEPALIVE, error);
                return false;
            }
        }
    }
    return true;
}

bool outersshpriv_reactor_finish_pending_write(SSHReactor *reactor)
{
    SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, 0);
    assert(action != NULL && action->must_resume);
    int result = olibssh_transport_resume_write(reactor->session);
    if (result == LIBSSH2_ERROR_EAGAIN) {
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
        return false;
    }
    return complete_packet_write(reactor, action, result) &&
        outersshpriv_reactor_accepts_work(reactor);
}

static bool complete_packet_write(SSHReactor *reactor, SSHWriteAction *action, int result)
{
    assert(result != LIBSSH2_ERROR_EAGAIN);
    action->must_resume = false;
    int error = 0;
    SSHReactorOperation failure_operation = SSH_REACTOR_OPERATION_WRITE;
    switch (action->type) {
    case SSH_WRITE_CHANNEL_DATA: {
        SSHReactorChannelToken token = action->token;
        SSHChannelState *state = &reactor->channels[token];
        size_t byte_count = action->payload.channel_data.byte_count;
        if (byte_count > channel_output_pending(state)) {
            outersshpriv_reactor_fail(reactor, failure_operation, LIBSSH2_ERROR_PROTO);
            return false;
        }
        if (result == 0) {
            state->send_window -= (uint32_t)byte_count;
            result = (int)byte_count;
        }
        action->payload.channel_data.byte_count = 0;

        if (result > 0) {
            if ((size_t)result > byte_count) {
                outersshpriv_reactor_fail(reactor, failure_operation, LIBSSH2_ERROR_PROTO);
                return false;
            }
            state->has_transmitted_data = true;
            consume_channel_output(state, (size_t)result);
            SSH_LOG_DEBUG(SSH_LOG_CATEGORY_CHANNEL,
                          "Wrote %{public}d bytes to SSH channel token=%{public}llu pointer=%{public}p",
                          result,
                          (unsigned long long)token,
                          state);
            if (state->is_closing) {
                if (state->purpose == SSH_CHANNEL_PURPOSE_RELAY) {
                    outersshpriv_relay_buffer_clear(&state->relay->to_ssh);
                } else {
                    outersshpriv_reactor_output_buffer_clear(&state->exec_input, true);
                }
                state->exec_input_tail = NULL;
                state->exec_input_tail_length = 0;
                outersshpriv_reactor_pop_write_action(reactor);
                return true;
            }
            if (channel_output_pending(state) > 0) {
                return true;
            }
            outersshpriv_reactor_pop_write_action(reactor);
            if (state->send_eof_after_output_drains) {
                state->send_eof_after_output_drains = false;
                int enqueue_result = outersshpriv_reactor_enqueue_channel_eof(
                    reactor,
                    state,
                    token);
                if (enqueue_result) {
                    outersshpriv_reactor_fail(reactor, failure_operation, enqueue_result);
                    return false;
                }
            }
            SSHReactorChannelOwner *owner =
                &reactor->channels[token].owner;
            switch (owner->type) {
                case SSH_REACTOR_CHANNEL_OWNER_RELAY: {
                    RelaySlot *relay = outersshpriv_reactor_slot_for_handle(
                        reactor,
                        owner->relay_handle);
                    if (relay == NULL) {
                        error = LIBSSH2_ERROR_PROTO;
                    } else {
                        outersshpriv_reactor_update_relay_read_source(reactor, relay);
                    }
                    break;
                }
                case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
                    break;
                case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
                    outersshpriv_reactor_socket_bridge_channel_became_writable(
                        reactor,
                        owner->socket_bridge_handle);
                    break;
                case SSH_REACTOR_CHANNEL_OWNER_NONE:
                case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
                    error = LIBSSH2_ERROR_PROTO;
                    break;
            }
            break;
        } else if (result == 0) {
            state->is_waiting_for_window = true;
            outersshpriv_reactor_pop_write_action(reactor);
            return true;
        } else {
            SSH_LOG_ERROR(SSH_LOG_CATEGORY_CHANNEL,
                          "Channel write failed with code %{public}d; has_transmitted_data=%{public}s token=%{public}llu pointer=%{public}p",
                          result,
                          state->has_transmitted_data ? "true" : "false",
                          (unsigned long long)token,
                          state);
            outersshpriv_reactor_fail(reactor, failure_operation, result);
            return false;
        }
    }

    case SSH_WRITE_CHANNEL_WINDOW_ADJUST: {
        SSHReactorChannelToken token = action->token;
        SSHChannelState *state = &reactor->channels[token];
        size_t byte_count = action->payload.window_adjust.byte_count;

        if (result < 0) {
            SSH_LOG_ERROR(
                SSH_LOG_CATEGORY_CHANNEL,
                "Channel window adjustment failed with code %{public}d token=%{public}llu pointer=%{public}p",
                result,
                (unsigned long long)token,
                state);
            outersshpriv_reactor_fail(reactor, failure_operation, result);
            return false;
        }
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Adjusted SSH channel window by %{public}zu bytes token=%{public}llu pointer=%{public}p",
            byte_count,
            (unsigned long long)token,
            state);
        state->receive_window += (uint32_t)byte_count;
        state->consumed_byte_count -= byte_count;
        outersshpriv_reactor_pop_write_action(reactor);
        result = outersshpriv_reactor_consume_channel_bytes(
            reactor,
            state,
            token,
            0);
        if (result) {
            outersshpriv_reactor_fail(reactor, failure_operation, result);
            return false;
        }
        return true;
    }

    case SSH_WRITE_CHANNEL_EOF: {
        SSHReactorChannelToken token = action->token;
        SSHChannelState *state = &reactor->channels[token];
        if (result >= 0) {
            state->sent_eof = true;
        }

        if (result < 0) {
            SSH_LOG_ERROR(
                SSH_LOG_CATEGORY_CHANNEL,
                "Sending channel EOF failed with code %{public}d; has_transmitted_data=%{public}s token=%{public}llu pointer=%{public}p",
                result,
                state->has_transmitted_data ? "true" : "false",
                (unsigned long long)token,
                state);
            outersshpriv_reactor_fail(reactor, failure_operation, result);
            return false;
        }
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Sent channel EOF result=%{public}d token=%{public}llu pointer=%{public}p",
            result,
            (unsigned long long)token,
            state);
        outersshpriv_reactor_pop_write_action(reactor);
        if (state->received_eof) {
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_CHANNEL,
                "Remote EOF was already received; scheduling channel close token=%{public}llu pointer=%{public}p",
                (unsigned long long)token,
                state);
            result = outersshpriv_reactor_enqueue_channel_close(
                reactor,
                token);
            if (result) {
                outersshpriv_reactor_fail(reactor, failure_operation, result);
                return false;
            }
        }
        return true;
    }

    case SSH_WRITE_CHANNEL_CLOSE: {
        SSHReactorChannelToken token = action->token;
        SSHChannelState *state = &reactor->channels[token];

        if (result < 0) {
            SSH_LOG_ERROR(
                SSH_LOG_CATEGORY_CHANNEL,
                "Closing channel failed with code %{public}d; has_transmitted_data=%{public}s token=%{public}llu pointer=%{public}p",
                result,
                state->has_transmitted_data ? "true" : "false",
                (unsigned long long)token,
                state);
            outersshpriv_reactor_fail(reactor, failure_operation, result);
            return false;
        }
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "channel_close: token=%{public}llu pointer=%{public}p result=%{public}d",
            (unsigned long long)token,
            state,
            result);
        outersshpriv_reactor_pop_write_action(reactor);
        state->close_sent = true;
        if (state->remote_closed) {
            SSHChannelState *channel = state;
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_CHANNEL,
                "Local close completed after remote close; freeing channel token=%{public}llu pointer=%{public}p",
                (unsigned long long)token,
                channel);
            error = complete_channel_close(reactor, token);
            break;
        }
        return true;
    }

    case SSH_WRITE_CHANNEL_OPEN: {
        if (result < 0) {
            SSH_LOG_ERROR(
                          SSH_LOG_CATEGORY_CHANNEL,
                          "Sending channel open failed with code %{public}d token=%{public}llu",
                          result,
                          (unsigned long long)action->token);
            outersshpriv_reactor_fail(reactor, failure_operation, result);
            return false;
        }
        SSH_LOG_DEBUG(
                      SSH_LOG_CATEGORY_CHANNEL,
                      "Sent channel open result=%{public}d token=%{public}llu",
                      result,
                      (unsigned long long)action->token);
        outersshpriv_reactor_pop_write_action(reactor);
        return true;
    }
    case SSH_WRITE_CHANNEL_EXEC: {
        SSHReactorChannelToken token = action->token;
        SSHChannelState *state = &reactor->channels[token];

        if (result < 0) {
            SSH_LOG_ERROR(
                SSH_LOG_CATEGORY_CHANNEL,
                "Starting exec request failed with code %{public}d token=%{public}llu",
                result,
                (unsigned long long)token);
        } else {
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_CHANNEL,
                "Started exec request token=%{public}llu",
                (unsigned long long)token);
        }
        outersshpriv_reactor_pop_write_action(reactor);
        if (result < 0) {
            int close_result = outersshpriv_reactor_begin_channel_close(
                reactor,
                state,
                token,
                false);
            if (close_result) {
                outersshpriv_reactor_fail(reactor, failure_operation, close_result);
                return false;
            }
        }
        SSHReactorChannelOwner *owner = &reactor->channels[token].owner;
        switch (owner->type) {
        case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
            if (result < 0) {
                outersshpriv_reactor_command_request_failed(owner->command.command, result);
            } else {
                outersshpriv_reactor_command_request_succeeded(owner->command.command);
            }
            break;
        case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
            if (result < 0) {
                outersshpriv_reactor_fail_socket_bridge_channel(
                    reactor,
                    owner->socket_bridge_handle,
                    SSH_REACTOR_SOCKET_BRIDGE_REQUEST_DENIED);
            }
            break;
        case SSH_REACTOR_CHANNEL_OWNER_NONE:
        case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
        case SSH_REACTOR_CHANNEL_OWNER_RELAY:
            error = LIBSSH2_ERROR_PROTO;
            break;
        }
        break;
    }

    case SSH_WRITE_KEEPALIVE: {
        if (result < 0) {
            outersshpriv_reactor_fail(reactor, failure_operation, result);
            return false;
        }
        SSH_LOG_NOTICE(
                       SSH_LOG_CATEGORY_KEEPALIVE,
                       "Sent SSH global request ping");
        reactor->has_pending_global_request = true;
        outersshpriv_reactor_pop_write_action(reactor);
        failure_operation = SSH_REACTOR_OPERATION_KEEPALIVE;
        if (!reactor->keepalive_pending) {
            reactor->keepalive_pending = true;
            reactor->keepalive_timeout_milliseconds =
                DefaultKeepaliveTimeoutMilliseconds;
        }
        if (reactor->keepalive_reason == NULL) {
            static const char validation_reason[] = "automatic SSH validation";
            reactor->keepalive_reason_length = sizeof(validation_reason) - 1;
            reactor->keepalive_reason = malloc(sizeof(validation_reason));
            if (reactor->keepalive_reason == NULL) {
                error = LIBSSH2_ERROR_ALLOC;
                break;
            }
            memcpy(reactor->keepalive_reason, validation_reason, sizeof(validation_reason));
        }
        break;
    }
    case SSH_WRITE_PROTOCOL_RESPONSE: {
        if (result < 0) {
            outersshpriv_reactor_fail(reactor, failure_operation, result);
            return false;
        }
        outersshpriv_reactor_pop_write_action(reactor);
        return true;
    }
    }
    if (!outersshpriv_reactor_accepts_work(reactor)) {
        return false;
    }
    if (error != 0) {
        outersshpriv_reactor_fail(reactor, failure_operation, error);
        return false;
    }
    return true;
}

// Keep waiting actions in place until validation completes. Selecting a later
// action may cross other channels, but never an earlier action on its own channel.
// The return value equals write_action_count when nothing can run.
static size_t
next_safely_runnable_write_offset(const SSHReactor *reactor)
{
    for (size_t offset = 0; offset < reactor->write_action_count; offset++) {
        const SSHWriteAction *action = outersshpriv_reactor_const_write_action_at(reactor, offset);
        if (action->must_resume) {
            return offset;
        }
        if (action->type == SSH_WRITE_KEEPALIVE ||
            write_action_starts_channel_activity(reactor, action)) {
            continue;
        }
        if (action->type == SSH_WRITE_PROTOCOL_RESPONSE) {
            return offset;
        }
        bool earlier_channel_action = false;
        for (size_t previous = 0; previous < offset; previous++) {
            const SSHWriteAction *waiting = outersshpriv_reactor_const_write_action_at(reactor, previous);
            if (waiting->type != SSH_WRITE_KEEPALIVE &&
                waiting->type != SSH_WRITE_PROTOCOL_RESPONSE &&
                waiting->token == action->token) {
                earlier_channel_action = true;
                break;
            }
        }
        if (!earlier_channel_action) {
            return offset;
        }
    }
    return reactor->write_action_count;
}

static bool
write_action_starts_channel_activity(
    const SSHReactor *reactor,
    const SSHWriteAction *action)
{
    // New channel activity waits for validation so it can move to another
    // session on failure. Established streams keep flowing while the check
    // is pending; an interrupted packet must always resume without preemption.
    if (action->must_resume) {
        return false;
    }
    switch (action->type) {
    case SSH_WRITE_CHANNEL_OPEN:
    case SSH_WRITE_CHANNEL_EXEC:
        return true;
    case SSH_WRITE_CHANNEL_DATA:
    case SSH_WRITE_CHANNEL_EOF:
        return outersshpriv_reactor_channel_lifecycle_allows_reassignment(
            &reactor->channels[action->token]);
    case SSH_WRITE_CHANNEL_CLOSE:
    case SSH_WRITE_CHANNEL_WINDOW_ADJUST:
    case SSH_WRITE_KEEPALIVE:
    case SSH_WRITE_PROTOCOL_RESPONSE:
        return false;
    }
    abort();
}

void outersshpriv_reactor_set_ssh_read_source_resumed(SSHReactor *reactor, bool resumed)
{
    outersshpriv_reactor_safely_set_source_resumed(
        reactor, reactor->read_socket_source,
        resumed && reactor->started && outersshpriv_reactor_accepts_work(reactor),
        &reactor->read_socket_source_is_resumed);
}

void outersshpriv_reactor_set_ssh_write_source_resumed(SSHReactor *reactor, bool resumed)
{
    outersshpriv_reactor_safely_set_source_resumed(
        reactor, reactor->write_socket_source,
        resumed && reactor->started && outersshpriv_reactor_accepts_work(reactor),
        &reactor->write_socket_source_is_resumed);
}

void outersshpriv_reactor_update_channel_write_source(SSHReactor *reactor)
{
    if (reactor->key_exchange_in_progress) {
        return;
    }
    bool writable = reactor->has_pending_global_request
        ? next_safely_runnable_write_offset(reactor) < reactor->write_action_count
        : reactor->write_action_count > 0;
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, writable);
}

#pragma mark - Validate the Session

static void keepalive_timeout_fired(void *opaque_context);

#if !defined(SSH_REACTOR_TESTS)

int outersshpriv_reactor_send_keepalive(
    SSHReactor *reactor,
    const char *reason,
    size_t reason_length,
    uint64_t timeout_milliseconds)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (!outersshpriv_reactor_accepts_work(reactor) ||
        timeout_milliseconds == 0) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (reactor->keepalive_pending) {
        return 0;
    }

    if (reason == NULL || reason_length == 0) {
        static const char validation_reason[] = "automatic SSH validation";
        reason = validation_reason;
        reason_length = sizeof(validation_reason) - 1;
    }
    if (reason_length > INT_MAX) return LIBSSH2_ERROR_INVAL;
    char *copied_reason = malloc(reason_length + 1);
    if (copied_reason == NULL) return LIBSSH2_ERROR_ALLOC;
    memcpy(copied_reason, reason, reason_length);
    copied_reason[reason_length] = '\0';
    const char *reason_text = copied_reason;
    SSH_LOG_NOTICE(
        SSH_LOG_CATEGORY_KEEPALIVE,
        "Poking SSH session for %{public}s",
        reason_text);
    if (copied_reason == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    int result = enqueue_keepalive(reactor);
    if (result == 0) {
        reactor->keepalive_pending = true;
        reactor->keepalive_reason = copied_reason;
        reactor->keepalive_reason_length = reason_length;
        reactor->keepalive_timeout_milliseconds = timeout_milliseconds;
        outersshpriv_reactor_update_channel_write_source(reactor);
    } else {
        SSH_LOG_ERROR(
            SSH_LOG_CATEGORY_KEEPALIVE,
            "Failed to queue SSH global request ping for %{public}s code=%{public}d",
            reason_text,
            result);
        free(copied_reason);
    }
    return result;
}

#endif

static int
enqueue_keepalive(SSHReactor *reactor)
{
    if (reactor->has_pending_global_request) {
        return 0;
    }
    for (size_t offset = 0; offset < reactor->write_action_count; offset++) {
        SSHWriteAction *queued = outersshpriv_reactor_write_action_at(reactor, offset);
        if (queued->type == SSH_WRITE_KEEPALIVE) {
            if (offset != 0 && !outersshpriv_reactor_write_action_at(reactor, 0)->must_resume) {
                outersshpriv_reactor_move_write_action_to_front(reactor, offset);
            }
            return 0;
        }
    }
    // Uses a non-standard request name that servers will reject, but still respond to.
    static const char request_name[] = "keepalive@outerssh.org";
    size_t packet_length = 1 + 4 + sizeof(request_name) - 1 + 1;
    unsigned char *packet = malloc(packet_length);
    if (packet == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    packet[0] = SSH_PACKET_GLOBAL_REQUEST;
    uint32_t name_length = htonl(sizeof(request_name) - 1);
    memcpy(packet + 1, &name_length, sizeof(name_length));
    memcpy(packet + 5, request_name, sizeof(request_name) - 1);
    packet[packet_length - 1] = 1; // Request a reply
    SSHWriteAction action = {
        .type = SSH_WRITE_KEEPALIVE,
        .payload.packet = {.bytes = packet, .length = packet_length}
    };
    SSHWriteAction *head = outersshpriv_reactor_write_action_at(reactor, 0);
    int append_result = outersshpriv_reactor_append_write_action(
        reactor,
        action,
        head == NULL || !head->must_resume);
    if (append_result) {
        outersshpriv_reactor_destroy_write_action(&action);
    }
    return append_result;
}

#if !defined(SSH_REACTOR_TESTS)

int outersshpriv_reactor_start_keepalive_timeout(
    SSHReactor *reactor)
{
    outersshpriv_reactor_cancel_keepalive_timeout(reactor);

    uint64_t timeout_milliseconds = reactor->keepalive_timeout_milliseconds
        ? reactor->keepalive_timeout_milliseconds
        : DefaultKeepaliveTimeoutMilliseconds;
    if (timeout_milliseconds > INT64_MAX / NSEC_PER_MSEC) {
        return LIBSSH2_ERROR_INVAL;
    }

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
    timer_context->generation = reactor->keepalive_timeout_generation;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(timer, timer_context);
    otsource_set_cancel_handler(timer, outersshpriv_reactor_timer_cancelled);
    reactor->keepalive_timeout_timer = timer;
    otsource_set_event_handler(timer, keepalive_timeout_fired);
    otsource_set_timer(
        timer,
        ottime(
            OTTIME_NOW,
            (int64_t)(timeout_milliseconds * NSEC_PER_MSEC)),
        OTTIME_FOREVER,
        100 * NSEC_PER_MSEC);
    otsource_activate(timer);
    return 0;
}

static void keepalive_timeout_fired(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    SSHReactor *reactor = context->reactor;
    if (reactor->keepalive_timeout_generation != context->generation ||
        reactor->keepalive_timeout_timer != context->source ||
        !reactor->keepalive_pending ||
        reactor->lifecycle >= SSH_REACTOR_LIFECYCLE_INVALIDATED) {
        return;
    }
    reactor->keepalive_timeout_timer = NULL;
    reactor->keepalive_pending = false;
    reactor->keepalive_timeout_generation += 1;
    outersshpriv_reactor_cancel_source(context->source);
    SSH_LOG_ERROR(
        SSH_LOG_CATEGORY_KEEPALIVE,
        "SSH global request timed out for %{public}s",
        reactor->keepalive_reason != NULL
            ? reactor->keepalive_reason
            : "automatic SSH validation");
    outersshpriv_reactor_fail(
        reactor,
        SSH_REACTOR_OPERATION_KEEPALIVE,
        LIBSSH2_ERROR_TIMEOUT);
}

static void clear_keepalive(
    SSHReactor *reactor)
{
    reactor->keepalive_pending = false;
    outersshpriv_reactor_cancel_keepalive_timeout(reactor);
    free(reactor->keepalive_reason);
    reactor->keepalive_reason = NULL;
}

void outersshpriv_reactor_cancel_keepalive_timeout(
    SSHReactor *reactor)
{
    reactor->keepalive_timeout_generation += 1;
    if (reactor->keepalive_timeout_timer != NULL) {
        outersshpriv_reactor_cancel_source(reactor->keepalive_timeout_timer);
        reactor->keepalive_timeout_timer = NULL;
    }
}


#endif

uint64_t outersshpriv_reactor_monotonic_time_nanoseconds(void)
{
#if defined(_WIN32)
    return ottime(OTTIME_NOW, 0);
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        SSH_LOG_ERROR(SSH_LOG_CATEGORY_SESSION, "Failed to read the monotonic clock");
        abort();
    }
    return (uint64_t)now.tv_sec * NSEC_PER_SEC + (uint64_t)now.tv_nsec;
#endif
}

#pragma mark - Open SSH Channels

static int
start_channel_open(
    SSHReactor *reactor,
    unsigned char *packet, size_t packet_length,
    uint32_t channel_id,
    SSHChannelPurpose purpose,
    SSHReactorChannelToken *channel_token,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open);
static int
register_channel(SSHReactor *reactor,
                 SSHReactorChannelToken token,
                 SSHChannelPurpose purpose);
static int
ensure_channel_capacity(SSHReactor *reactor, SSHReactorChannelToken token);
static int register_pending_channel_open(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open);
static void pending_channel_open_timed_out(void *opaque_context);

#if !defined(SSH_REACTOR_TESTS)

int outersshpriv_reactor_open_tcp_channel(
    SSHReactor *reactor,
    SSHReactorChannelToken *channel_token,
    const char *host,
    size_t host_length,
    int port,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (!outersshpriv_reactor_accepts_work(reactor) || channel_token == NULL ||
        host == NULL || host_length == 0 || host_length > INT_MAX ||
        source_host == NULL || source_host_length > INT_MAX ||
        timeout_milliseconds > INT64_MAX / NSEC_PER_MSEC) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (reactor->next_channel_id > UINT32_MAX) {
        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
    }
    uint32_t channel_id = (uint32_t)reactor->next_channel_id;
    static const char channel_type[] = "direct-tcpip";
    size_t packet_length = 17 + sizeof(channel_type) - 1 + host_length + source_host_length + 16;
    unsigned char *packet = malloc(packet_length);
    if (packet == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    packet[0] = SSH_PACKET_CHANNEL_OPEN;
    uint32_t length = htonl(sizeof(channel_type) - 1);
    memcpy(packet + 1, &length, 4);
    memcpy(packet + 5, channel_type, sizeof(channel_type) - 1);
    unsigned char *cursor = packet + 5 + sizeof(channel_type) - 1;
    uint32_t fields[] = {htonl(channel_id), htonl(SSH_READ_BUFFER_CAPACITY),
        htonl(LIBSSH2_CHANNEL_PACKET_DEFAULT)};
    memcpy(cursor, fields, sizeof(fields));
    cursor += sizeof(fields);
    length = htonl((uint32_t)host_length);
    memcpy(cursor, &length, 4); cursor += 4;
    memcpy(cursor, host, host_length); cursor += host_length;
    length = htonl((uint32_t)port);
    memcpy(cursor, &length, 4); cursor += 4;
    length = htonl((uint32_t)source_host_length);
    memcpy(cursor, &length, 4); cursor += 4;
    memcpy(cursor, source_host, source_host_length); cursor += source_host_length;
    length = htonl((uint32_t)source_port);
    memcpy(cursor, &length, 4);
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Opening direct-tcpip channel token=%{public}llu target=%{public}.*s:%{public}d source=%{public}.*s:%{public}d",
        (unsigned long long)channel_id,
        (int)host_length,
        host,
        port,
        (int)source_host_length, source_host,
        source_port);
    return start_channel_open(
        reactor,
        packet, packet_length,
        channel_id,
        SSH_CHANNEL_PURPOSE_RELAY,
        channel_token,
        timeout_milliseconds,
        pending_open);
}

int outersshpriv_reactor_open_streamlocal_channel(
    SSHReactor *reactor,
    SSHReactorChannelToken *channel_token,
    const char *socket_path,
    size_t socket_path_length,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (!outersshpriv_reactor_accepts_work(reactor) || channel_token == NULL ||
        socket_path == NULL || socket_path_length == 0 || socket_path_length > INT_MAX ||
        source_host == NULL || source_host_length > INT_MAX ||
        timeout_milliseconds > INT64_MAX / NSEC_PER_MSEC) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (reactor->next_channel_id > UINT32_MAX) {
        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
    }
    uint32_t channel_id = (uint32_t)reactor->next_channel_id;
    static const char channel_type[] = "direct-streamlocal@openssh.com";
    size_t packet_length = 17 + sizeof(channel_type) - 1 + socket_path_length + source_host_length + 12;
    unsigned char *packet = malloc(packet_length);
    if (packet == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    packet[0] = SSH_PACKET_CHANNEL_OPEN;
    uint32_t length = htonl(sizeof(channel_type) - 1);
    memcpy(packet + 1, &length, 4);
    memcpy(packet + 5, channel_type, sizeof(channel_type) - 1);
    unsigned char *cursor = packet + 5 + sizeof(channel_type) - 1;
    uint32_t fields[] = {htonl(channel_id), htonl(SSH_READ_BUFFER_CAPACITY),
        htonl(LIBSSH2_CHANNEL_PACKET_DEFAULT)};
    memcpy(cursor, fields, sizeof(fields));
    cursor += sizeof(fields);
    length = htonl((uint32_t)socket_path_length);
    memcpy(cursor, &length, 4); cursor += 4;
    memcpy(cursor, socket_path, socket_path_length); cursor += socket_path_length;
    length = htonl((uint32_t)source_host_length);
    memcpy(cursor, &length, 4); cursor += 4;
    memcpy(cursor, source_host, source_host_length); cursor += source_host_length;
    length = htonl((uint32_t)source_port);
    memcpy(cursor, &length, 4);
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Opening direct-streamlocal channel token=%{public}llu path=%{public}.*s source=%{public}.*s:%{public}d",
        (unsigned long long)channel_id,
        (int)socket_path_length,
        socket_path,
        (int)source_host_length, source_host,
        source_port);
    return start_channel_open(
        reactor,
        packet, packet_length,
        channel_id,
        SSH_CHANNEL_PURPOSE_RELAY,
        channel_token,
        timeout_milliseconds,
        pending_open);
}

int outersshpriv_reactor_open_session_channel(
    SSHReactor *reactor,
    SSHReactorChannelToken *channel_token,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (!outersshpriv_reactor_accepts_work(reactor) || channel_token == NULL ||
        timeout_milliseconds > INT64_MAX / NSEC_PER_MSEC) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (reactor->next_channel_id > UINT32_MAX) {
        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
    }
    uint32_t channel_id = (uint32_t)reactor->next_channel_id;
    static const char channel_type[] = "session";
    size_t packet_length = 17 + sizeof(channel_type) - 1;
    unsigned char *packet = malloc(packet_length);
    if (packet == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    packet[0] = SSH_PACKET_CHANNEL_OPEN;
    uint32_t length = htonl(sizeof(channel_type) - 1);
    memcpy(packet + 1, &length, 4);
    memcpy(packet + 5, channel_type, sizeof(channel_type) - 1);
    unsigned char *cursor = packet + 5 + sizeof(channel_type) - 1;
    uint32_t fields[] = {htonl(channel_id), htonl(SSH_READ_BUFFER_CAPACITY),
        htonl(LIBSSH2_CHANNEL_PACKET_DEFAULT)};
    memcpy(cursor, fields, sizeof(fields));
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Opening session channel token=%{public}llu",
        (unsigned long long)channel_id);
    return start_channel_open(
        reactor,
        packet, packet_length,
        channel_id,
        SSH_CHANNEL_PURPOSE_EXEC,
        channel_token,
        timeout_milliseconds,
        pending_open);
}

static int
start_channel_open(
    SSHReactor *reactor,
    unsigned char *packet, size_t packet_length,
    uint32_t channel_id,
    SSHChannelPurpose purpose,
    SSHReactorChannelToken *channel_token,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open)
{
    int result = register_channel(reactor, channel_id, purpose);
    if (result != 0) {
        free(packet);
        return result;
    }

    result = reactor->write_action_count == SIZE_MAX
        ? LIBSSH2_ERROR_ALLOC
        : outersshpriv_reactor_reserve_write_actions(reactor, reactor->write_action_count + 1);
    if (result == 0) {
        result = register_pending_channel_open(
            reactor, channel_id, timeout_milliseconds, pending_open);
    }
    if (result != 0) {
        clear_channel(reactor, channel_id);
        free(packet);
        return result;
    }

    SSHWriteAction action = {
        .type = SSH_WRITE_CHANNEL_OPEN,
        .token = channel_id,
        .payload.packet = {.bytes = packet, .length = packet_length}
    };
    outersshpriv_reactor_append_reserved_write_action(reactor, action, false);
    *channel_token = channel_id;
    reactor->next_channel_id += 1;
    reactor->created_channel_count += 1;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Created channel token=%{public}llu pointer=%{public}p created=%{public}zu freed=%{public}zu live=%{public}zu",
        (unsigned long long)channel_id,
        &reactor->channels[channel_id],
        reactor->created_channel_count,
        reactor->freed_channel_count,
        reactor->created_channel_count - reactor->freed_channel_count);
    outersshpriv_reactor_update_channel_write_source(reactor);
    return 0;
}

#endif

static int
register_channel(SSHReactor *reactor,
                 SSHReactorChannelToken token,
                 SSHChannelPurpose purpose)
{
    if (!reactor) {
        return LIBSSH2_ERROR_INVAL;
    }
    int capacity_result = ensure_channel_capacity(reactor, token);
    if (capacity_result) {
        return capacity_result;
    }
    if (reactor->channels[token].in_use ||
        reactor->channels[token].owner.type != SSH_REACTOR_CHANNEL_OWNER_NONE) {
        return LIBSSH2_ERROR_BAD_USE;
    }
    reactor->channels[token].in_use = true;
    reactor->channels[token].receive_window = SSH_READ_BUFFER_CAPACITY;
    reactor->channels[token].receive_packet_size = LIBSSH2_CHANNEL_PACKET_DEFAULT;
    reactor->channels[token].purpose = purpose;
    return 0;
}

static int
ensure_channel_capacity(SSHReactor *reactor, SSHReactorChannelToken token)
{
    if (token > SIZE_MAX / sizeof(*reactor->channels)) {
        return LIBSSH2_ERROR_ALLOC;
    }
    size_t required_capacity = (size_t)token + 1;
    if (required_capacity <= reactor->channel_capacity) {
        return 0;
    }

    size_t new_capacity = reactor->channel_capacity ? reactor->channel_capacity : 16;
    while (new_capacity < required_capacity) {
        if (new_capacity > SIZE_MAX / 2) {
            new_capacity = required_capacity;
            break;
        }
        new_capacity *= 2;
    }

    SSHChannelState *channels = realloc(
        reactor->channels,
        new_capacity * sizeof(*channels));
    if (!channels) {
        return LIBSSH2_ERROR_ALLOC;
    }
    for (size_t index = reactor->channel_capacity; index < new_capacity; index++) {
        memset((void *)&channels[index], 0, sizeof(channels[index]));
    }
    reactor->channels = channels;
    reactor->channel_capacity = new_capacity;
    return 0;
}

#if !defined(SSH_REACTOR_TESTS)

static int register_pending_channel_open(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open)
{
    SSHReactorChannelOwner *owner =
        &reactor->channels[channel_token].owner;
    if (timeout_milliseconds == 0) {
        owner->type = SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN;
        owner->pending_open = pending_open;
        return 0;
    }
    otsource_t timeout_timer = otsource_create(
        OTSOURCE_TYPE_TIMER,
        0,
        reactor->queue);
    if (timeout_timer == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    SSHReactorSourceContext *timer_context =
        outersshpriv_reactor_create_source_context(reactor, timeout_timer);
    if (timer_context == NULL) {
        otsource_activate(timeout_timer);
        outersshpriv_reactor_cancel_source(timeout_timer);
        return LIBSSH2_ERROR_ALLOC;
    }
    timer_context->channel_token = channel_token;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(timeout_timer, timer_context);
    otsource_set_cancel_handler(
        timeout_timer,
        outersshpriv_reactor_timer_cancelled);
    pending_open.timeout_timer = timeout_timer;
    owner->type = SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN;
    owner->pending_open = pending_open;
    otsource_set_event_handler(
        timeout_timer,
        pending_channel_open_timed_out);
    otsource_set_timer(
        timeout_timer,
        ottime(
            OTTIME_NOW,
            (int64_t)(timeout_milliseconds * NSEC_PER_MSEC)),
        OTTIME_FOREVER,
        100 * NSEC_PER_MSEC);
    otsource_activate(timeout_timer);
    return 0;
}

static int complete_pending_channel_open(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason)
{
    SSHReactorChannelOwner *owner =
        &reactor->channels[channel_token].owner;
    if (owner->type != SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN) {
        return LIBSSH2_ERROR_PROTO;
    }
    SSHReactorPendingChannelOpen pending_open = owner->pending_open;
    if (result == SSH_REACTOR_CHANNEL_OPEN_FAILED) {
        free_channel(reactor, channel_token);
    } else {
        *owner = (SSHReactorChannelOwner){0};
    }
    if (pending_open.timeout_timer != NULL) {
        outersshpriv_reactor_cancel_source(pending_open.timeout_timer);
    }

    if (pending_open.result_delivered) {
        if (result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED) {
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_CHANNEL,
                "Channel opened after its requester timed out; closing token=%{public}llu",
                (unsigned long long)channel_token);
            return outersshpriv_reactor_begin_channel_close(
                reactor,
                &reactor->channels[channel_token],
                channel_token,
                false);
        }
        return 0;
    }
    if (result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED) {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_CHANNEL,
            "Completing channel open token=%{public}llu",
            (unsigned long long)channel_token);
    } else {
        SSH_LOG_ERROR(
            SSH_LOG_CATEGORY_CHANNEL,
            "Completing failed channel open token=%{public}llu code=%{public}u",
            (unsigned long long)channel_token,
            reason);
    }
    pending_open.finished(
        reactor,
        &pending_open,
        channel_token,
        result,
        result == SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED ? 0 : reason);
    return 0;
}

static void pending_channel_open_timed_out(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    SSHReactor *reactor = context->reactor;
    SSHReactorChannelToken channel_token = context->channel_token;
    if (channel_token >= reactor->channel_capacity) {
        return;
    }
    SSHReactorChannelOwner *owner = &reactor->channels[channel_token].owner;
    if (owner->type != SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN) {
        return;
    }
    SSHReactorPendingChannelOpen *pending = &owner->pending_open;
    if (pending->result_delivered ||
        pending->timeout_timer != context->source) {
        return;
    }
    SSHReactorPendingChannelOpen pending_open = *pending;
    *pending = (SSHReactorPendingChannelOpen){
        .result_delivered = true
    };
    outersshpriv_reactor_cancel_source(context->source);
    SSH_LOG_ERROR(
        SSH_LOG_CATEGORY_CHANNEL,
        "Channel open timed out token=%{public}llu",
        (unsigned long long)channel_token);
    pending_open.finished(
        reactor,
        &pending_open,
        channel_token,
        SSH_REACTOR_CHANNEL_OPEN_TIMED_OUT,
        0);
}

#endif

#pragma mark - Execute Commands

static void handle_command_channel_open(
    SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason);
static void command_exit_close_timer_fired(void *opaque_context);
static void clear_command_channel(
    SSHReactorCommandChannel *channel);

#if !defined(SSH_REACTOR_TESTS)

int outersshpriv_reactor_open_command_session(
    SSHReactor *reactor,
    SSHReactorChannelToken *channel_token,
    uint64_t timeout_milliseconds,
    SSHReactorCommand *command)
{
    if (command == NULL) {
        return LIBSSH2_ERROR_INVAL;
    }
    return outersshpriv_reactor_open_session_channel(
        reactor,
        channel_token,
        timeout_milliseconds,
        (SSHReactorPendingChannelOpen){
            .finished = handle_command_channel_open,
            .target.command = command
        });
}

static void handle_command_channel_open(
    SSHReactor *reactor,
    const SSHReactorPendingChannelOpen *pending,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason)
{
    (void)reactor;
    outersshpriv_reactor_command_handle_channel_open(
        pending->target.command, channel_token, result, reason);
}

int outersshpriv_reactor_start_command(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    const char *command,
    size_t command_length,
    const void *input_prefix,
    size_t input_prefix_length,
    const void *input,
    size_t input_length,
    bool send_eof_after_input,
    SSHReactorCommand *command_state)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (!outersshpriv_reactor_accepts_work(reactor) || command_state == NULL) {
        return LIBSSH2_ERROR_INVAL;
    }
    assert(channel_token < reactor->channel_capacity);
    SSHReactorChannelOwner *owner =
        &reactor->channels[channel_token].owner;
    if (owner->type != SSH_REACTOR_CHANNEL_OWNER_NONE) {
        return LIBSSH2_ERROR_BAD_USE;
    }
    int result = outersshpriv_reactor_start_channel_exec_borrowing(
        reactor,
        channel_token,
        command,
        command_length,
        input_prefix,
        input_prefix_length,
        input,
        input_length,
        send_eof_after_input);
    if (result != 0) {
        return result;
    }

    owner->type = SSH_REACTOR_CHANNEL_OWNER_COMMAND;
    SSHReactorCommandChannel *channel = &owner->command;
    channel->command = command_state;
    outersshpriv_reactor_update_channel_write_source(reactor);
    return 0;
}

void outersshpriv_reactor_forget_command_input(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    SSHReactorCommand *command_state)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (channel_token >= reactor->channel_capacity) {
        return;
    }
    SSHChannelState *state = &reactor->channels[channel_token];
    if (!state->in_use || state->purpose != SSH_CHANNEL_PURPOSE_EXEC ||
        state->owner.type != SSH_REACTOR_CHANNEL_OWNER_COMMAND ||
        state->owner.command.command != command_state ||
        !state->exec_input_is_borrowed) {
        return;
    }
    state->exec_input = (SSHChannelOutputBuffer){0};
    state->exec_input_tail = NULL;
    state->exec_input_tail_length = 0;
    size_t kept_count = 0;
    size_t original_count = reactor->write_action_count;
    for (size_t offset = 0; offset < original_count; offset++) {
        SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, offset);
        if (!action->must_resume && action->token == channel_token &&
            action->type == SSH_WRITE_CHANNEL_DATA) {
            outersshpriv_reactor_destroy_write_action(action);
            continue;
        }
        if (kept_count != offset) {
            *outersshpriv_reactor_write_action_at(reactor, kept_count) = *action;
            memset(action, 0, sizeof(*action));
        }
        kept_count += 1;
    }
    reactor->write_action_count = kept_count;
    if (kept_count == 0) {
        reactor->write_action_head = 0;
    }
}

#endif

static int start_channel_exec(
    SSHReactor *reactor,
    SSHReactorChannelToken token,
    const char *command,
    size_t command_length,
    const void *initial_input,
    size_t initial_input_length,
    const void *input_tail,
    size_t input_tail_length,
    bool borrows_input,
    bool send_eof_after_initial_input);

int outersshpriv_reactor_start_channel_exec(
    SSHReactor *reactor,
    SSHReactorChannelToken token,
    const char *command,
    size_t command_length,
    const void *initial_input,
    size_t initial_input_length,
    bool send_eof_after_initial_input)
{
    return start_channel_exec(reactor, token, command, command_length,
        initial_input, initial_input_length, NULL, 0, false, send_eof_after_initial_input);
}

int outersshpriv_reactor_start_channel_exec_borrowing(
    SSHReactor *reactor,
    SSHReactorChannelToken token,
    const char *command,
    size_t command_length,
    const void *input,
    size_t input_length,
    const void *input_tail,
    size_t input_tail_length,
    bool send_eof_after_input)
{
    if (input_length == 0) {
        input = input_tail;
        input_length = input_tail_length;
        input_tail = NULL;
        input_tail_length = 0;
    }
    return start_channel_exec(reactor, token, command, command_length,
        input, input_length, input_tail, input_tail_length, true, send_eof_after_input);
}

static int start_channel_exec(
    SSHReactor *reactor,
    SSHReactorChannelToken token,
    const char *command,
    size_t command_length,
    const void *initial_input,
    size_t initial_input_length,
    const void *input_tail,
    size_t input_tail_length,
    bool borrows_input,
    bool send_eof_after_initial_input)
{
    SSHChannelState *state = &reactor->channels[token];
    if (command_length > UINT32_MAX || (!command && command_length > 0) ||
       (!initial_input && initial_input_length > 0) ||
       (!input_tail && input_tail_length > 0)) {
        return LIBSSH2_ERROR_INVAL;
    }
    if (!outersshpriv_reactor_channel_allows_initial_exec_assignment(reactor, state, token)) {
        return LIBSSH2_ERROR_BAD_USE;
    }
    bool sends_eof_immediately =
        send_eof_after_initial_input && initial_input_length == 0;
    size_t action_count = 1 +
        (initial_input_length > 0 ? 1 : 0) +
        (sends_eof_immediately ? 1 : 0);
    if (reactor->write_action_count > SIZE_MAX - action_count) {
        return LIBSSH2_ERROR_ALLOC;
    }
    int reserve_result = outersshpriv_reactor_reserve_write_actions(
        reactor,
        reactor->write_action_count + action_count);
    if (reserve_result) {
        return reserve_result;
    }

    SSHChannelOutputBuffer output_buffer = {0};
    if (borrows_input) {
        output_buffer = (SSHChannelOutputBuffer){
            .bytes = (unsigned char *)initial_input,
            .byte_count = initial_input_length,
            .capacity = initial_input_length,
        };
    } else {
        int buffer_result = outersshpriv_reactor_output_buffer_initialize(
            &output_buffer,
            SSH_READ_BUFFER_CAPACITY);
        if (buffer_result) {
            return buffer_result;
        }
    }

    SSHWriteAction exec_action = {
        .type = SSH_WRITE_CHANNEL_EXEC,
        .token = token
    };
    if (command_length > 0) {
        exec_action.payload.exec.command = malloc(command_length);
        if (!exec_action.payload.exec.command) {
            outersshpriv_reactor_output_buffer_deinitialize(&output_buffer);
            return LIBSSH2_ERROR_ALLOC;
        }
        memcpy(exec_action.payload.exec.command, command, command_length);
        exec_action.payload.exec.command_length = command_length;
    }

    if (!borrows_input && initial_input_length > 0) {
        int append_result = outersshpriv_reactor_output_buffer_append(
            &output_buffer,
            initial_input,
            initial_input_length);
        if (append_result) {
            outersshpriv_reactor_destroy_write_action(&exec_action);
            outersshpriv_reactor_output_buffer_deinitialize(&output_buffer);
            return append_result;
        }
    }

    state->exec_input = output_buffer;
    state->exec_input_is_borrowed = borrows_input;
    state->exec_input_tail = input_tail;
    state->exec_input_tail_length = input_tail_length;
    state->send_eof_after_output_drains =
        send_eof_after_initial_input && initial_input_length > 0;
    outersshpriv_reactor_append_reserved_write_action(reactor, exec_action, false);
    if (initial_input_length > 0) {
        SSHWriteAction data_action = {
            .type = SSH_WRITE_CHANNEL_DATA,
            .token = token
        };
        outersshpriv_reactor_append_reserved_write_action(reactor, data_action, false);
    }
    if (sends_eof_immediately) {
        SSHWriteAction eof_action = {
            .type = SSH_WRITE_CHANNEL_EOF,
            .token = token
        };
        outersshpriv_reactor_append_reserved_write_action(reactor, eof_action, false);
    }
    return 0;
}

size_t outersshpriv_reactor_pending_exec_input_byte_count(
    const SSHReactor *reactor,
    SSHReactorChannelToken token)
{
    if (!reactor || token >= reactor->channel_capacity) {
        return 0;
    }
    const SSHChannelState *state = &reactor->channels[token];
    if (!state->in_use || state->purpose != SSH_CHANNEL_PURPOSE_EXEC) {
        return 0;
    }
    return outersshpriv_reactor_buffer_pending_byte_count(
        &state->exec_input);
}

#if !defined(SSH_REACTOR_TESTS)

void outersshpriv_reactor_close_command(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    bool send_eof)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (!outersshpriv_reactor_accepts_work(reactor) ||
        channel_token >= reactor->channel_capacity) {
        return;
    }
    SSHReactorChannelOwner *owner =
        &reactor->channels[channel_token].owner;
    switch (owner->type) {
        case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
            break;
        case SSH_REACTOR_CHANNEL_OWNER_NONE:
        case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
        case SSH_REACTOR_CHANNEL_OWNER_RELAY:
        case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
            return;
    }
    int result = outersshpriv_reactor_begin_channel_close(
        reactor,
        &reactor->channels[channel_token],
        channel_token,
        send_eof);
    if (result != 0) {
        outersshpriv_reactor_fail(
            reactor,
            SSH_REACTOR_OPERATION_WRITE,
            result);
        return;
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
}

static int schedule_command_exit_close(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token)
{
    SSHReactorCommandChannel *channel =
        &reactor->channels[channel_token].owner.command;
    if (channel->exit_close_timer != NULL) {
        return 0;
    }
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
    timer_context->channel_token = channel_token;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(timer, timer_context);
    otsource_set_cancel_handler(timer, outersshpriv_reactor_timer_cancelled);
    otsource_set_event_handler(timer, command_exit_close_timer_fired);
    otsource_set_timer(
        timer,
        ottime(
            OTTIME_NOW,
            (int64_t)(ExecExitCloseGraceMilliseconds * NSEC_PER_MSEC)),
        OTTIME_FOREVER,
        100 * NSEC_PER_MSEC);
    channel->exit_close_timer = timer;
    otsource_activate(timer);
    return 0;
}

static void command_exit_close_timer_fired(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    SSHReactor *reactor = context->reactor;
    SSHReactorChannelToken channel_token = context->channel_token;
    if (channel_token >= reactor->channel_capacity) {
        return;
    }
    SSHReactorChannelOwner *owner = &reactor->channels[channel_token].owner;
    if (owner->type != SSH_REACTOR_CHANNEL_OWNER_COMMAND) {
        return;
    }
    SSHReactorCommandChannel *channel = &owner->command;
    if (channel->exit_close_timer != context->source) {
        return;
    }
    channel->exit_close_timer = NULL;
    outersshpriv_reactor_cancel_source(context->source);
    if (!outersshpriv_reactor_accepts_work(reactor)) {
        return;
    }
    int result = outersshpriv_reactor_begin_channel_close(
        reactor,
        &reactor->channels[channel_token],
        channel_token,
        false);
    if (result != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, result);
        return;
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
}

static void clear_command_channel(
    SSHReactorCommandChannel *channel)
{
    if (channel->exit_close_timer != NULL) {
        outersshpriv_reactor_cancel_source(channel->exit_close_timer);
        channel->exit_close_timer = NULL;
    }
    channel->command = NULL;
}

#endif

#pragma mark - Close SSH Channels

#if !defined(SSH_REACTOR_TESTS)

void outersshpriv_reactor_close_channel(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    bool send_eof)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (!outersshpriv_reactor_accepts_work(reactor) ||
        channel_token >= reactor->channel_capacity ||
        !reactor->channels[channel_token].in_use) {
        return;
    }
    int result = outersshpriv_reactor_begin_channel_close(
        reactor,
        &reactor->channels[channel_token],
        channel_token,
        send_eof);
    if (result != 0) {
        outersshpriv_reactor_fail(
            reactor,
            SSH_REACTOR_OPERATION_WRITE,
            result);
        return;
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
}

#endif

int outersshpriv_reactor_begin_channel_close(
    SSHReactor *reactor,
    SSHChannelState *state,
    SSHReactorChannelToken token,
    bool send_eof)
{
    if (!state || !state->in_use) {
        return LIBSSH2_ERROR_INVAL;
    }

    bool has_close_action = outersshpriv_reactor_has_write_action(
        reactor,
        SSH_WRITE_CHANNEL_CLOSE,
        token);
    bool wants_close = !send_eof || state->close_sent ||
        state->remote_closed ||
        (state->sent_eof && state->received_eof) || has_close_action;
    bool wants_eof = send_eof && !wants_close && !state->sent_eof;
    bool retains_close = false;
    bool retains_eof = false;
    size_t removed_action_count = 0;
    for (size_t offset = 0; offset < reactor->write_action_count; offset++) {
        SSHWriteAction *action = outersshpriv_reactor_write_action_at(reactor, offset);
        if (outersshpriv_reactor_write_action_is_removed_for_channel_close(action, token)) {
            removed_action_count += 1;
        }
        else if (action->token == token && action->must_resume) {
            retains_close = retains_close ||
                action->type == SSH_WRITE_CHANNEL_CLOSE;
            retains_eof = retains_eof ||
                action->type == SSH_WRITE_CHANNEL_EOF;
        }
    }
    bool appends_action =
        (wants_close && !state->close_sent && !retains_close) ||
        (wants_eof && !retains_close && !retains_eof);
    SSHWriteActionType action_type = wants_close
        ? SSH_WRITE_CHANNEL_CLOSE
        : SSH_WRITE_CHANNEL_EOF;
    size_t final_action_count =
        reactor->write_action_count - removed_action_count;
    if (appends_action) {
        if (final_action_count == SIZE_MAX) {
            return LIBSSH2_ERROR_ALLOC;
        }
        final_action_count += 1;
    }
    int reserve_result = outersshpriv_reactor_reserve_write_actions(reactor, final_action_count);
    if (reserve_result) {
        return reserve_result;
    }

    state->is_closing = true;
    state->is_waiting_for_window = false;
    state->send_eof_after_output_drains = false;
    switch (state->owner.type) {
    case SSH_REACTOR_CHANNEL_OWNER_RELAY: {
        SSHReactorRelayHandle handle = state->owner.relay_handle;
        RelaySlot *relay = &reactor->relay_slots[handle.index];
        if (relay->generation == handle.generation &&
            relay->state.channel_token == token &&
            relay->state.channel_phase == SSH_RELAY_CHANNEL_OPEN) {
            relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSING;
        }
        break;
    }
    case SSH_REACTOR_CHANNEL_OWNER_NONE:
    case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
    case SSH_REACTOR_CHANNEL_OWNER_COMMAND:
    case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
        break;
    }
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Beginning channel close; send_eof=%{public}s action=%{public}s sent_eof=%{public}s received_eof=%{public}s close_sent=%{public}s remote_closed=%{public}s token=%{public}llu pointer=%{public}p",
        send_eof ? "true" : "false",
        action_type == SSH_WRITE_CHANNEL_CLOSE ? "close" : "eof",
        state->sent_eof ? "true" : "false",
        state->received_eof ? "true" : "false",
        state->close_sent ? "true" : "false",
        state->remote_closed ? "true" : "false",
        (unsigned long long)token,
        state);
    outersshpriv_reactor_remove_channel_actions_for_close(reactor, token);
    if (appends_action) {
        SSHWriteAction action = {
            .type = action_type,
            .token = token
        };
        outersshpriv_reactor_append_reserved_write_action(reactor, action, false);
    }
    return 0;
}

#if !defined(SSH_REACTOR_TESTS)

static int complete_channel_close(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token)
{
    SSHChannelState *state = &reactor->channels[channel_token];
    SSHReactorChannelOwner owner = state->owner;
    if (owner.type == SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN) {
        return LIBSSH2_ERROR_PROTO;
    }
    free_channel(reactor, channel_token);
    switch (owner.type) {
        case SSH_REACTOR_CHANNEL_OWNER_RELAY: {
            SSHReactorRelayHandle handle = owner.relay_handle;
            RelaySlot *relay = outersshpriv_reactor_slot_for_handle(reactor, handle);
            if (relay == NULL) {
                return 0;
            }
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_RELAY,
                "SSH channel was freed for relay index=%{public}zu generation=%{public}llu channel=%{public}llu",
                handle.index,
                (unsigned long long)handle.generation,
                (unsigned long long)channel_token);

            if (relay->relay != NULL &&
                relay->state.socket_phase == SSH_RELAY_SOCKET_ACTIVE) {
                relay->state.remote_output_finished = true;
            }
            relay->state.channel_phase = SSH_RELAY_CHANNEL_CLOSED;
            if (!outersshpriv_reactor_close_finished_relay(reactor, relay)) {
                outersshpriv_reactor_update_relay_read_source(reactor, relay);
                outersshpriv_reactor_update_relay_write_source(reactor, relay);
            }
            return 0;
        }
        case SSH_REACTOR_CHANNEL_OWNER_COMMAND: {
            SSH_LOG_DEBUG(
                SSH_LOG_CATEGORY_CHANNEL,
                "Command channel was freed token=%{public}llu",
                (unsigned long long)channel_token);
            SSHReactorCommand *command = owner.command.command;
            clear_command_channel(&owner.command);
            outersshpriv_reactor_command_channel_closed(command);
            return 0;
        }
        case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE: {
            SSHReactorSocketBridgeHandle handle =
                owner.socket_bridge_handle;
            SSH_LOG_ERROR(
                SSH_LOG_CATEGORY_CHANNEL,
                "outerssh-helper channel was freed token=%{public}llu",
                (unsigned long long)channel_token);
            outersshpriv_reactor_socket_bridge_channel_closed(reactor, handle);
            return 0;
        }
        case SSH_REACTOR_CHANNEL_OWNER_NONE:
        case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN:
            return 0;
    }

    return 0;
}

#endif

static void free_channel(SSHReactor *reactor, SSHReactorChannelToken token)
{
    clear_channel(reactor, token);
    reactor->freed_channel_count += 1;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_CHANNEL,
        "Freed channel token=%{public}llu created=%{public}zu freed=%{public}zu live=%{public}zu",
        (unsigned long long)token,
        reactor->created_channel_count,
        reactor->freed_channel_count,
        reactor->created_channel_count - reactor->freed_channel_count);
}

static void
clear_channel(SSHReactor *reactor, SSHReactorChannelToken token)
{
    if (!reactor || token >= reactor->channel_capacity) {
        return;
    }
    SSHChannelState *state = &reactor->channels[token];
    if (state->purpose == SSH_CHANNEL_PURPOSE_EXEC && !state->exec_input_is_borrowed) {
        outersshpriv_reactor_output_buffer_deinitialize(&state->exec_input);
    }
    outersshpriv_reactor_output_buffer_deinitialize(&state->unattached_remote_buffer);
    outersshpriv_relay_release(state->relay);
    *state = (SSHChannelState){0};
}

#pragma mark - Fail and Destroy the Reactor

static void destroy_reactor_on_queue_context(void *context);
static void destroy_reactor_on_queue(SSHReactor *reactor);
static void invalidate_on_queue(
    SSHReactor *reactor);
static void invalidate_prepared_relays(SSHReactor *reactor);
static void ssh_socket_source_cancelled(SSHReactor *reactor);
static void finish_destroying_reactor(SSHReactor *reactor);
static int
teardown_ssh_channels(SSHReactor *reactor,
                              size_t *freed_channel_count);

#if !defined(SSH_REACTOR_TESTS)

void outersshpriv_reactor_fail(
    SSHReactor *reactor,
    SSHReactorOperation operation,
    int error_code)
{
    atomic_store_explicit(
        &reactor->session_failed,
        true,
        memory_order_release);
    char *pending_keepalive_reason = reactor->keepalive_reason;
    reactor->keepalive_reason = NULL;
    reactor->lifecycle = SSH_REACTOR_LIFECYCLE_FAILED;
    reactor->keepalive_pending = false;
    SSH_LOG_ERROR(
        SSH_LOG_CATEGORY_SESSION,
        "Failing SSH session operation=%{public}d error=%{public}d reason=%{public}s",
        operation,
        error_code,
        pending_keepalive_reason != NULL
            ? pending_keepalive_reason
            : "none");
    outersshpriv_reactor_cancel_keepalive_timeout(reactor);
    outersshpriv_reactor_cancel_key_exchange_timeout(reactor);
    outersshpriv_reactor_fail_all_socket_bridges(
        reactor,
        SSH_REACTOR_SOCKET_BRIDGE_SESSION_CLOSED);
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
    for (size_t index = 0; index < reactor->relay_slot_count; index++) {
        RelaySlot *relay = &reactor->relay_slots[index];
        if (relay->relay != NULL) {
            outersshpriv_reactor_safely_set_source_resumed(reactor,
                relay->state.read_socket_source, false, &relay->state.read_socket_source_is_resumed);
            outersshpriv_reactor_safely_set_source_resumed(reactor,
                relay->state.write_socket_source, false, &relay->state.write_socket_source_is_resumed);
        }
    }
    OuterSSHSessionPool *session_pool = reactor->session_pool;
    if (session_pool != NULL) {
        outersshpriv_recover_after_session_failure(
            session_pool,
            reactor->session_pool_handle,
            reactor);
    }
    free(pending_keepalive_reason);
    if (reactor->phase == SSH_REACTOR_PHASE_HANDSHAKE) {
        outersshpriv_handshake_failed(reactor, error_code);
    } else if (reactor->phase == SSH_REACTOR_PHASE_AUTHENTICATION) {
        outersshpriv_authentication_failed(reactor, error_code);
    }
}

void outersshpriv_reactor_destroy(SSHReactor *reactor, void (*completion)(void *), void *context)
{
    assert(reactor != NULL);
    reactor->destruction_completion = completion;
    reactor->destruction_context = context;

    otqueue_t queue = reactor->queue;
    otqueue_retain(queue);
    otqueue_async(
        queue,
        reactor,
        destroy_reactor_on_queue_context);
    otqueue_release(queue);
}

static void destroy_reactor_on_queue_context(void *context)
{
    destroy_reactor_on_queue(context);
}

static void destroy_reactor_on_queue(SSHReactor *reactor)
{
    outersshpriv_reactor_assert_queue(reactor);
    if (reactor->lifecycle == SSH_REACTOR_LIFECYCLE_DESTROY_WAITING) {
        return;
    }
    invalidate_on_queue(reactor);
    dispose_ssh_transport(reactor);
    if (reactor->session != NULL) {
        olibssh_session_free(reactor->session);
        reactor->session = NULL;
    }
    reactor->session_pool = NULL;
    reactor->session_pool_handle = (SSHSessionPoolSessionHandle){0};
    reactor->read_socket_source = NULL;
    reactor->write_socket_source = NULL;
    reactor->lifecycle = SSH_REACTOR_LIFECYCLE_DESTROY_WAITING;
    if (reactor->socket_source_count == 0) {
        finish_destroying_reactor(reactor);
    }
}

static void invalidate_on_queue(
    SSHReactor *reactor)
{
    outersshpriv_reactor_cancel_key_exchange_timeout(reactor);
    if (reactor->lifecycle == SSH_REACTOR_LIFECYCLE_INVALIDATED ||
        reactor->lifecycle == SSH_REACTOR_LIFECYCLE_DESTROY_WAITING) {
        return;
    }
    reactor->lifecycle = SSH_REACTOR_LIFECYCLE_INVALIDATED;
    clear_keepalive(reactor);
    outersshpriv_reactor_fail_all_socket_bridges(
        reactor,
        SSH_REACTOR_SOCKET_BRIDGE_SESSION_CLOSED);
    free(reactor->socket_bridge_read_buffer);
    reactor->socket_bridge_read_buffer = NULL;

    invalidate_prepared_relays(reactor);

    for (size_t index = 0;
         index < reactor->channel_capacity;
         index++) {
        SSHReactorChannelOwner *owner = &reactor->channels[index].owner;
        switch (owner->type) {
            case SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN: {
                SSHReactorPendingChannelOpen *pending =
                    &owner->pending_open;
                SSHReactorPendingChannelOpen pending_open = *pending;
                if (pending->timeout_timer != NULL) {
                    outersshpriv_reactor_cancel_source(pending->timeout_timer);
                }
                bool result_delivered = pending->result_delivered;
                *pending = (SSHReactorPendingChannelOpen){0};
                owner->type = SSH_REACTOR_CHANNEL_OWNER_NONE;
                if (!result_delivered) {
                    pending_open.finished(
                        reactor,
                        &pending_open,
                        index,
                        SSH_REACTOR_CHANNEL_OPEN_SESSION_CLOSED,
                        0);
                }
                break;
            }
            case SSH_REACTOR_CHANNEL_OWNER_COMMAND: {
                SSHReactorCommand *command = owner->command.command;
                clear_command_channel(&owner->command);
                owner->type = SSH_REACTOR_CHANNEL_OWNER_NONE;
                outersshpriv_reactor_command_handle_session_closed(command);
                break;
            }
            case SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE:
                owner->socket_bridge_handle =
                    (SSHReactorSocketBridgeHandle){0};
                owner->type = SSH_REACTOR_CHANNEL_OWNER_NONE;
                break;
            case SSH_REACTOR_CHANNEL_OWNER_NONE:
            case SSH_REACTOR_CHANNEL_OWNER_RELAY:
                break;
        }
    }

    for (size_t index = 0; index < reactor->relay_slot_count; index++) {
        RelaySlot *relay = &reactor->relay_slots[index];
        if (relay->relay == NULL) {
            continue;
        }
        SSHReactorRelayHandle handle = {
            .index = index,
            .generation = relay->generation
        };
        outersshpriv_reactor_remove_relay(reactor, handle);
    }

    outersshpriv_reactor_safely_cancel_source(
        reactor,
        reactor->read_socket_source,
        &reactor->read_socket_source_is_resumed);
    outersshpriv_reactor_safely_cancel_source(
        reactor,
        reactor->write_socket_source,
        &reactor->write_socket_source_is_resumed);
}

static void invalidate_prepared_relays(SSHReactor *reactor)
{
    for (size_t index = 0; index < reactor->relay_slot_count; index++) {
        RelaySlot *relay = &reactor->relay_slots[index];
        if (relay->state.socket_phase != SSH_RELAY_SOCKET_UNATTACHED ||
            (relay->state.channel_phase != SSH_RELAY_CHANNEL_OPENING &&
             relay->state.channel_phase != SSH_RELAY_CHANNEL_OPEN)) {
            continue;
        }
        SSHReactorRelayHandle handle = {
            .index = index,
            .generation = relay->generation
        };
        outersshpriv_reactor_remove_prepared_relay(reactor, handle);
    }
}

static void ssh_socket_source_cancelled_context(void *context)
{
    ssh_socket_source_cancelled(context);
}

static void ssh_socket_source_cancelled(SSHReactor *reactor)
{
    assert(reactor->uncancelled_socket_source_count > 0);
    reactor->uncancelled_socket_source_count -= 1;
    SSH_LOG_DEBUG(
        SSH_LOG_CATEGORY_SESSION,
        "SSH socket dispatch source cancelled; remaining dispatch sources=%{public}zu socket=%{public}lld",
        reactor->uncancelled_socket_source_count,
        (long long)reactor->socket);
    if (reactor->uncancelled_socket_source_count == 0) {
        SSH_LOG_DEBUG(
            SSH_LOG_CATEGORY_SESSION,
            "Closing SSH socket %{public}lld after all dispatch sources cancelled",
            (long long)reactor->socket);
        otsocket_close(reactor->socket);
        reactor->socket = -1;
    }
    outersshpriv_reactor_source_cancelled(reactor);
}

static void finish_destroying_reactor(SSHReactor *reactor)
{
    assert(reactor->uncancelled_socket_source_count == 0);
    assert(reactor->socket < 0);
    for (size_t index = 0; index < reactor->relay_slot_count; index++) {
        assert(reactor->relay_slots[index].state.channel_phase ==
               SSH_RELAY_CHANNEL_UNUSED);
        assert(reactor->relay_slots[index].state.socket_phase ==
               SSH_RELAY_SOCKET_UNATTACHED);
    }
    free(reactor->relay_slots);
    free(reactor->available_relay_indices);
    for (size_t index = 0;
         index < reactor->socket_bridge_slot_count;
         index++) {
        assert(reactor->socket_bridge_slots[index].phase ==
               SOCKET_BRIDGE_SLOT_FREE);
    }
    free(reactor->socket_bridge_slots);
    free(reactor->available_socket_bridge_indices);
    otqueue_t queue = reactor->queue;
    otqueue_retain(queue);
    reactor->queue = NULL;
    void (*completion)(void *) = reactor->destruction_completion;
    void *context = reactor->destruction_context;
    free(reactor);
    if (completion != NULL) completion(context);
    otqueue_release(queue);
    otqueue_release(queue);
}

int outersshpriv_reactor_teardown(
    SSHReactor *reactor,
    size_t *created_channel_count,
    size_t *freed_channel_count)
{
    outersshpriv_reactor_assert_queue(reactor);
    invalidate_on_queue(reactor);
    int result = 0;
    if (reactor->session != NULL) {
        size_t teardown_freed_channel_count = 0;
        result = teardown_ssh_channels(
            reactor,
            &teardown_freed_channel_count);
        reactor->freed_channel_count += teardown_freed_channel_count;
    }
    if (created_channel_count != NULL) {
        *created_channel_count = reactor->created_channel_count;
    }
    if (freed_channel_count != NULL) {
        *freed_channel_count = reactor->freed_channel_count;
    }
    SSH_LOG_NOTICE(
        SSH_LOG_CATEGORY_SESSION,
        "SSH reactor teardown complete; channels created=%{public}zu freed=%{public}zu live=%{public}zu result=%{public}d",
        reactor->created_channel_count,
        reactor->freed_channel_count,
        reactor->created_channel_count - reactor->freed_channel_count,
        result);
    return result;
}

#endif

static int
teardown_ssh_channels(SSHReactor *reactor,
                              size_t *freed_channel_count)
{
    if (!reactor) {
        return LIBSSH2_ERROR_INVAL;
    }
    size_t freed_count = 0;

    for (size_t index = 0; index < reactor->channel_capacity; index++) {
        if (!reactor->channels[index].in_use) {
            continue;
        }
        clear_channel(reactor, index);
        freed_count += 1;
    }

    while (reactor->write_action_count > 0) {
        outersshpriv_reactor_pop_write_action(reactor);
    }

    reactor->has_pending_global_request = false;
    if (freed_channel_count) {
        *freed_channel_count = freed_count;
    }
    return 0;
}

static void
dispose_ssh_transport(SSHReactor *reactor)
{
    if (reactor->session) {
        olibssh_key_exchange_cleanup(reactor->session, &reactor->key_exchange);
    }
    teardown_ssh_channels(reactor, NULL);
    free(reactor->channels);
    reactor->channels = NULL;
    reactor->channel_capacity = 0;
    free(reactor->write_actions);
    reactor->write_actions = NULL;
    reactor->write_action_capacity = 0;
}

#pragma mark - Dispatch Source Lifetime

#if !defined(SSH_REACTOR_TESTS)

SSHReactorSourceContext *outersshpriv_reactor_create_source_context(
    SSHReactor *reactor,
    otsource_t source)
{
    SSHReactorSourceContext *context = calloc(1, sizeof(*context));
    if (context != NULL) {
        context->reactor = reactor;
        context->source = source;
    }
    return context;
}

void outersshpriv_reactor_source_created(SSHReactor *reactor)
{
    reactor->socket_source_count += 1;
}

void outersshpriv_reactor_safely_set_source_resumed(
    SSHReactor *reactor,
    otsource_t socket_source,
    bool resumed,
    bool *is_resumed)
{
    if (!reactor->started ||
        reactor->lifecycle >= SSH_REACTOR_LIFECYCLE_INVALIDATED ||
        *is_resumed == resumed) {
        return;
    }
    if (resumed) {
        otsource_resume(socket_source);
    } else {
        otsource_suspend(socket_source);
    }
    *is_resumed = resumed;
}

/// Carefully handles resuming the dispatch source.
void outersshpriv_reactor_safely_cancel_source(
    SSHReactor *reactor,
    otsource_t socket_source,
    bool *is_resumed)
{
    if (!reactor->started || !*is_resumed) {
        otsource_resume(socket_source);
        *is_resumed = true;
    }
    outersshpriv_reactor_cancel_source(socket_source);
}

void outersshpriv_reactor_cancel_source(otsource_t source)
{
    otsource_cancel(source);
    otsource_release(source);
}

void outersshpriv_reactor_timer_cancelled(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    outersshpriv_reactor_source_cancelled(context->reactor);
    free(context);
}

void outersshpriv_reactor_source_cancelled(SSHReactor *reactor)
{
    outersshpriv_reactor_assert_queue(reactor);
    assert(reactor->socket_source_count > 0);
    reactor->socket_source_count -= 1;
    if (reactor->lifecycle == SSH_REACTOR_LIFECYCLE_DESTROY_WAITING &&
        reactor->socket_source_count == 0) {
        finish_destroying_reactor(reactor);
    }
}

#endif
