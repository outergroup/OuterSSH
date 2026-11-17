#include "SSHReactorInternal.h"
#include "SSHReactorReadInternal.h"
#include "olibssh/read_dispatch.h"
#include "platform/SSHLogging.h"

#include <assert.h>
#include <stdlib.h>

static void key_exchange_socket_became_readable(void *context);
static void key_exchange_socket_became_writable(void *context);
static void finish_key_exchange(SSHReactor *reactor);
static void key_exchange_timed_out(void *context);

#if !defined(SSH_REACTOR_TESTS)

int outersshpriv_reactor_begin_key_exchange(SSHReactor *reactor)
{
    assert(!reactor->key_exchange_in_progress);
    reactor->key_exchange_in_progress = true;
    otsource_set_event_handler(reactor->read_socket_source,
        key_exchange_socket_became_readable);
    otsource_set_event_handler(reactor->write_socket_source,
        key_exchange_socket_became_writable);
    if (reactor->phase != SSH_REACTOR_PHASE_HANDSHAKE) {
        SSHReactorSourceContext *context =
            outersshpriv_reactor_create_source_context(reactor, NULL);
        if (!context) {
            return LIBSSH2_ERROR_ALLOC;
        }
        otsource_t timer = otsource_create(
            OTSOURCE_TYPE_TIMER, 0, reactor->queue);
        if (!timer) {
            free(context);
            return LIBSSH2_ERROR_ALLOC;
        }
        context->source = timer;
        reactor->key_exchange_timeout_timer = timer;
        outersshpriv_reactor_source_created(reactor);
        otsource_set_context(timer, context);
        otsource_set_cancel_handler(timer, outersshpriv_reactor_timer_cancelled);
        otsource_set_event_handler(timer, key_exchange_timed_out);
        otsource_set_timer(timer,
            ottime(OTTIME_NOW, 60 * NSEC_PER_SEC),
            OTTIME_FOREVER, 0);
        otsource_activate(timer);
        // Ordinary requests cannot progress during rekeying. Its own timeout
        // bounds this wait; an outstanding keepalive gets a fresh deadline afterward.
        outersshpriv_reactor_cancel_keepalive_timeout(reactor);
        SSH_LOG_DEBUG(SSH_LOG_CATEGORY_SESSION, "Starting SSH key re-exchange");
    }
    const SSHWriteAction *head = reactor->write_action_count == 0
        ? NULL : &reactor->write_actions[reactor->write_action_head];
    if ((head && head->must_resume) ||
        (reactor->phase == SSH_REACTOR_PHASE_AUTHENTICATION &&
         reactor->startup.authentication.packet_write_pending)) {
        reactor->key_exchange_waiting_for_write = true;
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
        return 0;
    }
    return outersshpriv_reactor_advance_key_exchange(reactor);
}

#endif

static void key_exchange_socket_became_readable(void *context)
{
    SSHReactor *reactor = context;
    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor) ||
        !reactor->read_socket_source_is_resumed) {
        return;
    }
    outersshpriv_reactor_read_packets(reactor);
    if (outersshpriv_reactor_accepts_work(reactor) &&
        reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_COMPLETE) {
        finish_key_exchange(reactor);
    }
}

static void key_exchange_socket_became_writable(void *context)
{
    SSHReactor *reactor = context;
    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor) ||
        !reactor->write_socket_source_is_resumed) {
        return;
    }
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
    if (reactor->key_exchange_waiting_for_write) {
        if (reactor->phase == SSH_REACTOR_PHASE_AUTHENTICATION &&
            reactor->startup.authentication.packet_write_pending) {
            int error = outersshpriv_authentication_resume_write(reactor);
            if (error == LIBSSH2_ERROR_EAGAIN) {
                outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
                return;
            }
            if (error != 0) {
                outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
                return;
            }
        } else if (!outersshpriv_reactor_finish_pending_write(reactor)) {
            return;
        }
        reactor->key_exchange_waiting_for_write = false;
        int error = outersshpriv_reactor_advance_key_exchange(reactor);
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
            return;
        }
    }
    while (reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT) {
        int error = olibssh_key_exchange_write(reactor->session, &reactor->key_exchange);
        if (error == LIBSSH2_ERROR_EAGAIN) {
            outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
            return;
        }
        if (error == 0) {
            error = outersshpriv_reactor_advance_key_exchange(reactor);
        }
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
            return;
        }
        /* A prior read may have buffered the reply to this write. Apply NEWKEYS
         * before decoding the following packet, without waiting for a socket event. */
        if (reactor->read_socket_source_is_resumed &&
            olibssh_transport_has_buffered_input(reactor->session)) {
            outersshpriv_reactor_read_packets(reactor);
        }
        if (!outersshpriv_reactor_accepts_work(reactor) || !reactor->started) {
            return;
        }
    }
    if (reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_COMPLETE) {
        finish_key_exchange(reactor);
    }
}

#if !defined(SSH_REACTOR_TESTS)

int outersshpriv_reactor_advance_key_exchange(SSHReactor *reactor)
{
    switch (olibssh_key_exchange_advance(reactor->session,
                                        &reactor->key_exchange)) {
    case OLIBSSH_KEY_EXCHANGE_COMPLETE:
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
        return 0;
    case OLIBSSH_KEY_EXCHANGE_FAILED:
        outersshpriv_reactor_cancel_key_exchange_timeout(reactor);
        return reactor->key_exchange.error;
    case OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT:
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
        return 0;
    case OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT:
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
        return 0;
    case OLIBSSH_KEY_EXCHANGE_IDLE:
        abort();
    }
    abort();
}

static void finish_key_exchange(SSHReactor *reactor)
{
    outersshpriv_reactor_cancel_key_exchange_timeout(reactor);
    olibssh_key_exchange_cleanup(reactor->session, &reactor->key_exchange);
    reactor->last_server_activity_nanoseconds = outersshpriv_reactor_monotonic_time_nanoseconds();
    SSH_LOG_DEBUG(SSH_LOG_CATEGORY_SESSION, "SSH key exchange complete");
    if (reactor->keepalive_pending && reactor->has_pending_global_request) {
        int error = outersshpriv_reactor_start_keepalive_timeout(reactor);
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
            return;
        }
    }
    reactor->key_exchange_in_progress = false;
    switch (reactor->phase) {
    case SSH_REACTOR_PHASE_HANDSHAKE:
        outersshpriv_handshake_keys_exchanged(reactor);
        break;
    case SSH_REACTOR_PHASE_AUTHENTICATION:
        outersshpriv_authentication_keys_exchanged(reactor);
        break;
    case SSH_REACTOR_PHASE_CHANNELS:
        outersshpriv_reactor_resume_channels_after_key_exchange(reactor);
        break;
    case SSH_REACTOR_PHASE_NONE:
        abort();
    }
}

static void key_exchange_timed_out(void *opaque_context)
{
    SSHReactorSourceContext *context = opaque_context;
    SSHReactor *reactor = context->reactor;
    if (reactor->key_exchange_timeout_timer != context->source ||
       reactor->lifecycle != SSH_REACTOR_LIFECYCLE_ACTIVE) {
        return;
    }
    outersshpriv_reactor_cancel_key_exchange_timeout(reactor);
    SSH_LOG_ERROR(SSH_LOG_CATEGORY_SESSION, "SSH key re-exchange timed out");
    outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_TIMEOUT);
}

void outersshpriv_reactor_cancel_key_exchange_timeout(SSHReactor *reactor)
{
    if (reactor->key_exchange_timeout_timer) {
        outersshpriv_reactor_cancel_source(reactor->key_exchange_timeout_timer);
        reactor->key_exchange_timeout_timer = NULL;
    }
}

#endif

void outersshpriv_reactor_received_key_exchange_packet(SSHReactor *reactor,
    unsigned char *packet, size_t length)
{
    bool starts_exchange = reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_IDLE;
    int receive_error = olibssh_key_exchange_receive(reactor->session,
        &reactor->key_exchange, packet, length);
    if (receive_error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, receive_error);
        return;
    }
    if (starts_exchange) {
        int error = outersshpriv_reactor_begin_key_exchange(reactor);
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
        }
    }
}

#if !defined(SSH_REACTOR_TESTS)

void outersshpriv_reactor_resume_key_exchange(SSHReactor *reactor)
{
    otsource_set_event_handler(reactor->read_socket_source,
        key_exchange_socket_became_readable);
    otsource_set_event_handler(reactor->write_socket_source,
        key_exchange_socket_became_writable);
    if (reactor->key_exchange_waiting_for_write ||
        reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT) {
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    } else if (reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT) {
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
        key_exchange_socket_became_readable(reactor);
    }
}

#endif
