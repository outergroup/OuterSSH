#include "SSHReactorHandshake.h"
#include "SSHReactorInternal.h"
#include "SSHReactorReadInternal.h"
#include "olibssh/handshake.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

static void begin_handshake(void *context);
static void handshake_socket_became_readable(void *context);
static void handshake_socket_became_writable(void *context);
static void send_banner(SSHReactor *reactor);
static void receive_banner(SSHReactor *reactor);
static void request_authentication_service(SSHReactor *reactor);
static void finish_handshake(SSHReactor *reactor, int error);
static void handshake_timed_out(void *context);
static void deliver_handshake_result(void *context);
static void cancel_startup(void *context);

void outersshpriv_reactor_handshake(SSHReactor *reactor,
    void (*finished)(void *, int), void *completion_context)
{
    SSHHandshakeContext *context = &reactor->startup.handshake;
    *context = (SSHHandshakeContext){
        .reactor = reactor, .finished = finished, .context = completion_context
    };
    otqueue_async(reactor->queue, context, begin_handshake);
}

static void begin_handshake(void *opaque_context)
{
    SSHHandshakeContext *context = opaque_context;
    SSHReactor *reactor = context->reactor;
    outersshpriv_reactor_assert_queue(reactor);
    assert(!reactor->started && reactor->phase == SSH_REACTOR_PHASE_NONE);
    reactor->phase = SSH_REACTOR_PHASE_HANDSHAKE;
    otsource_set_event_handler(reactor->read_socket_source,
        handshake_socket_became_readable);
    otsource_set_event_handler(reactor->write_socket_source,
        handshake_socket_became_writable);
    reactor->started = true;

    SSHReactorSourceContext *timer_context =
        outersshpriv_reactor_create_source_context(reactor, NULL);
    otsource_t timer = timer_context == NULL ? NULL :
        otsource_create(OTSOURCE_TYPE_TIMER, 0, reactor->queue);
    if (timer == NULL) {
        free(timer_context);
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, LIBSSH2_ERROR_ALLOC);
        return;
    }
    timer_context->source = timer;
    context->timeout_timer = timer;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(timer, timer_context);
    otsource_set_cancel_handler(timer, outersshpriv_reactor_timer_cancelled);
    otsource_set_event_handler(timer, handshake_timed_out);
    otsource_set_timer(timer,
        ottime(OTTIME_NOW, 60 * NSEC_PER_SEC),
        OTTIME_FOREVER, 0);
    otsource_activate(timer);
    context->write = send_banner;
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
}

static void handshake_socket_became_readable(void *opaque_context)
{
    SSHReactor *reactor = opaque_context;
    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor) ||
        !reactor->read_socket_source_is_resumed) {
        return;
    }
    if (reactor->startup.handshake.read != NULL) {
        reactor->startup.handshake.read(reactor);
        return;
    }
    outersshpriv_reactor_read_packets(reactor);
    if (reactor->started && reactor->phase == SSH_REACTOR_PHASE_HANDSHAKE &&
        reactor->startup.handshake.service_requested) {
        outersshpriv_reactor_update_channel_write_source(reactor);
    }
}

static void handshake_socket_became_writable(void *opaque_context)
{
    SSHReactor *reactor = opaque_context;
    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor) ||
        !reactor->write_socket_source_is_resumed) {
        return;
    }
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
    if (reactor->startup.handshake.write != NULL) {
        reactor->startup.handshake.write(reactor);
        return;
    }
    if (reactor->startup.handshake.service_requested) {
        if (!outersshpriv_reactor_write_queued_packets(reactor)) {
            return;
        }
        outersshpriv_reactor_update_channel_write_source(reactor);
    }
}

static void send_banner(SSHReactor *reactor)
{
    SSHHandshakeContext *context = &reactor->startup.handshake;
    int error = olibssh_handshake_send_banner(reactor->session, &context->banner_offset);

    if (error != 0) {
        if (error != LIBSSH2_ERROR_EAGAIN) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
            return;
        }

        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
        return;
    }

    context->write = NULL;
    context->read = receive_banner;
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
}

static void receive_banner(SSHReactor *reactor)
{
    SSHHandshakeContext *context = &reactor->startup.handshake;
    int error = olibssh_handshake_receive_banner(reactor->session,
        context->banner, sizeof(context->banner), &context->banner_length);
    if (error == 0) {
        static const char windows_banner[] = "SSH-2.0-OpenSSH_for_Windows_";
        reactor->windows_banner = context->banner_length >= sizeof(windows_banner) - 1 &&
            memcmp(context->banner, windows_banner, sizeof(windows_banner) - 1) == 0;
        context->read = NULL;
        error = outersshpriv_reactor_begin_key_exchange(reactor);
    }
    if (error != 0 && error != LIBSSH2_ERROR_EAGAIN) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, error);
        return;
    }
}

void outersshpriv_handshake_keys_exchanged(SSHReactor *reactor)
{
    otsource_set_event_handler(reactor->read_socket_source,
        handshake_socket_became_readable);
    otsource_set_event_handler(reactor->write_socket_source,
        handshake_socket_became_writable);
    if (!reactor->startup.handshake.service_requested) {
        reactor->startup.handshake.write = request_authentication_service;
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    } else {
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
        outersshpriv_reactor_update_channel_write_source(reactor);
        handshake_socket_became_readable(reactor);
    }
}

static void request_authentication_service(SSHReactor *reactor)
{
    static const unsigned char request[] = "\x05\x00\x00\x00\x0c" "ssh-userauth";
    SSHHandshakeContext *context = &reactor->startup.handshake;
    int error = context->service_write_pending
        ? olibssh_transport_resume_write(reactor->session)
        : olibssh_transport_write(reactor->session, request, sizeof(request) - 1, NULL, 0);
    if (error == LIBSSH2_ERROR_EAGAIN) {
        context->service_write_pending = true;
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    } else if (error != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
        return;
    } else {
        context->service_write_pending = false;
        context->service_requested = true;
        context->write = NULL;
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
        handshake_socket_became_readable(reactor);
    }
}

void outersshpriv_reactor_received_service_accept(SSHReactor *reactor,
    const unsigned char *packet, size_t length)
{
    static const unsigned char response[] = "\x06\x00\x00\x00\x0c" "ssh-userauth";
    SSHHandshakeContext *context = &reactor->startup.handshake;
    if (reactor->phase != SSH_REACTOR_PHASE_HANDSHAKE || !context->service_requested ||
        length != sizeof(response) - 1 || memcmp(packet, response, length) != 0) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_PROTO);
        return;
    }
    finish_handshake(reactor, 0);
}

void outersshpriv_handshake_failed(SSHReactor *reactor, int error)
{
    finish_handshake(reactor, error);
}

static void finish_handshake(SSHReactor *reactor, int error)
{
    SSHHandshakeContext *context = &reactor->startup.handshake;
    if (context->timeout_timer != NULL) {
        outersshpriv_reactor_cancel_source(context->timeout_timer);
    }
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
    reactor->phase = SSH_REACTOR_PHASE_NONE;
    reactor->started = false;
    context->error = error;
    // Deliver completion after the transport has finished freeing this packet.
    otqueue_async(reactor->queue, context, deliver_handshake_result);
}

static void deliver_handshake_result(void *opaque_context)
{
    SSHHandshakeContext *context = opaque_context;
    context->finished(context->context, context->error);
}

static void handshake_timed_out(void *opaque_context)
{
    SSHReactorSourceContext *timer_context = opaque_context;
    SSHReactor *reactor = timer_context->reactor;
    if (reactor->phase != SSH_REACTOR_PHASE_HANDSHAKE ||
        reactor->startup.handshake.timeout_timer != timer_context->source) {
        return;
    }
    outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_TIMEOUT);
}

void outersshpriv_reactor_cancel_startup(SSHReactor *reactor)
{
    otqueue_async(reactor->queue, reactor, cancel_startup);
}

static void cancel_startup(void *context)
{
    SSHReactor *reactor = context;
    (void)otsocket_shutdown(reactor->socket, SHUT_RDWR);
    outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_SOCKET_DISCONNECT);
}
