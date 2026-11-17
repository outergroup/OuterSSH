#include "SSHTestReactor.h"
#include "SSHTestSupport.h"
#include "SSHReactorHandshake.h"
#include "SSHReactorInternal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool fail_timer;
static otsource_t handshake_test_source_create(otsource_type_t type,
    uintptr_t handle, otqueue_t queue);
#define otsource_create handshake_test_source_create
#include "SSHReactorHandshake.c"
#undef otsource_create

static otsource_t handshake_test_source_create(otsource_type_t type,
    uintptr_t handle, otqueue_t queue)
{
    return fail_timer ? NULL : otsource_create(type, handle, queue);
}

typedef struct {
    SSHReactor *reactor;
    ssh_test_semaphore_t finished;
    unsigned completions;
    int expected_error;
    otsocket_t socket;
    unsigned scenario;
} HandshakeTestContext;

static void destroyed(void *opaque)
{
    HandshakeTestContext *context = opaque;
    assert(context->completions == 1);
    assert(!ssh_test_socket_is_open(context->socket));
    ssh_test_semaphore_signal(context->finished);
}

static void handshake_completed(void *opaque, int error)
{
    HandshakeTestContext *context = opaque;
    outersshpriv_reactor_assert_queue(context->reactor);
    assert(++context->completions == 1);
    if (error != context->expected_error) {
        fprintf(stderr, "scenario %u: expected %d, received %d\n",
            context->scenario, context->expected_error, error);
    }
    assert(error == context->expected_error);
    assert(context->reactor->phase == SSH_REACTOR_PHASE_NONE && !context->reactor->started);
    memset(&context->reactor->startup, 0xa5, sizeof(context->reactor->startup));
    outersshpriv_reactor_destroy(context->reactor, destroyed, context);
}

static void expire_handshake(void *opaque)
{
    HandshakeTestContext *context = opaque;
    assert(context->reactor->startup.handshake.timeout_timer != NULL);
    SSHReactorSourceContext timer_context = {
        .reactor = context->reactor, .source = context->reactor->startup.handshake.timeout_timer
    };
    handshake_timed_out(&timer_context);
}

static void cancel_initial_exchange(void *opaque)
{
    HandshakeTestContext *context = opaque;
    SSHReactor *reactor = context->reactor;
    context->reactor->startup.handshake.read = NULL;
    context->reactor->startup.handshake.write = NULL;
    assert(outersshpriv_reactor_begin_key_exchange(reactor) == 0);
    assert(reactor->key_exchange.step == OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT);
    cancel_startup(reactor);
}

static void invalid_service_accept(void *opaque)
{
    HandshakeTestContext *context = opaque;
    static const unsigned char truncated[] = {6, 0, 0, 0, 12, 's'};
    context->reactor->startup.handshake.service_requested = true;
    outersshpriv_reactor_received_service_accept(context->reactor, truncated, sizeof(truncated));
}

static unsigned handshake_write_count;
static unsigned handshake_read_count;

static void handshake_read_ready(SSHReactor *reactor)
{
    handshake_read_count++;
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
}

static void handshake_write_ready(SSHReactor *reactor)
{
    assert(!reactor->write_socket_source_is_resumed);
    if (++handshake_write_count == 1) {
        // A partial write must rearm the source for another notification.
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    } else {
        reactor->startup.handshake.write = NULL;
        reactor->startup.handshake.read = handshake_read_ready;
        outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
    }
}

static void test_handshake_readiness_transitions(void *opaque)
{
    HandshakeTestContext *context = opaque;
    SSHReactor *reactor = context->reactor;
    reactor->startup.handshake.write = handshake_write_ready;
    reactor->startup.handshake.read = NULL;
    handshake_write_count = handshake_read_count = 0;
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    handshake_socket_became_writable(reactor);
    assert(handshake_write_count == 1 && reactor->write_socket_source_is_resumed);
    handshake_socket_became_writable(reactor);
    assert(handshake_write_count == 2 && !reactor->write_socket_source_is_resumed);
    handshake_socket_became_writable(reactor);
    assert(handshake_write_count == 2);
    handshake_socket_became_readable(reactor);
    assert(handshake_read_count == 1 && !reactor->read_socket_source_is_resumed);
    handshake_socket_became_readable(reactor);
    assert(handshake_read_count == 1);
    cancel_startup(reactor);
    handshake_socket_became_readable(reactor);
    handshake_socket_became_writable(reactor);
    assert(handshake_write_count == 2 && handshake_read_count == 1);
}

static void test_failure(unsigned scenario)
{
    otsocket_t sockets[2];
    otsocket_t listener = otsocket_create(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t address_length = sizeof(address);
    assert(listener >= 0);
    assert(otsocket_bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(otsocket_getsockname(listener, (struct sockaddr *)&address, &address_length) == 0);
    assert(otsocket_listen(listener, 1) == 0);
    sockets[0] = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(sockets[0] >= 0);
    assert(otsocket_connect(sockets[0], (struct sockaddr *)&address, sizeof(address)) == 0);
    sockets[1] = otsocket_accept(listener, NULL, NULL);
    assert(sockets[1] >= 0);
    assert(otsocket_set_nonblocking(sockets[1], false) == 0);
    otsocket_close(listener);
    SSHSessionStartResult result = {0};
    LIBSSH2_SESSION *session = outersshpriv_session_create(sockets[0], &result);
    assert(session && result.error.domain == OUTERSSH_ERROR_NONE);
    HandshakeTestContext context = {
        .reactor = ssh_test_reactor_create(sockets[0], session),
        .finished = ssh_test_semaphore_create(0), .socket = sockets[0], .scenario = scenario
    };
    assert(context.reactor && context.finished);
    fail_timer = scenario == 0;
    switch (scenario) {
    case 0: context.expected_error = LIBSSH2_ERROR_ALLOC; break;
    case 1: case 2: case 3: context.expected_error = LIBSSH2_ERROR_BANNER_RECV; break;
    case 4: case 5: case 7: case 9: context.expected_error = LIBSSH2_ERROR_SOCKET_DISCONNECT; break;
    case 6: context.expected_error = LIBSSH2_ERROR_TIMEOUT; break;
    case 8: context.expected_error = LIBSSH2_ERROR_PROTO; break;
    default: abort();
    }
    outersshpriv_reactor_handshake(context.reactor, handshake_completed, &context);
    if (scenario >= 1 && scenario <= 3) {
        char banner[256];
        size_t length;
        if (scenario == 1) {
            static const char legacy[] = "SSH-1.5-old-server\r\n";
            memcpy(banner, legacy, sizeof(legacy) - 1);
            length = sizeof(legacy) - 1;
        } else if (scenario == 2) {
            memset(banner, 'x', sizeof(banner));
            length = sizeof(banner);
        } else {
            banner[0] = '\0';
            length = 1;
        }
        assert(otsocket_write(sockets[1], banner, length) == (ssize_t)length);
    } else if (scenario == 4) {
        char byte;
        do {
            ssize_t count = otsocket_read(sockets[1], &byte, 1);
            if (count != 1) fprintf(stderr, "banner peer read returned %lld, errno=%d\n", (long long)count, errno);
            assert(count == 1);
        } while (byte != '\n');
        otsocket_shutdown(sockets[1], SHUT_RDWR);
    } else if (scenario == 5) {
        outersshpriv_reactor_cancel_startup(context.reactor);
    } else if (scenario == 6) {
        otqueue_async(context.reactor->queue, &context, expire_handshake);
    } else if (scenario == 7) {
        otqueue_async(context.reactor->queue, &context, cancel_initial_exchange);
    } else if (scenario == 8) {
        otqueue_async(context.reactor->queue, &context, invalid_service_accept);
    } else if (scenario == 9) {
        otqueue_async(context.reactor->queue, &context, test_handshake_readiness_transitions);
    }
    int wait_result = ssh_test_semaphore_wait(context.finished, 5 * NSEC_PER_SEC);
    if (wait_result != 0) fprintf(stderr, "scenario %u timed out\n", scenario);
    assert(wait_result == 0);
    ssh_test_semaphore_destroy(context.finished);
    otsocket_close(sockets[1]);
    outersshpriv_session_start_result_dispose(&result);
}

int main(void)
{
    assert(libssh2_init(0) == 0);
    for (unsigned scenario = 0; scenario < 10; scenario++) {
        test_failure(scenario);
    }
    libssh2_exit();
    puts("PASS: handshake allocation failure, invalid banners, disconnect, cancellation, deadline, interrupted initial exchange, and malformed service acceptance");
    return 0;
}
