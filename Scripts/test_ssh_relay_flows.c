#include "SSHTestSupport.h"
#include "platform/OTSocket.h"
#include <assert.h>
#include <errno.h>

#include "SSHRelayFlows.c"

static SSHProxyConnection controller;
static SSHForwarder test_server;
static OuterSSHSessionPool pool;
static ProxyConnectionRoute route;
static otqueue_t reactor_queue;
static ssh_test_semaphore_t finished;
enum {
    CONNECTION_ENDED_DURING_ACQUISITION = 10,
    LISTENER_ENDED_DURING_ACQUISITION,
    START_FAILURE_THEN_SUCCESS,
    SESSION_CLOSED_THEN_SUCCESS,
    CANCELLED_OPEN,
    REJECTED_TCP_CHANNEL,
    TIMEOUT_TWICE,
    ACQUISITION_FAILED,
    STAGE_COUNT
};
static unsigned stage;
static unsigned attempts;
static unsigned removals;
static unsigned cancellations;
static unsigned failures;
static unsigned attachments;
static unsigned fallbacks;
static otsocket_t transferred_socket = -1;
static bool listener_active;
static ConnectRelayContext *first_operation;

static unsigned diagnostic_count;
static bool testing_forwarding_denial;

static void connection_failed(void *context, OuterSSHSessionPool *callback_pool, const void *frontend, const char *host, size_t host_length,
    uint16_t port, const char *path, size_t socket_path_length, OuterSSHError error)
{
    (void)host_length; (void)socket_path_length;
    (void)callback_pool;
    assert(context == &controller && listener_active && frontend == test_server.frontend);
    assert(outersshpriv_proxy_reactor_pending_connection_is_active(test_server.reactor,
        (ProxyReactorPendingConnectionHandle){.generation = 1}));
    assert(strcmp(host, route.request.host) == 0 && port == route.request.port);
    assert(error.domain != OUTERSSH_ERROR_NONE);
    if (route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET) {
        assert(socket_path_length == route.unix_socket.path_length);
        assert(memcmp(path, route.unix_socket.path, socket_path_length) == 0);
    } else {
        assert(socket_path_length == 0 && path[0] == '\0');
    }
    if (stage == REJECTED_TCP_CHANNEL) {
        static const char message[] = "The SSH server rejected the channel (reason 3).";
        assert(error.code == OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE);
        assert(error.ssh_channel_open_reason == 3);
        assert(error.message_length == sizeof(message) - 1);
        assert(memcmp(error.message, message, error.message_length) == 0);
    } else if (stage == TIMEOUT_TWICE) {
        static const char message[] = "The remote server took too long to open the channel.";
        assert(error.code == OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_TIMED_OUT);
        assert(error.message_length == sizeof(message) - 1);
        assert(memcmp(error.message, message, error.message_length) == 0);
    } else if (stage == CANCELLED_OPEN) {
        static const char message[] = "The SSH operation was cancelled.";
        assert(error.code == OUTERSSH_SESSION_ERROR_CANCELLED);
        assert(error.message_length == sizeof(message) - 1);
        assert(memcmp(error.message, message, error.message_length) == 0);
    }
    diagnostic_count++;
}

static unsigned nothing_listening_reports;
static const char nothing_listening_path[] = "/run/stale.sock";

void outersshpriv_socket_service_found_nothing_listening(OuterSSHSessionPool *callback_pool,
    const char *path, size_t length)
{
    assert(callback_pool == &pool && length == sizeof(nothing_listening_path) - 1);
    assert(memcmp(path, nothing_listening_path, length) == 0);
    nothing_listening_reports++;
}

void outersshpriv_session_pool_post_connection_failure(OuterSSHSessionPool *callback_pool,
    const void *frontend, const char *host, size_t host_length, uint16_t port,
    const char *socket_path, size_t socket_path_length, OuterSSHError error)
{
    connection_failed(&controller, callback_pool, frontend, host, host_length, port,
        socket_path, socket_path_length, error);
}

static void run_stage(void *context);
static void verify_stage(void *context);

static void return_to_controller(void *context)
{
    otqueue_async(pool._queue, context, verify_stage);
}

static void schedule_verification(void)
{
    otqueue_async(reactor_queue, NULL, return_to_controller);
}

void outersshpriv_session_pool_begin_operation(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    pool->pending_operations++;
}

void outersshpriv_session_pool_end_operation(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    assert(pool->pending_operations != 0);
    pool->pending_operations--;
}

void outersshpriv_session_pool_finish_destroy_if_ready(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
}


static SSHCompletionHandler pending_session_resume;

static void session_acquired(void *context)
{
    static const char session_error_message_1[] = "The SSH session is no longer available.";

    ConnectRelayContext *operation = context;
    if (stage == LISTENER_ENDED_DURING_ACQUISITION) {
        listener_active = false;
    }
    pending_session_resume(operation,
        stage == ACQUISITION_FAILED
            ? outerssh_session_error(OUTERSSH_SESSION_ERROR_UNAVAILABLE, session_error_message_1, sizeof(session_error_message_1) - 1)
            : (OuterSSHError){0});
}

SSHReactor *outersshpriv_session_pool_ready_reactor(OuterSSHSessionPool *value,
    SSHSessionPoolSessionHandle *session, OuterSSHError *error)
{
    assert(value == &pool);
    *session = (SSHSessionPoolSessionHandle){0};
    if (error->domain != OUTERSSH_ERROR_NONE) return NULL;
    *session = (SSHSessionPoolSessionHandle){.generation = 1};
    return (SSHReactor *)&pool;
}

void outersshpriv_session_pool_run_when_ready(
    OuterSSHSessionPool *value, SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    otqueue_assert(value->_queue);
    assert(resume == ssh_relay_session_request_finished);
    assert(waiter == &((ConnectRelayContext *)context)->waiter);
    pending_session_resume = resume;
    if (first_operation == NULL) {
        first_operation = context;
    }
    assert(first_operation == context);
    otqueue_async(pool._queue, context, session_acquired);
}

SSHReactor *outersshpriv_session_pool_reactor_for_session(
    OuterSSHSessionPool *value, SSHSessionPoolSessionHandle session)
{
    assert(value == &pool && session.generation == 1);
    return (SSHReactor *)&pool;
}

otqueue_t outersshpriv_reactor_queue(SSHReactor *reactor)
{
    assert(reactor == (SSHReactor *)&pool);
    return reactor_queue;
}

void outersshpriv_remove_session(OuterSSHSessionPool *value, SSHSessionPoolSessionHandle session)
{
    assert(value == &pool && session.generation == 1);
    removals++;
}

static int open_relay(ConnectRelayContext *operation, SSHReactorRelayHandle *handle)
{
    otqueue_assert(reactor_queue);
    attempts++;
    *handle = (SSHReactorRelayHandle){.generation = 7};
    if (stage == 2 || (stage == START_FAILURE_THEN_SUCCESS && attempts == 1)) {
        return -1;
    }
    SSHReactorRelayOpenResult result = SSH_REACTOR_RELAY_OPEN_SUCCEEDED;
    if ((stage == 1 && attempts == 1) || stage == TIMEOUT_TWICE) {
        result = SSH_REACTOR_RELAY_OPEN_TIMED_OUT;
    } else if (stage == 3 || stage == REJECTED_TCP_CHANNEL) {
        result = SSH_REACTOR_RELAY_OPEN_CHANNEL_FAILED;
    } else if (stage == SESSION_CLOSED_THEN_SUCCESS && attempts == 1) {
        result = SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED;
    } else if (stage == CANCELLED_OPEN) {
        result = SSH_REACTOR_RELAY_OPEN_CANCELLED;
    }
    outersshpriv_session_pool_prepared_relay_completed(operation, *handle, result, 3);
    return 0;
}

int outersshpriv_reactor_prepare_relay(
    SSHReactor *reactor, SSHReactorRelayHandle *handle, ConnectRelayContext *operation,
    const SSHRelayTarget *target, const char *source_host, size_t source_host_length, int source_port,
    uint64_t timeout)
{
    assert(reactor == (SSHReactor *)&pool);
    if (target->kind == SSHRelayTargetTCP) {
        assert(target->destination_length == sizeof("localhost") - 1);
        assert(memcmp(target->destination, "localhost", target->destination_length) == 0);
        assert(target->port == 8080);
    } else {
        assert(target->kind == SSHRelayTargetUnixSocket);
        assert(target->destination_length == sizeof("/run/test.sock") - 1);
        assert(memcmp(target->destination, "/run/test.sock", target->destination_length) == 0);
    }
    assert(source_host_length == sizeof("127.0.0.1") - 1);
    assert(memcmp(source_host, "127.0.0.1", source_host_length) == 0 && source_port == 0);
    assert(timeout == 10000);
    return open_relay(operation, handle);
}

SSHProxyConnection outersshpriv_proxy_active_connection(
    SSHProxyConnection value)
{
    assert(value.pool == controller.pool);
    return (SSHProxyConnection){.server = &test_server, .pool = listener_active && !(stage == 4 && attempts != 0) ? &pool : NULL, .proxy_generation = 1};
}

ProxyPendingConnection *outersshpriv_proxy_pending_connection_for_handle(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle)
{
    (void)reactor; (void)handle;
    static ProxyPendingConnection pending;
    return &pending;
}

bool outersshpriv_proxy_reactor_pending_connection_is_active(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle connection)
{
    assert(reactor == test_server.reactor && connection.generation == 1);
    return !(stage == 6 && attempts != 0) &&
        stage != CONNECTION_ENDED_DURING_ACQUISITION;
}

bool outersshpriv_proxy_reactor_fail_pending_connection(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle connection, ProxySOCKSReplyStatus status)
{
    (void)status;
    assert(reactor == test_server.reactor && connection.generation == 1);
    if (testing_forwarding_denial) return true;
    failures++;
    schedule_verification();
    return true;
}

void outersshpriv_proxy_assign_bridge_connection(
    SSHProxyConnection value, ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute request_route, const char *path, size_t path_length, bool uses_sudo)
{
    (void)path_length;
    assert(value.pool == controller.pool && connection.generation == 1);
    assert(request_route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET);
    assert(strcmp(path, "/run/test.sock") == 0);
    assert(!uses_sudo);
    fallbacks++;
    schedule_verification();
}

bool outersshpriv_reactor_cancel_prepared_relay(SSHReactor *reactor, SSHReactorRelayHandle handle)
{
    otqueue_assert(reactor_queue);
    assert(reactor == (SSHReactor *)&pool && handle.generation == 7);
    cancellations++;
    if (stage == 5 || stage == 8) {
        schedule_verification();
    }
    return true;
}

typedef struct {
    ProxySocketTransferHandler finished;
    void *context;
} TestSocketDelivery;

static void deliver_socket(void *context)
{
    TestSocketDelivery *delivery = context;
    otsocket_t sockets[2];
    assert(ssh_test_socket_pair(sockets) == 0);
    otsocket_close(sockets[1]);
    transferred_socket = sockets[0];
    if (stage == 8) listener_active = false;
    delivery->finished(delivery->context, sockets[0]);
    free(delivery);
}

void outersshpriv_proxy_reactor_complete_pending_connection(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle connection,
    ProxySocketTransferHandler finished, void *context)
{
    assert(reactor == test_server.reactor && connection.generation == 1);
    assert(context == first_operation && pool.pending_operations == 1);
    if (stage == 5) {
        finished(context, -1);
        return;
    }
    TestSocketDelivery *delivery = malloc(sizeof(*delivery));
    assert(delivery != NULL);
    *delivery = (TestSocketDelivery){finished, context};
    otqueue_async(pool._queue, delivery, deliver_socket);
}

int outersshpriv_reactor_attach_prepared_relay(
    SSHReactor *reactor, SSHReactorRelayHandle handle, otsocket_t socket,
    uint64_t identifier, uint64_t group, SSHRelayTargetType type, const char *destination, size_t destination_length, int port)
{
    otqueue_assert(reactor_queue);
    assert(reactor == (SSHReactor *)&pool && handle.generation == 7);
    assert(identifier != 0 && group == 1);
    assert(type == (stage == 9 ? SSH_RELAY_TARGET_STREAMLOCAL : SSH_RELAY_TARGET_TCP));
    const char *expected = stage == 9 ? "/run/test.sock" : "localhost";
    assert(destination_length == strlen(expected) && memcmp(destination, expected, destination_length) == 0);
    assert(port == (stage == 9 ? 0 : 8080));
    assert(otsocket_close(socket) == 0);
    attachments++;
    schedule_verification();
    return stage == 7 ? -1 : 0;
}

void outersshpriv_socket_bridge_cancel_stream(SSHSocketBridge bridge, SSHSocketBridgeStream stream)
{
    (void)bridge;
    (void)stream;
    assert(false);
}

bool outersshpriv_reactor_socket_bridge_attach_stream(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle bridge,
    SSHReactorSocketBridgeStreamHandle stream, otsocket_t socket, uint64_t proxy_generation)
{
    (void)reactor; (void)bridge; (void)stream; (void)socket; (void)proxy_generation;
    assert(false);
    return false;
}

static void verify_stage(void *context)
{
    (void)context;
    assert(pool.pending_operations == 0);
    bool retry = stage == 1 || stage == 2 || stage == START_FAILURE_THEN_SUCCESS ||
        stage == SESSION_CLOSED_THEN_SUCCESS || stage == TIMEOUT_TWICE;
    bool rejected_before_open = stage == CONNECTION_ENDED_DURING_ACQUISITION || stage == LISTENER_ENDED_DURING_ACQUISITION ||
        stage == ACQUISITION_FAILED;
    assert(attempts == (rejected_before_open ? 0u : retry ? 2u : 1u));
    assert(removals == (unsigned)retry);
    assert(failures == (unsigned)(stage == 2 || stage == 4 || stage == 6 ||
        rejected_before_open || stage == CANCELLED_OPEN || stage == REJECTED_TCP_CHANNEL ||
        stage == TIMEOUT_TWICE));
    assert(cancellations == (unsigned)(stage == 4 || stage == 5 || stage == 6 || stage == 8));
    assert(attachments == (unsigned)(stage == 0 || stage == 1 || stage == 7 || stage == 9 ||
        stage == START_FAILURE_THEN_SUCCESS || stage == SESSION_CLOSED_THEN_SUCCESS));
    assert(fallbacks == (unsigned)(stage == 3));
    assert(pool._directStreamLocalUnsupported == (stage == 3));
    if (transferred_socket >= 0) {
        assert(!ssh_test_socket_is_open(transferred_socket));
    }
    stage++;
    if (stage == STAGE_COUNT) {
        ssh_test_semaphore_signal(finished);
    } else {
        run_stage(NULL);
    }
}

static void run_stage(void *context)
{
    (void)context;
    attempts = removals = cancellations = failures = attachments = fallbacks = 0;
    transferred_socket = -1;
    first_operation = NULL;
    listener_active = true;
    pool._directStreamLocalUnsupported = false;
    bool is_unix = stage == 3 || stage == 9;
    route = (ProxyConnectionRoute){
        .kind = is_unix ? PROXY_CONNECTION_ROUTE_UNIX_SOCKET : PROXY_CONNECTION_ROUTE_TCP,
        .request = {.host = "localhost", .host_length = sizeof("localhost") - 1, .port = 8080}
    };
    if (is_unix) {
        memcpy(route.unix_socket.path, "/run/test.sock", sizeof("/run/test.sock"));
        route.unix_socket.path_length = sizeof("/run/test.sock") - 1;
    } else {
        memcpy(route.tcp.host, "localhost", sizeof("localhost"));
        route.tcp.host_length = sizeof("localhost") - 1;
        route.tcp.port = 8080;
    }
    SSHRelayTarget target = {
        .kind = is_unix ? SSHRelayTargetUnixSocket : SSHRelayTargetTCP,
        .port = is_unix ? 0 : 8080
    };
    const char *destination = is_unix ? "/run/test.sock" : "localhost";
    target.destination_length = strlen(destination);
    memset(target.destination, 0xff, sizeof(target.destination));
    memcpy(target.destination, destination, target.destination_length);
    prepare_relay(
        controller, (ProxyReactorPendingConnectionHandle){.generation = 1}, route, target);
}

int main(void)
{
    OuterSSHError denied = {.domain = OUTERSSH_ERROR_SESSION,
        .code = OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE, .ssh_channel_open_reason = 1};
    assert(outersshpriv_proxy_reply_status_for_error(denied) == PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED);
    denied.ssh_channel_open_reason = 2;
    assert(outersshpriv_proxy_reply_status_for_error(denied) == PROXY_SOCKS_REPLY_CONNECTION_REFUSED);
    OuterSSHError not_listening = {.domain = OUTERSSH_ERROR_SESSION, .code = OUTERSSH_SESSION_ERROR_NOT_LISTENING};
    assert(outersshpriv_proxy_reply_status_for_error(not_listening) == PROXY_SOCKS_REPLY_CONNECTION_REFUSED);

    pool.pending_operations = 0;
    pool._queue = ssh_test_control_queue_create("relay-flow-test");
    pool._queue = pool._queue;
    controller = (SSHProxyConnection){&test_server, &pool, 1};
    test_server.queue = pool._queue;
    test_server.reactor = (ProxyReactor *)&controller;
    test_server.frontend = &test_server;
    testing_forwarding_denial = true;
    for (unsigned reason = 0; reason <= 3; reason++) {
        for (unsigned socket_route = 0; socket_route <= 1; socket_route++) {
            ProxyConnectionRoute destination = {.kind = socket_route ? PROXY_CONNECTION_ROUTE_UNIX_SOCKET : PROXY_CONNECTION_ROUTE_TCP};
            OuterSSHError error = {.domain = OUTERSSH_ERROR_SESSION,
                .code = OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE, .ssh_channel_open_reason = reason};
            ProxyReactorPendingConnectionHandle handle = {.generation = 1};
            outersshpriv_proxy_fail_connection(controller, handle, destination, error);
            assert(outersshpriv_proxy_pending_connection_for_handle(test_server.reactor, handle)->forwarding_denied ==
                (!socket_route && reason == 1));
        }
    }
    for (unsigned socket_route = 0; socket_route <= 1; socket_route++) {
        ProxyConnectionRoute destination = {.kind = socket_route ? PROXY_CONNECTION_ROUTE_UNIX_SOCKET : PROXY_CONNECTION_ROUTE_TCP};
        memcpy(destination.unix_socket.path, nothing_listening_path, sizeof(nothing_listening_path));
        destination.unix_socket.path_length = sizeof(nothing_listening_path) - 1;
        route = destination;
        listener_active = true;
        outersshpriv_proxy_fail_connection(controller, (ProxyReactorPendingConnectionHandle){.generation = 1},
            destination, not_listening);
        listener_active = false;
        assert(nothing_listening_reports == socket_route);
    }
    route = (ProxyConnectionRoute){0};
    diagnostic_count = 0;
    testing_forwarding_denial = false;
    pool._nextRelayIdentifier = 1;

    controller.proxy_generation = 1;
    reactor_queue = ssh_test_control_queue_create("relay-reactor-test");
    finished = ssh_test_semaphore_create(0);
    otqueue_async(pool._queue, NULL, run_stage);
    assert(ssh_test_semaphore_wait(finished,
        10 * NSEC_PER_SEC) == 0);
    assert(diagnostic_count > 0);
    ssh_test_semaphore_destroy(finished);
    otqueue_release(reactor_queue);
    otqueue_release(pool._queue);
    puts("PASS: relay ownership, retries, controller/connection cancellation, bridge fallback, and socket attachment");
    return 0;
}

void outersshpriv_proxy_connection_begin_work(SSHProxyConnection connection)
{
    outersshpriv_session_pool_begin_operation(connection.pool);
}
void outersshpriv_proxy_connection_end_work(SSHProxyConnection connection)
{
    outersshpriv_session_pool_end_operation(connection.pool);
}
bool outersshpriv_proxy_connection_is_active(SSHProxyConnection connection)
{
    return outersshpriv_proxy_active_connection(connection).pool != NULL;
}
