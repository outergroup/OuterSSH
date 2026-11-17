#include "SSHTestSupport.h"
#include "platform/OTSocket.h"
#include "ProxyReactorInternal.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum {
    SLOT_ALLOCATION_FAILURE,
    INDEX_ALLOCATION_FAILURE,
    USERNAME_ALLOCATION_FAILURE,
    PASSWORD_ALLOCATION_FAILURE,
    CONTEXT_ALLOCATION_FAILURE,
    SOURCE_CREATION_FAILURE,
    SOCKET_CREATION_FAILURE,
    BIND_FAILURE,
    LISTEN_FAILURE,
    ADDRESS_FAILURE,
    RAPID_RESTART,
    RELOCATE_SLOTS,
    DESTROY_WITH_HANDSHAKE,
    INVALID_INPUT,
    SCENARIO_COUNT
};
static ProxySourceContext *latest_context;
static unsigned scenario, allocations, live_contexts, source_creations, cancellations;
static otsocket_t peers[16], sockets[16];
static size_t socket_count;
static bool started, verification_queued, destroy_requested, destruction_completed;
static ProxyReactor *reactor;
static otqueue_t queue;
static ssh_test_semaphore_t finished;

static void *test_calloc(size_t count, size_t size);
static void *test_malloc(size_t size);
static char *test_strdup(const char *string);
static void test_free(void *pointer);
static ProxySourceContext *contexts[32];
static otsource_t test_source_create(otsource_type_t type, uintptr_t handle, otqueue_t target);
static otsocket_t test_socket(int domain, int type, int protocol);
static int test_bind(otsocket_t socket, const struct sockaddr *address, socklen_t length);
static int test_listen(otsocket_t socket, int backlog);
static int test_getsockname(otsocket_t socket, struct sockaddr *address, socklen_t *length);
static otsocket_t test_accept(otsocket_t socket, struct sockaddr *address, socklen_t *length);
#define free test_free
#define calloc test_calloc
#define malloc test_malloc
#define strdup test_strdup
#define otsource_create test_source_create
#define otsocket_create(...) test_socket(__VA_ARGS__)
#define otsocket_bind test_bind
#define otsocket_listen test_listen
#define otsocket_getsockname test_getsockname
#define otsocket_accept test_accept
#include "ProxyReactor.c"
#define set_close_on_exec socks_set_close_on_exec
#include "ProxyPendingConnections.c"
#include "ProxySOCKSHandshake.c"
#undef set_close_on_exec
#undef free
#undef calloc
#undef malloc
#undef strdup
#undef otsource_create
#undef otsocket_create
#undef otsocket_bind
#undef otsocket_listen
#undef otsocket_getsockname
#undef otsocket_accept

static void verify_scenario(void *context);

static void maybe_verify(void)
{
    if (started && live_contexts == 0 && !verification_queued) {
        verification_queued = true;
        otqueue_async(queue, NULL, verify_scenario);
    }
}

static bool fail_allocation(void)
{
    allocations++;
    return scenario <= CONTEXT_ALLOCATION_FAILURE && allocations == scenario + 1;
}

static void *test_calloc(size_t count, size_t size)
{
    if (size == sizeof(ProxyReactor)) return calloc(count, size);
    if (fail_allocation()) return NULL;
    void *pointer = calloc(count, size);
    if (pointer != NULL && count == 1 && size == sizeof(ProxySourceContext)) {
        assert(live_contexts < sizeof(contexts) / sizeof(contexts[0]));
        contexts[live_contexts++] = pointer;
        latest_context = pointer;
    }
    return pointer;
}

static void test_free(void *pointer)
{
    for (unsigned i = 0; i < live_contexts; i++) {
        if (contexts[i] != pointer) continue;
        ProxySourceContext *context = pointer;
        if (context->socket_to_close >= 0)
            assert(!ssh_test_socket_is_open(context->socket_to_close));
        if (context->source != NULL) cancellations++;
        contexts[i] = contexts[--live_contexts];
        maybe_verify();
        break;
    }
    free(pointer);
}

static void *test_malloc(size_t size)
{
    return fail_allocation() ? NULL : malloc(size);
}

static char *test_strdup(const char *string)
{
    return fail_allocation() ? NULL : strdup(string);
}

static otsource_t test_source_create(otsource_type_t type, uintptr_t handle, otqueue_t target)
{
    assert(live_contexts > 0);
    if (scenario == SOURCE_CREATION_FAILURE) {
        return NULL;
    }
    source_creations++;
    return otsource_create(type, handle, target);
}

static otsocket_t make_socket_pair(void)
{
    otsocket_t pair[2];
    assert(socket_count < sizeof(sockets) / sizeof(*sockets));
    assert(ssh_test_socket_pair(pair) == 0);
    sockets[socket_count] = pair[0];
    peers[socket_count++] = pair[1];
    return pair[0];
}

static otsocket_t test_socket(int domain, int type, int protocol)
{
    assert(domain == AF_INET && type == SOCK_STREAM && protocol == 0);
    if (scenario == SOCKET_CREATION_FAILURE) {
        errno = EMFILE;
        return -1;
    }
    return make_socket_pair();
}

static int test_bind(otsocket_t socket, const struct sockaddr *address, socklen_t length)
{
    (void)socket;
    assert(address->sa_family == AF_INET && length == sizeof(struct sockaddr_in));
    assert(((const struct sockaddr_in *)address)->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    if (scenario == BIND_FAILURE) {
        errno = EADDRINUSE;
        return -1;
    }
    return 0;
}

static int test_listen(otsocket_t socket, int backlog)
{
    (void)socket;
    assert(backlog == 128);
    if (scenario == LISTEN_FAILURE) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return 0;
}

static int test_getsockname(otsocket_t socket, struct sockaddr *address, socklen_t *length)
{
    (void)socket;
    assert(*length == sizeof(struct sockaddr_in));
    if (scenario == ADDRESS_FAILURE) {
        errno = EIO;
        return -1;
    }
    ((struct sockaddr_in *)address)->sin_port = htons(12345);
    return 0;
}

static otsocket_t test_accept(otsocket_t socket, struct sockaddr *address, socklen_t *length)
{
    (void)socket; (void)address; (void)length;
    assert(false);
    return -1;
}

void outersshpriv_proxy_reactor_cancel_all_tcp_connects(ProxyReactor *value)
{
    assert(value == reactor);
}




static void verify_scenario(void *context);

static void reactor_destroyed(void *context)
{
    otqueue_assert(queue);
    assert(!destruction_completed);
    destruction_completed = true;
    otqueue_async(queue, context, verify_scenario);
}

static void verify_scenario(void *context)
{
    (void)context;
    if (reactor == NULL) return;
    if (!destruction_completed) {
        if (!destroy_requested) {
            destroy_requested = true;
            outersshpriv_proxy_reactor_destroy(reactor, reactor_destroyed, NULL);
        }
        return;
    }
    assert(live_contexts == 0 && cancellations == source_creations);
    for (size_t i = 0; i < socket_count; i++) {
        assert(!ssh_test_socket_is_open(sockets[i]));
        otsocket_close(peers[i]);
    }
    reactor = NULL;
    ssh_test_semaphore_signal(finished);
}

static void run_scenario(void *context)
{
    (void)context;
    allocations = live_contexts = source_creations = cancellations = 0;
    socket_count = 0;
    started = verification_queued = destroy_requested = destruction_completed = false;
    reactor = outersshpriv_proxy_reactor_create(queue);
    reactor->server = (SSHForwarder *)reactor;
    ProxyReactorListenerHandle handle = {.generation = 99};
    int port = 99;
    OuterSSHError result = outersshpriv_proxy_reactor_create_listener(
        reactor, &handle, scenario == INVALID_INPUT ? -1 : 0,
        &port, "username", sizeof("username") - 1, "password", sizeof("password") - 1, true, 5000);
    if (scenario <= ADDRESS_FAILURE || scenario == INVALID_INPUT) {
        int32_t expected =
            scenario == BIND_FAILURE ? OUTERSSH_PROXY_ERROR_BIND_FAILED
            : scenario == LISTEN_FAILURE ? OUTERSSH_PROXY_ERROR_LISTEN_FAILED
            : scenario == ADDRESS_FAILURE ? OUTERSSH_PROXY_ERROR_LISTENER_ADDRESS_LOOKUP_FAILED
            : OUTERSSH_PROXY_ERROR_LISTEN_SOCKET_CREATION_FAILED;
        const char *expected_message = scenario == BIND_FAILURE
            ? "Failed to bind the SOCKS proxy listener."
            : scenario == LISTEN_FAILURE ? "Failed to listen on the SOCKS proxy socket."
            : scenario == ADDRESS_FAILURE ? "Failed to resolve the SOCKS proxy listener address."
            : "Failed to create the SOCKS proxy listener.";
        int expected_detail = scenario <= SOURCE_CREATION_FAILURE ? ENOMEM
            : scenario == SOCKET_CREATION_FAILURE ? EMFILE
            : scenario == BIND_FAILURE ? EADDRINUSE
            : scenario == LISTEN_FAILURE ? EOPNOTSUPP
            : scenario == INVALID_INPUT ? EINVAL : EIO;
        assert(result.domain == OUTERSSH_ERROR_PROXY);
        assert(result.code == expected && result.system_error_code == expected_detail);
        assert(strcmp(result.message, expected_message) == 0);
        assert(port == 0 && handle.generation == 0);
        assert(source_creations == 0 && live_contexts == 0);
        assert(reactor->listener_slot_count == 0);
        started = true;
        maybe_verify();
        return;
    }
    assert(result.domain == OUTERSSH_ERROR_NONE);
    assert(port == 12345 && result.system_error_code == 0 && handle.generation != 0);
    ListenerSlot *listener = outersshpriv_proxy_reactor_listener_for_handle(reactor, handle);
    assert(listener != NULL && listener->socket == sockets[0]);
#if !defined(_WIN32)
    assert((fcntl(listener->socket, F_GETFD) & FD_CLOEXEC) != 0);
#endif
#if !defined(_WIN32)
    assert((fcntl(listener->socket, F_GETFL) & O_NONBLOCK) != 0);
#endif
    ProxySourceContext stale = *latest_context;
    if (scenario == RAPID_RESTART) {
        assert(outersshpriv_proxy_reactor_remove_listener(reactor, handle));
        assert(ssh_test_socket_is_open(sockets[0]) && cancellations == 0);
        ProxyReactorListenerHandle next;
        assert(outersshpriv_proxy_reactor_create_listener(reactor, &next, 0, &port,
            "new-user", sizeof("new-user") - 1, "new-pass", sizeof("new-pass") - 1, true, 5000).domain ==
            OUTERSSH_ERROR_NONE);
        assert(next.index == handle.index && next.generation != handle.generation);
        assert(sockets[0] != sockets[1]);
        assert(!outersshpriv_proxy_reactor_remove_listener(reactor, handle));
        listener_socket_readable(&stale);
        assert(outersshpriv_proxy_reactor_listener_for_handle(reactor, next) != NULL);
        assert(outersshpriv_proxy_reactor_remove_listener(reactor, next));
    } else if (scenario == RELOCATE_SLOTS) {
        for (int i = 0; i < 6; i++) {
            ProxyReactorListenerHandle next;
            assert(outersshpriv_proxy_reactor_create_listener(reactor, &next, 0, &port,
                "u", sizeof("u") - 1, "p", sizeof("p") - 1, true, 5000).domain ==
                OUTERSSH_ERROR_NONE);
        }
        assert(outersshpriv_proxy_reactor_remove_listener(reactor, handle));
        listener_socket_readable(&stale);
    } else {
        otsocket_t socket = make_socket_pair();
        assert(otsocket_set_nonblocking(socket, true) == 0);
        start_socks5_handshake(reactor, handle, socket);
        assert(otsocket_write(peers[1], "\5", 1) == 1);
        process_handshake_reads(reactor, (SOCKSHandshakeHandle){.generation = 1});
        assert(reactor->pending_connections[0].socks->read_offset == 1);
    }
    outersshpriv_proxy_reactor_invalidate(reactor);
    listener_socket_readable(&stale);
    for (size_t i = 0; i < socket_count; i++) {
        assert(ssh_test_socket_is_open(sockets[i]));
    }
    assert(cancellations == 0);
    outersshpriv_proxy_reactor_destroy(reactor, reactor_destroyed, NULL);
    destroy_requested = true;
    started = true;
}

int main(void)
{
    queue = ssh_test_queue_create("test.listener.flow");
    finished = ssh_test_semaphore_create(0);
    for (scenario = 0; scenario < SCENARIO_COUNT; scenario++) {
        otqueue_async(queue, NULL, run_scenario);
        assert(ssh_test_semaphore_wait(finished,
            5 * NSEC_PER_SEC) == 0);
    }
    ssh_test_semaphore_destroy(finished);
    otqueue_release(queue);
    puts("PASS: listener allocation failures, socket setup, restart, stale events, and teardown");
    return 0;
}

bool outersshpriv_proxy_server_origin_for_credentials(SSHForwarder *server,
    const unsigned char *username, size_t username_length, const unsigned char *password, size_t password_length,
    char **origin, size_t *origin_length)
{
    (void)server; (void)username; (void)username_length; (void)password; (void)password_length;
    *origin = NULL;
    *origin_length = 0;
    return false;
}

void outersshpriv_proxy_server_pending_connection(SSHForwarder *server,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route)
{
    (void)server; (void)connection; (void)route;
    abort();
}
