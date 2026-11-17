#include "SSHTestSupport.h"
#include "platform/OTSocket.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include "ProxyReactorInternal.h"

enum {
    HANDOFF,
    CANCEL_HANDOFF,
    ADDRESS_FALLBACK,
    WRITE_CONTEXT_FAILURE,
    WRITE_SOURCE_FAILURE,
    TIMER_SOURCE_FAILURE,
    TIMER_CONTEXT_FAILURE,
    INVALIDATE_DURING_HANDOFF,
    CANCEL_ADDRESS_FALLBACK,
    CANCEL_PENDING_ERROR,
    CANCEL_DURING_DNS,
    DNS_FAILURE,
    RETRY_SUCCEEDS,
    RETRY_DNS_FAILURE,
    RETRY_CONNECTION_FAILURE,
    RETRY_EXHAUSTED,
    SCENARIO_COUNT
};
static unsigned scenario;
static unsigned completions;
static unsigned connect_attempts;
static unsigned resolutions;
static unsigned context_allocations;
static otsocket_t watched_socket;
static otsocket_t peer_socket;
static bool destroy_requested;
static ProxyReactor *reactor;
static ProxyReactorTCPConnectHandle handle;
static otqueue_t queue;
static ssh_test_semaphore_t finished;
static ssh_test_semaphore_t allow_resolution;

static int test_connect(otsocket_t socket, const struct sockaddr *address, socklen_t length);
static int test_resolve(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **out);
static void test_free_addresses(struct addrinfo *addresses);
static otsource_t test_source_create(otsource_type_t type, uintptr_t value, otqueue_t queue);
static ProxySourceContext *test_context_create(ProxyReactor *reactor, otsource_t source);
#define otsocket_connect test_connect
#define getaddrinfo test_resolve
#define freeaddrinfo test_free_addresses
#define otsource_create test_source_create
#define outersshpriv_proxy_reactor_create_source_context test_context_create
#include "ProxyConnect.c"
#undef otsocket_connect
#undef getaddrinfo
#undef freeaddrinfo
#undef otsource_create
#undef outersshpriv_proxy_reactor_create_source_context

static void run_scenario(void *context);
static void verify_scenario(void *context);

static struct addrinfo *make_address(void)
{
    struct addrinfo *info = calloc(1, sizeof(*info));
    struct sockaddr_in *address = calloc(1, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(12345);
    address->sin_addr.s_addr = htonl(scenario >= RETRY_SUCCEEDS ? 0x0a000001 : INADDR_LOOPBACK);
    info->ai_family = AF_INET;
    info->ai_socktype = SOCK_STREAM;
    info->ai_protocol = IPPROTO_TCP;
    info->ai_addrlen = sizeof(*address);
    info->ai_addr = (struct sockaddr *)address;
    return info;
}

static int test_resolve(const char *host, const char *service, const struct addrinfo *hints, struct addrinfo **out)
{
    assert(strcmp(host, "test-host") == 0 && strcmp(service, "12345") == 0);
    assert(hints->ai_socktype == SOCK_STREAM);
    resolutions++;
    if (scenario == CANCEL_DURING_DNS) {
        assert(ssh_test_semaphore_wait(allow_resolution,
            2 * NSEC_PER_SEC) == 0);
    }
    if (scenario == DNS_FAILURE || (scenario == RETRY_DNS_FAILURE && resolutions == 2)) {
        return EAI_NONAME;
    }
    *out = make_address();
    return 0;
}

static void test_free_addresses(struct addrinfo *addresses)
{
    while (addresses != NULL) {
        struct addrinfo *next = addresses->ai_next;
        free(addresses->ai_addr);
        free(addresses);
        addresses = next;
    }
    if (scenario == CANCEL_DURING_DNS) {
        otqueue_async(queue, NULL, verify_scenario);
    }
}

static int test_connect(otsocket_t socket, const struct sockaddr *address, socklen_t length)
{
    (void)socket;
    assert(address->sa_family == AF_INET && length == sizeof(struct sockaddr_in));
    connect_attempts++;
    if (scenario == RETRY_SUCCEEDS && connect_attempts == 2) {
        return 0;
    } else if (scenario == RETRY_CONNECTION_FAILURE && connect_attempts == 2) {
        errno = ECONNREFUSED;
    } else if (scenario >= RETRY_SUCCEEDS) {
        errno = ENETUNREACH;
    } else {
        errno = ECONNREFUSED;
    }
    return -1;
}

static otsource_t test_source_create(otsource_type_t type, uintptr_t value, otqueue_t target_queue)
{
    if ((scenario == WRITE_SOURCE_FAILURE && type == OTSOURCE_TYPE_WRITE) ||
        (scenario == TIMER_SOURCE_FAILURE && type == OTSOURCE_TYPE_TIMER)) {
        return NULL;
    }
    return otsource_create(type, value, target_queue);
}

static ProxySourceContext *test_context_create(ProxyReactor *value, otsource_t source)
{
    context_allocations++;
    if ((scenario == WRITE_CONTEXT_FAILURE && context_allocations == 1) ||
        (scenario == TIMER_CONTEXT_FAILURE && context_allocations == 2)) {
        return NULL;
    }
    return outersshpriv_proxy_reactor_create_source_context(value, source);
}

void outersshpriv_session_pool_tcp_connected(SSHSessionCreationOperation *operation, otsocket_t socket)
{
    otqueue_assert(queue);
    assert(operation == (SSHSessionCreationOperation *)reactor);
    assert(completions++ == 0);
    assert(!outersshpriv_proxy_reactor_cancel_tcp_connect(reactor, handle));
    assert(scenario == HANDOFF || scenario == RETRY_SUCCEEDS);
    assert(socket >= 0);
#if !defined(_WIN32)
    assert((fcntl(socket, F_GETFL) & O_NONBLOCK) == 0);
#endif
    if (scenario == HANDOFF) {
        assert(socket == watched_socket);
        assert(otsocket_write(socket, "x", 1) == 1);
        char byte;
        assert(otsocket_read(peer_socket, &byte, 1) == 1 && byte == 'x');
    }
    otsocket_close(socket);
    if (watched_socket >= 0) {
        assert(!ssh_test_socket_is_open(watched_socket));
    }
    otqueue_async(queue, NULL, verify_scenario);
}

void outersshpriv_session_pool_tcp_connect_failed(SSHSessionCreationOperation *operation, OuterSSHError error)
{
    otqueue_assert(queue);
    assert(operation == (SSHSessionCreationOperation *)reactor);
    assert(completions++ == 0);
    assert(!outersshpriv_proxy_reactor_cancel_tcp_connect(reactor, handle));
    assert(error.domain == OUTERSSH_ERROR_SESSION);
    if (scenario == CANCEL_HANDOFF || scenario == CANCEL_ADDRESS_FALLBACK ||
        scenario == CANCEL_PENDING_ERROR || scenario == INVALIDATE_DURING_HANDOFF ||
        scenario == CANCEL_DURING_DNS) {
        assert(error.code == OUTERSSH_SESSION_ERROR_CANCELLED);
        assert(strcmp(error.message, "The SSH operation was cancelled.") == 0);
    } else if (scenario == DNS_FAILURE || (scenario == RETRY_DNS_FAILURE && resolutions == 2)) {
        assert(error.code == OUTERSSH_SESSION_ERROR_UNAVAILABLE);
        char expected[256];
        snprintf(expected, sizeof(expected), "Failed to resolve test-host:12345: %s (%d).",
            gai_strerror(EAI_NONAME), (int)EAI_NONAME);
        if (strcmp(error.message, expected) != 0) {
            fprintf(stderr, "Scenario %u: expected [%s], received [%s]\n", scenario, expected, error.message);
            abort();
        }
    } else {
        assert(error.code == OUTERSSH_SESSION_ERROR_UNAVAILABLE);
        int expected_detail = scenario == ADDRESS_FALLBACK ? ECONNREFUSED :
            scenario >= RETRY_SUCCEEDS ? ENETUNREACH : ENOMEM;
        assert(error.system_error_code == expected_detail);
        char expected[256];
        const char *address = scenario >= RETRY_SUCCEEDS ? "10.0.0.1:12345" : "127.0.0.1:12345";
        snprintf(expected, sizeof(expected), "Failed to connect to test-host:12345 via %s: %s (errno %d).",
            address, strerror(expected_detail), expected_detail);
        if (strcmp(error.message, expected) != 0) {
            fprintf(stderr, "Scenario %u: expected [%s], received [%s]\n", scenario, expected, error.message);
            abort();
        }
    }
    if (watched_socket >= 0) {
        assert(!ssh_test_socket_is_open(watched_socket));
    }
    if (scenario != CANCEL_DURING_DNS) {
        otqueue_async(queue, NULL, verify_scenario);
    }
}




static void run_scenario(void *context)
{
    (void)context;
    completions = connect_attempts = resolutions = context_allocations = 0;
    watched_socket = peer_socket = -1;
    destroy_requested = false;
    reactor = outersshpriv_proxy_reactor_create(queue);
    if (scenario >= CANCEL_DURING_DNS) {
        char *host = malloc(9);
        assert(host != NULL);
        memcpy(host, "test-host", 9);
        handle = outersshpriv_proxy_reactor_connect_tcp(reactor, host, 9, 12345,
            (SSHSessionCreationOperation *)reactor);
        free(host);
        assert(handle.generation != 0);
        if (scenario == CANCEL_DURING_DNS) {
            assert(outersshpriv_proxy_reactor_cancel_tcp_connect(reactor, handle));
            assert(completions == 1);
            outersshpriv_proxy_reactor_destroy(reactor, NULL, NULL);
            destroy_requested = true;
            ssh_test_semaphore_signal(allow_resolution);
        }
        return;
    }
    assert(reserve_connect_slots(reactor, 1));
    reactor->connect_slot_count = 1;
    handle = (TCPConnectHandle){.generation = 1};
    otsocket_t sockets[2];
    assert(ssh_test_socket_pair(sockets) == 0);
    watched_socket = sockets[0];
    peer_socket = sockets[1];
    assert(otsocket_set_nonblocking(watched_socket, true) == 0);
    TCPConnectSlot *connection = &reactor->connect_slots[0];
    *connection = (TCPConnectSlot){
        .generation = 1, .host = malloc(9), .host_length = 9, .port = 12345,
        .last_address = "127.0.0.1:12345",
        .operation = (SSHSessionCreationOperation *)reactor,
        .socket = watched_socket, .is_active = true,
        .attempt_generation = 1, .addresses = make_address()
    };
    assert(connection->host != NULL);
    memcpy(connection->host, "test-host", 9);
    connection->current_address = connection->addresses;
    if (scenario == ADDRESS_FALLBACK || scenario == CANCEL_ADDRESS_FALLBACK) {
        connection->addresses->ai_next = make_address();
    }
    bool started = start_tcp_connect_wait(reactor, handle);
    if (scenario >= WRITE_CONTEXT_FAILURE && scenario <= TIMER_CONTEXT_FAILURE) {
        assert(!started);
    } else {
        assert(started);
        if (scenario == ADDRESS_FALLBACK || scenario == CANCEL_ADDRESS_FALLBACK) {
            finish_current_tcp_address(reactor, handle, ETIMEDOUT);
        } else if (scenario == CANCEL_PENDING_ERROR) {
            complete_tcp_connect_with_error(reactor, connection, (TCPConnectError){
                .code = PROXY_TCP_CONNECTION_FAILED,
                .detail = ETIMEDOUT,
            });
        } else {
            complete_tcp_connect_with_socket(reactor, connection);
        }
        if (scenario == CANCEL_HANDOFF || scenario == CANCEL_ADDRESS_FALLBACK ||
            scenario == CANCEL_PENDING_ERROR) {
            assert(outersshpriv_proxy_reactor_cancel_tcp_connect(reactor, handle));
            assert(!outersshpriv_proxy_reactor_cancel_tcp_connect(reactor, handle));
        } else if (scenario == INVALIDATE_DURING_HANDOFF) {
            outersshpriv_proxy_reactor_invalidate(reactor);
            outersshpriv_proxy_reactor_destroy(reactor, NULL, NULL);
            destroy_requested = true;
        }
    }
    if (scenario == WRITE_CONTEXT_FAILURE || scenario == WRITE_SOURCE_FAILURE) {
        assert(completions == 1);
    } else {
        assert(completions == 0 && connection->cancelling_write_source);
        assert(ssh_test_socket_is_open(watched_socket));
        assert(connect_attempts == 0);
        void (*continuation)(ProxyReactor *, TCPConnectSlot *) = connection->after_socket_watch;
        ProxySourceContext writable = {
            .reactor = reactor, .connection = handle,
            .attempt_generation = connection->attempt_generation
        };
        tcp_connect_socket_writable(&writable);
        ProxySourceContext timeout = {
            .reactor = reactor, .connection = handle,
            .attempt_generation = connection->attempt_generation
        };
        tcp_connect_timed_out(&timeout);
        assert(completions == 0 && connection->after_socket_watch == continuation);
        // A cancellation handler must resolve its handle after array relocation.
        assert(reserve_connect_slots(reactor, 32));
    }
}

static void verify_scenario(void *context)
{
    (void)context;
    assert(completions == 1);
    if (!destroy_requested) assert(connect_for_handle(reactor, handle) == NULL);
    if (scenario >= RETRY_SUCCEEDS) {
#if defined(__APPLE__)
        assert(connect_attempts == (scenario == RETRY_DNS_FAILURE ? 1u :
            scenario == RETRY_EXHAUSTED ? 3u : 2u));
        assert(resolutions == (scenario == RETRY_EXHAUSTED ? 3u : 2u));
#else
        assert(connect_attempts == 1);
        assert(resolutions == 1);
#endif
    } else {
        assert(connect_attempts == (scenario == ADDRESS_FALLBACK ? 1u : 0u));
    }
    if (peer_socket >= 0) {
        char byte;
        assert(otsocket_read(peer_socket, &byte, 1) == 0);
        otsocket_close(peer_socket);
    }
    if (!destroy_requested) {
        outersshpriv_proxy_reactor_destroy(reactor, NULL, NULL);
    }
    if (++scenario == SCENARIO_COUNT) {
        ssh_test_semaphore_signal(finished);
    } else {
        otqueue_async(queue, NULL, run_scenario);
    }
}

int main(void)
{
    queue = ssh_test_queue_create("tcp-flow-test");
    finished = ssh_test_semaphore_create(0);
    allow_resolution = ssh_test_semaphore_create(0);
    otqueue_async(queue, NULL, run_scenario);
    assert(ssh_test_semaphore_wait(finished,
        10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(allow_resolution);
    ssh_test_semaphore_destroy(finished);
    otqueue_release(queue);
    puts("PASS: TCP handoff, cancellation, descriptor lifetime, address fallback, DNS races, and platform-specific local-network retries");
    return 0;
}

void outersshpriv_socket_service_stop(OuterSSHSessionPool *pool)
{
    (void)pool;
}
