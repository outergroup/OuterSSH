#include "SSHTestSupport.h"
#include "SSHProxyAddress.h"
#include "platform/OTSocket.h"
#include "ProxyReactorInternal.h"
#include "SSHProxyState.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    HANDOFF,
    PARTIAL_REPLY,
    CANCEL_HANDOFF,
    DESTROY_HANDOFF,
    DISCONNECT_DURING_PREPARATION,
    READ_CONTEXT_FAILURE,
    READ_SOURCE_FAILURE,
    TIMER_CONTEXT_FAILURE,
    TIMER_SOURCE_FAILURE,
    WRITE_CONTEXT_FAILURE,
    WRITE_SOURCE_FAILURE,
    MULTIPLE_WRITE_GENERATIONS,
    CANCEL_PARTIAL_REPLY,
    TIMEOUT_PARTIAL_REPLY,
    DELAYED_TARGET_HANDOFF,
    ASYNC_PARTIAL_REPLY,
    NO_AUTH_HANDOFF,
    NO_AUTH_BOTH_METHODS,
    NO_AUTH_PASSWORD_ONLY,
    REQUIRED_AUTH_NO_AUTH,
    BAD_PASSWORD,
    ORIGIN_HANDOFF,
    DIRECT_HANDOFF,
    DIRECT_CANCEL_HANDOFF,
    DIRECT_FAILURE,
    SCENARIO_COUNT
};
static void socket_transferred(void *context, otsocket_t socket);
static int transfer_context;
static unsigned rejected_transfers;
static void transfer_rejected(void *context, otsocket_t socket)
{
    assert(context == &transfer_context && socket == -1);
    rejected_transfers++;
}
static unsigned scenario, context_allocations, live_contexts, completions, direct_completions;
static bool started, verification_queued, destroy_requested;
static bool continuation_queued;
static bool block_writes;
static size_t write_budget;
static otsocket_t browser_socket, watched_socket;
static ProxyReactor *reactor;
static ProxyReactorListenerHandle listener_handle;
static ProxyReactorPendingConnectionHandle handle;
static otqueue_t queue;
static ssh_test_semaphore_t finished;

static ssize_t test_send(otsocket_t socket, const void *bytes, size_t count, int flags);
static otsource_t test_source_create(otsource_type_t type,
    uintptr_t value, otqueue_t target);
static ProxySourceContext *test_context_create(
    ProxyReactor *value, otsource_t source);
static void test_context_cancelled(void *context);
#define otsocket_send test_send
#define otsource_create test_source_create
#define outersshpriv_proxy_reactor_create_source_context test_context_create
#define outersshpriv_proxy_reactor_source_cancelled test_context_cancelled
#include "ProxyPendingConnections.c"
#include "ProxySOCKSHandshake.c"
#undef otsocket_send
#undef otsource_create
#undef outersshpriv_proxy_reactor_create_source_context
#undef outersshpriv_proxy_reactor_source_cancelled

static void verify_scenario(void *context);
static void resume_preparation_or_reply(void *context);

static void maybe_verify(void)
{
    if (started && live_contexts == 0 && !verification_queued) {
        verification_queued = true;
        otqueue_async(queue, NULL, verify_scenario);
    }
}

static ssize_t test_send(otsocket_t socket, const void *bytes, size_t count, int flags)
{
    if (block_writes) {
        if (write_budget == 0) {
            errno = EAGAIN;
            return -1;
        }
        if (count > write_budget) {
            count = write_budget;
        }
        write_budget -= count;
    }
    return otsocket_send(socket, bytes, count, flags);
}

static otsource_t test_source_create(otsource_type_t type,
    uintptr_t value, otqueue_t target)
{
    if ((scenario == READ_SOURCE_FAILURE && type == OTSOURCE_TYPE_READ) ||
        (scenario == TIMER_SOURCE_FAILURE && type == OTSOURCE_TYPE_TIMER) ||
        (scenario == WRITE_SOURCE_FAILURE && type == OTSOURCE_TYPE_WRITE)) {
        return NULL;
    }
    return otsource_create(type, value, target);
}

static ProxySourceContext *test_context_create(
    ProxyReactor *value, otsource_t source)
{
    context_allocations++;
    if ((scenario == READ_CONTEXT_FAILURE && context_allocations == 1) ||
        (scenario == TIMER_CONTEXT_FAILURE && context_allocations == 2) ||
        (scenario == WRITE_CONTEXT_FAILURE && context_allocations == 3)) {
        return NULL;
    }
    ProxySourceContext *context =
        outersshpriv_proxy_reactor_create_source_context(value, source);
    assert(context != NULL);
    live_contexts++;
    return context;
}

static void test_context_cancelled(void *context)
{
    assert(live_contexts > 0);
    live_contexts--;
    outersshpriv_proxy_reactor_source_cancelled(context);
    if (started && !destroy_requested && !continuation_queued &&
        reactor->pending_connections[handle.index].is_active &&
        (scenario == DELAYED_TARGET_HANDOFF || scenario == ASYNC_PARTIAL_REPLY)) {
        continuation_queued = true;
        otqueue_async(queue, NULL, resume_preparation_or_reply);
    }
    maybe_verify();
}

static void resume_preparation_or_reply(void *context)
{
    (void)context;
    ProxyPendingConnection *slot = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    assert(slot != NULL && completions == 0);
    assert(ssh_test_socket_is_open(watched_socket));
    if (scenario == DELAYED_TARGET_HANDOFF) {
        assert(slot->uncancelled_socket_source_count == 0);
        outersshpriv_proxy_reactor_complete_pending_connection(
            reactor, handle, socket_transferred, &transfer_context);
        assert(completions == 1);
    } else {
        assert(slot->phase == PROXY_PENDING_REPLYING);
        assert(slot->uncancelled_socket_source_count == 1);
        block_writes = false;
    }
}

void outersshpriv_proxy_reactor_cancel_all_tcp_connects(ProxyReactor *value)
{
    assert(value == reactor);
}

bool outersshpriv_proxy_server_origin_for_credentials(SSHForwarder *server,
    const unsigned char *username, size_t username_length, const unsigned char *password, size_t password_length,
    char **origin, size_t *origin_length)
{
    assert(server == (SSHForwarder *)reactor);
    if (username_length != 1 || username[0] != 'o' || password_length != 1 || password[0] != 's') return false;
    *origin = strdup("http://app.example");
    *origin_length = 18;
    return true;
}

void outersshpriv_proxy_server_pending_connection(SSHForwarder *server,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route)
{
    assert(server == (SSHForwarder *)reactor);
    assert(strcmp(route.request.host, "example.com") == 0);
    assert(connection.generation == handle.generation);
    SOCKSHandshake *socks = outersshpriv_proxy_pending_connection_for_handle(reactor, connection)->socks;
    const char *origin;
    size_t origin_length;
    bool has_origin = socks != NULL && outersshpriv_socks_handshake_origin(socks, &origin, &origin_length);
    assert(has_origin == (scenario == ORIGIN_HANDOFF));
    if (has_origin) assert(origin_length == 18 && strcmp(origin, "http://app.example") == 0);
}

static void direct_completed(void *context, ProxySOCKSReplyStatus status, bool forwarding_denied)
{
    assert(context == &transfer_context);
    assert(direct_completions++ == 0);
    assert(forwarding_denied == (scenario == DIRECT_FAILURE));
    assert(status == (scenario == DIRECT_HANDOFF ? PROXY_SOCKS_REPLY_SUCCEEDED
        : scenario == DIRECT_FAILURE ? PROXY_SOCKS_REPLY_CONNECTION_REFUSED : PROXY_SOCKS_REPLY_GENERAL_FAILURE));
    assert(!outersshpriv_proxy_reactor_pending_connection_is_active(reactor, handle));
}

static void socket_transferred(void *context, otsocket_t socket)
{
    assert(context == &transfer_context);
    assert(completions++ == 0);
    ProxyPendingConnection *slot = &reactor->pending_connections[handle.index];
    assert(!slot->is_active && slot->uncancelled_socket_source_count == 0);
    assert(!outersshpriv_proxy_reactor_pending_connection_is_active(reactor, handle));
    if (scenario == DIRECT_HANDOFF) {
        assert(socket == watched_socket);
        char data[5];
        assert(otsocket_read(socket, data, sizeof(data)) == sizeof(data));
        assert(memcmp(data, "early", sizeof(data)) == 0);
        assert(otsocket_set_nonblocking(browser_socket, true) == 0);
        assert(otsocket_read(browser_socket, data, sizeof(data)) == -1);
        assert(errno == EAGAIN || errno == EWOULDBLOCK);
        otsocket_close(socket);
    } else if (scenario == HANDOFF || scenario == ORIGIN_HANDOFF || scenario == PARTIAL_REPLY ||
        scenario == NO_AUTH_HANDOFF || scenario == NO_AUTH_BOTH_METHODS ||
        scenario == MULTIPLE_WRITE_GENERATIONS ||
        scenario == DELAYED_TARGET_HANDOFF || scenario == ASYNC_PARTIAL_REPLY) {
        assert(socket == watched_socket);
        char data[5];
        assert(otsocket_read(socket, data, sizeof(data)) == sizeof(data));
        assert(memcmp(data, "early", sizeof(data)) == 0);
        unsigned char reply[10];
        assert(otsocket_read(browser_socket, reply, sizeof(reply)) == sizeof(reply));
        assert(reply[0] == 5 && reply[1] == PROXY_SOCKS_REPLY_SUCCEEDED);
        otsocket_close(socket);
    } else {
        assert(socket == -1);
    }
    assert(!ssh_test_socket_is_open(watched_socket));
}

static void verify_scenario(void *context)
{
    (void)context;
    assert(live_contexts == 0);
    if (!destroy_requested) {
        assert(!reactor->pending_connections[handle.index].is_active);
        assert(reactor->available_pending_connection_index_count == 1);
        unsigned before = rejected_transfers;
        outersshpriv_proxy_reactor_complete_pending_connection(reactor, handle, transfer_rejected, &transfer_context);
        assert(rejected_transfers == before + 1);
    }
    assert(!ssh_test_socket_is_open(watched_socket));
    bool no_transfer = (scenario >= DISCONNECT_DURING_PREPARATION &&
        scenario <= TIMER_SOURCE_FAILURE) || scenario == NO_AUTH_PASSWORD_ONLY ||
        scenario == REQUIRED_AUTH_NO_AUTH || scenario == BAD_PASSWORD || scenario == DIRECT_FAILURE;
    assert(completions == (no_transfer ? 0u : 1u));
    assert(direct_completions == (scenario >= DIRECT_HANDOFF ? 1u : 0u));
    if (!destroy_requested) {
        outersshpriv_proxy_reactor_destroy(reactor, NULL, NULL);
    }
    if (browser_socket >= 0) {
        otsocket_close(browser_socket);
    }
    ssh_test_semaphore_signal(finished);
}

static void run_scenario(void *context)
{
    (void)context;
    context_allocations = live_contexts = completions = direct_completions = 0;
    started = verification_queued = destroy_requested = block_writes = false;
    continuation_queued = false;
    write_budget = 0;
    reactor = outersshpriv_proxy_reactor_create(queue);
    reactor->server = (SSHForwarder *)reactor;
    reactor->listener_slots = calloc(1, sizeof(*reactor->listener_slots));
    reactor->available_listener_indices = calloc(1, sizeof(size_t));
    reactor->listener_slot_count = reactor->listener_slot_capacity = 1;
    reactor->listener_slots[0] = (ListenerSlot){
        .requires_authentication = scenario != NO_AUTH_HANDOFF &&
            scenario != NO_AUTH_BOTH_METHODS && scenario != NO_AUTH_PASSWORD_ONLY,
        .generation = 1, .socket = -1, .is_active = true,
        .username = (unsigned char *)strdup("u"), .username_length = 1,
        .password = (unsigned char *)strdup("p"), .password_length = 1,
        .pending_connection_timeout_milliseconds = 5000,
    };
    listener_handle = (ProxyReactorListenerHandle){.generation = 1};
    otsocket_t sockets[2];
    assert(ssh_test_socket_pair(sockets) == 0);
    watched_socket = sockets[0];
    browser_socket = sockets[1];
    assert(otsocket_set_nonblocking(watched_socket, true) == 0);
    assert(otsocket_configure_sigpipe(watched_socket) == 0);
    if (scenario >= DIRECT_HANDOFF) {
        handle = (ProxyReactorPendingConnectionHandle){.generation = 1};
        ProxyConnectRequest request = {.host = "example.com", .host_length = 11, .port = 80};
        outersshpriv_proxy_reactor_start_direct_connection(reactor, watched_socket,
            outersshpriv_proxy_resolve_request(request), direct_completed, &transfer_context);
        ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
        assert(pending != NULL && pending->socks == NULL && pending->timeout_timer == NULL);
        if (scenario == DIRECT_FAILURE) {
            pending->forwarding_denied = true;
            assert(outersshpriv_proxy_reactor_fail_pending_connection(reactor, handle, PROXY_SOCKS_REPLY_CONNECTION_REFUSED));
        } else {
            assert(otsocket_write(browser_socket, "early", 5) == 5);
            outersshpriv_proxy_reactor_complete_pending_connection(reactor, handle, socket_transferred, &transfer_context);
            assert(completions == 0 && direct_completions == 0);
            if (scenario == DIRECT_CANCEL_HANDOFF) outersshpriv_proxy_reactor_cancel_all_pending_connections(reactor);
        }
        started = true;
        maybe_verify();
        return;
    }
    start_socks5_handshake(reactor, listener_handle, watched_socket);
    handle = (SOCKSHandshakeHandle){.generation = 1};
    if (scenario >= READ_CONTEXT_FAILURE && scenario <= TIMER_SOURCE_FAILURE) {
        if (scenario >= TIMER_CONTEXT_FAILURE) {
            assert(ssh_test_socket_is_open(watched_socket));
            assert(reactor->pending_connections[0].phase == PROXY_PENDING_CLOSING);
            assert(otsocket_write(browser_socket, "hi", 2) == 2);
            process_handshake_reads(reactor, handle);
            assert(reactor->pending_connections[0].socks->read_offset == 0);
        }
        started = true;
        maybe_verify();
        return;
    }

    // Pipeline negotiation and browser bytes. The handshake must leave the
    // payload untouched for the eventual relay.
    const unsigned char request[] = {
        5, 1, 2, 1, 1, 'u', 1, 'p',
        5, 1, 0, 3, 11, 'e','x','a','m','p','l','e','.','c','o','m', 0, 80,
        'e','a','r','l','y'
    };
    if (scenario == NO_AUTH_PASSWORD_ONLY || scenario == REQUIRED_AUTH_NO_AUTH || scenario == BAD_PASSWORD) {
        unsigned char rejected_request[] = {5, 1, 2, 1, 1, 'u', 1, 'x'};
        size_t count = scenario == BAD_PASSWORD ? sizeof(rejected_request) : 3;
        if (scenario == REQUIRED_AUTH_NO_AUTH) rejected_request[2] = 0;
        assert(otsocket_write(browser_socket, rejected_request, count) == (ssize_t)count);
        process_handshake_reads(reactor, handle);
        unsigned char reply[4];
        size_t reply_count = scenario == BAD_PASSWORD ? 4 : 2;
        assert(otsocket_read(browser_socket, reply, reply_count) == (ssize_t)reply_count);
        assert(reply[0] == 5 && reply[1] == (scenario == BAD_PASSWORD ? 2 : 255));
        if (scenario == BAD_PASSWORD) assert(reply[2] == 1 && reply[3] == 1);
        assert(!outersshpriv_proxy_reactor_pending_connection_is_active(reactor, handle));
        started = true;
        return;
    }
    unsigned char unauthenticated_request[sizeof(request)];
    unsigned char origin_request[sizeof(request)];
    const unsigned char *request_bytes = request;
    if (scenario == ORIGIN_HANDOFF) {
        memcpy(origin_request, request, sizeof(request));
        origin_request[5] = 'o';
        origin_request[7] = 's';
        request_bytes = origin_request;
    }
    size_t request_length = sizeof(request);
    bool no_auth = scenario == NO_AUTH_HANDOFF || scenario == NO_AUTH_BOTH_METHODS;
    if (no_auth) {
        size_t greeting_length = scenario == NO_AUTH_BOTH_METHODS ? 4 : 3;
        unauthenticated_request[0] = 5;
        unauthenticated_request[1] = (unsigned char)(greeting_length - 2);
        unauthenticated_request[2] = 0;
        unauthenticated_request[3] = 2;
        memcpy(unauthenticated_request + greeting_length, request + 8, sizeof(request) - 8);
        request_bytes = unauthenticated_request;
        request_length = greeting_length + sizeof(request) - 8;
    }
    if (scenario == DISCONNECT_DURING_PREPARATION) {
        request_length -= 5;
    }
    assert(otsocket_write(browser_socket, request_bytes, request_length) == (ssize_t)request_length);
    process_handshake_reads(reactor, handle);
    assert(outersshpriv_proxy_reactor_pending_connection_is_active(reactor, handle));
    unsigned char negotiation[4];
    size_t negotiation_length = no_auth ? 2 : 4;
    assert(otsocket_read(browser_socket, negotiation, negotiation_length) == (ssize_t)negotiation_length);
    const unsigned char expected[] = {5, no_auth ? 0 : 2, 1, 0};
    assert(memcmp(negotiation, expected, negotiation_length) == 0);

    if (scenario == DISCONNECT_DURING_PREPARATION) {
        otsocket_close(browser_socket);
        browser_socket = -1;
        process_handshake_reads(reactor, handle);
        assert(!outersshpriv_proxy_reactor_pending_connection_is_active(reactor, handle));
        assert(ssh_test_socket_is_open(watched_socket));
        started = true;
        return;
    }

    ProxyPendingConnection *slot = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    assert(slot->read_socket_source == NULL);
    assert(slot->uncancelled_socket_source_count == 1);
    if (scenario == DELAYED_TARGET_HANDOFF) {
        started = true;
        return;
    }
    if (scenario == MULTIPLE_WRITE_GENERATIONS) {
        // Two drained writes cancel different source generations before either
        // cancel handler has had a chance to run.
        for (int i = 0; i < 2; i++) {
            block_writes = true;
            assert(queue_handshake_output(reactor, handle, outersshpriv_proxy_pending_connection_for_handle(reactor, handle), (const unsigned char *)"x", 1));
            block_writes = false;
            assert(process_handshake_writes(reactor, handle, outersshpriv_proxy_pending_connection_for_handle(reactor, handle)));
            char byte;
            assert(otsocket_read(browser_socket, &byte, 1) == 1 && byte == 'x');
        }
        assert(slot->uncancelled_socket_source_count == 3);
    }
    block_writes = scenario == PARTIAL_REPLY ||
        scenario == WRITE_CONTEXT_FAILURE || scenario == WRITE_SOURCE_FAILURE ||
        scenario == CANCEL_PARTIAL_REPLY || scenario == TIMEOUT_PARTIAL_REPLY ||
        scenario == ASYNC_PARTIAL_REPLY;
    write_budget = block_writes ? 3 : 0;
    outersshpriv_proxy_reactor_complete_pending_connection(
        reactor, handle, socket_transferred, &transfer_context);
    assert(completions == 0);
    unsigned rejected_before = rejected_transfers;
    outersshpriv_proxy_reactor_complete_pending_connection(reactor, handle, transfer_rejected, &transfer_context);
    assert(rejected_transfers == rejected_before + 1 && completions == 0);
    assert(ssh_test_socket_is_open(watched_socket));
    if (scenario == ASYNC_PARTIAL_REPLY) {
        started = true;
        return;
    }
    if (scenario == PARTIAL_REPLY || scenario == CANCEL_PARTIAL_REPLY ||
        scenario == TIMEOUT_PARTIAL_REPLY) {
        assert(slot->phase == PROXY_PENDING_REPLYING);
        assert(slot->socks->write_offset == 3 && slot->socks->write_count == 10);
        if (scenario == PARTIAL_REPLY) {
            block_writes = false;
            assert(!process_handshake_writes(reactor, handle, outersshpriv_proxy_pending_connection_for_handle(reactor, handle)));
            assert(slot->phase == PROXY_PENDING_TRANSFERRING);
        } else if (scenario == CANCEL_PARTIAL_REPLY) {
            outersshpriv_proxy_reactor_remove_listener(reactor, listener_handle);
        } else {
            handle_handshake_timeout(reactor, handle);
        }
    }
    if (scenario == CANCEL_HANDOFF) {
        static OuterSSHSessionPool first_pool, second_pool;
        outersshpriv_proxy_reactor_set_connection_pool(reactor, handle, &first_pool, 1);
        outersshpriv_proxy_reactor_cancel_pool_pending_connections(reactor, &second_pool, 1);
        assert(slot->phase == PROXY_PENDING_TRANSFERRING);
        outersshpriv_proxy_reactor_cancel_pool_pending_connections(reactor, &first_pool, 2);
        assert(slot->phase == PROXY_PENDING_TRANSFERRING);
        outersshpriv_proxy_reactor_cancel_pool_pending_connections(reactor, &first_pool, 1);
        assert(slot->phase == PROXY_PENDING_CLOSING);
    } else if (scenario == DESTROY_HANDOFF) {
        outersshpriv_proxy_reactor_invalidate(reactor);
        outersshpriv_proxy_reactor_destroy(reactor, NULL, NULL);
        destroy_requested = true;
        assert(slot->phase == PROXY_PENDING_CLOSING);
    }
    assert(ssh_test_socket_is_open(watched_socket));
    assert(reactor->available_pending_connection_index_count == 0);
    // Cancellation handlers must resolve handles, not hold a pointer into the
    // old allocation. Stale readiness and timer events must do nothing.
    assert(outersshpriv_proxy_pending_connection_reserve(reactor, reactor->pending_connection_capacity + 1));
    process_handshake_reads(reactor, handle);
    assert(!process_handshake_writes(reactor, handle, outersshpriv_proxy_pending_connection_for_handle(reactor, handle)));
    handle_handshake_timeout(reactor, handle);
    assert(completions == 0);
    started = true;
}

static void test_socket_addresses(void)
{
    size_t host_length, decoded_length;
    OuterSSHProxySocketKind kind;
    const char *paths[] = {"/run/user/1000/app.sock", "/tmp/UPPER lower.%+sock", "/tmp/é.sock"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        char host[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY], decoded[4097];
        assert(outerssh_proxy_encode_unix_socket_host(paths[i], strlen(paths[i]), host, sizeof(host), &host_length));
        assert(outerssh_proxy_decode_socket_host(host, host_length, &kind, decoded, sizeof(decoded), &decoded_length) && strcmp(decoded, paths[i]) == 0);
        assert(kind == OUTERSSH_PROXY_SOCKET_KIND_UNIX && decoded_length == strlen(paths[i]));
        assert(host[host_length] == 0 && decoded[decoded_length] == 0);
        ProxyConnectRequest request = {.port = 80};
        strcpy(request.host, host);
        request.host_length = host_length;
        ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(request);
        assert(route.kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET && strcmp(route.unix_socket.path, paths[i]) == 0);
        assert(route.unix_socket.path_length == strlen(paths[i]));
        request.port = 443;
        assert(outersshpriv_proxy_resolve_request(request).kind == PROXY_CONNECTION_ROUTE_REJECTED);
        for (size_t j = 0; host[j]; j++) if (host[j] >= 'a' && host[j] <= 'z') host[j] -= 32;
        assert(outerssh_proxy_decode_socket_host(host, host_length, &kind, decoded, sizeof(decoded), &decoded_length) && strcmp(decoded, paths[i]) == 0);
    }
    const char *invalid[] = {"invalid.unix.outerssh.localhost", "f4a.unix.outerssh.localhost",
        "f5xx.unix.outerssh.localhost", "f.4.unix.outerssh.localhost", "f4..unix.outerssh.localhost",
        "f4.s-.unix.outerssh.localhost", "f4.s-!bad.unix.outerssh.localhost", "unknown.outerssh.localhost"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        char path[4097];
        decoded_length = SIZE_MAX;
        assert(!outerssh_proxy_decode_socket_host(invalid[i], strlen(invalid[i]), &kind, path, sizeof(path), &decoded_length));
        assert(decoded_length == 0);
        ProxyConnectRequest request = {.port = 80}; strcpy(request.host, invalid[i]); request.host_length = strlen(invalid[i]);
        assert(outersshpriv_proxy_resolve_request(request).kind == PROXY_CONNECTION_ROUTE_REJECTED);
    }
    char host[254], path[180]; memset(path, 'a', sizeof(path)); path[0] = '/'; path[sizeof(path)-1] = 0;
    assert(!outerssh_proxy_encode_unix_socket_host(path, strlen(path), host, sizeof(host), &host_length));
    path[107] = 0;
    assert(outerssh_proxy_encode_unix_socket_host(path, strlen(path), host, sizeof(host), &host_length));
    char decoded[180]; assert(outerssh_proxy_decode_socket_host(host, host_length, &kind, decoded, sizeof(decoded), &decoded_length) && strcmp(decoded, path) == 0);
    assert(!outerssh_proxy_encode_unix_socket_host("relative", sizeof("relative") - 1, host, sizeof(host), &host_length));
    assert(!outerssh_proxy_encode_unix_socket_host("/tmp/a\nb", sizeof("/tmp/a\nb") - 1, host, sizeof(host), &host_length));
    host_length = SIZE_MAX;
    assert(!outerssh_proxy_encode_unix_socket_host("/tmp/a", sizeof("/tmp/a") - 1, host, 4, &host_length));
    assert(host_length == 0);
}

static void test_tcp_destinations(void)
{
    const char *cases[] = {"example.com", "EXAMPLE.COM", "localhost", "127.0.0.1", "worker.internal"};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ProxyConnectRequest request = {.port = 8080};
        request.host_length = strlen(cases[i]);
        memcpy(request.host, cases[i], request.host_length);
        ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(request);
        assert(route.kind == PROXY_CONNECTION_ROUTE_TCP);
        assert(route.tcp.host_length == request.host_length && route.tcp.port == request.port);
        assert(memcmp(route.tcp.host, request.host, request.host_length) == 0);
        assert(route.request.host_length == request.host_length && route.request.port == request.port);
        assert(memcmp(route.request.host, request.host, request.host_length) == 0);
    }
}

static void test_loopback_addresses(void)
{
    const char *hosts[][2] = {
        {"localhost.tcp.outerssh.localhost", "localhost"}, {"LOCALHOST.TCP.OUTERSSH.LOCALHOST", "localhost"},
        {"localhost.tcp.outerssh.localhost.", "localhost"}, {"127.0.0.1.tcp.outerssh.localhost", "127.0.0.1"},
        {"127.0.0.2.tcp.outerssh.localhost", "127.0.0.2"}, {"ip6-localhost.tcp.outerssh.localhost", "::1"}
    };
    const uint16_t ports[] = {80, 443, 3000, 51797, 65535};
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        assert(outersshpriv_proxy_is_tcp_host(hosts[i][0], strlen(hosts[i][0])));
        for (size_t j = 0; j < sizeof(ports) / sizeof(ports[0]); j++) {
            ProxyConnectRequest request = {.port = ports[j]};
            strcpy(request.host, hosts[i][0]); request.host_length = strlen(hosts[i][0]);
            ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(request);
            assert(route.kind == PROXY_CONNECTION_ROUTE_TCP && route.tcp.loopback);
            assert(strcmp(route.tcp.host, hosts[i][1]) == 0 && route.tcp.port == ports[j]);
            assert(route.tcp.host_length == strlen(hosts[i][1]));
            assert(route.request.port == ports[j] && route.request.host_length == request.host_length);
            assert(memcmp(route.request.host, request.host, request.host_length) == 0);
        }
    }
    const char *invalid[] = {
        ".tcp.outerssh.localhost", "8080.localhost.tcp.outerssh.localhost", "localhost.outerssh.localhost",
        "loopback-80.tcp.outerssh.localhost", "127.0.0.01.tcp.outerssh.localhost", "128.0.0.1.tcp.outerssh.localhost",
        "[localhost.tcp.outerssh.localhost]", "loopback-80.unix.outerssh.localhost", "outerssh.localhost"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        assert(!outersshpriv_proxy_is_tcp_host(invalid[i], strlen(invalid[i])));
        ProxyConnectRequest request = {.port = 80};
        strcpy(request.host, invalid[i]); request.host_length = strlen(invalid[i]);
        assert(outersshpriv_proxy_resolve_request(request).kind == PROXY_CONNECTION_ROUTE_REJECTED);
    }
    const char *unrelated = "localhost.tcp.outerssh.localhost.example.com";
    assert(!outersshpriv_proxy_is_tcp_host(unrelated, strlen(unrelated)));
    ProxyConnectRequest request = {.host = "localhost.tcp.outerssh.localhost",
        .host_length = sizeof("localhost.tcp.outerssh.localhost") - 1};
    assert(outersshpriv_proxy_resolve_request(request).kind == PROXY_CONNECTION_ROUTE_REJECTED);
}

static ProxyConnectionRoute route_for_host(const char *host)
{
    ProxyConnectRequest request = {.port = 8080};
    strcpy(request.host, host);
    request.host_length = strlen(host);
    return outersshpriv_proxy_resolve_request(request);
}

static void test_server_zones(void)
{
    const char *loopback[] = {
        "localhost", "LOCALHOST", "localhost.", "app.localhost", "127.0.0.1", "127.255.255.254", "0.0.0.0",
        "::1", "[::1]", "0:0:0:0:0:0:0:1", "::", "::ffff:127.0.0.1", "::FFFF:7f00:1", "::127.0.0.1", "::1%lo0"
    };
    for (size_t i = 0; i < sizeof(loopback) / sizeof(loopback[0]); i++) {
        ProxyConnectionRoute route = route_for_host(loopback[i]);
        assert(route.kind == PROXY_CONNECTION_ROUTE_TCP && route.tcp.loopback);
    }
    const char *elsewhere[] = {
        "example.com", "worker.internal", "10.0.0.5", "192.168.1.1", "1.2.3.4", "fe80::1", "2001:db8::1",
        "::ffff:10.0.0.5", "::2", "::0.0.0.2", "0.0.0.1", "1::", "localhost.example.com", "mylocalhost", "1e100.net", "v1.2a", "128.0.0.1"
    };
    for (size_t i = 0; i < sizeof(elsewhere) / sizeof(elsewhere[0]); i++) {
        ProxyConnectionRoute route = route_for_host(elsewhere[i]);
        assert(route.kind == PROXY_CONNECTION_ROUTE_TCP && !route.tcp.loopback);
    }
    const char *numeric[] = {
        "127.1", "2130706433", "0x7f000001", "0x7f.0.0.1", "0177.0.0.1", "127.000.000.001", "10.0.0.256",
        "example.123", "example.0x1f", "1.2.3.4.5", "0x", "127.0.0.1.0"
    };
    for (size_t i = 0; i < sizeof(numeric) / sizeof(numeric[0]); i++) {
        assert(route_for_host(numeric[i]).kind == PROXY_CONNECTION_ROUTE_REJECTED);
    }
}

int main(void)
{
    test_socket_addresses();
    test_tcp_destinations();
    test_loopback_addresses();
    test_server_zones();
    queue = ssh_test_queue_create("test.socks.flow");
    finished = ssh_test_semaphore_create(0);
    for (scenario = 0; scenario < SCENARIO_COUNT; scenario++) {
        otqueue_async(queue, NULL, run_scenario);
        assert(ssh_test_semaphore_wait(finished,
            5 * NSEC_PER_SEC) == 0);
    }
    ssh_test_semaphore_destroy(finished);
    otqueue_release(queue);
    puts("PASS: SOCKS negotiation and direct connections, partial replies, early payload, cancellation, source failures, and socket lifetime");
    return 0;
}

void outersshpriv_socket_service_stop(OuterSSHSessionPool *pool)
{
    (void)pool;
}
