#include "SSHTestReactor.h"
#include "SSHTestSupport.h"

#include <OuterSSH/OuterSSH.h>
#include "SSHForwarder.h"
#include "SSHTestEvents.h"
#include "SSHEventQueueInternal.h"
#include "SSHReactor.h"
#include "SSHSocketBridgeInternal.h"

static OuterSSHEventQueue *event_queue;
static const OuterSSHSOCKSProxyServerConfiguration server_configuration = {0};

#include <assert.h>
#include "platform/OTQueue.h"
#include "platform/OTSocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_unknown_answers(OuterSSHSessionPool *pool)
{
    OuterSSHEvent event;
    assert(outerssh_event_queue_poll(event_queue, &event, 1) == 0);
    outerssh_session_pool_answer_host_key(pool, 12345, true);
    outerssh_session_pool_provide_sudo_password(pool, 12345, "secret", 6);
    outerssh_session_pool_decline_sudo_password(pool, 12345);
}

static OuterSSHEvent next_event(OuterSSHEventQueue *event_queue)
{
    OuterSSHEvent event;
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        if (outerssh_event_queue_poll(event_queue, &event, 1) == 1) return event;
        ssh_test_event_queue_wait(event_queue, 100);
    }
    assert(!"timed out waiting for an event");
    return event;
}

static void expect_completion(OuterSSHEventQueue *event_queue, OuterSSHEventType type,
    const OuterSSHSessionPool *pool, uint64_t tag)
{
    OuterSSHEvent event = next_event(event_queue);
    assert(event.type == type && event.pool == pool && event.tag == tag);
    assert(type == OUTERSSH_EVENT_DESTROYED || event.operation_completed.error.domain == OUTERSSH_ERROR_NONE);
    if (type == OUTERSSH_EVENT_PROXY_STARTED) assert(event.proxy_started.listen_port > 0);
}

static void test_origin_credentials(OuterSSHSessionPool *pool, OuterSSHSOCKSProxyServer *server)
{
    char origin[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY + 8] = "http://";
    size_t host_length;
    static const char path[] = "/run/org.outershell.Top";
    assert(outerssh_proxy_encode_unix_socket_host(path, sizeof(path) - 1, origin + 7, sizeof(origin) - 7, &host_length));
    size_t origin_length = 7 + host_length;
    char long_name[256];
    memset(long_name, 'a', sizeof(long_name));
    assert(!outerssh_socks_proxy_server_add_origin_credentials(server, long_name, sizeof(long_name), "p", 1,
        origin, origin_length, 1));
    assert(!outerssh_socks_proxy_server_add_origin_credentials(server, "", 0, "p", 1, origin, origin_length, 1));
    assert(!outerssh_socks_proxy_server_add_origin_credentials(server, "o", 1, "", 0, origin, origin_length, 1));
    static const char *const invalid[] = {
        "", "http://", "/run/org.outershell.Top", "ftp://example.com", "http://example.com/",
        "http://example.com/path", "http://user@example.com", "http://example.com:0", "http://example.com:65536",
        "http://example.com:", "http://exa mple.com", "http://<b>.com", "https://f4.unix.outerssh.localhost",
        "http://f4.unix.outerssh.localhost:81", "http://unknown.outerssh.localhost", "http://[::1",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        assert(!outerssh_socks_proxy_server_add_origin_credentials(server, "o", 1, "p", 1,
            invalid[i], strlen(invalid[i]), 1));
    }
    assert(!outerssh_socks_proxy_server_remove_origin_credentials(server, "", 0, 1));
    assert(outerssh_socks_proxy_server_add_origin_credentials(server, "o", 1, "p", 1, origin, origin_length, 71));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 71);
    static const char tcp[] = "HTTP://LOCALHOST.tcp.outerssh.localhost:8080";
    assert(outerssh_socks_proxy_server_add_origin_credentials(server, "o", 1, "q", 1, tcp, sizeof(tcp) - 1, 72));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 72);
    static const char web[] = "https://example.com:443";
    assert(outerssh_socks_proxy_server_add_origin_credentials(server, "w", 1, "q", 1, web, sizeof(web) - 1, 73));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 73);
    assert(outerssh_socks_proxy_server_remove_origin_credentials(server, "o", 1, 74));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 74);
    assert(outerssh_socks_proxy_server_remove_origin_credentials(server, "w", 1, 75));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 75);
    assert(outerssh_socks_proxy_server_remove_origin_credentials(server, "unknown", 7, 76));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 76);
}

static void test_http_origin_credentials(OuterSSHSessionPool *pool)
{
    OuterSSHError error;
    const OuterSSHHTTPProxyServerConfiguration configuration = {0};
    OuterSSHHTTPProxyServer *server = outerssh_http_proxy_server_create(pool, &configuration, &error);
    assert(server != NULL);
    static const char origin[] = "http://localhost.tcp.outerssh.localhost:8080";
    assert(!outerssh_http_proxy_server_add_origin_credentials(server, "a:b", 3, "p", 1, origin, sizeof(origin) - 1, 1));
    assert(!outerssh_http_proxy_server_add_origin_credentials(server, "o", 1, "p", 1, "ftp://example.com", 17, 1));
    assert(outerssh_http_proxy_server_add_origin_credentials(server, "o", 1, "p", 1, origin, sizeof(origin) - 1, 81));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 81);
    assert(outerssh_http_proxy_server_remove_origin_credentials(server, "o", 1, 82));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 82);
    assert(outerssh_http_proxy_server_destroy(server, 83));
    expect_completion(event_queue, OUTERSSH_EVENT_DESTROYED, pool, 83);

    const OuterSSHHTTPProxyServerConfiguration unauthenticated = {.authentication = OUTERSSH_PROXY_AUTHENTICATION_NONE};
    server = outerssh_http_proxy_server_create(pool, &unauthenticated, &error);
    assert(server != NULL);
    assert(!outerssh_http_proxy_server_add_origin_credentials(server, "o", 1, "p", 1, origin, sizeof(origin) - 1, 1));
    assert(outerssh_http_proxy_server_destroy(server, 84));
    expect_completion(event_queue, OUTERSSH_EVENT_DESTROYED, pool, 84);
    puts("PASS: HTTP origin credentials validate their inputs and complete once");
}

static void test_tagged_requests(void)
{
    OuterSSHEventQueue *event_queue = ssh_test_event_queue_create();
    assert(event_queue != NULL);
    OuterSSHSessionPoolConfiguration configuration = {
        .hostname = "localhost", .hostname_length = 9,
        .username = "test", .username_length = 4,
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
            .password = "test", .password_length = 4},
    };
    OuterSSHError error;
    OuterSSHSessionPool *pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(pool != NULL);
    OuterSSHSOCKSProxyServer *server = outerssh_socks_proxy_server_create(pool, &server_configuration, &error);
    assert(server != NULL);
    const OuterSSHHTTPProxyServerConfiguration http_configuration = {0};
    OuterSSHHTTPProxyServer *http = outerssh_http_proxy_server_create(pool, &http_configuration, &error);
    assert(http != NULL);
    assert(outerssh_socks_proxy_server_start(server, 0, 1));
    expect_completion(event_queue, OUTERSSH_EVENT_PROXY_STARTED, pool, 1);
    assert(outerssh_http_proxy_server_start(http, 0, 2));
    expect_completion(event_queue, OUTERSSH_EVENT_PROXY_STARTED, pool, 2);
    assert(outerssh_socks_proxy_server_start(server, 0, 3));
    expect_completion(event_queue, OUTERSSH_EVENT_PROXY_STARTED, pool, 3);
    assert(outerssh_socks_proxy_server_stop(server, 5));
    expect_completion(event_queue, OUTERSSH_EVENT_OPERATION_COMPLETED, pool, 5);
    assert(outerssh_http_proxy_server_destroy(http, 7));
    assert(outerssh_socks_proxy_server_destroy(server, 8));
    assert(outerssh_session_pool_destroy(pool, 9));
    uint64_t frontends = 0;
    for (unsigned i = 0; i < 2; i++) {
        OuterSSHEvent event = next_event(event_queue);
        assert(event.type == OUTERSSH_EVENT_DESTROYED && event.pool == pool);
        assert(event.tag == 7 || event.tag == 8);
        frontends |= 1u << event.tag;
    }
    assert(frontends == ((1u << 7) | (1u << 8)));
    expect_completion(event_queue, OUTERSSH_EVENT_DESTROYED, pool, 9);
    assert(outerssh_event_queue_poll(event_queue, &(OuterSSHEvent){0}, 1) == 0);
    ssh_test_event_queue_destroy(event_queue);
    puts("PASS: tagged requests post one completion event each");
}

static SSHTestCompletions completions;
static uint64_t last_tag;

typedef enum { AWAIT_STARTED, AWAIT_STOPPED, AWAIT_FORWARD_STARTED, AWAIT_DESTROYED } AwaitKind;

/* Requests a test has submitted, in the order it will await them. */
typedef struct {
    int32_t port;
    OuterSSHErrorDomain domain;
    struct { AwaitKind kind; uint64_t tag; } pending[8];
    size_t pending_count;
} ServerTest;

#define SUBMIT(test, kind, request) do { \
    uint64_t request_tag = ++last_tag; \
    assert(request); \
    submitted((test), (kind), request_tag); \
} while (0)

static void submitted(ServerTest *test, AwaitKind kind, uint64_t tag)
{
    assert(test->pending_count < 8);
    test->pending[test->pending_count].kind = kind;
    test->pending[test->pending_count++].tag = tag;
}

static void await_result(ServerTest *test)
{
    assert(test->pending_count != 0);
    AwaitKind kind = test->pending[0].kind;
    uint64_t tag = test->pending[0].tag;
    memmove(test->pending, test->pending + 1, --test->pending_count * sizeof(test->pending[0]));
    static const OuterSSHEventType types[] = {OUTERSSH_EVENT_PROXY_STARTED, OUTERSSH_EVENT_OPERATION_COMPLETED,
        OUTERSSH_EVENT_PORT_FORWARD_STARTED, OUTERSSH_EVENT_DESTROYED};
    SSHTestCompletion completion = ssh_test_take(&completions, types[kind], tag);
    test->domain = completion.domain;
    if (kind == AWAIT_STARTED && completion.domain == OUTERSSH_ERROR_NONE) {
        test->port = completion.listen_port;
        assert(completion.username_length == 32 && completion.password_length == 32);
    } else if (kind == AWAIT_FORWARD_STARTED) {
        test->port = completion.listen_port;
    }
}

static void await_server(ServerTest *test)
{
    await_result(test);
    assert(test->domain == OUTERSSH_ERROR_NONE);
}

#define DESTROY(request) do { \
    ServerTest destruction = {0}; \
    SUBMIT(&destruction, AWAIT_DESTROYED, request); \
    await_server(&destruction); \
} while (0)

static void assert_port_free(int32_t port)
{
    otsocket_t socket = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(socket >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons((uint16_t)port)};
    assert(otsocket_bind(socket, (const struct sockaddr *)&address, sizeof(address)) == 0);
    otsocket_close(socket);
}

typedef struct {
    SSHProxyConnection connection;
    bool active;
} ForwardingRunTest;

static void capture_forwarding_run(void *context)
{
    ForwardingRunTest *test = context;
    test->connection.proxy_generation = test->connection.server->generation;
    assert(outersshpriv_proxy_connection_is_active(test->connection));
}

static void check_forwarding_run(void *context)
{
    ForwardingRunTest *test = context;
    assert(outersshpriv_proxy_connection_is_active(test->connection) == test->active);
}

static void test_forwarding_runs(OuterSSHSessionPool *pool)
{
    OuterSSHError error;
    OuterSSHSOCKSProxyServer *a = outerssh_socks_proxy_server_create(pool, &server_configuration, &error);
    OuterSSHSOCKSProxyServer *b = outerssh_socks_proxy_server_create(pool, &server_configuration, &error);
    assert(a != NULL && b != NULL);
    ServerTest test = {0};
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(a, 0, request_tag)); await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(b, 0, request_tag)); await_server(&test);
    ForwardingRunTest run = {.connection = {.server = outersshpriv_socks_proxy_server_forwarder(a), .pool = pool}, .active = true};
    ssh_test_sync(pool->_queue, &run, capture_forwarding_run);
    uint64_t initial_generation = run.connection.proxy_generation;
    SUBMIT(&test, AWAIT_STOPPED, outerssh_socks_proxy_server_stop(b, request_tag)); await_server(&test);
    ssh_test_sync(pool->_queue, &run, check_forwarding_run);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_socks_proxy_server_stop(a, request_tag)); await_server(&test);
    run.active = false;
    ssh_test_sync(pool->_queue, &run, check_forwarding_run);
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(a, 0, request_tag)); await_server(&test);
    ssh_test_sync(pool->_queue, &run, check_forwarding_run);
    ssh_test_sync(pool->_queue, &run, capture_forwarding_run);
    assert(run.connection.proxy_generation != initial_generation);
    DESTROY(outerssh_socks_proxy_server_destroy(a, request_tag));
    DESTROY(outerssh_socks_proxy_server_destroy(b, request_tag));
}

static void test_server_lifecycle(OuterSSHSessionPool *pool)
{
    OuterSSHError error;
    OuterSSHSOCKSProxyServer *server = outerssh_socks_proxy_server_create(pool, &server_configuration, &error);
    assert(server != NULL);
    ServerTest test = {0};
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, 0, request_tag));
    await_server(&test);
    int32_t original_port = test.port;
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, 0, request_tag));
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, original_port, request_tag));
    await_server(&test); await_server(&test);
    assert(test.port == original_port);
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, original_port == 1 ? 2 : 1, request_tag));
    await_result(&test);
    assert(test.domain != OUTERSSH_ERROR_NONE);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_socks_proxy_server_stop(server, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, original_port, request_tag));
    await_server(&test);
    assert(test.port == original_port);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_socks_proxy_server_stop(server, request_tag));
    await_server(&test);
    /* Queue restart immediately after stop to exercise asynchronous teardown. */
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, 0, request_tag));
    SUBMIT(&test, AWAIT_STOPPED, outerssh_socks_proxy_server_stop(server, request_tag));
    await_server(&test); await_server(&test);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_socks_proxy_server_stop(server, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, 0, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, test.port == 1 ? 2 : 1, request_tag));
    await_result(&test);
    assert(test.domain != OUTERSSH_ERROR_NONE);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_socks_proxy_server_stop(server, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, 0, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_DESTROYED, outerssh_socks_proxy_server_destroy(server, request_tag));
    await_server(&test);
    assert_port_free(test.port);
}

static void test_http_server_lifecycle(OuterSSHSessionPool *pool)
{
    OuterSSHError error;
    const OuterSSHHTTPProxyServerConfiguration server_configuration = {0};
    OuterSSHHTTPProxyServer *server = outerssh_http_proxy_server_create(pool, &server_configuration, &error);
    assert(server != NULL);
    ServerTest test = {0};
    OuterSSHHTTPProxyServer *blocker = outerssh_http_proxy_server_create(pool, &server_configuration, &error);
    assert(blocker != NULL);
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(blocker, 0, request_tag));
    await_server(&test);
    int32_t blocked_port = test.port;
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, blocked_port, request_tag));
    await_result(&test);
    assert(test.domain != OUTERSSH_ERROR_NONE);
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, 0, request_tag));
    await_server(&test);
    int32_t original_port = test.port;
    assert(original_port != blocked_port);
    SUBMIT(&test, AWAIT_DESTROYED, outerssh_http_proxy_server_destroy(blocker, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, 0, request_tag));
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, original_port, request_tag));
    await_server(&test); await_server(&test);
    assert(test.port == original_port);
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, original_port == 1 ? 2 : 1, request_tag));
    await_result(&test);
    assert(test.domain != OUTERSSH_ERROR_NONE);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_http_proxy_server_stop(server, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, original_port, request_tag));
    await_server(&test);
    assert(test.port == original_port);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_http_proxy_server_stop(server, request_tag));
    await_server(&test);
    /* Stop must permit startup on a different port. */
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, blocked_port, request_tag));
    SUBMIT(&test, AWAIT_STOPPED, outerssh_http_proxy_server_stop(server, request_tag));
    await_server(&test); await_server(&test);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_http_proxy_server_stop(server, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, 0, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, test.port == 1 ? 2 : 1, request_tag));
    await_result(&test);
    assert(test.domain != OUTERSSH_ERROR_NONE);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_http_proxy_server_stop(server, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, 0, request_tag));
    await_server(&test);
    otsocket_t clients[8];
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons((uint16_t)test.port)};
    for (size_t i = 0; i < 8; i++) {
        clients[i] = otsocket_create(AF_INET, SOCK_STREAM, 0);
        assert(otsocket_connect(clients[i], (const struct sockaddr *)&address, sizeof(address)) == 0);
        assert(otsocket_send(clients[i], "GET http://localhost/ HTTP/1.1\r\n", 32, OTSOCKET_SEND_FLAGS) == 32);
    }
    SUBMIT(&test, AWAIT_STOPPED, outerssh_http_proxy_server_stop(server, request_tag));
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, 0, request_tag));
    await_server(&test); await_server(&test);
    for (size_t i = 0; i < 8; i++) {
        char byte;
        assert(otsocket_recv(clients[i], &byte, 1, 0) <= 0);
        otsocket_close(clients[i]);
    }
    SUBMIT(&test, AWAIT_STARTED, outerssh_http_proxy_server_start(server, test.port, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_DESTROYED, outerssh_http_proxy_server_destroy(server, request_tag));
    await_server(&test);
    assert_port_free(test.port);
}

static void check_credentials(SSHTestCompletion completion, bool authenticated)
{
    assert(!completion.domain && completion.listen_port > 0);
    assert(completion.username_length == (authenticated ? 3 : 0));
    assert(completion.password_length == (authenticated ? 3 : 0));
    if (authenticated) {
        assert(memcmp(completion.username, "abc", 3) == 0);
        assert(memcmp(completion.password, "def", 3) == 0);
    }
}

static void test_http_realm_validation(OuterSSHSessionPool *pool)
{
    const char invalid_bytes[] = {'\0', '\n', '\r', '\x1f', '\x7f', '"', '\\'};
    OuterSSHHTTPProxyServerConfiguration configuration = {0};
    OuterSSHError error;
    for (size_t i = 0; i < sizeof(invalid_bytes); i++) {
        configuration.realm = &invalid_bytes[i];
        configuration.realm_length = 1;
        assert(outerssh_http_proxy_server_create(pool, &configuration, &error) == NULL && error.domain);
    }
    configuration.realm = NULL;
    assert(outerssh_http_proxy_server_create(pool, &configuration, &error) == NULL && error.domain);
    configuration.realm = "x";
    configuration.realm_length = 256;
    assert(outerssh_http_proxy_server_create(pool, &configuration, &error) == NULL && error.domain);
    configuration.realm_length = SIZE_MAX;
    assert(outerssh_http_proxy_server_create(pool, &configuration, &error) == NULL && error.domain);
}

static void test_proxy_credentials(OuterSSHSessionPool *pool)
{
    for (unsigned authenticated = 0; authenticated < 2; authenticated++) {
        char username[] = {'a', 'b', 'c'}, password[] = {'d', 'e', 'f'};
        OuterSSHProxyCredentials credentials = {username, sizeof(username), password, sizeof(password)};
        OuterSSHProxyAuthentication mode = authenticated
            ? OUTERSSH_PROXY_AUTHENTICATION_PASSWORD : OUTERSSH_PROXY_AUTHENTICATION_NONE;
        OuterSSHSOCKSProxyServerConfiguration socks_configuration = {
            .authentication = mode, .credentials = authenticated ? &credentials : NULL};
        OuterSSHHTTPProxyServerConfiguration http_configuration = {
            .authentication = mode, .credentials = authenticated ? &credentials : NULL};
        OuterSSHSOCKSProxyServer *socks = outerssh_socks_proxy_server_create(pool, &socks_configuration, NULL);
        OuterSSHHTTPProxyServer *http = outerssh_http_proxy_server_create(pool, &http_configuration, NULL);
        assert(socks != NULL && http != NULL);
        memset(username, 'x', sizeof(username));
        memset(password, 'x', sizeof(password));
        uint64_t socks_started = ++last_tag, http_started = ++last_tag;
        assert(outerssh_socks_proxy_server_start(socks, 0, socks_started));
        assert(outerssh_http_proxy_server_start(http, 0, http_started));
        check_credentials(ssh_test_take(&completions, OUTERSSH_EVENT_PROXY_STARTED, socks_started), authenticated);
        check_credentials(ssh_test_take(&completions, OUTERSSH_EVENT_PROXY_STARTED, http_started), authenticated);
        uint64_t socks_destroyed = ++last_tag, http_destroyed = ++last_tag;
        assert(outerssh_socks_proxy_server_destroy(socks, socks_destroyed));
        assert(outerssh_http_proxy_server_destroy(http, http_destroyed));
        ssh_test_take(&completions, OUTERSSH_EVENT_DESTROYED, socks_destroyed);
        ssh_test_take(&completions, OUTERSSH_EVENT_DESTROYED, http_destroyed);

        OuterSSHError error = {0};
        socks_configuration.authentication = http_configuration.authentication = OUTERSSH_PROXY_AUTHENTICATION_NONE;
        socks_configuration.credentials = http_configuration.credentials = &credentials;
        assert(outerssh_socks_proxy_server_create(pool, &socks_configuration, &error) == NULL && error.domain);
        assert(outerssh_http_proxy_server_create(pool, &http_configuration, &error) == NULL && error.domain);
        socks_configuration.authentication = http_configuration.authentication = (OuterSSHProxyAuthentication)99;
        assert(outerssh_socks_proxy_server_create(pool, &socks_configuration, &error) == NULL && error.domain);
        assert(outerssh_http_proxy_server_create(pool, &http_configuration, &error) == NULL && error.domain);
    }
    puts("PASS: HTTP/SOCKS explicit authentication, copied unterminated credentials, and invalid configuration");
}

typedef struct {
    OuterSSHEventQueue *event_queue;
    OuterSSHSessionPool *pool;
    ssh_test_semaphore_t ready;
} ControlTest;

static void control_worker(void *context)
{
    ControlTest *test = context;
    for (unsigned i = 0; i < 500; i++) {
        OuterSSHEvent event;
        assert(outerssh_event_queue_poll(test->event_queue, &event, 1) == 0);
    }
    ssh_test_semaphore_signal(test->ready);
}

static void test_event_queue(void)
{
    OuterSSHError error;
    OuterSSHEventQueue *event_queue = ssh_test_event_queue_create();
    assert(event_queue != NULL);
    ControlTest test = {.event_queue = event_queue, .ready = ssh_test_semaphore_create(0)};
    OuterSSHSessionPoolConfiguration configuration = {
        .hostname = "localhost", .hostname_length = 9,
        .username = "test", .username_length = 4,
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
            .password = "test", .password_length = 4},
    };
    test.pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(test.pool != NULL);
    OuterSSHSessionPool *peer = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(peer != NULL && peer->_queue != test.pool->_queue);
    OuterSSHSOCKSProxyServer *server = outerssh_socks_proxy_server_create(test.pool, &server_configuration, &error);
    assert(server != NULL);
    const OuterSSHHTTPProxyServerConfiguration http_configuration = {0};
    OuterSSHHTTPProxyServer *http = outerssh_http_proxy_server_create(test.pool, &http_configuration, &error);
    assert(http != NULL);
    SSHTestCompletions control = {.event_queue = event_queue};
    assert(outerssh_http_proxy_server_start(http, 0, 1));
    assert(ssh_test_take(&control, OUTERSSH_EVENT_PROXY_STARTED, 1).listen_port > 0);

    for (unsigned i = 0; i < 8; i++) {
        ssh_test_thread_start(control_worker, &test);
    }
    for (unsigned i = 0; i < 8; i++)
        assert(ssh_test_semaphore_wait(test.ready, 10 * NSEC_PER_SEC) == 0);
    assert(outerssh_socks_proxy_server_stop(server, 2));
    assert(outerssh_http_proxy_server_stop(http, 3));
    assert(outerssh_http_proxy_server_destroy(http, 4));
    assert(outerssh_socks_proxy_server_destroy(server, 5));
    assert(outerssh_session_pool_destroy(test.pool, 6));
    assert(outerssh_session_pool_destroy(peer, 7));
    assert(ssh_test_take(&control, OUTERSSH_EVENT_OPERATION_COMPLETED, 2).domain == OUTERSSH_ERROR_NONE);
    assert(ssh_test_take(&control, OUTERSSH_EVENT_OPERATION_COMPLETED, 3).domain == OUTERSSH_ERROR_NONE);
    ssh_test_take(&control, OUTERSSH_EVENT_DESTROYED, 4);
    ssh_test_take(&control, OUTERSSH_EVENT_DESTROYED, 5);
    ssh_test_take(&control, OUTERSSH_EVENT_DESTROYED, 6);
    ssh_test_take(&control, OUTERSSH_EVENT_DESTROYED, 7);
    ssh_test_event_queue_destroy(event_queue);
    ssh_test_semaphore_destroy(test.ready);
    puts("PASS: per-pool control queues, event queue lifetime, and concurrent public API calls");
}

#if defined(_WIN32)
#define INVALID_BRIDGE_FILE INVALID_HANDLE_VALUE

static bool descriptor_is_closed(OuterSSHFileHandle file)
{
    DWORD flags;
    return !GetHandleInformation(file, &flags) && GetLastError() == ERROR_INVALID_HANDLE;
}

static OuterSSHFileHandle bridge_binary_file(const unsigned char *bytes, size_t length)
{
    wchar_t directory[MAX_PATH], path[MAX_PATH];
    assert(GetTempPathW(MAX_PATH, directory) != 0 && GetTempFileNameW(directory, L"osb", 0, path) != 0);
    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    assert(file != INVALID_HANDLE_VALUE);
    DWORD written;
    assert(WriteFile(file, bytes, (DWORD)length, &written, NULL) && written == length);
    return file;
}
#else
#define INVALID_BRIDGE_FILE (-1)

static bool descriptor_is_closed(OuterSSHFileHandle descriptor)
{
    return fcntl(descriptor, F_GETFD) == -1 && errno == EBADF;
}

static OuterSSHFileHandle bridge_binary_file(const unsigned char *bytes, size_t length)
{
    char path[] = "/tmp/outerssh-bridge-binary.XXXXXX";
    int descriptor = mkstemp(path);
    assert(descriptor >= 0 && unlink(path) == 0);
    assert(write(descriptor, bytes, length) == (ssize_t)length);
    return descriptor;
}
#endif

static void test_bridge_binary_mapping(OuterSSHSessionPool *pool)
{
    unsigned char file[9000];
    for (size_t i = 0; i < sizeof(file); i++) file[i] = (unsigned char)(i * 7);
    const size_t offset = 5001, length = 3000;
    file[offset] = 0x1f;
    file[offset + 1] = 0x8b;
    OuterSSHError error;
    char *error_storage;

    OuterSSHFileHandle descriptor = bridge_binary_file(file, sizeof(file));
    SSHBridgeBinary *binary = outersshpriv_bridge_binary_map(descriptor, offset, length, &error, &error_storage);
    assert(binary != NULL && error_storage == NULL && descriptor_is_closed(descriptor));
    size_t mapped_length;
    const void *bytes = outersshpriv_bridge_binary_bytes(binary, &mapped_length);
    assert(mapped_length == length && memcmp(bytes, file + offset, length) == 0);
    assert(outersshpriv_bridge_binary_retain(binary) == binary);
    outersshpriv_bridge_binary_release(binary);
    assert(memcmp(bytes, file + offset, length) == 0);
    outersshpriv_bridge_binary_release(binary);

    const struct {
        uint64_t offset, length;
    } rejected[] = {{offset, sizeof(file)}, {sizeof(file) + 1, 1}, {offset, 0}, {offset + 1, 100}, {UINT64_MAX, 2}};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        descriptor = bridge_binary_file(file, sizeof(file));
        assert(outersshpriv_bridge_binary_map(descriptor, rejected[i].offset, rejected[i].length,
            &error, &error_storage) == NULL);
        assert(error.domain == OUTERSSH_ERROR_HELPER_INSTALLER &&
            error.code == OUTERSSH_HELPER_INSTALLER_ERROR_FAILED_TO_READ_PACKAGED_BINARY && error.message_length != 0);
        assert(descriptor_is_closed(descriptor));
        free(error_storage);
    }
    assert(outersshpriv_bridge_binary_map(INVALID_BRIDGE_FILE, 0, 2, &error, &error_storage) == NULL);
    free(error_storage);

    descriptor = bridge_binary_file(file, sizeof(file));
    outerssh_session_pool_provide_helper_binary(pool, 12345, descriptor, offset, length);
    assert(descriptor_is_closed(descriptor));
    descriptor = bridge_binary_file(file, sizeof(file));
    outerssh_session_pool_provide_helper_binary(pool, 12346, descriptor, 0, length);
    assert(descriptor_is_closed(descriptor));
    outerssh_session_pool_decline_helper_binary(pool, 12347, (OuterSSHError){0});
    puts("PASS: bridge binaries map in place at unaligned offsets, reject bad regions, and always close the file");
}

typedef struct {
    OuterSSHSessionPool *pool;
} ShutdownTest;

static void submit_then_destroy(void *context)
{
    ShutdownTest *test = context;
    assert(outerssh_session_pool_ensure_session(test->pool, 1));
    for (uint64_t tag = 2; tag < 6; tag++) {
        const char command[] = "true";
        assert(outerssh_session_pool_execute_command(test->pool, command, sizeof(command) - 1, NULL, 0, tag));
    }
    assert(outerssh_session_pool_ensure_session(test->pool, 6));
    assert(outerssh_session_pool_destroy(test->pool, 7));
}

static void test_destroy_with_pending_commands(void)
{
    OuterSSHEventQueue *event_queue = ssh_test_event_queue_create();
    assert(event_queue != NULL);
    ShutdownTest test = {0};
    OuterSSHSessionPoolConfiguration configuration = {
        .hostname = "127.0.0.1", .hostname_length = 9, .port = 1,
        .username = "test", .username_length = 4,
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
            .password = "test", .password_length = 4},
    };
    for (unsigned i = 0; i < 20; i++) {
        test.pool = outerssh_session_pool_create(event_queue, &configuration, NULL);
        assert(test.pool != NULL);
        // Submit together so shutdown is queued before resolution can return.
        otqueue_async(test.pool->_queue, &test, submit_then_destroy);
        unsigned commands = 0, ensures = 0;
        for (;;) {
            OuterSSHEvent event;
            assert(ssh_test_next_event(event_queue, &event, 10000));
            if (event.type == OUTERSSH_EVENT_DESTROYED) {
                assert(event.tag == 7 && commands == 4 && ensures == 2);
                break;
            }
            assert(event.operation_completed.error.domain != OUTERSSH_ERROR_NONE);
            if (event.type == OUTERSSH_EVENT_COMMAND_COMPLETED) commands++;
            else if (event.type == OUTERSSH_EVENT_OPERATION_COMPLETED) ensures++;
        }
        assert(outerssh_event_queue_poll(event_queue, &(OuterSSHEvent){0}, 1) == 0);
    }
    ssh_test_event_queue_destroy(event_queue);
    puts("PASS: pending command and session completions precede pool destruction");
}

typedef struct {
    SSHReactor *reactor;
    otqueue_t queue;
    otsocket_t socket;
    ssh_test_semaphore_t finished;
    bool submitting;
} ReactorDestructionTest;

static void reactor_destroyed(void *context)
{
    ReactorDestructionTest *test = context;
    otqueue_assert(test->queue);
    assert(!test->submitting);
    assert(!ssh_test_socket_is_open(test->socket));
    ssh_test_semaphore_signal(test->finished);
}

static void destroy_test_reactor(void *context)
{
    ReactorDestructionTest *test = context;
    test->submitting = true;
    outersshpriv_reactor_destroy(test->reactor, reactor_destroyed, test);
    assert(ssh_test_socket_is_open(test->socket));
    test->submitting = false;
}

static void test_reactor_destruction_completion(void)
{
    assert(outerssh_initialize(NULL));
    otsocket_t sockets[2];
    assert(ssh_test_socket_pair(sockets) == 0);
    LIBSSH2_SESSION *session = olibssh_session_init();
    assert(session != NULL);
    SSHReactor *reactor = ssh_test_reactor_create(sockets[0], session);
    assert(reactor != NULL);
    ReactorDestructionTest test = {.reactor = reactor, .queue = outersshpriv_reactor_queue(reactor),
        .socket = sockets[0], .finished = ssh_test_semaphore_create(0)};
    otqueue_retain(test.queue);
    otqueue_async(test.queue, &test, destroy_test_reactor);
    assert(ssh_test_semaphore_wait(test.finished, 5 * NSEC_PER_SEC) == 0);
    assert(ssh_test_semaphore_wait(test.finished, 0) != 0);
    char byte;
    assert(otsocket_recv(sockets[1], &byte, 1, 0) == 0);
    otsocket_close(sockets[1]);
    ssh_test_semaphore_destroy(test.finished);
    otqueue_release(test.queue);
    puts("PASS: reactor destruction completion follows socket-source cancellation");
}

static void test_port_forwards(void)
{
    OuterSSHError error = {0};
    OuterSSHSessionPoolConfiguration configuration = {
        .hostname = "localhost", .hostname_length = sizeof("localhost") - 1,
        .username = "test", .username_length = sizeof("test") - 1,
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
            .password = "test", .password_length = sizeof("test") - 1}
    };
    OuterSSHSessionPool *pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(pool != NULL && error.domain == OUTERSSH_ERROR_NONE);
    char *host = malloc(9);
    memcpy(host, "localhost", 9);
    OuterSSHPortForward *forward = outerssh_port_forward_create(pool, host, 9, 3000, &error);
    assert(forward != NULL && error.domain == OUTERSSH_ERROR_NONE);
    memset(host, 'x', 9);
    free(host);
    assert(outerssh_port_forward_create(pool, "bad\0host", 8, 3000, &error) == NULL);
    assert(error.domain != OUTERSSH_ERROR_NONE);
    assert(outerssh_port_forward_create(pool, "localhost", 9, 0, &error) == NULL);
    assert(error.domain != OUTERSSH_ERROR_NONE);

    ServerTest test = {0};
    SUBMIT(&test, AWAIT_FORWARD_STARTED, outerssh_port_forward_start(forward, 0, request_tag));
    await_server(&test);
    assert(test.port > 0);
    int32_t port = test.port;
    SUBMIT(&test, AWAIT_FORWARD_STARTED, outerssh_port_forward_start(forward, 0, request_tag));
    await_server(&test);
    assert(test.port == port);

    OuterSSHPortForward *other = outerssh_port_forward_create(pool, "localhost", 9, 4000, &error);
    assert(other != NULL && error.domain == OUTERSSH_ERROR_NONE);
    SUBMIT(&test, AWAIT_FORWARD_STARTED, outerssh_port_forward_start(other, port, request_tag));
    await_result(&test);
    assert(test.domain != OUTERSSH_ERROR_NONE && test.port == 0);
    SUBMIT(&test, AWAIT_FORWARD_STARTED, outerssh_port_forward_start(other, 0, request_tag));
    await_server(&test);
    assert(test.port > 0 && test.port != port);

    SUBMIT(&test, AWAIT_STOPPED, outerssh_port_forward_stop(forward, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_FORWARD_STARTED, outerssh_port_forward_start(forward, 0, request_tag));
    await_server(&test);
    assert(test.port > 0);
    SUBMIT(&test, AWAIT_STOPPED, outerssh_port_forward_stop(forward, request_tag));
    SUBMIT(&test, AWAIT_FORWARD_STARTED, outerssh_port_forward_start(forward, 0, request_tag));
    SUBMIT(&test, AWAIT_DESTROYED, outerssh_port_forward_destroy(forward, request_tag));
    await_server(&test);
    await_server(&test);
    await_server(&test);
    assert(test.pending_count == 0);
    SUBMIT(&test, AWAIT_DESTROYED, outerssh_port_forward_destroy(other, request_tag));
    await_server(&test);

    forward = outerssh_port_forward_create(pool, "localhost", 9, 3000, &error);
    assert(forward != NULL);
    SUBMIT(&test, AWAIT_DESTROYED, outerssh_port_forward_destroy(forward, request_tag));
    await_server(&test);
    SUBMIT(&test, AWAIT_DESTROYED, outerssh_session_pool_destroy(pool, request_tag));
    await_server(&test);
    puts("PASS: port forwards copy destinations, attach one pool, retry startup, restart, and drain queued operations before destruction");
}

int main(void)
{
    test_reactor_destruction_completion();
    test_destroy_with_pending_commands();
    test_event_queue();
    event_queue = ssh_test_event_queue_create();
    assert(event_queue != NULL);
    completions.event_queue = event_queue;
    test_port_forwards();
    OuterSSHSessionPoolConfiguration configuration = {
        .hostname = "localhost", .hostname_length = sizeof("localhost") - 1,
        .username = "test", .username_length = sizeof("test") - 1,
        .authentication = {
            .kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
            .password = "test", .password_length = sizeof("test") - 1
        },
    };
    char *hostname = malloc(configuration.hostname_length);
    char *username = malloc(configuration.username_length);
    char *password = malloc(configuration.authentication.password_length);
    assert(hostname != NULL && username != NULL && password != NULL);
    memcpy(hostname, configuration.hostname, configuration.hostname_length);
    memcpy(username, configuration.username, configuration.username_length);
    memcpy(password, configuration.authentication.password, configuration.authentication.password_length);
    configuration.hostname = hostname;
    configuration.username = username;
    configuration.authentication.password = password;
    OuterSSHError error = {0};
    OuterSSHSessionPool *pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(pool != NULL && error.domain == OUTERSSH_ERROR_NONE);
    OuterSSHSOCKSProxyServer *server = outerssh_socks_proxy_server_create(pool, &server_configuration, &error);
    assert(server != NULL);
    free(hostname);
    free(username);
    free(password);
    assert(outerssh_initialize(&error));
    test_unknown_answers(pool);
    test_origin_credentials(pool, server);
    test_http_origin_credentials(pool);
    test_bridge_binary_mapping(pool);
    test_tagged_requests();
    test_forwarding_runs(pool);
    test_server_lifecycle(pool);
    test_http_server_lifecycle(pool);
    test_proxy_credentials(pool);
    test_http_realm_validation(pool);
    ServerTest active_server = {0};
    SUBMIT(&active_server, AWAIT_STARTED, outerssh_socks_proxy_server_start(server, 0, request_tag));
    await_server(&active_server);
    DESTROY(outerssh_socks_proxy_server_destroy(server, request_tag));
    DESTROY(outerssh_session_pool_destroy(pool, request_tag));
    char user[] = {'u'};
    char secret[] = {'p', 0, 'w'};
    configuration.hostname = "localhost";
    configuration.username = user;
    configuration.username_length = sizeof(user);
    configuration.authentication.password = secret;
    configuration.authentication.password_length = sizeof(secret);
    pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(pool != NULL && error.domain == OUTERSSH_ERROR_NONE);
    DESTROY(outerssh_session_pool_destroy(pool, request_tag));

    configuration.authentication.password_length = 0;
    pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(pool != NULL && error.domain == OUTERSSH_ERROR_NONE);
    DESTROY(outerssh_session_pool_destroy(pool, request_tag));

    configuration.hostname = "local\0host";
    configuration.hostname_length = sizeof("local\0host") - 1;
    pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(pool == NULL && error.domain != OUTERSSH_ERROR_NONE);
    configuration.hostname = "localhost";
    configuration.hostname_length = sizeof("localhost") - 1;
    configuration.authentication = (OuterSSHSessionAuthentication){
        .kind = OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY,
        .private_key = "key", .private_key_length = 3,
        .passphrase = secret, .passphrase_length = sizeof(secret)
    };
    pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(pool == NULL && error.domain != OUTERSSH_ERROR_NONE);
    secret[1] = 'a';
    configuration.ssh_agent_socket_path = user;
    configuration.ssh_agent_socket_path_length = sizeof(user);
    pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    assert(pool != NULL && error.domain == OUTERSSH_ERROR_NONE);
    DESTROY(outerssh_session_pool_destroy(pool, request_tag));

    puts("PASS: public headers, standalone linking, automatic initialization, unterminated configuration, and event queue lifetime");
    ssh_test_event_queue_destroy(event_queue);
    return 0;
}
