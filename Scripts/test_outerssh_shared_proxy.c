#include "../OuterSSH/SSHSessionPoolInternal.h"
#include "../OuterSSH/SSHForwarder.h"
#define main single_server_integration_main
#include "test_outerssh_integration.c"
#undef main

static const ExpectedCommand checked_command = {.output = "OK", .count = 2, .error_output = ""};
static void use_bridge(void *context)
{
    OuterSSHSessionPool *pool = context;
    pool->_directStreamLocalUnsupported = true;
    ssh_test_semaphore_signal(completed);
}
static void expect_closed(otsocket_t socket)
{
    char byte;
    ssize_t count = otsocket_recv(socket, &byte, 1, 0);
    assert(count == 0 || (count < 0 && errno == ECONNRESET));
    otsocket_close(socket);
}

typedef struct { int port; const char *authorization; } HTTPTestEndpoint;
static void start_http(OuterSSHHTTPProxyServer *server, HTTPTestEndpoint *endpoint)
{
    assert(outerssh_http_proxy_server_start(server, 0, TAG_OPERATION));
    wait_for_completion(); check_error();
    endpoint->port = proxy_port;
}
static otsocket_t open_http(HTTPTestEndpoint endpoint, const char *host, int port, int status)
{
    otsocket_t socket = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(socket >= 0);
#if defined(_WIN32)
    DWORD timeout = 15000;
#else
    struct timeval timeout = {.tv_sec = 15};
#endif
    assert(!otsocket_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons((uint16_t)endpoint.port)};
    assert(!otsocket_connect(socket, (struct sockaddr *)&address, sizeof(address)));
    char request[1024];
    int n = snprintf(request, sizeof(request), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\n\r\n",
        host, port, host, port, endpoint.authorization);
    assert(n > 0 && (size_t)n < sizeof(request));
    send_all(socket, request, (size_t)n);
    char response[2048] = {0}; size_t count = 0;
    while (!strstr(response, "\r\n\r\n")) {
        assert(count + 1 < sizeof(response)); receive_all(socket, response + count++, 1);
    }
    assert(atoi(response + 9) == status);
    if (status != 200) { otsocket_close(socket); return -1; }
    return socket;
}
static void verify_shared_session(void *context)
{
    OuterSSHSessionPool *pool = context;
    size_t count = 0;
    for (SSHForwarder *server = pool->proxy_servers; server != NULL; server = server->next_in_pool) count++;
    assert(pool->live_sessions == 1 && count == 3);
    ssh_test_semaphore_signal(completed);
}
static void test_http_frontends(OuterSSHSessionPool *pool, const char *socket_host, int echo_port)
{
    OuterSSHProxyCredentials credentials = {.username = "web", .username_length = 3, .password = "secret", .password_length = 6};
    OuterSSHHTTPProxyServerConfiguration config = {.credentials = &credentials, .rewrite_loopback_addresses = true};
    OuterSSHError error;
    OuterSSHHTTPProxyServer *rewrite = outerssh_http_proxy_server_create(pool, &config, &error);
    assert(rewrite && !error.domain);
    credentials.username = "raw";
    config.rewrite_loopback_addresses = false;
    OuterSSHHTTPProxyServer *raw = outerssh_http_proxy_server_create(pool, &config, &error);
    assert(raw && !error.domain);
    HTTPTestEndpoint web_endpoint = {.authorization = "d2ViOnNlY3JldA=="}, raw_endpoint = {.authorization = "cmF3OnNlY3JldA=="};
    int socks_port = proxy_port;
    char socks_user[sizeof(proxy_username)], socks_password[sizeof(proxy_password)];
    memcpy(socks_user, proxy_username, sizeof(socks_user));
    memcpy(socks_password, proxy_password, sizeof(socks_password));
    start_http(rewrite, &web_endpoint);
    start_http(raw, &raw_endpoint);
    proxy_port = socks_port;
    memcpy(proxy_username, socks_user, sizeof(proxy_username));
    memcpy(proxy_password, socks_password, sizeof(proxy_password));
    HTTPTestEndpoint wrong = web_endpoint; wrong.authorization = raw_endpoint.authorization;
    open_http(wrong, "127.0.0.1", echo_port, 407);
    wrong = raw_endpoint; wrong.authorization = web_endpoint.authorization;
    open_http(wrong, "127.0.0.1", echo_port, 407);
    const char payload[] = "shared HTTP and SOCKS session";
    echo_stream(open_http(web_endpoint, "127.0.0.1", echo_port, 200), payload, sizeof(payload));
    echo_stream(open_http(raw_endpoint, "127.0.0.1", echo_port, 200), payload, sizeof(payload));
    echo_stream(open_http(web_endpoint, socket_host, 80, 200), payload, sizeof(payload));
    echo_stream(open_http(raw_endpoint, socket_host, 80, 200), payload, sizeof(payload));
    otqueue_async(pool->_queue, pool, verify_shared_session); wait_for_completion();
    otsocket_t held_web = open_http(web_endpoint, socket_host, 80, 200);
    otsocket_t held_raw = open_http(raw_endpoint, socket_host, 80, 200);
    assert(outerssh_http_proxy_server_destroy(rewrite, TAG_OPERATION)); wait_for_completion();
    expect_closed(held_web);
    echo_stream(held_raw, payload, sizeof(payload));
    echo_stream(open_socks(socket_host, 80, true, 0), payload, sizeof(payload));
    assert(outerssh_http_proxy_server_destroy(raw, TAG_OPERATION)); wait_for_completion();
}

int main(int argc, char **argv)
{
    start_events();
    assert(argc == 9);
    completed = ssh_test_semaphore_create(0);
    destroyed = ssh_test_semaphore_create(0);
    trusted_key = read_file(argv[3], &trusted_key_length);
    size_t key_length;
    void *key = read_file(argv[2], &key_length);
    bridge_path = argv[6];
    OuterSSHSessionPoolConfiguration configuration = {
        .hostname = "127.0.0.1", .hostname_length = sizeof("127.0.0.1") - 1,
        .username = "outerssh-test", .username_length = sizeof("outerssh-test") - 1,
        .port = atoi(argv[1]),
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY,
            .private_key = key, .private_key_length = key_length},
    };
    OuterSSHError error;
    OuterSSHSessionPool *a = create_pool(&configuration, HOST_KEYS_TRUST);
    configuration.port = atoi(argv[7]);
    configuration.username = "outerssh-second";
    configuration.username_length = sizeof("outerssh-second") - 1;
    OuterSSHSessionPool *b = create_pool(&configuration, HOST_KEYS_TRUST);
    free(key);
    /* Commands work before any proxy exists. */
    assert(outerssh_session_pool_execute_command(a, "printf OK", sizeof("printf OK") - 1, NULL, 0, command_tag(&checked_command)));
    wait_for_completion();
    assert(outerssh_session_pool_execute_command(b, "printf OK", sizeof("printf OK") - 1, NULL, 0, command_tag(&checked_command)));
    wait_for_completion();
    OuterSSHSOCKSProxyServerConfiguration proxy_configuration = {0};
    OuterSSHSOCKSProxyServer *server_a = outerssh_socks_proxy_server_create(a, &proxy_configuration, &error);
    OuterSSHSOCKSProxyServer *server_b = outerssh_socks_proxy_server_create(b, &proxy_configuration, &error);
    assert(server_a != NULL && server_b != NULL);
    assert(outerssh_socks_proxy_server_start(server_a, 0, TAG_OPERATION));
    wait_for_completion(); check_error();
    int port_a = proxy_port;
    char user_a[sizeof(proxy_username)], password_a[sizeof(proxy_password)];
    memcpy(user_a, proxy_username, sizeof(user_a));
    memcpy(password_a, proxy_password, sizeof(password_a));
    const char payload[] = "one SSH server per proxy";
    char socket_a[254], socket_b[254];
    size_t socket_a_length, socket_b_length;
    assert(outerssh_proxy_encode_unix_socket_host(argv[5], strlen(argv[5]), socket_a, sizeof(socket_a), &socket_a_length));
    assert(outerssh_proxy_encode_unix_socket_host(argv[8], strlen(argv[8]), socket_b, sizeof(socket_b), &socket_b_length));
    open_socks("127.0.0.1" OUTERSSH_PROXY_TCP_HOST_SUFFIX, atoi(argv[4]), false, 0);
    echo_stream(open_socks("127.0.0.1" OUTERSSH_PROXY_TCP_HOST_SUFFIX, atoi(argv[4]), true, 0), payload, sizeof(payload));
    echo_stream(open_socks("localhost", atoi(argv[4]), true, 0), payload, sizeof(payload));
    otqueue_async(a->_queue, a, use_bridge); wait_for_completion();
    echo_stream(open_socks(socket_a, 80, true, 0), payload, sizeof(payload));
    for (char *cursor = socket_a; *cursor; cursor++) {
        if (*cursor >= 'a' && *cursor <= 'z') *cursor -= 'a' - 'A';
    }
    echo_stream(open_socks(socket_a, 80, true, 0), payload, sizeof(payload));
    test_http_frontends(a, socket_a, atoi(argv[4]));
    otsocket_t held_a = open_socks(socket_a, 80, true, 0);
    assert(outerssh_socks_proxy_server_start(server_b, 0, TAG_OPERATION));
    wait_for_completion(); check_error();
    assert(proxy_port != port_a);
    echo_stream(open_socks("127.0.0.1" OUTERSSH_PROXY_TCP_HOST_SUFFIX, atoi(argv[4]), true, 0), payload, sizeof(payload));
    // The same socket URL goes through the selected proxy's server and allowlist.
    unsigned before = atomic_load(&binary_loads);
    open_socks(socket_a, 80, true, 1);
    echo_stream(open_socks(socket_b, 80, true, 0), payload, sizeof(payload));
    assert(atomic_load(&binary_loads) > before);
    otsocket_t held_b = open_socks(socket_b, 80, true, 0);
    assert(outerssh_socks_proxy_server_destroy(server_b, TAG_OPERATION)); wait_for_completion();
    expect_closed(held_b);
    assert(outerssh_session_pool_execute_command(b, "printf OK", sizeof("printf OK") - 1, NULL, 0, command_tag(&checked_command)));
    wait_for_completion();
    destroy_pool(b);
    echo_stream(held_a, payload, sizeof(payload));
    proxy_port = port_a;
    memcpy(proxy_username, user_a, sizeof(proxy_username));
    memcpy(proxy_password, password_a, sizeof(proxy_password));
    held_a = open_socks(socket_a, 80, true, 0);
    assert(outerssh_socks_proxy_server_stop(server_a, TAG_OPERATION)); wait_for_completion(); check_error();
    expect_closed(held_a);
    assert(outerssh_socks_proxy_server_start(server_a, 0, TAG_OPERATION)); wait_for_completion(); check_error();
    echo_stream(open_socks(socket_a, 80, true, 0), payload, sizeof(payload));
    assert(outerssh_socks_proxy_server_destroy(server_a, TAG_UNAWAITED));
    destroy_pool(a);
    for (int i = 0; i < 2; i++) assert(ssh_test_semaphore_wait(destroyed, 30 * NSEC_PER_SEC) == 0);
    free(trusted_key);
    ssh_test_semaphore_destroy(completed);
    ssh_test_semaphore_destroy(destroyed);
    stop_events();
    puts("PASS: separate proxies select independent SSH servers; shared session across HTTP and SOCKS, credentials, allowlists, restart, isolated teardown, and proxy-independent commands");
    return 0;
}
