#include "SSHTestEventQueue.h"
#include "SSHTestSupport.h"

#include <OuterSSH/OuterSSH.h>

static OuterSSHEventQueue *event_queue;

#include <assert.h>
#include "platform/OTQueue.h"
#include "platform/OTSocket.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ssh_test_semaphore_t completed, destroyed;
static OuterSSHError last_error;
static char *last_error_storage;
static int proxy_port;
static OuterSSHSOCKSProxyServer *proxy_server;
static char proxy_username[128], proxy_password[128];
static unsigned char *trusted_key;
static size_t trusted_key_length;
static atomic_uint validated_keys, binary_loads;
/* The gzip-compressed test bridge the pool asks for. */
static const char *bridge_path;

static char expected_failure_host[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
static atomic_uint reported_failures;
static char not_listening_host[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
static atomic_uint not_listening_failures;

static void connection_failed(const void *frontend, const char *host, uint16_t port, const char *path, OuterSSHError error)
{
    if (not_listening_host[0] != 0 && strcmp(host, not_listening_host) == 0) {
        assert(frontend == proxy_server && port == 80 && path[0] == '/');
        assert(error.domain == OUTERSSH_ERROR_SESSION && error.code == OUTERSSH_SESSION_ERROR_NOT_LISTENING);
        atomic_fetch_add(&not_listening_failures, 1);
        return;
    }
    if (strcmp(host, expected_failure_host) != 0) return;
    assert(frontend == proxy_server);
    assert(port == 80 && strstr(path, "-denied") != NULL);
    assert(error.domain == OUTERSSH_ERROR_PROXY);
    assert(error.code == OUTERSSH_PROXY_ERROR_SOCKET_AUTHORIZATION_FAILED);
    assert(strstr(error.message, "allowlist") != NULL);
    atomic_fetch_add(&reported_failures, 1);
}

static void wait_for_completion(void)
{
    assert(ssh_test_semaphore_wait(completed,
        30 * NSEC_PER_SEC) == 0);
}

static void check_error(void)
{
    if (last_error.domain != OUTERSSH_ERROR_NONE) {
        fprintf(stderr, "Unexpected error %d/%d: %s (%s)\n", last_error.domain,
            last_error.code, last_error.message, last_error.ssh_error_message);
        abort();
    }
}

/* Tags say what a completion event finishes. Commands pass their ExpectedCommand. */
enum { TAG_OPERATION = 1, TAG_POOL_DESTROYED, TAG_UNAWAITED };

static void record_error(OuterSSHError error)
{
    free(last_error_storage);
    last_error = outerssh_error_copy(error, &last_error_storage);
}

static void proxy_started(const OuterSSHEvent *event)
{
    if (event->proxy_started.error.domain != OUTERSSH_ERROR_NONE) return;
    proxy_port = event->proxy_started.listen_port;
    assert(event->proxy_started.username_length < sizeof(proxy_username));
    assert(event->proxy_started.password_length < sizeof(proxy_password));
    snprintf(proxy_username, sizeof(proxy_username), "%.*s", (int)event->proxy_started.username_length,
        event->proxy_started.username_length == 0 ? "" : event->proxy_started.username);
    snprintf(proxy_password, sizeof(proxy_password), "%.*s", (int)event->proxy_started.password_length,
        event->proxy_started.password_length == 0 ? "" : event->proxy_started.password);
}

static void *read_file(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
    long count = ftell(file);
    assert(count > 0 && fseek(file, 0, SEEK_SET) == 0);
    void *bytes = malloc((size_t)count);
    assert(bytes != NULL && fread(bytes, 1, (size_t)count, file) == (size_t)count);
    assert(fclose(file) == 0);
    *length = (size_t)count;
    return bytes;
}

typedef struct {
    const void *output;
    size_t count;
    const char *error_output;
    int status;
} ExpectedCommand;

static void command_completed(const OuterSSHEvent *event)
{
    const ExpectedCommand *expected = (const ExpectedCommand *)(uintptr_t)event->tag;
    record_error(event->command_completed.error);
    check_error();
    assert(event->command_completed.exit_status == expected->status);
    assert(event->command_completed.standard_output_length == expected->count);
    assert(expected->count == 0 || memcmp(event->command_completed.standard_output, expected->output, expected->count) == 0);
    size_t count = strlen(expected->error_output);
    assert(event->command_completed.standard_error_length == count);
    assert(count == 0 || memcmp(event->command_completed.standard_error, expected->error_output, count) == 0);
    ssh_test_semaphore_signal(completed);
}

static uint64_t command_tag(const ExpectedCommand *expected)
{
    return (uint64_t)(uintptr_t)expected;
}

static void send_all(otsocket_t socket, const void *bytes, size_t count)
{
    const unsigned char *cursor = bytes;
    while (count != 0) {
        ssize_t sent = otsocket_send(socket, cursor, count, OTSOCKET_SEND_FLAGS);
        if (sent < 0 && errno == EINTR) continue;
        assert(sent > 0);
        cursor += sent;
        count -= (size_t)sent;
    }
}

static void receive_all(otsocket_t socket, void *bytes, size_t count)
{
    unsigned char *cursor = bytes;
    while (count != 0) {
        ssize_t received = otsocket_recv(socket, cursor, count, 0);
        if (received < 0 && errno == EINTR) continue;
        assert(received > 0);
        cursor += received;
        count -= (size_t)received;
    }
}

static otsocket_t open_socks(const char *host, int port, bool authorized, int expected_status)
{
    otsocket_t socket_fd = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(socket_fd >= 0);
#if defined(_WIN32)
    DWORD timeout = 15000;
#else
    struct timeval timeout = {.tv_sec = 15};
#endif
    assert(otsocket_setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(otsocket_setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons((uint16_t)proxy_port)};
    assert(otsocket_connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    const unsigned char greeting[] = {5, 1, 2};
    unsigned char reply[10];
    send_all(socket_fd, greeting, sizeof(greeting));
    receive_all(socket_fd, reply, 2);
    assert(reply[0] == 5 && reply[1] == 2);
    const char *password = authorized ? proxy_password : "incorrect";
    unsigned char authentication[260];
    size_t user_length = strlen(proxy_username), password_length = strlen(password);
    authentication[0] = 1;
    authentication[1] = (unsigned char)user_length;
    memcpy(authentication + 2, proxy_username, user_length);
    authentication[2 + user_length] = (unsigned char)password_length;
    memcpy(authentication + 3 + user_length, password, password_length);
    send_all(socket_fd, authentication, 3 + user_length + password_length);
    receive_all(socket_fd, reply, 2);
    assert(reply[0] == 1 && reply[1] == (authorized ? 0 : 1));
    if (!authorized) { otsocket_close(socket_fd); return -1; }
    size_t host_length = strlen(host);
    unsigned char request[263] = {5, 1, 0, 3, (unsigned char)host_length};
    assert(host_length <= 255);
    memcpy(request + 5, host, host_length);
    request[5 + host_length] = (unsigned char)(port >> 8);
    request[6 + host_length] = (unsigned char)port;
    send_all(socket_fd, request, 7 + host_length);
    receive_all(socket_fd, reply, sizeof(reply));
    if (reply[0] != 5 || reply[1] != expected_status) {
        fprintf(stderr, "SOCKS %s:%d: expected %d, received %u/%u\n",
            host, port, expected_status, reply[0], reply[1]);
        abort();
    }
    if (expected_status != 0) { otsocket_close(socket_fd); return -1; }
    return socket_fd;
}

typedef struct { otsocket_t socket; const void *bytes; size_t count; ssh_test_semaphore_t done; } Writer;
static void write_stream(void *context)
{
    Writer *writer = context;
    send_all(writer->socket, writer->bytes, writer->count);
    assert(otsocket_shutdown(writer->socket, SHUT_WR) == 0);
    ssh_test_semaphore_signal(writer->done);
}

static void echo_stream(otsocket_t socket_fd, const void *bytes, size_t count)
{
    Writer writer = {.socket = socket_fd, .bytes = bytes, .count = count, .done = ssh_test_semaphore_create(0)};
    assert(writer.done);
    ssh_test_thread_start(write_stream, &writer);
    void *received = malloc(count);
    assert(received != NULL);
    receive_all(socket_fd, received, count);
    assert(memcmp(received, bytes, count) == 0);
    assert(ssh_test_semaphore_wait(writer.done, 30 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(writer.done);
    unsigned char last;
    assert(otsocket_recv(socket_fd, &last, 1, 0) == 0);
    free(received);
    otsocket_close(socket_fd);
}

typedef enum { HOST_KEYS_TRUST, HOST_KEYS_REJECT, HOST_KEYS_DEFER } HostKeyMode;

typedef struct {
    const char *path;
    ssh_test_semaphore_t updates;
    bool available;
} SocketWatch;

typedef struct {
    ssh_test_semaphore_t received;
    char *path;
    size_t path_length;
} ReceivedAvailability;

typedef struct {
    _Atomic(OuterSSHSessionPool *) pool;
    HostKeyMode host_keys;
} PoolHostKeys;

static PoolHostKeys pool_host_keys[8];
static atomic_bool pump_stopping;
static ssh_test_semaphore_t pump_stopped;
static SocketWatch *current_watches;
static ReceivedAvailability *current_received;
static ssh_test_semaphore_t deferred_host_key;
static char observed_fingerprint[OUTERSSH_HOST_KEY_FINGERPRINT_CAPACITY];
static size_t observed_fingerprint_length;
static unsigned char deferred_key[4096];
static size_t deferred_key_length;

static void socket_availability(const char *path, size_t length, bool available)
{
    if (current_received != NULL) {
        assert(available);
        free(current_received->path);
        current_received->path = malloc(length);
        assert(current_received->path != NULL);
        memcpy(current_received->path, path, length);
        current_received->path_length = length;
        ssh_test_semaphore_signal(current_received->received);
        return;
    }
    if (current_watches == NULL) return;
    for (size_t i = 0; i < 2; i++) {
        if (strlen(current_watches[i].path) == length && memcmp(path, current_watches[i].path, length) == 0) {
            current_watches[i].available = available;
            ssh_test_semaphore_signal(current_watches[i].updates);
            return;
        }
    }
    assert(false);
}

static PoolHostKeys *host_keys_for(const OuterSSHSessionPool *pool)
{
    for (size_t slot = 0; slot < 8; slot++) {
        if (atomic_load(&pool_host_keys[slot].pool) == pool) return &pool_host_keys[slot];
    }
    return NULL;
}

static void handle_completion(const OuterSSHEvent *event)
{
    switch (event->type) {
    case OUTERSSH_EVENT_COMMAND_COMPLETED:
        command_completed(event);
        return;
    case OUTERSSH_EVENT_DESTROYED:
        if (event->tag == TAG_POOL_DESTROYED) {
            atomic_store(&host_keys_for(event->pool)->pool, NULL);
            ssh_test_semaphore_signal(destroyed);
        } else if (event->tag == TAG_OPERATION) {
            ssh_test_semaphore_signal(completed);
        }
        return;
    case OUTERSSH_EVENT_PROXY_STARTED:
        proxy_started(event);
        break;
    default:
        break;
    }
    record_error(event->operation_completed.error);
    ssh_test_semaphore_signal(completed);
}

static void handle_event(const OuterSSHEvent *event)
{
    switch (event->type) {
    case OUTERSSH_EVENT_HOST_KEY_VALIDATION: {
        HostKeyMode host_keys = host_keys_for(event->pool)->host_keys;
        const unsigned char *key = event->host_key_validation.host_key;
        size_t length = event->host_key_validation.host_key_length;
        atomic_fetch_add(&validated_keys, 1);
        size_t algorithm_length = event->host_key_validation.host_key_algorithm_length;
        assert(algorithm_length > 0 && length >= 4 + algorithm_length &&
               memcmp(event->host_key_validation.host_key_algorithm, key + 4, algorithm_length) == 0 &&
               event->host_key_validation.host_key_algorithm[algorithm_length] == '\0');
        assert(event->host_key_validation.fingerprint_length < sizeof(observed_fingerprint));
        memcpy(observed_fingerprint, event->host_key_validation.fingerprint, event->host_key_validation.fingerprint_length + 1);
        observed_fingerprint_length = event->host_key_validation.fingerprint_length;
        if (host_keys == HOST_KEYS_DEFER) {
            assert(length <= sizeof(deferred_key));
            memcpy(deferred_key, key, length);
            deferred_key_length = length;
            ssh_test_semaphore_signal(deferred_host_key);
            break;
        }
        bool trusted = host_keys == HOST_KEYS_TRUST && length == trusted_key_length &&
            memcmp(key, trusted_key, length) == 0;
        outerssh_session_pool_answer_host_key(event->pool, event->host_key_validation.question, trusted);
        break;
    }
    case OUTERSSH_EVENT_HELPER_BINARY_NEEDED: {
        const char prefix[] = "linux-";
        const char suffix[] = "-glibc";
        size_t length = event->helper_binary_needed.platform_length;
        const char *name = event->helper_binary_needed.platform;
        assert(length > sizeof(prefix) - 1 + sizeof(suffix) - 1);
        assert(memcmp(name, prefix, sizeof(prefix) - 1) == 0);
        assert(memcmp(name + length - (sizeof(suffix) - 1), suffix, sizeof(suffix) - 1) == 0);
        atomic_fetch_add(&binary_loads, 1);
#if defined(_WIN32)
        HANDLE descriptor = CreateFileA(bridge_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);
        LARGE_INTEGER size;
        assert(descriptor != INVALID_HANDLE_VALUE && GetFileSizeEx(descriptor, &size));
        uint64_t file_size = (uint64_t)size.QuadPart;
#else
        int descriptor = open(bridge_path, O_RDONLY | O_CLOEXEC);
        struct stat status;
        assert(descriptor >= 0 && fstat(descriptor, &status) == 0);
        uint64_t file_size = (uint64_t)status.st_size;
#endif
        outerssh_session_pool_provide_helper_binary(event->pool, event->helper_binary_needed.question,
            descriptor, 0, file_size);
        break;
    }
    case OUTERSSH_EVENT_SOCKET_AVAILABILITY:
        socket_availability(event->socket_availability.path, event->socket_availability.path_length,
            event->socket_availability.available);
        break;
    case OUTERSSH_EVENT_CONNECTION_FAILED:
        connection_failed(event->connection_failed.frontend, event->connection_failed.host,
            event->connection_failed.port, event->connection_failed.socket_path, event->connection_failed.error);
        break;
    default:
        break;
    }
}

static void pump_events(void *context)
{
    (void)context;
    while (!atomic_load(&pump_stopping)) {
        if (!ssh_test_event_queue_wait(event_queue, 50)) continue;
        OuterSSHEvent events[8];
        size_t count;
        while ((count = outerssh_event_queue_poll(event_queue, events, 8)) != 0) {
            for (size_t i = 0; i < count; i++) {
                if (events[i].tag != 0) handle_completion(&events[i]);
                else handle_event(&events[i]);
            }
        }
    }
    ssh_test_semaphore_signal(pump_stopped);
}

static void start_events(void)
{
    event_queue = ssh_test_event_queue_create();
    assert(event_queue != NULL);
    atomic_init(&pump_stopping, false);
    pump_stopped = ssh_test_semaphore_create(0);
    ssh_test_thread_start(pump_events, NULL);
}

static void stop_events(void)
{
    atomic_store(&pump_stopping, true);
    assert(ssh_test_semaphore_wait(pump_stopped, 5 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(pump_stopped);
    ssh_test_event_queue_destroy(event_queue);
}

static OuterSSHSessionPool *create_pool(const OuterSSHSessionPoolConfiguration *configuration, HostKeyMode host_keys)
{
    OuterSSHSessionPool *pool = outerssh_session_pool_create(event_queue, configuration, &last_error);
    assert(pool != NULL);
    size_t slot = 0;
    while (atomic_load(&pool_host_keys[slot].pool) != NULL) assert(++slot < 8);
    pool_host_keys[slot].host_keys = host_keys;
    atomic_store(&pool_host_keys[slot].pool, pool);
    return pool;
}

static void destroy_pool(OuterSSHSessionPool *pool)
{
    assert(outerssh_session_pool_destroy(pool, TAG_POOL_DESTROYED));
}

/* A destination reached through a jump pool runs its SSH session over the jump
 * host's direct-tcpip channel, here to the same server. */
static void test_jump_host(OuterSSHSessionPool *jump_host, OuterSSHSessionPoolConfiguration configuration)
{
    configuration.jump_host = jump_host;
    OuterSSHSessionPool *destination = create_pool(&configuration, HOST_KEYS_TRUST);
    assert(outerssh_session_pool_ensure_session(destination, TAG_OPERATION));
    wait_for_completion(); check_error();
    ExpectedCommand command = {.output = "jumped", .count = 6, .error_output = ""};
    for (int i = 0; i < 3; i++) {
        assert(outerssh_session_pool_execute_command(destination, "printf jumped", sizeof("printf jumped") - 1,
            NULL, 0, command_tag(&command)));
    }
    for (int i = 0; i < 3; i++) wait_for_completion();
    outerssh_session_pool_poke(destination);
    outerssh_session_pool_poke(jump_host);
    assert(outerssh_session_pool_execute_command(destination, "printf jumped", sizeof("printf jumped") - 1,
        NULL, 0, command_tag(&command)));
    wait_for_completion();
    destroy_pool(destination);
    assert(ssh_test_semaphore_wait(destroyed, 30 * NSEC_PER_SEC) == 0);
}


static void disconnect_controller(OuterSSHSessionPool *pool)
{
    if (proxy_server != NULL) {
        assert(outerssh_socks_proxy_server_stop(proxy_server, TAG_OPERATION));
        wait_for_completion();
        assert(outerssh_socks_proxy_server_destroy(proxy_server, TAG_UNAWAITED));
        proxy_server = NULL;
    }
    destroy_pool(pool);
    assert(ssh_test_semaphore_wait(destroyed,
        30 * NSEC_PER_SEC) == 0);
}

typedef struct { const char *host; const void *bytes; size_t count; } SocketEcho;
static void connect_and_echo(void *context)
{
    SocketEcho *request = context;
    echo_stream(open_socks(request->host, 80, true, 0), request->bytes, request->count);
    ssh_test_semaphore_signal(completed);
}

static void expect_availability(SocketWatch *watch, bool available)
{
    assert(ssh_test_semaphore_wait(watch->updates, 20 * NSEC_PER_SEC) == 0);
    assert(watch->available == available);
}

static void run_remote(OuterSSHSessionPool *pool, const char *command)
{
    ExpectedCommand expected = {.output = "", .error_output = ""};
    assert(outerssh_session_pool_execute_command(pool, command, strlen(command), NULL, 0, command_tag(&expected)));
    wait_for_completion();
}

static void test_socket_service(OuterSSHSessionPool *pool, const char *echo_path, const char *host,
    const OuterSSHSessionPoolConfiguration *configuration)
{
    /* The integration SSH account and its allowlist belong to this disposable fixture. */
    const char monitor_path[] = "/tmp/outerssh-integration-monitor.sock";
    SocketWatch watches[] = {{echo_path, ssh_test_semaphore_create(0), false},
        {monitor_path, ssh_test_semaphore_create(0), false}};
    run_remote(pool, "rm -f /tmp/outerssh-integration-monitor.sock; "
        "printf '/tmp/outerssh-integration-monitor.sock\n' >> ~/.config/outerssh/http-unix.allow");
    current_watches = watches;
    for (size_t i = 0; i < 2; i++) {
        assert(outerssh_session_pool_watch_socket(pool, watches[i].path, strlen(watches[i].path), TAG_OPERATION));
        wait_for_completion(); check_error();
        expect_availability(&watches[i], i == 0);
    }
    run_remote(pool, "python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.bind('/tmp/outerssh-integration-monitor.sock')\"");
    expect_availability(&watches[1], true);
    /* Nothing listens at the file that bind left behind: a connection reports
     * it unavailable, and creating the socket again reports it available. */
    size_t monitor_host_length;
    assert(outerssh_proxy_encode_unix_socket_host(monitor_path, sizeof(monitor_path) - 1,
        not_listening_host, sizeof(not_listening_host), &monitor_host_length));
    open_socks(not_listening_host, 80, true, 5);
    expect_availability(&watches[1], false);
    for (unsigned attempt = 0; attempt < 100 && atomic_load(&not_listening_failures) == 0; attempt++)
        ssh_test_sleep_milliseconds(50);
    assert(atomic_load(&not_listening_failures) == 1);
    not_listening_host[0] = 0;
    run_remote(pool, "rm /tmp/outerssh-integration-monitor.sock; "
        "python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.bind('/tmp/outerssh-integration-monitor.sock')\"");
    expect_availability(&watches[1], true);
    run_remote(pool, "rm /tmp/outerssh-integration-monitor.sock");
    expect_availability(&watches[1], false);
    run_remote(pool, "pkill -f '[o]uterssh-helper service'");
    expect_availability(&watches[0], true);
    expect_availability(&watches[1], false);
    run_remote(pool, "printf '/tmp/outerssh-integration-monitor.sock\n' > ~/.config/outerssh/http-unix.allow");
    echo_stream(open_socks(host, 80, true, 0), "cached", 6);
    OuterSSHSessionPool *fresh_pool = create_pool(configuration, HOST_KEYS_TRUST);
    int saved_proxy_port = proxy_port;
    char saved_user[sizeof(proxy_username)], saved_password[sizeof(proxy_password)];
    memcpy(saved_user, proxy_username, sizeof(saved_user));
    memcpy(saved_password, proxy_password, sizeof(saved_password));
    OuterSSHSOCKSProxyServerConfiguration fresh_configuration = {0};
    OuterSSHSOCKSProxyServer *fresh_server = outerssh_socks_proxy_server_create(fresh_pool, &fresh_configuration, &last_error);
    assert(fresh_server != NULL);
    assert(outerssh_socks_proxy_server_start(fresh_server, 0, TAG_OPERATION));
    wait_for_completion(); check_error();
    char fresh_host[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
    size_t fresh_host_length;
    assert(outerssh_proxy_encode_unix_socket_host(echo_path, strlen(echo_path),
        fresh_host, sizeof(fresh_host), &fresh_host_length));
    open_socks(fresh_host, 80, true, 1);
    char command[1024];
    snprintf(command, sizeof(command),
        "mkdir -p ~/.config/outerloop; printf '%%s\n' '%s' > ~/.config/outerloop/http-unix.allow", echo_path);
    run_remote(pool, command);
    open_socks(fresh_host, 80, true, 1);
    assert(outerssh_socks_proxy_server_destroy(fresh_server, TAG_UNAWAITED));
    destroy_pool(fresh_pool);
    assert(ssh_test_semaphore_wait(destroyed, 30 * NSEC_PER_SEC) == 0);
    char legacy_path[] = "%h/.config/outerloop/http-unix.allow";
    OuterSSHSocketAllowlist legacy = {legacy_path, sizeof(legacy_path) - 1, false};
    OuterSSHSessionPoolConfiguration compatible = *configuration;
    compatible.additional_socket_allowlists = &legacy;
    compatible.additional_socket_allowlist_count = 1;
    fresh_pool = create_pool(&compatible, HOST_KEYS_TRUST);
    memset(legacy_path, 'x', sizeof(legacy_path));
    fresh_server = outerssh_socks_proxy_server_create(fresh_pool, &fresh_configuration, &last_error);
    assert(fresh_server != NULL);
    assert(outerssh_socks_proxy_server_start(fresh_server, 0, TAG_OPERATION));
    wait_for_completion(); check_error();
    echo_stream(open_socks(fresh_host, 80, true, 0), "legacy", 6);
    snprintf(command, sizeof(command), "printf '%%s\n' '%s' >> ~/.config/outerssh/http-unix.allow", echo_path);
    run_remote(pool, command);
    echo_stream(open_socks(fresh_host, 80, true, 0), "retry", 5);
    echo_stream(open_socks(host, 80, true, 0), "service", 7);
    assert(outerssh_socks_proxy_server_destroy(fresh_server, TAG_UNAWAITED));
    proxy_port = saved_proxy_port;
    memcpy(proxy_username, saved_user, sizeof(proxy_username));
    memcpy(proxy_password, saved_password, sizeof(proxy_password));
    destroy_pool(fresh_pool);
    assert(ssh_test_semaphore_wait(destroyed, 30 * NSEC_PER_SEC) == 0);
    for (size_t i = 0; i < 2; i++) {
        assert(outerssh_session_pool_unwatch_socket(pool, watches[i].path, strlen(watches[i].path), TAG_OPERATION));
        wait_for_completion(); check_error();
    }
    current_watches = NULL;
    assert(outerssh_session_pool_ensure_session(pool, TAG_OPERATION));
    wait_for_completion(); check_error();
    for (size_t i = 0; i < 2; i++) ssh_test_semaphore_destroy(watches[i].updates);
}

static void destroy_with_socket_watch(OuterSSHSessionPool *pool, const char *path)
{
    ReceivedAvailability received = {.received = ssh_test_semaphore_create(0)};
    current_received = &received;
    assert(outerssh_session_pool_watch_socket(pool, path, strlen(path), TAG_OPERATION));
    wait_for_completion(); check_error();
    assert(ssh_test_semaphore_wait(received.received, 20 * NSEC_PER_SEC) == 0);
    assert(outerssh_session_pool_watch_socket(pool, path, strlen(path), TAG_OPERATION));
    destroy_pool(pool);
    wait_for_completion();
    assert(ssh_test_semaphore_wait(destroyed, 30 * NSEC_PER_SEC) == 0);
    assert(received.path_length == strlen(path) && memcmp(received.path, path, received.path_length) == 0);
    current_received = NULL;
    free(received.path);
    ssh_test_semaphore_destroy(received.received);
}

static void test_destroy_during_host_decision(OuterSSHSessionPoolConfiguration configuration)
{
    deferred_host_key = ssh_test_semaphore_create(0);
    OuterSSHSessionPool *pool = create_pool(&configuration, HOST_KEYS_DEFER);
    assert(outerssh_session_pool_ensure_session(pool, TAG_OPERATION));
    assert(ssh_test_semaphore_wait(deferred_host_key, 10 * NSEC_PER_SEC) == 0);
    assert(deferred_key_length == trusted_key_length && memcmp(deferred_key, trusted_key, trusted_key_length) == 0);
    destroy_pool(pool);
    wait_for_completion();
    assert(last_error.domain != OUTERSSH_ERROR_NONE);
    assert(ssh_test_semaphore_wait(destroyed, 10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(deferred_host_key);
    puts("PASS: pool destruction cancels an unanswered host decision");
}

static void test_trusted_host_key_fingerprint(OuterSSHSessionPoolConfiguration configuration)
{
    assert(observed_fingerprint_length > 7 && memcmp(observed_fingerprint, "SHA256:", 7) == 0);
    assert(strlen(observed_fingerprint) == observed_fingerprint_length);
    char expected[OUTERSSH_HOST_KEY_FINGERPRINT_CAPACITY];
    memcpy(expected, observed_fingerprint, observed_fingerprint_length + 1);
    size_t expected_length = observed_fingerprint_length;
    unsigned questions = atomic_load(&validated_keys);
    configuration.trusted_host_key_fingerprint = expected;
    configuration.trusted_host_key_fingerprint_length = expected_length;
    OuterSSHSessionPool *pool = create_pool(&configuration, HOST_KEYS_REJECT);
    assert(outerssh_session_pool_command_dialect(pool) == OUTERSSH_COMMAND_DIALECT_UNKNOWN);
    assert(outerssh_session_pool_ensure_session(pool, TAG_OPERATION));
    wait_for_completion(); check_error();
    assert(outerssh_session_pool_command_dialect(pool) == OUTERSSH_COMMAND_DIALECT_POSIX);
    disconnect_controller(pool);
    assert(atomic_load(&validated_keys) == questions);

    static const char wrong[] = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    configuration.trusted_host_key_fingerprint = wrong;
    configuration.trusted_host_key_fingerprint_length = sizeof(wrong) - 1;
    observed_fingerprint_length = 0;
    pool = create_pool(&configuration, HOST_KEYS_REJECT);
    assert(outerssh_session_pool_ensure_session(pool, TAG_OPERATION));
    wait_for_completion();
    assert(last_error.domain == OUTERSSH_ERROR_HOST_KEY_VALIDATION);
    assert(observed_fingerprint_length == expected_length && strcmp(observed_fingerprint, expected) == 0);
    assert(outerssh_session_pool_command_dialect(pool) == OUTERSSH_COMMAND_DIALECT_UNKNOWN);
    disconnect_controller(pool);
    assert(atomic_load(&validated_keys) == questions + 1);

    observed_fingerprint_length = 0;
    pool = create_pool(&configuration, HOST_KEYS_TRUST);
    assert(outerssh_session_pool_ensure_session(pool, TAG_OPERATION));
    wait_for_completion(); check_error();
    assert(observed_fingerprint_length == expected_length && strcmp(observed_fingerprint, expected) == 0);
    disconnect_controller(pool);
    assert(atomic_load(&validated_keys) == questions + 2);
    puts("PASS: trusted fingerprints accept matching keys without questions and ask about others; the command dialect is known after connecting");
}

int main(int argc, char *argv[])
{
    start_events();
    assert(argc == 7 || argc == 8);
#if !defined(_WIN32)
    assert(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
#endif
    completed = ssh_test_semaphore_create(0);
    destroyed = ssh_test_semaphore_create(0);
    assert(completed != NULL && destroyed != NULL);
    trusted_key = read_file(argv[3], &trusted_key_length);
    size_t private_key_length;
    void *private_key = read_file(argv[2], &private_key_length);
    bridge_path = argv[6];
    OuterSSHSessionPoolConfiguration configuration = {
        .hostname = argc == 8 ? argv[7] : "127.0.0.1",
        .hostname_length = strlen(argc == 8 ? argv[7] : "127.0.0.1"),
        .username = "outerssh-test", .username_length = sizeof("outerssh-test") - 1, .port = atoi(argv[1]),
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY,
            .private_key = private_key, .private_key_length = private_key_length},
    };
    char *hostname = malloc(configuration.hostname_length);
    char *username = malloc(configuration.username_length);
    assert(hostname != NULL && username != NULL);
    memcpy(hostname, configuration.hostname, configuration.hostname_length);
    memcpy(username, configuration.username, configuration.username_length);
    configuration.hostname = hostname;
    configuration.username = username;
    OuterSSHSessionPool *pool = create_pool(&configuration, HOST_KEYS_REJECT);
    assert(outerssh_session_pool_ensure_session(pool, TAG_OPERATION));
    wait_for_completion();
    assert(last_error.domain == OUTERSSH_ERROR_HOST_KEY_VALIDATION);
    assert(strcmp(last_error.message, "The server's SSH host key was not trusted.") == 0);
    disconnect_controller(pool);
    assert(atomic_load(&validated_keys) == 1);
    test_trusted_host_key_fingerprint(configuration);

    test_destroy_during_host_decision(configuration);
    pool = create_pool(&configuration, HOST_KEYS_TRUST);
    assert(outerssh_session_pool_ensure_session(pool, TAG_OPERATION));
    wait_for_completion(); check_error();
    ExpectedCommand command = {.output = "stdout", .count = 6,
        .error_output = "stderr", .status = 7};
    static const char command_text[] = "printf stdout; printf stderr >&2; exit 7";
    char *command_bytes = malloc(sizeof(command_text) - 1);
    assert(command_bytes != NULL);
    memcpy(command_bytes, command_text, sizeof(command_text) - 1);
    for (int i = 0; i < 12; i++) {
        assert(outerssh_session_pool_execute_command(pool, command_bytes, sizeof(command_text) - 1,
            NULL, 0, command_tag(&command)));
    }
    free(command_bytes);
    for (int i = 0; i < 12; i++) wait_for_completion();
    test_jump_host(pool, configuration);

    size_t payload_length = 1024 * 1024;
    unsigned char *payload = malloc(payload_length);
    assert(payload != NULL);
    for (size_t i = 0; i < payload_length; i++) payload[i] = (unsigned char)(i * 37);
    ExpectedCommand cat = {.output = payload, .count = payload_length, .error_output = ""};
    assert(outerssh_session_pool_execute_command(pool, "cat", sizeof("cat") - 1, payload, payload_length,
        command_tag(&cat)));
    wait_for_completion();

    OuterSSHError server_error;
    OuterSSHSOCKSProxyServerConfiguration proxy_configuration = {0};
    proxy_server = outerssh_socks_proxy_server_create(pool, &proxy_configuration, &server_error);
    assert(proxy_server != NULL);
    assert(outerssh_socks_proxy_server_start(proxy_server, 0, TAG_OPERATION));
    wait_for_completion(); check_error();
    open_socks("127.0.0.1" OUTERSSH_PROXY_TCP_HOST_SUFFIX, atoi(argv[4]), false, 0);
    echo_stream(open_socks("127.0.0.1" OUTERSSH_PROXY_TCP_HOST_SUFFIX, atoi(argv[4]), true, 0), payload, payload_length);
    echo_stream(open_socks("127.0.0.1", atoi(argv[4]), true, 0), payload, payload_length);
    open_socks("127.0.0.1", 1, true, 5);

    char socket_host[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
    size_t socket_host_length;
    assert(outerssh_proxy_encode_unix_socket_host(argv[5], strlen(argv[5]), socket_host, sizeof(socket_host), &socket_host_length));
    SocketEcho first_connections = {.host = socket_host, .bytes = payload, .count = payload_length};
    for (unsigned i = 0; i < 4; i++) ssh_test_thread_start(connect_and_echo, &first_connections);
    for (unsigned i = 0; i < 4; i++) wait_for_completion();
    char session_username[sizeof(proxy_username)], session_password[sizeof(proxy_password)];
    strcpy(session_username, proxy_username);
    strcpy(session_password, proxy_password);
    char origin[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY + 8];
    snprintf(origin, sizeof(origin), "http://%s", socket_host);
    assert(!outerssh_socks_proxy_server_add_origin_credentials(proxy_server, "origin", 6, "origin-secret", 13,
        argv[5], strlen(argv[5]), TAG_OPERATION));
    assert(outerssh_socks_proxy_server_add_origin_credentials(proxy_server, "origin", 6, "origin-secret", 13,
        origin, strlen(origin), TAG_OPERATION));
    wait_for_completion(); check_error();
    strcpy(proxy_username, "origin");
    strcpy(proxy_password, "origin-secret");
    echo_stream(open_socks(socket_host, 80, true, 0), payload, payload_length);
    echo_stream(open_socks("127.0.0.1" OUTERSSH_PROXY_TCP_HOST_SUFFIX, atoi(argv[4]), true, 0), payload, payload_length);
    strcpy(proxy_username, session_username);
    strcpy(proxy_password, session_password);
    assert(outerssh_socks_proxy_server_remove_origin_credentials(proxy_server, "origin", 6, TAG_OPERATION));
    wait_for_completion(); check_error();
    char denied_host[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
    size_t denied_host_length;
    char denied_path[256];
    snprintf(denied_path, sizeof(denied_path), "%s-denied", argv[5]);
    assert(outerssh_proxy_encode_unix_socket_host(denied_path, strlen(denied_path), denied_host, sizeof(denied_host), &denied_host_length));
    strcpy(expected_failure_host, denied_host);
    open_socks(denied_host, 80, true, 1);
    for (unsigned attempt = 0; attempt < 100 && atomic_load(&reported_failures) == 0; attempt++)
        ssh_test_sleep_milliseconds(10);
    assert(atomic_load(&reported_failures) == 1);
    open_socks("invalid.unix.outerssh.localhost", 80, true, 2);
    open_socks(socket_host, 81, true, 2);
    echo_stream(open_socks(socket_host, 80, true, 0), payload, 64);

    test_socket_service(pool, argv[5], socket_host, &configuration);
    assert(atomic_load(&binary_loads) > 0);

    otsocket_t reset_socket = open_socks("127.0.0.1" OUTERSSH_PROXY_TCP_HOST_SUFFIX, atoi(argv[4]), true, 0);
    struct linger reset = {.l_onoff = 1, .l_linger = 0};
    assert(otsocket_setsockopt(reset_socket, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)) == 0);
    send_all(reset_socket, payload, 65536);
    otsocket_close(reset_socket);
    ExpectedCommand reset_cat = {.output = payload, .count = 16, .error_output = ""};
    assert(outerssh_session_pool_execute_command(pool, "cat", sizeof("cat") - 1, payload, 16, command_tag(&reset_cat)));
    wait_for_completion();
    disconnect_controller(pool);

    configuration.authentication = (OuterSSHSessionAuthentication){
        .kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD, .password = "outerssh-test-password",
        .password_length = sizeof("outerssh-test-password") - 1};
    char *password = malloc(configuration.authentication.password_length);
    assert(password != NULL);
    memcpy(password, configuration.authentication.password, configuration.authentication.password_length);
    configuration.authentication.password = password;
    pool = create_pool(&configuration, HOST_KEYS_TRUST);
    free(hostname);
    free(username);
    free(password);
    assert(outerssh_session_pool_execute_command(pool, command_text, sizeof(command_text) - 1,
        NULL, 0, command_tag(&command)));
    wait_for_completion();
    destroy_with_socket_watch(pool, argv[5]);
    free(private_key); free(trusted_key); free(payload);
    ssh_test_semaphore_destroy(completed);
    ssh_test_semaphore_destroy(destroyed);
    stop_events();
    puts("PASS: host-key rejection, key/password authentication, concurrent commands, binary stdin, SOCKS authentication, TCP/Unix/bridge relays, half-close, connection failure, reset isolation, pool-lifetime socket authorization, multi-path watches, missing sockets, sockets nothing listens on, service restart, independent pool authorization, authorization retries, and watch shutdown with application-owned notification data");
    return 0;
}
