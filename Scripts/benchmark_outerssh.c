/* Build with OUTERSSH_BENCHMARK_SERVER for the standalone remote source/sink. */
#include "SSHTestEventQueue.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static unsigned char buffer[64 * 1024];

static void fail(const char *message);
static void configure_socket(int socket);
static void send_bytes(int socket, const void *bytes, size_t length);
static void receive_bytes(int socket, void *bytes, size_t length);
static void encode_count(unsigned char bytes[8], uint64_t count);
static uint64_t decode_count(const unsigned char bytes[8]);
static void initialize_buffer(void);

#ifdef OUTERSSH_BENCHMARK_SERVER

static void serve_transfer(int socket);

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    initialize_buffer();
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) fail("socket");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    if (bind(listener, (struct sockaddr *)&address, length) != 0 ||
        listen(listener, 8) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0) fail("listen");
    printf("PORT %u\n", ntohs(address.sin_port));
    fflush(stdout);
    /* Closing the harness pipe ends the fixture, including on remote SSH. */
    struct pollfd descriptors[] = {{STDIN_FILENO, POLLIN, 0}, {listener, POLLIN, 0}};
    for (;;) {
        int result = poll(descriptors, 2, -1);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) fail("poll");
        if (descriptors[0].revents != 0) break;
        if (descriptors[1].revents & POLLIN) {
            int connection = accept(listener, NULL, NULL);
            if (connection < 0) fail("accept");
            configure_socket(connection);
            serve_transfer(connection);
            close(connection);
        }
    }
    close(listener);
    return 0;
}

static void serve_transfer(int socket)
{
    unsigned char request[9];
    receive_bytes(socket, request, sizeof(request));
    uint64_t count = decode_count(request + 1);
    if ((request[0] != 'U' && request[0] != 'D') || count == 0) fail("invalid request");
    send_bytes(socket, "R", 1);
    unsigned char start;
    receive_bytes(socket, &start, 1);
    if (start != 'G') fail("invalid start");
    for (uint64_t offset = 0; offset < count;) {
        size_t length = count - offset > sizeof(buffer) ? sizeof(buffer) : (size_t)(count - offset);
        if (request[0] == 'U') receive_bytes(socket, buffer, length);
        else send_bytes(socket, buffer, length);
        offset += length;
    }
    unsigned char acknowledgement[8];
    encode_count(acknowledgement, count);
    send_bytes(socket, acknowledgement, sizeof(acknowledgement));
}

#else

#include <OuterSSH/OuterSSH.h>
#include "SSHSessionPoolInternal.h"
#include "SSHReactorInternal.h"
#include <openssl/crypto.h>

static ssh_test_semaphore_t completed;
static unsigned char *trusted_keys;
static size_t trusted_keys_length;
static int forward_port;

static void wait_for_completion(void);
static void check_error(OuterSSHError error);
static OuterSSHEvent await_completion(OuterSSHEventQueue *event_queue, uint64_t tag);
static void inspect_session(void *context);
static void session_received(void *context, OuterSSHError error);
static void print_methods(void *context);
static void *read_file(const char *path, size_t *length);
static void transfer(char direction, uint64_t count, unsigned round);
static double monotonic_seconds(void);
static double cpu_seconds(void);
static uint64_t positive_number(const char *text, uint64_t maximum);

int main(int argc, char **argv)
{
    if (argc != 10) {
        fprintf(stderr, "Usage: %s host ssh-port user private-key trusted-host-keys destination-port bytes rounds warmup-bytes\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    initialize_buffer();
    int ssh_port = (int)positive_number(argv[2], 65535);
    uint16_t destination_port = (uint16_t)positive_number(argv[6], 65535);
    uint64_t count = positive_number(argv[7], INT64_MAX);
    unsigned rounds = (unsigned)positive_number(argv[8], 1000);
    uint64_t warmup = positive_number(argv[9], INT64_MAX);
    size_t key_length;
    void *key = read_file(argv[4], &key_length);
    trusted_keys = read_file(argv[5], &trusted_keys_length);
    completed = ssh_test_semaphore_create(0);
    if (completed == NULL) fail("semaphore allocation");
    OuterSSHEventQueue *event_queue = ssh_test_event_queue_create();
    if (event_queue == NULL) fail("event queue allocation");
    OuterSSHSessionPoolConfiguration configuration = {
        .hostname = argv[1], .hostname_length = strlen(argv[1]),
        .username = argv[3], .username_length = strlen(argv[3]), .port = ssh_port,
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY,
            .private_key = key, .private_key_length = key_length},
    };
    OuterSSHError error = {0};
    OuterSSHSessionPool *pool = outerssh_session_pool_create(event_queue, &configuration, &error);
    free(key);
    check_error(error);
    if (pool == NULL) fail("pool allocation");
    if (!outerssh_session_pool_ensure_session(pool, 1)) fail("session request");
    check_error(await_completion(event_queue, 1).operation_completed.error);
    otqueue_async(pool->_queue, pool, inspect_session);
    wait_for_completion();

    OuterSSHPortForward *forward = outerssh_port_forward_create(pool,
        "127.0.0.1", sizeof("127.0.0.1") - 1, destination_port, &error);
    check_error(error);
    if (forward == NULL) fail("forward allocation");
    if (!outerssh_port_forward_start(forward, 0, 2)) fail("forward request");
    OuterSSHEvent started = await_completion(event_queue, 2);
    check_error(started.port_forward_started.error);
    forward_port = started.port_forward_started.listen_port;
    if (forward_port == 0) fail("missing forward port");
    transfer('U', warmup, 0);
    transfer('D', warmup, 0);
    for (unsigned round = 1; round <= rounds; round++) {
        transfer('U', count, round);
        transfer('D', count, round);
    }
    if (!outerssh_port_forward_destroy(forward, 3)) fail("forward destruction");
    await_completion(event_queue, 3);
    if (!outerssh_session_pool_destroy(pool, 4)) fail("pool destruction");
    await_completion(event_queue, 4);
    ssh_test_event_queue_destroy(event_queue);
    ssh_test_semaphore_destroy(completed);
    free(trusted_keys);
    return 0;
}

static void wait_for_completion(void)
{
    if (ssh_test_semaphore_wait(completed, 30 * NSEC_PER_SEC) != 0)
        fail("SSH operation timed out");
}

static void check_error(OuterSSHError error)
{
    if (error.domain == OUTERSSH_ERROR_NONE) return;
    fprintf(stderr, "SSH error %d/%d: %.*s (%.*s)\n", error.domain, error.code,
        (int)error.message_length, error.message != NULL ? error.message : "",
        (int)error.ssh_error_message_length, error.ssh_error_message != NULL ? error.ssh_error_message : "");
    exit(1);
}

static OuterSSHEvent await_completion(OuterSSHEventQueue *event_queue, uint64_t tag)
{
    OuterSSHEvent event;
    for (int waited = 0; waited < 30000; waited += 100) {
        while (outerssh_event_queue_poll(event_queue, &event, 1) == 1) {
            if (event.type == OUTERSSH_EVENT_HOST_KEY_VALIDATION) {
                outerssh_session_pool_answer_host_key(event.pool, event.host_key_validation.question, true);
            } else if (event.tag == tag) {
                return event;
            }
        }
        ssh_test_event_queue_wait(event_queue, 100);
    }
    fail("SSH operation timed out");
    return event;
}

static SSHWaiter session_waiter;

static void inspect_session(void *context)
{
    outersshpriv_session_pool_run_when_ready(context, &session_waiter, session_received, context);
}

static void session_received(void *context, OuterSSHError error)
{
    SSHSessionPoolSessionHandle handle;
    SSHReactor *reactor = outersshpriv_session_pool_ready_reactor(context, &handle, &error);
    check_error(error);
    if (reactor == NULL) fail("missing SSH reactor");
    otqueue_async(reactor->queue, reactor, print_methods);
}

static void print_methods(void *context)
{
    SSHReactor *reactor = context;
    const int methods[] = {LIBSSH2_METHOD_KEX, LIBSSH2_METHOD_CRYPT_CS, LIBSSH2_METHOD_CRYPT_SC,
        LIBSSH2_METHOD_MAC_CS, LIBSSH2_METHOD_MAC_SC, LIBSSH2_METHOD_HOSTKEY, LIBSSH2_METHOD_COMP_CS, LIBSSH2_METHOD_COMP_SC};
    const char *names[] = {"kex", "upload_cipher", "download_cipher", "upload_mac", "download_mac", "host_key",
        "upload_compression", "download_compression"};
    printf("{\"type\":\"algorithms\",\"openssl\":\"%s\"", OpenSSL_version(OPENSSL_VERSION));
    for (size_t index = 0; index < sizeof(methods) / sizeof(methods[0]); index++) {
        const char *name = libssh2_session_methods(reactor->session, methods[index]);
        if (name == NULL) fail("missing negotiated algorithm");
        printf(",\"%s\":\"%s\"", names[index], name);
        if ((methods[index] == LIBSSH2_METHOD_COMP_CS || methods[index] == LIBSSH2_METHOD_COMP_SC) && strcmp(name, "none") != 0) fail("benchmark requires compression disabled");
    }
    printf("}\n");
    ssh_test_semaphore_signal(completed);
}

static void *read_file(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) fail(path);
    long size = ftell(file);
    if (size <= 0 || fseek(file, 0, SEEK_SET) != 0) fail(path);
    unsigned char *bytes = malloc((size_t)size);
    if (bytes == NULL || fread(bytes, 1, (size_t)size, file) != (size_t)size) fail(path);
    if (fclose(file) != 0) fail(path);
    *length = (size_t)size;
    return bytes;
}

static void transfer(char direction, uint64_t count, unsigned round)
{
    int connection = socket(AF_INET, SOCK_STREAM, 0);
    if (connection < 0) fail("socket");
    configure_socket(connection);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons((uint16_t)forward_port)};
    if (connect(connection, (struct sockaddr *)&address, sizeof(address)) != 0) fail("connect");
    unsigned char request[9] = {(unsigned char)direction};
    encode_count(request + 1, count);
    send_bytes(connection, request, sizeof(request));
    unsigned char ready;
    receive_bytes(connection, &ready, 1);
    if (ready != 'R') fail("invalid readiness acknowledgement");
    double cpu_start = cpu_seconds();
    double start = monotonic_seconds();
    send_bytes(connection, "G", 1);
    for (uint64_t offset = 0; offset < count;) {
        size_t length = count - offset > sizeof(buffer) ? sizeof(buffer) : (size_t)(count - offset);
        if (direction == 'U') send_bytes(connection, buffer, length);
        else receive_bytes(connection, buffer, length);
        offset += length;
    }
    unsigned char acknowledgement[8];
    receive_bytes(connection, acknowledgement, sizeof(acknowledgement));
    double elapsed = monotonic_seconds() - start;
    double cpu = cpu_seconds() - cpu_start;
    if (decode_count(acknowledgement) != count) fail("incorrect received byte count");
    close(connection);
    printf("{\"type\":\"%s\",\"direction\":\"%s\",\"round\":%u,\"bytes\":%" PRIu64
        ",\"seconds\":%.9f,\"cpu_seconds\":%.9f,\"mib_per_second\":%.3f}\n",
        round == 0 ? "warmup" : "sample", direction == 'U' ? "upload" : "download", round, count,
        elapsed, cpu, (double)count / (1024 * 1024) / elapsed);
}

static double monotonic_seconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) fail("clock_gettime");
    return value.tv_sec + value.tv_nsec / 1e9;
}

static double cpu_seconds(void)
{
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) fail("getrusage");
    return usage.ru_utime.tv_sec + usage.ru_stime.tv_sec +
        (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6;
}

static uint64_t positive_number(const char *text, uint64_t maximum)
{
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (text[0] == '-' || end == text || *end != 0 || errno != 0 || value == 0 || value > maximum)
        fail("invalid positive number");
    return (uint64_t)value;
}

#endif

static void fail(const char *message)
{
    fprintf(stderr, "%s (errno=%d: %s)\n", message, errno, strerror(errno));
    exit(1);
}

static void configure_socket(int socket)
{
    struct timeval timeout = {.tv_sec = 120};
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) fail("socket timeout");
}

static void send_bytes(int socket, const void *bytes, size_t length)
{
    const unsigned char *position = bytes;
    while (length != 0) {
        ssize_t count = send(socket, position, length, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail("send");
        position += count;
        length -= (size_t)count;
    }
}

static void receive_bytes(int socket, void *bytes, size_t length)
{
    unsigned char *position = bytes;
    while (length != 0) {
        ssize_t count = recv(socket, position, length, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail("receive (unexpected EOF or socket error)");
        position += count;
        length -= (size_t)count;
    }
}

static void encode_count(unsigned char bytes[8], uint64_t count)
{
    for (int index = 7; index >= 0; index--) {
        bytes[index] = (unsigned char)count;
        count >>= 8;
    }
}

static uint64_t decode_count(const unsigned char bytes[8])
{
    uint64_t count = 0;
    for (size_t index = 0; index < 8; index++) count = (count << 8) | bytes[index];
    return count;
}

static void initialize_buffer(void)
{
    uint32_t value = 0x51c734bd;
    for (size_t index = 0; index < sizeof(buffer); index++) {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        buffer[index] = (unsigned char)value;
    }
}
