#include "SSHTestReactor.h"
#include "SSHTestFakeEventQueue.h"
#include "SSHReactorAuthentication.h"
#include "SSHReactorHandshake.h"
#include "SSHSessionPoolInternal.h"
#include "SSHEventQueueInternal.h"
#include <stdio.h>
#include <string.h>

static ssh_test_semaphore_t completed, validation_entered;
static otqueue_t validation_queue;
static OuterSSHSessionPool host_pool;
static OuterSSHEventQueue host_event_queue;
static uint64_t pending_question;
static unsigned char pending_host_key[4096];
static size_t pending_host_key_length;
static unsigned completions;
static OuterSSHError result;
static char *result_storage;
static const char *expectation;

static void handshake_finished(void *context, int error)
{
    (void)context;
    assert(error == 0);
    ssh_test_semaphore_signal(completed);
}
static void authentication_finished(void *context, OuterSSHError error)
{
    (void)context;
    result = outerssh_error_copy(error, &result_storage);
    completions++;
    ssh_test_semaphore_signal(completed);
}
static void destroyed(void *context)
{
    (void)context;
    ssh_test_semaphore_signal(completed);
}
static void approve_host(const OuterSSHEvent *event)
{
    const unsigned char *key = event->host_key_validation.host_key;
    size_t length = event->host_key_validation.host_key_length;
    assert(key != NULL && length != 0);
    if (strcmp(expectation, "cancel") == 0 || strcmp(expectation, "delayed") == 0) {
        assert(length <= sizeof(pending_host_key));
        memcpy(pending_host_key, key, length);
        pending_host_key_length = length;
        pending_question = event->host_key_validation.question;
        ssh_test_semaphore_signal(validation_entered);
        return;
    }
    outerssh_session_pool_answer_host_key(&host_pool, event->host_key_validation.question,
        strcmp(expectation, "reject") != 0);
}
static void drain_host_questions(void *context)
{
    (void)context;
    OuterSSHEvent event;
    while (outerssh_event_queue_poll(&host_event_queue, &event, 1) == 1) {
        if (event.type == OUTERSSH_EVENT_HOST_KEY_VALIDATION) approve_host(&event);
    }
}
static void control_queue_is_available(void *context)
{
    (void)context;
    ssh_test_semaphore_signal(validation_entered);
}
static void *read_file(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file);
    assert(size > 0 && fseek(file, 0, SEEK_SET) == 0);
    *length = (size_t)size;
    void *bytes = malloc(*length);
    assert(bytes != NULL && fread(bytes, 1, *length, file) == *length);
    fclose(file);
    return bytes;
}
int main(int argc, char **argv)
{
    assert(argc == 8 || argc == 9);
    assert(otsocket_initialize() == 0);
    assert(libssh2_init(0) == 0);
    completed = ssh_test_semaphore_create(0);
    validation_entered = ssh_test_semaphore_create(0);
    validation_queue = ssh_test_queue_create("test.host-validation");
    assert(validation_queue != NULL);
    host_pool._queue = validation_queue;
    host_pool._event_queue = &host_event_queue;
    ssh_test_event_queue_observe(&host_event_queue, validation_queue, drain_host_questions, NULL);
    expectation = argv[7];
    otsocket_t socket = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(socket != -1);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[1]))};
    assert(inet_pton(AF_INET, argc == 9 ? argv[8] : "127.0.0.1", &address.sin_addr) == 1);
    assert(otsocket_connect(socket, (struct sockaddr *)&address, sizeof(address)) == 0);
    SSHSessionStartResult creation = {0};
    LIBSSH2_SESSION *session = outersshpriv_session_create(socket, &creation);
    assert(session != NULL);
    SSHReactor *reactor = ssh_test_reactor_create(socket, session);
    assert(reactor != NULL);
    outersshpriv_reactor_handshake(reactor, handshake_finished, NULL);
    assert(ssh_test_semaphore_wait(completed, 20 * NSEC_PER_SEC) == 0);

    void *key = NULL, *public_key = NULL;
    SSHAuthenticationRequest request = {.username = argv[2], .username_length = strlen(argv[2]),
        .host_key_pool = &host_pool,
        .timeout_milliseconds = strcmp(expectation, "delayed") == 0 ? 250 : 15000};
    if (strcmp(argv[3], "password") == 0) {
        request.credentials = (OuterSSHSessionAuthentication){
            .kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
            .password = argv[4], .password_length = strlen(argv[4])};
    } else if (strcmp(argv[3], "agent") == 0) {
        request.credentials.kind = OUTERSSH_SESSION_AUTHENTICATION_AGENT;
    } else {
        request.credentials.kind = OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY;
        key = read_file(argv[4], &request.credentials.private_key_length);
        request.credentials.private_key = key;
        if (strcmp(argv[3], "key-public") == 0 || strcmp(argv[3], "key-cert") == 0) {
            const char *suffix = strcmp(argv[3], "key-cert") == 0 ? "-cert.pub" : ".pub";
            size_t suffix_length = strlen(suffix);
            size_t path_length = strlen(argv[4]);
            char *path = malloc(path_length + suffix_length + 1);
            assert(path != NULL);
            memcpy(path, argv[4], path_length);
            memcpy(path + path_length, suffix, suffix_length + 1);
            public_key = read_file(path, &request.credentials.public_key_length);
            request.credentials.public_key = public_key;
            free(path);
        }
        request.credentials.passphrase = argv[5];
        request.credentials.passphrase_length = strlen(argv[5]);
    }
    request.agent_path = argv[6];
    request.agent_path_length = strlen(argv[6]);
    outersshpriv_reactor_authenticate(reactor, request, authentication_finished, NULL);
    if (strcmp(expectation, "cancel") == 0 || strcmp(expectation, "delayed") == 0) {
        assert(ssh_test_semaphore_wait(validation_entered, 5 * NSEC_PER_SEC) == 0);
        if (strcmp(expectation, "cancel") == 0) outersshpriv_reactor_cancel_startup(reactor);
        otqueue_async(validation_queue, NULL, control_queue_is_available);
        assert(ssh_test_semaphore_wait(validation_entered, 5 * NSEC_PER_SEC) == 0);
        assert(ssh_test_semaphore_wait(completed, 500 * NSEC_PER_MSEC) != 0);
        size_t key_length;
        const void *key_bytes = libssh2_session_hostkey(session, &key_length, NULL);
        assert(key_length == pending_host_key_length && memcmp(key_bytes, pending_host_key, key_length) == 0);
        outerssh_session_pool_answer_host_key(&host_pool, pending_question, true);
    }
    assert(ssh_test_semaphore_wait(completed, 20 * NSEC_PER_SEC) == 0);
    assert(completions == 1);
    bool success = strcmp(expectation, "success") == 0 || strcmp(expectation, "delayed") == 0;
    if ((result.domain == OUTERSSH_ERROR_NONE) != success) {
        fprintf(stderr, "expected %s, got error %d (%.*s)\n", expectation,
            result.ssh_error_code, (int)result.message_length, result.message);
        abort();
    }
    assert((libssh2_userauth_authenticated(session) != 0) == success);
    if (strcmp(expectation, "reject") == 0) assert(result.domain == OUTERSSH_ERROR_HOST_KEY_VALIDATION);
    if (strcmp(expectation, "cancel") == 0) assert(result.ssh_error_code == LIBSSH2_ERROR_SOCKET_DISCONNECT);
    outersshpriv_reactor_destroy(reactor, destroyed, NULL);
    assert(ssh_test_semaphore_wait(completed, 5 * NSEC_PER_SEC) == 0);
    free(key);
    free(public_key);
    free(result_storage);
    ssh_test_semaphore_destroy(completed);
    ssh_test_semaphore_destroy(validation_entered);
    otqueue_release(validation_queue);
    printf("PASS: %s authentication, expected %s\n", argv[3], expectation);
    return 0;
}
