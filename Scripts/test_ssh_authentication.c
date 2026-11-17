#include <stdlib.h>
#include "olibssh/libssh2/libssh2_priv.h"
#include "SSHReactorAuthentication.h"
#include "SSHReactorInternal.h"
#include <assert.h>
#include <stdio.h>

static int transport_result;
static unsigned transport_writes, queued_writes, write_updates;
static bool queued_packets_drained = true;
static bool finish_on_read;
static unsigned timer_arms, timer_cancels;
static void test_set_timer(otsource_t source, ottime_t start, uint64_t interval, uint64_t leeway)
{
    (void)start; (void)interval; (void)leeway;
    assert(source == (otsource_t)(uintptr_t)3);
    timer_arms++;
}
#undef otsource_set_timer
#define otsource_set_timer test_set_timer
static void (*read_handler)(void *), (*write_handler)(void *);

static int test_transport_write(LIBSSH2_SESSION *session,
    const unsigned char *packet, size_t length, const unsigned char *bytes, size_t byte_count)
{
    (void)session; (void)packet; (void)length; (void)bytes; (void)byte_count;
    transport_writes++;
    return transport_result;
}
static int test_transport_resume_write(LIBSSH2_SESSION *session)
{
    return test_transport_write(session, NULL, 0, NULL, 0);
}
static void test_set_event_handler(otsource_t source, void (*handler)(void *))
{
    if (source == (otsource_t)(uintptr_t)1) read_handler = handler;
    else {
        assert(source == (otsource_t)(uintptr_t)2);
        write_handler = handler;
    }
}
#undef otsource_set_event_handler
#define otsource_set_event_handler test_set_event_handler
#define olibssh_transport_write test_transport_write
#define olibssh_transport_resume_write test_transport_resume_write

static bool fail_next_allocation;
static void *authentication_test_malloc(size_t size)
{
    if (fail_next_allocation) {
        fail_next_allocation = false;
        return NULL;
    }
    return malloc(size);
}
static void schedule(otqueue_t queue, void *context, void (*function)(void *));
static void schedule_background(void *context, void (*function)(void *));
#undef otqueue_async
#define otqueue_async schedule
#define otqueue_async_background schedule_background
#define malloc authentication_test_malloc
#include "SSHReactorAuthentication.c"
#undef malloc
#undef otqueue_async
#undef otqueue_async_background

static void (*queued)(void *);
static void *queued_context;
static void (*background)(void *);
static unsigned completions;
static OuterSSHError result;
static char *result_storage;
static SSHReactor reactor;
static SSHAuthenticationContext *const authentication = &reactor.startup.authentication;

static void schedule(otqueue_t queue, void *context, void (*function)(void *))
{
    (void)queue;
    assert(queued == NULL);
    queued = function;
    queued_context = context;
}
static void schedule_background(void *context, void (*function)(void *))
{
    assert(background == NULL);
    (void)context;
    background = function;
}
static void run_queued(void)
{
    void (*function)(void *) = queued;
    queued = NULL;
    assert(function != NULL);
    function(queued_context);
}
static void completed(void *context, OuterSSHError error)
{
    assert(context == authentication);
    assert(reactor.phase == SSH_REACTOR_PHASE_NONE && !reactor.started);
    completions++;
    result = outerssh_error_copy(error, &result_storage);
    memset(&reactor.startup, 0xa5, sizeof(reactor.startup));
}
static void prepare(void)
{
    assert(queued == NULL && background == NULL);
    free(result_storage);
    result_storage = NULL;
    result = (OuterSSHError){0};
    completions = 0;
    transport_result = 0;
    transport_writes = queued_writes = write_updates = 0;
    queued_packets_drained = true;
    finish_on_read = false;
    timer_arms = timer_cancels = 0;
    reactor = (SSHReactor){.session = olibssh_session_init(), .started = true,
        .read_socket_source = (otsource_t)(uintptr_t)1,
        .write_socket_source = (otsource_t)(uintptr_t)2};
    assert(reactor.session != NULL);
    *authentication = (SSHAuthenticationContext){
        .reactor = &reactor, .finished = completed, .completion_context = authentication,
        .request = {.username = "user", .username_length = 4,
            .credentials = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
                .password = "p\0w", .password_length = 3}}
    };
    reactor.phase = SSH_REACTOR_PHASE_AUTHENTICATION;
}
static void dispose(void)
{
    if (reactor.phase == SSH_REACTOR_PHASE_AUTHENTICATION && !authentication->done) {
        fail_authentication(authentication, LIBSSH2_ERROR_SOCKET_DISCONNECT);
    }
    if (queued != NULL) run_queued();
    assert(completions == 1 && background == NULL);
    olibssh_session_free(reactor.session);
}
static void sent(void)
{
    assert(authentication->packet != NULL);
    free(authentication->packet);
    authentication->packet = NULL;
    authentication->packet_length = 0;
    authentication->awaiting_response = true;
}
static void receive(const void *packet, size_t length)
{
    outersshpriv_reactor_received_authentication(&reactor, packet, length);
}
static void rejected(const char *methods)
{
    unsigned char packet[256], *cursor = packet;
    *cursor++ = SSH_MSG_USERAUTH_FAILURE;
    _libssh2_store_str(&cursor, methods, strlen(methods));
    *cursor++ = 0;
    receive(packet, (size_t)(cursor - packet));
}
static void test_password(void)
{
    prepare();
    request_authentication_methods(authentication);
    sent();
    rejected("password,keyboard-interactive");
    assert(authentication->received == password_response_received);
    static const unsigned char ending[] = {0, 0, 0, 0, 3, 'p', 0, 'w'};
    assert(authentication->packet_length >= sizeof(ending));
    assert(memcmp(authentication->packet + authentication->packet_length - sizeof(ending),
        ending, sizeof(ending)) == 0);
    sent();
    rejected("keyboard-interactive");
    assert(authentication->received == keyboard_interactive_received);
    sent();
    const unsigned char success = SSH_MSG_USERAUTH_SUCCESS;
    receive(&success, 1);
    assert(authentication->done && (reactor.session->state & LIBSSH2_STATE_AUTHENTICATED));
    dispose();
}
static void test_prompts(void)
{
    for (unsigned count = 0; count < 4; count++) {
        prepare();
        request_keyboard_interactive(authentication);
        sent();
        for (unsigned round = 0; round < 2; round++) {
            unsigned char packet[256], *cursor = packet;
            *cursor++ = SSH_MSG_USERAUTH_INFO_REQUEST;
            _libssh2_store_str(&cursor, "name", 4);
            _libssh2_store_str(&cursor, "instruction", 11);
            _libssh2_store_u32(&cursor, 0);
            _libssh2_store_u32(&cursor, count);
            for (unsigned i = 0; i < count; i++) {
                _libssh2_store_str(&cursor, "Password:", 9);
                *cursor++ = (unsigned char)(i == 0);
            }
            receive(packet, (size_t)(cursor - packet));
            assert(!authentication->done && authentication->packet[0] == SSH_MSG_USERAUTH_INFO_RESPONSE);
            struct string_buf response = {.data = authentication->packet,
                .dataptr = authentication->packet + 1, .len = authentication->packet_length};
            uint32_t received_count;
            assert(_libssh2_get_u32(&response, &received_count) == 0 && received_count == count);
            for (unsigned i = 0; i < count; i++) {
                unsigned char *text;
                size_t length;
                assert(_libssh2_get_string(&response, &text, &length) == 0);
                size_t expected_length = count == 1 || i != 0 ? 3 : 0;
                assert(length == expected_length && memcmp(text, "p\0w", length) == 0);
            }
            assert(response.dataptr == response.data + response.len);
            sent();
        }
        rejected("keyboard-interactive");
        assert(authentication->done);
        dispose();
        assert(result.ssh_error_code == LIBSSH2_ERROR_AUTHENTICATION_FAILED);
    }
}
static void test_malformed_and_unexpected(void)
{
    const unsigned char prompts[] = {60, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,1, 0,0,0,1, '?', 0};
    for (size_t length = 1; length < sizeof(prompts); length++) {
        prepare();
        request_keyboard_interactive(authentication);
        sent();
        receive(prompts, length);
        assert(authentication->done);
        dispose();
        assert(result.ssh_error_code == LIBSSH2_ERROR_PROTO);
    }
    prepare();
    const unsigned char success = 52;
    receive(&success, 1);
    assert(!(reactor.session->state & LIBSSH2_STATE_AUTHENTICATED));
    dispose();
    assert(result.ssh_error_code == LIBSSH2_ERROR_PROTO);
}
static SSHQuestionContinuation pending_validation;
static void *pending_validation_context;
static const void *borrowed_host_key;
static OuterSSHEventQueue host_event_queue;
static OuterSSHSessionPool host_pool = {._event_queue = &host_event_queue};

void outersshpriv_session_pool_ask_host_key(OuterSSHSessionPool *pool,
    const void *key, size_t length, const char *fingerprint, size_t fingerprint_length,
    SSHQuestionContinuation continuation, void *context)
{
    assert(pool == &host_pool && key != NULL && length == 3);
    assert(fingerprint_length == 50 && memcmp(fingerprint, "SHA256:", 7) == 0);
    pending_validation = continuation;
    pending_validation_context = context;
    borrowed_host_key = key;
}

static void test_host_validation_lifetime(void)
{
    for (int reject = 0; reject < 2; reject++) {
        for (int cancel = 0; cancel < 4; cancel++) {
            prepare();
            host_pool._trustedHostKeyFingerprintLength = 0;
            authentication->request.host_key_pool = &host_pool;
            authentication->host_key = malloc(3);
            assert(authentication->host_key != NULL);
            memcpy(authentication->host_key, "key", 3);
            authentication->host_key_length = 3;
            record_fingerprint(authentication);
            authentication->validation_pending = true;
            authentication->timeout_timer = (otsource_t)(uintptr_t)3;
            if (cancel == 1) outersshpriv_authentication_failed(&reactor, LIBSSH2_ERROR_SOCKET_DISCONNECT);
            approve_host_key(authentication);
            assert(completions == 0 && queued == NULL && background == NULL);
            assert(authentication->packet == NULL && timer_arms == 0);
            if (cancel == 2) outersshpriv_authentication_failed(&reactor, LIBSSH2_ERROR_SOCKET_DISCONNECT);
            assert(memcmp(borrowed_host_key, "key", 3) == 0);
            pending_validation(pending_validation_context, reject ? SSH_QUESTION_DECLINED : SSH_QUESTION_ACCEPTED);
            assert(host_pool._trustedHostKeyFingerprintLength == (reject ? 0u : authentication->fingerprint_length));
            if (cancel == 3) outersshpriv_authentication_failed(&reactor, LIBSSH2_ERROR_SOCKET_DISCONNECT);
            assert(completions == 0);
            run_queued();
            if (!cancel && !reject) {
                assert(timer_arms == 1 && authentication->packet != NULL);
                assert(authentication->received == authentication_methods_received);
                SSHReactorSourceContext timer = {
                    .reactor = &reactor, .source = authentication->timeout_timer};
                authentication_timed_out(&timer);
            } else assert(timer_arms == 0);
            dispose();
            assert(timer_cancels == 1);
            if (cancel) assert(result.ssh_error_code == LIBSSH2_ERROR_SOCKET_DISCONNECT);
            else if (reject) {
                static const char untrusted[] = "The server's SSH host key was not trusted.";
                assert(result.domain == OUTERSSH_ERROR_HOST_KEY_VALIDATION && result.code == 1);
                assert(result.message_length == sizeof(untrusted) - 1 && memcmp(result.message, untrusted, sizeof(untrusted) - 1) == 0);
            } else assert(result.ssh_error_code == LIBSSH2_ERROR_TIMEOUT);
        }
    }
}

static void test_certificate_signature_names(void)
{
    static const char *certificates[] = {"rsa-sha2-512-cert-v01@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com",
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"};
    static const char *expected[] = {"rsa-sha2-512", "ssh-ed25519",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"};
    for (size_t index = 0; index < sizeof(certificates) / sizeof(certificates[0]); index++) {
        size_t length = strlen(certificates[index]);
        const char *method = olibssh_authentication_signature_method(certificates[index], &length);
        assert(length == strlen(expected[index]) && memcmp(method, expected[index], length) == 0);
    }
}

static void test_agent_algorithm_fallback(void)
{
    prepare();
    static const unsigned char key[] = "\0\0\0\x07" "ssh-rsa";
    authentication->key.session = olibssh_session_init();
    assert(authentication->key.session != NULL);
    authentication->key.agent = libssh2_agent_init(authentication->key.session);
    assert(authentication->key.agent != NULL);
    authentication->key.public_key = key;
    authentication->key.public_key_length = sizeof(key) - 1;
    authentication->signed_data = malloc(1);
    assert(authentication->signed_data != NULL);
    authentication->worker_error = LIBSSH2_ERROR_ALGO_UNSUPPORTED;
    authentication->worker_pending = true;
    public_key_request_signed(authentication);
    assert(authentication->using_original_key_method);
    assert(authentication->key_method_length == 7);
    assert(memcmp(authentication->key_method, "ssh-rsa", 7) == 0);
    assert(authentication->received == public_key_response_received && !authentication->done);
    dispose();
}

static void test_private_key_error_lifetime(void)
{
    prepare();
    authentication->key.session = olibssh_session_init();
    assert(authentication->key.session != NULL);
    static const char message[] = "Unsupported private-key format";
    _libssh2_error(authentication->key.session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED, message);
    authentication->worker_error = -1;
    capture_key_error(authentication);
    assert(authentication->worker_error == LIBSSH2_ERROR_METHOD_NOT_SUPPORTED);
    _libssh2_error(authentication->key.session, 0, NULL);
    authentication->worker_pending = true;
    private_key_loaded(authentication);
    dispose();
    assert(result.ssh_error_code == LIBSSH2_ERROR_METHOD_NOT_SUPPORTED);
    assert(result.ssh_error_message_length == sizeof(message) - 1);
    assert(memcmp(result.ssh_error_message, message, sizeof(message) - 1) == 0);
    assert(result.message_length == sizeof(message) - 1);
    assert(memcmp(result.message, message, sizeof(message) - 1) == 0);
}

static void test_allocation_failures(void)
{
    prepare();
    fail_next_allocation = true;
    request_password(authentication);
    assert(authentication->done);
    dispose();
    assert(result.ssh_error_code == LIBSSH2_ERROR_ALLOC);

    prepare();
    reactor.phase = SSH_REACTOR_PHASE_NONE;
    reactor.started = false;
    begin_authentication(authentication);
    assert(read_handler == authentication_socket_became_readable);
    assert(write_handler == authentication_socket_became_writable);
    assert(authentication->done);
    dispose();
    assert(result.ssh_error_code == LIBSSH2_ERROR_ALLOC);
}

void outersshpriv_reactor_assert_queue(SSHReactor *value) { assert(value == &reactor); }
bool outersshpriv_reactor_accepts_work(SSHReactor *value) { return value->lifecycle == SSH_REACTOR_LIFECYCLE_ACTIVE; }
void outersshpriv_reactor_set_ssh_read_source_resumed(SSHReactor *value, bool enabled)
{
    assert(value == &reactor);
    value->read_socket_source_is_resumed = enabled;
}
void outersshpriv_reactor_set_ssh_write_source_resumed(SSHReactor *value, bool enabled)
{
    assert(value == &reactor);
    value->write_socket_source_is_resumed = enabled;
}
void outersshpriv_reactor_read_packets(SSHReactor *value)
{
    assert(value == &reactor);
    if (finish_on_read) finish_authentication(authentication);
}
bool outersshpriv_reactor_write_queued_packets(SSHReactor *value)
{
    assert(value == &reactor && !authentication->packet_write_pending);
    queued_writes++;
    if (!queued_packets_drained) value->write_socket_source_is_resumed = true;
    return queued_packets_drained;
}
void outersshpriv_reactor_update_channel_write_source(SSHReactor *value)
{
    assert(value == &reactor);
    write_updates++;
    if (!value->key_exchange_in_progress) {
        value->write_socket_source_is_resumed = value->write_action_count != 0;
    }
}
void outersshpriv_reactor_safely_set_source_resumed(SSHReactor *value,
    otsource_t source, bool resumed, bool *is_resumed)
{ (void)value; (void)source; *is_resumed = resumed; }
void outersshpriv_reactor_fail(SSHReactor *value, SSHReactorOperation operation, int error)
{ (void)operation; outersshpriv_authentication_failed(value, error); }
SSHReactorSourceContext *outersshpriv_reactor_create_source_context(SSHReactor *value,
    otsource_t source) { (void)value; (void)source; return NULL; }
void outersshpriv_reactor_source_created(SSHReactor *value) { (void)value; abort(); }
void outersshpriv_reactor_cancel_source(otsource_t source)
{ assert(source == (otsource_t)(uintptr_t)3); timer_cancels++; }
void outersshpriv_reactor_timer_cancelled(void *context) { (void)context; abort(); }

static void test_authentication_source_transitions(void)
{
    prepare();
    request_password(authentication);
    transport_result = LIBSSH2_ERROR_EAGAIN;
    authentication_socket_became_writable(&reactor);
    assert(transport_writes == 1 && authentication->packet_write_pending);
    assert(reactor.write_socket_source_is_resumed);

    reactor.key_exchange_in_progress = true;
    reactor.read_socket_source_is_resumed = false;
    assert(outersshpriv_authentication_resume_write(&reactor) == LIBSSH2_ERROR_EAGAIN);
    assert(transport_writes == 2 && authentication->packet_write_pending);
    transport_result = 0;
    assert(outersshpriv_authentication_resume_write(&reactor) == 0);
    assert(transport_writes == 3 && authentication->packet == NULL);
    reactor.write_socket_source_is_resumed = false;
    request_password(authentication);
    assert(!reactor.write_socket_source_is_resumed);
    assert(transport_writes == 3);
    reactor.key_exchange_in_progress = false;
    outersshpriv_authentication_keys_exchanged(&reactor);
    assert(read_handler == authentication_socket_became_readable);
    assert(write_handler == authentication_socket_became_writable);
    assert(reactor.read_socket_source_is_resumed && reactor.write_socket_source_is_resumed);
    reactor.write_socket_source_is_resumed = true;
    queued_packets_drained = false;
    authentication_socket_became_writable(&reactor);
    assert(transport_writes == 3 && reactor.write_socket_source_is_resumed);
    queued_packets_drained = true;
    authentication_socket_became_writable(&reactor);
    assert(transport_writes == 4 && authentication->packet == NULL);
    assert(!reactor.write_socket_source_is_resumed);
    authentication_socket_became_writable(&reactor);
    assert(transport_writes == 4);

    reactor.read_socket_source_is_resumed = true;
    reactor.write_action_count = 1;
    authentication_socket_became_readable(&reactor);
    assert(reactor.write_socket_source_is_resumed);
    request_password(authentication);
    reactor.write_action_count = 0;
    unsigned updates = write_updates;
    authentication_socket_became_readable(&reactor);
    assert(write_updates == updates && reactor.write_socket_source_is_resumed);

    finish_on_read = true;
    authentication_socket_became_readable(&reactor);
    assert(authentication->done && !reactor.started && write_updates == updates);
    authentication_socket_became_writable(&reactor);
    assert(transport_writes == 4);
    dispose();
}

int main(void)
{
    assert(libssh2_init(0) == 0);
    test_authentication_source_transitions();
    test_password();
    test_prompts();
    test_malformed_and_unexpected();
    test_host_validation_lifetime();
    test_allocation_failures();
    test_private_key_error_lifetime();
    test_agent_algorithm_fallback();
    test_certificate_signature_names();
    free(result_storage);
    libssh2_exit();
    puts("PASS: byte-counted passwords, keyboard fallback/multiple rounds, prompt validation, unsolicited success rejection, host rejection, and deferred cancellation completion");
    return 0;
}
