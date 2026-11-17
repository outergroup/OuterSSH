#include "olibssh/libssh2/libssh2_priv.h"
#include "SSHReactorAuthentication.h"
#include "SSHReactorInternal.h"
#include "SSHSessionPoolInternal.h"
#include "SSHReactorReadInternal.h"
#include "platform/Base64.h"
#include "platform/SSHLogging.h"

#include <assert.h>

static const size_t MaximumAuthenticationPacketLength = MAX_SSH_PACKET_LEN - 0x100 - 1;

static void begin_authentication(void *context);
static void approve_host_key(void *context);
static void host_key_answered(void *context, SSHQuestionAnswer answer);
static void record_fingerprint(SSHAuthenticationContext *context);
static void host_key_approved(void *context);
static void request_authentication_methods(SSHAuthenticationContext *context);
static void authentication_methods_received(SSHAuthenticationContext *context, struct string_buf *packet);
static void request_password(SSHAuthenticationContext *context);
static void password_response_received(SSHAuthenticationContext *context, struct string_buf *packet);
static void request_keyboard_interactive(SSHAuthenticationContext *context);
static void keyboard_interactive_received(SSHAuthenticationContext *context, struct string_buf *packet);
static void open_agent(void *context);
static void agent_opened(void *context);
static void load_private_key(void *context);
static void capture_key_error(SSHAuthenticationContext *context);
static void private_key_loaded(void *context);
static void try_public_key(SSHAuthenticationContext *context);
static void public_key_response_received(SSHAuthenticationContext *context, struct string_buf *packet);
static void sign_public_key_request(void *context);
static void public_key_request_signed(void *context);
static void signed_response_received(SSHAuthenticationContext *context, struct string_buf *packet);
static void try_next_key(SSHAuthenticationContext *context);
static void next_agent_key(void *context);
static unsigned char *allocate_request(SSHAuthenticationContext *context,
    const char *method, size_t method_length, size_t payload_length);
static bool method_is_offered(const unsigned char *list, size_t length,
    const char *method, size_t method_length);
static int write_authentication_packet(SSHReactor *reactor);
static void authentication_socket_became_readable(void *context);
static void authentication_socket_became_writable(void *context);
static void send_packet(SSHAuthenticationContext *context,
    void (*received)(SSHAuthenticationContext *, struct string_buf *));
static void fail_authentication(SSHAuthenticationContext *context, int error);
static void finish_authentication(SSHAuthenticationContext *context);
static void deliver_authentication_result(void *context);
static bool worker_returned(SSHAuthenticationContext *context);
static void authentication_timed_out(void *context);

#pragma mark - Approve the Host and Discover Authentication Methods

void outersshpriv_reactor_authenticate(SSHReactor *reactor,
    SSHAuthenticationRequest request,
    void (*finished)(void *, OuterSSHError), void *completion_context)
{
    SSHAuthenticationContext *context = &reactor->startup.authentication;
    *context = (SSHAuthenticationContext){
        .reactor = reactor, .request = request,
        .finished = finished, .completion_context = completion_context
    };
    otqueue_async(reactor->queue, context, begin_authentication);
}

static void begin_authentication(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    SSHReactor *reactor = context->reactor;
    outersshpriv_reactor_assert_queue(reactor);
    assert(!reactor->started && reactor->phase == SSH_REACTOR_PHASE_NONE);
    reactor->phase = SSH_REACTOR_PHASE_AUTHENTICATION;
    otsource_set_event_handler(reactor->read_socket_source,
        authentication_socket_became_readable);
    otsource_set_event_handler(reactor->write_socket_source,
        authentication_socket_became_writable);
    reactor->started = true;
    if (!outersshpriv_reactor_accepts_work(reactor)) {
        fail_authentication(context, LIBSSH2_ERROR_SOCKET_DISCONNECT);
        return;
    }
    SSHReactorSourceContext *timer_context =
        outersshpriv_reactor_create_source_context(reactor, NULL);
    otsource_t timer = timer_context == NULL ? NULL :
        otsource_create(OTSOURCE_TYPE_TIMER, 0, reactor->queue);
    if (timer == NULL) {
        free(timer_context);
        fail_authentication(context, LIBSSH2_ERROR_ALLOC);
        return;
    }
    timer_context->source = timer;
    context->timeout_timer = timer;
    outersshpriv_reactor_source_created(reactor);
    otsource_set_context(timer, timer_context);
    otsource_set_cancel_handler(timer, outersshpriv_reactor_timer_cancelled);
    otsource_set_event_handler(timer, authentication_timed_out);
    otsource_set_timer(timer,
        context->request.host_key_pool == NULL
            ? ottime(OTTIME_NOW, context->request.timeout_milliseconds * NSEC_PER_MSEC)
            : OTTIME_FOREVER,
        OTTIME_FOREVER, 0);
    otsource_activate(timer);

    const char *client_cipher = libssh2_session_methods(reactor->session, LIBSSH2_METHOD_CRYPT_CS);
    const char *server_cipher = libssh2_session_methods(reactor->session, LIBSSH2_METHOD_CRYPT_SC);
    SSH_LOG_INFO(SSH_LOG_CATEGORY_AUTHENTICATION,
        "SSH ciphers: client-to-server=%{public}s, server-to-client=%{public}s",
        client_cipher != NULL ? client_cipher : "unknown",
        server_cipher != NULL ? server_cipher : "unknown");
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
    authentication_socket_became_readable(reactor);
    if (context->done) return;
    if (context->request.host_key_pool == NULL) {
        request_authentication_methods(context);
        return;
    }
    int host_key_type;
    const char *host_key = libssh2_session_hostkey(reactor->session,
        &context->host_key_length, &host_key_type);
    if (host_key == NULL || context->host_key_length == 0) {
        static const char message[] = "The SSH server did not provide a host key.";
        context->error = outerssh_session_error(OUTERSSH_SESSION_ERROR_HOST_KEY_UNAVAILABLE,
            message, sizeof(message) - 1);
        finish_authentication(context);
        return;
    }
    context->host_key = malloc(context->host_key_length);
    if (context->host_key == NULL) {
        fail_authentication(context, LIBSSH2_ERROR_ALLOC);
        return;
    }
    memcpy(context->host_key, host_key, context->host_key_length);
    record_fingerprint(context);
    context->validation_pending = true;
    otqueue_async(context->request.host_key_pool->_queue, context, approve_host_key);
}

static void record_fingerprint(SSHAuthenticationContext *context)
{
    static const char prefix[] = "SHA256:";
    unsigned char digest[32];
    unsigned char encoded[45];
    context->fingerprint_length = 0;
    if (context->host_key_length > UINT32_MAX ||
        libssh2_sha256(context->host_key, (uint32_t)context->host_key_length, digest) != 0) return;
    size_t length = outerssh_base64_encode(encoded, digest, sizeof(digest));
    while (length > 0 && encoded[length - 1] == '=') length--;
    memcpy(context->fingerprint, prefix, sizeof(prefix) - 1);
    memcpy(context->fingerprint + sizeof(prefix) - 1, encoded, length);
    context->fingerprint_length = sizeof(prefix) - 1 + length;
    context->fingerprint[context->fingerprint_length] = 0;
}

static bool fingerprint_is_trusted(SSHAuthenticationContext *context)
{
    OuterSSHSessionPool *pool = context->request.host_key_pool;
    return context->fingerprint_length != 0 &&
        context->fingerprint_length == pool->_trustedHostKeyFingerprintLength &&
        memcmp(context->fingerprint, pool->_trustedHostKeyFingerprint, context->fingerprint_length) == 0;
}

static void trust_fingerprint(SSHAuthenticationContext *context)
{
    OuterSSHSessionPool *pool = context->request.host_key_pool;
    size_t length = context->fingerprint_length;
    memcpy(pool->_trustedHostKeyFingerprint, context->fingerprint, length);
    pool->_trustedHostKeyFingerprintLength = length;
}

static void approve_host_key(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    OuterSSHSessionPool *pool = context->request.host_key_pool;
    if (fingerprint_is_trusted(context)) {
        host_key_answered(context, SSH_QUESTION_ACCEPTED);
        return;
    }
    if (context->fingerprint_length == 0) {
        host_key_answered(context, SSH_QUESTION_DECLINED);
        return;
    }
    outersshpriv_session_pool_ask_host_key(pool,
        context->host_key, context->host_key_length,
        context->fingerprint, context->fingerprint_length,
        host_key_answered, context);
}

static void host_key_answered(void *opaque_context, SSHQuestionAnswer answer)
{
    SSHAuthenticationContext *context = opaque_context;
    static const char untrusted[] = "The server's SSH host key was not trusted.";
    if (answer == SSH_QUESTION_ACCEPTED) {
        trust_fingerprint(context);
        context->validation_error = (OuterSSHError){0};
    } else if (answer == SSH_QUESTION_DECLINED) {
        context->validation_error = (OuterSSHError){.domain = OUTERSSH_ERROR_HOST_KEY_VALIDATION,
            .code = 1, .message = untrusted, .message_length = sizeof(untrusted) - 1};
    } else {
        context->validation_error = outerssh_proxy_closing_error();
    }
    otqueue_async(context->reactor->queue, context, host_key_approved);
}

static void host_key_approved(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    assert(context->validation_pending);
    context->validation_pending = false;
    if (context->done) {
        deliver_authentication_result(context);
        return;
    }
    free(context->host_key);
    context->host_key = NULL;
    if (context->validation_error.domain != OUTERSSH_ERROR_NONE) {
        context->error = context->validation_error;
        finish_authentication(context);
        return;
    }
    otsource_set_timer(context->timeout_timer,
        ottime(OTTIME_NOW, context->request.timeout_milliseconds * NSEC_PER_MSEC),
        OTTIME_FOREVER, 0);
    request_authentication_methods(context);
}

static void request_authentication_methods(SSHAuthenticationContext *context)
{
    static const char method[] = "none";
    if (allocate_request(context, method, sizeof(method) - 1, 0) != NULL) {
        send_packet(context, authentication_methods_received);
    }
}

static void authentication_methods_received(SSHAuthenticationContext *context, struct string_buf *packet)
{
    unsigned char *methods;
    size_t length;
    unsigned char partial_success;
    if (packet->data[0] != SSH_MSG_USERAUTH_FAILURE ||
        _libssh2_get_string(packet, &methods, &length) != 0 ||
        _libssh2_get_boolean(packet, &partial_success) != 0 ||
        packet->dataptr != packet->data + packet->len) {
        fail_authentication(context, LIBSSH2_ERROR_PROTO);
        return;
    }
    if (context->request.credentials.kind != OUTERSSH_SESSION_AUTHENTICATION_PASSWORD) {
        context->worker_pending = true;
        otqueue_async_background(context, open_agent);
        return;
    }
    static const char password[] = "password";
    static const char keyboard_interactive[] = "keyboard-interactive";
    context->keyboard_interactive_offered = method_is_offered(methods, length,
        keyboard_interactive, sizeof(keyboard_interactive) - 1);
    if (method_is_offered(methods, length, password, sizeof(password) - 1)) {
        request_password(context);
    } else if (context->keyboard_interactive_offered) {
        request_keyboard_interactive(context);
    } else {
        fail_authentication(context, LIBSSH2_ERROR_AUTHENTICATION_FAILED);
    }
}

#pragma mark - Password and Keyboard-Interactive Authentication

static void request_password(SSHAuthenticationContext *context)
{
    static const char method[] = "password";
    size_t length = context->request.credentials.password_length;
    unsigned char *cursor = allocate_request(context, method, sizeof(method) - 1, 5 + length);
    if (cursor == NULL) return;
    *cursor++ = 0;
    _libssh2_store_str(&cursor, context->request.credentials.password, length);
    send_packet(context, password_response_received);
}

static void password_response_received(SSHAuthenticationContext *context, struct string_buf *packet)
{
    if (packet->data[0] == SSH_MSG_USERAUTH_FAILURE) {
        if (context->keyboard_interactive_offered) {
            request_keyboard_interactive(context);
        } else {
            fail_authentication(context, LIBSSH2_ERROR_AUTHENTICATION_FAILED);
        }
    } else if (packet->data[0] == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
        fail_authentication(context, LIBSSH2_ERROR_PASSWORD_EXPIRED);
    } else {
        fail_authentication(context, LIBSSH2_ERROR_PROTO);
    }
}

static void request_keyboard_interactive(SSHAuthenticationContext *context)
{
    static const char method[] = "keyboard-interactive";
    unsigned char *cursor = allocate_request(context, method, sizeof(method) - 1, 8);
    if (cursor == NULL) return;
    _libssh2_store_u32(&cursor, 0);
    _libssh2_store_u32(&cursor, 0);
    send_packet(context, keyboard_interactive_received);
}

static void keyboard_interactive_received(SSHAuthenticationContext *context, struct string_buf *packet)
{
    if (packet->data[0] == SSH_MSG_USERAUTH_FAILURE) {
        fail_authentication(context, LIBSSH2_ERROR_AUTHENTICATION_FAILED);
        return;
    }
    unsigned char *text;
    size_t length;
    uint32_t count;
    if (packet->data[0] != SSH_MSG_USERAUTH_INFO_REQUEST ||
        _libssh2_get_string(packet, &text, &length) != 0 ||
        _libssh2_get_string(packet, &text, &length) != 0 ||
        _libssh2_get_string(packet, &text, &length) != 0 ||
        _libssh2_get_u32(packet, &count) != 0 ||
        count > (packet->len - (size_t)(packet->dataptr - packet->data)) / 5) {
        fail_authentication(context, LIBSSH2_ERROR_PROTO);
        return;
    }
    /* Count first, then serialize directly into one response allocation. */
    struct string_buf prompts = *packet;
    size_t response_length = 5 + (size_t)count * 4;
    if (response_length > MaximumAuthenticationPacketLength) {
        fail_authentication(context, LIBSSH2_ERROR_OUT_OF_BOUNDARY);
        return;
    }
    for (uint32_t index = 0; index < count; index++) {
        unsigned char echo;
        if (_libssh2_get_string(packet, &text, &length) != 0 ||
            _libssh2_get_boolean(packet, &echo) != 0) {
            fail_authentication(context, LIBSSH2_ERROR_PROTO);
            return;
        }
        if (echo == 0 || count == 1) {
            if (context->request.credentials.password_length > MaximumAuthenticationPacketLength - response_length) {
                fail_authentication(context, LIBSSH2_ERROR_OUT_OF_BOUNDARY);
                return;
            }
            response_length += context->request.credentials.password_length;
        }
    }
    if (packet->dataptr != packet->data + packet->len) {
        fail_authentication(context, LIBSSH2_ERROR_PROTO);
        return;
    }
    context->packet = malloc(response_length);
    if (context->packet == NULL) {
        fail_authentication(context, LIBSSH2_ERROR_ALLOC);
        return;
    }
    context->packet_length = response_length;
    unsigned char *cursor = context->packet;
    *cursor++ = SSH_MSG_USERAUTH_INFO_RESPONSE;
    _libssh2_store_u32(&cursor, count);
    for (uint32_t index = 0; index < count; index++) {
        unsigned char echo;
        _libssh2_get_string(&prompts, &text, &length);
        _libssh2_get_boolean(&prompts, &echo);
        size_t password_length = echo == 0 || count == 1
            ? context->request.credentials.password_length : 0;
        _libssh2_store_str(&cursor, context->request.credentials.password, password_length);
    }
    send_packet(context, keyboard_interactive_received);
}

#pragma mark - Try Agent Identities, Then the Supplied Private Key

static void open_agent(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    context->worker_error = olibssh_authentication_open_agent(&context->key,
        context->request.agent_path, context->request.agent_path_length);
    otqueue_async(context->reactor->queue, context, agent_opened);
}

static void agent_opened(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    if (!worker_returned(context)) return;
    if (context->worker_error == 0) {
        try_public_key(context);
    } else if (context->request.credentials.kind == OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY) {
        context->worker_pending = true;
        otqueue_async_background(context, load_private_key);
    } else {
        fail_authentication(context, context->worker_error);
    }
}

static void capture_key_error(SSHAuthenticationContext *context)
{
    free(context->worker_error_message);
    context->worker_error_message = NULL;
    if (context->worker_error != 0 && context->key.session != NULL) {
        char *message = NULL;
        int length = 0;
        int error = libssh2_session_last_error(context->key.session, &message, &length, 0);
        if (error != 0 && length > 0) {
            context->worker_error_message = malloc((size_t)length + 1);
            if (context->worker_error_message != NULL) {
                memcpy(context->worker_error_message, message, (size_t)length);
                context->worker_error_message[length] = '\0';
            }
            if (error == LIBSSH2_ERROR_METHOD_NOT_SUPPORTED) context->worker_error = error;
        }
    }
}

static void load_private_key(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    context->worker_error = olibssh_authentication_load_private_key(&context->key,
        context->request.credentials);
    capture_key_error(context);
    otqueue_async(context->reactor->queue, context, private_key_loaded);
}

static void private_key_loaded(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    if (!worker_returned(context)) return;
    if (context->worker_error != 0) {
        if (context->worker_error == LIBSSH2_ERROR_KEYFILE_AUTH_FAILED ||
            context->worker_error == LIBSSH2_ERROR_DECRYPT) {
            static const char message[] = "Could not unlock the private key. Check its passphrase.";
            context->error = outerssh_session_error(OUTERSSH_SESSION_ERROR_PASSPHRASE_REQUIRED,
                message, sizeof(message) - 1);
            context->error.ssh_error_code = context->worker_error;
            finish_authentication(context);
        } else {
            fail_authentication(context, context->worker_error);
        }
        return;
    }
    try_public_key(context);
}

static void try_public_key(SSHAuthenticationContext *context)
{
    if (context->key.public_key_length > MaximumAuthenticationPacketLength) {
        fail_authentication(context, LIBSSH2_ERROR_OUT_OF_BOUNDARY);
        return;
    }
    free(context->key_method);
    context->key_method = NULL;
    int error = olibssh_authentication_key_method(context->reactor->session,
        context->key.public_key, context->key.public_key_length,
        context->using_original_key_method, &context->key_method, &context->key_method_length);
    if (error != 0) {
        if (error == LIBSSH2_ERROR_METHOD_NONE) try_next_key(context);
        else fail_authentication(context, error);
        return;
    }
    static const char method[] = "publickey";
    unsigned char *cursor = allocate_request(context, method, sizeof(method) - 1,
        9 + context->key_method_length + context->key.public_key_length);
    if (cursor == NULL) return;
    *cursor++ = 0;
    _libssh2_store_str(&cursor, context->key_method, context->key_method_length);
    _libssh2_store_str(&cursor, (const char *)context->key.public_key, context->key.public_key_length);
    send_packet(context, public_key_response_received);
}

static void public_key_response_received(SSHAuthenticationContext *context, struct string_buf *packet)
{
    if (packet->data[0] == SSH_MSG_USERAUTH_FAILURE) {
        try_next_key(context);
        return;
    }
    unsigned char *method, *key;
    size_t method_length, key_length;
    if (packet->data[0] != SSH_MSG_USERAUTH_PK_OK ||
        _libssh2_get_string(packet, &method, &method_length) != 0 ||
        _libssh2_get_string(packet, &key, &key_length) != 0 ||
        packet->dataptr != packet->data + packet->len ||
        method_length != context->key_method_length ||
        memcmp(method, context->key_method, method_length) != 0 ||
        key_length != context->key.public_key_length ||
        memcmp(key, context->key.public_key, key_length) != 0) {
        fail_authentication(context, LIBSSH2_ERROR_PROTO);
        return;
    }
    static const char publickey[] = "publickey";
    unsigned char *cursor = allocate_request(context, publickey, sizeof(publickey) - 1,
        9 + method_length + key_length);
    if (cursor == NULL) return;
    *cursor++ = 1;
    _libssh2_store_str(&cursor, (const char *)method, method_length);
    _libssh2_store_str(&cursor, (const char *)key, key_length);
    size_t session_id_length;
    const unsigned char *session_id = olibssh_authentication_session_id(context->reactor->session,
        &session_id_length);
    context->signing_prefix_length = 4 + session_id_length;
    context->signed_data_length = context->signing_prefix_length + context->packet_length;
    context->signed_data = malloc(context->signed_data_length);
    if (context->signed_data == NULL) {
        fail_authentication(context, LIBSSH2_ERROR_ALLOC);
        return;
    }
    cursor = context->signed_data;
    _libssh2_store_str(&cursor, (const char *)session_id, session_id_length);
    memcpy(cursor, context->packet, context->packet_length);
    free(context->packet);
    context->packet = NULL;
    context->packet_length = 0;
    context->worker_pending = true;
    otqueue_async_background(context, sign_public_key_request);
}

static void sign_public_key_request(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    context->worker_error = olibssh_authentication_sign(&context->key,
        context->key_method, context->key_method_length,
        context->signed_data, context->signed_data_length,
        &context->signature, &context->signature_length);
    capture_key_error(context);
    otqueue_async(context->reactor->queue, context, public_key_request_signed);
}

static void public_key_request_signed(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    if (!worker_returned(context)) return;
    if (context->worker_error != 0) {
        free(context->signed_data);
        context->signed_data = NULL;
        if (context->worker_error == LIBSSH2_ERROR_ALGO_UNSUPPORTED &&
            !context->using_original_key_method) {
            context->using_original_key_method = true;
            try_public_key(context);
        } else if (context->key.agent != NULL) {
            try_next_key(context);
        } else if (context->worker_error == LIBSSH2_ERROR_METHOD_NOT_SUPPORTED) {
            fail_authentication(context, context->worker_error);
        } else {
            static const char message[] = "Could not unlock the private key. Check its passphrase.";
            context->error = outerssh_session_error(OUTERSSH_SESSION_ERROR_PASSPHRASE_REQUIRED,
                message, sizeof(message) - 1);
            context->error.ssh_error_code = context->worker_error;
            finish_authentication(context);
        }
        return;
    }
    size_t method_length = context->key_method_length;
    const char *signature_method = olibssh_authentication_signature_method(context->key_method, &method_length);
    bool security_key = method_length >= 3 && memcmp(signature_method, "sk-", 3) == 0;
    size_t request_length = context->signed_data_length - context->signing_prefix_length;
    if (context->signature_length > MaximumAuthenticationPacketLength) {
        fail_authentication(context, LIBSSH2_ERROR_OUT_OF_BOUNDARY);
        return;
    }
    size_t signature_blob_length = 4 + method_length + (security_key ? 0 : 4) + context->signature_length;
    if (signature_blob_length > MaximumAuthenticationPacketLength - 4 ||
        request_length > MaximumAuthenticationPacketLength - 4 - signature_blob_length) {
        fail_authentication(context, LIBSSH2_ERROR_OUT_OF_BOUNDARY);
        return;
    }
    context->packet_length = request_length + 4 + signature_blob_length;
    context->packet = malloc(context->packet_length);
    if (context->packet == NULL) {
        fail_authentication(context, LIBSSH2_ERROR_ALLOC);
        return;
    }
    memcpy(context->packet, context->signed_data + context->signing_prefix_length, request_length);
    unsigned char *cursor = context->packet + request_length;
    _libssh2_store_u32(&cursor, (uint32_t)signature_blob_length);
    _libssh2_store_str(&cursor, signature_method, method_length);
    if (!security_key) {
        _libssh2_store_u32(&cursor, (uint32_t)context->signature_length);
    }
    memcpy(cursor, context->signature, context->signature_length);
    libssh2_free(context->key.session, context->signature);
    context->signature = NULL;
    free(context->signed_data);
    context->signed_data = NULL;
    send_packet(context, signed_response_received);
}

static void signed_response_received(SSHAuthenticationContext *context, struct string_buf *packet)
{
    if (packet->data[0] == SSH_MSG_USERAUTH_FAILURE) {
        try_next_key(context);
    } else {
        fail_authentication(context, LIBSSH2_ERROR_PROTO);
    }
}

static void try_next_key(SSHAuthenticationContext *context)
{
    if (context->key.agent == NULL) {
        fail_authentication(context, LIBSSH2_ERROR_AUTHENTICATION_FAILED);
        return;
    }
    context->using_original_key_method = false;
    context->worker_pending = true;
    otqueue_async_background(context, next_agent_key);
}

static void next_agent_key(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    context->worker_error = olibssh_authentication_next_agent_key(&context->key);
    otqueue_async(context->reactor->queue, context, agent_opened);
}

#pragma mark - Authentication Packet I/O and Completion

static unsigned char *allocate_request(SSHAuthenticationContext *context,
    const char *method, size_t method_length, size_t payload_length)
{
    static const char service[] = "ssh-connection";
    assert(context->packet == NULL);
    size_t header_length = 1 + 12 + context->request.username_length + sizeof(service) - 1 + method_length;
    if (header_length > MaximumAuthenticationPacketLength || payload_length > MaximumAuthenticationPacketLength - header_length) {
        fail_authentication(context, LIBSSH2_ERROR_OUT_OF_BOUNDARY);
        return NULL;
    }
    context->packet_length = header_length + payload_length;
    context->packet = malloc(context->packet_length);
    if (context->packet == NULL) {
        fail_authentication(context, LIBSSH2_ERROR_ALLOC);
        return NULL;
    }
    unsigned char *cursor = context->packet;
    *cursor++ = SSH_MSG_USERAUTH_REQUEST;
    _libssh2_store_str(&cursor, context->request.username, context->request.username_length);
    _libssh2_store_str(&cursor, service, sizeof(service) - 1);
    _libssh2_store_str(&cursor, method, method_length);
    return cursor;
}

static bool method_is_offered(const unsigned char *list, size_t length,
    const char *method, size_t method_length)
{
    if (length == 0) return true;
    while (length != 0) {
        const unsigned char *end = memchr(list, ',', length);
        size_t item_length = end == NULL ? length : (size_t)(end - list);
        if (item_length == method_length && memcmp(list, method, method_length) == 0) return true;
        if (end == NULL) break;
        list = end + 1;
        length -= item_length + 1;
    }
    return false;
}

static void authentication_socket_became_readable(void *opaque_context)
{
    SSHReactor *reactor = opaque_context;
    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor) ||
        !reactor->read_socket_source_is_resumed) {
        return;
    }
    outersshpriv_reactor_read_packets(reactor);
    if (reactor->started && reactor->startup.authentication.packet == NULL) {
        outersshpriv_reactor_update_channel_write_source(reactor);
    }
}

static void authentication_socket_became_writable(void *opaque_context)
{
    SSHReactor *reactor = opaque_context;
    if (!reactor->started || !outersshpriv_reactor_accepts_work(reactor) ||
        !reactor->write_socket_source_is_resumed) {
        return;
    }
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
    if (reactor->startup.authentication.packet_write_pending) {
        int error = write_authentication_packet(reactor);
        if (error == LIBSSH2_ERROR_EAGAIN) {
            outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
            return;
        }
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
            return;
        }
    }
    if (!outersshpriv_reactor_write_queued_packets(reactor)) {
        return;
    }
    if (reactor->startup.authentication.packet != NULL) {
        int error = write_authentication_packet(reactor);
        if (error == LIBSSH2_ERROR_EAGAIN) {
            outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
            return;
        }
        if (error != 0) {
            outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_WRITE, error);
            return;
        }
    }
    outersshpriv_reactor_update_channel_write_source(reactor);
}

int outersshpriv_authentication_resume_write(SSHReactor *reactor)
{
    assert(reactor->startup.authentication.packet_write_pending);
    return write_authentication_packet(reactor);
}

void outersshpriv_authentication_keys_exchanged(SSHReactor *reactor)
{
    otsource_set_event_handler(reactor->read_socket_source,
        authentication_socket_became_readable);
    otsource_set_event_handler(reactor->write_socket_source,
        authentication_socket_became_writable);
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, true);
    if (reactor->startup.authentication.packet != NULL) {
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    } else {
        outersshpriv_reactor_update_channel_write_source(reactor);
    }
    authentication_socket_became_readable(reactor);
}

static void send_packet(SSHAuthenticationContext *context,
    void (*received)(SSHAuthenticationContext *, struct string_buf *))
{
    context->received = received;
    SSHReactor *reactor = context->reactor;
    if (!reactor->key_exchange_in_progress) {
        outersshpriv_reactor_set_ssh_write_source_resumed(reactor, true);
    }
}

static int write_authentication_packet(SSHReactor *reactor)
{
    SSHAuthenticationContext *context = &reactor->startup.authentication;
    int error = context->packet_write_pending
        ? olibssh_transport_resume_write(reactor->session)
        : olibssh_transport_write(reactor->session, context->packet, context->packet_length, NULL, 0);
    context->packet_write_pending = error == LIBSSH2_ERROR_EAGAIN;
    if (error == 0) {
        _libssh2_explicit_zero(context->packet, context->packet_length);
        free(context->packet);
        context->packet = NULL;
        context->packet_length = 0;
        context->awaiting_response = true;
    }
    return error;
}

void outersshpriv_reactor_received_authentication(SSHReactor *reactor,
    const unsigned char *bytes, size_t length)
{
    SSHAuthenticationContext *context = &reactor->startup.authentication;
    struct string_buf packet = {
        .data = (unsigned char *)bytes, .dataptr = (unsigned char *)bytes + 1, .len = length
    };
    if (length == 0 || reactor->phase != SSH_REACTOR_PHASE_AUTHENTICATION || context->done) {
        outersshpriv_reactor_fail(reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_PROTO);
        return;
    }
    if (bytes[0] == SSH_MSG_USERAUTH_BANNER) {
        unsigned char *text;
        size_t text_length;
        if (_libssh2_get_string(&packet, &text, &text_length) != 0 ||
            _libssh2_get_string(&packet, &text, &text_length) != 0 ||
            packet.dataptr != packet.data + packet.len) {
            fail_authentication(context, LIBSSH2_ERROR_PROTO);
        }
        return;
    }
    if (!context->awaiting_response || context->received == NULL || context->worker_pending) {
        fail_authentication(context, LIBSSH2_ERROR_PROTO);
        return;
    }
    context->awaiting_response = false;
    if (bytes[0] == SSH_MSG_USERAUTH_SUCCESS) {
        if (length != 1) {
            fail_authentication(context, LIBSSH2_ERROR_PROTO);
            return;
        }
        olibssh_authentication_succeeded(reactor->session);
        finish_authentication(context);
        return;
    }
    if (bytes[0] == SSH_MSG_USERAUTH_FAILURE) {
        struct string_buf failure = packet;
        unsigned char *methods, partial;
        size_t methods_length;
        if (_libssh2_get_string(&failure, &methods, &methods_length) != 0 ||
            _libssh2_get_boolean(&failure, &partial) != 0 ||
            failure.dataptr != failure.data + failure.len) {
            fail_authentication(context, LIBSSH2_ERROR_PROTO);
            return;
        }
    }
    context->received(context, &packet);
}

void outersshpriv_authentication_failed(SSHReactor *reactor, int error)
{
    fail_authentication(&reactor->startup.authentication, error);
}

static void fail_authentication(SSHAuthenticationContext *context, int error)
{
    if (context->done) return;
    static const char failed[] = "SSH authentication failed.";
    static const char timed_out[] = "Timed out authenticating with the SSH server.";
    const char *message = error == LIBSSH2_ERROR_TIMEOUT ? timed_out : failed;
    size_t length = error == LIBSSH2_ERROR_TIMEOUT ? sizeof(timed_out) - 1 : sizeof(failed) - 1;
    context->error = outerssh_session_error(OUTERSSH_SESSION_ERROR_AUTHENTICATION_FAILED, message, length);
    context->error.ssh_error_code = error;
    if (!context->worker_pending && error == context->worker_error && context->worker_error_message != NULL) {
        context->error.ssh_error_message = context->worker_error_message;
        context->error.ssh_error_message_length = strlen(context->worker_error_message);
        if (error == LIBSSH2_ERROR_METHOD_NOT_SUPPORTED) {
            context->error.message = context->worker_error_message;
            context->error.message_length = context->error.ssh_error_message_length;
        }
    }
    finish_authentication(context);
}

static void finish_authentication(SSHAuthenticationContext *context)
{
    assert(!context->done);
    context->done = true;
    SSHReactor *reactor = context->reactor;
    if (context->timeout_timer != NULL) {
        outersshpriv_reactor_cancel_source(context->timeout_timer);
        context->timeout_timer = NULL;
    }
    outersshpriv_reactor_set_ssh_read_source_resumed(reactor, false);
    outersshpriv_reactor_set_ssh_write_source_resumed(reactor, false);
    reactor->started = false;
    if (!context->worker_pending && !context->validation_pending) {
        otqueue_async(reactor->queue, context, deliver_authentication_result);
    }
}

static bool worker_returned(SSHAuthenticationContext *context)
{
    assert(context->worker_pending);
    context->worker_pending = false;
    if (context->done) {
        deliver_authentication_result(context);
        return false;
    }
    return true;
}

static void deliver_authentication_result(void *opaque_context)
{
    SSHAuthenticationContext *context = opaque_context;
    context->reactor->phase = SSH_REACTOR_PHASE_NONE;
    if (context->packet != NULL) {
        _libssh2_explicit_zero(context->packet, context->packet_length);
        free(context->packet);
    }
    free(context->host_key);
    free(context->signed_data);
    free(context->key_method);
    if (context->signature != NULL) libssh2_free(context->key.session, context->signature);
    olibssh_authentication_key_dispose(&context->key);
    /* Completion may destroy the reactor or reuse its startup storage. */
    char *worker_storage = context->worker_error_message;
    context->finished(context->completion_context, context->error);
    free(worker_storage);
}

static void authentication_timed_out(void *opaque_context)
{
    SSHReactorSourceContext *timer_context = opaque_context;
    SSHReactor *reactor = timer_context->reactor;
    SSHAuthenticationContext *context = &reactor->startup.authentication;
    if (reactor->phase == SSH_REACTOR_PHASE_AUTHENTICATION &&
        context->timeout_timer == timer_context->source) {
        outersshpriv_reactor_fail(context->reactor, SSH_REACTOR_OPERATION_READ, LIBSSH2_ERROR_TIMEOUT);
    }
}
