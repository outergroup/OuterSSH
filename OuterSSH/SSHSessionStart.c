#include "platform/OTSocket.h"
#include "SSHProxyErrorInternal.h"
#include "platform/OTQueue.h"
#include "SSHSessionStart.h"
#include "OuterSSH.h"
#include "olibssh/libssh2/libssh2_priv.h"
#include "olibssh/handshake.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#if !OUTERSSH_APPLE_CRYPTO && !OUTERSSH_WINDOWS_CRYPTO && !OUTERSSH_ANDROID_CRYPTO
#include <openssl/crypto.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const char *PreferredCipherMethods;

static int configure_session_socket(otsocket_t socket);
static void initialize_cipher_preferences(void *context);
#if !OUTERSSH_APPLE_CRYPTO && !OUTERSSH_WINDOWS_CRYPTO && !OUTERSSH_ANDROID_CRYPTO
static bool has_aes_gcm_acceleration(const char *cpu_settings);
#endif

LIBSSH2_SESSION *outersshpriv_session_create(otsocket_t socket, SSHSessionStartResult *result)
{
    *result = (SSHSessionStartResult){0};
    int socket_configuration_result = configure_session_socket(socket);
    if (socket_configuration_result != 0) {
        const char *message = strerror(socket_configuration_result);
        result->error = outersshpriv_error_format(&result->error_storage,
            (OuterSSHError){
                .domain = OUTERSSH_ERROR_SESSION,
                .code = OUTERSSH_SESSION_ERROR_SOCKET_CONFIGURATION_FAILED,
                .ssh_error_code = socket_configuration_result,
                .ssh_error_message = message,
                .ssh_error_message_length = strlen(message)
            },
            "Failed to configure the SSH socket with code %d (%s).", socket_configuration_result, message);
        return NULL;
    }

    LIBSSH2_SESSION *session = olibssh_session_init_ex(
        NULL,
        NULL,
        NULL,
        NULL);
    if (session == NULL) {
        static const char session_creation_message[] = "Failed to create the SSH session.";
        static const char error_message[] = "Failed to allocate SSH session";
        result->error = outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
            session_creation_message, sizeof(session_creation_message) - 1);
        result->error.ssh_error_code = LIBSSH2_ERROR_ALLOC;
        result->error.ssh_error_message = error_message;
        result->error.ssh_error_message_length = sizeof(error_message) - 1;
        return NULL;
    }

    static otonce_t cipher_preferences_once;
    otonce(&cipher_preferences_once, NULL, initialize_cipher_preferences);
    int32_t configuration_result = 0;
    const int methods[] = {
        LIBSSH2_METHOD_CRYPT_CS,
        LIBSSH2_METHOD_CRYPT_SC
    };
    for (size_t index = 0; index < sizeof(methods) / sizeof(methods[0]); index++) {
        configuration_result = libssh2_session_method_pref(
            session,
            methods[index],
            PreferredCipherMethods);
        if (configuration_result != 0) {
            break;
        }
    }
    if (configuration_result != 0) {
        char *session_message = NULL;
        int message_length = 0;
        libssh2_session_last_error(session, &session_message, &message_length, 0);
        const char *message = session_message;
        if (message == NULL) {
            static const char unknown_error[] = "Unknown error";
            message = unknown_error;
            message_length = sizeof(unknown_error) - 1;
        }
        result->error = outersshpriv_error_format(&result->error_storage,
            (OuterSSHError){
                .domain = OUTERSSH_ERROR_SESSION,
                .code = OUTERSSH_SESSION_ERROR_CIPHER_CONFIGURATION_FAILED,
                .ssh_error_code = configuration_result,
                .ssh_error_message = message,
                .ssh_error_message_length = (size_t)message_length
            },
            "Failed to configure SSH ciphers with code %d (%.*s).", configuration_result, message_length, message);
        olibssh_session_free(session);
        return NULL;
    }

    olibssh_handshake_set_socket(session, socket);
    return session;
}

static int configure_session_socket(otsocket_t socket)
{
    if (otsocket_prevent_inheritance(socket) != 0 ||
        otsocket_set_nonblocking(socket, true) != 0) {
        return errno;
    }
#ifdef SO_NOSIGPIPE
    int no_sigpipe = 1;
    if (otsocket_setsockopt(
            socket,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &no_sigpipe,
            sizeof(no_sigpipe)) != 0) {
        return errno;
    }
#endif
    return 0;
}

static void initialize_cipher_preferences(void *context)
{
    (void)context;
#if OUTERSSH_APPLE_CRYPTO || OUTERSSH_WINDOWS_CRYPTO || OUTERSSH_ANDROID_CRYPTO
    PreferredCipherMethods = "aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr";
#else
    PreferredCipherMethods = has_aes_gcm_acceleration(OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS))
        ? "aes128-gcm@openssh.com,aes256-gcm@openssh.com,"
          "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr"
        : "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,"
          "aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr";
#endif
}

#if !OUTERSSH_APPLE_CRYPTO && !OUTERSSH_WINDOWS_CRYPTO && !OUTERSSH_ANDROID_CRYPTO
static bool has_aes_gcm_acceleration(const char *cpu_settings)
{
    /* OpenSSL's public capability report reflects its assembly support and
     * runtime overrides. Unknown or unavailable reports use the software default. */
    if (cpu_settings == NULL) return false;
    uint64_t capabilities;
    if (sscanf(cpu_settings, "OPENSSL_armcap=%" SCNx64, &capabilities) == 1) {
        const uint64_t aes_and_pmull = (UINT64_C(1) << 2) | (UINT64_C(1) << 5);
        return (capabilities & aes_and_pmull) == aes_and_pmull;
    }
    if (sscanf(cpu_settings, "OPENSSL_ia32cap=%" SCNx64, &capabilities) == 1) {
        const uint64_t aesni_and_pclmulqdq = (UINT64_C(1) << 57) | (UINT64_C(1) << 33);
        return (capabilities & aesni_and_pclmulqdq) == aesni_and_pclmulqdq;
    }
    return false;
}

#endif

void outersshpriv_session_start_result_dispose(
    SSHSessionStartResult *result)
{
    if (result == NULL) {
        return;
    }
    free(result->error_storage);
    *result = (SSHSessionStartResult){0};
}


uint32_t outerssh_private_key_capabilities(void)
{
    uint32_t result = OUTERSSH_KEY_OPENSSH;
#if LIBSSH2_RSA
    result |= OUTERSSH_KEY_RSA;
#endif
#if LIBSSH2_ECDSA
    result |= OUTERSSH_KEY_ECDSA;
#endif
#if LIBSSH2_ED25519
    result |= OUTERSSH_KEY_ED25519;
#endif
#if !OUTERSSH_ANDROID_CRYPTO
    result |= OUTERSSH_KEY_RSA_PEM;
#endif
#if !OUTERSSH_ANDROID_CRYPTO && !OUTERSSH_WINDOWS_CRYPTO
    result |= OUTERSSH_KEY_EC_PEM;
#endif
#if !OUTERSSH_ANDROID_CRYPTO && !OUTERSSH_WINDOWS_CRYPTO && !OUTERSSH_APPLE_CRYPTO
    result |= OUTERSSH_KEY_PKCS8;
#endif
    return result;
}

static uint32_t key_algorithm(const unsigned char *name, size_t length)
{
    if(length == 7 && !memcmp(name, "ssh-rsa", 7)) return OUTERSSH_KEY_RSA;
    if(length == 11 && !memcmp(name, "ssh-ed25519", 11)) return OUTERSSH_KEY_ED25519;
    if(length == 19 && !memcmp(name, "ecdsa-sha2-nistp", 16) &&
       (!memcmp(name + 16, "256", 3) || !memcmp(name + 16, "384", 3) || !memcmp(name + 16, "521", 3)))
        return OUTERSSH_KEY_ECDSA;
    return 0;
}

const char *outerssh_check_private_key(const void *bytes, size_t length, uint32_t capabilities, bool validate)
{
    if(!bytes || length == 0 || length > 32768 || memchr(bytes, 0, length)) return "The shared private-key file is invalid or too large.";
    if(!outerssh_initialize(NULL)) return "Could not initialize SSH key validation.";
    char *text = malloc(length + 1);
    if(!text) return "Could not allocate SSH key validation.";
    memcpy(text, bytes, length); text[length] = 0;
    const char *error = NULL;
    uint32_t required = 0;
    LIBSSH2_SESSION *session = olibssh_session_init_ex(NULL, NULL, NULL, NULL);
    unsigned char *method = NULL, *public_key = NULL, *signature = NULL, *signed_blob = NULL;
    size_t method_length = 0, public_length = 0, signature_length = 0;
    unsigned char *expected_public = NULL; size_t expected_public_length = 0;
    void *private_context = NULL, *public_context = NULL;
    const LIBSSH2_HOSTKEY_METHOD *signer = NULL;
    if(!session) { error = "Could not allocate SSH key validation."; goto done; }
    if(strstr(text, "ENCRYPTED")) { error = "This private key is encrypted. Unlock and export an unencrypted key before sharing; its passphrase is not transferred."; goto done; }
    if(strstr(text, "-----BEGIN OPENSSH PRIVATE KEY-----")) {
        required = OUTERSSH_KEY_OPENSSH;
        const char *start = strstr(text, "-----BEGIN OPENSSH PRIVATE KEY-----") + 35;
        const char *end = strstr(start, "-----END OPENSSH PRIVATE KEY-----");
        char *encoded = malloc(length + 1), *decoded = NULL;
        size_t decoded_length = 0;
        size_t count = 0;
        if(!encoded || !end) { free(encoded); error = "Invalid OpenSSH private key."; goto done; }
        for(const char *p = start; p < end; p++) if(*p != '\r' && *p != '\n' && *p != ' ' && *p != '\t') encoded[count++] = *p;
        int rc = _libssh2_base64_decode(session, &decoded, &decoded_length, encoded, (unsigned int)count);
        _libssh2_explicit_zero(encoded, count); free(encoded);
        struct string_buf buffer = {.data = (unsigned char *)decoded, .len = decoded_length, .dataptr = (unsigned char *)decoded};
        unsigned char *cipher = NULL, *field = NULL; size_t cipher_length = 0, field_length = 0; uint32_t keys = 0;
        if(rc || decoded_length < 15 || memcmp(decoded, "openssh-key-v1\0", 15)) error = "Invalid OpenSSH private key.";
        else {
            buffer.dataptr += 15;
            if(_libssh2_get_string(&buffer, &cipher, &cipher_length) || _libssh2_get_string(&buffer, &field, &field_length) ||
               _libssh2_get_string(&buffer, &field, &field_length) || _libssh2_get_u32(&buffer, &keys) || keys != 1 ||
               _libssh2_get_string(&buffer, &field, &field_length)) error = "Invalid OpenSSH private key.";
            else if(cipher_length != 4 || memcmp(cipher, "none", 4)) error = "This private key is encrypted. Unlock and export an unencrypted key before sharing; its passphrase is not transferred.";
            else {
                struct string_buf pub = {.data = field, .len = field_length, .dataptr = field};
                unsigned char *name = NULL; size_t name_length = 0;
                uint32_t algorithm = _libssh2_get_string(&pub, &name, &name_length) ? 0 : key_algorithm(name, name_length);
                if(!algorithm) error = "This private-key algorithm cannot be shared. Hardware-backed keys require authorizing a new key on the server.";
                else {
                    required |= algorithm;
                    expected_public = malloc(field_length);
                    if(!expected_public) error = "Could not allocate SSH key validation.";
                    else { memcpy(expected_public, field, field_length); expected_public_length = field_length; }
                }
            }
        }
        if(decoded) { _libssh2_explicit_zero(decoded, decoded_length); LIBSSH2_FREE(session, decoded); }
        if(error) goto done;
    } else if(strstr(text, "-----BEGIN RSA PRIVATE KEY-----")) required = OUTERSSH_KEY_RSA_PEM | OUTERSSH_KEY_RSA;
    else if(strstr(text, "-----BEGIN EC PRIVATE KEY-----")) required = OUTERSSH_KEY_EC_PEM | OUTERSSH_KEY_ECDSA;
    else if(strstr(text, "-----BEGIN PRIVATE KEY-----")) required = OUTERSSH_KEY_PKCS8;
    else { error = "This private-key file format cannot be shared."; goto done; }
    if((required & capabilities) != required) {
        error = (required & OUTERSSH_KEY_ED25519) && !(capabilities & OUTERSSH_KEY_ED25519)
            ? "The receiving device cannot use Ed25519 private keys. Authorize a new compatible key on the server instead."
            : "The receiving device cannot import this private-key algorithm or file format. Authorize a new compatible key on the server instead.";
        goto done;
    }
    if(!validate) goto done;
    if(_libssh2_pub_priv_keyfilememory(session, &method, &method_length, &public_key, &public_length, text, length, "")) {
        error = "The receiving device could not import this private key. The key may be invalid or unsupported."; goto done;
    }
    if(expected_public && (expected_public_length != public_length || memcmp(expected_public, public_key, public_length))) {
        error = "The private key does not match its public identity."; goto done;
    }
    const char *name = method_length == 7 && !memcmp(method, "ssh-rsa", 7) ? "rsa-sha2-256" : NULL;
    for(const LIBSSH2_HOSTKEY_METHOD **m = libssh2_hostkey_methods(); *m; m++) {
        if(name ? !strcmp((*m)->name, name) : strlen((*m)->name) == method_length && !memcmp((*m)->name, method, method_length)) { signer = *m; break; }
    }
    error = "The receiving device could not sign and verify with this private key.";
    if(!signer || !signer->initPEMFromMemory || !signer->init || !signer->signv || !signer->sig_verify) goto done;
    if(signer->initPEMFromMemory(session, text, length, (const unsigned char *)"", &private_context) ||
       signer->init(session, public_key, public_length, &public_context)) goto done;
    unsigned char challenge[32];
    if(_libssh2_random(challenge, sizeof(challenge))) goto done;
    struct iovec vector = {.iov_base = challenge, .iov_len = sizeof(challenge)};
    if(signer->signv(session, &signature, &signature_length, 1, &vector, &private_context)) goto done;
    size_t name_length = strlen(signer->name), blob_length = 8 + name_length + signature_length;
    signed_blob = LIBSSH2_ALLOC(session, blob_length);
    if(!signed_blob) goto done;
    _libssh2_htonu32(signed_blob, (uint32_t)name_length); memcpy(signed_blob + 4, signer->name, name_length);
    _libssh2_htonu32(signed_blob + 4 + name_length, (uint32_t)signature_length); memcpy(signed_blob + 8 + name_length, signature, signature_length);
    if(!signer->sig_verify(session, signed_blob, blob_length, challenge, sizeof(challenge), &public_context)) error = NULL;
done:
    if(signer && private_context) signer->dtor(session, &private_context);
    if(signer && public_context) signer->dtor(session, &public_context);
    if(session) {
        LIBSSH2_FREE(session, method); LIBSSH2_FREE(session, public_key); LIBSSH2_FREE(session, signature); LIBSSH2_FREE(session, signed_blob);
        olibssh_session_free(session);
    }
    free(expected_public);
    _libssh2_explicit_zero(text, length); free(text);
    return error;
}
