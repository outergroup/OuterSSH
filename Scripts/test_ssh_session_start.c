#include "../OuterSSH/SSHSessionStart.h"
#include "libssh2_priv.h"

static LIBSSH2_SESSION *test_session_init(void);
static int test_last_error(char **message, int *length);
static int test_session_free(LIBSSH2_SESSION *session);

#define olibssh_session_init_ex(...) test_session_init()
#define libssh2_session_last_error(session, message, length, copy) test_last_error(message, length)
#define olibssh_session_free test_session_free
#include "../OuterSSH/SSHSessionStart.c"
#undef olibssh_session_init_ex
#undef libssh2_session_last_error
#undef olibssh_session_free

#include <assert.h>
#include <stdio.h>

static bool fail_allocation;
static bool missing_error_message;
static char borrowed_error[8];
static unsigned int sessions_freed;

static LIBSSH2_SESSION *test_session_init(void)
{
    return fail_allocation ? NULL : olibssh_session_init_ex(NULL, NULL, NULL, NULL);
}

static int test_last_error(char **message, int *length)
{
    *message = missing_error_message ? NULL : borrowed_error;
    *length = missing_error_message ? 0 : sizeof(borrowed_error);
    return LIBSSH2_ERROR_BANNER_RECV;
}

static int test_session_free(LIBSSH2_SESSION *session)
{
    memset(borrowed_error, 'x', sizeof(borrowed_error));
    sessions_freed++;
    return olibssh_session_free(session);
}

static void test_start_errors(void)
{
    SSHSessionStartResult result = {0};
    assert(outersshpriv_session_create(-1, &result) == NULL);
    assert(result.error.code == OUTERSSH_SESSION_ERROR_SOCKET_CONFIGURATION_FAILED);
    outersshpriv_session_start_result_dispose(&result);

    fail_allocation = true;
    otsocket_t socket = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(socket != -1);
    assert(outersshpriv_session_create(socket, &result) == NULL);
    assert(result.error.code == OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED);
    assert(result.error.ssh_error_code == LIBSSH2_ERROR_ALLOC);
    assert(sessions_freed == 0);
    outersshpriv_session_start_result_dispose(&result);
    fail_allocation = false;
    otsocket_close(socket);

}

static void test_cipher_preferences(const char *expected_first_cipher)
{
#if !OUTERSSH_APPLE_CRYPTO && !OUTERSSH_WINDOWS_CRYPTO
    const struct {
        const char *settings;
        bool accelerated;
    } cases[] = {
        {NULL, false},
        {"", false},
        {"unrecognized", false},
        {"OPENSSL_armcap=invalid", false},
        {"OPENSSL_armcap=0x987d", true},
        {"OPENSSL_armcap=0xbd", true},
        {"OPENSSL_armcap=0xb9 env:0xb9", false},
        {"OPENSSL_armcap=0x9d", false},
        {"OPENSSL_armcap=0x99", false},
        {"OPENSSL_armcap=0x0", false},
        {"OPENSSL_ia32cap=0x0200000200000000:0x0", true},
        {"OPENSSL_ia32cap=0x0200000000000000:0x0", false},
        {"OPENSSL_ia32cap=0x0000000200000000:0x0", false},
        {"OPENSSL_ia32cap=0x0:0xffffffffffffffff", false},
        {"OPENSSL_ia32cap=0x0:0x0 env:~0x200000200000000", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        assert(has_aes_gcm_acceleration(cases[i].settings) == cases[i].accelerated);

#endif
    for (unsigned i = 0; i < 2; i++) {
        otsocket_t socket = otsocket_create(AF_INET, SOCK_STREAM, 0);
        assert(socket != -1);
        SSHSessionStartResult result;
        LIBSSH2_SESSION *session = outersshpriv_session_create(socket, &result);
        assert(session != NULL);
        assert(strcmp(session->local.crypt_prefs, PreferredCipherMethods) == 0);
        assert(strcmp(session->remote.crypt_prefs, PreferredCipherMethods) == 0);
        assert(strstr(PreferredCipherMethods, "aes128-gcm@openssh.com") != NULL);
#if OUTERSSH_APPLE_CRYPTO || OUTERSSH_WINDOWS_CRYPTO
        assert(strstr(PreferredCipherMethods, "chacha20-poly1305@openssh.com") == NULL);
#else
        assert(strstr(PreferredCipherMethods, "chacha20-poly1305@openssh.com") != NULL);
#endif
        if (expected_first_cipher != NULL) {
            size_t length = strlen(expected_first_cipher);
            assert(strncmp(PreferredCipherMethods, expected_first_cipher, length) == 0);
            assert(PreferredCipherMethods[length] == ',');
        }
        printf("Cipher preferences: %s\n", session->local.crypt_prefs);
        olibssh_session_free(session);
        outersshpriv_session_start_result_dispose(&result);
        otsocket_close(socket);
    }
}

int main(int argc, char **argv)
{
    assert(argc <= 2);
    assert(otsocket_initialize() == 0);
    OuterSSHSessionAuthentication agent_authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_AGENT};
    assert(outersshpriv_session_configuration_is_valid("user", 4, agent_authentication, "/tmp/agent", 10));
    assert(!outersshpriv_session_configuration_is_valid("user", 4, agent_authentication, NULL, 0));
    assert(!outersshpriv_session_configuration_is_valid("user", 4, agent_authentication, "", 0));
    assert(libssh2_init(0) == 0);
    test_start_errors();
    test_cipher_preferences(argc == 2 ? argv[1] : NULL);
    char *username = malloc(4);
    char *password = malloc(3);
    assert(username != NULL && password != NULL);
    memcpy(username, "user", 4);
    memcpy(password, "p\0w", 3);
    OuterSSHSessionAuthentication authentication = {
        .kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
        .password = password,
        .password_length = 3
    };
    assert(outersshpriv_session_configuration_is_valid(username, 4, authentication, NULL, 0));
    assert(!outersshpriv_session_configuration_is_valid(username, 4, authentication, NULL, 1));
    assert(!outersshpriv_session_configuration_is_valid(username, (size_t)INT_MAX + 1, authentication, NULL, 0));
    memcpy(password, "pwd", 3);

    authentication.password_length = 0;
    assert(outersshpriv_session_configuration_is_valid(username, 4, authentication, NULL, 0));
    authentication.password = NULL;
    assert(!outersshpriv_session_configuration_is_valid(username, 4, authentication, NULL, 0));
    authentication = (OuterSSHSessionAuthentication){
        .kind = OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY,
        .private_key = "key", .private_key_length = 3,
        .passphrase = password, .passphrase_length = 3
    };
    assert(outersshpriv_session_configuration_is_valid(username, 4, authentication, NULL, 0));
    password[1] = 0;
    assert(!outersshpriv_session_configuration_is_valid(username, 4, authentication, NULL, 0));
    username[1] = 0;
    assert(!outersshpriv_session_configuration_is_valid(username, 4, authentication, NULL, 0));
    free(password);
    free(username);
    libssh2_exit();
    puts("PASS: session-start errors and diagnostic ownership; unterminated authentication strings, binary and empty passwords, C-string boundaries");
    return 0;
}
