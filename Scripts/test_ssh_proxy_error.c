#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool fail_allocation;
static size_t allocation_count;
static void *error_malloc(size_t size)
{
    allocation_count++;
    return fail_allocation ? NULL : malloc(size);
}
#define malloc error_malloc
#include "SSHProxyError.c"
#undef malloc

int main(void)
{
    char message[] = {'a', '\0', 'b'};
    char detail[] = {'c', 'd'};
    OuterSSHError source = outerssh_session_error(
        OUTERSSH_SESSION_ERROR_HANDSHAKE_FAILED, message, sizeof(message));
    source.system_error_code = 12;
    source.ssh_error_code = -5;
    source.ssh_channel_open_reason = 3;
    source.ssh_error_message = detail;
    source.ssh_error_message_length = sizeof(detail);
    assert(source.message == message);
    char *storage;
    OuterSSHError copy = outerssh_error_copy(source, &storage);
    assert(storage != NULL && copy.message != message && copy.ssh_error_message != detail);
    memset(message, 'x', sizeof(message));
    memset(detail, 'x', sizeof(detail));
    assert(copy.message_length == 3 && memcmp(copy.message, "a\0b", 3) == 0);
    assert(copy.ssh_error_message_length == 2 && memcmp(copy.ssh_error_message, "cd", 2) == 0);
    assert(copy.domain == source.domain && copy.code == source.code);
    assert(copy.system_error_code == 12 && copy.ssh_error_code == -5);
    assert(copy.ssh_channel_open_reason == 3);
    free(storage);

    char long_message[10001];
    memset(long_message, 'm', sizeof(long_message) - 1);
    long_message[sizeof(long_message) - 1] = '\0';
    OuterSSHError formatted = outerssh_session_error_format(&storage,
        OUTERSSH_SESSION_ERROR_HANDSHAKE_FAILED, "failure: %s", long_message);
    assert(formatted.message_length == 10009);
    assert(memcmp(formatted.message + 9, long_message, 10000) == 0);
    formatted.ssh_error_message = long_message;
    formatted.ssh_error_message_length = 10000;
    char *copy_storage;
    copy = outerssh_error_copy(formatted, &copy_storage);
    free(storage);
    memset(long_message, 'x', sizeof(long_message));
    assert(copy.message_length == 10009 && copy.message[10008] == 'm');
    assert(copy.ssh_error_message_length == 10000 && copy.ssh_error_message[9999] == 'm');
    free(copy_storage);

    char borrowed_detail[] = {'a', '\0', 'b'};
    source.ssh_error_message = borrowed_detail;
    source.ssh_error_message_length = sizeof(borrowed_detail);
    size_t before = allocation_count;
    formatted = outersshpriv_error_format(&storage, source, "failure %d", 42);
    assert(storage != NULL && allocation_count == before + 1);
    memset(borrowed_detail, 'x', sizeof(borrowed_detail));
    assert(formatted.message_length == sizeof("failure 42") - 1);
    assert(strcmp(formatted.message, "failure 42") == 0);
    assert(formatted.ssh_error_message_length == 3);
    assert(memcmp(formatted.ssh_error_message, "a\0b", 3) == 0);
    assert(formatted.ssh_error_message[3] == '\0');
    assert(formatted.domain == source.domain && formatted.code == source.code);
    assert(formatted.system_error_code == 12 && formatted.ssh_error_code == -5);
    assert(formatted.ssh_channel_open_reason == 3);
    free(storage);

    fail_allocation = true;
    copy = outerssh_error_copy(source, &storage);
    assert(storage == NULL && copy.domain == source.domain && copy.code == source.code);
    assert(copy.ssh_error_code == source.ssh_error_code && copy.ssh_channel_open_reason == 3);
    assert(copy.message_length != 0 && copy.ssh_error_message_length == 0);
    formatted = outerssh_session_error_format(&storage,
        OUTERSSH_SESSION_ERROR_AUTHENTICATION_FAILED, "failure %d", 42);
    assert(storage == NULL && formatted.code == OUTERSSH_SESSION_ERROR_AUTHENTICATION_FAILED);
    assert(formatted.message_length != 0);
    formatted = outersshpriv_error_format(&storage, source, "failure %d", 42);
    assert(storage == NULL && formatted.code == source.code);
    assert(formatted.ssh_error_code == source.ssh_error_code && formatted.ssh_channel_open_reason == 3);
    assert(formatted.message_length != 0 && formatted.ssh_error_message_length == 0);
    copy = outerssh_error_copy((OuterSSHError){0}, &storage);
    assert(storage == NULL && copy.domain == OUTERSSH_ERROR_NONE);
    fail_allocation = false;
    source.message_length = SIZE_MAX;
    copy = outerssh_error_copy(source, &storage);
    assert(storage == NULL && copy.code == source.code);
    source.ssh_error_message_length = SIZE_MAX;
    before = allocation_count;
    formatted = outersshpriv_error_format(&storage, source, "failure %d", 42);
    assert(storage == NULL && allocation_count == before);
    assert(formatted.code == source.code && formatted.ssh_error_message_length == 0);
    return 0;
}
