#ifndef OUTERSSH_HELPER_H
#define OUTERSSH_HELPER_H

#include <stdbool.h>
#include <stddef.h>

/* The OuterSSH helper runs on the server. Applications build it with their own
 * main, passing a handler for the requests their client sends with
 * outerssh_session_pool_send_helper_request. The handler runs only in the
 * helper's service mode, as the SSH user.
 *
 * On success, the handler returns true and sets *response to a malloc'd buffer,
 * or to NULL for an empty response. On failure, it returns false and writes a
 * NUL-terminated message into error. */
typedef bool (*OuterSSHHelperRequestHandler)(
    const unsigned char *request, size_t request_length,
    unsigned char **response, size_t *response_length,
    char *error, size_t error_capacity);

#ifdef _WIN32
#include <wchar.h>
int outerssh_helper_main(int argc, wchar_t **argv, OuterSSHHelperRequestHandler handler);
/* The named pipe allowlist this helper checks, for use by request handlers. */
const wchar_t *outerssh_helper_pipe_allowlist(void);
#else
int outerssh_helper_main(int argc, char **argv, OuterSSHHelperRequestHandler handler);
#endif

#endif
