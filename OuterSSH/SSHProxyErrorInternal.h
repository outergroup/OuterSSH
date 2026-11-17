#ifndef SSH_PROXY_ERROR_INTERNAL_H
#define SSH_PROXY_ERROR_INTERNAL_H

#include "SSHProxyError.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Borrows its message. */
OuterSSHError outersshpriv_proxy_error(
    OuterSSHProxyErrorCode code,
    const char *message,
    size_t message_length,
    int32_t system_error_code);

/* Replaces the main message and copies any underlying SSH detail, owning both
 * strings in one allocation as outerssh_error_copy does. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
OuterSSHError outersshpriv_error_format(
    char **storage, OuterSSHError error, const char *format, ...);

#ifdef __cplusplus
}
#endif
#endif
