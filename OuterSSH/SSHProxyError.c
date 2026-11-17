#include "SSHProxyError.h"
#include "SSHProxyErrorInternal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static OuterSSHError format_error(
    char **storage, OuterSSHError error, const char *format, va_list arguments);
static OuterSSHError diagnostic_allocation_failed(OuterSSHError error);

OuterSSHError outersshpriv_proxy_error(
    OuterSSHProxyErrorCode code, const char *message, size_t message_length,
    int32_t system_error_code)
{
    return (OuterSSHError){
        .domain = OUTERSSH_ERROR_PROXY, .code = code,
        .system_error_code = system_error_code,
        .message = message, .message_length = message_length,
    };
}

OuterSSHError outerssh_proxy_closing_error(void)
{
    static const char message[] = "The SSH connection is closing.";
    return outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_CONNECTION_CLOSING,
        message, sizeof(message) - 1, 0);
}

OuterSSHError outerssh_session_error(
    OuterSSHSessionErrorCode code, const char *message, size_t message_length)
{
    return (OuterSSHError){.domain = OUTERSSH_ERROR_SESSION, .code = code,
        .message = message, .message_length = message_length};
}

OuterSSHError outerssh_error_copy(OuterSSHError error, char **storage)
{
    *storage = NULL;
    if (error.message_length == 0 && error.ssh_error_message_length == 0) return error;
    if (error.message_length > SIZE_MAX - 2 ||
        error.ssh_error_message_length > SIZE_MAX - 2 - error.message_length)
        return diagnostic_allocation_failed(error);
    char *bytes = malloc(error.message_length + error.ssh_error_message_length + 2);
    if (bytes == NULL) return diagnostic_allocation_failed(error);
    if (error.message_length != 0) memcpy(bytes, error.message, error.message_length);
    bytes[error.message_length] = '\0';
    char *detail = bytes + error.message_length + 1;
    if (error.ssh_error_message_length != 0)
        memcpy(detail, error.ssh_error_message, error.ssh_error_message_length);
    detail[error.ssh_error_message_length] = '\0';
    *storage = bytes;
    error.message = bytes;
    error.ssh_error_message = detail;
    return error;
}

OuterSSHError outersshpriv_error_format(
    char **storage, OuterSSHError error, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    error = format_error(storage, error, format, arguments);
    va_end(arguments);
    return error;
}

OuterSSHError outerssh_session_error_format(
    char **storage, OuterSSHSessionErrorCode code, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    OuterSSHError error = format_error(storage,
        (OuterSSHError){.domain = OUTERSSH_ERROR_SESSION, .code = code}, format, arguments);
    va_end(arguments);
    return error;
}

static OuterSSHError format_error(
    char **storage, OuterSSHError error, const char *format, va_list arguments)
{
    *storage = NULL;
    va_list size_arguments;
    va_copy(size_arguments, arguments);
    int length = vsnprintf(NULL, 0, format, size_arguments);
    va_end(size_arguments);
    if (length < 0 || error.ssh_error_message_length > SIZE_MAX - (size_t)length - 2)
        return diagnostic_allocation_failed(error);
    *storage = malloc((size_t)length + error.ssh_error_message_length + 2);
    if (*storage == NULL) {
        return diagnostic_allocation_failed(error);
    }
    int written = vsnprintf(*storage, (size_t)length + 1, format, arguments);
    if (written < 0 || written != length) {
        free(*storage);
        *storage = NULL;
        return diagnostic_allocation_failed(error);
    }
    error.message = *storage;
    error.message_length = (size_t)length;
    if (error.ssh_error_message_length != 0) {
        char *detail = *storage + (size_t)length + 1;
        memcpy(detail, error.ssh_error_message, error.ssh_error_message_length);
        detail[error.ssh_error_message_length] = '\0';
        error.ssh_error_message = detail;
    } else {
        error.ssh_error_message = NULL;
    }
    return error;
}

static OuterSSHError diagnostic_allocation_failed(OuterSSHError error)
{
    static const char message[] = "Error diagnostic text could not be allocated.";
    error.message = message;
    error.message_length = sizeof(message) - 1;
    error.ssh_error_message = NULL;
    error.ssh_error_message_length = 0;
    return error;
}
