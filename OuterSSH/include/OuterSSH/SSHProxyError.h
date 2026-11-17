#ifndef SSH_PROXY_ERROR_H
#define SSH_PROXY_ERROR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OUTERSSH_ERROR_NONE,
    OUTERSSH_ERROR_PROXY,
    OUTERSSH_ERROR_SESSION,
    OUTERSSH_ERROR_HOST_KEY_VALIDATION,
    OUTERSSH_ERROR_HELPER_INSTALLER
} OuterSSHErrorDomain;

typedef enum {
    OUTERSSH_PROXY_ERROR_REACTOR_CREATION_FAILED,
    OUTERSSH_PROXY_ERROR_LISTEN_SOCKET_CREATION_FAILED,
    OUTERSSH_PROXY_ERROR_LISTENER_ADDRESS_LOOKUP_FAILED,
    OUTERSSH_PROXY_ERROR_BIND_FAILED,
    OUTERSSH_PROXY_ERROR_LISTEN_FAILED,
    OUTERSSH_PROXY_ERROR_INVALID_UNIX_SOCKET_PATH,
    OUTERSSH_PROXY_ERROR_BRIDGE_PRIVILEGE_CONFLICT,
    OUTERSSH_PROXY_ERROR_CREDENTIAL_GENERATION_FAILED,
    OUTERSSH_PROXY_ERROR_CONNECTION_CLOSING,
    OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED,
    OUTERSSH_PROXY_ERROR_SOCKET_AUTHORIZATION_FAILED,
    OUTERSSH_PROXY_ERROR_SUDO_PASSWORD_REQUIRED,
    OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION,
    OUTERSSH_PROXY_ERROR_PRIVILEGE_ESCALATION_DENIED
} OuterSSHProxyErrorCode;

typedef enum {
    OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
    OUTERSSH_SESSION_ERROR_CIPHER_CONFIGURATION_FAILED,
    OUTERSSH_SESSION_ERROR_HANDSHAKE_FAILED,
    OUTERSSH_SESSION_ERROR_HOST_KEY_UNAVAILABLE,
    OUTERSSH_SESSION_ERROR_AUTHENTICATION_FAILED,
    OUTERSSH_SESSION_ERROR_SOCKET_CONFIGURATION_FAILED,
    OUTERSSH_SESSION_ERROR_UNAVAILABLE,
    OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_START_FAILED,
    OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_TIMED_OUT,
    OUTERSSH_SESSION_ERROR_REMOTE_PORT_UNAVAILABLE,
    OUTERSSH_SESSION_ERROR_PASSPHRASE_REQUIRED,
    OUTERSSH_SESSION_ERROR_COMMAND_REQUEST_DENIED,
    OUTERSSH_SESSION_ERROR_COMMAND_OUTPUT_LIMIT_EXCEEDED,
    OUTERSSH_SESSION_ERROR_COMMAND_OUTPUT_ALLOCATION_FAILED,
    OUTERSSH_SESSION_ERROR_COMMAND_TIMED_OUT,
    OUTERSSH_SESSION_ERROR_CANCELLED,
    OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING,
    /* Nothing is listening at the destination on the SSH server: its Unix
     * socket or named pipe is missing or refuses connections, or its loopback
     * port refuses connections. */
    OUTERSSH_SESSION_ERROR_NOT_LISTENING
} OuterSSHSessionErrorCode;

/* Codes for errors in the OUTERSSH_ERROR_HELPER_INSTALLER domain.
 * Applications may also use them to decline OUTERSSH_EVENT_HELPER_BINARY_NEEDED. */
typedef enum {
    OUTERSSH_HELPER_INSTALLER_ERROR_UNSUPPORTED_PLATFORM,
    OUTERSSH_HELPER_INSTALLER_ERROR_MISSING_PACKAGED_BINARY,
    OUTERSSH_HELPER_INSTALLER_ERROR_FAILED_TO_READ_PACKAGED_BINARY,
    OUTERSSH_HELPER_INSTALLER_ERROR_ALLOCATION_FAILED
} OuterSSHHelperInstallerErrorCode;

/* Text is borrowed and need not be NUL-terminated. In an event it remains
 * valid until the next outerssh_event_queue_poll for that event queue, or
 * until the event queue is destroyed. Copy it with outerssh_error_copy before
 * retaining an error. Zero lengths allow NULL pointers. */
typedef struct {
    OuterSSHErrorDomain domain;
    int32_t code;
    int32_t system_error_code;
    int32_t ssh_error_code;
    uint32_t ssh_channel_open_reason;
    const char *message;
    size_t message_length;
    const char *ssh_error_message;
    size_t ssh_error_message_length;
} OuterSSHError;

OuterSSHError outerssh_proxy_closing_error(void);
/* Borrows its message. */
OuterSSHError outerssh_session_error(
    OuterSSHSessionErrorCode code, const char *message, size_t message_length);

/* Copy and format own both strings in one allocation. Format replaces the main
 * message. Free *storage after the last use of its text. These functions
 * initialize *storage; release any previous allocation separately. Copying an
 * error with no text needs no storage.
 * On allocation failure the original codes are retained and a static diagnostic
 * explains that the text could not be stored. */
OuterSSHError outerssh_error_copy(OuterSSHError error, char **storage);
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
OuterSSHError outerssh_session_error_format(
    char **storage, OuterSSHSessionErrorCode code, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
