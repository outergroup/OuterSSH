#ifndef SSH_SESSION_START_H
#define SSH_SESSION_START_H

#include "OTNullability.h"

#include "platform/OTSocket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <limits.h>
#include <string.h>
#include <libssh2.h>
#include "SSHSessionAuthentication.h"
#include "SSHProxyError.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

typedef struct {
    OuterSSHError error;
    char * OT_NULLABLE error_storage;
} SSHSessionStartResult;

static inline bool outersshpriv_session_configuration_is_valid(
    const char *username,
    size_t username_length,
    OuterSSHSessionAuthentication authentication,
    const char * OT_NULLABLE ssh_agent_socket_path,
    size_t ssh_agent_socket_path_length)
{
    return username != NULL && username_length != 0 &&
        username_length <= INT_MAX && memchr(username, 0, username_length) == NULL &&
        ssh_agent_socket_path_length < SIZE_MAX &&
        (ssh_agent_socket_path_length == 0 ||
         (ssh_agent_socket_path != NULL &&
          memchr(ssh_agent_socket_path, 0, ssh_agent_socket_path_length) == NULL)) &&
        authentication.passphrase_length < SIZE_MAX &&
        (authentication.passphrase_length == 0 ||
         (authentication.passphrase != NULL &&
          memchr(authentication.passphrase, 0, authentication.passphrase_length) == NULL)) &&
        (authentication.password != NULL || authentication.password_length == 0) &&
        ((authentication.kind == OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY &&
          authentication.private_key != NULL && authentication.private_key_length != 0 &&
          (authentication.public_key != NULL || authentication.public_key_length == 0)) ||
         (authentication.kind == OUTERSSH_SESSION_AUTHENTICATION_AGENT &&
          ssh_agent_socket_path != NULL && ssh_agent_socket_path_length != 0) ||
         (authentication.kind == OUTERSSH_SESSION_AUTHENTICATION_PASSWORD &&
          authentication.password != NULL && authentication.password_length <= UINT_MAX));
}

/* Creates/configures a session; the caller retains ownership of the socket. */
LIBSSH2_SESSION * OT_NULLABLE outersshpriv_session_create(
    otsocket_t socket, SSHSessionStartResult *result);

void outersshpriv_session_start_result_dispose(
    SSHSessionStartResult * OT_NULLABLE result);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif

#endif
