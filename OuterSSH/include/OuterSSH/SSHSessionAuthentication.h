#ifndef SSH_SESSION_AUTHENTICATION_H
#define SSH_SESSION_AUTHENTICATION_H

#include "OTNullability.h"

#include <stddef.h>

typedef enum {
    OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY,
    OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
    OUTERSSH_SESSION_AUTHENTICATION_AGENT
} OuterSSHSessionAuthenticationKind;

/* String lengths count bytes; no terminating null byte is required. NULL
 * with length zero means absent. A non-NULL password with length zero is an
 * empty password. Agent-only authentication requires an explicit agent socket
 * path in the pool configuration and does not fall back to a private key. Passphrases cannot contain embedded null bytes because the
 * underlying private-key API consumes a C string. */
typedef struct {
    OuterSSHSessionAuthenticationKind kind;
    const void * OT_NULLABLE public_key;
    size_t public_key_length;
    const void * OT_NULLABLE private_key;
    size_t private_key_length;
    const char * OT_NULLABLE passphrase;
    size_t passphrase_length;
    const char * OT_NULLABLE password;
    size_t password_length;
} OuterSSHSessionAuthentication;

#endif
