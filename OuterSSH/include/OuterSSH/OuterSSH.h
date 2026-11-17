#ifndef OUTER_SSH_H
#define OUTER_SSH_H

#include "OTNullability.h"
#include "SSHEventQueue.h"
#include "SSHEvents.h"

#include "SSHProxyAddress.h"
#include "SOCKSProxyServer.h"
#include "HTTPProxyServer.h"
#include "PortForward.h"
#include "OuterSSHAndroid.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Process-wide and thread-safe. Pool and server creation also initialize
 * OuterSSH. Returned error text remains valid for the process lifetime. */
bool outerssh_initialize(OuterSSHError * OT_NULLABLE error);

/* Sharing accepts unencrypted, exportable identities only. */
#define OUTERSSH_KEY_RSA 1u
#define OUTERSSH_KEY_ECDSA 2u
#define OUTERSSH_KEY_ED25519 4u
#define OUTERSSH_KEY_OPENSSH 8u
#define OUTERSSH_KEY_RSA_PEM 16u
#define OUTERSSH_KEY_EC_PEM 32u
#define OUTERSSH_KEY_PKCS8 64u

uint32_t outerssh_private_key_capabilities(void);
/* Returns a static explanation, or NULL on success. Validation imports the key
 * and verifies a locally generated signature; it does not contact a server. */
const char * OT_NULLABLE outerssh_check_private_key(const void * OT_NONNULL bytes,
    size_t length, uint32_t recipient_capabilities, bool validate);

#ifdef __cplusplus
}
#endif

#endif
