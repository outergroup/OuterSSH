#ifndef OLIBSSH_AUTHENTICATION_H
#define OLIBSSH_AUTHENTICATION_H

#include <stdbool.h>
#include <libssh2.h>
#include "SSHSessionAuthentication.h"

/* Used by one background job at a time. Its disconnected session supplies
 * allocators and crypto errors, never the network session or its transport. */
typedef struct {
    LIBSSH2_SESSION *session;
    LIBSSH2_AGENT *agent;
    struct libssh2_agent_publickey *identity;
    const unsigned char *public_key;
    size_t public_key_length;
    unsigned char *owned_public_key;
    char *passphrase;
    OuterSSHSessionAuthentication authentication;
} OLIBSSHAuthenticationKey;

int olibssh_authentication_open_agent(OLIBSSHAuthenticationKey *key,
    const char *path, size_t path_length);
int olibssh_authentication_next_agent_key(OLIBSSHAuthenticationKey *key);
int olibssh_authentication_load_private_key(OLIBSSHAuthenticationKey *key,
    OuterSSHSessionAuthentication authentication);
int olibssh_authentication_sign(OLIBSSHAuthenticationKey *key,
    const char *method, size_t method_length,
    const unsigned char *data, size_t length,
    unsigned char **signature, size_t *signature_length);
/* Returns a borrowed name: certificate requests carry the underlying signing
 * algorithm in their signature envelope and agent signing request. */
const char *olibssh_authentication_signature_method(const char *method, size_t *length);
void olibssh_authentication_key_dispose(OLIBSSHAuthenticationKey *key);

/* Reactor-queue access to the network session. Method is malloc-owned. */
int olibssh_authentication_key_method(LIBSSH2_SESSION *session,
    const unsigned char *public_key, size_t public_key_length,
    bool use_original_method, char **method, size_t *method_length);
const unsigned char *olibssh_authentication_session_id(LIBSSH2_SESSION *session,
    size_t *length);
void olibssh_authentication_succeeded(LIBSSH2_SESSION *session);

#endif
