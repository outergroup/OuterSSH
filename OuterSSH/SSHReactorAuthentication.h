#ifndef SSH_REACTOR_AUTHENTICATION_H
#define SSH_REACTOR_AUTHENTICATION_H

#include "SSHReactor.h"
#include "SSHSessionPool.h"
#include "SSHSessionStart.h"
#include "olibssh/authentication.h"

struct string_buf;

typedef struct {
    const char *username;
    size_t username_length;
    OuterSSHSessionAuthentication credentials;
    const char *agent_path;
    size_t agent_path_length;
    /* Asks this pool's application about the host key; NULL accepts any key. */
    OuterSSHSessionPool *host_key_pool;
    uint64_t timeout_milliseconds;
} SSHAuthenticationRequest;

/* Stored in the reactor. Request inputs must remain alive until finished,
 * called exactly once on the reactor queue with borrowed error strings.
 * Cancellation stops network I/O, then waits for host validation and local workers
 * before completion permits destroying the reactor or reusing startup storage. */
typedef struct SSHAuthenticationContext {
    SSHReactor *reactor;
    SSHAuthenticationRequest request;
    void (*finished)(void *, OuterSSHError);
    void *completion_context;
    void (*received)(struct SSHAuthenticationContext *, struct string_buf *);
    otsource_t timeout_timer;
    unsigned char *packet;
    size_t packet_length;
    bool packet_write_pending;
    bool awaiting_response;
    bool worker_pending;
    bool validation_pending;
    bool done;
    bool keyboard_interactive_offered;
    bool using_original_key_method;
    OuterSSHError error;

    /* Host validation borrows the key until it queues its result. Cancellation
     * leaves this storage intact until that result reaches the reactor. */
    unsigned char *host_key;
    size_t host_key_length;
    char fingerprint[OUTERSSH_HOST_KEY_FINGERPRINT_CAPACITY];
    size_t fingerprint_length;
    OuterSSHError validation_error;
    /* Background workers own these fields until their return continuation. */
    OLIBSSHAuthenticationKey key;
    int worker_error;
    char *worker_error_message;
    char *key_method;
    size_t key_method_length;
    unsigned char *signed_data;
    size_t signed_data_length;
    size_t signing_prefix_length;
    unsigned char *signature;
    size_t signature_length;
} SSHAuthenticationContext;

void outersshpriv_reactor_authenticate(SSHReactor *reactor,
    SSHAuthenticationRequest request,
    void (*finished)(void *, OuterSSHError), void *completion_context);

/* Reactor-queue continuations. */
int outersshpriv_authentication_resume_write(SSHReactor *reactor);
void outersshpriv_authentication_keys_exchanged(SSHReactor *reactor);
void outersshpriv_authentication_failed(SSHReactor *reactor, int error);

#endif
