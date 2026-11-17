#ifndef SSH_REACTOR_HANDSHAKE_H
#define SSH_REACTOR_HANDSHAKE_H

#include "SSHReactor.h"

/* Stored in the reactor until finished runs exactly once on its queue.
 * Completion leaves the reactor paused and permits reusing startup storage.
 * Cancel through outersshpriv_reactor_cancel_startup; destroy only after completion. */
typedef struct SSHHandshakeContext {
    SSHReactor *reactor;
    void (*finished)(void *context, int error);
    void *context;
    void (*read)(SSHReactor *reactor);
    void (*write)(SSHReactor *reactor);
    otsource_t timeout_timer;
    int error;
    size_t banner_offset;
    size_t banner_length;
    char banner[255];
    bool service_requested;
    bool service_write_pending;
} SSHHandshakeContext;

void outersshpriv_reactor_handshake(SSHReactor *reactor,
    void (*finished)(void *, int), void *completion_context);
/* Queued on the reactor, whose socket stays alive until startup finishes. */
void outersshpriv_reactor_cancel_startup(SSHReactor *reactor);

/* Reactor-queue continuations. */
void outersshpriv_handshake_keys_exchanged(SSHReactor *reactor);
void outersshpriv_handshake_failed(SSHReactor *reactor, int error);

#endif
