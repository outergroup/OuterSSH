#ifndef OUTERSSH_PORT_FORWARD_H
#define OUTERSSH_PORT_FORWARD_H

#include "ProxyTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

typedef struct OuterSSHPortForward OuterSSHPortForward;

/* Creates a fixed TCP forward through one pool. Copies host_length bytes;
 * null termination is not required and embedded null bytes are rejected.
 * The destination is resolved by the SSH server. Each local connection reaches
 * this same destination, with no proxy negotiation, credentials, or HTTP rewriting.
 * The pool must remain alive until the forward's OUTERSSH_EVENT_DESTROYED.
 * Returns NULL on failure; error text has process lifetime. */
OuterSSHPortForward * OT_NULLABLE outerssh_port_forward_create(OuterSSHSessionPool *pool,
    const char *host, size_t host_length, uint16_t port,
    OuterSSHError * OT_NULLABLE error);

/* Binds to 127.0.0.1; zero selects an available local port. Start is
 * idempotent for the current port; after a failure or stop, it may be called
 * again. Start completes with OUTERSSH_EVENT_PORT_FORWARD_STARTED and stop with
 * OUTERSSH_EVENT_OPERATION_COMPLETED. Listening does not imply that SSH
 * authentication or a remote connection has succeeded. Operations are
 * serialized in submission order. */
bool outerssh_port_forward_start(OuterSSHPortForward *forward, uint16_t preferred_port, uint64_t tag);
/* Closes the listener, cancels pending connections, and schedules closure of
 * active streams. The pool remains usable; the forward may be restarted. */
bool outerssh_port_forward_stop(OuterSSHPortForward *forward, uint64_t tag);

/* Stops forwarding and frees the object after its pending work and socket-source
 * cancellations finish, then posts OUTERSSH_EVENT_DESTROYED. No further calls
 * may use the forward after destroy. Wait for destruction before destroying
 * its pool. */
bool outerssh_port_forward_destroy(OuterSSHPortForward *forward, uint64_t tag);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif
#endif
