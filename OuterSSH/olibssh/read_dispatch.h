#ifndef OLIBSSH_READ_DISPATCH_H
#define OLIBSSH_READ_DISPATCH_H

#include <libssh2.h>

typedef struct SSHReactor SSHReactor;

/* Reads at most one complete packet and calls the reactor synchronously after
 * finalizing transport bookkeeping. Returns its SSH message number or a negative
 * transport error. Key exchange is advanced between packets by the reactor. */
int olibssh_transport_read(LIBSSH2_SESSION *session, SSHReactor *reactor);
int olibssh_transport_has_buffered_input(LIBSSH2_SESSION *session);

#endif
