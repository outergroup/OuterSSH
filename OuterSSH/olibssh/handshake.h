#ifndef OLIBSSH_HANDSHAKE_H
#define OLIBSSH_HANDSHAKE_H

#include <libssh2.h>

/* Socket is already nonblocking. These steps never wait for readiness. */
void olibssh_handshake_set_socket(LIBSSH2_SESSION *session, libssh2_socket_t socket);
int olibssh_handshake_send_banner(LIBSSH2_SESSION *session, size_t *offset);
int olibssh_handshake_receive_banner(LIBSSH2_SESSION *session,
    char *buffer, size_t capacity, size_t *length);

#endif
