#ifndef OLIBSSH_KEY_EXCHANGE_H
#define OLIBSSH_KEY_EXCHANGE_H

#include <libssh2.h>
#include "read_dispatch.h"

typedef enum {
    OLIBSSH_KEY_EXCHANGE_IDLE,
    OLIBSSH_KEY_EXCHANGE_NEEDS_INPUT,
    OLIBSSH_KEY_EXCHANGE_NEEDS_OUTPUT,
    OLIBSSH_KEY_EXCHANGE_COMPLETE,
    OLIBSSH_KEY_EXCHANGE_FAILED
} OLIBSSHKeyExchangeStep;

/* Own this state until completion or cancellation. The handshake driver and
 * reactor use this same engine, starting after the SSH banner exchange.
 * Only one driver may own an exchange on a session at a time. */
typedef struct OLIBSSHKeyExchange {
    struct OLIBSSHKeyExchangeState *state;
    OLIBSSHKeyExchangeStep step;
    const unsigned char *packet;
    size_t packet_length;
    unsigned char *input_packet;
    size_t input_length;
    int error;
    int packet_write_pending;
} OLIBSSHKeyExchange;

/* Takes ownership of one received exchange packet, including on error.
 * Call advance when the reactor can progress the exchange. */
int olibssh_key_exchange_receive(LIBSSH2_SESSION *session,
    OLIBSSHKeyExchange *exchange, unsigned char *packet, size_t length);

/* Runs computation/continuations only: never reads or writes.
 * Call once to start and after each transport read or completed packet write.
 */
OLIBSSHKeyExchangeStep olibssh_key_exchange_advance(
    LIBSSH2_SESSION *session, OLIBSSHKeyExchange *exchange);

/* Call only for NEEDS_OUTPUT, on socket writability. EAGAIN preserves the
 * pending packet. On completion, call advance before reading another packet
 * (in particular, to apply NEWKEYS at the correct packet boundary).
 */
int olibssh_key_exchange_write(
    LIBSSH2_SESSION *session, OLIBSSHKeyExchange *exchange);

/* Releases caller-owned exchange state after completion or cancellation.
 * Unless the exchange completed, the session must then be closed.
 */
void olibssh_key_exchange_cleanup(
    LIBSSH2_SESSION *session, OLIBSSHKeyExchange *exchange);

/* Starts a new packet: no key exchange or reads. Input is borrowed for this
 * call only. After EAGAIN, use resume_write until completion before starting
 * another packet. */
int olibssh_transport_write(
    LIBSSH2_SESSION *session, const unsigned char *data, size_t data_len,
    const unsigned char *data2, size_t data2_len);

/* Completes the existing encrypted packet without borrowing its original input.
 * The reactor must finish this write before starting any other packet. */
int olibssh_transport_resume_write(LIBSSH2_SESSION *session);

#endif
