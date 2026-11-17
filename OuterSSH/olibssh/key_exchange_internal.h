#ifndef OLIBSSH_KEY_EXCHANGE_INTERNAL_H
#define OLIBSSH_KEY_EXCHANGE_INTERNAL_H

#include "libssh2/libssh2_priv.h"
#include "key_exchange.h"

typedef int (*OLIBSSHKeyExchangeContinuation)(LIBSSH2_SESSION *, OLIBSSHKeyExchange *);

/* One allocation owns the algorithm resources and its network continuations. */
typedef struct OLIBSSHKeyExchangeState {
    key_exchange_state_low_t key_state;
    OLIBSSHKeyExchange *owner;
    OLIBSSHKeyExchangeContinuation next;
    OLIBSSHKeyExchangeContinuation written;
    OLIBSSHKeyExchangeContinuation received;
    void (*cleanup)(LIBSSH2_SESSION *, key_exchange_state_low_t *);
    unsigned char expected_type;
    unsigned char **input_destination;
    size_t *input_length_destination;
    int sha_algo;
    unsigned char reply_type;
    unsigned char *midhash;
    size_t midhash_length;
#if LIBSSH2_ECDSA
    libssh2_curve_type curve_type;
#endif
} OLIBSSHKeyExchangeState;

#endif
