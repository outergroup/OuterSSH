#ifndef SSH_REACTOR_READ_INTERNAL_H
#define SSH_REACTOR_READ_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <libssh2.h>

typedef struct SSHReactor SSHReactor;

/* Synchronous calls on the reactor queue, after transport packet bookkeeping
 * is complete. Handlers may close channels or invalidate the reactor. Borrowed
 * data remains valid through the call; session destruction is deferred. */
void outersshpriv_reactor_received_authentication(SSHReactor *reactor,
    const unsigned char *packet, size_t length);

void outersshpriv_reactor_received_service_accept(SSHReactor *reactor,
    const unsigned char *packet, size_t length);

void outersshpriv_reactor_received_channel_data(SSHReactor *reactor,
    uint32_t channel_id, uint32_t stream_id,
    const unsigned char *bytes, size_t byte_count);

void outersshpriv_reactor_received_channel_eof(SSHReactor *reactor,
    uint32_t channel_id);

void outersshpriv_reactor_received_channel_close(SSHReactor *reactor,
    uint32_t channel_id);

void outersshpriv_reactor_received_channel_window_adjust(SSHReactor *reactor,
    uint32_t channel_id, uint32_t adjustment);

void outersshpriv_reactor_received_channel_open_confirmation(SSHReactor *reactor,
    uint32_t channel_id, uint32_t remote_id, uint32_t window_size, uint32_t packet_size);

void outersshpriv_reactor_received_channel_open_failure(SSHReactor *reactor,
    uint32_t channel_id, uint32_t reason_code);

void outersshpriv_reactor_received_channel_request_success(SSHReactor *reactor,
    uint32_t channel_id);

void outersshpriv_reactor_received_channel_request_failure(SSHReactor *reactor,
    uint32_t channel_id);

void outersshpriv_reactor_received_channel_exit_status(SSHReactor *reactor,
    uint32_t channel_id, uint32_t exit_status);

bool outersshpriv_reactor_reject_channel_request(SSHReactor *reactor, uint32_t channel_id);

bool outersshpriv_reactor_queue_protocol_response(SSHReactor *reactor,
    const void *bytes, size_t byte_count);

void outersshpriv_reactor_received_global_response(SSHReactor *reactor, bool succeeded);

/* Takes ownership of the payload allocated by the session's allocator. */
void outersshpriv_reactor_received_key_exchange_packet(SSHReactor *reactor,
    unsigned char *packet, size_t length);

#endif
