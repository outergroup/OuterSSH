#ifndef SSH_EVENTS_INTERNAL_H
#define SSH_EVENTS_INTERNAL_H

#include "SSHSessionPoolInternal.h"

struct SSHPoolEvent {
    SSHPoolEvent *next;
    OuterSSHEvent event;
    uint64_t question;
    unsigned char *storage;
    /* Where a reserved reply posts; set by outersshpriv_reply_reserve. */
    OuterSSHEventQueue *event_queue;
};

typedef struct {
    const void *bytes;
    size_t length;
} SSHEventBytes;

SSHPoolEvent *outersshpriv_event_create(OuterSSHEventType type, OuterSSHSessionPool *pool, uint64_t tag);
/* Replaces the event's storage with one allocation holding each part followed
 * by a NUL, and stores a pointer to each copy. Returns false if allocation
 * fails, leaving the event without storage. */
bool outersshpriv_event_copy_parts(SSHPoolEvent *event, const SSHEventBytes *parts, size_t count, const void **copies);
/* Copies the error's text into the event's storage along with parts. */
bool outersshpriv_event_copy_error_and_parts(SSHPoolEvent *event, OuterSSHError *error,
    const SSHEventBytes *parts, size_t count, const void **copies);
void outersshpriv_event_post(OuterSSHEventQueue *event_queue, SSHPoolEvent *event);

/* Replies. A request reserves its completion event before it starts, so an
 * accepted request can always report. The operation that carries the reply
 * finishes by passing it to exactly one of the functions below, which copy
 * error text and payload into the event and post it to the pool's event queue.
 * If copying fails, the event reports an allocation error instead. Replies
 * may be sent from any queue, and remain valid after their pool is freed. */
SSHPoolEvent *outersshpriv_reply_reserve(OuterSSHSessionPool *pool, OuterSSHEventType type, uint64_t tag);
/* OUTERSSH_EVENT_OPERATION_COMPLETED and OUTERSSH_EVENT_DESTROYED. */
void outersshpriv_reply(SSHPoolEvent *reply, OuterSSHError error);
void outersshpriv_reply_command(SSHPoolEvent *reply, const SSHCommandOutput *output, OuterSSHError error);
/* found is false when no homepage is configured. */
void outersshpriv_reply_homepage(SSHPoolEvent *reply, bool found, const char *url, size_t url_length,
    const char *source_path, size_t source_path_length, OuterSSHError error);
void outersshpriv_reply_socket_bridges(SSHPoolEvent *reply, const OuterSSHBridgeInfo *bridges, size_t count,
    OuterSSHError error);
void outersshpriv_reply_proxy_started(SSHPoolEvent *reply, int32_t listen_port, const char *username,
    size_t username_length, const char *password, size_t password_length, OuterSSHError error);
/* An empty png reports that no icon is cached. */
void outersshpriv_reply_endpoint_icon(SSHPoolEvent *reply, const void *png, size_t length, OuterSSHError error);
void outersshpriv_reply_helper_response(SSHPoolEvent *reply, const void *bytes, size_t length, OuterSSHError error);
void outersshpriv_reply_port_forward_started(SSHPoolEvent *reply, int32_t listen_port, OuterSSHError error);

#endif
