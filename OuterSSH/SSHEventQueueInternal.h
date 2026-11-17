#ifndef SSH_EVENT_QUEUE_INTERNAL_H
#define SSH_EVENT_QUEUE_INTERNAL_H

#include "include/OuterSSH/SSHEventQueue.h"
#include "platform/OTLock.h"
#if !defined(__APPLE__)
#include "platform/OTEventSignal.h"
#endif
#include <stdbool.h>

typedef struct SSHPoolEvent SSHPoolEvent;

struct OuterSSHEventQueue {
    /* Guards the event fields below; posting runs on library queues, and
     * polling runs on the caller's thread. */
    OTLock event_lock;
    SSHPoolEvent *event_head;
    SSHPoolEvent *event_tail;
    SSHPoolEvent *delivered_events;
#if defined(__APPLE__)
    /* The application's source, signaled when events become pending. */
    dispatch_source_t events;
#else
    OTEventSignal event_signal;
#endif
};

void outersshpriv_event_queue_dispose_events(OuterSSHEventQueue *event_queue);

#endif
