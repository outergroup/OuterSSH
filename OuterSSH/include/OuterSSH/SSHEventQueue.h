#ifndef SSH_EVENT_QUEUE_H
#define SSH_EVENT_QUEUE_H

#include "OTNullability.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#if defined(__APPLE__)
#include <dispatch/dispatch.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

/* An event queue receives the events of every pool and frontend created in
 * it, in order, and signals the application when events are pending. It holds
 * only events: each pool has a serial control queue of its own, shared with its
 * frontends, and each SSH session runs on a queue of its own, so pools and
 * sessions run in parallel. OuterSSH runs on the platform's thread pool:
 * Dispatch on Apple platforms, the system thread pool on Windows, and on Linux
 * and Android a small pool of threads the library starts with the first pool.
 * Public request functions may be called from any thread. */
typedef struct OuterSSHEventQueue OuterSSHEventQueue;

#if defined(__APPLE__)
/* Creates an event queue. events is a DISPATCH_SOURCE_TYPE_DATA_OR source the
 * application created, targeting any queue; the event queue retains it and
 * merges data into it when events become pending. Drain them from its handler
 * with outerssh_event_queue_poll. Returns NULL if allocation fails. */
OuterSSHEventQueue * OT_NULLABLE outerssh_event_queue_create(dispatch_source_t events);
#else
/* Creates an event queue. Watch outerssh_event_queue_wait_handle to learn when
 * events are pending. Returns NULL if a resource could not be created. */
OuterSSHEventQueue * OT_NULLABLE outerssh_event_queue_create(void);
#endif

/* Destroys the event queue and its events. Destroy it only after every pool and
 * frontend created in it has posted OUTERSSH_EVENT_DESTROYED; no further
 * calls may use the event queue afterward. On Apple platforms, cancel the
 * events source and destroy the event queue on the queue the source targets, so
 * its handler is not running and does not run again. */
void outerssh_event_queue_destroy(OuterSSHEventQueue * OT_NULLABLE event_queue);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif
#endif
