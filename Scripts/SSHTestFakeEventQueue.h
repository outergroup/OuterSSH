#ifndef SSH_TEST_FAKE_EVENT_QUEUE_H
#define SSH_TEST_FAKE_EVENT_QUEUE_H

/* Event delivery for tests that build an OuterSSHEventQueue by hand around a
 * test queue, without outerssh_event_queue_create. */

#include "SSHTestSupport.h"
#include "SSHEventQueueInternal.h"
#include "include/OuterSSH/SSHEvents.h"

#if !defined(__APPLE__)
typedef struct {
    OuterSSHEventQueue *event_queue;
    otqueue_t queue;
    void (*drain)(void *);
    void *argument;
} SSHTestEventQueueObserver;

static void ssh_test_event_queue_watch(void *pointer)
{
    SSHTestEventQueueObserver *observer = pointer;
    OuterSSHEventWaitHandle handle = outerssh_event_queue_wait_handle(observer->event_queue);
    if (handle == OUTERSSH_EVENT_WAIT_HANDLE_INVALID) abort();
    for (;;) {
#if defined(_WIN32)
        if (WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0) continue;
#else
        struct pollfd entry = {.fd = handle, .events = POLLIN};
        if (poll(&entry, 1, -1) <= 0) continue;
#endif
        ssh_test_sync(observer->queue, observer->argument, observer->drain);
    }
}
#endif

/* Runs drain on queue whenever the event queue has pending events, as an
 * application's handler would; drain should poll until none remain. */
static inline void ssh_test_event_queue_observe(OuterSSHEventQueue *event_queue, otqueue_t queue,
    void (*drain)(void *), void *argument)
{
#if defined(__APPLE__)
    event_queue->events = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_OR, 0, 0, queue);
    dispatch_set_context(event_queue->events, argument);
    dispatch_source_set_event_handler_f(event_queue->events, drain);
    dispatch_activate(event_queue->events);
#else
    SSHTestEventQueueObserver *observer = malloc(sizeof(*observer));
    if (observer == NULL) abort();
    *observer = (SSHTestEventQueueObserver){event_queue, queue, drain, argument};
    ssh_test_thread_start(ssh_test_event_queue_watch, observer);
#endif
}

#endif
