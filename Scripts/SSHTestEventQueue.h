#ifndef SSH_TEST_EVENT_QUEUE_H
#define SSH_TEST_EVENT_QUEUE_H

/* Event queues for tests of the public API, created the way an application on
 * this platform creates them. */

#include <OuterSSH/OuterSSH.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#if defined(_WIN32)
#include <windows.h>
#elif !defined(__APPLE__)
#include <errno.h>
#include <poll.h>
#endif

#if defined(__APPLE__)
typedef struct {
    OuterSSHEventQueue *event_queue;
    dispatch_queue_t queue;
    dispatch_source_t events;
    dispatch_semaphore_t posted;
} SSHTestEventQueue;

static SSHTestEventQueue *ssh_test_event_queues[32];

static void ssh_test_event_queue_posted(void *user)
{
    SSHTestEventQueue *test = user;
    dispatch_semaphore_signal(test->posted);
}

static SSHTestEventQueue *ssh_test_event_queue_find(OuterSSHEventQueue *event_queue)
{
    for (size_t i = 0; i < sizeof(ssh_test_event_queues) / sizeof(ssh_test_event_queues[0]); i++) {
        if (ssh_test_event_queues[i] != NULL && ssh_test_event_queues[i]->event_queue == event_queue) return ssh_test_event_queues[i];
    }
    abort();
}

static inline OuterSSHEventQueue *ssh_test_event_queue_create(void)
{
    SSHTestEventQueue *test = calloc(1, sizeof(*test));
    if (test == NULL) return NULL;
    test->queue = dispatch_queue_create("org.outerssh.test-event-queue", DISPATCH_QUEUE_SERIAL);
    test->posted = dispatch_semaphore_create(0);
    test->events = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_OR, 0, 0, test->queue);
    dispatch_set_context(test->events, test);
    dispatch_source_set_event_handler_f(test->events, ssh_test_event_queue_posted);
    dispatch_activate(test->events);
    test->event_queue = outerssh_event_queue_create(test->events);
    if (test->event_queue == NULL) abort();
    for (size_t i = 0; i < sizeof(ssh_test_event_queues) / sizeof(ssh_test_event_queues[0]); i++) {
        if (ssh_test_event_queues[i] != NULL) continue;
        ssh_test_event_queues[i] = test;
        return test->event_queue;
    }
    abort();
}

/* Waits up to timeout_milliseconds (negative: no limit) for the event queue to post
 * events. Returns false on timeout; events may already be pending either way. */
static inline bool ssh_test_event_queue_wait(OuterSSHEventQueue *event_queue, int timeout_milliseconds)
{
    SSHTestEventQueue *test = ssh_test_event_queue_find(event_queue);
    dispatch_time_t deadline = timeout_milliseconds < 0 ? DISPATCH_TIME_FOREVER
        : dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_milliseconds * (int64_t)NSEC_PER_MSEC);
    return dispatch_semaphore_wait(test->posted, deadline) == 0;
}

static void ssh_test_event_queue_destroy_on_queue(void *pointer)
{
    SSHTestEventQueue *test = pointer;
    dispatch_source_cancel(test->events);
    outerssh_event_queue_destroy(test->event_queue);
}

/* Destroys the event queue once every pool and frontend in it has posted
 * OUTERSSH_EVENT_DESTROYED. */
static inline void ssh_test_event_queue_destroy(OuterSSHEventQueue *event_queue)
{
    if (event_queue == NULL) return;
    SSHTestEventQueue *test = ssh_test_event_queue_find(event_queue);
    for (size_t i = 0; i < sizeof(ssh_test_event_queues) / sizeof(ssh_test_event_queues[0]); i++) {
        if (ssh_test_event_queues[i] == test) ssh_test_event_queues[i] = NULL;
    }
    dispatch_sync_f(test->queue, test, ssh_test_event_queue_destroy_on_queue);
    dispatch_release(test->events);
    dispatch_release(test->queue);
    dispatch_release(test->posted);
    free(test);
}
#else
static inline OuterSSHEventQueue *ssh_test_event_queue_create(void)
{
    OuterSSHEventQueue *event_queue = outerssh_event_queue_create();
    if (event_queue == NULL) abort();
    return event_queue;
}

/* Waits up to timeout_milliseconds (negative: no limit) for events to be
 * pending. Returns false on timeout. */
static inline bool ssh_test_event_queue_wait(OuterSSHEventQueue *event_queue, int timeout_milliseconds)
{
    OuterSSHEventWaitHandle handle = outerssh_event_queue_wait_handle(event_queue);
    if (handle == OUTERSSH_EVENT_WAIT_HANDLE_INVALID) abort();
#if defined(_WIN32)
    return WaitForSingleObject(handle, timeout_milliseconds < 0 ? INFINITE : (DWORD)timeout_milliseconds) == WAIT_OBJECT_0;
#else
    struct pollfd entry = {.fd = handle, .events = POLLIN};
    int result;
    do result = poll(&entry, 1, timeout_milliseconds);
    while (result < 0 && errno == EINTR);
    return result > 0;
#endif
}

/* Destroys the event queue once every pool and frontend in it has posted
 * OUTERSSH_EVENT_DESTROYED. */
static inline void ssh_test_event_queue_destroy(OuterSSHEventQueue *event_queue)
{
    outerssh_event_queue_destroy(event_queue);
}
#endif

#endif
