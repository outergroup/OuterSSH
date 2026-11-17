#ifndef SSH_TEST_EVENTS_H
#define SSH_TEST_EVENTS_H

#include <OuterSSH/OuterSSH.h>
#include "SSHTestEventQueue.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Copies the next event, waiting up to timeout_milliseconds. Payload pointers
 * stay valid until the event queue is polled again. */
static inline bool ssh_test_next_event(OuterSSHEventQueue *event_queue, OuterSSHEvent *event, int timeout_milliseconds)
{
    if (outerssh_event_queue_poll(event_queue, event, 1) == 1) return true;
    for (int waited = 0; waited < timeout_milliseconds; waited += 10) {
        ssh_test_event_queue_wait(event_queue, 10);
        if (outerssh_event_queue_poll(event_queue, event, 1) == 1) return true;
    }
    return false;
}

/* Returns the completion for tag, skipping notifications. The completion must
 * be the next tagged event and have the expected type. */
static inline OuterSSHEvent ssh_test_expect(OuterSSHEventQueue *event_queue, OuterSSHEventType type, uint64_t tag)
{
    OuterSSHEvent event;
    do {
        if (!ssh_test_next_event(event_queue, &event, 30000)) {
            fprintf(stderr, "Timed out waiting for event %d with tag %llu\n", (int)type, (unsigned long long)tag);
            abort();
        }
    } while (event.tag == 0);
    if (event.type != type || event.tag != tag) {
        fprintf(stderr, "Expected event %d with tag %llu, received %d with tag %llu\n", (int)type,
            (unsigned long long)tag, (int)event.type, (unsigned long long)event.tag);
        abort();
    }
    return event;
}

/* The parts of a completion a test checks, copied so they outlive later polls. */
typedef struct {
    OuterSSHEventType type;
    uint64_t tag;
    const OuterSSHSessionPool *pool;
    OuterSSHErrorDomain domain;
    int32_t code;
    int32_t listen_port;
    size_t username_length, password_length;
    char username[64], password[64];
} SSHTestCompletion;

/* Completions that arrived before the test asked for them. Requests on
 * different queues can complete in either order. */
typedef struct {
    OuterSSHEventQueue *event_queue;
    SSHTestCompletion early[64];
    size_t early_count;
} SSHTestCompletions;

static inline SSHTestCompletion ssh_test_completion(const OuterSSHEvent *event)
{
    SSHTestCompletion completion = {.type = event->type, .tag = event->tag, .pool = event->pool,
        .domain = event->operation_completed.error.domain, .code = event->operation_completed.error.code};
    if (event->type == OUTERSSH_EVENT_PROXY_STARTED && completion.domain == OUTERSSH_ERROR_NONE) {
        completion.listen_port = event->proxy_started.listen_port;
        completion.username_length = event->proxy_started.username_length;
        completion.password_length = event->proxy_started.password_length;
        assert(completion.username_length < 64 && completion.password_length < 64);
        if (completion.username_length) memcpy(completion.username, event->proxy_started.username, completion.username_length);
        if (completion.password_length) memcpy(completion.password, event->proxy_started.password, completion.password_length);
    } else if (event->type == OUTERSSH_EVENT_PORT_FORWARD_STARTED) {
        completion.listen_port = event->port_forward_started.listen_port;
    }
    return completion;
}

/* Waits for the completion with this tag, keeping others for later calls. */
static inline SSHTestCompletion ssh_test_take(SSHTestCompletions *completions, OuterSSHEventType type, uint64_t tag)
{
    for (size_t i = 0; i < completions->early_count; i++) {
        if (completions->early[i].tag != tag) continue;
        SSHTestCompletion completion = completions->early[i];
        completions->early[i] = completions->early[--completions->early_count];
        assert(completion.type == type);
        return completion;
    }
    for (;;) {
        OuterSSHEvent event;
        if (!ssh_test_next_event(completions->event_queue, &event, 30000)) {
            fprintf(stderr, "Timed out waiting for event %d with tag %llu\n", (int)type, (unsigned long long)tag);
            abort();
        }
        if (event.tag == 0) continue;
        SSHTestCompletion completion = ssh_test_completion(&event);
        if (event.tag == tag) {
            assert(completion.type == type);
            return completion;
        }
        assert(completions->early_count < 64);
        completions->early[completions->early_count++] = completion;
    }
}

#endif
