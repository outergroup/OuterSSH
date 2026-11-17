#ifndef SSH_WAITING_H
#define SSH_WAITING_H

/* Waiting for something the pool learns once: a ready session, the remote
 * platform, the remote user, an installed bridge executable, an authorized
 * socket path. An operation that needs the fact parks a waiter embedded in its
 * own record. The first waiter starts the lookup. When the lookup finishes, the
 * pool stores the fact and wakes every waiter with only an error; each
 * operation resumes by reading the fact from pool state. Control queue only. */

#include "SSHContinuations.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct SSHWaiter {
    struct SSHWaiter *next;
    SSHCompletionHandler resume;
    void *context;
} SSHWaiter;

typedef struct {
    SSHWaiter *head;
    SSHWaiter *tail;
} SSHWaitList;

/* Parks waiter, which stays owned by the waiting operation until it resumes.
 * Returns true when the list was empty: the caller must start the lookup. */
static inline bool outersshpriv_wait(SSHWaitList *list, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context)
{
    *waiter = (SSHWaiter){.resume = resume, .context = context};
    bool first = list->head == NULL;
    if (first) list->head = waiter;
    else list->tail->next = waiter;
    list->tail = waiter;
    return first;
}

static inline bool outersshpriv_is_waiting(const SSHWaitList *list)
{
    return list->head != NULL;
}

/* Detaches every waiter, then resumes each in order. A resumed operation may
 * free itself or wait again; later waits start a new lookup. */
static inline void outersshpriv_wake(SSHWaitList *list, OuterSSHError error)
{
    SSHWaiter *waiter = list->head;
    list->head = list->tail = NULL;
    while (waiter != NULL) {
        SSHWaiter *next = waiter->next;
        waiter->next = NULL;
        waiter->resume(waiter->context, error);
        waiter = next;
    }
}

#endif
