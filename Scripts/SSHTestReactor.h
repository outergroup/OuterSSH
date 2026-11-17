#ifndef SSH_TEST_REACTOR_H
#define SSH_TEST_REACTOR_H

#include "SSHTestSupport.h"
#include "SSHReactor.h"

typedef struct {
    otsocket_t socket;
    LIBSSH2_SESSION *session;
    otqueue_t queue;
    SSHReactor *reactor;
    ssh_test_semaphore_t created;
} SSHTestReactorCreation;

static void ssh_test_reactor_created(void *context, SSHReactor *reactor)
{
    SSHTestReactorCreation *creation = context;
    creation->reactor = reactor;
    ssh_test_semaphore_signal(creation->created);
}

static void ssh_test_reactor_create_on_queue(void *context)
{
    SSHTestReactorCreation *creation = context;
    if (!outersshpriv_reactor_create(creation->queue, creation->socket, creation->session, ssh_test_reactor_created, creation))
        ssh_test_reactor_created(creation, NULL);
}

/* Creates a reactor on a queue of its own and waits for it. */
static inline SSHReactor *ssh_test_reactor_create(otsocket_t socket, LIBSSH2_SESSION *session)
{
    static otqueue_t queue;
    if (queue == NULL) queue = ssh_test_queue_create("reactor-creation");
    SSHTestReactorCreation creation = {.socket = socket, .session = session, .queue = queue,
        .created = ssh_test_semaphore_create(0)};
    assert(creation.created != NULL);
    otqueue_async(queue, &creation, ssh_test_reactor_create_on_queue);
    if (ssh_test_semaphore_wait(creation.created, 30 * NSEC_PER_SEC) != 0) abort();
    ssh_test_semaphore_destroy(creation.created);
    return creation.reactor;
}

#endif
