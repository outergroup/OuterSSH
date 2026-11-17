#include "SSHTestSupport.h"
#include "SSHTestEventQueue.h"
#include <OuterSSH/OuterSSH.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../OuterSSH/SSHSessionPoolInternal.h"

static unsigned destructions, operations;

static void require_bridge_cleanup(void *context)
{
    OuterSSHSessionPool *pool = context;
    pool->_userBridgeExecutablePath = strdup("/tmp/outerssh-jump-pool-test/bridge");
    assert(pool->_userBridgeExecutablePath);
    pool->_userBridgeExecutablePath_length = strlen(pool->_userBridgeExecutablePath);
}

static OuterSSHEvent next_event(OuterSSHEventQueue *event_queue)
{
    OuterSSHEvent event;
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        if (outerssh_event_queue_poll(event_queue, &event, 1) == 1) return event;
        ssh_test_event_queue_wait(event_queue, 100);
    }
    assert(!"timed out waiting for an event");
    return event;
}

/* Counts failed sessions and destructions until the pool's DESTROYED event. */
static void drain_until_destroyed(OuterSSHEventQueue *event_queue, OuterSSHSessionPool *pool)
{
    for (;;) {
        OuterSSHEvent event = next_event(event_queue);
        assert(event.pool == pool);
        if (event.type == OUTERSSH_EVENT_DESTROYED) {
            assert(event.tag == 2);
            destructions++;
            ssh_test_event_queue_destroy(event_queue);
            return;
        }
        assert(event.type == OUTERSSH_EVENT_OPERATION_COMPLETED && event.tag == 1);
        assert(event.operation_completed.error.domain != OUTERSSH_ERROR_NONE);
        operations++;
    }
}

static OuterSSHSessionPool *create_pool(OuterSSHEventQueue **event_queue, OuterSSHSessionPool *jump_host)
{
    *event_queue = ssh_test_event_queue_create();
    assert(*event_queue);
    OuterSSHSessionPoolConfiguration config = {
        .jump_host = jump_host,
        .hostname = "127.0.0.1", .hostname_length = 9,
        .username = "test", .username_length = 4, .port = 1,
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
            .password = "test", .password_length = 4}
    };
    OuterSSHError error = {0};
    OuterSSHSessionPool *pool = outerssh_session_pool_create(*event_queue, &config, &error);
    assert(pool && !error.domain);
    return pool;
}

static void test_shutdown_with_bridge_cleanup(bool start_transport)
{
    OuterSSHEventQueue *event_queues[2];
    OuterSSHSessionPool *pools[2];
    for (unsigned i = 0; i < 2; i++) pools[i] = create_pool(&event_queues[i], i ? pools[0] : NULL);
    if (start_transport) {
        assert(outerssh_session_pool_ensure_session(pools[1], 1));
        OuterSSHEvent event = next_event(event_queues[1]);
        assert(event.type == OUTERSSH_EVENT_OPERATION_COMPLETED && event.operation_completed.error.domain);
    }
    ssh_test_sync(pools[1]->_queue, pools[1], require_bridge_cleanup);
    for (unsigned i = 0; i < 2; i++) assert(outerssh_session_pool_destroy(pools[i], 2));
    for (unsigned i = 0; i < 2; i++) drain_until_destroyed(event_queues[i], pools[i]);
}

int main(void)
{
    for (unsigned iteration = 0; iteration < 30; iteration++) {
        OuterSSHEventQueue *event_queues[17];
        OuterSSHSessionPool *pools[17] = {0};
        for (unsigned i = 0; i < 17; i++) pools[i] = create_pool(&event_queues[i], i ? pools[i - 1] : NULL);
        OuterSSHSessionPoolConfiguration config = {
            .jump_host = pools[16],
            .hostname = "127.0.0.1", .hostname_length = 9,
            .username = "test", .username_length = 4, .port = 1,
            .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
                .password = "test", .password_length = 4}
        };
        OuterSSHError error = {0};
        assert(!outerssh_session_pool_create(event_queues[16], &config, &error));
        assert(error.domain != OUTERSSH_ERROR_NONE);
        assert(outerssh_session_pool_ensure_session(pools[16], 1));
        for (unsigned i = 0; i < 17; i++) assert(outerssh_session_pool_destroy(pools[i], 2));
        for (unsigned i = 0; i < 17; i++) drain_until_destroyed(event_queues[i], pools[i]);
        assert(operations == iteration + 1);
        assert(destructions == (iteration + 1) * 17);
    }
    for (unsigned iteration = 0; iteration < 30; iteration++) {
        test_shutdown_with_bridge_cleanup(false);
        test_shutdown_with_bridge_cleanup(true);
    }
    assert(destructions == 30 * 21);
    puts("PASS: cross-event-queue jump pool cancellation, depth limit, upstream-first teardown, and bridge cleanup");
}
