#include "SSHTestSupport.h"
#include "SSHSocketService.h"
#include "SSHSocketBridgeInternal.h"
#include "SSHEventQueueInternal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static OuterSSHSessionPool pool;
static OuterSSHEventQueue event_queue;
static bool events_are_pending(void);
static unsigned sent[22];
static uint32_t last_id[22];
static unsigned char last_payload[OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES + 4096];
static size_t last_payload_length;
static unsigned stopped;
static bool fail_next_allocation;
static bool fail_next_calloc;
static uint64_t test_time;
static ottime_t scheduled_deadline;
static unsigned timer_fires;
static unsigned timer_programs;

static void *service_calloc(size_t count, size_t size)
{
    if (fail_next_calloc) {
        fail_next_calloc = false;
        return NULL;
    }
    return calloc(count, size);
}

static ottime_t test_ottime(ottime_t base, int64_t delta)
{
    return (base == OTTIME_NOW ? test_time : base) + delta;
}

#if !defined(_WIN32)
static int test_clock_gettime(clockid_t clock, struct timespec *value)
{
    assert(clock == CLOCK_MONOTONIC);
    value->tv_sec = (time_t)(test_time / NSEC_PER_SEC);
    value->tv_nsec = (long)(test_time % NSEC_PER_SEC);
    return 0;
}
#endif

static void test_set_timer(otsource_t timer, ottime_t start, uint64_t interval, uint64_t leeway)
{
    assert(timer == (otsource_t)&scheduled_deadline);
    assert(interval == OTTIME_FOREVER && leeway == 100 * NSEC_PER_MSEC);
    scheduled_deadline = start;
    timer_programs++;
}

static void test_cancel_timer(otsource_t timer);
static void test_release_timer(otsource_t timer)
{
    assert(timer == (otsource_t)&scheduled_deadline);
}


static void *service_malloc(size_t size)
{
    if (fail_next_allocation) {
        fail_next_allocation = false;
        return NULL;
    }
    return malloc(size);
}

static void run_immediately(otqueue_t queue, void *context, void (*function)(void *))
{
    (void)queue;
    function(context);
}

#undef otqueue_async
#define otqueue_async run_immediately
#undef ottime
#undef otsource_set_timer
#undef otsource_cancel
#undef otsource_release
#define ottime test_ottime
#define otsource_set_timer test_set_timer
#define otsource_cancel test_cancel_timer
#define otsource_release test_release_timer
#if !defined(_WIN32)
#define clock_gettime test_clock_gettime
#endif
#define calloc service_calloc
#define malloc service_malloc
#include "../OuterSSH/SSHSocketService.c"
#undef malloc
#undef calloc
#undef clock_gettime
#undef ottime
#undef otsource_set_timer
#undef otsource_cancel
#undef otsource_release


void outersshpriv_session_pool_begin_operation(OuterSSHSessionPool *value) { value->pending_operations++; }
void outersshpriv_session_pool_end_operation(OuterSSHSessionPool *value)
{
    assert(value->pending_operations != 0);
    value->pending_operations--;
}
void outersshpriv_session_pool_finish_destroy_if_ready(OuterSSHSessionPool *value) { (void)value; }
void outersshpriv_proxy_ensure_user_bridge_executable(OuterSSHSessionPool *value,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    (void)value; (void)waiter; (void)resume; (void)context;
}
void outersshpriv_session_pool_run_when_ready(OuterSSHSessionPool *value, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context)
{
    (void)value; (void)waiter; (void)resume; (void)context;
    abort();
}
SSHReactor *outersshpriv_session_pool_ready_reactor(OuterSSHSessionPool *value,
    SSHSessionPoolSessionHandle *session, OuterSSHError *error)
{
    (void)value; (void)session; (void)error;
    abort();
}
SSHReactor *outersshpriv_session_pool_reactor_for_session(OuterSSHSessionPool *value, SSHSessionPoolSessionHandle session)
{
    (void)session;
    return (SSHReactor *)value;
}
otqueue_t outersshpriv_reactor_queue(SSHReactor *reactor) { (void)reactor; return pool._queue; }
int outersshpriv_reactor_start_socket_channel(SSHReactor *reactor, SSHReactorSocketBridgeHandle *handle,
    SSHSocketChannelCallbacks callbacks, const char *command, size_t command_length,
    const void *input, size_t input_length, uint64_t open_timeout, uint64_t ready_timeout)
{
    (void)reactor; (void)handle; (void)callbacks; (void)command; (void)command_length;
    (void)input; (void)input_length; (void)open_timeout; (void)ready_timeout;
    abort();
}
bool outersshpriv_reactor_socket_channel_send(SSHReactor *reactor, SSHReactorSocketBridgeHandle handle, HelperFrame frame)
{
    (void)reactor; (void)handle;
    assert(frame.type < 22);
    sent[frame.type]++;
    last_id[frame.type] = frame.stream_id;
    assert(frame.payload_length <= sizeof(last_payload));
    if (frame.payload_length) memcpy(last_payload, frame.payload, frame.payload_length);
    last_payload_length = frame.payload_length;
    return true;
}
void outersshpriv_reactor_stop_socket_bridge(SSHReactor *reactor, SSHReactorSocketBridgeHandle handle, bool send_eof)
{
    (void)reactor; (void)handle; (void)send_eof;
    stopped++;
}

typedef struct {
    SocketAuthorizationRequest request;
    SSHWaiter waiter;
    unsigned calls;
    bool failed;
} Completion;

static void completed(void *context, OuterSSHError error)
{
    Completion *result = context;
    result->calls++;
    result->failed = error.domain != OUTERSSH_ERROR_NONE;
    assert(result->calls == 1);
}

/* Notifications polled while delivering completions, with copied payloads. */
static OuterSSHEvent notifications[16];
static void *notification_copies[16];
static size_t notification_count;
static void *taken_copies[16];
static size_t taken_count;

/* Applies watch completions, whose tags name their Completion, and keeps
 * notifications for take_notifications. */
static void deliver(void)
{
    OuterSSHEvent event;
    while (outerssh_event_queue_poll(&event_queue, &event, 1) == 1) {
        if (event.tag != 0) {
            assert(event.type == OUTERSSH_EVENT_OPERATION_COMPLETED);
            completed((Completion *)(uintptr_t)event.tag, event.operation_completed.error);
            continue;
        }
        assert(notification_count < 16);
        void *copy = NULL;
        if (event.type == OUTERSSH_EVENT_SOCKET_AVAILABILITY) {
            copy = malloc(event.socket_availability.path_length + 1);
            assert(copy != NULL);
            memcpy(copy, event.socket_availability.path, event.socket_availability.path_length);
            event.socket_availability.path = copy;
        } else if (event.type == OUTERSSH_EVENT_ENDPOINT_NAMES && event.endpoint_names.known) {
            copy = outerssh_endpoint_records_copy(event.endpoint_names.records, event.endpoint_names.count);
            assert(copy != NULL);
            event.endpoint_names.records = copy;
        }
        notification_copies[notification_count] = copy;
        notifications[notification_count++] = event;
    }
}

/* Like outerssh_event_queue_poll, for notifications. Payloads stay valid
 * until the next call. */
static size_t take_notifications(OuterSSHEvent *events, size_t capacity)
{
    for (size_t i = 0; i < taken_count; i++) free(taken_copies[i]);
    deliver();
    taken_count = notification_count < capacity ? notification_count : capacity;
    memcpy(events, notifications, taken_count * sizeof(*events));
    memcpy(taken_copies, notification_copies, taken_count * sizeof(*taken_copies));
    notification_count -= taken_count;
    memmove(notifications, notifications + taken_count, notification_count * sizeof(*notifications));
    memmove(notification_copies, notification_copies + taken_count, notification_count * sizeof(*notification_copies));
    return taken_count;
}

static void watch_socket(const char *path, size_t length, Completion *completion)
{
    assert(outerssh_session_pool_watch_socket(&pool, path, length, (uint64_t)(uintptr_t)completion));
    deliver();
}

static void unwatch_socket(const char *path, size_t length, Completion *completion)
{
    assert(outerssh_session_pool_unwatch_socket(&pool, path, length, (uint64_t)(uintptr_t)completion));
    deliver();
}

static void reply(uint16_t type, uint32_t id, const char *bytes, size_t length)
{
    if (type == HELPER_FRAME_RESULT && length == 0 && id == last_id[HELPER_FRAME_AUTHORIZE]) {
        type = HELPER_FRAME_PREPARED;
        bytes = "\0";
        length = 1;
    }
    assert(channel_received(pool.socket_service->channel, (HelperFrame){
        .type = type, .stream_id = id, .payload = (const unsigned char *)bytes, .payload_length = length}));
}

static void test_cancel_timer(otsource_t timer)
{
    assert(timer == (otsource_t)&scheduled_deadline);
    scheduled_deadline = OTTIME_FOREVER;
    timer_cancelled(pool.socket_service);
}

static void fire_timer(void)
{
    scheduled_deadline = OTTIME_FOREVER;
    timer_fires++;
    service_deadline_reached(pool.socket_service);
    assert(scheduled_deadline > test_time);
}

static void advance_time(uint64_t duration)
{
    test_time += duration;
    if (scheduled_deadline <= test_time) fire_timer();
}

static bool path_is_authorized(OuterSSHSessionPool *value, const char *path, size_t length)
{
    SocketAuthorization *authorization = outersshpriv_socket_service_find_authorization(value, path, length);
    return authorization != NULL && authorization->pending == NULL;
}

static void authorize_path(OuterSSHSessionPool *value, const char *path, size_t length,
    SocketAuthorizationRequest *request, SSHWaiter *waiter,
    SSHCompletionHandler completion, void *context)
{
    SocketAuthorization *authorization = outersshpriv_socket_service_find_authorization(value, path, length);
    if (authorization != NULL && authorization->pending == NULL)
        completion(context, (OuterSSHError){0});
    else if (authorization != NULL)
        outersshpriv_socket_service_wait_for_authorization(authorization, waiter, completion, context);
    else
        outersshpriv_socket_service_authorize(value, path, length, request, waiter, completion, context);
}

static void reset_service(void)
{
    assert(pool.pending_operations == 0);
    pool.shutdown_requested = false;
    pool._endpointNamesObserved = false;
    outersshpriv_session_pool_dispose_events(&pool);
    outersshpriv_event_queue_dispose_events(&event_queue);
    for (size_t i = 0; i < notification_count; i++) free(notification_copies[i]);
    notification_count = 0;
    pool._event_queue = &event_queue;
    pool.socket_service = calloc(1, sizeof(*pool.socket_service));
    assert(pool.socket_service != NULL);
    pool.socket_service->pool = &pool;
    pool.socket_service->timer = (otsource_t)&scheduled_deadline;
    outersshpriv_session_pool_begin_operation(&pool);
    test_time = 100 * NSEC_PER_SEC;
    scheduled_deadline = OTTIME_FOREVER;
    timer_fires = timer_programs = 0;
    memset(sent, 0, sizeof(sent));
    memset(last_id, 0, sizeof(last_id));
    stopped = 0;
}

static void close_service(void)
{
    pool.shutdown_requested = true;
    outersshpriv_socket_service_stop(&pool);
    if (pool.socket_service->channel != NULL) finish_channel(pool.socket_service->channel);
    assert(pool.pending_operations == 0);
    outersshpriv_socket_service_dispose(&pool);
    pool.socket_service = NULL;
}

static void test_independent_lifetimes(void)
{
    reset_service();
    Completion authorization = {0}, watch = {0}, unwatch = {0};
    static const char path[] = "/tmp/socket";
    authorize_path(&pool, path, sizeof(path) - 1, &authorization.request, &authorization.waiter, completed, &authorization);
    watch_socket(path, sizeof(path) - 1, &watch);
    assert(sent[HELPER_FRAME_AUTHORIZE] == 0 && sent[HELPER_FRAME_WATCH] == 0);
    channel_ready(pool.socket_service->channel);
    assert(sent[HELPER_FRAME_AUTHORIZE] == 1 && sent[HELPER_FRAME_WATCH] == 1);
    uint32_t watch_id = last_id[HELPER_FRAME_WATCH];
    reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_AUTHORIZE], NULL, 0);
    deliver();
    assert(authorization.calls == 1 && !authorization.failed && watch.calls == 0);
    reply(HELPER_FRAME_RESULT, watch_id, NULL, 0);
    reply(HELPER_FRAME_SOCKET_STATE, watch_id, "\1", 1);
    deliver();
    assert(watch.calls == 1 && !watch.failed);
    assert(pool.socket_service->replies == NULL);

    Completion interrupted = {0};
    static const char other_path[] = "/tmp/other-socket";
    authorize_path(&pool, other_path, sizeof(other_path) - 1, &interrupted.request, &interrupted.waiter, completed, &interrupted);
    pool.socket_service->channel->error = outerssh_proxy_closing_error();
    finish_channel(pool.socket_service->channel);
    deliver();
    assert(interrupted.calls == 1 && interrupted.failed);
    assert(pool.socket_service->watches != NULL);
    advance_time(5 * NSEC_PER_SEC);
    channel_ready(pool.socket_service->channel);
    assert(sent[HELPER_FRAME_WATCH] == 2 && sent[HELPER_FRAME_AUTHORIZE] == 2);
    reply(HELPER_FRAME_RESULT, watch_id, NULL, 0);
    deliver();
    assert(watch.calls == 1);
    unwatch_socket(path, sizeof(path) - 1, &unwatch);
    deliver();
    assert(unwatch.calls == 1 && !unwatch.failed && pool.socket_service->watches == NULL);
    assert(sent[HELPER_FRAME_UNWATCH] == 1);
    close_service();
}

static void test_authorization_cache(void)
{
    static const char path[] = "/tmp/socket";
    for (unsigned lifetime = 0; lifetime < 2; lifetime++) {
        reset_service();
        assert(!path_is_authorized(&pool, path, sizeof(path) - 1));
        assert(pool.socket_service->channel == NULL);
        Completion requests[12] = {0};
        for (size_t i = 0; i < 12; i++) {
            if (i == 6) channel_ready(pool.socket_service->channel);
            authorize_path(&pool, path, sizeof(path) - 1, &requests[i].request, &requests[i].waiter, completed, &requests[i]);
            deliver();
            assert(requests[i].calls == 0);
            assert(!path_is_authorized(&pool, path, sizeof(path) - 1));
        }
        assert(sent[HELPER_FRAME_AUTHORIZE] == 1);
        SocketAuthorization *entry = outersshpriv_socket_service_find_authorization(&pool, path, sizeof(path) - 1);
        assert(entry != NULL && entry->pending != NULL);
        reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_AUTHORIZE], NULL, 0);
        assert(outersshpriv_socket_service_find_authorization(&pool, path, sizeof(path) - 1) == entry && entry->pending == NULL);
        for (size_t i = 0; i < 12; i++) assert(requests[i].calls == 1 && !requests[i].failed);
        assert(path_is_authorized(&pool, path, sizeof(path) - 1));
        assert(!path_is_authorized(&pool, path, sizeof(path) - 2));
        static const char other_path[] = "/tmp/soxket";
        assert(!path_is_authorized(&pool, other_path, sizeof(other_path) - 1));
        pool._disconnecting = true;
        assert(!path_is_authorized(&pool, path, sizeof(path) - 1));
        pool._disconnecting = false;

        for (unsigned connected = 0; connected < 2; connected++) {
            if (connected == 0) finish_channel(pool.socket_service->channel);
            else {
                start_service(pool.socket_service);
                channel_ready(pool.socket_service->channel);
            }
            Completion cached = {0};
            assert(path_is_authorized(&pool, path, sizeof(path) - 1));
            authorize_path(&pool, path, sizeof(path) - 1, &cached.request, &cached.waiter, completed, &cached);
            deliver();
            assert(cached.calls == 1 && !cached.failed);
            assert(sent[HELPER_FRAME_AUTHORIZE] == 1);
            assert(connected || pool.socket_service->channel == NULL);
        }
        pool.socket_service->next_id = UINT32_MAX;
        Completion cached = {0};
        authorize_path(&pool, path, sizeof(path) - 1, &cached.request, &cached.waiter, completed, &cached);
        deliver();
        assert(cached.calls == 1 && !cached.failed);
        pool.shutdown_requested = true;
        assert(!path_is_authorized(&pool, path, sizeof(path) - 1));
        Completion closing = {0};
        authorize_path(&pool, path, sizeof(path) - 1, &closing.request, &closing.waiter, completed, &closing);
        deliver();
        assert(closing.calls == 1 && closing.failed);
        close_service();
        assert(!path_is_authorized(&pool, path, sizeof(path) - 1));
        assert(pool.socket_service == NULL);
    }
}

typedef struct {
    Completion first;
    Completion repeated;
    const char *path;
    size_t path_length;
} RepeatedAuthorization;

static void authorize_again(void *context, OuterSSHError error)
{
    RepeatedAuthorization *request = context;
    completed(&request->first, error);
    authorize_path(&pool, request->path, request->path_length, &request->repeated.request, &request->repeated.waiter, completed, &request->repeated);
}

static void test_authorization_failure_and_reentrancy(void)
{
    for (unsigned fail = 0; fail < 2; fail++) {
        reset_service();
        static const char path[] = "/tmp/socket";
        RepeatedAuthorization request = {.path = path, .path_length = sizeof(path) - 1};
        Completion waiter = {0};
        authorize_path(&pool, path, sizeof(path) - 1, &request.first.request, &request.first.waiter, authorize_again, &request);
        authorize_path(&pool, path, sizeof(path) - 1, &waiter.request, &waiter.waiter, completed, &waiter);
        channel_ready(pool.socket_service->channel);
        uint32_t id = last_id[HELPER_FRAME_AUTHORIZE];
        static const char denied[] = "socket is not allowed";
        reply(HELPER_FRAME_RESULT, id, fail ? denied : NULL, fail ? sizeof(denied) - 1 : 0);
        deliver();
        assert(request.first.calls == 1 && request.first.failed == (fail != 0));
        deliver();
        assert(waiter.calls == 1 && waiter.failed == (fail != 0));
        if (fail) {
            assert(!path_is_authorized(&pool, path, sizeof(path) - 1));
            deliver();
            assert(request.repeated.calls == 0 && sent[HELPER_FRAME_AUTHORIZE] == 2);
            assert(last_id[HELPER_FRAME_AUTHORIZE] != id);
            reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_AUTHORIZE], NULL, 0);
        } else assert(sent[HELPER_FRAME_AUTHORIZE] == 1);
        deliver();
        assert(request.repeated.calls == 1 && !request.repeated.failed);
        close_service();
    }
}

static void test_join_without_allocation(void)
{
    reset_service();
    static const char path[] = "/tmp/socket";
    Completion first = {0}, second = {0}, last = {0};
    authorize_path(&pool, path, sizeof(path) - 1, &first.request, &first.waiter, completed, &first);
    fail_next_allocation = true;
    authorize_path(&pool, path, sizeof(path) - 1, &second.request, &second.waiter, completed, &second);
    authorize_path(&pool, path, sizeof(path) - 1, &last.request, &last.waiter, completed, &last);
    deliver();
    assert(fail_next_allocation && first.calls == 0 && second.calls == 0 && last.calls == 0);
    fail_next_allocation = false;
    channel_ready(pool.socket_service->channel);
    assert(sent[HELPER_FRAME_AUTHORIZE] == 1);
    reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_AUTHORIZE], NULL, 0);
    deliver();
    assert(first.calls == 1 && !first.failed && second.calls == 1 && !second.failed);
    deliver();
    assert(last.calls == 1 && !last.failed && path_is_authorized(&pool, path, sizeof(path) - 1));
    close_service();
}

typedef struct {
    SocketAuthorizationRequest request;
    SSHWaiter waiter;
    Completion *result;
} AuthorizationOwner;

static void authorization_owner_finished(void *context, OuterSSHError error)
{
    AuthorizationOwner *owner = context;
    assert(owner->waiter.next == NULL);
    completed(owner->result, error);
    free(owner);
}

static void test_completion_frees_waiter_owner(void)
{
    static const char path[] = "/tmp/socket";
    for (unsigned scenario = 0; scenario < 4; scenario++) {
        reset_service();
        Completion results[3] = {0};
        unsigned count = scenario == 3 ? 1 : 3;
        for (unsigned i = 0; i < count; i++) {
            AuthorizationOwner *owner = calloc(1, sizeof(*owner));
            assert(owner != NULL);
            owner->result = &results[i];
            fail_next_allocation = scenario == 3;
            authorize_path(&pool, path, sizeof(path) - 1, &owner->request, &owner->waiter,
                authorization_owner_finished, owner);
        }
        if (scenario < 2) {
            channel_ready(pool.socket_service->channel);
            static const char denied[] = "socket is not allowed";
            reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_AUTHORIZE],
                scenario == 1 ? denied : NULL, scenario == 1 ? sizeof(denied) - 1 : 0);
        }
        close_service();
        assert(!fail_next_allocation);
        deliver();
        for (unsigned i = 0; i < count; i++)
            assert(results[i].calls == 1 && results[i].failed == (scenario != 0));
    }
}

static void test_cancel_before_ready(void)
{
    reset_service();
    Completion first = {0}, second = {0}, authorization = {0}, unwatch = {0};
    static const char path[] = "/tmp/socket";
    watch_socket(path, sizeof(path) - 1, &first);
    authorize_path(&pool, path, sizeof(path) - 1, &authorization.request, &authorization.waiter, completed, &authorization);
    watch_socket(path, sizeof(path) - 1, &second);
    deliver();
    assert(first.calls == 1 && first.failed);
    unwatch_socket(path, sizeof(path) - 1, &unwatch);
    deliver();
    assert(second.calls == 1 && second.failed && unwatch.calls == 1);
    channel_ready(pool.socket_service->channel);
    assert(sent[HELPER_FRAME_WATCH] == 0 && sent[HELPER_FRAME_AUTHORIZE] == 1);
    reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_AUTHORIZE], NULL, 0);
    deliver();
    assert(authorization.calls == 1 && !authorization.failed);
    close_service();
}

static void test_replace_before_reply(void)
{
    reset_service();
    Completion first = {0}, second = {0};
    static const char path[] = "/tmp/socket";
    watch_socket(path, sizeof(path) - 1, &first);
    channel_ready(pool.socket_service->channel);
    uint32_t old_id = last_id[HELPER_FRAME_WATCH];
    watch_socket(path, sizeof(path) - 1, &second);
    uint32_t new_id = last_id[HELPER_FRAME_WATCH];
    deliver();
    assert(first.calls == 1 && first.failed && old_id != new_id);
    reply(HELPER_FRAME_RESULT, old_id, NULL, 0);
    reply(HELPER_FRAME_SOCKET_STATE, old_id, "\1", 1);
    deliver();
    assert(second.calls == 0);
    reply(HELPER_FRAME_RESULT, new_id, NULL, 0);
    deliver();
    assert(second.calls == 1 && !second.failed);
    close_service();
}

static void test_shutdown_and_failure(void)
{
    for (int ready = 0; ready < 2; ready++) {
        reset_service();
        Completion authorization = {0}, waiter = {0}, watch = {0};
        static const char path[] = "/tmp/socket";
        authorize_path(&pool, path, sizeof(path) - 1, &authorization.request, &authorization.waiter, completed, &authorization);
        authorize_path(&pool, path, sizeof(path) - 1, &waiter.request, &waiter.waiter, completed, &waiter);
        watch_socket(path, sizeof(path) - 1, &watch);
        if (ready) channel_ready(pool.socket_service->channel);
        close_service();
        deliver();
        assert(authorization.calls == 1 && authorization.failed && watch.calls == 1 && watch.failed);
        deliver();
        assert(waiter.calls == 1 && waiter.failed);

        reset_service();
        authorization = (Completion){0};
        waiter = (Completion){0};
        watch = (Completion){0};
        authorize_path(&pool, path, sizeof(path) - 1, &authorization.request, &authorization.waiter, completed, &authorization);
        authorize_path(&pool, path, sizeof(path) - 1, &waiter.request, &waiter.waiter, completed, &waiter);
        watch_socket(path, sizeof(path) - 1, &watch);
        if (ready) channel_ready(pool.socket_service->channel);
        pool.socket_service->channel->error = outerssh_proxy_closing_error();
        finish_channel(pool.socket_service->channel);
        deliver();
        assert(authorization.calls == 1 && authorization.failed && watch.calls == 1 && watch.failed);
        deliver();
        assert(waiter.calls == 1 && waiter.failed);
        assert(pool.socket_service->watches == NULL);
        close_service();
    }
}

static size_t poll_availability(OuterSSHEvent *event)
{
    OuterSSHEvent events[4];
    size_t count = take_notifications(events, 4);
    assert(count <= 1);
    if (count == 1) {
        assert(events[0].type == OUTERSSH_EVENT_SOCKET_AVAILABILITY);
        *event = events[0];
    }
    return count;
}

static void test_immediate_availability(void)
{
    reset_service();
    Completion watch = {0}, unwatch = {0};
    OuterSSHEvent event;
    static const char path[] = "/tmp/socket";
    watch_socket(path, sizeof(path) - 1, &watch);
    channel_ready(pool.socket_service->channel);
    uint32_t id = last_id[HELPER_FRAME_WATCH];
    reply(HELPER_FRAME_RESULT, id, NULL, 0);
    reply(HELPER_FRAME_SOCKET_STATE, id, "\1", 1);
    assert(poll_availability(&event) == 1 && event.socket_availability.available);
    assert(event.socket_availability.path_length == sizeof(path) - 1);
    assert(memcmp(event.socket_availability.path, path, sizeof(path) - 1) == 0);
    reply(HELPER_FRAME_SOCKET_STATE, id, "\0", 1);
    reply(HELPER_FRAME_SOCKET_STATE, id, "\1", 1);
    OuterSSHEvent events[4];
    assert(take_notifications(events, 4) == 2);
    assert(!events[0].socket_availability.available && events[1].socket_availability.available);
    reply(HELPER_FRAME_SOCKET_STATE, id, "\2", 1);
    assert(poll_availability(&event) == 0);
    unwatch_socket(path, sizeof(path) - 1, &unwatch);
    reply(HELPER_FRAME_SOCKET_STATE, id, "\1", 1);
    assert(poll_availability(&event) == 0);
    close_service();
    outersshpriv_session_pool_dispose_events(&pool);
}

static void test_deadline_timers(void)
{
    reset_service();
    advance_time(100 * NSEC_PER_SEC);
    assert(timer_fires == 0 && scheduled_deadline == OTTIME_FOREVER);
    static const char path[] = "/tmp/socket";
    Completion first = {0}, second = {0};
    authorize_path(&pool, path, sizeof(path) - 1, &first.request, &first.waiter, completed, &first);
    assert(scheduled_deadline == OTTIME_FOREVER);
    channel_ready(pool.socket_service->channel);
    uint32_t first_id = last_id[HELPER_FRAME_AUTHORIZE];
    uint64_t first_deadline = test_time + 30 * NSEC_PER_SEC;
    assert(scheduled_deadline == first_deadline);
    advance_time(10 * NSEC_PER_SEC);
    unsigned programs = timer_programs;
    static const char other[] = "/tmp/other";
    authorize_path(&pool, other, sizeof(other) - 1, &second.request, &second.waiter, completed, &second);
    uint32_t second_id = last_id[HELPER_FRAME_AUTHORIZE];
    assert(scheduled_deadline == first_deadline);
    reply(HELPER_FRAME_PONG, 0, NULL, 0);
    assert(scheduled_deadline == first_deadline);
    assert(timer_programs == programs);
    reply(HELPER_FRAME_RESULT, first_id, NULL, 0);
    assert(scheduled_deadline == test_time + 30 * NSEC_PER_SEC);
    reply(HELPER_FRAME_RESULT, second_id, NULL, 0);
    assert(scheduled_deadline == test_time + 45 * NSEC_PER_SEC);
    for (unsigned i = 0; i < 10; i++) {
        advance_time(15 * NSEC_PER_SEC);
        reply(HELPER_FRAME_PONG, 0, NULL, 0);
        assert(scheduled_deadline == test_time + 45 * NSEC_PER_SEC);
    }
    assert(timer_fires == 0 && stopped == 0);
    advance_time(44 * NSEC_PER_SEC);
    assert(timer_fires == 0);
    advance_time(NSEC_PER_SEC);
    assert(timer_fires == 1 && stopped == 1 && scheduled_deadline == OTTIME_FOREVER);
    finish_channel(pool.socket_service->channel);
    advance_time(100 * NSEC_PER_SEC);
    assert(timer_fires == 1 && pool.socket_service->channel == NULL);
    close_service();
}

static void test_delayed_request_timeout(void)
{
    reset_service();
    Completion request = {0};
    static const char path[] = "/tmp/socket";
    authorize_path(&pool, path, sizeof(path) - 1, &request.request, &request.waiter, completed, &request);
    channel_ready(pool.socket_service->channel);
    advance_time(15 * NSEC_PER_SEC);
    reply(HELPER_FRAME_PONG, 0, NULL, 0);
    advance_time(20 * NSEC_PER_SEC);
    assert(timer_fires == 1 && stopped == 1 && pool.socket_service->stopping_channel);
    assert(scheduled_deadline == OTTIME_FOREVER);
    close_service();
    deliver();
    assert(request.calls == 1 && request.failed);
}

static void test_restart_timer_cancelled(void)
{
    reset_service();
    static const char path[] = "/tmp/socket";
    Completion watch = {0}, unwatch = {0};
    watch_socket(path, sizeof(path) - 1, &watch);
    channel_ready(pool.socket_service->channel);
    reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_WATCH], NULL, 0);
    assert(scheduled_deadline == test_time + 45 * NSEC_PER_SEC);
    pool.socket_service->channel->error = outerssh_proxy_closing_error();
    finish_channel(pool.socket_service->channel);
    assert(scheduled_deadline == test_time + 5 * NSEC_PER_SEC);
    unwatch_socket(path, sizeof(path) - 1, &unwatch);
    assert(scheduled_deadline == OTTIME_FOREVER);
    advance_time(100 * NSEC_PER_SEC);
    assert(timer_fires == 0 && pool.socket_service->channel == NULL);
    close_service();
}

static void test_stop_allocation_failure(void)
{
    reset_service();
    Completion request = {0};
    static const char path[] = "/tmp/socket";
    authorize_path(&pool, path, sizeof(path) - 1, &request.request, &request.waiter, completed, &request);
    channel_ready(pool.socket_service->channel);
    fail_next_calloc = true;
    advance_time(30 * NSEC_PER_SEC);
    assert(!fail_next_calloc && timer_fires == 1 && stopped == 0);
    assert(scheduled_deadline == test_time + NSEC_PER_SEC);
    advance_time(NSEC_PER_SEC);
    assert(timer_fires == 2 && stopped == 1 && scheduled_deadline == OTTIME_FOREVER);
    close_service();
}

static void test_cancel_request_deadline(void)
{
    reset_service();
    static const char path[] = "/tmp/socket";
    static const char other[] = "/tmp/other";
    Completion watch = {0}, unwatch = {0}, request = {0};
    watch_socket(path, sizeof(path) - 1, &watch);
    channel_ready(pool.socket_service->channel);
    uint64_t first_deadline = scheduled_deadline;
    advance_time(10 * NSEC_PER_SEC);
    authorize_path(&pool, other, sizeof(other) - 1, &request.request, &request.waiter, completed, &request);
    assert(scheduled_deadline == first_deadline);
    unwatch_socket(path, sizeof(path) - 1, &unwatch);
    deliver();
    assert(watch.calls == 1 && watch.failed && unwatch.calls == 1);
    assert(scheduled_deadline == test_time + 30 * NSEC_PER_SEC);
    fire_timer();
    assert(stopped == 0 && scheduled_deadline == test_time + 30 * NSEC_PER_SEC);
    close_service();
    deliver();
    assert(scheduled_deadline == OTTIME_FOREVER && request.calls == 1 && request.failed);
}

static void test_prepared_modes(void)
{
    for (unsigned mode = 0; mode < 3; mode++) {
        reset_service();
        Completion request = {0};
        const char path[] = "/arbitrary/service";
        authorize_path(&pool, path, sizeof(path) - 1, &request.request, &request.waiter, completed, &request);
        channel_ready(pool.socket_service->channel);
        char byte = (char)mode;
        reply(HELPER_FRAME_PREPARED, last_id[HELPER_FRAME_AUTHORIZE], &byte, 1);
        SocketAuthorization *entry = outersshpriv_socket_service_find_authorization(&pool, path, sizeof(path) - 1);
        deliver();
        assert(request.calls == 1 && !request.failed && entry->connection_mode == (HelperConnectionMode)mode);
        assert(!entry->session_owned && !entry->root_owned && entry->owner_length == 0);
        close_service();
        const struct { unsigned char flags; const char *owner; } owners[] = {
            {HELPER_PREPARED_SESSION_OWNED, "1000"}, {HELPER_PREPARED_ROOT_OWNED, "0"},
            {0, "S-1-5-21-1-2-3-1001"},
        };
        for (size_t index = 0; index < sizeof(owners) / sizeof(owners[0]); index++) {
            reset_service();
            Completion owned = {0};
            authorize_path(&pool, path, sizeof(path) - 1, &owned.request, &owned.waiter, completed, &owned);
            channel_ready(pool.socket_service->channel);
            char prepared[64] = {(char)(mode | owners[index].flags)};
            size_t length = strlen(owners[index].owner);
            memcpy(prepared + 1, owners[index].owner, length);
            reply(HELPER_FRAME_PREPARED, last_id[HELPER_FRAME_AUTHORIZE], prepared, length + 1);
            entry = outersshpriv_socket_service_find_authorization(&pool, path, sizeof(path) - 1);
            deliver();
            assert(owned.calls == 1 && !owned.failed && entry->connection_mode == (HelperConnectionMode)mode);
            assert(entry->session_owned == ((owners[index].flags & HELPER_PREPARED_SESSION_OWNED) != 0));
            assert(entry->root_owned == ((owners[index].flags & HELPER_PREPARED_ROOT_OWNED) != 0));
            assert(entry->owner_length == length && memcmp(entry->owner, owners[index].owner, length) == 0);
            close_service();
        }
    }
    reset_service();
    Completion request = {0};
    authorize_path(&pool, "/socket", 7, &request.request, &request.waiter, completed, &request);
    channel_ready(pool.socket_service->channel);
    uint32_t id = last_id[HELPER_FRAME_AUTHORIZE];
    assert(!channel_received(pool.socket_service->channel, (HelperFrame){
        .type = HELPER_FRAME_PREPARED, .stream_id = id, .payload_length = 0}));
    const unsigned char invalid[][3] = {{3}, {3 | HELPER_PREPARED_ROOT_OWNED}, {0x20}, {0x04}, {1, '/', '1'}, {1, '1', ' '}};
    for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
        assert(!channel_received(pool.socket_service->channel, (HelperFrame){
            .type = HELPER_FRAME_PREPARED, .stream_id = id, .payload = invalid[index],
            .payload_length = invalid[index][1] ? 3 : 1}));
    }
    unsigned char long_owner[HELPER_OWNER_CAPACITY + 1];
    memset(long_owner, '1', sizeof(long_owner));
    long_owner[0] = 0;
    assert(!channel_received(pool.socket_service->channel, (HelperFrame){
        .type = HELPER_FRAME_PREPARED, .stream_id = id, .payload = long_owner, .payload_length = sizeof(long_owner)}));
    assert(channel_received(pool.socket_service->channel, (HelperFrame){
        .type = HELPER_FRAME_RESULT, .stream_id = id, .payload_length = 0}));
    deliver();
    assert(request.calls == 1 && request.failed);
    close_service();
}

static size_t poll_endpoint_names(OuterSSHEvent *event)
{
    OuterSSHEvent events[4];
    size_t count = take_notifications(events, 4);
    assert(count <= 1);
    if (count == 1) {
        assert(events[0].type == OUTERSSH_EVENT_ENDPOINT_NAMES);
        *event = events[0];
    }
    return count;
}

/* Reports whether events are pending. */
static bool events_are_pending(void)
{
    otlock_lock(&event_queue.event_lock);
    bool pending = event_queue.event_head != NULL;
    otlock_unlock(&event_queue.event_lock);
    return pending;
}

static void test_endpoint_names(void) {
    reset_service();
    assert(!events_are_pending());
    start_observing_endpoint_names(&pool);
    assert(pool.socket_service->channel != NULL);
    OuterSSHEvent event;
    assert(events_are_pending());
    assert(poll_endpoint_names(&event) == 1 && !event.endpoint_names.known);
    assert(!events_are_pending());
    channel_ready(pool.socket_service->channel);
    const char snapshot[] = "user\0outerssh-endpoints-v2\nunix /test\n\nFiles\n\0";
    reply(HELPER_FRAME_ENDPOINT_NAMES, 0, snapshot, sizeof(snapshot) - 1);
    assert(events_are_pending());
    assert(poll_endpoint_names(&event) == 1 && event.endpoint_names.known);
    assert(event.endpoint_names.count == 1);
    const OuterSSHEndpointRecord *record = &event.endpoint_names.records[0];
    assert(!strcmp(record->transport, "unix") && !strcmp(record->address, "/test") && record->port == 0);
    assert(!strcmp(record->name.user, "user") && !strcmp(record->name.container, "") && !strcmp(record->name.app, "Files"));
    assert(poll_endpoint_names(&event) == 0 && !events_are_pending());
    reply(HELPER_FRAME_ENDPOINT_NAMES_CHANGED, 0, NULL, 0);
    reply(HELPER_FRAME_ENDPOINT_NAMES, 0, snapshot, sizeof(snapshot) - 1);
    assert(poll_endpoint_names(&event) == 1 && event.endpoint_names.known);
    assert(poll_endpoint_names(&event) == 0);
    reply(HELPER_FRAME_ENDPOINT_NAMES_CHANGED, 0, NULL, 0);
    assert(poll_endpoint_names(&event) == 1 && !event.endpoint_names.known && event.endpoint_names.records == NULL && event.endpoint_names.count == 0);
    assert(sent[HELPER_FRAME_GET_ENDPOINT_NAMES] == 0);
    pool.socket_service->channel->error = outerssh_proxy_closing_error();
    finish_channel(pool.socket_service->channel);
    advance_time(5 * NSEC_PER_SEC);
    assert(pool.socket_service->channel != NULL);
    close_service();
    outersshpriv_session_pool_dispose_events(&pool);
}

static OuterSSHEvent poll_completion(uint64_t tag, void **copy)
{
    OuterSSHEvent event;
    assert(outerssh_event_queue_poll(&event_queue, &event, 1) == 1 && event.tag == tag);
    *copy = NULL;
    if (event.type == OUTERSSH_EVENT_ENDPOINT_ICON_RECEIVED && event.endpoint_icon_received.found) {
        *copy = malloc(event.endpoint_icon_received.length);
        assert(*copy != NULL);
        memcpy(*copy, event.endpoint_icon_received.png, event.endpoint_icon_received.length);
        event.endpoint_icon_received.png = *copy;
    }
    return event;
}

static void test_endpoint_icons(void)
{
    static const unsigned char png[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n',
        0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89,
        0, 0, 0, 1, 'I', 'D', 'A', 'T', 'x', 0x76, 0xe6, 0x84, 0xe6,
        0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82};
    assert(outerssh_endpoint_icon_is_valid(png, sizeof(png)));
    static const char path[] = "/run/user/1000/app";
    reset_service();
    assert(!outerssh_session_pool_get_endpoint_icon(&pool, "unix", "relative", 8, 0, 1));
    assert(!outerssh_session_pool_get_endpoint_icon(&pool, "tcp", "localhost", 9, 0, 1));
    assert(!outerssh_session_pool_store_endpoint_icon(&pool, "unix", path, sizeof(path) - 1, 0, png, sizeof(png) - 1, 1));
    assert(!events_are_pending());

    assert(outerssh_session_pool_get_endpoint_icon(&pool, "tcp", "LocalHost", 9, 6006, 10));
    assert(pool.socket_service->channel != NULL && sent[HELPER_FRAME_GET_ENDPOINT_ICON] == 0);
    channel_ready(pool.socket_service->channel);
    assert(sent[HELPER_FRAME_GET_ENDPOINT_ICON] == 1);
    assert(last_payload_length == 18 && !memcmp(last_payload, "tcp localhost 6006", 18));
    uint32_t id = last_id[HELPER_FRAME_GET_ENDPOINT_ICON];
    reply(HELPER_FRAME_ENDPOINT_ICON, id, (const char *)png, sizeof(png));
    void *copy;
    OuterSSHEvent event = poll_completion(10, &copy);
    assert(event.type == OUTERSSH_EVENT_ENDPOINT_ICON_RECEIVED && event.endpoint_icon_received.error.domain == OUTERSSH_ERROR_NONE);
    assert(event.endpoint_icon_received.found && event.endpoint_icon_received.length == sizeof(png));
    assert(!memcmp(event.endpoint_icon_received.png, png, sizeof(png)));
    free(copy);

    assert(outerssh_session_pool_get_endpoint_icon(&pool, "unix", path, sizeof(path) - 1, 0, 11));
    assert(last_payload_length == sizeof(path) + 4 && !memcmp(last_payload, "unix /run/user/1000/app", sizeof(path) + 4));
    reply(HELPER_FRAME_ENDPOINT_ICON, last_id[HELPER_FRAME_GET_ENDPOINT_ICON], NULL, 0);
    event = poll_completion(11, &copy);
    assert(event.endpoint_icon_received.error.domain == OUTERSSH_ERROR_NONE && !event.endpoint_icon_received.found);
    assert(event.endpoint_icon_received.png == NULL && event.endpoint_icon_received.length == 0);

    assert(outerssh_session_pool_get_endpoint_icon(&pool, "unix", path, sizeof(path) - 1, 0, 12));
    reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_GET_ENDPOINT_ICON], "Unsafe", 6);
    event = poll_completion(12, &copy);
    assert(event.endpoint_icon_received.error.domain != OUTERSSH_ERROR_NONE && !event.endpoint_icon_received.found);
    assert(event.endpoint_icon_received.error.message_length == 6);

    assert(outerssh_session_pool_get_endpoint_icon(&pool, "unix", path, sizeof(path) - 1, 0, 13));
    reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_GET_ENDPOINT_ICON], NULL, 0);
    event = poll_completion(13, &copy);
    assert(event.endpoint_icon_received.error.domain != OUTERSSH_ERROR_NONE);

    assert(outerssh_session_pool_store_endpoint_icon(&pool, "pipe", "\\\\.\\pipe\\App", 12, 0, png, sizeof(png), 14));
    assert(sent[HELPER_FRAME_STORE_ENDPOINT_ICON] == 1);
    assert(last_payload_length == 18 + sizeof(png) && !memcmp(last_payload, "pipe \\\\.\\pipe\\app", 18));
    assert(!memcmp(last_payload + 18, png, sizeof(png)));
    id = last_id[HELPER_FRAME_STORE_ENDPOINT_ICON];
    reply(HELPER_FRAME_ENDPOINT_ICON, id, (const char *)png, sizeof(png));
    event = poll_completion(14, &copy);
    assert(event.type == OUTERSSH_EVENT_OPERATION_COMPLETED && event.operation_completed.error.domain != OUTERSSH_ERROR_NONE);

    assert(outerssh_session_pool_store_endpoint_icon(&pool, "unix", path, sizeof(path) - 1, 0, png, sizeof(png), 15));
    reply(HELPER_FRAME_RESULT, last_id[HELPER_FRAME_STORE_ENDPOINT_ICON], NULL, 0);
    event = poll_completion(15, &copy);
    assert(event.type == OUTERSSH_EVENT_OPERATION_COMPLETED && event.operation_completed.error.domain == OUTERSSH_ERROR_NONE);

    assert(!channel_received(pool.socket_service->channel, (HelperFrame){
        .type = HELPER_FRAME_ENDPOINT_ICON, .stream_id = 0}));
    assert(!channel_received(pool.socket_service->channel, (HelperFrame){
        .type = HELPER_FRAME_ENDPOINT_ICON, .stream_id = 99, .payload = last_payload,
        .payload_length = OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES + 1}));

    assert(outerssh_session_pool_get_endpoint_icon(&pool, "unix", path, sizeof(path) - 1, 0, 16));
    assert(!events_are_pending());
    close_service();
    event = poll_completion(16, &copy);
    assert(event.type == OUTERSSH_EVENT_ENDPOINT_ICON_RECEIVED && event.endpoint_icon_received.error.domain != OUTERSSH_ERROR_NONE);
    assert(!events_are_pending());
    outersshpriv_session_pool_dispose_events(&pool);
}

static void run_tests(void *context)
{
    (void)context;
    test_endpoint_icons();
    test_endpoint_names();
    test_prepared_modes();
    test_deadline_timers();
    test_delayed_request_timeout();
    test_restart_timer_cancelled();
    test_stop_allocation_failure();
    test_cancel_request_deadline();
    test_independent_lifetimes();
    test_authorization_cache();
    test_authorization_failure_and_reentrancy();
    test_join_without_allocation();
    test_completion_frees_waiter_owner();
    test_cancel_before_ready();
    test_replace_before_reply();
    test_shutdown_and_failure();
    test_immediate_availability();
}

int main(void)
{
    pool._queue = ssh_test_control_queue_create("socket-service-test");
    ssh_test_sync(pool._queue, NULL, run_tests);
    otqueue_release(pool._queue);
    puts("Socket service flow tests passed.");
    return 0;
}
