#include "SSHSocketService.h"
#include "SSHProxyErrorInternal.h"
#include "SSHEventsInternal.h"
#include "SSHSocketBridgeInternal.h"
#include "SocketBridgeCommands.h"
#include "SSHProxyAddress.h"
#include "include/OuterSSH/SSHEndpointNames.h"
#include "SSHEndpointRecord.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct SocketWatch {
    struct SocketWatch *next;
    SocketServiceWork work;
    SSHSocketService *service;
    bool sent;
    bool cancelled;
    /* The last availability reported to the application. */
    bool reported_available;
    /* Pending until the first subscription result. */
    SSHPoolEvent *reply;
    size_t path_length;
    char path[];
} SocketWatch;

typedef struct {
    SSHSocketService *service;
    SSHSessionPoolSessionHandle session;
    SSHReactor *reactor;
    SSHReactorSocketBridgeHandle handle;
    char *command;
    size_t command_length;
    OuterSSHError error;
    char *error_storage;
    SSHWaiter waiter;
} SocketServiceChannel;

struct SSHSocketService {
    OuterSSHSessionPool *pool;
    SocketServiceWork *ready_head;
    SocketServiceWork *ready_tail;
    SocketServiceWork *replies;
    SocketWatch *watches;
    SocketAuthorization **authorizations;
    size_t authorization_count;
    size_t authorization_capacity;
    uint32_t next_id;
    uint64_t restart_deadline;
    uint64_t silence_deadline;
    uint64_t timer_deadline;
    OuterSSHEndpointRecord *endpoint_records;
    size_t endpoint_record_count;
    bool endpoint_names_valid;
    bool ready;
    bool stopping_channel;
    otsource_t timer;
    SocketServiceChannel *channel;
};

typedef struct {
    SocketServiceChannel *channel;
    HelperFrame frame;
    OuterSSHEndpointRecord *endpoint_records;
    size_t endpoint_record_count;
    unsigned char bytes[];
} SocketServiceMessage;

typedef struct {
    SSHReactor *reactor;
    SSHReactorSocketBridgeHandle handle;
    HelperFrame frame;
    unsigned char bytes[];
} SocketServiceSend;

typedef struct {
    OuterSSHSessionPool *pool;
    SSHPoolEvent *reply;
    size_t path_length;
    char path[];
} SocketWatchSubmission;

static void authorization_service_ready(void *context, OuterSSHError error);
static void authorization_finished(void *context, OuterSSHError error);
static void run_when_ready(SSHSocketService *service, SocketServiceWork *work,
    SSHCompletionHandler completion, void *context);
static SSHSocketService *get_service(OuterSSHSessionPool *pool);
static void start_service(SSHSocketService *service);
static void executable_ready(void *context, OuterSSHError error);
static void session_ready(void *context, OuterSSHError error);
static void start_channel(void *context);
static void channel_completed(void *context, SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result, uint32_t reason, const void *detail, size_t length);
static void channel_ready(void *context);
static void send_request(SSHSocketService *service, SocketServiceWork *work,
    HelperFrame frame, SSHCompletionHandler completion, void *context);
static bool queue_frame(SSHSocketService *service, HelperFrame frame);
static void send_message(void *context);
static bool channel_received(void *context, HelperFrame frame);
static void receive_message(void *context);
static void finish_work(SocketServiceWork *work, OuterSSHError error);
static void finish_channel(void *context);
static void fail_work(SSHSocketService *service, OuterSSHError error);
static void update_service_timer(SSHSocketService *service);
static void service_deadline_reached(void *context);
static uint64_t service_time_nanoseconds(void);
static OuterSSHError service_error(const char *message, size_t length);
static bool submit_watch_operation(OuterSSHSessionPool *pool, const char *path, size_t length,
    uint64_t tag, void (*submit)(void *));
static void submit_watch(void *context);
static void watch_service_ready(void *context, OuterSSHError error);
static void watch_registered(void *context, OuterSSHError error);
static void submit_unwatch(void *context);
static void remove_watch(SSHSocketService *service, const char *path, size_t length);
static bool cancel_work(SSHSocketService *service, SocketServiceWork *work);
static void stop_service_channel(SSHSocketService *service);
static void stop_channel(void *context);
static void timer_cancelled(void *context);

SocketAuthorization *outersshpriv_socket_service_find_authorization(OuterSSHSessionPool *pool, const char *path, size_t length)
{
    otqueue_assert(pool->_queue);
    SSHSocketService *service = pool->socket_service;
    if (service == NULL || pool->shutdown_requested || pool->_disconnecting || path == NULL) return NULL;
    for (size_t i = 0; i < service->authorization_count; i++) {
        SocketAuthorization *authorization = service->authorizations[i];
        if (authorization->path_length == length && memcmp(authorization->path, path, length) == 0)
            return authorization;
    }
    return NULL;
}

void outersshpriv_socket_service_wait_for_authorization(SocketAuthorization *authorization,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    SocketAuthorizationRequest *request = authorization->pending;
    assert(request != NULL);
    otqueue_assert(request->service->pool->_queue);
    outersshpriv_wait(&request->waiters, waiter, resume, context);
}

void outersshpriv_socket_service_authorize(OuterSSHSessionPool *pool,
                                  const char *path, size_t length,
                                  SocketAuthorizationRequest *request, SSHWaiter *waiter,
                                  SSHCompletionHandler completion,
                                  void *context)
{
    otqueue_assert(pool->_queue);
    if (pool->shutdown_requested) { completion(context, outerssh_proxy_closing_error()); return; }
    if (!outersshpriv_proxy_socket_path_is_valid(path, length)) {
        static const char message[] = "Invalid socket path.";
        completion(context, service_error(message, sizeof(message) - 1));
        return;
    }
    if (outerssh_proxy_is_named_pipe(path, length)) atomic_store(&pool->_commandDialect, OUTERSSH_COMMAND_DIALECT_WINDOWS);
    SSHSocketService *service = get_service(pool);
    if (service == NULL || service->next_id == UINT32_MAX) goto allocation_failed;
    if (service->authorization_count == service->authorization_capacity) {
        size_t capacity = service->authorization_capacity == 0 ? 8 : service->authorization_capacity * 2;
        if (capacity < service->authorization_capacity || capacity > SIZE_MAX / sizeof(*service->authorizations))
            goto allocation_failed;
        SocketAuthorization **authorizations = realloc(service->authorizations, capacity * sizeof(*authorizations));
        if (authorizations == NULL) goto allocation_failed;
        service->authorizations = authorizations;
        service->authorization_capacity = capacity;
    }
    SocketAuthorization *authorization = malloc(sizeof(*authorization) + length);
    if (authorization == NULL) goto allocation_failed;
    *authorization = (SocketAuthorization){.pending = request, .path_length = length};
    *request = (SocketAuthorizationRequest){.work.id = ++service->next_id,
        .service = service, .authorization = authorization};
    memcpy(authorization->path, path, length);
    service->authorizations[service->authorization_count++] = authorization;
    outersshpriv_socket_service_wait_for_authorization(authorization, waiter, completion, context);
    run_when_ready(service, &request->work, authorization_service_ready, request);
    return;

allocation_failed: {
    static const char message[] = "Could not allocate a socket authorization request.";
    completion(context, service_error(message, sizeof(message) - 1));
}
}

static void authorization_service_ready(void *context, OuterSSHError error)
{
    SocketAuthorizationRequest *request = context;
    SocketAuthorization *authorization = request->authorization;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        authorization_finished(request, error);
        return;
    }
    request->work.expects_preparation = true;
    send_request(request->service, &request->work, (HelperFrame){
        .type = HELPER_FRAME_AUTHORIZE, .stream_id = request->work.id,
        .payload = (const unsigned char *)authorization->path,
        .payload_length = authorization->path_length}, authorization_finished, request);
}

static void authorization_finished(void *context, OuterSSHError error)
{
    SocketAuthorizationRequest *request = context;
    SocketAuthorization *authorization = request->authorization;
    /* The first waiter owns request and may free it when resumed. */
    SSHWaitList waiters = request->waiters;
    request->waiters = (SSHWaitList){0};
    if (error.domain == OUTERSSH_ERROR_NONE) {
        const unsigned char *prepared = request->work.reply;
        authorization->connection_mode = request->work.connection_mode;
        authorization->session_owned = (prepared[0] & HELPER_PREPARED_SESSION_OWNED) != 0;
        authorization->root_owned = (prepared[0] & HELPER_PREPARED_ROOT_OWNED) != 0;
        authorization->owner_length = request->work.reply_length - 1;
        memcpy(authorization->owner, prepared + 1, authorization->owner_length);
        authorization->pending = NULL;
    } else {
        SSHSocketService *service = request->service;
        for (size_t i = 0; i < service->authorization_count; i++) {
            if (service->authorizations[i] != authorization) continue;
            service->authorizations[i] = service->authorizations[--service->authorization_count];
            break;
        }
        free(authorization);
    }
    outersshpriv_wake(&waiters, error);
}

#pragma mark - Observe Endpoint Names

static void start_observing_endpoint_names(void *context);

void outerssh_session_pool_observe_endpoint_names(OuterSSHSessionPool *pool)
{
    otqueue_async(pool->_queue, pool, start_observing_endpoint_names);
}

static void start_observing_endpoint_names(void *context)
{
    OuterSSHSessionPool *pool = context;
    if (pool->_endpointNamesObserved || pool->shutdown_requested) return;
    SSHSocketService *service = get_service(pool);
    if (service == NULL) {
        outersshpriv_session_pool_post_endpoint_names(pool, false, NULL, 0);
        return;
    }
    pool->_endpointNamesObserved = true;
    outersshpriv_session_pool_post_endpoint_names(pool, service->endpoint_names_valid,
        service->endpoint_records, service->endpoint_record_count);
    if (service->channel == NULL) start_service(service);
}

#pragma mark - Endpoint Icons

typedef struct {
    SocketServiceWork work;
    OuterSSHSessionPool *pool;
    SSHSocketService *service;
    SSHPoolEvent *reply;
    bool store;
    size_t length;
    unsigned char payload[];
} EndpointIconRequest;

static void submit_endpoint_icon(void *context);
static void endpoint_icon_service_ready(void *context, OuterSSHError error);
static void endpoint_icon_finished(void *context, OuterSSHError error);

static bool request_endpoint_icon(OuterSSHSessionPool *pool, const char *transport, const char *address,
    size_t address_length, uint16_t port, const void *png, size_t png_length, bool store, uint64_t tag)
{
    if (store && !outerssh_endpoint_icon_is_valid(png, png_length)) return false;
    size_t line_length;
    char *line = outersshpriv_endpoint_record_line(transport, address, address_length, port, &line_length);
    if (line == NULL) return false;
    size_t length = line_length + (store ? 1 + png_length : 0);
    EndpointIconRequest *request = malloc(sizeof(*request) + length);
    SSHPoolEvent *reply = request == NULL ? NULL : outersshpriv_reply_reserve(pool,
        store ? OUTERSSH_EVENT_OPERATION_COMPLETED : OUTERSSH_EVENT_ENDPOINT_ICON_RECEIVED, tag);
    if (reply == NULL) {
        free(request);
        free(line);
        return false;
    }
    *request = (EndpointIconRequest){.pool = pool, .reply = reply, .store = store, .length = length};
    memcpy(request->payload, line, line_length);
    free(line);
    if (store) {
        request->payload[line_length] = 0;
        memcpy(request->payload + line_length + 1, png, png_length);
    }
    otqueue_async(pool->_queue, request, submit_endpoint_icon);
    return true;
}

bool outerssh_session_pool_store_endpoint_icon(OuterSSHSessionPool *pool,
    const char *transport, const char *address, size_t address_length, uint16_t port,
    const void *png, size_t png_length, uint64_t tag)
{
    return request_endpoint_icon(pool, transport, address, address_length, port, png, png_length, true, tag);
}

bool outerssh_session_pool_get_endpoint_icon(OuterSSHSessionPool *pool,
    const char *transport, const char *address, size_t address_length, uint16_t port, uint64_t tag)
{
    return request_endpoint_icon(pool, transport, address, address_length, port, NULL, 0, false, tag);
}

static void submit_endpoint_icon(void *context)
{
    EndpointIconRequest *request = context;
    OuterSSHSessionPool *pool = request->pool;
    if (pool->shutdown_requested) {
        endpoint_icon_finished(request, outerssh_proxy_closing_error());
        return;
    }
    request->service = get_service(pool);
    if (request->service == NULL || request->service->next_id == UINT32_MAX) {
        static const char message[] = "Could not allocate an endpoint icon request.";
        endpoint_icon_finished(request, service_error(message, sizeof(message) - 1));
        return;
    }
    request->work.id = ++request->service->next_id;
    run_when_ready(request->service, &request->work, endpoint_icon_service_ready, request);
}

static void endpoint_icon_service_ready(void *context, OuterSSHError error)
{
    EndpointIconRequest *request = context;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        endpoint_icon_finished(request, error);
        return;
    }
    request->work.reply_type = request->store ? 0 : HELPER_FRAME_ENDPOINT_ICON;
    send_request(request->service, &request->work, (HelperFrame){
        .type = request->store ? HELPER_FRAME_STORE_ENDPOINT_ICON : HELPER_FRAME_GET_ENDPOINT_ICON,
        .stream_id = request->work.id, .payload = request->payload, .payload_length = request->length},
        endpoint_icon_finished, request);
}

static void endpoint_icon_finished(void *context, OuterSSHError error)
{
    EndpointIconRequest *request = context;
    if (request->store) outersshpriv_reply(request->reply, error);
    else outersshpriv_reply_endpoint_icon(request->reply, request->work.reply, request->work.reply_length, error);
    free(request);
}

#pragma mark - Application Requests

typedef struct {
    SocketServiceWork work;
    OuterSSHSessionPool *pool;
    SSHSocketService *service;
    SSHPoolEvent *reply;
    size_t length;
    unsigned char payload[];
} HelperRequest;

static void submit_helper_request(void *context);
static void helper_request_service_ready(void *context, OuterSSHError error);
static void helper_request_finished(void *context, OuterSSHError error);

bool outerssh_session_pool_send_helper_request(OuterSSHSessionPool *pool,
    const void *bytes, size_t length, uint64_t tag)
{
    if (bytes == NULL || length == 0 || length > HELPER_MAXIMUM_PAYLOAD_LENGTH) return false;
    HelperRequest *request = malloc(sizeof(*request) + length);
    SSHPoolEvent *reply = request == NULL ? NULL : outersshpriv_reply_reserve(pool, OUTERSSH_EVENT_HELPER_RESPONSE, tag);
    if (reply == NULL) {
        free(request);
        return false;
    }
    *request = (HelperRequest){.pool = pool, .reply = reply, .length = length};
    memcpy(request->payload, bytes, length);
    otqueue_async(pool->_queue, request, submit_helper_request);
    return true;
}

static void submit_helper_request(void *context)
{
    HelperRequest *request = context;
    OuterSSHSessionPool *pool = request->pool;
    if (pool->shutdown_requested) {
        helper_request_finished(request, outerssh_proxy_closing_error());
        return;
    }
    request->service = get_service(pool);
    if (request->service == NULL || request->service->next_id == UINT32_MAX) {
        static const char message[] = "Could not allocate a helper request.";
        helper_request_finished(request, service_error(message, sizeof(message) - 1));
        return;
    }
    request->work.id = ++request->service->next_id;
    run_when_ready(request->service, &request->work, helper_request_service_ready, request);
}

static void helper_request_service_ready(void *context, OuterSSHError error)
{
    HelperRequest *request = context;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        helper_request_finished(request, error);
        return;
    }
    request->work.reply_type = HELPER_FRAME_APP_RESPONSE;
    send_request(request->service, &request->work, (HelperFrame){
        .type = HELPER_FRAME_APP_REQUEST, .stream_id = request->work.id,
        .payload = request->payload, .payload_length = request->length},
        helper_request_finished, request);
}

static void helper_request_finished(void *context, OuterSSHError error)
{
    HelperRequest *request = context;
    outersshpriv_reply_helper_response(request->reply, request->work.reply, request->work.reply_length, error);
    free(request);
}

#pragma mark - Watch Remote Sockets

bool outerssh_session_pool_watch_socket(OuterSSHSessionPool *pool, const char *path, size_t length, uint64_t tag)
{
    return submit_watch_operation(pool, path, length, tag, submit_watch);
}

static bool submit_watch_operation(OuterSSHSessionPool *pool, const char *path, size_t length,
    uint64_t tag, void (*submit)(void *))
{
    if (path == NULL || length == 0 || length >= PROXY_UNIX_SOCKET_PATH_CAPACITY) return false;
    SocketWatchSubmission *submission = malloc(sizeof(*submission) + length);
    SSHPoolEvent *reply = submission == NULL ? NULL
        : outersshpriv_reply_reserve(pool, OUTERSSH_EVENT_OPERATION_COMPLETED, tag);
    if (reply == NULL) {
        free(submission);
        return false;
    }
    *submission = (SocketWatchSubmission){.pool = pool, .reply = reply, .path_length = length};
    memcpy(submission->path, path, length);
    otqueue_async(pool->_queue, submission, submit);
    return true;
}

static void submit_watch(void *context)
{
    SocketWatchSubmission *submission = context;
    OuterSSHSessionPool *pool = submission->pool;
    if (pool->shutdown_requested) {
        outersshpriv_reply(submission->reply, outerssh_proxy_closing_error());
        free(submission);
        return;
    }
    if (!outersshpriv_proxy_socket_path_is_valid(submission->path, submission->path_length)) {
        static const char message[] = "Invalid socket watch path.";
        outersshpriv_reply(submission->reply, service_error(message, sizeof(message) - 1));
        free(submission);
        return;
    }
    if (outerssh_proxy_is_named_pipe(submission->path, submission->path_length))
        atomic_store(&pool->_commandDialect, OUTERSSH_COMMAND_DIALECT_WINDOWS);
    SSHSocketService *service = get_service(pool);
    SocketWatch *watch = service == NULL ? NULL : malloc(sizeof(*watch) + submission->path_length);
    if (watch == NULL || service->next_id == UINT32_MAX) {
        free(watch);
        static const char message[] = "Could not allocate a socket watch.";
        outersshpriv_reply(submission->reply, service_error(message, sizeof(message) - 1));
        free(submission);
        return;
    }
    remove_watch(service, submission->path, submission->path_length);
    *watch = (SocketWatch){.work.id = ++service->next_id, .service = service,
        .reply = submission->reply,
        .path_length = submission->path_length, .next = service->watches};
    memcpy(watch->path, submission->path, submission->path_length);
    service->watches = watch;
    free(submission);
    run_when_ready(service, &watch->work, watch_service_ready, watch);
}

static void watch_service_ready(void *context, OuterSSHError error)
{
    SocketWatch *watch = context;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        watch_registered(watch, error);
        return;
    }
    watch->sent = true;
    send_request(watch->service, &watch->work, (HelperFrame){
        .type = HELPER_FRAME_WATCH, .stream_id = watch->work.id,
        .payload = (const unsigned char *)watch->path, .payload_length = watch->path_length},
        watch_registered, watch);
}

static void watch_registered(void *context, OuterSSHError error)
{
    SocketWatch *watch = context;
    SSHPoolEvent *reply = watch->reply;
    watch->reply = NULL;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        watch->sent = false;
        /* Established watches survive channel loss, but not a rejected subscription. */
        if (reply != NULL || watch->cancelled || watch->service->pool->shutdown_requested ||
            watch->service->ready) {
            SocketWatch **link = &watch->service->watches;
            while (*link != watch) link = &(*link)->next;
            *link = watch->next;
            free(watch);
        }
    }
    if (reply != NULL) outersshpriv_reply(reply, error);
}

bool outerssh_session_pool_unwatch_socket(OuterSSHSessionPool *pool, const char *path, size_t length, uint64_t tag)
{
    return submit_watch_operation(pool, path, length, tag, submit_unwatch);
}

static void submit_unwatch(void *context)
{
    SocketWatchSubmission *submission = context;
    SSHSocketService *service = submission->pool->socket_service;
    if (service != NULL) remove_watch(service, submission->path, submission->path_length);
    outersshpriv_reply(submission->reply, (OuterSSHError){0});
    free(submission);
}

static void remove_watch(SSHSocketService *service, const char *path, size_t length)
{
    for (SocketWatch *watch = service->watches; watch != NULL; watch = watch->next) {
        if (watch->path_length != length || memcmp(watch->path, path, length) != 0) continue;
        watch->cancelled = true;
        if (watch->sent) queue_frame(service, (HelperFrame){
            .type = HELPER_FRAME_UNWATCH, .stream_id = watch->work.id});
        if (!cancel_work(service, &watch->work)) watch_registered(watch, outerssh_proxy_closing_error());
        update_service_timer(service);
        return;
    }
}

static bool cancel_work(SSHSocketService *service, SocketServiceWork *work)
{
    SocketServiceWork **link = &service->ready_head;
    SocketServiceWork *previous = NULL;
    while (*link != NULL && *link != work) {
        previous = *link;
        link = &(*link)->next;
    }
    if (*link != NULL) {
        *link = work->next;
        if (service->ready_tail == work) service->ready_tail = previous;
    } else {
        link = &service->replies;
        while (*link != NULL && *link != work) link = &(*link)->next;
        if (*link == NULL) return false;
        *link = work->next;
    }
    finish_work(work, outerssh_proxy_closing_error());
    return true;
}

#pragma mark - Start the Shared Socket Service

static void run_when_ready(SSHSocketService *service, SocketServiceWork *work,
    SSHCompletionHandler completion, void *context)
{
    if (service->pool->shutdown_requested) {
        completion(context, outerssh_proxy_closing_error());
        return;
    }
    if (service->ready && !service->stopping_channel) {
        completion(context, (OuterSSHError){0});
        return;
    }
    work->completion = completion;
    work->context = context;
    work->next = NULL;
    if (service->ready_tail != NULL) service->ready_tail->next = work;
    else service->ready_head = work;
    service->ready_tail = work;
    if (service->channel == NULL) start_service(service);
    update_service_timer(service);
}

static SSHSocketService *get_service(OuterSSHSessionPool *pool)
{
    if (pool->socket_service != NULL) {
        return pool->socket_service;
    }

    SSHSocketService *service = calloc(1, sizeof(*service));
    if (service == NULL) return NULL;
    service->pool = pool;
    service->timer = otsource_create(OTSOURCE_TYPE_TIMER, 0, pool->_queue);
    if (service->timer == NULL) { free(service); return NULL; }
    outersshpriv_session_pool_begin_operation(pool);
    otsource_set_context(service->timer, service);
    otsource_set_event_handler(service->timer, service_deadline_reached);
    otsource_set_cancel_handler(service->timer, timer_cancelled);
    otsource_set_timer(service->timer,
        OTTIME_FOREVER, OTTIME_FOREVER, NSEC_PER_MSEC * 100);
    otsource_activate(service->timer);
    pool->socket_service = service;
    return service;
}

static void start_service(SSHSocketService *service)
{
    if (service->pool->shutdown_requested || service->channel != NULL) return;
    SocketServiceChannel *channel = calloc(1, sizeof(*channel));
    if (channel == NULL) {
        static const char message[] = "Could not allocate the socket service channel.";
        service->restart_deadline = service_time_nanoseconds() + 5 * NSEC_PER_SEC;
        fail_work(service, service_error(message, sizeof(message) - 1));
        update_service_timer(service);
        return;
    }
    channel->service = service;
    service->channel = channel;
    service->stopping_channel = false;
    update_service_timer(service);
    outersshpriv_session_pool_begin_operation(service->pool);
    outersshpriv_proxy_ensure_user_bridge_executable(service->pool, &channel->waiter, executable_ready, channel);
}

static void executable_ready(void *context, OuterSSHError error)
{
    SocketServiceChannel *channel = context;
    OuterSSHSessionPool *pool = channel->service->pool;
    if (error.domain != OUTERSSH_ERROR_NONE || pool->shutdown_requested) {
        channel->error = error.domain != OUTERSSH_ERROR_NONE ? error : outerssh_proxy_closing_error();
        finish_channel(channel);
        return;
    }
    channel->command = outersshpriv_socket_service_launch_command(pool->_userBridgeExecutablePath,
        pool->_userBridgeExecutablePath_length, pool->socket_allowlist_arguments, &channel->command_length);
    if (channel->command == NULL) {
        static const char message[] = "Could not allocate the socket service command.";
        channel->error = service_error(message, sizeof(message) - 1);
        finish_channel(channel);
        return;
    }
    outersshpriv_session_pool_run_when_ready(channel->service->pool, &channel->waiter, session_ready, channel);
}

static void session_ready(void *context, OuterSSHError error)
{
    SocketServiceChannel *channel = context;
    SSHSessionPoolSessionHandle session;
    SSHReactor *reactor = outersshpriv_session_pool_ready_reactor(channel->service->pool, &session, &error);
    if (error.domain != OUTERSSH_ERROR_NONE || channel->service->pool->shutdown_requested) {
        channel->error = error.domain != OUTERSSH_ERROR_NONE
            ? error : outerssh_proxy_closing_error();
        finish_channel(channel);
        return;
    }
    channel->session = session;
    channel->reactor = reactor;
    otqueue_async(outersshpriv_reactor_queue(reactor), channel, start_channel);
}

static void start_channel(void *context)
{
    SocketServiceChannel *channel = context;
    SSHReactorSocketBridgeHandle handle;
    int result = outersshpriv_reactor_start_socket_channel(channel->reactor, &handle,
        (SSHSocketChannelCallbacks){channel, channel_completed, channel_received},
        channel->command, channel->command_length, NULL, 0, 10000, 10000);
    if (result != 0) {
        channel->error = outerssh_session_error_format(&channel->error_storage, OUTERSSH_SESSION_ERROR_CHANNEL_OPEN_START_FAILED,
            "Could not start the socket service (code %d).", result);
        otqueue_async(channel->service->pool->_queue, channel, finish_channel);
    }
}

static void channel_completed(void *context, SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result, uint32_t reason, const void *detail, size_t length)
{
    (void)reason;
    SocketServiceChannel *channel = context;
    if (result == SSH_REACTOR_SOCKET_BRIDGE_READY) {
        channel->handle = handle;
        otqueue_async(channel->service->pool->_queue, channel, channel_ready);
    } else {
        static const char message[] = "The remote socket service stopped.";
        channel->error = length == 0
            ? service_error(message, sizeof(message) - 1)
            : outerssh_error_copy(service_error(detail, length), &channel->error_storage);
        otqueue_async(channel->service->pool->_queue, channel, finish_channel);
    }
}

static void channel_ready(void *context)
{
    SocketServiceChannel *channel = context;
    SSHSocketService *service = channel->service;
    service->ready = true;
    service->silence_deadline = service_time_nanoseconds() + 45 * NSEC_PER_SEC;
    update_service_timer(service);
    if (service->pool->shutdown_requested) {
        outersshpriv_socket_service_stop(service->pool);
        return;
    }
    for (SocketWatch *watch = service->watches; watch != NULL;) {
        SocketWatch *next = watch->next;
        if (!watch->sent && watch->work.completion == NULL)
            run_when_ready(service, &watch->work, watch_service_ready, watch);
        watch = next;
    }
    while (service->ready_head != NULL) {
        SocketServiceWork *work = service->ready_head;
        service->ready_head = work->next;
        if (service->ready_head == NULL) service->ready_tail = NULL;
        finish_work(work, (OuterSSHError){0});
    }
}

static void send_request(SSHSocketService *service, SocketServiceWork *work,
    HelperFrame frame, SSHCompletionHandler completion, void *context)
{
    if (!queue_frame(service, frame)) {
        static const char message[] = "Could not send a socket service request.";
        completion(context, service_error(message, sizeof(message) - 1));
        return;
    }
    work->completion = completion;
    work->context = context;
    work->deadline = service_time_nanoseconds() + 30 * NSEC_PER_SEC;
    work->next = service->replies;
    service->replies = work;
    update_service_timer(service);
}

static bool queue_frame(SSHSocketService *service, HelperFrame frame)
{
    SocketServiceChannel *channel = service->channel;
    SSHReactor *reactor = channel == NULL ? NULL :
        outersshpriv_session_pool_reactor_for_session(service->pool, channel->session);
    if (reactor == NULL || !service->ready || service->stopping_channel) return false;
    SocketServiceSend *send = malloc(sizeof(*send) + frame.payload_length);
    if (send == NULL) return false;
    *send = (SocketServiceSend){.reactor = reactor, .handle = channel->handle, .frame = frame};
    if (frame.payload_length != 0) memcpy(send->bytes, frame.payload, frame.payload_length);
    send->frame.payload = send->bytes;
    otqueue_async(outersshpriv_reactor_queue(reactor), send, send_message);
    return true;
}

static void send_message(void *context)
{
    SocketServiceSend *send = context;
    if (!outersshpriv_reactor_socket_channel_send(send->reactor, send->handle, send->frame)) {
        outersshpriv_reactor_stop_socket_bridge(send->reactor, send->handle, false);
    }
    free(send);
}

static bool channel_received(void *context, HelperFrame frame)
{
    OuterSSHEndpointRecord *endpoint_records = NULL;
    size_t endpoint_record_count = 0;
    if (frame.type == HELPER_FRAME_ENDPOINT_NAMES && frame.stream_id == 0) {
        if (!outersshpriv_endpoint_names_parse(frame.payload, frame.payload_length,
            &endpoint_records, &endpoint_record_count)) return false;
    } else if (frame.type == HELPER_FRAME_PONG || frame.type == HELPER_FRAME_ENDPOINT_NAMES_CHANGED) {
        if (frame.stream_id != 0 || frame.payload_length != 0) return false;
    } else if (frame.stream_id == 0 || (frame.type != HELPER_FRAME_RESULT &&
        frame.type != HELPER_FRAME_SOCKET_STATE && frame.type != HELPER_FRAME_PREPARED &&
        frame.type != HELPER_FRAME_ENDPOINT_NAMES && frame.type != HELPER_FRAME_ENDPOINT_ICON &&
        frame.type != HELPER_FRAME_APP_RESPONSE)) return false;
    if (frame.type == HELPER_FRAME_ENDPOINT_ICON && frame.payload_length > OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES)
        return false;
    if (frame.type == HELPER_FRAME_SOCKET_STATE &&
        (frame.payload_length != 1 || frame.payload[0] > 2)) return false;
    if (frame.type == HELPER_FRAME_PREPARED &&
        (frame.payload_length == 0 ||
         (frame.payload[0] & ~(HELPER_PREPARED_MODE_MASK | HELPER_PREPARED_SESSION_OWNED | HELPER_PREPARED_ROOT_OWNED)) ||
         (frame.payload[0] & HELPER_PREPARED_MODE_MASK) > HELPER_CONNECTION_PRIVILEGED ||
         !outersshpriv_helper_owner_is_valid(frame.payload + 1, frame.payload_length - 1))) return false;
    size_t payload_length = endpoint_records != NULL ? 0 : frame.payload_length;
    SocketServiceMessage *message = malloc(sizeof(*message) + payload_length);
    if (message == NULL) {
        free(endpoint_records);
        return false;
    }
    message->channel = context;
    message->frame = frame;
    message->frame.payload_length = (uint32_t)payload_length;
    message->endpoint_records = endpoint_records;
    message->endpoint_record_count = endpoint_record_count;
    if (payload_length != 0) memcpy(message->bytes, frame.payload, payload_length);
    message->frame.payload = message->bytes;
    otqueue_async(message->channel->service->pool->_queue, message, receive_message);
    return true;
}

static void receive_message(void *context)
{
    SocketServiceMessage *message = context;
    SSHSocketService *service = message->channel->service;
    service->silence_deadline = service_time_nanoseconds() + 45 * NSEC_PER_SEC;
    update_service_timer(service);
    if (!service->pool->shutdown_requested) {
        if (message->frame.stream_id != 0 && (message->frame.type == HELPER_FRAME_RESULT ||
            message->frame.type == HELPER_FRAME_PREPARED || message->frame.type == HELPER_FRAME_ENDPOINT_ICON ||
            message->frame.type == HELPER_FRAME_APP_RESPONSE)) {
            SocketServiceWork **link = &service->replies;
            while (*link != NULL && (*link)->id != message->frame.stream_id) link = &(*link)->next;
            SocketServiceWork *work = *link;
            if (work != NULL) {
                *link = work->next;
                update_service_timer(service);
                OuterSSHError error = {0};
                if (message->frame.type == HELPER_FRAME_PREPARED && work->expects_preparation) {
                    work->connection_mode = (HelperConnectionMode)(message->bytes[0] & HELPER_PREPARED_MODE_MASK);
                    work->reply = message->bytes;
                    work->reply_length = message->frame.payload_length;
                } else if (work->reply_type != 0 && message->frame.type == work->reply_type) {
                    work->reply = message->bytes;
                    work->reply_length = message->frame.payload_length;
                } else if (message->frame.type == HELPER_FRAME_RESULT && message->frame.payload_length != 0) {
                    error = service_error((const char *)message->bytes, message->frame.payload_length);
                } else if (work->expects_preparation || message->frame.type == HELPER_FRAME_PREPARED) {
                    static const char invalid[] = "Invalid socket preparation response.";
                    error = service_error(invalid, sizeof(invalid) - 1);
                } else if (work->reply_type != 0 || message->frame.type != HELPER_FRAME_RESULT) {
                    static const char invalid[] = "Invalid helper response.";
                    error = service_error(invalid, sizeof(invalid) - 1);
                }
                finish_work(work, error);
            }
        } else if (message->frame.type == HELPER_FRAME_ENDPOINT_NAMES_CHANGED ||
                   message->frame.type == HELPER_FRAME_ENDPOINT_NAMES) {
            free(service->endpoint_records);
            service->endpoint_records = message->endpoint_records;
            service->endpoint_record_count = message->endpoint_record_count;
            service->endpoint_names_valid = service->endpoint_records != NULL;
            message->endpoint_records = NULL;
            OuterSSHSessionPool *pool = service->pool;
            if (pool->_endpointNamesObserved) {
                outersshpriv_session_pool_post_endpoint_names(pool, service->endpoint_names_valid,
                    service->endpoint_records, service->endpoint_record_count);
            }
        } else if (message->frame.type == HELPER_FRAME_SOCKET_STATE) {
            for (SocketWatch *watch = service->watches; watch != NULL; watch = watch->next) {
                if (watch->work.id != message->frame.stream_id) continue;
                OuterSSHSessionPool *pool = service->pool;
                if (message->bytes[0] != 2) {
                    watch->reported_available = message->bytes[0] == 1;
                    outersshpriv_session_pool_post_socket_availability(pool,
                        watch->path, watch->path_length, watch->reported_available);
                }
                break;
            }
        }
    }
    free(message->endpoint_records);
    free(message);
}

void outersshpriv_socket_service_found_nothing_listening(OuterSSHSessionPool *pool, const char *path, size_t length)
{
    otqueue_assert(pool->_queue);
    SSHSocketService *service = pool->socket_service;
    for (SocketWatch *watch = service == NULL ? NULL : service->watches; watch != NULL; watch = watch->next) {
        if (watch->cancelled || !watch->reported_available || watch->path_length != length ||
            memcmp(watch->path, path, length) != 0) continue;
        watch->reported_available = false;
        outersshpriv_session_pool_post_socket_availability(pool, watch->path, watch->path_length, false);
    }
}

static void finish_work(SocketServiceWork *work, OuterSSHError error)
{
    SSHCompletionHandler completion = work->completion;
    void *context = work->context;
    work->completion = NULL;
    work->next = NULL;
    work->deadline = 0;
    completion(context, error);
}

static void finish_channel(void *context)
{
    SocketServiceChannel *channel = context;
    SSHSocketService *service = channel->service;
    OuterSSHSessionPool *pool = service->pool;
    service->channel = NULL;
    service->ready = false;
    service->endpoint_names_valid = false;
    service->restart_deadline = service_time_nanoseconds() + 5 * NSEC_PER_SEC;
    for (SocketWatch *watch = service->watches; watch != NULL; watch = watch->next) {
        watch->sent = false;
    }
    fail_work(service, channel->error);
    update_service_timer(service);
    free(channel->error_storage);
    free(channel->command);
    free(channel);
    outersshpriv_session_pool_end_operation(pool);
}

static void fail_work(SSHSocketService *service, OuterSSHError error)
{
    SocketServiceWork *ready = service->ready_head;
    SocketServiceWork *reply = service->replies;
    service->ready_head = service->ready_tail = service->replies = NULL;
    while (ready != NULL) {
        SocketServiceWork *next = ready->next;
        finish_work(ready, error);
        ready = next;
    }
    while (reply != NULL) {
        SocketServiceWork *next = reply->next;
        finish_work(reply, error);
        reply = next;
    }
}

static void update_service_timer(SSHSocketService *service)
{
    if (service->timer == NULL) return;
    uint64_t deadline = 0;
    if (!service->pool->shutdown_requested) {
        if (service->channel == NULL && (service->ready_head != NULL || service->watches != NULL || service->pool->_endpointNamesObserved)) {
            deadline = service->restart_deadline;
        } else if (service->ready && !service->stopping_channel) {
            deadline = service->silence_deadline;
            for (SocketServiceWork *work = service->replies; work != NULL; work = work->next) {
                if (work->deadline < deadline) deadline = work->deadline;
            }
        }
    }
    if (deadline == service->timer_deadline) return;
    service->timer_deadline = deadline;
    ottime_t start = OTTIME_FOREVER;
    if (deadline != 0) {
        uint64_t now = service_time_nanoseconds();
        start = ottime(OTTIME_NOW, deadline > now ? (int64_t)(deadline - now) : 0);
    }
    otsource_set_timer(service->timer, start, OTTIME_FOREVER, NSEC_PER_MSEC * 100);
}

static void service_deadline_reached(void *context)
{
    SSHSocketService *service = context;
    service->timer_deadline = 0;
    if (service->pool->shutdown_requested) return;
    uint64_t now = service_time_nanoseconds();
    if (service->channel == NULL && (service->ready_head != NULL || service->watches != NULL || service->pool->_endpointNamesObserved) &&
        now >= service->restart_deadline) {
        start_service(service);
    } else if (service->ready && !service->stopping_channel) {
        bool expired = now >= service->silence_deadline;
        for (SocketServiceWork *work = service->replies; work != NULL && !expired; work = work->next)
            expired = now >= work->deadline;
        if (expired) {
            stop_service_channel(service);
            if (!service->stopping_channel) {
                /* A failed stop-message allocation must not cause an immediate timer loop. */
                service->timer_deadline = now + NSEC_PER_SEC;
                otsource_set_timer(service->timer,
                    ottime(OTTIME_NOW, NSEC_PER_SEC), OTTIME_FOREVER, NSEC_PER_MSEC * 100);
                return;
            }
        }
    }
    update_service_timer(service);
}

static uint64_t service_time_nanoseconds(void)
{
#if defined(_WIN32)
    return ottime(OTTIME_NOW, 0);
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    return (uint64_t)now.tv_sec * NSEC_PER_SEC + (uint64_t)now.tv_nsec;
#endif
}

static OuterSSHError service_error(const char *message, size_t length)
{
    return outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_SOCKET_AUTHORIZATION_FAILED, message, length, 0);
}

#pragma mark - Stop and Dispose the Socket Service

void outersshpriv_socket_service_stop(OuterSSHSessionPool *pool)
{
    SSHSocketService *service = pool->socket_service;
    if (service == NULL) return;
    if (service->timer != NULL) {
        otsource_cancel(service->timer);
        otsource_release(service->timer);
        service->timer = NULL;
        service->timer_deadline = 0;
    }
    stop_service_channel(service);
    fail_work(service, outerssh_proxy_closing_error());
    while (service->watches != NULL) {
        SocketWatch *watch = service->watches;
        service->watches = watch->next;
        if (watch->reply != NULL) outersshpriv_reply(watch->reply, outerssh_proxy_closing_error());
        free(watch);
    }
}

static void stop_service_channel(SSHSocketService *service)
{
    if (!service->ready || service->stopping_channel) return;
    SocketServiceChannel *channel = service->channel;
    SSHReactor *reactor = outersshpriv_session_pool_reactor_for_session(service->pool, channel->session);
    if (reactor == NULL) return;
    SocketServiceSend *stop = calloc(1, sizeof(*stop));
    if (stop == NULL) return;
    stop->reactor = reactor;
    stop->handle = channel->handle;
    service->stopping_channel = true;
    update_service_timer(service);
    otqueue_async(outersshpriv_reactor_queue(reactor), stop, stop_channel);
}

static void stop_channel(void *context)
{
    SocketServiceSend *stop = context;
    outersshpriv_reactor_stop_socket_bridge(stop->reactor, stop->handle, true);
    free(stop);
}

static void timer_cancelled(void *context)
{
    SSHSocketService *service = context;
    outersshpriv_session_pool_end_operation(service->pool);
}

void outersshpriv_socket_service_dispose(OuterSSHSessionPool *pool)
{
    SSHSocketService *service = pool->socket_service;
    if (service == NULL) return;
    assert(service->channel == NULL && service->timer == NULL && service->ready_head == NULL &&
        service->ready_tail == NULL && service->replies == NULL && service->watches == NULL);
    for (size_t i = 0; i < service->authorization_count; i++) {
        assert(service->authorizations[i]->pending == NULL);
        free(service->authorizations[i]);
    }
    free(service->authorizations);
    free(service->endpoint_records);
    free(service);
}
