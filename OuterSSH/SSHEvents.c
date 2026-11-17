#include "SSHEventsInternal.h"
#include "SSHProxyErrorInternal.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct SSHPoolQuestion {
    SSHPoolQuestion *next;
    uint64_t identifier;
    OuterSSHEventType type;
    const void *owner;
    SSHQuestionContinuation continuation;
    SSHBridgeBinaryContinuation binary_continuation;
    SSHSudoPasswordContinuation password_continuation;
    void *context;
};

#pragma mark - Wake the Caller

#if defined(__APPLE__)
/* Called with the event lock held, after an event is added. */
static void note_event_added(OuterSSHEventQueue *event_queue)
{
    if (event_queue->events != NULL) dispatch_source_merge_data(event_queue->events, 1);
}

static void note_events_empty(OuterSSHEventQueue *event_queue)
{
    (void)event_queue;
}
#else
static void note_event_added(OuterSSHEventQueue *event_queue)
{
    otevent_signal_set(&event_queue->event_signal);
}

static void note_events_empty(OuterSSHEventQueue *event_queue)
{
    otevent_signal_clear(&event_queue->event_signal);
}

OuterSSHEventWaitHandle outerssh_event_queue_wait_handle(OuterSSHEventQueue *event_queue)
{
    otlock_lock(&event_queue->event_lock);
    OuterSSHEventWaitHandle handle = OUTERSSH_EVENT_WAIT_HANDLE_INVALID;
    if (otevent_signal_open(&event_queue->event_signal)) {
        if (event_queue->event_head != NULL) otevent_signal_set(&event_queue->event_signal);
#if defined(_WIN32)
        handle = event_queue->event_signal.event;
#else
        handle = event_queue->event_signal.descriptor;
#endif
    }
    otlock_unlock(&event_queue->event_lock);
    return handle;
}
#endif

#pragma mark - Queue Events

static void free_events(SSHPoolEvent *event)
{
    while (event != NULL) {
        SSHPoolEvent *next = event->next;
        free(event->storage);
        free(event);
        event = next;
    }
}

/* Each copy starts on a boundary suitable for any payload, including arrays of
 * structures, and is followed by a NUL. */
static size_t part_size(size_t length)
{
    const size_t alignment = 16;
    if (length > SIZE_MAX - alignment) return SIZE_MAX;
    return (length + alignment) & ~(alignment - 1);
}

bool outersshpriv_event_copy_parts(SSHPoolEvent *event, const SSHEventBytes *parts, size_t count, const void **copies)
{
    free(event->storage);
    event->storage = NULL;
    size_t total = 0;
    for (size_t i = 0; i < count; i++) {
        size_t size = part_size(parts[i].length);
        if (size == SIZE_MAX || size > SIZE_MAX - total) return false;
        total += size;
    }
    event->storage = malloc(total == 0 ? 1 : total);
    if (event->storage == NULL) return false;
    unsigned char *cursor = event->storage;
    for (size_t i = 0; i < count; i++) {
        copies[i] = cursor;
        if (parts[i].length != 0) memcpy(cursor, parts[i].bytes, parts[i].length);
        cursor[parts[i].length] = 0;
        cursor += part_size(parts[i].length);
    }
    return true;
}

bool outersshpriv_event_copy_error_and_parts(SSHPoolEvent *event, OuterSSHError *error,
    const SSHEventBytes *parts, size_t count, const void **copies)
{
    if (count > SIZE_MAX / sizeof(SSHEventBytes) - 2) return false;
    SSHEventBytes *all = malloc((count + 2) * sizeof(*all));
    const void **all_copies = malloc((count + 2) * sizeof(*all_copies));
    bool copied = all != NULL && all_copies != NULL;
    if (copied) {
        all[0] = (SSHEventBytes){error->message, error->message ? error->message_length : 0};
        all[1] = (SSHEventBytes){error->ssh_error_message, error->ssh_error_message ? error->ssh_error_message_length : 0};
        for (size_t i = 0; i < count; i++) all[i + 2] = parts[i];
        copied = outersshpriv_event_copy_parts(event, all, count + 2, all_copies);
    }
    if (copied) {
        error->message = all_copies[0];
        error->message_length = all[0].length;
        error->ssh_error_message = all_copies[1];
        error->ssh_error_message_length = all[1].length;
        for (size_t i = 0; i < count; i++) copies[i] = all_copies[i + 2];
    }
    free(all);
    free(all_copies);
    return copied;
}

SSHPoolEvent *outersshpriv_event_create(OuterSSHEventType type, OuterSSHSessionPool *pool, uint64_t tag)
{
    SSHPoolEvent *event = calloc(1, sizeof(*event));
    if (event == NULL) return NULL;
    event->event.type = type;
    event->event.pool = pool;
    event->event.tag = tag;
    return event;
}

static SSHPoolEvent *create_event(const SSHEventBytes *parts, size_t count, const void **copies)
{
    SSHPoolEvent *event = outersshpriv_event_create(0, NULL, 0);
    if (event == NULL) return NULL;
    if (!outersshpriv_event_copy_parts(event, parts, count, copies)) {
        free(event);
        return NULL;
    }
    return event;
}

void outersshpriv_event_post(OuterSSHEventQueue *event_queue, SSHPoolEvent *event)
{
    otlock_lock(&event_queue->event_lock);
    if (event_queue->event_tail == NULL) {
        event_queue->event_head = event;
    } else {
        event_queue->event_tail->next = event;
    }
    event_queue->event_tail = event;
    note_event_added(event_queue);
    otlock_unlock(&event_queue->event_lock);
}

#pragma mark - Reply to Requests

SSHPoolEvent *outersshpriv_reply_reserve(OuterSSHSessionPool *pool, OuterSSHEventType type, uint64_t tag)
{
    SSHPoolEvent *reply = outersshpriv_event_create(type, pool, tag);
    if (reply != NULL) reply->event_queue = pool->_event_queue;
    return reply;
}

static OuterSSHError allocation_error(void)
{
    static const char message[] = "Could not allocate an OuterSSH event.";
    return outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_REACTOR_CREATION_FAILED, message, sizeof(message) - 1, ENOMEM);
}

/* Copies error text and payload parts into the reply. On allocation failure,
 * reports an allocation error and an empty payload instead. */
static bool copy_result(SSHPoolEvent *reply, OuterSSHError *error, const SSHEventBytes *parts, size_t count,
    const void **copies)
{
    if (outersshpriv_event_copy_error_and_parts(reply, error, parts, count, copies)) return true;
    *error = allocation_error();
    return false;
}

static void send_reply(SSHPoolEvent *reply)
{
    outersshpriv_event_post(reply->event_queue, reply);
}

void outersshpriv_reply(SSHPoolEvent *reply, OuterSSHError error)
{
    copy_result(reply, &error, NULL, 0, NULL);
    reply->event.operation_completed.error = error;
    send_reply(reply);
}

void outersshpriv_reply_command(SSHPoolEvent *reply, const SSHCommandOutput *output, OuterSSHError error)
{
    bool has_output = output != NULL && error.domain == OUTERSSH_ERROR_NONE;
    SSHEventBytes parts[] = {
        {has_output ? output->stdout_bytes : NULL, has_output ? output->stdout_byte_count : 0},
        {has_output ? output->stderr_bytes : NULL, has_output ? output->stderr_byte_count : 0},
    };
    const void *copies[2];
    if (copy_result(reply, &error, parts, 2, copies) && has_output) {
        reply->event.command_completed.error = error;
        reply->event.command_completed.standard_output = copies[0];
        reply->event.command_completed.standard_output_length = parts[0].length;
        reply->event.command_completed.standard_error = copies[1];
        reply->event.command_completed.standard_error_length = parts[1].length;
        reply->event.command_completed.exit_status = output->exit_status;
    } else {
        reply->event.command_completed.error = error;
    }
    send_reply(reply);
}

void outersshpriv_reply_homepage(SSHPoolEvent *reply, bool found, const char *url, size_t url_length,
    const char *source_path, size_t source_path_length, OuterSSHError error)
{
    found = found && error.domain == OUTERSSH_ERROR_NONE;
    SSHEventBytes parts[] = {
        {found ? url : NULL, found ? url_length : 0},
        {found ? source_path : NULL, found ? source_path_length : 0},
    };
    const void *copies[2];
    if (copy_result(reply, &error, parts, 2, copies) && found) {
        reply->event.homepage_received.error = error;
        reply->event.homepage_received.found = true;
        reply->event.homepage_received.url = copies[0];
        reply->event.homepage_received.url_length = parts[0].length;
        reply->event.homepage_received.source_path = copies[1];
        reply->event.homepage_received.source_path_length = parts[1].length;
    } else {
        reply->event.homepage_received.error = error;
    }
    send_reply(reply);
}

void outersshpriv_reply_endpoint_icon(SSHPoolEvent *reply, const void *png, size_t length, OuterSSHError error)
{
    bool found = length != 0 && error.domain == OUTERSSH_ERROR_NONE;
    SSHEventBytes parts[] = {{found ? png : NULL, found ? length : 0}};
    const void *copies[1];
    if (copy_result(reply, &error, parts, 1, copies) && found) {
        reply->event.endpoint_icon_received.found = true;
        reply->event.endpoint_icon_received.png = copies[0];
        reply->event.endpoint_icon_received.length = length;
    }
    reply->event.endpoint_icon_received.error = error;
    send_reply(reply);
}

void outersshpriv_reply_helper_response(SSHPoolEvent *reply, const void *bytes, size_t length, OuterSSHError error)
{
    if (error.domain != OUTERSSH_ERROR_NONE) length = 0;
    SSHEventBytes parts[] = {{length ? bytes : NULL, length}};
    const void *copies[1];
    if (copy_result(reply, &error, parts, 1, copies) && length) {
        reply->event.helper_response.bytes = copies[0];
        reply->event.helper_response.length = length;
    }
    reply->event.helper_response.error = error;
    send_reply(reply);
}

void outersshpriv_reply_socket_bridges(SSHPoolEvent *reply, const OuterSSHBridgeInfo *bridges, size_t count,
    OuterSSHError error)
{
    if (error.domain != OUTERSSH_ERROR_NONE || bridges == NULL) count = 0;
    SSHEventBytes *parts = count > SIZE_MAX / sizeof(*parts) - 1 ? NULL : malloc((count + 1) * sizeof(*parts));
    const void **copies = parts == NULL ? NULL : malloc((count + 1) * sizeof(*copies));
    bool copied = false;
    if (copies != NULL) {
        parts[0] = (SSHEventBytes){bridges, count * sizeof(*bridges)};
        for (size_t i = 0; i < count; i++) parts[i + 1] = (SSHEventBytes){bridges[i].path, bridges[i].path_length};
        copied = copy_result(reply, &error, parts, count + 1, copies);
    } else {
        error = allocation_error();
    }
    if (copied && count != 0) {
        OuterSSHBridgeInfo *items = (OuterSSHBridgeInfo *)copies[0];
        for (size_t i = 0; i < count; i++) items[i].path = copies[i + 1];
        reply->event.bridges_received.error = error;
        reply->event.bridges_received.bridges = items;
        reply->event.bridges_received.count = count;
    } else {
        reply->event.bridges_received.error = error;
    }
    free(parts);
    free(copies);
    send_reply(reply);
}

void outersshpriv_reply_proxy_started(SSHPoolEvent *reply, int32_t listen_port, const char *username,
    size_t username_length, const char *password, size_t password_length, OuterSSHError error)
{
    bool started = error.domain == OUTERSSH_ERROR_NONE;
    SSHEventBytes parts[] = {
        {started ? username : NULL, started ? username_length : 0},
        {started ? password : NULL, started ? password_length : 0},
    };
    const void *copies[2];
    if (copy_result(reply, &error, parts, 2, copies) && started) {
        reply->event.proxy_started.error = error;
        reply->event.proxy_started.listen_port = (uint16_t)listen_port;
        reply->event.proxy_started.username = copies[0];
        reply->event.proxy_started.username_length = parts[0].length;
        reply->event.proxy_started.password = copies[1];
        reply->event.proxy_started.password_length = parts[1].length;
    } else {
        reply->event.proxy_started.error = error;
    }
    send_reply(reply);
}

void outersshpriv_reply_port_forward_started(SSHPoolEvent *reply, int32_t listen_port, OuterSSHError error)
{
    copy_result(reply, &error, NULL, 0, NULL);
    reply->event.port_forward_started.error = error;
    if (error.domain == OUTERSSH_ERROR_NONE) reply->event.port_forward_started.listen_port = (uint16_t)listen_port;
    send_reply(reply);
}

/* Returns true if the event for this question had not been polled yet. */
static bool remove_pending_question_event(OuterSSHSessionPool *pool, uint64_t question)
{
    OuterSSHEventQueue *event_queue = pool->_event_queue;
    otlock_lock(&event_queue->event_lock);
    SSHPoolEvent *previous = NULL;
    SSHPoolEvent *event = event_queue->event_head;
    while (event != NULL && (event->question != question || event->event.pool != pool)) {
        previous = event;
        event = event->next;
    }
    if (event != NULL) {
        if (previous == NULL) event_queue->event_head = event->next;
        else previous->next = event->next;
        if (event_queue->event_tail == event) event_queue->event_tail = previous;
        if (event_queue->event_head == NULL) note_events_empty(event_queue);
        event->next = NULL;
    }
    otlock_unlock(&event_queue->event_lock);
    free_events(event);
    return event != NULL;
}

size_t outerssh_event_queue_poll(OuterSSHEventQueue *event_queue, OuterSSHEvent *events, size_t capacity)
{
    otlock_lock(&event_queue->event_lock);
    free_events(event_queue->delivered_events);
    event_queue->delivered_events = NULL;
    SSHPoolEvent **delivered_tail = &event_queue->delivered_events;
    size_t count = 0;
    while (count < capacity && event_queue->event_head != NULL) {
        SSHPoolEvent *event = event_queue->event_head;
        event_queue->event_head = event->next;
        event->next = NULL;
        events[count++] = event->event;
        *delivered_tail = event;
        delivered_tail = &event->next;
    }
    if (event_queue->event_head == NULL) {
        event_queue->event_tail = NULL;
        note_events_empty(event_queue);
    }
    otlock_unlock(&event_queue->event_lock);
    return count;
}

#pragma mark - Post Notifications

void outersshpriv_session_pool_post_endpoint_names(OuterSSHSessionPool *pool,
    bool known, const OuterSSHEndpointRecord *records, size_t count)
{
    otqueue_assert(pool->_queue);
    OuterSSHEndpointRecord *copy = NULL;
    if (!known) {
        count = 0;
    } else {
        copy = outerssh_endpoint_records_copy(records, count);
        if (copy == NULL) {
            known = false;
            count = 0;
        }
    }
    OuterSSHEventQueue *event_queue = pool->_event_queue;
    otlock_lock(&event_queue->event_lock);
    SSHPoolEvent *event = event_queue->event_head;
    while (event != NULL && (event->event.type != OUTERSSH_EVENT_ENDPOINT_NAMES || event->event.pool != pool))
        event = event->next;
    if (event == NULL) {
        event = calloc(1, sizeof(*event));
        if (event == NULL) {
            otlock_unlock(&event_queue->event_lock);
            free(copy);
            return;
        }
        if (event_queue->event_tail == NULL) {
            event_queue->event_head = event;
        } else {
            event_queue->event_tail->next = event;
        }
        event_queue->event_tail = event;
    }
    free(event->storage);
    event->storage = (unsigned char *)copy;
    event->event = (OuterSSHEvent){
        .type = OUTERSSH_EVENT_ENDPOINT_NAMES,
        .pool = pool,
        .endpoint_names = {.known = known, .records = copy, .count = count},
    };
    note_event_added(event_queue);
    otlock_unlock(&event_queue->event_lock);
}

void outersshpriv_session_pool_post_socket_availability(OuterSSHSessionPool *pool,
    const char *path, size_t path_length, bool available)
{
    otqueue_assert(pool->_queue);
    const void *copies[1];
    SSHPoolEvent *event = create_event((SSHEventBytes[]){{path, path_length}}, 1, copies);
    if (event == NULL) return;
    event->event = (OuterSSHEvent){
        .type = OUTERSSH_EVENT_SOCKET_AVAILABILITY,
        .pool = pool,
        .socket_availability = {.path = copies[0], .path_length = path_length, .available = available},
    };
    outersshpriv_event_post(pool->_event_queue, event);
}

void outersshpriv_session_pool_post_connection_failure(OuterSSHSessionPool *pool,
    const void *frontend, const char *host, size_t host_length, uint16_t port,
    const char *socket_path, size_t socket_path_length, OuterSSHError error)
{
    otqueue_assert(pool->_queue);
    const void *copies[4];
    SSHEventBytes parts[] = {
        {host, host_length},
        {socket_path, socket_path_length},
        {error.message, error.message_length},
        {error.ssh_error_message, error.ssh_error_message_length},
    };
    SSHPoolEvent *event = create_event(parts, 4, copies);
    if (event == NULL) return;
    error.message = copies[2];
    error.ssh_error_message = copies[3];
    event->event = (OuterSSHEvent){
        .type = OUTERSSH_EVENT_CONNECTION_FAILED,
        .pool = pool,
        .connection_failed = {
            .frontend = frontend,
            .host = copies[0], .host_length = host_length, .port = port,
            .socket_path = copies[1], .socket_path_length = socket_path_length,
            .error = error,
        },
    };
    outersshpriv_event_post(pool->_event_queue, event);
}

#pragma mark - Ask Questions

static void resume_cancelled(const SSHPoolQuestion *question)
{
    if (question->binary_continuation != NULL)
        question->binary_continuation(question->context, SSH_QUESTION_CANCELLED, NULL, (OuterSSHError){0});
    else if (question->password_continuation != NULL)
        question->password_continuation(question->context, SSH_QUESTION_CANCELLED, NULL, 0);
    else
        question->continuation(question->context, SSH_QUESTION_CANCELLED);
}

static SSHPoolQuestion *take_question(OuterSSHSessionPool *pool, uint64_t identifier, OuterSSHEventType type)
{
    for (SSHPoolQuestion **link = &pool->_questions; *link != NULL; link = &(*link)->next) {
        SSHPoolQuestion *question = *link;
        if (question->identifier != identifier) continue;
        if (question->type != type) return NULL;
        *link = question->next;
        return question;
    }
    return NULL;
}

static void ask(OuterSSHSessionPool *pool, SSHPoolEvent *event, SSHPoolQuestion pending)
{
    SSHPoolQuestion *question = event == NULL || pool->shutdown_requested ? NULL
        : malloc(sizeof(*question));
    if (question == NULL) {
        free_events(event);
        resume_cancelled(&pending);
        return;
    }
    pending.next = pool->_questions;
    pending.identifier = ++pool->_nextQuestion;
    *question = pending;
    pool->_questions = question;
    event->question = question->identifier;
    switch (pending.type) {
    case OUTERSSH_EVENT_HOST_KEY_VALIDATION:
        event->event.host_key_validation.question = question->identifier;
        break;
    case OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED:
        event->event.sudo_password_needed.question = question->identifier;
        break;
    default:
        event->event.helper_binary_needed.question = question->identifier;
        break;
    }
    outersshpriv_event_post(pool->_event_queue, event);
}

/* An SSH host key blob begins with its algorithm name as an SSH string. */
static size_t host_key_algorithm(const void *host_key, size_t host_key_length, const char **name)
{
    const unsigned char *bytes = host_key;
    *name = "";
    if (host_key_length < 4) return 0;
    uint32_t name_length = (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 |
        (uint32_t)bytes[2] << 8 | (uint32_t)bytes[3];
    if (name_length > host_key_length - 4) return 0;
    *name = (const char *)bytes + 4;
    return name_length;
}

void outersshpriv_session_pool_ask_host_key(OuterSSHSessionPool *pool,
    const void *host_key, size_t host_key_length,
    const char *fingerprint, size_t fingerprint_length,
    SSHQuestionContinuation continuation, void *context)
{
    otqueue_assert(pool->_queue);
    const char *algorithm;
    size_t algorithm_length = host_key_algorithm(host_key, host_key_length, &algorithm);
    const void *copies[3];
    SSHEventBytes parts[] = {{host_key, host_key_length}, {algorithm, algorithm_length},
        {fingerprint, fingerprint_length}};
    SSHPoolEvent *event = create_event(parts, 3, copies);
    if (event != NULL) {
        event->event = (OuterSSHEvent){
            .type = OUTERSSH_EVENT_HOST_KEY_VALIDATION,
            .pool = pool,
            .host_key_validation = {
                .host_key = copies[0], .host_key_length = host_key_length,
                .host_key_algorithm = copies[1], .host_key_algorithm_length = algorithm_length,
                .fingerprint = copies[2], .fingerprint_length = fingerprint_length,
            },
        };
    }
    ask(pool, event, (SSHPoolQuestion){.type = OUTERSSH_EVENT_HOST_KEY_VALIDATION,
        .continuation = continuation, .context = context});
}

void outersshpriv_session_pool_ask_sudo_password(OuterSSHSessionPool *pool, const void *owner,
    const void *frontend, const char *socket_path, size_t socket_path_length,
    uint32_t attempt, OuterSSHError error,
    SSHSudoPasswordContinuation continuation, void *context)
{
    otqueue_assert(pool->_queue);
    const void *copies[3];
    SSHEventBytes parts[] = {
        {socket_path, socket_path_length},
        {error.message, error.message ? error.message_length : 0},
        {error.ssh_error_message, error.ssh_error_message ? error.ssh_error_message_length : 0},
    };
    SSHPoolEvent *event = create_event(parts, 3, copies);
    if (event != NULL) {
        error.message = copies[1];
        error.message_length = parts[1].length;
        error.ssh_error_message = copies[2];
        error.ssh_error_message_length = parts[2].length;
        event->event = (OuterSSHEvent){
            .type = OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED,
            .pool = pool,
            .sudo_password_needed = {
                .frontend = frontend,
                .socket_path = copies[0], .socket_path_length = socket_path_length,
                .attempt = attempt,
                .error = error,
            },
        };
    }
    ask(pool, event, (SSHPoolQuestion){.type = OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED, .owner = owner,
        .password_continuation = continuation, .context = context});
}

void outersshpriv_session_pool_ask_bridge_binary(OuterSSHSessionPool *pool,
    const char *name, size_t name_length,
    SSHBridgeBinaryContinuation continuation, void *context)
{
    otqueue_assert(pool->_queue);
    const void *copies[1];
    SSHPoolEvent *event = create_event((SSHEventBytes[]){{name, name_length}}, 1, copies);
    if (event != NULL) {
        event->event = (OuterSSHEvent){
            .type = OUTERSSH_EVENT_HELPER_BINARY_NEEDED,
            .pool = pool,
            .helper_binary_needed = {.platform = copies[0], .platform_length = name_length},
        };
    }
    ask(pool, event, (SSHPoolQuestion){.type = OUTERSSH_EVENT_HELPER_BINARY_NEEDED,
        .binary_continuation = continuation, .context = context});
}

void outersshpriv_session_pool_cancel_questions(OuterSSHSessionPool *pool, const void *owner)
{
    otqueue_assert(pool->_queue);
    SSHPoolQuestion **link = &pool->_questions;
    while (*link != NULL) {
        SSHPoolQuestion *question = *link;
        if (owner != NULL && question->owner != owner) {
            link = &question->next;
            continue;
        }
        *link = question->next;
        if (!remove_pending_question_event(pool, question->identifier)) {
            SSHPoolEvent *event = calloc(1, sizeof(*event));
            if (event != NULL) {
                event->event = (OuterSSHEvent){
                    .type = OUTERSSH_EVENT_QUESTION_CANCELLED,
                    .pool = pool,
                    .question_cancelled = {.question = question->identifier},
                };
                outersshpriv_event_post(pool->_event_queue, event);
            }
        }
        resume_cancelled(question);
        free(question);
    }
}

#pragma mark - Answer Questions

typedef struct {
    OuterSSHSessionPool *pool;
    uint64_t question;
    OuterSSHEventType type;
    bool accepted;
    SSHBridgeBinary *binary;
    char *password;
    size_t password_length;
    OuterSSHError error;
    char *error_storage;
} AnswerContext;

static void free_password(char *password, size_t length)
{
    if (password == NULL) return;
    volatile char *bytes = password;
    for (size_t i = 0; i < length; i++) bytes[i] = 0;
    free(password);
}

static void deliver_answer(void *context);

static void post_answer(AnswerContext answer)
{
    AnswerContext *answer_context = malloc(sizeof(*answer_context));
    if (answer_context == NULL) {
        outersshpriv_bridge_binary_release(answer.binary);
        free_password(answer.password, answer.password_length);
        free(answer.error_storage);
        return;
    }
    *answer_context = answer;
    otqueue_async(answer.pool->_queue, answer_context, deliver_answer);
}

static void answer(OuterSSHSessionPool *pool, uint64_t question, OuterSSHEventType type, bool accepted)
{
    post_answer((AnswerContext){.pool = pool, .question = question, .type = type, .accepted = accepted});
}

static void deliver_answer(void *context)
{
    AnswerContext answer_context = *(AnswerContext *)context;
    free(context);
    SSHPoolQuestion *question = take_question(answer_context.pool, answer_context.question, answer_context.type);
    SSHQuestionAnswer answer = answer_context.accepted ? SSH_QUESTION_ACCEPTED : SSH_QUESTION_DECLINED;
    if (question == NULL) {
        outersshpriv_bridge_binary_release(answer_context.binary);
        free_password(answer_context.password, answer_context.password_length);
    } else if (question->binary_continuation != NULL) {
        question->binary_continuation(question->context, answer, answer_context.binary, answer_context.error);
    } else if (question->password_continuation != NULL) {
        question->password_continuation(question->context, answer,
            answer_context.password, answer_context.password_length);
    } else {
        question->continuation(question->context, answer);
    }
    free(question);
    free(answer_context.error_storage);
}

void outerssh_session_pool_answer_host_key(OuterSSHSessionPool *pool, uint64_t question, bool trusted)
{
    answer(pool, question, OUTERSSH_EVENT_HOST_KEY_VALIDATION, trusted);
}

void outerssh_session_pool_provide_sudo_password(OuterSSHSessionPool *pool, uint64_t question,
    const char *password, size_t password_length)
{
    AnswerContext answer = {.pool = pool, .question = question, .type = OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED};
    answer.password = (password == NULL && password_length != 0) || password_length == SIZE_MAX
        ? NULL : malloc(password_length + 1);
    if (answer.password == NULL) {
        outerssh_session_pool_decline_sudo_password(pool, question);
        return;
    }
    if (password_length != 0) memcpy(answer.password, password, password_length);
    answer.password[password_length] = 0;
    answer.password_length = password_length;
    answer.accepted = true;
    post_answer(answer);
}

void outerssh_session_pool_decline_sudo_password(OuterSSHSessionPool *pool, uint64_t question)
{
    answer(pool, question, OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED, false);
}

void outerssh_session_pool_provide_helper_binary(OuterSSHSessionPool *pool, uint64_t question,
    OuterSSHFileHandle file, uint64_t offset, uint64_t length)
{
    AnswerContext answer = {.pool = pool, .question = question, .type = OUTERSSH_EVENT_HELPER_BINARY_NEEDED};
    answer.binary = outersshpriv_bridge_binary_map(file, offset, length, &answer.error, &answer.error_storage);
    answer.accepted = answer.binary != NULL;
    post_answer(answer);
}

void outerssh_session_pool_decline_helper_binary(OuterSSHSessionPool *pool, uint64_t question,
    OuterSSHError error)
{
    if (error.domain == OUTERSSH_ERROR_NONE) {
        static const char message[] = "The application did not provide the packaged socket-bridge binary.";
        error = (OuterSSHError){
            .domain = OUTERSSH_ERROR_HELPER_INSTALLER,
            .code = OUTERSSH_HELPER_INSTALLER_ERROR_MISSING_PACKAGED_BINARY,
            .message = message, .message_length = sizeof(message) - 1,
        };
    }
    AnswerContext answer = {.pool = pool, .question = question, .type = OUTERSSH_EVENT_HELPER_BINARY_NEEDED};
    answer.error = outerssh_error_copy(error, &answer.error_storage);
    post_answer(answer);
}

#pragma mark - Dispose

void outersshpriv_session_pool_dispose_events(OuterSSHSessionPool *pool)
{
    assert(pool->_questions == NULL);
    (void)pool;
}

void outersshpriv_event_queue_dispose_events(OuterSSHEventQueue *event_queue)
{
    free_events(event_queue->event_head);
    free_events(event_queue->delivered_events);
    event_queue->event_head = event_queue->event_tail = event_queue->delivered_events = NULL;
}
