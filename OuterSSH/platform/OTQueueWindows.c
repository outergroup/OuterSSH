#if defined(_WIN32)
#include "OTQueue.h"

/* OTQueue on the Windows thread pool. Each serial queue drains through a
 * thread-pool work object, sockets are watched with WSAEventSelect and
 * thread-pool waits, and timers are thread-pool timers. */

#include <assert.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>

typedef struct {
    atomic_uint references;
    void (*destroy)(void *);
} Object;

typedef struct Work {
    struct Work *next;
    void *context;
    void (*function)(void *);
} Work;

typedef struct QueueSpecific {
    struct QueueSpecific *next;
    const void *key;
    void *value;
} QueueSpecific;

struct OTQueue {
    Object object;
    SRWLOCK lock;
    Work *head;
    Work *tail;
    bool running;
    PTP_WORK worker;
    QueueSpecific *specifics;
};

static _Thread_local otqueue_t current_queue;

typedef struct { void *context; void (*function)(void *); } OnceCall;

typedef struct { void *context; void (*function)(void *); } BackgroundWork;

/* The registry lock protects native callbacks and source registration. User
 * handlers always run outside it, on the source's target queue. */
typedef struct SocketWatch {
    struct SocketWatch *next;
    SOCKET socket;
    WSAEVENT event;
    PTP_WAIT wait;
    otsource_t sources;
    bool cancelled;
} SocketWatch;
struct OTSource {
    Object object;
    void *context;
    otsource_type_t type;
    otqueue_t queue;
    void (*event_handler)(void *);
    void (*cancel_handler)(void *);
    bool active;
    unsigned suspensions;
    bool cancelled;
    bool pending;
    bool delivered;
    bool has_delivered_event;
    SocketWatch *watch;
    struct OTSource *next;
    PTP_TIMER timer;
    ottime_t deadline;
    uint64_t interval;
    uint64_t leeway;
};
static SRWLOCK registry_lock = SRWLOCK_INIT;
static SocketWatch *watches;

static void CALLBACK drain_queue(PTP_CALLBACK_INSTANCE instance, void *context, PTP_WORK worker);
static BOOL CALLBACK initialize_once(PINIT_ONCE once, void *parameter, void **result);
static void CALLBACK run_background_work(PTP_CALLBACK_INSTANCE instance, void *context);
static void arm_timer(otsource_t source);
static void enable_source(otsource_t source);
static void CALLBACK socket_signaled(PTP_CALLBACK_INSTANCE instance, void *context, PTP_WAIT wait, TP_WAIT_RESULT result);
static void CALLBACK timer_fired(PTP_CALLBACK_INSTANCE instance, void *context, PTP_TIMER timer);
static void schedule_event(otsource_t source);
static void deliver_event(void *context);
static bool socket_ready(otsource_t source);
static void cleanup_source(void *context);
static void finish_cancel(void *context);
static void destroy_queue(void *pointer);
static void destroy_source(void *pointer);

#pragma mark - Create a Serial Queue and Run Work

otqueue_t otqueue_create(otqueue_t peer, const char *label)
{
    (void)peer; (void)label;
    otqueue_t queue = calloc(1, sizeof(*queue));
    if (!queue) return NULL;
    queue->object = (Object){.references = 1, .destroy = destroy_queue};
    queue->worker = CreateThreadpoolWork(drain_queue, queue, NULL);
    if (!queue->worker) { free(queue); return NULL; }
    return queue;
}

void otqueue_async(otqueue_t queue, void *context, void (*function)(void *))
{
    Work *work = malloc(sizeof(*work));
    if (!work) abort();
    *work = (Work){.context = context, .function = function};
    AcquireSRWLockExclusive(&queue->lock);
    if (queue->tail) queue->tail->next = work;
    else queue->head = work;
    queue->tail = work;
    if (!queue->running) {
        queue->running = true;
        otqueue_retain(queue);
        SubmitThreadpoolWork(queue->worker);
    }
    ReleaseSRWLockExclusive(&queue->lock);
}

static void CALLBACK drain_queue(PTP_CALLBACK_INSTANCE instance, void *context, PTP_WORK worker)
{
    (void)instance; (void)worker;
    otqueue_t queue = context;
    otqueue_t previous = current_queue;
    current_queue = queue;
    for (unsigned count = 0; count < 64; count++) {
        AcquireSRWLockExclusive(&queue->lock);
        Work *work = queue->head;
        if (work) {
            queue->head = work->next;
            if (!queue->head) queue->tail = NULL;
        }
        ReleaseSRWLockExclusive(&queue->lock);
        if (!work) break;
        work->function(work->context);
        free(work);
    }
    current_queue = previous;
    AcquireSRWLockExclusive(&queue->lock);
    queue->running = queue->head != NULL;
    if (queue->running) {
        otqueue_retain(queue);
        SubmitThreadpoolWork(queue->worker);
    }
    ReleaseSRWLockExclusive(&queue->lock);
    otqueue_release(queue);
}

#pragma mark - Queue Identity and Storage

void otqueue_assert(otqueue_t queue) { if (current_queue != queue) abort(); }

void otqueue_set_specific(otqueue_t queue, const void *key, void *value)
{
    AcquireSRWLockExclusive(&queue->lock);
    QueueSpecific **link = &queue->specifics;
    while (*link && (*link)->key != key) link = &(*link)->next;
    QueueSpecific *previous = *link;
    if (value) {
        QueueSpecific *specific = malloc(sizeof(*specific));
        if (!specific) abort();
        *specific = (QueueSpecific){.next = previous ? previous->next : NULL,
            .key = key, .value = value};
        *link = specific;
    } else if (previous) {
        *link = previous->next;
    }
    ReleaseSRWLockExclusive(&queue->lock);
    free(previous);
}

void *otqueue_get_specific(const void *key)
{
    if (!current_queue) return NULL;
    AcquireSRWLockShared(&current_queue->lock);
    QueueSpecific *specific = current_queue->specifics;
    while (specific && specific->key != key) specific = specific->next;
    void *value = specific ? specific->value : NULL;
    ReleaseSRWLockShared(&current_queue->lock);
    return value;
}

#pragma mark - Run Once

void otonce(otonce_t *once, void *context, void (*function)(void *))
{
    OnceCall call = {context, function};
    if (!InitOnceExecuteOnce(once, initialize_once, &call, NULL)) abort();
}

static BOOL CALLBACK initialize_once(PINIT_ONCE once, void *parameter, void **result)
{
    (void)once; (void)result;
    OnceCall *call = parameter;
    call->function(call->context);
    return TRUE;
}

#pragma mark - Run Background Work

void otqueue_async_background(void *context, void (*function)(void *))
{
    BackgroundWork *work = malloc(sizeof(*work));
    if (!work) abort();
    *work = (BackgroundWork){context, function};
    if (!TrySubmitThreadpoolCallback(run_background_work, work, NULL)) {
        free(work);
        abort();
    }
}

static void CALLBACK run_background_work(PTP_CALLBACK_INSTANCE instance, void *context)
{
    BackgroundWork work = *(BackgroundWork *)context;
    free(context);
    CallbackMayRunLong(instance);
    work.function(work.context);
}

#pragma mark - Create and Configure Sources

otsource_t otsource_create(otsource_type_t type, uintptr_t handle, otqueue_t queue)
{
    otsource_t source = calloc(1, sizeof(*source));
    if (!source) return NULL;
    source->object = (Object){.references = 2, .destroy = destroy_source};
    source->type = type;
    source->queue = queue;
    source->deadline = OTTIME_FOREVER;
    source->interval = OTTIME_FOREVER;
    AcquireSRWLockExclusive(&registry_lock);
    if (type == OTSOURCE_TYPE_TIMER) {
        source->timer = CreateThreadpoolTimer(timer_fired, source, NULL);
        if (!source->timer) goto failed;
    } else {
        SocketWatch *watch = watches;
        while (watch && watch->socket != (SOCKET)handle) watch = watch->next;
        if (!watch) {
            watch = calloc(1, sizeof(*watch));
            if (!watch) goto failed;
            watch->socket = (SOCKET)handle;
            watch->event = WSACreateEvent();
            watch->wait = CreateThreadpoolWait(socket_signaled, watch, NULL);
            if (watch->event == WSA_INVALID_EVENT || !watch->wait ||
                WSAEventSelect(watch->socket, watch->event, FD_READ | FD_WRITE | FD_ACCEPT | FD_CONNECT | FD_CLOSE) != 0) {
                if (watch->wait) CloseThreadpoolWait(watch->wait);
                if (watch->event != WSA_INVALID_EVENT) WSACloseEvent(watch->event);
                free(watch);
                goto failed;
            }
            watch->next = watches;
            watches = watch;
            SetThreadpoolWait(watch->wait, watch->event, NULL);
        }
        source->watch = watch;
        source->next = watch->sources;
        watch->sources = source;
    }
    otqueue_retain(queue);
    ReleaseSRWLockExclusive(&registry_lock);
    return source;
failed:
    ReleaseSRWLockExclusive(&registry_lock);
    free(source);
    return NULL;
}

void otsource_set_context(otsource_t source, void *context) { source->context = context; }

void otsource_set_event_handler(otsource_t source, void (*handler)(void *)) { source->event_handler = handler; }

void otsource_set_cancel_handler(otsource_t source, void (*handler)(void *)) { source->cancel_handler = handler; }

void otsource_set_timer(otsource_t source, ottime_t start, uint64_t interval, uint64_t leeway)
{
    if (source->type != OTSOURCE_TYPE_TIMER || interval == 0) abort();
    AcquireSRWLockExclusive(&registry_lock);
    source->pending = false;
    source->deadline = start == OTTIME_NOW ? ottime(OTTIME_NOW, 0) : start;
    source->interval = interval;
    source->leeway = leeway;
    arm_timer(source);
    ReleaseSRWLockExclusive(&registry_lock);
}

static void arm_timer(otsource_t source)
{
    if (!source->active || source->cancelled || source->deadline == OTTIME_FOREVER) {
        SetThreadpoolTimer(source->timer, NULL, 0, 0);
        return;
    }
    uint64_t now = ottime(OTTIME_NOW, 0);
    uint64_t delay = source->deadline > now ? source->deadline - now : 1;
    LARGE_INTEGER due = {.QuadPart = -(LONGLONG)(delay / 100 + (delay % 100 != 0))};
    FILETIME time = {due.LowPart, (DWORD)due.HighPart};
    uint64_t window = source->leeway / NSEC_PER_MSEC;
    SetThreadpoolTimer(source->timer, &time, 0, window > MAXDWORD ? MAXDWORD : (DWORD)window);
}

typedef VOID (WINAPI *PreciseUnbiasedTimeFunction)(PULONGLONG);

static BOOL CALLBACK find_precise_unbiased_time(PINIT_ONCE once, void *parameter, void **result)
{
    (void)once; (void)parameter;
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    *result = kernel == NULL ? NULL : (void *)GetProcAddress(kernel, "QueryUnbiasedInterruptTimePrecise");
    return TRUE;
}

/* Interrupt time in 100-nanosecond units, excluding sleep. The precise form
 * (Windows 10) is not limited to the timer tick. */
static ULONGLONG unbiased_time(void)
{
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    void *function = NULL;
    if (!InitOnceExecuteOnce(&once, find_precise_unbiased_time, NULL, &function)) abort();
    ULONGLONG ticks;
    if (function != NULL) {
        ((PreciseUnbiasedTimeFunction)function)(&ticks);
    } else if (!QueryUnbiasedInterruptTime(&ticks)) {
        abort();
    }
    return ticks;
}

ottime_t ottime(ottime_t base, int64_t delta)
{
    if (base == OTTIME_FOREVER) return base;
    if (base == OTTIME_NOW) {
        base = unbiased_time() * 100;
        if (base == OTTIME_NOW) base = 1;
    }
    if (delta < 0) {
        uint64_t magnitude = (uint64_t)(-(delta + 1)) + 1;
        return base > magnitude ? base - magnitude : 1;
    }
    return UINT64_MAX - base > (uint64_t)delta ? base + (uint64_t)delta : OTTIME_FOREVER;
}

#pragma mark - Activate and Suspend Sources

void otsource_activate(otsource_t source)
{
    AcquireSRWLockExclusive(&registry_lock);
    if (!source->active) {
        source->active = true;
        if (source->timer) arm_timer(source);
        enable_source(source);
    }
    ReleaseSRWLockExclusive(&registry_lock);
}

void otsource_suspend(otsource_t source)
{
    AcquireSRWLockExclusive(&registry_lock);
    source->suspensions++;
    ReleaseSRWLockExclusive(&registry_lock);
}

void otsource_resume(otsource_t source)
{
    AcquireSRWLockExclusive(&registry_lock);
    if (source->suspensions) source->suspensions--;
    else if (!source->active) {
        source->active = true;
        if (source->timer) arm_timer(source);
    } else abort();
    enable_source(source);
    ReleaseSRWLockExclusive(&registry_lock);
}

static void enable_source(otsource_t source)
{
    if (source->type != OTSOURCE_TYPE_TIMER && !source->cancelled) {
        /* After its first readiness event, a resumed writer must attempt send
         * so WSAEWOULDBLOCK can arm FD_WRITE even with a full buffer. The first
         * event must reflect readiness: the socket may still be connecting. */
        if ((source->type == OTSOURCE_TYPE_WRITE && source->has_delivered_event) ||
            socket_ready(source)) schedule_event(source);
    }
    if (source->pending) schedule_event(source);
}

#pragma mark - Deliver Socket and Timer Events

static void CALLBACK socket_signaled(PTP_CALLBACK_INSTANCE instance, void *context, PTP_WAIT wait, TP_WAIT_RESULT result)
{
    (void)instance; (void)wait; (void)result;
    SocketWatch *watch = context;
    AcquireSRWLockExclusive(&registry_lock);
    if (!watch->cancelled) {
        WSANETWORKEVENTS events;
        bool failed = WSAEnumNetworkEvents(watch->socket, watch->event, &events) != 0;
        for (otsource_t source = watch->sources; source; source = source->next) {
            long mask = source->type == OTSOURCE_TYPE_READ ? FD_READ | FD_ACCEPT | FD_CLOSE : FD_WRITE | FD_CONNECT | FD_CLOSE;
            if (failed || (events.lNetworkEvents & mask)) schedule_event(source);
        }
        SetThreadpoolWait(watch->wait, watch->event, NULL);
    }
    ReleaseSRWLockExclusive(&registry_lock);
}

static void CALLBACK timer_fired(PTP_CALLBACK_INSTANCE instance, void *context, PTP_TIMER timer)
{
    (void)instance; (void)timer;
    AcquireSRWLockExclusive(&registry_lock);
    otsource_t source = context;
    uint64_t now = ottime(OTTIME_NOW, 0);
    if (!source->cancelled && now >= source->deadline) {
        schedule_event(source);
        if (source->interval == OTTIME_FOREVER) source->deadline = OTTIME_FOREVER;
        else {
            uint64_t delay = source->interval - (now - source->deadline) % source->interval;
            source->deadline = UINT64_MAX - now > delay ? now + delay : OTTIME_FOREVER;
        }
    }
    if (!source->cancelled) arm_timer(source);
    ReleaseSRWLockExclusive(&registry_lock);
}

static void schedule_event(otsource_t source)
{
    source->pending = true;
    if (!source->active || source->suspensions || source->cancelled || source->delivered) return;
    source->delivered = true;
    otsource_retain(source);
    otqueue_async(source->queue, source, deliver_event);
}

static void deliver_event(void *context)
{
    otsource_t source = context;
    AcquireSRWLockExclusive(&registry_lock);
    source->delivered = false;
    bool run = source->pending && !source->cancelled && source->active && !source->suspensions;
    if (run) {
        source->pending = false;
        source->has_delivered_event = true;
    }
    ReleaseSRWLockExclusive(&registry_lock);
    if (run && source->event_handler) source->event_handler(source->context);
    AcquireSRWLockExclusive(&registry_lock);
    if (!source->cancelled && source->active && !source->suspensions && socket_ready(source))
        schedule_event(source);
    ReleaseSRWLockExclusive(&registry_lock);
    otsource_release(source);
}

static bool socket_ready(otsource_t source)
{
    if (!source->watch) return false;
    fd_set ready, errors;
    FD_ZERO(&ready);
    FD_ZERO(&errors);
    FD_SET(source->watch->socket, &ready);
    FD_SET(source->watch->socket, &errors);
    struct timeval timeout = {0};
    return select(0, source->type == OTSOURCE_TYPE_READ ? &ready : NULL,
        source->type == OTSOURCE_TYPE_WRITE ? &ready : NULL, &errors, &timeout) != 0;
}

#pragma mark - Cancel Sources

void otsource_cancel(otsource_t source)
{
    AcquireSRWLockExclusive(&registry_lock);
    if (source->cancelled) { ReleaseSRWLockExclusive(&registry_lock); return; }
    source->cancelled = true;
    if (source->timer) SetThreadpoolTimer(source->timer, NULL, 0, 0);
    if (source->watch) {
        SocketWatch *watch = source->watch;
        otsource_t *link = &watch->sources;
        while (*link != source) link = &(*link)->next;
        *link = source->next;
        source->watch = NULL;
        if (!watch->sources) {
            watch->cancelled = true;
            SetThreadpoolWait(watch->wait, NULL, NULL);
            WSAEventSelect(watch->socket, NULL, 0);
            SocketWatch **link = &watches;
            while (*link != watch) link = &(*link)->next;
            *link = watch->next;
            source->watch = watch;
        }
    }
    ReleaseSRWLockExclusive(&registry_lock);
    otqueue_async_background(source, cleanup_source);
}

static void cleanup_source(void *context)
{
    otsource_t source = context;
    if (source->timer) {
        WaitForThreadpoolTimerCallbacks(source->timer, TRUE);
        CloseThreadpoolTimer(source->timer);
    }
    if (source->watch) {
        SocketWatch *watch = source->watch;
        WaitForThreadpoolWaitCallbacks(watch->wait, TRUE);
        CloseThreadpoolWait(watch->wait);
        WSACloseEvent(watch->event);
        free(watch);
    }
    otqueue_async(source->queue, source, finish_cancel);
}

static void finish_cancel(void *context)
{
    otsource_t source = context;
    if (source->cancel_handler) source->cancel_handler(source->context);
    otsource_release(source);
}

#pragma mark - Queue and Source Lifetime

static void retain_object(Object *object)
{
    atomic_fetch_add_explicit(&object->references, 1, memory_order_relaxed);
}

static void release_object(Object *object)
{
    if (atomic_fetch_sub_explicit(&object->references, 1, memory_order_acq_rel) == 1)
        object->destroy(object);
}

void otqueue_retain(otqueue_t queue) { retain_object(&queue->object); }

void otqueue_release(otqueue_t queue) { release_object(&queue->object); }

void otsource_retain(otsource_t source) { retain_object(&source->object); }

void otsource_release(otsource_t source) { release_object(&source->object); }

static void destroy_queue(void *pointer)
{
    otqueue_t queue = pointer;
    assert(!queue->head);
    CloseThreadpoolWork(queue->worker);
    while (queue->specifics) {
        QueueSpecific *specific = queue->specifics;
        queue->specifics = specific->next;
        free(specific);
    }
    free(queue);
}

static void destroy_source(void *pointer)
{
    otsource_t source = pointer;
    assert(source->cancelled);
    otqueue_release(source->queue);
    free(source);
}

#endif
