#if defined(__linux__)
#include "OTQueue.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

/* OTQueue on Linux and Android, which have no system thread pool. The library
 * owns one epoll thread, which watches sockets and timers, and a few worker
 * threads, which drain serial queues. They start with the first queue and
 * run for the rest of the process. */

#define WORKER_COUNT 4
/* Work items a worker runs from one queue before moving to the next. */
#define DRAIN_LIMIT 64

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

/* The lock guards the work list, running, and specifics. */
struct OTQueue {
    Object object;
    pthread_mutex_t lock;
    Work *head;
    Work *tail;
    bool running;
    QueueSpecific *specifics;
    otqueue_t next_runnable;
};

typedef enum { WATCH_WAKE, WATCH_SOCKET, WATCH_TIMER } WatchKind;

/* An epoll registration: one per socket, shared by its sources, or one per
 * timer. Registrations are one-shot; each report disarms the watch until it
 * is armed again with the interest of the sources ready for more. */
typedef struct Watch {
    WatchKind kind;
    int descriptor;
    otsource_t sources;
    bool removed;
    struct Watch *next;
} Watch;

struct OTSource {
    Object object;
    otsource_type_t type;
    otqueue_t queue;
    void *context;
    void (*event_handler)(void *);
    void (*cancel_handler)(void *);
    bool active;
    unsigned suspensions;
    bool cancelled;
    bool pending;
    bool delivery_queued;
    Watch *watch;
    otsource_t next_on_watch;
    ottime_t deadline;
    uint64_t interval;
};

typedef struct {
    void *context;
    void (*function)(void *);
} BackgroundWork;

/* The registry lock guards every source and watch, the socket list, and the
 * removed list. The epoll thread may still hold a watch from a batch it
 * harvested before the watch was removed, so it frees removed watches itself,
 * before its next wait. The run lock guards the run list. */
static struct {
    otonce_t once;
    int epoll;
    Watch wake;
    pthread_mutex_t registry_lock;
    Watch *sockets;
    Watch *removed;
    pthread_mutex_t run_lock;
    pthread_cond_t runnable;
    otqueue_t run_head;
    otqueue_t run_tail;
} loop = {
    .registry_lock = PTHREAD_MUTEX_INITIALIZER,
    .run_lock = PTHREAD_MUTEX_INITIALIZER,
    .runnable = PTHREAD_COND_INITIALIZER,
};

static _Thread_local otqueue_t current_queue;

static void start_loop(void *context);
static void make_runnable(otqueue_t queue);
static void *run_worker(void *context);
static void *run_epoll(void *context);
static void arm_socket(Watch *watch);
static void arm_timer(otsource_t source);
static void enable_source(otsource_t source);
static void schedule_event(otsource_t source);
static void deliver_event(void *context);
static void remove_watch(Watch *watch);
static void finish_cancel(void *context);
static void destroy_queue(void *pointer);
static void destroy_source(void *pointer);

#pragma mark - Start the Threads

static void start_thread(void *(*function)(void *))
{
    pthread_attr_t attributes;
    pthread_t thread;
    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) != 0 ||
        pthread_create(&thread, &attributes, function, NULL) != 0) abort();
    pthread_attr_destroy(&attributes);
}

static void start_loop(void *context)
{
    (void)context;
    loop.epoll = epoll_create1(EPOLL_CLOEXEC);
    loop.wake = (Watch){.kind = WATCH_WAKE, .descriptor = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)};
    struct epoll_event event = {.events = EPOLLIN, .data.ptr = &loop.wake};
    if (loop.epoll < 0 || loop.wake.descriptor < 0 ||
        epoll_ctl(loop.epoll, EPOLL_CTL_ADD, loop.wake.descriptor, &event) != 0) abort();
    start_thread(run_epoll);
    for (unsigned i = 0; i < WORKER_COUNT; i++) start_thread(run_worker);
}

static void wake_epoll_thread(void)
{
    uint64_t one = 1;
    ssize_t written = write(loop.wake.descriptor, &one, sizeof(one));
    (void)written;
}

#pragma mark - Create a Serial Queue and Run Work

otqueue_t otqueue_create(otqueue_t peer, const char *label)
{
    (void)peer; (void)label;
    otonce(&loop.once, NULL, start_loop);
    otqueue_t queue = calloc(1, sizeof(*queue));
    if (queue == NULL) return NULL;
    atomic_init(&queue->object.references, 1);
    queue->object.destroy = destroy_queue;
    if (pthread_mutex_init(&queue->lock, NULL) != 0) {
        free(queue);
        return NULL;
    }
    return queue;
}

void otqueue_async(otqueue_t queue, void *context, void (*function)(void *))
{
    Work *work = malloc(sizeof(*work));
    if (work == NULL) abort();
    *work = (Work){.context = context, .function = function};
    pthread_mutex_lock(&queue->lock);
    if (queue->tail != NULL) queue->tail->next = work;
    else queue->head = work;
    queue->tail = work;
    bool start = !queue->running;
    queue->running = true;
    pthread_mutex_unlock(&queue->lock);
    if (start) {
        otqueue_retain(queue);
        make_runnable(queue);
    }
}

static void make_runnable(otqueue_t queue)
{
    pthread_mutex_lock(&loop.run_lock);
    queue->next_runnable = NULL;
    if (loop.run_tail != NULL) loop.run_tail->next_runnable = queue;
    else loop.run_head = queue;
    loop.run_tail = queue;
    pthread_cond_signal(&loop.runnable);
    pthread_mutex_unlock(&loop.run_lock);
}

/* A running queue is on the run list or being drained, never both. */
static void drain_queue(otqueue_t queue)
{
    otqueue_t previous = current_queue;
    current_queue = queue;
    for (unsigned count = 0; count < DRAIN_LIMIT; count++) {
        pthread_mutex_lock(&queue->lock);
        Work *work = queue->head;
        if (work != NULL) {
            queue->head = work->next;
            if (queue->head == NULL) queue->tail = NULL;
        }
        pthread_mutex_unlock(&queue->lock);
        if (work == NULL) break;
        work->function(work->context);
        free(work);
    }
    current_queue = previous;
    pthread_mutex_lock(&queue->lock);
    queue->running = queue->head != NULL;
    bool again = queue->running;
    pthread_mutex_unlock(&queue->lock);
    if (again) make_runnable(queue);
    else otqueue_release(queue);
}

static void *run_worker(void *context)
{
    (void)context;
    for (;;) {
        pthread_mutex_lock(&loop.run_lock);
        while (loop.run_head == NULL) pthread_cond_wait(&loop.runnable, &loop.run_lock);
        otqueue_t queue = loop.run_head;
        loop.run_head = queue->next_runnable;
        if (loop.run_head == NULL) loop.run_tail = NULL;
        pthread_mutex_unlock(&loop.run_lock);
        drain_queue(queue);
    }
}

#pragma mark - Queue Identity and Storage

void otqueue_assert(otqueue_t queue)
{
    if (current_queue != queue) abort();
}

void otqueue_set_specific(otqueue_t queue, const void *key, void *value)
{
    pthread_mutex_lock(&queue->lock);
    QueueSpecific **link = &queue->specifics;
    while (*link != NULL && (*link)->key != key) link = &(*link)->next;
    QueueSpecific *previous = *link;
    if (value != NULL) {
        QueueSpecific *specific = malloc(sizeof(*specific));
        if (specific == NULL) abort();
        *specific = (QueueSpecific){.next = previous != NULL ? previous->next : NULL, .key = key, .value = value};
        *link = specific;
    } else if (previous != NULL) {
        *link = previous->next;
    }
    pthread_mutex_unlock(&queue->lock);
    free(previous);
}

void *otqueue_get_specific(const void *key)
{
    otqueue_t queue = current_queue;
    if (queue == NULL) return NULL;
    pthread_mutex_lock(&queue->lock);
    QueueSpecific *specific = queue->specifics;
    while (specific != NULL && specific->key != key) specific = specific->next;
    void *value = specific != NULL ? specific->value : NULL;
    pthread_mutex_unlock(&queue->lock);
    return value;
}

#pragma mark - Run Once

void otonce(otonce_t *once, void *context, void (*function)(void *))
{
    if (atomic_load_explicit(once, memory_order_acquire) == 2) return;
    int expected = 0;
    if (atomic_compare_exchange_strong(once, &expected, 1)) {
        function(context);
        atomic_store_explicit(once, 2, memory_order_release);
        return;
    }
    while (atomic_load_explicit(once, memory_order_acquire) != 2) sched_yield();
}

#pragma mark - Run Background Work

static void *run_background_work(void *pointer)
{
    BackgroundWork work = *(BackgroundWork *)pointer;
    free(pointer);
    work.function(work.context);
    return NULL;
}

/* Blocking work is rare and short, so each job gets a thread of its own. */
void otqueue_async_background(void *context, void (*function)(void *))
{
    BackgroundWork *work = malloc(sizeof(*work));
    if (work == NULL) abort();
    *work = (BackgroundWork){context, function};
    pthread_attr_t attributes;
    pthread_t thread;
    if (pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) != 0 ||
        pthread_create(&thread, &attributes, run_background_work, work) != 0) abort();
    pthread_attr_destroy(&attributes);
}

#pragma mark - Create and Configure Sources

static Watch *socket_watch(int descriptor)
{
    for (Watch *watch = loop.sockets; watch != NULL; watch = watch->next) {
        if (watch->descriptor == descriptor) return watch;
    }
    Watch *watch = calloc(1, sizeof(*watch));
    if (watch == NULL) return NULL;
    *watch = (Watch){.kind = WATCH_SOCKET, .descriptor = descriptor};
    struct epoll_event event = {.events = EPOLLONESHOT, .data.ptr = watch};
    if (epoll_ctl(loop.epoll, EPOLL_CTL_ADD, descriptor, &event) != 0) {
        free(watch);
        return NULL;
    }
    watch->next = loop.sockets;
    loop.sockets = watch;
    return watch;
}

static Watch *timer_watch(void)
{
    Watch *watch = calloc(1, sizeof(*watch));
    if (watch == NULL) return NULL;
    *watch = (Watch){.kind = WATCH_TIMER, .descriptor = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)};
    struct epoll_event event = {.events = EPOLLIN, .data.ptr = watch};
    if (watch->descriptor < 0 || epoll_ctl(loop.epoll, EPOLL_CTL_ADD, watch->descriptor, &event) != 0) {
        if (watch->descriptor >= 0) close(watch->descriptor);
        free(watch);
        return NULL;
    }
    return watch;
}

otsource_t otsource_create(otsource_type_t type, uintptr_t handle, otqueue_t queue)
{
    otsource_t source = calloc(1, sizeof(*source));
    if (source == NULL) return NULL;
    atomic_init(&source->object.references, 2);
    source->object.destroy = destroy_source;
    source->type = type;
    source->queue = queue;
    source->deadline = OTTIME_FOREVER;
    source->interval = OTTIME_FOREVER;
    pthread_mutex_lock(&loop.registry_lock);
    Watch *watch = type == OTSOURCE_TYPE_TIMER ? timer_watch() : socket_watch((int)handle);
    if (watch == NULL) {
        pthread_mutex_unlock(&loop.registry_lock);
        free(source);
        return NULL;
    }
    source->watch = watch;
    otsource_t *link = &watch->sources;
    while (*link != NULL) link = &(*link)->next_on_watch;
    *link = source;
    otqueue_retain(queue);
    pthread_mutex_unlock(&loop.registry_lock);
    return source;
}

void otsource_set_context(otsource_t source, void *context) { source->context = context; }

void otsource_set_event_handler(otsource_t source, void (*handler)(void *)) { source->event_handler = handler; }

void otsource_set_cancel_handler(otsource_t source, void (*handler)(void *)) { source->cancel_handler = handler; }

void otsource_set_timer(otsource_t source, ottime_t start, uint64_t interval, uint64_t leeway)
{
    (void)leeway;
    if (source->type != OTSOURCE_TYPE_TIMER || interval == 0) abort();
    pthread_mutex_lock(&loop.registry_lock);
    source->pending = false;
    source->deadline = start == OTTIME_NOW ? ottime(OTTIME_NOW, 0) : start;
    source->interval = interval;
    arm_timer(source);
    pthread_mutex_unlock(&loop.registry_lock);
}

ottime_t ottime(ottime_t base, int64_t delta)
{
    if (base == OTTIME_FOREVER) return base;
    if (base == OTTIME_NOW) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
        base = (uint64_t)now.tv_sec * NSEC_PER_SEC + (uint64_t)now.tv_nsec;
        if (base == OTTIME_NOW) base = 1;
    }
    if (delta < 0) {
        uint64_t magnitude = (uint64_t)(-(delta + 1)) + 1;
        return base > magnitude ? base - magnitude : 1;
    }
    return UINT64_MAX - base > (uint64_t)delta ? base + (uint64_t)delta : OTTIME_FOREVER;
}

#pragma mark - Arm Watches

static bool source_wants_events(otsource_t source)
{
    return source->active && source->suspensions == 0 && !source->cancelled && !source->delivery_queued;
}

/* Arms the socket for the sources ready for another report. With none, the
 * watch stays disarmed, so a hung-up socket cannot report endlessly. */
static void arm_socket(Watch *watch)
{
    uint32_t events = EPOLLONESHOT;
    for (otsource_t source = watch->sources; source != NULL; source = source->next_on_watch) {
        if (!source_wants_events(source)) continue;
        events |= source->type == OTSOURCE_TYPE_READ ? EPOLLIN | EPOLLRDHUP : EPOLLOUT;
    }
    if (events == EPOLLONESHOT) return;
    struct epoll_event event = {.events = events, .data.ptr = watch};
    if (epoll_ctl(loop.epoll, EPOLL_CTL_MOD, watch->descriptor, &event) != 0) abort();
}

/* Timers fire once at their deadline; the epoll thread computes the next one. */
static void arm_timer(otsource_t source)
{
    struct itimerspec timer = {0};
    if (source->active && !source->cancelled && source->deadline != OTTIME_FOREVER) {
        timer.it_value.tv_sec = (time_t)(source->deadline / NSEC_PER_SEC);
        timer.it_value.tv_nsec = (long)(source->deadline % NSEC_PER_SEC);
    }
    if (timerfd_settime(source->watch->descriptor, TFD_TIMER_ABSTIME, &timer, NULL) != 0) abort();
}

#pragma mark - Activate and Suspend Sources

void otsource_activate(otsource_t source)
{
    pthread_mutex_lock(&loop.registry_lock);
    if (!source->active) {
        source->active = true;
        if (source->type == OTSOURCE_TYPE_TIMER) arm_timer(source);
        enable_source(source);
    }
    pthread_mutex_unlock(&loop.registry_lock);
}

void otsource_suspend(otsource_t source)
{
    pthread_mutex_lock(&loop.registry_lock);
    source->suspensions++;
    pthread_mutex_unlock(&loop.registry_lock);
}

void otsource_resume(otsource_t source)
{
    pthread_mutex_lock(&loop.registry_lock);
    if (source->suspensions != 0) {
        source->suspensions--;
    } else if (!source->active) {
        source->active = true;
        if (source->type == OTSOURCE_TYPE_TIMER) arm_timer(source);
    } else {
        abort();
    }
    enable_source(source);
    pthread_mutex_unlock(&loop.registry_lock);
}

static void enable_source(otsource_t source)
{
    if (source->pending) schedule_event(source);
    if (source->type != OTSOURCE_TYPE_TIMER && !source->cancelled) arm_socket(source->watch);
}

#pragma mark - Deliver Socket and Timer Events

static void free_removed_watches(void)
{
    pthread_mutex_lock(&loop.registry_lock);
    Watch *removed = loop.removed;
    loop.removed = NULL;
    pthread_mutex_unlock(&loop.registry_lock);
    while (removed != NULL) {
        Watch *next = removed->next;
        free(removed);
        removed = next;
    }
}

static void socket_signaled(Watch *watch, uint32_t events)
{
    bool failed = (events & (EPOLLERR | EPOLLHUP)) != 0;
    for (otsource_t source = watch->sources; source != NULL; source = source->next_on_watch) {
        uint32_t wanted = source->type == OTSOURCE_TYPE_READ ? EPOLLIN | EPOLLRDHUP : EPOLLOUT;
        if (failed || (events & wanted) != 0) schedule_event(source);
    }
    arm_socket(watch);
}

static void timer_fired(Watch *watch)
{
    uint64_t expirations;
    while (read(watch->descriptor, &expirations, sizeof(expirations)) > 0) {
    }
    otsource_t source = watch->sources;
    ottime_t now = ottime(OTTIME_NOW, 0);
    if (source->cancelled || now < source->deadline) return;
    schedule_event(source);
    if (source->interval == OTTIME_FOREVER) {
        source->deadline = OTTIME_FOREVER;
    } else {
        uint64_t delay = source->interval - (now - source->deadline) % source->interval;
        source->deadline = UINT64_MAX - now > delay ? now + delay : OTTIME_FOREVER;
    }
    arm_timer(source);
}

static void *run_epoll(void *context)
{
    (void)context;
    struct epoll_event events[64];
    for (;;) {
        free_removed_watches();
        int count = epoll_wait(loop.epoll, events, 64, -1);
        if (count < 0) {
            if (errno == EINTR) continue;
            abort();
        }
        pthread_mutex_lock(&loop.registry_lock);
        for (int i = 0; i < count; i++) {
            Watch *watch = events[i].data.ptr;
            if (watch->kind == WATCH_WAKE) {
                uint64_t value;
                while (read(watch->descriptor, &value, sizeof(value)) > 0) {
                }
            } else if (!watch->removed) {
                if (watch->kind == WATCH_TIMER) timer_fired(watch);
                else socket_signaled(watch, events[i].events);
            }
        }
        pthread_mutex_unlock(&loop.registry_lock);
    }
}

static void schedule_event(otsource_t source)
{
    source->pending = true;
    if (!source->active || source->suspensions != 0 || source->cancelled || source->delivery_queued) return;
    source->delivery_queued = true;
    otsource_retain(source);
    otqueue_async(source->queue, source, deliver_event);
}

/* A socket watch rearms after the delivery, so a socket that is still ready
 * reports again: readiness is level-triggered, as in Dispatch. */
static void deliver_event(void *context)
{
    otsource_t source = context;
    pthread_mutex_lock(&loop.registry_lock);
    source->delivery_queued = false;
    bool run = source->pending && !source->cancelled && source->active && source->suspensions == 0;
    if (run) source->pending = false;
    pthread_mutex_unlock(&loop.registry_lock);
    if (run && source->event_handler != NULL) source->event_handler(source->context);
    pthread_mutex_lock(&loop.registry_lock);
    if (source->type != OTSOURCE_TYPE_TIMER && !source->cancelled) arm_socket(source->watch);
    pthread_mutex_unlock(&loop.registry_lock);
    otsource_release(source);
}

#pragma mark - Cancel Sources

/* Removing a watch from epoll stops its reports, so the cancellation handler
 * can follow at once, after deliveries already queued. */
void otsource_cancel(otsource_t source)
{
    pthread_mutex_lock(&loop.registry_lock);
    if (source->cancelled) {
        pthread_mutex_unlock(&loop.registry_lock);
        return;
    }
    source->cancelled = true;
    Watch *watch = source->watch;
    source->watch = NULL;
    otsource_t *link = &watch->sources;
    while (*link != source) link = &(*link)->next_on_watch;
    *link = source->next_on_watch;
    source->next_on_watch = NULL;
    if (watch->sources == NULL) remove_watch(watch);
    else arm_socket(watch);
    pthread_mutex_unlock(&loop.registry_lock);
    otqueue_async(source->queue, source, finish_cancel);
}

static void remove_watch(Watch *watch)
{
    epoll_ctl(loop.epoll, EPOLL_CTL_DEL, watch->descriptor, NULL);
    if (watch->kind == WATCH_TIMER) {
        close(watch->descriptor);
    } else {
        Watch **link = &loop.sockets;
        while (*link != watch) link = &(*link)->next;
        *link = watch->next;
    }
    watch->removed = true;
    watch->next = loop.removed;
    loop.removed = watch;
    wake_epoll_thread();
}

static void finish_cancel(void *context)
{
    otsource_t source = context;
    if (source->cancel_handler != NULL) source->cancel_handler(source->context);
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
    assert(queue->head == NULL);
    pthread_mutex_destroy(&queue->lock);
    while (queue->specifics != NULL) {
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
