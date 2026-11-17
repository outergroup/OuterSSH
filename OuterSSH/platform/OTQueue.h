#ifndef OTQUEUE_H
#define OTQUEUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The subset of Dispatch that OuterSSH's engine uses. Apple platforms use
 * Dispatch itself. Windows implements it on the system thread pool
 * (OTQueueWindows.c), and Linux and Android on an epoll thread and a small
 * pool of worker threads that the library owns (OTQueueLinux.c).
 *
 * Serial queues run work one item at a time in submission order, without
 * thread affinity. Each pool has a control queue, and each SSH session has a
 * queue of its own, so sessions run in parallel. otqueue_create gives a new
 * queue the quality of service of peer, or with a NULL peer, of the calling
 * thread where the platform has one, lowering user-interactive to
 * user-initiated.
 * otqueue_async_background runs independent, potentially blocking work on a
 * shared pool, without a queue identity or ordering guarantee.
 * Queue-specific values are borrowed; setting NULL removes a binding.
 * Zero-initialize an otonce_t and keep it alive for all callers of otonce.
 * Allocation failure while submitting work is fatal, never silent work loss.
 *
 * Queues and sources are reference counted. Creation returns an owned
 * reference, pending work retains its queue, and each source retains its
 * queue.
 *
 * Sources target serial queues. Creation returns NULL on resource failure.
 * Set context and handlers before activation. Activate once (an initial resume
 * also activates). Subsequent suspend and resume are balanced and pause
 * delivery, not the underlying timer schedule. Readiness and timer
 * notifications coalesce; they are not event counts. Balance suspensions
 * before cancellation. After native monitoring and queued deliveries finish,
 * the cancellation handler runs on the source queue. Only then may its
 * context be freed; close a socket after all its sources cancel. Cancel each
 * source before releasing its last owned reference.
 *
 * Times are opaque monotonic deadlines. Timer intervals are positive
 * nanoseconds, and leeway is nanoseconds. OTTIME_FOREVER selects a one-shot
 * interval or disables a timer deadline. Resetting a timer discards pending
 * expirations.
 */

#if defined(__APPLE__)
#include <dispatch/dispatch.h>

typedef dispatch_queue_t otqueue_t;
typedef dispatch_source_t otsource_t;
typedef dispatch_source_type_t otsource_type_t;
typedef dispatch_once_t otonce_t;
typedef dispatch_time_t ottime_t;

#define OTSOURCE_TYPE_READ DISPATCH_SOURCE_TYPE_READ
#define OTSOURCE_TYPE_WRITE DISPATCH_SOURCE_TYPE_WRITE
#define OTSOURCE_TYPE_TIMER DISPATCH_SOURCE_TYPE_TIMER
#define OTTIME_NOW DISPATCH_TIME_NOW
#define OTTIME_FOREVER DISPATCH_TIME_FOREVER

static inline otqueue_t otqueue_create(otqueue_t peer, const char *label)
{
    dispatch_qos_class_t qos = peer == NULL ? qos_class_self() : dispatch_queue_get_qos_class(peer, NULL);
    if (qos == QOS_CLASS_UNSPECIFIED) qos = QOS_CLASS_DEFAULT;
    if (qos == QOS_CLASS_USER_INTERACTIVE) qos = QOS_CLASS_USER_INITIATED;
    return dispatch_queue_create(label, dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, qos, 0));
}
#define otqueue_retain dispatch_retain
#define otqueue_release dispatch_release
static inline void otqueue_async(otqueue_t queue, void *context, void (*function)(void *))
{
    dispatch_async_f(queue, context, function);
}
void otqueue_async_background(void *context, void (*function)(void *));
static inline void otqueue_assert(otqueue_t queue) { dispatch_assert_queue(queue); }
static inline void otqueue_set_specific(otqueue_t queue, const void *key, void *value)
{
    dispatch_queue_set_specific(queue, key, value, NULL);
}
static inline void *otqueue_get_specific(const void *key) { return dispatch_get_specific(key); }

static inline otsource_t otsource_create(otsource_type_t type, uintptr_t handle, otqueue_t queue)
{
    return dispatch_source_create(type, handle, 0, queue);
}
#define otsource_retain dispatch_retain
#define otsource_release dispatch_release
static inline void otsource_set_context(otsource_t source, void *context) { dispatch_set_context(source, context); }
static inline void otsource_set_event_handler(otsource_t source, void (*handler)(void *))
{
    dispatch_source_set_event_handler_f(source, handler);
}
static inline void otsource_set_cancel_handler(otsource_t source, void (*handler)(void *))
{
    dispatch_source_set_cancel_handler_f(source, handler);
}
static inline void otsource_set_timer(otsource_t source, ottime_t start, uint64_t interval, uint64_t leeway)
{
    dispatch_source_set_timer(source, start, interval, leeway);
}
static inline void otsource_activate(otsource_t source) { dispatch_activate(source); }
static inline void otsource_suspend(otsource_t source) { dispatch_suspend(source); }
static inline void otsource_resume(otsource_t source) { dispatch_resume(source); }
static inline void otsource_cancel(otsource_t source) { dispatch_source_cancel(source); }

static inline ottime_t ottime(ottime_t base, int64_t delta) { return dispatch_time(base, delta); }
static inline void otonce(otonce_t *once, void *context, void (*function)(void *))
{
    dispatch_once_f(once, context, function);
}
#else

typedef struct OTQueue *otqueue_t;
typedef struct OTSource *otsource_t;
typedef enum {
    OTSOURCE_TYPE_READ,
    OTSOURCE_TYPE_WRITE,
    OTSOURCE_TYPE_TIMER,
} otsource_type_t;
typedef uint64_t ottime_t;

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
typedef INIT_ONCE otonce_t;
#else
#include <stdatomic.h>
typedef atomic_int otonce_t;
#endif

#define OTTIME_NOW UINT64_C(0)
#define OTTIME_FOREVER UINT64_MAX
#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC UINT64_C(1000000000)
#endif
#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC UINT64_C(1000000)
#endif
#ifndef NSEC_PER_USEC
#define NSEC_PER_USEC UINT64_C(1000)
#endif

otqueue_t otqueue_create(otqueue_t peer, const char *label);
void otqueue_retain(otqueue_t queue);
void otqueue_release(otqueue_t queue);
void otqueue_async(otqueue_t queue, void *context, void (*function)(void *));
void otqueue_async_background(void *context, void (*function)(void *));
void otqueue_assert(otqueue_t queue);
void otqueue_set_specific(otqueue_t queue, const void *key, void *value);
void *otqueue_get_specific(const void *key);

otsource_t otsource_create(otsource_type_t type, uintptr_t handle, otqueue_t queue);
void otsource_retain(otsource_t source);
void otsource_release(otsource_t source);
void otsource_set_context(otsource_t source, void *context);
void otsource_set_event_handler(otsource_t source, void (*handler)(void *));
void otsource_set_cancel_handler(otsource_t source, void (*handler)(void *));
void otsource_set_timer(otsource_t source, ottime_t start, uint64_t interval, uint64_t leeway);
void otsource_activate(otsource_t source);
void otsource_suspend(otsource_t source);
void otsource_resume(otsource_t source);
void otsource_cancel(otsource_t source);

ottime_t ottime(ottime_t base, int64_t delta);
void otonce(otonce_t *once, void *context, void (*function)(void *));
#endif

#endif
