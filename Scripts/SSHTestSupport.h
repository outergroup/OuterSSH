#ifndef SSH_TEST_SUPPORT_H
#define SSH_TEST_SUPPORT_H
#include "platform/OTSocket.h"
#include "platform/OTLock.h"
#include "platform/OTQueue.h"
#include <assert.h>

#include <limits.h>
#include <stdlib.h>
#include <time.h>
#if defined(_WIN32)
#include <process.h>
#else
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
typedef HANDLE ssh_test_semaphore_t;
#else
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    long count;
} *ssh_test_semaphore_t;
#endif

static inline ssh_test_semaphore_t ssh_test_semaphore_create(long value)
{
#if defined(_WIN32)
    return CreateSemaphoreW(NULL, value, LONG_MAX, NULL);
#else
    ssh_test_semaphore_t semaphore = calloc(1, sizeof(*semaphore));
    if (semaphore == NULL) return NULL;
    if (pthread_mutex_init(&semaphore->mutex, NULL) != 0 || pthread_cond_init(&semaphore->condition, NULL) != 0) abort();
    semaphore->count = value;
    return semaphore;
#endif
}
static inline void ssh_test_semaphore_destroy(ssh_test_semaphore_t semaphore)
{
#if defined(_WIN32)
    if (!CloseHandle(semaphore)) abort();
#else
    pthread_cond_destroy(&semaphore->condition);
    pthread_mutex_destroy(&semaphore->mutex);
    free(semaphore);
#endif
}
static inline void ssh_test_semaphore_signal(ssh_test_semaphore_t semaphore)
{
#if defined(_WIN32)
    if (!ReleaseSemaphore(semaphore, 1, NULL)) abort();
#else
    pthread_mutex_lock(&semaphore->mutex);
    semaphore->count++;
    pthread_cond_signal(&semaphore->condition);
    pthread_mutex_unlock(&semaphore->mutex);
#endif
}
/* Returns zero once signaled, nonzero after the relative timeout. */
static inline long ssh_test_semaphore_wait(ssh_test_semaphore_t semaphore, uint64_t timeout_nanoseconds)
{
#if defined(_WIN32)
    uint64_t milliseconds = timeout_nanoseconds / NSEC_PER_MSEC + (timeout_nanoseconds % NSEC_PER_MSEC != 0);
    DWORD timeout = timeout_nanoseconds == UINT64_MAX ? INFINITE : milliseconds >= INFINITE ? INFINITE - 1 : (DWORD)milliseconds;
    DWORD result = WaitForSingleObject(semaphore, timeout);
    if (result != WAIT_OBJECT_0 && result != WAIT_TIMEOUT) abort();
    return result == WAIT_OBJECT_0 ? 0 : 1;
#else
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) abort();
    bool forever = timeout_nanoseconds > INT64_MAX;
    if (!forever) {
        uint64_t nanoseconds = (uint64_t)deadline.tv_nsec + timeout_nanoseconds % NSEC_PER_SEC;
        deadline.tv_sec += (time_t)(timeout_nanoseconds / NSEC_PER_SEC + nanoseconds / NSEC_PER_SEC);
        deadline.tv_nsec = (long)(nanoseconds % NSEC_PER_SEC);
    }
    pthread_mutex_lock(&semaphore->mutex);
    int status = 0;
    while (semaphore->count == 0 && status == 0) {
        status = forever ? pthread_cond_wait(&semaphore->condition, &semaphore->mutex)
            : pthread_cond_timedwait(&semaphore->condition, &semaphore->mutex, &deadline);
    }
    long result = semaphore->count == 0 ? 1 : 0;
    if (result == 0) semaphore->count--;
    pthread_mutex_unlock(&semaphore->mutex);
    return result;
#endif
}

typedef struct {
    void *context;
    void (*function)(void *);
    ssh_test_semaphore_t done;
} SSHTestSync;
static inline void ssh_test_sync_completed(void *context)
{
    SSHTestSync *call = context;
    call->function(call->context);
    ssh_test_semaphore_signal(call->done);
}
/* Wait for queued test setup or inspection; never call from the target queue. */
static inline void ssh_test_sync(otqueue_t queue, void *context, void (*function)(void *))
{
    SSHTestSync call = {context, function, ssh_test_semaphore_create(0)};
    assert(call.done);
    otqueue_async(queue, &call, ssh_test_sync_completed);
    assert(ssh_test_semaphore_wait(call.done, 20 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(call.done);
}

static inline uint64_t ssh_test_monotonic_milliseconds(void)
{
#if defined(_WIN32)
    LARGE_INTEGER ticks, frequency;
    if (!QueryPerformanceCounter(&ticks) || !QueryPerformanceFrequency(&frequency)) abort();
    return (uint64_t)(ticks.QuadPart / frequency.QuadPart) * 1000 +
        (uint64_t)(ticks.QuadPart % frequency.QuadPart) * 1000 / (uint64_t)frequency.QuadPart;
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / NSEC_PER_MSEC;
#endif
}

static inline int ssh_test_socket_pair(otsocket_t pair[2])
{
#if defined(_WIN32)
    otsocket_t listener = otsocket_create(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    pair[0] = pair[1] = -1;
    if (otsocket_bind(listener, (struct sockaddr *)&address, length) != 0 ||
        otsocket_listen(listener, 1) != 0 ||
        otsocket_getsockname(listener, (struct sockaddr *)&address, &length) != 0) goto failed;
    pair[0] = otsocket_create(AF_INET, SOCK_STREAM, 0);
    if (pair[0] < 0 || otsocket_connect(pair[0], (struct sockaddr *)&address, length) != 0) goto failed;
    pair[1] = otsocket_accept(listener, NULL, NULL);
    if (pair[1] < 0) goto failed;
    otsocket_close(listener);
    return 0;
failed:
    if (pair[0] >= 0) otsocket_close(pair[0]);
    if (pair[1] >= 0) otsocket_close(pair[1]);
    otsocket_close(listener);
    return -1;
#else
    return socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
#endif
}
static inline bool ssh_test_socket_is_open(otsocket_t socket)
{
    int type;
    socklen_t length = sizeof(type);
    return otsocket_getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &length) == 0;
}
static inline void ssh_test_sleep_milliseconds(unsigned milliseconds)
{
#if defined(_WIN32)
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
#endif
}

typedef struct {
    void (*function)(void *);
    void *context;
} SSHTestThread;

#if defined(_WIN32)
static unsigned __stdcall ssh_test_thread_main(void *pointer)
#else
static void *ssh_test_thread_main(void *pointer)
#endif
{
    SSHTestThread thread = *(SSHTestThread *)pointer;
    free(pointer);
    thread.function(thread.context);
#if defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

/* Runs function on a new detached thread. */
static inline void ssh_test_thread_start(void (*function)(void *), void *context)
{
    SSHTestThread *thread = malloc(sizeof(*thread));
    if (thread == NULL) abort();
    *thread = (SSHTestThread){function, context};
#if defined(_WIN32)
    uintptr_t handle = _beginthreadex(NULL, 0, ssh_test_thread_main, thread, 0, NULL);
    if (handle == 0) abort();
    CloseHandle((HANDLE)handle);
#else
    pthread_t handle;
    if (pthread_create(&handle, NULL, ssh_test_thread_main, thread) != 0) abort();
    pthread_detach(handle);
#endif
}

static void ssh_test_initialize_sockets(void *context)
{
    (void)context;
    if (otsocket_initialize() != 0) abort();
}

/* Test queues run on the platform's runtime, like the library's own. Tests
 * drive them from the main thread through otqueue_async and ssh_test_sync. */
static inline otqueue_t ssh_test_queue_create(const char *name)
{
    static otonce_t once;
    otonce(&once, NULL, ssh_test_initialize_sockets);
    otqueue_t queue = otqueue_create(NULL, name);
    assert(queue != NULL);
    return queue;
}

#if defined(__OBJC__) && OS_OBJECT_USE_OBJC
#define SSH_TEST_QUEUE_POINTER(queue) ((__bridge void *)(queue))
#else
#define SSH_TEST_QUEUE_POINTER(queue) ((void *)(queue))
#endif

static inline otqueue_t ssh_test_control_queue_create(const char *name)
{
    otqueue_t queue = ssh_test_queue_create(name);
    otqueue_set_specific(queue, SSH_TEST_QUEUE_POINTER(queue), SSH_TEST_QUEUE_POINTER(queue));
    return queue;
}

#if defined(__OBJC__)
/* Calls the block without retaining it: copying would move the caller's
 * __block variables away from pointers the test already holds. */
static void ssh_test_run_block(void *context)
{
    __unsafe_unretained void (^block)(void) = (__bridge void (^)(void))context;
    block();
}

/* Runs block on queue and waits; never call from the target queue. */
static inline void ssh_test_sync_block(otqueue_t queue, void (^block)(void))
{
    ssh_test_sync(queue, (__bridge void *)block, ssh_test_run_block);
}
#endif
#endif
