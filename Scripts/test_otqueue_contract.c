#include "SSHTestSupport.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { QUEUE_ITEMS = 10000, SOCKET_COUNT = 128, TRANSFER_BYTES = 4 * 1024 * 1024 };
static ssh_test_semaphore_t done;
static otqueue_t queue;
static unsigned next_item;
static char first_key, second_key;
static void ordered_work(void *context)
{
    otqueue_assert(queue);
    assert(otqueue_get_specific(&first_key) == &first_key);
    assert(otqueue_get_specific(&second_key) == &second_key);
    assert(next_item++ == (uintptr_t)context);
    if (next_item == QUEUE_ITEMS) ssh_test_semaphore_signal(done);
}
static void wait_done(void)
{
    assert(ssh_test_semaphore_wait(done, 20 * NSEC_PER_SEC) == 0);
}
typedef struct {
    otsocket_t pair[2];
    otqueue_t queue;
    otsource_t source;
    unsigned events;
} Reader;
static atomic_uint cancelled;
static void reader_cancelled(void *context)
{
    Reader *reader = context;
    otqueue_assert(reader->queue);
    assert(reader->events == 1);
    otsocket_close(reader->pair[0]);
    otsocket_close(reader->pair[1]);
    if (atomic_fetch_add(&cancelled, 1) + 1 == SOCKET_COUNT) ssh_test_semaphore_signal(done);
}
static void reader_ready(void *context)
{
    Reader *reader = context;
    otqueue_assert(reader->queue);
    char byte;
    ssize_t count = otsocket_recv(reader->pair[0], &byte, 1, 0);
    if (count < 0) { assert(errno == EAGAIN); return; }
    assert(count == 1 && byte == 'x');
    reader->events++;
    otsource_cancel(reader->source);
    otsource_release(reader->source);
}
static void setup_reader(void *context)
{
    Reader *reader = context;
    assert(ssh_test_socket_pair(reader->pair) == 0);
    assert(otsocket_set_nonblocking(reader->pair[0], true) == 0);
    reader->source = otsource_create(OTSOURCE_TYPE_READ, reader->pair[0], reader->queue);
    assert(reader->source);
    otsource_set_context(reader->source, reader);
    otsource_set_event_handler(reader->source, reader_ready);
    otsource_set_cancel_handler(reader->source, reader_cancelled);
    otsource_resume(reader->source);
    otsource_suspend(reader->source);
    assert(otsocket_send(reader->pair[1], "x", 1, 0) == 1);
}
static void resume_reader(void *context)
{
    Reader *reader = context;
    assert(reader->events == 0);
    otsource_resume(reader->source);
}

typedef struct {
    otsocket_t pair[2];
    otsource_t read_source, write_source;
    otqueue_t read_queue;
    size_t sent, received;
    bool blocked;
    unsigned cancellations;
} Transfer;
static void transfer_cancelled(void *context)
{
    Transfer *transfer = context;
    if (++transfer->cancellations == 2) ssh_test_semaphore_signal(done);
}
static void finish_transfer(void *context)
{
    Transfer *transfer = context;
    assert(transfer->sent == TRANSFER_BYTES);
    assert(transfer->blocked);
    otsource_resume(transfer->write_source);
    otsource_cancel(transfer->write_source);
    otsource_release(transfer->write_source);
}
static void read_transfer(void *context)
{
    Transfer *transfer = context;
    unsigned char bytes[8192];
    for (;;) {
        ssize_t count = otsocket_recv(transfer->pair[1], bytes, sizeof(bytes), 0);
        if (count < 0) { assert(errno == EAGAIN); return; }
        assert(count > 0);
        for (ssize_t i = 0; i < count; i++) assert(bytes[i] == 0x5a);
        transfer->received += (size_t)count;
        if (transfer->received == TRANSFER_BYTES) {
            otsource_cancel(transfer->read_source);
            otsource_release(transfer->read_source);
            otqueue_async(queue, transfer, finish_transfer);
            return;
        }
    }
}
static void start_reading(void *context)
{
    Transfer *transfer = context;
    otsource_activate(transfer->read_source);
}
static void write_transfer(void *context)
{
    Transfer *transfer = context;
    unsigned char bytes[8192];
    memset(bytes, 0x5a, sizeof(bytes));
    while (transfer->sent < TRANSFER_BYTES) {
        size_t remaining = TRANSFER_BYTES - transfer->sent;
        ssize_t count = otsocket_send(transfer->pair[0], bytes, remaining < sizeof(bytes) ? remaining : sizeof(bytes), 0);
        if (count < 0) {
            assert(errno == EAGAIN);
            if (!transfer->blocked) {
                transfer->blocked = true;
                otqueue_async(transfer->read_queue, transfer, start_reading);
            }
            return;
        }
        assert(count > 0);
        transfer->sent += (size_t)count;
    }
    otsource_suspend(transfer->write_source);
}
static void read_cancelled(void *context)
{
    otqueue_async(queue, context, transfer_cancelled);
}
static void setup_transfer_reader(void *context)
{
    Transfer *transfer = context;
    transfer->read_source = otsource_create(OTSOURCE_TYPE_READ, transfer->pair[1], transfer->read_queue);
    assert(transfer->read_source);
    otsource_set_context(transfer->read_source, transfer);
    otsource_set_event_handler(transfer->read_source, read_transfer);
    otsource_set_cancel_handler(transfer->read_source, read_cancelled);
}
static void setup_transfer(void *context)
{
    Transfer *transfer = context;
    assert(ssh_test_socket_pair(transfer->pair) == 0);
    int size = 4096;
    assert(otsocket_setsockopt(transfer->pair[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
    assert(otsocket_set_nonblocking(transfer->pair[0], true) == 0);
    assert(otsocket_set_nonblocking(transfer->pair[1], true) == 0);
    transfer->read_queue = ssh_test_queue_create("transfer.reader");
    otqueue_async(transfer->read_queue, transfer, setup_transfer_reader);
    transfer->write_source = otsource_create(OTSOURCE_TYPE_WRITE, transfer->pair[0], queue);
    assert(transfer->write_source);
    otsource_set_context(transfer->write_source, transfer);
    otsource_set_event_handler(transfer->write_source, write_transfer);
    otsource_set_cancel_handler(transfer->write_source, transfer_cancelled);
    otsource_activate(transfer->write_source);
}
static unsigned timer_events;
static otsource_t timer;
static void timer_cancelled(void *context)
{
    (void)context;
    assert(timer_events == 3);
    ssh_test_semaphore_signal(done);
}
static void timer_ready(void *context)
{
    (void)context;
    if (++timer_events == 3) {
        otsource_cancel(timer);
        otsource_release(timer);
    }
}
static void setup_timer(void *context)
{
    (void)context;
    timer = otsource_create(OTSOURCE_TYPE_TIMER, 0, queue);
    assert(timer);
    otsource_set_event_handler(timer, timer_ready);
    otsource_set_cancel_handler(timer, timer_cancelled);
    otsource_set_timer(timer, ottime(OTTIME_NOW, NSEC_PER_MSEC), NSEC_PER_MSEC, 0);
    otsource_activate(timer);
}
static void check_bindings(void *context)
{
    (void)context;
    otqueue_set_specific(queue, &first_key, &second_key);
    assert(otqueue_get_specific(&first_key) == &second_key);
    otqueue_set_specific(queue, &first_key, NULL);
    assert(otqueue_get_specific(&first_key) == NULL);
    assert(otqueue_get_specific(&second_key) == &second_key);
    otqueue_set_specific(queue, &first_key, &first_key);
}
typedef struct {
    ssh_test_semaphore_t entered, unblock, finished;
} BackgroundWork;
static void background_work(void *context)
{
    BackgroundWork *work = context;
    assert(otqueue_get_specific(&first_key) == NULL);
    assert(otqueue_get_specific(&second_key) == NULL);
    ssh_test_semaphore_signal(work->entered);
    assert(ssh_test_semaphore_wait(work->unblock, 10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_signal(work->finished);
}
static void submit_background_work(void *context)
{
    otqueue_assert(queue);
    otqueue_async_background(context, background_work);
    otqueue_async_background(context, background_work);
}
static void test_background_work(void)
{
    BackgroundWork work = {
        .entered = ssh_test_semaphore_create(0),
        .unblock = ssh_test_semaphore_create(0),
        .finished = ssh_test_semaphore_create(0)
    };
    assert(work.entered && work.unblock && work.finished);
    ssh_test_sync(queue, &work, submit_background_work);
    for (int i = 0; i < 2; i++) assert(ssh_test_semaphore_wait(work.entered, 10 * NSEC_PER_SEC) == 0);
    for (int i = 0; i < 2; i++) ssh_test_semaphore_signal(work.unblock);
    for (int i = 0; i < 2; i++) assert(ssh_test_semaphore_wait(work.finished, 10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(work.entered);
    ssh_test_semaphore_destroy(work.unblock);
    ssh_test_semaphore_destroy(work.finished);
}
typedef struct {
    otqueue_t queue;
    ssh_test_semaphore_t entered, unblock, finished;
} QueueLifetime;
static void held_queue_work(void *context)
{
    QueueLifetime *test = context;
    ssh_test_semaphore_signal(test->entered);
    assert(ssh_test_semaphore_wait(test->unblock, 10 * NSEC_PER_SEC) == 0);
    otqueue_assert(test->queue);
    assert(otqueue_get_specific(test) == test);
    ssh_test_semaphore_signal(test->finished);
}
static void test_queue_lifetime(void)
{
    QueueLifetime test = {
        .queue = ssh_test_queue_create("queue.lifetime"),
        .entered = ssh_test_semaphore_create(0),
        .unblock = ssh_test_semaphore_create(0),
        .finished = ssh_test_semaphore_create(0)
    };
    assert(test.queue && test.entered && test.unblock && test.finished);
    otqueue_set_specific(test.queue, &test, &test);
    otqueue_async(test.queue, &test, held_queue_work);
    assert(ssh_test_semaphore_wait(test.entered, 10 * NSEC_PER_SEC) == 0);
    otqueue_release(test.queue);
    ssh_test_semaphore_signal(test.unblock);
    assert(ssh_test_semaphore_wait(test.finished, 10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(test.entered);
    ssh_test_semaphore_destroy(test.unblock);
    ssh_test_semaphore_destroy(test.finished);
}
typedef struct {
    otsource_t source;
    unsigned events;
} OneShot;
static void one_shot_ready(void *context)
{
    OneShot *test = context;
    assert(++test->events == 1);
    ssh_test_semaphore_signal(done);
}
static void one_shot_cancelled(void *context)
{
    OneShot *test = context;
    assert(test->events == 1);
    ssh_test_semaphore_signal(done);
}
static void setup_one_shot(void *context)
{
    OneShot *test = context;
    test->source = otsource_create(OTSOURCE_TYPE_TIMER, 0, queue);
    assert(test->source);
    otsource_set_context(test->source, test);
    otsource_set_event_handler(test->source, one_shot_ready);
    otsource_set_cancel_handler(test->source, one_shot_cancelled);
    otsource_set_timer(test->source, OTTIME_NOW, OTTIME_FOREVER, NSEC_PER_MSEC);
    otsource_activate(test->source);
    otsource_suspend(test->source);
    otsource_suspend(test->source);
}
static void resume_one_shot(void *context)
{
    otsource_resume(((OneShot *)context)->source);
}
static void resume_expired_timer(void *context)
{
    OneShot *test = context;
    assert(test->events == 1);
    otsource_suspend(test->source);
    otsource_resume(test->source);
}
static void cancel_one_shot(void *context)
{
    OneShot *test = context;
    otsource_cancel(test->source);
    otsource_release(test->source);
}
static void test_one_shot_suspension(void)
{
    OneShot test = {0};
    ssh_test_sync(queue, &test, setup_one_shot);
    assert(ssh_test_semaphore_wait(done, 30 * NSEC_PER_MSEC) != 0);
    ssh_test_sync(queue, &test, resume_one_shot);
    assert(ssh_test_semaphore_wait(done, 30 * NSEC_PER_MSEC) != 0);
    ssh_test_sync(queue, &test, resume_one_shot);
    wait_done();
    ssh_test_sync(queue, &test, resume_expired_timer);
    assert(ssh_test_semaphore_wait(done, 100 * NSEC_PER_MSEC) != 0);
    ssh_test_sync(queue, &test, cancel_one_shot);
    wait_done();
}
typedef struct {
    otsource_t source;
    otsocket_t pair[2];
    ssh_test_semaphore_t entered, unblock;
} PendingCancel;
static void unexpected_event(void *context)
{
    (void)context;
    assert(!"Cancelled source delivered an event");
}
static void pending_cancelled(void *context)
{
    PendingCancel *test = context;
    otqueue_assert(queue);
    otsocket_close(test->pair[0]);
    otsocket_close(test->pair[1]);
    ssh_test_semaphore_signal(done);
}
static void setup_pending_cancel(void *context)
{
    PendingCancel *test = context;
    assert(ssh_test_socket_pair(test->pair) == 0);
    test->source = otsource_create(OTSOURCE_TYPE_READ, test->pair[0], queue);
    assert(test->source);
    otsource_set_context(test->source, test);
    otsource_set_event_handler(test->source, unexpected_event);
    otsource_set_cancel_handler(test->source, pending_cancelled);
    otsource_activate(test->source);
    ssh_test_semaphore_signal(test->entered);
    assert(ssh_test_semaphore_wait(test->unblock, 10 * NSEC_PER_SEC) == 0);
    otsource_cancel(test->source);
    otsource_release(test->source);
}
static void test_pending_cancellation(void)
{
    PendingCancel test = {.entered = ssh_test_semaphore_create(0), .unblock = ssh_test_semaphore_create(0)};
    assert(test.entered && test.unblock);
    otqueue_async(queue, &test, setup_pending_cancel);
    assert(ssh_test_semaphore_wait(test.entered, 10 * NSEC_PER_SEC) == 0);
    assert(otsocket_send(test.pair[1], "x", 1, 0) == 1);
    assert(ssh_test_semaphore_wait(done, 30 * NSEC_PER_MSEC) != 0);
    ssh_test_semaphore_signal(test.unblock);
    wait_done();
    ssh_test_semaphore_destroy(test.entered);
    ssh_test_semaphore_destroy(test.unblock);
}

typedef struct {
    OneShot timer;
    ssh_test_semaphore_t entered, unblock;
    ottime_t earliest_delivery;
} TimerReset;
static void reset_timer_ready(void *context)
{
    TimerReset *test = context;
    assert(ottime(OTTIME_NOW, 0) >= test->earliest_delivery);
    one_shot_ready(&test->timer);
}
static void reset_timer_cancelled(void *context)
{
    one_shot_cancelled(&((TimerReset *)context)->timer);
}
static void setup_timer_reset(void *context)
{
    TimerReset *test = context;
    test->timer.source = otsource_create(OTSOURCE_TYPE_TIMER, 0, queue);
    assert(test->timer.source);
    otsource_set_context(test->timer.source, test);
    otsource_set_event_handler(test->timer.source, reset_timer_ready);
    otsource_set_cancel_handler(test->timer.source, reset_timer_cancelled);
    otsource_set_timer(test->timer.source, OTTIME_NOW, OTTIME_FOREVER, 0);
    otsource_activate(test->timer.source);
    ssh_test_semaphore_signal(test->entered);
    assert(ssh_test_semaphore_wait(test->unblock, 10 * NSEC_PER_SEC) == 0);
    otsource_set_timer(test->timer.source, ottime(OTTIME_NOW, 100 * NSEC_PER_MSEC), OTTIME_FOREVER, 0);
}
static void test_timer_reset(void)
{
    TimerReset test = {.entered = ssh_test_semaphore_create(0), .unblock = ssh_test_semaphore_create(0)};
    assert(test.entered && test.unblock);
    otqueue_async(queue, &test, setup_timer_reset);
    assert(ssh_test_semaphore_wait(test.entered, 10 * NSEC_PER_SEC) == 0);
    ssh_test_sleep_milliseconds(30);
    test.earliest_delivery = ottime(OTTIME_NOW, 100 * NSEC_PER_MSEC);
    ssh_test_semaphore_signal(test.unblock);
    wait_done();
    ssh_test_sync(queue, &test.timer, cancel_one_shot);
    wait_done();
    ssh_test_semaphore_destroy(test.entered);
    ssh_test_semaphore_destroy(test.unblock);
}

#if defined(_WIN32)
typedef struct {
    otsocket_t socket;
    otsource_t source;
} UnconnectedWriter;
static void unconnected_writer_ready(void *context)
{
    (void)context;
    assert(!"Unconnected socket reported writable");
}
static void unconnected_writer_cancelled(void *context)
{
    UnconnectedWriter *test = context;
    otsocket_close(test->socket);
    ssh_test_semaphore_signal(done);
}
static void setup_unconnected_writer(void *context)
{
    UnconnectedWriter *test = context;
    test->socket = otsocket_create(AF_INET, SOCK_STREAM, 0);
    assert(test->socket >= 0);
    test->source = otsource_create(OTSOURCE_TYPE_WRITE, test->socket, queue);
    assert(test->source);
    otsource_set_context(test->source, test);
    otsource_set_event_handler(test->source, unconnected_writer_ready);
    otsource_set_cancel_handler(test->source, unconnected_writer_cancelled);
    otsource_activate(test->source);
    otsource_suspend(test->source);
    otsource_resume(test->source);
}
static void cancel_unconnected_writer(void *context)
{
    UnconnectedWriter *test = context;
    otsource_cancel(test->source);
    otsource_release(test->source);
}
static void test_unconnected_writer(void)
{
    UnconnectedWriter test = {0};
    ssh_test_sync(queue, &test, setup_unconnected_writer);
    ssh_test_sync(queue, &test, cancel_unconnected_writer);
    wait_done();
}
#endif

int main(void)
{
    done = ssh_test_semaphore_create(0);
    queue = ssh_test_queue_create("queue.test");
    assert(done && queue);
    otqueue_set_specific(queue, &first_key, &first_key);
    otqueue_set_specific(queue, &second_key, &second_key);
    for (uintptr_t i = 0; i < QUEUE_ITEMS; i++) otqueue_async(queue, (void *)i, ordered_work);
    wait_done();
    ssh_test_sync(queue, NULL, check_bindings);
    test_background_work();
    test_queue_lifetime();
    test_one_shot_suspension();
    test_timer_reset();
    test_pending_cancellation();
#if defined(_WIN32)
    test_unconnected_writer();
#endif
    Reader readers[SOCKET_COUNT] = {0};
    for (unsigned i = 0; i < SOCKET_COUNT; i++) {
        readers[i].queue = ssh_test_queue_create("socket.test");
        ssh_test_sync(readers[i].queue, &readers[i], setup_reader);
    }
    ssh_test_sleep_milliseconds(10);
    for (unsigned i = 0; i < SOCKET_COUNT; i++) otqueue_async(readers[i].queue, &readers[i], resume_reader);
    wait_done();
    for (unsigned i = 0; i < SOCKET_COUNT; i++) otqueue_release(readers[i].queue);
    Transfer transfer = {0};
    otqueue_async(queue, &transfer, setup_transfer);
    wait_done();
    assert(transfer.received == TRANSFER_BYTES);
    otsocket_close(transfer.pair[0]);
    otsocket_close(transfer.pair[1]);
    otqueue_release(transfer.read_queue);
    otqueue_async(queue, NULL, setup_timer);
    wait_done();
    otqueue_release(queue);
    ssh_test_semaphore_destroy(done);
    puts("Queue ordering, background work, bindings, cancellation, 128 sockets, backpressure, timer suspension, and timer reset passed.");
    return 0;
}
