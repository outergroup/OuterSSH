#ifndef OTEVENT_SIGNAL_H
#define OTEVENT_SIGNAL_H

/* A level-triggered wait handle, signaled exactly while an event queue has pending
 * events: a manual-reset event on Windows, an eventfd on Linux and Android.
 * Valid when zero-initialized; it opens on first use. Callers serialize
 * access with the event queue's event lock. */

#include <stdbool.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#else
#include <stdint.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif

typedef struct {
    bool open;
#if defined(_WIN32)
    HANDLE event;
#else
    int descriptor;
#endif
} OTEventSignal;

static inline bool otevent_signal_open(OTEventSignal *signal)
{
    if (signal->open) return true;
#if defined(_WIN32)
    signal->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (signal->event == NULL) return false;
#else
    signal->descriptor = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (signal->descriptor < 0) return false;
#endif
    signal->open = true;
    return true;
}

static inline void otevent_signal_set(OTEventSignal *signal)
{
    if (!signal->open) return;
#if defined(_WIN32)
    SetEvent(signal->event);
#else
    uint64_t one = 1;
    ssize_t written = write(signal->descriptor, &one, sizeof(one));
    (void)written;
#endif
}

static inline void otevent_signal_clear(OTEventSignal *signal)
{
    if (!signal->open) return;
#if defined(_WIN32)
    ResetEvent(signal->event);
#else
    uint64_t value;
    ssize_t count = read(signal->descriptor, &value, sizeof(value));
    (void)count;
#endif
}

static inline void otevent_signal_close(OTEventSignal *signal)
{
    if (!signal->open) return;
#if defined(_WIN32)
    CloseHandle(signal->event);
#else
    close(signal->descriptor);
#endif
    signal->open = false;
}

#endif
