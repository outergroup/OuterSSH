#include "OuterSSH.h"
#include "SSHEventQueueInternal.h"
#include <stdlib.h>

#include "platform/OTQueue.h"
#include "platform/OTSocket.h"
#include <libssh2.h>

static int initialization_result;
static OuterSSHError initialization_error;
static char *initialization_error_storage;

static void initialize_library(void *context);

bool outerssh_initialize(OuterSSHError *error)
{
    static otonce_t once;
    otonce(&once, NULL, initialize_library);
    if (error != NULL) *error = initialization_error;
    return initialization_result == 0;
}

static void initialize_library(void *context)
{
    (void)context;
    initialization_result = otsocket_initialize();
    if (initialization_result == 0) initialization_result = libssh2_init(0);
    if (initialization_result != 0) {
        initialization_error = outerssh_session_error_format(&initialization_error_storage,
            OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED, "Failed to initialize libssh2: %d", initialization_result);
        initialization_error.ssh_error_code = initialization_result;
    }
}

#if defined(__APPLE__)
OuterSSHEventQueue *outerssh_event_queue_create(dispatch_source_t events)
{
    OuterSSHEventQueue *event_queue = calloc(1, sizeof(*event_queue));
    if (event_queue == NULL) return NULL;
    event_queue->events = events;
    dispatch_retain(events);
    return event_queue;
}

void outerssh_event_queue_destroy(OuterSSHEventQueue *event_queue)
{
    if (event_queue == NULL) return;
    outersshpriv_event_queue_dispose_events(event_queue);
    dispatch_release(event_queue->events);
    free(event_queue);
}
#else
OuterSSHEventQueue *outerssh_event_queue_create(void)
{
    OuterSSHEventQueue *event_queue = calloc(1, sizeof(*event_queue));
    if (event_queue == NULL) return NULL;
    if (!otevent_signal_open(&event_queue->event_signal)) {
        free(event_queue);
        return NULL;
    }
    return event_queue;
}

void outerssh_event_queue_destroy(OuterSSHEventQueue *event_queue)
{
    if (event_queue == NULL) return;
    outersshpriv_event_queue_dispose_events(event_queue);
    otevent_signal_close(&event_queue->event_signal);
    free(event_queue);
}
#endif
