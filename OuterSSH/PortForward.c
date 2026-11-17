#include "include/OuterSSH/PortForward.h"
#include "SSHProxyErrorInternal.h"
#include "SSHForwarder.h"
#include "SSHEventsInternal.h"
#include <stdlib.h>
#include <string.h>

struct OuterSSHPortForward {
    SSHForwarder *forwarder;
};

typedef struct {
    SSHForwarder *forwarder;
    int32_t port;
    SSHPoolEvent *reply;
} PortForwardStartContext;

static void start_port_forward(void *context);

#pragma mark - Create a Fixed TCP Forward

OuterSSHPortForward *outerssh_port_forward_create(OuterSSHSessionPool *pool,
    const char *host, size_t host_length, uint16_t port, OuterSSHError *error)
{
    if (error != NULL) *error = (OuterSSHError){0};
    if (pool == NULL || host == NULL || host_length == 0 ||
        host_length >= PROXY_HOST_CAPACITY || memchr(host, 0, host_length) != NULL || port == 0) {
        static const char message[] = "Invalid port forwarding destination or session pool.";
        if (error != NULL) *error = outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION,
            message, sizeof(message) - 1, 0);
        return NULL;
    }
    OuterSSHPortForward *forward = calloc(1, sizeof(*forward));
    if (forward == NULL) {
        static const char message[] = "Failed to allocate the TCP port forward.";
        if (error != NULL) *error = outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION,
            message, sizeof(message) - 1, 0);
        return NULL;
    }
    forward->forwarder = outersshpriv_tcp_forwarder_create(pool, host, host_length, port, error);
    if (forward->forwarder == NULL) {
        free(forward);
        return NULL;
    }
    forward->forwarder->frontend = forward;
    return forward;
}

#pragma mark - Start and Stop Listening

bool outerssh_port_forward_start(OuterSSHPortForward *forward, uint16_t port, uint64_t tag)
{
    PortForwardStartContext *operation = malloc(sizeof(*operation));
    SSHPoolEvent *reply = operation == NULL ? NULL
        : outersshpriv_reply_reserve(forward->forwarder->pool, OUTERSSH_EVENT_PORT_FORWARD_STARTED, tag);
    if (reply == NULL) {
        free(operation);
        return false;
    }
    *operation = (PortForwardStartContext){forward->forwarder, port, reply};
    otqueue_async(forward->forwarder->queue, operation, start_port_forward);
    return true;
}

static void start_port_forward(void *context)
{
    PortForwardStartContext *operation = context;
    SSHForwarder *forwarder = operation->forwarder;
    OuterSSHError error = outersshpriv_forwarder_listen(forwarder, operation->port);
    outersshpriv_reply_port_forward_started(operation->reply, forwarder->port, error);
    free(operation);
}

bool outerssh_port_forward_stop(OuterSSHPortForward *forward, uint64_t tag)
{
    SSHPoolEvent *reply = outersshpriv_reply_reserve(forward->forwarder->pool, OUTERSSH_EVENT_OPERATION_COMPLETED, tag);
    if (reply == NULL) return false;
    outersshpriv_forwarder_stop(forward->forwarder, reply);
    return true;
}

#pragma mark - Destroy the Forward

static void forwarder_destroyed(void *reply)
{
    outersshpriv_reply(reply, (OuterSSHError){0});
}

bool outerssh_port_forward_destroy(OuterSSHPortForward *forward, uint64_t tag)
{
    SSHPoolEvent *reply = outersshpriv_reply_reserve(forward->forwarder->pool, OUTERSSH_EVENT_DESTROYED, tag);
    if (reply == NULL) return false;
    outersshpriv_forwarder_destroy(forward->forwarder, forwarder_destroyed, reply);
    free(forward);
    return true;
}
