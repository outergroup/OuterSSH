#ifndef SSH_SOCKET_SERVICE_H
#define SSH_SOCKET_SERVICE_H

#include "SSHSessionPoolInternal.h"
#include "HelperProtocol.h"
#include "SSHProxyAddress.h"

typedef struct SSHSocketService SSHSocketService;

/* Work is embedded in its owner and belongs to either the readiness queue or
 * the pending-reply list. It is removed before its callback runs. */
typedef struct SocketServiceWork {
    struct SocketServiceWork *next;
    uint32_t id;
    uint64_t deadline;
    bool expects_preparation;
    /* ENDPOINT_ICON or APP_RESPONSE when the request expects that reply. */
    HelperFrameType reply_type;
    HelperConnectionMode connection_mode;
    /* The expected reply's payload, valid only during the completion. */
    const unsigned char *reply;
    size_t reply_length;
    SSHCompletionHandler completion;
    void *context;
} SocketServiceWork;

/* Owns the path for the pool's lifetime on success. NULL pending means authorized. */
typedef struct SocketAuthorization {
    struct SocketAuthorizationRequest *pending;
    size_t path_length;
    HelperConnectionMode connection_mode;
    bool session_owned;
    bool root_owned;
    size_t owner_length;
    char owner[HELPER_OWNER_CAPACITY];
    char path[];
} SocketAuthorization;

/* Embedded in the first caller's context and borrowed until its completion. */
typedef struct SocketAuthorizationRequest {
    SocketServiceWork work;
    SSHSocketService *service;
    SocketAuthorization *authorization;
    /* Operations waiting for this path's authorization. */
    SSHWaitList waiters;
} SocketAuthorizationRequest;

static inline bool outersshpriv_proxy_socket_path_is_valid(
    const char *path,
    size_t byte_count)
{
    if (path == NULL || byte_count == 0 || byte_count > 4096 ||
        (path[0] != '/' && !outerssh_proxy_is_named_pipe(path, byte_count))) {
        return false;
    }
    for (size_t index = 0; index < byte_count; index++) {
        if (path[index] == '\0' || path[index] == '\n' || path[index] == '\r') {
            return false;
        }
    }
    return true;
}

/* Control queue only. Returns a pending or completed entry, or NULL if absent
 * or the pool is closing or disconnecting.
 * Consume this result on the current queue turn, before calling other callbacks
 * or starting asynchronous work; a failed request removes its entry. */
SocketAuthorization *outersshpriv_socket_service_find_authorization(OuterSSHSessionPool *pool,
    const char *path, size_t path_length);

/* Control queue only. Waits for a pending authorization and resumes the
 * operation exactly once with its result. The entry must not already be
 * authorized. The waiter is embedded in the operation. */
void outersshpriv_socket_service_wait_for_authorization(SocketAuthorization *authorization,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context);

/* Control queue only. Starts a new authorization after a lookup found no entry
 * and waits for it, resuming the operation exactly once, possibly before
 * returning. Copies path. Successful authorizations last for the pool's
 * lifetime; failures are not cached. The caller owns request and waiter and
 * keeps both alive until it resumes, which may free their owner. */
void outersshpriv_socket_service_authorize(OuterSSHSessionPool *pool,
    const char *path, size_t path_length,
    SocketAuthorizationRequest *request, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context);
void outersshpriv_socket_service_stop(OuterSSHSessionPool *pool);
/* Control queue only. A connection found nothing listening at path, so a watch
 * that last reported it available reports it unavailable, until the helper
 * reports it present again. */
void outersshpriv_socket_service_found_nothing_listening(OuterSSHSessionPool *pool, const char *path, size_t length);
void outersshpriv_socket_service_dispose(OuterSSHSessionPool *pool);

#endif
