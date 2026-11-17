#ifndef SSH_PROXY_STATE_H
#define SSH_PROXY_STATE_H

#include "platform/OTSocket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "HelperProtocol.h"
#include "ProxyReactor.h"
#include "SSHSessionPoolInternal.h"

typedef struct {
    size_t index;
    uint64_t generation;
} SSHProxyBridgeHandle;

typedef struct {
    SSHProxyBridgeHandle bridge;
    /* On failure, the attempted bridge, or its predecessor if none was started. */
    SSHProxyBridgeHandle failed_bridge;
    OuterSSHError error;
} SSHBridgeResult;

typedef void (*SSHProxyBridgeHandler)(void *context, SSHBridgeResult result);

/* Embedded in a caller's context until bridge setup completes. Unlike facts the
 * pool learns once, a setup's result differs per request, so each waiter
 * carries its own result and receives it typed. */
typedef struct SSHSocketBridgeWaiter {
    SSHWaiter waiter;
    SSHProxyBridgeHandler finished;
    void *context;
    SSHProxyBridgeHandle failed_bridge;
    SSHBridgeResult result;
} SSHSocketBridgeWaiter;

typedef struct {
    const char *path;
    size_t path_length;
    bool uses_sudo;
    const char *sudo_password;
    size_t sudo_password_length;
    /* Optional predecessor whose failure prompted this request. */
    SSHProxyBridgeHandle failed_bridge;
} SSHBridgeRequest;

/* Embedded in the first caller until its setup completion begins. */
struct SSHSocketBridgeOperation {
    bool retry_cached_executable;
    SSHBridgeRequest request;
    OuterSSHSessionPool *pool;
    SSHProxyBridgeHandle bridge;
    SSHProxyBridgeHandle failed_bridge;
    struct SSHSocketBridgeOperation *next_setup;
    /* Requests sharing this setup, as embedded SSHSocketBridgeWaiter.waiter. */
    SSHWaitList requesters;
    /* This setup's own wait for an executable or a session. */
    SSHWaiter waiter;
    SSHReactor *starting_reactor;
    char *command;
    size_t command_byte_count;
    void *initial_input;
    size_t initial_input_byte_count;
    OuterSSHError completed_error;
    char *error_storage;
};

typedef struct SSHProxyBridgeState {
    uint64_t generation;
    char *path;
    size_t path_length;
    SSHSocketBridge bridge;
    bool uses_sudo;
    bool stopped;
    bool explicitly_closed;
    bool is_current;
} SSHProxyBridgeState;

typedef struct SSHForwarder SSHForwarder;
/* A forwarding request borrows its server and pool; asynchronous stages retain
 * them until their completion returns to the control queue. The generation
 * distinguishes forwarding runs across stops and restarts. */
typedef struct {
    SSHForwarder *server;
    OuterSSHSessionPool *pool;
    uint64_t proxy_generation;
} SSHProxyConnection;

SSHProxyBridgeState *outersshpriv_proxy_bridge_for_handle(
    OuterSSHSessionPool *pool,
    SSHProxyBridgeHandle handle);
SSHProxyBridgeState *outersshpriv_proxy_bridge_for_path(
    OuterSSHSessionPool *pool,
    const char *path,
    size_t path_length,
    SSHProxyBridgeHandle *handle);

/* Who owns a socket or named pipe. Requests to the SSH user's own sockets are
 * not checked when that user is not root. Any other socket accepts requests
 * that change state only from pages of a socket with the same owner, or of a
 * root-owned one. */
typedef struct {
    bool known;
    bool session_owned;
    bool root;
    size_t owner_length;
    char owner[HELPER_OWNER_CAPACITY];
} SSHSocketOwner;

/* Control queue only. Unknown until the path is authorized or bridged. An
 * empty owner means the socket did not exist when it was authorized. */
SSHSocketOwner outersshpriv_proxy_socket_owner(OuterSSHSessionPool *pool,
    const char *path, size_t path_length);

static inline bool outersshpriv_socket_owner_may_send(const SSHSocketOwner *sender,
    const SSHSocketOwner *destination)
{
    return sender->known && (sender->root || (sender->owner_length != 0 &&
        sender->owner_length == destination->owner_length &&
        memcmp(sender->owner, destination->owner, sender->owner_length) == 0));
}

typedef enum {
    /* The connection was judged before its destination's owner was needed. */
    SSH_SOCKET_SENDER_UNCHECKED,
    /* No request has been judged yet, so the connection may not use sudo. */
    SSH_SOCKET_SENDER_UNDECIDED,
    /* Requests act as the SSH user. */
    SSH_SOCKET_SENDER_SSH_USER,
    /* Requests come from content of a socket with this owner. */
    SSH_SOCKET_SENDER_OWNER
} SSHSocketSenderKind;

/* Who sends over a connection to a socket whose owner was not known when the
 * connection started. Judged by the zone rule once the owner is known, before
 * the connection uses sudo. */
typedef struct {
    SSHSocketSenderKind kind;
    SSHSocketOwner owner;
} SSHSocketSender;

static inline bool outersshpriv_socket_sender_permits(const SSHSocketSender *sender,
    const SSHSocketOwner *destination, bool remote_user_is_root, bool uses_sudo)
{
    switch (sender->kind) {
    case SSH_SOCKET_SENDER_UNCHECKED:
        return true;
    case SSH_SOCKET_SENDER_UNDECIDED:
        return !uses_sudo;
    case SSH_SOCKET_SENDER_SSH_USER:
        return destination->known && (destination->session_owned || remote_user_is_root);
    case SSH_SOCKET_SENDER_OWNER:
        return destination->known && outersshpriv_socket_owner_may_send(&sender->owner, destination);
    }
    return false;
}
SSHProxyBridgeState *outersshpriv_proxy_append_bridge_state(
    OuterSSHSessionPool *pool,
    const char *path,
    size_t path_length,
    bool uses_sudo,
    SSHProxyBridgeHandle *handle);

#endif
