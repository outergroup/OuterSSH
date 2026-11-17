#ifndef SSH_REACTOR_H
#define SSH_REACTOR_H

#include "OTNullability.h"
#include "HelperProtocol.h"

#include "platform/OTSocket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#include "platform/OTQueue.h"
#include <libssh2.h>
#include "SSHSessionStart.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

// This reactor manages a single SSH session and is the session-level surface
// of the shared proxy library. Keeping the hot data path in C also avoids
// accidental Swift overhead while relaying large uploads and downloads.

typedef struct SSHReactor SSHReactor;
typedef struct SSHReactorCommand SSHReactorCommand;
typedef struct OuterSSHSessionPool OuterSSHSessionPool;
typedef struct ConnectRelayContext ConnectRelayContext;
typedef struct SSHRelayRecoveryOperation SSHRelayRecoveryOperation;
typedef struct ExecuteCommandContext ExecuteCommandContext;
typedef struct SSHSessionCreationOperation SSHSessionCreationOperation;
typedef struct SSHSocketBridgeContext SSHSocketBridgeContext;
typedef struct ConnectBridgeStreamContext ConnectBridgeStreamContext;

typedef struct {
    size_t index;
    uint64_t generation;
} SSHSessionPoolSessionHandle;

typedef struct SSHChannelOutputBuffer {
    unsigned char *bytes;
    size_t byte_count;
    size_t offset;
    size_t capacity;
} SSHChannelOutputBuffer;

/* A fixed-capacity ring buffer. Readers and writers take one contiguous span
 * at a time; a span ends where the storage wraps. */
typedef struct SSHRelayBuffer {
    unsigned char *bytes;
    size_t capacity;
    size_t start;
    size_t count;
} SSHRelayBuffer;

static inline size_t outersshpriv_relay_buffer_pending(const SSHRelayBuffer *buffer)
{
    return buffer->count;
}

static inline size_t outersshpriv_relay_buffer_space(const SSHRelayBuffer *buffer)
{
    return buffer->capacity - buffer->count;
}

static inline const unsigned char *outersshpriv_relay_buffer_readable(
    const SSHRelayBuffer *buffer, size_t *length)
{
    size_t until_wrap = buffer->capacity - buffer->start;
    *length = buffer->count < until_wrap ? buffer->count : until_wrap;
    return buffer->bytes + buffer->start;
}

static inline unsigned char *outersshpriv_relay_buffer_writable(
    SSHRelayBuffer *buffer, size_t *length)
{
    size_t end = buffer->start + buffer->count;
    if (end >= buffer->capacity) {
        end -= buffer->capacity;
    }
    size_t until_wrap = buffer->capacity - end;
    size_t space = buffer->capacity - buffer->count;
    *length = space < until_wrap ? space : until_wrap;
    return buffer->bytes + end;
}

static inline void outersshpriv_relay_buffer_commit(SSHRelayBuffer *buffer, size_t length)
{
    buffer->count += length;
}

static inline void outersshpriv_relay_buffer_consume(SSHRelayBuffer *buffer, size_t length)
{
    buffer->count -= length;
    buffer->start = buffer->count == 0 ? 0 : (buffer->start + length) % buffer->capacity;
}

static inline void outersshpriv_relay_buffer_clear(SSHRelayBuffer *buffer)
{
    buffer->start = 0;
    buffer->count = 0;
}

typedef enum {
    SSH_RELAY_DETACHED,
    SSH_RELAY_PENDING_CHANNEL,
    SSH_RELAY_ATTACHING,
    SSH_RELAY_ATTACHED,
    SSH_RELAY_CLOSED
} SSHRelayOwnershipState;

typedef enum {
    SSH_RELAY_TARGET_TCP,
    SSH_RELAY_TARGET_STREAMLOCAL
} SSHRelayTargetType;

typedef enum {
    SSHRelayTargetTCP,
    SSHRelayTargetUnixSocket
} SSHRelayTargetKind;

enum {
    SSH_RELAY_TARGET_DESTINATION_CAPACITY = 4097
};

typedef struct {
    SSHRelayTargetKind kind;
    /* Only destination_length bytes are meaningful; no terminator is required. */
    char destination[SSH_RELAY_TARGET_DESTINATION_CAPACITY];
    size_t destination_length;
    int32_t port;
} SSHRelayTarget;

typedef struct {
    SSHRelayTargetType type;
    /* Destination bytes are not null-terminated. */
    char *destination;
    size_t destination_length;
    int port;
} SSHRelayRoute;

typedef struct SSHRelay {
    atomic_size_t reference_count;
    _Atomic(otsocket_t) socket;
    atomic_int ownership_state;
    SSHRelayBuffer to_ssh;
    SSHRelayBuffer to_socket;
    size_t pending_window_credit;
    bool socket_read_open;
    bool channel_read_open;
    bool socket_write_closed;
    uint64_t identifier;
    uint64_t proxy_generation;
    SSHRelayRoute route;
} SSHRelay;

/*
 * Reactor creation, creation cancellation/release, queue lookup, pre-start
 * session-pool association, start, and destroy may be called from any queue.
 * Authentication completion runs on the authentication work queue.
 * After starting, call every other API taking SSHReactor on
 * outersshpriv_reactor_queue(). Runtime callbacks run on that serial queue. Destroy
 * asynchronously schedules invalidation on that queue; reactor storage
 * captured by Dispatch source handlers is released after all Dispatch sources
 * finish cancelling.
 */

typedef struct {
    size_t index;
    uint64_t generation;
} SSHReactorRelayHandle;

typedef enum {
    SSH_REACTOR_RELAY_OPEN_SUCCEEDED,
    SSH_REACTOR_RELAY_OPEN_START_FAILED,
    SSH_REACTOR_RELAY_OPEN_CHANNEL_FAILED,
    SSH_REACTOR_RELAY_OPEN_TIMED_OUT,
    SSH_REACTOR_RELAY_OPEN_SESSION_CLOSED,
    SSH_REACTOR_RELAY_OPEN_ATTACHMENT_FAILED,
    SSH_REACTOR_RELAY_OPEN_CANCELLED
} SSHReactorRelayOpenResult;

typedef struct {
    size_t index;
    uint64_t generation;
} SSHReactorSocketBridgeHandle;

typedef struct {
    size_t index;
    uint64_t generation;
} SSHReactorSocketBridgeStreamHandle;

typedef enum {
    SSH_REACTOR_OPERATION_READ,
    SSH_REACTOR_OPERATION_WRITE,
    SSH_REACTOR_OPERATION_KEEPALIVE
} SSHReactorOperation;

typedef enum {
    SSH_REACTOR_SOCKET_BRIDGE_READY,
    SSH_REACTOR_SOCKET_BRIDGE_CANCELLED,
    SSH_REACTOR_SOCKET_BRIDGE_CHANNEL_OPEN_FAILED,
    SSH_REACTOR_SOCKET_BRIDGE_CHANNEL_OPEN_TIMED_OUT,
    SSH_REACTOR_SOCKET_BRIDGE_REQUEST_DENIED,
    SSH_REACTOR_SOCKET_BRIDGE_READY_TIMED_OUT,
    SSH_REACTOR_SOCKET_BRIDGE_EXITED,
    SSH_REACTOR_SOCKET_BRIDGE_PROTOCOL_ERROR,
    SSH_REACTOR_SOCKET_BRIDGE_SESSION_CLOSED
} SSHReactorSocketBridgeResult;

typedef enum {
    SSH_REACTOR_SOCKET_BRIDGE_STREAM_READY,
    SSH_REACTOR_SOCKET_BRIDGE_STREAM_CANCELLED,
    SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_FAILED,
    SSH_REACTOR_SOCKET_BRIDGE_STREAM_NOT_LISTENING,
    SSH_REACTOR_SOCKET_BRIDGE_STREAM_OPEN_TIMED_OUT,
    SSH_REACTOR_SOCKET_BRIDGE_STREAM_BRIDGE_CLOSED,
    SSH_REACTOR_SOCKET_BRIDGE_STREAM_SESSION_CLOSED
} SSHReactorSocketBridgeStreamResult;

typedef enum {
    SSH_REACTOR_COMMAND_COMPLETED,
    SSH_REACTOR_COMMAND_CHANNEL_OPEN_FAILED,
    SSH_REACTOR_COMMAND_CHANNEL_OPEN_TIMED_OUT,
    SSH_REACTOR_COMMAND_CHANNEL_OPEN_SESSION_CLOSED,
    SSH_REACTOR_COMMAND_SESSION_CLOSED,
    SSH_REACTOR_COMMAND_REQUEST_FAILED,
    SSH_REACTOR_COMMAND_CHANNEL_OPEN_START_FAILED,
    SSH_REACTOR_COMMAND_EXEC_START_FAILED,
    SSH_REACTOR_COMMAND_OUTPUT_LIMIT_EXCEEDED,
    SSH_REACTOR_COMMAND_OUTPUT_ALLOCATION_FAILED,
    SSH_REACTOR_COMMAND_TIMED_OUT
} SSHReactorCommandResult;

enum {
    SSH_REACTOR_COMMAND_MAXIMUM_OUTPUT_BYTE_COUNT = 16 * 1024 * 1024
};

// Transfers caller ownership to the reactor queue. Final deallocation waits
// for every dispatch source cancellation handler to finish. Completion, if supplied,
// runs once on the reactor queue after deallocation.
void outersshpriv_reactor_destroy(SSHReactor *reactor, void (* OT_NULLABLE completion)(void * OT_NULLABLE),
    void * OT_NULLABLE context);

otqueue_t outersshpriv_reactor_queue(SSHReactor *reactor);
bool outersshpriv_reactor_is_current_queue(SSHReactor *reactor);

void outersshpriv_reactor_start(SSHReactor *reactor);

void outersshpriv_reactor_set_session_pool(
    SSHReactor *reactor,
    OuterSSHSessionPool * OT_NULLABLE pool,
    SSHSessionPoolSessionHandle session);
OuterSSHSessionPool * OT_NULLABLE outersshpriv_detach_reactor_from_session_pool(
    SSHReactor *reactor);
bool outersshpriv_reactor_session_has_failed(SSHReactor *reactor);
SSHRelay * OT_NULLABLE outersshpriv_reactor_detach_next_recoverable_relay(
    SSHReactor *reactor,
    size_t *next_index);

// Borrows immutable command and input bytes from operation until it completes,
// sending input_prefix_bytes before input_bytes. Input is never copied.
// Runs on the reactor queue; channel/timer cleanup may outlive the operation.
void outersshpriv_reactor_execute_command(
    SSHReactor *reactor,
    const void * OT_NULLABLE command_bytes,
    size_t command_byte_count,
    const void * OT_NULLABLE input_prefix_bytes,
    size_t input_prefix_byte_count,
    const void * OT_NULLABLE input_bytes,
    size_t input_byte_count,
    uint64_t channel_open_timeout_milliseconds,
    uint64_t execution_timeout_milliseconds,
    ExecuteCommandContext *operation);

/*
 * Creates a reactor on a queue of its own, driven by queue's driver, so the
 * session runs in parallel with others. created runs on queue with the
 * reactor, or with NULL if construction failed. Returns false, with created
 * never running, if the reactor's queue could not be created.
 *
 * Takes ownership of socket, including on failure. Takes ownership of session
 * only on success; the caller frees session if reactor construction fails.
 */
bool outersshpriv_reactor_create(otqueue_t queue, otsocket_t socket, LIBSSH2_SESSION *session,
    void (*created)(void *context, SSHReactor * OT_NULLABLE reactor), void *context);

void outersshpriv_reactor_stop_socket_bridge(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    bool send_eof);
/*
 * Attaches a socket to a remotely accepted stream. The reactor owns socket
 * after this call, including on failure.
 */
bool outersshpriv_reactor_socket_bridge_attach_stream(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle,
    otsocket_t socket, uint64_t proxy_generation);
/* Cancels either a preparing stream or a ready stream awaiting attachment. */
bool outersshpriv_reactor_socket_bridge_cancel_stream(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle);

int outersshpriv_reactor_send_keepalive(
    SSHReactor *reactor,
    const char * OT_NULLABLE reason,
    size_t reason_length,
    uint64_t timeout_milliseconds);
void outersshpriv_relay_release(SSHRelay * OT_NULLABLE relay);
/* Closes a detached relay. Returns false while a reactor owns the relay. */
bool outersshpriv_relay_close(SSHRelay *relay);

/*
 * Attaches the client socket to a ready transaction. This call owns socket on
 * every return path. On success the handle identifies the active relay. On
 * failure it closes both sides of the transaction.
 */
int outersshpriv_reactor_attach_prepared_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle,
    otsocket_t socket,
    uint64_t identifier,
    uint64_t proxy_generation,
    SSHRelayTargetType target_type,
    const char *target_destination,
    size_t target_destination_length,
    int target_port);
bool outersshpriv_reactor_cancel_prepared_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);
int outersshpriv_reactor_prepare_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle *handle,
    ConnectRelayContext *operation,
    const SSHRelayTarget *target,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds);
void outersshpriv_reactor_close_proxy_connections(
    SSHReactor *reactor,
    uint64_t proxy_generation);

typedef struct {
    void * OT_NULLABLE context;
    /* READY is followed by exactly one terminal result. All callbacks run on
     * the reactor queue. Frame payloads are borrowed during received. */
    void (*completed)(void * OT_NULLABLE, SSHReactorSocketBridgeHandle,
        SSHReactorSocketBridgeResult, uint32_t, const void * OT_NULLABLE, size_t);
    bool (* OT_NULLABLE received)(void * OT_NULLABLE, HelperFrame);
} SSHSocketChannelCallbacks;

bool outersshpriv_reactor_socket_channel_send(SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle, HelperFrame frame);

int outersshpriv_reactor_start_socket_channel(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle *handle,
    SSHSocketChannelCallbacks callbacks,
    const char *command,
    size_t command_length,
    const void * OT_NULLABLE initial_input,
    size_t initial_input_length,
    uint64_t channel_open_timeout_milliseconds,
    uint64_t ready_timeout_milliseconds);
int outersshpriv_reactor_socket_bridge_prepare_stream(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle *stream_handle,
    ConnectBridgeStreamContext *operation,
    uint64_t timeout_milliseconds);

/*
 * These recovery-only calls consume relay after a successful start. Success
 * attaches it to the reactor. Asynchronous failure returns it to
 * recovery_operation, while a synchronous nonzero return leaves it detached and
 * reusable by the caller.
 * Destination and source-host buffers are length-delimited.
 */
int outersshpriv_reactor_open_tcp_relay(
    SSHReactor *reactor,
    SSHRelay *relay,
    SSHRelayRecoveryOperation *recovery_operation,
    const char *host,
    size_t host_length,
    int port,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds);
int outersshpriv_reactor_open_streamlocal_relay(
    SSHReactor *reactor,
    SSHRelay *relay,
    SSHRelayRecoveryOperation *recovery_operation,
    const char *socket_path,
    size_t socket_path_length,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds);

/* Releases channels locally; closing the transport terminates the SSH session. */
int outersshpriv_reactor_teardown(
    SSHReactor *reactor,
    size_t * OT_NULLABLE created_channel_count,
    size_t * OT_NULLABLE freed_channel_count);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif

#endif
