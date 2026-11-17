#ifndef SSH_REACTOR_INTERNAL_H
#define SSH_REACTOR_INTERNAL_H

#include "SSHReactor.h"
#include "SSHReactorHandshake.h"
#include "SSHReactorAuthentication.h"
#include "SSHReactorCommandInternal.h"
#include "olibssh/key_exchange.h"

int outersshpriv_reactor_begin_key_exchange(SSHReactor *reactor);
int outersshpriv_reactor_advance_key_exchange(SSHReactor *reactor);
void outersshpriv_reactor_cancel_key_exchange_timeout(SSHReactor *reactor);
void outersshpriv_reactor_resume_key_exchange(SSHReactor *reactor);
void outersshpriv_reactor_resume_channels_after_key_exchange(SSHReactor *reactor);
int outersshpriv_reactor_start_keepalive_timeout(SSHReactor *reactor);
void outersshpriv_reactor_cancel_keepalive_timeout(SSHReactor *reactor);
uint64_t outersshpriv_reactor_monotonic_time_nanoseconds(void);
void outersshpriv_reactor_read_packets(SSHReactor *reactor);

// Shared reactor implementation state. Runtime access belongs to the reactor queue.

typedef enum {
    SSH_WRITE_CHANNEL_DATA,
    SSH_WRITE_CHANNEL_WINDOW_ADJUST,
    SSH_WRITE_CHANNEL_EOF,
    SSH_WRITE_CHANNEL_CLOSE,
    SSH_WRITE_CHANNEL_OPEN,
    SSH_WRITE_CHANNEL_EXEC,
    SSH_WRITE_KEEPALIVE,
    SSH_WRITE_PROTOCOL_RESPONSE
} SSHWriteActionType;

typedef struct SSHWriteAction {
    SSHWriteActionType type;
    SSHReactorChannelToken token;
    bool must_resume;
    union {
        struct {
            size_t byte_count;
        } channel_data;
        struct {
            size_t byte_count;
        } window_adjust;
        struct {
            char *command;
            size_t command_length;
        } exec;
        struct {
            unsigned char *bytes;
            size_t length;
        } packet;
    } payload;
} SSHWriteAction;

typedef struct SocketBridgeSlot SocketBridgeSlot;

typedef enum {
    SSH_CHANNEL_PURPOSE_RELAY,
    SSH_CHANNEL_PURPOSE_EXEC
} SSHChannelPurpose;

typedef struct SSHReactorPendingChannelOpen {
    void (*finished)(
        SSHReactor *reactor,
        const struct SSHReactorPendingChannelOpen *pending,
        SSHReactorChannelToken channel_token,
        SSHReactorChannelOpenResult result,
        uint32_t reason);
    otsource_t timeout_timer;
    ConnectRelayContext *prepared_relay_operation;
    SSHRelayRecoveryOperation *recovery_operation;
    bool result_delivered;
    union {
        SSHReactorRelayHandle prepared_relay_handle;
        SSHRelay *relay;
        SSHReactorCommand *command;
        SSHReactorSocketBridgeHandle socket_bridge_handle;
    } target;
} SSHReactorPendingChannelOpen;

typedef struct {
    SSHReactorCommand *command;
    otsource_t exit_close_timer;
} SSHReactorCommandChannel;

typedef enum {
    SSH_REACTOR_CHANNEL_OWNER_NONE,
    SSH_REACTOR_CHANNEL_OWNER_PENDING_OPEN,
    SSH_REACTOR_CHANNEL_OWNER_RELAY,
    SSH_REACTOR_CHANNEL_OWNER_COMMAND,
    SSH_REACTOR_CHANNEL_OWNER_SOCKET_BRIDGE
} SSHReactorChannelOwnerType;

typedef struct {
    SSHReactorChannelOwnerType type;
    union {
        SSHReactorPendingChannelOpen pending_open;
        SSHReactorRelayHandle relay_handle;
        SSHReactorCommandChannel command;
        SSHReactorSocketBridgeHandle socket_bridge_handle;
    };
} SSHReactorChannelOwner;

typedef struct SSHChannelState {
    bool in_use;
    uint32_t remote_id;
    uint32_t send_window;
    uint32_t send_packet_size;
    uint32_t receive_window;
    uint32_t receive_packet_size;
    SSHChannelOutputBuffer exec_input;
    /* Borrowed input sent after exec_input; see exec_input_is_borrowed. */
    const unsigned char *exec_input_tail;
    size_t exec_input_tail_length;
    SSHChannelOutputBuffer unattached_remote_buffer;
    SSHRelay *relay;
    SSHReactorChannelOwner owner;
    SSHChannelPurpose purpose;
    size_t consumed_byte_count;
    bool sent_eof;
    bool received_eof;
    bool remote_closed;
    bool close_sent;
    bool has_transmitted_data;
    bool is_waiting_for_window;
    bool send_eof_after_output_drains;
    bool is_closing;
    /* exec_input points into its owner's storage instead of a heap copy. */
    bool exec_input_is_borrowed;
} SSHChannelState;

typedef enum {
    SSH_REACTOR_LIFECYCLE_ACTIVE,
    SSH_REACTOR_LIFECYCLE_FAILED,
    SSH_REACTOR_LIFECYCLE_INVALIDATED,
    SSH_REACTOR_LIFECYCLE_DESTROY_WAITING
} SSHReactorLifecycle;

// A prepared relay opens an SSH channel for an existing browser request,
// before the browser socket is transferred to the reactor. Its socket is
// UNATTACHED while its channel is OPENING or OPEN.
//
// An attached relay is actually being used by a local browser connection. Its
// socket is ACTIVE (or CANCELLING during teardown), independently of whether
// its SSH channel is still open.
typedef enum {
    SSH_RELAY_CHANNEL_UNUSED,
    SSH_RELAY_CHANNEL_OPENING,
    SSH_RELAY_CHANNEL_OPEN,
    SSH_RELAY_CHANNEL_CLOSING,
    SSH_RELAY_CHANNEL_CLOSED
} SSHRelayChannelPhase;

typedef enum {
    SSH_RELAY_SOCKET_UNATTACHED,
    SSH_RELAY_SOCKET_ACTIVE,

    // otsource_cancel calls are asynchronous, since the actual wait
    // APIs are called in a central location across many queues, not just the
    // current queue. While we wait for both cancel handlers, the relay state
    // is preserved because it holds the socket that must be closed afterward.
    SSH_RELAY_SOCKET_CANCELLING,
    SSH_RELAY_SOCKET_CLOSED
} SSHRelaySocketPhase;

typedef enum {
    SSH_REACTOR_RELAY_RELEASE_UNAVAILABLE = 0,
    SSH_REACTOR_RELAY_RELEASE_CLOSED,
    SSH_REACTOR_RELAY_RELEASE_DETACHED
} SSHReactorRelayReleaseResult;

typedef struct {
    SSHReactorChannelToken channel_token;
    otsocket_t socket;
    otsource_t read_socket_source;
    otsource_t write_socket_source;
    bool read_socket_source_is_resumed;
    bool write_socket_source_is_resumed;
    bool remote_output_finished;
    size_t uncancelled_socket_source_count;
    SSHRelayChannelPhase channel_phase;
    SSHRelaySocketPhase socket_phase;
} SSHReactorRelayState;

typedef struct RelaySlot {
    uint64_t generation;
    SSHRelay *relay;
    SSHReactorRelayState state;
} RelaySlot;

typedef enum {
    /* Startup completion may still be queued when no protocol phase is active. */
    SSH_REACTOR_PHASE_NONE,
    SSH_REACTOR_PHASE_HANDSHAKE,
    SSH_REACTOR_PHASE_AUTHENTICATION,
    SSH_REACTOR_PHASE_CHANNELS
} SSHReactorPhase;

struct SSHReactor {
    LIBSSH2_SESSION *session;
    bool windows_banner;
    SSHChannelState *channels;
    size_t channel_capacity;
    uint64_t next_channel_id;
    SSHWriteAction *write_actions;
    size_t write_action_head;
    size_t write_action_count;
    size_t write_action_capacity;
    SSHReactorPhase phase;
    union {
        SSHHandshakeContext handshake;
        SSHAuthenticationContext authentication;
    } startup;
    OLIBSSHKeyExchange key_exchange;
    bool key_exchange_waiting_for_write;
    /* Owns the socket sources, including while finishing a partial write. */
    bool key_exchange_in_progress;
    otsource_t key_exchange_timeout_timer;
    bool has_pending_global_request;
    uint64_t last_server_activity_nanoseconds;
    otqueue_t queue;
    otsource_t read_socket_source;
    otsource_t write_socket_source;
    otsource_t keepalive_timeout_timer;
    otsocket_t socket;
    size_t uncancelled_socket_source_count;
    bool read_socket_source_is_resumed;
    bool write_socket_source_is_resumed;
    bool started;
    SSHReactorLifecycle lifecycle;
    bool keepalive_pending;
    char *keepalive_reason;
    size_t keepalive_reason_length;
    uint64_t keepalive_timeout_milliseconds;
    uint64_t keepalive_timeout_generation;
    size_t created_channel_count;
    size_t freed_channel_count;
    RelaySlot *relay_slots;
    size_t relay_slot_count;
    size_t relay_capacity;
    size_t *available_relay_indices;
    size_t available_relay_index_count;
    SocketBridgeSlot *socket_bridge_slots;
    size_t socket_bridge_slot_count;
    size_t socket_bridge_slot_capacity;
    size_t *available_socket_bridge_indices;
    size_t available_socket_bridge_index_count;
    unsigned char *socket_bridge_read_buffer;
    size_t socket_source_count;
    void (*destruction_completion)(void *);
    void *destruction_context;
    OuterSSHSessionPool *session_pool;
    SSHSessionPoolSessionHandle session_pool_handle;
    atomic_bool session_failed;
};

typedef struct {
    SSHReactor *reactor;
    otsource_t source;
    SSHReactorRelayHandle relay;
    SSHReactorSocketBridgeHandle bridge;
    SSHReactorSocketBridgeStreamHandle stream;
    SSHReactorChannelToken channel_token;
    uint64_t generation;
    bool writes;
} SSHReactorSourceContext;

typedef enum {
    SOCKET_BRIDGE_STREAM_FREE,
    SOCKET_BRIDGE_STREAM_ACTIVE,
    SOCKET_BRIDGE_STREAM_CANCELLING
} SocketBridgeStreamPhase;

typedef struct SocketBridgeStream {
    uint64_t proxy_generation;
    size_t slot_index;
    uint32_t stream_id;
    otsocket_t socket;
    otsource_t read_socket_source;
    otsource_t write_socket_source;
    otsource_t open_timer;
    ConnectBridgeStreamContext *open_operation;
    unsigned char *to_local;
    size_t to_local_byte_count;
    size_t to_local_offset;
    size_t to_local_capacity;
    bool read_socket_source_is_resumed;
    bool write_socket_source_is_resumed;
    bool local_read_is_open;
    bool remote_read_is_open;
    size_t uncancelled_socket_source_count;
    SocketBridgeStreamPhase phase;
} SocketBridgeStream;

typedef struct SocketBridgeStreamSlot {
    uint64_t generation;
    SocketBridgeStream stream;
} SocketBridgeStreamSlot;

typedef struct SocketBridge {
    SSHReactorSocketBridgeHandle handle;
    SSHReactorChannelToken channel_token;
    char *command;
    size_t command_length;
    unsigned char *initial_input;
    size_t initial_input_length;
    HelperFrameParser parser;
    unsigned char *stderr_bytes;
    size_t stderr_byte_count;
    size_t stderr_capacity;
    SocketBridgeStreamSlot *stream_slots;
    size_t stream_slot_count;
    size_t stream_slot_capacity;
    size_t *available_stream_indices;
    size_t available_stream_index_count;
    size_t cancelling_stream_count;
    size_t *stream_indices_by_id;
    size_t stream_by_id_count;
    size_t stream_by_id_capacity;
    size_t pending_local_output_byte_count;
    uint32_t next_stream_id;
    otsource_t ready_timer;
    otsource_t ping_timer;
    SSHSocketChannelCallbacks callbacks;
    uint64_t ready_timeout_milliseconds;
    size_t uncredited_byte_count;
    bool is_ready;
} SocketBridge;

typedef enum {
    SOCKET_BRIDGE_SLOT_FREE,
    SOCKET_BRIDGE_SLOT_ACTIVE,
    SOCKET_BRIDGE_SLOT_CANCELLING
} SocketBridgeSlotPhase;

typedef struct SocketBridgeSlot {
    uint64_t generation;
    SocketBridgeSlotPhase phase;
    SocketBridge bridge;
} SocketBridgeSlot;

#pragma mark - Transport and Channel Operations

int outersshpriv_reactor_output_buffer_append(
    SSHChannelOutputBuffer *buffer,
    const void *bytes,
    size_t byte_count);
int outersshpriv_reactor_enqueue_channel_data(
    SSHReactor *reactor,
    SSHReactorChannelToken token);
int outersshpriv_reactor_begin_channel_close(
    SSHReactor *reactor,
    SSHChannelState *state,
    SSHReactorChannelToken token,
    bool send_eof);
int outersshpriv_reactor_start_channel_exec(
    SSHReactor *reactor,
    SSHReactorChannelToken token,
    const char *command,
    size_t command_length,
    const void *initial_input,
    size_t initial_input_length,
    bool send_eof_after_initial_input);
/* Like outersshpriv_reactor_start_channel_exec, but sends input and then
 * input_tail from their owner's storage instead of copying them. They must
 * stay valid until the channel is freed or its input is forgotten. */
int outersshpriv_reactor_start_channel_exec_borrowing(
    SSHReactor *reactor,
    SSHReactorChannelToken token,
    const char *command,
    size_t command_length,
    const void *input,
    size_t input_length,
    const void *input_tail,
    size_t input_tail_length,
    bool send_eof_after_input);
size_t outersshpriv_reactor_pending_exec_input_byte_count(
    const SSHReactor *reactor,
    SSHReactorChannelToken token);
int outersshpriv_reactor_consume_channel_bytes(
    SSHReactor *reactor,
    SSHChannelState *state,
    SSHReactorChannelToken token,
    size_t byte_count);
void outersshpriv_reactor_cancel_source(otsource_t source);
void outersshpriv_reactor_assert_queue(SSHReactor *reactor);
bool outersshpriv_reactor_accepts_work(SSHReactor *reactor);
void outersshpriv_reactor_source_created(SSHReactor *reactor);
void outersshpriv_reactor_source_cancelled(SSHReactor *reactor);
SSHReactorSourceContext *outersshpriv_reactor_create_source_context(
    SSHReactor *reactor,
    otsource_t source);
void outersshpriv_reactor_timer_cancelled(void *opaque_context);
void outersshpriv_reactor_safely_set_source_resumed(
    SSHReactor *reactor,
    otsource_t socket_source,
    bool resumed,
    bool *is_resumed);
void outersshpriv_reactor_safely_cancel_source(
    SSHReactor *reactor,
    otsource_t socket_source,
    bool *is_resumed);
bool outersshpriv_reactor_configure_nonblocking_stream_socket(otsocket_t socket);
/* Returns false on a blocked write or failure. */
bool outersshpriv_reactor_write_queued_packets(SSHReactor *reactor);
/* Resumes one interrupted packet at the queue head; false means blocked or failed.
 * Leaves any keepalive deadline for the key-exchange flow to start afterward. */
bool outersshpriv_reactor_finish_pending_write(SSHReactor *reactor);
void outersshpriv_reactor_update_channel_write_source(SSHReactor *reactor);
void outersshpriv_reactor_set_ssh_read_source_resumed(SSHReactor *reactor, bool resumed);
void outersshpriv_reactor_set_ssh_write_source_resumed(SSHReactor *reactor, bool resumed);
void outersshpriv_reactor_fail(
    SSHReactor *reactor,
    SSHReactorOperation operation,
    int error_code);
int outersshpriv_reactor_open_session_channel(
    SSHReactor *reactor,
    SSHReactorChannelToken *channel_token,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open);

#pragma mark - Socket Bridge Events

SocketBridge *outersshpriv_reactor_socket_bridge_for_handle(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle);
bool outersshpriv_reactor_release_socket_bridge_window_credit_if_drained(
    SSHReactor *reactor,
    SocketBridge *bridge);
void outersshpriv_reactor_fail_all_socket_bridges(
    SSHReactor *reactor,
    SSHReactorSocketBridgeResult result);
bool outersshpriv_reactor_socket_bridge_close_stream(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle bridge_handle,
    uint32_t stream_id,
    bool notify_remote);
void outersshpriv_reactor_socket_bridge_receive_channel_data(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    uint32_t stream_id,
    const void *bytes,
    size_t byte_count);
void outersshpriv_reactor_socket_bridge_channel_became_writable(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle);
void outersshpriv_reactor_fail_socket_bridge_channel(
    SSHReactor *reactor,
    SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result);
void outersshpriv_reactor_socket_bridge_channel_closed(
    SSHReactor *reactor, SSHReactorSocketBridgeHandle handle);

#define SSH_READ_BUFFER_CAPACITY (2 * 1024 * 1024)

/* Channel opens, in SSHReactor.c. */
int outersshpriv_reactor_open_streamlocal_channel(
    SSHReactor *reactor,
    SSHReactorChannelToken *channel_token,
    const char *socket_path,
    size_t socket_path_length,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open);
int outersshpriv_reactor_open_tcp_channel(
    SSHReactor *reactor,
    SSHReactorChannelToken *channel_token,
    const char *host,
    size_t host_length,
    int port,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds,
    SSHReactorPendingChannelOpen pending_open);
void outersshpriv_reactor_remove_channel_actions_for_close(SSHReactor *reactor,
    SSHReactorChannelToken token);

/* Relays, in SSHReactorRelay.c. */
int outersshpriv_reactor_apply_relay_data(
    SSHReactor *reactor,
    RelaySlot *relay,
    const unsigned char *bytes,
    size_t byte_count);
bool outersshpriv_reactor_channel_allows_initial_exec_assignment(SSHReactor *reactor,
    SSHChannelState *state,
    SSHReactorChannelToken token);
bool outersshpriv_reactor_channel_lifecycle_allows_reassignment(const SSHChannelState *state);
bool outersshpriv_reactor_close_finished_relay(SSHReactor *reactor, RelaySlot *relay);
int outersshpriv_reactor_receive_relay_eof(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle,
    SSHReactorChannelToken channel_token);
void outersshpriv_reactor_remove_prepared_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);
bool outersshpriv_reactor_remove_relay(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);
RelaySlot *outersshpriv_reactor_slot_for_handle(
    SSHReactor *reactor,
    SSHReactorRelayHandle handle);
void outersshpriv_reactor_update_relay_read_source(SSHReactor *reactor, RelaySlot *relay);
void outersshpriv_reactor_update_relay_write_source(SSHReactor *reactor, RelaySlot *relay);

/* Write actions and channel output buffers, in SSHReactorOutput.c. */
void outersshpriv_reactor_append_reserved_write_action(SSHReactor *reactor,
    SSHWriteAction action,
    bool at_front);
int outersshpriv_reactor_append_write_action(SSHReactor *reactor,
    SSHWriteAction action,
    bool at_front);
size_t outersshpriv_reactor_buffer_pending_byte_count(
    const SSHChannelOutputBuffer *buffer);
const SSHWriteAction *outersshpriv_reactor_const_write_action_at(const SSHReactor *reactor, size_t offset);
void outersshpriv_reactor_destroy_write_action(SSHWriteAction *action);
int outersshpriv_reactor_enqueue_channel_close(SSHReactor *reactor,
    SSHReactorChannelToken token);
int outersshpriv_reactor_enqueue_channel_eof(SSHReactor *reactor,
    SSHChannelState *state,
    SSHReactorChannelToken token);
int outersshpriv_reactor_enqueue_protocol_response(SSHReactor *reactor,
    const unsigned char *packet,
    size_t packet_length);
bool outersshpriv_reactor_has_write_action(SSHReactor *reactor,
    SSHWriteActionType type,
    SSHReactorChannelToken token);
void outersshpriv_reactor_move_write_action_to_front(SSHReactor *reactor, size_t offset);
void outersshpriv_reactor_output_buffer_clear(SSHChannelOutputBuffer *buffer,
    bool keeping_capacity);
void outersshpriv_reactor_output_buffer_deinitialize(SSHChannelOutputBuffer *buffer);
int outersshpriv_relay_buffer_initialize(SSHRelayBuffer *buffer, size_t capacity);
void outersshpriv_relay_buffer_deinitialize(SSHRelayBuffer *buffer);
/* Fails without copying when byte_count exceeds the free space. */
int outersshpriv_relay_buffer_append(SSHRelayBuffer *buffer, const void *bytes, size_t byte_count);
int outersshpriv_reactor_output_buffer_initialize(SSHChannelOutputBuffer *buffer,
    size_t initial_capacity);
void outersshpriv_reactor_pop_write_action(SSHReactor *reactor);
int outersshpriv_reactor_reserve_write_actions(SSHReactor *reactor, size_t minimum_capacity);
SSHWriteAction *outersshpriv_reactor_write_action_at(SSHReactor *reactor, size_t offset);
bool outersshpriv_reactor_write_action_is_removed_for_channel_close(
    const SSHWriteAction *action,
    SSHReactorChannelToken token);

#endif
