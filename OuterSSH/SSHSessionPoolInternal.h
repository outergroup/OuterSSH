#ifndef SSH_SESSION_POOL_INTERNAL_H
#define SSH_SESSION_POOL_INTERNAL_H

#include "OTNullability.h"
#include "SSHEventQueueInternal.h"
#include "SSHSessionPool.h"
#include "SSHContinuations.h"
#include "SSHWaiting.h"
#include "include/OuterSSH/ProxyTypes.h"
#include "include/OuterSSH/SSHEvents.h"

#include "platform/OTSocket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "platform/OTQueue.h"

#include "ProxyReactor.h"
#include "SSHReactor.h"
#include "SSHReactorHandshake.h"
#include "SSHReactorAuthentication.h"
#include "SSHProxyError.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

typedef struct SSHSocketBridgeOperation SSHSocketBridgeOperation;
typedef struct SSHProxyBridgeState SSHProxyBridgeState;
typedef struct SSHPoolEvent SSHPoolEvent;
typedef struct SSHPoolQuestion SSHPoolQuestion;
typedef struct SSHSudoPasswordRequest SSHSudoPasswordRequest;
typedef struct SSHBridgeBinary SSHBridgeBinary;

typedef struct {
    uint64_t generation;
    SSHReactor * OT_NULLABLE reactor;
} SSHSessionSlot;

/* What a bridge executable installation is waiting for. */
typedef enum {
    SSH_BRIDGE_INSTALL_IDLE,
    SSH_BRIDGE_INSTALL_NEEDS_SUDO_CHECK,
    SSH_BRIDGE_INSTALL_CHECKING_SUDO,
    SSH_BRIDGE_INSTALL_NEEDS_PLATFORM,
    SSH_BRIDGE_INSTALL_NEEDS_BINARY,
    SSH_BRIDGE_INSTALL_INSTALLING,
} SSHBridgeInstallStep;

typedef struct {
    SSHSessionSlot * OT_NULLABLE slots;
    size_t count;
    size_t capacity;
    size_t * OT_NULLABLE available_indices;
    size_t available_index_count;
    size_t available_index_capacity;
} SSHSessionStore;


struct OuterSSHSessionPool {
    struct SSHSocketService *socket_service;
    bool destroy_requested;
    bool destruction_submitted;
    atomic_size_t transport_dependents;
    OuterSSHSessionPool *jump_host;
    /* Relays this pool's SSH transport through jump_host. */
    struct SSHForwarder *jump_forward;
    unsigned route_depth;
    /* The reserved OUTERSSH_EVENT_DESTROYED reply, sent once the pool is freed. */
    SSHPoolEvent *destroyed_reply;
    size_t pending_operations;
    // Includes removed sessions until their reactor teardown returns to this queue.
    size_t live_sessions;
    otqueue_t _queue;
    ProxyReactor *_connectorReactor;
    SSHSessionStore _sessions;
    /* Operations waiting for a session; see outersshpriv_session_pool_run_when_ready. */
    SSHWaitList _sessionWaiters;
    ProxyReactorTCPConnectHandle _connectHandle;
    SSHSessionCreationOperation * OT_NULLABLE _sessionCreation;
    bool _disconnecting;
    bool _disconnected;
    /* Control queue only. Frontends unlink when destruction begins. */
    struct SSHForwarder * OT_NULLABLE proxy_servers;
    uint64_t proxy_generation;
    atomic_int _commandDialect;
    /* Control queue only; see SSHCommandFlows.c. */
    ExecuteCommandContext * OT_NULLABLE _windowsInputCommand;
    ExecuteCommandContext * OT_NULLABLE _heldCommands;
    size_t _windowsRunningCommands;
    char * OT_NULLABLE _remotePlatform;
    size_t _remotePlatformLength;
    bool _remotePlatformLookupRunning;
    /* Control queue only; see SSHBridgeInstallationFlows.c. */
    SSHBridgeInstallStep _userBridgeInstall;
    SSHBridgeInstallStep _sudoBridgeInstall;
    unsigned _bridgeInstallDepth;
    SSHProxyBridgeState *bridge_states;
    size_t bridge_state_count;
    size_t bridge_state_capacity;
    uint64_t _nextRelayIdentifier;
    bool _directStreamLocalUnsupported;
    char *_userBridgeInstallID;
    size_t _userBridgeInstallID_length;
    char *_sudoBridgeInstallID;
    size_t _sudoBridgeInstallID_length;
    char *_userBridgeExecutablePath;
    size_t _userBridgeExecutablePath_length;
    bool _userBridgeIsPreinstalled;
    char *_sudoBridgeExecutablePath;
    size_t _sudoBridgeExecutablePath_length;
    /* Operations waiting for _userBridgeExecutablePath or _sudoBridgeExecutablePath. */
    SSHWaitList _userBridgeWaiters;
    SSHWaitList _sudoBridgeWaiters;
    /* The packaged executable, asked of the application for installations
     * that need it and held until none do. */
    bool _bridgeBinaryRequested;
    SSHBridgeBinary * OT_NULLABLE _bridgeBinary;
    SSHSocketBridgeOperation *_bridgeSetupHead;
    /* Borrowed from the first operation waiting for the sudo executable. */
    const char * OT_NULLABLE _sudoBridgeInstallPassword;
    size_t _sudoBridgeInstallPasswordLength;
    /* The password and a newline, sent ahead of the executable. */
    char * OT_NULLABLE _sudoBridgeInstallPasswordLine;
    size_t _sudoBridgeInstallPasswordLineLength;
    bool _sudoBridgeInstallRequiresPassword;
    int8_t _remoteUserIsRoot;
    /* Operations waiting for _remoteUserIsRoot. */
    SSHWaitList _remoteUserWaiters;
    bool _disconnectFinalizationStarted;
    bool shutdown_requested;
    char *socket_allowlist_arguments;
    /* Control queue only. */
    char _trustedHostKeyFingerprint[OUTERSSH_HOST_KEY_FINGERPRINT_CAPACITY];
    size_t _trustedHostKeyFingerprintLength;
    bool _endpointNamesObserved;
    /* Must outlive the pool; receives its events. */
    OuterSSHEventQueue *_event_queue;
    /* Control queue only. */
    SSHPoolQuestion *_questions;
    uint64_t _nextQuestion;
    /* Proxy connections waiting for a sudo password, grouped by proxy and socket. */
    SSHSudoPasswordRequest *_sudoPasswordRequests;
    char *_hostname;
    size_t _hostnameLength;
    char *_username;
    size_t _usernameLength;
    int32_t _port;
    OuterSSHSessionAuthentication _authentication;
    char *_sshAgentSocketPath;
    size_t _sshAgentSocketPathLength;
};

struct SSHSessionCreationOperation {
    // Session startup remains pending through the authentication callback.
    OuterSSHSessionPool *pool;
    LIBSSH2_SESSION *session;
    bool cancellation_requested;
    bool windows_banner;
    OuterSSHError completed_error;
    char *error_storage;
    SSHReactor * OT_NULLABLE reactor;
};

typedef struct {
    SSHReactorSocketBridgeHandle handle;
    OuterSSHSessionPool *pool;
    SSHSessionPoolSessionHandle session;
} SSHSocketBridge;

typedef struct {
    SSHReactorSocketBridgeHandle bridge_handle;
    SSHReactorSocketBridgeStreamHandle handle;
    OuterSSHSessionPool *pool;
    SSHSessionPoolSessionHandle session;
} SSHSocketBridgeStream;

struct SSHRelayRecoveryOperation {
    // Owned here until handed to the reactor; a failed attempt returns it here.
    SSHRelay * OT_NULLABLE relay;
    OuterSSHSessionPool *pool;
    SSHSessionPoolSessionHandle session;
    SSHReactor * OT_NULLABLE reactor;
    bool may_retry;
    SSHReactorRelayOpenResult result;
    SSHWaiter waiter;
};

/* Control queue only. Count an asynchronous operation from its first queued
 * step through its final callback. Nested work covered by its parent does not
 * need another count. End and finish_destroy_if_ready may free the pool. */
void outersshpriv_session_pool_begin_operation(OuterSSHSessionPool *pool);
void outersshpriv_session_pool_end_operation(OuterSSHSessionPool *pool);
void outersshpriv_session_pool_finish_destroy_if_ready(OuterSSHSessionPool *pool);

/* Posting runs on the control queue and copies every borrowed value. A post
 * that cannot allocate is dropped. A new endpoint-names event replaces any
 * pending one. */
void outersshpriv_session_pool_post_endpoint_names(OuterSSHSessionPool *pool,
    bool known, const OuterSSHEndpointRecord * OT_NULLABLE records, size_t count);
void outersshpriv_session_pool_post_socket_availability(OuterSSHSessionPool *pool,
    const char *path, size_t path_length, bool available);
void outersshpriv_session_pool_post_connection_failure(OuterSSHSessionPool *pool,
    const void *frontend, const char *host, size_t host_length, uint16_t port,
    const char *socket_path, size_t socket_path_length, OuterSSHError error);

typedef enum {
    SSH_QUESTION_ACCEPTED,
    SSH_QUESTION_DECLINED,
    SSH_QUESTION_CANCELLED,
} SSHQuestionAnswer;

/* Runs exactly once on the control queue, possibly before ask returns and
 * possibly from within cancel_questions, so it must not re-enter either. */
typedef void (*SSHQuestionContinuation)(void * OT_NULLABLE context, SSHQuestionAnswer answer);

/* Control queue only. Posts a question event and waits for the application's
 * answer. Questions asked after shutdown begins are cancelled immediately. */
void outersshpriv_session_pool_ask_host_key(OuterSSHSessionPool *pool,
    const void *host_key, size_t host_key_length,
    const char *fingerprint, size_t fingerprint_length,
    SSHQuestionContinuation continuation, void * OT_NULLABLE context);
/* Runs like SSHQuestionContinuation. When accepted, password is a malloc'd
 * copy the continuation owns and must clear before freeing; otherwise NULL. */
typedef void (*SSHSudoPasswordContinuation)(void * OT_NULLABLE context, SSHQuestionAnswer answer,
    char * OT_NULLABLE password, size_t password_length);
void outersshpriv_session_pool_ask_sudo_password(OuterSSHSessionPool *pool, const void *owner,
    const void *frontend, const char *socket_path, size_t socket_path_length,
    uint32_t attempt, OuterSSHError error,
    SSHSudoPasswordContinuation continuation, void * OT_NULLABLE context);
/* Runs like SSHQuestionContinuation. When accepted, binary is the provided
 * mapping and the continuation owns one reference. When declined, error
 * describes why; its text is valid only during the call. */
typedef void (*SSHBridgeBinaryContinuation)(void * OT_NULLABLE context, SSHQuestionAnswer answer,
    SSHBridgeBinary * OT_NULLABLE binary, OuterSSHError error);
void outersshpriv_session_pool_ask_bridge_binary(OuterSSHSessionPool *pool,
    const char *name, size_t name_length,
    SSHBridgeBinaryContinuation continuation, void * OT_NULLABLE context);
/* Cancels pending questions from owner, or all questions when owner is NULL.
 * Unpolled question events are withdrawn; polled ones get a cancellation event. */
void outersshpriv_session_pool_cancel_questions(OuterSSHSessionPool *pool, const void * OT_NULLABLE owner);
void outersshpriv_session_pool_dispose_events(OuterSSHSessionPool *pool);

/* A read-only mapping of the packaged bridge executable. Reference counting
 * is safe on any queue. Mapping takes ownership of file and closes it in every
 * case. On failure it returns NULL and sets error, whose text is static or
 * stored in *error_storage for the caller to free. */
SSHBridgeBinary * OT_NULLABLE outersshpriv_bridge_binary_map(OuterSSHFileHandle file,
    uint64_t offset, uint64_t length, OuterSSHError *error, char * OT_NULLABLE * OT_NONNULL error_storage);
const void *outersshpriv_bridge_binary_bytes(const SSHBridgeBinary *binary, size_t *length);
SSHBridgeBinary *outersshpriv_bridge_binary_retain(SSHBridgeBinary *binary);
/* Takes an SSHBridgeBinary; matches SSHCommandRequest's release callbacks. */
void outersshpriv_bridge_binary_release(void * OT_NULLABLE binary);

SSHReactor * OT_NULLABLE outersshpriv_session_pool_available_reactor(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle *session);

/* Resumes the operation once a session is ready or cannot be, exactly once on
 * the pool queue and possibly before returning. The waiter is embedded in the
 * operation. On resume, call outersshpriv_session_pool_ready_reactor. */
void outersshpriv_session_pool_run_when_ready(
    OuterSSHSessionPool *pool,
    SSHWaiter *waiter,
    SSHCompletionHandler resume,
    void * OT_NULLABLE context);
/* After resuming from run_when_ready: the reactor of an available session, or
 * NULL with error set when the wait failed, the pool is closing, or no session
 * remains. */
SSHReactor * OT_NULLABLE outersshpriv_session_pool_ready_reactor(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle *session,
    OuterSSHError *error);
SSHSessionPoolSessionHandle outersshpriv_session_pool_allocate_session(
    OuterSSHSessionPool *pool,
    SSHReactor *reactor);
/* Wakes every operation waiting for a session. */
void outersshpriv_session_pool_wake_session_waiters(
    OuterSSHSessionPool *pool,
    OuterSSHError error);

typedef struct {
    const char *command;
    size_t command_byte_count;
    bool during_shutdown;
    /* Zero uses the default of five minutes. */
    uint64_t execution_timeout_milliseconds;
    void (* OT_NULLABLE release_command)(void * OT_NULLABLE context);
    void * OT_NULLABLE release_command_context;
    /* Sent before standard_input. Borrowed until completion. */
    const void * OT_NULLABLE standard_input_prefix;
    size_t standard_input_prefix_byte_count;
    const void * OT_NULLABLE standard_input;
    size_t standard_input_byte_count;
    void (* OT_NULLABLE release_input)(void * OT_NULLABLE context);
    void * OT_NULLABLE release_input_context;
} SSHCommandRequest;

/* Pool queue only. Completion can run before returning; result buffers are
 * borrowed until it returns. Command and input storage are borrowed, never
 * copied, including by the SSH channel that sends the input.
 * Each buffer must remain immutable until its release callback runs, exactly once
 * before completion, including validation/allocation failures. Without a release
 * callback, the caller keeps that buffer valid and immutable until completion.
 * Each release context must remain valid until its callback runs. */
void outersshpriv_execute_command(
    OuterSSHSessionPool *pool,
    SSHCommandRequest request,
    SSHCommandHandler completion,
    void *context);
void outersshpriv_disconnect_session_pool(OuterSSHSessionPool *pool);
SSHReactor * OT_NULLABLE outersshpriv_session_pool_reactor_for_session(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle session);
void outersshpriv_session_pool_close_proxy_connections(
    OuterSSHSessionPool *pool,
    uint64_t proxy_generation);

void outersshpriv_socket_bridge_cancel_stream(
    SSHSocketBridge bridge,
    SSHSocketBridgeStream stream);
void outersshpriv_socket_bridge_stop(SSHSocketBridge bridge);

void outersshpriv_session_pool_prepared_relay_completed(
    ConnectRelayContext *operation,
    SSHReactorRelayHandle handle,
    SSHReactorRelayOpenResult result,
    uint32_t reason);
void outersshpriv_session_pool_socket_bridge_completed(
    void *context,
    SSHReactorSocketBridgeHandle handle,
    SSHReactorSocketBridgeResult result,
    uint32_t reason,
    const void * OT_NULLABLE detail,
    size_t detail_length);
void outersshpriv_session_pool_socket_bridge_stream_completed(
    ConnectBridgeStreamContext *operation,
    SSHReactorSocketBridgeHandle bridge_handle,
    SSHReactorSocketBridgeStreamHandle stream_handle,
    SSHReactorSocketBridgeStreamResult result,
    const void * OT_NULLABLE detail,
    size_t detail_length);
// Pool queue only; completion owns the operation until authentication returns.
bool outersshpriv_cancel_session_startup(SSHSessionCreationOperation *operation);

OuterSSHSessionPool * OT_NULLABLE outersshpriv_session_pool_active(OuterSSHSessionPool *pool);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif

#endif
