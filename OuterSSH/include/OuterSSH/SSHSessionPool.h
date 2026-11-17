#ifndef SSH_SESSION_POOL_H
#define SSH_SESSION_POOL_H

#include <stdbool.h>

#include "OTNullability.h"
#include "SSHEventQueue.h"
#include "SSHSessionAuthentication.h"
#include "SSHProxyError.h"
#include "SSHEndpointNames.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

/* SSH connections to one server/account. Functions may be called from any queue
 * before the pool is destroyed.
 *
 * Requests take a tag chosen by the application and return true when accepted.
 * An accepted request posts exactly one completion event carrying that tag to
 * the pool's event queue, on success or failure; see SSHEvents.h. A request that
 * returns false did nothing and posts no event: its input was invalid or it
 * could not allocate its operation. A pool's and its frontends'
 * completion events arrive before their OUTERSSH_EVENT_DESTROYED events. */
typedef struct OuterSSHSessionPool OuterSSHSessionPool;

#if defined(_WIN32)
/* A file HANDLE. */
typedef void * OT_NULLABLE OuterSSHFileHandle;
#else
/* A file descriptor. */
typedef int OuterSSHFileHandle;
#endif

/* Host-key fingerprints are "SHA256:" followed by unpadded base64, as OpenSSH
 * prints them. The capacity includes a terminating NUL. */
#define OUTERSSH_HOST_KEY_FINGERPRINT_CAPACITY 64

/* Additional remote allowlists, checked alongside the standard OuterSSH files.
 * System paths must be absolute and files must be root-owned. User paths may
 * start with %h/ (remote home) or %c/ (remote XDG_CONFIG_HOME, default ~/.config).
 * User files must belong to the SSH user. Neither scope accepts symlinks or
 * group/world-writable files. Entries never grant access across scopes. */
typedef struct {
    const char *path;
    size_t path_length;
    bool system;
} OuterSSHSocketAllowlist;

typedef struct {
    /* Optional upstream SSH transport, with independent authentication and trust.
     * Retained until this pool finishes teardown. Destroy every descendant to
     * allow upstream destruction to complete. Maximum route depth is 16. */
    OuterSSHSessionPool * OT_NULLABLE jump_host;
    const char *hostname;
    size_t hostname_length;
    const char *username;
    size_t username_length;
    /* Zero selects 22. */
    uint16_t port;
    OuterSSHSessionAuthentication authentication;
    const char * OT_NULLABLE ssh_agent_socket_path;
    size_t ssh_agent_socket_path_length;
    /* Optional; see OUTERSSH_HOST_KEY_FINGERPRINT_CAPACITY. Copied. The pool
     * accepts a server host key matching this fingerprint without asking.
     * For any other key, or when this is NULL, it posts
     * OUTERSSH_EVENT_HOST_KEY_VALIDATION before login authentication and waits
     * for outerssh_session_pool_answer_host_key. Trusting a key makes it the
     * pool's trusted fingerprint, so later sessions accept it without asking.
     * Time awaiting the answer does not count toward the authentication
     * timeout; the server may still disconnect. */
    const char * OT_NULLABLE trusted_host_key_fingerprint;
    size_t trusted_host_key_fingerprint_length;
    /* Optional compatibility locations. The array and path bytes are copied
     * before create returns. NULL/0 uses only the standard OuterSSH files. */
    const OuterSSHSocketAllowlist * OT_NULLABLE additional_socket_allowlists;
    size_t additional_socket_allowlist_count;
} OuterSSHSessionPoolConfiguration;

/* Creates a pool and its serial control queue. On Apple platforms the queue
 * and the pool's session queues take the calling thread's quality of service,
 * with user-interactive lowered to user-initiated. Copies configuration
 * strings and authentication bytes before returning. String lengths count UTF-8 bytes,
 * excluding a terminator; null termination is not required. On failure,
 * returns NULL. If error is provided, it receives the result; its text remains
 * valid for the process lifetime. */
OuterSSHSessionPool * OT_NULLABLE outerssh_session_pool_create(
    OuterSSHEventQueue *event_queue,
    const OuterSSHSessionPoolConfiguration *configuration, OuterSSHError * OT_NULLABLE error);

/* Begins shutdown. First destroy every port forward using this pool and wait
 * for their OUTERSSH_EVENT_DESTROYED events. Destroy every HTTP and SOCKS frontend. Their
 * destruction may be submitted immediately before pool destruction on the
 * pool's control queue.
 * Pool destruction asserts that every frontend has begun teardown.
 * Finish submitting calls before destroying the pool and do not use it
 * afterward. Pending requests still complete. OUTERSSH_EVENT_DESTROYED follows
 * after the pool is freed and its reactors
 * have finished closing their sockets and cancelling sources. Remote executable
 * cleanup is best effort and does not produce a destroy error. Destroying a
 * proxy does not shut down its pool. */
bool outerssh_session_pool_destroy(OuterSSHSessionPool *pool, uint64_t tag);

/* Connects and authenticates if needed. Completes with
 * OUTERSSH_EVENT_OPERATION_COMPLETED. */
bool outerssh_session_pool_ensure_session(OuterSSHSessionPool *pool, uint64_t tag);

/* Requests keepalive checks for existing connections. */
void outerssh_session_pool_poke(OuterSSHSessionPool *pool);

/* Copies command and input before returning. Completes with
 * OUTERSSH_EVENT_COMMAND_COMPLETED. */
bool outerssh_session_pool_execute_command(OuterSSHSessionPool *pool,
    const char *command, size_t command_length,
    const void * OT_NULLABLE input, size_t input_length, uint64_t tag);

/* Reads user configuration, then system configuration if absent or empty.
 * Completes with OUTERSSH_EVENT_HOMEPAGE_RECEIVED; found is false without an
 * error when the client should use its own default. Does not authorize
 * endpoints. URL interpretation and supported schemes are the client's
 * responsibility. */
bool outerssh_session_pool_get_homepage(OuterSSHSessionPool *pool, uint64_t tag);

/* How commands run on the server. WINDOWS commands follow Windows
 * command-line rules and can call cmd.exe; POSIX commands run in a POSIX shell. */
typedef enum {
    OUTERSSH_COMMAND_DIALECT_UNKNOWN,
    OUTERSSH_COMMAND_DIALECT_POSIX,
    OUTERSSH_COMMAND_DIALECT_WINDOWS,
} OuterSSHCommandDialect;

/* A command-selection hint from the SSH banner, a named pipe request or remote
 * platform detection, not an identity or authorization result. UNKNOWN until a
 * session connects; once WINDOWS, stays WINDOWS. Safe on any queue. */
OuterSSHCommandDialect outerssh_session_pool_command_dialect(OuterSSHSessionPool *pool);

/* Watches an allowlisted path independently of forwarding. Paths are copied.
 * OUTERSSH_EVENT_OPERATION_COMPLETED reports subscription success or failure. Initial and
 * changed availability arrive as OUTERSSH_EVENT_SOCKET_AVAILABILITY. An absent
 * socket can be watched. A path is a Unix socket or, on Windows servers, a
 * named pipe.
 * A socket file can outlive the server that created it, so a connection that
 * finds nothing listening at a watched path (OUTERSSH_SESSION_ERROR_NOT_LISTENING)
 * also reports it unavailable, until the socket is created again.
 * Temporary observation failures do not report absence; watches resume after
 * reconnecting. Repeating watch replaces that path's subscription. Unwatch
 * removes it. Subscriptions end when the pool is destroyed. */
bool outerssh_session_pool_watch_socket(OuterSSHSessionPool *pool,
    const char *path, size_t path_length, uint64_t tag);
bool outerssh_session_pool_unwatch_socket(OuterSSHSessionPool *pool,
    const char *path, size_t path_length, uint64_t tag);

typedef struct {
    uint64_t identifier;
    const char *path;
    size_t path_length;
    bool privileged;
} OuterSSHBridgeInfo;

/* Lists running traffic bridges, excluding the authorization/watch service.
 * Completes with OUTERSSH_EVENT_BRIDGES_RECEIVED; identifiers belong to
 * this pool. */
bool outerssh_session_pool_get_bridges(OuterSSHSessionPool *pool, uint64_t tag);

/* Retires this bridge and schedules closure of all its streams. Old streams
 * cannot restart it. Future requests may start a new bridge normally.
 * An already retired identifier is a successful no-op. Completes with
 * OUTERSSH_EVENT_OPERATION_COMPLETED. */
bool outerssh_session_pool_close_bridge(OuterSSHSessionPool *pool,
    uint64_t identifier, uint64_t tag);

/* Starts the helper service if needed. Queues one OUTERSSH_EVENT_ENDPOINT_NAMES
 * with the current state, then another after each helper update. A pending
 * endpoint-names event is replaced rather than followed by a second one. */
void outerssh_session_pool_observe_endpoint_names(OuterSSHSessionPool *pool);

/* The server's per-user endpoint icon cache, kept by the helper service; see
 * SSHEndpointNames.h for its limits. transport is "unix", "pipe" or "tcp" and
 * port is zero except for tcp, as in outerssh_endpoint_records_find. Name
 * actual server-side endpoints, never browser forwarding addresses. Requests
 * return false for an endpoint that endpoints.d would reject, or for a PNG that
 * outerssh_endpoint_icon_is_valid rejects.
 *
 * Store copies its inputs, replaces the endpoint's icon, and completes with
 * OUTERSSH_EVENT_OPERATION_COMPLETED. Get completes with
 * OUTERSSH_EVENT_ENDPOINT_ICON_RECEIVED. */
bool outerssh_session_pool_store_endpoint_icon(OuterSSHSessionPool *pool,
    const char *transport, const char *address, size_t address_length, uint16_t port,
    const void *png, size_t png_length, uint64_t tag);
bool outerssh_session_pool_get_endpoint_icon(OuterSSHSessionPool *pool,
    const char *transport, const char *address, size_t address_length, uint16_t port, uint64_t tag);

/* Sends request bytes to the application-defined request handler of the
 * helper the application supplied (see OUTERSSH_EVENT_HELPER_BINARY_NEEDED),
 * over the helper's service channel, starting the helper if needed. Copies the
 * request, which must be 1 byte to 1 MiB. Completes with
 * OUTERSSH_EVENT_HELPER_RESPONSE. */
bool outerssh_session_pool_send_helper_request(OuterSSHSessionPool *pool,
    const void *request, size_t length, uint64_t tag);

/* Answer question events. Safe on any queue. */
void outerssh_session_pool_answer_host_key(OuterSSHSessionPool *pool, uint64_t question, bool trusted);

/* Answers OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED with the user's sudo password.
 * Copies the password before returning. OuterSSH starts the bridge with it and
 * clears its copy afterwards. If sudo rejects it, OuterSSH asks again with the
 * error. Send a saved password only on the first attempt: each rejected one is
 * a failed sudo login, which can lock the account. A NULL password with a
 * nonzero length declines. */
void outerssh_session_pool_provide_sudo_password(OuterSSHSessionPool *pool, uint64_t question,
    const char *password, size_t password_length);
/* Fails the connections waiting on OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED, for
 * example because the user cancelled or the application cannot prompt. */
void outerssh_session_pool_decline_sudo_password(OuterSSHSessionPool *pool, uint64_t question);

/* Answers OUTERSSH_EVENT_HELPER_BINARY_NEEDED with the packaged file's bytes:
 * length bytes starting at offset in file, for example an asset inside an
 * Android APK. OuterSSH maps the region read-only and uploads it without
 * copying; the bytes must not change while the pool may use them.
 *
 * Always takes ownership of file and closes it, including when the question is
 * stale or cancelled. An unreadable region fails the installation with an
 * OUTERSSH_ERROR_HELPER_INSTALLER error. */
void outerssh_session_pool_provide_helper_binary(OuterSSHSessionPool *pool, uint64_t question,
    OuterSSHFileHandle file, uint64_t offset, uint64_t length);
/* Fails the installation that asked with error. Copies the error's text before
 * returning. An error without a domain becomes
 * OUTERSSH_HELPER_INSTALLER_ERROR_MISSING_PACKAGED_BINARY. */
void outerssh_session_pool_decline_helper_binary(OuterSSHSessionPool *pool, uint64_t question,
    OuterSSHError error);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif
#endif
