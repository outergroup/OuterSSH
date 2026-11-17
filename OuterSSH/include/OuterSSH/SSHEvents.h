#ifndef SSH_EVENTS_H
#define SSH_EVENTS_H

#include "OTNullability.h"
#include "SSHEventQueue.h"
#include "SSHSessionPool.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

typedef enum {
    OUTERSSH_EVENT_ENDPOINT_NAMES = 1,
    OUTERSSH_EVENT_SOCKET_AVAILABILITY,
    OUTERSSH_EVENT_CONNECTION_FAILED,
    OUTERSSH_EVENT_HOST_KEY_VALIDATION,
    OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED,
    OUTERSSH_EVENT_HELPER_BINARY_NEEDED,
    OUTERSSH_EVENT_QUESTION_CANCELLED,
    OUTERSSH_EVENT_OPERATION_COMPLETED,
    OUTERSSH_EVENT_COMMAND_COMPLETED,
    OUTERSSH_EVENT_HOMEPAGE_RECEIVED,
    OUTERSSH_EVENT_BRIDGES_RECEIVED,
    OUTERSSH_EVENT_PROXY_STARTED,
    OUTERSSH_EVENT_PORT_FORWARD_STARTED,
    OUTERSSH_EVENT_DESTROYED,
    OUTERSSH_EVENT_ENDPOINT_ICON_RECEIVED,
    OUTERSSH_EVENT_HELPER_RESPONSE,
} OuterSSHEventType;

/* Events report something, ask a question, or complete a request. pool names
 * the pool the event concerns; after OUTERSSH_EVENT_DESTROYED it is only an
 * identifier. Completions carry the request's tag; other events have tag 0.
 *
 * A question carries an identifier; answer it once with the matching answer
 * function. The pool cancels questions it no longer needs: an unpolled question
 * is withdrawn from the queue, and a polled one is followed by
 * OUTERSSH_EVENT_QUESTION_CANCELLED. Answers to cancelled or unknown questions
 * are ignored.
 *
 * Strings and byte payloads, including error text, are followed by a NUL that
 * their lengths exclude. Completion payloads are empty when error.domain is not
 * OUTERSSH_ERROR_NONE. */
typedef struct {
    OuterSSHEventType type;
    OuterSSHSessionPool * OT_NULLABLE pool;
    uint64_t tag;
    union {
        /* The server's trusted endpoint registry, as described in
         * SSHEndpointNames.h. known is false when the helper could not read
         * its registrations; records is then NULL and count zero. */
        struct {
            bool known;
            const OuterSSHEndpointRecord * OT_NULLABLE records;
            size_t count;
        } endpoint_names;
        /* A watched path's initial or changed availability. */
        struct {
            const char *path;
            size_t path_length;
            bool available;
        } socket_availability;
        /* A frontend rejected a pending connection. frontend is the
         * OuterSSHSOCKSProxyServer, OuterSSHHTTPProxyServer or
         * OuterSSHPortForward that accepted it. socket_path is empty for TCP
         * destinations. */
        struct {
            const void *frontend;
            const char *host;
            size_t host_length;
            uint16_t port;
            const char *socket_path;
            size_t socket_path_length;
            OuterSSHError error;
        } connection_failed;
        /* Question: trust this host key? The pool has no trusted fingerprint,
         * or the key did not match it. host_key is the key blob in SSH wire
         * format; host_key_algorithm is its algorithm name, such as
         * "ssh-ed25519" or "ecdsa-sha2-nistp256". */
        struct {
            uint64_t question;
            const unsigned char *host_key;
            size_t host_key_length;
            const char *host_key_algorithm;
            size_t host_key_algorithm_length;
            const char *fingerprint;
            size_t fingerprint_length;
        } host_key_validation;
        /* Question: proxy connections to socket_path need a sudo bridge, and
         * sudo needs a password; OuterSSH has already tried without one.
         * frontend is the OuterSSHSOCKSProxyServer or OuterSSHHTTPProxyServer
         * whose connections wait. Connections from that proxy to the same
         * socket share one question. error is empty the first time;
         * when the previous password failed, it holds that failure. attempt
         * counts from 1; OuterSSH asks again after each failure until the
         * application declines.
         * Answer with outerssh_session_pool_provide_sudo_password or
         * outerssh_session_pool_decline_sudo_password. Every application with
         * a proxy must answer; one that cannot prompt declines. The
         * connections stay pending until the question is answered or
         * cancelled. */
        struct {
            uint64_t question;
            const void *frontend;
            const char *socket_path;
            size_t socket_path_length;
            uint32_t attempt;
            OuterSSHError error;
        } sudo_password_needed;
        /* Question: provide the application's OuterSSH helper build for the
         * server's platform: "linux-aarch64-glibc", "linux-aarch64-musl",
         * "linux-armv7-glibc", "linux-armv7-musl", "linux-x86_64-glibc",
         * "linux-x86_64-musl", "macos-arm64", "macos-x86_64", "windows-arm64",
         * "windows-x64" or "windows-x86". Answer with
         * outerssh_session_pool_provide_helper_binary or
         * outerssh_session_pool_decline_helper_binary. For "windows-" platforms,
         * provide a gzip-compressed tar archive holding one file named
         * "outerssh-helper.exe"; otherwise provide a gzip-compressed
         * executable. A pool asks for each platform at most once at a time;
         * concurrent installations share the answer. */
        struct {
            uint64_t question;
            const char *platform;
            size_t platform_length;
        } helper_binary_needed;
        struct {
            uint64_t question;
        } question_cancelled;
        /* A request that produces no value finished. */
        struct {
            OuterSSHError error;
        } operation_completed;
        struct {
            OuterSSHError error;
            const unsigned char * OT_NULLABLE standard_output;
            size_t standard_output_length;
            const unsigned char * OT_NULLABLE standard_error;
            size_t standard_error_length;
            int32_t exit_status;
        } command_completed;
        /* found is false without an error when no homepage is configured. */
        struct {
            OuterSSHError error;
            bool found;
            const char * OT_NULLABLE url;
            size_t url_length;
            const char * OT_NULLABLE source_path;
            size_t source_path_length;
        } homepage_received;
        struct {
            OuterSSHError error;
            const OuterSSHBridgeInfo * OT_NULLABLE bridges;
            size_t count;
        } bridges_received;
        /* A proxy started listening. */
        struct {
            OuterSSHError error;
            uint16_t listen_port;
            const char * OT_NULLABLE username;
            size_t username_length;
            const char * OT_NULLABLE password;
            size_t password_length;
        } proxy_started;
        struct {
            OuterSSHError error;
            uint16_t listen_port;
        } port_forward_started;
        /* found is false without an error when no icon is cached. */
        struct {
            OuterSSHError error;
            bool found;
            const unsigned char * OT_NULLABLE png;
            size_t length;
        } endpoint_icon_received;
        /* The helper's response to outerssh_session_pool_send_helper_request. */
        struct {
            OuterSSHError error;
            const unsigned char * OT_NULLABLE bytes;
            size_t length;
        } helper_response;
    };
} OuterSSHEvent;

#if !defined(__APPLE__)
#if defined(_WIN32)
/* A manual-reset event HANDLE. */
typedef void * OT_NULLABLE OuterSSHEventWaitHandle;
#define OUTERSSH_EVENT_WAIT_HANDLE_INVALID NULL
#else
/* An eventfd to watch for readability. */
typedef int OuterSSHEventWaitHandle;
#define OUTERSSH_EVENT_WAIT_HANDLE_INVALID (-1)
#endif

/* Returns a handle that is signaled while the event queue has pending events,
 * or OUTERSSH_EVENT_WAIT_HANDLE_INVALID if one could not be created. The event
 * queue owns it; only wait on it. Stop waiting before destroying the event
 * queue. Safe on any thread. */
OuterSSHEventWaitHandle outerssh_event_queue_wait_handle(OuterSSHEventQueue *event_queue);
#endif

/* Moves up to capacity pending events into events, oldest first, and returns
 * how many. Payloads stay valid until the next call for this event queue or
 * until the event queue is destroyed. Safe on any thread; calls for one event
 * queue must not overlap. */
size_t outerssh_event_queue_poll(OuterSSHEventQueue *event_queue, OuterSSHEvent *events, size_t capacity);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif
#endif
