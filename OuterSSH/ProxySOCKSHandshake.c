#include "platform/OTSocket.h"
#include "ProxyPendingConnectionsInternal.h"
#include "SSHSocketBridgeInternal.h"
#include <assert.h>
#include <errno.h>
#include "platform/SSHLogging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef ProxyReactorPendingConnectionHandle SOCKSHandshakeHandle;

typedef enum {
    SOCKS_HANDSHAKE_READING_GREETING_HEADER,
    SOCKS_HANDSHAKE_READING_METHODS,
    SOCKS_HANDSHAKE_READING_AUTHENTICATION_HEADER,
    SOCKS_HANDSHAKE_READING_USERNAME,
    SOCKS_HANDSHAKE_READING_PASSWORD_LENGTH,
    SOCKS_HANDSHAKE_READING_PASSWORD,
    SOCKS_HANDSHAKE_READING_REQUEST_HEADER,
    SOCKS_HANDSHAKE_READING_DOMAIN_LENGTH,
    SOCKS_HANDSHAKE_READING_ADDRESS,
    SOCKS_HANDSHAKE_READING_PORT,
} SOCKSHandshakePhase;

typedef struct {
    ProxySOCKSHandshakeErrorCode code;
    int detail;
    bool is_present;
} SOCKSHandshakeError;

struct SOCKSHandshake {
    unsigned char expected_username[UINT8_MAX + 1];
    size_t expected_username_length;
    unsigned char expected_password[UINT8_MAX + 1];
    size_t expected_password_length;
    unsigned char supplied_username[UINT8_MAX + 1];
    size_t supplied_username_length;
    char request_host[UINT8_MAX + 1];
    size_t request_host_length;
    SOCKSHandshakeError terminal_error;
    SOCKSHandshakePhase phase;
    unsigned char address_type;
    unsigned char read_bytes[UINT8_MAX + 1];
    size_t read_count, read_offset;
    unsigned char write_bytes[32];
    size_t write_count, write_offset;
    bool requires_authentication;
    bool has_origin;
    char *origin;
    size_t origin_length;
};

static void start_socks5_handshake(
    ProxyReactor *reactor,
    ProxyReactorListenerHandle listener_handle,
    otsocket_t socket);
static void handshake_socket_readable(void *opaque_context);
static void process_handshake_reads(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle);
static bool advance_socks_handshake(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    ProxyPendingConnection *handshake);
static void finish_handshake_with_reply_error(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    unsigned char status,
    SOCKSHandshakeError error);
static void finish_handshake_after_output(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    const unsigned char *bytes,
    size_t byte_count,
    SOCKSHandshakeError error);
static bool queue_handshake_output(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    ProxyPendingConnection *handshake,
    const unsigned char *bytes,
    size_t byte_count);
static void handshake_socket_writable(void *opaque_context);
static bool process_handshake_writes(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    ProxyPendingConnection *handshake);
static bool ensure_handshake_write_source(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    ProxyPendingConnection *handshake);
static void finish_handshake_with_error(ProxyReactor *reactor, SOCKSHandshakeHandle handle, SOCKSHandshakeError error);
static void reset_handshake_timeout(ProxyPendingConnection *handshake);
static void handshake_timed_out(void *opaque_context);
static void handle_handshake_timeout(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle);
static void set_handshake_read_count(
    ProxyPendingConnection *handshake,
    size_t byte_count);
static void stop_handshake_reads(ProxyPendingConnection *handshake);
static int configure_accepted_socket(otsocket_t socket);

static void report_handshake_start_error(
    otsocket_t socket,
    SOCKSHandshakeError error);
static SOCKSHandshakeError socks_error(
    ProxySOCKSHandshakeErrorCode code,
    int detail);
static void describe_socks_error(
    SOCKSHandshakeError error,
    char *description,
    size_t capacity);

#pragma mark - Accept and Negotiate SOCKS

void outersshpriv_proxy_reactor_accept_connections(
    ProxyReactor *reactor,
    ProxyReactorListenerHandle handle)
{
    while (true) {
        ListenerSlot *listener = outersshpriv_proxy_reactor_listener_for_handle(reactor, handle);
        if (listener == NULL) {
            return;
        }

        struct sockaddr_storage address = {0};
        socklen_t address_length = sizeof(address);
        otsocket_t socket = otsocket_accept(
            listener->socket,
            (struct sockaddr *)&address,
            &address_length);
        if (socket >= 0) {
            int configuration_error = configure_accepted_socket(socket);
            if (configuration_error != 0) {
                report_handshake_start_error(
                    socket,
                    socks_error(
                        PROXY_SOCKS_HANDSHAKE_READ_FAILED,
                        configuration_error));
                continue;
            }
            if (listener->forward_route.request.host_length != 0) {
                outersshpriv_proxy_reactor_start_forwarded_connection(reactor, handle, socket, listener->forward_route);
                continue;
            }
            start_socks5_handshake(
                reactor,
                handle,
                socket);
            continue;
        }

        int error_code = errno;
        if (error_code == EINTR) {
            continue;
        }
        if (error_code != EAGAIN && error_code != EWOULDBLOCK) {
            SSH_LOG_ERROR(SSH_LOG_CATEGORY_RELAY,
                "SOCKS proxy accept failed: %{public}s",
                strerror(error_code));
        }
        return;
    }
}

static void start_socks5_handshake(
    ProxyReactor *reactor,
    ProxyReactorListenerHandle listener_handle,
    otsocket_t socket)
{
    ListenerSlot *listener = outersshpriv_proxy_reactor_listener_for_handle(reactor, listener_handle);
    if (listener == NULL) {
        otsocket_close(socket);
        return;
    }
    if (listener->username == NULL || listener->password == NULL ||
        listener->username_length > UINT8_MAX ||
        listener->password_length > UINT8_MAX) {
        report_handshake_start_error(
            socket,
            socks_error(PROXY_SOCKS_HANDSHAKE_AUTHENTICATION_FAILED, 0));
        return;
    }

    SOCKSHandshake *socks = calloc(1, sizeof(*socks));
    if (socks == NULL) {
        report_handshake_start_error(socket, socks_error(PROXY_SOCKS_HANDSHAKE_READ_FAILED, ENOMEM));
        return;
    }
    SOCKSHandshakeHandle handle = outersshpriv_proxy_pending_connection_allocate(reactor, socket);
    if (handle.generation == 0) {
        free(socks);
        report_handshake_start_error(socket, socks_error(PROXY_SOCKS_HANDSHAKE_READ_FAILED, ENOMEM));
        return;
    }
    ProxyPendingConnection *handshake = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    handshake->socks = socks;
    handshake->listener = listener_handle;
    handshake->socks->requires_authentication = listener->requires_authentication;
    memcpy(
        handshake->socks->expected_username,
        listener->username,
        listener->username_length);
    handshake->socks->expected_username_length = listener->username_length;
    memcpy(
        handshake->socks->expected_password,
        listener->password,
        listener->password_length);
    handshake->socks->expected_password_length = listener->password_length;
    handshake->socks->phase = SOCKS_HANDSHAKE_READING_GREETING_HEADER;
    set_handshake_read_count(handshake, 2);

    if (!outersshpriv_proxy_pending_connection_watch_read(reactor, handle, handshake_socket_readable)) {
        finish_handshake_with_error(reactor, handle, socks_error(PROXY_SOCKS_HANDSHAKE_READ_FAILED, ENOMEM));
        return;
    }

    ProxySourceContext *timeout_context =
        outersshpriv_proxy_reactor_create_source_context(reactor, NULL);
    if (timeout_context == NULL) {
        finish_handshake_with_error(
            reactor, handle, socks_error(PROXY_SOCKS_HANDSHAKE_READ_FAILED, ENOMEM));
        return;
    }
    handshake->timeout_timer = otsource_create(
        OTSOURCE_TYPE_TIMER, 0, reactor->queue);
    if (handshake->timeout_timer == NULL) {
        outersshpriv_proxy_reactor_source_cancelled(timeout_context);
        finish_handshake_with_error(
            reactor, handle, socks_error(PROXY_SOCKS_HANDSHAKE_READ_FAILED, ENOMEM));
        return;
    }
    timeout_context->source = handshake->timeout_timer;
    timeout_context->pending_connection = handle;
    otsource_set_context(handshake->timeout_timer, timeout_context);
    otsource_set_cancel_handler(
        handshake->timeout_timer, outersshpriv_proxy_reactor_source_cancelled);
    otsource_set_event_handler(
        handshake->timeout_timer, handshake_timed_out);
    reset_handshake_timeout(handshake);
    otsource_activate(handshake->timeout_timer);

}

static void handshake_socket_readable(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    process_handshake_reads(context->reactor, context->pending_connection);
}

static void process_handshake_reads(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle)
{
    ProxyPendingConnection *handshake = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    while (true) {
        if (handshake == NULL ||
            handshake->phase == PROXY_PENDING_REPLYING ||
            handshake->phase == PROXY_PENDING_CLOSING ||
            handshake->phase == PROXY_PENDING_TRANSFERRING) {
            return;
        }
        if (handshake->phase == PROXY_PENDING_AWAITING_TARGET) {
            outersshpriv_proxy_pending_connection_monitor(reactor, handle, handshake);
            return;
        }
        if (handshake->socks->read_offset == handshake->socks->read_count) {
            if (!advance_socks_handshake(reactor, handle, handshake)) {
                return;
            }
            continue;
        }

        ssize_t result = otsocket_read(
            handshake->socket,
            handshake->socks->read_bytes + handshake->socks->read_offset,
            handshake->socks->read_count - handshake->socks->read_offset);
        if (result > 0) {
            handshake->socks->read_offset += (size_t)result;
            reset_handshake_timeout(handshake);
            continue;
        }
        if (result == 0) {
            finish_handshake_with_error(
                reactor,
                handle,
                socks_error(PROXY_SOCKS_HANDSHAKE_CLIENT_CLOSED, 0));
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        int error_code = errno;
        finish_handshake_with_error(
            reactor,
            handle,
            socks_error(PROXY_SOCKS_HANDSHAKE_READ_FAILED, error_code));
        return;
    }
}

static bool advance_socks_handshake(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    ProxyPendingConnection *handshake)
{
    switch (handshake->socks->phase) {
    case SOCKS_HANDSHAKE_READING_GREETING_HEADER: {
        if (handshake->socks->read_bytes[0] != 0x05) {
            finish_handshake_with_error(
                reactor,
                handle,
                socks_error(PROXY_SOCKS_HANDSHAKE_INVALID_GREETING, 0));
            return false;
        }
        handshake->socks->phase = SOCKS_HANDSHAKE_READING_METHODS;
        set_handshake_read_count(handshake, handshake->socks->read_bytes[1]);
        return true;
    }
    case SOCKS_HANDSHAKE_READING_METHODS: {
        const unsigned char method = handshake->socks->requires_authentication ? 0x02 : 0x00;
        bool supports_method = false;
        for (size_t index = 0; index < handshake->socks->read_count; index++) {
            if (handshake->socks->read_bytes[index] == method) {
                supports_method = true;
                break;
            }
        }
        if (!supports_method) {
            const unsigned char rejection[] = {0x05, 0xff};
            finish_handshake_after_output(
                reactor,
                handle,
                rejection,
                sizeof(rejection),
                socks_error(
                    PROXY_SOCKS_HANDSHAKE_AUTHENTICATION_METHOD_UNAVAILABLE,
                    0));
            return false;
        }
        const unsigned char selection[] = {0x05, method};
        if (!queue_handshake_output(
                reactor,
                handle, handshake,
                selection,
                sizeof(selection))) {
            return false;
        }
        handshake->socks->phase = handshake->socks->requires_authentication
            ? SOCKS_HANDSHAKE_READING_AUTHENTICATION_HEADER
            : SOCKS_HANDSHAKE_READING_REQUEST_HEADER;
        set_handshake_read_count(handshake, handshake->socks->requires_authentication ? 2 : 4);
        return true;
    }
    case SOCKS_HANDSHAKE_READING_AUTHENTICATION_HEADER:
        if (handshake->socks->read_bytes[0] != 0x01) {
            finish_handshake_with_error(
                reactor,
                handle,
                socks_error(PROXY_SOCKS_HANDSHAKE_INVALID_REQUEST, 0));
            return false;
        }
        handshake->socks->phase = SOCKS_HANDSHAKE_READING_USERNAME;
        set_handshake_read_count(handshake, handshake->socks->read_bytes[1]);
        return true;
    case SOCKS_HANDSHAKE_READING_USERNAME:
        memcpy(
            handshake->socks->supplied_username,
            handshake->socks->read_bytes,
            handshake->socks->read_count);
        handshake->socks->supplied_username_length = handshake->socks->read_count;
        handshake->socks->phase = SOCKS_HANDSHAKE_READING_PASSWORD_LENGTH;
        set_handshake_read_count(handshake, 1);
        return true;
    case SOCKS_HANDSHAKE_READING_PASSWORD_LENGTH:
        handshake->socks->phase = SOCKS_HANDSHAKE_READING_PASSWORD;
        set_handshake_read_count(handshake, handshake->socks->read_bytes[0]);
        return true;
    case SOCKS_HANDSHAKE_READING_PASSWORD: {
        bool credentials_match =
            handshake->socks->supplied_username_length ==
                handshake->socks->expected_username_length &&
            memcmp(
                handshake->socks->supplied_username,
                handshake->socks->expected_username,
                handshake->socks->expected_username_length) == 0 &&
            handshake->socks->read_count == handshake->socks->expected_password_length &&
            memcmp(
                handshake->socks->read_bytes,
                handshake->socks->expected_password,
                handshake->socks->expected_password_length) == 0;
        if (!credentials_match && handshake->socks->requires_authentication) {
            credentials_match = outersshpriv_proxy_server_origin_for_credentials(reactor->server,
                handshake->socks->supplied_username, handshake->socks->supplied_username_length,
                handshake->socks->read_bytes, handshake->socks->read_count,
                &handshake->socks->origin, &handshake->socks->origin_length);
            handshake->socks->has_origin = credentials_match;
        }
        handshake->socks->supplied_username_length = 0;
        if (!credentials_match) {
            const unsigned char rejection[] = {0x01, 0x01};
            finish_handshake_after_output(
                reactor,
                handle,
                rejection,
                sizeof(rejection),
                socks_error(PROXY_SOCKS_HANDSHAKE_AUTHENTICATION_FAILED, 0));
            return false;
        }
        const unsigned char success[] = {0x01, 0x00};
        if (!queue_handshake_output(
                reactor,
                handle, handshake,
                success,
                sizeof(success))) {
            return false;
        }
        handshake->socks->phase = SOCKS_HANDSHAKE_READING_REQUEST_HEADER;
        set_handshake_read_count(handshake, 4);
        return true;
    }
    case SOCKS_HANDSHAKE_READING_REQUEST_HEADER:
        if (handshake->socks->read_bytes[0] != 0x05 ||
            handshake->socks->read_bytes[2] != 0x00) {
            finish_handshake_with_error(
                reactor,
                handle,
                socks_error(PROXY_SOCKS_HANDSHAKE_INVALID_REQUEST, 0));
            return false;
        }
        if (handshake->socks->read_bytes[1] != 0x01) {
            finish_handshake_with_reply_error(
                reactor,
                handle,
                0x07,
                socks_error(
                    PROXY_SOCKS_HANDSHAKE_UNSUPPORTED_COMMAND,
                    handshake->socks->read_bytes[1]));
            return false;
        }
        handshake->socks->address_type = handshake->socks->read_bytes[3];
        switch (handshake->socks->address_type) {
        case 0x01:
            handshake->socks->phase = SOCKS_HANDSHAKE_READING_ADDRESS;
            set_handshake_read_count(handshake, 4);
            return true;
        case 0x03:
            handshake->socks->phase = SOCKS_HANDSHAKE_READING_DOMAIN_LENGTH;
            set_handshake_read_count(handshake, 1);
            return true;
        case 0x04:
            handshake->socks->phase = SOCKS_HANDSHAKE_READING_ADDRESS;
            set_handshake_read_count(handshake, 16);
            return true;
        default:
            finish_handshake_with_reply_error(
                reactor,
                handle,
                0x08,
                socks_error(
                    PROXY_SOCKS_HANDSHAKE_UNSUPPORTED_ADDRESS_TYPE,
                    handshake->socks->address_type));
            return false;
        }
    case SOCKS_HANDSHAKE_READING_DOMAIN_LENGTH:
        handshake->socks->phase = SOCKS_HANDSHAKE_READING_ADDRESS;
        set_handshake_read_count(handshake, handshake->socks->read_bytes[0]);
        return true;
    case SOCKS_HANDSHAKE_READING_ADDRESS:
        switch (handshake->socks->address_type) {
        case 0x01: {
            char text[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(
                    AF_INET,
                    handshake->socks->read_bytes,
                    text,
                    sizeof(text)) == NULL) {
                finish_handshake_with_error(
                    reactor,
                    handle,
                    socks_error(PROXY_SOCKS_HANDSHAKE_INVALID_REQUEST, 0));
                return false;
            }
            handshake->socks->request_host_length = strlen(text);
            memcpy(
                handshake->socks->request_host,
                text,
                handshake->socks->request_host_length);
            break;
        }
        case 0x03:
            handshake->socks->request_host_length = handshake->socks->read_count;
            memcpy(
                handshake->socks->request_host,
                handshake->socks->read_bytes,
                handshake->socks->request_host_length);
            break;
        case 0x04: {
            char text[INET6_ADDRSTRLEN] = {0};
            if (inet_ntop(
                    AF_INET6,
                    handshake->socks->read_bytes,
                    text,
                    sizeof(text)) == NULL) {
                finish_handshake_with_error(
                    reactor,
                    handle,
                    socks_error(PROXY_SOCKS_HANDSHAKE_INVALID_REQUEST, 0));
                return false;
            }
            handshake->socks->request_host_length = strlen(text);
            memcpy(
                handshake->socks->request_host,
                text,
                handshake->socks->request_host_length);
            break;
        }
        default:
            finish_handshake_with_error(
                reactor,
                handle,
                socks_error(PROXY_SOCKS_HANDSHAKE_INVALID_REQUEST, 0));
            return false;
        }
        handshake->socks->phase = SOCKS_HANDSHAKE_READING_PORT;
        set_handshake_read_count(handshake, 2);
        return true;
    case SOCKS_HANDSHAKE_READING_PORT: {
        uint16_t port = (uint16_t)(
            ((uint16_t)handshake->socks->read_bytes[0] << 8) |
            handshake->socks->read_bytes[1]);
        ProxyConnectRequest request = {
            .host_length = handshake->socks->request_host_length,
            .port = port
        };
        memcpy(
            request.host,
            handshake->socks->request_host,
            handshake->socks->request_host_length);
        request.host[handshake->socks->request_host_length] = '\0';
        ListenerSlot *listener = outersshpriv_proxy_reactor_listener_for_handle(
            reactor,
            handshake->listener);
        if (listener == NULL) {
            finish_handshake_with_error(
                reactor,
                handle,
                socks_error(PROXY_SOCKS_HANDSHAKE_INVALID_REQUEST, 0));
            return false;
        }
        ProxyConnectionRoute route = outersshpriv_proxy_resolve_request(request);
        handshake->route = route;
        if (route.kind == PROXY_CONNECTION_ROUTE_REJECTED) {
            finish_handshake_with_reply_error(
                reactor,
                handle,
                PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED,
                (SOCKSHandshakeError){0});
            return false;
        }
        handshake->phase = PROXY_PENDING_AWAITING_TARGET;
        otsource_set_timer(
            handshake->timeout_timer,
            ottime(
                OTTIME_NOW,
                (int64_t)(
                    listener->pending_connection_timeout_milliseconds *
                    NSEC_PER_MSEC)),
            OTTIME_FOREVER,
            0);
        outersshpriv_proxy_server_pending_connection(reactor->server, handle, route);
        handshake = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
        if (handshake == NULL) {
            return false;
        }
        if (handshake->phase != PROXY_PENDING_AWAITING_TARGET) {
            return false;
        }
        outersshpriv_proxy_pending_connection_monitor(reactor, handle, handshake);
        return false;
    }
    }
    abort();
}

#pragma mark - Prepare the Target and Reply

void outersshpriv_socks_pending_connection_ready(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle)
{
    const unsigned char reply[] = {0x05, PROXY_SOCKS_REPLY_SUCCEEDED, 0x00, 0x01, 127, 0, 0, 1, 0, 0};
    finish_handshake_after_output(reactor, handle, reply, sizeof(reply), (SOCKSHandshakeError){0});
}

bool outersshpriv_socks_pending_connection_failed(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle,
    ProxySOCKSReplyStatus status)
{
    switch (status) {
    case PROXY_SOCKS_REPLY_GENERAL_FAILURE:
    case PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED:
    case PROXY_SOCKS_REPLY_NETWORK_UNREACHABLE:
    case PROXY_SOCKS_REPLY_HOST_UNREACHABLE:
    case PROXY_SOCKS_REPLY_CONNECTION_REFUSED:
        break;
    case PROXY_SOCKS_REPLY_SUCCEEDED:
        return false;
    }
    finish_handshake_with_reply_error(reactor, handle, (unsigned char)status, (SOCKSHandshakeError){0});
    return true;
}

static void finish_handshake_with_reply_error(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    unsigned char status,
    SOCKSHandshakeError error)
{
    const unsigned char reply[] = {
        0x05, status, 0x00, 0x01, 127, 0, 0, 1, 0, 0
    };
    finish_handshake_after_output(
        reactor,
        handle,
        reply,
        sizeof(reply),
        error);
}

static void finish_handshake_after_output(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    const unsigned char *bytes,
    size_t byte_count,
    SOCKSHandshakeError error)
{
    ProxyPendingConnection *handshake = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    if (handshake == NULL) {
        return;
    }
    handshake->phase = PROXY_PENDING_REPLYING;
    handshake->socks->terminal_error = error;
    stop_handshake_reads(handshake);
    reset_handshake_timeout(handshake);
    queue_handshake_output(reactor, handle, handshake, bytes, byte_count);
}

static bool queue_handshake_output(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    ProxyPendingConnection *handshake,
    const unsigned char *bytes,
    size_t byte_count)
{
    size_t pending_count = handshake->socks->write_count - handshake->socks->write_offset;
    if (pending_count > 0 && handshake->socks->write_offset > 0) {
        memmove(
            handshake->socks->write_bytes,
            handshake->socks->write_bytes + handshake->socks->write_offset,
            pending_count);
    }
    if (byte_count > sizeof(handshake->socks->write_bytes) - pending_count) {
        finish_handshake_with_error(
            reactor,
            handle,
            socks_error(PROXY_SOCKS_HANDSHAKE_WRITE_FAILED, ENOBUFS));
        return false;
    }
    memcpy(handshake->socks->write_bytes + pending_count, bytes, byte_count);
    handshake->socks->write_offset = 0;
    handshake->socks->write_count = pending_count + byte_count;
    return process_handshake_writes(reactor, handle, handshake);
}

static void handshake_socket_writable(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    ProxyPendingConnection *handshake = outersshpriv_proxy_pending_connection_for_handle(context->reactor, context->pending_connection);
    (void)process_handshake_writes(context->reactor, context->pending_connection, handshake);
}

static bool process_handshake_writes(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    ProxyPendingConnection *handshake)
{
    if (handshake == NULL ||
        handshake->phase == PROXY_PENDING_CLOSING ||
        handshake->phase == PROXY_PENDING_TRANSFERRING) {
        return false;
    }
    while (true) {
        if (handshake->socks->write_offset == handshake->socks->write_count) {
            handshake->socks->write_offset = 0;
            handshake->socks->write_count = 0;
            if (handshake->write_socket_source != NULL) {
                outersshpriv_proxy_reactor_cancel_source(&handshake->write_socket_source);
            }
            if (handshake->phase == PROXY_PENDING_REPLYING) {
                SOCKSHandshakeError error = handshake->socks->terminal_error;
                if (handshake->transfer_finished != NULL) {
                    outersshpriv_proxy_pending_connection_transfer(reactor, handle);
                } else {
                    finish_handshake_with_error(reactor, handle, error);
                }
                return false;
            }
            return true;
        }

        ssize_t result = otsocket_send(
            handshake->socket,
            handshake->socks->write_bytes + handshake->socks->write_offset,
            handshake->socks->write_count - handshake->socks->write_offset,
            OTSOCKET_SEND_FLAGS);
        if (result > 0) {
            handshake->socks->write_offset += (size_t)result;
            reset_handshake_timeout(handshake);
            continue;
        }
        if (result == 0) {
            finish_handshake_with_error(
                reactor,
                handle,
                socks_error(PROXY_SOCKS_HANDSHAKE_CLIENT_CLOSED, 0));
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ensure_handshake_write_source(reactor, handle, handshake);
        }
        int error_code = errno;
        finish_handshake_with_error(
            reactor,
            handle,
            socks_error(PROXY_SOCKS_HANDSHAKE_WRITE_FAILED, error_code));
        return false;
    }
}

static bool ensure_handshake_write_source(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle,
    ProxyPendingConnection *handshake)
{
    if (handshake->write_socket_source != NULL) {
        return true;
    }

    ProxySourceContext *context =
        outersshpriv_proxy_reactor_create_source_context(reactor, NULL);
    if (context == NULL) {
        finish_handshake_with_error(
            reactor, handle, socks_error(PROXY_SOCKS_HANDSHAKE_WRITE_FAILED, ENOMEM));
        return false;
    }
    handshake->write_socket_source = otsource_create(
        OTSOURCE_TYPE_WRITE,
        (uintptr_t)handshake->socket,
        reactor->queue);
    if (handshake->write_socket_source == NULL) {
        outersshpriv_proxy_reactor_source_cancelled(context);
        finish_handshake_with_error(
            reactor, handle, socks_error(PROXY_SOCKS_HANDSHAKE_WRITE_FAILED, ENOMEM));
        return false;
    }
    context->source = handshake->write_socket_source;
    context->pending_connection = handle;
    handshake->uncancelled_socket_source_count++;
    otsource_set_context(handshake->write_socket_source, context);
    otsource_set_cancel_handler(
        handshake->write_socket_source,
        outersshpriv_proxy_pending_connection_source_cancelled);
    otsource_set_event_handler(
        handshake->write_socket_source,
        handshake_socket_writable);
    otsource_activate(handshake->write_socket_source);
    return true;
}

#pragma mark - Handshake Failure

void outersshpriv_socks_pending_connection_read_failed(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle,
    bool closed, int error)
{
    finish_handshake_with_error(reactor, handle,
        socks_error(closed ? PROXY_SOCKS_HANDSHAKE_CLIENT_CLOSED : PROXY_SOCKS_HANDSHAKE_READ_FAILED, error));
}

static void finish_handshake_with_error(ProxyReactor *reactor, SOCKSHandshakeHandle handle, SOCKSHandshakeError error)
{
    ProxyPendingConnection *handshake = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    if (handshake == NULL || handshake->phase == PROXY_PENDING_CLOSING) return;
    handshake->socks->terminal_error = error;
    outersshpriv_proxy_pending_connection_close(reactor, handle);
}

#pragma mark - Handshake Deadlines

static void reset_handshake_timeout(ProxyPendingConnection *handshake)
{
    otsource_set_timer(
        handshake->timeout_timer,
        ottime(OTTIME_NOW, 5 * NSEC_PER_SEC),
        OTTIME_FOREVER,
        0);
}

static void handshake_timed_out(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    handle_handshake_timeout(context->reactor, context->pending_connection);
}

static void handle_handshake_timeout(
    ProxyReactor *reactor,
    SOCKSHandshakeHandle handle)
{
    ProxyPendingConnection *handshake = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    if (handshake == NULL ||
        handshake->phase == PROXY_PENDING_CLOSING ||
        handshake->phase == PROXY_PENDING_TRANSFERRING) {
        return;
    }
    SOCKSHandshakeError error = socks_error(
        PROXY_SOCKS_HANDSHAKE_TIMED_OUT,
        0);
    if (handshake->phase == PROXY_PENDING_AWAITING_TARGET) {
        finish_handshake_with_reply_error(
            reactor,
            handle,
            PROXY_SOCKS_REPLY_GENERAL_FAILURE,
            error);
        return;
    }
    finish_handshake_with_error(reactor, handle, error);
}

#pragma mark - Socket Setup

static void set_handshake_read_count(
    ProxyPendingConnection *handshake,
    size_t byte_count)
{
    handshake->socks->read_count = byte_count;
    handshake->socks->read_offset = 0;
}

static void stop_handshake_reads(ProxyPendingConnection *handshake)
{
    if (handshake->read_socket_source != NULL) {
        outersshpriv_proxy_reactor_cancel_source(&handshake->read_socket_source);
    }
}

static int configure_accepted_socket(otsocket_t socket)
{
    if (otsocket_prevent_inheritance(socket) != 0) {
        return errno;
    }
    int error_code = otsocket_configure_sigpipe(socket);
    if (error_code != 0) {
        return error_code;
    }
    int one = 1;
    if (otsocket_setsockopt(
            socket,
            IPPROTO_TCP,
            TCP_NODELAY,
            &one,
            sizeof(one)) != 0) {
        return errno;
    }
    if (otsocket_set_nonblocking(socket, true) != 0) {
        return errno;
    }
    return 0;
}

#pragma mark - Destroy the Handshake

bool outersshpriv_socks_handshake_origin(const SOCKSHandshake *socks, const char **origin, size_t *origin_length)
{
    *origin = socks->origin;
    *origin_length = socks->origin_length;
    return socks->has_origin;
}

void outersshpriv_socks_handshake_destroy(SOCKSHandshake *socks, otsocket_t socket)
{
    if (socks == NULL) return;
    free(socks->origin);
    if (socks->terminal_error.is_present) {
        char description[256] = {0};
        describe_socks_error(socks->terminal_error, description, sizeof(description));
        SSH_LOG_ERROR(SSH_LOG_CATEGORY_RELAY,
            "SOCKS handshake failed for socket %lld: %{public}s", (long long)socket, description);
    }
    free(socks);
}

#pragma mark - Describe Handshake Errors

static void report_handshake_start_error(
    otsocket_t socket,
    SOCKSHandshakeError error)
{
    otsocket_close(socket);
    char description[256] = {0};
    describe_socks_error(error, description, sizeof(description));
    SSH_LOG_ERROR(SSH_LOG_CATEGORY_RELAY,
        "SOCKS handshake failed for socket %lld: %{public}s",
        (long long)socket,
        description);
}

static SOCKSHandshakeError socks_error(
    ProxySOCKSHandshakeErrorCode code,
    int detail)
{
    return (SOCKSHandshakeError){
        .code = code,
        .detail = detail,
        .is_present = true
    };
}

static void describe_socks_error(
    SOCKSHandshakeError error,
    char *description,
    size_t capacity)
{
    switch (error.code) {
    case PROXY_SOCKS_HANDSHAKE_READ_FAILED:
        snprintf(description, capacity, "SOCKS read failed: %s.",
            strerror(error.detail));
        break;
    case PROXY_SOCKS_HANDSHAKE_WRITE_FAILED:
        snprintf(description, capacity, "SOCKS write failed: %s.",
            strerror(error.detail));
        break;
    case PROXY_SOCKS_HANDSHAKE_TIMED_OUT:
        snprintf(description, capacity, "SOCKS handshake timed out.");
        break;
    case PROXY_SOCKS_HANDSHAKE_CLIENT_CLOSED:
        snprintf(description, capacity,
            "SOCKS client closed the connection.");
        break;
    case PROXY_SOCKS_HANDSHAKE_INVALID_GREETING:
        snprintf(description, capacity, "Invalid SOCKS greeting.");
        break;
    case PROXY_SOCKS_HANDSHAKE_AUTHENTICATION_METHOD_UNAVAILABLE:
        snprintf(description, capacity,
            "SOCKS client did not offer username/password authentication.");
        break;
    case PROXY_SOCKS_HANDSHAKE_AUTHENTICATION_FAILED:
        snprintf(description, capacity, "SOCKS authentication failed.");
        break;
    case PROXY_SOCKS_HANDSHAKE_INVALID_REQUEST:
        snprintf(description, capacity, "Invalid SOCKS request.");
        break;
    case PROXY_SOCKS_HANDSHAKE_UNSUPPORTED_COMMAND:
        snprintf(description, capacity, "Unsupported SOCKS command %d.",
            error.detail);
        break;
    case PROXY_SOCKS_HANDSHAKE_UNSUPPORTED_ADDRESS_TYPE:
        snprintf(description, capacity,
            "Unsupported SOCKS address type %d.", error.detail);
        break;
    }
}
