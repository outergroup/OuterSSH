#include "ProxyPendingConnectionsInternal.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void direct_connection_readable(void *opaque);
static void cancel_pending_connection_sources(
    ProxyReactor *reactor,
    ProxyPendingConnection *pending);
static void complete_pending_connection(
    ProxyReactor *reactor,
    ProxyPendingConnection *pending);

#pragma mark - Start a Direct Connection

static void start_connection(ProxyReactor *reactor, otsocket_t socket,
    ProxyConnectionRoute route, ProxyReactorListenerHandle listener,
    ProxyDirectConnectionCompletion completion, void *context)
{
    ProxyReactorPendingConnectionHandle handle = outersshpriv_proxy_pending_connection_allocate(reactor, socket);
    if (handle.generation == 0) {
        otsocket_close(socket);
        if (completion) completion(context, PROXY_SOCKS_REPLY_GENERAL_FAILURE, false);
        return;
    }
    ProxyPendingConnection *connection = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    connection->route = route;
    connection->listener = listener;
    connection->direct_completion = completion;
    connection->direct_context = context;
    connection->phase = PROXY_PENDING_AWAITING_TARGET;
    if (!outersshpriv_proxy_pending_connection_watch_read(reactor, handle, direct_connection_readable)) {
        outersshpriv_proxy_pending_connection_close(reactor, handle);
        return;
    }
    outersshpriv_proxy_server_pending_connection(reactor->server, handle, route);
}

void outersshpriv_proxy_reactor_start_direct_connection(ProxyReactor *reactor, otsocket_t socket,
    ProxyConnectionRoute route, ProxyDirectConnectionCompletion completion, void *context)
{
    start_connection(reactor, socket, route, (ProxyReactorListenerHandle){0}, completion, context);
}

void outersshpriv_proxy_reactor_start_forwarded_connection(ProxyReactor *reactor,
    ProxyReactorListenerHandle listener, otsocket_t socket, ProxyConnectionRoute route)
{
    start_connection(reactor, socket, route, listener, NULL, NULL);
}

static void direct_connection_readable(void *opaque)
{
    ProxySourceContext *context = opaque;
    ProxyPendingConnection *connection = outersshpriv_proxy_pending_connection_for_handle(context->reactor, context->pending_connection);
    if (connection) outersshpriv_proxy_pending_connection_monitor(context->reactor, context->pending_connection, connection);
}

#pragma mark - Allocate and Look Up Pending Connections

ProxyReactorPendingConnectionHandle outersshpriv_proxy_pending_connection_allocate(ProxyReactor *reactor, otsocket_t socket)
{
    size_t index;
    if (reactor->available_pending_connection_index_count) {
        index = reactor->available_pending_connection_indices[--reactor->available_pending_connection_index_count];
    } else {
        if (reactor->pending_connection_count == SIZE_MAX ||
            !outersshpriv_proxy_pending_connection_reserve(reactor, reactor->pending_connection_count + 1))
            return (ProxyReactorPendingConnectionHandle){0};
        index = reactor->pending_connection_count++;
    }
    ProxyPendingConnection *connection = &reactor->pending_connections[index];
    if (++connection->generation == 0) connection->generation = 1;
    connection->socket = socket;
    connection->is_active = true;
    return (ProxyReactorPendingConnectionHandle){index, connection->generation};
}

bool outersshpriv_proxy_pending_connection_reserve(
    ProxyReactor *reactor,
    size_t minimum_capacity)
{
    if (reactor->pending_connection_capacity >= minimum_capacity) {
        return true;
    }

    size_t capacity = reactor->pending_connection_capacity == 0
        ? 8
        : reactor->pending_connection_capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*reactor->pending_connections)) {
        return false;
    }

    ProxyPendingConnection *slots = calloc(capacity, sizeof(*slots));
    if (slots == NULL) {
        return false;
    }
    size_t *available_indices = malloc(
        capacity * sizeof(*available_indices));
    if (available_indices == NULL) {
        free(slots);
        return false;
    }

    if (reactor->pending_connection_count != 0) {
        memcpy(slots, reactor->pending_connections, reactor->pending_connection_count * sizeof(*slots));
    }
    if (reactor->available_pending_connection_index_count > 0) {
        memcpy(
            available_indices,
            reactor->available_pending_connection_indices,
            reactor->available_pending_connection_index_count *
                sizeof(*available_indices));
    }

    free(reactor->pending_connections);
    free(reactor->available_pending_connection_indices);
    reactor->pending_connections = slots;
    reactor->available_pending_connection_indices = available_indices;
    reactor->pending_connection_capacity = capacity;
    return true;
}

ProxyPendingConnection *outersshpriv_proxy_pending_connection_for_handle(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle handle)
{
    if (handle.generation == 0 ||
        handle.index >= reactor->pending_connection_count) {
        return NULL;
    }
    ProxyPendingConnection *pending = &reactor->pending_connections[handle.index];
    if (!pending->is_active ||
        pending->generation != handle.generation) {
        return NULL;
    }
    return pending;
}

bool outersshpriv_proxy_reactor_pending_connection_is_active(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection_handle)
{
    if (reactor == NULL) {
        return false;
    }
    otqueue_assert(reactor->queue);
    ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(
        reactor,
        connection_handle);
    return pending != NULL &&
        pending->phase == PROXY_PENDING_AWAITING_TARGET;
}

#pragma mark - Monitor Pending Sockets

bool outersshpriv_proxy_pending_connection_watch_read(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle,
    void (*readable)(void *))
{
    ProxyPendingConnection *connection = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    ProxySourceContext *context = outersshpriv_proxy_reactor_create_source_context(reactor, NULL);
    if (context == NULL) return false;
    connection->read_socket_source = otsource_create(
        OTSOURCE_TYPE_READ, (uintptr_t)connection->socket, reactor->queue);
    if (connection->read_socket_source == NULL) {
        outersshpriv_proxy_reactor_source_cancelled(context);
        return false;
    }
    context->source = connection->read_socket_source;
    context->pending_connection = handle;
    connection->uncancelled_socket_source_count++;
    otsource_set_context(connection->read_socket_source, context);
    otsource_set_cancel_handler(connection->read_socket_source, outersshpriv_proxy_pending_connection_source_cancelled);
    otsource_set_event_handler(connection->read_socket_source, readable);
    otsource_activate(connection->read_socket_source);
    return true;
}

void outersshpriv_proxy_pending_connection_monitor(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle handle,
    ProxyPendingConnection *pending)
{
    if (pending->phase != PROXY_PENDING_AWAITING_TARGET) {
        return;
    }
    while (true) {
        unsigned char byte = 0;
        ssize_t result = otsocket_recv(
            pending->socket,
            &byte,
            sizeof(byte),
            MSG_PEEK);
        if (result > 0) {
            outersshpriv_proxy_reactor_cancel_source(&pending->read_socket_source);
            return;
        }
        if (result == 0) {
            if (pending->socks) outersshpriv_socks_pending_connection_read_failed(reactor, handle, true, 0);
            else outersshpriv_proxy_pending_connection_close(reactor, handle);
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        int error_code = errno;
        if (pending->socks) outersshpriv_socks_pending_connection_read_failed(reactor, handle, false, error_code);
        else outersshpriv_proxy_pending_connection_close(reactor, handle);
        return;
    }
}

#pragma mark - Complete or Fail a Pending Connection

void outersshpriv_proxy_reactor_complete_pending_connection(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection_handle,
    ProxySocketTransferHandler finished,
    void *context)
{
    otqueue_assert(reactor->queue);
    ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(reactor, connection_handle);
    if (pending == NULL ||
        pending->phase != PROXY_PENDING_AWAITING_TARGET ||
        pending->route.request.host[0] == '\0' || pending->transfer_finished != NULL) {
        finished(context, -1);
        return;
    }
    pending->transfer_finished = finished;
    pending->transfer_context = context;
    if (pending->socks == NULL) outersshpriv_proxy_pending_connection_transfer(reactor, connection_handle);
    else outersshpriv_socks_pending_connection_ready(reactor, connection_handle);
}

bool outersshpriv_proxy_reactor_fail_pending_connection(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection_handle,
    ProxySOCKSReplyStatus status)
{
    if (reactor == NULL) {
        return false;
    }
    otqueue_assert(reactor->queue);
    ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(
        reactor,
        connection_handle);
    if (pending == NULL ||
        pending->phase != PROXY_PENDING_AWAITING_TARGET) {
        return false;
    }
    if (pending->socks == NULL) {
        pending->failure_status = status;
        outersshpriv_proxy_pending_connection_close(reactor, connection_handle);
        return true;
    }
    return outersshpriv_socks_pending_connection_failed(reactor, connection_handle, status);
}

void outersshpriv_proxy_reactor_transfer_pending_connection(ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection,
    ProxySocketTransferHandler finished, void *context)
{
    otqueue_assert(reactor->queue);
    ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(reactor, connection);
    if (pending == NULL || pending->phase != PROXY_PENDING_AWAITING_TARGET ||
        pending->transfer_finished != NULL) {
        finished(context, -1);
        return;
    }
    pending->transfer_finished = finished;
    pending->transfer_context = context;
    outersshpriv_proxy_pending_connection_transfer(reactor, connection);
}

void outersshpriv_proxy_pending_connection_transfer(
    ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle handle)
{
    ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    assert(pending != NULL && pending->transfer_finished != NULL);
    pending->phase = PROXY_PENDING_TRANSFERRING;
    cancel_pending_connection_sources(reactor, pending);
}

void outersshpriv_proxy_pending_connection_close(ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle)
{
    ProxyPendingConnection *connection = outersshpriv_proxy_pending_connection_for_handle(reactor, handle);
    if (connection == NULL || connection->phase == PROXY_PENDING_CLOSING) return;
    connection->phase = PROXY_PENDING_CLOSING;
    cancel_pending_connection_sources(reactor, connection);
}

static void cancel_pending_connection_sources(
    ProxyReactor *reactor,
    ProxyPendingConnection *pending)
{
    outersshpriv_proxy_reactor_cancel_source(&pending->read_socket_source);
    outersshpriv_proxy_reactor_cancel_source(&pending->write_socket_source);
    outersshpriv_proxy_reactor_cancel_source(&pending->timeout_timer);
    if (pending->uncancelled_socket_source_count == 0) {
        complete_pending_connection(reactor, pending);
    }
}

void outersshpriv_proxy_pending_connection_source_cancelled(void *opaque_context)
{
    ProxySourceContext *context = opaque_context;
    ProxyReactor *reactor = context->reactor;
    ProxyPendingConnection *pending =
        &reactor->pending_connections[context->pending_connection.index];
    assert(pending->is_active &&
           pending->generation == context->pending_connection.generation);
    assert(pending->uncancelled_socket_source_count > 0);
    pending->uncancelled_socket_source_count--;
    if (pending->uncancelled_socket_source_count == 0 &&
        (pending->phase == PROXY_PENDING_CLOSING ||
         pending->phase == PROXY_PENDING_TRANSFERRING)) {
        complete_pending_connection(reactor, pending);
    }
    outersshpriv_proxy_reactor_source_cancelled(context);
}

static void complete_pending_connection(
    ProxyReactor *reactor,
    ProxyPendingConnection *pending)
{
    assert(pending->uncancelled_socket_source_count == 0);
    size_t index = (size_t)(pending - reactor->pending_connections);
    ProxySocketTransferHandler finished = pending->transfer_finished;
    void *context = pending->transfer_context;
    ProxyDirectConnectionCompletion direct_completion = pending->direct_completion;
    void *direct_context = pending->direct_context;
    bool forwarding_denied = pending->forwarding_denied;
    ProxySOCKSReplyStatus failure_status = pending->failure_status == PROXY_SOCKS_REPLY_SUCCEEDED
        ? PROXY_SOCKS_REPLY_GENERAL_FAILURE : pending->failure_status;
    SOCKSHandshake *socks = pending->socks;
    otsocket_t original_socket = pending->socket;
    otsocket_t transferred_socket = -1;
    if (pending->phase == PROXY_PENDING_TRANSFERRING) {
        assert(finished != NULL);
        transferred_socket = pending->socket;
        pending->socket = -1;
    }
    if (pending->socket >= 0) {
        otsocket_close(pending->socket);
    }
    *pending = (ProxyPendingConnection){
        .generation = pending->generation,
        .socket = -1
    };
    reactor->available_pending_connection_indices[
        reactor->available_pending_connection_index_count++] = index;

    outersshpriv_socks_handshake_destroy(socks, original_socket);
    if (finished != NULL) {
        finished(context, transferred_socket);
    }
    if (direct_completion) {
        direct_completion(direct_context, transferred_socket != -1 ? PROXY_SOCKS_REPLY_SUCCEEDED : failure_status,
            forwarding_denied);
    }
}

#pragma mark - Associate Connections with Session Pools

void outersshpriv_proxy_reactor_set_connection_pool(ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection, OuterSSHSessionPool *pool, uint64_t proxy_generation)
{
    ProxyPendingConnection *pending = outersshpriv_proxy_pending_connection_for_handle(reactor, connection);
    if (pending != NULL) {
        pending->pool = pool;
        pending->proxy_generation = proxy_generation;
    }
}

void outersshpriv_proxy_reactor_cancel_pool_pending_connections(ProxyReactor *reactor, OuterSSHSessionPool *pool, uint64_t proxy_generation)
{
    for (size_t i = 0; i < reactor->pending_connection_count; i++) {
        ProxyPendingConnection *pending = &reactor->pending_connections[i];
        if (pending->is_active && pending->pool == pool && pending->proxy_generation == proxy_generation)
            outersshpriv_proxy_pending_connection_close(reactor, (ProxyReactorPendingConnectionHandle){i, pending->generation});
    }
}

#pragma mark - Cancel Listener Connections

void outersshpriv_proxy_reactor_cancel_pending_connections_for_listener(
    ProxyReactor *reactor,
    ProxyReactorListenerHandle listener_handle)
{
    for (size_t index = 0;
         index < reactor->pending_connection_count;
         index++) {
        ProxyPendingConnection *pending = &reactor->pending_connections[index];
        if (!pending->is_active ||
            pending->listener.index != listener_handle.index ||
            pending->listener.generation != listener_handle.generation) {
            continue;
        }
        ProxyReactorPendingConnectionHandle handle = {
            .index = index,
            .generation = pending->generation
        };
        outersshpriv_proxy_pending_connection_close(reactor, handle);
    }
}

void outersshpriv_proxy_reactor_cancel_all_pending_connections(ProxyReactor *reactor)
{
    for (size_t index = 0;
         index < reactor->pending_connection_count;
         index++) {
        ProxyPendingConnection *pending = &reactor->pending_connections[index];
        if (!pending->is_active) {
            continue;
        }
        ProxyReactorPendingConnectionHandle handle = {
            .index = index,
            .generation = pending->generation
        };
        outersshpriv_proxy_pending_connection_close(reactor, handle);
    }
}
