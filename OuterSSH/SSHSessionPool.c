#include "SSHSocketService.h"
#include "SSHEventsInternal.h"
#include "SSHForwarder.h"
#include "OuterSSH.h"

#include <assert.h>
#include <libssh2.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "ProxyReactorInternal.h"
#include "SSHFlows.h"
#include "SSHSocketBridgeInternal.h"
#include "SocketBridgeCommands.h"
#include "SSHReactor.h"
#include "platform/SSHLogging.h"

static void destroy_pool_on_queue(void *context);
static void finalize_session_pool(void *context);
static void begin_pool_shutdown(OuterSSHSessionPool *pool);
static void dispose_session_configuration(OuterSSHSessionPool *pool);
static void clear_authentication_bytes(const void *bytes, size_t byte_count);
static SSHSessionSlot *session_slot_for_handle(
    SSHSessionStore *store,
    SSHSessionPoolSessionHandle handle);

static inline bool control_queue_is_current(otqueue_t queue)
{
    return otqueue_get_specific(queue) == (void *)queue;
}

OuterSSHCommandDialect outerssh_session_pool_command_dialect(OuterSSHSessionPool *pool)
{
    return (OuterSSHCommandDialect)atomic_load(&pool->_commandDialect);
}

OuterSSHSessionPool *outerssh_session_pool_create(
    OuterSSHEventQueue *event_queue,
    const OuterSSHSessionPoolConfiguration *configuration,
    OuterSSHError *error)
{
    if (error != NULL) *error = (OuterSSHError){0};
    if (!outerssh_initialize(error)) return NULL;
    const char *hostname = configuration->hostname;
    size_t hostname_length = configuration->hostname_length;
    const char *username = configuration->username;
    size_t username_length = configuration->username_length;
    uint16_t port = configuration->port;
    OuterSSHSessionAuthentication authentication = configuration->authentication;
    const char *ssh_agent_socket_path = configuration->ssh_agent_socket_path;
    size_t ssh_agent_socket_path_length = configuration->ssh_agent_socket_path_length;
    size_t fingerprint_length = configuration->trusted_host_key_fingerprint_length;
    static const char fingerprint_prefix[] = "SHA256:";
    bool fingerprint_valid = fingerprint_length == 0 || (configuration->trusted_host_key_fingerprint != NULL &&
            fingerprint_length < OUTERSSH_HOST_KEY_FINGERPRINT_CAPACITY &&
            fingerprint_length > sizeof(fingerprint_prefix) - 1 &&
            memcmp(configuration->trusted_host_key_fingerprint, fingerprint_prefix, sizeof(fingerprint_prefix) - 1) == 0);
    if (!fingerprint_valid ||
        (configuration->jump_host != NULL && configuration->jump_host->route_depth >= 16) ||
        hostname == NULL || hostname_length == 0 ||
        hostname_length > INT_MAX || memchr(hostname, 0, hostname_length) != NULL ||
        !outersshpriv_session_configuration_is_valid(
            username, username_length, authentication,
            ssh_agent_socket_path, ssh_agent_socket_path_length)) {
        if (error != NULL) {
            static const char invalid_configuration_message[] = "Invalid SSH session configuration.";
            *error = outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
                invalid_configuration_message, sizeof(invalid_configuration_message) - 1);
        }
        return NULL;
    }
    OuterSSHSessionPool *pool = calloc(1, sizeof(*pool));
    if (pool == NULL) {
        if (error != NULL) {
            static const char allocation_message[] = "Failed to allocate the SSH session pool.";
            *error = outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
                allocation_message, sizeof(allocation_message) - 1);
        }
        return NULL;
    }
    atomic_init(&pool->_commandDialect, OUTERSSH_COMMAND_DIALECT_UNKNOWN);
    atomic_init(&pool->transport_dependents, 0);
    pool->socket_allowlist_arguments = outersshpriv_socket_bridge_allowlist_arguments(
        configuration->additional_socket_allowlists, configuration->additional_socket_allowlist_count);
    pool->_hostname = malloc(hostname_length);
    pool->_hostnameLength = hostname_length;
    if (pool->_hostname != NULL) {
        memcpy(pool->_hostname, hostname, hostname_length);
    }
    pool->_username = malloc(username_length);
    pool->_usernameLength = username_length;
    if (pool->_username != NULL) {
        memcpy(pool->_username, username, username_length);
    }
    pool->_port = port > 0 ? port : 22;
    if (authentication.kind == OUTERSSH_SESSION_AUTHENTICATION_PASSWORD) {
        pool->_authentication.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD;
        char *password = malloc(authentication.password_length == 0 ? 1 : authentication.password_length);
        if (password != NULL) {
            memcpy(password, authentication.password, authentication.password_length);
        }
        pool->_authentication.password = password;
        pool->_authentication.password_length = authentication.password_length;
    } else if (authentication.kind == OUTERSSH_SESSION_AUTHENTICATION_AGENT) {
        pool->_authentication.kind = OUTERSSH_SESSION_AUTHENTICATION_AGENT;
    } else {
        pool->_authentication.kind = OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY;
        if (authentication.public_key_length != 0) {
            void *public_key = malloc(authentication.public_key_length);
            if (public_key != NULL) {
                memcpy(public_key, authentication.public_key, authentication.public_key_length);
            }
            pool->_authentication.public_key = public_key;
        }
        pool->_authentication.public_key_length = authentication.public_key_length;
        void *private_key = malloc(authentication.private_key_length);
        if (private_key != NULL) {
            memcpy(private_key, authentication.private_key, authentication.private_key_length);
        }
        pool->_authentication.private_key = private_key;
        pool->_authentication.private_key_length = authentication.private_key_length;
        if (authentication.passphrase != NULL) {
            char *passphrase = malloc(authentication.passphrase_length == 0 ? 1 : authentication.passphrase_length);
            if (passphrase != NULL) {
                memcpy(passphrase, authentication.passphrase, authentication.passphrase_length);
            }
            pool->_authentication.passphrase = passphrase;
            pool->_authentication.passphrase_length = authentication.passphrase_length;
        }
    }
    if (ssh_agent_socket_path != NULL) {
        pool->_sshAgentSocketPath = malloc(ssh_agent_socket_path_length == 0 ? 1 : ssh_agent_socket_path_length);
        if (pool->_sshAgentSocketPath != NULL) {
            memcpy(pool->_sshAgentSocketPath, ssh_agent_socket_path, ssh_agent_socket_path_length);
        }
        pool->_sshAgentSocketPathLength = ssh_agent_socket_path_length;
    }
    bool configuration_allocated = pool->socket_allowlist_arguments != NULL && pool->_hostname != NULL &&
        pool->_username != NULL &&
        (authentication.kind == OUTERSSH_SESSION_AUTHENTICATION_AGENT ||
         (authentication.kind == OUTERSSH_SESSION_AUTHENTICATION_PASSWORD
            ? pool->_authentication.password != NULL
            : pool->_authentication.private_key != NULL &&
              (pool->_authentication.public_key_length == 0 ||
               pool->_authentication.public_key != NULL) &&
              (authentication.passphrase == NULL ||
               pool->_authentication.passphrase != NULL))) &&
        (ssh_agent_socket_path == NULL || pool->_sshAgentSocketPath != NULL);
    if (!configuration_allocated) {
        dispose_session_configuration(pool);
        free(pool);
        if (error != NULL) {
            static const char configuration_copy_message[] = "Failed to copy the SSH session configuration.";
            *error = outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
                configuration_copy_message, sizeof(configuration_copy_message) - 1);
        }
        return NULL;
    }
    pool->_event_queue = event_queue;
    pool->_queue = otqueue_create(NULL, "org.outerssh.control");
    if (pool->_queue != NULL) otqueue_set_specific(pool->_queue, pool->_queue, pool->_queue);
    pool->_connectorReactor = pool->_queue == NULL ? NULL : outersshpriv_proxy_reactor_create(pool->_queue);
    if (pool->_connectorReactor == NULL) {
        static const char connector_creation_message[] = "Failed to create the SSH session pool connector.";
        if (pool->_queue != NULL) otqueue_release(pool->_queue);
        dispose_session_configuration(pool);
        free(pool);
        if (error != NULL) *error = outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
            connector_creation_message, sizeof(connector_creation_message) - 1);
        return NULL;
    }
    int32_t install_id_error = 0;
    pool->_userBridgeInstallID_length = 64;
    pool->_userBridgeInstallID = outersshpriv_proxy_reactor_create_credential(32, &install_id_error);
    pool->_sudoBridgeInstallID_length = 64;
    pool->_sudoBridgeInstallID = outersshpriv_proxy_reactor_create_credential(32, &install_id_error);
    if (pool->_userBridgeInstallID == NULL || pool->_sudoBridgeInstallID == NULL) {
        static const char installation_id_message[] = "Failed to allocate socket bridge installation identifiers.";
        if (error != NULL) *error = outerssh_session_error(OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED,
            installation_id_message, sizeof(installation_id_message) - 1);
        free(pool->_userBridgeInstallID);
        free(pool->_sudoBridgeInstallID);
        outersshpriv_proxy_reactor_destroy(pool->_connectorReactor, NULL, NULL);
        otqueue_release(pool->_queue);
        dispose_session_configuration(pool);
        free(pool);
        return NULL;
    }
    pool->_remoteUserIsRoot = -1;
    pool->_nextRelayIdentifier = 1;
    if (fingerprint_length != 0) memcpy(pool->_trustedHostKeyFingerprint, configuration->trusted_host_key_fingerprint, fingerprint_length);
    pool->_trustedHostKeyFingerprintLength = fingerprint_length;
    pool->jump_host = configuration->jump_host;
    if (pool->jump_host != NULL) {
        pool->route_depth = pool->jump_host->route_depth + 1;
        atomic_fetch_add(&pool->jump_host->transport_dependents, 1);
    }
    return pool;
}

bool outerssh_session_pool_destroy(OuterSSHSessionPool *pool, uint64_t tag)
{
    pool->destroyed_reply = outersshpriv_reply_reserve(pool, OUTERSSH_EVENT_DESTROYED, tag);
    if (pool->destroyed_reply == NULL) return false;
    otqueue_async(pool->_queue, pool, destroy_pool_on_queue);
    return true;
}

static void destroy_pool_on_queue(void *context)
{
    OuterSSHSessionPool *pool = context;
    otqueue_assert(pool->_queue);
    assert(!pool->destruction_submitted);
    pool->destruction_submitted = true;
    begin_pool_shutdown(pool);
}

static void transport_released(void *context)
{
    OuterSSHSessionPool *pool = context;
    atomic_fetch_sub(&pool->transport_dependents, 1);
    if (pool->destruction_submitted) begin_pool_shutdown(pool);
}

static void jump_forward_destroyed(void *context)
{
    outersshpriv_session_pool_end_operation(context);
}

static void jump_transport_closed(void *context)
{
    OuterSSHSessionPool *pool = context;
    otqueue_async(pool->_queue, pool, jump_forward_destroyed);
}

static void begin_pool_shutdown(OuterSSHSessionPool *pool)
{
    if (atomic_load(&pool->transport_dependents) != 0 || pool->shutdown_requested) return;
    pool->destroy_requested = true;
    assert(pool->proxy_servers == NULL);
    outersshpriv_disconnect_session_pool(pool);
    outersshpriv_session_pool_finish_destroy_if_ready(pool);
}

void outersshpriv_session_pool_begin_operation(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    assert(pool->pending_operations != SIZE_MAX);
    pool->pending_operations++;
}

void outersshpriv_session_pool_end_operation(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    assert(pool->pending_operations != 0);
    pool->pending_operations--;
    outersshpriv_session_pool_finish_destroy_if_ready(pool);
}

void outersshpriv_session_pool_finish_destroy_if_ready(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    if (!pool->destroy_requested || !pool->_disconnected ||
        pool->pending_operations != 0 || pool->live_sessions != 0 ||
        outersshpriv_proxy_bridge_installs_busy(pool) || pool->_bridgeSetupHead != NULL) return;
    ProxyReactor *reactor = pool->_connectorReactor;
    if (reactor == NULL) return;
    pool->_connectorReactor = NULL;
    outersshpriv_proxy_reactor_destroy(reactor, finalize_session_pool, pool);
}

#pragma mark - Disconnect the Session Pool

static void disconnect_after_bridge_cleanup(void *context);

void outersshpriv_proxy_continue_disconnect_if_requested(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    if (!pool->shutdown_requested || pool->_disconnectFinalizationStarted ||
        outersshpriv_proxy_bridge_installs_busy(pool)) return;
    pool->_disconnectFinalizationStarted = true;
    outersshpriv_proxy_cleanup_bridge_executables(pool, disconnect_after_bridge_cleanup, pool);
}

void outersshpriv_disconnect_session_pool(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    if (pool->shutdown_requested) return;
    pool->shutdown_requested = true;
    outersshpriv_session_pool_cancel_questions(pool, NULL);
    outersshpriv_socket_service_stop(pool);
    for (size_t i = 0; i < pool->bridge_state_count; i++) {
        if (pool->bridge_states[i].is_current)
            outersshpriv_proxy_stop_bridge(pool, (SSHProxyBridgeHandle){i, pool->bridge_states[i].generation});
    }
    outersshpriv_proxy_advance_bridge_installs(pool);
}

static void disconnect_after_bridge_cleanup(void *context)
{
    OuterSSHSessionPool *pool = context;
    otqueue_assert(pool->_queue);
    if (pool->_disconnected) {
        return;
    }
    pool->_disconnecting = true;
    if (pool->jump_forward != NULL) {
        outersshpriv_session_pool_begin_operation(pool);
        outersshpriv_forwarder_destroy(pool->jump_forward, jump_transport_closed, pool);
        pool->jump_forward = NULL;
    }
    if (pool->_connectHandle.generation != 0) {
        (void)outersshpriv_proxy_reactor_cancel_tcp_connect(
            pool->_connectorReactor,
            pool->_connectHandle);
        pool->_connectHandle = (ProxyReactorTCPConnectHandle){0};
    }
    if (pool->_sessionCreation != NULL) {
        (void)outersshpriv_cancel_session_startup(pool->_sessionCreation);
    }
    static const char message[] = "The SSH connection is closing.";
    OuterSSHError closing_error = {
        .domain = OUTERSSH_ERROR_SESSION,
        .code = OUTERSSH_SESSION_ERROR_CONNECTION_CLOSING,
        .message = message, .message_length = sizeof(message) - 1
    };
    outersshpriv_session_pool_wake_session_waiters(pool, closing_error);
    for (size_t index = 0; index < pool->_sessions.count; index++) {
        SSHSessionSlot *slot = &pool->_sessions.slots[index];
        if (slot->reactor != NULL) {
            outersshpriv_remove_session(pool, (SSHSessionPoolSessionHandle){
                .index = index,
                .generation = slot->generation
            });
        }
    }
    pool->_disconnected = true;
    outersshpriv_session_pool_finish_destroy_if_ready(pool);
}

#pragma mark - Remove Session

static void teardown_removed_session(void *opaque_reactor);
static void session_teardown_finished(void *context);
static void session_reactor_destroyed(void *context);

void outersshpriv_remove_session(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle handle)
{
    otqueue_assert(pool->_queue);
    if (handle.generation == 0 || handle.index >= pool->_sessions.count) {
        return;
    }
    SSHSessionSlot *session = &pool->_sessions.slots[handle.index];
    if (session->generation != handle.generation || session->reactor == NULL) {
        return;
    }
    SSHReactor *reactor = session->reactor;
    session->reactor = NULL;
    pool->_sessions.available_indices[
        pool->_sessions.available_index_count++] = handle.index;
    otqueue_async(
        outersshpriv_reactor_queue(reactor),
        reactor,
        teardown_removed_session);
}

static void teardown_removed_session(void *opaque_reactor)
{
    SSHReactor *reactor = opaque_reactor;
    assert(outersshpriv_reactor_is_current_queue(reactor));
    OuterSSHSessionPool *pool =
        outersshpriv_detach_reactor_from_session_pool(reactor);
    assert(pool != NULL);
    size_t created_channel_count = 0;
    size_t freed_channel_count = 0;
    outersshpriv_reactor_teardown(
        reactor,
        &created_channel_count,
        &freed_channel_count);
    SSH_LOG_INFO(
        SSH_LOG_CATEGORY_SESSION,
        "SSH session disconnected; channels created=%{public}zu freed=%{public}zu live=%{public}zu",
        created_channel_count,
        freed_channel_count,
        created_channel_count - freed_channel_count);
    outersshpriv_reactor_destroy(reactor, session_reactor_destroyed, pool);
}

static void session_reactor_destroyed(void *context)
{
    OuterSSHSessionPool *pool = context;
    otqueue_async(pool->_queue, pool, session_teardown_finished);
}

static void session_teardown_finished(void *context)
{
    OuterSSHSessionPool *pool = context;
    otqueue_assert(pool->_queue);
    assert(pool->live_sessions != 0);
    pool->live_sessions--;
    outersshpriv_session_pool_finish_destroy_if_ready(pool);
}

#pragma mark - Dispose Pool Resources

static void finalize_session_pool(void *context)
{
    OuterSSHSessionPool *pool = context;
    for (size_t i = 0; i < pool->bridge_state_count; i++) free(pool->bridge_states[i].path);
    free(pool->bridge_states);
    outersshpriv_socket_service_dispose(pool);
    free(pool->_userBridgeInstallID);
    free(pool->_sudoBridgeInstallID);
    free(pool->_userBridgeExecutablePath);
    free(pool->_sudoBridgeExecutablePath);
    outersshpriv_session_pool_dispose_events(pool);
    otqueue_t queue = pool->_queue;
    free(pool->_sessions.slots);
    free(pool->_sessions.available_indices);
    assert(!outersshpriv_is_waiting(&pool->_sessionWaiters));
    assert(!outersshpriv_is_waiting(&pool->_remoteUserWaiters) &&
        !outersshpriv_is_waiting(&pool->_userBridgeWaiters) &&
        !outersshpriv_is_waiting(&pool->_sudoBridgeWaiters) &&
        pool->_bridgeBinary == NULL && !pool->_bridgeBinaryRequested);
    free(pool->_remotePlatform);
    dispose_session_configuration(pool);
    pool->_queue = NULL;
    SSHPoolEvent *destroyed_reply = pool->destroyed_reply;
    OuterSSHSessionPool *jump_host = pool->jump_host;
    free(pool);
    if (jump_host != NULL) otqueue_async(jump_host->_queue, jump_host, transport_released);
    outersshpriv_reply(destroyed_reply, (OuterSSHError){0});
    otqueue_release(queue);
}

static void dispose_session_configuration(OuterSSHSessionPool *pool)
{
    OuterSSHSessionAuthentication *authentication = &pool->_authentication;
    if (authentication->password != NULL) {
        clear_authentication_bytes(authentication->password, authentication->password_length);
    }
    if (authentication->public_key != NULL) {
        clear_authentication_bytes(authentication->public_key, authentication->public_key_length);
    }
    if (authentication->private_key != NULL) {
        clear_authentication_bytes(authentication->private_key, authentication->private_key_length);
    }
    if (authentication->passphrase != NULL) {
        clear_authentication_bytes(authentication->passphrase, authentication->passphrase_length);
    }
    free(pool->socket_allowlist_arguments);
    free(pool->_hostname);
    free(pool->_username);
    free((void *)pool->_authentication.password);
    free((void *)pool->_authentication.public_key);
    free((void *)pool->_authentication.private_key);
    free((void *)pool->_authentication.passphrase);
    free(pool->_sshAgentSocketPath);
    pool->_hostname = NULL;
    pool->_hostnameLength = 0;
    pool->_username = NULL;
    pool->_usernameLength = 0;
    pool->_authentication = (OuterSSHSessionAuthentication){0};
    pool->_sshAgentSocketPath = NULL;
    pool->_sshAgentSocketPathLength = 0;
}

static void clear_authentication_bytes(const void *bytes, size_t byte_count)
{
    volatile unsigned char *cursor = (volatile unsigned char *)bytes;
    while (byte_count > 0) {
        *cursor++ = 0;
        byte_count--;
    }
}

SSHSessionPoolSessionHandle outersshpriv_session_pool_allocate_session(
    OuterSSHSessionPool *pool,
    SSHReactor *reactor)
{
    SSHSessionStore *store = &pool->_sessions;
    size_t index;
    if (store->available_index_count > 0) {
        index = store->available_indices[--store->available_index_count];
    } else {
        if (store->count == store->capacity) {
            size_t capacity = store->capacity == 0 ? 4 : store->capacity * 2;
            if (capacity <= store->capacity || capacity > SIZE_MAX / sizeof(*store->slots)) {
                return (SSHSessionPoolSessionHandle){0};
            }
            SSHSessionSlot *slots = realloc(store->slots, capacity * sizeof(*slots));
            if (slots == NULL) {
                return (SSHSessionPoolSessionHandle){0};
            }
            memset(slots + store->capacity, 0, (capacity - store->capacity) * sizeof(*slots));
            store->slots = slots;
            store->capacity = capacity;
        }
        if (store->count == store->available_index_capacity) {
            size_t capacity = store->available_index_capacity == 0
                ? 4
                : store->available_index_capacity * 2;
            if (capacity <= store->available_index_capacity ||
                capacity > SIZE_MAX / sizeof(*store->available_indices)) {
                return (SSHSessionPoolSessionHandle){0};
            }
            size_t *indices = realloc(store->available_indices, capacity * sizeof(*indices));
            if (indices == NULL) {
                return (SSHSessionPoolSessionHandle){0};
            }
            store->available_indices = indices;
            store->available_index_capacity = capacity;
        }
        index = store->count++;
    }
    SSHSessionSlot *slot = &store->slots[index];
    slot->generation += 1;
    if (slot->generation == 0) {
        slot->generation = 1;
    }
    slot->reactor = reactor;
    pool->live_sessions++;
    return (SSHSessionPoolSessionHandle){
        .index = index,
        .generation = slot->generation
    };
}

SSHReactor *outersshpriv_session_pool_available_reactor(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle *session)
{
    assert(control_queue_is_current(pool->_queue));
    for (size_t index = 0; index < pool->_sessions.count; index++) {
        SSHSessionSlot *slot = &pool->_sessions.slots[index];
        if (slot->reactor != NULL &&
            !outersshpriv_reactor_session_has_failed(slot->reactor)) {
            *session = (SSHSessionPoolSessionHandle){
                .index = index,
                .generation = slot->generation
            };
            return slot->reactor;
        }
    }
    *session = (SSHSessionPoolSessionHandle){0};
    return NULL;
}

SSHReactor *outersshpriv_session_pool_reactor_for_session(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle handle)
{
    assert(control_queue_is_current(pool->_queue));
    SSHSessionSlot *session = session_slot_for_handle(&pool->_sessions, handle);
    return session == NULL ? NULL : session->reactor;
}

static SSHSessionSlot *session_slot_for_handle(
    SSHSessionStore *store,
    SSHSessionPoolSessionHandle handle)
{
    if (handle.generation == 0 || handle.index >= store->count) {
        return NULL;
    }
    SSHSessionSlot *slot = &store->slots[handle.index];
    return slot->generation == handle.generation && slot->reactor != NULL
        ? slot
        : NULL;
}

#pragma mark - Close Proxy Connections

typedef struct {
    SSHReactor *reactor;
    uint64_t proxy_generation;
} CloseProxyConnectionsContext;

static void close_proxy_connections_on_reactor_and_free(void *opaque_context);

void outersshpriv_session_pool_close_proxy_connections(
    OuterSSHSessionPool *pool,
    uint64_t proxy_generation)
{
    otqueue_assert(pool->_queue);
    for (size_t index = 0; index < pool->_sessions.count; index++) {
        SSHSessionSlot *session = &pool->_sessions.slots[index];
        if (session->reactor == NULL) {
            continue;
        }
        CloseProxyConnectionsContext *context = malloc(sizeof(*context));
        if (context == NULL) {
            outersshpriv_remove_session(
                pool,
                (SSHSessionPoolSessionHandle){
                    .index = index,
                    .generation = session->generation
                });
            continue;
        }
        *context = (CloseProxyConnectionsContext){
            .reactor = session->reactor,
            .proxy_generation = proxy_generation
        };
        otqueue_async(
            outersshpriv_reactor_queue(session->reactor),
            context,
            close_proxy_connections_on_reactor_and_free);
    }
}

static void close_proxy_connections_on_reactor_and_free(void *opaque_context)
{
    CloseProxyConnectionsContext *context = opaque_context;
    outersshpriv_reactor_close_proxy_connections(
        context->reactor,
        context->proxy_generation);
    free(opaque_context);
}

OuterSSHSessionPool *outersshpriv_session_pool_active(OuterSSHSessionPool *pool)
{
    return pool->shutdown_requested || pool->_disconnecting ? NULL : pool;
}
