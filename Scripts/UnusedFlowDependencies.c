#include "SSHProxyErrorInternal.h"
#include "SSHSocketBridgeInternal.h"
#include "SSHSessionPoolInternal.h"
#include "SSHSocketService.h"
#include "ProxyReactorInternal.h"
#include "ProxyPendingConnectionsInternal.h"
#include "SSHFlows.h"
#include "SSHReactorCommandInternal.h"
#include "olibssh/key_exchange.h"
#include "olibssh/key_exchange.h"

#include <stdio.h>
#include <stdlib.h>

/* Strong test doubles override these fallbacks. Reaching one is a failure.
 * COFF linkers also require definitions for dependencies in unused functions. */
#if defined(_MSC_VER) && !defined(__clang__)
#define UNUSED_FLOW(return_type, name, parameters) \
    __pragma(comment(linker, "/alternatename:" #name "=unused_flow_" #name)) \
    return_type unused_flow_##name parameters \
    { fputs("Unexpected flow dependency: " #name "\n", stderr); abort(); }
#else
#define UNUSED_FLOW(return_type, name, parameters) \
    __attribute__((weak)) return_type name parameters \
    { fputs("Unexpected flow dependency: " #name "\n", stderr); abort(); }
#endif

UNUSED_FLOW(int, olibssh_session_free,
    (LIBSSH2_SESSION * session))
UNUSED_FLOW(bool, outerssh_initialize,
    (OuterSSHError * OT_NULLABLE error))
UNUSED_FLOW(OLIBSSHKeyExchangeStep, olibssh_key_exchange_advance,
    (LIBSSH2_SESSION * session, OLIBSSHKeyExchange * exchange))
UNUSED_FLOW(void, olibssh_key_exchange_cleanup,
    (LIBSSH2_SESSION * session, OLIBSSHKeyExchange * exchange))
UNUSED_FLOW(int, olibssh_key_exchange_receive,
    (LIBSSH2_SESSION *session, OLIBSSHKeyExchange *exchange, unsigned char *packet, size_t length))
UNUSED_FLOW(int, olibssh_key_exchange_write,
    (LIBSSH2_SESSION * session, OLIBSSHKeyExchange * exchange))
UNUSED_FLOW(int, olibssh_transport_has_buffered_input,
    (LIBSSH2_SESSION * session))
UNUSED_FLOW(int, olibssh_transport_read,
    (LIBSSH2_SESSION * session, SSHReactor * reactor))
UNUSED_FLOW(int, olibssh_transport_write,
    (LIBSSH2_SESSION *session, const unsigned char *bytes, size_t length, const unsigned char *bytes2, size_t length2))
UNUSED_FLOW(int, olibssh_transport_resume_write,
    (LIBSSH2_SESSION *session))
UNUSED_FLOW(bool, outersshpriv_proxy_reactor_cancel_tcp_connect,
    (ProxyReactor * reactor, ProxyReactorTCPConnectHandle handle))
UNUSED_FLOW(bool, outersshpriv_cancel_session_startup,
    (SSHSessionCreationOperation * OT_NONNULL operation))
UNUSED_FLOW(OuterSSHSessionPool * OT_NULLABLE, outersshpriv_detach_reactor_from_session_pool,
    (SSHReactor * OT_NONNULL reactor))
UNUSED_FLOW(void, outersshpriv_session_pool_wake_session_waiters,
    (OuterSSHSessionPool * OT_NONNULL pool, OuterSSHError error))
UNUSED_FLOW(SSHReactor * OT_NULLABLE, outersshpriv_session_pool_ready_reactor,
    (OuterSSHSessionPool * OT_NONNULL pool, SSHSessionPoolSessionHandle *session, OuterSSHError *error))
UNUSED_FLOW(void, outersshpriv_proxy_cleanup_bridge_executables,
    (OuterSSHSessionPool * OT_NONNULL controller, SSHDestroyHandler OT_NULLABLE completion, void * OT_NULLABLE context))
UNUSED_FLOW(OuterSSHError, outerssh_proxy_closing_error,
    (void))
UNUSED_FLOW(OuterSSHError, outersshpriv_proxy_error,
    (OuterSSHProxyErrorCode code, const char *message, size_t message_length, int32_t system_error_code))
UNUSED_FLOW(void, outersshpriv_proxy_stop_bridge,
    (OuterSSHSessionPool * OT_NONNULL controller, SSHProxyBridgeHandle bridge_handle))
UNUSED_FLOW(void, outersshpriv_reactor_close_proxy_connections,
    (SSHReactor * OT_NONNULL reactor, uint64_t proxy_generation))
UNUSED_FLOW(void, outersshpriv_reactor_command_request_succeeded,
    (SSHReactorCommand *command))
UNUSED_FLOW(void, outersshpriv_reactor_command_request_failed,
    (SSHReactorCommand *command, int error_code))
UNUSED_FLOW(void, outersshpriv_reactor_command_received_data,
    (SSHReactorCommand *command, uint32_t stream_id, const void *data, size_t data_length))
UNUSED_FLOW(void, outersshpriv_reactor_command_channel_closed,
    (SSHReactorCommand *command))
UNUSED_FLOW(void, outersshpriv_reactor_command_received_exit_status,
    (SSHReactorCommand *command, int32_t exit_status))
UNUSED_FLOW(void, outersshpriv_reactor_command_handle_session_closed,
    (SSHReactorCommand * OT_NONNULL command))
UNUSED_FLOW(void, outersshpriv_reactor_destroy,
    (SSHReactor * OT_NONNULL reactor, void (* OT_NULLABLE completion)(void * OT_NULLABLE), void * OT_NULLABLE context))
UNUSED_FLOW(bool, outersshpriv_reactor_is_current_queue,
    (SSHReactor * OT_NONNULL reactor))
UNUSED_FLOW(bool, outersshpriv_reactor_session_has_failed,
    (SSHReactor *reactor))
UNUSED_FLOW(otqueue_t  OT_NONNULL, outersshpriv_reactor_queue,
    (SSHReactor * OT_NONNULL reactor))
UNUSED_FLOW(int, outersshpriv_reactor_teardown,
    (SSHReactor * OT_NONNULL reactor, size_t * OT_NULLABLE created_channel_count, size_t * OT_NULLABLE freed_channel_count))
UNUSED_FLOW(void, outersshpriv_session_pool_end_operation,
    (OuterSSHSessionPool * OT_NONNULL pool))
UNUSED_FLOW(void, outersshpriv_session_pool_begin_operation,
    (OuterSSHSessionPool * OT_NONNULL pool))
UNUSED_FLOW(void, outersshpriv_session_pool_finish_destroy_if_ready,
    (OuterSSHSessionPool * OT_NONNULL pool))
UNUSED_FLOW(void, outersshpriv_socket_service_stop, (OuterSSHSessionPool *pool))
UNUSED_FLOW(void, outersshpriv_socket_service_dispose, (OuterSSHSessionPool *pool))
UNUSED_FLOW(void, outersshpriv_socket_service_found_nothing_listening,
    (OuterSSHSessionPool *pool, const char *path, size_t length))
UNUSED_FLOW(SocketAuthorization *, outersshpriv_socket_service_find_authorization,
    (OuterSSHSessionPool *pool, const char *path, size_t path_length))
UNUSED_FLOW(void, outersshpriv_socket_service_wait_for_authorization,
    (SocketAuthorization *authorization, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context))
UNUSED_FLOW(void, outersshpriv_socket_service_authorize,
    (OuterSSHSessionPool *pool, const char *path, size_t path_length,
    SocketAuthorizationRequest *request, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context))
UNUSED_FLOW(void, outersshpriv_execute_command,
    (OuterSSHSessionPool *pool, SSHCommandRequest request,
    SSHCommandHandler completion, void *context))
UNUSED_FLOW(SSHProxyBridgeState *, outersshpriv_proxy_bridge_for_path,
    (OuterSSHSessionPool *pool, const char *path, size_t path_length,
    SSHProxyBridgeHandle *handle))
UNUSED_FLOW(void, outersshpriv_proxy_ensure_bridge,
    (OuterSSHSessionPool *pool, SSHBridgeRequest request,
    SSHSocketBridgeOperation *operation, SSHSocketBridgeWaiter *waiter,
    SSHProxyBridgeHandler finished, void * OT_NULLABLE context))

UNUSED_FLOW(bool, outersshpriv_proxy_reactor_fail_pending_connection,
    (ProxyReactor *reactor, ProxyReactorPendingConnectionHandle connection, ProxySOCKSReplyStatus status))
UNUSED_FLOW(bool, outersshpriv_socket_bridge_should_use_sudo, (const char *path, size_t path_length))
UNUSED_FLOW(void, outersshpriv_proxy_request_sudo_for_connection,
    (SSHProxyConnection controller, ProxyReactorPendingConnectionHandle connection,
     ProxyConnectionRoute route,  const char *path, size_t path_length, OuterSSHError error))
UNUSED_FLOW(void, outersshpriv_proxy_fail_connection,
    (SSHProxyConnection controller,
     ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route, OuterSSHError error))
UNUSED_FLOW(void, outersshpriv_proxy_server_pending_connection,
    (SSHForwarder *server, ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route))
UNUSED_FLOW(bool, outersshpriv_proxy_server_origin_for_credentials,
    (SSHForwarder *server, const unsigned char *username, size_t username_length,
        const unsigned char *password, size_t password_length, char **origin, size_t *origin_length))
UNUSED_FLOW(bool, outersshpriv_forwarder_connection_permits,
    (SSHForwarder *server, ProxyReactorPendingConnectionHandle connection, const SSHSocketOwner *destination,
        bool uses_sudo))
UNUSED_FLOW(void, outersshpriv_disconnect_session_pool, (OuterSSHSessionPool *pool))
UNUSED_FLOW(SSHProxyConnection, outersshpriv_proxy_active_connection, (SSHProxyConnection connection))
UNUSED_FLOW(bool, outersshpriv_proxy_connection_is_active, (SSHProxyConnection connection))
UNUSED_FLOW(void, outersshpriv_proxy_connection_begin_work, (SSHProxyConnection connection))
UNUSED_FLOW(void, outersshpriv_proxy_connection_end_work, (SSHProxyConnection connection))
UNUSED_FLOW(OuterSSHSessionPool *, outersshpriv_session_pool_active, (OuterSSHSessionPool *pool))

UNUSED_FLOW(void, outersshpriv_remove_session,
    (OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle session))

UNUSED_FLOW(void, outersshpriv_proxy_reactor_complete_pending_connection,
    (ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection,
    ProxySocketTransferHandler finished, void *context))

UNUSED_FLOW(int, outersshpriv_reactor_attach_prepared_relay,
    (SSHReactor *reactor,
    SSHReactorRelayHandle handle,
    otsocket_t socket,
    uint64_t identifier,
    uint64_t proxy_generation,
    SSHRelayTargetType target_type,
    const char *target_destination,
    size_t target_destination_length,
    int target_port))

UNUSED_FLOW(bool, outersshpriv_reactor_cancel_prepared_relay,
    (SSHReactor *reactor,
    SSHReactorRelayHandle handle))

UNUSED_FLOW(int, outersshpriv_reactor_prepare_relay,
    (SSHReactor *reactor,
    SSHReactorRelayHandle *handle,
    ConnectRelayContext *operation,
    const SSHRelayTarget *target,
    const char *source_host,
    size_t source_host_length,
    int source_port,
    uint64_t timeout_milliseconds))

UNUSED_FLOW(SSHReactor * OT_NULLABLE, outersshpriv_session_pool_reactor_for_session,
    (OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle session))

UNUSED_FLOW(void, outersshpriv_proxy_ensure_user_bridge_executable,
    (OuterSSHSessionPool *pool, SSHWaiter *waiter, SSHCompletionHandler resume, void *context))
UNUSED_FLOW(ProxyPendingConnection *, outersshpriv_proxy_pending_connection_for_handle,
    (ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle))
