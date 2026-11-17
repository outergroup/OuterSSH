#ifndef SSH_SOCKET_BRIDGE_INTERNAL_H
#define SSH_SOCKET_BRIDGE_INTERNAL_H

#include "OTNullability.h"
#include "SSHEventQueueInternal.h"

#include "SSHForwarder.h"
#include "SSHProxyState.h"

OT_ASSUME_NONNULL_BEGIN


/* Control queue only. The caller supplies the current forwarding run and a
 * pending connection awaiting its target. */
void outersshpriv_proxy_start_connection(SSHProxyConnection source, ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route);
void outersshpriv_proxy_fail_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route,
    OuterSSHError error);
void outersshpriv_proxy_request_sudo_for_connection(
    SSHProxyConnection source, ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route,
    const char *path,
    size_t path_length, OuterSSHError error);

/* Control queue only; pool must be active. Request bytes are borrowed until
 * finished begins. Calls finished exactly once, possibly before returning,
 * including failure. The first caller supplies operation storage for the shared
 * setup; later callers only link their waiters and leave operation untouched.
 * Neither needs initialization. Keep both alive until finished begins, which
 * may free their owner. Setup detaches before callbacks; diagnostics remain
 * borrowed until each callback returns. */
void outersshpriv_proxy_ensure_bridge(
    OuterSSHSessionPool *pool,
    SSHBridgeRequest request, SSHSocketBridgeOperation *operation,
    SSHSocketBridgeWaiter *waiter, SSHProxyBridgeHandler finished,
    void * OT_NULLABLE context);
void outersshpriv_proxy_stop_bridge(
    OuterSSHSessionPool *pool,
    SSHProxyBridgeHandle bridge_handle);
/* Control queue only. Resume the operation once the user or sudo bridge
 * executable is installed or cannot be, exactly once and possibly before
 * returning. On success the executable is pool->_userBridgeExecutablePath or
 * pool->_sudoBridgeExecutablePath. The sudo installation borrows the first
 * waiting operation's password until that operation resumes. */
void outersshpriv_proxy_ensure_user_bridge_executable(
    OuterSSHSessionPool *pool,
    SSHWaiter *waiter, SSHCompletionHandler resume, void * OT_NULLABLE context);
void outersshpriv_proxy_ensure_sudo_bridge_executable(
    OuterSSHSessionPool *pool,
    const char * OT_NULLABLE password, size_t password_length,
    SSHWaiter *waiter, SSHCompletionHandler resume, void * OT_NULLABLE context);

ProxySOCKSReplyStatus outersshpriv_proxy_reply_status_for_error(OuterSSHError error);

void outersshpriv_proxy_assign_bridge_connection(
    SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection,
    ProxyConnectionRoute route,
    const char *path,
    size_t path_length,
    bool uses_sudo);
/* Control queue only. Attempts remote cleanup even if individual commands fail.
 * A supplied completion runs exactly once, possibly before returning, including
 * when allocation fails. It signals the end of cleanup attempts, not success.
 * Context remains borrowed until completion, which may destroy it. */
void outersshpriv_proxy_cleanup_bridge_executables(
    OuterSSHSessionPool *pool,
    SSHDestroyHandler OT_NULLABLE completion,
    void * OT_NULLABLE context);
void outersshpriv_proxy_continue_disconnect_if_requested(OuterSSHSessionPool *pool);
/* Control queue only. Moves every installation that can move; after shutdown
 * begins, fails those that have not started installing. */
void outersshpriv_proxy_advance_bridge_installs(OuterSSHSessionPool *pool);
/* Whether an installation is in progress or delivering its result. */
bool outersshpriv_proxy_bridge_installs_busy(const OuterSSHSessionPool *pool);

OT_ASSUME_NONNULL_END

#endif
