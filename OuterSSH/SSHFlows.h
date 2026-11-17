#ifndef SSH_FLOWS_H
#define SSH_FLOWS_H

#include "OTNullability.h"

#include "SSHReactor.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

void outersshpriv_remove_session(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle session);

void outersshpriv_recover_after_session_failure(
    OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle session,
    SSHReactor *reactor);

void outersshpriv_relay_recovery_open_completed(
    SSHRelayRecoveryOperation *operation,
    SSHReactorRelayOpenResult result,
    SSHRelay * OT_NULLABLE detached_relay);

// Takes ownership of both output allocations, including on failure.
void outersshpriv_session_pool_command_completed(
    ExecuteCommandContext *operation,
    SSHReactorCommandResult result,
    void * OT_NULLABLE stdout_bytes,
    size_t stdout_byte_count,
    void * OT_NULLABLE stderr_bytes,
    size_t stderr_byte_count,
    int32_t exit_status,
    int32_t error_code,
    uint32_t channel_open_reason);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif

#endif
