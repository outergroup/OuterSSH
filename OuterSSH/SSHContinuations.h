#ifndef SSH_CONTINUATIONS_H
#define SSH_CONTINUATIONS_H

/* Continuations for engine steps. Engine steps report to the operation or
 * subsystem that started them; only operations report to applications, by
 * posting their reserved completion event. */

#include "OTNullability.h"
#include "include/OuterSSH/SSHProxyError.h"
#include <stddef.h>
#include <stdint.h>

OT_ASSUME_NONNULL_BEGIN

/* error.domain is OUTERSSH_ERROR_NONE on success. */
typedef void (*SSHCompletionHandler)(void * OT_NULLABLE context, OuterSSHError error);
typedef void (*SSHDestroyHandler)(void * OT_NULLABLE context);

typedef struct {
    const void * OT_NULLABLE stdout_bytes;
    size_t stdout_byte_count;
    const void * OT_NULLABLE stderr_bytes;
    size_t stderr_byte_count;
    int32_t exit_status;
} SSHCommandOutput;

/* The output and its buffers are borrowed during the call. */
typedef void (*SSHCommandHandler)(void * OT_NULLABLE context,
    const SSHCommandOutput * OT_NULLABLE output, OuterSSHError error);

OT_ASSUME_NONNULL_END

#endif
