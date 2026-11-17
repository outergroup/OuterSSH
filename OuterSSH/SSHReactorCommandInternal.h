#ifndef SSH_REACTOR_COMMAND_INTERNAL_H
#define SSH_REACTOR_COMMAND_INTERNAL_H

#include "OTNullability.h"

#include "SSHReactor.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

typedef uint64_t SSHReactorChannelToken;

typedef enum {
    SSH_REACTOR_CHANNEL_OPEN_SUCCEEDED,
    SSH_REACTOR_CHANNEL_OPEN_FAILED,
    SSH_REACTOR_CHANNEL_OPEN_TIMED_OUT,
    SSH_REACTOR_CHANNEL_OPEN_SESSION_CLOSED
} SSHReactorChannelOpenResult;

/* Borrows input_prefix and input until command_state completes; see
 * outersshpriv_reactor_forget_command_input. */
int outersshpriv_reactor_start_command(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    const char *command,
    size_t command_length,
    const void * OT_NULLABLE input_prefix,
    size_t input_prefix_length,
    const void * OT_NULLABLE input,
    size_t input_length,
    bool send_eof_after_input,
    SSHReactorCommand *command_state);
/* Stops sending input that command_state still has pending, so its storage
 * can be released. Does nothing once the channel no longer belongs to it. */
void outersshpriv_reactor_forget_command_input(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    SSHReactorCommand *command_state);
void outersshpriv_reactor_close_command(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    bool send_eof);

void outersshpriv_reactor_command_request_succeeded(SSHReactorCommand *command);
void outersshpriv_reactor_command_request_failed(SSHReactorCommand *command, int error_code);
void outersshpriv_reactor_command_received_data(SSHReactorCommand *command, uint32_t stream_id,
    const void *data, size_t data_length);
void outersshpriv_reactor_command_channel_closed(SSHReactorCommand *command);
void outersshpriv_reactor_command_received_exit_status(SSHReactorCommand *command, int32_t exit_status);
void outersshpriv_reactor_command_handle_session_closed(
    SSHReactorCommand *command);
void outersshpriv_reactor_command_handle_channel_open(
    SSHReactorCommand *command,
    SSHReactorChannelToken channel_token,
    SSHReactorChannelOpenResult result,
    uint32_t reason);

int outersshpriv_reactor_open_command_session(
    SSHReactor *reactor,
    SSHReactorChannelToken *channel_token,
    uint64_t timeout_milliseconds,
    SSHReactorCommand *command);
void outersshpriv_reactor_close_channel(
    SSHReactor *reactor,
    SSHReactorChannelToken channel_token,
    bool send_eof);

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif

#endif
