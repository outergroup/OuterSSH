#include "SSHSocketBridgeInternal.h"
#include "SSHProxyErrorInternal.h"
#include "SSHSessionPoolInternal.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "SocketBridgeCommands.h"

#include "RemotePlatform.h"

static const char remote_platform_command[] = OUTERSSH_REMOTE_PLATFORM_COMMAND;
static const uint64_t bridge_install_timeout_milliseconds = 60000;

static OuterSSHError internal_command_error(
    OuterSSHError error,
    const SSHCommandOutput *result,
    OuterSSHProxyErrorCode code,
    const char *fallback);

#pragma mark - Advance the Installations

/* The pool runs at most one user and one sudo installation. Each one's step
 * says what it waits for, and the facts it needs, the remote platform and the
 * packaged binary, live on the pool. A request moves an idle installation to
 * its first step, a completion moves it past the work it waited for or
 * finishes it, and advance_bridge_install makes every other transition. The
 * start functions only issue work. Every entry point changes state between
 * enter_bridge_installs and leave_bridge_installs. Only the outermost leave
 * advances, until nothing moves, and then lets a requested disconnect
 * continue. */

static bool advance_bridge_install(OuterSSHSessionPool *pool, bool sudo);
static void start_sudo_check(OuterSSHSessionPool *pool);
static void start_remote_platform_lookup(OuterSSHSessionPool *pool);
static void request_bridge_binary(OuterSSHSessionPool *pool);
static void start_user_bridge_install(OuterSSHSessionPool *pool);
static void start_sudo_bridge_install(OuterSSHSessionPool *pool);
static void finish_user_bridge_install(OuterSSHSessionPool *pool, OuterSSHError error);
static void finish_sudo_bridge_install(OuterSSHSessionPool *pool, OuterSSHError error);

/* Returns true when something moved. */
static bool advance_bridge_installs_once(OuterSSHSessionPool *pool)
{
    if (advance_bridge_install(pool, false) || advance_bridge_install(pool, true)) return true;
    bool binary_needed = pool->_userBridgeInstall == SSH_BRIDGE_INSTALL_NEEDS_BINARY ||
        pool->_sudoBridgeInstall == SSH_BRIDGE_INSTALL_NEEDS_BINARY;
    if (pool->_bridgeBinary == NULL || binary_needed) return false;
    SSHBridgeBinary *binary = pool->_bridgeBinary;
    pool->_bridgeBinary = NULL;
    outersshpriv_bridge_binary_release(binary);
    return true;
}

static void enter_bridge_installs(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    pool->_bridgeInstallDepth++;
}

static void leave_bridge_installs(OuterSSHSessionPool *pool)
{
    assert(pool->_bridgeInstallDepth != 0);
    if (pool->_bridgeInstallDepth == 1) {
        while (advance_bridge_installs_once(pool)) {}
    }
    if (--pool->_bridgeInstallDepth == 0) outersshpriv_proxy_continue_disconnect_if_requested(pool);
}

void outersshpriv_proxy_advance_bridge_installs(OuterSSHSessionPool *pool)
{
    enter_bridge_installs(pool);
    leave_bridge_installs(pool);
}

bool outersshpriv_proxy_bridge_installs_busy(const OuterSSHSessionPool *pool)
{
    return pool->_bridgeInstallDepth != 0 ||
        pool->_userBridgeInstall != SSH_BRIDGE_INSTALL_IDLE ||
        pool->_sudoBridgeInstall != SSH_BRIDGE_INSTALL_IDLE;
}

static void finish_bridge_install(OuterSSHSessionPool *pool, bool sudo, OuterSSHError error)
{
    if (sudo) finish_sudo_bridge_install(pool, error);
    else finish_user_bridge_install(pool, error);
}

static void fail_bridge_installs_at(OuterSSHSessionPool *pool, SSHBridgeInstallStep step, OuterSSHError error)
{
    if (pool->_userBridgeInstall == step) finish_user_bridge_install(pool, error);
    if (pool->_sudoBridgeInstall == step) finish_sudo_bridge_install(pool, error);
}

/* Moves one installation a step and returns true, or returns false when it is
 * idle or waiting on work already started. */
static bool advance_bridge_install(OuterSSHSessionPool *pool, bool sudo)
{
    SSHBridgeInstallStep *step = sudo ? &pool->_sudoBridgeInstall : &pool->_userBridgeInstall;
    /* After shutdown begins, only a running install command finishes, since
     * it may leave an executable to clean up. Earlier steps have written
     * nothing to the server. */
    if (pool->shutdown_requested && *step != SSH_BRIDGE_INSTALL_IDLE && *step != SSH_BRIDGE_INSTALL_INSTALLING) {
        finish_bridge_install(pool, sudo, outerssh_proxy_closing_error());
        return true;
    }
    switch (*step) {
    case SSH_BRIDGE_INSTALL_IDLE:
    case SSH_BRIDGE_INSTALL_CHECKING_SUDO:
    case SSH_BRIDGE_INSTALL_INSTALLING:
        return false;
    case SSH_BRIDGE_INSTALL_NEEDS_SUDO_CHECK:
        *step = SSH_BRIDGE_INSTALL_CHECKING_SUDO;
        start_sudo_check(pool);
        return true;
    case SSH_BRIDGE_INSTALL_NEEDS_PLATFORM:
        if (pool->_remotePlatform != NULL) {
            *step = SSH_BRIDGE_INSTALL_NEEDS_BINARY;
            return true;
        }
        if (pool->_remotePlatformLookupRunning) return false;
        start_remote_platform_lookup(pool);
        return true;
    case SSH_BRIDGE_INSTALL_NEEDS_BINARY:
        if (pool->_bridgeBinary != NULL) {
            *step = SSH_BRIDGE_INSTALL_INSTALLING;
            if (sudo) start_sudo_bridge_install(pool);
            else start_user_bridge_install(pool);
            return true;
        }
        if (pool->_bridgeBinaryRequested) return false;
        request_bridge_binary(pool);
        return true;
    }
    return false;
}

#pragma mark - Install the User Bridge Executable

static void user_bridge_install_finished(
    void *context,
    const SSHCommandOutput *result,
    OuterSSHError error);

void outersshpriv_proxy_ensure_user_bridge_executable(
    OuterSSHSessionPool *pool,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    otqueue_assert(pool->_queue);
    if (pool->_userBridgeExecutablePath != NULL) {
        resume(context, (OuterSSHError){0});
        return;
    }
    enter_bridge_installs(pool);
    if (outersshpriv_wait(&pool->_userBridgeWaiters, waiter, resume, context)) {
        assert(pool->_userBridgeInstall == SSH_BRIDGE_INSTALL_IDLE);
        pool->_userBridgeInstall = SSH_BRIDGE_INSTALL_NEEDS_PLATFORM;
    }
    leave_bridge_installs(pool);
}

static void start_user_bridge_install(OuterSSHSessionPool *pool)
{
    const char *platform = outersshpriv_helper_platform(pool->_remotePlatform, pool->_remotePlatformLength, NULL);
    bool windows = platform && !strncmp(platform, "windows-", strlen("windows-"));
    if (windows) atomic_store(&pool->_commandDialect, OUTERSSH_COMMAND_DIALECT_WINDOWS);

    size_t command_length;
    char *command = (windows ? outersshpriv_socket_bridge_install_windows_command : outersshpriv_socket_bridge_install_user_command)(
        pool->_userBridgeInstallID, pool->_userBridgeInstallID_length, &command_length);
    if (command == NULL) {
        static const char error_message[] = "Failed to allocate the outerssh-helper install command.";
        finish_user_bridge_install(pool,
                                   outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED, error_message, sizeof(error_message) - 1, 0));
        return;
    }
    size_t binary_byte_count;
    const void *binary_bytes = outersshpriv_bridge_binary_bytes(pool->_bridgeBinary, &binary_byte_count);
    outersshpriv_execute_command(pool, (SSHCommandRequest){
        .command = command,
        .command_byte_count = command_length,
        .execution_timeout_milliseconds = bridge_install_timeout_milliseconds,
        .release_command = free,
        .release_command_context = command,
        .standard_input = binary_bytes,
        .standard_input_byte_count = binary_byte_count,
        .release_input = outersshpriv_bridge_binary_release,
        .release_input_context = outersshpriv_bridge_binary_retain(pool->_bridgeBinary),
    }, user_bridge_install_finished, pool);
}

static void user_bridge_install_finished(
    void *context,
    const SSHCommandOutput *result,
    OuterSSHError error)
{
    OuterSSHSessionPool *pool = context;
    enter_bridge_installs(pool);
    if (error.domain != OUTERSSH_ERROR_NONE || result == NULL ||
        result->exit_status != 0) {
        finish_user_bridge_install(pool,
                                   internal_command_error(error, result, OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED, "Failed to install outerssh-helper."));
        leave_bridge_installs(pool);
        return;
    }

    size_t path_length;
    char *path = outersshpriv_socket_bridge_installed_executable_path(
        result->stdout_bytes, result->stdout_byte_count,
        pool->_userBridgeInstallID, pool->_userBridgeInstallID_length, false, &path_length);
    if (path == NULL) {
        static const char message[] = "The outerssh-helper installer did not report a valid executable path.";
        finish_user_bridge_install(pool, outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED, message, sizeof(message) - 1, 0));
        leave_bridge_installs(pool);
        return;
    }
    pool->_userBridgeExecutablePath = path;
    pool->_userBridgeExecutablePath_length = path_length;
    if (outersshpriv_session_pool_active(pool) == NULL) {
        if (!pool->shutdown_requested) {
            outersshpriv_proxy_cleanup_bridge_executables(pool, NULL, NULL);
        }
        finish_user_bridge_install(pool, outerssh_proxy_closing_error());
    } else {
        finish_user_bridge_install(pool, (OuterSSHError){0});
    }
    leave_bridge_installs(pool);
}

static void finish_user_bridge_install(
    OuterSSHSessionPool *pool,
    OuterSSHError error)
{
    pool->_userBridgeInstall = SSH_BRIDGE_INSTALL_IDLE;
    outersshpriv_wake(&pool->_userBridgeWaiters, error);
}

#pragma mark - Detect the Remote Platform

static void unix_platform_received(
    void *context, const SSHCommandOutput *result, OuterSSHError error);

static void start_remote_platform_lookup(OuterSSHSessionPool *pool)
{
    pool->_remotePlatformLookupRunning = true;
    const char *command = atomic_load(&pool->_commandDialect) == OUTERSSH_COMMAND_DIALECT_WINDOWS ? OUTERSSH_WINDOWS_PLATFORM_COMMAND : remote_platform_command;
    outersshpriv_execute_command(pool, (SSHCommandRequest){
        .command = command,
        .command_byte_count = strlen(command),
    }, unix_platform_received, pool);
}

static void remote_platform_received(void *context, const SSHCommandOutput *result, OuterSSHError error)
{
    OuterSSHSessionPool *pool = context;
    enter_bridge_installs(pool);
    pool->_remotePlatformLookupRunning = false;
    if (pool->_disconnecting || pool->_disconnected) {
        error = outerssh_proxy_closing_error();
    } else if (error.domain != OUTERSSH_ERROR_NONE || result == NULL ||
               result->exit_status != 0 || result->stdout_bytes == NULL || result->stdout_byte_count == 0) {
        error = internal_command_error(error, result,
            OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED, "Failed to detect the remote platform.");
    } else {
        char *platform = malloc(result->stdout_byte_count);
        if (platform == NULL) {
            static const char message[] = "Failed to allocate the remote platform string.";
            error = outersshpriv_proxy_error(
                OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED,
                message, sizeof(message) - 1, 0);
        } else {
            memcpy(platform, result->stdout_bytes, result->stdout_byte_count);
            pool->_remotePlatform = platform;
            pool->_remotePlatformLength = result->stdout_byte_count;
        }
    }
    if (error.domain != OUTERSSH_ERROR_NONE) fail_bridge_installs_at(pool, SSH_BRIDGE_INSTALL_NEEDS_PLATFORM, error);
    leave_bridge_installs(pool);
}

/* A Unix probe that fails may be talking to Windows, so it asks again. */
static void unix_platform_received(void *context, const SSHCommandOutput *result, OuterSSHError error)
{
    OuterSSHSessionPool *pool = context;
    if (error.domain == OUTERSSH_ERROR_NONE && result && result->exit_status != 0 && !pool->shutdown_requested) {
        static const char command[] = OUTERSSH_WINDOWS_PLATFORM_COMMAND;
        outersshpriv_execute_command(pool, (SSHCommandRequest){.command = command, .command_byte_count = sizeof(command) - 1}, remote_platform_received, pool);
        return;
    }
    remote_platform_received(context, result, error);
}

#pragma mark - Ask for the Packaged Binary

static void bridge_binary_answered(void *context, SSHQuestionAnswer answer,
    SSHBridgeBinary *binary, OuterSSHError error);

static void request_bridge_binary(OuterSSHSessionPool *pool)
{
    size_t name_length;
    const char *name = outersshpriv_helper_platform(pool->_remotePlatform, pool->_remotePlatformLength, &name_length);
    if (name == NULL) {
        size_t platform_length = pool->_remotePlatformLength;
        char *error_storage = NULL;
        OuterSSHError error = outersshpriv_error_format(&error_storage, (OuterSSHError){
                .domain = OUTERSSH_ERROR_HELPER_INSTALLER,
                .code = OUTERSSH_HELPER_INSTALLER_ERROR_UNSUPPORTED_PLATFORM,
            },
            "No OuterSSH helper is available for remote platform '%.*s'.",
            (int)(platform_length < INT_MAX ? platform_length : INT_MAX),
            pool->_remotePlatform != NULL ? pool->_remotePlatform : "");
        fail_bridge_installs_at(pool, SSH_BRIDGE_INSTALL_NEEDS_BINARY, error);
        free(error_storage);
        return;
    }
    pool->_bridgeBinaryRequested = true;
    outersshpriv_session_pool_ask_bridge_binary(pool, name, name_length, bridge_binary_answered, pool);
}

static void bridge_binary_answered(void *context, SSHQuestionAnswer answer,
    SSHBridgeBinary *binary, OuterSSHError error)
{
    OuterSSHSessionPool *pool = context;
    enter_bridge_installs(pool);
    pool->_bridgeBinaryRequested = false;
    switch (answer) {
    case SSH_QUESTION_ACCEPTED:
        assert(pool->_bridgeBinary == NULL);
        pool->_bridgeBinary = binary;
        break;
    case SSH_QUESTION_DECLINED:
        fail_bridge_installs_at(pool, SSH_BRIDGE_INSTALL_NEEDS_BINARY, error);
        break;
    case SSH_QUESTION_CANCELLED:
        fail_bridge_installs_at(pool, SSH_BRIDGE_INSTALL_NEEDS_BINARY, outerssh_proxy_closing_error());
        break;
    }
    leave_bridge_installs(pool);
}

#pragma mark - Install the Privileged Bridge Executable

static void sudo_credentials_checked(
    void *context,
    const SSHCommandOutput *result,
    OuterSSHError error);
static void sudo_install_finished(
    void *context,
    const SSHCommandOutput *result,
    OuterSSHError error);

void outersshpriv_proxy_ensure_sudo_bridge_executable(
    OuterSSHSessionPool *pool,
    const char *password, size_t password_length,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    otqueue_assert(pool->_queue);
    if (pool->_sudoBridgeExecutablePath != NULL) {
        resume(context, (OuterSSHError){0});
        return;
    }
    enter_bridge_installs(pool);
    if (outersshpriv_wait(&pool->_sudoBridgeWaiters, waiter, resume, context)) {
        assert(pool->_sudoBridgeInstall == SSH_BRIDGE_INSTALL_IDLE);
        pool->_sudoBridgeInstallPassword = password;
        pool->_sudoBridgeInstallPasswordLength = password_length;
        pool->_sudoBridgeInstall = SSH_BRIDGE_INSTALL_NEEDS_SUDO_CHECK;
    }
    leave_bridge_installs(pool);
}

static void start_sudo_check(OuterSSHSessionPool *pool)
{
    static const char command[] = "sudo -n true";
    outersshpriv_execute_command(pool, (SSHCommandRequest){
        .command = command,
        .command_byte_count = sizeof(command) - 1,
    }, sudo_credentials_checked, pool);
}

/* Only shutdown abandons a check, and no installation starts after it. */
static void sudo_credentials_checked(
    void *context,
    const SSHCommandOutput *result,
    OuterSSHError error)
{
    OuterSSHSessionPool *pool = context;
    if (pool->_sudoBridgeInstall != SSH_BRIDGE_INSTALL_CHECKING_SUDO) return;
    enter_bridge_installs(pool);
    bool requires_password = result == NULL || result->exit_status != 0;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        finish_sudo_bridge_install(pool, error);
    } else if (requires_password && pool->_sudoBridgeInstallPassword == NULL) {
        static const char error_message[] = "A sudo password is required to start the socket bridge.";
        finish_sudo_bridge_install(
            pool,
            outersshpriv_proxy_error(
                OUTERSSH_PROXY_ERROR_SUDO_PASSWORD_REQUIRED,
                error_message, sizeof(error_message) - 1,
                0));
    } else {
        pool->_sudoBridgeInstallRequiresPassword = requires_password;
        pool->_sudoBridgeInstall = SSH_BRIDGE_INSTALL_NEEDS_PLATFORM;
    }
    leave_bridge_installs(pool);
}

static void start_sudo_bridge_install(OuterSSHSessionPool *pool)
{
    bool requires_password = pool->_sudoBridgeInstallRequiresPassword;
    if (requires_password) {
        assert(pool->_sudoBridgeInstallPassword != NULL);
        size_t password_length = pool->_sudoBridgeInstallPasswordLength;
        char *password_line = password_length == SIZE_MAX ? NULL : malloc(password_length + 1);
        if (password_line == NULL) {
            static const char error_message[] = "Failed to allocate the outerssh-helper install input.";
            finish_sudo_bridge_install(
                pool,
                outersshpriv_proxy_error(
                    OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED,
                    error_message, sizeof(error_message) - 1,
                    0));
            return;
        }
        memcpy(password_line, pool->_sudoBridgeInstallPassword, password_length);
        password_line[password_length] = '\n';
        pool->_sudoBridgeInstallPasswordLine = password_line;
        pool->_sudoBridgeInstallPasswordLineLength = password_length + 1;
    }
    size_t command_length;
    char *command = outersshpriv_socket_bridge_install_command(
        pool->_sudoBridgeInstallID, pool->_sudoBridgeInstallID_length,
        requires_password, &command_length);
    if (command == NULL) {
        static const char error_message[] = "Failed to allocate the sudo outerssh-helper install command.";
        finish_sudo_bridge_install(
            pool,
            outersshpriv_proxy_error(
                OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED,
                error_message, sizeof(error_message) - 1,
                0));
        return;
    }

    size_t binary_byte_count;
    const void *binary_bytes = outersshpriv_bridge_binary_bytes(pool->_bridgeBinary, &binary_byte_count);
    outersshpriv_execute_command(pool, (SSHCommandRequest){
        .command = command,
        .command_byte_count = command_length,
        .release_command = free,
        .release_command_context = command,
        .execution_timeout_milliseconds = bridge_install_timeout_milliseconds,
        .standard_input_prefix = pool->_sudoBridgeInstallPasswordLine,
        .standard_input_prefix_byte_count = pool->_sudoBridgeInstallPasswordLineLength,
        .standard_input = binary_bytes,
        .standard_input_byte_count = binary_byte_count,
        .release_input = outersshpriv_bridge_binary_release,
        .release_input_context = outersshpriv_bridge_binary_retain(pool->_bridgeBinary),
    }, sudo_install_finished, pool);
}

static void sudo_install_finished(
    void *context,
    const SSHCommandOutput *result,
    OuterSSHError error)
{
    OuterSSHSessionPool *pool = context;
    enter_bridge_installs(pool);
    if (error.domain != OUTERSSH_ERROR_NONE || result == NULL ||
        result->exit_status != 0) {
        finish_sudo_bridge_install(
            pool,
            internal_command_error(
                error,
                result,
                OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED,
                "Failed to install outerssh-helper with sudo."));
        leave_bridge_installs(pool);
        return;
    }

    size_t path_length;
    char *path = outersshpriv_socket_bridge_installed_executable_path(
        result->stdout_bytes, result->stdout_byte_count,
        pool->_sudoBridgeInstallID, pool->_sudoBridgeInstallID_length, true, &path_length);
    if (path == NULL) {
        static const char message[] = "The sudo outerssh-helper installer did not report a valid executable path.";
        finish_sudo_bridge_install(pool, outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_HELPER_INSTALL_FAILED, message, sizeof(message) - 1, 0));
        leave_bridge_installs(pool);
        return;
    }
    pool->_sudoBridgeExecutablePath = path;
    pool->_sudoBridgeExecutablePath_length = path_length;
    if (outersshpriv_session_pool_active(pool) == NULL) {
        if (!pool->shutdown_requested) {
            outersshpriv_proxy_cleanup_bridge_executables(pool, NULL, NULL);
        }
        finish_sudo_bridge_install(pool, outerssh_proxy_closing_error());
    } else {
        finish_sudo_bridge_install(pool, (OuterSSHError){0});
    }
    leave_bridge_installs(pool);
}

static void finish_sudo_bridge_install(
    OuterSSHSessionPool *pool,
    OuterSSHError error)
{
    pool->_sudoBridgeInstall = SSH_BRIDGE_INSTALL_IDLE;
    pool->_sudoBridgeInstallPassword = NULL;
    pool->_sudoBridgeInstallPasswordLength = 0;
    if (pool->_sudoBridgeInstallPasswordLine != NULL) {
        volatile char *line = pool->_sudoBridgeInstallPasswordLine;
        for (size_t i = 0; i < pool->_sudoBridgeInstallPasswordLineLength; i++) line[i] = 0;
        free(pool->_sudoBridgeInstallPasswordLine);
        pool->_sudoBridgeInstallPasswordLine = NULL;
        pool->_sudoBridgeInstallPasswordLineLength = 0;
    }
    outersshpriv_wake(&pool->_sudoBridgeWaiters, error);
}

#pragma mark - Clean Up Remote Bridge Executables

typedef struct {
    SSHDestroyHandler completion;
    void *completion_context;
    size_t pending_steps;
} CleanupBridgeExecutablesContext;

static void cleanup_command_finished(
    void *context,
    const SSHCommandOutput *result,
    OuterSSHError error);
static void finish_cleanup_step(
    CleanupBridgeExecutablesContext *cleanup_context);

void outersshpriv_proxy_cleanup_bridge_executables(
    OuterSSHSessionPool *pool,
    SSHDestroyHandler completion,
    void *context)
{
    CleanupBridgeExecutablesContext *cleanup_context = calloc(1, sizeof(*cleanup_context));
    char *user_path = pool->_userBridgeExecutablePath;
    size_t user_path_length = pool->_userBridgeExecutablePath_length;
    pool->_userBridgeExecutablePath = NULL;
    pool->_userBridgeExecutablePath_length = 0;
    if (pool->_userBridgeIsPreinstalled) {
        free(user_path);
        user_path = NULL;
        pool->_userBridgeIsPreinstalled = false;
    }
    char *sudo_path = pool->_sudoBridgeExecutablePath;
    size_t sudo_path_length = pool->_sudoBridgeExecutablePath_length;
    pool->_sudoBridgeExecutablePath = NULL;
    pool->_sudoBridgeExecutablePath_length = 0;
    if (cleanup_context == NULL) {
        free(user_path);
        free(sudo_path);
        if (completion != NULL) {
            completion(context);
        }
        return;
    }

    cleanup_context->completion = completion;
    cleanup_context->completion_context = context;
    // Keep submission pending because command callbacks can run synchronously.
    cleanup_context->pending_steps = 1;
    if (user_path != NULL) {
        size_t command_length;
        char *command = outersshpriv_socket_bridge_cleanup_user_command(user_path, user_path_length, &command_length);
        if (command != NULL) {
            cleanup_context->pending_steps++;
            outersshpriv_execute_command(pool, (SSHCommandRequest){
                .command = command,
                .during_shutdown = true,
                .command_byte_count = command_length,
                .release_command = free,
                .release_command_context = command,
            }, cleanup_command_finished, cleanup_context);
        }
        free(user_path);
    }
    if (sudo_path != NULL) {
        size_t command_length;
        char *command = outersshpriv_socket_bridge_cleanup_command(sudo_path, sudo_path_length, &command_length);
        if (command != NULL) {
            cleanup_context->pending_steps++;
            outersshpriv_execute_command(pool, (SSHCommandRequest){
                .command = command,
                .during_shutdown = true,
                .command_byte_count = command_length,
                .release_command = free,
                .release_command_context = command,
            }, cleanup_command_finished, cleanup_context);
        }
        free(sudo_path);
    }
    finish_cleanup_step(cleanup_context);
}

static void cleanup_command_finished(
    void *context,
    const SSHCommandOutput *result,
    OuterSSHError error)
{
    (void)result;
    (void)error;
    finish_cleanup_step(context);
}

static void finish_cleanup_step(CleanupBridgeExecutablesContext *cleanup_context)
{
    assert(cleanup_context->pending_steps != 0);
    if (--cleanup_context->pending_steps != 0) {
        return;
    }
    if (cleanup_context->completion != NULL) {
        cleanup_context->completion(cleanup_context->completion_context);
    }
    free(cleanup_context);
}


#pragma mark - Installation Errors

static OuterSSHError internal_command_error(
    OuterSSHError error,
    const SSHCommandOutput *result,
    OuterSSHProxyErrorCode code,
    const char *fallback)
{
    if (error.domain != OUTERSSH_ERROR_NONE) {
        return error;
    }
    error = outersshpriv_proxy_error(code, fallback, strlen(fallback), 0);
    if (result == NULL) {
        return error;
    }
    const void *bytes = result->stderr_byte_count != 0
        ? result->stderr_bytes
        : result->stdout_bytes;
    size_t byte_count = result->stderr_byte_count != 0
        ? result->stderr_byte_count
        : result->stdout_byte_count;
    if (byte_count == 0) {
        return error;
    }
    error.message = bytes;
    error.message_length = byte_count;
    return error;
}
