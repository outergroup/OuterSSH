#ifndef SOCKET_BRIDGE_COMMANDS_H
#define SOCKET_BRIDGE_COMMANDS_H

#include <stdbool.h>
#include <stddef.h>
#include "SSHSessionPool.h"

#include "RemotePlatform.h"

/* Install commands read the gzip-compressed packaged binary from standard input:
 * the executable for Unix, a tar archive holding outerssh-helper.exe for
 * Windows. */
char *outersshpriv_socket_bridge_install_windows_command(const char *install_id, size_t id_length, size_t *command_length);
char *outersshpriv_windows_command(const char *script, size_t *command_length);

char *outersshpriv_socket_bridge_allowlist_arguments(const OuterSSHSocketAllowlist *allowlists, size_t count);

/* Returns the static helper platform name, such as "linux-aarch64-glibc",
 * "macos-arm64" or "windows-x64", or NULL for an unsupported platform. */
const char *outersshpriv_helper_platform(
    const char *remote_platform, size_t remote_platform_byte_count, size_t *name_length);

/* Input spans need not be null-terminated; shell arguments reject embedded nulls.
 * Returned strings are malloc-owned and null-terminated. Optional output lengths
 * exclude the terminator and are zero on failure. */
char *outersshpriv_socket_bridge_launch_command(
    const char *socket_path,
    size_t socket_path_length,
    const char *executable_path,
    size_t executable_path_length,
    const char *allowlist_arguments,
    bool sudo_password_is_available,
    size_t *command_length);
char *outersshpriv_socket_bridge_launch_user_command(
    const char *socket_path,
    size_t socket_path_length,
    const char *executable_path,
    size_t executable_path_length,
    const char *allowlist_arguments,
    size_t *command_length);
char *outersshpriv_socket_bridge_install_command(
    const char *install_id,
    size_t install_id_length,
    bool requires_password,
    size_t *command_length);
char *outersshpriv_socket_bridge_install_user_command(
    const char *install_id,
    size_t install_id_length,
    size_t *command_length);
char *outersshpriv_socket_bridge_cleanup_command(const char *executable_path, size_t executable_path_length,
    size_t *command_length);
char *outersshpriv_socket_bridge_cleanup_user_command(const char *executable_path, size_t executable_path_length,
    size_t *command_length);
char *outersshpriv_socket_service_launch_command(const char *executable_path,
    size_t executable_path_length, const char *allowlist_arguments, size_t *command_length);

/* Command output need not be null-terminated. Returns an owned, null-terminated
 * string, or NULL if the output is invalid or allocation fails. */
char *outersshpriv_socket_bridge_installed_executable_path(
    const char *output,
    size_t output_byte_count,
    const char *install_id,
    size_t install_id_length,
    bool requires_root_directory,
    size_t *executable_path_length);

#endif
