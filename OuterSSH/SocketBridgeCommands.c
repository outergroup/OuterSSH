#include "SocketBridgeCommands.h"
#include "SSHProxyAddress.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRIDGE_RUNTIME_DIRECTORY "/var/tmp/outerssh-helper"
#define USER_BRIDGE_RUNTIME_DIRECTORY "outerssh-helper"

static char *shell_quote(const char *value, size_t value_length);
static bool installed_windows_executable(const char *path, size_t length) {
    static const char executable[] = OUTERSSH_WINDOWS_BRIDGE_EXECUTABLE;
    return path && length == sizeof(executable) - 1 && !memcmp(path, executable, length);
}
static bool windows_executable(const char *path, size_t length) {
    return installed_windows_executable(path, length) ||
        (path && length > 3 && isalpha((unsigned char)path[0]) && path[1] == ':' && path[2] == '\\');
}
static char *windows_cleanup(const char *path, size_t length, size_t *command_length);
static char *windows_launch(const char *path, size_t length, const char *endpoint, size_t endpoint_length, size_t *command_length);


#pragma mark - Choose Privileges and Launch the Bridge

char *outersshpriv_socket_bridge_allowlist_arguments(const OuterSSHSocketAllowlist *allowlists, size_t count)
{
    if (count != 0 && allowlists == NULL) return NULL;
    char *arguments = malloc(1);
    if (arguments == NULL) return NULL;
    arguments[0] = '\0';
    size_t length = 0;
    for (size_t i = 0; i < count; i++) {
        const OuterSSHSocketAllowlist *entry = &allowlists[i];
        if (entry->path == NULL || entry->path_length == 0 ||
            (entry->path[0] != '/' && (entry->system || entry->path_length < 3 ||
                entry->path[0] != '%' || (entry->path[1] != 'h' && entry->path[1] != 'c') ||
                entry->path[2] != '/'))) {
            free(arguments);
            return NULL;
        }
        char *quoted = shell_quote(entry->path, entry->path_length);
        if (quoted == NULL) { free(arguments); return NULL; }
        const char *option = entry->system ? " --system-allowlist " : " --user-allowlist ";
        size_t option_length = strlen(option), quoted_length = strlen(quoted);
        if (length > SIZE_MAX - option_length - 1 ||
            quoted_length > SIZE_MAX - length - option_length - 1) {
            free(quoted);
            free(arguments);
            return NULL;
        }
        char *expanded = realloc(arguments, length + option_length + quoted_length + 1);
        if (expanded == NULL) { free(quoted); free(arguments); return NULL; }
        arguments = expanded;
        memcpy(arguments + length, option, option_length);
        length += option_length;
        memcpy(arguments + length, quoted, quoted_length + 1);
        length += quoted_length;
        free(quoted);
    }
    return arguments;
}

char *outersshpriv_socket_bridge_launch_command(
    const char *socket_path,
    size_t socket_path_length,
    const char *executable_path,
    size_t executable_path_length,
    const char *allowlist_arguments,
    bool sudo_password_is_available, size_t *command_length)
{
    if (command_length != NULL) *command_length = 0;
    char *quoted_executable = shell_quote(executable_path, executable_path_length);
    char *quoted_socket = shell_quote(socket_path, socket_path_length);
    const char bridge_format[] = "%s%s bridge --socket %s";
    int bridge_byte_count = quoted_executable == NULL || quoted_socket == NULL
        ? -1 : snprintf(NULL, 0, bridge_format, quoted_executable, allowlist_arguments, quoted_socket);
    char *bridge = bridge_byte_count < 0 ? NULL : malloc((size_t)bridge_byte_count + 1);
    if (bridge != NULL) {
        if (snprintf(
                bridge, (size_t)bridge_byte_count + 1,
                bridge_format, quoted_executable, allowlist_arguments, quoted_socket) != bridge_byte_count) {
            free(bridge);
            bridge = NULL;
        }
    }
    free(quoted_executable);
    free(quoted_socket);
    if (bridge == NULL) {
        return NULL;
    }
    char *command;
    if (sudo_password_is_available) {
        const char command_format[] =
            "if sudo -n true 2>/dev/null; then\n"
            "  IFS= read -r discarded_password\n"
            "  unset discarded_password\n"
            "  exec sudo -n %s\n"
            "fi\n"
            "exec sudo -S -p '' %s";
        int command_byte_count = snprintf(NULL, 0, command_format, bridge, bridge);
        command = command_byte_count < 0 ? NULL : malloc((size_t)command_byte_count + 1);
        if (command != NULL) {
            if (snprintf(
                    command, (size_t)command_byte_count + 1,
                    command_format, bridge, bridge) != command_byte_count) {
                free(command);
                command = NULL;
            } else if (command_length != NULL) {
                *command_length = (size_t)command_byte_count;
            }
        }
    } else {
        const char command_format[] =
            "if ! sudo -n true 2>/dev/null; then\n"
            "  echo 'A sudo password is required to start the socket bridge.' >&2\n"
            "  exit 1\n"
            "fi\n"
            "exec sudo -n %s";
        int command_byte_count = snprintf(NULL, 0, command_format, bridge);
        command = command_byte_count < 0 ? NULL : malloc((size_t)command_byte_count + 1);
        if (command != NULL) {
            if (snprintf(
                    command, (size_t)command_byte_count + 1,
                    command_format, bridge) != command_byte_count) {
                free(command);
                command = NULL;
            } else if (command_length != NULL) {
                *command_length = (size_t)command_byte_count;
            }
        }
    }
    free(bridge);
    return command;
}

char *outersshpriv_socket_bridge_launch_user_command(
    const char *socket_path,
    size_t socket_path_length,
    const char *executable_path,
    size_t executable_path_length, const char *allowlist_arguments, size_t *command_length)
{
    if (windows_executable(executable_path, executable_path_length))
        return windows_launch(executable_path, executable_path_length, socket_path, socket_path_length, command_length);
    if (command_length != NULL) *command_length = 0;
    char *quoted_executable = shell_quote(executable_path, executable_path_length);
    char *quoted_socket = shell_quote(socket_path, socket_path_length);
    const char command_format[] = "%s%s bridge --socket %s";
    int command_byte_count = quoted_executable == NULL || quoted_socket == NULL
        ? -1 : snprintf(NULL, 0, command_format, quoted_executable, allowlist_arguments, quoted_socket);
    char *command = command_byte_count < 0 ? NULL : malloc((size_t)command_byte_count + 1);
    if (command != NULL) {
        if (snprintf(
                command, (size_t)command_byte_count + 1,
                command_format, quoted_executable, allowlist_arguments, quoted_socket) != command_byte_count) {
            free(command);
            command = NULL;
        } else if (command_length != NULL) {
            *command_length = (size_t)command_byte_count;
        }
    }
    free(quoted_executable);
    free(quoted_socket);
    return command;
}

char *outersshpriv_socket_service_launch_command(const char *executable_path,
    size_t executable_path_length, const char *allowlist_arguments, size_t *command_length)
{
    if (windows_executable(executable_path, executable_path_length))
        return windows_launch(executable_path, executable_path_length, NULL, 0, command_length);
    *command_length = 0;
    char *quoted_executable = shell_quote(executable_path, executable_path_length);
    if (quoted_executable == NULL) return NULL;
    const char format[] = "exec %s%s service";
    int count = snprintf(NULL, 0, format, quoted_executable, allowlist_arguments);
    char *command = count < 0 ? NULL : malloc((size_t)count + 1);
    if (command != NULL) {
        snprintf(command, (size_t)count + 1, format, quoted_executable, allowlist_arguments);
        *command_length = (size_t)count;
    }
    free(quoted_executable);
    return command;
}

#pragma mark - Install and Remove Bridge Executables

char *outersshpriv_socket_bridge_install_command(
    const char *install_id,
    size_t install_id_length,
    bool requires_password, size_t *command_length)
{
    if (command_length != NULL) *command_length = 0;
    size_t script_length = 0;
    const char script_format[] =
        "set -eu\n"
        "invoking_uid=\"$1\"\n"
        "install_id=\"$2\"\n"
        "case \"$invoking_uid\" in ''|*[!0-9]*) echo \"invalid invoking uid for outerssh-helper install\" >&2; exit 1 ;; esac\n"
        "case \"$install_id\" in ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]*) echo \"invalid install id for outerssh-helper install\" >&2; exit 1 ;; esac\n"
        "case \"$(uname -s)\" in Darwin) root_group=wheel ;; Linux) root_group=root ;; *) echo \"Unsupported bridge platform\" >&2; exit 1 ;; esac\n"
        "command -v gzip >/dev/null 2>&1 || { echo \"outerssh-helper install requires gzip on the server\" >&2; exit 1; }\n"
        "binary_upload=\"$(mktemp)\"\n"
        "trap 'rm -f \"$binary_upload\"' EXIT\n"
        "gzip -dc > \"$binary_upload\" || { echo \"outerssh-helper upload was truncated or corrupt\" >&2; exit 1; }\n"
        "chmod 0755 \"$binary_upload\"\n"
        "runtime_dir='" BRIDGE_RUNTIME_DIRECTORY "'\n"
        "base_dir=\"$runtime_dir/$invoking_uid\"\n"
        "install_dir=\"$base_dir/$install_id\"\n"
        "executable_path=\"$install_dir/outerssh-helper\"\n"
        "prepare_directory() { dir=\"$1\"; if [ -e \"$dir\" ] && { [ ! -d \"$dir\" ] || [ -L \"$dir\" ]; }; then echo \"outerssh-helper runtime path is not a directory: $dir\" >&2; exit 1; fi; install -d -o root -g \"$root_group\" -m 0700 \"$dir\"; [ -d \"$dir\" ] && [ ! -L \"$dir\" ] || { echo \"outerssh-helper runtime path is invalid: $dir\" >&2; exit 1; }; owner=\"$(stat -c %%u \"$dir\" 2>/dev/null || stat -f %%u \"$dir\" 2>/dev/null || echo '')\"; [ \"$owner\" = 0 ] || { echo \"outerssh-helper runtime path is not root-owned: $dir\" >&2; exit 1; }; chmod 0700 \"$dir\"; }\n"
        "prepare_directory \"$runtime_dir\"\n"
        "prepare_directory \"$base_dir\"\n"
        "rm -rf \"$install_dir\"\n"
        "prepare_directory \"$install_dir\"\n"
        "install -o root -g \"$root_group\" -m 0755 \"$binary_upload\" \"$executable_path\"\n"
        "version=\"$(\"$executable_path\" --version 2>&1)\" || { status=$?; rm -rf \"$install_dir\"; echo \"outerssh-helper failed to execute at $executable_path: $version\" >&2; exit \"$status\"; }\n"
        "case \"$version\" in outerssh-helper*) ;; *) rm -rf \"$install_dir\"; echo \"outerssh-helper is not current at $executable_path\" >&2; exit 1 ;; esac\n"
        "rm -f /usr/local/libexec/outerssh-helper /etc/sudoers.d/outerssh-helper\n"
        "printf 'OUTERSSH_HELPER_EXECUTABLE=%%s\\n' \"$executable_path\"\n"
        "\"$executable_path\" --version";
    int script_byte_count = snprintf(NULL, 0, script_format);
    char *script = script_byte_count < 0 ? NULL : malloc((size_t)script_byte_count + 1);
    if (script != NULL) {
        if (snprintf(
                script, (size_t)script_byte_count + 1,
                script_format) != script_byte_count) {
            free(script);
            script = NULL;
        } else {
            script_length = (size_t)script_byte_count;
        }
    }
    char *quoted_script = shell_quote(script, script_length);
    char *quoted_install_id = shell_quote(install_id, install_id_length);
    const char command_format[] = "uid=\"$(id -u)\"; sudo %s sh -c %s sh \"$uid\" %s";
    int command_byte_count = quoted_script == NULL || quoted_install_id == NULL
        ? -1 : snprintf(NULL, 0, command_format, requires_password ? "-S -p ''" : "-n", quoted_script, quoted_install_id);
    char *command = command_byte_count < 0 ? NULL : malloc((size_t)command_byte_count + 1);
    if (command != NULL) {
        if (snprintf(
                command, (size_t)command_byte_count + 1,
                command_format, requires_password ? "-S -p ''" : "-n", quoted_script, quoted_install_id) != command_byte_count) {
            free(command);
            command = NULL;
        } else if (command_length != NULL) {
            *command_length = (size_t)command_byte_count;
        }
    }
    free(script);
    free(quoted_script);
    free(quoted_install_id);
    return command;
}

char *outersshpriv_socket_bridge_install_user_command(
    const char *install_id,
    size_t install_id_length, size_t *command_length)
{
    if (command_length != NULL) *command_length = 0;
    char *quoted_install_id = shell_quote(install_id, install_id_length);
    if (quoted_install_id == NULL) {
        return NULL;
    }
    const char script_format[] =
        "set -eu\n"
        "install_id=%s\n"
        "case \"$install_id\" in ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]*) echo \"invalid install id for outerssh-helper install\" >&2; exit 1 ;; esac\n"
        "case \"$(uname -s)\" in Darwin|Linux) ;; *) echo \"Unsupported bridge platform\" >&2; exit 1 ;; esac\n"
        "if [ \"$(uname -s)\" = Darwin ]; then base_root=\"$(getconf DARWIN_USER_TEMP_DIR)\"; else base_root=\"${XDG_RUNTIME_DIR:-}\"; fi\n"
        "[ -n \"$base_root\" ] || base_root=\"${HOME:-}/.cache\"\n"
        "case \"$base_root\" in /*) ;; *) echo \"could not resolve an absolute user runtime directory for outerssh-helper\" >&2; exit 1 ;; esac\n"
        "base_dir=\"$base_root/" USER_BRIDGE_RUNTIME_DIRECTORY "\"\n"
        "install_dir=\"$base_dir/$install_id\"\n"
        "executable_path=\"$install_dir/outerssh-helper\"\n"
        "command -v gzip >/dev/null 2>&1 || { echo \"outerssh-helper install requires gzip on the server\" >&2; exit 1; }\n"
        "binary_upload=\"$(mktemp)\"\n"
        "trap 'rm -f \"$binary_upload\"' EXIT\n"
        "gzip -dc > \"$binary_upload\" || { echo \"outerssh-helper upload was truncated or corrupt\" >&2; exit 1; }\n"
        "rm -rf \"$install_dir\"\n"
        "install -d -m 0700 \"$install_dir\"\n"
        "install -m 0755 \"$binary_upload\" \"$executable_path\"\n"
        "version=\"$(\"$executable_path\" --version 2>&1)\" || { status=$?; rm -rf \"$install_dir\"; echo \"outerssh-helper failed to execute at $executable_path: $version\" >&2; exit \"$status\"; }\n"
        "case \"$version\" in outerssh-helper*) ;; *) rm -rf \"$install_dir\"; echo \"outerssh-helper is not current at $executable_path\" >&2; exit 1 ;; esac\n"
        "printf 'OUTERSSH_HELPER_EXECUTABLE=%%s\\n' \"$executable_path\"\n"
        "\"$executable_path\" --version";
    int script_byte_count = snprintf(NULL, 0, script_format, quoted_install_id);
    char *script = script_byte_count < 0 ? NULL : malloc((size_t)script_byte_count + 1);
    if (script != NULL) {
        if (snprintf(
                script, (size_t)script_byte_count + 1,
                script_format, quoted_install_id) != script_byte_count) {
            free(script);
            script = NULL;
        } else if (command_length != NULL) {
            *command_length = (size_t)script_byte_count;
        }
    }
    free(quoted_install_id);
    return script;
}

char *outersshpriv_socket_bridge_cleanup_command(const char *executable_path, size_t executable_path_length, size_t *command_length)
{
    if (command_length != NULL) *command_length = 0;
    char *quoted_executable = shell_quote(executable_path, executable_path_length);
    static const char command_format[] =
        "sudo -n sh -c 'set -eu\n"
        "executable_path=\"$1\"\n"
        "case \"$executable_path\" in\n"
        "  '\\''" BRIDGE_RUNTIME_DIRECTORY "'\\''/*/outerssh-helper) ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n"
        "install_dir=\"$(dirname \"$executable_path\")\"\n"
        "base_dir=\"$(dirname \"$install_dir\")\"\n"
        "runtime_dir=\"$(dirname \"$base_dir\")\"\n"
        "rm -rf -- \"$install_dir\"\n"
        "rmdir \"$base_dir\" \"$runtime_dir\" 2>/dev/null || true' sh %s";
    int command_byte_count = quoted_executable == NULL
        ? -1 : snprintf(NULL, 0, command_format, quoted_executable);
    char *command = command_byte_count < 0 ? NULL : malloc((size_t)command_byte_count + 1);
    if (command != NULL) {
        if (snprintf(
                command, (size_t)command_byte_count + 1,
                command_format, quoted_executable) != command_byte_count) {
            free(command);
            command = NULL;
        } else if (command_length != NULL) {
            *command_length = (size_t)command_byte_count;
        }
    }
    free(quoted_executable);
    return command;
}

char *outersshpriv_socket_bridge_cleanup_user_command(const char *executable_path, size_t executable_path_length, size_t *command_length)
{
    if (windows_executable(executable_path, executable_path_length))
        return windows_cleanup(executable_path, executable_path_length, command_length);
    if (command_length != NULL) *command_length = 0;
    char *quoted_executable = shell_quote(executable_path, executable_path_length);
    const char script_format[] =
        "set -eu\n"
        "executable_path=%s\n"
        "case \"$executable_path\" in\n"
        "  */" USER_BRIDGE_RUNTIME_DIRECTORY "/*/outerssh-helper) ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n"
        "install_dir=\"$(dirname \"$executable_path\")\"\n"
        "base_dir=\"$(dirname \"$install_dir\")\"\n"
        "rm -rf -- \"$install_dir\"\n"
        "rmdir \"$base_dir\" 2>/dev/null || true";
    int script_byte_count = quoted_executable == NULL
        ? -1 : snprintf(NULL, 0, script_format, quoted_executable);
    char *script = script_byte_count < 0 ? NULL : malloc((size_t)script_byte_count + 1);
    if (script != NULL) {
        if (snprintf(
                script, (size_t)script_byte_count + 1,
                script_format, quoted_executable) != script_byte_count) {
            free(script);
            script = NULL;
        } else if (command_length != NULL) {
            *command_length = (size_t)script_byte_count;
        }
    }
    free(quoted_executable);
    return script;
}

#pragma mark - Locate Bridge Executables

char *outersshpriv_socket_bridge_installed_executable_path(
    const char *output,
    size_t output_byte_count,
    const char *install_id,
    size_t install_id_length,
    bool requires_root_directory, size_t *executable_path_length)
{
    if (executable_path_length != NULL) *executable_path_length = 0;
    if (output == NULL || install_id == NULL) {
        return NULL;
    }
    static const char prefix[] = "OUTERSSH_HELPER_EXECUTABLE=";
    const char *path_start = NULL;
    const char *path_end = NULL;
    const char *end = output + output_byte_count;
    for (const char *line = output; line < end;) {
        const char *line_end = memchr(line, '\n', (size_t)(end - line));
        if (line_end == NULL) {
            line_end = end;
        }
        if ((size_t)(line_end - line) >= sizeof(prefix) - 1 &&
            memcmp(line, prefix, sizeof(prefix) - 1) == 0) {
            path_start = line + sizeof(prefix) - 1;
            path_end = line_end;
        }
        line = line_end == end ? end : line_end + 1;
    }
    if (path_start == NULL) {
        return NULL;
    }
    while (path_start < path_end && isspace((unsigned char)*path_start)) {
        path_start++;
    }
    while (path_end > path_start && isspace((unsigned char)path_end[-1])) {
        path_end--;
    }
    size_t path_length = (size_t)(path_end - path_start);
    bool windows = windows_executable(path_start, path_length);
    if (windows && requires_root_directory) return NULL;
    const char *filename = windows ? "\\outerssh-helper.exe" : "/outerssh-helper";
    size_t filename_length = strlen(filename);
    static const char root_directory[] = BRIDGE_RUNTIME_DIRECTORY "/";
    if (path_length < filename_length + 1 ||
        install_id_length > path_length - filename_length - 1) {
        return NULL;
    }
    const char *id_start = path_end - filename_length - install_id_length;
    if ((!windows && path_start[0] != '/') || memchr(path_start, '\0', path_length) != NULL ||
        memcmp(path_end - filename_length, filename, filename_length) != 0 ||
        memcmp(id_start, install_id, install_id_length) != 0 ||
        (windows ? ((size_t)(id_start - path_start) < sizeof("\\OuterSSH-Helper-") - 1 ||
            memcmp(id_start - (sizeof("\\OuterSSH-Helper-") - 1), "\\OuterSSH-Helper-", sizeof("\\OuterSSH-Helper-") - 1)) : id_start[-1] != '/') ||
        (requires_root_directory &&
         (path_length < sizeof(root_directory) - 1 ||
          memcmp(path_start, root_directory, sizeof(root_directory) - 1) != 0))) {
        return NULL;
    }
    char *path = malloc(path_length + 1);
    if (path != NULL) {
        memcpy(path, path_start, path_length);
        path[path_length] = '\0';
        if (executable_path_length != NULL) *executable_path_length = path_length;
    }
    return path;
}

const char *outersshpriv_helper_platform(
    const char *remote_platform,
    size_t remote_platform_byte_count, size_t *name_length)
{
    if (name_length != NULL) *name_length = 0;
    if (remote_platform == NULL) {
        return NULL;
    }
    size_t offset = 0;
    while (offset < remote_platform_byte_count &&
           isspace((unsigned char)remote_platform[offset])) {
        offset++;
    }
    char architecture[sizeof("aarch64") - 1];
    size_t architecture_length = 0;
    while (offset < remote_platform_byte_count &&
           !isspace((unsigned char)remote_platform[offset])) {
        if (architecture_length == sizeof(architecture)) {
            return NULL;
        }
        architecture[architecture_length++] =
            (char)tolower((unsigned char)remote_platform[offset++]);
    }
    while (offset < remote_platform_byte_count &&
           isspace((unsigned char)remote_platform[offset])) {
        offset++;
    }
    char libc[sizeof("windows") - 1];
    size_t libc_length = 0;
    while (offset < remote_platform_byte_count &&
           !isspace((unsigned char)remote_platform[offset])) {
        if (libc_length == sizeof(libc)) {
            return NULL;
        }
        libc[libc_length++] =
            (char)tolower((unsigned char)remote_platform[offset++]);
    }
    while (offset < remote_platform_byte_count &&
           isspace((unsigned char)remote_platform[offset])) {
        offset++;
    }
    if (offset != remote_platform_byte_count) {
        return NULL;
    }
    enum { ARM64, X86_64, X86, ARMV7, ARCHITECTURE_COUNT };
    static const struct {
        const char *name;
        size_t architecture;
    } architectures[] = {
        {"aarch64", ARM64}, {"arm64", ARM64}, {"x86_64", X86_64}, {"amd64", X86_64}, {"x86", X86},
        {"armv7l", ARMV7}, {"armv7", ARMV7}, {"armv8l", ARMV7},
    };
    size_t architecture_index = ARCHITECTURE_COUNT;
    for (size_t i = 0; i < sizeof(architectures) / sizeof(architectures[0]); i++) {
        if (strlen(architectures[i].name) == architecture_length &&
            memcmp(architectures[i].name, architecture, architecture_length) == 0) {
            architecture_index = architectures[i].architecture;
            break;
        }
    }
    if (architecture_index == ARCHITECTURE_COUNT) {
        return NULL;
    }
    const char *name = NULL;
    if (libc_length == sizeof("windows") - 1 && memcmp(libc, "windows", libc_length) == 0) {
        static const char *const names[ARCHITECTURE_COUNT] = {
            [ARM64] = "windows-arm64", [X86_64] = "windows-x64", [X86] = "windows-x86",
        };
        name = names[architecture_index];
    } else if (libc_length == sizeof("darwin") - 1 && memcmp(libc, "darwin", libc_length) == 0) {
        static const char *const names[ARCHITECTURE_COUNT] = {
            [ARM64] = "macos-arm64", [X86_64] = "macos-x86_64",
        };
        name = names[architecture_index];
    } else if (libc_length == sizeof("glibc") - 1 && memcmp(libc, "glibc", libc_length) == 0) {
        static const char *const names[ARCHITECTURE_COUNT] = {
            [ARM64] = "linux-aarch64-glibc", [X86_64] = "linux-x86_64-glibc", [ARMV7] = "linux-armv7-glibc",
        };
        name = names[architecture_index];
    } else if (libc_length == sizeof("musl") - 1 && memcmp(libc, "musl", libc_length) == 0) {
        static const char *const names[ARCHITECTURE_COUNT] = {
            [ARM64] = "linux-aarch64-musl", [X86_64] = "linux-x86_64-musl", [ARMV7] = "linux-armv7-musl",
        };
        name = names[architecture_index];
    }
    if (name != NULL && name_length != NULL) *name_length = strlen(name);
    return name;
}

#pragma mark - Quote Shell Arguments

static char *shell_quote(const char *value, size_t value_length)
{
    if (value == NULL || value_length > (SIZE_MAX - 3) / 4 ||
        memchr(value, '\0', value_length) != NULL) {
        return NULL;
    }
    size_t length = 2;
    for (const char *cursor = value; cursor < value + value_length; cursor++) {
        if (length > SIZE_MAX - (*cursor == '\'' ? 4 : 1)) {
            return NULL;
        }
        length += *cursor == '\'' ? 4 : 1;
    }
    char *quoted = malloc(length + 1);
    if (quoted == NULL) {
        return NULL;
    }
    char *output = quoted;
    *output++ = '\'';
    for (const char *cursor = value; cursor < value + value_length; cursor++) {
        if (*cursor == '\'') {
            memcpy(output, "'\\''", 4);
            output += 4;
        } else {
            *output++ = *cursor;
        }
    }
    *output++ = '\'';
    *output = '\0';
    return quoted;
}

static char *base64(const unsigned char *bytes, size_t length)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (length > (SIZE_MAX / 4 - 1) * 3) return NULL;
    size_t size = ((length + 2) / 3) * 4;
    char *result = malloc(size + 1);
    if (!result) return NULL;
    for (size_t i = 0, out = 0; i < length; i += 3) {
        uint32_t value = (uint32_t)bytes[i] << 16;
        if (i + 1 < length) value |= (uint32_t)bytes[i + 1] << 8;
        if (i + 2 < length) value |= bytes[i + 2];
        result[out++] = alphabet[value >> 18];
        result[out++] = alphabet[(value >> 12) & 63];
        result[out++] = i + 1 < length ? alphabet[(value >> 6) & 63] : '=';
        result[out++] = i + 2 < length ? alphabet[value & 63] : '=';
    }
    result[size] = 0;
    return result;
}

char *outersshpriv_windows_command(const char *script, size_t *command_length)
{
    if (command_length) *command_length = 0;
    if (!script) return NULL;
    size_t length = strlen(script);
    if (length > SIZE_MAX / 2) return NULL;
    unsigned char *unicode = malloc(length ? length * 2 : 1);
    if (!unicode) return NULL;
    size_t used = 0;
    for (size_t i = 0; i < length;) {
        uint32_t scalar = (unsigned char)script[i++], minimum = 0;
        unsigned continuation = 0;
        if (scalar >= 0xc2 && scalar <= 0xdf) { scalar &= 31; continuation = 1; minimum = 0x80; }
        else if (scalar >= 0xe0 && scalar <= 0xef) { scalar &= 15; continuation = 2; minimum = 0x800; }
        else if (scalar >= 0xf0 && scalar <= 0xf4) { scalar &= 7; continuation = 3; minimum = 0x10000; }
        else if (scalar >= 0x80) { free(unicode); return NULL; }
        if (length - i < continuation) { free(unicode); return NULL; }
        for (unsigned j = 0; j < continuation; j++) {
            unsigned char byte = (unsigned char)script[i++];
            if ((byte & 0xc0) != 0x80) { free(unicode); return NULL; }
            scalar = (scalar << 6) | (byte & 63);
        }
        if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)) { free(unicode); return NULL; }
        if (scalar > 0xffff) {
            scalar -= 0x10000;
            uint16_t high = 0xd800 | (uint16_t)(scalar >> 10);
            unicode[used++] = (unsigned char)high; unicode[used++] = (unsigned char)(high >> 8);
            scalar = 0xdc00 | (scalar & 1023);
        }
        unicode[used++] = (unsigned char)scalar; unicode[used++] = (unsigned char)(scalar >> 8);
    }
    char *encoded = base64(unicode, used);
    free(unicode);
    if (!encoded) return NULL;
    static const char prefix[] = OUTERSSH_WINDOWS_COMMAND_PREFIX;
    size_t command_size = sizeof(prefix) - 1 + strlen(encoded);
    char *command = malloc(command_size + 1);
    if (command) {
        memcpy(command, prefix, sizeof(prefix) - 1);
        strcpy(command + sizeof(prefix) - 1, encoded);
        if (command_length) *command_length = command_size;
    }
    free(encoded);
    return command;
}

static char *powershell_literal(const char *value, size_t length)
{
    if (!value || length > (SIZE_MAX - 3) / 2 || memchr(value, 0, length)) return NULL;
    char *result = malloc(2 * length + 3);
    if (!result) return NULL;
    size_t out = 0;
    result[out++] = '\'';
    for (size_t i = 0; i < length; i++) {
        result[out++] = value[i];
        if (value[i] == '\'') result[out++] = '\'';
    }
    result[out++] = '\''; result[out] = 0;
    return result;
}

static char *windows_launch(const char *path, size_t length, const char *endpoint, size_t endpoint_length, size_t *command_length)
{
    if (command_length) *command_length = 0;
    if (endpoint && !outerssh_proxy_is_named_pipe(endpoint, endpoint_length)) return NULL;
    if (installed_windows_executable(path, length)) {
        const char *format = endpoint ? "$outerBridgeArguments='bridge --socket %.*s'\n" OUTERSSH_WINDOWS_BRIDGE_RESOLVE_SCRIPT
            : "$outerBridgeArguments='service'\n" OUTERSSH_WINDOWS_BRIDGE_RESOLVE_SCRIPT;
        int count = snprintf(NULL, 0, format, (int)endpoint_length, endpoint);
        char *script = count < 0 ? NULL : malloc((size_t)count + 1);
        if (!script) return NULL;
        snprintf(script, (size_t)count + 1, format, (int)endpoint_length, endpoint);
        char *command = outersshpriv_windows_command(script, command_length);
        free(script);
        return command;
    }

    bool plain = length > 3;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = path[i];
        if (!isalnum(c) && c != ':' && c != '\\' && c != '.' && c != '-' && c != '_') plain = false;
    }
    if (plain) {
        size_t capacity = length + endpoint_length + 32;
        char *command = malloc(capacity);
        if (!command) return NULL;
        if (endpoint) snprintf(command, capacity, "%.*s bridge --socket %.*s", (int)length, path, (int)endpoint_length, endpoint);
        else snprintf(command, capacity, "%.*s service", (int)length, path);
        if (command_length) *command_length = strlen(command);
        return command;
    }
    char *executable = powershell_literal(path, length);
    char *argument = endpoint ? powershell_literal(endpoint, endpoint_length) : powershell_literal("", 0);
    if (!executable || !argument) { free(executable); free(argument); return NULL; }
    const char *format = endpoint ? "& %s bridge --socket %s; exit $LASTEXITCODE" : "& %s service; exit $LASTEXITCODE";
    size_t size = strlen(executable) + strlen(argument) + strlen(format) + 1;
    char *script = malloc(size);
    if (script) snprintf(script, size, format, executable, argument);
    free(executable); free(argument);
    char *command = script ? outersshpriv_windows_command(script, command_length) : NULL;
    free(script); return command;
}

char *outersshpriv_socket_bridge_install_windows_command(const char *install_id, size_t id_length,
    size_t *command_length)
{
    if (command_length) *command_length = 0;
    if (!install_id || !id_length || id_length > 128) return NULL;
    for (size_t i = 0; i < id_length; i++) {
        unsigned char c = install_id[i];
        if (!isalnum(c) && c != '-' && c != '_') return NULL;
    }
    const char format[] =
        "$ErrorActionPreference='Stop'; "
        "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); $a=([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
        "$root=[Environment]::GetFolderPath($(if($a){'CommonApplicationData'}else{'LocalApplicationData'})); "
        "$dir=Join-Path $root 'OuterSSH-Helper-%.*s'; if(Test-Path -LiteralPath $dir){throw 'Bridge staging already exists'}; "
        "$acl=[Security.AccessControl.DirectorySecurity]::new(); $s='D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'; if(!$a){$s+='(A;OICI;FA;;;'+$i.User.Value+')'}; "
        "$acl.SetSecurityDescriptorSddlForm($s); [void][IO.Directory]::CreateDirectory($dir,$acl); "
        "$item=Get-Item -LiteralPath $dir -Force; if($item.Attributes -band 1024){throw 'Unsafe bridge staging'}; "
        "$actual=[IO.Directory]::GetAccessControl($dir); $owner=$actual.GetOwner([Security.Principal.SecurityIdentifier]).Value; "
        "if($a -and $owner -notin @('S-1-5-18','S-1-5-32-544')){throw 'Untrusted elevated bridge owner'}; "
        "foreach($rule in $actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($a -and $rule.AccessControlType -eq 0 -and ($rule.FileSystemRights -band 0xD0156) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Writable elevated bridge staging'}}; "
        "$path=Join-Path $dir 'outerssh-helper.exe'; "
        "$tar=Join-Path ([Environment]::SystemDirectory) 'tar.exe'; if(!(Test-Path -LiteralPath $tar -PathType Leaf)){throw 'outerssh-helper install requires tar.exe (Windows 10 version 1803 or later)'}; "
        "$s=[Diagnostics.ProcessStartInfo]::new(); $s.FileName=$tar; $s.Arguments='-xzf - -C \"'+$dir+'\" outerssh-helper.exe'; $s.UseShellExecute=$false; "
        "$q=[Diagnostics.Process]::Start($s); $q.WaitForExit(); if($q.ExitCode -ne 0){throw 'outerssh-helper upload was truncated or corrupt'}; "
        "if(@(Get-ChildItem -LiteralPath $dir -Force).Count -ne 1 -or !(Test-Path -LiteralPath $path -PathType Leaf)){throw 'outerssh-helper upload did not contain the bridge executable'}; "
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::WriteLine('OUTERSSH_HELPER_EXECUTABLE='+$path)";
    int size = snprintf(NULL, 0, format, (int)id_length, install_id);
    char *script = size < 0 ? NULL : malloc((size_t)size + 1);
    if (!script) return NULL;
    snprintf(script, (size_t)size + 1, format, (int)id_length, install_id);
    char *command = outersshpriv_windows_command(script, command_length);
    free(script); return command;
}

static char *windows_cleanup(const char *path, size_t length, size_t *command_length)
{
    if (command_length) *command_length = 0;
    char *literal = powershell_literal(path, length);
    if (!literal) return NULL;
    const char format[] = "$ErrorActionPreference='Stop'; $path=%s; $dir=[IO.Path]::GetDirectoryName($path); "
        "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); $a=([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
        "$root=[Environment]::GetFolderPath($(if($a){'CommonApplicationData'}else{'LocalApplicationData'})); "
        "if([IO.Path]::GetFileName($path) -cne 'outerssh-helper.exe' -or [IO.Path]::GetDirectoryName($dir) -ine $root -or [IO.Path]::GetFileName($dir) -cnotmatch '\\AOuterSSH-Helper-[A-Za-z0-9_-]+\\z'){throw 'Invalid bridge cleanup path'}; "
        "Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop";
    size_t size = sizeof(format) + strlen(literal);
    char *script = malloc(size);
    if (script) snprintf(script, size, format, literal);
    free(literal);
    char *command = script ? outersshpriv_windows_command(script, command_length) : NULL;
    free(script); return command;
}

