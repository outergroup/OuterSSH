#include "SocketBridgeCommands.h"
#include "SSHProxyAddress.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void test_platform_names(void)
{
    const struct {
        const char *platform;
        const char *name;
    } cases[] = {
        {"arm64 windows", "windows-arm64"},
        {"amd64 windows", "windows-x64"},
        {"x86 windows", "windows-x86"},
        {"arm64 darwin", "macos-arm64"},
        {"x86_64 darwin", "macos-x86_64"},
        {"aarch64 glibc", "linux-aarch64-glibc"},
        {"arm64 musl", "linux-aarch64-musl"},
        {"amd64 glibc", "linux-x86_64-glibc"},
        {"x86_64 musl", "linux-x86_64-musl"},
        {"armv7l glibc", "linux-armv7-glibc"},
        {"armv8l musl", "linux-armv7-musl"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t length = 0;
        const char *name = outersshpriv_helper_platform(
            cases[i].platform, strlen(cases[i].platform), &length);
        assert(name != NULL && length == strlen(cases[i].name));
        assert(memcmp(name, cases[i].name, length) == 0);
    }
    size_t invalid_length = 123;
    assert(outersshpriv_helper_platform(NULL, 0, &invalid_length) == NULL);
    assert(invalid_length == 0);

    char platform[sizeof(" ARM64   MUSL\n") - 1];
    memcpy(platform, " ARM64   MUSL\n", sizeof(platform));
    const char *name = outersshpriv_helper_platform(platform, sizeof(platform), NULL);
    assert(name != NULL);
    assert(strcmp(name, "linux-aarch64-musl") == 0);

    name = outersshpriv_helper_platform("amd64 glibc", sizeof("amd64 glibc") - 1, NULL);
    assert(name != NULL);
    assert(strcmp(name, "linux-x86_64-glibc") == 0);

    name = outersshpriv_helper_platform("amd64 glibc extra", sizeof("amd64 glibc") - 1, NULL);
    assert(name != NULL);
    assert(strcmp(name, "linux-x86_64-glibc") == 0);
    assert(outersshpriv_helper_platform("", 0, NULL) == NULL);
    assert(outersshpriv_helper_platform("amd64", sizeof("amd64") - 1, NULL) == NULL);
    assert(outersshpriv_helper_platform("amd64 glibc\0extra", sizeof("amd64 glibc\0extra") - 1, NULL) == NULL);
    assert(outersshpriv_helper_platform("armv6l glibc", sizeof("armv6l glibc") - 1, NULL) == NULL);
    assert(outersshpriv_helper_platform("i686 glibc", sizeof("i686 glibc") - 1, NULL) == NULL);
    assert(outersshpriv_helper_platform("x86 glibc", sizeof("x86 glibc") - 1, NULL) == NULL);
    assert(outersshpriv_helper_platform("armv7l darwin", sizeof("armv7l darwin") - 1, NULL) == NULL);
    assert(outersshpriv_helper_platform("armv7l windows", sizeof("armv7l windows") - 1, NULL) == NULL);
    assert(outersshpriv_helper_platform("x86_64 glibc extra", sizeof("x86_64 glibc extra") - 1, NULL) == NULL);
}

static void test_command_quoting(void)
{
    char *command = outersshpriv_socket_bridge_launch_user_command(
        "/tmp/a'b.sock", sizeof("/tmp/a'b.sock") - 1,
        "/tmp/helper", sizeof("/tmp/helper") - 1, "", NULL);
    assert(command != NULL);
    assert(strcmp(
        command,
        "'/tmp/helper' bridge --socket '/tmp/a'\\''b.sock'") == 0);
    free(command);

    size_t service_command_length;
    command = outersshpriv_socket_service_launch_command(
        "/tmp/helper", sizeof("/tmp/helper") - 1, "", &service_command_length);
    assert(command != NULL);
    assert(strcmp(
        command,
        "exec '/tmp/helper' service") == 0);
    free(command);

    command = outersshpriv_socket_bridge_install_user_command("install-id", sizeof("install-id") - 1, NULL);
    assert(command != NULL);
    assert(strstr(command, "command -v gzip") != NULL);
    assert(strstr(command, "gzip -dc > \"$binary_upload\"") != NULL);
    assert(strstr(command, "dd ") == NULL);
    assert(strstr(command, "install_id='install-id'") != NULL);
    assert(strstr(command, "printf 'OUTERSSH_HELPER_EXECUTABLE=%s\\n'") != NULL);
    free(command);
}

static void test_additional_allowlists(void)
{
    static const char path[] = "%c/old client's/http-unix.allow";
    static const char system_path[] = "/etc/old-client/http-unix.allow";
    OuterSSHSocketAllowlist entries[] = {
        {path, sizeof(path) - 1, false},
        {system_path, sizeof(system_path) - 1, true},
    };
    char *arguments = outersshpriv_socket_bridge_allowlist_arguments(entries, 2);
    assert(arguments != NULL);
    assert(strstr(arguments, " --user-allowlist ") != NULL);
    assert(strstr(arguments, "'%c/old client'\\''s/http-unix.allow'") != NULL);
    assert(strstr(arguments, " --system-allowlist '/etc/old-client/http-unix.allow'") != NULL);
    size_t length;
    char *command = outersshpriv_socket_service_launch_command("/bridge", 7, arguments, &length);
    assert(command != NULL && length == strlen(command));
    assert(strstr(command, arguments) != NULL);
    free(command);
    command = outersshpriv_socket_bridge_launch_command("/socket", 7, "/bridge", 7, arguments, true, &length);
    assert(command != NULL && strstr(command, arguments) != NULL);
    free(command);
    free(arguments);
    entries[0].system = true;
    assert(outersshpriv_socket_bridge_allowlist_arguments(entries, 1) == NULL);
    entries[0].system = false;
    entries[0].path_length = sizeof(path); /* Embedded terminator is rejected. */
    assert(outersshpriv_socket_bridge_allowlist_arguments(entries, 1) == NULL);
    assert(outersshpriv_socket_bridge_allowlist_arguments(NULL, 1) == NULL);
}

static void test_installed_paths(void)
{
    static const char installed[] =
        "noise\nOUTERSSH_HELPER_EXECUTABLE= /var/tmp/outerssh-helper/501/id/outerssh-helper \r\n";
    char output[sizeof(installed) - 1];
    memcpy(output, installed, sizeof(output));
    char *path = outersshpriv_socket_bridge_installed_executable_path(output, sizeof(output), "id", sizeof("id") - 1, true, NULL);
    assert(path != NULL);
    assert(strcmp(path, "/var/tmp/outerssh-helper/501/id/outerssh-helper") == 0);
    free(path);

    static const char user_installed[] =
        "OUTERSSH_HELPER_EXECUTABLE=/home/alice/.cache/outerssh-helper/id/outerssh-helper";
    path = outersshpriv_socket_bridge_installed_executable_path(user_installed, sizeof(user_installed) - 1, "id", sizeof("id") - 1, false, NULL);
    assert(path != NULL);
    assert(strcmp(path, "/home/alice/.cache/outerssh-helper/id/outerssh-helper") == 0);
    free(path);

    static const char multiple[] =
        "OUTERSSH_HELPER_EXECUTABLE=/old/id/outerssh-helper\n"
        "OUTERSSH_HELPER_EXECUTABLE=/new/id/outerssh-helper\n";
    path = outersshpriv_socket_bridge_installed_executable_path(multiple, sizeof(multiple) - 1, "id", sizeof("id") - 1, false, NULL);
    assert(path != NULL && strcmp(path, "/new/id/outerssh-helper") == 0);
    free(path);
    path = outersshpriv_socket_bridge_installed_executable_path(multiple,
        sizeof("OUTERSSH_HELPER_EXECUTABLE=/old/id/outerssh-helper\n") - 1, "id", sizeof("id") - 1, false, NULL);
    assert(path != NULL && strcmp(path, "/old/id/outerssh-helper") == 0);
    free(path);

    static const char embedded_null[] =
        "OUTERSSH_HELPER_EXECUTABLE=/tmp/\0/id/outerssh-helper";
    assert(outersshpriv_socket_bridge_installed_executable_path(embedded_null, sizeof(embedded_null) - 1, "id", sizeof("id") - 1, false, NULL) == NULL);
    const char *invalid[] = {
        "",
        "OUTERSSH_HELPER_EXECUTABLE=",
        "OUTERSSH_HELPER_EXECUTABLE=relative/id/outerssh-helper",
        "OUTERSSH_HELPER_EXECUTABLE=/tmp/wrong-id/outerssh-helper",
        "OUTERSSH_HELPER_EXECUTABLE=/tmp/xid/outerssh-helper",
        "OUTERSSH_HELPER_EXECUTABLE=/tmp/id/outerssh-helper-extra",
        "OUTERSSH_HELPER_EXECUTABLE=/tmp/id/outerssh-helper\nOUTERSSH_HELPER_EXECUTABLE=bad"
    };
    for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
        assert(outersshpriv_socket_bridge_installed_executable_path(invalid[index], strlen(invalid[index]), "id", sizeof("id") - 1, false, NULL) == NULL);
    }
    assert(outersshpriv_socket_bridge_installed_executable_path(user_installed, sizeof(user_installed) - 1, "id", sizeof("id") - 1, true, NULL) == NULL);
}

static void test_length_delimited_strings(void)
{
    char path[sizeof("/tmp/café's.sock") - 1];
    memcpy(path, "/tmp/café's.sock", sizeof(path));
    char helper[sizeof("/tmp/helper") - 1];
    memcpy(helper, "/tmp/helper", sizeof(helper));
    size_t command_length = 0;
    char *command = outersshpriv_socket_bridge_launch_user_command(path, sizeof(path), helper, sizeof(helper), "", &command_length);
    assert(command != NULL && command_length == strlen(command));
    assert(strstr(command, "café") != NULL && strstr(command, "'\\''") != NULL);
    free(command);
    char invalid[] = {'/', 't', '\0', 'x'};
    assert(outersshpriv_socket_bridge_launch_user_command(invalid, sizeof(invalid), helper, sizeof(helper), "", &command_length) == NULL);
    assert(command_length == 0);

    char host[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
    size_t host_length, decoded_length;
    OuterSSHProxySocketKind kind;
    assert(outerssh_proxy_encode_unix_socket_host(path, sizeof(path), host, sizeof(host), &host_length));
    char *host_bytes = malloc(host_length);
    assert(host_bytes != NULL);
    memcpy(host_bytes, host, host_length);
    char decoded[sizeof(path) + 1];
    assert(outerssh_proxy_decode_socket_host(host_bytes, host_length, &kind, decoded, sizeof(decoded), &decoded_length));
    assert(kind == OUTERSSH_PROXY_SOCKET_KIND_UNIX);
    assert(decoded_length == sizeof(path) && memcmp(decoded, path, sizeof(path)) == 0);
    host_bytes[0] = '\0';
    assert(!outerssh_proxy_decode_socket_host(host_bytes, host_length, &kind, decoded, sizeof(decoded), &decoded_length));
    assert(decoded_length == 0);
    free(host_bytes);
    assert(!outerssh_proxy_decode_socket_host("x", SIZE_MAX, &kind, decoded, sizeof(decoded), &decoded_length));
    assert(decoded_length == 0);
    assert(!outersshpriv_proxy_is_tcp_host("x", SIZE_MAX));
    assert(!outersshpriv_proxy_is_tcp_host(NULL, 0));
    char encoded[OUTERSSH_PROXY_TCP_HOST_CAPACITY];
    size_t encoded_length = 1;
    assert(!outerssh_proxy_encode_tcp_host("x", SIZE_MAX, encoded, sizeof(encoded), &encoded_length));
    assert(encoded_length == 0);
    const char loopback[] = "localhost.tcp.outerssh.localhost";
    assert(outersshpriv_proxy_is_tcp_host(loopback, sizeof(loopback) - 1));
}


static void test_windows_pipe_addresses(void)
{
    const char pipe[] = "\\\\.\\pipe\\org.outershell.outershell.s-1-5-18";
    char host[254], decoded[145]; size_t host_length = 0, decoded_length = 0;
    OuterSSHProxySocketKind kind;
    assert(outerssh_proxy_encode_named_pipe_host(pipe, strlen(pipe), host, sizeof(host), &host_length));
    assert(strstr(host, ".pipe.outerssh.localhost"));
    assert(outerssh_proxy_decode_socket_host(host, host_length, &kind, decoded, sizeof(decoded), &decoded_length));
    assert(kind == OUTERSSH_PROXY_SOCKET_KIND_NAMED_PIPE && !strcmp(pipe, decoded));
    memcpy(strstr(host, ".pipe."), ".unix.", 6);
    assert(!outerssh_proxy_decode_socket_host(host, host_length, &kind, decoded, sizeof(decoded), &decoded_length));
    assert(!outerssh_proxy_encode_unix_socket_host(pipe, strlen(pipe), host, sizeof(host), &host_length));
    assert(!outerssh_proxy_encode_named_pipe_host("/run/app.sock", strlen("/run/app.sock"), host, sizeof(host), &host_length));
    assert(!outerssh_proxy_is_named_pipe("\\\\server\\pipe\\app", strlen("\\\\server\\pipe\\app")));
    assert(!outerssh_proxy_is_named_pipe("\\\\.\\pipe\\app\\child", strlen("\\\\.\\pipe\\app\\child")));
    const char installed[] = OUTERSSH_WINDOWS_BRIDGE_EXECUTABLE;
    size_t native_length = 0;
    char *native = outersshpriv_socket_service_launch_command(installed, sizeof(installed) - 1, "", &native_length);
    assert(native && !strcmp(native, OUTERSSH_WINDOWS_BRIDGE_SERVICE_COMMAND) && native_length == strlen(native));
    free(native);
    native = outersshpriv_socket_bridge_launch_user_command(pipe, strlen(pipe), installed, sizeof(installed) - 1, "", &native_length);
    const char prefix[] = OUTERSSH_WINDOWS_COMMAND_PREFIX;
    assert(native && !strncmp(native, prefix, sizeof(prefix) - 1));
    assert(native_length == strlen(native) && native_length < 8191);
    free(native);
    const char malicious[] = "\\\\.\\pipe\\app&whoami";
    native = outersshpriv_socket_bridge_launch_user_command(malicious, strlen(malicious), installed, sizeof(installed) - 1, "", &native_length);
    assert(native == NULL && native_length == 0);
    for (unsigned value = 0; value <= 255; ++value) {
        char candidate[] = "\\\\.\\pipe\\appX";
        candidate[sizeof(candidate) - 2] = (char)value;
        bool permitted = (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
            value == '.' || value == '-' || value == '_';
        native_length = 123;
        native = outersshpriv_socket_bridge_launch_user_command(candidate, sizeof(candidate) - 1,
            installed, sizeof(installed) - 1, "", &native_length);
        assert((native != NULL) == permitted);
        if (native) assert(native_length == strlen(native));
        else assert(native_length == 0);
        free(native);
    }
    const char path[] = "C:\\Users\\A'B\\OuterSSH-Helper-install-id\\outerssh-helper.exe";
    size_t length = 0;
    char *command = outersshpriv_socket_service_launch_command(path, strlen(path), "", &length);
    assert(command && length == strlen(command) && strstr(command, "-EncodedCommand "));
    assert(!strstr(command, "A'B")); free(command);
    command = outersshpriv_socket_bridge_install_windows_command("bad';id", 7, &length);
    assert(!command && !length);
    command = outersshpriv_socket_bridge_install_windows_command("install-id", 10, &length);
    assert(command && length == strlen(command) && strstr(command, "-EncodedCommand "));
    free(command);
    const char output[] = "OUTERSSH_HELPER_EXECUTABLE=C:\\Users\\A'B\\OuterSSH-Helper-install-id\\outerssh-helper.exe\r\n";
    command = outersshpriv_socket_bridge_installed_executable_path(output, strlen(output), "install-id", 10, false, &length);
    assert(command && !strcmp(command, path)); free(command);
    assert(!outersshpriv_socket_bridge_installed_executable_path(output, strlen(output), "install-id", 10, true, &length));
}

static void test_windows_actions(void)
{
    const char path[] = "C:\\ProgramData\\OuterSSH-Helper-install-id\\outerssh-helper.exe";
    size_t length = 0;
    char *command;
    const char output[] = "OUTERSSH_HELPER_EXECUTABLE=C:\\ProgramData\\OuterSSH-Helper-install-id\\outerssh-helper.exe\r\n";
    command = outersshpriv_socket_bridge_installed_executable_path(output, strlen(output), "install-id", 10, false, &length);
    assert(command && !strcmp(command, path)); free(command);
    command = outersshpriv_socket_bridge_installed_executable_path(output, strlen(output), "other-id", 8, false, &length);
    assert(!command && !length);
}

int main(void)
{
    test_windows_actions();
    test_windows_pipe_addresses();
    test_additional_allowlists();
    test_length_delimited_strings();
    test_platform_names();
    test_command_quoting();
    test_installed_paths();
    return 0;
}
