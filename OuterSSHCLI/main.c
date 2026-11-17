#include "CLIPlatform.h"
#include <OuterSSH/OuterSSH.h>
#include <libssh2.h>
#include "../OuterSSH/platform/Base64.h"
#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#elif OUTERSSH_WINDOWS_CRYPTO
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void clear_secret(void *memory, size_t length)
{
    volatile unsigned char *bytes = memory;
    while (length-- != 0) *bytes++ = 0;
}

#ifndef OUTERSSH_CLI_VERSION
#define OUTERSSH_CLI_VERSION "development"
#endif

static void usage(FILE *stream)
{
    fprintf(stream,
        "Usage: outerssh [-L port:host:port] [-D port] [--http-proxy port] [-p ssh-port] [-l user] [-i identity] [-F config] [-J [user@]host[:port][,...]] [options] [user@]host\n"
        "\n"
        "Creates loopback port forwards, SOCKS5 and HTTP proxies sharing one SSH pool.\n"
        "  -L port:host:port        Forward raw TCP to a fixed destination (repeatable)\n"
        "                           IPv6 destinations: port:[host]:port; local 0 is allowed\n"
        "  -D port                  Local SOCKS port (0 chooses an available port)\n"
        "  -p port                  SSH port (overrides SSH configuration)\n"
        "  -l user                  SSH user (overrides SSH configuration)\n"
        "  -J destination           Connect through [user@]host[:port] (comma-separated hops)\n"
        "                           Use brackets for IPv6; 'none' overrides ProxyJump\n"
        "  -i path                  Private key (overrides configured identity)\n"
        "  -F path                  Alternate OpenSSH configuration file\n"
        "  --ask-passphrase         Prompt for the private key's passphrase\n"
        "  --password               Prompt for the SSH password without trying keys first\n"
        "  --proxy-user user        Require proxy username/password authentication\n"
        "                           and prompt for the proxy password\n"
        "  --proxy-password-env var Read the proxy password from this environment variable\n"
        "  --known-hosts path       Override the configured host key file\n"
        "  --http-proxy port        Serve HTTP/CONNECT directly over SSH\n"
        "  --rewrite-http           Rewrite HTTP traffic in SOCKS and HTTP listeners\n"
        "  --batch                  Reject unknown host keys without prompting\n"
        "  -h, --help               Show this help\n"
        "  --version                Show the version\n"
        "\n"
        "Without --proxy-user, both listeners need no credentials. Chrome SOCKS requires this.\n"
        "Connection settings, including ProxyJump, are resolved with ssh -G.\n"
        "Remote commands, ProxyCommand, and UDP are not supported.\n");
}

static bool parse_port(const char *text, bool allow_zero, int *port)
{
    if (*text == '\0') return false;
    for (const char *p = text; *p != '\0'; p++) if (*p < '0' || *p > '9') return false;
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || *end != '\0' || value < (allow_zero ? 0 : 1) || value > UINT16_MAX) return false;
    *port = (int)value;
    return true;
}

static void print_error(OuterSSHError error)
{
    fprintf(stderr, "outerssh: %.*s", (int)error.message_length, error.message == NULL ? "" : error.message);
    if (error.ssh_error_message_length != 0)
        fprintf(stderr, ": %.*s", (int)error.ssh_error_message_length, error.ssh_error_message);
    if (error.system_error_code != 0) fprintf(stderr, ": %s", strerror(error.system_error_code));
    fputc('\n', stderr);
}

static OuterSSHError trust_error(const char *message)
{
    return (OuterSSHError){.domain = OUTERSSH_ERROR_HOST_KEY_VALIDATION,
        .code = 1, .message = message, .message_length = strlen(message)};
}

typedef struct {
    const char *hostname;
    int port;
    const char *path;
    bool batch;
} HostTrust;

static int known_host_key_type(const char *algorithm)
{
    static const struct { const char *name; int type; } types[] = {
        {"ssh-rsa", LIBSSH2_KNOWNHOST_KEY_SSHRSA},
        {"ecdsa-sha2-nistp256", LIBSSH2_KNOWNHOST_KEY_ECDSA_256},
        {"ecdsa-sha2-nistp384", LIBSSH2_KNOWNHOST_KEY_ECDSA_384},
        {"ecdsa-sha2-nistp521", LIBSSH2_KNOWNHOST_KEY_ECDSA_521},
        {"ssh-ed25519", LIBSSH2_KNOWNHOST_KEY_ED25519},
    };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
        if (strcmp(algorithm, types[i].name) == 0) return types[i].type;
    return 0;
}

static OuterSSHError check_host_key(HostTrust *trust, const void *key, size_t length, const char *algorithm);

static OuterSSHError check_host_key(HostTrust *trust, const void *key, size_t length, const char *algorithm)
{
    int key_type = known_host_key_type(algorithm);
    if (key_type == 0 || length > UINT32_MAX) return trust_error("Unsupported SSH host key type.");
    LIBSSH2_SESSION *session = olibssh_session_init();
    LIBSSH2_KNOWNHOSTS *hosts = session == NULL ? NULL : libssh2_knownhost_init(session);
    if (hosts == NULL) {
        if (session != NULL) olibssh_session_free(session);
        return trust_error("Unable to allocate host key verifier.");
    }
    OuterSSHError error = {0};
    char *line = NULL;
    char *host = NULL;
    do {
        struct stat info;
        if (stat(trust->path, &info) == 0) {
            if (libssh2_knownhost_readfile(hosts, trust->path, LIBSSH2_KNOWNHOST_FILE_OPENSSH) < 0) {
                error = trust_error("Unable to read known_hosts.");
                break;
            }
        } else if (errno != ENOENT) {
            error = trust_error("Unable to access known_hosts.");
            break;
        }
        int mask = LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | key_type;
        int check = libssh2_knownhost_checkp(hosts, trust->hostname, trust->port, key, length, mask, NULL);
        if (check == LIBSSH2_KNOWNHOST_CHECK_MATCH) break;
        if (check != LIBSSH2_KNOWNHOST_CHECK_NOTFOUND) {
            error = trust_error("SSH host key does not match known_hosts; connection refused.");
            break;
        }
        unsigned char digest[32];
        unsigned int digest_length = sizeof(digest);
#if OUTERSSH_WINDOWS_CRYPTO
        if (length > ULONG_MAX || BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)key, (ULONG)length, digest, sizeof(digest)) < 0) {
#elif defined(__APPLE__)
        if (length > UINT32_MAX || !CC_SHA256(key, (CC_LONG)length, digest)) {
#else
        if (!EVP_Digest(key, length, digest, &digest_length, EVP_sha256(), NULL)) {
#endif
            error = trust_error("Unable to fingerprint the SSH host key.");
            break;
        }
        unsigned char fingerprint[4 * ((32 + 2) / 3) + 1];
        size_t fingerprint_length = outerssh_base64_encode(fingerprint, digest, (int)digest_length);
        while (fingerprint_length > 0 && fingerprint[fingerprint_length - 1] == '=') fingerprint_length--;
        fingerprint[fingerprint_length] = '\0';
        fprintf(stderr, "Unknown host %s:%d\nSHA256:%s\n", trust->hostname, trust->port, fingerprint);
        char answer[32];
        if (trust->batch || !cli_prompt("Trust this host and save its key? Type yes: ", answer,
                sizeof(answer), true) || strcmp(answer, "yes") != 0) {
            error = trust_error("SSH host key was not accepted.");
            break;
        }
        size_t host_capacity = strlen(trust->hostname) + 16;
        host = malloc(host_capacity);
        if (host == NULL) { error = trust_error("Unable to allocate host key entry."); break; }
        if (trust->port == 22) snprintf(host, host_capacity, "%s", trust->hostname);
        else snprintf(host, host_capacity, "[%s]:%d", trust->hostname, trust->port);
        struct libssh2_knownhost *entry = NULL;
        if (libssh2_knownhost_addc(hosts, host, NULL, key, length, NULL, 0, mask, &entry) != 0) {
            error = trust_error("Unable to encode the SSH host key.");
            break;
        }
        size_t line_length = 0;
        int result = libssh2_knownhost_writeline(hosts, entry, NULL, 0, &line_length, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
        if (result != LIBSSH2_ERROR_BUFFER_TOO_SMALL || line_length == SIZE_MAX) {
            error = trust_error("Unable to format the SSH host key.");
            break;
        }
        line = malloc(line_length + 1);
        if (line == NULL) { error = trust_error("Unable to allocate host key entry."); break; }
        if (libssh2_knownhost_writeline(hosts, entry, line, line_length + 1,
                &line_length, LIBSSH2_KNOWNHOST_FILE_OPENSSH) != 0) {
            error = trust_error("Unable to format the SSH host key.");
            break;
        }
        if (!cli_append_known_host(trust->path, line, line_length))
            error = trust_error("Unable to save the SSH host key.");
    } while (false);
    free(line);
    free(host);
    libssh2_knownhost_free(hosts);
    olibssh_session_free(session);
    return error;
}

typedef struct {
    void *semaphore;
    bool succeeded;
    bool authentication_failed;
    int port;
} Completion;

static uint64_t tag(Completion *completion)
{
    return (uint64_t)(uintptr_t)completion;
}

/* A request the library did not accept fails at once. */
static void submitted(Completion *completion, bool accepted)
{
    if (accepted) return;
    fputs("outerssh: could not submit the SSH request.\n", stderr);
    completion->succeeded = false;
    cli_semaphore_signal(completion->semaphore);
}

static bool wait_for_operation(Completion *completion)
{
    cli_semaphore_wait(completion->semaphore);
    return completion->succeeded;
}

typedef struct {
    OuterSSHSessionPool *pool;
    HostTrust *trust;
} PoolTrust;

/* The event queue and the host-key trust for each of its pools. */
static struct {
    OuterSSHEventQueue *event_queue;
    CLIEvents *source;
    PoolTrust pools[17];
    size_t pool_count;
} events;

static void trust_pool(OuterSSHSessionPool *pool, HostTrust *trust)
{
    events.pools[events.pool_count++] = (PoolTrust){.pool = pool, .trust = trust};
}

static void forget_pool(OuterSSHSessionPool *pool)
{
    for (size_t i = 0; i < events.pool_count; i++) {
        if (events.pools[i].pool != pool) continue;
        events.pools[i] = events.pools[--events.pool_count];
        return;
    }
}

static HostTrust *pool_trust(OuterSSHSessionPool *pool)
{
    for (size_t i = 0; i < events.pool_count; i++) if (events.pools[i].pool == pool) return events.pools[i].trust;
    return NULL;
}

static void complete(const OuterSSHEvent *event)
{
    Completion *completion = (Completion *)(uintptr_t)event->tag;
    OuterSSHError error = event->operation_completed.error;
    completion->succeeded = error.domain == OUTERSSH_ERROR_NONE;
    completion->authentication_failed = false;
    if (event->type == OUTERSSH_EVENT_DESTROYED) completion->succeeded = true;
    else if (!completion->succeeded) {
        completion->authentication_failed = error.domain == OUTERSSH_ERROR_SESSION &&
            error.code == OUTERSSH_SESSION_ERROR_AUTHENTICATION_FAILED;
        if (!completion->authentication_failed) print_error(error);
        else if (error.ssh_error_code == LIBSSH2_ERROR_METHOD_NOT_SUPPORTED)
            fprintf(stderr, "outerssh: %.*s\n", (int)error.message_length, error.message);
    }
    else if (event->type == OUTERSSH_EVENT_PROXY_STARTED) completion->port = event->proxy_started.listen_port;
    else if (event->type == OUTERSSH_EVENT_PORT_FORWARD_STARTED) completion->port = event->port_forward_started.listen_port;
    cli_semaphore_signal(completion->semaphore);
}

static void handle_event(const OuterSSHEvent *event)
{
    switch (event->type) {
    case OUTERSSH_EVENT_HOST_KEY_VALIDATION: {
        HostTrust *trust = pool_trust(event->pool);
        OuterSSHError error = trust == NULL ? trust_error("Unknown SSH session.")
            : check_host_key(trust, event->host_key_validation.host_key,
                event->host_key_validation.host_key_length, event->host_key_validation.host_key_algorithm);
        if (error.domain != OUTERSSH_ERROR_NONE) print_error(error);
        outerssh_session_pool_answer_host_key(event->pool, event->host_key_validation.question,
            error.domain == OUTERSSH_ERROR_NONE);
        break;
    }
    case OUTERSSH_EVENT_HELPER_BINARY_NEEDED: {
        static const char message[] = "outerssh does not package the remote socket bridge helpers.";
        outerssh_session_pool_decline_helper_binary(event->pool, event->helper_binary_needed.question, (OuterSSHError){
            .domain = OUTERSSH_ERROR_HELPER_INSTALLER,
            .code = OUTERSSH_HELPER_INSTALLER_ERROR_MISSING_PACKAGED_BINARY,
            .message = message, .message_length = sizeof(message) - 1,
        });
        break;
    }
    case OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED:
        fprintf(stderr, "outerssh: %.*s needs a sudo password, which outerssh does not prompt for\n",
            (int)event->sudo_password_needed.socket_path_length, event->sudo_password_needed.socket_path);
        outerssh_session_pool_decline_sudo_password(event->pool, event->sudo_password_needed.question);
        break;
    case OUTERSSH_EVENT_CONNECTION_FAILED:
        fprintf(stderr, "outerssh: forwarding %.*s:%u failed\n", (int)event->connection_failed.host_length,
            event->connection_failed.host, event->connection_failed.port);
        print_error(event->connection_failed.error);
        break;
    default:
        break;
    }
}

static void drain_events(void *context)
{
    (void)context;
    OuterSSHEvent batch[8];
    size_t count;
    while ((count = outerssh_event_queue_poll(events.event_queue, batch, 8)) != 0) {
        for (size_t i = 0; i < count; i++) {
            if (batch[i].tag != 0) complete(&batch[i]);
            else handle_event(&batch[i]);
        }
    }
}

static OuterSSHEventQueue *start_events(void)
{
    events.source = cli_events_start(drain_events, NULL);
    events.event_queue = events.source == NULL ? NULL : cli_event_queue(events.source);
    return events.event_queue;
}

/* Call after every pool and frontend has been destroyed. */
static void stop_events(void)
{
    cli_events_stop(events.source);
    events.source = NULL;
    events.event_queue = NULL;
}

typedef struct Configuration {
    char *name;
    char *value;
    struct Configuration *next;
} Configuration;

static Configuration *resolve_configuration(char *const arguments[])
{
    char *text = cli_resolve_configuration(arguments);
    if (text == NULL) return NULL;
    Configuration *first = NULL, **tail = &first;
    while (*text) {
        char *end = strchr(text, '\n');
        if (end != NULL) *end = '\0';
        size_t length = strlen(text);
        if (length && text[length - 1] == '\r') text[length - 1] = '\0';
        char *separator = strchr(text, ' ');
        if (separator != NULL) {
            *separator = '\0';
            Configuration *entry = cli_allocate(sizeof(*entry));
            entry->name = text;
            entry->value = separator + 1;
            *tail = entry;
            tail = &entry->next;
        }
        if (end == NULL) break;
        text = end + 1;
    }
    return first;
}

static char *configuration_value(Configuration *configuration, const char *name)
{
    for (; configuration != NULL; configuration = configuration->next)
        if (strcmp(configuration->name, name) == 0) return configuration->value;
    return NULL;
}

static bool equals(const char *value, const char *expected)
{
    return value != NULL && strcmp(value, expected) == 0;
}

static size_t text_length(const char *value) { return value == NULL ? 0 : strlen(value); }

static char *expand_identity_path(const char *path, const char *host, const char *original_host, const char *user, int port)
{
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%d", port);
    char *home = cli_home(), *local_user = cli_username();
    size_t capacity = strlen(path) + 1, length = 0;
    char *expanded = cli_allocate(capacity);
    for (size_t index = 0; path[index]; index++) {
        char single[2] = {path[index], 0};
        const char *value = single;
        if (path[index] == '%') {
            switch (path[++index]) {
                case '%': value = "%"; break;
                case 'd': value = home; break;
                case 'h': value = host; break;
                case 'n': value = original_host; break;
                case 'r': value = user; break;
                case 'u': value = local_user; break;
                case 'p': value = port_text; break;
                default: return NULL;
            }
        } else if (path[index] == '$' && path[index + 1] == '{') {
            const char *end = strchr(path + index + 2, '}');
            if (end == NULL) return NULL;
            char *name = cli_copy(path + index + 2);
            name[end - path - index - 2] = '\0';
            value = getenv(name);
            index = (size_t)(end - path);
        }
        if (value == NULL) return NULL;
        size_t count = strlen(value);
        if (count > SIZE_MAX - length - 1) return NULL;
        if (length + count + 1 > capacity) {
            size_t required = length + count + 1;
            capacity = capacity <= SIZE_MAX / 2 && capacity * 2 > required ? capacity * 2 : required;
            char *grown = cli_allocate(capacity);
            memcpy(grown, expanded, length);
            expanded = grown;
        }
        memcpy(expanded + length, value, count);
        length += count;
        expanded[length] = '\0';
    }
    return cli_expand_home(expanded);
}

static bool is_rooted_path(const char *path)
{
    return path[0] == '/' || path[0] == '\\' || path[0] == '~' ||
        (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':');
}

static char *first_known_hosts_file(const char *value)
{
    if (value == NULL) return NULL;
    char *files = cli_copy(value);
    while (*files == ' ' || *files == '\t') files++;
    if (*files == '"' || *files == '\'') {
        char quote = *files++;
        char *end = strchr(files, quote);
        if (end == NULL) return NULL;
        *end = '\0';
        return files;
    }
    char *whole_path = cli_expand_home(files);
    struct stat info;
    if (whole_path != NULL && stat(whole_path, &info) == 0) return files;
    bool whitespace = false;
    for (char *p = files; *p; p++) {
        if (*p != ' ' && *p != '\t') continue;
        whitespace = true;
        char *next = p;
        while (*next == ' ' || *next == '\t') next++;
        if (is_rooted_path(next)) { *p = '\0'; return files; }
    }
    if (whitespace && !is_rooted_path(files)) return NULL;
    return files;
}

static void *read_key(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) return NULL;
    void *data = NULL;
    if (fseek(file, 0, SEEK_END) == 0) {
        long size = ftell(file);
        if (size > 0 && size <= 16 * 1024 * 1024 && fseek(file, 0, SEEK_SET) == 0) {
            data = cli_allocate((size_t)size);
            if (fread(data, 1, (size_t)size, file) == (size_t)size) *length = (size_t)size;
            else { clear_secret(data, (size_t)size); data = NULL; }
        }
    }
    fclose(file);
    return data;
}

typedef struct LocalForward {
    struct LocalForward *next;
    char *host;
    int local_port;
    int remote_port;
    OuterSSHPortForward *port_forward;
} LocalForward;

static bool parse_forward(char *text, LocalForward *forward)
{
    char *separator = strchr(text, ':');
    if (!separator) return false;
    *separator++ = '\0';
    if (!parse_port(text, true, &forward->local_port)) return false;
    forward->host = separator;
    if (*separator == '[') {
        forward->host = ++separator;
        separator = strchr(separator, ']');
        if (!separator || separator[1] != ':') return false;
        *separator = '\0';
        separator += 2;
    } else {
        separator = strchr(separator, ':');
        if (!separator) return false;
        *separator++ = '\0';
    }
    if (!*forward->host || strlen(forward->host) > 253) return false;
    for (const char *p = forward->host; *p; p++) {
        if ((unsigned char)*p <= 32 || *p == '[' || *p == ']') return false;
    }
    return parse_port(separator, false, &forward->remote_port);
}

static int invalid_arguments(void)
{
    fprintf(stderr, "outerssh: invalid arguments.\n");
    usage(stderr);
    return 2;
}

/* How many passwords to prompt for, following the resolved OpenSSH
 * configuration. Zero when batch mode or the configuration rules out password
 * and keyboard-interactive authentication. */
static int password_prompts(Configuration *configuration, bool batch)
{
    if (batch) return 0;
    if (equals(configuration_value(configuration, "passwordauthentication"), "no") &&
        equals(configuration_value(configuration, "kbdinteractiveauthentication"), "no")) return 0;
    int prompts = 3;
    const char *value = configuration_value(configuration, "numberofpasswordprompts");
    if (value != NULL && !parse_port(value, true, &prompts)) prompts = 3;
    return prompts;
}

/* Creates a pool and connects its first session. On failure, destroys the pool
 * and leaves authentication_failed set when the server rejected the
 * credentials. */
static OuterSSHSessionPool *start_pool(OuterSSHEventQueue *event_queue,
    const OuterSSHSessionPoolConfiguration *configuration, HostTrust *trust, Completion *completion)
{
    OuterSSHError error = {0};
    completion->authentication_failed = false;
    OuterSSHSessionPool *pool = outerssh_session_pool_create(event_queue, configuration, &error);
    if (pool == NULL) { print_error(error); return NULL; }
    trust_pool(pool, trust);
    submitted(completion, outerssh_session_pool_ensure_session(pool, tag(completion)));
    if (wait_for_operation(completion)) return pool;
    bool authentication_failed = completion->authentication_failed;
    submitted(completion, outerssh_session_pool_destroy(pool, tag(completion)));
    cli_semaphore_wait(completion->semaphore);
    forget_pool(pool);
    completion->authentication_failed = authentication_failed;
    return NULL;
}

/* Connects with the configured key or agent when try_configured is set, then,
 * like OpenSSH, prompts for up to prompts passwords while the server rejects
 * the credentials. The pool keeps the password for reconnecting. */
static OuterSSHSessionPool *connect_pool(OuterSSHEventQueue *event_queue,
    OuterSSHSessionPoolConfiguration configuration, bool try_configured, int prompts,
    HostTrust *trust, Completion *completion)
{
    if (try_configured) {
        OuterSSHSessionPool *pool = start_pool(event_queue, &configuration, trust, completion);
        if (pool != NULL || !completion->authentication_failed) return pool;
    }
    char prompt[1400];
    snprintf(prompt, sizeof(prompt), "%.*s@%.*s's password: ", (int)configuration.username_length,
        configuration.username, (int)configuration.hostname_length, configuration.hostname);
    for (int attempt = 0; attempt < prompts; attempt++) {
        if (attempt != 0) fputs("Permission denied, please try again.\n", stderr);
        char password[4096] = {0};
        if (!cli_prompt(prompt, password, sizeof(password), false)) {
            clear_secret(password, sizeof(password));
            fputs("outerssh: unable to read the SSH password.\n", stderr);
            return NULL;
        }
        configuration.authentication = (OuterSSHSessionAuthentication){
            .kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD,
            .password = password, .password_length = strlen(password)};
        OuterSSHSessionPool *pool = start_pool(event_queue, &configuration, trust, completion);
        clear_secret(password, sizeof(password));
        if (pool != NULL || !completion->authentication_failed) return pool;
    }
    fputs("outerssh: SSH authentication failed.\n", stderr);
    return NULL;
}

static bool connect_jump_hosts(const char *route, const char *config_file, const char *known_hosts,
    bool batch, bool ask_passphrase, const char *default_agent, unsigned depth, OuterSSHEventQueue *event_queue,
    OuterSSHSessionPool **pools, size_t *pool_count, Completion *completion)
{
    if (text_length(route) == 0 || equals(route, "none")) return true;
    if (depth >= 16) { fputs("outerssh: cyclic SSH route or more than 16 hops.\n", stderr); return false; }
    char *cursor = cli_copy(route);
    while (cursor && *cursor) {
        if (*pool_count >= 16) { fputs("outerssh: SSH route exceeds 16 hops.\n", stderr); return false; }
        char *next = strchr(cursor, ',');
        if (next) *next++ = '\0';
        if (!*cursor || cursor[0] == '-' || strpbrk(cursor, " \t\r\n%")) return false;
        char *destination = cursor;
        if (strncmp(cursor, "ssh://", 6) != 0 && strchr(cursor, ':')) {
            destination = cli_allocate(strlen(cursor) + 7);
            snprintf(destination, strlen(cursor) + 7, "ssh://%s", cursor);
        }
        char *arguments[8] = {"ssh", "-G", "-T"}; size_t count = 3;
        if (config_file) { arguments[count++] = "-F"; arguments[count++] = (char *)config_file; }
        arguments[count++] = "--"; arguments[count++] = destination;
        Configuration *configuration = resolve_configuration(arguments);
        if (!configuration) return false;
        const char *command = configuration_value(configuration, "proxycommand");
        if (text_length(command) && !equals(command, "none")) {
            fputs("outerssh: ProxyCommand is not supported; use ProxyJump.\n", stderr); return false;
        }
        char *host = configuration_value(configuration, "hostname"), *user = configuration_value(configuration, "user");
        int port = 0;
        if (!text_length(host) || !text_length(user) || !configuration_value(configuration, "port") ||
            !parse_port(configuration_value(configuration, "port"), false, &port) || *pool_count >= 16) return false;
        const char *original_gateway = configuration_value(configuration, "host");
        if (!text_length(original_gateway)) original_gateway = host;
        char *nested = configuration_value(configuration, "proxyjump");
        if (nested) {
            nested = expand_identity_path(nested, host, original_gateway, user, port);
            if (!nested) { fputs("outerssh: invalid ProxyJump token.\n", stderr); return false; }
        }
        if (*pool_count == 0 && !connect_jump_hosts(nested, config_file, known_hosts,
            batch, ask_passphrase, default_agent, depth + 1, event_queue, pools, pool_count, completion)) return false;
        char *identity = NULL;
        for (Configuration *entry = configuration; entry; entry = entry->next) {
            if (!equals(entry->name, "identityfile") || equals(entry->value, "none")) continue;
            char *path = expand_identity_path(entry->value, host, original_gateway, user, port);
            struct stat info;
            if (path && stat(path, &info) == 0) { identity = path; break; }
        }
        const char *agent = configuration_value(configuration, "identityagent");
        if (!agent || equals(agent, "SSH_AUTH_SOCK")) agent = default_agent;
        else if (*agent == '$') agent = getenv(agent + 1);
#ifdef _WIN32
        if (!agent) agent = "\\\\.\\pipe\\openssh-ssh-agent";
#endif
        if (equals(agent, "none") || equals(configuration_value(configuration, "identitiesonly"), "yes")) agent = NULL;
        bool try_configured = identity || agent;
        int prompts = password_prompts(configuration, batch);
        if (!try_configured && prompts == 0) {
            fprintf(stderr, "outerssh: no identity, SSH agent, or password authentication is available for %s.\n", host);
            return false;
        }
        char secret[4096] = {0};
        if (identity && ask_passphrase) {
            char prompt[1400]; snprintf(prompt, sizeof(prompt), "%s@%s key passphrase: ", user, host);
            if (batch || !cli_prompt(prompt, secret, sizeof(secret), false)) return false;
        }
        size_t key_length = 0;
        void *key = identity ? read_key(identity, &key_length) : NULL;
        if (identity && !key) { clear_secret(secret, sizeof(secret)); return false; }
        char *trust_path = known_hosts ? cli_copy(known_hosts) : first_known_hosts_file(configuration_value(configuration, "userknownhostsfile"));
        trust_path = trust_path ? expand_identity_path(trust_path, host, original_gateway, user, port) : NULL;
        if (!text_length(trust_path) || equals(trust_path, "none")) {
            fputs("outerssh: cannot resolve the gateway known_hosts file.\n", stderr); return false;
        }
        HostTrust *trust = cli_allocate(sizeof(*trust));
        char *alias = configuration_value(configuration, "hostkeyalias");
        *trust = (HostTrust){.hostname = alias ? alias : host, .port = alias ? 22 : port,
            .path = trust_path, .batch = batch};
        OuterSSHSessionPoolConfiguration pool_configuration = {
            .jump_host = *pool_count ? pools[*pool_count - 1] : NULL,
            .hostname = host, .hostname_length = strlen(host), .username = user, .username_length = strlen(user), .port = port,
            .authentication = {.kind = identity ? OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY : OUTERSSH_SESSION_AUTHENTICATION_AGENT,
                .private_key = key, .private_key_length = key_length,
                .passphrase = identity && ask_passphrase ? secret : NULL, .passphrase_length = identity && ask_passphrase ? strlen(secret) : 0},
            .ssh_agent_socket_path = agent, .ssh_agent_socket_path_length = text_length(agent),
        };
        OuterSSHSessionPool *pool = connect_pool(event_queue, pool_configuration, try_configured, prompts,
            trust, completion);
        clear_secret(secret, sizeof(secret)); clear_secret(key, key_length);
        if (!pool) return false;
        pools[(*pool_count)++] = pool;
        if (next && !*next) return false;
        cursor = next;
    }
    return true;
}

static int run(int argc, char **argv)
{
    int local_port = -1, ssh_port = 0, http_port = -1;
    LocalForward *forwards = NULL;
    char *user = NULL, *identity = NULL, *proxy_user = NULL, *proxy_password_variable = NULL, *config_file = NULL;
    char *known_hosts = NULL, *destination = NULL, *jump_hosts = NULL;
    bool ask_passphrase = false, use_password = false, batch = false, rewrite_http = false;
    bool options_done = false;
    for (int index = 1; index < argc; index++) {
        const char *argument = argv[index];
        if (!options_done && strcmp(argument, "--") == 0) { options_done = true; continue; }
        if (options_done || argument[0] != '-' || argument[1] == '\0') {
            if (destination != NULL) return invalid_arguments();
            destination = cli_copy(argument);
            continue;
        }
        if (equals(argument, "--help") || equals(argument, "-h")) { usage(stdout); return EXIT_SUCCESS; }
        if (equals(argument, "--version")) { printf("outerssh %s\n", OUTERSSH_CLI_VERSION); return EXIT_SUCCESS; }
        if (equals(argument, "--ask-passphrase")) { ask_passphrase = true; continue; }
        if (equals(argument, "--password")) { use_password = true; continue; }
        if (equals(argument, "--batch")) { batch = true; continue; }
        if (equals(argument, "--rewrite-http")) { rewrite_http = true; continue; }
        char *option = cli_copy(argument);
        char *value = NULL;
        if (option[1] == '-') {
            value = strchr(option, '=');
            if (value != NULL) *value++ = '\0';
        } else if (option[2]) {
            value = cli_copy(option + 2);
            option[2] = '\0';
        }
        if (value == NULL) {
            if (++index == argc) return invalid_arguments();
            value = argv[index];
        }
        if (equals(option, "-D")) { if (!parse_port(value, true, &local_port)) return invalid_arguments(); }
        else if (equals(option, "-L")) {
            LocalForward parsed = {0};
            if (!parse_forward(cli_copy(value), &parsed)) return invalid_arguments();
            LocalForward *forward = malloc(sizeof(*forward));
            if (!forward) return EXIT_FAILURE;
            *forward = parsed;
            forward->next = forwards;
            forwards = forward;
        }
        else if (equals(option, "-J")) {
            if (jump_hosts) {
                fputs("outerssh: only a single -J option is permitted; use commas to separate jump hosts.\n", stderr);
                return 2;
            }
            if (!*value) return invalid_arguments();
            jump_hosts = value;
        }
        else if (equals(option, "-p")) { if (!parse_port(value, false, &ssh_port)) return invalid_arguments(); }
        else if (equals(option, "--http-proxy")) { if (!parse_port(value, true, &http_port)) return invalid_arguments(); }
        else if (equals(option, "-l")) user = value;
        else if (equals(option, "-i")) { identity = cli_expand_home(value); if (!identity) return invalid_arguments(); }
        else if (equals(option, "-F")) { config_file = cli_expand_home(value); if (!config_file) return invalid_arguments(); }
        else if (equals(option, "--known-hosts")) { known_hosts = cli_expand_home(value); if (!known_hosts) return invalid_arguments(); }
        else if (equals(option, "--proxy-user")) proxy_user = value;
        else if (equals(option, "--proxy-password-env")) proxy_password_variable = value;
        else return invalid_arguments();
    }
    if (rewrite_http && http_port < 0 && local_port < 0) {
        fprintf(stderr, "outerssh: --rewrite-http requires -D port or --http-proxy port.\n");
        return invalid_arguments();
    }
    if ((local_port < 0 && http_port < 0 && forwards == NULL) || destination == NULL || (use_password && (identity != NULL || ask_passphrase)) ||
        (proxy_password_variable != NULL && proxy_user == NULL) ||
        (proxy_user != NULL && (strlen(proxy_user) == 0 || strlen(proxy_user) > 255)) ||
        (batch && (use_password || ask_passphrase || (proxy_user != NULL && proxy_password_variable == NULL)))) return invalid_arguments();
    char *host = destination;
    char *separator = strrchr(host, '@');
    if (separator != NULL) {
        if (user != NULL) return invalid_arguments();
        *separator = '\0'; user = host; host = separator + 1;
    }
    size_t host_length = strlen(host);
    if (host_length >= 2 && host[0] == '[' && host[host_length - 1] == ']') {
        host[host_length - 1] = '\0'; host++;
    }
    if (host[0] == '\0' || (user != NULL && user[0] == '\0') ||
        (known_hosts != NULL && known_hosts[0] == '\0')) return invalid_arguments();
    char *original_host = host;
    bool explicit_identity = identity != NULL;
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%d", ssh_port);
    char *config_arguments[18] = {"ssh", "-G", "-T"};
    size_t count = 3;
    if (config_file != NULL) { config_arguments[count++] = "-F"; config_arguments[count++] = config_file; }
    if (ssh_port != 0) { config_arguments[count++] = "-p"; config_arguments[count++] = port_text; }
    if (user != NULL) { config_arguments[count++] = "-l"; config_arguments[count++] = user; }
    if (identity != NULL) { config_arguments[count++] = "-i"; config_arguments[count++] = identity; }
    if (jump_hosts) { config_arguments[count++] = "-J"; config_arguments[count++] = jump_hosts; }
    config_arguments[count++] = "--"; config_arguments[count++] = host;
    Configuration *configuration = resolve_configuration(config_arguments);
    if (configuration == NULL) return EXIT_FAILURE;
    host = configuration_value(configuration, "hostname");
    user = configuration_value(configuration, "user");
    char *configured_port = configuration_value(configuration, "port");
    if (text_length(host) == 0 || text_length(user) == 0 || configured_port == NULL ||
        !parse_port(configured_port, false, &ssh_port)) {
        fprintf(stderr, "outerssh: ssh -G did not return a valid hostname, user, and port.\n");
        return EXIT_FAILURE;
    }
    const char *unsupported[] = {"proxycommand"};
    for (size_t index = 0; index < sizeof(unsupported) / sizeof(*unsupported); index++) {
        const char *value = configuration_value(configuration, unsupported[index]);
        if (text_length(value) != 0 && !equals(value, "none")) {
            fprintf(stderr, "outerssh: %s is configured for %s but is not supported by OuterSSH.\n", unsupported[index], original_host);
            return EXIT_FAILURE;
        }
    }
    jump_hosts = configuration_value(configuration, "proxyjump");
    if (jump_hosts) {
        jump_hosts = expand_identity_path(jump_hosts, host, original_host, user, ssh_port);
        if (!jump_hosts) { fputs("outerssh: invalid ProxyJump token.\n", stderr); return EXIT_FAILURE; }
    }
    if (equals(configuration_value(configuration, "batchmode"), "yes")) batch = true;
    if (identity == NULL && !use_password) {
        for (Configuration *entry = configuration; entry != NULL; entry = entry->next) {
            if (!equals(entry->name, "identityfile") || equals(entry->value, "none")) continue;
            char *expanded = expand_identity_path(entry->value, host, original_host, user, ssh_port);
            if (expanded == NULL) {
                fprintf(stderr, "outerssh: cannot expand configured identity path: %s\n", entry->value);
                return EXIT_FAILURE;
            }
            struct stat info;
            if (stat(expanded, &info) == 0) { identity = expanded; break; }
        }
    }
    if (ask_passphrase && identity == NULL) {
        fprintf(stderr, "outerssh: no private key was found for --ask-passphrase.\n");
        return EXIT_FAILURE;
    }
    if (batch && (use_password || ask_passphrase || (proxy_user != NULL && proxy_password_variable == NULL))) {
        fprintf(stderr, "outerssh: batch mode does not allow credential prompts.\n");
        return EXIT_FAILURE;
    }
    const char *known_hosts_override = known_hosts;
    if (known_hosts == NULL) {
        known_hosts = first_known_hosts_file(configuration_value(configuration, "userknownhostsfile"));
        if (text_length(known_hosts) == 0 || equals(known_hosts, "none")) {
            fprintf(stderr, "outerssh: cannot resolve UserKnownHostsFile; supply --known-hosts for ambiguous paths.\n");
            return EXIT_FAILURE;
        }
    }
    known_hosts = cli_expand_home(known_hosts);
    if (known_hosts == NULL) { fputs("outerssh: cannot expand known_hosts path.\n", stderr); return EXIT_FAILURE; }
    char *agent_path = configuration_value(configuration, "identityagent");
    if (agent_path == NULL || equals(agent_path, "SSH_AUTH_SOCK")) agent_path = getenv("SSH_AUTH_SOCK");
    else if (agent_path[0] == '$') agent_path = getenv(agent_path + 1);
#ifdef _WIN32
    if (agent_path == NULL) agent_path = "\\\\.\\pipe\\openssh-ssh-agent";
#endif
    bool disable_agent = explicit_identity || equals(agent_path, "none") ||
        equals(configuration_value(configuration, "identitiesonly"), "yes");
    if (disable_agent) agent_path = NULL;
    const char *agent = text_length(agent_path) == 0 ? NULL : agent_path;
    const char *default_agent = cli_copy(getenv("SSH_AUTH_SOCK"));
    if (agent == NULL && !cli_disable_agent()) {
        perror("outerssh: unable to disable SSH agent");
        return EXIT_FAILURE;
    }
    bool try_configured = !use_password && (identity != NULL || agent != NULL);
    int prompts = password_prompts(configuration, batch);
    if (!try_configured && prompts == 0) {
        fprintf(stderr, "outerssh: no identity, SSH agent, or password authentication is available; supply -i.\n");
        return EXIT_FAILURE;
    }
    char *host_key_alias = configuration_value(configuration, "hostkeyalias");
    if (!cli_prepare_signals()) { fputs("outerssh: unable to install signal handlers.\n", stderr); return EXIT_FAILURE; }
    char secret[4096] = {0}, proxy_password[256] = {0};
    if (ask_passphrase && !cli_prompt("Key passphrase: ", secret, sizeof(secret), false)) {
        fprintf(stderr, "outerssh: unable to read SSH credentials.\n");
        clear_secret(secret, sizeof(secret));
        return EXIT_FAILURE;
    }
    if (proxy_user != NULL) {
        if (proxy_password_variable != NULL) {
            const char *value = getenv(proxy_password_variable);
            if (value == NULL || strlen(value) == 0 || strlen(value) > 255) {
                fprintf(stderr, "outerssh: proxy password environment variable must contain 1–255 bytes.\n");
                clear_secret(secret, sizeof(secret));
                return EXIT_FAILURE;
            }
            memcpy(proxy_password, value, strlen(value) + 1);
        } else if (!cli_prompt("Proxy password: ", proxy_password, sizeof(proxy_password), false) ||
                proxy_password[0] == '\0') {
            fprintf(stderr, "outerssh: unable to read a nonempty proxy password.\n");
            clear_secret(proxy_password, sizeof(proxy_password));
            clear_secret(secret, sizeof(secret));
            return EXIT_FAILURE;
        }
    }
    size_t key_length = 0;
    void *key = identity == NULL ? NULL : read_key(identity, &key_length);
    if (identity != NULL && key == NULL) {
        fprintf(stderr, "outerssh: cannot read private key (missing, empty, or too large).\n");
        clear_secret(secret, sizeof(secret));
        clear_secret(proxy_password, sizeof(proxy_password));
        return EXIT_FAILURE;
    }
    HostTrust trust = {.hostname = host_key_alias == NULL ? host : host_key_alias,
        .port = host_key_alias == NULL ? ssh_port : 22, .path = known_hosts, .batch = batch};
    OuterSSHSessionPoolConfiguration pool_configuration = {
        .hostname = host, .hostname_length = text_length(host),
        .username = user, .username_length = text_length(user),
        .port = ssh_port,
        .authentication = {.kind = identity == NULL ? OUTERSSH_SESSION_AUTHENTICATION_AGENT
                : OUTERSSH_SESSION_AUTHENTICATION_PRIVATE_KEY,
            .private_key = key, .private_key_length = key_length,
            .passphrase = ask_passphrase ? secret : NULL, .passphrase_length = ask_passphrase ? strlen(secret) : 0},
        .ssh_agent_socket_path = agent,
        .ssh_agent_socket_path_length = agent == NULL ? 0 : strlen(agent),
    };
    OuterSSHProxyCredentials credentials = {.username = proxy_user,
        .username_length = text_length(proxy_user),
        .password = proxy_password, .password_length = strlen(proxy_password)};
    OuterSSHSOCKSProxyServerConfiguration proxy_configuration = {
        .credentials = proxy_user == NULL ? NULL : &credentials,
        .authentication = proxy_user == NULL ? OUTERSSH_PROXY_AUTHENTICATION_NONE : OUTERSSH_PROXY_AUTHENTICATION_PASSWORD,
        .rewrite_loopback_addresses = rewrite_http
    };
    Completion completion = {.semaphore = cli_semaphore_create()};
    if (completion.semaphore == NULL) {
        clear_secret(secret, sizeof(secret));
        clear_secret(proxy_password, sizeof(proxy_password));
        clear_secret(key, key_length);
        fputs("outerssh: unable to create completion semaphore.\n", stderr);
        return EXIT_FAILURE;
    }
    OuterSSHError error = {0};
    OuterSSHEventQueue *event_queue = start_events();
    OuterSSHSessionPool *jump_pools[16] = {0}; size_t jump_count = 0;
    bool route_ready = event_queue != NULL && connect_jump_hosts(jump_hosts, config_file, known_hosts_override,
        batch, ask_passphrase, default_agent, 0, event_queue, jump_pools, &jump_count, &completion);
    pool_configuration.jump_host = jump_count ? jump_pools[jump_count - 1] : NULL;
    OuterSSHSessionPool *pool = route_ready ? connect_pool(event_queue, pool_configuration, try_configured, prompts,
        &trust, &completion) : NULL;
    clear_secret(secret, sizeof(secret));
    if (key_length != 0) clear_secret(key, key_length);
    OuterSSHSOCKSProxyServer *server = pool == NULL || local_port < 0 ? NULL : outerssh_socks_proxy_server_create(pool, &proxy_configuration, &error);
    OuterSSHHTTPProxyServer *http_server = NULL;
    int status = EXIT_FAILURE;
    if (pool == NULL) goto cleanup;
    if (local_port >= 0 && server == NULL) {
        if (error.domain != OUTERSSH_ERROR_NONE) print_error(error);
        else fprintf(stderr, "outerssh: unable to allocate proxy resources.\n");
        goto cleanup;
    }
    int socks_port = -1;
    if (server != NULL) {
        submitted(&completion, outerssh_socks_proxy_server_start(server, local_port, tag(&completion)));
        if (!wait_for_operation(&completion)) goto cleanup;
        socks_port = completion.port;
    }
    if (http_port >= 0) {
        OuterSSHHTTPProxyServerConfiguration http_configuration = {
            .authentication = proxy_user == NULL ? OUTERSSH_PROXY_AUTHENTICATION_NONE : OUTERSSH_PROXY_AUTHENTICATION_PASSWORD,
            .credentials = proxy_user == NULL ? NULL : &credentials,
            .rewrite_loopback_addresses = rewrite_http
        };
        http_server = outerssh_http_proxy_server_create(pool, &http_configuration, &error);
        if (http_server == NULL) { print_error(error); goto cleanup; }
        submitted(&completion, outerssh_http_proxy_server_start(http_server, http_port, tag(&completion)));
        if (!wait_for_operation(&completion)) goto cleanup;
        fprintf(stderr, "HTTP proxy listening on 127.0.0.1:%d (HTTP rewriting %s)\n",
            completion.port, rewrite_http ? "enabled" : "disabled");
    }
    for (LocalForward *forward = forwards; forward; forward = forward->next) {
        forward->port_forward = outerssh_port_forward_create(pool,
            forward->host, strlen(forward->host), (uint16_t)forward->remote_port, &error);
        if (!forward->port_forward) { print_error(error); goto cleanup; }
        submitted(&completion, outerssh_port_forward_start(forward->port_forward, forward->local_port, tag(&completion)));
        if (!wait_for_operation(&completion)) goto cleanup;
        fprintf(stderr, "Forward listening on 127.0.0.1:%d -> [%s]:%d via SSH\n",
            completion.port, forward->host, forward->remote_port);
    }
    clear_secret(proxy_password, sizeof(proxy_password));
    if (socks_port >= 0) fprintf(stderr, "SOCKS5 listening on 127.0.0.1:%d via %s@%s:%d (%s; %s)\n",
        socks_port, user, host, ssh_port, proxy_user == NULL ? "no proxy authentication" : "username/password required",
        rewrite_http ? "HTTP rewriting enabled" : "raw TCP forwarding");
    cli_wait_for_signal();
    status = EXIT_SUCCESS;
cleanup:
    while (forwards) {
        LocalForward *forward = forwards;
        forwards = forward->next;
        if (forward->port_forward) {
            submitted(&completion, outerssh_port_forward_destroy(forward->port_forward, tag(&completion)));
            cli_semaphore_wait(completion.semaphore);
        }
        free(forward);
    }
    clear_secret(proxy_password, sizeof(proxy_password));
    if (http_server != NULL) {
        submitted(&completion, outerssh_http_proxy_server_destroy(http_server, tag(&completion)));
        cli_semaphore_wait(completion.semaphore);
    }
    if (server != NULL) submitted(&completion, outerssh_socks_proxy_server_destroy(server, tag(&completion)));
    if (pool != NULL) submitted(&completion, outerssh_session_pool_destroy(pool, tag(&completion)));
    if (server != NULL) cli_semaphore_wait(completion.semaphore);
    if (pool != NULL) cli_semaphore_wait(completion.semaphore);
    while (jump_count) {
        submitted(&completion, outerssh_session_pool_destroy(jump_pools[--jump_count], tag(&completion)));
        cli_semaphore_wait(completion.semaphore);
    }
    if (event_queue != NULL) stop_events();
    cli_semaphore_destroy(completion.semaphore);
    return status;
}

int main(int argc, char **argv)
{
    int status = run(argc, argv);
    cli_free_allocations();
    return status;
}
