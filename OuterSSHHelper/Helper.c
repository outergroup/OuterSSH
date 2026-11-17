#include "../Common/LaunchdSocket.h"
#include "../OuterSSH/HelperProtocol.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "EndpointNamesWatch.h"
#include "OuterSSHHelper.h"
#include "../OuterSSH/include/OuterSSH/SSHEndpointNames.h"
#include "../OuterSSH/SSHEndpointRecord.h"

#define OSB_MAGIC 0x3142524fu
#define OSB_VERSION 1u
#define OSB_MAX_PAYLOAD (1024u * 1024u)
#define OSB_CHUNK 65536u
#define OSB_KEEPALIVE_TIMEOUT_MS 60000u
#define OSB_POLL_INTERVAL_MS 1000u
#define OSB_SOCKET_MISSING_DEBOUNCE_MS 3000u
#define OSB_ALLOWLIST_MAX_LINE 4096u

#ifdef __APPLE__
#define OSB_USER_ALLOWLIST_SUFFIX "/Library/Application Support/org.outerssh/http-unix.allow"
#define OSB_SYSTEM_ALLOWLIST "/Library/Application Support/org.outerssh/http-unix.allow"
#define OSB_SYSTEM_RUNTIME_DIR "/var/run"
#else
#define OSB_USER_ALLOWLIST_SUFFIX "/.config/outerssh/http-unix.allow"
#define OSB_SYSTEM_ALLOWLIST "/etc/outerssh/http-unix.allow"
#define OSB_SYSTEM_RUNTIME_DIR "/run"
#endif

static bool is_service_address(const char *path, bool *system, const char **label) {
#ifdef __APPLE__
    return outer_launchd_address(path, system, label);
#else
    (void)path; (void)system; (void)label;
    return false;
#endif
}

static bool has_service_prefix(const char *path) {
#ifdef __APPLE__
    return path && strncmp(path, OUTER_LAUNCHD_PREFIX, strlen(OUTER_LAUNCHD_PREFIX)) == 0;
#else
    (void)path;
    return false;
#endif
}

static int copy_format(char *out, size_t out_len, const char *format, const char *value) {
    int written = snprintf(out, out_len, format, value);
    return written >= 0 && (size_t)written < out_len ? 0 : -1;
}

enum {
    OSB_HELLO = 1,
    OSB_OPEN = 2,
    OSB_OPEN_OK = 3,
    OSB_OPEN_ERROR = 4,
    OSB_DATA = 5,
    OSB_EOF = 6,
    OSB_CLOSE = 7,
    OSB_PING = 8,
    OSB_PONG = 9,
    OSB_SOCKET_STATE = 10,
    OSB_AUTHORIZE = 11,
    OSB_RESULT = 12,
    OSB_WATCH = 13,
    OSB_UNWATCH = 14,
    OSB_PREPARED = 15,
    OSB_ENDPOINT_NAMES = 16,
    OSB_GET_ENDPOINT_NAMES = 17,
    OSB_ENDPOINT_NAMES_CHANGED = 18,
    OSB_STORE_ENDPOINT_ICON = 19,
    OSB_GET_ENDPOINT_ICON = 20,
    OSB_ENDPOINT_ICON = 21,
    OSB_APP_REQUEST = 22,
    OSB_APP_RESPONSE = 23,
    OSB_OPEN_NOT_LISTENING = 24
};

static OuterSSHHelperRequestHandler request_handler;

struct frame {
    uint16_t type;
    uint32_t stream_id;
    uint32_t length;
    unsigned char *payload;
};

struct stream {
    uint32_t id;
    int fd;
};

enum socket_scope {
    SOCKET_SCOPE_USER,
    SOCKET_SCOPE_SYSTEM
};

static uint16_t rd16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
}

static void wr32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;
        p += n;
        len -= (size_t)n;
    }
    return 1;
}

static int send_frame(uint16_t type, uint32_t stream_id, const void *payload, uint32_t length) {
    unsigned char header[16];
    wr32(header, OSB_MAGIC);
    wr16(header + 4, OSB_VERSION);
    wr16(header + 6, type);
    wr32(header + 8, stream_id);
    wr32(header + 12, length);
    if (write_all(STDOUT_FILENO, header, sizeof(header)) < 0) return -1;
    if (length > 0 && write_all(STDOUT_FILENO, payload, length) < 0) return -1;
    return 0;
}

static int read_frame(struct frame *f) {
    unsigned char header[16];
    int r = read_all(STDIN_FILENO, header, sizeof(header));
    if (r <= 0) return r;
    if (rd32(header) != OSB_MAGIC || rd16(header + 4) != OSB_VERSION) return -1;
    f->type = rd16(header + 6);
    f->stream_id = rd32(header + 8);
    f->length = rd32(header + 12);
    f->payload = NULL;
    if (f->length > OSB_MAX_PAYLOAD) return -1;
    if (f->length > 0) {
        f->payload = (unsigned char *)malloc(f->length);
        if (!f->payload) return -1;
        r = read_all(STDIN_FILENO, f->payload, f->length);
        if (r <= 0) {
            free(f->payload);
            f->payload = NULL;
            return r;
        }
    }
    return 1;
}

static char *trim_line(char *line) {
    while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n') line++;
    char *end = line + strlen(line);
    while (end > line && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return line;
}

static int path_has_prefix_component(const char *path, const char *prefix) {
    size_t n = strlen(prefix);
    if (strncmp(path, prefix, n) != 0) return 0;
    return path[n] == '\0' || path[n] == '/';
}

static int current_home_directory(char *out, size_t out_len) {
    const char *home = getenv("HOME");
    if (home && home[0]) {
        return copy_format(out, out_len, "%s", home);
    }
    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_dir && pw->pw_dir[0]) {
        return copy_format(out, out_len, "%s", pw->pw_dir);
    }
    return -1;
}

static int additional_allowlist_argc;
static char **additional_allowlist_argv;

static int additional_allowlist_path(const char *value, int system, char *out, size_t out_len) {
    if (value[0] == '/') return copy_format(out, out_len, "%s", value);
    if (system || value[0] != '%' || (value[1] != 'h' && value[1] != 'c') || value[2] != '/') return -1;
    char home[PATH_MAX];
    if (value[1] == 'c') {
        const char *xdg = getenv("XDG_CONFIG_HOME");
        if (xdg && xdg[0]) {
            int n = snprintf(out, out_len, "%s%s", xdg, value + 2);
            return n >= 0 && (size_t)n < out_len ? 0 : -1;
        }
    }
    if (current_home_directory(home, sizeof(home)) < 0) return -1;
    int n = snprintf(out, out_len, "%s%s%s", home, value[1] == 'c' ? "/.config" : "", value + 2);
    return n >= 0 && (size_t)n < out_len ? 0 : -1;
}

static int user_allowlist_path(char *out, size_t out_len) {
#ifndef __APPLE__
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0]) {
        return copy_format(out, out_len, "%s/outerssh/http-unix.allow", xdg);
    }
#endif
    char home[PATH_MAX];
    if (current_home_directory(home, sizeof(home)) < 0) return -1;
    return copy_format(out, out_len, "%s" OSB_USER_ALLOWLIST_SUFFIX, home);
}

static int user_runtime_dir(char *out, size_t out_len) {
#ifdef __APPLE__
    size_t required = confstr(_CS_DARWIN_USER_TEMP_DIR, NULL, 0);
    if (required > 0 && required < out_len && confstr(_CS_DARWIN_USER_TEMP_DIR, out, required) > 0 && out[0]) {
        size_t n = strlen(out);
        if (n > 1 && out[n - 1] == '/') out[n - 1] = '\0';
        return 0;
    }
    snprintf(out, out_len, "/tmp");
    return 0;
#else
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    if (runtime && runtime[0]) {
        snprintf(out, out_len, "%s", runtime);
        return 0;
    }
    snprintf(out, out_len, "/run/user/%ld", (long)getuid());
    return 0;
#endif
}

static int expand_allowlist_path(const char *value, char *out, size_t out_len) {
    char runtime[PATH_MAX];
    char uid[32];
    if (user_runtime_dir(runtime, sizeof(runtime)) < 0) return -1;
    snprintf(uid, sizeof(uid), "%ld", (long)getuid());

    size_t used = 0;
    for (const char *p = value; *p; p++) {
        const char *replacement = NULL;
        char literal[2] = {*p, '\0'};
        if (*p == '%' && p[1]) {
            p++;
            switch (*p) {
            case 't':
                replacement = runtime;
                break;
            case 'T':
                replacement = OSB_SYSTEM_RUNTIME_DIR;
                break;
            case 'u':
                replacement = uid;
                break;
            case '%':
                replacement = "%";
                break;
            default:
                return -1;
            }
        } else {
            replacement = literal;
        }
        size_t n = strlen(replacement);
        if (used + n >= out_len) return -1;
        memcpy(out + used, replacement, n);
        used += n;
    }
    out[used] = '\0';
    return 0;
}

static int allowlist_file_is_safe(const char *path, uid_t owner_uid) {
    struct stat st;
    if (lstat(path, &st) < 0) return 0;
    if (!S_ISREG(st.st_mode)) return 0;
    if (st.st_uid != owner_uid) return 0;
    if ((st.st_mode & 0022) != 0) return 0;
    return 1;
}

static int classify_socket(const char *path, const struct stat *st) {
#ifndef __APPLE__
    char user_run_prefix[64];
    snprintf(user_run_prefix, sizeof(user_run_prefix), "/run/user/%ld", (long)getuid());
    if (path_has_prefix_component(path, user_run_prefix) && st->st_uid == getuid()) {
        return SOCKET_SCOPE_USER;
    }
#else
    char runtime[PATH_MAX];
    if (user_runtime_dir(runtime, sizeof(runtime)) == 0 &&
        path_has_prefix_component(path, runtime) &&
        st->st_uid == getuid()) {
        return SOCKET_SCOPE_USER;
    }
#endif
    if (st->st_uid == getuid() && geteuid() != 0 && !path_has_prefix_component(path, OSB_SYSTEM_RUNTIME_DIR)) {
        return SOCKET_SCOPE_USER;
    }
    return SOCKET_SCOPE_SYSTEM;
}

static int allowlist_contains_socket(const char *allowlist_path,
                                     uid_t owner_uid,
                                     const char *socket_path,
                                     char *err,
                                     size_t err_len) {
    if (!allowlist_file_is_safe(allowlist_path, owner_uid)) {
        snprintf(err, err_len, "allowlist is missing or unsafe");
        return 0;
    }
    FILE *file = fopen(allowlist_path, "r");
    if (!file) {
        snprintf(err, err_len, "failed to read allowlist: %s", strerror(errno));
        return 0;
    }
    char line[OSB_ALLOWLIST_MAX_LINE];
    while (fgets(line, sizeof(line), file)) {
        char *trimmed = trim_line(line);
        if (!trimmed[0] || trimmed[0] == '#') continue;
        char *comment = strchr(trimmed, '#');
        if (comment) {
            *comment = '\0';
            trimmed = trim_line(trimmed);
            if (!trimmed[0]) continue;
        }
        char expanded[PATH_MAX];
        if (expand_allowlist_path(trimmed, expanded, sizeof(expanded)) < 0) continue;
        if (strcmp(expanded, socket_path) == 0) {
            fclose(file);
            if (err_len != 0) err[0] = '\0';
            return 1;
        }
    }
    fclose(file);
    snprintf(err, err_len, "socket is not on the allowlist");
    return 0;
}

static int socket_is_allowlisted(const char *path, int scope, char *err, size_t err_len) {
    int system = scope == SOCKET_SCOPE_SYSTEM;
    uid_t owner = system ? 0 : getuid();
    char allowlist[PATH_MAX];
    if (system) {
        if (allowlist_contains_socket(OSB_SYSTEM_ALLOWLIST, owner, path, err, err_len)) return 1;
    } else if (user_allowlist_path(allowlist, sizeof(allowlist)) == 0 &&
               allowlist_contains_socket(allowlist, owner, path, err, err_len)) {
        return 1;
    }
    for (int i = 0; i < additional_allowlist_argc; i += 2) {
        if (strcmp(additional_allowlist_argv[i], system ? "--system-allowlist" : "--user-allowlist") != 0) continue;
        if (additional_allowlist_path(additional_allowlist_argv[i + 1], system, allowlist, sizeof(allowlist)) == 0 &&
            allowlist_contains_socket(allowlist, owner, path, err, err_len)) return 1;
    }
    snprintf(err, err_len, "socket is not on a safe allowlist");
    return 0;
}

static char cached_service_address[256];
#ifdef __APPLE__
static char cached_service_socket[PATH_MAX];
#endif

static int resolve_service_socket(const char *path, char *resolved, size_t capacity, char *err, size_t err_len) {
    bool system;
    const char *label;
    if (!has_service_prefix(path)) {
        return copy_format(resolved, capacity, "%s", path);
    }
    if (!is_service_address(path, &system, &label)) {
        snprintf(err, err_len, "Invalid launchd service address");
        return -1;
    }
    if (!socket_is_allowlisted(path, system ? SOCKET_SCOPE_SYSTEM : SOCKET_SCOPE_USER, err, err_len)) return -1;
#ifdef __APPLE__
    struct stat socket_info;
    if (strcmp(cached_service_address, path) == 0 && lstat(cached_service_socket, &socket_info) == 0 &&
        S_ISSOCK(socket_info.st_mode) && socket_info.st_uid == (system ? 0 : getuid())) {
        return copy_format(resolved, capacity, "%s", cached_service_socket);
    }
    if (!outer_launchd_resolve(path, resolved, capacity, err, err_len)) return -1;
    snprintf(cached_service_address, sizeof(cached_service_address), "%s", path);
    snprintf(cached_service_socket, sizeof(cached_service_socket), "%s", resolved);
    return 0;
#else
    snprintf(err, err_len, "Launchd services require macOS");
    return -1;
#endif
}

static int validate_socket(const char *path, char *err, size_t err_len) {
    char resolved[PATH_MAX];
    bool system;
    const char *label;
    if (path && is_service_address(path, &system, &label)) {
        return resolve_service_socket(path, resolved, sizeof(resolved), err, err_len);
    }
    struct stat st;
    if (!path || path[0] != '/') {
        snprintf(err, err_len, "socket path must be absolute");
        return -1;
    }
    if (lstat(path, &st) < 0) {
        snprintf(err, err_len, "lstat failed: %s", strerror(errno));
        return -1;
    }
    if (!S_ISSOCK(st.st_mode)) {
        snprintf(err, err_len, "target is not a Unix socket");
        return -1;
    }
    int scope = classify_socket(path, &st);
    if (!socket_is_allowlisted(path, scope, err, err_len)) return -1;
    if (scope == SOCKET_SCOPE_SYSTEM && geteuid() != 0) {
        snprintf(err, err_len, "root/system socket requires socket bridge");
        return -1;
    }
    return 0;
}

static int authorize_socket_command(const char *path) {
    char err[512];
    if (validate_socket(path, err, sizeof(err)) < 0) {
        fprintf(stderr, "%s\n", err);
        return 3;
    }
    printf("allowed %s\n", path);
    return 0;
}

static void list_allowlist(const char *allowlist_path, uid_t owner_uid, const char *scope) {
    if (!allowlist_file_is_safe(allowlist_path, owner_uid)) return;
    FILE *file = fopen(allowlist_path, "r");
    if (!file) return;
    char line[OSB_ALLOWLIST_MAX_LINE];
    while (fgets(line, sizeof(line), file)) {
        char *trimmed = trim_line(line);
        if (!trimmed[0] || trimmed[0] == '#') continue;
        char *comment = strchr(trimmed, '#');
        if (comment) {
            *comment = '\0';
            trimmed = trim_line(trimmed);
            if (!trimmed[0]) continue;
        }
        char expanded[PATH_MAX];
        if (expand_allowlist_path(trimmed, expanded, sizeof(expanded)) < 0) continue;
        struct stat st;
        int available = lstat(expanded, &st) == 0 && S_ISSOCK(st.st_mode);
        printf("%s\t%s\t%s\n", scope, expanded, available ? "available" : "missing");
    }
    fclose(file);
}

static int list_command(void) {
    char user_path[PATH_MAX];
    if (user_allowlist_path(user_path, sizeof(user_path)) == 0) {
        list_allowlist(user_path, getuid(), "user");
    }
    list_allowlist(OSB_SYSTEM_ALLOWLIST, 0, "system");
    for (int i = 0; i < additional_allowlist_argc; i += 2) {
        int system = strcmp(additional_allowlist_argv[i], "--system-allowlist") == 0;
        char path[PATH_MAX];
        if (additional_allowlist_path(additional_allowlist_argv[i + 1], system, path, sizeof(path)) == 0)
            list_allowlist(path, system ? 0 : getuid(), system ? "system" : "user");
    }
    return 0;
}

/* Whether a socket path names nothing, so that nothing can be listening there. */
static bool socket_is_missing(const char *path) {
    struct stat st;
    return lstat(path, &st) < 0 && (errno == ENOENT || errno == ENOTDIR);
}

/* Sets *not_listening when the connection failed because nothing is listening:
 * the socket is missing or refuses connections. */
static int connect_socket_attempt(const char *path, char *err, size_t err_len, bool retry, bool *not_listening) {
    *not_listening = false;
    const char *service_address = path;
    bool is_service = strncmp(path, OUTER_LAUNCHD_PREFIX, strlen(OUTER_LAUNCHD_PREFIX)) == 0;
    char resolved[PATH_MAX];
    if (strncmp(path, OUTER_LAUNCHD_PREFIX, strlen(OUTER_LAUNCHD_PREFIX)) == 0) {
        if (resolve_service_socket(path, resolved, sizeof(resolved), err, err_len) < 0) return -1;
        path = resolved;
    } else if (validate_socket(path, err, err_len) < 0) {
        *not_listening = socket_is_missing(path);
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, err_len, "socket failed: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        snprintf(err, err_len, "socket path is too long");
        close(fd);
        return -1;
    }
    strcpy(addr.sun_path, path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int failure = errno;
        close(fd);
        if (is_service && retry && (failure == ECONNREFUSED || failure == ENOENT)) {
            cached_service_address[0] = '\0';
            return connect_socket_attempt(service_address, err, err_len, false, not_listening);
        }
        *not_listening = failure == ECONNREFUSED || failure == ENOENT;
        snprintf(err, err_len, "connect failed: %s", strerror(failure));
        return -1;
    }
    return fd;
}

static int find_stream(struct stream *streams, size_t count, uint32_t id) {
    for (size_t i = 0; i < count; i++) {
        if (streams[i].id == id) return (int)i;
    }
    return -1;
}

static void remove_stream(struct stream *streams, size_t *count, size_t index) {
    close(streams[index].fd);
    if (index + 1 < *count) {
        memmove(&streams[index], &streams[index + 1], (*count - index - 1) * sizeof(streams[0]));
    }
    (*count)--;
}

static int connect_socket(const char *path, char *err, size_t err_len, bool *not_listening) {
    return connect_socket_attempt(path, err, err_len, true, not_listening);
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) return 0;
    return ((uint64_t)ts.tv_sec * 1000u) + ((uint64_t)ts.tv_nsec / 1000000u);
}

enum {
    OSB_PREPARED_SESSION_OWNED = 0x40,
    OSB_PREPARED_ROOT_OWNED = 0x80
};

/* The service can authorize an absent path. Socket type and privilege are
 * checked again by each traffic bridge when opening a connection. */
static int authorize_path(const char *path, unsigned char *mode, char *err, size_t err_len) {
    bool system;
    const char *label;
    if (is_service_address(path, &system, &label)) {
        if (mode) *mode = system && geteuid() != 0 ? 2 : 1;
        return socket_is_allowlisted(path, system ? SOCKET_SCOPE_SYSTEM : SOCKET_SCOPE_USER, err, err_len) ? 0 : -1;
    }
    struct stat st = {0};
    st.st_uid = getuid();
    if (path[0] != '/') {
        snprintf(err, err_len, "socket path must be absolute");
        return -1;
    }
    int exists = lstat(path, &st) == 0;
    if (!exists && errno != ENOENT && errno != ENOTDIR) {
        snprintf(err, err_len, "lstat failed: %s", strerror(errno));
        return -1;
    }
    if (!exists) st.st_uid = getuid();
    if (exists && !S_ISSOCK(st.st_mode)) {
        snprintf(err, err_len, "target is not a Unix socket");
        return -1;
    }
    if (classify_socket(path, &st) == SOCKET_SCOPE_SYSTEM) {
        if (!socket_is_allowlisted(path, SOCKET_SCOPE_SYSTEM, err, err_len)) return -1;
        if (mode) *mode = geteuid() != 0 ? 2 : 0;
        return 0;
    }
    return socket_is_allowlisted(path, SOCKET_SCOPE_USER, err, err_len) ? 0 : -1;
}

/* Writes the owner flags and decimal uid that follow the connection mode in a
 * PREPARED reply. System services belong to root and user services to the
 * service's user. A socket that does not exist yet has no known owner. */
static size_t describe_owner(const char *path, unsigned char *reply, size_t capacity) {
    bool system;
    const char *label;
    uid_t owner;
    struct stat st;
    if (is_service_address(path, &system, &label)) {
        owner = system ? 0 : geteuid();
    } else if (lstat(path, &st) == 0) {
        owner = st.st_uid;
    } else {
        return 1;
    }
    if (owner == 0) reply[0] |= OSB_PREPARED_ROOT_OWNED;
    else if (owner == geteuid()) reply[0] |= OSB_PREPARED_SESSION_OWNED;
    int length = snprintf((char *)reply + 1, capacity - 1, "%lu", (unsigned long)owner);
    return length > 0 && (size_t)length < capacity - 1 ? (size_t)length + 1 : 1;
}

struct socket_watch {
    uint32_t id;
    char *path;
    unsigned char state; /* 0 absent, 1 present, 2 unknown */
    uint64_t missing_since_ms;
    uint64_t last_checked_ms;
    dev_t device;
    ino_t inode;
    struct timespec changed;
};

/* A socket's identity: a recreated socket can reuse the inode number, but not
 * its change time. */
static struct timespec status_change_time(const struct stat *st) {
#ifdef __APPLE__
    return st->st_ctimespec;
#else
    return st->st_ctim;
#endif
}

static int update_watch(struct socket_watch *watch) {
    if (has_service_prefix(watch->path)) {
        uint64_t now = monotonic_ms();
        if (watch->last_checked_ms && now - watch->last_checked_ms < 5000) return 0;
        watch->last_checked_ms = now;
    }
    char error[512];
    struct stat st;
    unsigned char state;
    bool replaced = false;
    if (authorize_path(watch->path, NULL, error, sizeof(error)) != 0) {
        state = 2;
    } else if (has_service_prefix(watch->path)) {
#ifdef __APPLE__
        bool system;
        const char *label;
        char target[256];
        if (!is_service_address(watch->path, &system, &label)) state = 2;
        else {
            if (system) snprintf(target, sizeof(target), "system/%s", label);
            else snprintf(target, sizeof(target), "gui/%u/%s", getuid(), label);
            char *arguments[] = {"launchctl", "print", target, NULL};
            state = outer_launchd_run(arguments) == 0 ? 1 : 0;
        }
#else
        state = 2;
#endif
    } else if (lstat(watch->path, &st) == 0) {
        state = S_ISSOCK(st.st_mode) ? 1 : 0;
        if (state == 1) {
            struct timespec changed = status_change_time(&st);
            replaced = watch->state == 1 && (st.st_dev != watch->device || st.st_ino != watch->inode ||
                changed.tv_sec != watch->changed.tv_sec || changed.tv_nsec != watch->changed.tv_nsec);
            watch->device = st.st_dev;
            watch->inode = st.st_ino;
            watch->changed = changed;
        }
    } else {
        state = errno == ENOENT || errno == ENOTDIR ? 0 : 2;
    }
    uint64_t now = monotonic_ms();
    if (state == 0 && watch->state == 1) {
        if (watch->missing_since_ms == 0) watch->missing_since_ms = now;
        if (now - watch->missing_since_ms < OSB_SOCKET_MISSING_DEBOUNCE_MS) return 0;
    } else {
        watch->missing_since_ms = 0;
    }
    if (state == watch->state && !replaced) return 0;
    watch->state = state;
    return send_frame(OSB_SOCKET_STATE, watch->id, &state, 1);
}

static int send_endpoint_names(uint32_t id) {
    unsigned char *bytes = NULL;
    size_t length = 0;
    if (!outersshpriv_endpoint_names_read_snapshot(&bytes, &length)) {
        const char error[] = "Could not read trusted endpoint registrations.";
        return send_frame(id ? OSB_RESULT : OSB_ENDPOINT_NAMES_CHANGED, id,
                          id ? error : NULL, id ? sizeof(error) - 1 : 0);
    }
    int result = send_frame(OSB_ENDPOINT_NAMES, id, bytes, (uint32_t)length);
    free(bytes);
    return result;
}

/* STORE carries an endpoint record line, a NUL and the PNG; GET carries the
 * line. GET replies with ENDPOINT_ICON, empty when there is no icon. */
static int handle_endpoint_icon(const struct frame *frame) {
    const char *error = NULL;
    const unsigned char *end = memchr(frame->payload, 0, frame->length);
    bool store = frame->type == OSB_STORE_ENDPOINT_ICON;
    size_t line_length = end ? (size_t)(end - frame->payload) : frame->length;
    char *line = store == (end != NULL) && line_length > 0 ? malloc(line_length + 1) : NULL;
    const char *transport, *address;
    uint16_t port;
    if (line) {
        memcpy(line, frame->payload, line_length);
        line[line_length] = 0;
    }
    if (!line || !outersshpriv_endpoint_record_parse(line, &transport, &address, &port)) {
        error = "Invalid endpoint.";
    } else if (store) {
        outerssh_endpoint_icon_store_local(transport, address, strlen(address), port,
            frame->payload + line_length + 1, frame->length - line_length - 1, &error);
    } else {
        unsigned char *png = NULL;
        size_t length = 0;
        if (outerssh_endpoint_icon_read_local(transport, address, strlen(address), port, &png, &length, &error)) {
            free(line);
            int result = send_frame(OSB_ENDPOINT_ICON, frame->stream_id, png, (uint32_t)length);
            free(png);
            return result;
        }
    }
    free(line);
    return send_frame(OSB_RESULT, frame->stream_id, error, error ? (uint32_t)strlen(error) : 0);
}

static int handle_app_request(const struct frame *frame) {
    char error[512] = "The OuterSSH helper does not support this request.";
    unsigned char *response = NULL;
    size_t length = 0;
    if (request_handler && request_handler(frame->payload, frame->length, &response, &length, error, sizeof(error))) {
        int result = length <= OSB_MAX_PAYLOAD ? send_frame(OSB_APP_RESPONSE, frame->stream_id, response, (uint32_t)length) : -1;
        free(response);
        return result;
    }
    error[sizeof(error) - 1] = 0;
    return send_frame(OSB_RESULT, frame->stream_id, error, (uint32_t)strlen(error));
}

static int service_command(void) {
    struct socket_watch watches[1024];
    size_t count = 0;
    int result = 0;
    uint64_t last_frame_ms = monotonic_ms();
    struct endpoint_names_watch names;
    if (endpoint_names_watch_open(&names) < 0) return 1;
    if (send_frame(OSB_HELLO, 0, NULL, 0) < 0 ||
        send_endpoint_names(0) < 0) {
        endpoint_names_watch_close(&names);
        return 1;
    }
    for (;;) {
        struct pollfd inputs[] = {{.fd = STDIN_FILENO, .events = POLLIN}, {.fd = names.fd, .events = POLLIN}};
        int ready = poll(inputs, 2, OSB_POLL_INTERVAL_MS);
        if (ready < 0) {
            if (errno == EINTR) continue;
            result = 1;
            break;
        }
        if (monotonic_ms() - last_frame_ms >= OSB_KEEPALIVE_TIMEOUT_MS) break;
        for (size_t i = 0; i < count; i++) {
            if (update_watch(&watches[i]) < 0) { result = 1; goto finished; }
        }
        if (inputs[1].revents && endpoint_names_watch_changed(&names)) {
            endpoint_names_watch_close(&names);
            if (endpoint_names_watch_open(&names) < 0 || send_endpoint_names(0) < 0) {
                result = 1;
                break;
            }
        }
        if (!inputs[0].revents) continue;
        struct frame frame;
        int read_result = read_frame(&frame);
        if (read_result <= 0) { result = read_result < 0; break; }
        last_frame_ms = monotonic_ms();
        char error[512] = {0};
        if (frame.type == OSB_PING) {
            result = send_frame(OSB_PONG, frame.stream_id, frame.payload, frame.length);
        } else if (frame.type == OSB_GET_ENDPOINT_NAMES && frame.stream_id && frame.length == 0) {
            result = send_endpoint_names(frame.stream_id);
        } else if ((frame.type == OSB_STORE_ENDPOINT_ICON || frame.type == OSB_GET_ENDPOINT_ICON) &&
                   frame.stream_id && frame.length > 0) {
            result = handle_endpoint_icon(&frame);
        } else if (frame.type == OSB_UNWATCH && frame.length == 0) {
            for (size_t i = 0; i < count; i++) {
                if (watches[i].id != frame.stream_id) continue;
                free(watches[i].path);
                watches[i] = watches[--count];
                break;
            }
        } else if ((frame.type == OSB_AUTHORIZE || frame.type == OSB_WATCH) &&
                   frame.stream_id != 0 && frame.length > 0 && frame.length < PATH_MAX &&
                   memchr(frame.payload, 0, frame.length) == NULL) {
            char path[PATH_MAX];
            memcpy(path, frame.payload, frame.length);
            path[frame.length] = 0;
            unsigned char mode = 0;
            if (authorize_path(path, &mode, error, sizeof(error)) == 0 && frame.type == OSB_WATCH) {
                if (count == 1024) {
                    snprintf(error, sizeof(error), "too many socket watches");
                } else {
                    char *copy = malloc(frame.length + 1);
                    if (copy == NULL) snprintf(error, sizeof(error), "could not allocate socket watch");
                    else {
                        memcpy(copy, path, frame.length + 1);
                        watches[count++] = (struct socket_watch){.id = frame.stream_id, .path = copy, .state = 255};
                    }
                }
            }
            if (frame.type == OSB_AUTHORIZE && error[0] == 0) {
                unsigned char reply[32] = {mode};
                size_t length = describe_owner(path, reply, sizeof(reply));
                result = send_frame(OSB_PREPARED, frame.stream_id, reply, (uint32_t)length);
            } else {
                result = send_frame(OSB_RESULT, frame.stream_id, error, (uint32_t)strlen(error));
            }
        } else if (frame.type == OSB_APP_REQUEST && frame.stream_id) {
            result = handle_app_request(&frame);
        } else if (frame.stream_id) {
            static const char unsupported[] = "The OuterSSH helper does not support this request.";
            result = send_frame(OSB_RESULT, frame.stream_id, unsupported, sizeof(unsupported) - 1);
        }
        free(frame.payload);
        if (result < 0) { result = 1; break; }
    }
finished:
    endpoint_names_watch_close(&names);
    for (size_t i = 0; i < count; i++) free(watches[i].path);
    return result;
}

#ifdef __linux__
static int descriptor_bridge(const char *path) {
    char error[512];
    if (validate_socket(path, error, sizeof(error)) < 0) {
        fprintf(stderr, "%s\n", error);
        return 2;
    }
    if (write_all(STDOUT_FILENO, "R", 1) < 0) return 1;
    unsigned char command;
    while (read_all(STDIN_FILENO, &command, 1) == 1) {
        if (command != 'O') return 2;
        alarm(10);
        bool not_listening;
        int fd = connect_socket(path, error, sizeof(error), &not_listening);
        alarm(0);
        unsigned char status = fd < 0 ? 1 : 0;
        struct iovec iov = {.iov_base = &status, .iov_len = 1};
        union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
        if (fd >= 0) {
            message.msg_control = control.bytes;
            message.msg_controllen = sizeof(control.bytes);
            struct cmsghdr *header = CMSG_FIRSTHDR(&message);
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(header), &fd, sizeof(fd));
        } else fprintf(stderr, "%s\n", error);
        ssize_t sent;
        do { sent = sendmsg(STDOUT_FILENO, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
        if (fd >= 0) close(fd);
        if (sent != 1) return 1;
    }
    return 0;
}
#endif

int outerssh_helper_main(int argc, char **argv, OuterSSHHelperRequestHandler handler) {
    const char *socket_path = NULL;
    request_handler = handler;
    signal(SIGPIPE, SIG_IGN);
    additional_allowlist_argv = argv + 1;
    while (argc > 1 && (strcmp(argv[1], "--user-allowlist") == 0 || strcmp(argv[1], "--system-allowlist") == 0)) {
        char path[PATH_MAX];
        int system = strcmp(argv[1], "--system-allowlist") == 0;
        if (argc < 3 || additional_allowlist_path(argv[2], system, path, sizeof(path)) < 0) {
            fprintf(stderr, "invalid additional allowlist path\n");
            return 2;
        }
        additional_allowlist_argc += 2;
        argc -= 2;
        argv += 2;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("outerssh-helper 1");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "list") == 0) {
        return list_command();
    }
    if (argc == 4 && strcmp(argv[1], "authorize") == 0 && strcmp(argv[2], "--socket") == 0) {
        return authorize_socket_command(argv[3]);
    }
    if (argc == 2 && strcmp(argv[1], "service") == 0) {
        return service_command();
    }
#ifdef __linux__
    if (argc == 4 && strcmp(argv[1], "fd-bridge") == 0 && strcmp(argv[2], "--socket") == 0) {
        return descriptor_bridge(argv[3]);
    }
#endif
    if (argc == 4 && strcmp(argv[1], "bridge") == 0 && strcmp(argv[2], "--socket") == 0) {
        socket_path = argv[3];
    } else if (argc == 3 && strcmp(argv[1], "--socket") == 0) {
        socket_path = argv[2];
    } else {
        fprintf(stderr, "usage: outerssh-helper [--user-allowlist PATH] [--system-allowlist PATH] list|service|authorize --socket PATH|bridge --socket PATH\n");
        return 2;
    }
    char err[512];
    if (validate_socket(socket_path, err, sizeof(err)) < 0) {
        if (!has_service_prefix(socket_path) && socket_is_missing(socket_path))
            fprintf(stderr, "%s\n", HELPER_NOT_LISTENING_MESSAGE);
        fprintf(stderr, "%s\n", err);
        return 2;
    }
    if (send_frame(OSB_HELLO, 0, NULL, 0) < 0) return 1;

    /*
     * Each active stream is one logical client connection from the caller,
     * mapped to one Unix-domain socket fd connected to socket_path.
     */
    struct stream streams[1024];
    size_t stream_count = 0;
    unsigned char buf[OSB_CHUNK];
    uint64_t last_frame_ms = monotonic_ms();

    for (;;) {
        struct pollfd pfds[1025];
        size_t polled_stream_count = stream_count;
        memset(pfds, 0, sizeof(pfds));

        /*
         * pfds[0] watches stdin for framed commands from the parent process.
         * pfds[1...] watch the Unix-socket fds for bytes flowing back.
         */
        pfds[0].fd = STDIN_FILENO;
        pfds[0].events = POLLIN;
        for (size_t i = 0; i < polled_stream_count; i++) {
            pfds[i + 1].fd = streams[i].fd;
            pfds[i + 1].events = POLLIN;
        }
        uint64_t now_ms = monotonic_ms();
        if (last_frame_ms > 0 && now_ms > last_frame_ms &&
            now_ms - last_frame_ms >= OSB_KEEPALIVE_TIMEOUT_MS) {
            return 0;
        }

        int timeout_ms = OSB_POLL_INTERVAL_MS;
        if (last_frame_ms > 0 && now_ms >= last_frame_ms) {
            uint64_t remaining_ms = OSB_KEEPALIVE_TIMEOUT_MS - (now_ms - last_frame_ms);
            if (remaining_ms < (uint64_t)timeout_ms) timeout_ms = (int)remaining_ms;
            if (timeout_ms < 1) timeout_ms = 1;
        }

        nfds_t poll_count = (nfds_t)(polled_stream_count + 1);
        int pr = poll(pfds, poll_count, timeout_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        if (pr == 0) continue;

        /* Forward data from Unix sockets back to stdout as OSB_DATA frames.
         * Walk backward so removing a stream can only compact entries that have
         * already been processed for this poll result.
         */
        for (size_t i = polled_stream_count; i > 0; i--) {
            size_t idx = i - 1;
            if (!(pfds[idx + 1].revents & (POLLIN | POLLHUP | POLLERR))) {
                continue;
            }
            ssize_t n = read(streams[idx].fd, buf, sizeof(buf));
            if (n > 0) {
                if (send_frame(OSB_DATA, streams[idx].id, buf, (uint32_t)n) < 0) return 1;
            } else {
                send_frame(OSB_EOF, streams[idx].id, NULL, 0);
                send_frame(OSB_CLOSE, streams[idx].id, NULL, 0);
                remove_stream(streams, &stream_count, idx);
            }
        }

        /* Handle framed commands from stdin: open streams, write data, or close. */
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            struct frame f;
            int rr = read_frame(&f);
            if (rr == 0) return 0;
            if (rr < 0) return 1;
            last_frame_ms = monotonic_ms();

            if (f.type == OSB_OPEN) {
                if (stream_count >= 1024) {
                    const char *msg = "too many streams";
                    send_frame(OSB_OPEN_ERROR, f.stream_id, msg, (uint32_t)strlen(msg));
                } else {
                    bool not_listening;
                    int fd = connect_socket(socket_path, err, sizeof(err), &not_listening);
                    if (fd < 0) {
                        send_frame(not_listening ? OSB_OPEN_NOT_LISTENING : OSB_OPEN_ERROR,
                            f.stream_id, err, (uint32_t)strlen(err));
                    } else {
                        streams[stream_count].id = f.stream_id;
                        streams[stream_count].fd = fd;
                        stream_count++;
                        send_frame(OSB_OPEN_OK, f.stream_id, NULL, 0);
                    }
                }
            } else {
                int idx = find_stream(streams, stream_count, f.stream_id);
                if (idx < 0) {
                    if (f.stream_id != 0) {
                        send_frame(OSB_CLOSE, f.stream_id, NULL, 0);
                    }
                } else {
                    switch (f.type) {
                    case OSB_DATA:
                        if (write_all(streams[idx].fd, f.payload, f.length) < 0) {
                            send_frame(OSB_CLOSE, f.stream_id, NULL, 0);
                            remove_stream(streams, &stream_count, (size_t)idx);
                        }
                        break;
                    case OSB_EOF:
                        shutdown(streams[idx].fd, SHUT_WR);
                        break;
                    case OSB_CLOSE:
                        remove_stream(streams, &stream_count, (size_t)idx);
                        break;
                    case OSB_PING:
                        send_frame(OSB_PONG, f.stream_id, f.payload, f.length);
                        break;
                    }
                }
            }
            free(f.payload);
        }
    }
}
