#ifndef OUTERSSH_ENDPOINT_NAMES_READ_H
#define OUTERSSH_ENDPOINT_NAMES_READ_H
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

static bool names_file_name(const char *name) {
    if (!*name || !((*name >= 'a' && *name <= 'z') || (*name >= 'A' && *name <= 'Z') || (*name >= '0' && *name <= '9'))) return false;
    size_t length = strlen(name);
    if (length >= 4 && !strcmp(name + length - 4, ".tmp")) return false;
    return strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == length;
}

static bool names_directory(const char *path, uid_t uid, const char *account,
                            unsigned char **bytes, size_t *length, unsigned *count) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT;
    struct stat st;
    if (fstat(fd, &st) || st.st_uid != uid || (st.st_mode & 022)) { close(fd); return false; }
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return false; }
    bool valid = true;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (!names_file_name(entry->d_name)) continue;
        int file = openat(fd, entry->d_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (file < 0 && errno == ENOENT) continue;
        if (file < 0) { valid = false; break; }
        unsigned char data[65537];
        size_t used = 0;
        valid = !fstat(file, &st) && S_ISREG(st.st_mode) && st.st_uid == uid && !(st.st_mode & 022) &&
            st.st_size <= 65536 && ++*count <= 64;
        while (valid && used < sizeof(data)) {
            ssize_t n = read(file, data + used, sizeof(data) - used);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) valid = false;
            if (n <= 0) break;
            used += (size_t)n;
        }
        close(file);
        size_t account_length = strlen(account) + 1;
        if (!valid || used > 65536 || memchr(data, 0, used) || *length + account_length + used + 1 > 1024 * 1024) {
            valid = false; break;
        }
        unsigned char *grown = realloc(*bytes, *length + account_length + used + 1);
        if (!grown) { valid = false; break; }
        *bytes = grown;
        memcpy(grown + *length, account, account_length);
        memcpy(grown + *length + account_length, data, used);
        *length += account_length + used;
        grown[(*length)++] = 0;
    }
    closedir(directory);
    return valid;
}

bool outersshpriv_endpoint_names_read_snapshot(unsigned char **bytes, size_t *length) {
    *bytes = NULL; *length = 0;
    uid_t uid = getuid();
    struct passwd value, *user = NULL;
    char user_buffer[16384];
    if (getpwuid_r(uid, &value, user_buffer, sizeof(user_buffer), &user) || !user || !user->pw_name) return false;
    char *account = strdup(user->pw_name);
    if (!account) return false;
    const char *home = getenv("HOME");
    char directory[PATH_MAX];
    bool valid = home && home[0] == '/';
    unsigned count = 0;
#ifdef __APPLE__
    const char *system = "/Library/Application Support/org.outerssh/endpoints.d";
    if (valid) valid = snprintf(directory, sizeof(directory), "%s/Library/Application Support/org.outerssh/endpoints.d", home) < (int)sizeof(directory);
#else
    const char *system = "/etc/outerssh/endpoints.d";
    const char *config = getenv("XDG_CONFIG_HOME");
    if (valid) valid = (config && config[0] == '/' ?
        snprintf(directory, sizeof(directory), "%s/outerssh/endpoints.d", config) :
        snprintf(directory, sizeof(directory), "%s/.config/outerssh/endpoints.d", home)) < (int)sizeof(directory);
#endif
    valid = valid && names_directory(system, 0, "root", bytes, length, &count) &&
        names_directory(directory, uid, account, bytes, length, &count);
    free(account);
    OuterSSHEndpointRecord *records = NULL;
    size_t record_count = 0;
    valid = valid && outersshpriv_endpoint_names_parse(*bytes, *length, &records, &record_count);
    free(records);
    if (!valid) { free(*bytes); *bytes = NULL; *length = 0; }
    return valid;
}

bool outerssh_endpoint_names_read_local(OuterSSHEndpointRecord **records, size_t *count) {
    *records = NULL; *count = 0;
    unsigned char *bytes;
    size_t length;
    if (!outersshpriv_endpoint_names_read_snapshot(&bytes, &length)) return false;
    bool valid = outersshpriv_endpoint_names_parse(bytes, length, records, count);
    free(bytes);
    return valid;
}
#endif
