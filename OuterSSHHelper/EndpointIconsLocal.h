#ifndef OUTERSSH_ENDPOINT_ICONS_LOCAL_H
#define OUTERSSH_ENDPOINT_ICONS_LOCAL_H
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

static bool icons_set_error(const char **error, const char *text) {
    if (error) *error = text;
    return false;
}

/* Writes the user cache directory and the length of its existing prefix that
 * must not be created (the home or configuration directory). */
static bool icons_directory_path(char *path, size_t capacity, size_t *base) {
    const char *home = getenv("HOME");
#ifdef __APPLE__
    if (!home || home[0] != '/') return false;
    *base = strlen(home);
    return snprintf(path, capacity, "%s/Library/Application Support/org.outerssh/endpoint-icons", home) < (int)capacity;
#else
    const char *config = getenv("XDG_CONFIG_HOME");
    if (config && config[0] == '/') {
        *base = strlen(config);
        return snprintf(path, capacity, "%s/outerssh/endpoint-icons", config) < (int)capacity;
    }
    if (!home || home[0] != '/') return false;
    *base = strlen(home);
    return snprintf(path, capacity, "%s/.config/outerssh/endpoint-icons", home) < (int)capacity;
#endif
}

static bool icons_entry_name(const char *name) {
    return strlen(name) == 68 && strspn(name, "0123456789abcdef") == 64 && !strcmp(name + 64, ".png");
}

/* Opens the cache directory, creating it if create is set. Returns -1 on
 * error, or -2 when it is absent and create is not set. */
static int icons_open_directory(bool create, const char **error) {
    char path[PATH_MAX];
    size_t base;
    if (!icons_directory_path(path, sizeof(path), &base)) {
        icons_set_error(error, "Could not locate the endpoint icon cache.");
        return -1;
    }
    if (create) {
        for (char *slash = strchr(path + base + 1, '/'); ; slash = strchr(slash + 1, '/')) {
            if (slash) *slash = 0;
            int made = mkdir(path, 0700);
            if (slash) *slash = '/';
            if (made && errno != EEXIST) {
                icons_set_error(error, "Could not create the endpoint icon cache.");
                return -1;
            }
            if (!slash) break;
        }
    }
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (!create && (errno == ENOENT || errno == ENOTDIR)) return -2;
        icons_set_error(error, "Could not open the endpoint icon cache.");
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 022)) {
        close(fd);
        icons_set_error(error, "Unsafe endpoint icon cache permissions.");
        return -1;
    }
    return fd;
}

bool outerssh_endpoint_icon_read_local(const char *transport, const char *address, size_t address_length,
    uint16_t port, unsigned char **png, size_t *length, const char **error) {
    *png = NULL;
    *length = 0;
    char name[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY];
    if (!outerssh_endpoint_icon_file_name(transport, address, address_length, port, name))
        return icons_set_error(error, "Invalid endpoint.");
    int directory = icons_open_directory(false, error);
    if (directory == -2) return true;
    if (directory < 0) return false;
    int file = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    int failure = errno;
    close(directory);
    if (file < 0) return failure == ENOENT ? true : icons_set_error(error, "Could not open the cached endpoint icon.");
    struct stat st;
    unsigned char *bytes = NULL;
    size_t used = 0;
    bool valid = !fstat(file, &st) && S_ISREG(st.st_mode) && st.st_uid == getuid() && !(st.st_mode & 022) &&
        st.st_size <= OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES;
    if (!valid) icons_set_error(error, "Unsafe cached endpoint icon.");
    else if (!(bytes = malloc(OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES + 1))) valid = icons_set_error(error, "Out of memory.");
    while (valid && used <= OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES) {
        ssize_t n = read(file, bytes + used, OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES + 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) valid = icons_set_error(error, "Could not read the cached endpoint icon.");
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(file);
    if (valid && !outerssh_endpoint_icon_is_valid(bytes, used))
        valid = icons_set_error(error, "The cached endpoint icon is not a valid PNG.");
    if (!valid) { free(bytes); return false; }
    *png = bytes;
    *length = used;
    return true;
}

/* Removes the least recently written icons until a new one fits. */
static bool icons_make_room(int directory, const char *name) {
    struct stat st;
    if (!fstatat(directory, name, &st, AT_SYMLINK_NOFOLLOW)) return true;
    for (;;) {
        int copy = dup(directory);
        DIR *listing = copy < 0 ? NULL : fdopendir(copy);
        if (!listing) { if (copy >= 0) close(copy); return false; }
        size_t count = 0;
        char oldest[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY] = {0};
        struct timespec oldest_time = {0, 0};
        struct dirent *entry;
        while ((entry = readdir(listing))) {
            if (!icons_entry_name(entry->d_name) || fstatat(directory, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) continue;
            count++;
#ifdef __APPLE__
            struct timespec time = st.st_mtimespec;
#else
            struct timespec time = st.st_mtim;
#endif
            if (!oldest[0] || time.tv_sec < oldest_time.tv_sec ||
                (time.tv_sec == oldest_time.tv_sec && time.tv_nsec < oldest_time.tv_nsec)) {
                memcpy(oldest, entry->d_name, sizeof(oldest));
                oldest_time = time;
            }
        }
        closedir(listing);
        if (count < OUTERSSH_ENDPOINT_ICON_MAXIMUM_COUNT) return true;
        if (unlinkat(directory, oldest, 0) && errno != ENOENT) return false;
    }
}

bool outerssh_endpoint_icon_store_local(const char *transport, const char *address, size_t address_length,
    uint16_t port, const void *png, size_t length, const char **error) {
    char name[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY];
    if (!outerssh_endpoint_icon_file_name(transport, address, address_length, port, name))
        return icons_set_error(error, "Invalid endpoint.");
    if (!outerssh_endpoint_icon_is_valid(png, length))
        return icons_set_error(error, "Endpoint icons must be PNG images of at most 64 KiB and 512x512 pixels.");
    int directory = icons_open_directory(true, error);
    if (directory < 0) return false;
    char temporary[96];
    snprintf(temporary, sizeof(temporary), ".%.64s.%ld.tmp", name, (long)getpid());
    bool stored = false;
    int file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file < 0 && errno == EEXIST && !unlinkat(directory, temporary, 0))
        file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file < 0) {
        icons_set_error(error, "Could not create the endpoint icon.");
    } else {
        const unsigned char *bytes = png;
        size_t remaining = length;
        bool written = !fchmod(file, 0600);
        while (written && remaining) {
            ssize_t n = write(file, bytes, remaining);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { written = false; break; }
            bytes += n;
            remaining -= (size_t)n;
        }
        written = !fsync(file) && written;
        written = !close(file) && written;
        if (!written) icons_set_error(error, "Could not write the endpoint icon.");
        else if (!icons_make_room(directory, name)) icons_set_error(error, "Could not evict old endpoint icons.");
        else if (renameat(directory, temporary, directory, name)) icons_set_error(error, "Could not replace the endpoint icon.");
        else stored = true;
        if (!stored) unlinkat(directory, temporary, 0);
    }
    close(directory);
    return stored;
}
#endif
