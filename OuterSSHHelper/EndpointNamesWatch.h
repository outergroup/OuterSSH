#ifndef OUTERSSH_ENDPOINT_NAMES_WATCH_H
#define OUTERSSH_ENDPOINT_NAMES_WATCH_H

#include <dirent.h>
#ifdef __APPLE__
#include <sys/event.h>
#else
#include <sys/inotify.h>
#endif

struct endpoint_names_parent {
    int handle;
    int exists;
    size_t name;
    char path[PATH_MAX];
};

struct endpoint_names_watch {
    int fd;
    struct endpoint_names_parent parents[16];
    size_t parent_count;
#ifdef __APPLE__
    int files[1024];
    size_t count;
#endif
};

static void endpoint_names_watch_close(struct endpoint_names_watch *watch) {
#ifdef __APPLE__
    for (size_t i = 0; i < watch->count; i++) close(watch->files[i]);
    watch->count = 0;
#endif
    if (watch->fd >= 0) close(watch->fd);
    watch->fd = -1;
}

static int endpoint_names_watch_path(struct endpoint_names_watch *watch, const char *path) {
#ifdef __APPLE__
    if (watch->count == 1024) return -1;
    int fd = open(path, O_EVTONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct kevent event;
    EV_SET(&event, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
           NOTE_WRITE | NOTE_DELETE | NOTE_RENAME | NOTE_ATTRIB | NOTE_REVOKE, 0, NULL);
    if (kevent(watch->fd, &event, 1, NULL, 0, NULL) < 0) { close(fd); return -1; }
    watch->files[watch->count++] = fd;
    return fd;
#else
    return inotify_add_watch(watch->fd, path, IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO |
        IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_DONT_FOLLOW);
#endif
}

static int endpoint_names_path_exists(const char *path) {
    struct stat status;
    return lstat(path, &status) == 0;
}

static int endpoint_names_watch_ancestor(struct endpoint_names_watch *watch, const char *directory) {
    if (watch->parent_count == 16) return 1;
    struct endpoint_names_parent *parent = &watch->parents[watch->parent_count];
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s", directory);
    char *slash;
    while ((slash = strrchr(path, '/'))) {
        *slash = 0;
        parent->handle = endpoint_names_watch_path(watch, slash == path ? "/" : path);
        if (parent->handle < 0) continue;
        parent->name = (size_t)(slash - path) + 1;
        size_t length = parent->name + strcspn(directory + parent->name, "/");
        memcpy(parent->path, directory, length);
        parent->path[length] = 0;
        parent->exists = endpoint_names_path_exists(parent->path);
        watch->parent_count++;
        return !parent->exists;
    }
    return 1;
}

static void endpoint_names_watch_directory(struct endpoint_names_watch *watch, const char *directory) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s", directory) >= (int)sizeof(path)) return;
    for (int attempt = 0; attempt < 4; attempt++) {
        if (endpoint_names_watch_path(watch, directory) < 0) {
            if (endpoint_names_watch_ancestor(watch, directory)) return;
            continue;
        }
        DIR *entries = opendir(directory);
        if (entries == NULL) return;
        struct dirent *entry;
        size_t count = 0;
        while ((entry = readdir(entries)) && count < 256) {
            if (entry->d_name[0] == '.') continue;
            count++;
            if (snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) < (int)sizeof(path))
                endpoint_names_watch_path(watch, path);
        }
        closedir(entries);
        return;
    }
}

static int endpoint_names_watch_event(const struct endpoint_names_watch *watch, int handle,
                                      const char *name, int replaced) {
    int parent = 0;
    for (size_t i = 0; i < watch->parent_count; i++) {
        const struct endpoint_names_parent *candidate = &watch->parents[i];
        if (candidate->handle != handle) continue;
        parent = 1;
        if (replaced) return 1;
        if (name ? strcmp(name, candidate->path + candidate->name) == 0
                 : endpoint_names_path_exists(candidate->path) != candidate->exists) return 1;
    }
    return !parent;
}

static int endpoint_names_watch_changed(struct endpoint_names_watch *watch) {
    int changed = 0;
#ifdef __APPLE__
    struct kevent events[64];
    struct timespec immediately = {0, 0};
    int count;
    while ((count = kevent(watch->fd, NULL, 0, events, 64, &immediately)) > 0) {
        for (int i = 0; i < count; i++) {
            int replaced = (events[i].fflags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)) != 0;
            if (endpoint_names_watch_event(watch, (int)events[i].ident, NULL, replaced)) changed = 1;
        }
    }
    return changed || count < 0;
#else
    char buffer[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t length;
    while ((length = read(watch->fd, buffer, sizeof(buffer))) > 0) {
        for (char *cursor = buffer; cursor < buffer + length;) {
            const struct inotify_event *event = (const struct inotify_event *)cursor;
            cursor += sizeof(*event) + event->len;
            int replaced = (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED | IN_UNMOUNT)) != 0;
            if (endpoint_names_watch_event(watch, event->wd, event->len ? event->name : "", replaced))
                changed = 1;
        }
    }
    return changed || (length < 0 && errno != EAGAIN && errno != EINTR);
#endif
}

static int endpoint_names_watch_open(struct endpoint_names_watch *watch) {
    *watch = (struct endpoint_names_watch){.fd = -1};
#ifdef __APPLE__
    watch->fd = kqueue();
#else
    watch->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
#endif
    if (watch->fd < 0) return -1;
    if (fcntl(watch->fd, F_SETFD, FD_CLOEXEC) < 0) { endpoint_names_watch_close(watch); return -1; }
    char user[PATH_MAX];
    const char *home = getenv("HOME");
    if (home == NULL || home[0] != '/') { errno = EINVAL; endpoint_names_watch_close(watch); return -1; }
#ifdef __APPLE__
    snprintf(user, sizeof(user), "%s/Library/Application Support/org.outerssh/endpoints.d", home);
    const char *system = "/Library/Application Support/org.outerssh/endpoints.d";
#else
    const char *config = getenv("XDG_CONFIG_HOME");
    if (config && config[0] == '/') snprintf(user, sizeof(user), "%s/outerssh/endpoints.d", config);
    else snprintf(user, sizeof(user), "%s/.config/outerssh/endpoints.d", home);
    const char *system = "/etc/outerssh/endpoints.d";
#endif
    endpoint_names_watch_directory(watch, user);
    endpoint_names_watch_directory(watch, system);
    return 0;
}

#endif
