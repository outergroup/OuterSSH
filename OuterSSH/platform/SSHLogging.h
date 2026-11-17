#ifndef SSHLogging_h
#define SSHLogging_h

typedef enum {
    SSH_LOG_CATEGORY_SESSION,
    SSH_LOG_CATEGORY_AUTHENTICATION,
    SSH_LOG_CATEGORY_CHANNEL,
    SSH_LOG_CATEGORY_RELAY,
    SSH_LOG_CATEGORY_KEEPALIVE
} SSHLogCategory;

#if defined(__APPLE__)

#include <dispatch/dispatch.h>
#include <os/log.h>

typedef struct {
    os_log_t log;
    const char *category;
} SSHLogStorage;

static void initialize_ssh_log(void *context)
{
    SSHLogStorage *storage = context;
    storage->log = os_log_create(
        "org.outergroup.OuterLoop.browser",
        storage->category);
}

static os_log_t log_for_ssh_category(SSHLogCategory category)
{
    static SSHLogStorage logs[] = {
        { .category = "SSH.Session" },
        { .category = "SSH.Authentication" },
        { .category = "SSH.Channel" },
        { .category = "SSH.Relay" },
        { .category = "SSH.Keepalive" }
    };
    static dispatch_once_t once_tokens[
        sizeof(logs) / sizeof(logs[0])];
    size_t index = (size_t)category;
    if (index >= sizeof(logs) / sizeof(logs[0])) {
        index = SSH_LOG_CATEGORY_SESSION;
    }
    dispatch_once_f(
        &once_tokens[index],
        &logs[index],
        initialize_ssh_log);
    return logs[index].log;
}

#define SSH_LOG_DEBUG(category, ...) do { \
    os_log_t log = log_for_ssh_category(category); \
    if (os_log_type_enabled(log, OS_LOG_TYPE_DEBUG)) { \
        os_log_with_type(log, OS_LOG_TYPE_DEBUG, __VA_ARGS__); \
    } \
} while (0)

#define SSH_LOG_INFO(category, ...) do { \
    os_log_t log = log_for_ssh_category(category); \
    if (os_log_type_enabled(log, OS_LOG_TYPE_INFO)) { \
        os_log_with_type(log, OS_LOG_TYPE_INFO, __VA_ARGS__); \
    } \
} while (0)

#define SSH_LOG_NOTICE(category, ...) do { \
    os_log_t log = log_for_ssh_category(category); \
    if (os_log_type_enabled(log, OS_LOG_TYPE_DEFAULT)) { \
        os_log_with_type(log, OS_LOG_TYPE_DEFAULT, __VA_ARGS__); \
    } \
} while (0)

#define SSH_LOG_ERROR(category, ...) do { \
    os_log_t log = log_for_ssh_category(category); \
    if (os_log_type_enabled(log, OS_LOG_TYPE_ERROR)) { \
        os_log_with_type(log, OS_LOG_TYPE_ERROR, __VA_ARGS__); \
    } \
} while (0)

#else

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void outersshpriv_log(SSHLogCategory category, int level, const char *format, ...)
{
    if (level < 2 && getenv("OUTERSSH_LOG") == NULL) {
        return;
    }
    char *plain_format = malloc(strlen(format) + 1);
    if (plain_format == NULL) {
        return;
    }
    char *output = plain_format;
    for (const char *input = format; *input != '\0'; input++) {
        *output++ = *input;
        if (*input == '%' && input[1] == '{') {
            const char *end = strchr(input + 2, '}');
            if (end != NULL) {
                input = end;
            }
        }
    }
    *output = '\0';
#if defined(_WIN32)
    _lock_file(stderr);
#else
    flockfile(stderr);
#endif
    fprintf(stderr, "OuterSSH[%d]: ", category);
    va_list arguments;
    va_start(arguments, format);
    vfprintf(stderr, plain_format, arguments);
    va_end(arguments);
    fputc('\n', stderr);
#if defined(_WIN32)
    _unlock_file(stderr);
#else
    funlockfile(stderr);
#endif
    free(plain_format);
}

#define SSH_LOG_DEBUG(category, ...) outersshpriv_log(category, 0, __VA_ARGS__)
#define SSH_LOG_INFO(category, ...) outersshpriv_log(category, 1, __VA_ARGS__)
#define SSH_LOG_NOTICE(category, ...) outersshpriv_log(category, 2, __VA_ARGS__)
#define SSH_LOG_ERROR(category, ...) outersshpriv_log(category, 3, __VA_ARGS__)

#endif

#endif
