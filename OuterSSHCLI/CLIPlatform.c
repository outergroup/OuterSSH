#include "CLIPlatform.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <io.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#endif

typedef struct Allocation {
    struct Allocation *next;
#ifdef _MSC_VER
    _Alignas(MEMORY_ALLOCATION_ALIGNMENT) unsigned char data[];
#else
    max_align_t data[];
#endif
} Allocation;
static Allocation *allocations;

void *cli_allocate(size_t size)
{
    if (size > SIZE_MAX - sizeof(Allocation)) abort();
    Allocation *allocation = calloc(1, sizeof(Allocation) + size);
    if (allocation == NULL) { fputs("outerssh: out of memory.\n", stderr); exit(EXIT_FAILURE); }
    allocation->next = allocations;
    allocations = allocation;
    return allocation->data;
}

char *cli_copy(const char *text)
{
    if (text == NULL) return NULL;
    char *copy = cli_allocate(strlen(text) + 1);
    strcpy(copy, text);
    return copy;
}

void cli_free_allocations(void)
{
    while (allocations != NULL) {
        Allocation *next = allocations->next;
        free(allocations);
        allocations = next;
    }
}

char *cli_home(void)
{
#ifdef _WIN32
    return cli_copy(getenv("USERPROFILE"));
#else
    struct passwd *user = getpwuid(getuid());
    return cli_copy(user == NULL ? getenv("HOME") : user->pw_dir);
#endif
}

char *cli_username(void)
{
#ifdef _WIN32
    return cli_copy(getenv("USERNAME"));
#else
    struct passwd *user = getpwuid(getuid());
    return cli_copy(user == NULL ? getenv("USER") : user->pw_name);
#endif
}

char *cli_expand_home(const char *path)
{
    if (path == NULL || path[0] != '~') return cli_copy(path);
    const char *tail = path + 1;
    while (*tail && *tail != '/' && *tail != '\\') tail++;
    char *home = NULL;
    if (tail == path + 1) home = cli_home();
#ifndef _WIN32
    else {
        char *name = cli_copy(path + 1);
        name[tail - path - 1] = '\0';
        struct passwd *user = getpwnam(name);
        if (user != NULL) home = cli_copy(user->pw_dir);
    }
#endif
    if (home == NULL) return NULL;
    char *expanded = cli_allocate(strlen(home) + strlen(tail) + 1);
    strcpy(expanded, home);
    strcat(expanded, tail);
    return expanded;
}

#ifdef _WIN32
static wchar_t *wide_string(const char *text)
{
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (count == 0) return NULL;
    wchar_t *result = cli_allocate((size_t)count * sizeof(wchar_t));
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, result, count)) return NULL;
    return result;
}

static char *command_line(char *const arguments[])
{
    size_t size = 1;
    for (size_t i = 0; arguments[i]; i++) size += strlen(arguments[i]) * 2 + 3;
    char *line = cli_allocate(size), *out = line;
    for (size_t i = 0; arguments[i]; i++) {
        if (i) *out++ = ' ';
        *out++ = '"';
        const char *in = arguments[i];
        while (*in) {
            size_t slashes = 0;
            while (*in == '\\') { slashes++; in++; }
            size_t count = (*in == '"' || *in == '\0') ? slashes * 2 : slashes;
            while (count--) *out++ = '\\';
            if (*in == '"') *out++ = '\\';
            if (*in) *out++ = *in++;
        }
        *out++ = '"';
    }
    *out = '\0';
    return line;
}
#endif

char *cli_resolve_configuration(char *const arguments[])
{
    size_t capacity = 8192, length = 0;
    char *buffer = malloc(capacity);
    if (buffer == NULL) return NULL;
    bool ok = true;
#ifdef _WIN32
    HANDLE input = NULL, output = NULL, null_input = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    PROCESS_INFORMATION process = {0};
    wchar_t *command = wide_string(command_line(arguments));
    if (command == NULL || !CreatePipe(&input, &output, &security, 0) ||
        !SetHandleInformation(input, HANDLE_FLAG_INHERIT, 0)) { ok = false; goto done; }
    null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    STARTUPINFOW startup = {.cb = sizeof(startup), .dwFlags = STARTF_USESTDHANDLES,
        .hStdInput = null_input, .hStdOutput = output, .hStdError = GetStdHandle(STD_ERROR_HANDLE)};
    if (null_input == INVALID_HANDLE_VALUE ||
        !CreateProcessW(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        ok = false; goto done;
    }
    CloseHandle(output); output = NULL;
    CloseHandle(null_input); null_input = INVALID_HANDLE_VALUE;
#else
    int descriptors[2];
    if (pipe(descriptors) != 0) { free(buffer); return NULL; }
    pid_t pid = fork();
    if (pid == 0) {
        close(descriptors[0]);
        int null_input = open("/dev/null", O_RDONLY);
        if (null_input < 0 || dup2(null_input, STDIN_FILENO) < 0 || dup2(descriptors[1], STDOUT_FILENO) < 0) _exit(127);
        close(null_input); close(descriptors[1]);
        execvp(arguments[0], arguments);
        perror("outerssh: unable to run ssh -G");
        _exit(127);
    }
    close(descriptors[1]);
    if (pid < 0) { close(descriptors[0]); free(buffer); return NULL; }
#endif
    for (;;) {
        if (capacity - length < 4096) {
            if (capacity >= 16 * 1024 * 1024) { ok = false; break; }
            capacity *= 2;
            char *grown = realloc(buffer, capacity);
            if (grown == NULL) { ok = false; break; }
            buffer = grown;
        }
#ifdef _WIN32
        DWORD count;
        if (!ReadFile(input, buffer + length, (DWORD)(capacity - length - 1), &count, NULL)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) ok = false;
            break;
        }
#else
        ssize_t count = read(descriptors[0], buffer + length, capacity - length - 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { ok = false; break; }
#endif
        if (count == 0) break;
        length += (size_t)count;
    }
#ifdef _WIN32
    CloseHandle(input); input = NULL;
    if (!ok) TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD status;
    if (!GetExitCodeProcess(process.hProcess, &status) || status != 0) ok = false;
done:
    if (input) CloseHandle(input);
    if (output) CloseHandle(output);
    if (null_input != INVALID_HANDLE_VALUE) CloseHandle(null_input);
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
#else
    close(descriptors[0]);
    if (!ok) kill(pid, SIGTERM);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) ok = false;
#endif
    buffer[length] = '\0';
    char *result = ok ? cli_copy(buffer) : NULL;
    free(buffer);
    if (!ok) fputs("outerssh: ssh -G failed; ensure OpenSSH is installed and the configuration is valid.\n", stderr);
    return result;
}

bool cli_prompt(const char *prompt, char *buffer, size_t capacity, bool echo)
{
    if (capacity < 2) return false;
    bool ok = true, overflow = false;
    size_t length = 0;
#ifdef _WIN32
    HANDLE input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    DWORD mode;
    if (input == INVALID_HANDLE_VALUE) return false;
    if (!GetConsoleMode(input, &mode)) { CloseHandle(input); return false; }
    DWORD changed = mode | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
    if (!echo) changed &= ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(input, changed)) { CloseHandle(input); return false; }
    fputs(prompt, stderr); fflush(stderr);
    wchar_t line[4096]; DWORD count = 0;
    ok = ReadConsoleW(input, line, 4095, &count, NULL) != 0;
    if (ok) {
        while (count && (line[count - 1] == L'\r' || line[count - 1] == L'\n')) count--;
        line[count] = 0;
        ok = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, line, -1, buffer, (int)capacity, NULL, NULL) != 0;
    }
    SecureZeroMemory(line, sizeof(line));
    SetConsoleMode(input, mode); CloseHandle(input);
    (void)length; (void)overflow;
#else
    int input = open("/dev/tty", O_RDWR | O_CLOEXEC);
    struct termios mode;
    if (input < 0) return false;
    if (tcgetattr(input, &mode) != 0) { close(input); return false; }
    struct termios changed = mode;
    if (!echo) changed.c_lflag &= ~ECHO;
    if (tcsetattr(input, TCSAFLUSH, &changed) != 0) { close(input); return false; }
    fputs(prompt, stderr); fflush(stderr);
    for (;;) {
        char byte;
        ssize_t count = read(input, &byte, 1);
        if (count <= 0) { ok = false; break; }
        if (byte == '\n' || byte == '\r') break;
        if (length + 1 < capacity) buffer[length++] = byte;
        else overflow = true;
    }
    buffer[length] = '\0';
    if (tcsetattr(input, TCSAFLUSH, &mode) != 0) ok = false;
    close(input);
#endif
    if (!echo) fputc('\n', stderr);
    return ok && !overflow;
}

bool cli_append_known_host(const char *path, const char *line, size_t length)
{
    char *directory = malloc(strlen(path) + 1);
    if (directory == NULL) return false;
    strcpy(directory, path);
    for (char *p = directory + 1; *p; p++) {
        if (*p != '/' && *p != '\\') continue;
#ifndef _WIN32
        if (*p == '\\') continue;
#endif
        char separator = *p; *p = '\0';
#ifdef _WIN32
        int result = _mkdir(directory);
#else
        int result = mkdir(directory, 0700);
#endif
        *p = separator;
        if (result != 0 && errno != EEXIST) { free(directory); return false; }
    }
    free(directory);
    bool ok = false;
#ifdef _WIN32
    HANDLE file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    OVERLAPPED lock = {0};
    if (LockFileEx(file, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &lock)) {
        LARGE_INTEGER end, zero = {0};
        DWORD count = 0;
        char last = '\n';
        ok = SetFilePointerEx(file, zero, &end, FILE_END) != 0;
        if (ok && end.QuadPart > 0) {
            LARGE_INTEGER previous = {.QuadPart = -1};
            ok = SetFilePointerEx(file, previous, NULL, FILE_END) && ReadFile(file, &last, 1, &count, NULL) && count == 1;
        }
        if (ok && last != '\n') ok = WriteFile(file, "\n", 1, &count, NULL) && count == 1;
        for (size_t offset = 0; ok && offset < length;) {
            DWORD chunk = (DWORD)((length - offset > MAXDWORD) ? MAXDWORD : length - offset);
            ok = WriteFile(file, line + offset, chunk, &count, NULL) && count > 0;
            offset += count;
        }
        if (ok) ok = FlushFileBuffers(file) != 0;
        UnlockFileEx(file, 0, MAXDWORD, MAXDWORD, &lock);
    }
    CloseHandle(file);
#else
    int file = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (file < 0) return false;
    if (flock(file, LOCK_EX) == 0) {
        off_t end = lseek(file, 0, SEEK_END);
        char last = '\n';
        ok = end >= 0 && (end == 0 || pread(file, &last, 1, end - 1) == 1);
        if (ok && last != '\n') ok = write(file, "\n", 1) == 1;
        for (size_t offset = 0; ok && offset < length;) {
            ssize_t count = write(file, line + offset, length - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { ok = false; break; }
            offset += (size_t)count;
        }
        if (ok) ok = fsync(file) == 0;
    }
    close(file);
#endif
    return ok;
}

bool cli_disable_agent(void)
{
#ifdef _WIN32
    return _putenv_s("SSH_AUTH_SOCK", "") == 0;
#else
    return unsetenv("SSH_AUTH_SOCK") == 0;
#endif
}

#ifdef _WIN32
void *cli_semaphore_create(void) { return CreateSemaphoreW(NULL, 0, LONG_MAX, NULL); }
void cli_semaphore_signal(void *semaphore) { if (!ReleaseSemaphore(semaphore, 1, NULL)) abort(); }
void cli_semaphore_wait(void *semaphore) { if (WaitForSingleObject(semaphore, INFINITE) != WAIT_OBJECT_0) abort(); }
void cli_semaphore_destroy(void *semaphore) { CloseHandle(semaphore); }
static HANDLE stopped;
static BOOL WINAPI console_signal(DWORD signal)
{
    if (signal != CTRL_C_EVENT && signal != CTRL_BREAK_EVENT) return FALSE;
    SetEvent(stopped);
    return TRUE;
}
bool cli_prepare_signals(void)
{
    stopped = CreateEventW(NULL, TRUE, FALSE, NULL);
    return stopped != NULL && SetConsoleCtrlHandler(console_signal, TRUE);
}
void cli_wait_for_signal(void) { WaitForSingleObject(stopped, INFINITE); }
#else
typedef struct { pthread_mutex_t mutex; pthread_cond_t condition; unsigned count; } Semaphore;
void *cli_semaphore_create(void)
{
    Semaphore *semaphore = calloc(1, sizeof(*semaphore));
    if (semaphore == NULL) return NULL;
    if (pthread_mutex_init(&semaphore->mutex, NULL) != 0) { free(semaphore); return NULL; }
    if (pthread_cond_init(&semaphore->condition, NULL) != 0) {
        pthread_mutex_destroy(&semaphore->mutex); free(semaphore); return NULL;
    }
    return semaphore;
}
void cli_semaphore_signal(void *pointer)
{
    Semaphore *semaphore = pointer;
    pthread_mutex_lock(&semaphore->mutex);
    semaphore->count++;
    pthread_cond_signal(&semaphore->condition);
    pthread_mutex_unlock(&semaphore->mutex);
}
void cli_semaphore_wait(void *pointer)
{
    Semaphore *semaphore = pointer;
    pthread_mutex_lock(&semaphore->mutex);
    while (!semaphore->count) pthread_cond_wait(&semaphore->condition, &semaphore->mutex);
    semaphore->count--;
    pthread_mutex_unlock(&semaphore->mutex);
}
void cli_semaphore_destroy(void *pointer)
{
    Semaphore *semaphore = pointer;
    pthread_cond_destroy(&semaphore->condition);
    pthread_mutex_destroy(&semaphore->mutex);
    free(semaphore);
}
static volatile sig_atomic_t stopped;
static void stop_signal(int number) { (void)number; stopped = 1; }
bool cli_prepare_signals(void)
{
    struct sigaction action = {0};
    action.sa_handler = stop_signal;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) == 0 && sigaction(SIGTERM, &action, NULL) == 0;
}
void cli_wait_for_signal(void)
{
    while (!stopped) { struct timespec delay = {0, 50000000}; nanosleep(&delay, NULL); }
}
#endif


#if defined(__APPLE__)
struct CLIEvents {
    dispatch_queue_t queue;
    dispatch_source_t source;
    OuterSSHEventQueue *event_queue;
    void (*events_posted)(void *);
    void *user;
};

static void events_ready(void *pointer)
{
    CLIEvents *events = pointer;
    events->events_posted(events->user);
}

CLIEvents *cli_events_start(void (*events_posted)(void *), void *user)
{
    CLIEvents *events = calloc(1, sizeof(*events));
    if (events == NULL) return NULL;
    events->events_posted = events_posted;
    events->user = user;
    events->queue = dispatch_queue_create("org.outerssh.cli", DISPATCH_QUEUE_SERIAL);
    events->source = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_OR, 0, 0, events->queue);
    dispatch_set_context(events->source, events);
    dispatch_source_set_event_handler_f(events->source, events_ready);
    dispatch_activate(events->source);
    events->event_queue = outerssh_event_queue_create(events->source);
    if (events->event_queue == NULL) {
        dispatch_source_cancel(events->source);
        dispatch_release(events->source);
        dispatch_release(events->queue);
        free(events);
        return NULL;
    }
    return events;
}

static void destroy_on_queue(void *pointer)
{
    CLIEvents *events = pointer;
    dispatch_source_cancel(events->source);
    outerssh_event_queue_destroy(events->event_queue);
}

void cli_events_stop(CLIEvents *events)
{
    if (events == NULL) return;
    dispatch_sync_f(events->queue, events, destroy_on_queue);
    dispatch_release(events->source);
    dispatch_release(events->queue);
    free(events);
}
#else
/* A thread waits on the event queue's event handle and a stop signal. */
struct CLIEvents {
    OuterSSHEventQueue *event_queue;
    void (*events_posted)(void *);
    void *user;
#ifdef _WIN32
    HANDLE stop;
    HANDLE thread;
#else
    int stop[2];
    pthread_t thread;
#endif
};

#ifdef _WIN32
static DWORD WINAPI watch_events(void *pointer)
{
    CLIEvents *events = pointer;
    HANDLE handles[] = {events->stop, outerssh_event_queue_wait_handle(events->event_queue)};
    while (WaitForMultipleObjects(2, handles, FALSE, INFINITE) == WAIT_OBJECT_0 + 1)
        events->events_posted(events->user);
    return 0;
}
#else
static void *watch_events(void *pointer)
{
    CLIEvents *events = pointer;
    struct pollfd entries[] = {
        {.fd = events->stop[0], .events = POLLIN},
        {.fd = outerssh_event_queue_wait_handle(events->event_queue), .events = POLLIN},
    };
    for (;;) {
        int count = poll(entries, 2, -1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || entries[0].revents != 0) return NULL;
        if (entries[1].revents != 0) events->events_posted(events->user);
    }
}
#endif

CLIEvents *cli_events_start(void (*events_posted)(void *), void *user)
{
    CLIEvents *events = calloc(1, sizeof(*events));
    if (events == NULL) return NULL;
    events->events_posted = events_posted;
    events->user = user;
    events->event_queue = outerssh_event_queue_create();
    if (events->event_queue == NULL ||
        outerssh_event_queue_wait_handle(events->event_queue) == OUTERSSH_EVENT_WAIT_HANDLE_INVALID) goto failed;
#ifdef _WIN32
    events->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (events->stop == NULL) goto failed;
    events->thread = CreateThread(NULL, 0, watch_events, events, 0, NULL);
    if (events->thread == NULL) { CloseHandle(events->stop); goto failed; }
#else
    if (pipe(events->stop) != 0) goto failed;
    if (pthread_create(&events->thread, NULL, watch_events, events) != 0) {
        close(events->stop[0]); close(events->stop[1]);
        goto failed;
    }
#endif
    return events;
failed:
    outerssh_event_queue_destroy(events->event_queue);
    free(events);
    return NULL;
}

void cli_events_stop(CLIEvents *events)
{
    if (events == NULL) return;
#ifdef _WIN32
    SetEvent(events->stop);
    WaitForSingleObject(events->thread, INFINITE);
    CloseHandle(events->thread);
    CloseHandle(events->stop);
#else
    close(events->stop[1]);
    pthread_join(events->thread, NULL);
    close(events->stop[0]);
#endif
    outerssh_event_queue_destroy(events->event_queue);
    free(events);
}
#endif

OuterSSHEventQueue *cli_event_queue(CLIEvents *events) { return events->event_queue; }
