#include "../OuterSSHHelper.h"
#include "NamedPipes.h"
#include "EndpointNames.h"
#include "../../OuterSSH/HelperProtocol.h"
#include "../../OuterSSH/SSHEndpointRecord.h"
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

enum {
    MAXIMUM_STREAMS = 64,
    CHUNK_CAPACITY = 32768
};

static wchar_t allowlist[OUTER_PATH_CAPACITY];
static OuterSSHHelperRequestHandler request_handler;
static HANDLE output_lock;

static void write_line(DWORD which, const char *text)
{
    HANDLE handle = GetStdHandle(which);
    DWORD count = 0;
    WriteFile(handle, text, (DWORD)strlen(text), &count, NULL);
    WriteFile(handle, "\r\n", 2, &count, NULL);
}

static bool write_all(const void *bytes, size_t length)
{
    const unsigned char *cursor = bytes;
    while (length) {
        DWORD count = 0;
        if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), cursor, (DWORD)length, &count, NULL) || !count) return false;
        cursor += count;
        length -= count;
    }
    return true;
}

static bool stopped(HANDLE stop)
{
    return stop && WaitForSingleObject(stop, 0) == WAIT_OBJECT_0;
}

static bool output(HelperFrameType type, uint32_t id, const void *bytes, size_t size, HANDLE stop)
{
    unsigned char header[HELPER_FRAME_HEADER_LENGTH];
    if (!outersshpriv_helper_encode_header(type, id, size, header)) return false;
    HANDLE events[] = {output_lock, stop};
    DWORD waited = WaitForMultipleObjects(stop ? 2 : 1, events, FALSE, INFINITE);
    if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED_0) return false;
    bool ok = !stopped(stop) && write_all(header, sizeof(header)) && write_all(bytes, size);
    ReleaseMutex(output_lock);
    return ok;
}

static bool output_text(HelperFrameType type, uint32_t id, const char *text)
{
    return output(type, id, text, strlen(text), NULL);
}

typedef struct Chunk {
    struct Chunk *next;
    DWORD length;
    unsigned char bytes[];
} Chunk;

typedef struct {
    SRWLOCK lock;
    CONDITION_VARIABLE changed;
    Chunk *head, *tail;
    size_t buffered;
    bool ended, stopping;
    HANDLE thread;
} Input;

static DWORD WINAPI input_main(void *context)
{
    Input *input = context;
    for (;;) {
        Chunk *chunk = malloc(sizeof(Chunk) + CHUNK_CAPACITY);
        DWORD count = 0;
        if (!chunk || !ReadFile(GetStdHandle(STD_INPUT_HANDLE), chunk->bytes, CHUNK_CAPACITY, &count, NULL) || !count) {
            free(chunk);
            break;
        }
        Chunk *shrunk = realloc(chunk, sizeof(Chunk) + count);
        if (shrunk) chunk = shrunk;
        chunk->next = NULL;
        chunk->length = count;
        AcquireSRWLockExclusive(&input->lock);
        while (!input->stopping && input->buffered + count > HELPER_MAXIMUM_BUFFERED_BYTE_COUNT)
            SleepConditionVariableSRW(&input->changed, &input->lock, INFINITE, 0);
        if (input->stopping) {
            ReleaseSRWLockExclusive(&input->lock);
            free(chunk);
            break;
        }
        if (input->tail) input->tail->next = chunk;
        else input->head = chunk;
        input->tail = chunk;
        input->buffered += count;
        WakeAllConditionVariable(&input->changed);
        ReleaseSRWLockExclusive(&input->lock);
    }
    AcquireSRWLockExclusive(&input->lock);
    input->ended = true;
    WakeAllConditionVariable(&input->changed);
    ReleaseSRWLockExclusive(&input->lock);
    return 0;
}

static bool input_start(Input *input)
{
    *input = (Input){0};
    InitializeSRWLock(&input->lock);
    InitializeConditionVariable(&input->changed);
    input->thread = CreateThread(NULL, 0, input_main, input, 0, NULL);
    return input->thread != NULL;
}

/* Returns a chunk, or NULL with *ended set when no chunk arrived within a second. */
static Chunk *input_next(Input *input, bool *ended)
{
    AcquireSRWLockExclusive(&input->lock);
    if (!input->ended && !input->head) SleepConditionVariableSRW(&input->changed, &input->lock, 1000, 0);
    Chunk *chunk = input->head;
    if (chunk) {
        input->head = chunk->next;
        if (!input->head) input->tail = NULL;
        input->buffered -= chunk->length;
        WakeAllConditionVariable(&input->changed);
    }
    *ended = !chunk && input->ended;
    ReleaseSRWLockExclusive(&input->lock);
    return chunk;
}

static void input_stop(Input *input)
{
    AcquireSRWLockExclusive(&input->lock);
    input->stopping = true;
    WakeAllConditionVariable(&input->changed);
    while (!input->ended) {
        ReleaseSRWLockExclusive(&input->lock);
        CancelSynchronousIo(input->thread);
        AcquireSRWLockExclusive(&input->lock);
        if (!input->ended) SleepConditionVariableSRW(&input->changed, &input->lock, 20, 0);
    }
    ReleaseSRWLockExclusive(&input->lock);
    WaitForSingleObject(input->thread, INFINITE);
    CloseHandle(input->thread);
    for (Chunk *chunk = input->head; chunk;) {
        Chunk *next = chunk->next;
        free(chunk);
        chunk = next;
    }
}

static bool transfer(HANDLE pipe, HANDLE stop, void *bytes, DWORD size, bool write, DWORD *count, OuterError *error)
{
    *count = 0;
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!event) return outer_error_set(error, "Could not create I/O event.");
    OVERLAPPED operation = {0};
    operation.hEvent = event;
    BOOL ok = write ? WriteFile(pipe, bytes, size, count, &operation) : ReadFile(pipe, bytes, size, count, &operation);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        HANDLE events[] = {event, stop};
        if (WaitForMultipleObjects(2, events, FALSE, write ? 30000 : INFINITE) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &operation);
            GetOverlappedResult(pipe, &operation, count, TRUE);
            CloseHandle(event);
            return outer_error_set(error, "Pipe operation cancelled or timed out.");
        }
        ok = GetOverlappedResult(pipe, &operation, count, FALSE);
    }
    DWORD failure = ok ? 0 : GetLastError();
    CloseHandle(event);
    if (ok) return true;
    *count = 0;
    if (!write && (failure == ERROR_BROKEN_PIPE || failure == ERROR_PIPE_NOT_CONNECTED)) return true;
    return outer_error_set(error, "Pipe I/O failed (Windows error %lu).", failure);
}

typedef struct {
    uint32_t id;
    HANDLE pipe, stop, thread;
    volatile LONG done;
    bool input_ended;
} Stream;

static DWORD WINAPI stream_main(void *context)
{
    Stream *stream = context;
    unsigned char bytes[CHUNK_CAPACITY];
    OuterError error;
    DWORD count = 0;
    bool ok;
    for (;;) {
        ok = transfer(stream->pipe, stream->stop, bytes, sizeof(bytes), false, &count, &error);
        if (!ok || !count) break;
        if (!output(HELPER_FRAME_DATA, stream->id, bytes, count, stream->stop)) {
            ok = false;
            break;
        }
    }
    bool sent = ok && output(HELPER_FRAME_EOF, stream->id, NULL, 0, stream->stop) &&
        output(HELPER_FRAME_CLOSE, stream->id, NULL, 0, stream->stop);
    if (!sent) output(HELPER_FRAME_CLOSE, stream->id, NULL, 0, stream->stop);
    InterlockedExchange(&stream->done, 1);
    return 0;
}

static void stream_destroy(Stream *stream)
{
    SetEvent(stream->stop);
    CancelIoEx(stream->pipe, NULL);
    if (stream->thread) {
        while (!InterlockedCompareExchange(&stream->done, 0, 0)) {
            CancelSynchronousIo(stream->thread);
            Sleep(20);
        }
        WaitForSingleObject(stream->thread, INFINITE);
        CloseHandle(stream->thread);
    }
    CloseHandle(stream->stop);
    CloseHandle(stream->pipe);
    free(stream);
}

static bool stream_write(Stream *stream, const unsigned char *bytes, size_t size)
{
    if (stream->input_ended) return false;
    while (size) {
        DWORD count = 0;
        if (!transfer(stream->pipe, stream->stop, (void *)bytes, (DWORD)size, true, &count, NULL) || !count) return false;
        bytes += count;
        size -= count;
    }
    return true;
}

typedef struct {
    uint32_t id;
    char path[OUTER_PIPE_PATH_CAPACITY];
    unsigned char state;
} Watch;

static bool update_watches(Watch *watches, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        Watch *watch = &watches[i];
        wchar_t name[OUTER_PIPE_PATH_CAPACITY];
        for (size_t j = 0;; j++) {
            name[j] = (unsigned char)watch->path[j];
            if (!watch->path[j]) break;
        }
        unsigned char state = 2;
        if (WaitNamedPipeW(name, 1)) state = 1;
        else {
            DWORD failure = GetLastError();
            if (failure == ERROR_SEM_TIMEOUT || failure == ERROR_PIPE_BUSY) state = 1;
            else if (failure == ERROR_FILE_NOT_FOUND || failure == ERROR_PATH_NOT_FOUND) state = 0;
        }
        if (state == 1 && !outer_named_pipe_authorize(watch->path, allowlist, NULL)) state = 2;
        if (state != watch->state) {
            if (!output(HELPER_FRAME_SOCKET_STATE, watch->id, &state, 1, NULL)) return false;
            watch->state = state;
        }
    }
    return true;
}

static bool send_endpoint_names(uint32_t id, HANDLE stop)
{
    unsigned char *bytes = NULL;
    size_t length = 0;
    OuterError error;
    if (outer_endpoint_names_read(&bytes, &length, &error)) {
        bool sent = output(HELPER_FRAME_ENDPOINT_NAMES, id, bytes, length, stop);
        free(bytes);
        return sent;
    }
    if (id) return output(HELPER_FRAME_RESULT, id, error.text, strlen(error.text), stop);
    return output(HELPER_FRAME_ENDPOINT_NAMES_CHANGED, 0, NULL, 0, stop);
}

typedef struct {
    HANDLE stop, thread;
    OuterEndpointNamesWatch watch;
} NamesWatch;

static DWORD WINAPI names_watch_main(void *context)
{
    NamesWatch *names = context;
    OuterError error;
    bool ok = send_endpoint_names(0, names->stop);
    if (!ok) outer_error_set(&error, "SSH output closed.");
    while (ok) {
        HANDLE events[MAXIMUM_WAIT_OBJECTS];
        events[0] = names->stop;
        memcpy(events + 1, names->watch.handles, names->watch.count * sizeof(HANDLE));
        DWORD result = WaitForMultipleObjects(names->watch.count + 1, events, FALSE, INFINITE);
        if (result == WAIT_OBJECT_0) return 0;
        if (result == WAIT_FAILED) ok = outer_error_set(&error, "Endpoint registration watch failed.");
        else if (!outer_endpoint_names_watch_reset(&names->watch, &error)) ok = false;
        else if (!send_endpoint_names(0, names->stop)) ok = outer_error_set(&error, "SSH output closed.");
    }
    if (!stopped(names->stop)) {
        write_line(STD_ERROR_HANDLE, error.text);
        ExitProcess(1);
    }
    return 0;
}

static NamesWatch *names_watch_start(OuterError *error)
{
    NamesWatch *names = calloc(1, sizeof(NamesWatch));
    if (!names) {
        outer_error_set(error, "Out of memory.");
        return NULL;
    }
    names->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!names->stop) {
        free(names);
        outer_error_set(error, "Could not create endpoint watch cancellation event.");
        return NULL;
    }
    if (outer_endpoint_names_watch_reset(&names->watch, error)) {
        names->thread = CreateThread(NULL, 0, names_watch_main, names, 0, NULL);
        if (names->thread) return names;
        outer_error_set(error, "Could not start the endpoint registration watch.");
    }
    outer_endpoint_names_watch_clear(&names->watch);
    CloseHandle(names->stop);
    free(names);
    return NULL;
}

static void names_watch_stop(NamesWatch *names)
{
    if (!names) return;
    SetEvent(names->stop);
    WaitForSingleObject(names->thread, INFINITE);
    CloseHandle(names->thread);
    outer_endpoint_names_watch_clear(&names->watch);
    CloseHandle(names->stop);
    free(names);
}

static Stream *find_stream(Stream **streams, size_t count, uint32_t id, size_t *index)
{
    for (size_t i = 0; i < count; i++) {
        if (streams[i]->id == id) {
            if (index) *index = i;
            return streams[i];
        }
    }
    return NULL;
}

static void remove_stream(Stream **streams, size_t *count, size_t index)
{
    stream_destroy(streams[index]);
    streams[index] = streams[--*count];
}

static Watch *find_watch(Watch *watches, size_t count, uint32_t id, size_t *index)
{
    for (size_t i = 0; i < count; i++) {
        if (watches[i].id == id) {
            if (index) *index = i;
            return &watches[i];
        }
    }
    return NULL;
}

static Stream *open_stream(uint32_t id, const char *path, OuterError *error, bool *not_listening)
{
    HANDLE pipe = outer_named_pipe_open(path, allowlist, error, not_listening);
    if (!pipe) return NULL;
    Stream *stream = calloc(1, sizeof(Stream));
    HANDLE stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stream || !stop) {
        free(stream);
        if (stop) CloseHandle(stop);
        CloseHandle(pipe);
        outer_error_set(error, "Could not create cancellation event.");
        return NULL;
    }
    stream->id = id;
    stream->pipe = pipe;
    stream->stop = stop;
    return stream;
}

/* STORE carries an endpoint record line, a NUL and the PNG; GET carries the
 * line. GET replies with ENDPOINT_ICON, empty when there is no icon. */
static bool handle_endpoint_icon(const HelperFrame *frame)
{
    bool store = frame->type == HELPER_FRAME_STORE_ENDPOINT_ICON;
    const unsigned char *end = memchr(frame->payload, 0, frame->payload_length);
    size_t line_length = end ? (size_t)(end - frame->payload) : frame->payload_length;
    char *line = store == (end != NULL) && line_length > 0 ? malloc(line_length + 1) : NULL;
    const char *transport, *address;
    uint16_t port;
    OuterError error = {{0}};
    if (line) {
        memcpy(line, frame->payload, line_length);
        line[line_length] = 0;
    }
    if (!line || !outersshpriv_endpoint_record_parse(line, &transport, &address, &port)) {
        outer_error_set(&error, "Invalid endpoint.");
    } else if (store) {
        outer_endpoint_icon_store(transport, address, port, frame->payload + line_length + 1,
            frame->payload_length - line_length - 1, &error);
    } else {
        unsigned char *png = NULL;
        size_t length = 0;
        if (outer_endpoint_icon_read(transport, address, port, &png, &length, &error)) {
            free(line);
            bool sent = output(HELPER_FRAME_ENDPOINT_ICON, frame->stream_id, png, length, NULL);
            free(png);
            return sent;
        }
    }
    free(line);
    return output_text(HELPER_FRAME_RESULT, frame->stream_id, error.text);
}

const wchar_t *outerssh_helper_pipe_allowlist(void)
{
    return allowlist;
}

static bool handle_app_request(const HelperFrame *frame)
{
    char error[512] = "The OuterSSH helper does not support this request.";
    unsigned char *response = NULL;
    size_t length = 0;
    if (request_handler && request_handler(frame->payload, frame->payload_length, &response, &length, error, sizeof(error))) {
        bool sent = length <= HELPER_MAXIMUM_PAYLOAD_LENGTH && output(HELPER_FRAME_APP_RESPONSE, frame->stream_id, response, length, NULL);
        free(response);
        return sent;
    }
    error[sizeof(error) - 1] = 0;
    return output_text(HELPER_FRAME_RESULT, frame->stream_id, error);
}

static bool handle_service_frame(const HelperFrame *frame, Watch *watches, size_t *watch_count)
{
    if (frame->type == HELPER_FRAME_APP_REQUEST) return handle_app_request(frame);
    if ((frame->type == HELPER_FRAME_STORE_ENDPOINT_ICON || frame->type == HELPER_FRAME_GET_ENDPOINT_ICON) &&
        frame->stream_id && frame->payload_length)
        return handle_endpoint_icon(frame);
    if (frame->type == HELPER_FRAME_GET_ENDPOINT_NAMES && !frame->payload_length)
        return send_endpoint_names(frame->stream_id, NULL);
    if (frame->type == HELPER_FRAME_UNWATCH && !frame->payload_length) {
        size_t index = 0;
        if (find_watch(watches, *watch_count, frame->stream_id, &index)) watches[index] = watches[--*watch_count];
        return true;
    }
    if ((frame->type != HELPER_FRAME_AUTHORIZE && frame->type != HELPER_FRAME_WATCH) ||
        !frame->payload_length || frame->payload_length > 110)
        return output_text(HELPER_FRAME_RESULT, frame->stream_id, "The OuterSSH helper does not support this request.");
    OuterError error;
    char endpoint[OUTER_PIPE_PATH_CAPACITY];
    if (!outer_canonical_pipe_path((const char *)frame->payload, frame->payload_length, endpoint, &error) ||
        !outer_named_pipe_authorize(endpoint, allowlist, &error))
        return output_text(HELPER_FRAME_RESULT, frame->stream_id, error.text);
    if (frame->type == HELPER_FRAME_AUTHORIZE) {
        unsigned char reply[1 + OUTER_SID_CAPACITY];
        bool current_user = false, root = false;
        if (!outer_named_pipe_owner(endpoint, (char *)reply + 1, &current_user, &root, &error))
            return output_text(HELPER_FRAME_RESULT, frame->stream_id, error.text);
        reply[0] = HELPER_CONNECTION_MANAGED | (current_user ? HELPER_PREPARED_SESSION_OWNED : 0) |
            (root ? HELPER_PREPARED_ROOT_OWNED : 0);
        return output(HELPER_FRAME_PREPARED, frame->stream_id, reply, 1 + strlen((char *)reply + 1), NULL);
    }
    if (*watch_count >= MAXIMUM_STREAMS || find_watch(watches, *watch_count, frame->stream_id, NULL))
        return output_text(HELPER_FRAME_RESULT, frame->stream_id, "Watch limit or duplicate watch ID.");
    Watch *watch = &watches[(*watch_count)++];
    watch->id = frame->stream_id;
    strcpy(watch->path, endpoint);
    watch->state = 255;
    return output(HELPER_FRAME_RESULT, frame->stream_id, NULL, 0, NULL);
}

static bool handle_forwarding_frame(const HelperFrame *frame, const char *path, Stream **streams, size_t *stream_count,
    const char **failure)
{
    if (frame->type == HELPER_FRAME_OPEN && !frame->payload_length) {
        if (find_stream(streams, *stream_count, frame->stream_id, NULL)) {
            *failure = "Duplicate stream ID.";
            return false;
        }
        if (*stream_count >= MAXIMUM_STREAMS)
            return output_text(HELPER_FRAME_OPEN_ERROR, frame->stream_id, "Stream limit exceeded.");
        OuterError error;
        bool not_listening;
        Stream *stream = open_stream(frame->stream_id, path, &error, &not_listening);
        if (!stream) return output_text(not_listening ? HELPER_FRAME_OPEN_NOT_LISTENING : HELPER_FRAME_OPEN_ERROR,
            frame->stream_id, error.text);
        if (!output(HELPER_FRAME_OPEN_OK, frame->stream_id, NULL, 0, NULL)) {
            stream_destroy(stream);
            return false;
        }
        stream->thread = CreateThread(NULL, 0, stream_main, stream, 0, NULL);
        if (!stream->thread) {
            stream_destroy(stream);
            return output(HELPER_FRAME_CLOSE, frame->stream_id, NULL, 0, NULL);
        }
        streams[(*stream_count)++] = stream;
        return true;
    }
    if (frame->type == HELPER_FRAME_CLOSE && !frame->payload_length) {
        size_t index = 0;
        if (find_stream(streams, *stream_count, frame->stream_id, &index)) remove_stream(streams, stream_count, index);
        return true;
    }
    if (frame->type == HELPER_FRAME_DATA || (frame->type == HELPER_FRAME_EOF && !frame->payload_length)) {
        size_t index = 0;
        Stream *stream = find_stream(streams, *stream_count, frame->stream_id, &index);
        if (!stream) return true;
        if (frame->type == HELPER_FRAME_EOF) {
            stream->input_ended = true;
            return true;
        }
        if (stream_write(stream, frame->payload, frame->payload_length)) return true;
        bool sent = output(HELPER_FRAME_CLOSE, frame->stream_id, NULL, 0, NULL);
        remove_stream(streams, stream_count, index);
        return sent;
    }
    *failure = "Invalid forwarding request.";
    return false;
}

static int run(bool service, const char *path)
{
    OuterError error;
    if (!service && !outer_named_pipe_authorize(path, allowlist, &error)) {
        write_line(STD_ERROR_HANDLE, error.text);
        return 1;
    }
    if (!output(HELPER_FRAME_HELLO, 0, NULL, 0, NULL)) {
        write_line(STD_ERROR_HANDLE, "SSH output closed.");
        return 1;
    }
    NamesWatch *names = NULL;
    if (service && !(names = names_watch_start(&error))) {
        write_line(STD_ERROR_HANDLE, error.text);
        return 1;
    }
    Input input;
    if (!input_start(&input)) {
        names_watch_stop(names);
        write_line(STD_ERROR_HANDLE, "Could not start the input reader.");
        return 1;
    }
    Stream *streams[MAXIMUM_STREAMS];
    Watch watches[MAXIMUM_STREAMS];
    size_t stream_count = 0, watch_count = 0;
    HelperFrameParser parser = {0};
    const char *failure = NULL;
    ULONGLONG last_input = GetTickCount64();
    for (;;) {
        for (size_t i = 0; i < stream_count;) {
            if (InterlockedCompareExchange(&streams[i]->done, 0, 0)) remove_stream(streams, &stream_count, i);
            else i++;
        }
        if (service && !update_watches(watches, watch_count)) {
            failure = "SSH output closed.";
            break;
        }
        if (GetTickCount64() - last_input > 120000) break;
        bool ended = false;
        Chunk *chunk = input_next(&input, &ended);
        if (!chunk) {
            if (!ended) continue;
            if (outersshpriv_helper_frame_parser_byte_count(&parser)) failure = "Truncated input frame.";
            break;
        }
        last_input = GetTickCount64();
        bool appended = outersshpriv_helper_frame_parser_append(&parser, chunk->bytes, chunk->length);
        free(chunk);
        if (!appended) {
            failure = "Input buffer exceeded.";
            break;
        }
        for (;;) {
            HelperFrame frame = {0};
            uint32_t invalid = 0;
            HelperParseResult status = outersshpriv_helper_frame_parser_peek(&parser, &frame, &invalid);
            if (status == HELPER_PARSE_NEEDS_DATA) break;
            bool ok;
            if (status != HELPER_PARSE_FRAME_AVAILABLE) {
                failure = "Invalid bridge frame.";
                ok = false;
            } else if (frame.type == HELPER_FRAME_PING) {
                ok = output(HELPER_FRAME_PONG, frame.stream_id, frame.payload, frame.payload_length, NULL);
            } else if (!frame.stream_id) {
                failure = service ? NULL : "Expected a nonzero stream ID.";
                ok = service;
            } else if (service) {
                ok = handle_service_frame(&frame, watches, &watch_count);
            } else {
                ok = handle_forwarding_frame(&frame, path, streams, &stream_count, &failure);
            }
            if (!ok) {
                if (!failure) failure = "SSH output closed.";
                goto done;
            }
            outersshpriv_helper_frame_parser_consume(&parser);
        }
    }
done:
    outersshpriv_helper_frame_parser_deinitialize(&parser);
    while (stream_count) remove_stream(streams, &stream_count, stream_count - 1);
    input_stop(&input);
    names_watch_stop(names);
    if (failure) {
        write_line(STD_ERROR_HANDLE, failure);
        return 1;
    }
    return 0;
}

int outerssh_helper_main(int argc, wchar_t **argv, OuterSSHHelperRequestHandler handler)
{
    OuterError error;
    request_handler = handler;
    output_lock = CreateMutexW(NULL, FALSE, NULL);
    if (!output_lock) {
        write_line(STD_ERROR_HANDLE, "Could not create the output lock.");
        return 1;
    }
    if (!outer_pipe_allowlist_path(allowlist, &error)) {
        write_line(STD_ERROR_HANDLE, error.text);
        return 1;
    }
    if (argc >= 3 && !wcscmp(argv[1], L"--user-allowlist")) {
        if (wcslen(argv[2]) >= OUTER_PATH_CAPACITY) {
            write_line(STD_ERROR_HANDLE, "The allowlist path is too long.");
            return 1;
        }
        wcscpy(allowlist, argv[2]);
        argc -= 2;
        argv += 2;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--version")) {
        write_line(STD_OUTPUT_HANDLE, "outerssh-helper 1 windows");
        return 0;
    }
    if (argc == 2 && !wcscmp(argv[1], L"service")) return run(true, NULL);
    if (argc == 4 && !wcscmp(argv[1], L"bridge") && !wcscmp(argv[2], L"--socket")) {
        char text[OUTER_PIPE_PATH_CAPACITY * 4], path[OUTER_PIPE_PATH_CAPACITY];
        int count = WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, text, sizeof(text), NULL, NULL);
        if (count <= 0) outer_error_set(&error, "Enter a local named pipe path beginning with \\\\.\\pipe\\.");
        if (count <= 0 || !outer_canonical_pipe_path(text, (size_t)count - 1, path, &error)) {
            write_line(STD_ERROR_HANDLE, error.text);
            return 1;
        }
        return run(false, path);
    }
    write_line(STD_ERROR_HANDLE, "Usage: outerssh-helper service | bridge --socket PIPE | --version");
    return 1;
}

#ifdef OUTERSSH_HELPER_ENTRY
void __cdecl __security_init_cookie(void);
int wmain(int argc, wchar_t **argv);

DWORD WINAPI outerssh_helper_entry(void)
{
    __security_init_cookie();
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    ExitProcess(argv ? (UINT)wmain(argc, argv) : 1);
}
#endif
