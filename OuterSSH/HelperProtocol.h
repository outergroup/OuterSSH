#ifndef HELPER_PROTOCOL_H
#define HELPER_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    HELPER_FRAME_HEADER_LENGTH = 16,
    HELPER_MAXIMUM_PAYLOAD_LENGTH = 1024 * 1024,
    HELPER_MAXIMUM_BUFFERED_BYTE_COUNT = 4 * 1024 * 1024
};

/* Service mode uses stream_id as a nonzero request/watch ID. AUTHORIZE and
 * WATCH carry endpoint bytes. AUTHORIZE succeeds with PREPARED: a byte holding
 * the connection mode and owner flags, then the endpoint owner's identity (a
 * Unix uid in decimal or a Windows SID), empty when the owner is not known yet.
 * HELPER_PREPARED_SESSION_OWNED marks the SSH user's own endpoint when that user
 * is not root; HELPER_PREPARED_ROOT_OWNED marks root, SYSTEM or Administrators.
 * RESULT contains an error or an empty WATCH success.
 * SOCKET_STATE carries one byte: 0 absent, 1 present, 2 unknown. The helper
 * sends it when the state changes, and sends present again when a present
 * socket is replaced by a new one. UNWATCH has no payload. HELLO and PING/PONG
 * are shared with forwarding mode. */
/* In forwarding mode, OPEN completes with OPEN_OK, or fails with OPEN_ERROR or,
 * when nothing is listening at the endpoint (it is missing or refuses
 * connections), OPEN_NOT_LISTENING. Both failures carry error text. A bridge
 * that cannot start because nothing is listening writes
 * HELPER_NOT_LISTENING_MESSAGE to stderr. */
/* ENDPOINT_NAMES carries a validated snapshot: ID zero is a push, nonzero
 * replies to GET_ENDPOINT_NAMES. ENDPOINT_NAMES_CHANGED (ID zero, empty) clears
 * an unreadable snapshot; GET then returns RESULT with the read error. */
/* STORE_ENDPOINT_ICON carries an endpoint record line, a NUL, and a PNG; it
 * completes with RESULT. GET_ENDPOINT_ICON carries the line and completes with
 * ENDPOINT_ICON, whose payload is the PNG or empty when none is cached, or
 * with RESULT containing an error. */
/* APP_REQUEST carries bytes for the application's request handler and
 * completes with APP_RESPONSE, or with RESULT containing an error. The helper
 * answers any other request it does not support with a RESULT error, and
 * ignores unsupported frames with ID zero. */

typedef enum {
    HELPER_FRAME_HELLO = 1,
    HELPER_FRAME_OPEN = 2,
    HELPER_FRAME_OPEN_OK = 3,
    HELPER_FRAME_OPEN_ERROR = 4,
    HELPER_FRAME_DATA = 5,
    HELPER_FRAME_EOF = 6,
    HELPER_FRAME_CLOSE = 7,
    HELPER_FRAME_PING = 8,
    HELPER_FRAME_PONG = 9,
    HELPER_FRAME_SOCKET_STATE = 10,
    HELPER_FRAME_AUTHORIZE = 11,
    HELPER_FRAME_RESULT = 12,
    HELPER_FRAME_WATCH = 13,
    HELPER_FRAME_UNWATCH = 14,
    HELPER_FRAME_PREPARED = 15,
    HELPER_FRAME_ENDPOINT_NAMES = 16,
    HELPER_FRAME_GET_ENDPOINT_NAMES = 17,
    HELPER_FRAME_ENDPOINT_NAMES_CHANGED = 18,
    HELPER_FRAME_STORE_ENDPOINT_ICON = 19,
    HELPER_FRAME_GET_ENDPOINT_ICON = 20,
    HELPER_FRAME_ENDPOINT_ICON = 21,
    HELPER_FRAME_APP_REQUEST = 22,
    HELPER_FRAME_APP_RESPONSE = 23,
    HELPER_FRAME_OPEN_NOT_LISTENING = 24
} HelperFrameType;

#define HELPER_NOT_LISTENING_MESSAGE "Nothing is listening at the socket."

typedef enum {
    HELPER_CONNECTION_DIRECT = 0,
    HELPER_CONNECTION_MANAGED = 1,
    HELPER_CONNECTION_PRIVILEGED = 2
} HelperConnectionMode;

enum {
    HELPER_PREPARED_MODE_MASK = 0x03,
    HELPER_PREPARED_SESSION_OWNED = 0x40,
    HELPER_PREPARED_ROOT_OWNED = 0x80,
    HELPER_OWNER_CAPACITY = 192
};

static inline bool outersshpriv_helper_owner_is_valid(const unsigned char *owner, size_t length)
{
    if (length >= HELPER_OWNER_CAPACITY) return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = owner[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-')) return false;
    }
    return true;
}

typedef enum {
    HELPER_PARSE_FRAME_AVAILABLE,
    HELPER_PARSE_NEEDS_DATA,
    HELPER_PARSE_INVALID_MAGIC,
    HELPER_PARSE_UNSUPPORTED_VERSION,
    HELPER_PARSE_PAYLOAD_TOO_LARGE,
    HELPER_PARSE_ALLOCATION_FAILED
} HelperParseResult;

typedef struct {
    HelperFrameType type;
    uint32_t stream_id;
    const unsigned char *payload;
    size_t payload_length;
} HelperFrame;

typedef struct {
    unsigned char *bytes;
    size_t byte_count;
    size_t capacity;
    size_t pending_frame_length;
} HelperFrameParser;

void outersshpriv_helper_frame_parser_deinitialize(
    HelperFrameParser *parser);

/* Returns false for invalid input, a pending frame, buffer limit, or OOM. */
bool outersshpriv_helper_frame_parser_append(
    HelperFrameParser *parser,
    const void *bytes,
    size_t byte_count);
size_t outersshpriv_helper_frame_parser_byte_count(
    const HelperFrameParser *parser);

/* The returned payload remains valid until consume or append is called. */
HelperParseResult outersshpriv_helper_frame_parser_peek(
    HelperFrameParser *parser,
    HelperFrame *frame,
    uint32_t *invalid_value);

void outersshpriv_helper_frame_parser_consume(
    HelperFrameParser *parser);

bool outersshpriv_helper_encode_header(
    HelperFrameType type,
    uint32_t stream_id,
    size_t payload_length,
    unsigned char header[HELPER_FRAME_HEADER_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
