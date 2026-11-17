#include "HelperProtocol.h"

#include <stdlib.h>
#include <string.h>

static const uint32_t FrameMagic = 0x3142524f;
static const uint16_t ProtocolVersion = 1;

static bool reserve_bytes(
    HelperFrameParser *parser,
    size_t minimum_capacity);
static uint16_t read_uint16(const unsigned char *bytes);
static uint32_t read_uint32(const unsigned char *bytes);
static void write_uint16(unsigned char *bytes, uint16_t value);
static void write_uint32(unsigned char *bytes, uint32_t value);

#pragma mark - Buffer and Parse Frames

bool outersshpriv_helper_frame_parser_append(
    HelperFrameParser *parser,
    const void *bytes,
    size_t byte_count)
{
    if (parser->pending_frame_length != 0 ||
        (byte_count != 0 && bytes == NULL) ||
        byte_count > HELPER_MAXIMUM_BUFFERED_BYTE_COUNT -
            parser->byte_count) {
        return false;
    }
    size_t required_capacity = parser->byte_count + byte_count;
    if (!reserve_bytes(parser, required_capacity)) {
        return false;
    }
    if (byte_count != 0) {
        memcpy(parser->bytes + parser->byte_count, bytes, byte_count);
        parser->byte_count += byte_count;
    }
    return true;
}

static bool reserve_bytes(
    HelperFrameParser *parser,
    size_t minimum_capacity)
{
    if (parser->capacity >= minimum_capacity) {
        return true;
    }
    size_t capacity = parser->capacity == 0 ? 4096 : parser->capacity;
    while (capacity < minimum_capacity) {
        if (capacity > SIZE_MAX / 2) {
            return false;
        }
        capacity *= 2;
    }
    unsigned char *bytes = realloc(parser->bytes, capacity);
    if (bytes == NULL) {
        return false;
    }
    parser->bytes = bytes;
    parser->capacity = capacity;
    return true;
}

size_t outersshpriv_helper_frame_parser_byte_count(
    const HelperFrameParser *parser)
{
    return parser->byte_count;
}

HelperParseResult outersshpriv_helper_frame_parser_peek(
    HelperFrameParser *parser,
    HelperFrame *frame,
    uint32_t *invalid_value)
{
    if (frame == NULL) {
        return HELPER_PARSE_ALLOCATION_FAILED;
    }
    if (invalid_value != NULL) {
        *invalid_value = 0;
    }
    *frame = (HelperFrame){0};
    if (parser->pending_frame_length != 0) {
        size_t payload_length =
            parser->pending_frame_length - HELPER_FRAME_HEADER_LENGTH;
        frame->type = (HelperFrameType)read_uint16(parser->bytes + 6);
        frame->stream_id = read_uint32(parser->bytes + 8);
        frame->payload = payload_length == 0
            ? NULL
            : parser->bytes + HELPER_FRAME_HEADER_LENGTH;
        frame->payload_length = payload_length;
        return HELPER_PARSE_FRAME_AVAILABLE;
    }
    if (parser->byte_count < HELPER_FRAME_HEADER_LENGTH) {
        return HELPER_PARSE_NEEDS_DATA;
    }

    uint32_t magic = read_uint32(parser->bytes);
    if (magic != FrameMagic) {
        if (invalid_value != NULL) {
            *invalid_value = magic;
        }
        return HELPER_PARSE_INVALID_MAGIC;
    }
    uint16_t version = read_uint16(parser->bytes + 4);
    if (version != ProtocolVersion) {
        if (invalid_value != NULL) {
            *invalid_value = version;
        }
        return HELPER_PARSE_UNSUPPORTED_VERSION;
    }
    uint16_t raw_type = read_uint16(parser->bytes + 6);
    uint32_t payload_length = read_uint32(parser->bytes + 12);
    if (payload_length > HELPER_MAXIMUM_PAYLOAD_LENGTH) {
        if (invalid_value != NULL) {
            *invalid_value = payload_length;
        }
        return HELPER_PARSE_PAYLOAD_TOO_LARGE;
    }
    size_t frame_length =
        HELPER_FRAME_HEADER_LENGTH + (size_t)payload_length;
    if (parser->byte_count < frame_length) {
        return HELPER_PARSE_NEEDS_DATA;
    }

    parser->pending_frame_length = frame_length;
    frame->type = (HelperFrameType)raw_type;
    frame->stream_id = read_uint32(parser->bytes + 8);
    frame->payload = payload_length == 0
        ? NULL
        : parser->bytes + HELPER_FRAME_HEADER_LENGTH;
    frame->payload_length = payload_length;
    return HELPER_PARSE_FRAME_AVAILABLE;
}

static uint16_t read_uint16(const unsigned char *bytes)
{
    return (uint16_t)bytes[0] |
        ((uint16_t)bytes[1] << 8);
}

static uint32_t read_uint32(const unsigned char *bytes)
{
    return (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

void outersshpriv_helper_frame_parser_consume(
    HelperFrameParser *parser)
{
    if (parser->pending_frame_length == 0) {
        return;
    }
    size_t remaining = parser->byte_count - parser->pending_frame_length;
    if (remaining != 0) {
        memmove(
            parser->bytes,
            parser->bytes + parser->pending_frame_length,
            remaining);
    }
    parser->byte_count = remaining;
    parser->pending_frame_length = 0;
}

void outersshpriv_helper_frame_parser_deinitialize(
    HelperFrameParser *parser)
{
    free(parser->bytes);
    *parser = (HelperFrameParser){0};
}

#pragma mark - Encode Frame Headers

bool outersshpriv_helper_encode_header(
    HelperFrameType type,
    uint32_t stream_id,
    size_t payload_length,
    unsigned char header[HELPER_FRAME_HEADER_LENGTH])
{
    if (type < HELPER_FRAME_HELLO || type > HELPER_FRAME_APP_RESPONSE ||
        payload_length > HELPER_MAXIMUM_PAYLOAD_LENGTH ||
        header == NULL) {
        return false;
    }
    write_uint32(header, FrameMagic);
    write_uint16(header + 4, ProtocolVersion);
    write_uint16(header + 6, (uint16_t)type);
    write_uint32(header + 8, stream_id);
    write_uint32(header + 12, (uint32_t)payload_length);
    return true;
}

static void write_uint16(unsigned char *bytes, uint16_t value)
{
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
}

static void write_uint32(unsigned char *bytes, uint32_t value)
{
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
}
