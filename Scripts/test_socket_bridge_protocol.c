#include "../OuterSSH/HelperProtocol.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void test_incremental_and_concatenated_frames(void)
{
    unsigned char first[HELPER_FRAME_HEADER_LENGTH + 3];
    assert(outersshpriv_helper_encode_header(
        HELPER_FRAME_DATA,
        42,
        3,
        first));
    memcpy(first + HELPER_FRAME_HEADER_LENGTH, "abc", 3);

    unsigned char second[HELPER_FRAME_HEADER_LENGTH];
    assert(outersshpriv_helper_encode_header(
        HELPER_FRAME_EOF,
        42,
        0,
        second));

    HelperFrameParser parser = {0};
    assert(outersshpriv_helper_frame_parser_append(&parser, first, 7));
    HelperFrame frame = {0};
    uint32_t invalid_value = 0;
    assert(outersshpriv_helper_frame_parser_peek(
        &parser,
        &frame,
        &invalid_value) == HELPER_PARSE_NEEDS_DATA);

    unsigned char tail[sizeof(first) - 7 + sizeof(second)];
    memcpy(tail, first + 7, sizeof(first) - 7);
    memcpy(tail + sizeof(first) - 7, second, sizeof(second));
    assert(outersshpriv_helper_frame_parser_append(
        &parser,
        tail,
        sizeof(tail)));
    assert(outersshpriv_helper_frame_parser_peek(
        &parser,
        &frame,
        &invalid_value) == HELPER_PARSE_FRAME_AVAILABLE);
    assert(frame.type == HELPER_FRAME_DATA);
    assert(frame.stream_id == 42);
    assert(frame.payload_length == 3);
    assert(memcmp(frame.payload, "abc", 3) == 0);
    assert(!outersshpriv_helper_frame_parser_append(&parser, "x", 1));
    outersshpriv_helper_frame_parser_consume(&parser);

    assert(outersshpriv_helper_frame_parser_peek(
        &parser,
        &frame,
        &invalid_value) == HELPER_PARSE_FRAME_AVAILABLE);
    assert(frame.type == HELPER_FRAME_EOF);
    assert(frame.stream_id == 42);
    assert(frame.payload == NULL);
    assert(frame.payload_length == 0);
    outersshpriv_helper_frame_parser_consume(&parser);
    assert(outersshpriv_helper_frame_parser_byte_count(&parser) == 0);
    outersshpriv_helper_frame_parser_deinitialize(&parser);
}

static HelperParseResult parse_header(
    const unsigned char header[HELPER_FRAME_HEADER_LENGTH],
    uint32_t *invalid_value)
{
    HelperFrameParser parser = {0};
    assert(outersshpriv_helper_frame_parser_append(
        &parser,
        header,
        HELPER_FRAME_HEADER_LENGTH));
    HelperFrame frame = {0};
    HelperParseResult result =
        outersshpriv_helper_frame_parser_peek(
            &parser,
            &frame,
            invalid_value);
    outersshpriv_helper_frame_parser_deinitialize(&parser);
    return result;
}

static void test_header_rejections(void)
{
    unsigned char header[HELPER_FRAME_HEADER_LENGTH];
    assert(!outersshpriv_helper_encode_header(
        (HelperFrameType)0,
        0,
        0,
        header));
    assert(!outersshpriv_helper_encode_header(
        HELPER_FRAME_DATA,
        0,
        HELPER_MAXIMUM_PAYLOAD_LENGTH + 1,
        header));
    assert(!outersshpriv_helper_encode_header(
        HELPER_FRAME_DATA,
        0,
        0,
        NULL));

    assert(outersshpriv_helper_encode_header(
        HELPER_FRAME_HELLO,
        0,
        0,
        header));
    uint32_t invalid_value = 0;
    header[0] ^= 0xff;
    assert(parse_header(header, &invalid_value) ==
           HELPER_PARSE_INVALID_MAGIC);
    header[0] ^= 0xff;

    header[4] = 2;
    header[5] = 0;
    assert(parse_header(header, &invalid_value) ==
           HELPER_PARSE_UNSUPPORTED_VERSION);
    header[4] = 1;

    header[6] = 0xff;
    header[7] = 0xff;
    assert(parse_header(header, &invalid_value) ==
           HELPER_PARSE_FRAME_AVAILABLE);
    header[6] = HELPER_FRAME_DATA;
    header[7] = 0;

    uint32_t oversized = HELPER_MAXIMUM_PAYLOAD_LENGTH + 1;
    header[12] = (unsigned char)oversized;
    header[13] = (unsigned char)(oversized >> 8);
    header[14] = (unsigned char)(oversized >> 16);
    header[15] = (unsigned char)(oversized >> 24);
    assert(parse_header(header, &invalid_value) ==
           HELPER_PARSE_PAYLOAD_TOO_LARGE);
}

static void test_maximum_payload(void)
{
    const size_t payload_length =
        HELPER_MAXIMUM_PAYLOAD_LENGTH;
    const size_t frame_length =
        HELPER_FRAME_HEADER_LENGTH + payload_length;
    unsigned char *bytes = malloc(frame_length);
    assert(bytes != NULL);
    assert(outersshpriv_helper_encode_header(
        HELPER_FRAME_DATA,
        UINT32_MAX,
        payload_length,
        bytes));
    memset(
        bytes + HELPER_FRAME_HEADER_LENGTH,
        0xa5,
        payload_length);

    HelperFrameParser parser = {0};
    assert(outersshpriv_helper_frame_parser_append(
        &parser,
        bytes,
        frame_length - 1));
    HelperFrame frame = {0};
    assert(outersshpriv_helper_frame_parser_peek(
        &parser,
        &frame,
        NULL) == HELPER_PARSE_NEEDS_DATA);
    assert(outersshpriv_helper_frame_parser_append(
        &parser,
        bytes + frame_length - 1,
        1));
    assert(outersshpriv_helper_frame_parser_peek(
        &parser,
        &frame,
        NULL) == HELPER_PARSE_FRAME_AVAILABLE);
    assert(frame.stream_id == UINT32_MAX);
    assert(frame.payload_length == payload_length);
    assert(frame.payload[0] == 0xa5);
    assert(frame.payload[payload_length - 1] == 0xa5);
    outersshpriv_helper_frame_parser_consume(&parser);
    outersshpriv_helper_frame_parser_deinitialize(&parser);
    free(bytes);
}

static void test_invalid_arguments(void)
{
    HelperFrameParser parser = {0};
    assert(!outersshpriv_helper_frame_parser_append(&parser, NULL, 1));
    assert(outersshpriv_helper_frame_parser_append(&parser, NULL, 0));
    assert(outersshpriv_helper_frame_parser_peek(&parser, NULL, NULL) ==
           HELPER_PARSE_ALLOCATION_FAILED);
    outersshpriv_helper_frame_parser_consume(&parser);
    outersshpriv_helper_frame_parser_deinitialize(&parser);
}

static void test_buffer_limit(void)
{
    unsigned char *bytes = calloc(
        HELPER_MAXIMUM_BUFFERED_BYTE_COUNT,
        1);
    assert(bytes != NULL);
    HelperFrameParser parser = {0};
    assert(outersshpriv_helper_frame_parser_append(
        &parser,
        bytes,
        HELPER_MAXIMUM_BUFFERED_BYTE_COUNT));
    assert(outersshpriv_helper_frame_parser_byte_count(&parser) ==
        HELPER_MAXIMUM_BUFFERED_BYTE_COUNT);
    assert(!outersshpriv_helper_frame_parser_append(&parser, bytes, 1));
    outersshpriv_helper_frame_parser_deinitialize(&parser);
    free(bytes);
}

int main(void)
{
    test_incremental_and_concatenated_frames();
    test_header_rejections();
    test_maximum_payload();
    test_invalid_arguments();
    test_buffer_limit();
    return 0;
}
