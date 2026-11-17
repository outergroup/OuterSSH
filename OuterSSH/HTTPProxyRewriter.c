#include "HTTPProxyRewriter.h"
#include "ProxyReactor.h"
#include "SSHProxyAddress.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *bytes;
    size_t byte_count, capacity;
} ByteBuffer;

struct HTTPProxyRewriter {
    char *target_authority;
    bool rewrite_loopback_urls_in_html;
    ByteBuffer body;
    bool buffering_body, finished_body;
};

static const size_t maximum_rewritable_response_body_length = 2 * 1024 * 1024;
static const size_t maximum_rewritten_response_body_length = 8 * 1024 * 1024;

static bool safe_context_string(const char *string, size_t string_length, size_t maximum_length);
static char *rewrite_url_host(const char *value, bool encode);
static bool is_html(const char *value);
static bool is_identity_encoding(const char *value);
static bool rewrite_loopback_urls_in_body(const ByteBuffer *body, ByteBuffer *output, bool *rewrote);
static bool loopback_url_match_length(const unsigned char *bytes, size_t byte_count, int previous_byte,
    size_t *prefix_length, char *tcp_host, size_t tcp_host_capacity, size_t *tcp_host_length, size_t *port_start,
    size_t *match_length);
static bool header_name_equals(const char *value, const char *expected);
static bool bytes_equal_ignoring_ascii_case(
    const unsigned char *bytes, size_t byte_count, const char *string, size_t string_length);
static bool append_bytes(ByteBuffer *buffer, const void *bytes, size_t byte_count);

#pragma mark - Create the Rewriter

HTTPProxyRewriter *outersshpriv_http_proxy_rewriter_create(const ProxyConnectionRoute *route,
    bool rewrite_request_authorities, bool rewrite_loopback_urls_in_html)
{
    if (route->kind != PROXY_CONNECTION_ROUTE_TCP && route->kind != PROXY_CONNECTION_ROUTE_UNIX_SOCKET) {
        return NULL;
    }
    const char *source_host = route->request.host;
    size_t source_host_length = route->request.host_length;
    if (!safe_context_string(source_host, source_host_length, sizeof(route->request.host) - 1)) {
        return NULL;
    }

    HTTPProxyRewriter *rewriter = calloc(1, sizeof(*rewriter));
    if (rewriter == NULL) {
        return NULL;
    }
    if (rewrite_request_authorities && route->kind == PROXY_CONNECTION_ROUTE_TCP &&
        outersshpriv_proxy_is_tcp_host(source_host, source_host_length)) {
        char target_authority[PROXY_HOST_CAPACITY + 10];
        size_t target_authority_length = 0;
        if (!safe_context_string(route->tcp.host, route->tcp.host_length, sizeof(route->tcp.host) - 1) ||
            !outersshpriv_http_proxy_format_authority(route->tcp.host, route->tcp.host_length, route->tcp.port,
                target_authority, sizeof(target_authority), &target_authority_length) ||
            (rewriter->target_authority = malloc(target_authority_length + 1)) == NULL) {
            outersshpriv_http_proxy_rewriter_destroy(rewriter);
            return NULL;
        }
        memcpy(rewriter->target_authority, target_authority, target_authority_length + 1);
    }

    static const char remote_suffix[] = ".outerssh.localhost";
    size_t hostname_length = source_host_length;
    while (hostname_length > 0 && source_host[hostname_length - 1] == '.') hostname_length--;
    rewriter->rewrite_loopback_urls_in_html = rewrite_loopback_urls_in_html &&
        hostname_length > sizeof(remote_suffix) - 1 &&
        bytes_equal_ignoring_ascii_case(
            (const unsigned char *)source_host + hostname_length - (sizeof(remote_suffix) - 1),
            sizeof(remote_suffix) - 1, remote_suffix, sizeof(remote_suffix) - 1);

    return rewriter;
}

static bool safe_context_string(const char *string, size_t string_length, size_t maximum_length)
{
    if (string == NULL) {
        return false;
    }
    size_t length = string_length;
    if (length > maximum_length) {
        return false;
    }
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = (unsigned char)string[index];
        if (byte < 0x20 || byte == 0x7f) {
            return false;
        }
    }
    return true;
}

bool outersshpriv_http_proxy_format_authority(const char *host, size_t host_length, uint16_t port, char *authority,
    size_t authority_capacity, size_t *authority_length)
{
    if (host == NULL || host_length > INT_MAX || memchr(host, '\0', host_length) != NULL ||
        authority == NULL || authority_capacity == 0) {
        return false;
    }
    bool needs_brackets = memchr(host, ':', host_length) != NULL &&
                          !(host_length >= 2 && host[0] == '[' && host[host_length - 1] == ']');
    int length = snprintf(authority, authority_capacity, needs_brackets ? "[%.*s]:%u" : "%.*s:%u",
        (int)host_length, host, port);
    if (length < 0 || (size_t)length >= authority_capacity) {
        return false;
    }
    if (authority_length != NULL) {
        *authority_length = (size_t)length;
    }
    return true;
}

#pragma mark - Rewrite Headers

bool outersshpriv_http_proxy_rewrite_request_headers(HTTPProxyRewriter *rewriter, const HTTPProxyHeader *headers,
    size_t count, HTTPProxyHeaderOutput output, void *context)
{
    bool accepts_html = false;
    for (size_t i = 0; rewriter->rewrite_loopback_urls_in_html && i < count; i++) {
        if (header_name_equals(headers[i].name, "accept") && is_html(headers[i].value)) accepts_html = true;
    }
    for (size_t i = 0; i < count; i++) {
        const char *name = headers[i].name, *value = headers[i].value;
        if (accepts_html && header_name_equals(name, "accept-encoding")) {
            continue;
        }
        char *rewritten = NULL;
        if (rewriter->target_authority != NULL) {
            if (header_name_equals(name, "host")) {
                value = rewriter->target_authority;
            } else if (header_name_equals(name, "origin") || header_name_equals(name, "referer") ||
                       header_name_equals(name, "sec-websocket-origin")) {
                if ((rewritten = rewrite_url_host(value, false)) == NULL) {
                    return false;
                }
                value = rewritten;
            }
        }
        bool ok = output(context, name, value);
        free(rewritten);
        if (!ok) {
            return false;
        }
    }
    return !accepts_html || output(context, "Accept-Encoding", "identity");
}

bool outersshpriv_http_proxy_rewrite_response_headers(HTTPProxyRewriter *rewriter, const HTTPProxyHeader *headers,
    size_t count, bool has_body, HTTPProxyHeaderOutput output, void *context)
{
    bool html = false, unencoded = true;
    for (size_t i = 0; i < count; i++) {
        const char *name = headers[i].name, *value = headers[i].value;
        char *rewritten = NULL;
        if (rewriter->target_authority != NULL &&
            (header_name_equals(name, "location") || header_name_equals(name, "access-control-allow-origin"))) {
            if ((rewritten = rewrite_url_host(value, true)) == NULL) {
                return false;
            }
            value = rewritten;
        }
        if (rewriter->rewrite_loopback_urls_in_html && header_name_equals(name, "content-type")) {
            html = is_html(value);
        }
        if (rewriter->rewrite_loopback_urls_in_html && header_name_equals(name, "content-encoding") &&
            !is_identity_encoding(value)) {
            unencoded = false;
        }
        bool ok = output(context, name, value);
        free(rewritten);
        if (!ok) {
            return false;
        }
    }
    rewriter->buffering_body = has_body && html && unencoded && rewriter->rewrite_loopback_urls_in_html;
    return true;
}

/* Rewrites the host of the URL at the start of a header value. Decoding turns a
 * .tcp.outerssh.localhost host of any web scheme into its loopback spelling;
 * encoding turns an http or ws loopback host into its .tcp.outerssh.localhost
 * form. Everything else, including the port, is kept. Returns NULL only when
 * memory runs out. */
static char *rewrite_url_host(const char *value, bool encode)
{
    static const char *encoded_schemes[] = {"http", "ws"};
    static const char *decoded_schemes[] = {"http", "https", "ws", "wss"};
    const char **schemes = encode ? encoded_schemes : decoded_schemes;
    size_t scheme_count = encode ? 2 : 4;
    char host[OUTERSSH_PROXY_TCP_HOST_CAPACITY];
    size_t host_length = 0;
    const char *authority = strstr(value, "://");
    bool replace = false;
    for (size_t i = 0; authority != NULL && i < scheme_count && !replace; i++) {
        replace = bytes_equal_ignoring_ascii_case(
            (const unsigned char *)value, (size_t)(authority - value), schemes[i], strlen(schemes[i]));
    }
    size_t original_host_length = 0;
    if (replace) {
        authority += 3;
        size_t authority_length = strcspn(authority, "/?#");
        const char *host_end = authority[0] == '['
            ? memchr(authority, ']', authority_length)
            : memchr(authority, ':', authority_length);
        original_host_length = host_end == NULL ? authority_length
            : (size_t)(host_end - authority) + (authority[0] == '[' ? 1 : 0);
        replace = encode
            ? outerssh_proxy_encode_tcp_host(authority, original_host_length, host, sizeof(host), &host_length)
            : outerssh_proxy_decode_tcp_host(authority, original_host_length, host, sizeof(host), &host_length);
    }
    ByteBuffer result = {0};
    bool ok = replace
        ? append_bytes(&result, value, (size_t)(authority - value)) && append_bytes(&result, host, host_length) &&
              append_bytes(&result, authority + original_host_length, strlen(authority + original_host_length) + 1)
        : append_bytes(&result, value, strlen(value) + 1);
    if (!ok) {
        free(result.bytes);
        return NULL;
    }
    return (char *)result.bytes;
}

static bool is_html(const char *value)
{
    size_t length = strlen(value);
    for (size_t i = 0; i + 9 <= length; i++) {
        if (bytes_equal_ignoring_ascii_case((const unsigned char *)value + i, 9, "text/html", 9)) {
            return true;
        }
    }
    return false;
}

static bool is_identity_encoding(const char *value)
{
    while (*value == ' ' || *value == '\t') {
        value++;
    }
    size_t length = strlen(value);
    while (length && (value[length - 1] == ' ' || value[length - 1] == '\t')) {
        length--;
    }
    return length == 0 ||
           bytes_equal_ignoring_ascii_case((const unsigned char *)value, length, "identity", 8);
}

#pragma mark - Rewrite Response Bodies

void outersshpriv_http_proxy_rewrite_body(
    HTTPProxyRewriter *rewriter, const void *bytes, size_t length, HTTPProxyBodyOutput output, void *context)
{
    if (rewriter->finished_body) {
        return;
    }
    if (rewriter->buffering_body) {
        if (length <= maximum_rewritable_response_body_length - rewriter->body.byte_count &&
            append_bytes(&rewriter->body, bytes, length)) {
            return;
        }
        rewriter->buffering_body = false;
        output(context, rewriter->body.bytes, rewriter->body.byte_count);
        rewriter->body.byte_count = 0;
    }
    output(context, bytes, length);
}

void outersshpriv_http_proxy_rewrite_body_finish(HTTPProxyRewriter *rewriter, HTTPProxyBodyOutput output, void *context)
{
    if (rewriter->finished_body) {
        return;
    }
    rewriter->finished_body = true;
    if (!rewriter->buffering_body) {
        return;
    }
    ByteBuffer rewritten = {0};
    bool changed = false;
    bool ok = rewrite_loopback_urls_in_body(&rewriter->body, &rewritten, &changed);
    const ByteBuffer *body = ok && changed ? &rewritten : &rewriter->body;
    output(context, body->bytes, body->byte_count);
    free(rewritten.bytes);
    rewriter->body.byte_count = 0;
}

static bool rewrite_loopback_urls_in_body(const ByteBuffer *body, ByteBuffer *output, bool *rewrote)
{
    size_t unchanged_start = 0;
    *rewrote = false;
    for (size_t index = 0; index < body->byte_count;) {
        static const char colon[] = ":";
        char tcp_host[OUTERSSH_PROXY_TCP_HOST_CAPACITY];
        size_t tcp_host_length;
        size_t prefix_length;
        size_t port_start;
        size_t match_length;
        if (!loopback_url_match_length(body->bytes + index, body->byte_count - index,
                index == 0 ? -1 : body->bytes[index - 1], &prefix_length, tcp_host, sizeof(tcp_host),
                &tcp_host_length, &port_start, &match_length)) {
            index++;
            continue;
        }
        if (!append_bytes(output, body->bytes + unchanged_start, index - unchanged_start) ||
            !append_bytes(output, body->bytes + index, prefix_length) ||
            !append_bytes(output, tcp_host, tcp_host_length) ||
            !append_bytes(output, colon, sizeof(colon) - 1) ||
            !append_bytes(output, body->bytes + index + port_start, match_length - port_start) ||
            output->byte_count > maximum_rewritten_response_body_length) {
            return false;
        }
        index += match_length;
        unchanged_start = index;
        *rewrote = true;
    }
    return append_bytes(output, body->bytes + unchanged_start, body->byte_count - unchanged_start) &&
           output->byte_count <= maximum_rewritten_response_body_length;
}

/* Matches an http or ws URL, or a protocol-relative URL, whose host is a
 * loopback address followed by an explicit port. A protocol-relative URL must
 * follow a quote, '=', '(' or whitespace, so line comments such as
 * "x = 1;//localhost:3000" are left alone. */
static bool loopback_url_match_length(const unsigned char *bytes, size_t byte_count, int previous_byte,
    size_t *prefix_length, char *tcp_host, size_t tcp_host_capacity, size_t *tcp_host_length, size_t *port_start,
    size_t *match_length)
{
    static const char http_prefix[] = "http://";
    static const char websocket_prefix[] = "ws://";
    size_t host_start;
    if (byte_count >= 7 && bytes_equal_ignoring_ascii_case(bytes, 7, http_prefix, sizeof(http_prefix) - 1)) {
        host_start = 7;
    } else if (byte_count >= 5 &&
               bytes_equal_ignoring_ascii_case(bytes, 5, websocket_prefix, sizeof(websocket_prefix) - 1)) {
        host_start = 5;
    } else if (byte_count >= 2 && bytes[0] == '/' && bytes[1] == '/' &&
               (previous_byte < 0 || (previous_byte != 0 && strchr("\"'=( \t\r\n\f", previous_byte) != NULL))) {
        host_start = 2;
    } else {
        return false;
    }
    size_t host_end = host_start;
    if (host_end < byte_count && bytes[host_end] == '[') {
        while (host_end < byte_count && bytes[host_end] != ']' && host_end - host_start < 32) host_end++;
        host_end++;
    } else {
        while (host_end < byte_count && bytes[host_end] != ':' && (isalnum(bytes[host_end]) || bytes[host_end] == '.') &&
               host_end - host_start < 32) {
            host_end++;
        }
    }
    if (host_end >= byte_count || bytes[host_end] != ':' ||
        !outerssh_proxy_encode_tcp_host((const char *)bytes + host_start, host_end - host_start,
            tcp_host, tcp_host_capacity, tcp_host_length)) {
        return false;
    }
    size_t digit_start = host_end + 1;
    size_t digit_count = 0;
    unsigned int port = 0;
    while (digit_start + digit_count < byte_count && isdigit(bytes[digit_start + digit_count]) &&
           digit_count < 5) {
        port = port * 10 + (unsigned int)(bytes[digit_start + digit_count] - '0');
        digit_count++;
    }
    if (digit_count == 0 || port > UINT16_MAX) {
        return false;
    }
    *prefix_length = host_start;
    *port_start = digit_start;
    *match_length = digit_start + digit_count;
    return true;
}

#pragma mark - Destroy the Rewriter

void outersshpriv_http_proxy_rewriter_destroy(HTTPProxyRewriter *rewriter)
{
    if (rewriter == NULL) {
        return;
    }
    free(rewriter->target_authority);
    free(rewriter->body.bytes);
    free(rewriter);
}

#pragma mark - Compare and Append Bytes

static bool header_name_equals(const char *value, const char *expected)
{
    return bytes_equal_ignoring_ascii_case(
        (const unsigned char *)value, strlen(value), expected, strlen(expected));
}

static bool bytes_equal_ignoring_ascii_case(
    const unsigned char *bytes, size_t byte_count, const char *string, size_t string_length)
{
    if (byte_count != string_length) {
        return false;
    }
    for (size_t index = 0; index < byte_count; index++) {
        if (tolower(bytes[index]) != tolower((unsigned char)string[index])) {
            return false;
        }
    }
    return true;
}

static bool append_bytes(ByteBuffer *buffer, const void *bytes, size_t byte_count)
{
    if (byte_count == 0) {
        return true;
    }
    if (bytes == NULL || byte_count > SIZE_MAX - buffer->byte_count) {
        return false;
    }
    size_t required_capacity = buffer->byte_count + byte_count;
    if (required_capacity > buffer->capacity) {
        size_t capacity = buffer->capacity == 0 ? 256 : buffer->capacity;
        while (capacity < required_capacity) {
            if (capacity > SIZE_MAX / 2) {
                capacity = required_capacity;
                break;
            }
            capacity *= 2;
        }
        unsigned char *replacement = realloc(buffer->bytes, capacity);
        if (replacement == NULL) {
            return false;
        }
        buffer->bytes = replacement;
        buffer->capacity = capacity;
    }
    memcpy(buffer->bytes + buffer->byte_count, bytes, byte_count);
    buffer->byte_count += byte_count;
    return true;
}
