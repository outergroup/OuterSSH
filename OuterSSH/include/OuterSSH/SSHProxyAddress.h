#ifndef SSH_PROXY_ADDRESS_H
#define SSH_PROXY_ADDRESS_H

#include "OTNullability.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Socket URLs use unpadded lowercase base32, split into 50-character labels,
 * followed by .unix.outerssh.localhost or .pipe.outerssh.localhost. TCP loopback
 * hosts keep the spelling the page used, followed by .tcp.outerssh.localhost:
 * localhost, a 127.x.x.x dotted quad, or ip6-localhost for [::1]. The port stays
 * separate. The configured proxy selects the SSH server. No DNS is consulted for
 * these hosts.
 * Inputs use UTF-8 byte counts and need not be null-terminated. Output capacities
 * include space for a terminator. Output-length pointers are required; lengths
 * exclude the terminator and are set to zero on failure.
 * These pure helpers are header-only so browser adapters need no SSH runtime. */
enum { OUTERSSH_PROXY_SOCKET_HOST_CAPACITY = 254, OUTERSSH_PROXY_TCP_HOST_CAPACITY = 64 };

#define OUTERSSH_PROXY_TCP_HOST_SUFFIX ".tcp.outerssh.localhost"

static inline bool outersshpriv_proxy_bytes_equal_ignoring_case(const char * OT_NONNULL bytes, size_t length,
    const char * OT_NONNULL expected)
{
    if (length != strlen(expected)) return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)bytes[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)expected[i]) return false;
    }
    return true;
}

static inline bool outersshpriv_proxy_is_loopback_ipv4(const char * OT_NONNULL host, size_t host_length)
{
    if (host_length < 9 || memcmp(host, "127.", 4) != 0) return false;
    size_t index = 4;
    for (int component = 0; component < 3; component++) {
        if (component > 0) {
            if (index >= host_length || host[index] != '.') return false;
            index++;
        }
        size_t start = index;
        unsigned value = 0;
        while (index < host_length && index - start < 3 && host[index] >= '0' && host[index] <= '9') {
            value = value * 10 + (unsigned)(host[index] - '0');
            index++;
        }
        size_t digits = index - start;
        if (digits == 0 || value > 255 || (digits > 1 && host[start] == '0')) return false;
    }
    return index == host_length;
}

/* Recognizes a loopback host as a URL spells it and writes its canonical
 * spelling: localhost, the 127.x.x.x dotted quad, or [::1]. Dotted quads with
 * leading zeros are rejected, because URL parsers read those as octal. */
static inline bool outerssh_proxy_canonical_loopback_host(const char * OT_NULLABLE host, size_t host_length,
    char * OT_NULLABLE output, size_t capacity, size_t * OT_NONNULL output_length)
{
    *output_length = 0;
    if (!host || !output || capacity == 0) return false;
    output[0] = 0;
    if (host_length >= OUTERSSH_PROXY_TCP_HOST_CAPACITY) return false;
    const char *canonical;
    size_t canonical_length;
    if (outersshpriv_proxy_bytes_equal_ignoring_case(host, host_length, "localhost")) {
        canonical = "localhost";
        canonical_length = 9;
    } else if (outersshpriv_proxy_is_loopback_ipv4(host, host_length)) {
        canonical = host;
        canonical_length = host_length;
    } else if (outersshpriv_proxy_bytes_equal_ignoring_case(host, host_length, "[::1]") ||
               outersshpriv_proxy_bytes_equal_ignoring_case(host, host_length, "::1") ||
               outersshpriv_proxy_bytes_equal_ignoring_case(host, host_length, "[0:0:0:0:0:0:0:1]") ||
               outersshpriv_proxy_bytes_equal_ignoring_case(host, host_length, "0:0:0:0:0:0:0:1")) {
        canonical = "[::1]";
        canonical_length = 5;
    } else {
        return false;
    }
    if (canonical_length >= capacity) return false;
    memcpy(output, canonical, canonical_length);
    output[canonical_length] = 0;
    *output_length = canonical_length;
    return true;
}

/* Encodes a loopback host, in any spelling the canonical helper accepts, as
 * <label>.tcp.outerssh.localhost. */
static inline bool outerssh_proxy_encode_tcp_host(const char * OT_NULLABLE host, size_t host_length,
    char * OT_NULLABLE output, size_t capacity, size_t * OT_NONNULL output_length)
{
    static const char suffix[] = OUTERSSH_PROXY_TCP_HOST_SUFFIX;
    char canonical[OUTERSSH_PROXY_TCP_HOST_CAPACITY];
    size_t canonical_length;
    *output_length = 0;
    if (!output || capacity == 0) return false;
    output[0] = 0;
    if (!outerssh_proxy_canonical_loopback_host(host, host_length, canonical, sizeof(canonical), &canonical_length)) {
        return false;
    }
    const char *label = canonical[0] == '[' ? "ip6-localhost" : canonical;
    size_t label_length = strlen(label);
    if (label_length + sizeof(suffix) > capacity) return false;
    memcpy(output, label, label_length);
    memcpy(output + label_length, suffix, sizeof(suffix));
    *output_length = label_length + sizeof(suffix) - 1;
    return true;
}

/* Decodes <label>.tcp.outerssh.localhost, ignoring ASCII case and one trailing
 * dot, and writes the canonical loopback spelling: localhost, the dotted quad,
 * or [::1]. */
static inline bool outerssh_proxy_decode_tcp_host(const char * OT_NULLABLE host, size_t host_length,
    char * OT_NULLABLE output, size_t capacity, size_t * OT_NONNULL output_length)
{
    static const char suffix[] = OUTERSSH_PROXY_TCP_HOST_SUFFIX;
    *output_length = 0;
    if (!host || !output || capacity == 0) return false;
    output[0] = 0;
    if (host_length >= OUTERSSH_PROXY_TCP_HOST_CAPACITY) return false;
    if (host_length > 0 && host[host_length - 1] == '.') host_length--;
    if (host_length <= sizeof(suffix) - 1 ||
        !outersshpriv_proxy_bytes_equal_ignoring_case(
            host + host_length - (sizeof(suffix) - 1), sizeof(suffix) - 1, suffix)) {
        return false;
    }
    size_t label_length = host_length - (sizeof(suffix) - 1);
    if (outersshpriv_proxy_bytes_equal_ignoring_case(host, label_length, "ip6-localhost")) {
        return outerssh_proxy_canonical_loopback_host("[::1]", 5, output, capacity, output_length);
    }
    if (outersshpriv_proxy_bytes_equal_ignoring_case(host, label_length, "localhost") ||
        outersshpriv_proxy_is_loopback_ipv4(host, label_length)) {
        return outerssh_proxy_canonical_loopback_host(host, label_length, output, capacity, output_length);
    }
    return false;
}

static inline bool outersshpriv_proxy_is_tcp_host(const char * OT_NULLABLE host, size_t host_length)
{
    char decoded[OUTERSSH_PROXY_TCP_HOST_CAPACITY];
    size_t decoded_length;
    return outerssh_proxy_decode_tcp_host(host, host_length, decoded, sizeof(decoded), &decoded_length);
}

static inline bool outerssh_proxy_is_named_pipe(const char * OT_NULLABLE path, size_t length)
{
    if (!path || length <= 9 || length > 110 || memcmp(path, "\\\\.\\pipe\\", 9)) return false;
    for (size_t i = 9; i < length; i++) {
        unsigned char c = path[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return false;
    }
    return true;
}

/* Socket hosts encode a Unix socket path or a Windows named pipe path. The
 * suffix records which kind it is, so decoding never guesses from the path. */
typedef enum {
    OUTERSSH_PROXY_SOCKET_KIND_UNIX,
    OUTERSSH_PROXY_SOCKET_KIND_NAMED_PIPE
} OuterSSHProxySocketKind;

static inline const char * OT_NONNULL outersshpriv_proxy_socket_suffix(OuterSSHProxySocketKind kind)
{
    return kind == OUTERSSH_PROXY_SOCKET_KIND_NAMED_PIPE ? ".pipe.outerssh.localhost" : ".unix.outerssh.localhost";
}

static inline bool outersshpriv_proxy_encode_socket_host(OuterSSHProxySocketKind kind,
    const char * OT_NONNULL path, size_t path_length, char * OT_NULLABLE host, size_t capacity, size_t * OT_NONNULL host_length)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
    const char *suffix = outersshpriv_proxy_socket_suffix(kind);
    size_t suffix_length = strlen(suffix);
    if (!host || capacity == 0) return false;
    host[0] = 0;
    if (path_length > 144) return false;
    for (size_t i = 0; i < path_length; i++)
        if ((unsigned char)path[i] < 32 || path[i] == 127) return false;
    size_t symbols = (path_length * 8 + 4) / 5;
    size_t total = symbols + (symbols - 1) / 50 + suffix_length;
    if (total >= capacity || total >= OUTERSSH_PROXY_SOCKET_HOST_CAPACITY) return false;
    uint32_t bits = 0;
    unsigned count = 0;
    size_t out = 0, emitted = 0;
    for (size_t i = 0; i < path_length || count; ) {
        if (count < 5 && i < path_length) { bits = (bits << 8) | (unsigned char)path[i++]; count += 8; }
        if (count < 5) { bits <<= 5 - count; count = 5; }
        if (emitted && emitted % 50 == 0) host[out++] = '.';
        count -= 5;
        host[out++] = alphabet[(bits >> count) & 31];
        emitted++;
        bits &= (1u << count) - 1;
    }
    memcpy(host + out, suffix, suffix_length + 1);
    *host_length = total;
    return true;
}

/* Encodes an absolute Unix socket path as <base32>.unix.outerssh.localhost. */
static inline bool outerssh_proxy_encode_unix_socket_host(
    const char * OT_NULLABLE path, size_t path_length,
    char * OT_NULLABLE host, size_t capacity, size_t * OT_NONNULL host_length)
{
    *host_length = 0;
    if (!path || path_length == 0 || path[0] != '/') {
        if (host && capacity) host[0] = 0;
        return false;
    }
    return outersshpriv_proxy_encode_socket_host(OUTERSSH_PROXY_SOCKET_KIND_UNIX, path, path_length, host, capacity, host_length);
}

/* Encodes a \\.\pipe\<name> path as <base32>.pipe.outerssh.localhost. */
static inline bool outerssh_proxy_encode_named_pipe_host(
    const char * OT_NULLABLE path, size_t path_length,
    char * OT_NULLABLE host, size_t capacity, size_t * OT_NONNULL host_length)
{
    *host_length = 0;
    if (!outerssh_proxy_is_named_pipe(path, path_length)) {
        if (host && capacity) host[0] = 0;
        return false;
    }
    return outersshpriv_proxy_encode_socket_host(OUTERSSH_PROXY_SOCKET_KIND_NAMED_PIPE, path, path_length, host, capacity, host_length);
}

/* Decodes a socket host, reporting its kind from the suffix. Accepts only the
 * canonical spelling, ignoring ASCII case, and only paths of the suffix's kind. */
static inline bool outerssh_proxy_decode_socket_host(
    const char * OT_NULLABLE host, size_t host_length, OuterSSHProxySocketKind * OT_NONNULL kind,
    char * OT_NULLABLE path, size_t capacity, size_t * OT_NONNULL path_length)
{
    *path_length = 0;
    *kind = OUTERSSH_PROXY_SOCKET_KIND_UNIX;
    if (!host || !path || capacity == 0) return false;
    path[0] = 0;
    size_t length = host_length, suffix_length = sizeof(".unix.outerssh.localhost") - 1;
    if (length <= suffix_length || length >= OUTERSSH_PROXY_SOCKET_HOST_CAPACITY ||
        memchr(host, '\0', length) != NULL) return false;
    char normalized[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
    for (size_t i = 0; i < length; i++) {
        unsigned char c = host[i];
        normalized[i] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
    }
    normalized[length] = '\0';
    OuterSSHProxySocketKind decoded_kind;
    if (!strcmp(normalized + length - suffix_length, outersshpriv_proxy_socket_suffix(OUTERSSH_PROXY_SOCKET_KIND_UNIX)))
        decoded_kind = OUTERSSH_PROXY_SOCKET_KIND_UNIX;
    else if (!strcmp(normalized + length - suffix_length, outersshpriv_proxy_socket_suffix(OUTERSSH_PROXY_SOCKET_KIND_NAMED_PIPE)))
        decoded_kind = OUTERSSH_PROXY_SOCKET_KIND_NAMED_PIPE;
    else return false;
    size_t end = length - suffix_length;
    normalized[end] = 0;
    uint32_t bits = 0;
    unsigned count = 0;
    size_t out = 0;
    for (size_t i = 0; i < end; i++) {
        unsigned char c = normalized[i];
        if (c == '.') continue;
        unsigned value;
        if (c >= 'a' && c <= 'z') value = c - 'a';
        else if (c >= '2' && c <= '7') value = c - '2' + 26;
        else return false;
        bits = (bits << 5) | value; count += 5;
        if (count >= 8) {
            count -= 8;
            unsigned char byte = (unsigned char)(bits >> count);
            if (byte < 32 || byte == 127 || out + 1 >= capacity) return false;
            path[out++] = byte;
            bits &= (1u << count) - 1;
        }
    }
    path[out] = 0;
    char canonical[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
    size_t canonical_length;
    bool encoded = decoded_kind == OUTERSSH_PROXY_SOCKET_KIND_NAMED_PIPE
        ? outerssh_proxy_encode_named_pipe_host(path, out, canonical, sizeof(canonical), &canonical_length)
        : outerssh_proxy_encode_unix_socket_host(path, out, canonical, sizeof(canonical), &canonical_length);
    /* Re-encoding rejects alternate label splits, padding, and trailing bits. */
    if (!encoded || canonical_length != length || memcmp(canonical, normalized, end) != 0) {
        path[0] = 0;
        return false;
    }
    *kind = decoded_kind;
    *path_length = out;
    return true;
}

#endif
