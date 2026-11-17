#ifndef OUTERSSH_ENDPOINT_NAMES_H
#define OUTERSSH_ENDPOINT_NAMES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *container;
    const char *user; /* Registration account supplied by the trusted reader. */
    const char *app;
} OuterSSHEndpointName;

/* One registered endpoint and its resolved name. transport is "unix", "pipe"
 * or "tcp"; port is zero except for tcp.
 *
 * A registry is a list of distinct named endpoints in registration order.
 * Identical duplicate registrations appear once, using the first record's
 * spelling, and endpoints registered under conflicting names are omitted. */
typedef struct {
    const char *transport;
    const char *address;
    uint16_t port;
    OuterSSHEndpointName name;
} OuterSSHEndpointRecord;

/* Finds the record for an actual server-side endpoint, never a browser
 * forwarding address. Unix paths match exactly; pipe paths and TCP hosts match
 * ignoring ASCII case, and TCP hosts otherwise match as written, so localhost,
 * 127.0.0.1 and ::1 are distinct. */
const OuterSSHEndpointRecord *outerssh_endpoint_records_find(const OuterSSHEndpointRecord *records, size_t count,
    const char *transport, const char *address, uint16_t port);
/* Copies records and their strings into one allocation, freed with free().
 * Returns NULL only on failure. */
OuterSSHEndpointRecord *outerssh_endpoint_records_copy(const OuterSSHEndpointRecord *records, size_t count);

/* The per-user endpoint icon cache. Icons are PNG files of at most
 * OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES bytes and
 * OUTERSSH_ENDPOINT_ICON_MAXIMUM_DIMENSION pixels on each side. The cache holds
 * at most OUTERSSH_ENDPOINT_ICON_MAXIMUM_COUNT icons; storing a new one
 * beyond that evicts the least recently written. */
#define OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES 65536
#define OUTERSSH_ENDPOINT_ICON_MAXIMUM_DIMENSION 512
#define OUTERSSH_ENDPOINT_ICON_MAXIMUM_COUNT 512
/* 64 hex digits, ".png" and a NUL. */
#define OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY 69

/* Checks the PNG signature, a leading IHDR within the dimension limits, chunk
 * lengths and CRCs, and a final IEND. Does not decode image data. */
bool outerssh_endpoint_icon_is_valid(const void *png, size_t length);
/* Writes an endpoint's cache file name: the lowercase hex SHA-256 of its
 * canonical record line, followed by ".png". The canonical line is the
 * endpoints.d endpoint line ("unix PATH", "pipe PATH" or "tcp HOST PORT") with
 * pipe paths and TCP hosts in ASCII lowercase. Returns false for an endpoint
 * that endpoints.d would reject. */
bool outerssh_endpoint_icon_file_name(const char *transport, const char *address, size_t address_length,
    uint16_t port, char name[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY]);
#ifndef _WIN32
/* Reads this user's trusted registry, as one allocation freed with free(). */
bool outerssh_endpoint_names_read_local(OuterSSHEndpointRecord **records, size_t *count);
/* Reads this user's cached icon for an endpoint. Returns true with *png NULL
 * when there is none. On failure returns false and, if error is provided,
 * sets it to static text. Free *png with free(). */
bool outerssh_endpoint_icon_read_local(const char *transport, const char *address, size_t address_length,
    uint16_t port, unsigned char **png, size_t *length, const char **error);
/* Validates and atomically replaces this user's cached icon for an endpoint,
 * creating the cache directory as needed. */
bool outerssh_endpoint_icon_store_local(const char *transport, const char *address, size_t address_length,
    uint16_t port, const void *png, size_t length, const char **error);
#endif
#ifdef __cplusplus
}
#endif
#endif
