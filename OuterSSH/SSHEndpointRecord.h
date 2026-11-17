#ifndef SSH_ENDPOINT_RECORD_H
#define SSH_ENDPOINT_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "include/OuterSSH/SSHEndpointNames.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Socket-service icon requests identify endpoints by their canonical
 * endpoints.d record line, without a terminator. Returns a malloc'd, NUL-
 * terminated line, or NULL for an endpoint that endpoints.d would reject. */
char *outersshpriv_endpoint_record_line(const char *transport, const char *address, size_t address_length,
    uint16_t port, size_t *length);
/* Validates a NUL-terminated record line and splits it in place. */
bool outersshpriv_endpoint_record_parse(char *line, const char **transport, const char **address, uint16_t *port);
/* Parses the helper's registry snapshot: account-NUL/file-NUL pairs, where
 * accounts are derived from directory scope, never from registration
 * contents. Empty input is an empty registry; a malformed file invalidates the
 * snapshot. Writes the registry as one allocation, freed with free(). */
bool outersshpriv_endpoint_names_parse(const void *bytes, size_t length, OuterSSHEndpointRecord **records, size_t *count);
#ifndef _WIN32
/* Reads this user's trusted registrations as a snapshot. Free *bytes with free(). */
bool outersshpriv_endpoint_names_read_snapshot(unsigned char **bytes, size_t *length);
#endif

#ifdef __cplusplus
}
#endif

#endif
