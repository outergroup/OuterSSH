#ifndef OUTER_ENDPOINT_NAMES_READ_H
#define OUTER_ENDPOINT_NAMES_READ_H

#include "NamedPipes.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { OUTER_ENDPOINT_NAMES_WATCH_CAPACITY = MAXIMUM_WAIT_OBJECTS - 1 };

typedef struct {
    HANDLE handles[OUTER_ENDPOINT_NAMES_WATCH_CAPACITY];
    DWORD count;
} OuterEndpointNamesWatch;

/* Checks that an open endpoints.d or icon-cache object is neither a reparse
 * point nor writable by anyone other than SYSTEM, Administrators, and (for
 * user scope) the current user. */
bool outer_endpoint_object_validate(HANDLE handle, bool system, bool directory, OuterError *error);
/* Reads a validated snapshot of both endpoints.d directories. Free the result with free(). */
bool outer_endpoint_names_read(unsigned char **bytes, size_t *length, OuterError *error);
/* Replaces the change notifications with ones for each endpoints.d directory and its parents. */
bool outer_endpoint_names_watch_reset(OuterEndpointNamesWatch *watch, OuterError *error);
void outer_endpoint_names_watch_clear(OuterEndpointNamesWatch *watch);
/* The user's endpoint icon cache in %LOCALAPPDATA%\OuterSSH\endpoint-icons.
 * Read returns true with *png NULL when no icon is cached; free *png with free(). */
bool outer_endpoint_icon_read(const char *transport, const char *address, uint16_t port,
    unsigned char **png, size_t *length, OuterError *error);
bool outer_endpoint_icon_store(const char *transport, const char *address, uint16_t port,
    const void *png, size_t length, OuterError *error);

#ifdef __cplusplus
}
#endif

#endif
