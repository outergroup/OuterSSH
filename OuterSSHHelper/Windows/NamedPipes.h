#ifndef OUTER_NAMED_PIPES_H
#define OUTER_NAMED_PIPES_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    OUTER_PIPE_PATH_CAPACITY = 112,
    OUTER_SID_CAPACITY = 192,
    OUTER_PATH_CAPACITY = 1024
};

typedef struct {
    char text[256];
} OuterError;

bool outer_error_set(OuterError *error, const char *format, ...);

bool outer_user_sid(wchar_t sid[OUTER_SID_CAPACITY], OuterError *error);
bool outer_user_sid_utf8(char sid[OUTER_SID_CAPACITY], OuterError *error);
bool outer_known_folder_path(const GUID *folder, const wchar_t *suffix, wchar_t path[OUTER_PATH_CAPACITY]);

bool outer_canonical_pipe_path(const char *path, size_t length, char canonical[OUTER_PIPE_PATH_CAPACITY], OuterError *error);
/* Writes the SID embedded after ".s-" in a canonical pipe name, or an empty string. */
void outer_pipe_identity_sid(const char *canonical, char sid[OUTER_SID_CAPACITY]);
bool outer_pipe_allowlist_path(wchar_t path[OUTER_PATH_CAPACITY], OuterError *error);

bool outer_named_pipe_is_allowed(const char *path, const wchar_t *allowlist, bool *allowed, OuterError *error);
bool outer_named_pipe_authorize(const char *path, const wchar_t *allowlist, OuterError *error);
bool outer_named_pipe_verify_identity(HANDLE pipe, const char *path, OuterError *error);
/* A pipe belongs to the SID in its canonical name, or to the current user when
 * it has none. The current user's pipes must be served by that user without
 * elevation. SYSTEM and Administrators count as root. */
bool outer_named_pipe_owner(const char *path, char owner[OUTER_SID_CAPACITY], bool *current_user, bool *root,
    OuterError *error);
bool outer_named_pipe_validate_activation_principal(void *principal, OuterError *error);
/* Returns NULL on failure, and sets *not_listening when the pipe never
 * appeared, so nothing is listening at it. not_listening may be NULL. */
HANDLE outer_named_pipe_open(const char *path, const wchar_t *allowlist, OuterError *error, bool *not_listening);

#ifdef __cplusplus
}
#endif

#endif
