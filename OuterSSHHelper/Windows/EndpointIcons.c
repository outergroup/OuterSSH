#include "EndpointNames.h"
#include "../../OuterSSH/include/OuterSSH/SSHEndpointNames.h"
#include <shlobj.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static bool icon_directory(wchar_t path[OUTER_PATH_CAPACITY], bool create, bool *exists, OuterError *error)
{
    *exists = false;
    wchar_t parent[OUTER_PATH_CAPACITY];
    if (!outer_known_folder_path(&FOLDERID_LocalAppData, L"\\OuterSSH", parent) ||
        !outer_known_folder_path(&FOLDERID_LocalAppData, L"\\OuterSSH\\endpoint-icons", path))
        return outer_error_set(error, "Could not locate the endpoint icon cache.");
    if (create && ((!CreateDirectoryW(parent, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) ||
                   (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)))
        return outer_error_set(error, "Could not create the endpoint icon cache.");
    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD failure = GetLastError();
        if (!create && (failure == ERROR_FILE_NOT_FOUND || failure == ERROR_PATH_NOT_FOUND)) return true;
        return outer_error_set(error, "Could not open the endpoint icon cache.");
    }
    bool ok = outer_endpoint_object_validate(handle, false, true, error);
    CloseHandle(handle);
    *exists = ok;
    return ok;
}

static bool icon_name(const char *transport, const char *address, uint16_t port,
    wchar_t name[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY], OuterError *error)
{
    char ascii[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY];
    if (!outerssh_endpoint_icon_file_name(transport, address, strlen(address), port, ascii))
        return outer_error_set(error, "Invalid endpoint.");
    for (size_t i = 0; i < OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY; i++) name[i] = (wchar_t)ascii[i];
    return true;
}

static bool icon_path(const wchar_t *directory, const wchar_t *name, wchar_t path[OUTER_PATH_CAPACITY], OuterError *error)
{
    if (_snwprintf(path, OUTER_PATH_CAPACITY, L"%ls\\%ls", directory, name) < 0)
        return outer_error_set(error, "The endpoint icon path is too long.");
    return true;
}

bool outer_endpoint_icon_read(const char *transport, const char *address, uint16_t port,
    unsigned char **png, size_t *length, OuterError *error)
{
    *png = NULL;
    *length = 0;
    wchar_t directory[OUTER_PATH_CAPACITY], path[OUTER_PATH_CAPACITY], name[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY];
    bool exists;
    if (!icon_name(transport, address, port, name, error) || !icon_directory(directory, false, &exists, error)) return false;
    if (!exists) return true;
    if (!icon_path(directory, name, path, error)) return false;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD failure = GetLastError();
        if (failure == ERROR_FILE_NOT_FOUND || failure == ERROR_PATH_NOT_FOUND) return true;
        return outer_error_set(error, "Could not open the cached endpoint icon.");
    }
    LARGE_INTEGER size;
    unsigned char *bytes = NULL;
    DWORD used = 0;
    bool ok = outer_endpoint_object_validate(file, false, false, error);
    if (ok && (!GetFileSizeEx(file, &size) || size.QuadPart > OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES))
        ok = outer_error_set(error, "The cached endpoint icon is too large.");
    if (ok && !(bytes = malloc(OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES + 1))) ok = outer_error_set(error, "Out of memory.");
    if (ok && !ReadFile(file, bytes, OUTERSSH_ENDPOINT_ICON_MAXIMUM_BYTES + 1, &used, NULL))
        ok = outer_error_set(error, "Could not read the cached endpoint icon.");
    CloseHandle(file);
    if (ok && !outerssh_endpoint_icon_is_valid(bytes, used))
        ok = outer_error_set(error, "The cached endpoint icon is not a valid PNG.");
    if (!ok) {
        free(bytes);
        return false;
    }
    *png = bytes;
    *length = used;
    return true;
}

static bool icon_entry_name(const wchar_t *name)
{
    if (wcslen(name) != 68 || wcscmp(name + 64, L".png")) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((name[i] >= L'0' && name[i] <= L'9') || (name[i] >= L'a' && name[i] <= L'f'))) return false;
    return true;
}

/* Removes the least recently written icons until a new one fits. */
static bool make_room(const wchar_t *directory, const wchar_t *path)
{
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return true;
    wchar_t pattern[OUTER_PATH_CAPACITY + 8];
    _snwprintf(pattern, OUTER_PATH_CAPACITY + 8, L"%ls\\*.png", directory);
    for (;;) {
        WIN32_FIND_DATAW entry;
        HANDLE find = FindFirstFileW(pattern, &entry);
        if (find == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
        size_t count = 0;
        wchar_t oldest[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY] = {0};
        FILETIME oldest_time = {0};
        do {
            if (!icon_entry_name(entry.cFileName)) continue;
            count++;
            if (!oldest[0] || CompareFileTime(&entry.ftLastWriteTime, &oldest_time) < 0) {
                wcscpy(oldest, entry.cFileName);
                oldest_time = entry.ftLastWriteTime;
            }
        } while (FindNextFileW(find, &entry));
        FindClose(find);
        if (count < OUTERSSH_ENDPOINT_ICON_MAXIMUM_COUNT) return true;
        wchar_t victim[OUTER_PATH_CAPACITY];
        _snwprintf(victim, OUTER_PATH_CAPACITY, L"%ls\\%ls", directory, oldest);
        if (!DeleteFileW(victim) && GetLastError() != ERROR_FILE_NOT_FOUND) return false;
    }
}

bool outer_endpoint_icon_store(const char *transport, const char *address, uint16_t port,
    const void *png, size_t length, OuterError *error)
{
    wchar_t directory[OUTER_PATH_CAPACITY], path[OUTER_PATH_CAPACITY], name[OUTERSSH_ENDPOINT_ICON_FILE_NAME_CAPACITY];
    wchar_t temporary[OUTER_PATH_CAPACITY];
    bool exists;
    if (!icon_name(transport, address, port, name, error)) return false;
    if (!outerssh_endpoint_icon_is_valid(png, length))
        return outer_error_set(error, "Endpoint icons must be PNG images of at most 64 KiB and 512x512 pixels.");
    if (!icon_directory(directory, true, &exists, error) || !icon_path(directory, name, path, error)) return false;
    _snwprintf(temporary, OUTER_PATH_CAPACITY, L"%ls\\.%.64ls.%lu.tmp", directory, name, GetCurrentProcessId());
    HANDLE file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) return outer_error_set(error, "Could not create the endpoint icon.");
    DWORD written = 0;
    bool ok = outer_endpoint_object_validate(file, false, false, error) &&
        WriteFile(file, png, (DWORD)length, &written, NULL) && written == length && FlushFileBuffers(file);
    CloseHandle(file);
    if (!ok) outer_error_set(error, "Could not write the endpoint icon.");
    else if (!make_room(directory, path)) ok = outer_error_set(error, "Could not evict old endpoint icons.");
    else if (!MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        ok = outer_error_set(error, "Could not replace the endpoint icon.");
    if (!ok) DeleteFileW(temporary);
    return ok;
}
