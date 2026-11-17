#include "EndpointNames.h"
#include "../../OuterSSH/SSHEndpointRecord.h"
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static bool trusted_sid(PSID sid, bool system, const char *user)
{
    LPSTR text = NULL;
    if (!sid || !ConvertSidToStringSidA(sid, &text)) return false;
    bool trusted = !strcmp(text, "S-1-5-18") || !strcmp(text, "S-1-5-32-544") || (!system && !strcmp(text, user));
    LocalFree(text);
    return trusted;
}

bool outer_endpoint_object_validate(HANDLE handle, bool system, bool directory, OuterError *error)
{
    FILE_ATTRIBUTE_TAG_INFO info = {0};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) ||
        (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory)
        return outer_error_set(error, "Invalid endpoint registration object.");
    PSECURITY_DESCRIPTOR security = NULL;
    PSID owner = NULL;
    PACL acl = NULL;
    char user[OUTER_SID_CAPACITY];
    bool ok = false;
    if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, NULL, &acl, NULL, &security) != ERROR_SUCCESS || !acl) {
        outer_error_set(error, "Could not verify endpoint permissions.");
        goto done;
    }
    if (!outer_user_sid_utf8(user, error)) goto done;
    if (!trusted_sid(owner, system, user)) {
        outer_error_set(error, "Unsafe endpoint registration owner.");
        goto done;
    }
    const DWORD writable = 0xD0156 | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; i < acl->AceCount; i++) {
        void *raw = NULL;
        if (!GetAce(acl, i, &raw)) {
            outer_error_set(error, "Invalid endpoint ACL.");
            goto done;
        }
        ACE_HEADER *header = raw;
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *ace = raw;
            if ((ace->Mask & writable) && !trusted_sid(&ace->SidStart, system, user)) {
                outer_error_set(error, "Unsafe endpoint permissions.");
                goto done;
            }
        } else if (header->AceType != ACCESS_DENIED_ACE_TYPE) {
            outer_error_set(error, "Unsupported endpoint ACL.");
            goto done;
        }
    }
    ok = true;
done:
    if (security) LocalFree(security);
    return ok;
}

static char *utf8_copy(const wchar_t *text)
{
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, NULL, 0, NULL, NULL);
    char *result = count > 0 ? malloc((size_t)count) : NULL;
    if (result && !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, result, count, NULL, NULL)) {
        free(result);
        result = NULL;
    }
    return result;
}

static char *account_name(OuterError *error)
{
    wchar_t user[OUTER_SID_CAPACITY];
    PSID sid = NULL;
    if (!outer_user_sid(user, error)) return NULL;
    if (!ConvertStringSidToSidW(user, &sid)) {
        outer_error_set(error, "Could not resolve endpoint account.");
        return NULL;
    }
    DWORD name_length = 0, domain_length = 0;
    SID_NAME_USE use;
    LookupAccountSidW(NULL, sid, NULL, &name_length, NULL, &domain_length, &use);
    wchar_t *name = calloc((size_t)name_length + 1, sizeof(wchar_t));
    wchar_t *domain = calloc((size_t)domain_length + 1, sizeof(wchar_t));
    bool found = name && domain && LookupAccountSidW(NULL, sid, name, &name_length, domain, &domain_length, &use);
    LocalFree(sid);
    char *result = NULL;
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computer_length = MAX_COMPUTERNAME_LENGTH + 1;
    if (!found) {
        outer_error_set(error, "Could not resolve endpoint account.");
    } else if (!GetComputerNameW(computer, &computer_length)) {
        outer_error_set(error, "Could not resolve local account domain.");
    } else {
        if (domain[0] && _wcsicmp(domain, computer)) {
            size_t size = wcslen(domain) + wcslen(name) + 2;
            wchar_t *qualified = malloc(size * sizeof(wchar_t));
            if (qualified) {
                _snwprintf(qualified, size, L"%ls\\%ls", domain, name);
                result = utf8_copy(qualified);
                free(qualified);
            }
        } else {
            result = utf8_copy(name);
        }
        if (!result) outer_error_set(error, "Invalid Unicode text.");
    }
    free(name);
    free(domain);
    return result;
}

static bool registration_name(const char *name)
{
    size_t length = strlen(name);
    if (!length) return false;
    char first = name[0];
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9'))) return false;
    for (size_t i = 0; i < length; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'))
            return false;
    }
    return length < 4 || strcmp(name + length - 4, ".tmp");
}

typedef struct {
    unsigned char *bytes;
    size_t length;
} Snapshot;

static bool append(Snapshot *snapshot, const void *bytes, size_t length)
{
    unsigned char *grown = realloc(snapshot->bytes, snapshot->length + length + 1);
    if (!grown) return false;
    snapshot->bytes = grown;
    memcpy(grown + snapshot->length, bytes, length);
    grown[snapshot->length + length] = 0;
    snapshot->length += length + 1;
    return true;
}

static bool read_directory(Snapshot *snapshot, bool system, const char *account, unsigned *count, OuterError *error)
{
    wchar_t directory[OUTER_PATH_CAPACITY], pattern[OUTER_PATH_CAPACITY + 2];
    if (!outer_known_folder_path(system ? &FOLDERID_ProgramData : &FOLDERID_LocalAppData, L"\\OuterSSH\\endpoints.d", directory))
        return outer_error_set(error, "Could not locate endpoint registrations.");
    HANDLE handle = CreateFileW(directory, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD failure = GetLastError();
        if (failure == ERROR_FILE_NOT_FOUND || failure == ERROR_PATH_NOT_FOUND) return true;
        return outer_error_set(error, "Could not open endpoint registrations.");
    }
    bool ok = outer_endpoint_object_validate(handle, system, true, error);
    CloseHandle(handle);
    if (!ok) return false;
    _snwprintf(pattern, OUTER_PATH_CAPACITY + 2, L"%ls\\*", directory);
    WIN32_FIND_DATAW entry;
    HANDLE find = FindFirstFileW(pattern, &entry);
    if (find == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) return true;
        return outer_error_set(error, "Could not list endpoint registrations.");
    }
    unsigned char *bytes = malloc(65537);
    if (!bytes) {
        FindClose(find);
        return outer_error_set(error, "Out of memory.");
    }
    const char *owner = system ? "SYSTEM" : account;
    do {
        if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
        char *name = utf8_copy(entry.cFileName);
        if (!name) {
            ok = outer_error_set(error, "Invalid Unicode text.");
            break;
        }
        bool eligible = registration_name(name);
        free(name);
        if (!eligible) continue;
        wchar_t path[OUTER_PATH_CAPACITY + MAX_PATH];
        _snwprintf(path, OUTER_PATH_CAPACITY + MAX_PATH, L"%ls\\%ls", directory, entry.cFileName);
        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) continue;
        ok = file != INVALID_HANDLE_VALUE ? outer_endpoint_object_validate(file, system, false, error)
            : outer_error_set(error, "Invalid endpoint registration object.");
        LARGE_INTEGER size;
        DWORD used = 0;
        if (ok && (!GetFileSizeEx(file, &size) || size.QuadPart > 65536 || ++*count > 64))
            ok = outer_error_set(error, "Endpoint registration limit exceeded.");
        if (ok && (!ReadFile(file, bytes, 65537, &used, NULL) || used > 65536))
            ok = outer_error_set(error, "Could not read endpoint registration.");
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        if (ok && memchr(bytes, 0, used)) ok = outer_error_set(error, "Invalid endpoint registration.");
        if (ok && snapshot->length + strlen(owner) + used + 2 > 1024 * 1024)
            ok = outer_error_set(error, "Endpoint snapshot limit exceeded.");
        if (ok && (!append(snapshot, owner, strlen(owner)) || !append(snapshot, bytes, used)))
            ok = outer_error_set(error, "Out of memory.");
    } while (ok && FindNextFileW(find, &entry));
    free(bytes);
    FindClose(find);
    return ok;
}

bool outer_endpoint_names_read(unsigned char **bytes, size_t *length, OuterError *error)
{
    *bytes = NULL;
    *length = 0;
    char *account = account_name(error);
    if (!account) return false;
    Snapshot snapshot = {0};
    unsigned count = 0;
    bool ok = read_directory(&snapshot, true, account, &count, error) &&
        read_directory(&snapshot, false, account, &count, error);
    free(account);
    if (ok) {
        OuterSSHEndpointRecord *records = NULL;
        size_t count = 0;
        if (outersshpriv_endpoint_names_parse(snapshot.bytes, snapshot.length, &records, &count)) free(records);
        else ok = outer_error_set(error, "Invalid endpoint registrations.");
    }
    if (!ok) {
        free(snapshot.bytes);
        return false;
    }
    *bytes = snapshot.bytes;
    *length = snapshot.length;
    return true;
}

void outer_endpoint_names_watch_clear(OuterEndpointNamesWatch *watch)
{
    for (DWORD i = 0; i < watch->count; i++) FindCloseChangeNotification(watch->handles[i]);
    watch->count = 0;
}

static void watch_path(OuterEndpointNamesWatch *watch, wchar_t *path)
{
    size_t root = path[0] && path[1] == L':' && path[2] == L'\\' ? 3 : 0;
    bool recursive = true;
    for (;;) {
        size_t length = wcslen(path);
        if (!length || length <= root) return;
        if (watch->count < OUTER_ENDPOINT_NAMES_WATCH_CAPACITY) {
            HANDLE handle = FindFirstChangeNotificationW(path, recursive,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY);
            if (handle != INVALID_HANDLE_VALUE) watch->handles[watch->count++] = handle;
        }
        recursive = false;
        wchar_t *separator = wcsrchr(path, L'\\');
        if (!separator) return;
        if ((size_t)(separator - path) < root) separator = path + root;
        *separator = 0;
    }
}

bool outer_endpoint_names_watch_reset(OuterEndpointNamesWatch *watch, OuterError *error)
{
    outer_endpoint_names_watch_clear(watch);
    const GUID *folders[] = {&FOLDERID_LocalAppData, &FOLDERID_ProgramData};
    for (size_t i = 0; i < sizeof(folders) / sizeof(folders[0]); i++) {
        wchar_t path[OUTER_PATH_CAPACITY];
        if (!outer_known_folder_path(folders[i], L"\\OuterSSH\\endpoints.d", path)) {
            outer_endpoint_names_watch_clear(watch);
            return outer_error_set(error, "Could not locate endpoint registration directory.");
        }
        watch_path(watch, path);
    }
    if (!watch->count) {
        outer_endpoint_names_watch_clear(watch);
        return outer_error_set(error, "Could not watch endpoint registration directories.");
    }
    return true;
}
