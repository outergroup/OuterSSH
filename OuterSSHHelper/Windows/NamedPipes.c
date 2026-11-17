#define COBJMACROS
#include "NamedPipes.h"
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <taskschd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

bool outer_error_set(OuterError *error, const char *format, ...)
{
    if (error) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error->text, sizeof(error->text), format, arguments);
        va_end(arguments);
    }
    return false;
}

static bool sid_text(PSID sid, char text[OUTER_SID_CAPACITY])
{
    LPSTR value = NULL;
    if (!sid || !ConvertSidToStringSidA(sid, &value)) return false;
    bool fits = strlen(value) < OUTER_SID_CAPACITY;
    if (fits) strcpy(text, value);
    LocalFree(value);
    return fits;
}

static bool token_user_sid(HANDLE token, char text[OUTER_SID_CAPACITY])
{
    DWORD length = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &length);
    TOKEN_USER *user = length ? malloc(length) : NULL;
    bool ok = user && GetTokenInformation(token, TokenUser, user, length, &length) && sid_text(user->User.Sid, text);
    free(user);
    return ok;
}

bool outer_user_sid_utf8(char sid[OUTER_SID_CAPACITY], OuterError *error)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return outer_error_set(error, "Could not inspect user (Windows error %lu).", GetLastError());
    bool ok = token_user_sid(token, sid);
    CloseHandle(token);
    return ok || outer_error_set(error, "Could not read user SID.");
}

bool outer_user_sid(wchar_t sid[OUTER_SID_CAPACITY], OuterError *error)
{
    char text[OUTER_SID_CAPACITY];
    if (!outer_user_sid_utf8(text, error)) return false;
    for (size_t i = 0;; i++) {
        sid[i] = (unsigned char)text[i];
        if (!text[i]) return true;
    }
}

bool outer_known_folder_path(const GUID *folder, const wchar_t *suffix, wchar_t path[OUTER_PATH_CAPACITY])
{
    PWSTR root = NULL;
    if (FAILED(SHGetKnownFolderPath(folder, 0, NULL, &root))) return false;
    int count = _snwprintf(path, OUTER_PATH_CAPACITY, L"%ls%ls", root, suffix);
    CoTaskMemFree(root);
    return count > 0 && count < OUTER_PATH_CAPACITY;
}

static bool pipe_name_character(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

bool outer_canonical_pipe_path(const char *path, size_t length, char canonical[OUTER_PIPE_PATH_CAPACITY], OuterError *error)
{
    static const char prefix[] = "\\\\.\\pipe\\";
    const size_t prefix_length = sizeof(prefix) - 1;
    if (length <= prefix_length || length > 110 || _strnicmp(path, prefix, prefix_length))
        return outer_error_set(error, "Enter a local named pipe path beginning with \\\\.\\pipe\\.");
    for (size_t i = prefix_length; i < length; i++) {
        if (!pipe_name_character(path[i]))
            return outer_error_set(error, "Pipe names may contain letters, numbers, dots, hyphens, and underscores.");
    }
    memcpy(canonical, prefix, prefix_length);
    for (size_t i = prefix_length; i < length; i++) {
        char c = path[i];
        canonical[i] = c >= 'A' && c <= 'Z' ? (char)(c + 'a' - 'A') : c;
    }
    canonical[length] = 0;
    return true;
}

void outer_pipe_identity_sid(const char *canonical, char sid[OUTER_SID_CAPACITY])
{
    sid[0] = 0;
    const char *separator = NULL;
    for (const char *cursor = strstr(canonical, ".s-"); cursor; cursor = strstr(cursor + 1, ".s-")) separator = cursor;
    if (!separator || separator - canonical <= 9) return;
    const char *suffix = separator + 1;
    char text[OUTER_SID_CAPACITY];
    if (strlen(suffix) >= sizeof(text)) return;
    strcpy(text, suffix);
    text[0] = 'S';
    PSID value = NULL;
    if (!ConvertStringSidToSidA(text, &value)) return;
    char normalized[OUTER_SID_CAPACITY];
    if (IsValidSid(value) && sid_text(value, normalized) && !_stricmp(normalized, suffix) && strlen(normalized) == strlen(suffix))
        strcpy(sid, normalized);
    LocalFree(value);
}

bool outer_pipe_allowlist_path(wchar_t path[OUTER_PATH_CAPACITY], OuterError *error)
{
    return outer_known_folder_path(&FOLDERID_LocalAppData, L"\\OuterSSH\\http-pipe.allow", path) ||
        outer_error_set(error, "Could not locate local application data.");
}

static bool validate_allowlist_object(HANDLE file, OuterError *error)
{
    PSECURITY_DESCRIPTOR security = NULL;
    PSID owner = NULL;
    PACL acl = NULL;
    char user[OUTER_SID_CAPACITY], text[OUTER_SID_CAPACITY];
    bool ok = false;
    if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, NULL, &acl, NULL, &security) != ERROR_SUCCESS || !acl) {
        outer_error_set(error, "Could not verify named pipe allowlist permissions.");
        goto done;
    }
    if (!outer_user_sid_utf8(user, error)) goto done;
#define TRUSTED(sid) (sid_text((sid), text) && (!strcmp(text, user) || !strcmp(text, "S-1-5-18") || !strcmp(text, "S-1-5-32-544")))
    if (!TRUSTED(owner)) {
        outer_error_set(error, "Named pipe allowlist has an untrusted owner.");
        goto done;
    }
    const DWORD writable = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; i < acl->AceCount; i++) {
        void *raw = NULL;
        if (!GetAce(acl, i, &raw)) {
            outer_error_set(error, "Invalid named pipe allowlist ACL.");
            goto done;
        }
        ACE_HEADER *header = raw;
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *ace = raw;
            if ((ace->Mask & writable) && !TRUSTED(&ace->SidStart)) {
                outer_error_set(error, "Named pipe allowlist is writable by another principal.");
                goto done;
            }
        } else if (header->AceType != ACCESS_DENIED_ACE_TYPE) {
            outer_error_set(error, "Unsupported named pipe allowlist ACL.");
            goto done;
        }
    }
#undef TRUSTED
    FILE_ATTRIBUTE_TAG_INFO info = {0};
    if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &info, sizeof(info)) ||
        (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        outer_error_set(error, "Named pipe allowlist must not be a reparse point.");
        goto done;
    }
    ok = true;
done:
    if (security) LocalFree(security);
    return ok;
}

static char *read_small_file(HANDLE file, LONGLONG maximum, size_t *length, const char *too_large, const char *unreadable, OuterError *error)
{
    LARGE_INTEGER size = {0};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > maximum) {
        outer_error_set(error, "%s", too_large);
        return NULL;
    }
    char *data = malloc((size_t)size.QuadPart + 1);
    DWORD count = 0;
    if (!data || !ReadFile(file, data, (DWORD)size.QuadPart, &count, NULL) || count != (DWORD)size.QuadPart) {
        free(data);
        outer_error_set(error, "%s", unreadable);
        return NULL;
    }
    data[count] = 0;
    *length = count;
    return data;
}

static HANDLE open_existing(const wchar_t *path, DWORD access, DWORD share, DWORD flags, DWORD *failure)
{
    HANDLE handle = CreateFileW(path, access, share, NULL, OPEN_EXISTING, flags, NULL);
    *failure = handle == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    return handle == INVALID_HANDLE_VALUE ? NULL : handle;
}

static int compare_strings(const void *left, const void *right)
{
    return strcmp(*(char *const *)left, *(char *const *)right);
}

typedef struct {
    char **endpoints;
    size_t count;
} Endpoints;

static void endpoints_free(Endpoints *endpoints)
{
    for (size_t i = 0; i < endpoints->count; i++) free(endpoints->endpoints[i]);
    free(endpoints->endpoints);
}

static bool find_activation(const char *contents, size_t length, const char *pipe, wchar_t **task, OuterError *error)
{
    *task = NULL;
    if (length && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, contents, (int)length, NULL, 0))
        return outer_error_set(error, "Invalid UTF-8 text.");
    Endpoints endpoints = {0};
    bool ok = false;
    for (size_t start = 0; start < length;) {
        const char *line = contents + start;
        const char *newline = memchr(line, '\n', length - start);
        size_t line_length = newline ? (size_t)(newline - line) : length - start;
        start += line_length + 1;
        if (line_length && line[line_length - 1] == '\r') line_length--;
        if (!line_length) continue;
        const char *tab = memchr(line, '\t', line_length);
        size_t tab_offset = tab ? (size_t)(tab - line) : 0;
        if (!tab || !tab_offset || tab_offset + 1 == line_length || memchr(tab + 1, '\t', line_length - tab_offset - 1)) {
            outer_error_set(error, "Invalid row in activations.tsv; expected pipe, tab, task path.");
            goto done;
        }
        for (size_t i = 0; i < line_length; i++) {
            if (i != tab_offset && (unsigned char)line[i] < 32) {
                outer_error_set(error, "Invalid control character in activations.tsv.");
                goto done;
            }
        }
        char endpoint[OUTER_PIPE_PATH_CAPACITY];
        if (!outer_canonical_pipe_path(line, tab_offset, endpoint, error)) goto done;
        const char *path = tab + 1;
        size_t path_length = line_length - tab_offset - 1;
        if (path[0] != '\\' || path[path_length - 1] == '\\') {
            outer_error_set(error, "Task activation requires an absolute task path.");
            goto done;
        }
        char **grown = realloc(endpoints.endpoints, (endpoints.count + 1) * sizeof(char *));
        char *copy = grown ? _strdup(endpoint) : NULL;
        if (grown) endpoints.endpoints = grown;
        if (!copy) {
            outer_error_set(error, "Out of memory.");
            goto done;
        }
        endpoints.endpoints[endpoints.count++] = copy;
        if (!strcmp(endpoint, pipe) && !*task) {
            int count = MultiByteToWideChar(CP_UTF8, 0, path, (int)path_length, NULL, 0);
            *task = count > 0 ? calloc((size_t)count + 1, sizeof(wchar_t)) : NULL;
            if (!*task) {
                outer_error_set(error, "Out of memory.");
                goto done;
            }
            MultiByteToWideChar(CP_UTF8, 0, path, (int)path_length, *task, count);
        }
    }
    if (endpoints.count) qsort(endpoints.endpoints, endpoints.count, sizeof(char *), compare_strings);
    for (size_t i = 1; i < endpoints.count; i++) {
        if (!strcmp(endpoints.endpoints[i - 1], endpoints.endpoints[i])) {
            outer_error_set(error, "Duplicate named pipe in activations.tsv.");
            goto done;
        }
    }
    ok = true;
done:
    endpoints_free(&endpoints);
    if (!ok) {
        free(*task);
        *task = NULL;
    }
    return ok;
}

bool outer_named_pipe_validate_activation_principal(void *opaque, OuterError *error)
{
    IPrincipal *principal = opaque;
    TASK_RUNLEVEL_TYPE run_level = TASK_RUNLEVEL_HIGHEST;
    TASK_LOGON_TYPE logon_type = TASK_LOGON_NONE;
    BSTR account = NULL;
    HRESULT hr = principal ? IPrincipal_get_RunLevel(principal, &run_level) : E_POINTER;
    if (SUCCEEDED(hr)) hr = IPrincipal_get_LogonType(principal, &logon_type);
    if (SUCCEEDED(hr)) hr = IPrincipal_get_UserId(principal, &account);
    if (FAILED(hr) || run_level != TASK_RUNLEVEL_LUA || logon_type != TASK_LOGON_INTERACTIVE_TOKEN || !account || !account[0]) {
        SysFreeString(account);
        return outer_error_set(error, "Named pipe activation requires a non-elevated interactive task for the current user.");
    }
    PSID sid = NULL;
    void *lookup = NULL;
    bool allocated = ConvertStringSidToSidW(account, &sid) != FALSE;
    if (!allocated) {
        DWORD sid_size = 0, domain_size = 0;
        SID_NAME_USE use;
        LookupAccountNameW(NULL, account, NULL, &sid_size, NULL, &domain_size, &use);
        lookup = sid_size ? malloc(sid_size) : NULL;
        wchar_t *domain = calloc((size_t)domain_size + 1, sizeof(wchar_t));
        if (lookup && domain && LookupAccountNameW(NULL, account, lookup, &sid_size, domain, &domain_size, &use)) sid = lookup;
        free(domain);
    }
    SysFreeString(account);
    char text[OUTER_SID_CAPACITY], user[OUTER_SID_CAPACITY];
    bool same = sid && sid_text(sid, text) && outer_user_sid_utf8(user, NULL) && !strcmp(text, user);
    if (allocated) LocalFree(sid);
    free(lookup);
    return same || outer_error_set(error, "Named pipe activation cannot run a task as another account.");
}

static bool run_activation_task(const wchar_t *task_path, bool *requested, OuterError *error)
{
    HRESULT initialized = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE)
        return outer_error_set(error, "Could not initialize Task Scheduler access.");
    ITaskService *service = NULL;
    ITaskFolder *folder = NULL;
    IRegisteredTask *task = NULL;
    IRunningTask *running = NULL;
    ITaskDefinition *definition = NULL;
    IPrincipal *principal = NULL;
    VARIANT empty;
    VariantInit(&empty);
    bool ok = true;
    BSTR root = SysAllocString(L"\\"), name = SysAllocString(task_path);
    HRESULT hr = root && name ? CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service) : E_OUTOFMEMORY;
    if (SUCCEEDED(hr)) hr = ITaskService_Connect(service, empty, empty, empty, empty);
    if (SUCCEEDED(hr)) hr = ITaskService_GetFolder(service, root, &folder);
    if (SUCCEEDED(hr)) hr = ITaskFolder_GetTask(folder, name, &task);
    SysFreeString(root);
    SysFreeString(name);
    if (SUCCEEDED(hr)) hr = IRegisteredTask_get_Definition(task, &definition);
    if (SUCCEEDED(hr)) hr = ITaskDefinition_get_Principal(definition, &principal);
    if (SUCCEEDED(hr) && !outer_named_pipe_validate_activation_principal(principal, error)) ok = false;
    TASK_STATE state = TASK_STATE_UNKNOWN;
    if (ok && SUCCEEDED(hr)) hr = IRegisteredTask_get_State(task, &state);
    if (ok && SUCCEEDED(hr) && state != TASK_STATE_RUNNING && state != TASK_STATE_QUEUED) {
        hr = IRegisteredTask_Run(task, empty, &running);
        if (SUCCEEDED(hr)) *requested = true;
    }
    if (ok && FAILED(hr)) {
        char task_text[512] = "";
        WideCharToMultiByte(CP_UTF8, 0, task_path, -1, task_text, sizeof(task_text), NULL, NULL);
        ok = outer_error_set(error, "Could not activate task %s (HRESULT 0x%lx).", task_text, (unsigned long)hr);
    }
    if (running) IRunningTask_Release(running);
    if (principal) IPrincipal_Release(principal);
    if (definition) ITaskDefinition_Release(definition);
    if (task) IRegisteredTask_Release(task);
    if (folder) ITaskFolder_Release(folder);
    if (service) ITaskService_Release(service);
    if (SUCCEEDED(initialized)) CoUninitialize();
    return ok;
}

static bool activate_named_pipe(const char *pipe, bool *mapped, bool *requested, OuterError *error)
{
    *mapped = false;
    wchar_t directory_path[OUTER_PATH_CAPACITY], file_path[OUTER_PATH_CAPACITY];
    if (!outer_known_folder_path(&FOLDERID_LocalAppData, L"\\org.outerssh", directory_path) ||
        !outer_known_folder_path(&FOLDERID_LocalAppData, L"\\org.outerssh\\activations.tsv", file_path))
        return outer_error_set(error, "Could not locate task activation registrations.");
    DWORD failure = 0;
    HANDLE directory = open_existing(directory_path, READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, &failure);
    if (!directory) {
        if (failure == ERROR_FILE_NOT_FOUND || failure == ERROR_PATH_NOT_FOUND) return true;
        return outer_error_set(error, "Could not open task activation directory.");
    }
    HANDLE file = NULL;
    char *contents = NULL;
    wchar_t *task = NULL;
    bool ok = false;
    if (!validate_allowlist_object(directory, error)) goto done;
    file = open_existing(file_path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_FLAG_OPEN_REPARSE_POINT, &failure);
    if (!file) {
        if (failure == ERROR_FILE_NOT_FOUND) ok = true;
        else outer_error_set(error, "Could not open task activation registrations.");
        goto done;
    }
    if (!validate_allowlist_object(file, error)) goto done;
    size_t length = 0;
    contents = read_small_file(file, 1024 * 1024, &length, "Task activation registrations exceed the size limit.",
        "Could not read task activation registrations.", error);
    if (!contents || !find_activation(contents, length, pipe, &task, error)) goto done;
    if (!task) {
        ok = true;
        goto done;
    }
    ok = run_activation_task(task, requested, error);
    *mapped = ok;
done:
    free(task);
    free(contents);
    if (file) CloseHandle(file);
    CloseHandle(directory);
    return ok;
}

bool outer_named_pipe_is_allowed(const char *path, const wchar_t *allowlist, bool *allowed, OuterError *error)
{
    *allowed = false;
    char canonical[OUTER_PIPE_PATH_CAPACITY];
    if (!outer_canonical_pipe_path(path, strlen(path), canonical, error)) return false;
    wchar_t parent[OUTER_PATH_CAPACITY];
    size_t length = wcslen(allowlist);
    if (length >= OUTER_PATH_CAPACITY) return outer_error_set(error, "Could not open the named pipe allowlist directory.");
    wcscpy(parent, allowlist);
    wchar_t *separator = wcsrchr(parent, L'\\');
    wchar_t *alternate = wcsrchr(parent, L'/');
    if (alternate > separator) separator = alternate;
    if (separator) {
        if (separator == parent + 2 && parent[1] == L':') separator[1] = 0;
        else *separator = 0;
    } else {
        wcscpy(parent, L".");
    }
    DWORD failure = 0;
    HANDLE directory = open_existing(parent, READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, &failure);
    if (!directory) {
        if (failure == ERROR_FILE_NOT_FOUND || failure == ERROR_PATH_NOT_FOUND) return true;
        return outer_error_set(error, "Could not open the named pipe allowlist directory.");
    }
    bool valid = validate_allowlist_object(directory, error);
    CloseHandle(directory);
    if (!valid) return false;
    HANDLE file = open_existing(allowlist, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, FILE_FLAG_OPEN_REPARSE_POINT, &failure);
    if (!file) {
        if (failure == ERROR_FILE_NOT_FOUND || failure == ERROR_PATH_NOT_FOUND) return true;
        return outer_error_set(error, "Could not open the named pipe allowlist.");
    }
    size_t data_length = 0;
    char *data = validate_allowlist_object(file, error) ? read_small_file(file, 65536, &data_length,
        "Named pipe allowlist is too large.", "Could not read named pipe allowlist.", error) : NULL;
    CloseHandle(file);
    if (!data) return false;
    bool ok = true;
    for (size_t start = 0; start < data_length && !*allowed;) {
        const char *line = data + start;
        const char *newline = memchr(line, '\n', data_length - start);
        size_t line_length = newline ? (size_t)(newline - line) : data_length - start;
        start += line_length + 1;
        while (line_length && strchr(" \t\r\n", line[0])) { line++; line_length--; }
        while (line_length && strchr(" \t\r\n", line[line_length - 1])) line_length--;
        if (!line_length || line[0] == '#') continue;
        char entry[OUTER_PIPE_PATH_CAPACITY];
        if (!outer_canonical_pipe_path(line, line_length, entry, error)) {
            ok = false;
            break;
        }
        *allowed = !strcmp(entry, canonical);
    }
    free(data);
    return ok;
}

bool outer_named_pipe_authorize(const char *path, const wchar_t *allowlist, OuterError *error)
{
    bool allowed = false;
    if (!outer_named_pipe_is_allowed(path, allowlist, &allowed, error)) return false;
    return allowed || outer_error_set(error, "This named pipe is not in the HTTP allowlist.");
}

bool outer_named_pipe_verify_identity(HANDLE pipe, const char *path, OuterError *error)
{
    char canonical[OUTER_PIPE_PATH_CAPACITY], expected[OUTER_SID_CAPACITY], text[OUTER_SID_CAPACITY];
    if (!outer_canonical_pipe_path(path, strlen(path), canonical, error)) return false;
    outer_pipe_identity_sid(canonical, expected);
    if (!expected[0]) return true;
    PSECURITY_DESCRIPTOR security = NULL;
    PSID owner = NULL;
    PACL acl = NULL;
    bool ok = false;
    if (GetSecurityInfo(pipe, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, NULL, &acl, NULL, &security) != ERROR_SUCCESS || !owner || !acl) {
        outer_error_set(error, "Could not verify named pipe ownership and permissions.");
        goto done;
    }
    if (!sid_text(owner, text) || strcmp(text, expected)) {
        outer_error_set(error, "The named pipe owner does not match the SID in its name.");
        goto done;
    }
    const DWORD authority = FILE_CREATE_PIPE_INSTANCE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; i < acl->AceCount; i++) {
        void *raw = NULL;
        if (!GetAce(acl, i, &raw)) {
            outer_error_set(error, "Invalid named pipe ACL.");
            goto done;
        }
        ACE_HEADER *header = raw;
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *ace = raw;
            if ((ace->Mask & authority) && (!sid_text(&ace->SidStart, text) || (strcmp(text, expected) &&
                    strcmp(text, "S-1-5-18") && strcmp(text, "S-1-5-32-544") && strcmp(text, "S-1-3-4")))) {
                outer_error_set(error, "The named pipe allows another principal to create servers or change its identity.");
                goto done;
            }
        } else if (header->AceType != ACCESS_DENIED_ACE_TYPE) {
            outer_error_set(error, "Unsupported named pipe ACL; its identity cannot be verified.");
            goto done;
        }
    }
    ok = true;
done:
    if (security) LocalFree(security);
    return ok;
}

bool outer_named_pipe_owner(const char *path, char owner[OUTER_SID_CAPACITY], bool *current_user, bool *root,
    OuterError *error)
{
    char canonical[OUTER_PIPE_PATH_CAPACITY], user[OUTER_SID_CAPACITY];
    if (!outer_canonical_pipe_path(path, strlen(path), canonical, error) || !outer_user_sid_utf8(user, error)) return false;
    outer_pipe_identity_sid(canonical, owner);
    if (!owner[0]) strcpy(owner, user);
    *current_user = !strcmp(owner, user);
    *root = !strcmp(owner, "S-1-5-18") || !strcmp(owner, "S-1-5-32-544");
    return true;
}

static bool verify_server_account(HANDLE pipe, OuterError *error)
{
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid)) return outer_error_set(error, "Could not identify the pipe server.");
    HANDLE server = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), token = NULL;
    bool opened = server && OpenProcessToken(server, TOKEN_QUERY, &token);
    if (server) CloseHandle(server);
    if (!opened) return outer_error_set(error, "Could not verify the pipe server account.");
    char owner[OUTER_SID_CAPACITY], user[OUTER_SID_CAPACITY];
    bool same = token_user_sid(token, owner) && outer_user_sid_utf8(user, NULL) && !strcmp(owner, user);
    TOKEN_ELEVATION elevation = {0};
    DWORD length = 0;
    bool known = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length);
    CloseHandle(token);
    if (!same) return outer_error_set(error, "Named pipes without another account's identity must run as the current user.");
    if (!known) return outer_error_set(error, "Could not verify the pipe server account.");
    return !elevation.TokenIsElevated || outer_error_set(error,
        "An elevated pipe server must end its pipe name with its owner's SID, such as .s-1-5-32-544.");
}

HANDLE outer_named_pipe_open(const char *path, const wchar_t *allowlist, OuterError *error, bool *not_listening)
{
    if (not_listening) *not_listening = false;
    char canonical[OUTER_PIPE_PATH_CAPACITY];
    if (!outer_canonical_pipe_path(path, strlen(path), canonical, error) ||
        !outer_named_pipe_authorize(canonical, allowlist, error)) return NULL;
    wchar_t name[OUTER_PIPE_PATH_CAPACITY];
    for (size_t i = 0;; i++) {
        name[i] = (unsigned char)canonical[i];
        if (!canonical[i]) break;
    }
    HANDLE pipe = NULL;
    ULONGLONG deadline = GetTickCount64() + 5000, activation_check_at = 0;
    bool activation_checked = false, activation_mapped = false, activation_requested = false;
    for (;;) {
        pipe = CreateFileW(name, FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | SYNCHRONIZE, 0, NULL,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
        if (pipe != INVALID_HANDLE_VALUE) break;
        DWORD failure = GetLastError();
        if ((failure != ERROR_PIPE_BUSY && failure != ERROR_FILE_NOT_FOUND) || GetTickCount64() >= deadline) {
            if (not_listening) *not_listening = failure == ERROR_FILE_NOT_FOUND;
            outer_error_set(error, "The named pipe app is unavailable (Windows error %lu).", failure);
            return NULL;
        }
        if (failure == ERROR_FILE_NOT_FOUND) {
            if ((!activation_checked || (activation_mapped && !activation_requested)) && GetTickCount64() >= activation_check_at) {
                bool mapped = false;
                if (!activate_named_pipe(canonical, &mapped, &activation_requested, error)) return NULL;
                activation_mapped = mapped;
                if (!activation_checked && activation_mapped) deadline = GetTickCount64() + 15000;
                activation_checked = true;
                activation_check_at = GetTickCount64() + 250;
            }
            Sleep(50);
        } else {
            WaitNamedPipeW(name, 100);
        }
    }
    char owner[OUTER_SID_CAPACITY];
    bool current_user = false, root = false;
    if (!outer_named_pipe_verify_identity(pipe, canonical, error) ||
        !outer_named_pipe_owner(canonical, owner, &current_user, &root, error) ||
        (current_user && !verify_server_account(pipe, error))) {
        CloseHandle(pipe);
        return NULL;
    }
    return pipe;
}
