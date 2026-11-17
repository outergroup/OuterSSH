#include "SSHSessionPoolInternal.h"
#include "SSHProxyErrorInternal.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* The application's packaged bridge executable, mapped read-only where it
 * rests and lent to install commands without copying. */
struct SSHBridgeBinary {
    atomic_size_t references;
    void *view;
    size_t view_length;
    const unsigned char *bytes;
    size_t length;
};

static void close_file(OuterSSHFileHandle file)
{
#if defined(_WIN32)
    if (file != NULL && file != INVALID_HANDLE_VALUE) CloseHandle(file);
#else
    if (file >= 0) close(file);
#endif
}

static OuterSSHError map_error(OuterSSHHelperInstallerErrorCode code, const char *message,
    int system_error_code, char **error_storage)
{
    OuterSSHError error = {
        .domain = OUTERSSH_ERROR_HELPER_INSTALLER,
        .code = code,
        .system_error_code = system_error_code,
    };
    if (system_error_code == 0) {
        error.message = message;
        error.message_length = strlen(message);
        return error;
    }
#if defined(_WIN32)
    return outersshpriv_error_format(error_storage, error, "%s (Windows error %d).", message, system_error_code);
#else
    return outersshpriv_error_format(error_storage, error, "%s: %s.", message, strerror(system_error_code));
#endif
}

SSHBridgeBinary *outersshpriv_bridge_binary_map(OuterSSHFileHandle file,
    uint64_t offset, uint64_t length, OuterSSHError *error, char **error_storage)
{
    *error_storage = NULL;
    static const char unreadable[] = "Could not map the packaged socket-bridge binary";
    SSHBridgeBinary *binary = calloc(1, sizeof(*binary));
    if (binary == NULL) {
        close_file(file);
        *error = map_error(OUTERSSH_HELPER_INSTALLER_ERROR_ALLOCATION_FAILED,
            "Failed to allocate the packaged socket-bridge mapping.", 0, error_storage);
        return NULL;
    }
#if defined(_WIN32)
    SYSTEM_INFO system;
    GetSystemInfo(&system);
    uint64_t granularity = system.dwAllocationGranularity;
    LARGE_INTEGER size = {0};
    bool valid = file != NULL && file != INVALID_HANDLE_VALUE && GetFileType(file) == FILE_TYPE_DISK &&
        GetFileSizeEx(file, &size) && size.QuadPart >= 0;
    uint64_t file_size = valid ? (uint64_t)size.QuadPart : 0;
#else
    uint64_t granularity = (uint64_t)sysconf(_SC_PAGESIZE);
    struct stat status;
    bool valid = file >= 0 && fstat(file, &status) == 0 && S_ISREG(status.st_mode) && status.st_size >= 0;
    uint64_t file_size = valid ? (uint64_t)status.st_size : 0;
#endif
    if (!valid || granularity == 0 || length == 0 || offset > file_size || length > file_size - offset) {
        close_file(file);
        free(binary);
        *error = map_error(OUTERSSH_HELPER_INSTALLER_ERROR_FAILED_TO_READ_PACKAGED_BINARY,
            "The packaged socket-bridge region is not within a readable regular file.", 0, error_storage);
        return NULL;
    }
    uint64_t view_offset = offset - offset % granularity;
    uint64_t view_length = offset - view_offset + length;
    if (view_length > SIZE_MAX) {
        close_file(file);
        free(binary);
        *error = map_error(OUTERSSH_HELPER_INSTALLER_ERROR_FAILED_TO_READ_PACKAGED_BINARY,
            "The packaged socket-bridge binary is too large to map.", 0, error_storage);
        return NULL;
    }
#if defined(_WIN32)
    HANDLE mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    void *view = mapping == NULL ? NULL : MapViewOfFile(mapping, FILE_MAP_READ,
        (DWORD)(view_offset >> 32), (DWORD)view_offset, (SIZE_T)view_length);
    int system_error_code = view == NULL ? (int)GetLastError() : 0;
    if (mapping != NULL) CloseHandle(mapping);
#else
    void *view = mmap(NULL, (size_t)view_length, PROT_READ, MAP_PRIVATE, file, (off_t)view_offset);
    int system_error_code = view == MAP_FAILED ? errno : 0;
    if (view == MAP_FAILED) view = NULL;
#endif
    close_file(file);
    if (view == NULL) {
        free(binary);
        *error = map_error(OUTERSSH_HELPER_INSTALLER_ERROR_FAILED_TO_READ_PACKAGED_BINARY,
            unreadable, system_error_code, error_storage);
        return NULL;
    }
    atomic_init(&binary->references, 1);
    binary->view = view;
    binary->view_length = (size_t)view_length;
    binary->bytes = (const unsigned char *)view + (offset - view_offset);
    binary->length = (size_t)length;
    if (binary->length < 2 || binary->bytes[0] != 0x1f || binary->bytes[1] != 0x8b) {
        outersshpriv_bridge_binary_release(binary);
        *error = map_error(OUTERSSH_HELPER_INSTALLER_ERROR_FAILED_TO_READ_PACKAGED_BINARY,
            "The packaged socket-bridge binary is not gzip-compressed.", 0, error_storage);
        return NULL;
    }
    return binary;
}

const void *outersshpriv_bridge_binary_bytes(const SSHBridgeBinary *binary, size_t *length)
{
    *length = binary->length;
    return binary->bytes;
}

SSHBridgeBinary *outersshpriv_bridge_binary_retain(SSHBridgeBinary *binary)
{
    atomic_fetch_add_explicit(&binary->references, 1, memory_order_relaxed);
    return binary;
}

void outersshpriv_bridge_binary_release(void *opaque_binary)
{
    SSHBridgeBinary *binary = opaque_binary;
    if (binary == NULL || atomic_fetch_sub_explicit(&binary->references, 1, memory_order_acq_rel) != 1) return;
#if defined(_WIN32)
    UnmapViewOfFile(binary->view);
#else
    munmap(binary->view, binary->view_length);
#endif
    free(binary);
}
