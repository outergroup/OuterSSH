#ifndef SECURE_RANDOM_H
#define SECURE_RANDOM_H

#include <errno.h>
#include <limits.h>
#include <stddef.h>

#if defined(__APPLE__)
#include <Security/Security.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

static inline int secure_random_bytes(void *buffer, size_t byte_count)
{
#if defined(__APPLE__)
    return (int)SecRandomCopyBytes(kSecRandomDefault, byte_count, buffer);
#elif defined(_WIN32)
    if (byte_count > ULONG_MAX) return EINVAL;
    return BCryptGenRandom(NULL, buffer, (ULONG)byte_count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : EIO;
#else
    unsigned char *bytes = buffer;
    while (byte_count != 0) {
        ssize_t count = getrandom(bytes, byte_count, 0);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        if (count == 0) {
            return EIO;
        }
        bytes += count;
        byte_count -= (size_t)count;
    }
    return 0;
#endif
}

#endif
