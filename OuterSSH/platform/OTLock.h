#ifndef OTLOCK_H
#define OTLOCK_H

/* A short-held mutual-exclusion lock, valid when zero-initialized. */

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
typedef SRWLOCK OTLock;
static inline void otlock_lock(OTLock *lock) { AcquireSRWLockExclusive(lock); }
static inline void otlock_unlock(OTLock *lock) { ReleaseSRWLockExclusive(lock); }
#elif defined(__APPLE__)
#include <os/lock.h>
typedef os_unfair_lock OTLock;
static inline void otlock_lock(OTLock *lock) { os_unfair_lock_lock(lock); }
static inline void otlock_unlock(OTLock *lock) { os_unfair_lock_unlock(lock); }
#else
#include <pthread.h>
typedef pthread_mutex_t OTLock;
static inline void otlock_lock(OTLock *lock) { pthread_mutex_lock(lock); }
static inline void otlock_unlock(OTLock *lock) { pthread_mutex_unlock(lock); }
#endif

#endif
