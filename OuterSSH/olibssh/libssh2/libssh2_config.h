#ifndef OLIBSSH_CONFIG_H
#define OLIBSSH_CONFIG_H

/* Shared configuration for OuterSSH's Apple, Linux, and Windows builds. */
#if !OUTERSSH_APPLE_CRYPTO && !OUTERSSH_WINDOWS_CRYPTO && !OUTERSSH_ANDROID_CRYPTO
#define LIBSSH2_OPENSSL 1
#endif
#define LIBSSH2_HAVE_ZLIB 1
#define LIBSSH2_NO_DEPRECATED 1
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_SNPRINTF 1
#define HAVE_STRTOLL 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SELECT 1

#if DEBUG && !defined(LIBSSH2DEBUG)
#define LIBSSH2DEBUG 1
#endif

#if !defined(_WIN32)
#define HAVE_UNISTD_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_SYS_UIO_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_O_NONBLOCK 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1
#endif

#if defined(__APPLE__)
#define HAVE_MEMSET_S 1
#endif

#endif
