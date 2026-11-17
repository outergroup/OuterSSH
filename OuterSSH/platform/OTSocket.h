#ifndef OTSOCKET_H
#define OTSOCKET_H

/* OTSocket provides the portable socket handles and operations used by OuterSSH,
 * with POSIX-style results and errno values. */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <BaseTsd.h>
typedef intptr_t otsocket_t;
typedef SSIZE_T ssize_t;
typedef int socklen_t;
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH
#define strcasecmp _stricmp
#define strncasecmp _strnicmp

int otsocket_initialize(void);
static inline int otsocket_error(int error)
{
    switch (error) {
    case 0: return 0;
    case WSAEWOULDBLOCK: return EAGAIN;
    case WSAEINPROGRESS: return EINPROGRESS;
    case WSAEALREADY: return EALREADY;
    case WSAEINTR: return EINTR;
    case WSAENOTSOCK: return EBADF;
    case WSAECONNRESET: return ECONNRESET;
    case WSAECONNREFUSED: return ECONNREFUSED;
    case WSAECONNABORTED: return ECONNABORTED;
    case WSAENOTCONN: return ENOTCONN;
    case WSAETIMEDOUT: return ETIMEDOUT;
    case WSAENETUNREACH: return ENETUNREACH;
    case WSAEHOSTUNREACH: return EHOSTUNREACH;
    case WSAEADDRINUSE: return EADDRINUSE;
    case WSAEADDRNOTAVAIL: return EADDRNOTAVAIL;
    case WSAEACCES: return EACCES;
    case WSAEINVAL: return EINVAL;
    case WSAEMFILE: return EMFILE;
    case WSAENOBUFS: return ENOMEM;
    case WSAESHUTDOWN: return EPIPE;
    default: return EIO;
    }
}
static inline int otsocket_result(int result)
{
    if (result == SOCKET_ERROR) errno = otsocket_error(WSAGetLastError());
    return result;
}
static inline otsocket_t otsocket_create(int domain, int type, int protocol)
{
    if (otsocket_initialize() != 0) return -1;
    SOCKET result = WSASocketW(domain, type, protocol, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (result == INVALID_SOCKET) errno = otsocket_error(WSAGetLastError());
    return (otsocket_t)result;
}
static inline int otsocket_close(otsocket_t socket) { return otsocket_result(closesocket((SOCKET)socket)); }
static inline ssize_t otsocket_recv(otsocket_t socket, void *buffer, size_t count, int flags)
{
    return otsocket_result(recv((SOCKET)socket, buffer, count > INT_MAX ? INT_MAX : (int)count, flags));
}
static inline ssize_t otsocket_send(otsocket_t socket, const void *buffer, size_t count, int flags)
{
    return otsocket_result(send((SOCKET)socket, buffer, count > INT_MAX ? INT_MAX : (int)count, flags));
}
static inline int otsocket_connect(otsocket_t socket, const struct sockaddr *address, socklen_t length)
{
    int result = otsocket_result(connect((SOCKET)socket, address, length));
    if (result < 0 && errno == EAGAIN) errno = EINPROGRESS;
    return result;
}
static inline int otsocket_bind(otsocket_t socket, const struct sockaddr *address, socklen_t length)
{ return otsocket_result(bind((SOCKET)socket, address, length)); }
static inline int otsocket_listen(otsocket_t socket, int backlog)
{ return otsocket_result(listen((SOCKET)socket, backlog)); }
static inline otsocket_t otsocket_accept(otsocket_t socket, struct sockaddr *address, socklen_t *length)
{
    SOCKET accepted = accept((SOCKET)socket, address, length);
    if (accepted == INVALID_SOCKET) errno = otsocket_error(WSAGetLastError());
    else WSAEventSelect(accepted, NULL, 0);
    return (otsocket_t)accepted;
}
static inline int otsocket_getsockname(otsocket_t socket, struct sockaddr *address, socklen_t *length)
{ return otsocket_result(getsockname((SOCKET)socket, address, length)); }
static inline int otsocket_setsockopt(otsocket_t socket, int level, int option, const void *value, socklen_t length)
{ return otsocket_result(setsockopt((SOCKET)socket, level, option, value, length)); }
static inline int otsocket_getsockopt(otsocket_t socket, int level, int option, void *value, socklen_t *length)
{
    int result = otsocket_result(getsockopt((SOCKET)socket, level, option, value, length));
    if (!result && level == SOL_SOCKET && option == SO_ERROR) *(int *)value = otsocket_error(*(int *)value);
    return result;
}
static inline int otsocket_shutdown(otsocket_t socket, int how)
{ return otsocket_result(shutdown((SOCKET)socket, how)); }
static inline int otsocket_set_nonblocking(otsocket_t socket, bool enabled)
{
    u_long value = enabled;
    return otsocket_result(ioctlsocket((SOCKET)socket, FIONBIO, &value));
}
static inline int otsocket_prevent_inheritance(otsocket_t socket)
{
    if (SetHandleInformation((HANDLE)socket, HANDLE_FLAG_INHERIT, 0)) return 0;
    errno = EBADF;
    return -1;
}
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int otsocket_t;
static inline int otsocket_initialize(void) { return 0; }
static inline otsocket_t otsocket_create(int domain, int type, int protocol)
{ return socket(domain, type, protocol); }
static inline int otsocket_close(otsocket_t socket)
{ return close(socket); }
static inline ssize_t otsocket_recv(otsocket_t socket, void *buffer, size_t count, int flags)
{ return recv(socket, buffer, count, flags); }
static inline ssize_t otsocket_send(otsocket_t socket, const void *buffer, size_t count, int flags)
{ return send(socket, buffer, count, flags); }
static inline int otsocket_connect(otsocket_t socket, const struct sockaddr *address, socklen_t length)
{ return connect(socket, address, length); }
static inline int otsocket_bind(otsocket_t socket, const struct sockaddr *address, socklen_t length)
{ return bind(socket, address, length); }
static inline int otsocket_listen(otsocket_t socket, int backlog)
{ return listen(socket, backlog); }
static inline otsocket_t otsocket_accept(otsocket_t socket, struct sockaddr *address, socklen_t *length)
{ return accept(socket, address, length); }
static inline int otsocket_getsockname(otsocket_t socket, struct sockaddr *address, socklen_t *length)
{ return getsockname(socket, address, length); }
static inline int otsocket_setsockopt(otsocket_t socket, int level, int option, const void *value, socklen_t length)
{ return setsockopt(socket, level, option, value, length); }
static inline int otsocket_getsockopt(otsocket_t socket, int level, int option, void *value, socklen_t *length)
{ return getsockopt(socket, level, option, value, length); }
static inline int otsocket_shutdown(otsocket_t socket, int how)
{ return shutdown(socket, how); }
static inline int otsocket_set_nonblocking(otsocket_t socket, bool enabled)
{
    int flags = fcntl(socket, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(socket, F_SETFL, enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK);
}
static inline int otsocket_prevent_inheritance(otsocket_t socket)
{
    int flags = fcntl(socket, F_GETFD, 0);
    return flags < 0 ? -1 : fcntl(socket, F_SETFD, flags | FD_CLOEXEC);
}
#endif

/* Darwin's TCP_CONNECTION_INFO uses BSD TCP states; LISTEN is 1.
 * SO_ACCEPTCONN is not implemented by Darwin's getsockopt. */
static inline bool otsocket_is_listening(otsocket_t socket)
{
#if defined(__APPLE__)
    struct tcp_connection_info info = {0};
    socklen_t length = sizeof(info);
    return otsocket_getsockopt(socket, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &length) == 0 &&
        info.tcpi_state == 1;
#else
    int listening = 0;
    socklen_t length = sizeof(listening);
    return otsocket_getsockopt(socket, SOL_SOCKET, SO_ACCEPTCONN, &listening, &length) == 0 && listening;
#endif
}

static inline ssize_t otsocket_read(otsocket_t socket, void *bytes, size_t count)
{ return otsocket_recv(socket, bytes, count, 0); }
static inline ssize_t otsocket_write(otsocket_t socket, const void *bytes, size_t count)
{ return otsocket_send(socket, bytes, count, 0); }

#ifdef MSG_NOSIGNAL
#define OTSOCKET_SEND_FLAGS MSG_NOSIGNAL
#else
#define OTSOCKET_SEND_FLAGS 0
#endif

static inline int otsocket_configure_sigpipe(otsocket_t socket)
{
#ifdef SO_NOSIGPIPE
    int one = 1;
    return otsocket_setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) == 0
        ? 0 : errno;
#else
    (void)socket;
    return 0;
#endif
}
#endif
