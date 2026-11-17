#ifndef OTSOCKET_PAIR_H
#define OTSOCKET_PAIR_H
#include "OTSocket.h"

static inline int otsocket_pair(otsocket_t pair[2])
{
#if !defined(_WIN32)
    return socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
#else
    otsocket_t listener = otsocket_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    otsocket_t client = -1, peer = -1;
    struct sockaddr_in address = {0}, local = {0}, remote = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t size = sizeof(address);
    int exclusive = 1;
    if (listener == -1 || otsocket_setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &exclusive, sizeof(exclusive)) ||
        otsocket_bind(listener, (struct sockaddr *)&address, size) || otsocket_listen(listener, 1) ||
        otsocket_getsockname(listener, (struct sockaddr *)&address, &size)) goto failed;
    client = otsocket_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == -1 || otsocket_connect(client, (struct sockaddr *)&address, size) ||
        otsocket_getsockname(client, (struct sockaddr *)&local, &size)) goto failed;
    peer = otsocket_accept(listener, (struct sockaddr *)&remote, &size);
    if (peer == -1 || remote.sin_addr.s_addr != local.sin_addr.s_addr || remote.sin_port != local.sin_port) goto failed;
    otsocket_close(listener);
    pair[0] = client; pair[1] = peer;
    return 0;
failed:
    if (listener != -1) otsocket_close(listener);
    if (client != -1) otsocket_close(client);
    if (peer != -1) otsocket_close(peer);
    return -1;
#endif
}
#endif
