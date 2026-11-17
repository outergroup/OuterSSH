/* Copyright (C) Sara Golemon <sarag@libssh2.org>
 * Copyright (C) Daniel Stenberg
 * Copyright (C) Simon Josefsson <simon@josefsson.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include "handshake.h"
#include "libssh2/libssh2_priv.h"

void olibssh_handshake_set_socket(LIBSSH2_SESSION *session, libssh2_socket_t socket)
{
    session->socket_fd = socket;
}

int olibssh_handshake_send_banner(LIBSSH2_SESSION *session, size_t *offset)
{
    static const char banner[] = LIBSSH2_SSH_DEFAULT_BANNER_WITH_CRLF;
    while(*offset < sizeof(banner) - 1) {
        ssize_t count = LIBSSH2_SEND(session, banner + *offset,
            sizeof(banner) - 1 - *offset, LIBSSH2_SOCKET_SEND_FLAGS(session));
        if(count == -EAGAIN)
            return LIBSSH2_ERROR_EAGAIN;
        if(count == -EINTR)
            continue;
        if(count <= 0)
            return _libssh2_error(session, LIBSSH2_ERROR_BANNER_SEND,
                                  "Failed sending SSH banner");
        *offset += (size_t)count;
    }
    return 0;
}

int olibssh_handshake_receive_banner(LIBSSH2_SESSION *session,
    char *buffer, size_t capacity, size_t *length)
{
    /* Read only through the identification line. Encrypted transport input
     * may follow it in the same TCP segment. */
    for(;;) {
        char byte;
        ssize_t count = LIBSSH2_RECV(session, &byte, 1,
                                     LIBSSH2_SOCKET_RECV_FLAGS(session));
        if(count == -EAGAIN)
            return LIBSSH2_ERROR_EAGAIN;
        if(count == -EINTR)
            continue;
        if(count <= 0)
            return _libssh2_error(session, LIBSSH2_ERROR_SOCKET_DISCONNECT,
                                  "Connection closed while reading SSH banner");
        if(byte == '\0' || *length == capacity)
            return _libssh2_error(session, LIBSSH2_ERROR_BANNER_RECV,
                                  "Invalid or oversized SSH banner");
        buffer[(*length)++] = byte;
        if(byte != '\n')
            continue;
        if(*length < 4 || memcmp(buffer, "SSH-", 4)) {
            *length = 0;
            continue;
        }
        if(*length < 8 || (memcmp(buffer, "SSH-2.0-", 8) &&
                            (*length < 9 || memcmp(buffer, "SSH-1.99-", 9))))
            return _libssh2_error(session, LIBSSH2_ERROR_BANNER_RECV,
                                  "Server does not support SSH 2");
        while(*length && (buffer[*length - 1] == '\r' || buffer[*length - 1] == '\n'))
            --*length;
        session->remote.banner = LIBSSH2_ALLOC(session, *length + 1);
        if(!session->remote.banner)
            return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                  "Failed allocating SSH banner");
        memcpy(session->remote.banner, buffer, *length);
        session->remote.banner[*length] = '\0';
        return 0;
    }
}
