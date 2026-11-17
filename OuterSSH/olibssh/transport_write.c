/* Copyright (C) The Written Word, Inc.
 * Copyright (C) Daniel Stenberg
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

/*
 * This file handles reading and writing to the SECSH transport layer. RFC4253.
 */

#include "key_exchange_internal.h"
#include "libssh2_priv.h"

#include <errno.h>
#include <ctype.h>
#include <assert.h>

#include "mac.h"

#ifdef LIBSSH2DEBUG
static void
debugdump(LIBSSH2_SESSION * session,
          const char *desc, const unsigned char *ptr, size_t size);
#else
#define debugdump(a,x,y,z) do {} while(0)
#endif

#pragma mark - Write Transport Packets

/*
 * libssh2_transport_send
 *
 * Send a packet, encrypting it and adding a MAC code if necessary
 * Returns 0 on success, non-zero on failure.
 *
 * The data is provided as _two_ data areas that are combined by this
 * function.  The 'data' part is sent immediately before 'data2'. 'data2' may
 * be set to NULL to only use a single part.
 *
 * Returns LIBSSH2_ERROR_EAGAIN if it would block or if the whole packet was
 * not sent yet. Continue with olibssh_transport_resume_write until success
 * or failure. Input is borrowed only during this call; retries use the
 * encrypted output buffer.
 *
 * This function DOES NOT call _libssh2_error() on any errors.
 */
int olibssh_transport_write(LIBSSH2_SESSION *session,
                            const unsigned char *data, size_t data_len,
                            const unsigned char *data2, size_t data2_len)
{
    if(session->packet.ototal_num)
        return LIBSSH2_ERROR_BAD_USE;

    int blocksize =
        (session->state & LIBSSH2_STATE_NEWKEYS) ?
        session->local.crypt->blocksize : 8;
    ssize_t padding_length;
    size_t packet_length;
    ssize_t total_length;
#ifdef LIBSSH2_RANDOM_PADDING
    int rand_max;
    int seed = data[0];         /* FIXME: make this random */
#endif
    struct transportpacket *p = &session->packet;
    int encrypted;
    int compressed;
    int etm;
    int rc;
    const LIBSSH2_MAC_METHOD *local_mac = NULL;
    unsigned int auth_len = 0;
    size_t crypt_offset, etm_crypt_offset;

    /*
     * If the last read operation was interrupted in the middle of a key
     * exchange, we must complete that key exchange before continuing to write
     * further data.
     *
     * See the similar block in _libssh2_transport_read for more details.
     */
    /* OLIBSSH BEGIN: unlike the upstream path described above, the caller
     * advances key exchange explicitly; writing never enters it or reads.
     */
    /* OLIBSSH END */

    debugdump(session, "libssh2_transport_write plain", data, data_len);
    if(data2)
        debugdump(session, "libssh2_transport_write plain2", data2, data2_len);

    encrypted = (session->state & LIBSSH2_STATE_NEWKEYS) ? 1 : 0;

    if(encrypted && session->local.crypt &&
        CRYPT_FLAG_L(session, REQUIRES_FULL_PACKET)) {
        auth_len = session->local.crypt->auth_len;
    }
    else {
        local_mac = session->local.mac;
    }

    etm = encrypted && local_mac ? local_mac->etm : 0;

    compressed = session->local.comp &&
                 session->local.comp->compress &&
                 ((session->state & LIBSSH2_STATE_AUTHENTICATED) ||
                  session->local.comp->use_in_auth);

    if(encrypted && compressed && session->local.comp_abstract) {
        /* the idea here is that these function must fail if the output gets
           larger than what fits in the assigned buffer so thus they don't
           check the input size as we don't know how much it compresses */
        size_t dest_len = MAX_SSH_PACKET_LEN-5-256;
        size_t dest2_len = dest_len;

        /* compress directly to the target buffer */
        rc = session->local.comp->comp(session,
                                       &p->outbuf[5], &dest_len,
                                       data, data_len,
                                       &session->local.comp_abstract);
        if(rc)
            return rc;     /* compression failure */

        if(data2 && data2_len) {
            /* compress directly to the target buffer right after where the
               previous call put data */
            dest2_len -= dest_len;

            rc = session->local.comp->comp(session,
                                           &p->outbuf[5 + dest_len],
                                           &dest2_len,
                                           data2, data2_len,
                                           &session->local.comp_abstract);
        }
        else
            dest2_len = 0;
        if(rc)
            return rc;     /* compression failure */

        data_len = dest_len + dest2_len; /* use the combined length */
    }
    else {
        if((data_len + data2_len) >= (MAX_SSH_PACKET_LEN-0x100))
            /* too large packet, return error for this until we make this
               function split it up and send multiple SSH packets */
            return LIBSSH2_ERROR_INVAL;

        /* copy the payload data */
        memcpy(&p->outbuf[5], data, data_len);
        if(data2 && data2_len)
            memcpy(&p->outbuf[5 + data_len], data2, data2_len);
        data_len += data2_len; /* use the combined length */
    }


    /* RFC4253 says: Note that the length of the concatenation of
       'packet_length', 'padding_length', 'payload', and 'random padding'
       MUST be a multiple of the cipher block size or 8, whichever is
       larger. */

    /* Plain math: (4 + 1 + packet_length + padding_length) % blocksize == 0 */

    packet_length = data_len + 1 + 4;   /* 1 is for padding_length field
                                           4 for the packet_length field */
    /* subtract 4 bytes of the packet_length field when padding AES-GCM
       or with ETM */
    crypt_offset = (etm || auth_len ||
                    (encrypted && CRYPT_FLAG_L(session, PKTLEN_AAD)))
                   ? 4 : 0;
    etm_crypt_offset = etm ? 4 : 0;

    /* at this point we have it all except the padding */

    /* first figure out our minimum padding amount to make it an even
       block size */
    padding_length = blocksize - ((packet_length - crypt_offset) % blocksize);

    /* if the padding becomes too small we add another blocksize worth
       of it (taken from the original libssh2 where it didn't have any
       real explanation) */
    if(padding_length < 4) {
        padding_length += blocksize;
    }
#ifdef LIBSSH2_RANDOM_PADDING
    /* FIXME: we can add padding here, but that also makes the packets
       bigger etc */

    /* now we can add 'blocksize' to the padding_length N number of times
       (to "help thwart traffic analysis") but it must be less than 255 in
       total */
    rand_max = (255 - padding_length) / blocksize + 1;
    padding_length += blocksize * (seed % rand_max);
#endif

    packet_length += padding_length;

    /* append the MAC length to the total_length size */
    total_length =
        packet_length + (encrypted && local_mac ? local_mac->mac_len : 0);

    total_length += auth_len;

    /* store packet_length, which is the size of the whole packet except
       the MAC and the packet_length field itself */
    _libssh2_htonu32(p->outbuf, (uint32_t)(packet_length - 4));
    /* store padding_length */
    p->outbuf[4] = (unsigned char)padding_length;

    /* fill the padding area with random junk */
    if(_libssh2_random(p->outbuf + 5 + data_len, padding_length)) {
        return _libssh2_error(session, LIBSSH2_ERROR_RANDGEN,
                              "Unable to get random bytes for packet padding");
    }

    if(encrypted) {
        size_t i;

        /* Calculate MAC hash. Put the output at index packet_length,
           since that size includes the whole packet. The MAC is
           calculated on the entire unencrypted packet, including all
           fields except the MAC field itself. This is skipped in the
           INTEGRATED_MAC case, where the crypto algorithm also does its
           own hash. */
        if(!etm && local_mac && !CRYPT_FLAG_L(session, INTEGRATED_MAC)) {
            if(local_mac->hash(session, p->outbuf + packet_length,
                               session->local.seqno, p->outbuf,
                               packet_length, NULL, 0,
                               &session->local.mac_abstract))
                return _libssh2_error(session, LIBSSH2_ERROR_MAC_FAILURE,
                                      "Failed to calculate MAC");
        }

        if(CRYPT_FLAG_L(session, REQUIRES_FULL_PACKET)) {
            if(session->local.crypt->crypt(session,
                                           session->local.seqno,
                                           p->outbuf,
                                           packet_length,
                                           &session->local.crypt_abstract,
                                           0)) {
                return LIBSSH2_ERROR_ENCRYPT;
            }
        }
        else {
            /* Encrypt the whole packet data, one block size at a time.
               The MAC field is not encrypted unless INTEGRATED_MAC. */
            /* Some crypto back-ends could handle a single crypt() call for
               encryption, but (presumably) others cannot, so break it up
               into blocksize-sized chunks to satisfy them all. */
            for(i = etm_crypt_offset; i < packet_length;
                i += session->local.crypt->blocksize) {
                size_t block_offset = i;
                unsigned char *ptr = &p->outbuf[block_offset];
                size_t bsize = LIBSSH2_MIN(session->local.crypt->blocksize,
                                           (int)(packet_length-block_offset));
                /* The INTEGRATED_MAC case always has an extra call below, so
                   it will never be LAST_BLOCK up here. */
                int firstlast = block_offset == 0 ? FIRST_BLOCK :
                (!CRYPT_FLAG_L(session, INTEGRATED_MAC)
                 && (block_offset == packet_length -
                     session->local.crypt->blocksize)
                 ? LAST_BLOCK : MIDDLE_BLOCK);
                if(CRYPT_FLAG_L(session, PKTLEN_AAD)) {
                    bsize = packet_length - block_offset;
                    i += bsize - session->local.crypt->blocksize;
                }
                /* In the AAD case, the last block would be only 4 bytes
                   because everything is offset by 4 since the initial
                   packet_length isn't encrypted. In this case, combine that
                   last short packet with the previous one since AES-GCM
                   crypt() assumes that the entire MAC is available in that
                   packet so it can set that to the authentication tag. */
                if(!CRYPT_FLAG_L(session, INTEGRATED_MAC))
                    if(i > packet_length - 2*bsize) {
                        /* increase the final block size */
                        bsize = packet_length - i;
                        /* advance the loop counter by the extra amount */
                        i += bsize - session->local.crypt->blocksize;
                    }
                _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                                "crypting bytes %lu-%lu",
                                (unsigned long)block_offset,
                                (unsigned long)(block_offset + bsize - 1)));
                if(session->local.crypt->crypt(session, 0, ptr,
                                               bsize,
                                               &session->local.crypt_abstract,
                                               firstlast))
                    return LIBSSH2_ERROR_ENCRYPT;     /* encryption failure */
            }

            /* Call crypt() one last time so it can be filled in with the
               MAC */
            if(CRYPT_FLAG_L(session, INTEGRATED_MAC)) {
                int authlen = local_mac ? local_mac->mac_len : 0;
                assert((size_t)total_length <=
                       packet_length + session->local.crypt->blocksize);
                if(session->local.crypt->crypt(session,
                                               0,
                                               &p->outbuf[packet_length],
                                               authlen,
                                               &session->local.crypt_abstract,
                                               LAST_BLOCK))
                    return LIBSSH2_ERROR_ENCRYPT;     /* encryption failure */
            }
        }

        if(etm) {
            /* Calculate MAC hash. Put the output at index packet_length,
               since that size includes the whole packet. The MAC is
               calculated on the entire packet (length plain the rest
               encrypted), including all fields except the MAC field
               itself. */
            if(local_mac->hash(session, p->outbuf + packet_length,
                               session->local.seqno, p->outbuf,
                               packet_length, NULL, 0,
                               &session->local.mac_abstract))
                return _libssh2_error(session, LIBSSH2_ERROR_MAC_FAILURE,
                                      "Failed to calculate MAC");
        }
    }

    session->local.seqno++;

    if(session->kex_strict && data[0] == SSH_MSG_NEWKEYS) {
        session->local.seqno = 0;
    }

    p->osent = 0;
    p->ototal_num = total_length;
    return olibssh_transport_resume_write(session);
}

int olibssh_transport_resume_write(LIBSSH2_SESSION *session)
{
    struct transportpacket *p = &session->packet;
    if(!p->ototal_num)
        return LIBSSH2_ERROR_BAD_USE;

    ssize_t length = p->ototal_num - p->osent;
    ssize_t sent = LIBSSH2_SEND(session, &p->outbuf[p->osent], length,
                               LIBSSH2_SOCKET_SEND_FLAGS(session));
    if(sent < 0) {
        _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                       "Error sending %ld bytes: %ld",
                       (long)length, (long)-sent));
        if(sent != -EAGAIN)
            return LIBSSH2_ERROR_SOCKET_SEND;
    }
    else {
        _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                       "Sent %ld/%ld bytes at %p+%lu", (long)sent, (long)length,
                       (void *)p->outbuf, (unsigned long)p->osent));
        debugdump(session, "libssh2_transport_write send()",
                  &p->outbuf[p->osent], sent);
        p->osent += sent;
        if(sent == length) {
            p->ototal_num = 0;
            p->osent = 0;
            return 0;
        }
    }
    return LIBSSH2_ERROR_EAGAIN;
}

#pragma mark - Debug Packet Tracing

#ifdef LIBSSH2DEBUG
#define UNPRINTABLE_CHAR '.'
static void
debugdump(LIBSSH2_SESSION * session,
          const char *desc, const unsigned char *ptr, size_t size)
{
    size_t i;
    size_t c;
    unsigned int width = 0x10;
    char buffer[256];  /* Must be enough for width*4 + about 30 or so */
    size_t used;
    static const char *hex_chars = "0123456789ABCDEF";

    if(!(session->showmask & LIBSSH2_TRACE_TRANS)) {
        /* not asked for, bail out */
        return;
    }

    used = snprintf(buffer, sizeof(buffer), "=> %s (%lu bytes)\n",
                    desc, (unsigned long) size);
    if(session->tracehandler)
        (session->tracehandler)(session, session->tracehandler_context,
                                buffer, used);
    else
        fprintf(stderr, "%s", buffer);

    for(i = 0; i < size; i += width) {

        used = snprintf(buffer, sizeof(buffer), "%04lx: ", (long)i);

        /* hex not disabled, show it */
        for(c = 0; c < width; c++) {
            if(i + c < size) {
                buffer[used++] = hex_chars[(ptr[i + c] >> 4) & 0xF];
                buffer[used++] = hex_chars[ptr[i + c] & 0xF];
            }
            else {
                buffer[used++] = ' ';
                buffer[used++] = ' ';
            }

            buffer[used++] = ' ';
            if((width/2) - 1 == c)
                buffer[used++] = ' ';
        }

        buffer[used++] = ':';
        buffer[used++] = ' ';

        for(c = 0; (c < width) && (i + c < size); c++) {
            buffer[used++] = isprint(ptr[i + c]) ?
                ptr[i + c] : UNPRINTABLE_CHAR;
        }
        buffer[used] = 0;

        if(session->tracehandler)
            (session->tracehandler)(session, session->tracehandler_context,
                                    buffer, used);
        else
            fprintf(stderr, "%s\n", buffer);
    }
}
#endif
