#include <errno.h>
/* Copyright (C) The Written Word, Inc.
 * Copyright (C) Daniel Stenberg
 * Copyright (C) Sara Golemon <sarag@libssh2.org>
 * Copyright (C) Mikhail Gusarov
 * Copyright (C) Simon Josefsson
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

#include "read_dispatch.h"
#include "../SSHReactorReadInternal.h"

#if !defined(_WIN32)
#include <sys/uio.h>
#endif
#include <stdlib.h>
#include <ctype.h>

#include "libssh2/libssh2_priv.h"

#include <libssh2.h>
#include <mac.h>
#include <assert.h>

static int
decrypt(LIBSSH2_SESSION * session, unsigned char *source,
        unsigned char *dest, ssize_t len, int firstlast);
static int
fullpacket_dispatch(LIBSSH2_SESSION *session, int encrypted, SSHReactor *reactor);
static int
dispatch_packet(SSHReactor *reactor, LIBSSH2_SESSION *session, unsigned char *data,
                size_t datalen, int macstate, uint32_t seq);
#ifdef LIBSSH2DEBUG
static void
debugdump(LIBSSH2_SESSION * session,
          const char *desc, const unsigned char *ptr, size_t size);
#else
#define debugdump(a,x,y,z) do {} while(0)
#endif

#pragma mark - Read Transport Packets

int olibssh_transport_has_buffered_input(LIBSSH2_SESSION *session)
{
    return session->packet.readidx < session->packet.writeidx;
}

int olibssh_transport_read(LIBSSH2_SESSION *session, SSHReactor *reactor)
{
   int rc;
   struct transportpacket *p = &session->packet;
   ssize_t remainpack; /* how much there is left to add to the current payload
                          package */
   ssize_t remainbuf;  /* how much data there is remaining in the buffer to
                          deal with before we should read more from the
                          network */
   ssize_t numbytes;   /* how much data to deal with from the buffer on this
                          iteration through the loop */
   ssize_t numdecrypt; /* number of bytes to decrypt this iteration */
   unsigned char block[MAX_BLOCKSIZE]; /* working block buffer */
   int blocksize;  /* minimum number of bytes we need before we can
                      use them */
   int encrypted = 1; /* whether the packet is encrypted or not */
   int firstlast = FIRST_BLOCK; /* if the first or last block to decrypt */
   unsigned int auth_len = 0; /* length of the authentication tag */
   const LIBSSH2_MAC_METHOD *remote_mac = NULL; /* The remote MAC, if used */

   block[4] = 0;

   /* SSHReactor advances key exchange explicitly between transport packets. */

   do {
       int etm;
       if(session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) {
           return LIBSSH2_ERROR_SOCKET_DISCONNECT;
       }

       if(session->state & LIBSSH2_STATE_NEWKEYS) {
           blocksize = session->remote.crypt->blocksize;
       }
       else {
           encrypted = 0;      /* not encrypted */
           blocksize = 5;      /* not strictly true, but we can use 5 here to
                                  make the checks below work fine still */
       }

       if(encrypted) {
           if(CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
               auth_len = session->remote.crypt->auth_len;
           }
           else {
               remote_mac = session->remote.mac;
           }
       }

       etm = encrypted && remote_mac ? remote_mac->etm : 0;

       /* read/use a whole big chunk into a temporary area stored in
          the LIBSSH2_SESSION struct. We will decrypt data from that
          buffer into the packet buffer so this temp one doesn't have
          to be able to keep a whole SSH packet, just be large enough
          so that we can read big chunks from the network layer. */

       /* how much data there is remaining in the buffer to deal with
          before we should read more from the network */
       remainbuf = p->writeidx - p->readidx;

       /* if remainbuf turns negative we have a bad internal error */
       assert(remainbuf >= 0);

       if(remainbuf < blocksize ||
          (CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)
           && ((ssize_t)p->total_num) > remainbuf)) {
           /* If we have less than a blocksize left, it is too
              little data to deal with, read more */
           ssize_t nread;

           /* move any remainder to the start of the buffer so
              that we can do a full refill */
           if(remainbuf) {
               memmove(p->buf, &p->buf[p->readidx], remainbuf);
               p->readidx = 0;
               p->writeidx = remainbuf;
           }
           else {
               /* nothing to move, just zero the indexes */
               p->readidx = p->writeidx = 0;
           }

           /* now read a big chunk from the network into the temp buffer */
           nread = LIBSSH2_RECV(session, &p->buf[remainbuf],
                                PACKETBUFSIZE - remainbuf,
                                LIBSSH2_SOCKET_RECV_FLAGS(session));
           if(nread <= 0) {
               /* check if this is due to EAGAIN and return the special
                  return code if so, error out normally otherwise */
               if((nread < 0) && (nread == -EAGAIN)) {
                   return LIBSSH2_ERROR_EAGAIN;
               }
               _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                              "Error recving %ld bytes (got %ld)",
                              (long)(PACKETBUFSIZE - remainbuf),
                              (long)-nread));
               return LIBSSH2_ERROR_SOCKET_RECV;
           }
           _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                          "Recved %ld/%ld bytes to %p+%ld", (long)nread,
                          (long)(PACKETBUFSIZE - remainbuf), (void *)p->buf,
                          (long)remainbuf));

           debugdump(session, "libssh2_transport_read() raw",
                     &p->buf[remainbuf], nread);
           /* advance write pointer */
           p->writeidx += nread;

           /* update remainbuf counter */
           remainbuf = p->writeidx - p->readidx;
       }

       /* how much data to deal with from the buffer */
       numbytes = remainbuf;

       if(!p->total_num) {
           size_t total_num; /* the number of bytes following the initial
                                (5 bytes) packet length and padding length
                                fields */

           /* packet length is not encrypted in encode-then-mac mode
              and we donøt need to decrypt first block */
           ssize_t required_size = etm ? 4 : blocksize;

           /* No payload package area allocated yet. To know the
              size of this payload, we need enough to decrypt the first
              blocksize data. */

           if(numbytes < required_size) {
               /* we can't act on anything less than blocksize, but this
                  check is only done for the initial block since once we have
                  got the start of a block we can in fact deal with fractions
               */
               return LIBSSH2_ERROR_EAGAIN;
           }

           if(etm) {
               /* etm size field is not encrypted */
               memcpy(block, &p->buf[p->readidx], 4);
               memcpy(p->init, &p->buf[p->readidx], 4);
           }
           else if(encrypted && session->remote.crypt->get_len) {
               unsigned int len = 0;
               unsigned char *ptr = NULL;

               rc = session->remote.crypt->get_len(session,
                                           session->remote.seqno,
                                           &p->buf[p->readidx],
                                           numbytes,
                                           &len,
                                           &session->remote.crypt_abstract);

               if(rc != LIBSSH2_ERROR_NONE) {
                   p->total_num = 0;   /* no packet buffer available */
                   if(p->payload)
                       LIBSSH2_FREE(session, p->payload);
                   p->payload = NULL;
                   return rc;
               }

               /* store size in buffers for use below */
               ptr = &block[0];
               _libssh2_store_u32(&ptr, len);

               ptr = &p->init[0];
               _libssh2_store_u32(&ptr, len);
           }
           else {
               if(encrypted) {
                   /* first decrypted block */
                   rc = decrypt(session, &p->buf[p->readidx],
                                block, blocksize, FIRST_BLOCK);
                   if(rc != LIBSSH2_ERROR_NONE) {
                       return rc;
                   }
                   /* Save the first 5 bytes of the decrypted package, to be
                      used in the hash calculation later down.
                      This is ignored in the INTEGRATED_MAC case. */
                   memcpy(p->init, block, 5);
               }
               else {
                   /* the data is plain, just copy it verbatim to
                      the working block buffer */
                   memcpy(block, &p->buf[p->readidx], blocksize);
               }

               /* advance the read pointer */
               p->readidx += blocksize;

               /* we now have the initial blocksize bytes decrypted,
                * and we can extract packet and padding length from it
                */
               p->packet_length = _libssh2_ntohu32(block);
           }

           if(!encrypted || !CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
               if(p->packet_length < 1) {
                   return LIBSSH2_ERROR_DECRYPT;
               }
               else if(p->packet_length > LIBSSH2_PACKET_MAXPAYLOAD) {
                   return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
               }

               if(etm) {
                   /* we collect entire undecrypted packet including the
                      packet length field that we run MAC over */
                   p->packet_length = _libssh2_ntohu32(block);
                   total_num = 4 + p->packet_length +
                       remote_mac->mac_len;
               }
               else {
                   /* padding_length has not been authenticated yet, but it
                      won't actually be used (except for the sanity check
                      immediately following) until after the entire packet is
                      authenticated, so this is safe. */
                   p->padding_length = block[4];
                   if(p->padding_length > p->packet_length - 1) {
                       return LIBSSH2_ERROR_DECRYPT;
                   }

                   /* total_num is the number of bytes following the initial
                      (5 bytes) packet length and padding length fields */
                   total_num = p->packet_length - 1 +
                       (encrypted && remote_mac ? remote_mac->mac_len : 0);
               }
           }
           else {
               /* advance the read pointer past size field if the packet
                  length is not required for decryption */

               /* add size field to be included in total packet size
                * calculation so it doesn't get dropped off on subsequent
                * partial reads
                */
               total_num = 4;

               p->packet_length = _libssh2_ntohu32(block);
               if(p->packet_length < 1)
                   return LIBSSH2_ERROR_DECRYPT;

               /* total_num may include size field, however due to existing
                * logic it needs to be removed after the entire packet is read
                */

               total_num += p->packet_length +
                   (remote_mac ? remote_mac->mac_len : 0) + auth_len;

               /* don't know what padding is until we decrypt the full
                  packet */
               p->padding_length = 0;
           }

           /* RFC4253 section 6.1 Maximum Packet Length says:
            *
            * "All implementations MUST be able to process
            * packets with uncompressed payload length of 32768
            * bytes or less and total packet size of 35000 bytes
            * or less (including length, padding length, payload,
            * padding, and MAC.)."
            */
           if(total_num > LIBSSH2_PACKET_MAXPAYLOAD || total_num == 0) {
               return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
           }

           /* Get a packet handle put data into. We get one to
              hold all data, including padding and MAC. */
           p->payload = LIBSSH2_ALLOC(session, total_num);
           if(!p->payload) {
               return LIBSSH2_ERROR_ALLOC;
           }
           p->total_num = total_num;
           /* init write pointer to start of payload buffer */
           p->wptr = p->payload;

           if(!encrypted || !CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
               if(!etm && blocksize > 5) {
                   /* copy the data from index 5 to the end of
                      the blocksize from the temporary buffer to
                      the start of the decrypted buffer */
                   if(blocksize - 5 <= (int) total_num) {
                       memcpy(p->wptr, &block[5], blocksize - 5);
                       p->wptr += blocksize - 5; /* advance write pointer */
                       if(etm) {
                           /* advance past unencrypted packet length */
                           p->wptr += 4;
                       }
                   }
                   else {
                       if(p->payload)
                           LIBSSH2_FREE(session, p->payload);
                       return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
                   }
               }

               /* init the data_num field to the number of bytes of
                  the package read so far */
               p->data_num = p->wptr - p->payload;

               /* we already dealt with a blocksize worth of data */
               if(!etm)
                   numbytes -= blocksize;
           }
           else {
               /* haven't started reading payload yet */
               p->data_num = 0;

               /* we already dealt with packet size worth of data */
               if(!encrypted)
                   numbytes -= 4;
           }
       }

       /* how much there is left to add to the current payload
          package */
       remainpack = p->total_num - p->data_num;

       if(numbytes > remainpack) {
           /* if we have more data in the buffer than what is going into this
              particular packet, we limit this round to this packet only */
           numbytes = remainpack;
       }

       if(encrypted && CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
           if(numbytes < remainpack) {
               /* need a full packet before checking MAC */
               return LIBSSH2_ERROR_EAGAIN;
           }

           /* we have a full packet, now remove the size field from numbytes
              and total_num to process only the packet data */
           numbytes -= 4;
           p->total_num -= 4;
       }

       if(encrypted && !etm) {
           /* At the end of the incoming stream, there is a MAC,
              and we don't want to decrypt that since we need it
              "raw". We MUST however decrypt the padding data
              since it is used for the hash later on. */
           int skip = (remote_mac ? remote_mac->mac_len : 0) + auth_len;

           if(CRYPT_FLAG_R(session, INTEGRATED_MAC))
               /* This crypto method DOES need the MAC to go through
                  decryption so it can be authenticated. */
               skip = 0;

           /* if what we have plus numbytes is bigger than the
              total minus the skip margin, we should lower the
              amount to decrypt even more */
           if((p->data_num + numbytes) >= (p->total_num - skip)) {
               /* decrypt the entire rest of the package */
               numdecrypt = LIBSSH2_MAX(0,
                   (int)(p->total_num - skip) - (int)p->data_num);
               firstlast = LAST_BLOCK;
           }
           else {
               ssize_t frac;
               numdecrypt = numbytes;
               frac = numdecrypt % blocksize;
               if(frac) {
                   /* not an aligned amount of blocks, align it by reducing
                      the number of bytes processed this loop */
                   numdecrypt -= frac;
                   /* and make it no unencrypted data
                      after it */
                   numbytes = 0;
               }
               if(CRYPT_FLAG_R(session, INTEGRATED_MAC)) {
                   /* Make sure that we save enough bytes to make the last
                    * block large enough to hold the entire integrated MAC */
                   numdecrypt = LIBSSH2_MIN(numdecrypt,
                       (int)(p->total_num - skip - blocksize - p->data_num));
                   numbytes = 0;
               }
               firstlast = MIDDLE_BLOCK;
           }
       }
       else {
           /* unencrypted data should not be decrypted at all */
           numdecrypt = 0;
       }
       assert(numdecrypt >= 0);

       /* if there are bytes to decrypt, do that */
       if(numdecrypt > 0) {
           /* now decrypt the lot */
           if(CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
               rc = session->remote.crypt->crypt(session,
                                              session->remote.seqno,
                                              &p->buf[p->readidx],
                                              numdecrypt,
                                              &session->remote.crypt_abstract,
                                              0);

               if(rc != LIBSSH2_ERROR_NONE) {
                   LIBSSH2_FREE(session, p->payload);
                   p->payload = NULL;
                   p->total_num = 0;
                   return rc;
               }

               memcpy(p->wptr, &p->buf[p->readidx], numbytes);

               /* advance read index past size field now that we've decrypted
                  full packet */
               p->readidx += 4;

               /* include auth tag in bytes decrypted */
               numdecrypt += auth_len;

               /* set padding now that the packet has been verified and
                  decrypted */
               p->padding_length = p->wptr[0];

               if(p->padding_length > p->packet_length - 1) {
                   return LIBSSH2_ERROR_DECRYPT;
               }
           }
           else {
               rc = decrypt(session, &p->buf[p->readidx], p->wptr, numdecrypt,
                            firstlast);

               if(rc != LIBSSH2_ERROR_NONE) {
                   p->total_num = 0;   /* no packet buffer available */
                   return rc;
               }
           }

           /* advance the read pointer */
           p->readidx += numdecrypt;
           /* advance write pointer */
           p->wptr += numdecrypt;
           /* increase data_num */
           p->data_num += numdecrypt;

           /* bytes left to take care of without decryption */
           numbytes -= numdecrypt;
       }

       /* if there are bytes to copy that aren't decrypted,
          copy them as-is to the target buffer */
       if(numbytes > 0) {

           if((size_t)numbytes <= (p->total_num - (p->wptr - p->payload))) {
               memcpy(p->wptr, &p->buf[p->readidx], numbytes);
           }
           else {
               if(p->payload)
                   LIBSSH2_FREE(session, p->payload);
               return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
           }

           /* advance the read pointer */
           p->readidx += numbytes;
           /* advance write pointer */
           p->wptr += numbytes;
           /* increase data_num */
           p->data_num += numbytes;
       }

       /* now check how much data there's left to read to finish the
          current packet */
       remainpack = p->total_num - p->data_num;

       if(!remainpack) {
           return fullpacket_dispatch(session, encrypted, reactor);
       }
   } while(1);                /* loop */

   return LIBSSH2_ERROR_SOCKET_RECV; /* we never reach this point */
}

#pragma mark - Decrypt and Validate Packets

static int
decrypt(LIBSSH2_SESSION * session, unsigned char *source,
        unsigned char *dest, ssize_t len, int firstlast)
{
    struct transportpacket *p = &session->packet;
    int blocksize = session->remote.crypt->blocksize;

    /* if we get called with a len that isn't an even number of blocksizes
       we risk losing those extra bytes. AAD is an exception, since those first
       few bytes aren't encrypted so it throws off the rest of the count. */
    if(!CRYPT_FLAG_R(session, PKTLEN_AAD))
        assert((len % blocksize) == 0);

    while(len > 0) {
        /* normally decrypt up to blocksize bytes at a time */
        ssize_t decryptlen = CRYPT_FLAG_R(session, PKTLEN_AAD) ? len :
            LIBSSH2_MIN(blocksize, len);
        /* The first block is special (since it needs to be decoded to get the
           length of the remainder of the block) and takes priority. When the
           length finally gets to the last blocksize bytes, and there's no
           more data to come, it's the end. */
        int lowerfirstlast = IS_FIRST(firstlast) ? FIRST_BLOCK :
            ((len <= decryptlen) ? firstlast : MIDDLE_BLOCK);
        /* If the last block would be less than a whole blocksize, combine it
           with the previous block to make it larger. This ensures that the
           whole MAC is included in a single decrypt call. */
        if(CRYPT_FLAG_R(session, PKTLEN_AAD) && IS_LAST(firstlast)
           && (len < blocksize*2)) {
            decryptlen = len;
            lowerfirstlast = LAST_BLOCK;
        }

        if(session->remote.crypt->crypt(session, 0, source, decryptlen,
                                        &session->remote.crypt_abstract,
                                        lowerfirstlast)) {
            LIBSSH2_FREE(session, p->payload);
            return LIBSSH2_ERROR_DECRYPT;
        }

        /* if the crypt() function would write to a given address it
           wouldn't have to memcpy() and we could avoid this memcpy()
           too */
        memcpy(dest, source, decryptlen);

        len -= decryptlen;       /* less bytes left */
        dest += decryptlen;      /* advance write pointer */
        source += decryptlen;    /* advance read pointer */
    }
    return LIBSSH2_ERROR_NONE;         /* all is fine */
}

static int
fullpacket_dispatch(LIBSSH2_SESSION *session, int encrypted, SSHReactor *reactor)
{
    unsigned char macbuf[MAX_MACSIZE];
    struct transportpacket *p = &session->packet;
    int rc;
    int compressed;
    int macstate = LIBSSH2_MAC_CONFIRMED;
    size_t payload_length = p->packet_length - 1;
    const LIBSSH2_MAC_METHOD *remote_mac = NULL;
    uint32_t seq = session->remote.seqno;

    if(!encrypted || (!CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET) &&
                      !CRYPT_FLAG_R(session, INTEGRATED_MAC))) {
        remote_mac = session->remote.mac;
    }


    if(encrypted && remote_mac) {

        /* Calculate MAC hash */
        int etm = remote_mac->etm;
        size_t mac_len = remote_mac->mac_len;
        if(etm) {
            /* store hash here */
            remote_mac->hash(session, macbuf,
                             session->remote.seqno,
                             p->payload, p->total_num - mac_len,
                             NULL, 0,
                             &session->remote.mac_abstract);
        }
        else {
            /* store hash here */
            remote_mac->hash(session, macbuf,
                             session->remote.seqno,
                             p->init, 5,
                             p->payload,
                             payload_length,
                             &session->remote.mac_abstract);
        }

        /* Compare the calculated hash with the MAC we just read from
         * the network. The read one is at the very end of the payload
         * buffer. Note that 'payload_len' here is the packet_length
         * field which includes the padding but not the MAC.
         */
        if(memcmp(macbuf, p->payload + p->total_num - mac_len, mac_len)) {
            _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                           "Failed MAC check"));
            macstate = LIBSSH2_MAC_INVALID;

        }
        else if(etm) {
            /* MAC was ok and we start by decrypting the first block that
               contains padding length since this allows us to decrypt
               all other blocks to the right location in memory
               avoiding moving a larger block of memory one byte. */
            unsigned char first_block[MAX_BLOCKSIZE];
            ssize_t decrypt_size;
            unsigned char *decrypt_buffer;
            int blocksize = session->remote.crypt->blocksize;

            first_block[0] = 0;

            rc = decrypt(session, p->payload + 4,
                         first_block, blocksize, FIRST_BLOCK);
            if(rc) {
                return rc;
            }

            /* we need buffer for decrypt */
            decrypt_size = p->total_num - mac_len - 4;
            decrypt_buffer = LIBSSH2_ALLOC(session, decrypt_size);
            if(!decrypt_buffer) {
                return LIBSSH2_ERROR_ALLOC;
            }

            /* grab padding length and copy anything else
               into target buffer */
            p->padding_length = first_block[0];
            if(blocksize > 1) {
                memcpy(decrypt_buffer, first_block + 1, blocksize - 1);
            }

            /* decrypt all other blocks packet */
            if(blocksize < decrypt_size) {
                rc = decrypt(session, p->payload + blocksize + 4,
                             decrypt_buffer + blocksize - 1,
                             decrypt_size - blocksize, LAST_BLOCK);
                if(rc) {
                    LIBSSH2_FREE(session, decrypt_buffer);
                    return rc;
                }
            }

            /* replace encrypted payload with plain text payload */
            LIBSSH2_FREE(session, p->payload);
            p->payload = decrypt_buffer;
        }
    }
    else if(encrypted && CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
        /* etm trim off padding byte from payload */
        memmove(p->payload, &p->payload[1], p->packet_length - 1);
    }

    session->remote.seqno++;

    /* ignore the padding */
    if(p->padding_length >= payload_length) {
        LIBSSH2_FREE(session, p->payload);
        p->payload = NULL;
        p->total_num = 0;
        return _libssh2_error(session, LIBSSH2_ERROR_PROTO, "Invalid SSH packet padding");
    }
    payload_length -= p->padding_length;

    /* Check for and deal with decompression */
    compressed = session->local.comp &&
                 session->local.comp->compress &&
                 ((session->state & LIBSSH2_STATE_AUTHENTICATED) ||
                  session->local.comp->use_in_auth);

    if(compressed && session->remote.comp_abstract) {
        /*
         * The buffer for the decompression (remote.comp_abstract) is
         * initialised in time when it is needed so as long it is NULL we
         * cannot decompress.
         */

        unsigned char *data;
        size_t data_len;
        rc = session->remote.comp->decomp(session,
                                          &data, &data_len,
                                          LIBSSH2_PACKET_MAXDECOMP,
                                          p->payload,
                                          payload_length,
                                          &session->remote.comp_abstract);
        LIBSSH2_FREE(session, p->payload);
        if(rc)
            return rc;

        p->payload = data;
        payload_length = data_len;
    }

    if(payload_length == 0) {
        LIBSSH2_FREE(session, p->payload);
        p->payload = NULL;
        p->total_num = 0;
        return _libssh2_error(session, LIBSSH2_ERROR_PROTO, "Empty SSH packet");
    }
    int packet_type = p->payload[0];

    debugdump(session, "libssh2_transport_read() plain",
              p->payload, payload_length);


    unsigned char *data = p->payload;
    p->payload = NULL;
    p->total_num = 0;
    if (session->kex_strict && packet_type == SSH_MSG_NEWKEYS) {
        session->remote.seqno = 0;
    }

    /* Dispatch owns data. It may free channels or consume key-exchange packets;
     * do not inspect the completed packet or its channel after this call. */
    rc = dispatch_packet(reactor, session, data, payload_length, macstate, seq);
    return rc != 0 ? rc : packet_type;
}

#pragma mark - Deliver Packets to the Reactor

/* Takes ownership of a completed packet. Channel payloads are borrowed by
 * reactor handlers only for the call; key-exchange packets transfer ownership
 * to the exchange. */
static int
dispatch_packet(SSHReactor *reactor, LIBSSH2_SESSION *session, unsigned char *data,
                size_t datalen, int macstate, uint32_t seq)
{
    int rc = 0;
    unsigned char *message = NULL;
    unsigned char *language = NULL;
    size_t message_len = 0;
    size_t language_len = 0;
    size_t data_head = 0;
    unsigned char msg = data[0];

    uint32_t channel = 0;
    uint32_t len = 0;
    uint32_t stream_id = 0;
    unsigned char want_reply = 0;

    if((macstate == LIBSSH2_MAC_INVALID) &&
       (!session->macerror || LIBSSH2_MACERROR(session, (char *)data, datalen))) {
        LIBSSH2_FREE(session, data);
        return _libssh2_error(session, LIBSSH2_ERROR_INVALID_MAC, "Invalid MAC received");
    }

    if(session->state & LIBSSH2_STATE_INITIAL_KEX) {
        if(msg == SSH_MSG_KEXINIT) {
            if(!session->kex_strict) {
                if(datalen < 17) {
                    LIBSSH2_FREE(session, data);

                    return _libssh2_error(session,
                                          LIBSSH2_ERROR_BUFFER_TOO_SMALL,
                                          "Data too short extracting kex");
                }
                else {
                    const unsigned char *strict =
                        (const unsigned char *)"kex-strict-s-v00@openssh.com";
                    struct string_buf buf;
                    unsigned char *algs = NULL;
                    size_t algs_len = 0;

                    buf.data = (unsigned char *)data;
                    buf.dataptr = buf.data;
                    buf.len = datalen;
                    buf.dataptr += 17; /* advance past type and cookie */

                    if(_libssh2_get_string(&buf, &algs, &algs_len)) {
                        LIBSSH2_FREE(session, data);

                        return _libssh2_error(session,
                                              LIBSSH2_ERROR_BUFFER_TOO_SMALL,
                                              "Algs too short");
                    }

                    if(algs_len == 0 ||
                       _libssh2_kex_agree_instr(algs, algs_len, strict, 28)) {
                        session->kex_strict = 1;
                    }
                }
            }

            if(session->kex_strict && seq) {
                LIBSSH2_FREE(session, data);
                session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;

                /* OLIBSSH: report the failure without writing from a read. */

                return _libssh2_error(session, LIBSSH2_ERROR_SOCKET_DISCONNECT,
                                      "strict KEX violation: "
                                      "KEXINIT was not the first packet");
            }
        }

        if(session->kex_strict && session->fullpacket_required_type &&
            session->fullpacket_required_type != msg) {
            LIBSSH2_FREE(session, data);
            session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;

            /* OLIBSSH: report the failure without writing from a read. */

            return _libssh2_error(session, LIBSSH2_ERROR_SOCKET_DISCONNECT,
                                  "strict KEX violation: "
                                  "unexpected packet type");
        }
    }

    switch(msg) {
    case SSH_MSG_USERAUTH_FAILURE:
    case SSH_MSG_USERAUTH_SUCCESS:
    case SSH_MSG_USERAUTH_BANNER:
    case SSH_MSG_USERAUTH_PK_OK: /* Also password change and keyboard prompts. */
        outersshpriv_reactor_received_authentication(reactor, data, datalen);
        LIBSSH2_FREE(session, data);
        return 0;

    case SSH_MSG_SERVICE_ACCEPT:
        outersshpriv_reactor_received_service_accept(reactor, data, datalen);
        LIBSSH2_FREE(session, data);
        return 0;


        /*
          byte      SSH_MSG_DISCONNECT
          uint32    reason code
          string    description in ISO-10646 UTF-8 encoding [RFC3629]
          string    language tag [RFC3066]
        */

    case SSH_MSG_DISCONNECT:
        if(datalen >= 5) {
            uint32_t reason = 0;
            struct string_buf buf;
            buf.data = (unsigned char *)data;
            buf.dataptr = buf.data;
            buf.len = datalen;
            buf.dataptr++; /* advance past type */

            _libssh2_get_u32(&buf, &reason);
            _libssh2_get_string(&buf, &message, &message_len);
            _libssh2_get_string(&buf, &language, &language_len);

            if(session->ssh_msg_disconnect) {
                LIBSSH2_DISCONNECT(session, reason, (const char *)message,
                                   message_len, (const char *)language,
                                   language_len);
            }

            _libssh2_debug((session, LIBSSH2_TRACE_TRANS,
                           "Disconnect(%d): %s(%s)", reason,
                           message, language));
        }

        LIBSSH2_FREE(session, data);
        session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;

        return _libssh2_error(session, LIBSSH2_ERROR_SOCKET_DISCONNECT,
                              "socket disconnect");
        /*
          byte      SSH_MSG_IGNORE
          string    data
        */

    case SSH_MSG_IGNORE:
        if(datalen >= 2) {
            if(session->ssh_msg_ignore) {
                LIBSSH2_IGNORE(session, (char *) data + 1, datalen - 1);
            }
        }
        else if(session->ssh_msg_ignore) {
            LIBSSH2_IGNORE(session, "", 0);
        }
        LIBSSH2_FREE(session, data);

        return 0;

        /*
          byte      SSH_MSG_DEBUG
          boolean   always_display
          string    message in ISO-10646 UTF-8 encoding [RFC3629]
          string    language tag [RFC3066]
        */

    case SSH_MSG_DEBUG:
        if(datalen >= 2) {
            int always_display = data[1];

            if(datalen >= 6) {
                struct string_buf buf;
                buf.data = (unsigned char *)data;
                buf.dataptr = buf.data;
                buf.len = datalen;
                buf.dataptr += 2; /* advance past type & always display */

                _libssh2_get_string(&buf, &message, &message_len);
                _libssh2_get_string(&buf, &language, &language_len);
            }

            if(session->ssh_msg_debug) {
                LIBSSH2_DEBUG(session, always_display,
                              (const char *)message,
                              message_len, (const char *)language,
                              language_len);
            }
        }

        /*
         * _libssh2_debug() will actually truncate this for us so
         * that it's not an inordinate about of data
         */
        _libssh2_debug((session, LIBSSH2_TRACE_TRANS,
                       "Debug Packet: %s", message));
        LIBSSH2_FREE(session, data);

        return 0;

        /*
          byte      SSH_MSG_EXT_INFO
          uint32    nr-extensions
          [repeat   "nr-extensions" times]
          string    extension-name  [RFC8308]
          string    extension-value (binary)
        */

    case SSH_MSG_EXT_INFO:
        if(datalen >= 5) {
            uint32_t nr_extensions = 0;
            struct string_buf buf;
            buf.data = (unsigned char *)data;
            buf.dataptr = buf.data;
            buf.len = datalen;
            buf.dataptr += 1; /* advance past type */

            if(_libssh2_get_u32(&buf, &nr_extensions) != 0) {
                rc = _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                                    "Invalid extension info received");
            }

            while(rc == 0 && nr_extensions > 0) {

                size_t name_len = 0;
                size_t value_len = 0;
                unsigned char *name = NULL;
                unsigned char *value = NULL;

                nr_extensions -= 1;

                _libssh2_get_string(&buf, &name, &name_len);
                _libssh2_get_string(&buf, &value, &value_len);

                if(name && value) {
                    _libssh2_debug((session,
                                   LIBSSH2_TRACE_KEX,
                                   "Server to Client extension %.*s: %.*s",
                                   (int)name_len, name,
                                   (int)value_len, value));
                }

                if(name && name_len == 15 &&
                    memcmp(name, "server-sig-algs", 15) == 0) {
                    if(session->server_sign_algorithms) {
                        LIBSSH2_FREE(session,
                                     session->server_sign_algorithms);
                    }

                    session->server_sign_algorithms =
                                            LIBSSH2_ALLOC(session,
                                                          value_len + 1);

                    if(value && session->server_sign_algorithms) {
                        memcpy(session->server_sign_algorithms,
                               value, value_len);
                        session->server_sign_algorithms[value_len] = '\0';
                    }
                    else {
                        rc = _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                            "memory for server sign algo");
                    }
                }
            }
        }

        LIBSSH2_FREE(session, data);

        return rc;

        /*
          byte      SSH_MSG_GLOBAL_REQUEST
          string    request name in US-ASCII only
          boolean   want reply
          ....      request-specific data follows
        */

    case SSH_MSG_GLOBAL_REQUEST:
        if(datalen >= 5) {
            want_reply = 0;
            len = _libssh2_ntohu32(data + 1);
            if((len <= (UINT_MAX - 6)) && (datalen >= (6 + len))) {
                want_reply = data[5 + len];
                _libssh2_debug((session,
                               LIBSSH2_TRACE_CONN,
                               "Received global request type %.*s (wr %X)",
                               (int)len, data + 5, want_reply));
            }

            if(want_reply) {
                const unsigned char response = SSH_MSG_REQUEST_FAILURE;
                outersshpriv_reactor_queue_protocol_response(reactor, &response, 1);
            }
        }
        LIBSSH2_FREE(session, data);

        return 0;

    case SSH_MSG_REQUEST_SUCCESS:
    case SSH_MSG_REQUEST_FAILURE:
        /* Handle global request response */
        outersshpriv_reactor_received_global_response(reactor, msg == SSH_MSG_REQUEST_SUCCESS);
        LIBSSH2_FREE(session, data);

        return 0;

        /*
          byte      SSH_MSG_CHANNEL_EXTENDED_DATA
          uint32    recipient channel
          uint32    data_type_code
          string    data
        */

    case SSH_MSG_CHANNEL_EXTENDED_DATA:
        data_head = 13;
        if(datalen >= data_head)
            stream_id = _libssh2_ntohu32(data + 5);
        LIBSSH2_FALLTHROUGH();
    case SSH_MSG_CHANNEL_DATA:
        if(data_head == 0)
            data_head = 9;
        if(datalen < data_head ||
           _libssh2_ntohu32(data + data_head - 4) > datalen - data_head) {
            LIBSSH2_FREE(session, data);
            return _libssh2_error(session, LIBSSH2_ERROR_PROTO,
                                  "Invalid channel data length");
        }
        outersshpriv_reactor_received_channel_data(reactor, _libssh2_ntohu32(data + 1),
            stream_id, data + data_head, _libssh2_ntohu32(data + data_head - 4));
        LIBSSH2_FREE(session, data);
        return 0;

    case SSH_MSG_CHANNEL_EOF:
        if(datalen >= 5)
            outersshpriv_reactor_received_channel_eof(reactor, _libssh2_ntohu32(data + 1));
        LIBSSH2_FREE(session, data);
        return 0;

    case SSH_MSG_CHANNEL_REQUEST:
        if(datalen >= 9) {
            bool received_exit_status = false;
            uint32_t exit_status_value = 0;
            struct string_buf request;
            unsigned char *request_type = NULL;
            size_t request_type_length = 0;
            request.data = data;
            request.dataptr = data + 5;
            request.len = datalen;
            channel = _libssh2_ntohu32(data + 1);

            if(_libssh2_get_string(&request, &request_type,
                                   &request_type_length) ||
               _libssh2_get_boolean(&request, &want_reply)) {
                LIBSSH2_FREE(session, data);

                return _libssh2_error(
                    session,
                    LIBSSH2_ERROR_PROTO,
                    "Invalid channel request");
            }

            _libssh2_debug((session,
                           LIBSSH2_TRACE_CONN,
                           "Channel %u received request type %.*s (wr %X)",
                           channel, (int)request_type_length,
                           request_type, want_reply));

            static const char exit_status_request[] = "exit-status";
            static const char exit_signal_request[] = "exit-signal";
            if(request_type_length == sizeof(exit_status_request) - 1 &&
               !memcmp(exit_status_request, request_type,
                       request_type_length)) {

                /* we've got "exit-status" packet. Set the session value */
                if(_libssh2_get_u32(&request, &exit_status_value)) {
                    LIBSSH2_FREE(session, data);

                    return _libssh2_error(
                        session,
                        LIBSSH2_ERROR_PROTO,
                        "Invalid exit-status channel request");
                }

                received_exit_status = true;

            }
            else if(request_type_length == sizeof(exit_signal_request) - 1 &&
                    !memcmp(exit_signal_request, request_type,
                            request_type_length)) {
                /* command terminated due to signal */
                unsigned char *signal_name = NULL;
                size_t signal_name_length = 0;
                unsigned char core_dumped = 0;
                unsigned char *error_message = NULL;
                size_t error_message_length = 0;
                unsigned char *language_tag = NULL;
                size_t language_tag_length = 0;
                if(_libssh2_get_string(&request, &signal_name,
                                       &signal_name_length) ||
                   _libssh2_get_boolean(&request, &core_dumped) ||
                   _libssh2_get_string(&request, &error_message,
                                       &error_message_length) ||
                   _libssh2_get_string(&request, &language_tag,
                                       &language_tag_length)) {
                    LIBSSH2_FREE(session, data);

                    return _libssh2_error(
                        session,
                        LIBSSH2_ERROR_PROTO,
                        "Invalid exit-signal channel request");
                }


            }

            if(want_reply && !outersshpriv_reactor_reject_channel_request(reactor, channel)) {
                LIBSSH2_FREE(session, data);
                return 0;
            }
            if(received_exit_status)
                outersshpriv_reactor_received_channel_exit_status(reactor, channel, exit_status_value);
        }
        LIBSSH2_FREE(session, data);

        return rc;

        /*
          byte      SSH_MSG_CHANNEL_CLOSE
          uint32    recipient channel
        */

    case SSH_MSG_CHANNEL_CLOSE:
        if(datalen >= 5)
            outersshpriv_reactor_received_channel_close(reactor, _libssh2_ntohu32(data + 1));
        LIBSSH2_FREE(session, data);
        return 0;

    // Server-initiated channels are not enabled by OuterSSH.
    case SSH_MSG_CHANNEL_OPEN:
        if(datalen < 17) {
            LIBSSH2_FREE(session, data);

            return _libssh2_error(
                session,
                LIBSSH2_ERROR_PROTO,
                "Invalid server-initiated channel open");
        }
        len = _libssh2_ntohu32(data + 1);
        if((size_t)len > datalen - 17) {
            LIBSSH2_FREE(session, data);

            return _libssh2_error(
                session,
                LIBSSH2_ERROR_PROTO,
                "Invalid server-initiated channel type");
        }
        channel = _libssh2_ntohu32(data + 5 + (size_t)len);
        unsigned char response[17] = {SSH_MSG_CHANNEL_OPEN_FAILURE};
        _libssh2_htonu32(&response[1], channel);
        _libssh2_htonu32(
            &response[5],
            SSH_OPEN_UNKNOWN_CHANNELTYPE);
        _libssh2_htonu32(&response[9], 0);
        _libssh2_htonu32(&response[13], 0);
        outersshpriv_reactor_queue_protocol_response(reactor, response, sizeof(response));
        LIBSSH2_FREE(session, data);

        return 0;

        /*
          byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
          uint32    recipient channel
          uint32    sender channel
          uint32    initial window size
          uint32    maximum packet size
        */
    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
        if(datalen < 17) {
            LIBSSH2_FREE(session, data);

            return _libssh2_error(
                session,
                LIBSSH2_ERROR_PROTO,
                "Invalid channel-open confirmation");
        }
        outersshpriv_reactor_received_channel_open_confirmation(reactor,
            _libssh2_ntohu32(data + 1), _libssh2_ntohu32(data + 5),
            _libssh2_ntohu32(data + 9), _libssh2_ntohu32(data + 13));

        LIBSSH2_FREE(session, data);

        return 0;
    }

        /*
          byte      SSH_MSG_CHANNEL_OPEN_FAILURE
          uint32    recipient channel
          uint32    reason code
          string    description in ISO-10646 UTF-8 encoding [RFC3629]
          string    language tag [RFC3066]
        */
    case SSH_MSG_CHANNEL_OPEN_FAILURE:
        if(datalen >= 9) {
            uint32_t channelId = _libssh2_ntohu32(data + 1);
            uint32_t reason_code = _libssh2_ntohu32(data + 5);

            outersshpriv_reactor_received_channel_open_failure(reactor, channelId, reason_code);
        }
        LIBSSH2_FREE(session, data);

        return 0;

        /*
          byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
          uint32    recipient channel
          uint32    bytes to add
        */
    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        if(datalen >= 9)
            outersshpriv_reactor_received_channel_window_adjust(reactor,
                _libssh2_ntohu32(data + 1), _libssh2_ntohu32(data + 5));
        LIBSSH2_FREE(session, data);
        return 0;
    case SSH_MSG_CHANNEL_SUCCESS:
        if(datalen >= 5) {
            outersshpriv_reactor_received_channel_request_success(
                reactor, _libssh2_ntohu32(data + 1));
        }
        LIBSSH2_FREE(session, data);

        return 0;
    case SSH_MSG_CHANNEL_FAILURE:
        if(datalen >= 5) {
            outersshpriv_reactor_received_channel_request_failure(
                reactor, _libssh2_ntohu32(data + 1));
        }
        LIBSSH2_FREE(session, data);

        return 0;
    default:
        break;
    }

    if(msg == SSH_MSG_KEXINIT || msg == SSH_MSG_NEWKEYS || (msg >= 30 && msg <= 49)) {
        outersshpriv_reactor_received_key_exchange_packet(reactor, data, datalen);
        return 0;
    }
    LIBSSH2_FREE(session, data);
    return 0;
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
