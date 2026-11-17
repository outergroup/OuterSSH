/* $OpenBSD: cipher-chachapoly.h,v 1.4 2014/06/24 01:13:21 djm Exp $ */

/*
 * Copyright (c) Damien Miller 2013 <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef CHACHA_POLY_AEAD_H
#define CHACHA_POLY_AEAD_H

#include <openssl/evp.h>

#define POLY1305_KEYLEN 32
#define POLY1305_TAGLEN 16

#define CHACHA_KEYLEN   32 /* Only 256 bit keys used here */

/* OLIBSSH BEGIN: the context owns reusable OpenSSL allocations across SSH
 * packets; olibssh_chachapoly_cleanup releases them. */
struct chachapoly_ctx {
    EVP_CIPHER_CTX *main_ctx, *header_ctx;
    EVP_MAC_CTX *poly1305_ctx;
};

void olibssh_chachapoly_cleanup(struct chachapoly_ctx *ctx);
/* OLIBSSH END */

int olibssh_chachapoly_init(struct chachapoly_ctx *cpctx,
                    const u_char *key, u_int keylen);
int olibssh_chachapoly_crypt(struct chachapoly_ctx *cpctx, u_int seqnr,
                     u_char *dest, const u_char *src, u_int len, u_int aadlen,
                     int do_encrypt);
int olibssh_chachapoly_get_length(struct chachapoly_ctx *cpctx,
                          u_int *plenp, u_int seqnr, const u_char *cp,
                          u_int len);

#endif /* CHACHA_POLY_AEAD_H */
