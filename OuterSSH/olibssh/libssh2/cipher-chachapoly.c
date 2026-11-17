#include "libssh2_config.h"
#if !OUTERSSH_APPLE_CRYPTO && !OUTERSSH_WINDOWS_CRYPTO && !OUTERSSH_ANDROID_CRYPTO
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Adapted by Will Cosgrove <will@panic.com> for libssh2
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

/* $OpenBSD: cipher-chachapoly.c,v 1.8 2016/08/03 05:41:57 djm Exp $ */

#include "libssh2_priv.h"
#include "misc.h"
#include "cipher-chachapoly.h"

/* OLIBSSH BEGIN: retain the OpenSSH packet construction, using OpenSSL's
 * raw ChaCha20 and Poly1305 primitives rather than the combined IETF AEAD. */
int
olibssh_chachapoly_init(struct chachapoly_ctx *ctx, const u_char *key, u_int keylen)
{
    *ctx = (struct chachapoly_ctx){0};
    if(keylen != 2 * CHACHA_KEYLEN)
        return LIBSSH2_ERROR_INVAL;

    ctx->main_ctx = EVP_CIPHER_CTX_new();
    ctx->header_ctx = EVP_CIPHER_CTX_new();
    EVP_MAC *poly1305 = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if(poly1305) {
        ctx->poly1305_ctx = EVP_MAC_CTX_new(poly1305);
        EVP_MAC_free(poly1305);
    }
    if(!ctx->main_ctx || !ctx->header_ctx || !ctx->poly1305_ctx) {
        olibssh_chachapoly_cleanup(ctx);
        return LIBSSH2_ERROR_ALLOC;
    }

    if(EVP_EncryptInit_ex(ctx->main_ctx, EVP_chacha20(), NULL, key, NULL) != 1 ||
       EVP_EncryptInit_ex(ctx->header_ctx, EVP_chacha20(), NULL,
                          key + CHACHA_KEYLEN, NULL) != 1) {
        olibssh_chachapoly_cleanup(ctx);
        return LIBSSH2_ERROR_ENCRYPT;
    }
    return 0;
}

void
olibssh_chachapoly_cleanup(struct chachapoly_ctx *ctx)
{
    EVP_CIPHER_CTX_free(ctx->main_ctx);
    EVP_CIPHER_CTX_free(ctx->header_ctx);
    EVP_MAC_CTX_free(ctx->poly1305_ctx);
    *ctx = (struct chachapoly_ctx){0};
}

int
olibssh_chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
                 const u_char *src, u_int len, u_int aadlen, int do_encrypt)
{
    /* Raw EVP ChaCha20 uses a little-endian 64-bit block counter followed
     * by an 8-byte nonce. SSH encodes the sequence number in big-endian. */
    unsigned char iv[16] = {0};
    unsigned char *nonce = iv + 8;
    _libssh2_store_u64(&nonce, seqnr);
    unsigned char poly_key[POLY1305_KEYLEN] = {0};
    unsigned char expected_tag[POLY1305_TAGLEN];
    int written;
    size_t tag_length;
    int result = do_encrypt ? LIBSSH2_ERROR_ENCRYPT : LIBSSH2_ERROR_DECRYPT;
    if(len > INT_MAX || aadlen > INT_MAX)
        goto out;

    /* Block zero supplies the one-time Poly1305 key. */
    if(EVP_EncryptInit_ex(ctx->main_ctx, NULL, NULL, NULL, iv) != 1 ||
       EVP_EncryptUpdate(ctx->main_ctx, poly_key, &written,
                          poly_key, sizeof(poly_key)) != 1 ||
       written != (int)sizeof(poly_key) ||
       EVP_MAC_init(ctx->poly1305_ctx, poly_key, sizeof(poly_key), NULL) != 1)
        goto out;

    /* Authenticate the encrypted length and payload before decrypting. */
    if(!do_encrypt) {
        if(EVP_MAC_update(ctx->poly1305_ctx, src, (size_t)aadlen + len) != 1 ||
           EVP_MAC_final(ctx->poly1305_ctx, expected_tag, &tag_length,
                          sizeof(expected_tag)) != 1 ||
           tag_length != POLY1305_TAGLEN ||
           CRYPTO_memcmp(expected_tag, src + aadlen + len,
                          POLY1305_TAGLEN) != 0)
            goto out;
    }

    if(aadlen) {
        if(EVP_EncryptInit_ex(ctx->header_ctx, NULL, NULL, NULL, iv) != 1 ||
           EVP_EncryptUpdate(ctx->header_ctx, dest, &written,
                              src, (int)aadlen) != 1 ||
           written != (int)aadlen)
            goto out;
    }

    /* Payload encryption begins at block one, under the other key. */
    iv[0] = 1;
    if(EVP_EncryptInit_ex(ctx->main_ctx, NULL, NULL, NULL, iv) != 1 ||
       EVP_EncryptUpdate(ctx->main_ctx, dest + aadlen, &written,
                          src + aadlen, (int)len) != 1 ||
       written != (int)len)
        goto out;

    if(do_encrypt) {
        if(EVP_MAC_update(ctx->poly1305_ctx, dest, (size_t)aadlen + len) != 1 ||
           EVP_MAC_final(ctx->poly1305_ctx, dest + aadlen + len,
                          &tag_length, POLY1305_TAGLEN) != 1 ||
           tag_length != POLY1305_TAGLEN)
            goto out;
    }
    result = 0;
out:
    OPENSSL_cleanse(poly_key, sizeof(poly_key));
    OPENSSL_cleanse(expected_tag, sizeof(expected_tag));
    return result;
}

int
olibssh_chachapoly_get_length(struct chachapoly_ctx *ctx, unsigned int *plenp,
                      unsigned int seqnr, const unsigned char *cp,
                      unsigned int len)
{
    if(len < 4)
        return LIBSSH2_ERROR_INVAL;
    unsigned char iv[16] = {0}, buffer[4];
    unsigned char *nonce = iv + 8;
    _libssh2_store_u64(&nonce, seqnr);
    int written;
    if(EVP_EncryptInit_ex(ctx->header_ctx, NULL, NULL, NULL, iv) != 1 ||
       EVP_EncryptUpdate(ctx->header_ctx, buffer, &written, cp, 4) != 1 ||
       written != 4)
        return LIBSSH2_ERROR_DECRYPT;
    *plenp = _libssh2_ntohu32(buffer);
    return 0;
}
/* OLIBSSH END */

#endif
