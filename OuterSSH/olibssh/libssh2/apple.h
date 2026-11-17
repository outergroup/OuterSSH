#ifndef OLIBSSH_APPLE_H
#define OLIBSSH_APPLE_H
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include <Security/SecRandom.h>
#include <stdlib.h>
#include <string.h>
#define LIBSSH2_CRYPTO_ENGINE libssh2_apple
#define LIBSSH2_RSA 1
#define LIBSSH2_RSA_SHA1 0
#define LIBSSH2_RSA_SHA2 1
#define LIBSSH2_DSA 0
#define LIBSSH2_ECDSA 1
#define LIBSSH2_ED25519 1
#define LIBSSH2_MD5 0
#define LIBSSH2_HMAC_RIPEMD 0
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1
#define LIBSSH2_AES_CTR 1
#define LIBSSH2_AES_CBC 0
#define LIBSSH2_AES_GCM 1
#define LIBSSH2_BLOWFISH 0
#define LIBSSH2_RC4 0
#define LIBSSH2_CAST 0
#define LIBSSH2_3DES 0
#include "crypto_config.h"
#define EC_MAX_POINT_LEN 133
#define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH CC_SHA256_DIGEST_LENGTH
#define SHA384_DIGEST_LENGTH CC_SHA384_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH CC_SHA512_DIGEST_LENGTH
#define _libssh2_random(buf, len) (SecRandomCopyBytes(kSecRandomDefault, len, buf) == errSecSuccess ? 0 : -1)
#define libssh2_prepare_iovec(vec, len)
#define libssh2_crypto_init() ((void)0)
#define libssh2_crypto_exit() ((void)0)
typedef CC_SHA1_CTX libssh2_sha1_ctx;
#define libssh2_sha1_init(ctx) CC_SHA1_Init(ctx)
static inline int olibssh_sha1_update(libssh2_sha1_ctx *ctx, const void *data, size_t len) {
    const unsigned char *bytes = data;
    while(len) { CC_LONG count = len > UINT32_MAX ? UINT32_MAX : (CC_LONG)len;
        if(!CC_SHA1_Update(ctx, bytes, count)) return 0;
        bytes += count; len -= count;
    }
    return 1;
}
#define libssh2_sha1_update(ctx, data, len) olibssh_sha1_update(&(ctx), data, len)
#define libssh2_sha1_final(ctx, out) CC_SHA1_Final(out, &(ctx))
static inline int libssh2_sha1(const unsigned char *data, size_t len, unsigned char *out) {
    libssh2_sha1_ctx ctx;
    return libssh2_sha1_init(&ctx) && libssh2_sha1_update(ctx, data, len) && libssh2_sha1_final(ctx, out) ? 0 : -1;
}
typedef CC_SHA256_CTX libssh2_sha256_ctx;
#define libssh2_sha256_init(ctx) CC_SHA256_Init(ctx)
static inline int olibssh_sha256_update(libssh2_sha256_ctx *ctx, const void *data, size_t len) {
    const unsigned char *bytes = data;
    while(len) { CC_LONG count = len > UINT32_MAX ? UINT32_MAX : (CC_LONG)len;
        if(!CC_SHA256_Update(ctx, bytes, count)) return 0;
        bytes += count; len -= count;
    }
    return 1;
}
#define libssh2_sha256_update(ctx, data, len) olibssh_sha256_update(&(ctx), data, len)
#define libssh2_sha256_final(ctx, out) CC_SHA256_Final(out, &(ctx))
static inline int libssh2_sha256(const unsigned char *data, size_t len, unsigned char *out) {
    libssh2_sha256_ctx ctx;
    return libssh2_sha256_init(&ctx) && libssh2_sha256_update(ctx, data, len) && libssh2_sha256_final(ctx, out) ? 0 : -1;
}
typedef CC_SHA512_CTX libssh2_sha384_ctx;
#define libssh2_sha384_init(ctx) CC_SHA384_Init(ctx)
static inline int olibssh_sha384_update(libssh2_sha384_ctx *ctx, const void *data, size_t len) {
    const unsigned char *bytes = data;
    while(len) { CC_LONG count = len > UINT32_MAX ? UINT32_MAX : (CC_LONG)len;
        if(!CC_SHA384_Update(ctx, bytes, count)) return 0;
        bytes += count; len -= count;
    }
    return 1;
}
#define libssh2_sha384_update(ctx, data, len) olibssh_sha384_update(&(ctx), data, len)
#define libssh2_sha384_final(ctx, out) CC_SHA384_Final(out, &(ctx))
static inline int libssh2_sha384(const unsigned char *data, size_t len, unsigned char *out) {
    libssh2_sha384_ctx ctx;
    return libssh2_sha384_init(&ctx) && libssh2_sha384_update(ctx, data, len) && libssh2_sha384_final(ctx, out) ? 0 : -1;
}
typedef CC_SHA512_CTX libssh2_sha512_ctx;
#define libssh2_sha512_init(ctx) CC_SHA512_Init(ctx)
static inline int olibssh_sha512_update(libssh2_sha512_ctx *ctx, const void *data, size_t len) {
    const unsigned char *bytes = data;
    while(len) { CC_LONG count = len > UINT32_MAX ? UINT32_MAX : (CC_LONG)len;
        if(!CC_SHA512_Update(ctx, bytes, count)) return 0;
        bytes += count; len -= count;
    }
    return 1;
}
#define libssh2_sha512_update(ctx, data, len) olibssh_sha512_update(&(ctx), data, len)
#define libssh2_sha512_final(ctx, out) CC_SHA512_Final(out, &(ctx))
static inline int libssh2_sha512(const unsigned char *data, size_t len, unsigned char *out) {
    libssh2_sha512_ctx ctx;
    return libssh2_sha512_init(&ctx) && libssh2_sha512_update(ctx, data, len) && libssh2_sha512_final(ctx, out) ? 0 : -1;
}
typedef struct { CCHmacContext context; } libssh2_hmac_ctx;
typedef void libssh2_rsa_ctx;
typedef void libssh2_ecdsa_ctx;
typedef void libssh2_ed25519_ctx;
typedef void _libssh2_ec_key;
void olibssh_apple_key_free(void *key);
void olibssh_apple_exchange_free(void *key);
#define _libssh2_rsa_free olibssh_apple_key_free
#define _libssh2_ecdsa_free olibssh_apple_key_free
#define _libssh2_ed25519_free olibssh_apple_key_free
typedef enum { LIBSSH2_EC_CURVE_NISTP256 = 256, LIBSSH2_EC_CURVE_NISTP384 = 384, LIBSSH2_EC_CURVE_NISTP521 = 521 } libssh2_curve_type;
typedef struct { unsigned char bytes[66]; size_t length; } _libssh2_bn;
typedef void _libssh2_bn_ctx;
typedef void *_libssh2_dh_ctx;
#define _libssh2_bn_init() calloc(1, sizeof(_libssh2_bn))
#define _libssh2_bn_init_from_bin() _libssh2_bn_init()
static inline void _libssh2_bn_free(_libssh2_bn *bn) { if(bn) { memset_s(bn, sizeof(*bn), 0, sizeof(*bn)); free(bn); } }
int _libssh2_bn_from_bin(_libssh2_bn *bn, size_t len, const unsigned char *bytes);
static inline int _libssh2_bn_to_bin(_libssh2_bn *bn, unsigned char *out) { memcpy(out, bn->bytes, bn->length); return 0; }
#define _libssh2_bn_bytes(bn) ((bn)->length)
static inline int _libssh2_bn_bits(_libssh2_bn *bn) {
    if(!bn->length) return 0;
    unsigned char first = bn->bytes[0]; int bits = (int)(bn->length - 1) * 8;
    while(first) { bits++; first >>= 1; } return bits;
}
typedef struct { CCCryptorRef cryptor; void *key; unsigned char iv[12]; int exhausted; } _libssh2_cipher_ctx;
#define _libssh2_cipher_type(name) int name
#define _libssh2_cipher_aes128gcm 116
#define _libssh2_cipher_aes256gcm 132
#define _libssh2_cipher_aes128ctr 16
#define _libssh2_cipher_aes192ctr 24
#define _libssh2_cipher_aes256ctr 32
void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx);
#endif
