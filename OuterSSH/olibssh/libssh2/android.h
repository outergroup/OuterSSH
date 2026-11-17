#ifndef OLIBSSH_ANDROID_H
#define OLIBSSH_ANDROID_H
#include <stdlib.h>
#include <string.h>
#include "../../platform/android/AndroidCryptoBridge.h"
#define LIBSSH2_CRYPTO_ENGINE libssh2_android
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

#define LIBSSH2_CURVE25519 1
#define LIBSSH2_CURVE25519_PRIVATE_LEN 32
#include "crypto_config.h"
#define EC_MAX_POINT_LEN 133
#define _libssh2_random ol_android_random
#define libssh2_prepare_iovec(vec, len)
#define libssh2_crypto_init() ((void)0)
#define libssh2_crypto_exit() ((void)0)
#define SHA1_DIGEST_LENGTH 20
typedef void *libssh2_sha1_ctx;
#define libssh2_sha1_init(ctx) ol_android_hash_init(ctx, 20)
#define libssh2_sha1_update(ctx, data, len) ol_android_update(ctx, data, len)
#define libssh2_sha1_final(ctx, out) ol_android_final(&(ctx), out, 20)
static inline int libssh2_sha1(const unsigned char *data, size_t len, unsigned char *out) {
    return ol_android_digest(20, data, len, out);
}
#define SHA256_DIGEST_LENGTH 32
typedef void *libssh2_sha256_ctx;
#define libssh2_sha256_init(ctx) ol_android_hash_init(ctx, 32)
#define libssh2_sha256_update(ctx, data, len) ol_android_update(ctx, data, len)
#define libssh2_sha256_final(ctx, out) ol_android_final(&(ctx), out, 32)
static inline int libssh2_sha256(const unsigned char *data, size_t len, unsigned char *out) {
    return ol_android_digest(32, data, len, out);
}
#define SHA384_DIGEST_LENGTH 48
typedef void *libssh2_sha384_ctx;
#define libssh2_sha384_init(ctx) ol_android_hash_init(ctx, 48)
#define libssh2_sha384_update(ctx, data, len) ol_android_update(ctx, data, len)
#define libssh2_sha384_final(ctx, out) ol_android_final(&(ctx), out, 48)
static inline int libssh2_sha384(const unsigned char *data, size_t len, unsigned char *out) {
    return ol_android_digest(48, data, len, out);
}
#define SHA512_DIGEST_LENGTH 64
typedef void *libssh2_sha512_ctx;
#define libssh2_sha512_init(ctx) ol_android_hash_init(ctx, 64)
#define libssh2_sha512_update(ctx, data, len) ol_android_update(ctx, data, len)
#define libssh2_sha512_final(ctx, out) ol_android_final(&(ctx), out, 64)
static inline int libssh2_sha512(const unsigned char *data, size_t len, unsigned char *out) {
    return ol_android_digest(64, data, len, out);
}
#define SHA_DIGEST_LENGTH SHA1_DIGEST_LENGTH
typedef struct { void *context; size_t length; } libssh2_hmac_ctx;
typedef void libssh2_rsa_ctx;
typedef void libssh2_ecdsa_ctx;
typedef void libssh2_ed25519_ctx;
typedef void _libssh2_ec_key;
void olibssh_android_key_free(void *key);
void olibssh_android_exchange_free(void *key);
#define _libssh2_rsa_free olibssh_android_key_free
#define _libssh2_ecdsa_free olibssh_android_key_free
#define _libssh2_ed25519_free olibssh_android_key_free
#define _libssh2_ed25519_free olibssh_android_key_free
typedef enum { LIBSSH2_EC_CURVE_NISTP256 = 256, LIBSSH2_EC_CURVE_NISTP384 = 384, LIBSSH2_EC_CURVE_NISTP521 = 521 } libssh2_curve_type;
typedef struct { unsigned char bytes[66]; size_t length; } _libssh2_bn;
typedef void _libssh2_bn_ctx;
typedef void *_libssh2_dh_ctx;
#define _libssh2_bn_init() calloc(1, sizeof(_libssh2_bn))
#define _libssh2_bn_init_from_bin() _libssh2_bn_init()
static inline void _libssh2_bn_free(_libssh2_bn *bn) { if(bn) { ol_android_cleanse(bn, sizeof(*bn)); free(bn); } }
int _libssh2_bn_from_bin(_libssh2_bn *bn, size_t len, const unsigned char *bytes);
static inline int _libssh2_bn_to_bin(_libssh2_bn *bn, unsigned char *out) { memcpy(out, bn->bytes, bn->length); return 0; }
#define _libssh2_bn_bytes(bn) ((bn)->length)
static inline int _libssh2_bn_bits(_libssh2_bn *bn) {
    if(!bn->length) return 0;
    unsigned char first = bn->bytes[0]; int bits = (int)(bn->length - 1) * 8;
    while(first) { bits++; first >>= 1; } return bits;
}
typedef struct { void *cryptor; void *key; unsigned char iv[12]; int exhausted; } _libssh2_cipher_ctx;
#define _libssh2_cipher_type(name) int name
#define _libssh2_cipher_aes128gcm 116
#define _libssh2_cipher_aes256gcm 132
#define _libssh2_cipher_aes128ctr 16
#define _libssh2_cipher_aes192ctr 24
#define _libssh2_cipher_aes256ctr 32
void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx);
#endif
