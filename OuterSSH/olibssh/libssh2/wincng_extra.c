#include "libssh2_priv.h"
#if OUTERSSH_WINDOWS_CRYPTO
#include <stdlib.h>

static int curve25519_provider(BCRYPT_ALG_HANDLE *algorithm)
{
    *algorithm = NULL;
    if(BCryptOpenAlgorithmProvider(algorithm, BCRYPT_ECDH_ALGORITHM,
                                  MS_PRIMITIVE_PROVIDER, 0) < 0)
        return -1;
    const WCHAR curve[] = BCRYPT_ECC_CURVE_25519;
    if(BCryptSetProperty(*algorithm, BCRYPT_ECC_CURVE_NAME,
                         (PUCHAR)curve, sizeof(curve), 0) < 0) {
        BCryptCloseAlgorithmProvider(*algorithm, 0);
        *algorithm = NULL;
        return -1;
    }
    return 0;
}

int _libssh2_curve25519_new(LIBSSH2_SESSION *session,
                          uint8_t **public_key, uint8_t **private_key)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    unsigned char blob[104];
    ULONG count = 0;
    int result = -1;
    *public_key = *private_key = NULL;
    if(curve25519_provider(&algorithm)) goto cleanup;
    if(BCryptGenerateKeyPair(algorithm, &key, 255, 0) < 0 ||
       BCryptFinalizeKeyPair(key, 0) < 0 ||
       BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, blob, sizeof(blob),
                       &count, 0) < 0 || count != sizeof(blob)) goto cleanup;
    *public_key = LIBSSH2_ALLOC(session, 32);
    *private_key = LIBSSH2_ALLOC(session, 32);
    if(!*public_key || !*private_key) goto cleanup;
    memcpy(*public_key, blob + 8, 32);
    memcpy(*private_key, blob + 72, 32);
    result = 0;
cleanup:
    SecureZeroMemory(blob, sizeof(blob));
    if(key) BCryptDestroyKey(key);
    if(algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if(result) {
        LIBSSH2_FREE(session, *public_key);
        LIBSSH2_FREE(session, *private_key);
        *public_key = *private_key = NULL;
    }
    return result;
}

int _libssh2_curve25519_gen_k(_libssh2_bn **k, uint8_t private_key[32],
                            uint8_t public_key[32])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE local = NULL, peer = NULL;
    BCRYPT_SECRET_HANDLE agreement = NULL;
    struct { BCRYPT_ECCKEY_BLOB header; unsigned char x[32], y[32]; } blob = {
        { BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, 32 }, {0}, {0}
    };
    unsigned char secret[32] = {0};
    ULONG count = 0;
    int result = -1;
    memcpy(blob.x, public_key, 32);
    blob.x[31] &= 0x7f;
    int reduce = blob.x[31] == 0x7f && blob.x[0] >= 0xed;
    for(size_t i = 1; i < 31; ++i) reduce &= blob.x[i] == 0xff;
    if(reduce) {
        blob.x[0] -= 0xed;
        memset(blob.x + 1, 0, 31);
    }
    struct { BCRYPT_ECCKEY_BLOB header; unsigned char x[32], y[32], d[32]; } private_blob = {
        { BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC, 32 }, {0}, {0}, {0}
    };
    memcpy(private_blob.d, private_key, 32);
    private_blob.d[0] &= 248;
    private_blob.d[31] = (private_blob.d[31] & 127) | 64;
    if(curve25519_provider(&algorithm)) goto cleanup;
    if(BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPRIVATE_BLOB, &local,
                           (PUCHAR)&private_blob, sizeof(private_blob), 0) < 0 ||
       BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, &peer,
                           (PUCHAR)&blob, sizeof(blob), 0) < 0 ||
       BCryptSecretAgreement(local, peer, &agreement, 0) < 0 ||
       BCryptDeriveKey(agreement, BCRYPT_KDF_RAW_SECRET, NULL, secret,
                       sizeof(secret), &count, 0) < 0 || count != 32) goto cleanup;
    unsigned char nonzero = 0;
    for(size_t i = 0; i < sizeof(secret); ++i) nonzero |= secret[i];
    if(!nonzero) goto cleanup;
    for(size_t i = 0; i < 16; ++i) {
        unsigned char byte = secret[i]; secret[i] = secret[31 - i]; secret[31 - i] = byte;
    }
    result = _libssh2_bn_from_bin(*k, sizeof(secret), secret);
cleanup:
    SecureZeroMemory(private_blob.d, sizeof(private_blob.d));
    SecureZeroMemory(secret, sizeof(secret));
    if(agreement) BCryptDestroySecret(agreement);
    if(peer) BCryptDestroyKey(peer);
    if(local) BCryptDestroyKey(local);
    if(algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

int olibssh_cng_gcm_init(_libssh2_cipher_ctx *ctx, unsigned char *iv,
                        unsigned char *secret, ULONG length)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    int result = -1;
    if(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM,
                                  MS_PRIMITIVE_PROVIDER, 0) < 0) return -1;
    if(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                         (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                         sizeof(BCRYPT_CHAIN_MODE_GCM), 0) >= 0 &&
       BCryptGenerateSymmetricKey(algorithm, &ctx->hKey, NULL, 0,
                                  secret, length, 0) >= 0) {
        memcpy(ctx->nonce, iv, sizeof(ctx->nonce));
        result = 0;
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

int olibssh_cng_gcm_crypt(_libssh2_cipher_ctx *ctx, unsigned char *packet,
                         size_t length, int encrypt)
{
    if(ctx->exhausted || (encrypt && length < 4)) return -1;
    size_t payload = encrypt ? length - 4 : length;
    if(payload > ULONG_MAX) return -1;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = ctx->nonce;
    info.cbNonce = sizeof(ctx->nonce);
    info.pbAuthData = packet;
    info.cbAuthData = 4;
    info.pbTag = packet + 4 + payload;
    info.cbTag = 16;
    ULONG written = 0;
    NTSTATUS status = encrypt
        ? BCryptEncrypt(ctx->hKey, packet + 4, (ULONG)payload, &info, NULL, 0,
                         packet + 4, (ULONG)payload, &written, 0)
        : BCryptDecrypt(ctx->hKey, packet + 4, (ULONG)payload, &info, NULL, 0,
                         packet + 4, (ULONG)payload, &written, 0);
    if(status < 0 || written != payload) {
        if(!encrypt) SecureZeroMemory(packet + 4, payload);
        ctx->exhausted = 1;
        return LIBSSH2_ERROR_DECRYPT;
    }
    if(!encrypt) memmove(packet, packet + 4, payload);
    for(int i = 11; i >= 4; --i) {
        if(++ctx->nonce[i]) break;
        if(i == 4) ctx->exhausted = 1;
    }
    return 0;
}
#endif
