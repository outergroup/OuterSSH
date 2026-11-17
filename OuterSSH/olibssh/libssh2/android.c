#include "libssh2_priv.h"
#if OUTERSSH_ANDROID_CRYPTO

extern void *olibssh_android_key_create(int kind, const void *bytes, size_t count, int is_private);
extern void *olibssh_android_rsa_public(const void *e, size_t elen, const void *n, size_t nlen);
extern void *olibssh_android_key_parse(const void *bytes, size_t count, int *error);
extern int olibssh_android_key_kind(void *key);
extern ptrdiff_t olibssh_android_key_export(void *key, void *output, size_t capacity);
extern ptrdiff_t olibssh_android_sign(void *key, const void *message, size_t count, void *output, size_t capacity);
extern int olibssh_android_verify(void *key, const void *signature, size_t signature_count, const void *message, size_t count, size_t hash_length);
extern int olibssh_android_verify_ec(void *key, const void *r, size_t rlen, const void *s, size_t slen, const void *message, size_t count);
extern int olibssh_android_ec_generate(int kind, void *private_bytes, void *public_bytes);
extern int olibssh_android_ec_shared(int kind, const void *private_bytes, size_t private_count, const void *public_bytes, size_t public_count, void *output);
extern void *olibssh_android_packet_key_create(const void *bytes, size_t count);
extern void olibssh_android_packet_key_free(void *key);
extern int olibssh_android_gcm(void *key, const void *iv, void *packet, size_t length, int encrypt);

int _libssh2_hmac_ctx_init(libssh2_hmac_ctx *ctx) { memset(ctx, 0, sizeof(*ctx)); return 1; }
static int hmac_init(libssh2_hmac_ctx *ctx, void *key, size_t len, int hash) {
    ctx->length = (size_t)hash;
    ctx->context = ol_android_create(2, hash, key, len, NULL, 0);
    return ctx->context != NULL;
}
int _libssh2_hmac_sha1_init(libssh2_hmac_ctx *ctx, void *key, size_t len) { return hmac_init(ctx, key, len, 20); }
int _libssh2_hmac_sha256_init(libssh2_hmac_ctx *ctx, void *key, size_t len) { return hmac_init(ctx, key, len, 32); }
int _libssh2_hmac_sha512_init(libssh2_hmac_ctx *ctx, void *key, size_t len) { return hmac_init(ctx, key, len, 64); }
int _libssh2_hmac_update(libssh2_hmac_ctx *ctx, const void *data, size_t len) { return ol_android_update(ctx->context, data, len); }
int _libssh2_hmac_final(libssh2_hmac_ctx *ctx, void *out) { return ol_android_result(2, 0, ctx->context, NULL, 0, NULL, 0, NULL, 0, out, ctx->length) == (ptrdiff_t)ctx->length; }
void _libssh2_hmac_cleanup(libssh2_hmac_ctx *ctx) { ol_android_free(ctx->context); memset(ctx, 0, sizeof(*ctx)); }

int _libssh2_bn_from_bin(_libssh2_bn *bn, size_t len, const unsigned char *bytes) {
    while(len && *bytes == 0) { bytes++; len--; }
    if(!bn || len > sizeof(bn->bytes)) return -1;
    memcpy(bn->bytes, bytes, len); bn->length = len; return 0;
}

int _libssh2_cipher_init(_libssh2_cipher_ctx *ctx, int algorithm, unsigned char *iv, unsigned char *secret, int encrypt) {
    *ctx = (_libssh2_cipher_ctx){0};
    if(algorithm == 116 || algorithm == 132) {
        ctx->key = olibssh_android_packet_key_create(secret, algorithm - 100);
        memcpy(ctx->iv, iv, sizeof(ctx->iv));
        return ctx->key ? 0 : -1;
    }
    ctx->cryptor = ol_android_create(3, encrypt, secret, (size_t)algorithm, iv, 16);
    return ctx->cryptor ? 0 : -1;
}
void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx) {
    ol_android_free(ctx->cryptor);
    if(ctx->key) olibssh_android_packet_key_free(ctx->key);
    ol_android_cleanse(ctx, sizeof(*ctx));
}
int olibssh_cipher_crypt(_libssh2_cipher_ctx *ctx, int algorithm, int encrypt, unsigned char *block, size_t length, int firstlast) {
    (void)firstlast;
    if(algorithm == 116 || algorithm == 132) {
        if(ctx->exhausted || (encrypt && length < 4)) return -1;
        size_t payload_length = encrypt ? length - 4 : length;
        if(olibssh_android_gcm(ctx->key, ctx->iv, block, payload_length, encrypt)) return LIBSSH2_ERROR_DECRYPT;
        if(!encrypt) memmove(block, block + 4, payload_length);
        for(int i = 11; i >= 4; i--) {
            if(++ctx->iv[i]) break;
            if(i == 4) ctx->exhausted = 1;
        }
        return 0;
    }
    return ol_android_result(3, 0, ctx->cryptor, block, length, NULL, 0, NULL, 0, block, length) == (ptrdiff_t)length ? 0 : -1;
}

static int parse_private(LIBSSH2_SESSION *session, const char *bytes, size_t len, int kind, void **key) {
    int error = 0;
    *key = olibssh_android_key_parse(bytes, len, &error);
    if(!*key) return _libssh2_error(session, error == 1 || error == 2 ? LIBSSH2_ERROR_METHOD_NOT_SUPPORTED : LIBSSH2_ERROR_FILE,
        error == 1 ? "Android crypto does not support encrypted private-key files; use a managed key or SSH agent" :
        error == 2 ? "Private-key format is unsupported by Android crypto" : "Invalid private key");
    if(kind >= 0 && olibssh_android_key_kind(*key) != kind) {
        olibssh_android_key_free(*key); *key = NULL;
        return _libssh2_error(session, LIBSSH2_ERROR_FILE, "Private-key algorithm mismatch");
    }
    return 0;
}
static int read_private(LIBSSH2_SESSION *session, const char *filename, int kind, void **key) {
    *key = NULL;
    FILE *file = fopen(filename, "rb");
    if(!file) return _libssh2_error(session, LIBSSH2_ERROR_FILE, "Cannot open private key");
    unsigned char *data = LIBSSH2_ALLOC(session, 1024 * 1024);
    if(!data) { fclose(file); return LIBSSH2_ERROR_ALLOC; }
    size_t count = fread(data, 1, 1024 * 1024, file);
    int result = ferror(file) || count == 1024 * 1024 ? LIBSSH2_ERROR_FILE : parse_private(session, (char *)data, count, kind, key);
    fclose(file);
    ol_android_cleanse(data, 1024 * 1024); LIBSSH2_FREE(session, data);
    return result;
}
static int sign_key(LIBSSH2_SESSION *session, void *key, const unsigned char *message, size_t length, unsigned char **signature, size_t *signature_length) {
    unsigned char buffer[2048];
    ptrdiff_t count = olibssh_android_sign(key, message, length, buffer, sizeof(buffer));
    if(count < 0) return -1;
    *signature = LIBSSH2_ALLOC(session, (size_t)count);
    if(!*signature) return LIBSSH2_ERROR_ALLOC;
    memcpy(*signature, buffer, (size_t)count); *signature_length = (size_t)count; return 0;
}
static int export_key(LIBSSH2_SESSION *session, void *key, unsigned char **method, size_t *method_length, unsigned char **public_key, size_t *public_length) {
    ptrdiff_t count = olibssh_android_key_export(key, NULL, 0);
    if(count < 4) return -1;
    unsigned char *blob = LIBSSH2_ALLOC(session, (size_t)count);
    if(!blob) return LIBSSH2_ERROR_ALLOC;
    if(olibssh_android_key_export(key, blob, (size_t)count) != count) { LIBSSH2_FREE(session, blob); return -1; }
    size_t name_length = _libssh2_ntohu32(blob);
    if(name_length > (size_t)count - 4) { LIBSSH2_FREE(session, blob); return -1; }
    unsigned char *name = LIBSSH2_ALLOC(session, name_length);
    if(!name) { LIBSSH2_FREE(session, blob); return LIBSSH2_ERROR_ALLOC; }
    memcpy(name, blob + 4, name_length);
    *method = name; *method_length = name_length; *public_key = blob; *public_length = (size_t)count;
    return 0;
}
int _libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session, unsigned char **method, size_t *method_len,
    unsigned char **pubkeydata, size_t *pubkeydata_len, const char *data, size_t len, const char *passphrase) {
    (void)passphrase; void *key = NULL;
    int result = parse_private(session, data, len, -1, &key);
    if(!result) result = export_key(session, key, method, method_len, pubkeydata, pubkeydata_len);
    olibssh_android_key_free(key); return result;
}
int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session, unsigned char **method, size_t *method_len,
    unsigned char **pubkeydata, size_t *pubkeydata_len, const char *filename, const char *passphrase) {
    (void)passphrase; void *key = NULL;
    int result = read_private(session, filename, -1, &key);
    if(!result) result = export_key(session, key, method, method_len, pubkeydata, pubkeydata_len);
    olibssh_android_key_free(key); return result;
}
const char *_libssh2_supported_key_sign_algorithms(LIBSSH2_SESSION *session, unsigned char *method, size_t len) {
    (void)session;
    if((len == 7 && !memcmp(method, "ssh-rsa", 7)) ||
       (len == 28 && !memcmp(method, "ssh-rsa-cert-v01@openssh.com", 28))) return "rsa-sha2-512,rsa-sha2-256";
    return NULL;
}
int _libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx **key, LIBSSH2_SESSION *session, const char *data, size_t len, const unsigned char *passphrase) {
    (void)passphrase;
    int result = parse_private(session, data, len, 0, key);
    return result;
}
int _libssh2_rsa_new_private(libssh2_rsa_ctx **key, LIBSSH2_SESSION *session, const char *filename, const unsigned char *passphrase) {
    (void)passphrase;
    int result = read_private(session, filename, 0, key);
    return result;
}
int _libssh2_ecdsa_new_private_frommemory(libssh2_ecdsa_ctx **key, LIBSSH2_SESSION *session, const char *data, size_t len, const unsigned char *passphrase) {
    (void)passphrase;
    int result = parse_private(session, data, len, -1, key);
    if(!result && olibssh_android_key_kind(*key) < 256) { olibssh_android_key_free(*key); *key = NULL; return -1; }
    return result;
}
int _libssh2_ecdsa_new_private(libssh2_ecdsa_ctx **key, LIBSSH2_SESSION *session, const char *filename, const unsigned char *passphrase) {
    (void)passphrase;
    int result = read_private(session, filename, -1, key);
    if(!result && olibssh_android_key_kind(*key) < 256) { olibssh_android_key_free(*key); *key = NULL; return -1; }
    return result;
}
int _libssh2_rsa_new(libssh2_rsa_ctx **rsa, const unsigned char *e, unsigned long elen, const unsigned char *n, unsigned long nlen,
    const unsigned char *d, unsigned long dlen, const unsigned char *p, unsigned long plen, const unsigned char *q, unsigned long qlen,
    const unsigned char *e1, unsigned long e1len, const unsigned char *e2, unsigned long e2len, const unsigned char *coefficient, unsigned long coefficient_len) {
    (void)dlen; (void)p; (void)plen; (void)q; (void)qlen; (void)e1; (void)e1len; (void)e2; (void)e2len; (void)coefficient; (void)coefficient_len;
    *rsa = NULL;
    if(d) return -1;
    *rsa = olibssh_android_rsa_public(e, elen, n, nlen); return *rsa ? 0 : -1;
}
int _libssh2_rsa_sha2_verify(libssh2_rsa_ctx *key, size_t hash_len, const unsigned char *signature, size_t signature_len, const unsigned char *message, size_t length) {
    return olibssh_android_verify(key, signature, signature_len, message, length, hash_len);
}
int _libssh2_rsa_sha2_sign(LIBSSH2_SESSION *session, libssh2_rsa_ctx *key, const unsigned char *hash, size_t hash_len, unsigned char **signature, size_t *signature_len) {
    return sign_key(session, key, hash, hash_len, signature, signature_len);
}
int _libssh2_ecdsa_curve_name_with_octal_new(libssh2_ecdsa_ctx **key, const unsigned char *data, size_t len, libssh2_curve_type type) {
    *key = olibssh_android_key_create(type, data, len, 0); return *key ? 0 : -1;
}
libssh2_curve_type _libssh2_ecdsa_get_curve_type(libssh2_ecdsa_ctx *key) { return (libssh2_curve_type)olibssh_android_key_kind(key); }
int _libssh2_ecdsa_curve_type_from_name(const char *name, libssh2_curve_type *type) {
    if(!strcmp(name, "ecdsa-sha2-nistp256")) *type = LIBSSH2_EC_CURVE_NISTP256;
    else if(!strcmp(name, "ecdsa-sha2-nistp384")) *type = LIBSSH2_EC_CURVE_NISTP384;
    else if(!strcmp(name, "ecdsa-sha2-nistp521")) *type = LIBSSH2_EC_CURVE_NISTP521;
    else return -1;
    return 0;
}
int _libssh2_ecdsa_verify(libssh2_ecdsa_ctx *key, const unsigned char *r, size_t rlen, const unsigned char *s, size_t slen, const unsigned char *message, size_t length) {
    return olibssh_android_verify_ec(key, r, rlen, s, slen, message, length);
}
int _libssh2_ecdsa_sign(LIBSSH2_SESSION *session, libssh2_ecdsa_ctx *key, const unsigned char *hash, size_t hash_len, unsigned char **signature, size_t *signature_len) {
    return sign_key(session, key, hash, hash_len, signature, signature_len);
}

typedef struct { int kind; unsigned char secret[66]; size_t length; } AndroidExchangeKey;
int _libssh2_ecdsa_create_key(LIBSSH2_SESSION *session, _libssh2_ec_key **private_key, unsigned char **public_key, size_t *public_length, libssh2_curve_type type) {
    unsigned char bytes[133];
    AndroidExchangeKey *key = calloc(1, sizeof(*key));
    if(!key) return -1;
    key->kind = type; key->length = (type + 7) / 8;
    int count = olibssh_android_ec_generate(type, key->secret, bytes);
    if(count < 0) { free(key); return -1; }
    *public_key = LIBSSH2_ALLOC(session, (size_t)count);
    if(!*public_key) { ol_android_cleanse(key, sizeof(*key)); free(key); return -1; }
    memcpy(*public_key, bytes, (size_t)count); *public_length = (size_t)count; *private_key = key; return 0;
}
void olibssh_android_exchange_free(void *pointer) {
    if(pointer) { ol_android_cleanse(pointer, sizeof(AndroidExchangeKey)); free(pointer); }
}
int _libssh2_ecdh_gen_k(_libssh2_bn **k, _libssh2_ec_key *private_key, const unsigned char *public_key, size_t public_length) {
    AndroidExchangeKey *key = private_key; unsigned char secret[66];
    int count = olibssh_android_ec_shared(key->kind, key->secret, key->length, public_key, public_length, secret);
    int result = count < 0 ? -1 : _libssh2_bn_from_bin(*k, (size_t)count, secret);
    ol_android_cleanse(secret, sizeof(secret)); return result;
}
int _libssh2_curve25519_new(LIBSSH2_SESSION *session, uint8_t **public_key, uint8_t **private_key) {
    *public_key = LIBSSH2_ALLOC(session, 32); *private_key = LIBSSH2_ALLOC(session, 32);
    if(!*public_key || !*private_key) {
        LIBSSH2_FREE(session, *public_key); LIBSSH2_FREE(session, *private_key); *public_key = *private_key = NULL; return -1;
    }
    return olibssh_android_ec_generate(1, *private_key, *public_key) == 32 ? 0 : -1;
}
int _libssh2_curve25519_gen_k(_libssh2_bn **k, uint8_t private_key[32], uint8_t public_key[32]) {
    unsigned char secret[32];
    int count = olibssh_android_ec_shared(1, private_key, 32, public_key, 32, secret);
    int result = count < 0 ? -1 : _libssh2_bn_from_bin(*k, 32, secret);
    ol_android_cleanse(secret, sizeof(secret)); return result;
}
int _libssh2_ecdsa_new_private_sk(libssh2_ecdsa_ctx ** ec_ctx,
                              unsigned char *flags,
                              const char **application,
                              const unsigned char **key_handle,
                              size_t *handle_len,
                              LIBSSH2_SESSION * session,
                              const char *filename,
                              const unsigned char *passphrase) {
    (void)ec_ctx;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)session;
    (void)filename;
    (void)passphrase;
    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED, "Android crypto does not support security-key file import; use an SSH agent");
}
int _libssh2_ecdsa_new_private_frommemory_sk(libssh2_ecdsa_ctx ** ec_ctx,
                                             unsigned char *flags,
                                             const char **application,
                                             const unsigned char **key_handle,
                                             size_t *handle_len,
                                             LIBSSH2_SESSION * session,
                                             const char *filedata,
                                             size_t filedata_len,
                                             const unsigned char *passphrase) {
    (void)ec_ctx;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)session;
    (void)filedata;
    (void)filedata_len;
    (void)passphrase;
    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED, "Android crypto does not support security-key file import; use an SSH agent");
}
int _libssh2_sk_pub_keyfilememory(LIBSSH2_SESSION *session,
                                  unsigned char **method,
                                  size_t *method_len,
                                  unsigned char **pubkeydata,
                                  size_t *pubkeydata_len,
                                  int *algorithm,
                                  unsigned char *flags,
                                  const char **application,
                                  const unsigned char **key_handle,
                                  size_t *handle_len,
                                  const char *privatekeydata,
                                  size_t privatekeydata_len,
                                  const char *passphrase) {
    (void)session;
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)algorithm;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)privatekeydata;
    (void)privatekeydata_len;
    (void)passphrase;
    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED, "Android crypto does not support security-key file import; use an SSH agent");
}

int _libssh2_ed25519_new_private_frommemory(libssh2_ed25519_ctx **key, LIBSSH2_SESSION *session, const char *data, size_t len, const unsigned char *passphrase) {
    (void)passphrase;
    int result = parse_private(session, data, len, 1, key);
    return result;
}
int _libssh2_ed25519_new_private(libssh2_ed25519_ctx **key, LIBSSH2_SESSION *session, const char *filename, const unsigned char *passphrase) {
    (void)passphrase;
    int result = read_private(session, filename, 1, key);
    return result;
}

int _libssh2_ed25519_new_public(libssh2_ed25519_ctx **key, LIBSSH2_SESSION *session, const unsigned char *data, size_t len) {
    (void)session; *key = olibssh_android_key_create(1, data, len, 0); return *key ? 0 : -1;
}
int _libssh2_ed25519_verify(libssh2_ed25519_ctx *key, const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t length) {
    return olibssh_android_verify(key, signature, signature_len, message, length, 0);
}
int _libssh2_ed25519_sign(libssh2_ed25519_ctx *key, LIBSSH2_SESSION *session, uint8_t **signature, size_t *signature_len, const uint8_t *message, size_t length) {
    return sign_key(session, key, message, length, signature, signature_len);
}

int _libssh2_ed25519_new_private_sk(libssh2_ed25519_ctx **ed_ctx,
                                unsigned char *flags,
                                const char **application,
                                const unsigned char **key_handle,
                                size_t *handle_len,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const uint8_t *passphrase) {
    (void)ed_ctx;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)session;
    (void)filename;
    (void)passphrase;
    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED, "Android crypto does not support security-key file import");
}
int _libssh2_ed25519_new_private_frommemory_sk(libssh2_ed25519_ctx **ed_ctx,
                                           unsigned char *flags,
                                           const char **application,
                                           const unsigned char **key_handle,
                                           size_t *handle_len,
                                           LIBSSH2_SESSION *session,
                                           const char *filedata,
                                           size_t filedata_len,
                                           const unsigned char *passphrase) {
    (void)ed_ctx;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)session;
    (void)filedata;
    (void)filedata_len;
    (void)passphrase;
    return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED, "Android crypto does not support security-key file import");
}

#endif
