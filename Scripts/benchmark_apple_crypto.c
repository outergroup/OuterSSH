/* Benchmark-only replacement for crypt.o: retain all production algorithms,
 * replacing AES-GCM with a whole-packet implementation. Linking this object
 * before libOuterSSH.a leaves the archive's crypt.o unused. */
#define libssh2_crypt_methods benchmark_original_crypt_methods
#include "../OuterSSH/olibssh/libssh2/crypt.c"
#undef libssh2_crypt_methods

#include <dispatch/dispatch.h>

#if BENCHMARK_CRYPTOKIT
extern void *benchmark_cryptokit_key_create(const void *bytes, size_t count);
extern void benchmark_cryptokit_key_destroy(void *context);
extern int32_t benchmark_cryptokit_packet(void *context, const void *iv,
    void *packet, size_t payload_length, int32_t encrypt);

typedef struct {
    void *key;
    unsigned char iv[12];
    int encrypt;
} PacketCipher;

static int packet_cipher_init(LIBSSH2_SESSION *session, const LIBSSH2_CRYPT_METHOD *method,
    unsigned char *iv, int *free_iv, unsigned char *secret, int *free_secret,
    int encrypt, void **abstract);
static int packet_cipher_destroy(LIBSSH2_SESSION *session, void **abstract);
#endif
static int packet_cipher_crypt(LIBSSH2_SESSION *session, unsigned int seqno,
    unsigned char *buffer, size_t length, void **abstract, int firstlast);
static int packet_length(LIBSSH2_SESSION *session, unsigned int seqno,
    unsigned char *buffer, size_t length, unsigned int *result, void **abstract);
static void configure_packet_methods(void *context);
static void verify_packet_method(const LIBSSH2_CRYPT_METHOD *method);

const LIBSSH2_CRYPT_METHOD **libssh2_crypt_methods(void)
{
    static dispatch_once_t once;
    dispatch_once_f(&once, NULL, configure_packet_methods);
    return benchmark_original_crypt_methods();
}

static void configure_packet_methods(void *context)
{
    (void)context;
    static LIBSSH2_CRYPT_METHOD methods[2];
    const LIBSSH2_CRYPT_METHOD **table = benchmark_original_crypt_methods();
    size_t count = 0;
    for (size_t index = 0; table[index] != NULL; index++) {
        if (strcmp(table[index]->name, "aes128-gcm@openssh.com") != 0 &&
            strcmp(table[index]->name, "aes256-gcm@openssh.com") != 0) continue;
        if (count == 2) abort();
        LIBSSH2_CRYPT_METHOD *method = &methods[count++];
        *method = *table[index];
        method->flags = LIBSSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET;
        method->get_len = packet_length;
        method->crypt = packet_cipher_crypt;
#if BENCHMARK_CRYPTOKIT
        method->init = packet_cipher_init;
        method->dtor = packet_cipher_destroy;
#endif
        verify_packet_method(method);
        table[index] = method;
    }
    if (count != 2) abort();
}

#if BENCHMARK_CRYPTOKIT
static int packet_cipher_init(LIBSSH2_SESSION *session, const LIBSSH2_CRYPT_METHOD *method,
    unsigned char *iv, int *free_iv, unsigned char *secret, int *free_secret,
    int encrypt, void **abstract)
{
    PacketCipher *cipher = LIBSSH2_ALLOC(session, sizeof(*cipher));
    if (cipher == NULL) return LIBSSH2_ERROR_ALLOC;
    cipher->key = benchmark_cryptokit_key_create(secret, method->secret_len);
    memcpy(cipher->iv, iv, sizeof(cipher->iv));
    cipher->encrypt = encrypt;
    *abstract = cipher;
    *free_iv = *free_secret = 1;
    return 0;
}

static int packet_cipher_destroy(LIBSSH2_SESSION *session, void **abstract)
{
    PacketCipher *cipher = *abstract;
    if (cipher != NULL) {
        benchmark_cryptokit_key_destroy(cipher->key);
        LIBSSH2_FREE(session, cipher);
        *abstract = NULL;
    }
    return 0;
}
#endif

static int packet_cipher_crypt(LIBSSH2_SESSION *session, unsigned int seqno,
    unsigned char *buffer, size_t length, void **abstract, int firstlast)
{
    (void)session; (void)seqno; (void)firstlast;
#if BENCHMARK_CRYPTOKIT
    PacketCipher *cipher = *abstract;
#else
    struct crypt_ctx *cipher = *abstract;
#endif
    if (cipher->encrypt && length < 4) return LIBSSH2_ERROR_INVAL;
    /* On writes length includes the four-byte header; on reads it excludes it.
     * In both cases the tag has storage immediately after the payload. */
    size_t payload_length = cipher->encrypt ? length - 4 : length;
#if BENCHMARK_CRYPTOKIT
    int result = benchmark_cryptokit_packet(cipher->key, cipher->iv, buffer,
        payload_length, cipher->encrypt);
    /* SSH GCM uses a fixed four-byte prefix and a big-endian invocation counter. */
    if (result == 0) {
        for (int index = 11; index >= 4; index--) {
            if (++cipher->iv[index] != 0) break;
        }
    }
#else
    int result = olibssh_cipher_crypt(&cipher->h, cipher->algo, cipher->encrypt,
        buffer, payload_length + 4, FIRST_BLOCK);
    if (result == 0)
        result = olibssh_cipher_crypt(&cipher->h, cipher->algo, cipher->encrypt,
            buffer + payload_length + 4, 16, LAST_BLOCK);
#endif
    /* The whole-packet reader expects the decrypted padding byte at offset zero. */
    if (result == 0 && !cipher->encrypt) memmove(buffer, buffer + 4, payload_length);
    return result;
}

static int packet_length(LIBSSH2_SESSION *session, unsigned int seqno,
    unsigned char *buffer, size_t length, unsigned int *result, void **abstract)
{
    (void)session; (void)seqno; (void)abstract;
    if (length < 4) return LIBSSH2_ERROR_INVAL;
    *result = _libssh2_ntohu32(buffer);
    return 0;
}

/* Run outside measurement. Compare successive packets to the production OpenSSL
 * path, including a carry in the nonce and authenticated header/tag rejection. */
static void verify_packet_method(const LIBSSH2_CRYPT_METHOD *method)
{
    LIBSSH2_SESSION *session = olibssh_session_init();
    if (session == NULL) abort();
    unsigned char secret[32], iv[12];
    for (size_t index = 0; index < sizeof(secret); index++) secret[index] = (unsigned char)index;
    for (size_t index = 0; index < sizeof(iv); index++) iv[index] = (unsigned char)(index + 1);
    iv[11] = 250;
    void *reference = NULL, *sender = NULL, *receiver = NULL;
    int free_iv, free_secret;
    if (crypt_init(session, method, iv, &free_iv, secret, &free_secret, 1, &reference) != 0 ||
        method->init(session, method, iv, &free_iv, secret, &free_secret, 1, &sender) != 0 ||
        method->init(session, method, iv, &free_iv, secret, &free_secret, 0, &receiver) != 0) abort();
    unsigned char expected[32768 + 4 + 16], actual[sizeof(expected)], decoded[sizeof(expected)];
    const size_t lengths[] = {16, 32, 1024, 32768};
    for (unsigned packet = 0; packet < 20; packet++) {
        size_t length = lengths[packet % 4];
        unsigned char *header = expected;
        _libssh2_store_u32(&header, (uint32_t)length);
        for (size_t index = 0; index < length; index++) expected[index + 4] = (unsigned char)(index + packet);
        memcpy(actual, expected, length + 4);
        if (crypt_encrypt(session, packet, expected, length + 4, &reference, FIRST_BLOCK) != 0 ||
            crypt_encrypt(session, packet, expected + length + 4, 16, &reference, LAST_BLOCK) != 0 ||
            method->crypt(session, packet, actual, length + 4, &sender, 0) != 0 ||
            memcmp(actual, expected, length + 4 + 16) != 0) abort();
        memcpy(decoded, actual, length + 4 + 16);
        if (method->crypt(session, packet, decoded, length, &receiver, 0) != 0) abort();
        for (size_t index = 0; index < length; index++)
            if (decoded[index] != (unsigned char)(index + packet)) abort();
        if (packet == 0) {
            const size_t corruptions[] = {0, 4, length + 4};
            for (size_t index = 0; index < 3; index++) {
                void *bad_receiver = NULL;
                if (method->init(session, method, iv, &free_iv, secret, &free_secret, 0, &bad_receiver) != 0) abort();
                memcpy(decoded, actual, length + 4 + 16);
                decoded[corruptions[index]] ^= 1;
                if (method->crypt(session, packet, decoded, length, &bad_receiver, 0) == 0) abort();
                method->dtor(session, &bad_receiver);
            }
        }
    }
    crypt_dtor(session, &reference);
    method->dtor(session, &sender);
    method->dtor(session, &receiver);
    olibssh_session_free(session);
}
