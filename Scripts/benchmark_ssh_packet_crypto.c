/* Measures the production SSH packet encryption calls without a peer/socket. */
#include "libssh2_priv.h"
#include <errno.h>
#include <stdio.h>
#include <time.h>

static double now(void);

int main(int argc, char **argv)
{
    if(argc == 2 && strcmp(argv[1], "--info") == 0) {
        if(OPENSSL_init_crypto(0, NULL) != 1)
            return 1;
        printf("%s\n", OpenSSL_version(OPENSSL_VERSION));
        const char *settings = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS);
        if(settings)
            puts(settings);
        return 0;
    }
    if(argc < 2 || argc > 4 || (strcmp(argv[1], "chacha20-poly1305@openssh.com") &&
                    strcmp(argv[1], "aes128-gcm@openssh.com") &&
                    strcmp(argv[1], "aes256-gcm@openssh.com"))) {
        fprintf(stderr, "usage: %s {chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com} [MiB [rounds]]\n", argv[0]);
        return 1;
    }
    unsigned parameters[] = {512, 7};
    const unsigned limits[] = {65536, 1000};
    for(int i = 2; i < argc; i++) {
        char *end;
        errno = 0;
        unsigned long value = strtoul(argv[i], &end, 10);
        if(errno || end == argv[i] || *end || value == 0 || value > limits[i - 2]) {
            fprintf(stderr, "invalid %s: %s\n", i == 2 ? "MiB" : "rounds", argv[i]);
            return 1;
        }
        parameters[i - 2] = (unsigned)value;
    }
    const LIBSSH2_CRYPT_METHOD **methods = libssh2_crypt_methods();
    while(*methods && strcmp((*methods)->name, argv[1]))
        methods++;
    if(!*methods) {
        fprintf(stderr, "cipher unavailable: %s\n", argv[1]);
        return 1;
    }
    const LIBSSH2_CRYPT_METHOD *cipher = *methods;
    LIBSSH2_SESSION *session = olibssh_session_init();
    if(!session)
        return 1;
    unsigned char key[64], iv[12] = {0};
    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)i;
    void *context = NULL;
    int free_iv, free_key;
    if(cipher->init(session, cipher, iv, &free_iv, key, &free_key, 1, &context)) {
        fprintf(stderr, "cipher initialization failed\n");
        olibssh_session_free(session);
        return 1;
    }

    enum { BODY_SIZE = 32768, PACKET_SIZE = 4 + BODY_SIZE, TAG_SIZE = 16 };
    unsigned char plaintext[PACKET_SIZE], packet[PACKET_SIZE + TAG_SIZE];
    _libssh2_htonu32(plaintext, BODY_SIZE);
    for(size_t i = 4; i < sizeof(plaintext); i++)
        plaintext[i] = (unsigned char)(i * 73);
    plaintext[4] = 8; /* SSH padding length; padding is included in BODY_SIZE. */
    unsigned sequence = 0;
    int status = 0;
    puts("round,mib,seconds,mib_per_second");
    for(unsigned round = 0; round <= parameters[1]; round++) {
        unsigned mib = round == 0 ? 16 : parameters[0];
        unsigned packets = mib * (1024 * 1024 / BODY_SIZE);
        double start = now();
        for(unsigned i = 0; i < packets; i++, sequence++) {
            memcpy(packet, plaintext, sizeof(plaintext));
            int error;
            if(cipher->flags & LIBSSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET) {
                error = cipher->crypt(session, sequence, packet, PACKET_SIZE,
                                      &context, 0);
            }
            else {
                error = cipher->crypt(session, 0, packet, PACKET_SIZE,
                                      &context, FIRST_BLOCK);
                if(!error)
                    error = cipher->crypt(session, 0, packet + PACKET_SIZE,
                                          TAG_SIZE, &context, LAST_BLOCK);
            }
            if(error) {
                fprintf(stderr, "packet encryption failed: %d\n", error);
                status = 1;
                goto done;
            }
        }
        double seconds = now() - start;
        if(round)
            printf("%u,%u,%.6f,%.3f\n", round, mib, seconds, mib / seconds);
    }
done:
    cipher->dtor(session, &context);
    olibssh_session_free(session);
    return status;
}

static double now(void)
{
    struct timespec value;
    if(clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return value.tv_sec + value.tv_nsec / 1000000000.0;
}
