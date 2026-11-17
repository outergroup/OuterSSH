#include "libssh2_priv.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static void hex(unsigned char *out, const char *text)
{
    while(*text) {
        unsigned int value;
        assert(sscanf(text, "%2x", &value) == 1);
        *out++ = (unsigned char)value;
        text += 2;
    }
}

static void test_x25519(void)
{
    unsigned char scalar[32], peer[32], expected[32], actual[32];
    hex(scalar, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    hex(peer, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    hex(expected, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    _libssh2_bn *k = _libssh2_bn_init();
    assert(k);
    assert(_libssh2_curve25519_gen_k(&k, scalar, peer) == 0);
    assert(_libssh2_bn_bytes(k) == 32);
    _libssh2_bn_to_bin(k, actual);
    assert(memcmp(actual, expected, 32) == 0);
    memset(peer, 0, sizeof(peer));
    assert(_libssh2_curve25519_gen_k(&k, scalar, peer) != 0);
    _libssh2_bn_free(k);
}

static void test_gcm(void)
{
    unsigned char key[16], iv[12], packet[4 + 16 + 16] = {0};
    unsigned char expected[32];
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    /* Independently generated AES-GCM vector: zero key/nonce/plaintext, four zero AAD bytes. */
    hex(expected, "0388dace60b6a392f328c2b971b2fe78b526422fa13b1a934f689289f0dcb33d");
    _libssh2_cipher_ctx encrypt, decrypt;
    _libssh2_cipher_type(type) = _libssh2_cipher_aes128gcm;
    assert(_libssh2_cipher_init(&encrypt, type, iv, key, 1) == 0);
    assert(_libssh2_cipher_init(&decrypt, type, iv, key, 0) == 0);
    assert(olibssh_cipher_crypt(&encrypt, type, 1, packet, 20, 0) == 0);
    assert(memcmp(packet + 4, expected, 32) == 0);
    assert(olibssh_cipher_crypt(&decrypt, type, 0, packet, 16, 0) == 0);
    for(size_t i = 0; i < 16; ++i) assert(packet[i] == 0);
    _libssh2_cipher_dtor(&encrypt);
    _libssh2_cipher_dtor(&decrypt);
    memset(packet, 0, sizeof(packet));
    assert(_libssh2_cipher_init(&encrypt, type, iv, key, 1) == 0);
    assert(_libssh2_cipher_init(&decrypt, type, iv, key, 0) == 0);
    assert(olibssh_cipher_crypt(&encrypt, type, 1, packet, 20, 0) == 0);
    packet[35] ^= 1;
    assert(olibssh_cipher_crypt(&decrypt, type, 0, packet, 16, 0) != 0);
    _libssh2_cipher_dtor(&encrypt);
    _libssh2_cipher_dtor(&decrypt);
}

int main(void)
{
    libssh2_crypto_init();
    test_x25519();
    test_gcm();
    libssh2_crypto_exit();
    puts("PASS: CNG X25519 RFC 7748, low-order rejection, AES-GCM and tampered tag rejection");
    return 0;
}
