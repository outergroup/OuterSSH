#ifndef OUTERSSH_ANDROID_CRYPTO_BRIDGE_H
#define OUTERSSH_ANDROID_CRYPTO_BRIDGE_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void ol_android_cleanse(void *data, size_t length);
void *ol_android_create(int operation, int kind, const void *a, size_t an, const void *b, size_t bn);
ptrdiff_t ol_android_result(int operation, int kind, void *context, const void *a, size_t an,
    const void *b, size_t bn, const void *c, size_t cn, void *output, size_t capacity);
void ol_android_free(void *context);
int ol_android_random(void *output, size_t length);
int ol_android_digest(int kind, const void *data, size_t length, void *output);
int ol_android_hash_init(void **context, int kind);
int ol_android_update(void *context, const void *data, size_t length);
int ol_android_final(void **context, void *output, size_t length);
#ifdef __cplusplus
}
#endif
#endif
