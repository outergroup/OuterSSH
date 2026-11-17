#if defined(__ANDROID__) && OUTERSSH_ANDROID_CRYPTO
#include "AndroidCryptoBridge.h"
#include "OuterSSHAndroid.h"
#include <jni.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static JavaVM *vm;
static jclass bridge;
static jmethodID create_method, run_method;
static pthread_key_t attachment;
static void detach(void *value) { if(value && vm) (*vm)->DetachCurrentThread(vm); }
static JNIEnv *environment(void) {
    JNIEnv *env = NULL;
    if(!vm) return NULL;
    if((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) return env;
    if((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) return NULL;
    if(pthread_setspecific(attachment, (void *)1)) { (*vm)->DetachCurrentThread(vm); return NULL; }
    return env;
}
bool outerssh_android_initialize(JavaVM *machine) {
    if(vm) return true;
    JNIEnv *env = NULL;
    if((*machine)->GetEnv(machine, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return false;
    jclass local = (*env)->FindClass(env, "org/outerssh/AndroidCrypto");
    if(!local) { (*env)->ExceptionClear(env); return false; }
    bridge = (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    if(!bridge) return false;
    create_method = (*env)->GetStaticMethodID(env, bridge, "create", "(II[B[B)Ljava/lang/Object;");
    run_method = (*env)->GetStaticMethodID(env, bridge, "run", "(IILjava/lang/Object;[B[B[B)[B");
    if(!create_method || !run_method || pthread_key_create(&attachment, detach)) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteGlobalRef(env, bridge);
        bridge = NULL;
        return false;
    }
    vm = machine;
    return true;
}
void ol_android_cleanse(void *data, size_t length) {
    volatile unsigned char *bytes = data;
    while(length--) *bytes++ = 0;
}
static jbyteArray array(JNIEnv *env, const void *data, size_t length) {
    if(length > INT_MAX || (length && !data)) return NULL;
    jbyteArray result = (*env)->NewByteArray(env, (jsize)length);
    if(result && length) (*env)->SetByteArrayRegion(env, result, 0, (jsize)length, data);
    return result;
}
static int failed(JNIEnv *env) {
    if(!(*env)->ExceptionCheck(env)) return 0;
    (*env)->ExceptionClear(env);
    return 1;
}
void *ol_android_create(int operation, int kind, const void *a, size_t an, const void *b, size_t bn) {
    JNIEnv *env = environment();
    if(!env || (*env)->PushLocalFrame(env, 8)) return NULL;
    jbyteArray aa = array(env, a, an), bb = array(env, b, bn);
    jobject result = NULL;
    if(!failed(env) && aa && bb) {
        jobject local = (*env)->CallStaticObjectMethod(env, bridge, create_method, operation, kind, aa, bb);
        if(!failed(env) && local) result = (*env)->NewGlobalRef(env, local);
    }
    if(failed(env)) result = NULL;
    (*env)->PopLocalFrame(env, NULL);
    return result;
}
ptrdiff_t ol_android_result(int operation, int kind, void *context, const void *a, size_t an,
    const void *b, size_t bn, const void *c, size_t cn, void *output, size_t capacity) {
    JNIEnv *env = environment();
    if(!env || (*env)->PushLocalFrame(env, 8)) return -1;
    ptrdiff_t count = -1;
    jbyteArray aa = array(env, a, an), bb = array(env, b, bn), cc = array(env, c, cn);
    if(!failed(env) && aa && bb && cc) {
        jbyteArray result = (*env)->CallStaticObjectMethod(env, bridge, run_method, operation, kind, context, aa, bb, cc);
        if(!failed(env) && result) {
            jsize length = (*env)->GetArrayLength(env, result);
            if(!output) count = length;
            else if((size_t)length <= capacity) {
                (*env)->GetByteArrayRegion(env, result, 0, length, output);
                if(!failed(env)) count = length;
            }
        }
    }
    (*env)->PopLocalFrame(env, NULL);
    return count;
}
void ol_android_free(void *context) {
    JNIEnv *env = environment();
    if(env && context) (*env)->DeleteGlobalRef(env, context);
}
int ol_android_random(void *output, size_t length) {
    if(length > INT_MAX) return -1;
    return ol_android_result(4, (int)length, NULL, NULL, 0, NULL, 0, NULL, 0, output, length) == (ptrdiff_t)length ? 0 : -1;
}
int ol_android_digest(int kind, const void *data, size_t length, void *output) {
    return ol_android_result(5, kind, NULL, data, length, NULL, 0, NULL, 0, output, (size_t)kind) == kind ? 0 : -1;
}
int ol_android_hash_init(void **context, int kind) { *context = ol_android_create(1, kind, NULL, 0, NULL, 0); return *context != NULL; }
int ol_android_update(void *context, const void *data, size_t length) {
    return context && ol_android_result(1, 0, context, data, length, NULL, 0, NULL, 0, NULL, 0) == 0;
}
int ol_android_final(void **context, void *output, size_t length) {
    int result = *context && ol_android_result(2, 0, *context, NULL, 0, NULL, 0, NULL, 0, output, length) == (ptrdiff_t)length;
    ol_android_free(*context); *context = NULL; return result;
}
void olibssh_android_key_free(void *key) { ol_android_free(key); }
void *olibssh_android_key_create(int kind, const void *bytes, size_t count, int private_key) {
    return private_key ? NULL : ol_android_create(4, kind, bytes, count, NULL, 0);
}
void *olibssh_android_rsa_public(const void *e, size_t en, const void *n, size_t nn) { return ol_android_create(5, 0, e, en, n, nn); }
void *olibssh_android_key_parse(const void *bytes, size_t count, int *error) {
    void *key = ol_android_create(6, 0, bytes, count, NULL, 0); *error = key ? 0 : 2; return key;
}
int olibssh_android_key_kind(void *key) {
    unsigned char bytes[4];
    if(ol_android_result(6, 0, key, NULL, 0, NULL, 0, NULL, 0, bytes, 4) != 4) return -1;
    return (int)((uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3]);
}
ptrdiff_t olibssh_android_key_export(void *key, void *out, size_t capacity) { return ol_android_result(7, 0, key, NULL, 0, NULL, 0, NULL, 0, out, capacity); }
ptrdiff_t olibssh_android_sign(void *key, const void *data, size_t length, void *out, size_t capacity) { return ol_android_result(8, 0, key, data, length, NULL, 0, NULL, 0, out, capacity); }
int olibssh_android_verify(void *key, const void *sig, size_t sn, const void *data, size_t length, size_t hash) {
    return ol_android_result(9, (int)hash, key, sig, sn, data, length, NULL, 0, NULL, 0) == 0 ? 0 : -1;
}
int olibssh_android_verify_ec(void *key, const void *r, size_t rn, const void *s, size_t sn, const void *data, size_t length) {
    return ol_android_result(10, 0, key, r, rn, s, sn, data, length, NULL, 0) == 0 ? 0 : -1;
}
int olibssh_android_ec_generate(int kind, void *private_bytes, void *public_bytes) {
    unsigned char output[199];
    size_t private_count = kind == 1 ? 32 : (size_t)(kind + 7) / 8;
    ptrdiff_t count = ol_android_result(11, kind, NULL, NULL, 0, NULL, 0, NULL, 0, output, sizeof(output));
    if(count < (ptrdiff_t)private_count) return -1;
    memcpy(private_bytes, output, private_count);
    memcpy(public_bytes, output + private_count, (size_t)count - private_count);
    ol_android_cleanse(output, sizeof(output));
    return (int)((size_t)count - private_count);
}
int olibssh_android_ec_shared(int kind, const void *private_bytes, size_t pn, const void *public_bytes, size_t qn, void *output) {
    return (int)ol_android_result(12, kind, NULL, private_bytes, pn, public_bytes, qn, NULL, 0, output, kind == 1 ? 32 : (size_t)(kind + 7) / 8);
}
void *olibssh_android_packet_key_create(const void *bytes, size_t count) { return ol_android_create(7, 0, bytes, count, NULL, 0); }
void olibssh_android_packet_key_free(void *key) { ol_android_free(key); }
int olibssh_android_gcm(void *key, const void *iv, void *packet, size_t length, int encrypt) {
    size_t input = 4 + length + (encrypt ? 0 : 16), output = 4 + length + (encrypt ? 16 : 0);
    return ol_android_result(13, encrypt, key, iv, 12, packet, input, NULL, 0, packet, output) == (ptrdiff_t)output ? 0 : -1;
}
#endif
