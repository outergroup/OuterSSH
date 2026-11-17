#ifndef OUTERSSH_ANDROID_H
#define OUTERSSH_ANDROID_H

#if defined(__ANDROID__) && OUTERSSH_ANDROID_CRYPTO
#include <jni.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Android platform cryptography calls into the Java class org.outerssh.AndroidCrypto,
 * from OuterSSH/platform/android/java; add that directory to the app's Java sources
 * and keep the class's public static methods from shrinking. Call this from the
 * native library's JNI_OnLoad, before using OuterSSH, so the class loads with the
 * app's class loader. Returns false if the class cannot be loaded. */
bool outerssh_android_initialize(JavaVM *vm);

#ifdef __cplusplus
}
#endif

#endif
#endif
