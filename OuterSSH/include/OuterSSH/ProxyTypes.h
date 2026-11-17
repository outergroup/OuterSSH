#ifndef OUTERSSH_PROXY_TYPES_H
#define OUTERSSH_PROXY_TYPES_H

#include "SSHSessionPool.h"

#ifdef __cplusplus
extern "C" {
#endif

OT_ASSUME_NONNULL_BEGIN

typedef enum {
    OUTERSSH_PROXY_AUTHENTICATION_PASSWORD,
    OUTERSSH_PROXY_AUTHENTICATION_NONE
} OuterSSHProxyAuthentication;

typedef struct {
    const char *username;
    size_t username_length;
    const char *password;
    size_t password_length;
} OuterSSHProxyCredentials;

OT_ASSUME_NONNULL_END

#ifdef __cplusplus
}
#endif
#endif
