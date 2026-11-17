#include <stdlib.h>
/* Copyright (C) Sara Golemon <sarag@libssh2.org>
 * Copyright (C) Mikhail Gusarov <dottedmag@dottedmag.net>
 * Copyright (C) Daniel Stenberg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include "libssh2/libssh2_priv.h"
#include "authentication.h"
#include <ctype.h>

int olibssh_authentication_open_agent(OLIBSSHAuthenticationKey *key,
    const char *path, size_t path_length)
{
    key->session = olibssh_session_init();
    if (key->session == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    key->agent = libssh2_agent_init(key->session);
    if (key->agent == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    if (path_length != 0) {
        char *terminated_path = malloc(path_length + 1);
        if (terminated_path == NULL) {
            return LIBSSH2_ERROR_ALLOC;
        }
        memcpy(terminated_path, path, path_length);
        terminated_path[path_length] = 0;
        libssh2_agent_set_identity_path(key->agent, terminated_path);
        free(terminated_path);
    }
    int error = libssh2_agent_connect(key->agent);
    if (error == 0) {
        error = libssh2_agent_list_identities(key->agent);
    }
    if (error == 0) {
        error = olibssh_authentication_next_agent_key(key);
    }
    return error;
}

int olibssh_authentication_next_agent_key(OLIBSSHAuthenticationKey *key)
{
    struct libssh2_agent_publickey *identity = NULL;
    int error = libssh2_agent_get_identity(key->agent, &identity, key->identity);
    if (error != 0 || identity == NULL) {
        return error < 0 ? error : LIBSSH2_ERROR_AUTHENTICATION_FAILED;
    }
    key->identity = identity;
    key->public_key = identity->blob;
    key->public_key_length = identity->blob_len;
    return 0;
}

int olibssh_authentication_load_private_key(OLIBSSHAuthenticationKey *key,
    OuterSSHSessionAuthentication authentication)
{
    olibssh_authentication_key_dispose(key);
    key->authentication = authentication;
    key->session = olibssh_session_init();
    if (key->session == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    if (authentication.passphrase != NULL) {
        key->passphrase = malloc(authentication.passphrase_length + 1);
        if (key->passphrase == NULL) {
            return LIBSSH2_ERROR_ALLOC;
        }
        memcpy(key->passphrase, authentication.passphrase, authentication.passphrase_length);
        key->passphrase[authentication.passphrase_length] = 0;
    }
    size_t length = authentication.public_key_length;
    int error;
    if (length != 0) {
        const char *text = authentication.public_key;
        while (length != 0 && isspace((unsigned char)text[length - 1])) {
            length--;
        }
        const char *space = memchr(text, ' ', length);
        if (space == NULL) {
            return LIBSSH2_ERROR_FILE;
        }
        const char *base64 = space + 1;
        size_t base64_length = length - (size_t)(base64 - text);
        space = memchr(base64, ' ', base64_length);
        if (space != NULL) {
            base64_length = (size_t)(space - base64);
        }
        error = _libssh2_base64_decode(key->session,
            (char **)&key->owned_public_key, &key->public_key_length, base64, base64_length);
    } else {
        unsigned char *method = NULL;
        size_t method_length = 0;
        error = _libssh2_pub_priv_keyfilememory(key->session, &method, &method_length,
            &key->owned_public_key, &key->public_key_length,
            authentication.private_key, authentication.private_key_length, key->passphrase);
        LIBSSH2_FREE(key->session, method);
    }
    key->public_key = key->owned_public_key;
    return error;
}

int olibssh_authentication_sign(OLIBSSHAuthenticationKey *key,
    const char *method, size_t method_length,
    const unsigned char *data, size_t length,
    unsigned char **signature, size_t *signature_length)
{
    if (key->agent != NULL) {
        method = olibssh_authentication_signature_method(method, &method_length);
        return olibssh_agent_sign(key->agent, key->identity, signature, signature_length,
            data, length, method, (unsigned int)method_length);
    }
    const LIBSSH2_HOSTKEY_METHOD **methods = libssh2_hostkey_methods();
    while (*methods != NULL) {
        const LIBSSH2_HOSTKEY_METHOD *signer = *methods++;
        if (signer->initPEMFromMemory == NULL || signer->signv == NULL ||
            strlen(signer->name) != method_length ||
            memcmp(signer->name, method, method_length) != 0) {
            continue;
        }
        void *private_key = NULL;
        int error = signer->initPEMFromMemory(key->session,
            key->authentication.private_key, key->authentication.private_key_length,
            (const unsigned char *)key->passphrase, &private_key);
        if (error == 0) {
            struct iovec vector;
            libssh2_prepare_iovec(&vector, 1);
            vector.iov_base = (void *)data;
            vector.iov_len = length;
            error = signer->signv(key->session, signature, signature_length, 1,
                &vector, &private_key);
        }
        if (signer->dtor != NULL && private_key != NULL) {
            signer->dtor(key->session, &private_key);
        }
        return error;
    }
    return LIBSSH2_ERROR_METHOD_NONE;
}

const char *olibssh_authentication_signature_method(const char *method, size_t *length)
{
    static const char suffix[] = "-cert-v01@openssh.com";
    if (*length <= sizeof(suffix) - 1 ||
        memcmp(method + *length - (sizeof(suffix) - 1), suffix, sizeof(suffix) - 1) != 0) {
        return method;
    }
    *length -= sizeof(suffix) - 1;
    static const char security_ecdsa[] = "sk-ecdsa-sha2-nistp256@openssh.com";
    static const char security_ed25519[] = "sk-ssh-ed25519@openssh.com";
    const size_t vendor_suffix_length = sizeof("@openssh.com") - 1;
    if (*length == sizeof(security_ecdsa) - 1 - vendor_suffix_length && memcmp(method, security_ecdsa, *length) == 0) {
        *length = sizeof(security_ecdsa) - 1;
        return security_ecdsa;
    }
    if (*length == sizeof(security_ed25519) - 1 - vendor_suffix_length && memcmp(method, security_ed25519, *length) == 0) {
        *length = sizeof(security_ed25519) - 1;
        return security_ed25519;
    }
    return method;
}

void olibssh_authentication_key_dispose(OLIBSSHAuthenticationKey *key)
{
    if (key->agent != NULL) {
        libssh2_agent_free(key->agent);
    }
    if (key->session != NULL) {
        LIBSSH2_FREE(key->session, key->owned_public_key);
        olibssh_session_free(key->session);
    }
    if (key->passphrase != NULL) {
        volatile char *bytes = key->passphrase;
        for (size_t index = 0; index < key->authentication.passphrase_length; index++) {
            bytes[index] = 0;
        }
        free(key->passphrase);
    }
    *key = (OLIBSSHAuthenticationKey){0};
}

int olibssh_authentication_key_method(LIBSSH2_SESSION *session,
    const unsigned char *public_key, size_t public_key_length,
    bool use_original_method, char **method, size_t *method_length)
{
    if (public_key_length < 4) {
        return LIBSSH2_ERROR_PROTO;
    }
    size_t original_length = _libssh2_ntohu32(public_key);
    if (original_length == 0 || original_length > public_key_length - 4) {
        return LIBSSH2_ERROR_PROTO;
    }
    const char *original = (const char *)public_key + 4;
    const char *selected = original;
    size_t selected_length = original_length;
    static const char rsa_certificate[] = "ssh-rsa-cert-v01@openssh.com";
    static const char certificate_suffix[] = "-cert-v01@openssh.com";
    bool certificate = original_length == sizeof(rsa_certificate) - 1 &&
        memcmp(original, rsa_certificate, original_length) == 0;
    const char *supported = _libssh2_supported_key_sign_algorithms(session,
        (unsigned char *)original, original_length);
    if (!use_original_method && supported != NULL && session->server_sign_algorithms != NULL) {
        selected = NULL;
        const char *candidate = session->sign_algo_prefs != NULL
            ? session->sign_algo_prefs : supported;
        while (*candidate != 0 && selected == NULL) {
            const char *end = strchr(candidate, ',');
            size_t length = end == NULL ? strlen(candidate) : (size_t)(end - candidate);
            if (_libssh2_kex_agree_instr((unsigned char *)supported, strlen(supported),
                    (const unsigned char *)candidate, length) != NULL &&
                _libssh2_kex_agree_instr((unsigned char *)session->server_sign_algorithms,
                    strlen(session->server_sign_algorithms),
                    (const unsigned char *)candidate, length) != NULL) {
                selected = candidate;
                selected_length = length;
            }
            if (end == NULL) break;
            candidate = end + 1;
        }
        if (selected == NULL) {
            return LIBSSH2_ERROR_METHOD_NONE;
        }
    }
    bool append_suffix = certificate && selected != original;
    *method_length = selected_length + (append_suffix ? sizeof(certificate_suffix) - 1 : 0);
    *method = malloc(*method_length);
    if (*method == NULL) {
        return LIBSSH2_ERROR_ALLOC;
    }
    memcpy(*method, selected, selected_length);
    if (append_suffix) {
        memcpy(*method + selected_length, certificate_suffix, sizeof(certificate_suffix) - 1);
    }
    return 0;
}

const unsigned char *olibssh_authentication_session_id(LIBSSH2_SESSION *session,
    size_t *length)
{
    *length = session->session_id_len;
    return session->session_id;
}

void olibssh_authentication_succeeded(LIBSSH2_SESSION *session)
{
    session->state |= LIBSSH2_STATE_AUTHENTICATED;
}
