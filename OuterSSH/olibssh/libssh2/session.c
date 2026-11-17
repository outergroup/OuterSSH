/* Copyright (C) Sara Golemon <sarag@libssh2.org>
 * Copyright (C) Daniel Stenberg
 * Copyright (C) Simon Josefsson <simon@josefsson.org>
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

#include "libssh2_priv.h"
#include "mac.h"
#include <stdlib.h>

static LIBSSH2_ALLOC_FUNC(libssh2_default_alloc);
static LIBSSH2_FREE_FUNC(libssh2_default_free);
static LIBSSH2_REALLOC_FUNC(libssh2_default_realloc);

/* OLIBSSH: initialize storage only; the reactor owns protocol startup and deadlines. */
LIBSSH2_API LIBSSH2_SESSION *
olibssh_session_init_ex(LIBSSH2_ALLOC_FUNC((*my_alloc)),
                        LIBSSH2_FREE_FUNC((*my_free)),
                        LIBSSH2_REALLOC_FUNC((*my_realloc)), void *abstract)
{
    LIBSSH2_ALLOC_FUNC((*local_alloc)) = libssh2_default_alloc;
    LIBSSH2_FREE_FUNC((*local_free)) = libssh2_default_free;
    LIBSSH2_REALLOC_FUNC((*local_realloc)) = libssh2_default_realloc;
    LIBSSH2_SESSION *session;

    if(my_alloc) {
        local_alloc = my_alloc;
    }
    if(my_free) {
        local_free = my_free;
    }
    if(my_realloc) {
        local_realloc = my_realloc;
    }

    session = local_alloc(sizeof(LIBSSH2_SESSION), &abstract);
    if(session) {
        memset(session, 0, sizeof(LIBSSH2_SESSION));
        session->alloc = local_alloc;
        session->free = local_free;
        session->realloc = local_realloc;
        session->send = _libssh2_send;
        session->recv = _libssh2_recv;
        session->abstract = abstract;
        session->state = LIBSSH2_STATE_INITIAL_KEX;
        session->fullpacket_required_type = 0;
        session->kex = NULL;
        _libssh2_debug((session, LIBSSH2_TRACE_TRANS,
                       "New session resource allocated"));
        _libssh2_init_if_needed();
    }
    return session;
}

/* OLIBSSH: release retained crypto and transport storage without socket I/O.
 * The reactor disposes its handshake, authentication, and channels first. */
LIBSSH2_API int
olibssh_session_free(LIBSSH2_SESSION *session)
{
    if(session->state & LIBSSH2_STATE_NEWKEYS) {
        /* hostkey */
        if(session->hostkey && session->hostkey->dtor) {
            session->hostkey->dtor(session, &session->server_hostkey_abstract);
        }

        /* Client to Server */
        /* crypt */
        if(session->local.crypt && session->local.crypt->dtor) {
            session->local.crypt->dtor(session,
                                       &session->local.crypt_abstract);
        }
        /* comp */
        if(session->local.comp && session->local.comp->dtor) {
            session->local.comp->dtor(session, 1,
                                      &session->local.comp_abstract);
        }
        /* mac */
        if(session->local.mac && session->local.mac->dtor) {
            session->local.mac->dtor(session, &session->local.mac_abstract);
        }

        /* Server to Client */
        /* crypt */
        if(session->remote.crypt && session->remote.crypt->dtor) {
            session->remote.crypt->dtor(session,
                                        &session->remote.crypt_abstract);
        }
        /* comp */
        if(session->remote.comp && session->remote.comp->dtor) {
            session->remote.comp->dtor(session, 0,
                                       &session->remote.comp_abstract);
        }
        /* mac */
        if(session->remote.mac && session->remote.mac->dtor) {
            session->remote.mac->dtor(session, &session->remote.mac_abstract);
        }

        /* session_id */
        if(session->session_id) {
            LIBSSH2_FREE(session, session->session_id);
        }
    }

    /* Free banner(s) */
    if(session->remote.banner) {
        LIBSSH2_FREE(session, session->remote.banner);
    }
    if(session->local.banner) {
        LIBSSH2_FREE(session, session->local.banner);
    }

    /* Free preference(s) */
    if(session->kex_prefs) {
        LIBSSH2_FREE(session, session->kex_prefs);
    }
    if(session->hostkey_prefs) {
        LIBSSH2_FREE(session, session->hostkey_prefs);
    }

    if(session->local.kexinit) {
        LIBSSH2_FREE(session, session->local.kexinit);
    }
    if(session->local.crypt_prefs) {
        LIBSSH2_FREE(session, session->local.crypt_prefs);
    }
    if(session->local.mac_prefs) {
        LIBSSH2_FREE(session, session->local.mac_prefs);
    }
    if(session->local.comp_prefs) {
        LIBSSH2_FREE(session, session->local.comp_prefs);
    }
    if(session->local.lang_prefs) {
        LIBSSH2_FREE(session, session->local.lang_prefs);
    }

    if(session->remote.kexinit) {
        LIBSSH2_FREE(session, session->remote.kexinit);
    }
    if(session->remote.crypt_prefs) {
        LIBSSH2_FREE(session, session->remote.crypt_prefs);
    }
    if(session->remote.mac_prefs) {
        LIBSSH2_FREE(session, session->remote.mac_prefs);
    }
    if(session->remote.comp_prefs) {
        LIBSSH2_FREE(session, session->remote.comp_prefs);
    }
    if(session->remote.lang_prefs) {
        LIBSSH2_FREE(session, session->remote.lang_prefs);
    }
    if(session->server_sign_algorithms) {
        LIBSSH2_FREE(session, session->server_sign_algorithms);
    }
    if(session->sign_algo_prefs) {
        LIBSSH2_FREE(session, session->sign_algo_prefs);
    }

    if(session->packet.total_num)
        LIBSSH2_FREE(session, session->packet.payload);
    if(session->server_hostkey)
        LIBSSH2_FREE(session, session->server_hostkey);
    if(session->err_msg && (session->err_flags & LIBSSH2_ERR_FLAG_DUP))
        LIBSSH2_FREE(session, (char *)LIBSSH2_UNCONST(session->err_msg));
    LIBSSH2_FREE(session, session);
    return 0;
}

LIBSSH2_API libssh2_cb_generic *
libssh2_session_callback_set2(LIBSSH2_SESSION *session, int cbtype,
                              libssh2_cb_generic *callback)
{
    libssh2_cb_generic *oldcb;

    switch(cbtype) {
    case LIBSSH2_CALLBACK_IGNORE:
        oldcb = (libssh2_cb_generic *)session->ssh_msg_ignore;
        session->ssh_msg_ignore = (LIBSSH2_IGNORE_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_DEBUG:
        oldcb = (libssh2_cb_generic *)session->ssh_msg_debug;
        session->ssh_msg_debug = (LIBSSH2_DEBUG_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_DISCONNECT:
        oldcb = (libssh2_cb_generic *)session->ssh_msg_disconnect;
        session->ssh_msg_disconnect = (LIBSSH2_DISCONNECT_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_MACERROR:
        oldcb = (libssh2_cb_generic *)session->macerror;
        session->macerror = (LIBSSH2_MACERROR_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_X11:
        oldcb = (libssh2_cb_generic *)session->x11;
        session->x11 = (LIBSSH2_X11_OPEN_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_SEND:
        oldcb = (libssh2_cb_generic *)session->send;
        session->send = (LIBSSH2_SEND_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_RECV:
        oldcb = (libssh2_cb_generic *)session->recv;
        session->recv = (LIBSSH2_RECV_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_AUTHAGENT:
        oldcb = (libssh2_cb_generic *)session->authagent;
        session->authagent = (LIBSSH2_AUTHAGENT_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_AUTHAGENT_IDENTITIES:
        oldcb = (libssh2_cb_generic *)session->addLocalIdentities;
        session->addLocalIdentities =
            (LIBSSH2_ADD_IDENTITIES_FUNC((*)))callback;
        return oldcb;

    case LIBSSH2_CALLBACK_AUTHAGENT_SIGN:
        oldcb = (libssh2_cb_generic *)session->agentSignCallback;
        session->agentSignCallback =
            (LIBSSH2_AUTHAGENT_SIGN_FUNC((*)))callback;
        return oldcb;
    }
    _libssh2_debug((session, LIBSSH2_TRACE_TRANS, "Setting Callback %d",
                   cbtype));

    return NULL;
}

LIBSSH2_API const char *
libssh2_session_methods(LIBSSH2_SESSION * session, int method_type)
{
    /* All methods have char *name as their first element */
    const LIBSSH2_KEX_METHOD *method = NULL;

    switch(method_type) {
    case LIBSSH2_METHOD_KEX:
        method = session->kex;
        break;

    case LIBSSH2_METHOD_HOSTKEY:
        method = (const LIBSSH2_KEX_METHOD *) session->hostkey;
        break;

    case LIBSSH2_METHOD_CRYPT_CS:
        method = (const LIBSSH2_KEX_METHOD *) session->local.crypt;
        break;

    case LIBSSH2_METHOD_CRYPT_SC:
        method = (const LIBSSH2_KEX_METHOD *) session->remote.crypt;
        break;

    case LIBSSH2_METHOD_MAC_CS:
        method = (const LIBSSH2_KEX_METHOD *) session->local.mac;
        break;

    case LIBSSH2_METHOD_MAC_SC:
        method = (const LIBSSH2_KEX_METHOD *) session->remote.mac;
        break;

    case LIBSSH2_METHOD_COMP_CS:
        method = (const LIBSSH2_KEX_METHOD *) session->local.comp;
        break;

    case LIBSSH2_METHOD_COMP_SC:
        method = (const LIBSSH2_KEX_METHOD *) session->remote.comp;
        break;

    case LIBSSH2_METHOD_LANG_CS:
        return "";

    case LIBSSH2_METHOD_LANG_SC:
        return "";

    default:
        _libssh2_error(session, LIBSSH2_ERROR_INVAL,
                       "Invalid parameter specified for method_type");
        return NULL;
    }

    if(!method) {
        _libssh2_error(session, LIBSSH2_ERROR_METHOD_NONE,
                       "No method negotiated");
        return NULL;
    }

    return method->name;
}

LIBSSH2_API int
libssh2_session_last_error(LIBSSH2_SESSION * session, char **errmsg,
                           int *errmsg_len, int want_buf)
{
    size_t msglen = 0;

    /* No error to report */
    if(!session->err_code) {
        if(errmsg) {
            if(want_buf) {
                *errmsg = LIBSSH2_ALLOC(session, 1);
                if(*errmsg) {
                    **errmsg = 0;
                }
            }
            else {
                *errmsg = (char *)LIBSSH2_UNCONST("");
            }
        }
        if(errmsg_len) {
            *errmsg_len = 0;
        }
        return 0;
    }

    if(errmsg) {
        const char *error = session->err_msg ? session->err_msg : "";

        msglen = strlen(error);

        if(want_buf) {
            /* Make a copy so the calling program can own it */
            *errmsg = LIBSSH2_ALLOC(session, msglen + 1);
            if(*errmsg) {
                memcpy(*errmsg, error, msglen);
                (*errmsg)[msglen] = 0;
            }
        }
        else
            *errmsg = (char *)LIBSSH2_UNCONST(error);
    }

    if(errmsg_len) {
        *errmsg_len = (int)msglen;
    }

    return session->err_code;
}

LIBSSH2_API int
libssh2_session_last_errno(LIBSSH2_SESSION * session)
{
    return session->err_code;
}

static
LIBSSH2_ALLOC_FUNC(libssh2_default_alloc)
{
    (void)abstract;
    return malloc(count);
}

static
LIBSSH2_FREE_FUNC(libssh2_default_free)
{
    (void)abstract;
    free(ptr);
}

static
LIBSSH2_REALLOC_FUNC(libssh2_default_realloc)
{
    (void)abstract;
    return realloc(ptr, count);
}

/* OLIBSSH: retained from userauth.c as a query of reactor-owned state. */
LIBSSH2_API int
libssh2_userauth_authenticated(LIBSSH2_SESSION *session)
{
    return (session->state & LIBSSH2_STATE_AUTHENTICATED) != 0;
}
