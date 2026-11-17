#include "include/OuterSSH/SOCKSProxyServer.h"
#include "SSHProxyErrorInternal.h"
#include "SSHForwarder.h"
#include "SSHEventsInternal.h"
#include "include/OuterSSH/HTTPProxyServer.h"
#include "ProxyReactorInternal.h"
#include <stdlib.h>
#include <string.h>

struct OuterSSHSOCKSProxyServer {
    SSHForwarder *forwarder;
    OuterSSHHTTPProxyServer *inspection;
};


#pragma mark - Create and Configure the SOCKS Proxy

OuterSSHSOCKSProxyServer *outerssh_socks_proxy_server_create(OuterSSHSessionPool *pool,
    const OuterSSHSOCKSProxyServerConfiguration *configuration, OuterSSHError *error)
{
    if (!configuration || (configuration->authentication != OUTERSSH_PROXY_AUTHENTICATION_PASSWORD &&
        configuration->authentication != OUTERSSH_PROXY_AUTHENTICATION_NONE)) {
        static const char message[] = "Invalid SOCKS authentication mode.";
        if (error != NULL) *error = outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION,
            message, sizeof(message) - 1, 0);
        return NULL;
    }
    OuterSSHSOCKSProxyServer *server = calloc(1, sizeof(*server));
    if (!server) {
        static const char message[] = "Failed to allocate the SOCKS frontend.";
        if (error) {
            *error =
                outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION, message, sizeof(message) - 1, 0);
        }
        return NULL;
    }
    server->inspection = outersshpriv_inspected_socks_create(pool, configuration->credentials,
        configuration->authentication, configuration->rewrite_loopback_addresses, error);
    if (!server->inspection) {
        free(server);
        return NULL;
    }
    server->forwarder = outersshpriv_inspected_socks_forwarder(server->inspection);
    server->forwarder->frontend = server;
    return server;
}

#pragma mark - Start and Stop Listening

static SSHPoolEvent *reserve(OuterSSHSOCKSProxyServer *server, OuterSSHEventType type, uint64_t tag)
{
    return outersshpriv_reply_reserve(server->forwarder->pool, type, tag);
}

bool outerssh_socks_proxy_server_start(OuterSSHSOCKSProxyServer *server, uint16_t port, uint64_t tag)
{
    SSHPoolEvent *reply = reserve(server, OUTERSSH_EVENT_PROXY_STARTED, tag);
    if (reply == NULL) return false;
    outersshpriv_http_proxy_start(server->inspection, port, reply);
    return true;
}

bool outerssh_socks_proxy_server_stop(OuterSSHSOCKSProxyServer *server, uint64_t tag)
{
    SSHPoolEvent *reply = reserve(server, OUTERSSH_EVENT_OPERATION_COMPLETED, tag);
    if (reply == NULL) return false;
    outersshpriv_http_proxy_stop(server->inspection, reply);
    return true;
}

#pragma mark - Identify Content by Its Origin

bool outerssh_socks_proxy_server_add_origin_credentials(OuterSSHSOCKSProxyServer *server,
    const char *username, size_t username_length, const char *password, size_t password_length,
    const char *origin, size_t origin_length, uint64_t tag)
{
    return password != NULL && outersshpriv_forwarder_submit_origin_credentials(server->forwarder,
        username, username_length, password, password_length, origin, origin_length, tag);
}

bool outerssh_socks_proxy_server_remove_origin_credentials(OuterSSHSOCKSProxyServer *server,
    const char *username, size_t username_length, uint64_t tag)
{
    return outersshpriv_forwarder_submit_origin_credentials(server->forwarder, username, username_length,
        NULL, 0, NULL, 0, tag);
}

SSHForwarder *outersshpriv_socks_proxy_server_forwarder(OuterSSHSOCKSProxyServer *server)
{
    return server->forwarder;
}

#pragma mark - Destroy the SOCKS Proxy

/* Nothing refers to the frontend once destruction is submitted, so it is
 * freed here; its HTTP server finishes the teardown. */
bool outerssh_socks_proxy_server_destroy(OuterSSHSOCKSProxyServer *server, uint64_t tag)
{
    SSHPoolEvent *reply = reserve(server, OUTERSSH_EVENT_DESTROYED, tag);
    if (reply == NULL) return false;
    outersshpriv_http_proxy_destroy(server->inspection, reply);
    free(server);
    return true;
}
