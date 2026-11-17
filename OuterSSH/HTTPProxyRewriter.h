#ifndef HTTP_PROXY_REWRITER_H
#define HTTP_PROXY_REWRITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct HTTPProxyRewriter HTTPProxyRewriter;
typedef struct { const char *name, *value; } HTTPProxyHeader;
typedef bool (*HTTPProxyHeaderOutput)(void *context, const char *name, const char *value);
typedef void (*HTTPProxyBodyOutput)(void *context, const void *bytes, size_t length);

bool outersshpriv_http_proxy_format_authority(const char *host, size_t host_length, uint16_t port,
    char *authority, size_t capacity, size_t *length);

struct ProxyConnectionRoute;
/* One rewriter per exchange, configured from a resolved route. The route is
 * borrowed during creation; header inputs and callback arguments are borrowed. */
HTTPProxyRewriter *outersshpriv_http_proxy_rewriter_create(const struct ProxyConnectionRoute *route,
    bool rewrite_request_authorities, bool rewrite_loopback_urls_in_html);
void outersshpriv_http_proxy_rewriter_destroy(HTTPProxyRewriter *rewriter);

bool outersshpriv_http_proxy_rewrite_request_headers(HTTPProxyRewriter *rewriter,
    const HTTPProxyHeader *headers, size_t count, HTTPProxyHeaderOutput output, void *context);
bool outersshpriv_http_proxy_rewrite_response_headers(HTTPProxyRewriter *rewriter,
    const HTTPProxyHeader *headers, size_t count, bool has_body,
    HTTPProxyHeaderOutput output, void *context);

/* Input is decoded body data. Framing and message completion belong to the caller. */
void outersshpriv_http_proxy_rewrite_body(HTTPProxyRewriter *rewriter, const void *bytes, size_t length,
    HTTPProxyBodyOutput output, void *context);
void outersshpriv_http_proxy_rewrite_body_finish(HTTPProxyRewriter *rewriter,
    HTTPProxyBodyOutput output, void *context);

#endif
