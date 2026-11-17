#include "../OuterSSH/HTTPProxyRewriter.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t realloc_failure_countdown;
static void *test_realloc(void *bytes, size_t size)
{
    if (realloc_failure_countdown && --realloc_failure_countdown == 0) return NULL;
    return realloc(bytes, size);
}
#define realloc test_realloc
#include "../OuterSSH/HTTPProxyRewriter.c"
#undef realloc

typedef struct { char *data; size_t size; } Output;
static void output_body(void *context, const void *bytes, size_t length)
{
    Output *out = context;
    char *replacement = realloc(out->data, out->size + length + 1);
    assert(replacement != NULL);
    out->data = replacement;
    if (length) memcpy(out->data + out->size, bytes, length);
    out->size += length;
    out->data[out->size] = '\0';
}
static bool output_header(void *context, const char *name, const char *value)
{
    output_body(context, name, strlen(name));
    output_body(context, "=", 1);
    output_body(context, value, strlen(value));
    output_body(context, "\n", 1);
    return true;
}
static bool reject_header(void *context, const char *name, const char *value)
{
    (void)context; (void)name; (void)value;
    return false;
}
static HTTPProxyRewriter *create_route_rewriter(const char *request_host, const char *connect_host, uint16_t port,
    bool authorities, bool html)
{
    ProxyConnectionRoute route = {
        .kind = PROXY_CONNECTION_ROUTE_TCP,
        .request = {.host_length = strlen(request_host), .port = port},
        .tcp = {.host_length = strlen(connect_host), .port = port}
    };
    memcpy(route.request.host, request_host, strlen(request_host) + 1);
    memcpy(route.tcp.host, connect_host, strlen(connect_host) + 1);
    HTTPProxyRewriter *rewriter = outersshpriv_http_proxy_rewriter_create(&route, authorities, html);
    assert(rewriter != NULL);
    return rewriter;
}
static HTTPProxyRewriter *create_rewriter(void)
{
    return create_route_rewriter("localhost.tcp.outerssh.localhost", "localhost", 8080, true, true);
}
static void begin_body(HTTPProxyRewriter *rewriter, const char *type, const char *encoding, bool has_body)
{
    HTTPProxyHeader headers[] = {{"Content-Type", type}, {"Content-Encoding", encoding}};
    Output out = {0};
    assert(outersshpriv_http_proxy_rewrite_response_headers(rewriter, headers, 2, has_body, output_header, &out));
    free(out.data);
}
static void expect_request_header(HTTPProxyRewriter *rewriter, const char *name, const char *value,
    const char *expected)
{
    HTTPProxyHeader field = {name, value};
    Output out = {0};
    char line[512];
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, &field, 1, output_header, &out));
    snprintf(line, sizeof(line), "%s=%s\n", name, expected);
    assert(strcmp(out.data, line) == 0);
    free(out.data);
}
static void expect_response_header(HTTPProxyRewriter *rewriter, const char *name, const char *value,
    const char *expected)
{
    HTTPProxyHeader field = {name, value};
    Output out = {0};
    char line[512];
    assert(outersshpriv_http_proxy_rewrite_response_headers(rewriter, &field, 1, false, output_header, &out));
    snprintf(line, sizeof(line), "%s=%s\n", name, expected);
    assert(strcmp(out.data, line) == 0);
    free(out.data);
}
static void test_tcp_host_encoding(void)
{
    const char *cases[][2] = {
        {"localhost", "localhost.tcp.outerssh.localhost"}, {"LocalHost", "localhost.tcp.outerssh.localhost"},
        {"127.0.0.1", "127.0.0.1.tcp.outerssh.localhost"}, {"127.1.2.250", "127.1.2.250.tcp.outerssh.localhost"},
        {"[::1]", "ip6-localhost.tcp.outerssh.localhost"}, {"::1", "ip6-localhost.tcp.outerssh.localhost"},
        {"[0:0:0:0:0:0:0:1]", "ip6-localhost.tcp.outerssh.localhost"}
    };
    char host[OUTERSSH_PROXY_TCP_HOST_CAPACITY];
    size_t length;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert(outerssh_proxy_encode_tcp_host(cases[i][0], strlen(cases[i][0]), host, sizeof(host), &length));
        assert(length == strlen(cases[i][1]) && strcmp(host, cases[i][1]) == 0);
    }
    const char *not_loopback[] = {"127.0.0", "127.0.0.256", "127.0.0.01", "128.0.0.1", "localhost.", "example.com",
        "[::2]", ""};
    for (size_t i = 0; i < sizeof(not_loopback) / sizeof(not_loopback[0]); i++) {
        assert(!outerssh_proxy_encode_tcp_host(not_loopback[i], strlen(not_loopback[i]), host, sizeof(host), &length));
        assert(length == 0 && host[0] == 0);
    }
    assert(!outerssh_proxy_encode_tcp_host("localhost", 9, host, 32, &length));
    const char *decoded[][2] = {
        {"localhost.tcp.outerssh.localhost", "localhost"}, {"LOCALHOST.TCP.OUTERSSH.LOCALHOST.", "localhost"},
        {"127.0.0.1.tcp.outerssh.localhost", "127.0.0.1"}, {"127.9.8.7.tcp.outerssh.localhost", "127.9.8.7"},
        {"ip6-localhost.tcp.outerssh.localhost", "[::1]"}
    };
    for (size_t i = 0; i < sizeof(decoded) / sizeof(decoded[0]); i++) {
        assert(outerssh_proxy_decode_tcp_host(decoded[i][0], strlen(decoded[i][0]), host, sizeof(host), &length));
        assert(length == strlen(decoded[i][1]) && strcmp(host, decoded[i][1]) == 0);
        assert(outersshpriv_proxy_is_tcp_host(decoded[i][0], strlen(decoded[i][0])));
    }
    const char *invalid[] = {"tcp.outerssh.localhost", ".tcp.outerssh.localhost", "example.tcp.outerssh.localhost",
        "127.0.0.01.tcp.outerssh.localhost", "x.localhost.tcp.outerssh.localhost", "localhost.outerssh.localhost",
        "localhost.tcp.outerssh.localhost.example", "localhost.tcp.outerssh.localhost.."};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        assert(!outerssh_proxy_decode_tcp_host(invalid[i], strlen(invalid[i]), host, sizeof(host), &length));
        assert(!outersshpriv_proxy_is_tcp_host(invalid[i], strlen(invalid[i])));
    }
}
static void test_headers(void)
{
    HTTPProxyRewriter *rewriter = create_rewriter();
    HTTPProxyHeader headers[] = {
        {"Host", "localhost.tcp.outerssh.localhost:8080"}, {"Origin", "http://localhost.tcp.outerssh.localhost:8080"},
        {"Referer", "https://127.0.0.1.tcp.outerssh.localhost:3000/path"},
        {"Sec-WebSocket-Origin", "ws://ip6-localhost.tcp.outerssh.localhost:8080/path"},
        {"X-Outer-Loop-User", "forged"}, {"x-outer-loop-user", "also-forged"}, {"Other", "preserved"}
    };
    Output out = {0};
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, headers, 7, output_header, &out));
    assert(strcmp(out.data, "Host=localhost:8080\nOrigin=http://localhost:8080\n"
        "Referer=https://127.0.0.1:3000/path\nSec-WebSocket-Origin=ws://[::1]:8080/path\n"
        "X-Outer-Loop-User=forged\nx-outer-loop-user=also-forged\nOther=preserved\n") == 0);
    free(out.data);
    const char *unrelated[] = {
        "http://localhost.tcp.outerssh.localhost.example.com/path",
        "http://8080.localhost.tcp.outerssh.localhost@other.example/path",
        "http://evil.example@localhost.tcp.outerssh.localhost:8080/",
        "http://localhost.outerssh.localhost:8080",
        "null"
    };
    for (size_t i = 0; i < sizeof(unrelated) / sizeof(unrelated[0]); i++) {
        expect_request_header(rewriter, "Referer", unrelated[i], unrelated[i]);
    }
    expect_request_header(rewriter, "Origin", "http://LOCALHOST.TCP.OUTERSSH.LOCALHOST.:3000",
        "http://localhost:3000");
    expect_request_header(rewriter, "Origin", "http://127.0.0.1.tcp.outerssh.localhost", "http://127.0.0.1");
    expect_request_header(rewriter, "Host", "anything", "localhost:8080");
    assert(!outersshpriv_http_proxy_rewrite_request_headers(rewriter, headers, 7, reject_header, NULL));
    outersshpriv_http_proxy_rewriter_destroy(rewriter);

    rewriter = create_route_rewriter("ip6-localhost.tcp.outerssh.localhost", "::1", 3000, true, false);
    expect_request_header(rewriter, "Host", "ip6-localhost.tcp.outerssh.localhost:3000", "[::1]:3000");
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
    rewriter = create_route_rewriter("127.0.0.2.tcp.outerssh.localhost", "127.0.0.2", 80, true, false);
    expect_request_header(rewriter, "Host", "127.0.0.2.tcp.outerssh.localhost", "127.0.0.2:80");
    outersshpriv_http_proxy_rewriter_destroy(rewriter);

    rewriter = create_route_rewriter("host", "host", 80, true, true);
    out = (Output){0};
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, headers, 7, output_header, &out));
    assert(strstr(out.data, "Host=localhost.tcp.outerssh.localhost:8080\n"));
    assert(strstr(out.data, "Origin=http://localhost.tcp.outerssh.localhost:8080\n"));
    free(out.data);
    expect_response_header(rewriter, "Location", "http://localhost:3000/", "http://localhost:3000/");
    outersshpriv_http_proxy_rewriter_destroy(rewriter);

    rewriter = create_route_rewriter("localhost.tcp.outerssh.localhost", "localhost", 8080, false, true);
    expect_request_header(rewriter, "Host", "localhost.tcp.outerssh.localhost:8080",
        "localhost.tcp.outerssh.localhost:8080");
    expect_response_header(rewriter, "Location", "http://localhost:8080/", "http://localhost:8080/");
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
}
static void test_response_headers(void)
{
    HTTPProxyRewriter *rewriter = create_rewriter();
    const char *cases[][3] = {
        {"Location", "http://localhost:8080/login?next=/", "http://localhost.tcp.outerssh.localhost:8080/login?next=/"},
        {"Location", "http://127.0.0.1:3000", "http://127.0.0.1.tcp.outerssh.localhost:3000"},
        {"location", "ws://[::1]:9000/socket", "ws://ip6-localhost.tcp.outerssh.localhost:9000/socket"},
        {"Location", "http://LOCALHOST/", "http://localhost.tcp.outerssh.localhost/"},
        {"Location", "/relative", "/relative"},
        {"Location", "https://localhost:8443/", "https://localhost:8443/"},
        {"Location", "http://localhost.example:8080/", "http://localhost.example:8080/"},
        {"Location", "http://127.0.0.01:8080/", "http://127.0.0.01:8080/"},
        {"Location", "http://example.com/?to=http://localhost:8080/", "http://example.com/?to=http://localhost:8080/"},
        {"Access-Control-Allow-Origin", "http://localhost:8080", "http://localhost.tcp.outerssh.localhost:8080"},
        {"Access-Control-Allow-Origin", "http://127.0.0.1:3000", "http://127.0.0.1.tcp.outerssh.localhost:3000"},
        {"Access-Control-Allow-Origin", "*", "*"},
        {"Access-Control-Allow-Origin", "null", "null"},
        {"Access-Control-Allow-Origin", "http://allowed.example", "http://allowed.example"},
        {"Content-Location", "http://localhost:8080/", "http://localhost:8080/"},
        {"Vary", "Origin", "Origin"}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        expect_response_header(rewriter, cases[i][0], cases[i][1], cases[i][2]);
    }
    HTTPProxyHeader response[] = {{"Location", "http://localhost:8080/"}, {"Content-Type", "text/html"}};
    assert(!outersshpriv_http_proxy_rewrite_response_headers(rewriter, response, 2, true, reject_header, NULL));
    outersshpriv_http_proxy_rewriter_destroy(rewriter);

    static const char host[] = "f4.unix.outerssh.localhost";
    ProxyConnectionRoute route = {.kind = PROXY_CONNECTION_ROUTE_UNIX_SOCKET,
        .request = {.host_length = sizeof(host) - 1, .port = 80}};
    memcpy(route.request.host, host, sizeof(host));
    rewriter = outersshpriv_http_proxy_rewriter_create(&route, true, true);
    assert(rewriter != NULL);
    expect_response_header(rewriter, "Location", "http://localhost:8080/", "http://localhost:8080/");
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
}
static void expect_html_rewrite(const char *input, const char *expected)
{
    HTTPProxyRewriter *rewriter = create_rewriter();
    begin_body(rewriter, "text/html", "", true);
    Output out = {0};
    outersshpriv_http_proxy_rewrite_body(rewriter, input, strlen(input), output_body, &out);
    outersshpriv_http_proxy_rewrite_body_finish(rewriter, output_body, &out);
    assert(out.size == strlen(expected) && memcmp(out.data, expected, out.size) == 0);
    free(out.data);
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
}
static void test_html_url_forms(void)
{
    const char *cases[][2] = {
        {"<img src=\"//localhost:3000/a.png\">", "<img src=\"//localhost.tcp.outerssh.localhost:3000/a.png\">"},
        {"<a href='//127.0.0.1:8080/'>", "<a href='//127.0.0.1.tcp.outerssh.localhost:8080/'>"},
        {"<a href=//[::1]:9000/>", "<a href=//ip6-localhost.tcp.outerssh.localhost:9000/>"},
        {"background: url(//localhost:3000/bg.png)", "background: url(//localhost.tcp.outerssh.localhost:3000/bg.png)"},
        {"srcset=\"/a.png 1x,\n//localhost:3000/b.png 2x\"", "srcset=\"/a.png 1x,\n//localhost.tcp.outerssh.localhost:3000/b.png 2x\""},
        {"//localhost:3000/", "//localhost.tcp.outerssh.localhost:3000/"},
        {"HTTP://LOCALHOST:3000/", "HTTP://localhost.tcp.outerssh.localhost:3000/"},
        {"x = 1;//localhost:3000 comment", "x = 1;//localhost:3000 comment"},
        {"https://localhost:3000/", "https://localhost:3000/"},
        {"wss://localhost:3000/", "wss://localhost:3000/"},
        {"src=\"//localhost/a.png\"", "src=\"//localhost/a.png\""},
        {"src=\"//example.com:3000/\"", "src=\"//example.com:3000/\""},
        {"src=\"//localhost.example.com:3000/\"", "src=\"//localhost.example.com:3000/\""},
        {"src=\"///localhost:3000/\"", "src=\"///localhost:3000/\""},
        {"src=\"http:\\/\\/localhost:3000\"", "src=\"http:\\/\\/localhost:3000\""},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        expect_html_rewrite(cases[i][0], cases[i][1]);
    }
    static const char nul_before[] = "\0//localhost:3000/";
    HTTPProxyRewriter *rewriter = create_rewriter();
    begin_body(rewriter, "text/html", "", true);
    Output out = {0};
    outersshpriv_http_proxy_rewrite_body(rewriter, nul_before, sizeof(nul_before) - 1, output_body, &out);
    outersshpriv_http_proxy_rewrite_body_finish(rewriter, output_body, &out);
    assert(out.size == sizeof(nul_before) - 1 && memcmp(out.data, nul_before, out.size) == 0);
    free(out.data);
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
}
static void test_body(void)
{
    const char input[] = "<a href='http://localhost:3000/x'>x</a><script>ws://[::1]:8080/</script>";
    const char expected[] = "<a href='http://localhost.tcp.outerssh.localhost:3000/x'>x</a><script>ws://ip6-localhost.tcp.outerssh.localhost:8080/</script>";
    HTTPProxyRewriter *rewriter = create_rewriter();
    begin_body(rewriter, "text/html; charset=utf-8", "identity", true);
    Output out = {0};
    for (size_t i = 0; i < sizeof(input) - 1; i++) outersshpriv_http_proxy_rewrite_body(rewriter, input + i, 1, output_body, &out);
    assert(out.size == 0);
    outersshpriv_http_proxy_rewrite_body_finish(rewriter, output_body, &out);
    assert(strcmp(out.data, expected) == 0);
    outersshpriv_http_proxy_rewrite_body_finish(rewriter, output_body, &out);
    assert(out.size == sizeof(expected) - 1);
    free(out.data); outersshpriv_http_proxy_rewriter_destroy(rewriter);
    for (unsigned variant = 0; variant < 4; variant++) {
        rewriter = create_rewriter(); out = (Output){0};
        begin_body(rewriter, variant == 0 ? "application/octet-stream" : "text/html",
            variant == 1 ? "gzip" : variant == 2 ? "br" : "", variant != 3);
        outersshpriv_http_proxy_rewrite_body(rewriter, input, sizeof(input), output_body, &out);
        assert(out.size == sizeof(input) && memcmp(out.data, input, sizeof(input)) == 0);
        outersshpriv_http_proxy_rewrite_body_finish(rewriter, output_body, &out);
        assert(out.size == sizeof(input));
        free(out.data); outersshpriv_http_proxy_rewriter_destroy(rewriter);
    }
}
static void test_independent_options(void)
{
    static const char host[] = "f4.unix.outerssh.localhost";
    ProxyConnectionRoute route = {.kind = PROXY_CONNECTION_ROUTE_UNIX_SOCKET,
        .request = {.host_length = sizeof(host) - 1, .port = 80}};
    memcpy(route.request.host, host, sizeof(host));
    for (unsigned options = 0; options < 4; options++) {
        bool authorities = (options & 1) != 0, html = (options & 2) != 0;
        HTTPProxyRewriter *rewriter = outersshpriv_http_proxy_rewriter_create(&route, authorities, html);
        assert(rewriter != NULL);
        Output out = {0};
        HTTPProxyHeader fields[] = {{"Host", host}, {"Origin", "http://f4.unix.outerssh.localhost"}};
        assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, fields, 2, output_header, &out));
        assert(strcmp(out.data, "Host=f4.unix.outerssh.localhost\nOrigin=http://f4.unix.outerssh.localhost\n") == 0);
        free(out.data); out = (Output){0};
        begin_body(rewriter, "text/html", "identity", true);
        static const char body[] = "<a href='http://localhost:9000/'>app</a>";
        for (size_t i = 0; i < sizeof(body) - 1; i++) {
            outersshpriv_http_proxy_rewrite_body(rewriter, body + i, 1, output_body, &out);
            assert(out.size == (html ? 0 : i + 1));
            if (!html) assert(rewriter->body.bytes == NULL);
        }
        outersshpriv_http_proxy_rewrite_body_finish(rewriter, output_body, &out);
        assert(strcmp(out.data, html ? "<a href='http://localhost.tcp.outerssh.localhost:9000/'>app</a>" : body) == 0);
        free(out.data);
        outersshpriv_http_proxy_rewriter_destroy(rewriter);
    }
}
static void test_html_requests_are_uncompressed(void)
{
    HTTPProxyRewriter *rewriter = create_rewriter();
    HTTPProxyHeader page[] = {{"Accept-Encoding", "gzip, br"}, {"Accept", "text/html,application/xhtml+xml"}};
    Output out = {0};
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, page, 2, output_header, &out));
    assert(strcmp(out.data, "Accept=text/html,application/xhtml+xml\nAccept-Encoding=identity\n") == 0);
    free(out.data); out = (Output){0};
    HTTPProxyHeader repeated[] = {{"accept-encoding", "gzip"}, {"Accept", "TEXT/HTML"}, {"Accept-Encoding", "br"}};
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, repeated, 3, output_header, &out));
    assert(strcmp(out.data, "Accept=TEXT/HTML\nAccept-Encoding=identity\n") == 0);
    free(out.data); out = (Output){0};
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, page + 1, 1, output_header, &out));
    assert(strcmp(out.data, "Accept=text/html,application/xhtml+xml\nAccept-Encoding=identity\n") == 0);
    free(out.data); out = (Output){0};
    assert(!outersshpriv_http_proxy_rewrite_request_headers(rewriter, page + 1, 1, reject_header, NULL));
    HTTPProxyHeader script[] = {{"Accept", "*/*"}, {"Accept-Encoding", "gzip"}};
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, script, 2, output_header, &out));
    assert(strcmp(out.data, "Accept=*/*\nAccept-Encoding=gzip\n") == 0);
    free(out.data); out = (Output){0};
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
    rewriter = create_route_rewriter("localhost.tcp.outerssh.localhost", "localhost", 8080, true, false);
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, page, 2, output_header, &out));
    assert(strcmp(out.data, "Accept-Encoding=gzip, br\nAccept=text/html,application/xhtml+xml\n") == 0);
    free(out.data);
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
}
static void test_socket_headers_pass_through(void)
{
    ProxyConnectionRoute route = {.kind = PROXY_CONNECTION_ROUTE_UNIX_SOCKET,
        .request = {.host = "f4.unix.outerssh.localhost", .host_length = sizeof("f4.unix.outerssh.localhost") - 1, .port = 80}};
    HTTPProxyHeader request[] = {{"Host", "f4.unix.outerssh.localhost"}, {"X-Forwarded-Host", "page.example"},
        {"Origin", "http://f4.unix.outerssh.localhost"}, {"Referer", "http://f4.unix.outerssh.localhost/lab"}};
    HTTPProxyHeader response[] = {{"Location", "http://localhost/auth-sign-in?appUri=%2F"},
        {"Access-Control-Allow-Origin", "http://f4.unix.outerssh.localhost"}};
    HTTPProxyRewriter *rewriter = outersshpriv_http_proxy_rewriter_create(&route, true, true);
    assert(rewriter != NULL);
    Output out = {0};
    assert(outersshpriv_http_proxy_rewrite_request_headers(rewriter, request, 4, output_header, &out));
    assert(strcmp(out.data, "Host=f4.unix.outerssh.localhost\nX-Forwarded-Host=page.example\n"
        "Origin=http://f4.unix.outerssh.localhost\nReferer=http://f4.unix.outerssh.localhost/lab\n") == 0);
    free(out.data); out = (Output){0};
    assert(outersshpriv_http_proxy_rewrite_response_headers(rewriter, response, 2, false, output_header, &out));
    assert(strcmp(out.data, "Location=http://localhost/auth-sign-in?appUri=%2F\n"
        "Access-Control-Allow-Origin=http://f4.unix.outerssh.localhost\n") == 0);
    free(out.data);
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
}
static void test_limits_and_allocation_failure(void)
{
    size_t length = 2 * 1024 * 1024 + 1;
    char *large = malloc(length); assert(large != NULL);
    memset(large, 'x', length); memcpy(large, "http://localhost:3000/", 22);
    for (unsigned fragmented = 0; fragmented < 2; fragmented++) {
        HTTPProxyRewriter *rewriter = create_rewriter(); Output out = {0};
        begin_body(rewriter, "text/html", "", true);
        size_t prefix = fragmented ? 100 : 0;
        outersshpriv_http_proxy_rewrite_body(rewriter, large, prefix, output_body, &out);
        outersshpriv_http_proxy_rewrite_body(rewriter, large + prefix, length - prefix, output_body, &out);
        outersshpriv_http_proxy_rewrite_body_finish(rewriter, output_body, &out);
        assert(out.size == length && memcmp(out.data, large, length) == 0);
        free(out.data); outersshpriv_http_proxy_rewriter_destroy(rewriter);
    }
    free(large);
    for (unsigned allocation = 0; allocation < 3; allocation++) {
        HTTPProxyRewriter *rewriter = create_rewriter(); Output out = {0};
        begin_body(rewriter, "text/html", "", true);
        char input[600]; memset(input, 'x', sizeof(input)); memcpy(input, "http://localhost:3000/", 22);
        if (allocation == 0) realloc_failure_countdown = 1;
        outersshpriv_http_proxy_rewrite_body(rewriter, input, 100, output_body, &out);
        if (allocation == 1) realloc_failure_countdown = 1;
        outersshpriv_http_proxy_rewrite_body(rewriter, input + 100, 500, output_body, &out);
        if (allocation == 2) realloc_failure_countdown = 1;
        outersshpriv_http_proxy_rewrite_body_finish(rewriter, output_body, &out);
        assert(realloc_failure_countdown == 0);
        assert(out.size == sizeof(input) && memcmp(out.data, input, sizeof(input)) == 0);
        free(out.data); outersshpriv_http_proxy_rewriter_destroy(rewriter);
    }
}
static void test_context(void)
{
    char authority[64];
    assert(outersshpriv_http_proxy_format_authority("::1", 3, 443, authority, sizeof(authority), NULL));
    assert(strcmp(authority, "[::1]:443") == 0);
    ProxyConnectionRoute route = {.kind = PROXY_CONNECTION_ROUTE_REJECTED};
    assert(outersshpriv_http_proxy_rewriter_create(&route, true, true) == NULL);
    route = (ProxyConnectionRoute){.kind = PROXY_CONNECTION_ROUTE_TCP,
        .request = {.host = "localhost.tcp.outerssh.localhost", .host_length = 32, .port = 80},
        .tcp = {.host = "bad\r\n", .host_length = 5, .port = 80}};
    assert(outersshpriv_http_proxy_rewriter_create(&route, true, true) == NULL);
    route.tcp.host_length = sizeof(route.tcp.host);
    assert(outersshpriv_http_proxy_rewriter_create(&route, true, true) == NULL);
    memcpy(route.tcp.host, "localhost", 9); route.tcp.host_length = 9;
    HTTPProxyRewriter *rewriter = outersshpriv_http_proxy_rewriter_create(&route, true, true);
    assert(rewriter != NULL); memset(&route, 'x', sizeof(route));
    expect_request_header(rewriter, "Host", "host", "localhost:80");
    outersshpriv_http_proxy_rewriter_destroy(rewriter);
}
int main(void)
{
    test_socket_headers_pass_through(); test_html_requests_are_uncompressed(); test_context(); test_tcp_host_encoding(); test_headers(); test_response_headers(); test_body(); test_html_url_forms(); test_independent_options(); test_limits_and_allocation_failure();
    puts("PASS: parsed header rewriting, body boundaries, eligibility, limits, and allocation failures");
    return 0;
}
