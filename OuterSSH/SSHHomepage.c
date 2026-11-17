#include "SSHEventsInternal.h"
#include "SSHProxyErrorInternal.h"
#include <stdlib.h>
#include <string.h>

/* Reads the user homepage file, then the system one if the user file is absent
 * or empty, on one session. */
typedef struct {
    OuterSSHSessionPool *pool;
    SSHPoolEvent *reply;
    SSHWaiter waiter;
    bool system;
} HomepageRequest;

static const char *homepage_command(bool windows, bool system)
{
    if (windows) {
        return system
            ? "powershell.exe -NoProfile -NonInteractive -Command \"$ErrorActionPreference='Stop'; $p=Join-Path $env:ProgramData 'OuterSSH/homepage'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::WriteLine($p); try { if (Test-Path -LiteralPath $p) { $f=[IO.File]::OpenRead($p); try { $b=New-Object byte[] 8193; $n=0; while ($n -lt $b.Length) { $r=$f.Read($b,$n,$b.Length-$n); if ($r -eq 0) { break }; $n+=$r }; [Console]::OpenStandardOutput().Write($b,0,$n) } finally { $f.Dispose() } } } catch { [Console]::Error.WriteLine($_); exit 1 }\""
            : "powershell.exe -NoProfile -NonInteractive -Command \"$ErrorActionPreference='Stop'; $p=Join-Path $env:LOCALAPPDATA 'OuterSSH/homepage'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::WriteLine($p); try { if (Test-Path -LiteralPath $p) { $f=[IO.File]::OpenRead($p); try { $b=New-Object byte[] 8193; $n=0; while ($n -lt $b.Length) { $r=$f.Read($b,$n,$b.Length-$n); if ($r -eq 0) { break }; $n+=$r }; [Console]::OpenStandardOutput().Write($b,0,$n) } finally { $f.Dispose() } } } catch { [Console]::Error.WriteLine($_); exit 1 }\"";
    }
    return system
        ? "case $(uname -s) in Darwin) p='/Library/Application Support/org.outerssh/homepage';; *) p=/etc/outerssh/homepage;; esac; printf '%s\\n' \"$p\"; if [ -e \"$p\" ] || [ -L \"$p\" ]; then [ -f \"$p\" ] && head -c 8193 \"$p\" || exit 1; fi"
        : "case $(uname -s) in Darwin) p=\"$HOME/Library/Application Support/org.outerssh/homepage\";; *) case \"$XDG_CONFIG_HOME\" in /*) p=\"$XDG_CONFIG_HOME/outerssh/homepage\";; *) p=\"$HOME/.config/outerssh/homepage\";; esac;; esac; printf '%s\\n' \"$p\"; if [ -e \"$p\" ] || [ -L \"$p\" ]; then [ -f \"$p\" ] && head -c 8193 \"$p\" || exit 1; fi";
}

static void read_homepage(HomepageRequest *request);

static void finish_homepage(HomepageRequest *request, bool found, const char *url, size_t url_length,
    const char *source_path, size_t source_path_length, OuterSSHError error)
{
    OuterSSHSessionPool *pool = request->pool;
    outersshpriv_reply_homepage(request->reply, found, url, url_length, source_path, source_path_length, error);
    free(request);
    outersshpriv_session_pool_end_operation(pool);
}

static bool homepage_whitespace(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void homepage_received(void *context, const SSHCommandOutput *result, OuterSSHError error)
{
    HomepageRequest *request = context;
    if (error.domain != OUTERSSH_ERROR_NONE) {
        finish_homepage(request, false, NULL, 0, NULL, 0, error);
        return;
    }
    const char *bytes = result ? result->stdout_bytes : NULL;
    const char *separator = bytes ? memchr(bytes, '\n', result->stdout_byte_count) : NULL;
    struct {
        const char *url;
        size_t url_length;
        const char *source_path;
        size_t source_path_length;
    } homepage = {0};
    if (separator) {
        homepage.source_path = bytes;
        homepage.source_path_length = (size_t)(separator - bytes);
        if (homepage.source_path_length && bytes[homepage.source_path_length - 1] == '\r')
            --homepage.source_path_length;
        homepage.url = separator + 1;
        homepage.url_length = result->stdout_byte_count - (size_t)(homepage.url - bytes);
    }
    const char *failure = NULL;
    if (!result || !separator) failure = "Invalid response while reading the server homepage.";
    else if (result->exit_status != 0) failure = "Could not read the server homepage configuration.";
    else if (homepage.url_length > 8192) failure = "The server homepage configuration exceeds 8192 bytes.";
    if (!failure) {
        while (homepage.url_length && homepage_whitespace((unsigned char)*homepage.url)) {
            ++homepage.url;
            --homepage.url_length;
        }
        while (homepage.url_length && homepage_whitespace((unsigned char)homepage.url[homepage.url_length - 1]))
            --homepage.url_length;
        for (size_t i = 0; i < homepage.url_length; ++i) {
            if ((unsigned char)homepage.url[i] <= 32 || (unsigned char)homepage.url[i] == 127) {
                failure = "The server homepage must contain a single URL without whitespace or control characters.";
                break;
            }
        }
    }
    if (failure) {
        char *storage = NULL;
        error = outersshpriv_error_format(&storage,
            outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_INVALID_CONFIGURATION, NULL, 0, 0),
            "%s %.*s%s", failure, (int)homepage.source_path_length,
            homepage.source_path ? homepage.source_path : "", homepage.source_path ? " (homepage file)" : "");
        finish_homepage(request, false, NULL, 0, NULL, 0, error);
        free(storage);
    } else if (!homepage.url_length && !request->system) {
        request->system = true;
        read_homepage(request);
    } else {
        finish_homepage(request, homepage.url_length != 0, homepage.url, homepage.url_length,
            homepage.source_path, homepage.source_path_length, (OuterSSHError){0});
    }
}

static void read_homepage(HomepageRequest *request)
{
    const char *command = homepage_command(outerssh_session_pool_command_dialect(request->pool) == OUTERSSH_COMMAND_DIALECT_WINDOWS, request->system);
    outersshpriv_execute_command(request->pool, (SSHCommandRequest){.command = command, .command_byte_count = strlen(command)}, homepage_received, request);
}

static void homepage_session_ready(void *context, OuterSSHError error)
{
    HomepageRequest *request = context;
    SSHSessionPoolSessionHandle session;
    outersshpriv_session_pool_ready_reactor(request->pool, &session, &error);
    if (error.domain != OUTERSSH_ERROR_NONE) {
        finish_homepage(request, false, NULL, 0, NULL, 0, error);
        return;
    }
    read_homepage(request);
}

static void start_homepage(void *context)
{
    HomepageRequest *request = context;
    outersshpriv_session_pool_begin_operation(request->pool);
    if (request->pool->shutdown_requested) {
        finish_homepage(request, false, NULL, 0, NULL, 0, outerssh_proxy_closing_error());
        return;
    }
    outersshpriv_session_pool_run_when_ready(request->pool, &request->waiter, homepage_session_ready, request);
}

bool outerssh_session_pool_get_homepage(OuterSSHSessionPool *pool, uint64_t tag)
{
    HomepageRequest *request = malloc(sizeof(*request));
    SSHPoolEvent *reply = request == NULL ? NULL
        : outersshpriv_reply_reserve(pool, OUTERSSH_EVENT_HOMEPAGE_RECEIVED, tag);
    if (reply == NULL) {
        free(request);
        return false;
    }
    *request = (HomepageRequest){.pool = pool, .reply = reply};
    otqueue_async(pool->_queue, request, start_homepage);
    return true;
}
