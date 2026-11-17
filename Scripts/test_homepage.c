#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../OuterSSH/platform/OTQueue.h"

static void run_immediately(otqueue_t queue, void *context, void (*function)(void *))
{
    (void)queue;
    function(context);
}
#undef otqueue_async
#define otqueue_async run_immediately
#include "../OuterSSH/SSHHomepage.c"
#undef otqueue_async

static const char *fixture_paths[2];
static int fixture_status[2];
static int reads;
static bool fail_authentication;
static bool completed;

void outersshpriv_session_pool_run_when_ready(OuterSSHSessionPool *pool, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context)
{
    (void)pool; (void)waiter;
    resume(context, fail_authentication ? outerssh_proxy_closing_error() : (OuterSSHError){0});
}

SSHReactor *outersshpriv_session_pool_ready_reactor(OuterSSHSessionPool *pool,
    SSHSessionPoolSessionHandle *session, OuterSSHError *error)
{
    (void)pool; (void)error;
    *session = (SSHSessionPoolSessionHandle){0};
    return NULL;
}

void outersshpriv_session_pool_begin_operation(OuterSSHSessionPool *pool) { (void)pool; }
void outersshpriv_session_pool_end_operation(OuterSSHSessionPool *pool) { (void)pool; }

static SSHPoolEvent reply;

SSHPoolEvent *outersshpriv_reply_reserve(OuterSSHSessionPool *pool, OuterSSHEventType type, uint64_t tag)
{
    (void)pool;
    assert(type == OUTERSSH_EVENT_HOMEPAGE_RECEIVED && tag == 7);
    return &reply;
}

OuterSSHCommandDialect outerssh_session_pool_command_dialect(OuterSSHSessionPool *pool)
{
    (void)pool;
    return OUTERSSH_COMMAND_DIALECT_POSIX;
}

void outersshpriv_execute_command(OuterSSHSessionPool *pool, SSHCommandRequest request,
    SSHCommandHandler completion, void *context)
{
    (void)pool; (void)request;
    assert(reads < 2);
    int index = reads++;
    FILE *file = fopen(fixture_paths[index], "rb");
    assert(file);
    char bytes[20000];
    size_t length = fread(bytes, 1, sizeof(bytes), file);
    assert(!ferror(file));
    fclose(file);
    SSHCommandOutput result = {.stdout_bytes = bytes, .stdout_byte_count = length,
                                   .exit_status = fixture_status[index]};
    completion(context, &result, (OuterSSHError){0});
}

void outersshpriv_reply_homepage(SSHPoolEvent *sent, bool found, const char *url, size_t url_length,
    const char *source_path, size_t source_path_length, OuterSSHError error)
{
    assert(sent == &reply && !completed);
    completed = true;
    if (error.domain != OUTERSSH_ERROR_NONE)
        printf("ERROR:%.*s\n", (int)error.message_length, error.message);
    else if (found)
        printf("URL:%.*s\nSOURCE:%.*s\n", (int)url_length, url, (int)source_path_length, source_path);
    else puts("DEFAULT");
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "command") == 0) {
        puts(homepage_command(atoi(argv[2]), atoi(argv[3])));
        return 0;
    }
    assert(argc == 6);
    fixture_paths[0] = argv[1]; fixture_paths[1] = argv[2];
    fixture_status[0] = atoi(argv[3]); fixture_status[1] = atoi(argv[4]);
    fail_authentication = atoi(argv[5]);
    OuterSSHSessionPool pool = {0};
    assert(outerssh_session_pool_get_homepage(&pool, 7));
    assert(completed);
    printf("READS:%d\n", reads);
}
