#include "SSHTestSupport.h"
#include <OuterSSH/OuterSSH.h>

#include <assert.h>
#include "platform/OTQueue.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static atomic_uint initialization_count;
static int initialization_result;
static ssh_test_semaphore_t completed;

int libssh2_init(int flags)
{
    assert(flags == 0);
    atomic_fetch_add(&initialization_count, 1);
    return initialization_result;
}

static void initialize(void *context)
{
    (void)context;
    OuterSSHError error = {.domain = OUTERSSH_ERROR_PROXY};
    bool succeeded = outerssh_initialize(&error);
    assert(succeeded == (initialization_result == 0));
    assert(error.ssh_error_code == initialization_result);
    if (succeeded) {
        assert(error.domain == OUTERSSH_ERROR_NONE);
    } else {
        assert(error.domain == OUTERSSH_ERROR_SESSION);
        assert(error.code == OUTERSSH_SESSION_ERROR_INITIALIZATION_FAILED);
        assert(strstr(error.message, "-1") != NULL);
    }
    ssh_test_semaphore_signal(completed);
}

int main(int argc, const char *argv[])
{
    (void)argv;
    initialization_result = argc > 1 ? -1 : 0;
    completed = ssh_test_semaphore_create(0);
    assert(completed);
    for (unsigned i = 0; i < 128; i++) ssh_test_thread_start(initialize, NULL);
    for (unsigned i = 0; i < 128; i++)
        assert(ssh_test_semaphore_wait(completed, 10 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(completed);
    assert(atomic_load(&initialization_count) == 1);
    assert(outerssh_initialize(NULL) == (initialization_result == 0));
    assert(atomic_load(&initialization_count) == 1);
    puts("PASS: concurrent initialization and persistent initialization result");
    return 0;
}
