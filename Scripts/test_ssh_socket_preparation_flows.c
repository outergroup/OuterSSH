#include "SSHTestSupport.h"
#include "SSHProxyAddress.h"
#include "SSHProxyErrorInternal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "SSHSocketBridgeInternal.h"
#include "SSHSocketService.h"
#include "ProxyReactorInternal.h"
#include "ProxyPendingConnectionsInternal.h"

static OuterSSHSessionPool controller;
static SSHForwarder test_server;
static SSHProxyConnection test_connection;
static ssh_test_semaphore_t finished;
static bool listener_active = true;
static bool immediate_authorization;
static bool cached_authorization;
static bool existing_authorization;
static SocketAuthorization authorization_entry;
static SocketAuthorizationRequest authorization_request;
static unsigned authorization_lookups;
static const char *expected_connection_path = "/run/outer.sock";
static bool fail_bridge_allocation;
static bool bridge_completes_immediately;
static unsigned pending_failures;
static bool entering_public_api;
static unsigned completions;
static unsigned bridge_assignments;
static unsigned user_id_commands;
static OuterSSHError last_error;
static char *last_error_storage;
static SSHWaiter *pending_authorization;
static void *pending_user_id;
static SSHCommandHandler pending_user_id_finished;
typedef struct {
    SSHBridgeRequest request;
    SSHSocketBridgeWaiter *waiter;
} PendingBridge;
static PendingBridge bridge_setup;
static PendingBridge *pending_bridge;

void outersshpriv_session_pool_begin_operation(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    pool->pending_operations++;
}

void outersshpriv_session_pool_end_operation(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
    assert(pool->pending_operations != 0);
    pool->pending_operations--;
}

void outersshpriv_session_pool_finish_destroy_if_ready(OuterSSHSessionPool *pool)
{
    otqueue_assert(pool->_queue);
}


OuterSSHSessionPool *outersshpriv_session_pool_active(
    OuterSSHSessionPool *value)
{
    assert(value == &controller);
    return listener_active && !value->shutdown_requested ? &controller : NULL;
}

SocketAuthorization *outersshpriv_socket_service_find_authorization(OuterSSHSessionPool *pool, const char *path, size_t length)
{
    assert(pool == &controller && length == strlen(expected_connection_path));
    assert(memcmp(path, expected_connection_path, length) == 0);
    authorization_lookups++;
    authorization_entry.pending = cached_authorization ? NULL : &authorization_request;
    return cached_authorization || existing_authorization ? &authorization_entry : NULL;
}

void outersshpriv_socket_service_authorize(OuterSSHSessionPool *pool, const char *path, size_t length,
    SocketAuthorizationRequest *request, SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    assert(pool == &controller && length == strlen(expected_connection_path));
    assert(memcmp(path, expected_connection_path, length) == 0);
    assert(pending_authorization == NULL);
    assert(!cached_authorization && !existing_authorization);
    *request = (SocketAuthorizationRequest){0};
    if (immediate_authorization)
        resume(context, (OuterSSHError){0});
    else {
        *waiter = (SSHWaiter){.resume = resume, .context = context};
        pending_authorization = waiter;
    }
}

void outersshpriv_socket_service_wait_for_authorization(SocketAuthorization *authorization,
    SSHWaiter *waiter, SSHCompletionHandler resume, void *context)
{
    assert(authorization == &authorization_entry && authorization->pending != NULL);
    assert(existing_authorization && pending_authorization == NULL);
    *waiter = (SSHWaiter){.resume = resume, .context = context};
    pending_authorization = waiter;
}

void outersshpriv_execute_command(
    OuterSSHSessionPool *value, SSHCommandRequest request,
    SSHCommandHandler completion, void *context)
{
    assert(request.release_input == NULL && request.release_input_context == NULL);
    assert(value == &controller && request.standard_input == NULL && request.standard_input_byte_count == 0);
    if (request.command_byte_count == sizeof("id -u") - 1 &&
        memcmp(request.command, "id -u", request.command_byte_count) == 0) {
        assert(pending_user_id == NULL);
        user_id_commands++;
        pending_user_id = context;
        pending_user_id_finished = completion;
    } else { assert(false); }
    if (request.release_command != NULL) request.release_command(request.release_command_context);
}

void outersshpriv_proxy_ensure_bridge(
    OuterSSHSessionPool *binding, SSHBridgeRequest request, SSHSocketBridgeOperation *operation,
    SSHSocketBridgeWaiter *waiter, SSHProxyBridgeHandler finished, void *context)
{
    assert(binding == &controller && request.path != NULL && operation != NULL);
    assert(pending_bridge == NULL);
    if (fail_bridge_allocation) {
        finished(context, (SSHBridgeResult){.error = outersshpriv_proxy_error(
            OUTERSSH_PROXY_ERROR_REACTOR_CREATION_FAILED,
            "allocation failed", sizeof("allocation failed") - 1, 0)});
        return;
    }
    if (bridge_completes_immediately) {
        finished(context, (SSHBridgeResult){.bridge = {.generation = 7}});
        return;
    }
    *waiter = (SSHSocketBridgeWaiter){.finished = finished, .context = context};
    bridge_setup = (PendingBridge){request, waiter};
    pending_bridge = &bridge_setup;
}

void outersshpriv_proxy_stop_bridge(
    OuterSSHSessionPool *value, SSHProxyBridgeHandle handle)
{
    assert(value == &controller && handle.generation == 7);
}

static bool pending_connection_active = true;
static bool test_root_preparation;
static SSHSocketSender test_sender;
static unsigned sender_refusals;
static SSHProxyBridgeState *existing_bridge;

bool outersshpriv_forwarder_connection_permits(SSHForwarder *server,
    ProxyReactorPendingConnectionHandle connection, const SSHSocketOwner *destination, bool uses_sudo)
{
    assert(server == &test_server && connection.generation == 42);
    otqueue_assert(controller._queue);
    if (outersshpriv_socket_sender_permits(&test_sender, destination, controller._remoteUserIsRoot == 1, uses_sudo))
        return true;
    sender_refusals++;
    return false;
}

ProxyPendingConnection *outersshpriv_proxy_pending_connection_for_handle(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle handle)
{
    static ProxyPendingConnection connection;
    assert(reactor == controller._connectorReactor && handle.generation == 42);
    return pending_connection_active ? &connection : NULL;
}


static unsigned fail_allocation_number;
static void *route_calloc(size_t count, size_t size);
static void *route_malloc(size_t size);
#define calloc route_calloc
#define malloc route_malloc
#include "SSHRelayFlows.c"
#undef malloc
#undef calloc

static void *route_calloc(size_t count, size_t size)
{
    if (size == sizeof(ConnectRelayContext)) return calloc(count, size);
    return fail_allocation_number != 0 && --fail_allocation_number == 0
        ? NULL : calloc(count, size);
}
static void *route_malloc(size_t size)
{
    return fail_allocation_number != 0 && --fail_allocation_number == 0
        ? NULL : malloc(size);
}


static void route_completed(void *context, OuterSSHError error)
{
    assert(context == &controller && !entering_public_api);
    otqueue_assert(controller._queue);
    completions++;
    free(last_error_storage);
    last_error = outerssh_error_copy(error, &last_error_storage);
}

/* Looks up the remote user as a separate operation with its own waiter. */
static void lookup_user(void)
{
    static SSHWaiter waiters[4];
    static unsigned next_waiter;
    lookup_remote_user(&controller, &waiters[next_waiter++ % 4], route_completed, &controller);
}

static void start_connection(void)
{
    ProxyConnectionRoute route = {.kind = PROXY_CONNECTION_ROUTE_UNIX_SOCKET};
    route.unix_socket.path_length = strlen(expected_connection_path);
    memcpy(route.unix_socket.path, expected_connection_path, route.unix_socket.path_length);
    if (test_root_preparation) {
        prepare_root_socket_connection(test_connection, (ProxyReactorPendingConnectionHandle){.generation = 42}, route);
    } else {
        assign_socket_connection_if_allowed(test_connection, (ProxyReactorPendingConnectionHandle){.generation = 42}, route);
    }
}

static void complete_user_id(const char *output, int status, OuterSSHError error)
{
    SSHCommandOutput result = {.exit_status = status,
        .stdout_bytes = output, .stdout_byte_count = output == NULL ? 0 : strlen(output)};
    void *context = pending_user_id;
    pending_user_id = NULL;
    pending_user_id_finished(context, &result, error);
}

static void finish_bridge(OuterSSHError error)
{
    PendingBridge setup = *pending_bridge;
    pending_bridge = NULL;
    setup.waiter->finished(setup.waiter->context, (SSHBridgeResult){.bridge = {.generation = 7}, .error = error});
}

static void record_socket_result(SSHProxyConnection value,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route, OuterSSHError error)
{
    assert(value.pool == &controller);
    assert(connection.generation == 42 && route.unix_socket.path_length == strlen(expected_connection_path));
    assert(memcmp(route.unix_socket.path, expected_connection_path, route.unix_socket.path_length) == 0);
    free(last_error_storage);
    last_error = outerssh_error_copy(error, &last_error_storage);
    completions++;
}

static void failed_connection(void *context, OuterSSHSessionPool *pool, const void *frontend,
    const char *host, size_t host_length, uint16_t remote_port,
    const char *path, size_t path_length, OuterSSHError error)
{
    (void)context; (void)frontend; (void)host; (void)host_length; (void)remote_port;
    assert(pool == &controller && path_length == strlen(expected_connection_path));
    assert(memcmp(path, expected_connection_path, path_length) == 0);
    free(last_error_storage);
    last_error = outerssh_error_copy(error, &last_error_storage);
    completions++;
}

void outersshpriv_session_pool_post_connection_failure(OuterSSHSessionPool *pool,
    const void *frontend, const char *host, size_t host_length, uint16_t port,
    const char *socket_path, size_t socket_path_length, OuterSSHError error)
{
    failed_connection(NULL, pool, frontend, host, host_length, port,
        socket_path, socket_path_length, error);
}

bool outersshpriv_proxy_reactor_pending_connection_is_active(ProxyReactor *reactor,
    ProxyReactorPendingConnectionHandle connection)
{
    (void)reactor; (void)connection;
    return pending_connection_active;
}

void outersshpriv_proxy_assign_bridge_connection(SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route,
    const char *path, size_t length, bool uses_sudo)
{
    (void)path; (void)length; (void)uses_sudo;
    bridge_assignments++;
    record_socket_result(source, connection, route, (OuterSSHError){0});
}

void outersshpriv_proxy_request_sudo_for_connection(SSHProxyConnection source,
    ProxyReactorPendingConnectionHandle connection, ProxyConnectionRoute route,
    const char *path, size_t length, OuterSSHError error)
{
    (void)path; (void)length;
    record_socket_result(source, connection, route, error);
}

void outersshpriv_session_pool_run_when_ready(OuterSSHSessionPool *pool, SSHWaiter *waiter,
    SSHCompletionHandler resume, void *context)
{
    (void)pool; (void)waiter; (void)resume;
    ConnectRelayContext *relay_context = context;
    record_socket_result(relay_context->source, relay_context->connection,
        relay_context->route, (OuterSSHError){0});
    destroy_relay_context(relay_context);
}

bool outersshpriv_proxy_reactor_fail_pending_connection(
    ProxyReactor *reactor, ProxyReactorPendingConnectionHandle connection, ProxySOCKSReplyStatus status)
{
    assert(reactor == controller._connectorReactor && connection.generation == 42);
    (void)status;
    pending_failures++;
    return true;
}

static void complete_authorization(OuterSSHError error)
{
    SSHWaiter *waiter = pending_authorization;
    pending_authorization = NULL;
    waiter->resume(waiter->context, error);
}

static void test_authorization(void)
{
    expected_connection_path = "/run/user/1000/outer.sock";
    controller._remoteUserIsRoot = -1;
    immediate_authorization = false;
    unsigned before = completions;
    unsigned commands_before = user_id_commands, lookups_before = authorization_lookups;
    fail_allocation_number = 2;
    start_connection();
    assert(fail_allocation_number == 1);
    fail_allocation_number = 0;
    assert(pending_authorization != NULL && completions == before);
    assert(pending_user_id == NULL && user_id_commands == commands_before);
    assert(authorization_lookups == lookups_before + 1);
    complete_authorization((OuterSSHError){0});
    assert(completions == before + 1 && last_error.domain == OUTERSSH_ERROR_NONE);
    assert(controller._remoteUserIsRoot == -1 && controller.pending_operations == 0);

    existing_authorization = true;
    lookups_before = authorization_lookups;
    start_connection();
    assert(pending_authorization != NULL && authorization_lookups == lookups_before + 1);
    complete_authorization((OuterSSHError){0});
    existing_authorization = false;

    const char denial[] = "socket is not on the allowlist";
    before = completions;
    start_connection();
    complete_authorization(outersshpriv_proxy_error(OUTERSSH_PROXY_ERROR_SOCKET_AUTHORIZATION_FAILED,
        denial, sizeof(denial) - 1, 0));
    assert(completions == before + 1 && last_error.code == OUTERSSH_PROXY_ERROR_SOCKET_AUTHORIZATION_FAILED);
    assert(strcmp(last_error.message, denial) == 0);
    for (unsigned closing = 0; closing < 2; closing++) {
        unsigned failures = pending_failures;
        before = completions;
        start_connection();
        controller.shutdown_requested = closing == 0;
        listener_active = closing == 0;
        complete_authorization((OuterSSHError){0});
        assert(pending_failures == failures + 1 && completions == before);
        assert(controller.pending_operations == 0);
        controller.shutdown_requested = false;
        listener_active = true;
    }
    const char *invalid[] = {"relative", "", "/run/a\nb", "/run/a\rb"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        expected_connection_path = invalid[i];
        start_connection();
        assert(last_error.code == OUTERSSH_PROXY_ERROR_INVALID_UNIX_SOCKET_PATH);
    }
    expected_connection_path = "/run/outer.sock";
}

static void test_privileged_preparation(void)
{
    immediate_authorization = false;
    for (unsigned root = 0; root < 2; root++) {
        controller._remoteUserIsRoot = -1;
        unsigned before = completions, commands_before = user_id_commands;
        fail_allocation_number = 2;
        start_connection();
        assert(pending_user_id == &controller && user_id_commands == commands_before + 1);
        assert(pending_authorization == NULL && pending_bridge == NULL);
        complete_user_id(root ? "0\n" : "1000\n", 0, (OuterSSHError){0});
        assert(controller._remoteUserIsRoot == (int)root && completions == before);
        assert(fail_allocation_number == 1);
        fail_allocation_number = 0;
        if (root) {
            assert(pending_authorization != NULL && pending_bridge == NULL);
            complete_authorization((OuterSSHError){0});
        } else {
            assert(pending_bridge != NULL && pending_authorization == NULL);
            assert(pending_bridge->request.uses_sudo);
            finish_bridge((OuterSSHError){0});
        }
        assert(completions == before + 1 && last_error.domain == OUTERSSH_ERROR_NONE);
        assert(controller.pending_operations == 0);
        start_connection();
        assert(user_id_commands == commands_before + 1);
        if (root) complete_authorization((OuterSSHError){0});
        else finish_bridge((OuterSSHError){0});
    }

    controller._remoteUserIsRoot = -1;
    unsigned failures = pending_failures, before = completions;
    start_connection();
    listener_active = false;
    complete_user_id("0\n", 0, (OuterSSHError){0});
    assert(pending_failures == failures + 1 && completions == before);
    assert(controller._remoteUserIsRoot == -1 && controller.pending_operations == 0);
    listener_active = true;

    controller._remoteUserIsRoot = 0;
    fail_bridge_allocation = true;
    start_connection();
    assert(last_error.code == OUTERSSH_PROXY_ERROR_REACTOR_CREATION_FAILED);
    assert(controller.pending_operations == 0);
    fail_bridge_allocation = false;
}

static void test_cached_authorization_after_user_lookup(void)
{
    controller._remoteUserIsRoot = -1;
    immediate_authorization = false;
    unsigned before = completions, lookups_before = authorization_lookups;
    start_connection();
    assert(pending_user_id != NULL && authorization_lookups == lookups_before);
    cached_authorization = true;
    complete_user_id("0\n", 0, (OuterSSHError){0});
    assert(authorization_lookups == lookups_before + 2 && completions == before + 1);
    assert(last_error.domain == OUTERSSH_ERROR_NONE && controller.pending_operations == 0);
    cached_authorization = false;
}

static void test_shared_user_lookup(void)
{
    for (unsigned root = 0; root < 2; root++) {
        controller._remoteUserIsRoot = -1;
        immediate_authorization = true;
        bridge_completes_immediately = true;
        unsigned before = completions, commands_before = user_id_commands;
        start_connection();
        start_connection();
        assert(controller.pending_operations == 2 && completions == before);
        assert(user_id_commands == commands_before + 1);
        complete_user_id(root ? "0\n" : "1000\n", 0, (OuterSSHError){0});
        assert(completions == before + 2 && controller.pending_operations == 0);
        assert(!outersshpriv_is_waiting(&controller._remoteUserWaiters));
        immediate_authorization = false;
        bridge_completes_immediately = false;
    }
    for (unsigned scenario = 0; scenario < 5; scenario++) {
        controller._remoteUserIsRoot = -1;
        unsigned before = completions, commands_before = user_id_commands;
        lookup_user();
        lookup_user();
        assert(user_id_commands == commands_before + 1 && completions == before);
        const char *outputs[] = {"0\n", "1000\n", "", "oops", "0\n"};
        complete_user_id(outputs[scenario], scenario == 4 ? 1 : 0, (OuterSSHError){0});
        assert(completions == before + 2);
        assert(!outersshpriv_is_waiting(&controller._remoteUserWaiters));
        if (scenario < 2) {
            assert(controller._remoteUserIsRoot == (scenario == 0 ? 1 : 0));
            lookup_user();
            assert(completions == before + 3 && user_id_commands == commands_before + 1);
        } else {
            assert(last_error.domain != OUTERSSH_ERROR_NONE && controller._remoteUserIsRoot == -1);
            lookup_user();
            assert(user_id_commands == commands_before + 2);
            complete_user_id("1000\n", 0, (OuterSSHError){0});
            assert(controller._remoteUserIsRoot == 0 && completions == before + 3);
        }
    }
    controller._remoteUserIsRoot = -1;
    unsigned before = completions;
    lookup_user();
    lookup_user();
    controller.shutdown_requested = true;
    complete_user_id(NULL, 0, outerssh_proxy_closing_error());
    assert(completions == before + 2 && controller._remoteUserIsRoot == -1);
    assert(last_error.code == OUTERSSH_PROXY_ERROR_CONNECTION_CLOSING);
    controller.shutdown_requested = false;
}

static void test_remote_connection_modes(void)
{
    const char *paths[] = {"/launchd/user/org.outershell.Files", "/tmp/arbitrary-service", "/run/outer.sock"};
    cached_authorization = true;
    controller._remoteUserIsRoot = 0;
    controller._directStreamLocalUnsupported = false;
    for (unsigned path = 0; path < 3; path++) {
        expected_connection_path = paths[path];
        for (unsigned mode = 0; mode < 3; mode++) {
            authorization_entry.connection_mode = (HelperConnectionMode)mode;
            unsigned before = bridge_assignments, completed = completions;
            start_connection();
            if (mode == HELPER_CONNECTION_PRIVILEGED) {
                assert(pending_bridge && pending_bridge->request.uses_sudo);
                finish_bridge((OuterSSHError){0});
            }
            assert(bridge_assignments == before + (mode != HELPER_CONNECTION_DIRECT));
            assert(completions == completed + 1 && controller.pending_operations == 0);
        }
    }
    authorization_entry.connection_mode = HELPER_CONNECTION_MANAGED;
    unsigned completed = completions;
    pending_connection_active = false;
    start_connection();
    assert(completions == completed && controller.pending_operations == 0);
    pending_connection_active = true;
    cached_authorization = false;
    existing_authorization = false;
    immediate_authorization = false;
    unsigned before = bridge_assignments;
    start_connection();
    assert(pending_authorization != NULL && bridge_assignments == before);
    cached_authorization = true;
    complete_authorization((OuterSSHError){0});
    assert(bridge_assignments == before + 1 && controller.pending_operations == 0);
    cached_authorization = false;
    authorization_entry.connection_mode = HELPER_CONNECTION_DIRECT;
}

static void test_socket_owner(void)
{
    expected_connection_path = "/run/outer.sock";
    const size_t length = strlen(expected_connection_path);
    cached_authorization = true;
    controller._remoteUserIsRoot = 1;
    authorization_entry.session_owned = false;
    authorization_entry.root_owned = true;
    authorization_entry.owner_length = 1;
    memcpy(authorization_entry.owner, "0", 1);
    SSHSocketOwner owner = outersshpriv_proxy_socket_owner(&controller, expected_connection_path, length);
    assert(owner.known && owner.root && !owner.session_owned && owner.owner_length == 1 && owner.owner[0] == '0');
    authorization_entry.session_owned = true;
    authorization_entry.root_owned = false;
    owner = outersshpriv_proxy_socket_owner(&controller, expected_connection_path, length);
    assert(owner.known && owner.session_owned && !owner.root);

    SSHSocketOwner root = {.known = true, .root = true, .owner_length = 1, .owner = "0"};
    SSHSocketOwner bob = {.known = true, .owner_length = 4, .owner = "1001"};
    SSHSocketOwner other_bob = bob;
    SSHSocketOwner alice = {.known = true, .session_owned = true, .owner_length = 4, .owner = "1000"};
    SSHSocketOwner absent = {.known = true};
    SSHSocketOwner unknown = {0};
    assert(outersshpriv_socket_owner_may_send(&root, &bob) && outersshpriv_socket_owner_may_send(&other_bob, &bob));
    assert(!outersshpriv_socket_owner_may_send(&alice, &bob) && !outersshpriv_socket_owner_may_send(&bob, &root));
    assert(!outersshpriv_socket_owner_may_send(&absent, &absent) && !outersshpriv_socket_owner_may_send(&unknown, &bob));

    cached_authorization = false;
    existing_authorization = true;
    controller._remoteUserIsRoot = 0;
    assert(!outersshpriv_proxy_socket_owner(&controller, expected_connection_path, length).known);
    existing_authorization = false;
    authorization_entry.session_owned = false;
    authorization_entry.owner_length = 0;
    authorization_entry.connection_mode = HELPER_CONNECTION_DIRECT;
}

/* A sender the zone rule refuses never prepares sudo, whether the socket's
 * owner is learned by authorizing it, from an earlier authorization, or from
 * an existing sudo bridge; an allowed one still does. */
static void test_sender_judged_before_sudo(void)
{
    expected_connection_path = "/run/outer.sock";
    controller._remoteUserIsRoot = 0;
    immediate_authorization = false;
    authorization_entry.session_owned = false;
    authorization_entry.root_owned = true;
    authorization_entry.owner_length = 1;
    memcpy(authorization_entry.owner, "0", 1);
    const SSHSocketSender bob = {.kind = SSH_SOCKET_SENDER_OWNER,
        .owner = {.known = true, .owner_length = 4, .owner = "1001"}};
    const SSHSocketSender alice = {.kind = SSH_SOCKET_SENDER_OWNER,
        .owner = {.known = true, .session_owned = true, .owner_length = 4, .owner = "1000"}};
    const SSHSocketSender root = {.kind = SSH_SOCKET_SENDER_OWNER,
        .owner = {.known = true, .root = true, .owner_length = 1, .owner = "0"}};
    const SSHSocketSender refused[] = {
        bob, alice,
        {.kind = SSH_SOCKET_SENDER_OWNER},
        {.kind = SSH_SOCKET_SENDER_SSH_USER},
        {.kind = SSH_SOCKET_SENDER_UNDECIDED},
    };
    const SSHSocketSender allowed[] = {root, {.kind = SSH_SOCKET_SENDER_UNCHECKED}};
    for (unsigned source = 0; source < 3; source++) {
        for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]) + sizeof(allowed) / sizeof(allowed[0]); i++) {
            bool refuses = i < sizeof(refused) / sizeof(refused[0]);
            test_sender = refuses ? refused[i] : allowed[i - sizeof(refused) / sizeof(refused[0])];
            authorization_entry.connection_mode = HELPER_CONNECTION_PRIVILEGED;
            static SSHProxyBridgeState sudo_bridge = {.uses_sudo = true};
            existing_bridge = source == 2 ? &sudo_bridge : NULL;
            cached_authorization = source != 0;
            unsigned failures = pending_failures, refusals = sender_refusals, before = completions;
            unsigned commands_before = user_id_commands, assignments = bridge_assignments;
            start_connection();
            if (source == 0) {
                assert(pending_authorization != NULL);
                cached_authorization = true;
                complete_authorization((OuterSSHError){0});
            }
            if (refuses) {
                assert(sender_refusals == refusals + 1 && pending_failures == failures + 1);
                assert(completions == before && bridge_assignments == assignments);
            } else {
                assert(sender_refusals == refusals && pending_failures == failures);
                if (source == 2) {
                    assert(bridge_assignments == assignments + 1);
                } else {
                    assert(pending_bridge != NULL && pending_bridge->request.uses_sudo);
                    finish_bridge((OuterSSHError){0});
                    assert(bridge_assignments == assignments + 1);
                }
                assert(completions == before + 1 && last_error.domain == OUTERSSH_ERROR_NONE);
            }
            assert(pending_bridge == NULL && pending_user_id == NULL && user_id_commands == commands_before);
            assert(controller.pending_operations == 0);
        }
    }
    existing_bridge = NULL;

    authorization_entry.connection_mode = HELPER_CONNECTION_DIRECT;
    authorization_entry.root_owned = false;
    memcpy(authorization_entry.owner, "1001", 4);
    authorization_entry.owner_length = 4;
    cached_authorization = true;
    test_sender = (SSHSocketSender){.kind = SSH_SOCKET_SENDER_UNDECIDED};
    unsigned before = completions, failures = pending_failures;
    start_connection();
    assert(completions == before + 1 && pending_failures == failures && pending_bridge == NULL);
    test_sender = alice;
    start_connection();
    assert(completions == before + 1 && pending_failures == failures + 1);
    test_sender = bob;
    start_connection();
    assert(completions == before + 2 && pending_failures == failures + 1);

    authorization_entry.connection_mode = HELPER_CONNECTION_PRIVILEGED;
    controller._remoteUserIsRoot = 1;
    test_sender = (SSHSocketSender){.kind = SSH_SOCKET_SENDER_UNDECIDED};
    start_connection();
    assert(completions == before + 3 && pending_bridge == NULL && controller.pending_operations == 0);

    test_sender = (SSHSocketSender){.kind = SSH_SOCKET_SENDER_UNCHECKED};
    cached_authorization = false;
    authorization_entry.connection_mode = HELPER_CONNECTION_DIRECT;
    authorization_entry.owner_length = 0;
    controller._remoteUserIsRoot = -1;
}

static void test_sockets(void *context)
{
    (void)context;
    test_sender_judged_before_sudo();
    test_authorization();
    test_root_preparation = true;
    test_privileged_preparation();
    test_cached_authorization_after_user_lookup();
    test_shared_user_lookup();
    test_root_preparation = false;
    test_remote_connection_modes();
    test_socket_owner();
    ssh_test_semaphore_signal(finished);
}

int main(void)
{
    test_connection = (SSHProxyConnection){&test_server, &controller, 1};
    controller.pending_operations = 0;
    test_server.port = 12345;
    controller._queue = ssh_test_control_queue_create("test.ssh-socket-preparation");
    controller._connectorReactor = (ProxyReactor *)&controller;
    test_server.reactor = controller._connectorReactor;
    test_server.queue = controller._queue;
    controller._userBridgeExecutablePath = "/tmp/outerssh-helper";
    controller._userBridgeExecutablePath_length = sizeof("/tmp/outerssh-helper") - 1;

    test_server.port = 1080;
    finished = ssh_test_semaphore_create(0);
    otqueue_async(controller._queue, NULL, test_sockets);
    assert(ssh_test_semaphore_wait(finished, 5 * NSEC_PER_SEC) == 0);
    ssh_test_semaphore_destroy(finished);
    otqueue_release(controller._queue);
    puts("PASS: socket authorization, zone checks before sudo, sudo bridge readiness, controller replacement, and allocation failures");
    return 0;
}

void outersshpriv_proxy_connection_begin_work(SSHProxyConnection connection)
{
    outersshpriv_session_pool_begin_operation(connection.pool);
}
void outersshpriv_proxy_connection_end_work(SSHProxyConnection connection)
{
    outersshpriv_session_pool_end_operation(connection.pool);
}
SSHProxyConnection outersshpriv_proxy_active_connection(SSHProxyConnection connection)
{
    if (outersshpriv_session_pool_active(connection.pool) == NULL) connection.pool = NULL;
    return connection;
}
bool outersshpriv_proxy_connection_is_active(SSHProxyConnection connection)
{
    return outersshpriv_proxy_active_connection(connection).pool != NULL;
}

SSHProxyBridgeState *outersshpriv_proxy_bridge_for_path(OuterSSHSessionPool *pool,
    const char *path, size_t path_length, SSHProxyBridgeHandle *handle)
{
    (void)path; (void)path_length;
    assert(pool == &controller && pool->bridge_state_count == 0);
    if (handle != NULL) *handle = (SSHProxyBridgeHandle){0};
    return existing_bridge;
}
