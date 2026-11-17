#include "SSHTestSupport.h"
#include "SSHTestEventQueue.h"
#include <OuterSSH/OuterSSH.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#include "../OuterSSH/SSHForwarder.h"

static void fixture_connect(SSHForwarder *forwarder, otsocket_t socket, const char *host, size_t length,
    uint16_t port, SSHSocketSender sender, SSHForwarderConnectionCompletion completion, void *context);
static bool force_listener_repair;
static bool fixture_listener_is_listening(otsocket_t socket)
{
    if (force_listener_repair) {
        force_listener_repair = false;
        return false;
    }
    return otsocket_is_listening(socket);
}
/* Socket owners come from the pool's authorizations, which this fixture never
 * performs, so paths name their owner: /root/ is root's, /bob/ another user's,
 * /absent/ has no known owner, /new/ is never authorized, /pending/ is
 * authorized when a connection to it starts and is then owned like the rest of
 * its path, and everything else is the SSH user's. Root's sockets need sudo. */
static char authorized_paths[64][PROXY_UNIX_SOCKET_PATH_CAPACITY];
static size_t authorized_path_count;
static SSHSocketOwner fixture_socket_owner(OuterSSHSessionPool *pool, const char *path, size_t length)
{
    (void)pool;
    SSHSocketOwner owner = {.known = true};
    const char *uid = "1000";
    if (length >= 6 && memcmp(path, "/root/", 6) == 0) {
        owner.root = true;
        uid = "0";
    } else if (length >= 5 && memcmp(path, "/bob/", 5) == 0) {
        uid = "1001";
    } else if (length >= 8 && memcmp(path, "/absent/", 8) == 0) {
        uid = "";
    } else if (length >= 5 && memcmp(path, "/new/", 5) == 0) {
        return (SSHSocketOwner){0};
    } else if (length >= 9 && memcmp(path, "/pending/", 9) == 0) {
        for (size_t i = 0; i < authorized_path_count; i++) {
            if (strlen(authorized_paths[i]) == length && memcmp(authorized_paths[i], path, length) == 0) {
                return fixture_socket_owner(pool, path + 8, length - 8);
            }
        }
        return (SSHSocketOwner){0};
    } else {
        owner.session_owned = true;
    }
    owner.owner_length = strlen(uid);
    memcpy(owner.owner, uid, owner.owner_length);
    return owner;
}
#define otsocket_is_listening fixture_listener_is_listening
#define outersshpriv_forwarder_connect fixture_connect
#define outersshpriv_proxy_socket_owner fixture_socket_owner
#include "../OuterSSH/HTTPProxyServer.c"
#undef outersshpriv_proxy_socket_owner
#undef outersshpriv_forwarder_connect
#undef otsocket_is_listening

/* Substitute only SSH forwarding. HTTP still uses its production socket pair,
 * queues, connection completion, and teardown. The Python peer receives a
 * length-prefixed destination followed by the unmodified stream. */
typedef struct {
    SSHForwarder *forwarder;
    otsocket_t sockets[2];
    SSHSocketSender sender;
    SSHForwarderConnectionCompletion completion;
    void *context;
    unsigned char destination[259];
    size_t destination_length;
    ProxyConnectionRoute route;
    unsigned remaining;
    bool connected;
    bool forwarding_denied;
} FixtureConnection;

static int fixture_port;
static void fixture_begin_connection(void *context);
static void fixture_open_connection(void *context);
static void fixture_connection_opened(void *context);
static void fixture_copy_request(void *context);
static void fixture_copy_response(void *context);
static void fixture_direction_finished(void *context);

static void fixture_connect(SSHForwarder *forwarder, otsocket_t socket, const char *host, size_t length,
    uint16_t port, SSHSocketSender sender, SSHForwarderConnectionCompletion completion, void *context)
{
    FixtureConnection *connection = calloc(1, sizeof(*connection));
    if (!connection || length > sizeof(connection->destination) - 4) {
        free(connection);
        otsocket_close(socket);
        completion(context, (SSHForwarderConnectionResult){.status = PROXY_SOCKS_REPLY_GENERAL_FAILURE});
        return;
    }
    connection->forwarder = forwarder;
    connection->sockets[0] = socket;
    connection->sockets[1] = -1;
    connection->sender = sender;
    connection->completion = completion;
    connection->context = context;
    connection->destination[0] = (unsigned char)(length >> 8);
    connection->destination[1] = (unsigned char)length;
    connection->destination[2] = (unsigned char)(port >> 8);
    connection->destination[3] = (unsigned char)port;
    memcpy(connection->destination + 4, host, length);
    connection->destination_length = length + 4;
    ProxyConnectRequest request = {.host_length = length, .port = port};
    memcpy(request.host, host, length);
    connection->route = outersshpriv_proxy_resolve_request(request);
    otqueue_async(forwarder->queue, connection, fixture_begin_connection);
}

/* Authorizes the destination and, like the pool, judges the sender once the
 * socket's owner is known. A refused connection never reaches the peer, as a
 * refused connection never starts a sudo bridge. */
static void fixture_begin_connection(void *context)
{
    FixtureConnection *connection = context;
    ProxyConnectionRoute *route = &connection->route;
    if (route->kind == PROXY_CONNECTION_ROUTE_UNIX_SOCKET) {
        if (strncmp(route->unix_socket.path, "/pending/", 9) == 0 &&
            !fixture_socket_owner(NULL, route->unix_socket.path, route->unix_socket.path_length).known &&
            authorized_path_count < sizeof(authorized_paths) / sizeof(authorized_paths[0]) &&
            route->unix_socket.path_length < sizeof(authorized_paths[0])) {
            memcpy(authorized_paths[authorized_path_count++], route->unix_socket.path,
                route->unix_socket.path_length + 1);
        }
        SSHSocketOwner owner = fixture_socket_owner(NULL, route->unix_socket.path, route->unix_socket.path_length);
        if (owner.known && !outersshpriv_socket_sender_permits(&connection->sender, &owner, false, owner.root)) {
            otsocket_close(connection->sockets[0]);
            connection->completion(connection->context, (SSHForwarderConnectionResult){
                .status = PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED, .refused = true});
            free(connection);
            return;
        }
    }
    outersshpriv_proxy_server_begin_work(connection->forwarder);
    ssh_test_thread_start(fixture_open_connection, connection);
}

static bool fixture_send_all(otsocket_t socket, const void *bytes, size_t length)
{
    const char *remaining = bytes;
    while (length) {
        ssize_t count = otsocket_send(socket, remaining, length, OTSOCKET_SEND_FLAGS);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        remaining += count;
        length -= (size_t)count;
    }
    return true;
}

static void fixture_open_connection(void *context)
{
    FixtureConnection *connection = context;
    otsocket_t socket = otsocket_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    connection->sockets[1] = socket;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)fixture_port);
    unsigned char accepted = 0;
    connection->connected = socket != -1 &&
        otsocket_configure_sigpipe(socket) == 0 &&
        otsocket_configure_sigpipe(connection->sockets[0]) == 0 &&
        otsocket_set_nonblocking(connection->sockets[0], false) == 0 &&
        otsocket_connect(socket, (struct sockaddr *)&address, sizeof(address)) == 0 &&
        fixture_send_all(socket, connection->destination, connection->destination_length) &&
        otsocket_recv(socket, &accepted, 1, 0) == 1 && accepted == 1;
    connection->forwarding_denied = accepted == 2;
    otqueue_async(connection->forwarder->queue, connection, fixture_connection_opened);
}

static void fixture_connection_opened(void *context)
{
    FixtureConnection *connection = context;
    connection->completion(connection->context, (SSHForwarderConnectionResult){
        .status = connection->connected ? PROXY_SOCKS_REPLY_SUCCEEDED
            : connection->forwarding_denied ? PROXY_SOCKS_REPLY_CONNECTION_NOT_ALLOWED : PROXY_SOCKS_REPLY_GENERAL_FAILURE,
        .forwarding_denied = connection->forwarding_denied});
    if (!connection->connected) {
        connection->remaining = 1;
        fixture_direction_finished(connection);
        return;
    }
    connection->remaining = 2;
    ssh_test_thread_start(fixture_copy_request, connection);
    ssh_test_thread_start(fixture_copy_response, connection);
}

static void fixture_copy_stream(FixtureConnection *connection, unsigned direction)
{
    otsocket_t source = connection->sockets[direction];
    otsocket_t destination = connection->sockets[1 - direction];
    char bytes[16384];
    for (;;) {
        ssize_t count = otsocket_recv(source, bytes, sizeof(bytes), 0);
        if (count < 0 && errno == EINTR) continue;
        if (count == 0) {
            otsocket_shutdown(destination, SHUT_WR);
            break;
        }
        if (count < 0 || !fixture_send_all(destination, bytes, (size_t)count)) {
            otsocket_shutdown(source, SHUT_RDWR);
            otsocket_shutdown(destination, SHUT_RDWR);
            break;
        }
    }
    otqueue_async(connection->forwarder->queue, connection, fixture_direction_finished);
}

static void fixture_copy_request(void *context) { fixture_copy_stream(context, 0); }
static void fixture_copy_response(void *context) { fixture_copy_stream(context, 1); }

static void fixture_direction_finished(void *context)
{
    FixtureConnection *connection = context;
    if (--connection->remaining) return;
    otsocket_close(connection->sockets[0]);
    if (connection->sockets[1] != -1) otsocket_close(connection->sockets[1]);
    outersshpriv_proxy_server_end_work(connection->forwarder);
    free(connection);
}

static atomic_int port;
enum { STARTED_TAG = 1, REFRESHED_TAG, SERVER_DESTROYED_TAG, POOL_DESTROYED_TAG };
static void pause_briefly(void)
{
#ifdef _WIN32
    Sleep(1);
#else
    struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
#endif
}
static OuterSSHEventQueue *event_queue;
static bool repair_requested, destroy_during_repair;
static HTTPListener *previous_listener;
static uint64_t previous_generation;
static atomic_int checked;

/* Waits for the completion with this tag; the fixture has one request in flight. */
static OuterSSHEvent wait_for(uint64_t tag)
{
    OuterSSHEvent event;
    for (;;) {
        if (outerssh_event_queue_poll(event_queue, &event, 1) == 1) {
            if (event.tag == tag) return event;
            if (event.tag != 0) abort();
        } else {
            ssh_test_event_queue_wait(event_queue, 100);
        }
    }
}

static void refresh_listener(void *context)
{
    OuterSSHHTTPProxyServer *server = context;
    previous_listener = server->listener;
    previous_generation = server->forwarder->generation;
    force_listener_repair = repair_requested;
    if (!outerssh_http_proxy_server_start(server, 0, REFRESHED_TAG)) abort();
    if (destroy_during_repair && !outerssh_http_proxy_server_destroy(server, SERVER_DESTROYED_TAG)) abort();
}

/* Origin credentials for the socks and apple modes, named for the origin's owner. */
static void add_origin_credentials(void *context)
{
    OuterSSHHTTPProxyServer *server = context;
    static const char *const credentials[][2] = {
        {"user-origin", "/home/user/app.sock"},
        {"bob-origin", "/bob/app.sock"},
        {"root-origin", "/root/files.sock"},
        {"absent-origin", "/absent/app.sock"},
        {"tcp-origin", NULL},
        {"network-origin", NULL},
    };
    for (size_t i = 0; i < sizeof(credentials) / sizeof(credentials[0]); i++) {
        char origin[PROXY_ORIGIN_CAPACITY] = "http://localhost.tcp.outerssh.localhost:8080";
        if (strcmp(credentials[i][0], "network-origin") == 0) {
            snprintf(origin, sizeof(origin), "http://intranet.example:8080");
        } else if (credentials[i][1] != NULL) {
            char host[OUTERSSH_PROXY_SOCKET_HOST_CAPACITY];
            size_t host_length;
            if (!outerssh_proxy_encode_unix_socket_host(credentials[i][1], strlen(credentials[i][1]),
                    host, sizeof(host), &host_length)) abort();
            snprintf(origin, sizeof(origin), "http://%s", host);
        }
        char normalized[PROXY_ORIGIN_CAPACITY];
        size_t normalized_length;
        ProxyConnectionRoute route;
        if (!outersshpriv_proxy_parse_origin(origin, strlen(origin), normalized, &normalized_length, &route) ||
            outersshpriv_forwarder_set_origin_credentials(server->forwarder, credentials[i][0],
                strlen(credentials[i][0]), "secret", 6, normalized, normalized_length).domain) abort();
    }
}

static void check_refreshed_listener(void *context)
{
    OuterSSHHTTPProxyServer *server = context;
    if (server->forwarder->generation != previous_generation ||
        (!repair_requested && server->listener != previous_listener)) abort();
    atomic_store(&checked, 1);
}

int main(int argc, char **argv)
{
    if (argc < 2 || !outerssh_initialize(NULL)) return 1;
    fixture_port = atoi(argv[1]);
    event_queue = ssh_test_event_queue_create();
    if (!event_queue) return 1;
    OuterSSHProxyCredentials credentials = {.username = "browser", .username_length = 7, .password = "secret", .password_length = 6};
    OuterSSHHTTPProxyServerConfiguration config = {
        .credentials = argc > 2 && (strcmp(argv[2], "auth") == 0 || strcmp(argv[2], "apple") == 0 || strcmp(argv[2], "socks") == 0 || strncmp(argv[2], "realm", 5) == 0) ? &credentials : NULL,
        .rewrite_loopback_addresses = argc < 3 || strcmp(argv[2], "raw") != 0
    };
    char realm[] = {'T', 'e', 's', 't'};
    char maximum_realm[255];
    memset(maximum_realm, 'a', sizeof(maximum_realm));
    if (argc > 2 && strcmp(argv[2], "realm") == 0) {
        config.realm = realm;
        config.realm_length = sizeof(realm);
    } else if (argc > 2 && strcmp(argv[2], "realm-empty") == 0) {
        config.realm = realm;
        config.realm_length = 0;
    } else if (argc > 2 && strcmp(argv[2], "realm-max") == 0) {
        config.realm = maximum_realm;
        config.realm_length = sizeof(maximum_realm);
    }
    config.authentication = config.credentials ? OUTERSSH_PROXY_AUTHENTICATION_PASSWORD : OUTERSSH_PROXY_AUTHENTICATION_NONE;
    OuterSSHError error;
    OuterSSHSessionPoolConfiguration pool_config = {
        .hostname = "localhost", .hostname_length = 9,
        .username = "fixture", .username_length = 7,
        .authentication = {.kind = OUTERSSH_SESSION_AUTHENTICATION_PASSWORD, .password = "", .password_length = 0},
    };
    OuterSSHSessionPool *pool = outerssh_session_pool_create(event_queue, &pool_config, &error);
    if (!pool) return 1;
    bool socks = argc > 2 && (strcmp(argv[2], "socks") == 0 || strcmp(argv[2], "socks-raw") == 0);
    bool rewrites = socks && strcmp(argv[2], "socks") == 0;
    if (socks) {
        config.credentials = &credentials;
        config.authentication = OUTERSSH_PROXY_AUTHENTICATION_PASSWORD;
    }
    OuterSSHHTTPProxyServer *server = socks
        ? outersshpriv_inspected_socks_create(pool, config.credentials, config.authentication, rewrites, &error)
        : outerssh_http_proxy_server_create(pool, &config, &error);
    if (!server) { fprintf(stderr, "%.*s\n", (int)error.message_length, error.message); return 1; }
    if (socks || (argc > 2 && strcmp(argv[2], "apple") == 0)) otqueue_async(server->queue, server, add_origin_credentials);
    memset(realm, 0, sizeof(realm));
    memset(maximum_realm, 0, sizeof(maximum_realm));
    if (!outerssh_http_proxy_server_start(server, 0, STARTED_TAG)) return 1;
    OuterSSHEvent started = wait_for(STARTED_TAG);
    OuterSSHError start_error = started.proxy_started.error;
    if (start_error.domain) fprintf(stderr, "%.*s\n", (int)start_error.message_length, start_error.message);
    atomic_store(&port, start_error.domain ? -1 : started.proxy_started.listen_port);
    printf("%d\n", atomic_load(&port)); fflush(stdout);
    char command[32];
    while (atomic_load(&port) > 0 && fgets(command, sizeof(command), stdin)) {
        destroy_during_repair = strcmp(command, "repair-destroy\n") == 0;
        if (!destroy_during_repair && strcmp(command, "refresh\n") != 0 && strcmp(command, "repair\n") != 0) break;
        repair_requested = strcmp(command, "refresh\n") != 0;
        otqueue_async(server->queue, server, refresh_listener);
        OuterSSHEvent refreshed = wait_for(REFRESHED_TAG);
        if (destroy_during_repair) {
            if (!refreshed.proxy_started.error.domain) abort();
        } else {
            if (refreshed.proxy_started.error.domain || refreshed.proxy_started.listen_port != atomic_load(&port)) abort();
            atomic_store(&checked, 0);
            otqueue_async(server->queue, server, check_refreshed_listener);
            while (!atomic_load(&checked)) pause_briefly();
        }
        printf("REFRESHED\n"); fflush(stdout);
        if (destroy_during_repair) { server = NULL; break; }
    }
    if (server && !outerssh_http_proxy_server_destroy(server, SERVER_DESTROYED_TAG)) return 1;
    wait_for(SERVER_DESTROYED_TAG);
    if (!outerssh_session_pool_destroy(pool, POOL_DESTROYED_TAG)) return 1;
    wait_for(POOL_DESTROYED_TAG);
    ssh_test_event_queue_destroy(event_queue);
    return atomic_load(&port) < 0;
}
