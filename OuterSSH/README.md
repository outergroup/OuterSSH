# OuterSSH

OuterSSH is the C SSH and proxy library that Outer Loop uses on macOS, iOS, Android,
Windows, and Linux, with an Xcode target for Apple platforms and CMake builds for macOS,
Linux, Windows, and Android. It owns the connection flows,
session pool, reactors, SOCKS and HTTP relays, remote socket-bridge commands, and
libssh2 adaptations.

The portable C [outerssh command-line tool](../OuterSSHCLI/README.md) runs this library
as a standalone SOCKS5 and/or HTTP proxy on macOS, Linux, and Windows. Both
listeners connect directly to the same SSH session pool without chaining.

This README is maintained in the Outer Loop repository, and describes Outer Loop's
clients as the reference. Commands that start with `OuterLoop/Scripts/` run there. In the
OuterSSH repository, build and test with CMake as its top-level README describes.

`platform` contains the OS interfaces and implementations; `olibssh` contains
the libssh2 adaptations. SSH and proxy flows remain at the top level.

`SOCKSProxyServer.c` implements the SOCKS API, `HTTPProxyServer.c` implements
the HTTP proxy, and `PortForward.c` implements fixed TCP forwarding. All use the shared forwarding
machinery in `SSHForwarder.c` and `SSHForwarder.h`. Their public headers share
endpoint values and pool options through `ProxyTypes.h`.

## Architecture

OuterSSH takes requests and gives back events. No callback crosses the public
boundary, and the library uses no private callback version of its own API.

1. **Event queue and work queues.** An `OuterSSHEventQueue` holds only events.
   Work runs on serial queues the library creates: a control queue per pool,
   shared with its frontends, plus one per SSH session. Queues run on the
   platform's thread pool (see "Threads and events"). Applications submit
   requests from any thread and drain events with `outerssh_event_queue_poll`
   when the event queue signals that events are pending.
2. **Request.** Each request takes an application-chosen `uint64_t` tag. It
   validates its input, reserves its completion event, and hands an operation to
   its pool's control queue. It returns false only when it did nothing: invalid input or
   no memory for the operation or its event.
3. **Operation.** A control-queue record that owns its reserved event, called its
   reply. It runs engine steps and finishes exactly once by writing its result
   into the reply and posting it (`outersshpriv_reply*` in `SSHEventsInternal.h`).
   Every accepted request therefore produces exactly one completion event, even
   on failure or teardown. A frontend (SOCKS, HTTP, port forward) reserves the
   reply and passes it to the forwarder or HTTP operation that carries it.
4. **Engine.** Session acquisition, command channels, the socket service,
   bridges, forwarders, and reactors. Engine steps report to the operation or
   subsystem that started them through continuations (`SSHContinuations.h`).
   `OuterSSH` names are public; internal file and type names carry their
   subsystem's prefix (see "File layout"). Compositions
   inside the library are built from engine steps: the homepage lookup waits for
   a session and runs commands, a jump host relays through an engine forwarder on
   the upstream pool, and an inspected SOCKS frontend forwards its replies into
   the HTTP server's operations.
5. **Notifications and questions.** Engine state changes post untagged events.
   Questions (host keys, sudo passwords, the packaged bridge binary) carry
   identifiers and wait for an answer; a question still queued when it stops
   mattering is withdrawn, and one already delivered is followed by
   `OUTERSSH_EVENT_QUESTION_CANCELLED`.
6. **Teardown.** Destroy is an operation whose reply is `OUTERSSH_EVENT_DESTROYED`,
   posted after the object is freed. An object's completions arrive before its
   `DESTROYED` event. Destroy an event queue only after every pool and frontend in it
   has posted `DESTROYED`.

### Threads and events

OuterSSH is written against `platform/OTQueue.h`, the subset of Dispatch its
engine uses: serial queues, read/write/timer sources, background work,
queue-specific values, and once. Each platform implements it natively:

| Platform | Implementation | Pending events signal |
| --- | --- | --- |
| macOS and iOS | Dispatch itself (`OTQueueApple.c` adds autorelease pools to background work) | a `DISPATCH_SOURCE_TYPE_DATA_OR` source the application passes to `outerssh_event_queue_create` |
| Windows | `OTQueueWindows.c`: a thread-pool work object per queue, thread-pool waits on `WSAEventSelect` events, thread-pool timers | a manual-reset event from `outerssh_event_queue_wait_handle` |
| Linux and Android | `OTQueueLinux.c`: one epoll thread and four workers the library starts with its first queue; one-shot epoll watches shared by a socket's sources, a `timerfd` per timer, a thread per blocking job | an eventfd from `outerssh_event_queue_wait_handle` |

Each pool's control queue is the library's own on every platform; the
application never supplies one. On Apple platforms it takes the quality of
service of the thread that creates the pool, with user-interactive lowered to
user-initiated. Each SSH session gets a queue of its own at its control
queue's quality of service, so pools and the sessions of one pool can run in
parallel. The pending-events signal is level-triggered where it is a handle:
it stays signaled until `outerssh_event_queue_poll` drains the last event.
OuterSSH has no blocking wait; a program without an event loop waits on the
handle itself on a thread it owns. On Apple platforms, the application creates the source with its own
handler, and the event queue merges data into it once events become pending; the
application cancels it and destroys the event queue on the queue the source
targets. No platform calls back into application code.

Linux and Android have no system thread pool, so the library owns these
threads; an application with its own pool would change `OTQueueLinux.c`.

### Data at rest and dynamic input

The application tells OuterSSH where data at rest lives, and the library reads
it itself. OuterSSH copies only dynamic inputs: passwords, command text, and
command input passed to `outerssh_session_pool_execute_command`. The packaged
bridge binary is data at rest, so the application answers for it with a file
and a region rather than bytes, and the bytes travel from the page cache to the
SSH channel without a heap copy.

### Waiting inside the engine

Inside the engine, operations wait for facts the pool learns once: a ready
session, whether the remote user is root, an installed user or sudo bridge
executable, an authorized socket path, a running bridge. Every wait follows one
rule, implemented by `SSHWaiting.h`:

1. An operation that needs a fact parks an `SSHWaiter` embedded in its own
   record on that fact's `SSHWaitList`. Waiting never allocates.
2. The first waiter starts the lookup; later waiters join it.
3. When the lookup finishes, the pool stores the fact in its own state and wakes
   every waiter with only an error.
4. Each operation resumes and reads the fact from pool state, for example
   `outersshpriv_session_pool_ready_reactor` or
   `pool->_userBridgeExecutablePath`.

An operation waits for one fact at a time, so it embeds one `waiter`. The pool's
wait lists are fields on the pool, and finalization asserts that they are empty.
Bridge setup is the one wait whose result differs per request (which bridge was
attempted, which predecessor failed). Its `SSHSocketBridgeWaiter` embeds an
`SSHWaiter` and carries that result, and it receives the result typed.

Wait lists are for operations outside the pool. The pool's own work, installing
the bridge executables, is a state machine instead: each installation's
`SSHBridgeInstallStep` says what it waits for, and one function advances every
installation that can move (described below with the installation entry
points). Shutdown can then see what each installation is waiting for and fail
it, rather than waiting for a lookup to finish.

Between queues, the engine already passes messages: an operation record is
dispatched to a reactor's queue, and the reactor reports back by storing results
in the record and dispatching it to the control queue. Each serial queue acts as
a mailbox, so an explicit mailbox and `switch` would rename this mechanism
without removing any state.

### File layout

Each internal file name starts with the subsystem it belongs to:

| Prefix | Subsystem |
| --- | --- |
| `SSHReactor*` | one SSH session's transport and channels, on the reactor queue |
| `SSHSessionPool*`, `SSH*Flows.c`, other `SSH*` files | the pool, its control-queue operations, and the engine pieces they use (forwarder, socket service, homepage, endpoint names, waiting) |
| `SSHEvents*`, `SSHEventQueue*` | requests, replies, notifications, and questions |
| `Proxy*` | the local listener reactor: listeners, TCP connects, pending connections, SOCKS negotiation |
| `HTTPProxy*` | the HTTP proxy and its rewriting |
| `SocketBridge*`, `SSHBridgeBinary.c` | the bridge wire protocol, remote commands, and the packaged binary |
| `OuterSSH.c`, `PortForward.c`, `SOCKSProxyServer.c` | public entry points and frontends |
| `platform/OTQueue*` | the serial queues and sources, one implementation per platform |

A `*Internal.h` header holds declarations or struct layout private to one
subsystem, often beside a public or engine-facing header of the same name.

`include/OuterSSH` contains the public headers. Consumers include
`<OuterSSH/OuterSSH.h>`. Public functions use `outerssh_`; internal functions
shared between files use `outersshpriv_`, including helpers defined in private
headers. File-local `static` functions do not need a namespace prefix. Type names
are independent of this convention. The OT platform interfaces, `olibssh`
adaptations, and vendored libraries keep their own prefixes. On Apple platforms,
link `libOuterSSH.a`, Security, zlib, and the Objective-C runtime (`-lobjc`).
The default Apple backend also uses Foundation, CryptoKit, and the system Swift
runtime; Xcode handles their autolinking. The optional OpenSSL backend bundles
OpenSSL into the archive instead.
Its Swift implementation module is `OuterSSHAppleCrypto`, separate from the public
C module `OuterSSH`. Crypto headers remain private.
Bridge binary selection, socket privilege classification, launch, installation,
cleanup, and installed-path parsing stay internal in `SocketBridgeCommands.h`.
The remote socket service authorizes endpoints and selects direct, managed-bridge,
or privileged-bridge connections. OuterSSH follows that result without interpreting
platform-specific endpoint names. Remote-platform detection remains private to
bridge installation; products can run their own platform queries.

Pool and server creation initialize the library once per process. A host that must
initialize before applying a sandbox can call `outerssh_initialize` explicitly.
Initialization errors are reported through `OuterSSHError`.

With the OpenSSL backend, cipher preferences are selected once per process from OpenSSL's runtime CPU
capability report. AES-128-GCM leads when ARM AES + PMULL or x86 AES-NI +
PCLMULQDQ are available; otherwise ChaCha20-Poly1305 leads. Missing or unknown
capability reports also select ChaCha. Both remain offered, followed by the
existing AES-CTR fallbacks. OpenSSL capability overrides apply to this selection.
The Apple and Windows CNG backends always prefer AES-128-GCM, then AES-256-GCM and AES-CTR.

Host-key validators run on the control queue and receive a completion. Call it
exactly once, from any queue: `OUTERSSH_ERROR_NONE` accepts the key, while a
populated error rejects it before login authentication. Validators may complete
immediately or return and arrange a UI prompt. Key bytes remain valid until
completion; error text is copied before completion returns. The authentication
timeout starts after approval. Complete outstanding decisions even after shutdown
is requested: destruction waits for them, and late answers cannot revive a cancelled
connection. Session startup preserves rejection domains, codes, and diagnostics.

`outerssh-helper` is the remote **executable**. The application supplies its
build: OuterSSH's own `OuterSSHHelper/Main.c` passes no request handler, while an
application such as Outer Loop links `OuterSSHHelper/Helper.c` with its own `main`
and handler (see `OuterSSHHelper/OuterSSHHelper.h`). A packaged **binary** is the
platform-specific byte buffer uploaded to install it. A **bridge** is a running
instance serving one socket or pipe; one installed executable can be used by
multiple bridges and by a persistent helper service.

`SSHBridgeInstallationFlows.c` installs and removes these executables.
`SSHRelayFlows.c` authorizes socket access and opens direct relays.
`SSHSocketBridgeFlows.c` prepares privileged access and bridge streams.
User sockets go straight to cached authorization. Root sockets first use the
pool's cached user identity: root users take the authorization path; other users
start or reuse a sudo bridge. Concurrent user lookups share one `id -u` command.
Cached authorization and existing bridges need no preparation allocation.
Otherwise, one connection context holds the route through lookup, authorization,
or bridge setup until `socket_connection_prepared` resumes the connection.
The public ensure-bridge API copies its path and password into one submission
allocation, kept until `sudo_bridge_preparation_finished` delivers its result.
Command execution, the authorization cache, and running bridges have separate
storage. Pending authorization and bridge setup use storage embedded in the
caller's context.
`SSHSocketBridgeFlows.c` starts and manages running bridges. Callers pass a
complete `SSHBridgeRequest` value, embedded `SSHSocketBridgeOperation` storage,
and an embedded waiter to `outersshpriv_proxy_ensure_bridge`. Neither storage object needs
initialization. New setup uses the first caller's operation; joining callers
contribute only their waiters. Existing bridges complete without using either.
Each caller receives an `SSHBridgeResult` exactly once, including failure.
Request bytes and embedded storage remain borrowed until its callback begins,
which may free their owner. Setup detaches from the pool and releases its command
and input before callbacks; diagnostic storage survives until all callbacks return.
Socket preparation, sudo submission, connection attachment, and stream recovery
all follow this ownership rule, without a separate setup allocation.

On each session's reactor queue, `SSHReactor.c` drives the SSH transport,
session validation, channel opens and closes, and command channels.
`SSHReactorRelay.c` attaches, forwards, recovers, and closes direct relays.
`SSHReactorSocketBridge.c` drives bridge frames, multiplexed streams, and their
socket lifetimes. `SSHReactorOutput.c` queues SSH writes and owns channel output
buffers. The startup phases are `SSHReactorHandshake.c`,
`SSHReactorKeyExchange.c`, and `SSHReactorAuthentication.c`, which drive the
protocol code in `olibssh/` on the reactor's socket. These files share reactor
state and direct internal calls through `SSHReactorInternal.h`.

### Packaged helper binaries

Applications package every helper compressed, and OuterSSH uploads it as
packaged: the server decompresses it. When an installation needs a helper, the
pool posts `OUTERSSH_EVENT_HELPER_BINARY_NEEDED` with a question identifier and
the server's helper platform. The application chooses its own file names:

| Remote platform | Platform | Contents |
| --- | --- | --- |
| Linux | `linux-{aarch64,x86_64}-{glibc,musl}` | gzip of the executable |
| macOS | `macos` | gzip of the executable |
| Windows | `windows-{arm64,x64,x86}` | gzip of a tar holding one `outerssh-helper.exe` |

The application answers with `outerssh_session_pool_provide_helper_binary(pool,
question, file, offset, length)`: an open file descriptor (a `HANDLE` on
Windows, see `OuterSSHFileHandle`) and the region holding the helper. The offset
need not be aligned, so an Android app can pass the descriptor, offset, and
length of an uncompressed APK asset. An application that cannot supply the
helper calls `outerssh_session_pool_decline_helper_binary` with an error, which
fails the installation.

The provide call always takes ownership of the file and closes it, including
when the question is stale or cancelled and when the call returns false. It maps
the region read-only (`mmap`, or `MapViewOfFile` on Windows), closes the file,
and checks the gzip header. `SSHBridgeBinary.c` holds the reference-counted
mapping. Each installation command borrows it through
`SSHCommandRequest.release_input`, and the SSH channel sends it straight from
the mapping; the last release unmaps it. Pool teardown cancels an open question
like any other.

A pool asks for the helper at most once at a time, while an installation is at
`SSH_BRIDGE_INSTALL_NEEDS_BINARY` and `_bridgeBinary` is unset. The answer is
held in `_bridgeBinary` until no installation needs it, and each install command
takes its own reference, so concurrent user and sudo installations share one
answer.

On Unix servers the install script runs `gzip -dc` into a temporary file after
checking `command -v gzip`; gzip's length and CRC trailer reject a truncated or
corrupt upload. The script then validates `--version` as before. On Windows the
PowerShell install script prepares the protected directory and runs
`%SystemRoot%\System32\tar.exe -xzf -` (Windows 10 version 1803 or later) with
its standard input inherited. PowerShell itself cannot read the upload: through
Windows OpenSSH, `[Console]::OpenStandardInput()` and other .NET console readers
stall after roughly 160 KB or never see end of input, while `tar.exe` receives
multi-megabyte binary input intact.

Windows OpenSSH also stalls a command's standard input, whatever reads it, when
another command starts or exits on the same connection while that input is
being delivered; the macOS OpenSSH client reproduces this over one multiplexed
connection. So on Windows servers `SSHCommandFlows.c` runs a command with
standard input alone: it waits for running commands to finish, and later
commands wait for it, starting in order. Bridge streams and the socket service
are not held. Bridge install commands time out after 60 seconds, not the
default five minutes for commands, so a stuck install fails with an error.

Resource lookup, XPC, authorization policy, and other application adapters
remain outside the library.

`platform/OTQueue.h` defines the scheduling contract the engine uses: serial
queues, background work submission, queue-specific values, once-only
initialization, and socket/timer sources. On Apple platforms it maps onto
Dispatch; `OTQueueWindows.c` and `OTQueueLinux.c` implement it on the Windows
thread pool and on epoll (see "Threads and events"). An event queue has a control
queue, and each SSH session's reactor has a queue of its own, so sessions can
run in parallel. Keep hops between the control queue and a reactor queue as
`otqueue_async` calls, never direct calls: they cross queues that may run in
parallel. A reactor is constructed by the first work item on its queue, and
its sources are created and controlled from work on that queue. Queues and
sources are reference counted; pending work and sources retain their queue.
On Apple platforms each background job runs in an autorelease pool.
Platform helpers cover sockets, clocks, and secure random bytes.
`platform/OTSocket.h` provides the cross-platform socket API, including SIGPIPE
configuration and send flags. `platform/SecureRandom.h` provides `secure_random_bytes`
without depending on the socket API.
Apple logging uses os_log; other platforms write notices and errors to stderr,
with debug/info enabled by setting `OUTERSSH_LOG`.

Source contexts are borrowed until cancellation completes. Suspension pauses
event delivery without restarting a timer; resetting a timer discards pending
expirations. The header documents ownership, activation, and cancellation rules.
Semaphores used to coordinate tests, test queue creation, and synchronous test
setup helpers live in `../Scripts/SSHTestSupport.h`, outside the production
interface. `../Scripts/SSHTestEventQueue.h` creates public-API test event queues the
way an application on that platform would, and `../Scripts/SSHTestFakeEventQueue.h`
delivers events for event queues that tests assemble by hand.

The reactor owns the connected socket and session from the start.
`SSHReactorHandshake.c` drives banner exchange, initial key exchange, and the
`ssh-userauth` service request on the reactor queue, with a single handshake
deadline. Initial exchange and later rekeys use the same transport and key
exchange continuations. The reactor embeds handshake and authentication contexts
in a union, with an explicit phase selecting the active protocol flow. Startup
completion permits reusing that storage for the next phase. The session-creation
operation stays alive through startup and any failure cleanup.

`SSHReactorAuthentication.c` follows host-key approval with method discovery, password,
keyboard-interactive, or public-key request/reply continuations on the reactor.
Private-key configurations try ssh-agent first, then the supplied key; password
configurations fall back to keyboard-interactive when offered. Authentication
has one deadline and shares the reactor's packet reader, partial-write handling,
and rekey engine. Neither startup nor authentication calls libssh2's SSH protocol
state machines.

Host-key approval, local key parsing/decryption, and agent IPC/signing run as
background work on the platform's thread pool. `olibssh/authentication.c` reuses libssh2's crypto and agent
routines with a separate disconnected session for allocator/error storage; these
jobs never access the live network session. Cancellation stops reactor I/O, but
completion waits for an outstanding worker before releasing its context and key
material. Completion runs exactly once, after packet dispatch has unwound. The
pool then publishes the authenticated session and resumes its reactor.

Session-dependent flows wait with `outersshpriv_session_pool_run_when_ready`, passing
the operation's embedded waiter and the function that continues the work:

```c
outersshpriv_session_pool_run_when_ready(
    operation->pool, &operation->waiter, ssh_command_session_request_finished, operation);
```

The continuation runs exactly once on the pool queue, either immediately or after
session creation, and calls `outersshpriv_session_pool_ready_reactor` for the
session to use. That call rechecks availability and shutdown, so a resumed
operation never uses a session that closed while it waited. Waiters resume in
submission order; this does not serialize SSH channel work.

Bridge executable installation uses two parallel entry points:
`outersshpriv_proxy_ensure_user_bridge_executable` and
`outersshpriv_proxy_ensure_sudo_bridge_executable`. Each resumes its waiter once the
executable is installed or cannot be. The path is then
`pool->_userBridgeExecutablePath` or `pool->_sudoBridgeExecutablePath`. An installed
executable resumes the operation immediately. A sudo installation borrows the first
waiting operation's password until that operation resumes.

`SSHBridgeInstallationFlows.c` keeps the two installations as steps on the pool,
`_userBridgeInstall` and `_sudoBridgeInstall`:

| Step | Waiting for |
| --- | --- |
| `NEEDS_SUDO_CHECK`, `CHECKING_SUDO` | `sudo -n true` (sudo only) |
| `NEEDS_PLATFORM` | the remote platform probe |
| `NEEDS_BINARY` | the application's answer for the packaged binary |
| `INSTALLING` | the install command |

Every entry point, a request or a command or question completion, changes state
between `enter_bridge_installs` and `leave_bridge_installs`. The outermost leave
calls `advance_bridge_installs_once` until nothing moves. That runs
`advance_bridge_install` for each installation, a `switch` on its step that
makes every forward transition: it starts the probe, asks for the binary, or
starts the install command once the pool knows enough. The start functions only
issue work. Completions record what they learned, move an installation past the
work it waited for, or finish it. Nested entries, such as a woken operation that
requests another installation, only change state, so the advance loop never
re-enters itself. The pool counts as busy until the outermost leave, so a
disconnect never runs cleanup while an installation is still waking its
operations.

The platform probe is shared: concurrent user and sudo installations wait for
one probe, and a successful result is copied as bytes and a length and reused
for the pool's lifetime. Failed detection is not cached and fails every
installation at `NEEDS_PLATFORM`.

Once shutdown begins, advancing fails every installation that has not reached
`INSTALLING` with the closing error, since nothing has been written to the
server yet. That lets a disconnect continue at once even when the probe is still
waiting for an SSH handshake. A running install command finishes, so the
executable it may have written can be cleaned up.

Bridge setup takes a request value and its continuation through
`outersshpriv_proxy_ensure_bridge`. The continuation receives a result value containing
the available bridge or an error exactly once. Explicit preparation,
connection attachment, and bridge replacement supply their own next functions.
Setup can finish immediately when a bridge already exists. Concurrent requests for
the same pool and path wait for one startup; they all complete on success or
failure. Different privilege modes cannot share a bridge. A replacement keeps
the original failed-bridge handle independently of the continuation it uses.

`ProxyPendingConnections.c` owns pending connections shared by the HTTP and SOCKS
frontends: slot allocation, forwarding ownership, cancellation, and socket handoff.
`ProxySOCKSHandshake.c` owns SOCKS negotiation, authentication, replies, and deadlines;
direct HTTP connections do not allocate SOCKS handshake state. `ProxyReactor`
retains its general name because it also manages listeners and SSH TCP connections.

Socket transfers store their callback and context directly on the pending
connection. Completion runs exactly once, including immediate rejection. Successful
SOCKS completion drains its reply; both frontends wait for socket-source
cancellation before passing ownership of the socket to the callback. Each caller
keeps one `ConnectRelayContext` or `ConnectBridgeStreamContext` from channel setup
through socket attachment, including retries.

A task's `Context` struct holds the locals that survive its asynchronous steps.
Keep its definition, forward declarations, entry point, continuations, and cleanup
together under the corresponding section. Embed subordinate work when its lifetime
fits the task; keep persistent resources and independently running tasks separate.

Internal commands pass an `SSHCommandRequest` value and result handler to
`outersshpriv_execute_command` with a pool. The request names the command, an
optional input prefix, the input bytes, and optional release callbacks. Storage
is borrowed, never copied: the SSH channel writes the prefix and then the input
directly from the caller's buffers, and forgets them when the command completes.
Release callbacks run exactly once before completion, including on failure.
Without a release callback, the bytes remain borrowed until completion begins. Each call
requests a session and invokes its completion exactly once on the pool queue,
possibly before returning. Results and their output buffers are borrowed until
the completion returns. The command machinery then destroys its private
`ExecuteCommandContext` and result buffers. The public copying API places the
context, command, and input in one allocation.

User bridge executable installation runs platform detection and installation as
two separate commands. `user_bridge_platform_received` selects the binary and
starts the installation command with `user_bridge_install_finished` as its callback.
Shutdown waits for the installation sequence to finish; its callbacks use the
pool as context. Each command has its own operation and session request.
User installation lends a reference to the mapped binary to the command
operation. The operation keeps it through session waiting and retries, then
releases it on the control queue before completion, including on failure.
Generated command text also transfers with its release callback; static commands
need no cleanup.
Privileged installation lends the binary the same way. When sudo needs a
password, the password and a newline go in the input prefix, a small copy owned
by the pool until the installation finishes and cleared before it is freed.
The public command API copies its caller's command and input before handing
them to this flow.

Command text carries its byte count from the public API through to the reactor;
it does not require a null terminator. Installer-output parsing likewise uses the
returned byte counts, allocating only the final path or package name.

Remote executable cleanup submits both commands independently, then invokes the supplied
completion exactly once on the control queue. Completion may run before the
call returns, including when allocation fails or there is nothing to clean up.
It means all cleanup attempts have finished, not that remote cleanup succeeded.
The completion owns the remaining lifetime of its context; cleanup frees its
own operation afterward. Standalone cleanup passes no completion or context.

Socket destinations can be carried directly in an HTTP hostname under
`unix.outerssh.localhost`. `SSHProxyAddress.h` provides the shared, header-only
encoder and decoder used by the browsers; no SSH runtime is needed to format an
address. Each SOCKS connection starts socket preparation. Direct-streamlocal
connections ask the persistent socket service to check the allowlist once per path per pool;
traffic bridges check it themselves at each stream open. Active bridges are reused. Browsers do not need a separate registration exchange, and
embedded requests can reach another allowed socket without a top-level navigation.

The hostname contains the socket path's bytes as unpadded RFC 4648 base32, in
lowercase, split into labels of 50 characters. The configured proxy determines
which SSH server to use. Total hostname length is at most 253 characters;
overlong paths fail encoding rather than being truncated or hashed.
Only port 80 denotes HTTP over a Unix socket. Malformed reserved names and other
ports are rejected rather than resolved through DNS.

On macOS, `/launchd/user/<label>` and `/launchd/system/<label>` are stable
service addresses in this same encoding, not filesystem paths. The socket
bridge resolves them through `SecureSocketWithKey` using the environment key
`OUTERSHELL_SOCKET_<label>`. A one-shot job in the target launchd domain reads
that variable before the target app starts. These addresses always use a
traffic bridge, even when the SSH server supports direct-streamlocal channels.
The authorization service returns a managed or privileged connection mode for
these addresses; OuterSSH does not parse them. The bridge checks the exact
service address against the shared allowlist before
resolution and on every stream open. System services require root privileges.
Generated paths are cached within a traffic bridge and resolved again when a
connection fails because a job has reloaded. On localhost, OuterNetworkProxy
resolves user service addresses itself with the same resolver and connects to
the generated socket directly, caching the path and resolving again when a
connection fails. Allowlist checks run in OuterNetworkProxy before a route is
registered. System services and other root-owned sockets use
`outer-root-socket-bridge`, a local-only helper that OuterNetworkProxy runs under
sudo and multiplexes over its stdin and stdout; nothing listens on a port.
OuterNetworkProxy is a SOCKS proxy, but it frames the HTTP requests in each
tunnel to a root-owned socket with `Common/HTTPRequestInspector.h`, which the
Linux and Windows localhost proxies share, and applies the zone rule
below, where only a root-owned socket registered under the same proxy
credentials counts as a sender in root's zone. Refused requests, and requests
with ambiguous framing, get an error response and the connection closes. Browser origins encode the stable service
address; generated paths and proxy registration IDs do not participate in that
origin. WebKit data stores remain separated by server.

Remote loopback TCP destinations keep the spelling the page used:
`localhost.tcp.outerssh.localhost:<port>`, `127.0.0.1.tcp.outerssh.localhost:<port>`
(any canonical `127.x.x.x` dotted quad), or `ip6-localhost.tcp.outerssh.localhost:<port>`
for `[::1]`. The proxy asks the SSH server to connect to `localhost`, the dotted
quad, or `::1` at that port, without route registration. The shared address
helpers encode and decode these hostnames; the destination port is carried in
the URL or proxy request. HTTP response rewriting and the browser's localhost
compatibility script produce these aliases, including when the page itself uses
a Unix socket. Unknown names in the reserved namespace are rejected.
Local-machine forwarding continues to use its separate `outerloop.localhost`
namespace.

With `rewrite_loopback_addresses`, requests to these hosts reach the backend
with the loopback spelling the page used. `Host` becomes that spelling and the
destination port, and loopback aliases in `Origin`, `Referer`, and
`Sec-WebSocket-Origin` become their spellings, keeping each URL's own port.
Responses get the inverse: an `http` or `ws` loopback URL at the start of
`Location` or `Access-Control-Allow-Origin` becomes its alias, so redirects stay
on the proxy and CORS checks match the browser's origin. Wildcard, `null`, and
other allow-origin values are preserved, so the backend still decides which
origins may access its responses.

Every socket and named pipe has an owner, which the helper reports when it
authorizes the path: the socket's uid on Unix, or on Windows the SID at the end
of the pipe name (`.s-1-5-18` for SYSTEM, for example), defaulting to the
current user. Root, SYSTEM and Administrators count as root. Endpoints form
zones. From lowest to highest: other hosts the SSH server can reach; the SSH
server's loopback ports, along with sockets without a known owner; each
account's sockets, that account's zone; and root's sockets. A request reaches
an endpoint from its own zone or a higher one; from a lower zone it is blocked,
with no opt-in. Other accounts' apps stay isolated from each other, and from the
SSH user's, whichever account you log in as, and a page on another machine
cannot drive services that listen only on the server's loopback interface.

The zone of a TCP destination follows from its spelling, since the SSH server
resolves names: `localhost`, names under `.localhost`, `127.0.0.0/8`, `0.0.0.0`,
`::1`, `::`, those IPv4 addresses mapped into IPv6, and the
`*.tcp.outerssh.localhost` aliases are loopback; every other name and address is
another host. As in the URL standard, a host whose last label is a number is an
IPv4 address, and only the dotted-quad spelling is accepted, so shortened and
octal or hexadecimal forms such as `127.1` or `0x7f000001` are refused rather
than ranked. A name that the server resolves to its own loopback, such as a
`hosts` entry or a rebinding DNS name, still ranks as another host; services
that listen on loopback should check `Host` as they would behind any browser.

HTTP listeners check each request to a socket host or a loopback port before
forwarding it; requests to other hosts are not checked. The sender is the
endpoint named by `Origin`, or, without `Origin`, by the origin of `Referer`;
anything else, including `Origin: null`, is the lowest zone. A request to a
loopback port passes when the sender is on the SSH server: a loopback port or a
socket. A request to a socket passes when the sender is the destination socket,
has the same owner, or is root's; loopback ports rank with unknown owners, below
every socket. A request with neither `Origin` nor `Sec-Fetch-Site` acts as the SSH
user: browsers always send fetch metadata to these trustworthy hosts and
`Origin` with every write, so such a request comes from the application's own
code or the CLI user, who already act as the SSH user. It reaches loopback
ports and the SSH user's own sockets with any method, or every socket when the
SSH user is root.
From a lower zone, only these pass:

- `Sec-Fetch-Site: same-origin`, the socket's own page;
- a `GET` or `HEAD` without an upgrade that is a top-level navigation
  (`Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`), so links from
  other pages still open the socket's app, though frames do not;
- a `GET` or `HEAD` without an upgrade with `Sec-Fetch-Site: none`, an address
  the user typed or bookmarked;
- a `GET` or `HEAD` without an upgrade that has neither `Origin` nor
  `Sec-Fetch-Site`, such as the application's icon and manifest fetches from
  other accounts' sockets.

These are the only requests from other hosts that reach loopback ports.

Anything else gets `403 Forbidden`: images, scripts, frames and fetches from
other pages, form posts, and WebSocket handshakes. Browsers set these headers
and pages cannot forge them; a repeated `Origin`, `Referer`, or `Sec-Fetch-Site`,
`-Mode` or `-Dest` header is refused. When a socket's
owner is not known until the socket is authorized, the request is held and
its sender is judged as soon as authorization reveals the owner, before the
connection is prepared: a refused request gets `403 Forbidden` without any
stream to the socket, sudo bridge, or sudo password question. `CONNECT` tunnels to socket hosts and
loopback ports are always parsed as HTTP so each request inside them is checked;
a tunnel to another account's socket that does not carry HTTP is closed, while
one to a loopback port or the SSH user's own socket passes it through, so TLS to
a loopback port works but is not judged. Every SOCKS listener inspects the same
way: streams to sockets and loopback ports are always parsed as HTTP/1.1, while
streams to other hosts stay byte-transparent unless the listener rewrites
HTTP. A tunnel has sent no request when it opens, so its
connection may reach a socket directly but not through sudo: when the socket
needs a sudo bridge, the tunnel opens without a connection, and its first
request connects once it passes the rule, so only a request such as a
navigation into root's app can start a bridge or ask for the sudo password.
That connection's failure is answered with `502` inside the tunnel, and a
tunnel to such a socket that does not carry HTTP is closed. Connections with the listener's own credentials are the
application's code or its web view, and get the rule above.

Content that is not a web page, such as an Outerframe, makes its requests with
URLSession, so its traffic is treated as web requests. It connects with origin
credentials (`outerssh_socks_proxy_server_add_origin_credentials`) naming the
web origin it was loaded from, such as `http://<encoded>.unix.outerssh.localhost`
or a TCP origin. Those connections are decided once, when they open, by the
credential's origin and the destination, never by what the client sends.
Content from the SSH server reaches every TCP destination, the origin socket
itself, and sockets with the origin socket's owner; content from root's sockets
reaches every socket, and content from a loopback port has no owner, so it
reaches no socket. Content from another host reaches only that host and port.
Any other connection fails the SOCKS request with "connection not allowed"; when the
destination's owner is not known until the socket is authorized, the SOCKS reply
waits for that, and a refused connection fails right after authorization,
before any stream, sudo bridge, or sudo password question. An allowed connection's bytes are relayed untouched in both
directions, without HTTP parsing or rewriting, since every destination it
reaches is one its owner could already send any request to.

The Windows helper refuses a pipe without another account's SID whose server
is elevated or runs as a different account. A `GET` that changes state is still
reachable from any page; applications must not offer one.

Every new socket path is checked against the remote allowlist, including the
default Outer Shell socket. This also guards direct OpenSSH stream-local
forwarding, which otherwise has no knowledge of our allowlist. OuterSSH chooses
direct forwarding or a bridge based on the remote socket service’s preparation result. Host
applications describe the endpoint without selecting a privilege mode. They may
use their own path heuristics for presentation, independently of OuterSSH.
A connection whose sender is judged only once the socket's owner is known
carries that sender, and the pool judges it after authorization and before
preparing the connection; a refusal fails the connection with "connection not
allowed" and posts no `OUTERSSH_EVENT_CONNECTION_FAILED`. Sudo is therefore
used only for connections the rule allows.
OuterSSH starts sudo bridges without a password first, including replacements
for failed bridges. When sudo needs one, it asks the host application with
`OUTERSSH_EVENT_SUDO_PASSWORD_NEEDED`; connections from one proxy to the same
socket share the question. Every application with a proxy must answer it, with
`outerssh_session_pool_provide_sudo_password` or, when it cannot prompt,
`outerssh_session_pool_decline_sudo_password`, which fails the connections.
OuterSSH starts the bridge with the password and clears its copy. If sudo
rejects the password, it asks again with the error until the application
declines. Failure detection retires failed
bridges inside OuterSSH. The pending connections stay subject to cancellation
and the listener's timeout.

There is no registered-route table. SOCKS hostnames determine destinations;
authorization success continues directly into connection setup. The pool owns
its socket service and current bridges with their privilege modes. Pool shutdown
stops both the service and the bridges. Friendly names remain browser-level
metadata.

Every frontend reports the original error when socket preparation or channel
opening fails. The pool posts
`OUTERSSH_EVENT_CONNECTION_FAILED` before the rejection, identifying the listener
port, requested host and port, and Unix socket path. Cancelled connections do not
produce events. SOCKS carries only a failure status, so the Mac app
forwards these diagnostics over its control channel. Its error page accepts either
notification order, and only a failed top-level navigation changes the page.
Embedded-request diagnostics are retained separately. Remote socket navigation
failures show their connection error rather than triggering installation recovery;
Outer Shell availability discovery still runs independently.

`HelperProtocol.h` defines socket-bridge framing and parsing, independent of
the SSH transport that uses it.

Build the `outerssh` scheme for macOS, iOS, or the iOS simulator. Vendor build
settings live in `OuterSSH.xcconfig`. Existing flow tests live in `../Scripts`;
they exercise internal implementation files directly. To test the exported
library independently after a macOS build:

```sh
OUTERSSH_PRODUCTS_DIR=/path/to/Build/Products/Debug \
    bash OuterLoop/Scripts/test_outerssh_library.sh
```

Run `bash OuterLoop/Scripts/test_otqueue_contract.sh` on macOS to test the scheduling
contract and Apple's per-job autorelease pool under sanitizers.

## Apple crypto backend

Apple builds accept `OUTERSSH_CRYPTO_BACKEND=apple` (default) or `openssl`.
Pass the setting to the entire Xcode build, or set it in `OuterSSH.xcconfig`.
The public C API is identical. Linux uses OpenSSL. Windows defaults to CNG, described
below. The Android browser defaults to Android platform crypto
(`OUTERSSH_ANDROID_CRYPTO`, Gradle property `outersshCrypto=android`).

With `OUTERSSH_ANDROID_CRYPTO=ON`, the CMake target builds the JNI bridge in
`platform/android`, which calls the Java class `org.outerssh.AndroidCrypto`. Apps add
`platform/android/java` to their Java sources, keep that class's public static methods
from shrinking, and call `outerssh_android_initialize` (`OuterSSHAndroid.h`) from their
native library's `JNI_OnLoad`.

```sh
xcodebuild -project OuterLoop/OuterLoop.xcodeproj -scheme OuterSSHCLI \
    -configuration Debug -derivedDataPath /tmp/outerssh-apple \
    OUTERSSH_CRYPTO_BACKEND=apple build

xcodebuild -project OuterLoop/OuterLoop.xcodeproj -scheme 'OuterLoop Mobile' \
    -configuration Debug -destination 'generic/platform=iOS' \
    -derivedDataPath /tmp/outerssh-apple-mobile OUTERSSH_CRYPTO_BACKEND=apple build
```

Use scheme `OuterLoop` for the macOS app, or `outerssh` for the library alone.
Use `OUTERSSH_CRYPTO_BACKEND=openssl` to switch back. Separate derived-data paths
make comparisons easier, but changing the backend in the same path is supported.
No export-compliance declarations or shipping defaults are changed by this option.

The Apple backend calls public OS APIs only: CryptoKit for AES-GCM, Curve25519,
Ed25519 and elliptic-curve operations; CommonCrypto for AES-CTR, hashes and HMAC;
and Security for RSA, ECDSA digest signatures and secure random bytes. It does not
build or link OpenSSL, bundled Blowfish, bcrypt, or the OpenSSH ChaCha construction.
SSH framing, key encoding, and SSH's hash-based key derivation remain in OuterSSH.
The existing macOS 14.6 and iOS/iPadOS 17 deployment targets are unchanged. AES-GCM
uses CryptoKit's copying APIs available on those versions; it does not require
the macOS 27 in-place APIs used by the separate benchmark experiment.

| Capability | Apple backend |
| --- | --- |
| Packet ciphers | AES-128/256-GCM; AES-128/192/256-CTR |
| Key exchange | Curve25519 (both SSH names); ECDH NIST P-256/384/521 |
| Host signatures | Ed25519, ECDSA P-256/384/521, RSA SHA-256/512 |
| MACs | SHA-2 HMAC, including encrypt-then-MAC; existing SHA-1 HMAC compatibility |
| Private-key files | Unencrypted OpenSSH Ed25519/ECDSA/RSA, RSA PKCS#1 PEM, CryptoKit-supported EC PEM |
| Other authentication | Password, keyboard-interactive, and SSH agent where available |

The Apple backend does not offer finite-field Diffie–Hellman, OpenSSH ChaCha20,
RSA/SHA-1 signatures, or legacy CBC ciphers. Servers requiring those algorithms
cannot connect. Encrypted private-key files and security-key file import return an
explicit unsupported-format error. An SSH
agent can perform signing for keys whose files OuterSSH cannot import. This does
not add agent support to iOS. App-generated Ed25519 identities work directly.

RSA OpenSSH keys are converted in memory to the PKCS#1 representation required by
Security, including deriving the two CRT exponents. RSA signing uses Security.

Run the local OpenSSH interoperability and archive-content checks:

```sh
bash OuterLoop/Scripts/test_apple_rsa_import.sh
python3 OuterLoop/Scripts/test_apple_crypto.py /tmp/outerssh-apple/Build/Products/Debug/outerssh
python3 OuterLoop/Scripts/test_outerssh_cli.py /tmp/outerssh-apple/Build/Products/Debug/outerssh --apple-crypto
OUTERSSH_CRYPTO_BACKEND=apple \
    OUTERSSH_PRODUCTS_DIR=/tmp/outerssh-apple/Build/Products/Debug \
    bash OuterLoop/Scripts/test_outerssh_library.sh
OUTERSSH_CRYPTO_BACKEND=apple \
    SSH_REKEY_PRODUCTS_DIR=/tmp/outerssh-apple/Build/Products/Debug \
    bash OuterLoop/Scripts/test_olibssh_rekey.sh
```

The rekey suite covers all four key-exchange families, all five ciphers, and
cancellation, timeout and disconnect at NEWKEYS, with ASan/UBSan on the instrumented
C transport/reactor/exchange paths. It also checks fragmented packets, write retries,
and authentication-tag rejection. The interoperability suite checks Ed25519,
ECDSA and RSA identities and host keys against OpenSSH with server-initiated rekeying.
Tests use disposable loopback servers and generated identities.

## Pools and proxy listeners

Create an `OuterSSHEventQueue` with `outerssh_event_queue_create`, then pass it to
`outerssh_session_pool_create`. Pass that pool to either proxy create API. Each
pool creates its own serial control queue, which its proxy servers and port
forwards share. Each underlying SSH session has a separate reactor queue for SSH
and relay I/O, so pools and sessions run in parallel. A jump host, in this event queue
or another, is reached through asynchronous hops to its own control queue. Each
proxy forwards through the pool supplied at creation. Public APIs remain
callable from any thread.

The event queue receives the events of every pool and frontend created in it and
nothing else. Servers retain their pool's queue. Destroy the pools and servers
first, and destroy the event queue after each has posted `OUTERSSH_EVENT_DESTROYED`.

`SSHSessionPool.h` represents a remote server/account and its authenticated SSH
sessions. A pool owns authentication, commands, keepalives, remote-platform
knowledge, socket authorization, installed bridge executables, running bridges,
and socket availability notifications. Its configuration supplies the host-key
policy; packaged bridge binaries are requested with a question event. Commands
work without a proxy.

`SSHSocketService.c` owns one lazy `outerssh-helper service` process per pool.
It shares an installed executable with user traffic bridges, but has its own SSH
channel and never enters the bridge-routing table. It multiplexes authorization
requests and socket watches using request IDs on the existing framed transport.
Successful authorizations are cached for the pool's lifetime, including across
socket-service restarts. Concurrent requests for the same path share a lookup;
failures are not cached. Removing an allowlist entry takes effect for direct-streamlocal
connections when a new pool is created, rather than revoking an existing pool's authorization.
Privileged traffic bridges still enforce the system allowlist at each open.
The socket service runs as the SSH user, so the system allowlist must be readable
by that user (for example, mode 644 and owned by root); a root-only allowlist
rejects every root-owned socket before sudo is requested.

The service uses a one-shot timer for the earliest request timeout (30 seconds),
silence timeout (45 seconds), or needed restart (5 seconds after channel loss).
Deadlines use elapsed monotonic time. Replies and watch removal update or disarm
the timer; there is no periodic local tick. The reactor still exchanges service
heartbeats every 15 seconds, and the remote service still polls watched paths.

Call `outerssh_session_pool_watch_socket` to subscribe to an allowlisted path,
including one that does not exist yet. Its completion reports whether the
subscription succeeded. `OUTERSSH_EVENT_SOCKET_AVAILABILITY` events report an
initial state and changes, independent of how traffic reaches that path. Path
bytes stay valid until the next poll; copy them before dispatching work elsewhere.
Missing sockets are debounced for three seconds after being present. Permission
or observation failures leave the state unknown rather than reporting absence.
A service exit fails pending requests and restarts established watches after a
five-second delay. `outerssh_session_pool_unwatch_socket` removes a subscription.
A socket file can outlive its server. When a connection finds nothing listening
at a watched path (`OUTERSSH_SESSION_ERROR_NOT_LISTENING`: the server's connect
failed, or the helper reported `OPEN_NOT_LISTENING` or could not start its
bridge), the pool reports that path unavailable. The helper reports a present
socket again when a new one replaces it, by device, inode and change time.
Destroying the pool stops its service, cancels its retry timer, and completes
pending requests. Application work dispatched by notifications owns its data and
may outlive the pool.

`OuterSSHSOCKSProxyServer` owns the local SOCKS listener and its credentials. It
always inspects streams made with its own credentials with the HTTP frontend:
streams to sockets are parsed as HTTP/1.1, and streams to TCP destinations carry
raw bytes unless its configuration enables HTTP rewriting, which then applies to
plaintext HTTP/1.1 after the SOCKS handshake. Origin credentials let other
clients share the listener: their connections are decided when they open by the
web origin that loaded them and then relayed untouched.
Create it with `outerssh_socks_proxy_server_create(pool, configuration, error)`,
then call `outerssh_socks_proxy_server_start` with the desired port. Configuration
strings are copied; NULL configuration credentials are generated.
`OuterSSHHTTPProxyServer` uses the same authentication policy, lifecycle and
origin credentials, with HTTP-specific realm and rewriting options. Its origin
credentials decide a CONNECT tunnel when it opens and each other request on its
own, by that request's Proxy-Authorization and destination, without rewriting. Both default to password authentication;
`OUTERSSH_PROXY_AUTHENTICATION_NONE` explicitly disables it and requires NULL credentials.
Every request uses this fixed pool, which also supplies the control queue.

A pool can serve multiple SOCKS and HTTP frontends. Each frontend has independent
credentials and stream ownership. Stopping one closes its listener, cancels its
pending requests, and schedules closure of its relays and bridge streams, leaving
other frontends and the pool's SSH sessions usable. A generation distinguishes
successive runs so restarting cannot revive old requests or recover old relays.

Start and stop operations run in order on the control queue. Each accepted
request posts exactly one completion event. Start on an active server returns
the existing endpoint if the port matches. After stop or failed startup, call
start again to retry.

`OuterSSHPortForward` represents one fixed TCP destination on one pool.
Create it with `outerssh_port_forward_create(pool, host, host_length, port, error)`,
then call `outerssh_port_forward_start` with a local port (zero selects an
available port). Startup reports the listening port without proxy credentials.
`outerssh_port_forward_stop` closes the listener and schedules its streams for
closure; start can listen again through the same pool. Failed startup can
also be retried. `outerssh_port_forward_destroy` finishes teardown; wait for its
`OUTERSSH_EVENT_DESTROYED` before destroying the pool. The destination bytes are copied at
creation and resolved remotely. Traffic has no proxy negotiation or HTTP rewriting.

Pool disconnect rejects new work, stops its bridges, waits for installations
already in progress, attempts executable cleanup, then tears down SSH sessions.
Outstanding operations still complete. The caller owns the pool and calls
destroy once, after finishing submissions. Before destroying a pool, submit destruction
for every HTTP and SOCKS frontend. These requests can be submitted immediately
before pool destruction on the pool's control queue.
Pool destruction asserts that every frontend has begun teardown. Each destroy
request posts `OUTERSSH_EVENT_DESTROYED` after the object is freed, its owned
contexts are destroyed, and its reactors finish socket-source cancellation and
DNS work. Remote cleanup is best effort; destruction has no error result.

Server destruction is the final queued operation. The server also counts its
outstanding asynchronous forwarding stages, including sudo prompts and bridge
setup, and frees itself after they finish. Do not submit calls after requesting
destruction, including while handling its earlier events. The proxy reactor independently
waits for socket-source cancellation handlers and DNS lookups before freeing its
storage; server destruction waits for that final cleanup too. All these counts
belong to the control queue.

Pool destruction waits for pending operations and session teardown.
Operations are counted from their first control-queue step
through their reply. Nested steps covered by a parent operation need no separate count.
Sessions remain counted after removal until their reactor destruction reports back
to the control queue, so callbacks already sent by a reactor reach the pool first.
Public calls copy inputs and submit work before returning; callers must finish
submitting before requesting destruction. All pool lifecycle bookkeeping runs on
the control queue without atomics or queued retain/release calls.

On Apple platforms, `SSHConnection` (`SSHProxy/SSHConnection.h`) owns an event queue
whose events source targets the connection's serial queue, drains events on that
queue when the event queue reports them, and records each tagged request as a typed record that one switch
completes. Closing it destroys its proxy servers and pool, waits for every
outstanding request, including the destroys, and then destroys the event queue.

Proxy credentials authorize access to the proxy's fixed pool. That pool checks
its remote socket allowlist. Every event carries its pool so the host can
identify the corresponding server/account.

SOCKS negotiation and forwarding setup run on the pool's control queue. After the
remote connection succeeds, the proxy drains its SOCKS reply, cancels its socket
watches, and transfers the socket to the SSH reactor for relay or bridge I/O.
There is no second loopback connection.

## Linux

The Linux build supports GCC and Clang and requires CMake 3.24 or newer,
OpenSSL, and zlib. It compiles the retained libssh2 sources in `olibssh/libssh2` directly
into OuterSSH. It does not use the distribution's libssh2 or require
a Swift runtime. `../Scripts/Linux/Dockerfile` supplies a reproducible Ubuntu
24.04 toolchain. Applications watch each event queue's eventfd, for example with
`g_unix_fd_add`.

Nullability annotations use `OTNullability.h`: Clang retains the annotations and
other compilers omit them.

From the repository root (use `CC=gcc` to build with GCC):

```sh
CC=clang cmake -S OuterLoop/OuterSSH -B /tmp/outerssh-linux -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DOUTERSSH_BUILD_TESTS=OFF
cmake --build /tmp/outerssh-linux
```

CMake consumers can use `add_subdirectory` and link `OuterSSH::OuterSSH`, which
carries the include paths and link dependencies. The archive includes the
retained libssh2 code. Linux links OpenSSL and zlib separately; Apple bundles
OpenSSL into the archive only when that backend is selected.
The public API is unchanged; Linux hosts supply their own configuration and
answer host-key and packaged-binary questions. The integration test is a complete C
consumer of that API. There is no Linux XPC service or browser executable here.

Run the Docker tests from the repository root:

```sh
bash OuterLoop/Scripts/test_outerssh_linux.sh
OUTERSSH_LINUX_COMPILER=gcc bash OuterLoop/Scripts/test_outerssh_linux.sh
```

The script builds the test image, mounts the repository read-only, and keeps
build products in separate `outerssh-linux-build-clang` and
`outerssh-linux-build-gcc` Docker volumes. SSH keys, the test
user, allowlist, OpenSSH server, and echo servers live in the disposable container.
No ports are published and no configured remote servers are contacted. The image
and build volume are retained for subsequent runs.

Tests cover the public library, internal C flows, host-key rejection, private-key
and password authentication, concurrent commands, binary stdin, SOCKS
credentials, TCP/direct Unix/bridge relays, half-close, failed connections, local
socket resets, and shutdown. The rekey matrix exercises three key exchanges and
three ciphers, including cancellation, timeout, and disconnect at NEWKEYS.
AddressSanitizer, UndefinedBehaviorSanitizer, and leak detection are enabled.

Docker selects its native architecture by default. To test another architecture
with Docker emulation, set `OUTERSSH_LINUX_PLATFORM=linux/amd64` or `linux/arm64`;
the script uses a separate image and build volume for each explicit platform.
`OUTERSSH_LINUX_IMAGE` and `OUTERSSH_LINUX_BUILD_VOLUME` override those names.

## Android

Android uses the same queue implementation as Linux. A standalone NDK build runs
the queue and source contract (`test_otqueue_contract.c`) on an emulator or
device:

```sh
bash OuterLoop/Scripts/test_otqueue_android.sh
```

Outer Loop's `OuterLoop/Scripts/Android/README.md` covers the dependencies,
configuration and coverage of these native tests. Outer Loop's Android browser
links OuterSSH through JNI, watches each session's event queue eventfd on a thread
and routes WebView traffic through OuterSSH's authenticated HTTP proxy.

## Windows

Windows builds default to `OUTERSSH_WINDOWS_CRYPTO=ON`. OuterSSH and its CLI use
Windows CNG (`bcrypt.dll`) and Crypt32 for cryptographic operations and RSA PEM
parsing; they do not require, link, or fall back to OpenSSL. The minimum OS is
Windows 10. Other products linked alongside OuterSSH can independently use OpenSSL.
To build the alternative OpenSSL backend, explicitly pass
`-DOUTERSSH_WINDOWS_CRYPTO=OFF` and install OpenSSL 3.

The native backend supports:

- Curve25519/X25519 and NIST P-256/P-384/P-521 key exchange.
- RSA-SHA2 and ECDSA server signatures and user identities; password authentication.
- AES-128/256-GCM and AES-128/192/256-CTR, SHA hashes and HMAC through CNG.
- Unencrypted OpenSSH RSA/ECDSA private keys, from files or memory, and unencrypted
  PKCS#1 RSA PEM keys. Public keys can be derived from these private keys.

Ed25519 and security-key identities are not offered. A server must have a usable
RSA or ECDSA host key, even when logging in with a password. Existing Ed25519
identities must be replaced with RSA/ECDSA identities or password authentication.
Encrypted OpenSSH private keys are rejected explicitly: their bcrypt password KDF
is not supplied by CNG. ChaCha20-Poly1305 is not advertised. AES-CTR uses the CNG AES
primitive with SSH's counter construction; no AES implementation is bundled.

`olibssh/libssh2/wincng.c` and `wincng.h` derive from libssh2 1.11.1's BSD-licensed
WinCNG backend, adapted to OuterSSH's interface. Local changes include bounded
OpenSSH RSA/ECDSA import, ECDSA signature bounds and resource cleanup, and canonical
shared-secret encoding. `wincng_extra.c` supplies native X25519 and packet AES-GCM.
X25519 is independent of the Ed25519 feature flag. GCM authenticates packet length,
rejects tampered data, and refuses to reuse a nonce after counter exhaustion.

`outerssh-windows-crypto-test` checks RFC 7748 and independent AES-GCM vectors,
including low-order X25519 peers and tag rejection. The optional
`Scripts/test_windows_crypto_interop.py` fixture uses Paramiko/cryptography on the
fixture host to force individual KEX/cipher/host-key combinations and test accepted
and rejected private-key formats against `outerssh-authentication-test`. Those
Python dependencies belong to the test server, not to OuterSSH.


Windows applications watch each event queue's manual-reset event, for example
with a thread-pool wait.
`OTQueueWindows.c` needs nothing newer than Windows 10. Each queue drains
through one thread-pool work object, so it runs serially while queues share
the process thread pool. Each socket has one `WSAEventSelect` registration and
a thread-pool wait. Winsock events report changes, so sources also check
readiness with `select` when interest is enabled and after delivering
readiness; a consumed notification cannot strand pending work. Each timer is a
thread-pool timer, and background work runs as long-running thread-pool
callbacks. It does not use `ProcessSocketNotifications` (Windows 11 and Server
2022) or `WSAPoll`, which does not report failed connections before Windows 10
version 2004. The clock is `QueryUnbiasedInterruptTimePrecise`, looked up at
run time, with `QueryUnbiasedInterruptTime` as the fallback.

`platform/OTSocket.h` supplies pointer-sized
Windows socket handles, normalized socket errors, nonblocking mode, inheritance
control, and shutdown for startup cancellation. Secure random
bytes come from BCrypt.

Use an ARM64 or x64 Visual Studio developer shell with MSVC, the Windows SDK,
CMake, Ninja, Git (`patch.exe`), and vcpkg. Install static dependencies for the
chosen architecture, then run:

```powershell
C:\path\to\vcpkg\vcpkg.exe install zlib:arm64-windows-static
powershell -NoProfile -File OuterLoop/Scripts/test_outerssh_windows.ps1 `
    -Compiler msvc -VcpkgRoot C:\path\to\vcpkg
```

MSVC builds enable `/experimental:c11atomics` for the standard C atomics used
by OuterSSH. To use native Clang instead, install it and pass `-Compiler clang`
(the default). The script keeps the two compilers' build directories separate;
`-BuildDirectory` overrides the location.

For x64, install the `x64-windows-static` dependencies and pass `-Architecture x64`
from an x64 developer shell. ARM64 is the configuration tested in the Parallels
VM, including MSVC 19.44 (Visual Studio 2022 17.14). These builds use the MSVC ABI
and static runtime, without MinGW, Cygwin, or Swift.

CTest runs initialization success/failure, the public-library test, all thirteen
flow suites, and the queue contract. `test_otqueue_contract.c` runs the queue and source
contract on the platform's implementation: FIFO ordering, overlapping background jobs, queue
lifetime, queue-specific value replacement/removal, 128 socket queues, initial
activation by resume, write backpressure, timer suspension and reset, and
cancellation behind queued work.
Windows test doubles for unused
flow dependencies abort if called; they accommodate COFF symbol resolution
without suppressing linker errors or weakening the test assertions.

The real-SSH integration client also builds on Windows. To supply a disposable
Linux server, first build the Linux test image and bridge binary with the Linux
test script, then run from the repository root on the Docker host:

```sh
mkdir -p /tmp/outerssh-windows-fixture
chmod 755 /tmp/outerssh-windows-fixture
docker run --rm --name outerssh-windows-fixture -p 22222:22 \
    --mount type=bind,src="$PWD",dst=/workspace,readonly \
    --mount type=bind,src=/tmp/outerssh-windows-fixture,dst=/fixture \
    --mount type=volume,src=outerssh-linux-build-clang,dst=/build,readonly \
    outerssh-linux-test python3 OuterLoop/Scripts/Windows/ssh_fixture.py
```

Use a fresh empty fixture directory for each server run. Copy `client`,
`host.blob`, `ready.json`, and `outerssh-test-bridge` from that directory into the
VM, then pass `-FixtureDirectory C:\path\to\fixture -SSHHost <Docker-host-address>`
to the PowerShell test script. The client verifies the generated host key and
uses disposable credentials. The bridge executable is a Linux binary because it executes
on the SSH server. Stop the container after testing and remove the fixture files.

This integration run exercises host-key rejection, key/password authentication,
concurrent commands, binary stdin, SOCKS credentials, TCP/direct Unix/bridge
relays, half-close, connection failures, local resets, and shutdown. The server
uses a small rekey limit to exercise rekeying during transfers. The separate
adversarial rekey matrix still uses its Unix process/socket harness and runs in
the Linux tests.

## Strings

Use `const char *` and a separate `size_t` byte length for string inputs, with
matching pointer and length fields for stored values. Text uses UTF-8; lengths
count bytes, not characters. The length is authoritative: callers need not
provide a null terminator, and code must not read `bytes[length]`. Copy exactly
the supplied bytes and retain the length when work moves between queues.
Ownership remains explicit and separate from the pointer/length pair.

Connection configuration and authentication follow this convention throughout
the pool, session pool, TCP connector, and session-start flow. The resolver
and libssh2's agent and passphrase APIs receive temporary terminated copies at
their boundaries. Those fields reject embedded null bytes instead of truncating;
password authentication serializes the supplied bytes and length directly into SSH packets.
Socket authorization, SOCKS credentials, bridge setup, availability/recovery callbacks,
HTTP rewrite context, and address/command helpers use the same convention. Generated
commands and addresses report their lengths; their outputs also retain a terminator
for OS and URL consumers. Swift callers pass `string.utf8.count`, and C++ callers
pass `string.size()`, rather than scanning the temporary C-string representation.

The exceptions are native Dispatch queue labels, printf-style format strings,
and libssh2-owned method names and errors.
These follow their underlying APIs' C-string contracts. Scans at those boundaries
are intentional; lengths are retained when ordinary text enters an OuterSSH flow.

Error values contain codes and borrowed message/detail pointers with byte lengths.
They have no inline text buffers and impose no diagnostic size limit. Callback
text stays valid until that callback returns. A consumer sending an error to
another queue must copy its text first, either into its native string/error type
or with `outerssh_error_copy`; the latter returns one allocation through
`storage`, which the consumer frees after its last use. Assigning the error struct
alone does not extend the text's lifetime.

Static errors borrow literals without allocation. Formatted errors allocate their
message with `outerssh_session_error_format` or `outersshpriv_error_format`;
the owning operation keeps that storage through its completion and then frees it.
Formatting also copies any underlying SSH detail into the same allocation.
Allocation failure preserves the error codes and substitutes a static diagnostic.

## HTTP proxy frontend

`HTTPProxyRewriter` takes a resolved route and owns the HTTP translation policy:
synthetic destinations receive the remote authority, while ordinary TCP
destinations retain theirs. Route resolution contains no HTTP rewrite policy or
intranet classification. The rewriter consumes parsed header fields and decoded response body bytes.
The frontend parses each message with llhttp, applies header rewrites during its
single serialization pass, and owns all transfer framing and connection reuse.
Frontends expose one option, `rewrite_loopback_addresses`, which enables both
header and HTML rewriting. Chromium clients that proxy localhost load loopback
URLs directly and normally leave it off. Socket and pipe requests keep the
browser's authority, as behind a reverse proxy, so applications generate URLs
for the socket endpoint. WebKit clients normally enable it.
The rewriter buffers only eligible HTML bodies when enabled, up to 2 MiB, and completes them at
the parser's message boundary; larger or encoded bodies pass through. Response
headers can be sent immediately while an eligible body is still being buffered.
The rewriter neither detects HTTP nor parses or produces HTTP message framing.


`HTTPProxyServer.h` exposes a pure-C, loopback HTTP/1.1 proxy. Pass its session
pool to `outerssh_http_proxy_server_create`, then start the listener. HTTP and SOCKS
use the same forwarding layer for routing, authorization, SSH channels, Unix
socket bridges, and sudo passwords. Browser traffic no longer passes through a
SOCKS listener or handshake.

One pool can serve a rewriting HTTP listener, a non-rewriting HTTP listener, and
a SOCKS listener simultaneously. Give HTTP listeners separate configurations and
credentials and configure both rewriting options independently for each listener.
All three can share one session reactor. Applications only need to start the endpoints their clients use.
Stopping one frontend closes its own streams. The caller keeps the pool alive
until its frontends are destroyed. HTTP framing uses a private socket pair to feed the socket-based SSH
reactor (a connected loopback pair on Windows); this is not a SOCKS connection.

HTTP supports optional Basic authentication and copies configuration strings.
Start/destroy callbacks run on its own serial queue; forwarding callbacks run on the SSH control queue. Destroy waits for client sockets,
forwarding operations, and dispatch-source cancellations.

The pinned MIT-licensed llhttp parser frames each request and response, including
Content-Length, chunked encoding, informational responses, HEAD/204/304, and
close-delimited responses. Each exchange gets its own transformer, finished at
message boundaries. Request bodies stream; eligible HTML bodies retain the
existing bounded buffering policy. Body responses are re-framed with chunked
encoding. Chunk extensions and trailers are consumed, not forwarded. Hop-by-hop
headers and proxy credentials are removed. A 101 response switches to a raw tunnel.
Pipelined requests are serialized; an upstream connection is reused only for the
same destination and when its previous response permits persistence. HTTPS stays
opaque. With rewriting enabled, the frontend recognizes an initial HTTP/1.1
request inside CONNECT and frames subsequent exchanges. This supports Apple
WebKit's plaintext HTTP tunnels and browsers that tunnel WebSocket handshakes.
TLS and other protocols stay opaque.
The macOS and iOS browsers use a rewriting SOCKS listener for WKWebView and a
non-rewriting SOCKS listener for outerframe networking and URLSession callbacks.
Both inspect requests to sockets. Both listener ports are retained in the
application endpoint; both listeners use the generated session credentials, and
each Outerframe load adds origin credentials for its origin on the
non-rewriting listener.

Run `bash OuterLoop/Scripts/test_http_proxy.sh` after building the Debug library
on macOS; `OUTERSSH_PRODUCTS_DIR` overrides its products directory. This compiles
the C frontend and parser under ASan/UBSan and substitutes a deterministic
transport at the internal forwarding call. CMake also exposes `outerssh-http-proxy-fixture` and the Python `http-proxy`
test. The macOS script also runs an isolated WKWebView against the authenticated
proxy to verify request and HTML rewrites and upstream connection reuse.
`test_outerssh_cli.py` covers HTTP-only and combined listeners over real SSH.
`test_ssh_authentication.c` checks authentication packet parsing, keyboard-interactive
rounds and fallback, allocation failures, agent algorithm fallback, and completion
ownership. The Linux integration runner adds disposable ssh-agent and PAM fixtures
for agent identity selection, supplied-key fallback, encrypted keys, RSA/ECDSA/
Ed25519, and keyboard-interactive login. `test_outerssh_authentication.c` also
checks cancellation with an outstanding host-key decision and approval delayed
beyond the authentication timeout without blocking the control queue.

`test_outerssh_shared_proxy.c` checks two authenticated HTTP frontends and SOCKS
sharing one session, credential isolation, independent shutdown,
TCP/Unix forwarding, and explicit removal before pool destruction.

## Throughput benchmark

[The streaming benchmark](../Scripts/benchmark_outerssh.md) measures Release-build
upload/download throughput and client CPU time through a real SSH connection,
using either an isolated local server or a remote host such as a Raspberry Pi.

## Application helper requests

`outerssh_session_pool_send_helper_request(pool, bytes, length, tag)` sends
request bytes to the application-defined handler of the helper the application
supplied, over the helper service channel, and completes with
`OUTERSSH_EVENT_HELPER_RESPONSE`. OuterSSH does not interpret the bytes. The
handler runs in the unprivileged service process as the SSH user; sudo bridges
only relay traffic. A helper without a handler, or a handler that rejects the
request, completes it with an error. Helpers answer any request frame they do
not support with a `RESULT` error and ignore unsupported frames with ID zero, so
the channel survives newer clients. Outer Loop uses this to find Outer Shell; see
`OuterLoopHelper/OuterLoopHelperRequests.h`.

## Server-defined homepage

A server can override a client's default homepage with a UTF-8 file containing
one absolute URL. User configuration takes precedence over system configuration:

| Server OS | User file | System file |
| --- | --- | --- |
| Linux / other Unix | `$XDG_CONFIG_HOME/outerssh/homepage` (if absolute), otherwise `~/.config/outerssh/homepage` | `/etc/outerssh/homepage` |
| macOS | `~/Library/Application Support/org.outerssh/homepage` | `/Library/Application Support/org.outerssh/homepage` |
| Windows | `%LOCALAPPDATA%\OuterSSH\homepage` | `%ProgramData%\OuterSSH\homepage` |

These locations sit alongside the standard OuterSSH configuration. Additional
socket allowlists supplied by an application do not change homepage lookup.

Example file contents:

```text
http+unix://%2Frun%2Fdashboard.sock/projects?view=active#overview
```

Or use a TCP service:

```text
https://localhost:8443/projects
```

Outer Loop's macOS, iOS/iPadOS, and Android clients support `http`, `https`, `http+unix`,
and `http+pipe`. Socket/pipe paths occupy the percent-encoded authority; the
following path, query, and fragment belong to the page. `localhost` means the
SSH server. The explicitly configured HTTP(S) origin stays in the server session,
including a publicly named host; unrelated Internet links retain normal client
behavior. URL credentials, relative addresses, and executable schemes are rejected.

`outerssh_session_pool_get_homepage` authenticates through the existing session
pool and reads the configuration asynchronously. Its
`OUTERSSH_EVENT_HOMEPAGE_RECEIVED` event carries the URL and source-path bytes.
`found` is false with no error when there is no override; the client supplies its
own default. Values stay valid until the next poll. The library retrieves the declaration;
clients interpret supported schemes and validate their navigation destinations.

Files are limited to 8192 bytes. Missing files and files containing only ASCII
spaces, tabs, CR, and LF fall through to the next level. Leading/trailing whitespace
is trimmed. Read failures, oversized files, and embedded whitespace/control bytes
produce errors rather than silently selecting another homepage. Clients report
invalid URL configuration with its file location.

Apple and Android clients resolve this once when establishing a server session and use the
result for initial navigation and the Home button. Establish a new session to
reread changes. A configured homepage takes precedence over Outer Shell discovery
and does not require Outer Shell to be installed. Loading failures remain errors
for that destination; they do not trigger Outer Shell installation or replacement.

A homepage declaration grants no endpoint access. Socket and named-pipe allowlists,
SSH forwarding restrictions, and existing privilege handling still apply.

Validation:

```sh
python3 OuterLoop/Scripts/test_homepage.py
bash OuterLoop/Scripts/test_mobile_remote_navigation.sh
```

The file-lookup tests use disposable configuration files and emulate the Linux and
macOS directory layouts; they do not change the machine's actual configuration.

## Endpoint names and icons

`outerssh_session_pool_observe_endpoint_names` delivers the server's
`endpoints.d` registry as a list of `OuterSSHEndpointRecord`s: each named
endpoint once, in registration order, with conflicting registrations left out.
Look up one endpoint with `outerssh_endpoint_records_find`, and keep records
past the next poll with `outerssh_endpoint_records_copy`.
Publishers register only endpoints that are running or start on connection,
so clients can offer the records as destinations.
See `docs/homepage-endpoint-names.md`.

The socket helper also keeps a per-user endpoint icon cache next to `endpoints.d`:

| Server OS | Directory |
| --- | --- |
| Linux / other Unix | `$XDG_CONFIG_HOME/outerssh/endpoint-icons` (if absolute), otherwise `~/.config/outerssh/endpoint-icons` |
| macOS | `~/Library/Application Support/org.outerssh/endpoint-icons` |
| Windows | `%LOCALAPPDATA%\OuterSSH\endpoint-icons` |

Files are named by the lowercase hex SHA-256 of the endpoint's canonical record
line plus `.png`, hold a validated PNG of at most 64 KiB and 512×512 pixels, follow
the user `endpoints.d` ownership and permission rules, and are replaced
atomically. The cache keeps at most 512 icons, evicting the least recently
written. `outerssh_session_pool_store_endpoint_icon` and
`outerssh_session_pool_get_endpoint_icon` use the socket service's
`STORE_ENDPOINT_ICON` (19), `GET_ENDPOINT_ICON` (20), and `ENDPOINT_ICON` (21)
frames; icons are fetched on request, never pushed with names. See
`docs/endpoint-icons.md`.

## Application-controlled socket bridge lifetime

OuterSSH exposes `outerssh_session_pool_get_bridges` to inspect running
traffic helpers, including their socket paths and whether they were launched
with sudo. Its identifiers are scoped to the pool and distinguish successive
helpers for the same path. The authorization/watch service is separate and is
not included.

`outerssh_session_pool_close_bridge` retires one identifier and schedules
closure of its SSH channel and all streams. It does not uninstall the executable,
disconnect the pool, or close another helper for the same path. Callers may
close an already retired identifier. Old stream failures cannot automatically
restart an intentionally closed helper. A new connection can start a new helper
through normal authorization and sudo handling; it does not inherit the previous
helper's privilege.

Outer Loop's macOS, iOS/iPadOS, and Android clients own the idle policy. They inspect helpers
once per second and close helpers that have been unused by current tab pages for
30 seconds. Background tabs count as open. Back/forward history and a browser page
retained behind the mobile Servers page do not. Returning during the grace period
resets it. An unprivileged homepage helper stays warm; a homepage helper launched
with sudo receives the same timeout as any other privileged helper. macOS applies
the policy to local root socket helpers as well.

The policy lives in the app, not OuterSSH or the remote helper. It reduces retained
privilege during normal operation; a compromised application can suppress its own
cleanup. Expiry does not change sudo configuration or clear sudo's timestamps.
Starting another privileged helper follows the server's policy at that time.

Regression checks:

```sh
bash OuterLoop/Scripts/test_socket_bridge_cleanup.sh
bash OuterLoop/Scripts/test_ssh_bridge_flows.sh
```
