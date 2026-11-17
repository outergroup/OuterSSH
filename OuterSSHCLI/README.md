# outerssh

`outerssh` is a pure-C command-line tool for macOS, Linux, and Windows, using
the same OuterSSH library as the browsers. It offers SOCKS5 and HTTP/CONNECT
listeners and fixed-destination TCP forwards, each connected directly to one shared SSH session pool. Neither
listener depends on the other. Both bind only to `127.0.0.1`. HTTP rewriting
and proxy authentication are disabled by default.

## Building

Run these commands from the folder that contains `OuterSSH/`: the root of the
OuterSSH repository, or `OuterLoop/` in the Outer Loop repository.

On macOS, install CMake, Ninja, and OpenSSL 3 (for example with Homebrew):

```sh
cmake -S OuterSSH -B build/outerssh -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
  -DOUTERSSH_BUILD_CLI=ON -DOUTERSSH_BUILD_TESTS=OFF
cmake --build build/outerssh --target outerssh
./build/outerssh/outerssh --help
```

In the Outer Loop repository, the `OuterSSHCLI` scheme in `OuterLoop.xcodeproj` also
builds it, using Apple's cryptography instead of OpenSSL.

On Linux, install a C17 compiler, CMake 3.24+, OpenSSL, zlib, and `patch`.
`Scripts/Linux/Dockerfile` provides a complete build and test environment. The CLI handles its event queue's events on a Dispatch queue on macOS
and on a thread that waits on the event queue's event handle elsewhere.

```sh
cmake -S OuterSSH -B build/outerssh -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DOUTERSSH_BUILD_CLI=ON -DOUTERSSH_BUILD_TESTS=OFF
cmake --build build/outerssh --target outerssh
./build/outerssh/outerssh --help
```

On Windows, use a Visual Studio developer terminal with Clang or MSVC, CMake,
Ninja, Git's `patch`, and vcpkg zlib. Windows uses native CNG by default;
OpenSSL is only needed when configuring `-DOUTERSSH_WINDOWS_CRYPTO=OFF`. For an x64 static build:

```powershell
cmake -S OuterSSH -B build/outerssh -G Ninja `
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang `
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  -DOUTERSSH_BUILD_CLI=ON -DOUTERSSH_BUILD_TESTS=OFF
cmake --build build/outerssh --target outerssh
.\build\outerssh\bin\outerssh.exe --help
```

For ARM64, also pass `-DCMAKE_C_COMPILER_TARGET=aarch64-pc-windows-msvc`
and use an ARM64 developer environment with `arm64-windows-static`.
`cmake --install build/outerssh --prefix <destination>` installs the executable
under `bin`. The CLI is built by default when configuring OuterSSH directly;
embedded library consumers can opt in with `OUTERSSH_BUILD_CLI=ON`.

OpenSSH's `ssh` must be on `PATH` at runtime on all platforms. Windows can use
its OpenSSH Client optional feature. Windows uses native synchronization and
console input; it does not require Foundation or a POSIX shell.

## Local port forwarding

```sh
outerssh -L 8080:localhost:8888 build-server
outerssh -L 8080:localhost:8888 -L 5433:db.internal:5432 -D 1080 --http-proxy 8081 build-server
outerssh -L '8080:[::1]:8888' build-server
```

Connect directly to `localhost:8080` to reach `localhost:8888` from the SSH server.
Each accepted connection opens a channel through the shared SSH session pool,
without SOCKS negotiation, HTTP parsing, or rewriting. Destination hostnames are
resolved remotely. Repeat `-L` for multiple destinations; a local port of `0`
chooses an available port and prints it.

This supports the `port:host:port` form of OpenSSH's `-L`, with bracketed IPv6
destinations. Listeners bind to `127.0.0.1`; custom bind addresses and Unix socket
forwarding syntax are not supported. Proxy credentials and `--rewrite-http` do
not apply to fixed forwards. A failure to bind any requested listener exits the
command and closes listeners already started.

## Connecting

```sh
# Resolve an alias using OpenSSH configuration, just like ssh.
outerssh -D 1080 build-server

# Use the configured user, port, identity, and agent settings.
outerssh -D 1080 user@server

# Use a specific private key, without consulting the agent.
outerssh -D 1080 -i ~/.ssh/id_ed25519 user@server

# Prompt for an encrypted private key's passphrase.
outerssh -D 1080 -i ~/.ssh/id_ed25519 --ask-passphrase user@server

# Prompt for an SSH password.
outerssh -D 1080 --password user@server

# Use a different SSH port or let the OS choose the proxy port.
outerssh -D 0 -p 2222 user@server
```

The tool runs `ssh -G` to resolve `Host` aliases, `Include` files, and
OpenSSH's configuration precedence. It uses the resolved hostname, username, port,
first existing identity file, agent settings, and first `UserKnownHostsFile`.
OpenSSH's dump does not quote paths; use `--known-hosts` if a list of relative
known-host paths is ambiguous because of spaces.
`-p`, `-l`, `user@host`, `-i`, and `--known-hosts` override configured values;
`-F path` selects an alternate SSH config. `IdentityAgent none` disables the
agent. On Windows, the default agent is the OpenSSH named pipe
`\\.\pipe\openssh-ssh-agent`; `IdentityAgent` can select a different pipe.
`IdentitiesOnly yes` selects the configured private key without trying
unrelated agent identities. `HostKeyAlias` controls host-key lookup when present.

The tool verifies host keys against the selected known-hosts file (normally
`~/.ssh/known_hosts`), including hashed host entries. Unknown keys display a SHA-256 fingerprint and require typing `yes` in
the terminal before the key is appended. Changed keys are rejected.
`--known-hosts path` selects another file. `--batch` rejects unknown keys and
options that would require a credential prompt.

The ready message on stderr reports the actual proxy port after SSH authentication
and listener startup succeed. Ctrl-C (or Ctrl-Break on Windows, SIGTERM on Unix)
closes the listeners, active forwarding connections, and SSH session. Startup errors exit nonzero; individual
forwarding failures are reported on stderr without stopping the proxy.

## HTTP proxy and persistent rewriting

```sh
outerssh -D 1080 --http-proxy 8080 --rewrite-http build-server
```

This runs both listeners. The path for Chrome is
`Chrome → HTTP proxy :8080 → SSH → remote service`.
The SOCKS listener independently opens channels on the same SSH session pool.
With `--rewrite-http`, both listeners use the same HTTP framing and transformations. Repeated requests on one
browser connection are rewritten independently, and upstream SSH channels
are reused for the same destination when the server permits it. Neither side
is forced closed after each exchange. If an origin closes its connection, the
HTTP proxy can keep the browser connection and reconnect upstream.

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir=/tmp/outerssh-http-chrome \
  --proxy-server="http://127.0.0.1:8080" \
  --proxy-bypass-list="<-loopback>"
```

Omit `--rewrite-http` to disable transformations on both listeners.
Omit `-D` to run only HTTP; `--http-proxy 0`
allocates an ephemeral HTTP port. `--proxy-user` and `--proxy-password-env` apply
to both listeners. Without them, both listeners require no authentication.

The HTTP listener accepts HTTP/1.1 proxy requests, including chunked uploads,
`Expect: 100-continue`, and pipelining (processed one exchange at a time).
Responses with bodies are sent using chunked framing, including responses that
were originally delimited by connection closure. Chunk extensions and trailers
are consumed rather than forwarded. Successful WebSocket upgrades become opaque
streams. CONNECT accepts HTTP/1.0 or HTTP/1.1; HTTPS content is not rewritten. With rewriting enabled,
plaintext HTTP/1.1 inside CONNECT is framed and rewritten before an upgrade;
this also covers browsers that tunnel WebSocket handshakes.

Host, Origin, Referer, and eligible HTML transformations
use the existing OuterSSH rules. The CLI does not inject `X-Outer-Loop-User`;
application frontends supply their own identity metadata. HTML rewriting still buffers eligible uncompressed
bodies up to 2 MiB, now until the message ends rather than until the socket closes.
Larger bodies stream unchanged. Chunked HTML is now eligible because the HTTP
proxy decodes its framing before transformation. Regular `localhost` URLs do not
trigger HTML loopback-URL rewriting; that applies to OuterSSH synthetic aliases.

To enable rewriting with only a SOCKS listener:

```sh
outerssh -D 1080 --rewrite-http build-server
```

Plaintext HTTP/1.1 after the SOCKS handshake uses the same inspection as CONNECT
payloads, including subsequent requests on reused connections. WebSocket upgrades
and opaque traffic pass through; HTTPS is not decrypted. Without `--rewrite-http`,
SOCKS relays raw bytes to TCP destinations. Streams to remote Unix sockets are
always parsed as HTTP/1.1 so the socket owner rule applies to each request; opaque
bytes reach only the SSH user's own sockets, since the CLI's own connections are
trusted like an application's. The flag requires `-D` or `--http-proxy` and applies to all
proxy listeners, but never to fixed `-L` forwards. Rewriting does not force ordinary
HTTP connections to close.

## Comparing with OpenSSH in Chrome

Run either proxy on the same port, stopping one before starting the other:

```sh
outerssh -D 1080 -i ~/.ssh/id_ed25519 user@server
ssh -N -D 127.0.0.1:1080 -i ~/.ssh/id_ed25519 user@server
```

Launch a separate Chrome profile:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir=/tmp/outerssh-chrome \
  --proxy-server="socks5://127.0.0.1:1080" \
  --proxy-bypass-list="<-loopback>"
```

Opening `http://localhost:8080` then reaches port 8080 on the SSH server.
Chromium documents the [loopback bypass override and SOCKS5 limitations](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md).
Quit that Chrome instance between runs to reset its connections. Use the Release
build, the same remote service and credentials, and consistent browser cache state
for comparisons. OuterSSH and OpenSSH may negotiate different SSH algorithms.

A smaller forwarding check is:

```sh
curl --proxy socks5h://127.0.0.1:1080 --noproxy '' http://localhost:8080/
```

## Jump hosts (`-J`)

Use OpenSSH-style `-J [user@]host[:port]` to reach a server through a gateway:

```sh
outerssh -J alice@gateway.example.com:2222 -L 8080:localhost:8080 alice@build-server
outerssh -J gateway1,user@gateway2:2222 -D 1080 private-server
outerssh -J 'user@[2001:db8::1]:2222' -D 1080 private-server
```

The first command exposes build-server's port 8080 at `localhost:8080` on this machine.
The gateway only needs SSH TCP forwarding permission; shell access is not required.
The listener's destination is reached from the final SSH server.

A single `-J` option accepts multiple hops separated by commas, in connection order.
The attached form (`-Jgateway`) and SSH URI form (`-J ssh://user@gateway:2222`)
are also accepted. Routes are limited to 16 gateways. Use `-J none` to override a
configured `ProxyJump` and connect directly.

Without `-J`, the CLI follows `ProxyJump` from `~/.ssh/config` (or `-F config`):

```sshconfig
Host private-server
    HostName build-server
    User alice
    ProxyJump gateway

Host gateway
    HostName gateway.example.com
    User alice
    Port 2222
    IdentityFile ~/.ssh/gateway_key
```

Then run `outerssh -D 1080 private-server`. Each gateway uses its own host
configuration, identity or agent, and host-key verification. Destination flags
such as `-i`, `-l`, and `-p` do not set credentials or ports for gateways; configure
them in their own `Host` entries or use the user and port fields in `-J`.
`--known-hosts` and `--batch` apply to the entire route.

## Optional proxy credentials

```sh
outerssh -D 1080 --proxy-user test user@server
```

This prompts separately for a proxy password. When an HTTP listener is enabled,
the same credentials protect both listeners. For automation,
`--proxy-password-env VARIABLE` reads it from a named environment variable instead.
These credentials govern access to the local proxy; they are separate from SSH
credentials. Chrome does not support SOCKS5 username/password authentication; use the HTTP
listener for authenticated Chrome testing, or omit credentials with SOCKS. Authenticated listeners never fall back
to unauthenticated access.

This is a focused TCP forwarding tool, not a complete OpenSSH frontend. It uses
OpenSSH to resolve configuration, but OuterSSH still owns every SSH connection, including
jump hosts. `ProxyCommand`, remote commands, and UDP are unsupported. It follows Outer Loop's first-existing-key
selection rather than OpenSSH's full sequence of authentication methods. Encrypted
keys require `--ask-passphrase` unless the configured agent can unlock them. It does
not package the remote Unix socket bridge helpers. SSH passwords and key passphrases are read from a terminal,
not command-line arguments.

## Tests

After building, run the integration fixture with the executable's absolute path:

```sh
python3 Scripts/test_outerssh_cli.py /path/to/outerssh
bash Scripts/test_proxy_socks_handshake.sh
bash Scripts/test_ssh_listener_flows.sh
```

The integration test runs on macOS and Linux using `sshd`, `ssh-keygen`, `ssh-agent`, and `ssh-add`.
It starts only loopback listeners and generates keys, an SSH configuration, a
known-hosts file, and an isolated agent in a temporary directory. It does not
modify the user's SSH configuration, keys, agent, or system SSH service.

`test_outerssh_cli_remote.py` also runs natively on Windows. Supply an isolated
SSH config/alias, an echo server port on the SSH host, and the `HTTPOrigin` fixture
from `test_outerssh_cli.py` on that host:

```sh
python3 Scripts/test_outerssh_cli_remote.py /path/to/outerssh \
  --config /path/to/test-config --user remote-user --echo-port 9001 --http-port 9002
```

This exercises raw local forwarding, SOCKS-only, HTTP-only, both listeners, proxy authentication,
repeated rewriting, binary CONNECT traffic, and graceful shutdown. It uses
generated/trusted batch credentials supplied by the fixture; on Windows it
creates a console for the child and sends Ctrl-Break to test native teardown.

Outer Loop exposes session identity to its app content through
`window.outerLoop.sessionContext` (a frozen `{ username }` object) and
`InitializeContentArguments.sessionUsername` for outerframes. The CLI exposes
neither API and does not synthesize application identity headers.
