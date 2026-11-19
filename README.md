# OuterSSH

OuterSSH is an SSH tunneling library for browsers and web views. It connects to
servers over SSH and lets a browser reach ports, Unix domain sockets, and Windows
named pipes on them, through a local HTTP or SOCKS proxy or through port forwards.
It is built into [Outer Loop](https://outerloop.sh), and you can build it into your
own SSH client. Documentation is at [outerssh.org](https://outerssh.org).

This repository also contains `outerssh`, a command-line tool that opens those
proxies and forwards for any browser.

## Layout

| Folder | Contents |
| --- | --- |
| `OuterSSH/` | The C library. Public headers are in `OuterSSH/include/OuterSSH`; `OuterSSH/README.md` describes the design. |
| `OuterSSHCLI/` | The `outerssh` command-line tool. See `OuterSSHCLI/README.md`. |
| `OuterSSHHelper/` | `outerssh-helper`, which OuterSSH installs on servers to reach root-owned sockets through `sudo` and to bridge sockets when the SSH server can't. |
| `Scripts/` | Tests, benchmarks, and the Linux and Windows test environments. |
| `Common/` | A header shared with the helper. |

`OuterSSH/olibssh` is derived from [libssh2](https://libssh2.org) and keeps its
license in `OuterSSH/olibssh/libssh2/COPYING`. `OuterSSH/llhttp` is
[llhttp](https://github.com/nodejs/llhttp), under `OuterSSH/llhttp/LICENSE-MIT`.

## Building

OuterSSH builds with CMake 3.24+ on macOS, Linux, Windows, and Android. It needs
a C17 compiler, zlib, and `patch`. It uses the platform's cryptography on macOS
(CryptoKit and Security) and Windows (CNG), and optionally on Android. Elsewhere it
uses OpenSSL 3.

On macOS, with the Xcode command-line tools, CMake, and Ninja:

```sh
cmake -S OuterSSH -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/outerssh --help
```

Apple cryptography is written in Swift, which CMake builds only with the Ninja or
Xcode generator. To use OpenSSL on macOS instead, add `-DOUTERSSH_APPLE_CRYPTO=OFF`
and `-DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"`. Apple cryptography doesn't
read encrypted private-key files; use an SSH agent for those keys.

On Linux, install OpenSSL and zlib development packages and use the same command.
`OuterSSHCLI/README.md` has Windows instructions.

Building from the top level builds the library, the CLI, and the tests. When
OuterSSH is added to another CMake project with `add_subdirectory`, the CLI and
tests are off by default; link `OuterSSH::OuterSSH`.

## Testing

```sh
cmake -S OuterSSH -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DOUTERSSH_SANITIZE=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

`Scripts/test_outerssh_linux.sh` builds and tests in a Linux container with Docker,
including integration tests against a real `sshd`.

