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
a C17 compiler, zlib, and `patch`. It uses OpenSSL 3 for cryptography, except on
Windows, which uses CNG, and optionally on Android, which can use the platform's
cryptography.

On macOS, with CMake, Ninja, and OpenSSL 3 from Homebrew:

```sh
cmake -S OuterSSH -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
cmake --build build
./build/outerssh --help
```

On Linux, install OpenSSL and zlib development packages and drop the
`OPENSSL_ROOT_DIR` setting. `OuterSSHCLI/README.md` has Windows instructions.

Building from the top level builds the library, the CLI, and the tests. When
OuterSSH is added to another CMake project with `add_subdirectory`, the CLI and
tests are off by default; link `OuterSSH::OuterSSH`.

## Testing

```sh
cmake -S OuterSSH -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DOUTERSSH_SANITIZE=ON \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
cmake --build build
ctest --test-dir build --output-on-failure
```

`Scripts/test_outerssh_linux.sh` builds and tests in a Linux container with Docker,
including integration tests against a real `sshd`.

## Development

OuterSSH is developed inside the Outer Loop repository, and this repository is
updated from it periodically. Issues and discussion are welcome here.
