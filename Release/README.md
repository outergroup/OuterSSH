# Building outerssh releases

These scripts build the `outerssh` command-line tool's release archives and the
`outerssh-helper` executables that OuterSSH uploads to servers. Run them from the
repository root. Official releases are signed and published together at
`https://outerssh.org/download/outerssh/<version>/`, with a `SHA256SUMS` file.
The install scripts on outerssh.org install the command-line tool.

| Archive | Contents |
|---|---|
| `outerssh-macos-universal.tar.gz` | arm64 and x86_64, macOS 12+, CryptoKit and Security |
| `outerssh-linux-x86_64.tar.gz` | Fully static (musl), runs on any distribution |
| `outerssh-linux-aarch64.tar.gz` | Fully static (musl), runs on any distribution |
| `outerssh-windows-x64.zip` | Windows CNG, static runtime |
| `outerssh-windows-arm64.zip` | Windows CNG, static runtime |

## macOS

```sh
Release/build_macos.sh 1.2.0 dist
```

Needs the Xcode command-line tools, CMake, and Ninja. It builds each architecture
separately, since CMake compiles Swift for one architecture at a time, and joins
them with `lipo`. Set `MACOS_SIGNING_IDENTITY` to sign with a Developer ID
Application certificate from the keychain, and `NOTARY_KEYCHAIN_PROFILE` (or
`APPLE_API_KEY_PATH`, `APPLE_API_KEY_ID` and `APPLE_API_ISSUER_ID`) to notarize
too; see `Release/sign_macos.sh`.

## Linux

```sh
docker run --rm -v "$PWD:/src" -w /src alpine:3.22 Release/build_linux.sh 1.2.0 dist
```

This builds for the container's architecture. Add `--platform linux/amd64` or
`--platform linux/arm64` to build the other one under emulation.

## Windows

In a Visual Studio developer environment for the target architecture, with CMake,
Ninja, Clang, and vcpkg:

```powershell
Release/build_windows.ps1 -Version 1.2.0 -Architecture arm64 -Output build/package
```

It leaves an unsigned `outerssh.exe` and `LICENSE` in the output directory.

## Helpers

OuterSSH asks the application for a helper with `OUTERSSH_EVENT_HELPER_BINARY_NEEDED`,
naming a platform such as `linux-x86_64-glibc`. A release has one file per platform,
named so that an application can answer with `outerssh-helper-<platform>` plus the
extension below:

| Files | Contents |
|---|---|
| `outerssh-helper-linux-{aarch64,armv7,x86_64}-{glibc,musl}.gz` | gzip-compressed executable; glibc builds need glibc 2.17+ (2.31+ on armv7) |
| `outerssh-helper-macos-{arm64,x86_64}.gz` | gzip-compressed executable for macOS 11+, signed and notarized |
| `outerssh-helper-windows-{arm64,x64,x86}.tar.gz` | gzip-compressed tar archive holding one signed `outerssh-helper.exe` |

Applications should pin a version and check each file against a SHA-256 they
record, rather than downloading the newest release, since the helper can run as
root through `sudo`.

```sh
Scripts/build_outerssh_linux_helpers.sh dist
Release/build_helpers_macos.sh dist
```

The Linux script builds every variant in Docker, under emulation where needed. The
macOS script builds one universal executable, signs and notarizes it like
`build_macos.sh`, then splits it, and each architecture keeps its signature and
notarization. On Windows, in a Visual Studio developer environment for the target
architecture with CMake, Ninja, and LLVM:

```powershell
Release/build_helpers_windows.ps1 -Architecture x86 -Output build/helper-x86
```

It leaves an unsigned `outerssh-helper.exe`. Sign it, then package it on macOS or
Linux; the archive is reproducible:

```sh
Release/package_helper_windows.sh build/helper-x86/outerssh-helper.exe \
    dist/outerssh-helper-windows-x86.tar.gz
```

## Install scripts

`install.sh`, `install.ps1` and `uninstall.ps1` on outerssh.org read
`https://outerssh.org/download/outerssh/LATEST`, download that version's archive,
and check it against the version's `SHA256SUMS` before installing. Running the
install command again updates outerssh.

On macOS and Linux, outerssh goes in `~/.local/bin` unless `--dir` says otherwise:

```sh
curl -fsSL https://outerssh.org/install.sh | sh
rm -f ~/.local/bin/outerssh
```

On Windows, it goes in `%LOCALAPPDATA%\Programs\outerssh`, which the install
script adds to the user's PATH and `uninstall.ps1` removes again:

```powershell
irm https://outerssh.org/install.ps1 | iex
irm https://outerssh.org/uninstall.ps1 | iex
```
