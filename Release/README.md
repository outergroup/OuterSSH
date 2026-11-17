# Building outerssh releases

These scripts build the `outerssh` command-line tool's release archives. Run them
from the repository root. Official releases are signed, published at
`https://outerssh.org/download/outerssh/`, and installed by the scripts on
outerssh.org.

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
them with `lipo`. Set `MACOS_SIGNING_IDENTITY`
to sign with a Developer ID Application certificate from the keychain, and
`NOTARY_KEYCHAIN_PROFILE` (or `APPLE_API_KEY_PATH`, `APPLE_API_KEY_ID` and
`APPLE_API_ISSUER_ID`) to notarize too; see the top of the script.

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
