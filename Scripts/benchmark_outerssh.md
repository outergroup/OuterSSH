# OuterSSH streaming throughput

`benchmark_outerssh.py` measures uploads and downloads through a real OuterSSH
SSH connection and raw TCP forward. It supports macOS and Linux. It can create an
isolated local SSH server, or use a server such as Pircus through its SSH alias.

The native C driver links the production library. A second build of the same C
file is a standalone source/sink requiring only libc. Both use 64 KiB buffers;
no large file is allocated or written to disk. Payload bytes are initialized
before timing, compression must negotiate `none`, and each transfer checks the
receiver's final byte count. This is a throughput benchmark, not a payload
integrity test; it does not hash or compare every byte during timing.

Authentication, forwarding-listener creation, channel opening, and the remote
readiness acknowledgement happen before timing. The timer includes a small
start message, the data transfer, and the receiver acknowledgement. Each run
warms up both directions, then alternates measured uploads and downloads on one
SSH connection, opening a new channel per transfer. Teardown is outside timing.

Reported CPU seconds include all threads of the benchmark process: OuterSSH and
the native traffic driver. They exclude the SSH server and the source/sink.
Thus CPU seconds can exceed elapsed seconds. Python only starts processes and
collects results; it is not in the measured data path. Negotiated ciphers, MACs,
compression, key exchange, host-key algorithm, and OpenSSL version are recorded.
Private queue access is used only to inspect the negotiated methods before
transferring; the forwarding path uses the public API.

## macOS

Build the optimized library, then point the harness at its Release products:

```sh
xcodebuild -project OuterLoop/OuterLoop.xcodeproj -scheme outerssh \
  -configuration Release -derivedDataPath /tmp/outerssh-benchmark-build \
  CODE_SIGNING_ALLOWED=NO build

python3 OuterLoop/Scripts/benchmark_outerssh.py \
  --products /tmp/outerssh-benchmark-build/Build/Products/Release \
  --output /tmp/outerssh-local-baseline.json
```

Defaults: five 512 MiB transfers in each direction, preceded by a 16 MiB warm-up
per direction. The local fixture restricts the server to AES-128-GCM, matching
OuterSSH's first cipher preference. To compare another algorithm:

```sh
python3 OuterLoop/Scripts/benchmark_outerssh.py \
  --products /tmp/outerssh-benchmark-build/Build/Products/Release \
  --cipher chacha20-poly1305@openssh.com \
  --output /tmp/outerssh-local-chacha.json
```

### Other OpenSSL builds

`build_crypto_benchmark.py` recompiles OuterSSH against an installed static
OpenSSL 3 library, independently of the Xcode products and vendor build.
It writes a combined `libOuterSSH.a` and a native benchmark executable:

```sh
python3 OuterLoop/Scripts/build_crypto_benchmark.py \
  --crypto-prefix /tmp/openssl-install \
  --output /tmp/outerssh-openssl-benchmark
python3 OuterLoop/Scripts/benchmark_outerssh.py \
  --binary /tmp/outerssh-openssl-benchmark/benchmark-outerssh \
  --output /tmp/outerssh-openssl.json
```

Use a separate output directory for each library and architecture. `--arch`
defaults to the host architecture; the installed crypto archive must match it.
This build uses `-Os` for OuterSSH and the driver. For a matched comparison,
also build the OpenSSL baseline with this script, pointing `--crypto-prefix` at
the Xcode Release products' `openssl-arm64` directory. Run benchmarks sequentially
after builds finish. The JSON algorithms record's `openssl` field identifies
the actual linked library version.

See [the historical LibreSSL experiment](benchmark_libressl.md) for its results
and source revision; current code uses OpenSSL 3 APIs.
The [ChaCha experiment](benchmark_openssl_chacha.md) compares OpenSSL's primitives
with the earlier bundled implementation and AES-GCM.
The [acceleration fallback experiment](benchmark_crypto_fallback.md) compares
these ciphers with AES and/or PMULL disabled on the Mac and Raspberry Pi.
The [trimmed OpenSSL experiment](benchmark_openssl_trim.md) measures the smaller
Apple OpenSSL build profile without replacing its crypto backend.

The harness generates temporary client/server keys and a local-only sshd
configuration. It requires `sshd` and `ssh-keygen`, and does not modify the user's
SSH configuration. It also compiles the small driver on each invocation.

## Raspberry Pi or another remote server

```sh
python3 OuterLoop/Scripts/benchmark_outerssh.py \
  --products /tmp/outerssh-benchmark-build/Build/Products/Release \
  --remote Pircus --mib 64 --rounds 3 \
  --output /tmp/outerssh-pircus-baseline.json
```

The alias must already be trusted by OpenSSH and support noninteractive login.
The benchmark uses the hostname, port, username, and first existing identity from
`ssh -G`; `--config` and `--identity` can select alternatives. The native driver
currently requires an unencrypted private key and a direct connection (no jump
host or ProxyCommand). This intentionally does not reproduce the CLI's complete
credential-selection logic.

The server needs `cc`, `head`, `mktemp`, and readable host public keys under
`/etc/ssh/ssh_host_*_key.pub`. The harness sends the source over a verified SSH
connection, compiles it in a temporary directory, and starts the source/sink on
an ephemeral **loopback-only** port. It fetches the server's public keys over that
same verified connection and pins them for the OuterSSH connection. Closing the
harness pipe stops the helper and removes its temporary directory. No SSH-server
configuration or installed software is changed.

Remote runs use production OuterSSH cipher preferences and report what actually
negotiates. `--cipher` applies only to the disposable local server. On Pircus,
OpenSSH's own preference order selected ChaCha20-Poly1305 during setup, whereas
OuterSSH selected AES-128-GCM in both directions. These are separate connections;
only the latter carries measured traffic.

## Linux

Use the existing OpenSSL/zlib build environment, with sanitizers off:

```sh
cmake -S OuterLoop/OuterSSH -B /tmp/outerssh-benchmark-build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DOUTERSSH_BUILD_TESTS=OFF \
  -DOUTERSSH_BUILD_CLI=OFF -DOUTERSSH_BUILD_BENCHMARK=ON
cmake --build /tmp/outerssh-benchmark-build --parallel
python3 OuterLoop/Scripts/benchmark_outerssh.py \
  --binary /tmp/outerssh-benchmark-build/benchmark-outerssh \
  --output /tmp/outerssh-linux-baseline.json
```

The build also produces `benchmark-packet-crypto`, which takes a cipher name
and measures packet encryption without a peer. See the
[Pircus loopback results](benchmark_pircus.md) for a Raspberry Pi 5 comparison
that keeps all measured traffic on the Pi.

The local fixture needs a working `sshd` runtime directory (`/run/sshd` in the
Ubuntu test container). Remote mode uses the same options as on macOS.

## Comparing changes

Keep build optimization, cipher, payload size, server, network, and logging
settings fixed. Do not use Debug, sanitizer, Instruments, or verbose packet-trace
runs as throughput baselines. The `--binary` option assumes an appropriate Release
build. Compare the per-direction medians and inspect individual samples for
outliers. JSON output retains warm-ups and every measured sample.

Local runs use `RekeyLimit 4G 1h`; remote runs preserve the server's existing rekey
policy. Any rekeys during a transfer remain part of the measurement. On localhost,
the SSH server competes for the same machine's resources. On a Pi, its CPU or the
network may cap throughput before client crypto does. Reduced client CPU time
can still be useful even when throughput is unchanged.

## CryptoKit experiment (macOS 27)

The Apple harness accepts three `--crypto` modes:

- `openssl` (default): the unmodified production library.
- `openssl-packet`: OpenSSL AES-GCM using the existing whole-packet transport path.
- `cryptokit`: the same whole-packet path, calling macOS 27 CryptoKit's in-place
  AES-GCM APIs through a small Swift adapter.

```sh
python3 OuterLoop/Scripts/benchmark_outerssh.py \
  --products /tmp/outerssh-benchmark-build/Build/Products/Release \
  --crypto cryptokit --mib 512 --rounds 7 \
  --output /tmp/outerssh-cryptokit.json
```

Repeat with `--crypto openssl` and `--crypto openssl-packet`, sequentially. The
whole-packet OpenSSL control separates crypto implementation differences from
the change in how fragmented input is collected/decrypted. Compare CPU time as
well as throughput. `--cipher aes256-gcm@openssh.com` also works.

These experiments require `--products` and a local fixture; remote runs are
rejected. The CryptoKit mode requires macOS 27 and its SDK. It does not change
product deployment targets, source files, or the built library. The harness
compiles a replacement `crypt.o` and links it ahead of the existing archive.
Only the two AES-GCM methods change; key exchange, authentication, and all other
algorithms still use the production implementation. The reported OpenSSL version
therefore remains relevant even in CryptoKit mode.

The adapter retains a CryptoKit key per cipher context and borrows the C packet
buffer through spans, encrypting/decrypting in place. No Swift `Data` payload or
copy-back buffer is created by the adapter. The existing whole-packet transport
still performs its normal buffer copies. Key objects and nonce state are renewed
when key exchange installs replacement cipher contexts.

Before any measured traffic, both experimental modes check AES-128/256-GCM
against the production OpenSSL path: matching ciphertext/tags, successive nonce
values including a carry, plaintext recovery at several packet sizes, and
rejection of modified headers, ciphertext, and tags. These checks run with
Release optimizations and do not rely on `assert`.
