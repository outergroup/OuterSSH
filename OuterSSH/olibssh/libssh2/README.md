# Retained libssh2 support

These private sources were imported from Outer Loop's `libssh2-1.11.2-marcus.tar.gz`
(the archive identifies itself as `1.11.2_DEV`), with the existing Outer Loop
patch applied. The source archive SHA-256 was:

```
82e1b0447178e58ae52d383ec83b8478a70e43b635326a478926a4cae5b5f733
```

This is not a standalone libssh2 distribution or a public compatibility API.
OuterSSH compiles these files directly into its own library on Apple, Linux,
and Windows, using `libssh2_config.h` for the shared platform configuration.
`blowfish.c` is included by `bcrypt_pbkdf.c`, not compiled separately.

Retained code supplies selectable OpenSSL or Apple-native crypto operations, algorithm tables, key parsing,
ssh-agent IPC, known-host-file handling for the command-line client, allocation,
serialization, and session storage. The reactor owns handshake, authentication,
key exchange, channel lifecycle, packet delivery, readiness, and deadlines.
Session destruction releases storage; it never performs socket I/O.

SFTP, SCP, the public-key management subsystem, standalone keepalive, the old
channel/packet/transport/authentication engines, and upstream alternative crypto backends
are omitted. The replacement protocol implementation is in the parent directory
and the OuterSSH reactor/flow files. OpenSSL 3.0 or newer remains an upstream dependency for the default backend.
Apple builds can instead select the OS-only backend described in the
[OuterSSH README](../../README.md#apple-crypto-backend).

`cipher-chachapoly.c` retains OpenSSH's two-key SSH packet construction, using
OpenSSL's raw ChaCha20 and Poly1305 implementations. The combined IETF AEAD
API has a different wire format. Cipher and MAC contexts live until rekey or
session teardown; packet processing reuses them. The upstream scalar ChaCha20
and Poly1305 implementations are omitted.

Search for `OLIBSSH BEGIN` / `OLIBSSH END` to find localized behavioral changes.
`OLIBSSH:` comments identify rewritten functions or moved implementations.
Straightforward deletions are not individually marked. Existing adaptations in
the parent directory are described in its README.
Functions with OuterSSH-specific contracts use `olibssh_*`; a local edit alone
does not require renaming a retained upstream function. See the
[naming convention](../README.md#naming).

The original copyright notices are retained in each imported file. `COPYING`
contains the distribution notice; the application's acknowledgments also retain
that notice. Consult upstream libssh2 changes when maintaining the retained code,
especially crypto, key parsing, and agent handling.
