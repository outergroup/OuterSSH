# Explicit libssh2 operations

This directory contains OuterSSH's protocol implementation and the retained
libssh2 building blocks in [`libssh2/`](libssh2/README.md). They compile directly
into OuterSSH; there is no separate libssh2 build, archive extraction, or patch
application. Private session storage and crypto/key/agent support remain in the
imported subtree. The reactor owns receiving packets, advancing protocol state,
and writing packets. Channels have no corresponding libssh2 channel objects.

## Naming

`olibssh_*` names identify operations whose contracts belong to OuterSSH.
Retained upstream building blocks keep `libssh2_*` / `_libssh2_*` names when
their contracts remain substantially intact, even if they contain local fixes
or have moved between files. `OLIBSSH` comments track edits independently of
the function prefix. All of these interfaces are private to OuterSSH.

The adapted interfaces include `olibssh_session_init_ex` / `olibssh_session_free`
for reactor-owned session storage, `olibssh_agent_sign` for a blocking worker
transaction, `olibssh_cipher_crypt` for span-based AES-GCM, and
`olibssh_chachapoly_*` for the OpenSSL-backed SSH ChaCha construction and its
owned crypto contexts. Algorithm preferences, error queries, and the
authentication-status query retain their upstream names and contracts.

## Packet delivery

`olibssh_transport_read(session, reactor)` reads one packet and calls the named
reactor functions declared in `SSHReactorReadInternal.h`. These calls are
synchronous on the reactor queue. Before delivery, the reader detaches the
completed payload and resets its packet bookkeeping. A handler may close its
channel or invalidate the reactor; session destruction waits until this call
has returned.

Channel bytes are borrowed until the handler returns. They go directly to the
consumer without a libssh2 packet-list node, a second channel-data lookup, or a
copy into a reactor read buffer. Consumers copy bytes they need to retain.
The reactor debits the receive window and queues window credits as the
consumer drains those bytes. Protocol replies also enter the reactor's write
queue, so reads never write to the socket.

Key-exchange packets transfer ownership directly to the exchange, which holds
at most one received packet until it can run the next continuation. There is no
generic packet list.

## Channels and outgoing packets

The reactor's channel array holds local and remote IDs, packet limits, flow-control
windows, and lifecycle flags alongside each channel's consumer. Incoming channel
packets address this array directly, without a second channel registry.

The reactor builds channel-open packets directly into one allocation owned by the
write action. Data, exec, EOF, close, and window-adjustment actions construct their
headers on the stack. The transport encrypts the packet into its existing output
buffer before returning, so it does not borrow those headers across calls.

When a write blocks, the action retains its progress and calls
`olibssh_transport_resume_write` to finish the encrypted packet. It does not rebuild
or encrypt the packet again, and does not need the original plaintext address.
All outgoing traffic, including keepalives, protocol replies, and key exchange,
uses this start/resume contract. Starting another packet before completion is an
error; the transport never identifies retries by their plaintext pointers.
The action commits window changes and consumes outgoing bytes only when that
packet finishes. Reads may change window credits or relocate buffers between
write attempts; the in-flight action keeps its original byte count.

## Initial key exchange and re-exchange

Initial key exchange and re-exchange run the same negotiation, algorithm
continuations, and NEWKEYS handling in `key_exchange.c`. The original `src/kex.c`
and its legacy blocking driver are not retained.

`SSHHandshake.c` drives initial startup on the reactor queue: the nonblocking
banner steps in `handshake.c`, the shared exchange engine, then the
`ssh-userauth` service request. `SSHAuthentication.c` continues on that queue;
host-key approval, local private-key parsing/signing, and ssh-agent IPC run on
background workers. All SSH network I/O remains reactor-driven.

The reactor drives both initial exchange and re-exchange directly:

1. `olibssh_transport_read` receives KEXINIT and transfers its allocation
   through `outersshpriv_reactor_received_key_exchange_packet` to the exchange.
2. The reactor starts the exchange. `olibssh_key_exchange_advance`
   performs computation and consumes already-received packets. It never
   reads or writes a socket.
3. `NEEDS_OUTPUT` enables the SSH write Dispatch source and pauses reads.
   `process_writes` calls `olibssh_key_exchange_write`; partial writes retain
   the pending packet and resume on the next writable event.
4. After writing a complete packet, the reactor advances the exchange and
   calls the named write continuation. That continuation specifies the next
   expected packet and its receive continuation. `NEEDS_INPUT` enables reads.
   The receive continuation runs before decoding another packet, so NEWKEYS
   takes effect at the correct boundary. Buffered bytes are drained without
   requiring another kernel event.
5. On completion, the reactor cleans up the exchange and resumes the ordinary
   write-action queue. Failure, cancellation, or the 60-second exchange timeout
   leads to session teardown.

An outstanding keepalive's response timer is paused during the exchange and
restarted on completion if its reply is still outstanding. Rekeying does not
count as the keepalive reply. Channel-open and command deadlines remain their
normal end-to-end deadlines.

Validation is not a session-wide write barrier. While a ping is awaiting its
reply, channel opens, exec requests, and first data/EOF writes on recoverable
channels wait. Established traffic, window adjustments, teardown, protocol
responses, and incomplete packet retries can continue. The write queue selects
eligible work without changing the order of waiting actions or allowing a
later operation to overtake an earlier operation on the same channel. Its
write Dispatch source sleeps when only validation-dependent work remains.

Ordinary reads continue while an outgoing packet is partially written. If
KEXINIT arrives then, the reactor pauses further reads and finishes only that
packet before advancing the exchange. Ordinary channel operations remain
queued throughout the exchange. Scheduling does not consult
`libssh2_session_block_directions`.

Each algorithm follows a chain of named continuations: send its initial packet,
receive the peer reply, send NEWKEYS, and receive NEWKEYS. Group-exchange DH
first requests and receives the group parameters. Continuations run once;
there is no re-entry into a send operation to retrieve a saved result, and no
numeric libssh2 algorithm state drives this flow. The reactor's exchange timer
bounds all packet waits.

The public exchange state owns one allocation containing continuations and
algorithm resources. The resource structs retain the algorithm inputs and crypto resources; legacy
execution and packet-wait state is removed. Outgoing packet pointers
borrow storage from those resources through write completion. Incoming packets
transfer into the algorithm resources without another allocation or copy;
cleanup frees any input still waiting for its continuation as well.
Always clean up an exchange before freeing its session. After an incomplete
exchange is cleaned up, the session cannot be reused.

## Copied code

- `read_dispatch.c`: packet reading, decryption, and validation from
  `src/transport.c`, with packet handling from `src/packet.c` adapted to call
  the reactor directly.
- `handshake.c`: nonblocking banner I/O adapted from `src/session.c`.
- `key_exchange.c`: key-exchange methods, negotiation, and algorithm-preference
  APIs from `src/kex.c`.
  Network steps use named continuations and direct packet ownership. The
  method table retains upstream callback signatures; each entry starts an
  algorithm once. Crypto calculations and algorithm negotiation retain the
  upstream implementations.
- `transport_write.c`: adapted from `transport_send` in `src/transport.c`,
  with separate start/resume entry points and no implicit re-exchange. Encryption, partial-packet
  handling, and strict-KEX sequence resets are retained.

These C files retain their upstream copyright notices and BSD-3-Clause license
text at the top of each file. `read_dispatch.c` includes the copyright holders
from both source files. The headers in this directory define OuterSSH's protocol interfaces.
The imported subtree retains the private declarations those interfaces need.
The imported code's full notice is also reproduced in
[`Vendor/acknowledgments.txt`](../../Vendor/acknowledgments.txt).

The exchange releases the previous server-host-key buffer before replacing it.
`libssh2/libssh2_priv.h` supplies the retained declarations and shared configuration.
Apple Debug builds enable `LIBSSH2DEBUG` consistently across these sources.
Cookie-generation failure releases the unsent KEXINIT allocation. The imported
code also fixes the AES-GCM no-op MAC initializer's key ownership, so derived
MAC keys are erased and freed in both the initial handshake and re-exchanges.
It releases the temporary OpenSSL 3 ECDH key, import context, and BIGNUM context
after shared-secret derivation.

There are no implicit exchange entry points. The reactor uses explicit olibssh
transport operations; retained libssh2 code provides crypto primitives and final
session storage cleanup.

## Tests

After building the Debug SSH Proxy target:

```sh
SSH_REKEY_PRODUCTS_DIR=/path/to/Build/Products/Debug \
    bash OuterLoop/Scripts/test_olibssh_rekey.sh
```

`test_ssh_handshake.c` covers malformed banners, allocation failure, disconnect,
cancellation, handshake deadline, interrupted initial exchange, and malformed
service acceptance, including completion and socket destruction ordering.

The script runs isolated local OpenSSH servers with temporary keys and a small
rekey limit. It verifies initial handshakes with fragmented I/O and injected
EAGAIN and retention of the original session ID. Socket-free tests dispose
exchanges during partial writes and packet waits, and check cleanup after
cookie-generation failure. It also tests the exchange API and the actual Dispatch-driven reactor,
including client/server initiation, partial writes, injected EAGAIN, and
NEWKEYS boundaries. The reactor relays 256 KiB through a remote `cat` process
and checks every returned byte across repeated server-initiated rekeys. Tests
also cover keepalive timer pause/resumption, cookie-generation failure, and
cancellation, timeout, and socket disconnection while awaiting peer NEWKEYS.
The live reactor tests verify that channel data and KEXINIT are actually received
during partial writes, and that exchange computation waits for the current
ordinary packet to finish. Unit tests cover channel-close lifetime during write
retries and the boundary between the unfinished packet and subsequent output.
Live traffic also continues with a synthetic validation reply held pending;
unit tests check selective scheduling, same-channel ordering, wrapped queues,
and resumption after the validation reply.
Each test runs with explicit Curve25519, ECDH, and finite-field DH preferences
and AES-GCM, ChaCha20-Poly1305, and AES-CTR cipher preferences.
The harness uses ASan/UBSan and tracks libssh2 allocations through teardown.
It does not launch Outer Loop or connect to any configured server.

AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 packet tests check payload
integrity from 5 to 32768 bytes, fragmented reads down to one byte, partial writes with EAGAIN,
and rejection of corrupted ciphertext and authentication tags before delivery.
They also verify bulk cipher calls and that write retries do not encrypt again.
ChaCha tests compare a complete encrypted packet against the upstream
implementation, exercise sequence-number resets, and verify that corrupted
lengths, payloads, and tags leave ciphertext untouched on rejection.
Set `SSH_TRANSPORT_TEST_ONLY=1` to run the socket-free transport and exchange
continuation tests. These also check packet ownership, duplicate/unexpected
packets, optimistic-packet discard, malformed replies, partial writes, and
cancellation of every supported method with allocation tracking.

The transport retains AES-GCM batching: outgoing
packets use one cipher update followed by tag finalization, and incoming data
uses the largest decryptable span already available. Packet alignment, nonce
advancement, and authentication boundaries are unchanged; other cipher paths
retain their existing processing.

The same rekey matrix runs on Linux through
`bash OuterLoop/Scripts/test_outerssh_linux.sh` from the repository root.

Direct-delivery tests check receive-window accounting, ignored extended data,
channel destruction inside a data handler, and subsequent buffered packets.
