# Windows OuterSSH helper

The Windows helper speaks the same ORB1 framing as the Unix helper. `service`
checks `%LOCALAPPDATA%\OuterSSH\http-pipe.allow`, authorizes endpoints in managed
mode, and watches pipe availability. `bridge --socket PIPE` multiplexes byte
streams over native named pipes. `--user-allowlist PATH` selects another allowlist
with the same ownership and ACL requirements.

Each connection rechecks the allowlist, pipe owner and server-authority ACL using
the same implementation as Windows Localhost mode. The helper requests only
client rights and identification-level impersonation. No listener TCP port or
WSL runtime is involved.

Windows pipes have no write-half-close operation. ORB1 EOF prevents further
client writes while the bridge continues reading the response. Backends must use
HTTP message framing rather than waiting for transport EOF to delimit a request.

Limits: 64 concurrent streams/watches, 1 MiB frames, 4 MiB input queue, 30-second
pipe write timeout, and a 120-second SSH input idle timeout. The caller must send
keepalives during otherwise idle connections.

This CMake project builds `outerssh-helper`, which has no application requests,
and the `named-pipe-bridge` test. `OuterSSHHelper.cmake` lets applications build
their own helper from these sources. Outer Loop's `OuterLoopHelper/build.ps1
-VisualStudioRoot <Build Tools directory> -SignToolPath <signtool.exe>
-SigningLibraryPath <Azure.CodeSigning.Dlib.dll> -SigningMetadataPath <metadata.json>`
builds `outerloop-helper` for all three architectures with a static C runtime,
signs it with Azure Artifact Signing, and copies it to `Resources/WindowsHelpers`
after verifying the Authenticode signature, timestamp, and publisher. The
macOS SSH service, iOS/iPadOS, Android and Windows apps bundle these same files,
and the WindowsBrowser project builds the same `outerloop-helper` target.

Windows SSH selects an installation using the remote process token:

- Elevated sessions use `%ProgramData%\OuterSSH\Users\<SID>\versions\<SHA256>\outerssh-helper.exe`.
- Non-administrative sessions use `%LOCALAPPDATA%\OuterSSH\versions\<SHA256>\outerssh-helper.exe`.

Run `install.ps1 -SourcePath <bridge.exe>` as the connecting user. Without
elevation it installs only in that user's Local AppData and never requests UAC
or writes machine-wide state. For elevated SSH, run it elevated; `-UserSid <SID>`
lets an administrator install for another account. The installer uses the actual
token identity, not the desktop username or environment variables, as its default.

Each account has a `current.txt` containing a SHA-256 version identifier. Updates
publish that account's pointer atomically and leave previous binaries intact,
so active sessions and other accounts' versions are unaffected. Elevated
installations have administrator/SYSTEM ownership and write access. Installation
rejects unsafe owners, writable ACLs, and reparse points.

The fixed launcher in `ResolveBridge.ps1` is encoded into the trusted client's
commands; no shared launcher binary needs installation. It uses the remote token
to select the directory and validates protected ancestors, the version pointer,
and the executable before an elevated launch. An elevated connection never falls
back to Local AppData or the former shared/per-user paths. A non-administrative
connection never requires the protected installation. Neither mode elevates.
The native child's standard handles are inherited directly to preserve binary
ORB1 traffic. There is no arbitrary executable-path parameter.

`Scripts/generate_windows_bridge_commands.py` produces the shared command header;
run it after editing the launcher, or with `--check` to verify freshness. Commands
use Windows PowerShell's absolute system path with `-NoProfile`; currently the
client requires Windows installed at `C:\Windows`. Both cmd and PowerShell SSH
shells are supported. The configured SSH shell and its startup environment must
still be trusted for elevated sessions.

Applications add requests through `outerssh_helper_main`'s handler; Outer Loop's
`outerloop-helper` answers `outer-shell-home` with the canonical per-user Outer
Shell pipe when the native HTTP allowlist allows it. Named pipe requests select the
installed Windows helper, whose ORB1 HELLO validates protocol compatibility. Disconnecting
does not delete installed versions. There is no per-session Windows upload.

The helper is plain C because OuterSSH uploads it on first use, so its size is part
of connection time. `NamedPipes.c` and `EndpointNames.c` are the single implementation
of the allowlist, pipe-identity, activation and `endpoints.d` checks; Windows Localhost
mode calls them through thin C++ wrappers. Release builds use `/O1`, link the static
vcruntime with the Windows-provided UCRT (`ucrt.lib` in place of `libucrt.lib`), and
replace the CRT startup with `outerssh_helper_entry`, which initializes the `/GS` cookie,
parses the command line with `CommandLineToArgvW` and calls `wmain`.

`test_installation.ps1 -SourcePath <bridge.exe>` exercises installation, immutable
upgrades, rollback, and launch for the current token. Run it under both an elevated
and a standard account; `-RequireNonAdministrative` asserts the latter.
`test_bridge.py <bridge.exe> --launcher` exercises binary forwarding through the
installed version and launcher rather than invoking the supplied executable directly.

Windows endpoints use `http+pipe://<percent-encoded-pipe>/path` links. The macOS
address bar also accepts a raw canonical pipe path. Its synthetic proxy hostname
uses the `.pipe.outerssh.localhost` suffix; it never resolves through DNS.

A pipe whose name ends in `.s-<SID>` must be owned by that SID, and AUTHORIZE
reports that SID as the pipe's owner in its PREPARED reply, marking SYSTEM
(`.s-1-5-18`) and Administrators (`.s-1-5-32-544`) as root. OuterSSH then lets
only pages of pipes with the same owner, or of root's, act on another account's
pipe. Every other pipe belongs to the current user and must be served by the
current user's process without elevation. An
elevated server, whose pipes are owned by Administrators by default, must
therefore put that SID in its pipe name.

Successful OPEN_OK replies have no payload. Pipe ownership and ACL checks run
before a connection succeeds; they do not generate display labels. Friendly
names come from the independently validated `endpoints.d` snapshot, which the
helper reads and watches through its service channel.

## On-demand Windows tasks

The bridge and Windows Localhost mode read
`%LOCALAPPDATA%\org.outerssh\activations.tsv` when an allowlisted named pipe is
absent. The file maps each pipe to an existing Task Scheduler task:

```text
\\.\pipe\my.app	\MyAppTask
```

The separator is one literal tab. Use UTF-8 without a BOM, LF or CRLF endings,
exactly two nonempty fields per row, and absolute task paths beginning with `\`.
Blank lines are ignored. Comments, quoting, escapes, and embedded control
characters are unsupported. Pipe names use the same flat ASCII format and
110-character limit as the pipe allowlist. Matching is case-insensitive;
duplicate pipe registrations and malformed rows fail activation. Multiple pipes
may map to one task. The maximum file size is 1 MiB.

Registration does not grant network access: the pipe must also be in
`%LOCALAPPDATA%\OuterSSH\http-pipe.allow`. Both the activation directory and file
must be owned by the current user, SYSTEM, or Administrators, must not be reparse
points, and must not grant other principals write access. Writers should use
an atomic replacement; Outer Shell serializes writers using `activations.lock`
in the same directory. Task Scheduler enforces task execution permissions.
The mapping contains task paths, never executable paths or command lines.
Activation accepts only least-privilege interactive-token tasks whose principal is the
current user. Highest-privilege, other-account, and
non-interactive logon types are rejected before requesting execution.

Connections first attempt to open the pipe directly. On a missing pipe, the
client loads the mapping, requests task execution through the native Task
Scheduler API, and retries for up to 15 seconds. Running or queued tasks are
not restarted. Tasks should use `IgnoreNew` for concurrent activation requests.
Disabled tasks stay disabled; activation does not re-enable them. Task lookup
and launch failures include the task path and HRESULT in the connection error.
Opening a pipe with an unrelated client does not activate its task.

Outer Shell's Windows installer registers independent interactive-user tasks
for Outer Shell and Files, with no logon trigger or stored password. The user
must have a desktop session. Idle apps can exit normally while leaving their
tasks enabled; subsequent connections activate them again. Stopping or closing
the bridge does not stop a task.
