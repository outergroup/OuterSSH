#!/usr/bin/env python3
"""Exercise remote allowlist policy with a real bridge and disposable files."""
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

bridge = str(Path(sys.argv[1]).resolve())
uid = 65534 if os.getuid() == 0 else os.getuid()

def as_user():
    if os.getuid() == 0:
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

with tempfile.TemporaryDirectory(prefix='osb-', dir='/tmp') as directory:
    root = Path(directory)
    root.chmod(0o755)
    home = root / 'home'
    config = root / 'config'
    home.mkdir()
    config.mkdir()
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(config))
    canonical = (home / 'Library/Application Support/org.outerssh/http-unix.allow'
                 if sys.platform == 'darwin' else config / 'outerssh/http-unix.allow')
    legacy = (home / 'Library/Application Support/dev.outergroup.OuterLoop/http-unix.allow'
              if sys.platform == 'darwin' else config / 'outerloop/http-unix.allow')
    template = ('%h/Library/Application Support/dev.outergroup.OuterLoop/http-unix.allow'
                if sys.platform == 'darwin' else '%c/outerloop/http-unix.allow')
    sockpath = str(root / 'app.sock')
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(sockpath)
    if os.getuid() == 0:
        os.chown(sockpath, uid, uid)
    option = ['--user-allowlist', template]

    def write_policy(path, owner=uid):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(sockpath + '\n')
        path.chmod(0o644)
        if os.getuid() == 0:
            os.chown(path, owner, owner)

    def authorize(options=(), expected=True):
        result = subprocess.run([bridge, *options, 'authorize', '--socket', sockpath],
                                env=env, preexec_fn=as_user, capture_output=True)
        assert (result.returncode == 0) == expected, (options, result.stderr)

    authorize(expected=False)
    write_policy(legacy)
    authorize(expected=False)
    authorize(option)
    # User policy cannot be supplied as a system policy to authorize user sockets.
    authorize(['--system-allowlist', str(legacy)], expected=False)
    legacy.chmod(0o666)
    authorize(option, expected=False)
    legacy.chmod(0o644)
    saved = legacy.with_suffix('.saved')
    legacy.rename(saved)
    legacy.symlink_to(saved)
    authorize(option, expected=False)
    legacy.unlink()
    saved.rename(legacy)
    if os.getuid() == 0:
        os.chown(legacy, 0, 0)
        authorize(option, expected=False)
        os.chown(legacy, uid, uid)
    write_policy(canonical)
    authorize()
    canonical.unlink()
    # Exercise the persistent authorization service, used before direct-streamlocal.
    # Frame header: magic/version/type/id/length, as defined by the bridge protocol.
    with subprocess.Popen([bridge, *option, 'service'], env=env, preexec_fn=as_user,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
        def frame():
            # The service also sends unsolicited endpoint-name snapshots
            # (ENDPOINT_NAMES and ENDPOINT_NAMES_CHANGED with ID 0).
            while True:
                header = process.stdout.read(16)
                assert len(header) == 16
                magic, version, kind, ident, length = struct.unpack('<IHHII', header)
                payload = process.stdout.read(length)
                if kind in (16, 18) and ident == 0:
                    continue
                return magic, version, kind, ident, payload
        magic, version, kind, _, _ = frame()
        assert kind == 1
        payload = sockpath.encode()
        process.stdin.write(struct.pack('<IHHII', magic, version, 11, 1, len(payload)) + payload)
        process.stdin.flush()
        _, _, kind, ident, payload = frame()
        assert kind == 15 and ident == 1 and payload == b'\x40' + str(uid).encode(), (kind, ident, payload)
        logical = '/launchd/user/org.outershell.Test'
        legacy.write_text(logical + '\n')
        payload = logical.encode()
        process.stdin.write(struct.pack('<IHHII', magic, version, 11, 2, len(payload)) + payload)
        process.stdin.flush()
        _, _, kind, ident, payload = frame()
        expected = b'\x41' + str(uid).encode() if sys.platform == 'darwin' else b'\0'
        assert kind == 15 and ident == 2 and payload == expected, (kind, ident, payload)
        process.stdin.close()
        assert process.wait(timeout=5) == 0
    # With root available, verify root policy is mandatory for a root-owned socket.
    if os.getuid() == 0:
        os.chown(sockpath, 0, 0)
        system = root / 'system.allow'
        write_policy(system, owner=0)
        def root_authorize(options, expected):
            result = subprocess.run([bridge, *options, 'authorize', '--socket', sockpath], env=env, capture_output=True)
            assert (result.returncode == 0) == expected, result.stderr
        root_authorize(['--user-allowlist', str(system)], False)
        root_authorize(['--system-allowlist', str(system)], True)
        with subprocess.Popen([bridge, '--system-allowlist', str(system), 'service'],
                              env=env, preexec_fn=as_user, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
            assert frame()[2] == 1
            payload = sockpath.encode()
            process.stdin.write(struct.pack('<IHHII', magic, version, 11, 3, len(payload)) + payload)
            process.stdin.flush()
            _, _, kind, ident, payload = frame()
            assert kind == 15 and ident == 3 and payload == b'\x820', (kind, ident, payload)
            process.stdin.close()
            assert process.wait(timeout=5) == 0
        system.chmod(0o666)
        root_authorize(['--system-allowlist', str(system)], False)
        system.chmod(0o644)
        os.chown(system, uid, uid)
        root_authorize(['--system-allowlist', str(system)], False)
    sock.close()
print('Canonical paths, opt-in compatibility, scope, ownership, permissions, symlinks, and service authorization passed.')
