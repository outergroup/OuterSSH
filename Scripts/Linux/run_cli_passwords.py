#!/usr/bin/env python3
"""Check that outerssh falls back to prompting for a password, as OpenSSH does.

Runs as root in the Linux test container, against a disposable sshd that
accepts the outerssh-test user's password and an authorized key.
"""
import errno
import os
from pathlib import Path
import pty
import pwd
import re
import secrets
import select
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

PASSWORD = "outerssh-test-password"


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class CLI:
    def __init__(self, binary, arguments):
        environment = {key: value for key, value in os.environ.items() if key != "SSH_AUTH_SOCK"}
        self.pid, self.terminal = pty.fork()
        if self.pid == 0:
            os.execve(binary, [binary, *arguments], environment)
        self.output = b""
        self.status = None

    def read(self, timeout):
        if select.select([self.terminal], [], [], timeout)[0]:
            try:
                data = os.read(self.terminal, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            self.output += data
            return bool(data)
        return True

    def expect(self, pattern):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            match = re.search(pattern, self.output)
            if match:
                self.output = self.output[match.end():]
                return match
            if not self.read(0.1):
                break
        raise AssertionError(f"Missing {pattern!r}: {self.output.decode(errors='replace')}")

    def reply(self, text):
        os.write(self.terminal, text.encode() + b"\n")

    def wait(self, expected):
        deadline = time.monotonic() + 20
        while self.status is None and time.monotonic() < deadline:
            self.read(0.05)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
        assert self.status == expected, (self.status, self.output.decode(errors="replace"))

    def close(self):
        if self.status is None:
            os.kill(self.pid, signal.SIGTERM)
            self.wait(0)
        os.close(self.terminal)


def available_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def check_echo(port):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall(b"ping")
        assert connection.recv(4) == b"ping"


def main():
    binary = str(Path(sys.argv[1]).resolve() / "outerssh")
    try:
        pwd.getpwnam("outerssh-test")
    except KeyError:
        subprocess.run(["useradd", "-m", "-s", "/bin/sh", "outerssh-test"], check=True)
    subprocess.run(["chpasswd"], input=f"outerssh-test:{PASSWORD}\nroot:{secrets.token_urlsafe(32)}\n",
                   text=True, check=True)
    Path("/run/sshd").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="outerssh-cli-passwords-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        for name in ("host", "authorized", "unauthorized"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        (root / "authorized_keys").write_text((root / "authorized.pub").read_text())
        (root / "authorized_keys").chmod(0o644)
        ssh_port = available_port()
        (root / "sshd_config").write_text(
            f"Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {root / 'host'}\nPidFile {root / 'sshd.pid'}\n"
            f"AuthorizedKeysFile {root / 'authorized_keys'}\nStrictModes no\nUsePAM no\n"
            "PasswordAuthentication yes\nKbdInteractiveAuthentication no\nAllowUsers outerssh-test\n"
            "MaxAuthTries 20\n")
        host_key = (root / "host.pub").read_text()
        (root / "known_hosts").write_text(f"[127.0.0.1]:{ssh_port} {host_key}[localhost]:{ssh_port} {host_key}")
        echo = TCPServer(("127.0.0.1", 0), Echo)
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        echo_port = echo.server_address[1]
        log = (root / "sshd.log").open("w")
        sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(root / "sshd_config")],
                                stdout=log, stderr=log)
        try:
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", ssh_port), timeout=0.1).close()
                    break
                except OSError:
                    time.sleep(0.05)

            def configure(name, identity, extra=""):
                path = root / name
                path.write_text(
                    f"Host *\n  User outerssh-test\n  Port {ssh_port}\n  IdentityFile {identity}\n"
                    f"  IdentityAgent none\n  UserKnownHostsFile {root / 'known_hosts'}\n{extra}")
                return str(path)

            def start(config, *options, destination="127.0.0.1"):
                forward_port = available_port()
                cli = CLI(binary, ["-F", config, "-L", f"{forward_port}:127.0.0.1:{echo_port}",
                                   *options, destination])
                return cli, forward_port

            prompt = rb"outerssh-test@127\.0\.0\.1's password: "
            unauthorized = configure("unauthorized_config", root / "unauthorized")
            missing = configure("missing_config", root / "missing")

            cli, port = start(unauthorized)
            cli.expect(prompt)
            cli.reply("wrong")
            cli.expect(rb"Permission denied, please try again\.")
            cli.expect(prompt)
            cli.reply(PASSWORD)
            cli.expect(rb"Forward listening")
            check_echo(port)
            cli.close()
            assert b"Pseudo-terminal" not in cli.output, cli.output
            print("ok: rejected key falls back to a password, and a wrong one is asked again")

            cli, port = start(missing)
            cli.expect(prompt)
            cli.reply(PASSWORD)
            cli.expect(rb"Forward listening")
            check_echo(port)
            cli.close()
            print("ok: no key or agent prompts for a password")

            cli, _ = start(configure("two_prompts_config", root / "missing", "  NumberOfPasswordPrompts 2\n"))
            for attempt in range(2):
                cli.expect(prompt)
                cli.reply("wrong")
            cli.expect(rb"outerssh: SSH authentication failed\.")
            cli.wait(1)
            print("ok: gives up after NumberOfPasswordPrompts")

            cli, _ = start(unauthorized, "--batch")
            cli.expect(rb"outerssh: SSH authentication failed\.")
            cli.wait(1)
            assert b"password" not in cli.output, cli.output
            print("ok: batch mode does not prompt")

            cli, _ = start(configure("no_password_config", root / "missing",
                                     "  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n"))
            cli.expect(rb"no identity, SSH agent, or password authentication is available")
            cli.wait(1)
            print("ok: disabled password authentication does not prompt")

            cli, port = start(configure("authorized_config", root / "authorized"), "--password")
            cli.expect(prompt)
            cli.reply(PASSWORD)
            cli.expect(rb"Forward listening")
            check_echo(port)
            cli.close()
            print("ok: --password skips the key")

            cli, port = start(missing, "-J", f"outerssh-test@localhost:{ssh_port}")
            cli.expect(rb"outerssh-test@localhost's password: ")
            cli.reply(PASSWORD)
            cli.expect(prompt)
            cli.reply(PASSWORD)
            cli.expect(rb"Forward listening")
            check_echo(port)
            cli.close()
            print("ok: jump hosts prompt for passwords too")
        finally:
            sshd.terminate()
            sshd.wait(timeout=5)
            log.close()


if __name__ == "__main__":
    main()
