#!/usr/bin/env python3
"""Exercise the macOS/Linux CLI with a disposable loopback SSH server and generated keys."""
import argparse
import contextlib
import errno
import http.client
import http.server
import os
from pathlib import Path
import pty
import pwd
import re
import select
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


def available_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


class CLI:
    def __init__(self, binary, arguments, environment):
        self.pid, self.terminal = pty.fork()
        if self.pid == 0:
            os.execve(binary, [binary, *arguments], environment)
        self.output = b""
        self.status = None

    def expect(self, pattern):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            match = re.search(pattern, self.output)
            if match:
                return match
            if select.select([self.terminal], [], [], 0.1)[0]:
                try:
                    data = os.read(self.terminal, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b""
                if not data:
                    break
                self.output += data
        raise AssertionError(f"Missing {pattern!r}: {self.output.decode(errors='replace')}")

    def reply(self, text):
        os.write(self.terminal, text.encode() + b"\n")

    def wait(self, expected=0):
        deadline = time.monotonic() + 10
        while self.status is None and time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                break
            time.sleep(0.02)
        assert self.status == expected, (self.status, self.output)

    def close(self):
        if self.status is None:
            try:
                os.kill(self.pid, signal.SIGTERM)
                self.wait()
            finally:
                if self.status is None:
                    os.kill(self.pid, signal.SIGKILL)
                    os.waitpid(self.pid, 0)
        os.close(self.terminal)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class HTTPOrigin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        data = (str(self.headers.get("X-Outer-Loop-User", "")) + "|" +
                str(self.headers.get("Connection", ""))).encode()
        if self.path == "/headers":
            data = (self.headers.get("Host", "") + "|" + self.headers.get("Origin", "")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def receive(connection, count):
    result = b""
    while len(result) < count:
        data = connection.recv(count - len(result))
        assert data, "Unexpected EOF"
        result += data
    return result


def relay(port, target_port, authenticated=False):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(bytes([5, 1, 2 if authenticated else 0]))
        assert receive(connection, 2) == bytes([5, 2 if authenticated else 0])
        if authenticated:
            connection.sendall(b"\x01\x04test\x06secret")
            assert receive(connection, 2) == b"\x01\x00"
        request = b"opaque TCP payload\x00\xff"
        payload = request + bytes(range(256)) * 4096
        # Pipeline application bytes after a domain-name SOCKS CONNECT.
        connection.sendall(b"\x05\x01\x00\x03\x09localhost" + target_port.to_bytes(2, "big") + request)
        reply = receive(connection, 10)
        assert reply[:2] == b"\x05\x00", reply
        assert receive(connection, len(request)) == request
        for offset in range(0, len(payload), 32768):
            part = payload[offset:offset + 32768]
            connection.sendall(part)
            assert receive(connection, len(part)) == part
        connection.shutdown(socket.SHUT_WR)
        assert connection.recv(1) == b""


def rewritten_socks(port, target_port, authenticated):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as stream:
        stream.sendall(bytes([5, 1, 2 if authenticated else 0]))
        assert receive(stream, 2) == bytes([5, 2 if authenticated else 0])
        if authenticated:
            stream.sendall(b"\x01\x04test\x06secret")
            assert receive(stream, 2) == b"\x01\x00"
        host = b"127.0.0.1.tcp.outerssh.localhost"
        stream.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + target_port.to_bytes(2, "big"))
        assert receive(stream, 10)[:2] == b"\x05\x00"
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.sock = stream
        for _ in range(3):
            authority = f"127.0.0.1.tcp.outerssh.localhost:{target_port}"
            connection.request("GET", "/headers", headers={"Host": authority, "Origin": f"http://{authority}"})
            response = connection.getresponse()
            assert response.status == 200 and not response.will_close
            assert response.read() == f"127.0.0.1:{target_port}|http://127.0.0.1:{target_port}".encode()
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda path: str(Path(path).resolve()))
    parser.add_argument("--apple-crypto", action="store_true")
    args = parser.parse_args()
    run(args.binary, "--help")
    for arguments in [[], ["-D", "-1", "host"], ["-D", "65536", "host"], ["-D", "abc", "host"],
                      ["-D", "1080", "-p", "0", "host"], ["-D", "0", "-J", "", "host"],
                      ["-D", "0", "-J", "one", "-Jtwo", "host"], ["-L", "8080:localhost:80", "--rewrite-http", "host"]]:
        assert subprocess.run([args.binary, *arguments], capture_output=True).returncode == 2
    for specification in ("8080", "8080:host", "-1:host:80", "65536:host:80",
                          "8080::80", "8080:host:0", "8080:host:65536", "8080:[::1:80",
                          "8080:::1:80", "8080:host:80:90", "8080:bad host:80"):
        assert subprocess.run([args.binary, "-L", specification, "host"], capture_output=True).returncode == 2
    with tempfile.TemporaryDirectory(prefix="outerssh-cli-") as directory, contextlib.ExitStack() as stack:
        root = Path(directory)
        environment = {**os.environ}
        environment.pop("SSH_AUTH_SOCK", None)
        for name, passphrase in [("host", ""), ("client", ""), ("encrypted", "passphrase"), ("other", "")]:
            run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-f", str(root / name))
        (root / "authorized_keys").write_bytes((root / "client.pub").read_bytes() + (root / "encrypted.pub").read_bytes())
        ssh_port = available_port()
        (root / "sshd_config").write_text(
            f"Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {root}/host\nPidFile {root}/sshd.pid\n"
            f"AuthorizedKeysFile {root}/authorized_keys\nStrictModes no\nPasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\nUsePAM no\nMaxSessions 0\nAllowTcpForwarding yes\nLogLevel ERROR\n")
        log = stack.enter_context((root / "sshd.log").open("w"))
        sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(root / "sshd_config")], stdout=log, stderr=log)
        def stop_process(process):
            process.terminate()
            process.wait(timeout=5)
        stack.callback(stop_process, sshd)
        for _ in range(100):
            if sshd.poll() is not None:
                raise AssertionError((root / "sshd.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", ssh_port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise AssertionError("sshd did not start")
        echo = stack.enter_context(EchoServer(("127.0.0.1", 0), Echo))
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        stack.callback(echo.shutdown)
        (root / "client_config").write_text("Host *\n    IdentityFile none\n")
        base = ["-F", str(root / "client_config"), "-D", "0", "-p", str(ssh_port), "--known-hosts", str(root / "known_hosts")]
        identity = ["-i", str(root / "client")]
        def start(arguments, env=environment):
            cli = CLI(args.binary, [*base, *arguments, "127.0.0.1"], env)
            stack.callback(cli.close)
            return cli
        def ready(cli):
            return int(cli.expect(rb"SOCKS5 listening on 127\.0\.0\.1:(\d+)").group(1))
        unknown = start([*identity, "--batch"])
        unknown.expect(b"SSH host key was not accepted")
        unknown.wait(1)
        cli = start(identity)
        cli.expect(b"Type yes:")
        cli.reply("yes")
        port = ready(cli)
        assert (root / "known_hosts").read_text().startswith(f"[127.0.0.1]:{ssh_port} ssh-ed25519 ")
        relay(port, echo.server_address[1])
        os.kill(cli.pid, signal.SIGINT)
        cli.wait()
        with socket.socket() as connection:
            assert connection.connect_ex(("127.0.0.1", port)) != 0
        # Forward-only and combined listeners must carry bytes without a proxy greeting.
        for combined in (False, True):
            forward_base = base if combined else [value for i, value in enumerate(base) if i not in (2, 3)]
            cli = CLI(args.binary, [*forward_base, *identity, "--batch",
                "-L", f"0:localhost:{echo.server_address[1]}",
                "-L", f"0:127.0.0.1:{echo.server_address[1]}", "127.0.0.1"], environment)
            stack.callback(cli.close)
            cli.expect(rb"Forward listening.*\r?\nForward listening")
            ports = [int(p) for p in re.findall(rb"Forward listening on 127\.0\.0\.1:(\d+)", cli.output)]
            assert len(ports) == 2
            for port in ports:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
                    payload = bytes(range(256)) * 128
                    stream.sendall(payload)
                    stream.shutdown(socket.SHUT_WR)
                    received = b""
                    while chunk := stream.recv(65536):
                        received += chunk
                    assert received == payload
            if combined:
                relay(ready(cli), echo.server_address[1])
            os.kill(cli.pid, signal.SIGINT)
            cli.wait()
            for port in ports:
                with socket.socket() as stream:
                    assert stream.connect_ex(("127.0.0.1", port)) != 0
        print("PASS: repeated raw local forwards, standalone/combined, remote hostname, binary data, half-close, shutdown")
        origin = stack.enter_context(http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTPOrigin))
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        stack.callback(origin.shutdown)
        for authenticated in (False, True):
            options = [*identity, "--batch", "--rewrite-http"]
            if authenticated:
                options += ["--proxy-user", "test", "--proxy-password-env", "OUTERSSH_TEST_PASSWORD"]
            cli = start(options, {**environment, "OUTERSSH_TEST_PASSWORD": "secret"})
            rewritten_socks(ready(cli), origin.server_port, authenticated)
            os.kill(cli.pid, signal.SIGTERM)
            cli.wait()
        for authenticated in (False, True):
            arguments = [*identity, "--batch", "--http-proxy", "0", "--rewrite-http"]
            if authenticated:
                arguments += ["--proxy-user", "test", "--proxy-password-env", "OUTERSSH_TEST_PASSWORD"]
            cli = start(arguments, {**environment, "OUTERSSH_TEST_PASSWORD": "secret"})
            socks_port = ready(cli)
            http_port = int(cli.expect(rb"HTTP proxy listening on 127\.0\.0\.1:(\d+)").group(1))
            relay(socks_port, echo.server_address[1], authenticated=authenticated)
            rewritten_socks(socks_port, origin.server_port, authenticated)
            connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
            for _ in range(3):
                fields = {"Proxy-Authorization": "Basic dGVzdDpzZWNyZXQ="} if authenticated else {}
                connection.request("GET", f"http://localhost:{origin.server_port}/", headers=fields)
                response = connection.getresponse()
                assert response.status == 200 and not response.will_close
                assert response.read() == b"|"
            connection.close()
            os.kill(cli.pid, signal.SIGTERM)
            cli.wait()
        http_only = CLI(args.binary, [*base[:2], *base[4:], *identity, "--batch", "--http-proxy", "0", "127.0.0.1"], environment)
        stack.callback(http_only.close)
        http_port = int(http_only.expect(rb"HTTP proxy listening on 127\.0\.0\.1:(\d+)").group(1))
        connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
        connection.request("GET", f"http://localhost:{origin.server_port}/")
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        connection.close()
        os.kill(http_only.pid, signal.SIGINT)
        http_only.wait()
        print("PASS: direct HTTP proxy over SSH, HTTP-only operation, authenticated/unauthenticated, repeated rewriting through SOCKS-only and combined listeners, opaque SOCKS traffic")
        run("/usr/bin/ssh-keygen", "-H", "-f", str(root / "known_hosts"))
        cli = start([*identity, "--batch", "--proxy-user", "test", "--proxy-password-env", "OUTERSSH_TEST_PASSWORD"],
                    {**environment, "OUTERSSH_TEST_PASSWORD": "secret"})
        port = ready(cli)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            connection.sendall(b"\x05\x01\x00")
            assert receive(connection, 2) == b"\x05\xff"
        relay(port, echo.server_address[1], authenticated=True)
        os.kill(cli.pid, signal.SIGTERM)
        cli.wait()
        cli = start(["-i", str(root / "encrypted"), "--ask-passphrase"])
        cli.expect(b"Key passphrase:")
        cli.reply("passphrase")
        if args.apple_crypto:
            cli.expect(b"Apple crypto does not support encrypted private-key files")
            cli.wait(expected=1)
        else:
            relay(ready(cli), echo.server_address[1])
            os.kill(cli.pid, signal.SIGTERM)
            cli.wait()
        agent_socket = str(root / "agent.sock")
        agent = subprocess.Popen(["/usr/bin/ssh-agent", "-D", "-a", agent_socket], stdout=log, stderr=log)
        stack.callback(stop_process, agent)
        for _ in range(100):
            if Path(agent_socket).exists():
                break
            time.sleep(0.02)
        agent_environment = {**environment, "SSH_AUTH_SOCK": agent_socket}
        run("/usr/bin/ssh-add", str(root / "client"), env=agent_environment)
        cli = start(["--batch"], agent_environment)
        relay(ready(cli), echo.server_address[1])
        os.kill(cli.pid, signal.SIGTERM)
        cli.wait()
        username = pwd.getpwuid(os.getuid()).pw_name
        (root / "PircusTest").write_bytes((root / "client").read_bytes())
        (root / "GatewayToken").write_bytes((root / "client").read_bytes())
        (root / "space directory").mkdir()
        (root / "space directory" / "client").write_bytes((root / "client").read_bytes())
        (root / "space directory" / "known_hosts").write_bytes((root / "known_hosts").read_bytes())
        (root / "included_config").write_text(
            f"Host PircusTest\n    HostName 127.0.0.1\n    User {username}\n    Port {ssh_port}\n"
            f"    IdentityFile {root}/missing\n    IdentityFile {root}/%n\n    IdentitiesOnly yes\n"
            f"    UserKnownHostsFile {root}/known_hosts\n"
            f'Host SpaceTest\n    HostName 127.0.0.1\n    User {username}\n    Port {ssh_port}\n'
            f'    IdentityFile "{root}/space directory/client"\n    IdentitiesOnly yes\n'
            f'    UserKnownHostsFile "{root}/space directory/known_hosts"\n'
            f"Host OverrideTest\n    HostName 127.0.0.1\n    User wrong-user\n    Port 1\n"
            f"    IdentityFile {root}/other\n    UserKnownHostsFile {root}/wrong_hosts\n"
            f"Host ConfigAgent NoAgent\n    HostName 127.0.0.1\n    User {username}\n    Port {ssh_port}\n"
            f"    IdentityFile none\n    UserKnownHostsFile {root}/known_hosts\n"
            f"Host ConfigAgent\n    IdentityAgent {agent_socket}\n"
            f"Host NoAgent\n    IdentityAgent none\n"
            f"Host GatewayToken\n    HostName 127.0.0.1\n    User {username}\n    Port {ssh_port}\n"
            f"    IdentityFile {root}/%n\n    IdentitiesOnly yes\n    UserKnownHostsFile {root}/known_hosts\n"
            f"Host JumpTest\n    ProxyJump Gateway,Gateway2\n"
            f"Host Gateway Gateway2 JumpTest\n    HostName 127.0.0.1\n    User {username}\n    Port {ssh_port}\n"
            f"    IdentityFile {root}/client\n    IdentitiesOnly yes\n    UserKnownHostsFile {root}/known_hosts\n")
        (root / "aliases").write_text(f"Include {root}/included_config\n")
        def alias(name, arguments=(), env=environment):
            cli = CLI(args.binary, ["-D", "0", "-F", str(root / "aliases"), "--batch", *arguments, name], env)
            stack.callback(cli.close)
            return cli
        cli = alias("PircusTest")
        relay(ready(cli), echo.server_address[1])
        os.kill(cli.pid, signal.SIGTERM)
        cli.wait()
        cli = alias("SpaceTest")
        relay(ready(cli), echo.server_address[1])
        os.kill(cli.pid, signal.SIGTERM)
        cli.wait()
        cli = alias("OverrideTest", ["-p", str(ssh_port), "-l", username, *identity,
                                     "--known-hosts", str(root / "known_hosts")])
        relay(ready(cli), echo.server_address[1])
        os.kill(cli.pid, signal.SIGTERM)
        cli.wait()
        cli = alias("ConfigAgent")
        relay(ready(cli), echo.server_address[1])
        os.kill(cli.pid, signal.SIGTERM)
        cli.wait()
        cli = alias("NoAgent", env=agent_environment)
        cli.expect(b"no configured identity or SSH agent")
        cli.wait(1)
        with (root / "aliases").open("a") as config:
            config.write("Host DirectOverride\n    ProxyJump missing-gateway.invalid\n"
                         f"    HostName 127.0.0.1\n    User {username}\n    Port {ssh_port}\n"
                         f"    IdentityFile {root}/client\n    IdentitiesOnly yes\n    UserKnownHostsFile {root}/known_hosts\n")
        for name, options in [("JumpTest", []), ("PircusTest", ["-J", "Gateway,Gateway2"]),
                              ("PircusTest", ["-JGateway"]),
                              ("PircusTest", ["-J", f"{username}@Gateway:{ssh_port}"]),
                              ("PircusTest", ["-J", f"ssh://{username}@Gateway:{ssh_port}"]),
                              ("PircusTest", ["-J", f"{username}@GatewayToken:{ssh_port}"]),
                              ("DirectOverride", ["-J", "none"])]:
            cli = alias(name, options)
            relay(ready(cli), echo.server_address[1])
            os.kill(cli.pid, signal.SIGTERM)
            cli.wait()
        with (root / "aliases").open("a") as config:
            config.write(f"Host AgentGateway\n    HostName 127.0.0.1\n    User {username}\n    Port {ssh_port}\n"
                         f"    IdentityFile none\n    IdentitiesOnly no\n    UserKnownHostsFile {root}/known_hosts\n")
        cli = alias("PircusTest", ["-i", str(root / "client"), "-J", "AgentGateway"], env=agent_environment)
        relay(ready(cli), echo.server_address[1])
        os.kill(cli.pid, signal.SIGTERM)
        cli.wait()
        print("PASS: automatic ProxyJump, explicit -J, forwarding-only gateways, and independent agent authentication")
        cli = start([*identity, "-F", str(root / "missing_config")])
        cli.expect(b"ssh -G failed")
        cli.wait(1)
        cli = start(["--batch"], {**environment, "SSH_AUTH_SOCK": str(root / "missing-agent")})
        cli.expect(b"outerssh:")
        cli.wait(1)
        occupied = stack.enter_context(socket.socket())
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        cli = start([*identity, "--batch", "-D", str(occupied.getsockname()[1])])
        cli.expect(b"Failed to bind")
        cli.wait(1)
        cli = start([*identity, "--batch", "-L", f"{occupied.getsockname()[1]}:localhost:80",
                     "-L", f"0:localhost:{echo.server_address[1]}"])
        started_port = int(cli.expect(rb"Forward listening on 127\.0\.0\.1:(\d+)").group(1))
        cli.expect(b"Failed to bind")
        cli.wait(1)
        with socket.socket() as stream:
            assert stream.connect_ex(("127.0.0.1", started_port)) != 0
        (root / "known_hosts").write_text(f"[127.0.0.1]:{ssh_port} " + (root / "other.pub").read_text())
        cli = start([*identity, "--batch"])
        cli.expect(b"does not match known_hosts")
        cli.wait(1)
        print("PASS: ssh -G aliases/includes/overrides/identity tokens/agent settings/config errors, CLI arguments, host trust/TOFU/hashed keys/mismatch, private/agent keys and encrypted-key behavior, "
              "SOCKS authentication, optional HTTP rewriting, unchanged HTTP/binary relay, half-close, port conflicts, and signal shutdown")


if __name__ == "__main__":
    main()
