#!/usr/bin/env python3
import base64
import gzip
import os
import pwd
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import run_authentication


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except (ConnectionResetError, BrokenPipeError):
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def main():
    build = Path(sys.argv[1]).resolve()
    subprocess.run(["useradd", "-m", "-s", "/bin/sh", "outerssh-test"], check=True)
    subprocess.run(["useradd", "-m", "-s", "/bin/sh", "outerssh-second"], check=True)
    subprocess.run(["chpasswd"], input="outerssh-test:outerssh-test-password\nouterssh-second:outerssh-test-password\n"
                   f"root:{secrets.token_urlsafe(32)}\n", text=True, check=True)
    Path("/run/sshd").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="outerssh-integration-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        for name in ("host", "client"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(root / name)], check=True)
        (root / "host.blob").write_bytes(base64.b64decode((root / "host.pub").read_text().split()[1]))
        tcp = TCPServer(("127.0.0.1", 0), Echo)
        unix = UnixServer(str(root / "echo.sock"), Echo)
        denied = UnixServer(str(root / "echo.sock-denied"), Echo)
        user = pwd.getpwnam("outerssh-test")
        os.chown(root / "echo.sock-denied", user.pw_uid, user.pw_gid)
        (root / "echo.sock-denied").chmod(0o600)
        os.chown(root / "echo.sock", user.pw_uid, user.pw_gid)
        (root / "echo.sock").chmod(0o600)
        allowlist = Path(user.pw_dir) / ".config/outerssh/http-unix.allow"
        allowlist.parent.mkdir(parents=True)
        allowlist.write_text(f"{root / 'echo.sock'}\n")
        for path in (allowlist.parent.parent, allowlist.parent, allowlist):
            os.chown(path, user.pw_uid, user.pw_gid)
        allowlist.chmod(0o600)
        second_unix = UnixServer(str(root / "second.sock"), Echo)
        second_user = pwd.getpwnam("outerssh-second")
        os.chown(root / "second.sock", second_user.pw_uid, second_user.pw_gid)
        (root / "second.sock").chmod(0o600)
        second_allowlist = Path(second_user.pw_dir) / ".config/outerssh/http-unix.allow"
        second_allowlist.parent.mkdir(parents=True)
        second_allowlist.write_text(f"{root / 'second.sock'}\n")
        for path in (second_allowlist.parent.parent, second_allowlist.parent, second_allowlist):
            os.chown(path, second_user.pw_uid, second_user.pw_gid)
        second_allowlist.chmod(0o600)
        for server in (tcp, unix, denied, second_unix):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            ssh_port = reserve.getsockname()[1]
        (root / "sshd_config").write_text(f"""Port {ssh_port}
ListenAddress 127.0.0.1
HostKey {root / 'host'}
PidFile {root / 'sshd.pid'}
AuthorizedKeysFile {root / 'client.pub'}
StrictModes no
UsePAM no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers outerssh-test
MaxSessions 32
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
RekeyLimit 64K
LogLevel ERROR
""")
        with (root / "sshd.log").open("w+") as log:
            sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(root / "sshd_config")],
                                    stdout=log, stderr=log, start_new_session=True)
            try:
                for _ in range(100):
                    if sshd.poll() is not None:
                        raise RuntimeError("sshd exited before listening")
                    try:
                        with socket.create_connection(("127.0.0.1", ssh_port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise TimeoutError("sshd did not start")
                run_authentication.run(build, root, ssh_port)
                bridge = root / "outerloop-helper-linux-glibc.gz"
                bridge.write_bytes(gzip.compress((build / "outerssh-test-bridge").read_bytes()))
                subprocess.run([str(build / "outerssh-integration-test"), str(ssh_port),
                                str(root / "client"), str(root / "host.blob"),
                                str(tcp.server_address[1]), str(root / "echo.sock"),
                                str(bridge)], check=True, timeout=120)
                with socket.socket() as reserve:
                    reserve.bind(("127.0.0.1", 0))
                    second_port = reserve.getsockname()[1]
                second_config = (root / "sshd_config").read_text().replace(
                    f"Port {ssh_port}", f"Port {second_port}").replace("AllowUsers outerssh-test", "AllowUsers outerssh-second")
                (root / "second_sshd_config").write_text(second_config)
                second = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(root / "second_sshd_config")],
                                          stdout=log, stderr=log, start_new_session=True)
                try:
                    for _ in range(100):
                        try:
                            with socket.create_connection(("127.0.0.1", second_port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        raise TimeoutError("second sshd did not start")
                    subprocess.run([str(build / "outerssh-shared-proxy-test"), str(ssh_port),
                                    str(root / "client"), str(root / "host.blob"),
                                    str(tcp.server_address[1]), str(root / "echo.sock"),
                                    str(bridge), str(second_port), str(root / "second.sock")], check=True, timeout=120)
                finally:
                    os.killpg(second.pid, signal.SIGTERM)
                    second.wait(timeout=10)
                if os.environ.get("OUTERSSH_SKIP_REKEY_TESTS") == "1":
                    return
                subprocess.run([str(build / "outerssh-rekey-test"), "unused", "unused", "unused", "unused"],
                               check=True, timeout=90)
                for method in ("curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"):
                    for cipher in ("aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-ctr"):
                        args = [str(root / "host"), str(root / "client"), method, cipher]
                        for ending in ("cancel", "timeout", "disconnect"):
                            subprocess.run([str(build / "outerssh-reactor-rekey-test"), *args, ending],
                                           check=True, timeout=90)
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                os.killpg(sshd.pid, signal.SIGTERM)
                sshd.wait(timeout=10)
                for server in (tcp, unix, denied, second_unix):
                    server.shutdown()
                    server.server_close()


if __name__ == "__main__":
    main()
