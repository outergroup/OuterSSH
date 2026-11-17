#!/usr/bin/env python3
"""Test a native CLI against a disposable SSH/echo/HTTP fixture on another host.

The SSH alias must use a trusted host key and a noninteractive identity. The remote
HTTP fixture should return the X-Outer-Loop-User header followed by | and Connection.
"""
import argparse
import base64
import contextlib
import ctypes
import http.client
import os
from pathlib import Path
import queue
import re
import signal
import socket
import subprocess
import threading


def receive(connection, count):
    result = b""
    while len(result) < count:
        data = connection.recv(count - len(result))
        assert data, "Unexpected EOF"
        result += data
    return result


class CLI:
    def __init__(self, args, options):
        self.lines = queue.Queue()
        self.output = []
        self.process = subprocess.Popen(
            [args.binary, "-F", args.config, "--batch", *options, args.alias],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            env={**os.environ, "OUTERSSH_TEST_PASSWORD": "secret"},
            creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0)
        def read():
            for line in self.process.stderr:
                self.lines.put(line)
            self.lines.put(b"")
        threading.Thread(target=read, daemon=True).start()

    def ready(self, name):
        pattern = name.encode() + rb" listening on 127\.0\.0\.1:(\d+)"
        while True:
            for line in self.output:
                match = re.search(pattern, line)
                if match:
                    return int(match.group(1))
            try:
                line = self.lines.get(timeout=30)
            except queue.Empty:
                raise AssertionError(self.output)
            if not line:
                self.process.wait(timeout=15)
                raise AssertionError(self.output)
            self.output.append(line)

    def close(self):
        try:
            if self.process.poll() is None:
                if os.name == "nt":
                    kernel = ctypes.windll.kernel32
                    kernel.FreeConsole()
                    assert kernel.AttachConsole(self.process.pid), ctypes.get_last_error()
                    handler = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_ulong)(lambda event: True)
                    assert kernel.SetConsoleCtrlHandler(handler, True)
                    assert kernel.GenerateConsoleCtrlEvent(1, 0)
                    assert self.process.wait(timeout=15) == 0, self.output
                    kernel.FreeConsole()
                else:
                    self.process.send_signal(signal.SIGTERM)
                    assert self.process.wait(timeout=15) == 0, self.output
            else:
                assert self.process.returncode == 0, self.output
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda path: str(Path(path).resolve()))
    parser.add_argument("--config", required=True)
    parser.add_argument("--alias", default="PircusTest")
    parser.add_argument("--user", required=True)
    parser.add_argument("--echo-port", required=True, type=int)
    parser.add_argument("--http-port", required=True, type=int)
    args = parser.parse_args()
    subprocess.run([args.binary, "--help"], check=True, capture_output=True)
    for options in ([], ["-D", "-1"], ["--http-proxy=65536"], ["-L", "8080:localhost:80", "--rewrite-http"]):
        result = subprocess.run([args.binary, *options, args.alias], capture_output=True)
        assert result.returncode == 2, result
    cli = CLI(args, ["-L", f"0:localhost:{args.echo_port}"])
    try:
        port = cli.ready("Forward")
        with socket.create_connection(("127.0.0.1", port), timeout=10) as stream:
            payload = bytes(range(256)) * 256
            stream.sendall(payload)
            stream.shutdown(socket.SHUT_WR)
            assert receive(stream, len(payload)) == payload
            assert stream.recv(1) == b""
    finally:
        cli.close()
    with socket.socket() as stream:
        assert stream.connect_ex(("127.0.0.1", port)) != 0
    print("PASS: raw local forwarding, binary data, half-close, and shutdown")
    for socks, http_enabled, rewrite, authenticated in ((True, False, False, False), (False, True, False, False),
                                               (True, False, True, False), (True, False, True, True), (True, True, True, False), (True, True, True, True)):
        options = []
        if socks:
            options += ["-D0"]
        if http_enabled:
            options += ["--http-proxy=0"]
        if rewrite:
            options += ["--rewrite-http"]
        if authenticated:
            options += ["--proxy-user", "test", "--proxy-password-env", "OUTERSSH_TEST_PASSWORD"]
        cli = CLI(args, options)
        with contextlib.ExitStack() as stack:
            stack.callback(cli.close)
            if socks:
                port = cli.ready("SOCKS5")
                with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
                    connection.sendall(bytes([5, 1, 2 if authenticated else 0]))
                    assert receive(connection, 2) == bytes([5, 2 if authenticated else 0])
                    if authenticated:
                        connection.sendall(b"\x01\x04test\x06secret")
                        assert receive(connection, 2) == b"\x01\x00"
                    connection.sendall(b"\x05\x01\x00\x03\x09localhost" + args.echo_port.to_bytes(2, "big"))
                    assert receive(connection, 10)[:2] == b"\x05\x00"
                    data = (b"opaque payload" if rewrite else b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n") + bytes(range(256)) * 32
                    connection.sendall(data)
                    assert receive(connection, len(data)) == data
                    connection.shutdown(socket.SHUT_WR)
                    assert connection.recv(1) == b""
            if http_enabled:
                port = cli.ready("HTTP proxy")
                headers = {"Proxy-Authorization": "Basic " + base64.b64encode(b"test:secret").decode()} if authenticated else {}
                if authenticated:
                    denied = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    denied.request("GET", f"http://localhost:{args.http_port}/")
                    response = denied.getresponse()
                    assert response.status == 407
                    response.read()
                    denied.close()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                for _ in range(3):
                    connection.request("GET", f"http://localhost:{args.http_port}/", headers=headers)
                    response = connection.getresponse()
                    assert response.status == 200 and not response.will_close
                    assert response.read() == b"|"
                connection.close()
                tunnel = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                tunnel.set_tunnel("localhost", args.echo_port, headers=headers)
                tunnel.connect()
                data = b"opaque tunnel payload\x00\xff"
                tunnel.sock.sendall(data)
                assert receive(tunnel.sock, len(data)) == data
                tunnel.close()
        print(f"PASS: SOCKS={socks} HTTP={http_enabled} rewriting={rewrite} authenticated={authenticated}", flush=True)


if __name__ == "__main__":
    main()
