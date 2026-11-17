#!/usr/bin/env python3
"""Exercise the shared HTTP proxy against a deterministic forwarding fixture."""
import concurrent.futures
import base64
import contextlib
import http.client
import os
import queue
import re
import socket
import subprocess
import sys
import threading


def read_exact(stream, n):
    data = stream.read(n)
    assert len(data) == n, (len(data), n)
    return data


def headers(stream):
    first = stream.readline()
    assert first.endswith(b"\r\n"), first
    fields = {}
    while (line := stream.readline()) != b"\r\n":
        assert line.endswith(b"\r\n"), line
        name, value = line.rstrip(b"\r\n").split(b":", 1)
        fields[name.lower()] = value.strip()
    return first, fields


def body(stream, fields):
    if fields.get(b"transfer-encoding") == b"chunked":
        chunks = []
        while True:
            n = int(stream.readline().split(b";", 1)[0], 16)
            if not n:
                while stream.readline() != b"\r\n":
                    pass
                return b"".join(chunks)
            chunks.append(read_exact(stream, n))
            assert read_exact(stream, 2) == b"\r\n"
    return read_exact(stream, int(fields.get(b"content-length", 0)))


class ForwardingFixture:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.jobs = queue.Queue()
        self.stopped = False
        self.workers = []
        self.accepts = 0
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def expect(self, handler, before_connect=None):
        result = concurrent.futures.Future()
        self.jobs.put((handler, result, before_connect))
        return result

    def run(self):
        while not self.stopped:
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepts += 1
            job = self.jobs.get(timeout=10)
            worker = threading.Thread(target=self.handle, args=(conn, *job))
            self.workers.append(worker)
            worker.start()

    def handle(self, conn, handler, result, before_connect):
        try:
            with conn, conn.makefile("rb") as stream:
                conn.settimeout(8)
                host_length = int.from_bytes(read_exact(stream, 2), "big")
                port = int.from_bytes(read_exact(stream, 2), "big")
                host = read_exact(stream, host_length).decode()
                accepted = before_connect() if before_connect else True
                conn.sendall(bytes([accepted]))
                result.set_result(handler(conn, stream, host, port))
        except BaseException as error:
            import traceback
            traceback.print_exc()
            result.set_exception(error)

    def close(self):
        self.stopped = True
        self.listener.close()
        self.thread.join(3)
        for thread in self.workers:
            thread.join(10)
            assert not thread.is_alive()


@contextlib.contextmanager
def proxy(transport, mode="rewrite", with_process=False, expected_stderr=None):
    process = subprocess.Popen([sys.argv[1], str(transport.port), mode], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        port = int(process.stdout.readline())
        assert port > 0
        yield (port, process) if with_process else port
    finally:
        if process.poll() is None:
            process.stdin.write(b"\n")
            process.stdin.flush()
        _, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, (process.returncode, stderr.decode())
        if expected_stderr is not None:
            assert re.fullmatch(expected_stderr, stderr), stderr.decode()
        else:
            assert not stderr, stderr.decode()


def request(path="/", host="host", method="GET", fields=b"", data=b""):
    return f"{method} http://{host}{path} HTTP/1.1\r\nHost: {host}\r\n".encode() + fields + b"\r\n" + data


def connect(port):
    return socket.create_connection(("127.0.0.1", port), timeout=8)


def response(conn, method="GET"):
    r = http.client.HTTPResponse(conn, method=method)
    r.begin()
    data = r.read()
    return r, data


def test_reuse(transport, port):
    host = "localhost.tcp.outerssh.localhost:8888"
    def origin(conn, stream, routed_host, routed_port):
        assert (routed_host, routed_port) == ("localhost.tcp.outerssh.localhost", 8888)
        for i in range(3):
            first, fields = headers(stream)
            assert first == f"GET /{i} HTTP/1.1\r\n".encode()
            assert fields[b"host"] == b"localhost:8888", fields
            assert fields[b"origin"] == b"http://localhost:8888"
            assert b"x-outer-loop-user" not in fields
            assert b"connection" not in fields and b"x-hop" not in fields
            html = b'<a href="http://localhost:9000/page">x</a>'
            if i == 1:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n")
                for part in [html[:10], html[10:]]:
                    conn.sendall(f"{len(part):x};extension=yes\r\n".encode() + part + b"\r\n")
                conn.sendall(b"0\r\nX-Trailer: yes\r\n\r\n")
            else:
                conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nLocation: http://localhost:8888/next\r\n"
                             f"Content-Length: {len(html)}\r\n\r\n".encode() + html)
        assert stream.read(1) == b""
    job = transport.expect(origin)
    with connect(port) as c:
        for i in range(3):
            c.sendall(request(f"/{i}", host, fields=f"Origin: http://{host}\r\nConnection: X-Hop\r\nX-Hop: discard\r\n".encode()))
            r, data = response(c)
            assert r.status == 200 and not r.will_close
            assert r.getheader("Access-Control-Allow-Origin") is None
            assert r.getheader("Location") == (None if i == 1 else "http://localhost.tcp.outerssh.localhost:8888/next")
            assert b"http://localhost.tcp.outerssh.localhost:9000/page" in data, data
    job.result(10)


def test_authority_policy(transport, port, rewrite_authorities=True, rewrite_html=True):
    cases = [
        ("worker.internal", None, False),
        ("worker.local", None, False),
        ("worker", None, False),
        ("localhost", None, False),
        ("192.168.1.4", None, False),
        ("[::1]", None, False),
        ("example.com", None, False),
        ("localhost.tcp.outerssh.localhost:8080", "localhost:8080", True),
        ("LOCALHOST.TCP.OUTERSSH.LOCALHOST.:8080", "localhost:8080", True),
        ("127.0.0.1.tcp.outerssh.localhost:8080", "127.0.0.1:8080", True),
        ("ip6-localhost.tcp.outerssh.localhost:8080", "[::1]:8080", True),
        ("f4.unix.outerssh.localhost", None, True),
    ]
    body = b'<a href="http://localhost:9000/">app</a>'
    for host, replacement, rewrite_body in cases:
        authority = replacement if rewrite_authorities and replacement else host
        def origin(conn, stream, routed_host, routed_port):
            first, fields = headers(stream)
            assert fields[b"origin"] == f"http://{authority}".encode(), fields
            assert fields[b"referer"] == f"http://{authority}/page".encode(), fields
            assert fields[b"sec-websocket-origin"] == f"http://{authority}".encode(), fields
            assert fields[b"host"] == (replacement if rewrite_authorities and replacement else host.lower()).encode(), fields
            conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
        job = transport.expect(origin)
        with connect(port) as c:
            fields = (f"Origin: http://{host}\r\nReferer: http://{host}/page\r\n"
                      f"Sec-WebSocket-Origin: http://{host}\r\n").encode()
            c.sendall(request(host=host, fields=fields))
            r, data = response(c)
            assert r.status == 200
            assert data == (body.replace(b"localhost:9000", b"localhost.tcp.outerssh.localhost:9000") if rewrite_html and rewrite_body else body)
        job.result(10)


def test_cross_port_cors(transport, port, rewrite_authorities=True):
    host = "localhost.tcp.outerssh.localhost:34157"
    browser_origin = "http://localhost.tcp.outerssh.localhost:3000"
    backend_origin = "http://localhost:3000"

    def origin(conn, stream, routed_host, routed_port):
        for method in ("OPTIONS", "GET"):
            first, fields = headers(stream)
            assert first.startswith(f"{method} /api/events/count ".encode()), first
            expected = backend_origin if rewrite_authorities else browser_origin
            assert fields[b"origin"] == expected.encode(), fields
            if method == "OPTIONS":
                assert fields[b"access-control-request-method"] == b"GET"
                assert fields[b"access-control-request-headers"] == b"x-session-api-key"
            if rewrite_authorities:
                conn.sendall(("HTTP/1.1 200 OK\r\n"
                              f"Access-Control-Allow-Origin: {backend_origin}\r\n"
                              "Access-Control-Allow-Credentials: true\r\n"
                              "Access-Control-Allow-Methods: GET\r\n"
                              "Access-Control-Allow-Headers: x-session-api-key\r\n"
                              "Vary: Origin\r\nContent-Length: 2\r\n\r\nOK").encode())
            else:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")

    job = transport.expect(origin)
    with connect(port) as c:
        for method in ("OPTIONS", "GET"):
            fields = f"Origin: {browser_origin}\r\n".encode()
            if method == "OPTIONS":
                fields += (b"Access-Control-Request-Method: GET\r\n"
                           b"Access-Control-Request-Headers: x-session-api-key\r\n")
            c.sendall(request("/api/events/count", host, method, fields))
            r, data = response(c)
            assert r.status == (200 if rewrite_authorities else 400)
            assert r.getheader("Access-Control-Allow-Origin") == (browser_origin if rewrite_authorities else None)
            if rewrite_authorities:
                assert r.getheader("Access-Control-Allow-Credentials") == "true"
                assert r.getheader("Vary") == "Origin"
                assert data == b"OK"
    job.result(10)


def test_socket_redirect(transport, port):
    host = "f4.unix.outerssh.localhost"
    def origin(conn, stream, routed_host, routed_port):
        assert (routed_host, routed_port) == (host, 80)
        _, fields = headers(stream)
        assert fields[b"host"] == host.encode(), fields
        assert b"x-forwarded-host" not in fields
        conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://" + host.encode() + b"/auth-sign-in?appUri=%2F\r\nContent-Length: 0\r\n\r\n")
    job = transport.expect(origin)
    with connect(port) as c:
        c.sendall(request(host=host))
        r, _ = response(c)
        assert r.status == 302
        assert r.getheader("Location") == "http://" + host + "/auth-sign-in?appUri=%2F"
    job.result(10)


def test_rewriting_disabled(transport):
    with proxy(transport, "raw") as port:
        test_authority_policy(transport, port, False, False)
        test_cross_port_cors(transport, port, False)
    with proxy(transport, "raw") as port:
        received_prefix = threading.Event()
        prefix = b'<a href="http://localhost:9000/">'
        suffix = b'app</a>'
        def origin(conn, stream, host, port):
            _, fields = headers(stream)
            assert fields[b"host"] == b"f4.unix.outerssh.localhost", fields
            conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(prefix) + len(suffix)}\r\n\r\n".encode() + prefix)
            assert received_prefix.wait(5), "A proxy without rewriting buffered the HTML response"
            conn.sendall(suffix)
        job = transport.expect(origin)
        with connect(port) as c:
            c.sendall(request(host="f4.unix.outerssh.localhost"))
            r = http.client.HTTPResponse(c)
            r.begin()
            assert r.status == 200
            assert r.read(len(prefix)) == prefix
            received_prefix.set()
            assert r.read() == suffix
        job.result(10)


def test_rewrite_boundaries(transport, port):
    host = "localhost.tcp.outerssh.localhost:8888"
    released_body = threading.Event()
    html = b"<p>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1000</p>http://localhost:9000/"
    encoded = b"\x1f\x8bhttp://localhost:9000/\x00\xff"
    def origin(conn, stream, routed_host, routed_port):
        for i in range(4):
            first, fields = headers(stream)
            assert fields[b"host"] == b"localhost:8888"
            if i == 1:
                assert first.startswith(b"HEAD ")
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1000\r\n\r\n")
            elif i == 2:
                conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {len(encoded)}\r\n\r\n".encode() + encoded)
            else:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n")
                if i == 0:
                    assert released_body.wait(5), "Response headers were buffered with the HTML body"
                for byte in html:
                    conn.sendall(b"1\r\n" + bytes([byte]) + b"\r\n")
                conn.sendall(b"0\r\n\r\n")
    job = transport.expect(origin)
    with connect(port) as c:
        for i in range(4):
            method = "HEAD" if i == 1 else "GET"
            fields = f"Origin: http://localhost:{3000 + i}\r\n".encode() if i < 3 else b""
            c.sendall(request(host=host, method=method, fields=fields))
            r = http.client.HTTPResponse(c, method=method)
            r.begin()
            if i == 0:
                released_body.set()
            assert r.status == 200 and not r.will_close
            assert r.getheader("Access-Control-Allow-Origin") is None
            data = r.read()
            if i == 1:
                assert data == b"" and r.getheader("Content-Length") == "1000"
                assert r.getheader("Transfer-Encoding") is None
            else:
                assert r.getheader("Content-Length") is None
                assert r.getheader("Transfer-Encoding") == "chunked"
                assert data == (encoded if i == 2 else html.replace(b"http://localhost:9000/", b"http://localhost.tcp.outerssh.localhost:9000/"))
    job.result(10)


def test_framing(transport, port):
    def origin(conn, stream, host, port):
        assert host == "host"
        first, fields = headers(stream)
        assert first.startswith(b"POST /upload") and fields[b"expect"] == b"100-continue"
        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        assert body(stream, fields) == b"hello world"
        conn.sendall(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
        first, fields = headers(stream)
        assert first.startswith(b"HEAD ")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nContent-Type: text/html\r\n\r\n")
        for status in (204, 304):
            headers(stream)
            conn.sendall(f"HTTP/1.1 {status} Fine\r\n\r\n".encode())
        headers(stream)
        conn.sendall(b"HTTP/1.1 299 Custom\r\nContent-Length: 3\r\n\r\nend")
    job = transport.expect(origin)
    with connect(port) as c, c.makefile("rb") as stream:
        c.sendall(request("/upload", method="POST", fields=b"Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n"))
        first, _ = headers(stream)
        assert b"100" in first
        c.sendall(b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-End: true\r\n\r\n")
        first, fields = headers(stream)
        assert b"201" in first and body(stream, fields) == b"ok"
        c.sendall(request(method="HEAD") + request("/204") + request("/304") + request("/custom"))
        first, fields = headers(stream)
        assert fields[b"content-length"] == b"1234"
        for status in (204, 304):
            first, fields = headers(stream)
            assert str(status).encode() in first and b"transfer-encoding" not in fields
        first, fields = headers(stream)
        assert b"299" in first and body(stream, fields) == b"end"
    job.result(10)


def test_reconnect(transport, port):
    def first(conn, stream, host, port):
        headers(stream)
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfirst")
    def second(conn, stream, host, port):
        assert host == "other" and port == 9000
        headers(stream)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")
    a, b = transport.expect(first), transport.expect(second)
    with connect(port) as c:
        c.sendall(request())
        r, data = response(c)
        assert data == b"first" and not r.will_close
        c.sendall(request(host="other:9000"))
        assert response(c)[1] == b"second"
    a.result(10); b.result(10)


def test_tunnel(transport, port, upgrade=False, version="1.1"):
    payload = bytes(range(256)) * 8192
    def origin(conn, stream, host, port):
        if upgrade:
            _, fields = headers(stream)
            assert fields[b"connection"] == b"Upgrade"
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nwelcome")
        assert read_exact(stream, len(payload)) == payload
        assert stream.read(1) == b""
        conn.sendall(payload)
    job = transport.expect(origin)
    with connect(port) as c, c.makefile("rb") as stream:
        if upgrade:
            c.sendall(request(fields=b"Connection: Upgrade\r\nUpgrade: websocket\r\n").replace(b"http://", b"ws://", 1))
            assert b"101" in headers(stream)[0]
            assert read_exact(stream, 7) == b"welcome"
        else:
            c.sendall(f"CONNECT host:443 HTTP/{version}\r\nHost: host:443\r\n\r\n".encode() + payload[:100])
            assert b"200" in headers(stream)[0]
        c.sendall(payload if upgrade else payload[100:])
        c.shutdown(socket.SHUT_WR)
        assert read_exact(stream, len(payload)) == payload
        assert stream.read(1) == b""
    job.result(10)


def test_listener_recovery(transport):
    def origin(conn, stream, host, port):
        headers(stream)
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        for _ in range(12):
            data = read_exact(stream, 4)
            assert data == b"ping"
            conn.sendall(b"pong")
    job = transport.expect(origin)
    with proxy(transport, with_process=True) as (port, process):
        with connect(port) as c, c.makefile("rb") as stream:
            c.sendall(request(fields=b"Connection: Upgrade\r\nUpgrade: websocket\r\n"))
            assert b"101" in headers(stream)[0]
            for command in (b"refresh\n", b"repair\n") * 6:
                process.stdin.write(command)
                process.stdin.flush()
                assert process.stdout.readline() in (b"REFRESHED\n", b"REFRESHED\r\n")
                c.sendall(b"ping")
                assert read_exact(stream, 4) == b"pong"
                # New requests also work on the original port after repair.
                test_reuse(transport, port)
    job.result(10)


def test_destroy_during_listener_recovery(transport):
    process = subprocess.Popen([sys.argv[1], str(transport.port)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert int(process.stdout.readline()) > 0
    process.stdin.write(b"repair-destroy\n")
    process.stdin.flush()
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 0 and stdout in (b"REFRESHED\n", b"REFRESHED\r\n") and not stderr, (stdout, stderr)


def socket_host(path):
    bits = "".join(f"{byte:08b}" for byte in path.encode())
    text = "".join("abcdefghijklmnopqrstuvwxyz234567"[int(bits[i:i + 5].ljust(5, "0"), 2)] for i in range(0, len(bits), 5))
    return ".".join(text[i:i + 50] for i in range(0, len(text), 50)) + ".unix.outerssh.localhost"


ROOT = socket_host("/root/files.sock")
OTHER_ROOT = socket_host("/root/other.sock")
USER = socket_host("/home/user/app.sock")
OTHER_USER = socket_host("/home/user/other.sock")
UNKNOWN = socket_host("/new/files.sock")
BOB = socket_host("/bob/app.sock")
OTHER_BOB = socket_host("/bob/other.sock")
ABSENT = socket_host("/absent/app.sock")


def forwarded(transport, port, host, method="GET", fields=b""):
    seen = {}
    def origin(conn, stream, routed_host, routed_port):
        first, request_fields = headers(stream)
        seen.update(first=first, fields=request_fields)
        conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
    job = transport.expect(origin)
    with connect(port) as c:
        c.sendall(request("/act", host, method, fields))
        assert response(c, method)[0].status == 204
    job.result(10)
    return seen


def blocked(transport, port, host, method="POST", fields=b"", connects=False):
    before = transport.accepts
    job = None
    if connects:
        def origin(conn, stream, routed_host, routed_port):
            assert stream.read() == b""
        job = transport.expect(origin)
    with connect(port) as c:
        c.sendall(request("/act", host, method, fields + (b"Content-Length: 0\r\n" if method == "POST" else b"")))
        r, data = response(c, method)
        assert r.status == 403, r.status
        assert b"Request Blocked" in data
    if job:
        job.result(10)
    assert transport.accepts == before + (1 if connects else 0)


def test_socket_ownership(transport, port):
    origin = lambda host: f"Origin: http://{host}\r\n".encode()
    forwarded(transport, port, ROOT)
    forwarded(transport, port, ROOT, "HEAD")
    forwarded(transport, port, ROOT, "POST", origin(ROOT) + b"Content-Length: 0\r\n")
    forwarded(transport, port, ROOT, "POST", f"Origin: http://{ROOT.upper()}:80\r\n".encode() + b"Content-Length: 0\r\n")
    forwarded(transport, port, ROOT, "POST", origin(OTHER_ROOT) + b"Content-Length: 0\r\n")
    forwarded(transport, port, ROOT, "POST", b"Origin: null\r\nSec-Fetch-Site: same-origin\r\nContent-Length: 0\r\n")
    forwarded(transport, port, USER)
    forwarded(transport, port, USER, "POST", origin(USER) + b"Content-Length: 0\r\n")
    forwarded(transport, port, USER, "POST", origin(OTHER_USER) + b"Content-Length: 0\r\n")
    forwarded(transport, port, USER, "POST", origin(ROOT) + b"Content-Length: 0\r\n")
    for fields in (b"Origin: http://example.com\r\n", b"Origin: null\r\n",
                   b"Origin: http://localhost.tcp.outerssh.localhost:8080\r\n", origin(BOB),
                   b"Sec-Fetch-Site: cross-site\r\n"):
        blocked(transport, port, USER, fields=fields)
    forwarded(transport, port, USER, "POST", b"Content-Length: 0\r\n")
    forwarded(transport, port, USER, "GET", b"Connection: Upgrade\r\nUpgrade: websocket\r\n")
    for host in (BOB, ROOT):
        blocked(transport, port, host)
        blocked(transport, port, host, "GET", b"Connection: Upgrade\r\nUpgrade: websocket\r\n")
    blocked(transport, port, USER, "GET", origin(BOB) + b"Connection: Upgrade\r\nUpgrade: websocket\r\n")
    forwarded(transport, port, USER, "GET", origin(OTHER_USER) + b"Connection: Upgrade\r\nUpgrade: websocket\r\n")
    for fields in (origin(USER), b"Origin: http://example.com\r\n", b"Origin: null\r\n",
                   f"Origin: http://{ROOT}:81\r\n".encode(), f"Origin: https://{ROOT}\r\n".encode(),
                   origin(ROOT) + origin(USER), b"", f"Origin: http://localhost.tcp.outerssh.localhost:8080\r\n".encode(),
                   origin(USER) + b"Sec-Fetch-Site: same-site\r\n",
                   b"Origin: null\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Site: same-origin\r\n"):
        blocked(transport, port, ROOT, fields=fields)
    blocked(transport, port, ROOT, "GET", origin(USER) + b"Connection: Upgrade\r\nUpgrade: websocket\r\n")
    blocked(transport, port, ROOT, "PUT", origin(USER))
    blocked(transport, port, UNKNOWN, fields=origin(USER), connects=True)
    blocked(transport, port, UNKNOWN, fields=origin(ROOT), connects=True)
    forwarded(transport, port, UNKNOWN)
    post = b"Content-Length: 0\r\n"
    for sender in (BOB, OTHER_BOB, ROOT):
        forwarded(transport, port, BOB, "POST", origin(sender) + post)
    for sender in (USER, ABSENT):
        blocked(transport, port, BOB, fields=origin(sender))
    blocked(transport, port, ROOT, fields=origin(BOB))
    forwarded(transport, port, ABSENT, "POST", origin(ABSENT) + post)
    forwarded(transport, port, ABSENT, "POST", origin(ROOT) + post)
    blocked(transport, port, ABSENT, fields=origin(BOB))


def test_page_zones(transport, port):
    origin = lambda host: f"Origin: http://{host}\r\n".encode()
    referer = lambda host, path="/page": f"Referer: http://{host}{path}\r\n".encode()
    fetch = lambda site, mode, dest: f"Sec-Fetch-Site: {site}\r\nSec-Fetch-Mode: {mode}\r\nSec-Fetch-Dest: {dest}\r\n".encode()
    image = lambda site: fetch(site, "no-cors", "image")
    tcp_page = "localhost.tcp.outerssh.localhost:8080"
    for sender in (tcp_page, BOB, USER, ABSENT):
        for site in ("cross-site", "same-site"):
            blocked(transport, port, ROOT, "GET", referer(sender) + image(site))
            blocked(transport, port, ROOT, "GET", origin(sender) + fetch(site, "cors", "empty"))
            blocked(transport, port, ROOT, "GET", referer(sender) + fetch(site, "no-cors", "script"))
    blocked(transport, port, ROOT, "GET", image("cross-site"))
    blocked(transport, port, ROOT, "GET", b"Origin: null\r\n" + image("cross-site"))
    blocked(transport, port, ROOT, "GET", origin(USER) + referer(ROOT) + image("same-site"))
    blocked(transport, port, BOB, "GET", referer(USER) + image("same-site"))
    blocked(transport, port, USER, "GET", referer(BOB) + image("same-site"))
    blocked(transport, port, USER, "GET", referer(tcp_page) + image("cross-site"))
    for path in ("/page?x=1#y", "", "?q", "#f"):
        blocked(transport, port, ROOT, "GET", referer(USER, path) + image("same-site"))
    blocked(transport, port, ROOT, "GET", f"Referer: http://{USER}:80/page\r\n".encode() + image("same-site"))
    blocked(transport, port, ROOT, "GET", f"Referer: https://{ROOT}/page\r\n".encode() + image("same-site"))
    blocked(transport, port, ROOT, "GET", f"Referer: http://{ROOT}:81/page\r\n".encode() + image("same-site"))
    blocked(transport, port, ROOT, "GET", f"Referer: http://user@{ROOT}/page\r\n".encode() + image("same-site"))
    blocked(transport, port, ROOT, "GET", f"Referer: {ROOT}/page\r\n".encode() + image("same-site"))
    for host in (USER, BOB, ABSENT, OTHER_ROOT):
        forwarded(transport, port, host, "GET", referer(ROOT) + image("same-site"))
        forwarded(transport, port, host, "GET", origin(ROOT) + fetch("same-site", "cors", "empty"))
    forwarded(transport, port, USER, "GET", f"Referer: http://{ROOT.upper()}:80/a?b#c\r\n".encode() + image("same-site"))
    forwarded(transport, port, USER, "GET", referer(ROOT, "") + image("same-site"))
    forwarded(transport, port, USER, "GET", referer(OTHER_USER) + image("same-site"))
    forwarded(transport, port, OTHER_USER, "GET", referer(USER) + fetch("same-site", "no-cors", "script"))
    forwarded(transport, port, BOB, "GET", referer(OTHER_BOB) + image("same-site"))
    forwarded(transport, port, ROOT, "GET", referer(ROOT) + image("same-origin"))
    forwarded(transport, port, ROOT, "GET", referer(USER) + image("same-origin"))
    navigation = fetch("same-site", "navigate", "document")
    for sender in (tcp_page, USER, BOB):
        forwarded(transport, port, ROOT, "GET", referer(sender) + navigation)
        forwarded(transport, port, ROOT, "HEAD", referer(sender) + navigation)
        blocked(transport, port, ROOT, "GET", referer(sender) + fetch("same-site", "navigate", "iframe"))
        blocked(transport, port, ROOT, "GET", referer(sender) + fetch("same-site", "navigate", "frame"))
        blocked(transport, port, ROOT, "GET", referer(sender) + fetch("same-site", "no-cors", "document"))
    forwarded(transport, port, ROOT, "GET", navigation)
    blocked(transport, port, ROOT, "POST", origin(USER) + navigation)
    blocked(transport, port, ROOT, "GET", origin(USER) + navigation + b"Connection: Upgrade\r\nUpgrade: websocket\r\n")
    forwarded(transport, port, ROOT, "GET", fetch("none", "navigate", "document"))
    forwarded(transport, port, ROOT, "GET", fetch("none", "no-cors", "empty"))
    forwarded(transport, port, ROOT, "HEAD", b"Sec-Fetch-Site: none\r\n")
    blocked(transport, port, ROOT, "POST", fetch("none", "navigate", "document"))
    forwarded(transport, port, ROOT, "GET", b"Accept: image/png\r\n")
    for sender in (origin(USER), origin(BOB), b"Origin: null\r\n", origin(tcp_page)):
        blocked(transport, port, ROOT, "GET", sender)
        blocked(transport, port, ROOT, "GET", sender + referer(ROOT))
    upgrade = b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
    for metadata in (navigation, fetch("none", "navigate", "document"), fetch("none", "websocket", "empty"), b""):
        for sender in (b"", origin(USER), origin(tcp_page), referer(USER)):
            blocked(transport, port, ROOT, "GET", sender + metadata + upgrade)
    forwarded(transport, port, ROOT, "GET", origin(ROOT) + upgrade)
    forwarded(transport, port, ROOT, "GET", b"Origin: null\r\nSec-Fetch-Site: same-origin\r\n" + upgrade)
    forwarded(transport, port, BOB, "HEAD")
    blocked(transport, port, ROOT, "GET", referer(USER) + b"Sec-Fetch-Mode: no-cors\r\nSec-Fetch-Dest: image\r\n"
            b"Sec-Fetch-Site: same-site\r\n")
    for duplicate in (b"Sec-Fetch-Site: none\r\n", b"Sec-Fetch-Mode: navigate\r\n", b"Sec-Fetch-Dest: document\r\n"):
        blocked(transport, port, ROOT, "GET", fetch("none", "navigate", "document") + duplicate)
    blocked(transport, port, USER, "GET", referer(OTHER_USER) + referer(OTHER_USER) + image("same-site"))
    blocked(transport, port, USER, "GET", origin(OTHER_USER) + origin(OTHER_USER) + fetch("same-site", "cors", "empty"))
    blocked(transport, port, UNKNOWN, "GET", referer(USER) + image("same-site"), connects=True)
    blocked(transport, port, UNKNOWN, "GET", referer(ROOT) + image("same-site"), connects=True)
    forwarded(transport, port, UNKNOWN, "GET", referer(USER) + navigation)


def test_pending_root_requests(transport, port):
    """Requests to root's sockets whose owner is not yet known are judged once
    authorization reveals it, before sudo: refused ones never connect."""
    origin = lambda host: f"Origin: http://{host}\r\n".encode()
    referer = lambda host: f"Referer: http://{host}/page\r\n".encode()
    fetch = lambda site, mode, dest: f"Sec-Fetch-Site: {site}\r\nSec-Fetch-Mode: {mode}\r\nSec-Fetch-Dest: {dest}\r\n".encode()
    pending = lambda name: socket_host(f"/pending/root/{name}.sock")
    tcp_page = "localhost.tcp.outerssh.localhost:8080"
    blocked(transport, port, pending("image"), "GET", referer(USER) + fetch("same-site", "no-cors", "image"))
    blocked(transport, port, pending("bob-image"), "GET", referer(BOB) + fetch("same-site", "no-cors", "image"))
    blocked(transport, port, pending("port-fetch"), "GET", origin(tcp_page) + fetch("cross-site", "cors", "empty"))
    blocked(transport, port, pending("post"), fields=origin(USER))
    blocked(transport, port, pending("bare-post"))
    forwarded(transport, port, pending("navigation"), "GET", referer(USER) + fetch("same-site", "navigate", "document"))
    forwarded(transport, port, pending("content"), "POST", origin(ROOT) + b"Content-Length: 0\r\n")
    same = socket_host("/pending/home/user/same.sock")
    forwarded(transport, port, same, "POST", origin(same) + b"Content-Length: 0\r\n")
    forwarded(transport, port, socket_host("/pending/home/user/bare.sock"), "POST", b"Content-Length: 0\r\n")


def test_loopback_zone(transport, port):
    """The SSH server's loopback ports rank above other hosts: pages from other
    hosts only navigate to them, and other hosts are not judged."""
    origin = lambda sender: f"Origin: {sender}\r\n".encode()
    referer = lambda sender: f"Referer: {sender}/page\r\n".encode()
    fetch = lambda site, mode, dest: f"Sec-Fetch-Site: {site}\r\nSec-Fetch-Mode: {mode}\r\nSec-Fetch-Dest: {dest}\r\n".encode()
    upgrade = b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
    post = b"Content-Length: 0\r\n"
    elsewhere = ("http://intranet.example", "http://10.0.0.5:8080", "https://example.com",
                 "http://localhost.example.com", "http://[fe80::1]:3000")
    on_server = ("http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000", "http://app.localhost",
                 "http://localhost.tcp.outerssh.localhost:3000", f"http://{USER}", f"http://{ROOT}")
    for host in ("localhost.tcp.outerssh.localhost:8888", "localhost:8888", "127.0.0.1:8888", "[::1]:8888",
                 "app.localhost:8888"):
        for sender in elsewhere + ("null", "http://127.1:3000"):
            blocked(transport, port, host, fields=origin(sender))
            blocked(transport, port, host, "GET", origin(sender) + fetch("cross-site", "cors", "empty"))
        for sender in elsewhere:
            blocked(transport, port, host, "GET", referer(sender) + fetch("cross-site", "no-cors", "image"))
            blocked(transport, port, host, "GET", origin(sender) + upgrade)
            blocked(transport, port, host, "GET", referer(sender) + fetch("cross-site", "navigate", "iframe"))
            forwarded(transport, port, host, "GET", referer(sender) + fetch("cross-site", "navigate", "document"))
        blocked(transport, port, host, "GET", fetch("cross-site", "no-cors", "image"))
        for sender in on_server:
            forwarded(transport, port, host, "POST", origin(sender) + post)
            forwarded(transport, port, host, "GET", origin(sender) + upgrade)
            forwarded(transport, port, host, "GET", referer(sender) + fetch("same-site", "no-cors", "image"))
        forwarded(transport, port, host, "POST", post)
        forwarded(transport, port, host, "POST", b"Origin: null\r\nSec-Fetch-Site: same-origin\r\n" + post)
        forwarded(transport, port, host, "GET", fetch("none", "navigate", "document"))
    for host in ("intranet.example:8080", "10.0.0.6", "localhost.example.com"):
        for sender in elsewhere + ("null",):
            forwarded(transport, port, host, "POST", origin(sender) + post)
    before = transport.accepts
    for host in ("127.1:8888", "2130706433:8888", "0x7f.0.0.1:8888", "0177.0.0.1:8888", "intranet.0x1f:80"):
        with connect(port) as c:
            c.sendall(request(host=host))
            assert response(c)[0].status == 400
    assert transport.accepts == before


def test_loopback_tunnels(transport, mode):
    """Tunnels to loopback ports are judged request by request even without
    rewriting; opaque streams such as TLS pass."""
    socks = mode.startswith("socks")
    post = lambda sender: (f"POST /act HTTP/1.1\r\nHost: localhost:8888\r\nOrigin: {sender}\r\n"
                           "Content-Length: 0\r\n\r\n").encode()
    with proxy(transport, mode) as port:
        for host in ("localhost", "127.0.0.1", "localhost.tcp.outerssh.localhost"):
            def refused(conn, stream, routed_host, routed_port):
                assert stream.read() == b""
            job = transport.expect(refused)
            with connect(port) as c, c.makefile("rb") as stream:
                open_tunnel(c, stream, host, 8888, socks)
                c.sendall(post("http://intranet.example"))
                first, fields = headers(stream)
                assert b" 403 " in first, first
                body(stream, fields)
                assert stream.read() == b""
            job.result(10)
            def allowed(conn, stream, routed_host, routed_port):
                first, _ = headers(stream)
                assert first.startswith(b"POST /act "), first
                conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                assert stream.read() == b""
            job = transport.expect(allowed)
            with connect(port) as c, c.makefile("rb") as stream:
                open_tunnel(c, stream, host, 8888, socks)
                c.sendall(post("http://localhost:3000"))
                assert b" 204 " in headers(stream)[0]
            job.result(10)
            def opaque(conn, stream, routed_host, routed_port):
                assert read_exact(stream, 10) == b"\x16\x03\x01\x00\x05hello"
                conn.sendall(b"reply")
            job = transport.expect(opaque)
            with connect(port) as c, c.makefile("rb") as stream:
                open_tunnel(c, stream, host, 8888, socks)
                c.sendall(b"\x16\x03\x01\x00\x05hello")
                assert read_exact(stream, 5) == b"reply"
            job.result(10)


def test_tunnels_wait_for_first_request(transport, mode):
    """SOCKS and CONNECT tunnels to a socket that needs sudo open without
    connecting and connect for their first request once it is judged."""
    socks = mode == "socks"
    referer = lambda host: f"Referer: http://{host}/page\r\n".encode()
    fetch = lambda site, mode, dest: f"Sec-Fetch-Site: {site}\r\nSec-Fetch-Mode: {mode}\r\nSec-Fetch-Dest: {dest}\r\n".encode()
    with proxy(transport, mode) as port:
        for host in (socket_host("/pending/root/tunnel-image.sock"), ROOT):
            before = transport.accepts
            with connect(port) as c, c.makefile("rb") as stream:
                open_tunnel(c, stream, host, 80, socks)
                c.sendall(f"GET /image HTTP/1.1\r\nHost: {host}\r\n".encode() + referer(USER) +
                          fetch("same-site", "no-cors", "image") + b"\r\n")
                first, fields = headers(stream)
                assert b" 403 " in first, first
                assert b"Request Blocked" in body(stream, fields)
                assert stream.read() == b""
            assert transport.accepts == before
        host = socket_host("/pending/root/tunnel-navigation.sock")
        def navigation(conn, stream, routed_host, routed_port):
            assert (routed_host, routed_port) == (host, 80)
            first, _ = headers(stream)
            assert first.startswith(b"GET /app "), first
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            assert stream.read() == b""
        before = transport.accepts
        job = transport.expect(navigation)
        with connect(port) as c, c.makefile("rb") as stream:
            open_tunnel(c, stream, host, 80, socks)
            assert transport.accepts == before
            c.sendall(f"GET /app HTTP/1.1\r\nHost: {host}\r\n".encode() + referer(USER) +
                      fetch("same-site", "navigate", "document") + b"\r\n")
            _, fields = headers(stream)
            assert body(stream, fields) == b"ok"
            c.sendall(f"GET /image HTTP/1.1\r\nHost: {host}\r\n".encode() + referer(USER) +
                      fetch("same-site", "no-cors", "image") + b"\r\n")
            first, fields = headers(stream)
            assert b" 403 " in first, first
            body(stream, fields)
            assert stream.read() == b""
        job.result(10)
        assert transport.accepts == before + 1


def test_foreign_socket_tunnels(transport, mode):
    socks = mode == "socks"
    with proxy(transport, mode) as port:
        def inner(conn, stream, routed_host, routed_port):
            first, _ = headers(stream)
            assert first.startswith(b"GET /page "), first
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            assert stream.read() == b""
        job = transport.expect(inner)
        with connect(port) as c, c.makefile("rb") as stream:
            open_tunnel(c, stream, ROOT, 80, socks)
            c.sendall(f"GET /page HTTP/1.1\r\nHost: {ROOT}\r\n\r\n".encode())
            _, fields = headers(stream)
            assert body(stream, fields) == b"ok"
            c.sendall(f"GET /socket HTTP/1.1\r\nHost: {ROOT}\r\nOrigin: http://{USER}\r\n"
                      "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n".encode())
            first, fields = headers(stream)
            assert b" 403 " in first, first
            body(stream, fields)
            assert stream.read() == b""
        job.result(10)
        before = transport.accepts
        with connect(port) as c, c.makefile("rb") as stream:
            open_tunnel(c, stream, ROOT, 80, socks)
            c.sendall(b"\x16\x03\x01\x00\x05hello")
            assert stream.read() == b""
        assert transport.accepts == before
        def user_opaque(conn, stream, routed_host, routed_port):
            assert read_exact(stream, 10) == b"\x16\x03\x01\x00\x05hello"
            conn.sendall(b"reply")
        job = transport.expect(user_opaque)
        with connect(port) as c, c.makefile("rb") as stream:
            open_tunnel(c, stream, USER, 80, socks)
            c.sendall(b"\x16\x03\x01\x00\x05hello")
            assert read_exact(stream, 5) == b"reply"
        job.result(10)


OTHER_ABSENT = socket_host("/absent/other.sock")


def content_relayed(transport, port, username, host, sent, answer, destination_port=80, socks=True):
    """Opens a SOCKS or CONNECT tunnel with origin credentials and checks that bytes cross it untouched."""
    def upstream(conn, stream, routed_host, routed_port):
        assert (routed_host, routed_port) == (host, destination_port)
        assert read_exact(stream, len(sent)) == sent
        conn.sendall(answer)
        assert stream.read() == b""
    job = transport.expect(upstream)
    with connect(port) as c, c.makefile("rb") as stream:
        open_tunnel(c, stream, host, destination_port, socks, username=username)
        c.sendall(sent)
        assert read_exact(stream, len(answer)) == answer
        c.shutdown(socket.SHUT_WR)
        assert stream.read() == b""
    job.result(10)


def content_refused(transport, port, username, host, authorizes=False, socks=True):
    """The SOCKS request fails with "connection not allowed", or CONNECT with 403. Only a destination
    whose owner stays unknown is connected to, and it receives nothing; one whose
    owner its authorization reveals is refused before any connection or sudo."""
    before = transport.accepts
    job = None
    if authorizes:
        def upstream(conn, stream, routed_host, routed_port):
            assert stream.read() == b""
        job = transport.expect(upstream)
    with connect(port) as c, c.makefile("rb") as stream:
        open_tunnel(c, stream, host, 80, socks, status=2, username=username)
        assert stream.read() == b""
    if job:
        job.result(10)
    assert transport.accepts == before + (1 if authorizes else 0)


def content_payloads(host):
    page = b'<a href="http://localhost:9000/">x</a>'
    forged = (f"POST /act HTTP/1.1\r\nHost: {host}\r\nOrigin: http://example.com\r\n"
              "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n"
              "Content-Length: 4\r\n\r\nbody").encode()
    answer = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + f"Content-Length: {len(page)}\r\n\r\n".encode() + page
    upgrade = (f"GET /socket HTTP/1.1\r\nHost: {host}\r\nOrigin: http://example.com\r\n"
               "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\nping").encode()
    switched = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\npong"
    return ((forged, answer), (upgrade, switched), (b"\x16\x03\x01\x00\x05hello", b"\x00reply\xff"))


def content_passes(transport, port, username, host, destination_port=80, socks=True):
    for sent, answer in content_payloads(host):
        content_relayed(transport, port, username, host, sent, answer, destination_port, socks)


def test_origin_credentials(transport, port, socks=True):
    content_passes(transport, port, b"user-origin", USER, socks=socks)
    content_passes(transport, port, b"user-origin", OTHER_USER, socks=socks)
    content_passes(transport, port, b"bob-origin", BOB, socks=socks)
    content_passes(transport, port, b"bob-origin", OTHER_BOB, socks=socks)
    content_passes(transport, port, b"absent-origin", ABSENT, socks=socks)
    for host in (ROOT, OTHER_ROOT, USER, BOB, ABSENT, OTHER_ABSENT):
        content_passes(transport, port, b"root-origin", host, socks=socks)
    for username in (b"user-origin", b"bob-origin", b"root-origin", b"absent-origin", b"tcp-origin"):
        content_passes(transport, port, username, "localhost.tcp.outerssh.localhost", 8080, socks=socks)
        content_passes(transport, port, username, "host", 8080, socks=socks)

    for host in (BOB, OTHER_BOB, ROOT, ABSENT):
        content_refused(transport, port, b"user-origin", host, socks=socks)
    for host in (ROOT, OTHER_ROOT, USER, ABSENT):
        content_refused(transport, port, b"bob-origin", host, socks=socks)
    content_refused(transport, port, b"absent-origin", OTHER_ABSENT, socks=socks)
    content_refused(transport, port, b"absent-origin", USER, socks=socks)
    for host in (USER, BOB, ROOT, ABSENT, UNKNOWN, socket_host("/pending/home/user/tcp.sock")):
        content_refused(transport, port, b"tcp-origin", host, socks=socks)
    content_passes(transport, port, b"network-origin", "intranet.example", 8080, socks=socks)
    for host in ("intranet.example", "other.example", "localhost", "localhost.tcp.outerssh.localhost", USER, ROOT):
        content_refused(transport, port, b"network-origin", host, socks=socks)

    content_refused(transport, port, b"user-origin", UNKNOWN, authorizes=True, socks=socks)
    content_refused(transport, port, b"root-origin", UNKNOWN, authorizes=True, socks=socks)
    content_refused(transport, port, b"user-origin", socket_host("/pending/bob/refused.sock"), socks=socks)
    content_refused(transport, port, b"bob-origin", socket_host("/pending/root/refused.sock"), socks=socks)
    content_refused(transport, port, b"user-origin", socket_host("/pending/root/user-refused.sock"), socks=socks)
    content_refused(transport, port, b"absent-origin", socket_host("/pending/root/absent-refused.sock"), socks=socks)
    content_relayed(transport, port, b"user-origin", socket_host("/pending/home/user/allowed.sock"),
                    b"\x16\x03\x01\x00\x05hello", b"reply", socks=socks)
    content_relayed(transport, port, b"root-origin", socket_host("/pending/bob/allowed.sock"),
                    b"\x16\x03\x01\x00\x05hello", b"reply", socks=socks)
    content_relayed(transport, port, b"root-origin", socket_host("/pending/root/allowed.sock"),
                    b"\x16\x03\x01\x00\x05hello", b"reply", socks=socks)


def origin_request(username, host, path="/", method="GET", fields=b"", data=b""):
    token = base64.b64encode(username + b":secret")
    return request(path, host, method, b"Proxy-Authorization: Basic " + token + b"\r\n" + fields, data)


def test_http_origin_requests(transport, port):
    """Plain requests through the HTTP proxy are each decided by their own origin
    credentials and destination, whatever else they send, and are not rewritten."""
    page = b'<a href="http://localhost:9000/">x</a>'
    forged = b"Origin: http://example.com\r\nSec-Fetch-Site: same-origin\r\nContent-Length: 4\r\n"
    tcp = "localhost.tcp.outerssh.localhost:8080"
    def reached(host, port_number, first_line, host_field):
        def upstream(conn, stream, routed_host, routed_port):
            assert (routed_host, routed_port) == (host, port_number)
            first, fields = headers(stream)
            assert first == first_line and fields[b"host"] == host_field, (first, fields)
            if first.startswith(b"POST"):
                assert fields[b"origin"] == b"http://example.com"
                assert read_exact(stream, 4) == b"body"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
                         f"Content-Length: {len(page)}\r\n\r\n".encode() + page)
            assert stream.read() == b""
        return transport.expect(upstream)
    jobs = [reached(USER, 80, b"POST /act HTTP/1.1\r\n", USER.encode()),
            reached(OTHER_USER, 80, b"GET / HTTP/1.1\r\n", OTHER_USER.encode()),
            reached("localhost.tcp.outerssh.localhost", 8080, b"GET / HTTP/1.1\r\n", tcp.encode())]
    before = transport.accepts
    with connect(port) as c:
        c.sendall(origin_request(b"user-origin", USER, "/act", "POST", forged, b"body"))
        r, data = response(c)
        assert r.status == 200 and data == page, (r.status, data)
        c.sendall(origin_request(b"user-origin", OTHER_USER))
        r, data = response(c)
        assert r.status == 200 and data == page
        c.sendall(origin_request(b"tcp-origin", tcp))
        r, data = response(c)
        assert r.status == 200 and data == page
        c.sendall(origin_request(b"bob-origin", USER))
        r, _ = response(c)
        assert r.status == 403 and r.will_close
    for job in jobs:
        job.result(10)
    assert transport.accepts == before + 3
    for username, host in ((b"tcp-origin", USER), (b"network-origin", tcp), (b"user-origin", BOB)):
        with connect(port) as c:
            c.sendall(origin_request(username, host))
            assert response(c)[0].status == 403
    with connect(port) as c:
        c.sendall(origin_request(b"unknown-origin", USER))
        assert response(c)[0].status == 407
    assert transport.accepts == before + 3

    allowed = socket_host("/pending/home/user/allowed.sock")
    job = reached(allowed, 80, b"GET / HTTP/1.1\r\n", allowed.encode())
    with connect(port) as c:
        c.sendall(origin_request(b"user-origin", allowed))
        r, data = response(c)
        assert r.status == 200 and data == page
    job.result(10)
    with connect(port) as c:
        c.sendall(origin_request(b"user-origin", socket_host("/pending/bob/refused.sock")))
        assert response(c)[0].status == 403
    assert transport.accepts == before + 4
    def unused(conn, stream, routed_host, routed_port):
        assert stream.read() == b""
    job = transport.expect(unused)
    with connect(port) as c:
        c.sendall(origin_request(b"user-origin", UNKNOWN))
        assert response(c)[0].status == 403
    job.result(10)
    assert transport.accepts == before + 5


def test_raw_tcp_tunnels(transport):
    """Without rewriting, TCP destinations carry bytes untouched, whatever the credentials."""
    with proxy(transport, "socks-raw") as port:
        for username in (b"browser", b"user-origin", b"tcp-origin"):
            sent = b"GET /x HTTP/1.1\r\nHost: host\r\nOrigin: http://example.com\r\nSec-Fetch-Site: same-origin\r\n\r\n"
            def raw(conn, stream, routed_host, routed_port):
                assert (routed_host, routed_port) == ("host", 8080)
                assert read_exact(stream, len(sent)) == sent
                conn.sendall(b"not http at all")
            job = transport.expect(raw)
            with connect(port) as c, c.makefile("rb") as stream:
                open_tunnel(c, stream, "host", 8080, True, username=username)
                c.sendall(sent)
                assert read_exact(stream, 15) == b"not http at all"
            job.result(10)
        def half_closed(conn, stream, routed_host, routed_port):
            assert stream.read() == b"request"
            conn.sendall(b"reply after half-close")
        job = transport.expect(half_closed)
        with connect(port) as c, c.makefile("rb") as stream:
            open_tunnel(c, stream, "host", 8080, True)
            c.sendall(b"request")
            c.shutdown(socket.SHUT_WR)
            assert stream.read() == b"reply after half-close"
        job.result(10)
        test_origin_credentials(transport, port)


def test_reject(transport, port):
    before = transport.accepts
    for fields in (b"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n", b"Content-Length: 1\r\nContent-Length: 2\r\n",
                   b"Transfer-Encoding: gzip, chunked\r\n", b"Connection: Content-Length\r\nContent-Length: 0\r\n"):
        with connect(port) as c:
            c.sendall(request(fields=fields))
            assert response(c)[0].status == 400
    assert transport.accepts == before


def test_raw_auth(transport):
    for mode, realm in (("realm", "Test"), ("realm-empty", ""), ("realm-max", "a" * 255)):
        with proxy(transport, mode) as port:
            with connect(port) as c:
                c.sendall(request())
                r, _ = response(c)
                assert r.status == 407
                assert r.getheader("Proxy-Authenticate") == f'Basic realm="{realm}"'
    with proxy(transport, "auth") as port:
        for i in range(2):
            with connect(port) as c:
                c.sendall(request())
                r, _ = response(c)
                assert r.status == 407 and r.getheader("Proxy-Authenticate") == 'Basic realm="OuterSSH"'
        def origin(conn, stream, host, port):
            for i in range(2):
                _, fields = headers(stream)
                assert b"proxy-authorization" not in fields
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        job = transport.expect(origin)
        with connect(port) as c:
            for i in range(2):
                c.sendall(request(fields=b"Proxy-Authorization: Basic YnJvd3NlcjpzZWNyZXQ=\r\n"))
                assert response(c)[0].status == 200
        job.result(10)
    with proxy(transport, "raw") as port:
        def origin(conn, stream, host, port):
            _, fields = headers(stream)
            assert b"x-outer-loop-user" not in fields
            assert fields[b"host"] == b"localhost.tcp.outerssh.localhost:8080", fields
            assert fields[b"origin"] == b"http://localhost.tcp.outerssh.localhost:8080", fields
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nraw")
        job = transport.expect(origin)
        with connect(port) as c:
            c.sendall(request(host="localhost.tcp.outerssh.localhost:8080",
                              fields=b"Origin: http://localhost.tcp.outerssh.localhost:8080\r\n"))
            assert response(c)[1] == b"raw"
        job.result(10)


def test_fragmented(transport, port):
    host = "localhost.tcp.outerssh.localhost:8888"
    def origin(conn, stream, host, port):
        first, fields = headers(stream)
        assert len(first) > 2048
        for byte in b"HTTP/1.1 304 Not Modified\r\nContent-Length: 999\r\nContent-Type: text/html\r\n\r\n":
            conn.sendall(bytes([byte]))
        headers(stream)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx")
    job = transport.expect(origin)
    with connect(port) as c:
        raw = request("/" + "x" * 2048, host)
        for offset in range(0, len(raw), 7):
            c.sendall(raw[offset:offset + 7])
        r, data = response(c)
        assert r.status == 304 and r.getheader("Content-Length") == "999" and data == b""
        c.sendall(request(host=host, fields=b"Connection: close\r\n"))
        r, data = response(c)
        assert data == b"x" and r.will_close
        assert c.recv(1) == b""
    job.result(10)


def test_large(transport, port):
    data = b'<a href="http://localhost:9000/">x</a>' + b"x" * (3 * 1024 * 1024)
    def origin(conn, stream, host, port):
        _, fields = headers(stream)
        assert body(stream, fields) == data
        conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(data)}\r\nContent-Type: text/html\r\n\r\n".encode())
        conn.sendall(data)
    job = transport.expect(origin)
    with connect(port) as c:
        c.sendall(request(host="localhost.tcp.outerssh.localhost:8888", method="POST",
                          fields=f"Content-Length: {len(data)}\r\n".encode(), data=data))
        assert response(c)[1] == data
    job.result(10)


def test_invalid_response(transport, port):
    for raw in (b"", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"):
        def origin(conn, stream, host, port):
            headers(stream)
            conn.sendall(raw)
        job = transport.expect(origin)
        with connect(port) as c:
            c.sendall(request())
            try:
                r, data = response(c)
                assert r.status == 502
            except (http.client.IncompleteRead, http.client.RemoteDisconnected):
                pass
        job.result(10)


def open_tunnel(c, stream, host, port, socks, status=0, username=b"browser"):
    if socks:
        c.sendall(b"\x05\x01\x02")
        assert read_exact(stream, 2) == b"\x05\x02"
        c.sendall(b"\x01" + bytes([len(username)]) + username + b"\x06secret")
        assert read_exact(stream, 2) == b"\x01\x00"
        encoded = host.encode()
        c.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + port.to_bytes(2, "big"))
        assert read_exact(stream, 10) == bytes([5, status, 0, 1]) + bytes(6)
    else:
        token = base64.b64encode(username + b":secret").decode()
        c.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n".encode())
        first, fields = headers(stream)
        assert (b" 403 " if status else b" 200 ") in first, first
        if status:
            read_exact(stream, int(fields[b"content-length"]))


def test_http_connect(transport, socks=False):
    host = "localhost.tcp.outerssh.localhost:8888"
    expected = rb"(OuterSSH\[3\]: SOCKS handshake failed for socket [0-9]+: SOCKS authentication failed\.\r?\n)?" if socks else None
    with proxy(transport, "socks" if socks else "apple", expected_stderr=expected) as port:
        if socks:
            with connect(port) as c, c.makefile("rb") as stream:
                c.sendall(b"\x05\x01\x02")
                assert read_exact(stream, 2) == b"\x05\x02"
                c.sendall(b"\x01\x07browser\x05wrong")
                assert read_exact(stream, 2) == b"\x01\x01"
            def failed(conn, stream, host, port):
                assert stream.read() == b""
            job = transport.expect(failed, before_connect=lambda: False)
            with connect(port) as c, c.makefile("rb") as stream:
                open_tunnel(c, stream, "host", 80, True, status=1)
            job.result(10)
        def origin(conn, stream, routed_host, routed_port):
            assert (routed_host, routed_port) == ("localhost.tcp.outerssh.localhost", 8888)
            for i in range(3):
                first, fields = headers(stream)
                assert first == f"GET /{i} HTTP/1.1\r\n".encode()
                assert fields[b"host"] == b"localhost:8888"
                assert b"x-outer-loop-user" not in fields
                assert b"proxy-authorization" not in fields
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        job = transport.expect(origin)
        with connect(port) as c, c.makefile("rb") as stream:
            open_tunnel(c, stream, "localhost.tcp.outerssh.localhost", 8888, socks)
            for i in range(3):
                raw = f"GET /{i} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
                for offset in range(0, len(raw), 3):
                    c.sendall(raw[offset:offset + 3])
                _, fields = headers(stream)
                assert body(stream, fields) == b"ok"
                assert b"connection" not in fields
        job.result(10)
        def upgraded(conn, stream, routed_host, routed_port):
            assert (routed_host, routed_port) == ("f4.unix.outerssh.localhost", 80)
            first, fields = headers(stream)
            assert first == b"POST /upload HTTP/1.1\r\n"
            assert fields[b"host"] == b"f4.unix.outerssh.localhost"
            assert fields[b"origin"] == b"http://f4.unix.outerssh.localhost"
            assert body(stream, fields) == b"hello"
            conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")
            first, fields = headers(stream)
            assert first == b"GET /ws HTTP/1.1\r\n"
            assert fields[b"host"] == b"f4.unix.outerssh.localhost"
            assert fields[b"upgrade"] == b"websocket"
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            assert read_exact(stream, 5) == b"hello"
            conn.sendall(b"world")
        job = transport.expect(upgraded)
        with connect(port) as c, c.makefile("rb") as stream:
            open_tunnel(c, stream, "f4.unix.outerssh.localhost", 80, socks)
            c.sendall(b"POST /upload HTTP/1.1\r\nHost: f4.unix.outerssh.localhost\r\nOrigin: http://f4.unix.outerssh.localhost\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n")
            assert body(stream, headers(stream)[1]) == b"ok"
            c.sendall(b"GET /ws HTTP/1.1\r\nHost: f4.unix.outerssh.localhost\r\nOrigin: http://f4.unix.outerssh.localhost\r\n"
                      b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            assert b"101" in headers(stream)[0]
            c.sendall(b"hello")
            assert read_exact(stream, 5) == b"world"
        job.result(10)
        payload = b"\x16\x03\x01" + bytes(range(256)) * 4
        def opaque(conn, stream, host, port):
            assert read_exact(stream, len(payload)) == payload
            conn.sendall(payload)
        job = transport.expect(opaque)
        with connect(port) as c, c.makefile("rb") as stream:
            open_tunnel(c, stream, "host", 443, socks)
            c.sendall(payload)
            assert read_exact(stream, len(payload)) == payload
        job.result(10)
        if socks:
            def denied(conn, stream, host, remote_port):
                assert stream.read() == b""
            job = transport.expect(denied, before_connect=lambda: 2)
            with connect(port) as c, c.makefile("rb") as stream:
                open_tunnel(c, stream, "host", 443, True, status=2)
            job.result(10)



def test_apple_webkit(transport, socks=False):
    client = os.environ.get("OUTERSSH_APPLE_HTTP_CLIENT")
    if not client:
        return
    with proxy(transport, "socks" if socks else "apple") as port:
        def origin(conn, stream, host, port):
            first, fields = headers(stream)
            assert first == b"GET /apple HTTP/1.1\r\n"
            assert fields[b"host"] == b"localhost:8888"
            content = b'<html><a href="http://localhost:8888/">link</a></html>'
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + str(len(content)).encode() + b"\r\n\r\n" + content)
            for i in range(3):
                first, fields = headers(stream)
                assert first == f"POST /check{i} HTTP/1.1\r\n".encode()
                assert fields[b"host"] == b"localhost:8888"
                assert fields[b"origin"] == b"http://localhost:8888"
                body(stream, fields)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        job = transport.expect(origin)
        result = subprocess.run([client, str(port)] + (["socks"] if socks else []), capture_output=True, timeout=20)
        assert result.returncode == 0, (result.stdout, result.stderr)
        job.result(10)
        print(result.stdout.decode().strip(), flush=True)


def test_apple_favicon(transport):
    client = os.environ.get("OUTERSSH_APPLE_HTTP_CLIENT")
    if not client:
        return
    with proxy(transport, "socks") as port:
        def origin(conn, stream, host, remote_port):
            first, fields = headers(stream)
            assert first == b"GET /static/favicons/favicon.ico HTTP/1.1\r\n"
            assert fields[b"host"] == b"f4.unix.outerssh.localhost"
            content = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aN1sAAAAASUVORK5CYII=")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nConnection: close\r\nContent-Length: " + str(len(content)).encode() + b"\r\n\r\n" + content)
        job = transport.expect(origin)
        result = subprocess.run([client, str(port), "favicon", "socks"], capture_output=True, timeout=20)
        assert result.returncode == 0, (result.stdout, result.stderr)
        job.result(10)
        print(result.stdout.decode().strip(), flush=True)


def test_connection_failure(transport, port):
    def origin(conn, stream, host, remote_port):
        assert stream.read() == b""
    for denied in (False, True):
        job = transport.expect(origin, before_connect=lambda: 2 if denied else 0)
        with connect(port) as client:
            client.sendall(request())
            result, body = response(client)
            assert result.status == 502
            if denied:
                assert result.getheader("OuterSSH-Proxy-Error") is None
                assert result.reason == "SSH Server Denied Port Forwarding"
                assert b"SSH Server Denied Port Forwarding" in body
                assert b"Your SSH connection succeeded" in body
                assert b"server refused forwarding to port 80" in body
            else:
                assert result.getheader("OuterSSH-Proxy-Error") == "connection-failed"
                assert result.reason == "SSH Connection Failed"
                assert body == b""
        job.result(10)


def test_connect_forwarding_denial(transport, port):
    def origin(conn, stream, host, remote_port):
        assert remote_port == 443
        assert stream.read() == b""
    job = transport.expect(origin, before_connect=lambda: 2)
    with connect(port) as client:
        client.sendall(b"CONNECT host:443 HTTP/1.1\r\nHost: host:443\r\n\r\n")
        result, body = response(client)
        assert result.status == 502
        assert result.reason == "SSH Server Denied Port Forwarding"
        assert b"refused forwarding to port 443" in body
    job.result(10)


def test_pending_connection_shutdown(transport):
    waiting = threading.Event()
    proceed = threading.Event()
    def before_connect():
        waiting.set()
        assert proceed.wait(8)
        return True
    def origin(conn, stream, host, remote_port):
        assert stream.read() == b""
    job = transport.expect(origin, before_connect=before_connect)
    process = subprocess.Popen([sys.argv[1], str(transport.port)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        port = int(process.stdout.readline())
        with connect(port) as client:
            client.sendall(request())
            assert waiting.wait(8)
            process.stdin.write(b"\n")
            process.stdin.flush()
            # The HTTP client closes before the outstanding forwarding call completes.
            assert client.recv(1) == b""
            proceed.set()
        _, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, (process.returncode, stderr.decode())
        assert not stderr, stderr.decode()
        job.result(10)
    finally:
        proceed.set()
        if process.poll() is None:
            process.kill()
            process.communicate()


def test_shutdown(transport):
    clients = []
    with proxy(transport) as port:
        for _ in range(16):
            c = connect(port)
            c.sendall(b"GET http://host/ HTTP/1.1\r\nHost: ")
            clients.append(c)
    for c in clients:
        with c:
            try:
                assert c.recv(1) == b""
            except ConnectionResetError:
                pass


def main():
    transport = ForwardingFixture()
    try:
        with proxy(transport) as port:
            for test in (test_socket_redirect, test_reuse, test_authority_policy, test_cross_port_cors, test_rewrite_boundaries, test_framing, test_reconnect, test_tunnel, test_reject, test_fragmented, test_large, test_invalid_response, test_connection_failure, test_connect_forwarding_denial, test_socket_ownership, test_page_zones, test_pending_root_requests, test_loopback_zone):
                test(transport, port)
                print("PASS", test.__name__, flush=True)
            test_tunnel(transport, port, version="1.0")
            test_tunnel(transport, port, upgrade=True)
            print("PASS WebSocket upgrade", flush=True)
        test_destroy_during_listener_recovery(transport)
        test_listener_recovery(transport)
        print("PASS active WebSocket survives healthy checks and listener repairs", flush=True)
        test_http_connect(transport)
        test_http_connect(transport, socks=True)
        test_apple_webkit(transport)
        test_apple_webkit(transport, socks=True)
        test_apple_favicon(transport)
        print("PASS authenticated CONNECT/SOCKS: reuse, chunked bodies, Unix socket hosts, WebSocket upgrade, opaque TLS", flush=True)
        test_rewriting_disabled(transport)
        print("PASS rewriting disabled and unbuffered HTML streaming", flush=True)
        for mode in ("raw", "socks", "apple"):
            test_foreign_socket_tunnels(transport, mode)
            test_tunnels_wait_for_first_request(transport, mode)
        print("PASS privileged sockets accept only their own and other privileged origins, in requests and tunnels", flush=True)
        print("PASS refused requests and tunnels to sockets that need sudo never connect", flush=True)
        for mode in ("raw", "socks-raw", "socks"):
            test_loopback_tunnels(transport, mode)
        print("PASS tunnels to loopback ports refuse requests from other hosts", flush=True)
        with proxy(transport, "socks") as port:
            test_origin_credentials(transport, port)
        test_raw_tcp_tunnels(transport)
        print("PASS origin credentials: decided when connections open, relayed untouched, refused at the SOCKS level", flush=True)
        with proxy(transport, "apple") as port:
            test_origin_credentials(transport, port, socks=False)
            test_http_origin_requests(transport, port)
        print("PASS HTTP origin credentials: CONNECT tunnels decided when they open, other requests decided one by one, never rewritten", flush=True)
        test_raw_auth(transport)
        test_shutdown(transport)
        test_pending_connection_shutdown(transport)
        print("PASS authentication, raw mode, and active-client shutdown", flush=True)
    finally:
        transport.close()


if __name__ == "__main__":
    main()
