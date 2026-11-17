"""Native Windows integration test; accepts a built helper, with --outerloop for outerloop-helper."""
import ctypes as c
import base64
from ctypes import wintypes as w
import pathlib
import struct
import subprocess
import sys
import tempfile
import threading

kernel = c.WinDLL('kernel32', use_last_error=True)
advapi = c.WinDLL('advapi32', use_last_error=True)
class Security(c.Structure):
    _fields_ = [('length', w.DWORD), ('descriptor', c.c_void_p), ('inherit', w.BOOL)]
advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
kernel.CreateNamedPipeW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.DWORD, w.DWORD, w.DWORD, w.DWORD, c.POINTER(Security)]
kernel.CreateNamedPipeW.restype = w.HANDLE
kernel.ConnectNamedPipe.argtypes = [w.HANDLE, c.c_void_p]
kernel.ReadFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
kernel.WriteFile.argtypes = kernel.ReadFile.argtypes
kernel.FlushFileBuffers.argtypes = [w.HANDLE]
kernel.DisconnectNamedPipe.argtypes = [w.HANDLE]
kernel.CloseHandle.argtypes = [w.HANDLE]
kernel.LocalFree.argtypes = [c.c_void_p]
advapi.SetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, c.c_void_p]
identity = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], text=True).strip().split(',')[-1].strip('"')
pipe = r'\\.\pipe\org.outershell.bridgetest.' + identity.lower()
security = c.c_void_p()
assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW('O:' + identity + 'D:P(A;;GA;;;' + identity + ')(A;;GA;;;SY)', 1, c.byref(security), None)
attributes = Security(c.sizeof(Security), security, False)

def send(process, kind, stream=0, payload=b''):
    process.stdin.write(struct.pack('<IHHII', 0x3142524f, 1, kind, stream, len(payload)) + payload)
    process.stdin.flush()

def read_exact(file, size):
    result = b''
    while len(result) < size:
        data = file.read(size - len(result))
        assert data, 'Unexpected protocol EOF'
        result += data
    return result

def receive_frame(process):
    magic, version, kind, stream, size = struct.unpack('<IHHII', read_exact(process.stdout, 16))
    assert magic == 0x3142524f and version == 1 and size <= 1024 * 1024
    return kind, stream, read_exact(process.stdout, size)

def receive(process):
    while True:
        frame = receive_frame(process)
        if not (frame[0] in (16, 18) and frame[1] == 0):
            return frame

outerloop = '--outerloop' in sys.argv[2:]
with tempfile.TemporaryDirectory(prefix='outerssh-helper-test-') as root:
    directory_security = c.c_void_p()
    assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;OICI;FA;;;' + identity + ')(A;OICI;FA;;;SY)', 1, c.byref(directory_security), None)
    assert advapi.SetFileSecurityW(root, 0x80000004, directory_security), c.get_last_error()
    kernel.LocalFree(directory_security)
    allowlist = pathlib.Path(root) / 'http-pipe.allow'
    allowlist.write_text(pipe + '\n', encoding='ascii')
    def command(*args):
        arguments = ['--user-allowlist', str(allowlist), *args]
        if '--launcher' in sys.argv[2:]:
            script = "$outerBridgeArguments='" + subprocess.list2cmdline(arguments).replace("'", "''") + "'\n"
            script += pathlib.Path(__file__).with_name('ResolveBridge.ps1').read_text()
            encoded = base64.b64encode(script.encode('utf-16le')).decode()
            return [r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]
        return [sys.argv[1], *arguments]
    def launch(*args):
        return subprocess.Popen(command(*args), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def request(payload):
        with launch('service') as service:
            assert receive(service) == (1, 0, b'')
            send(service, 22, 9, payload)
            reply = receive(service)
            send(service, 99, 10)
            unsupported = receive(service)
            assert unsupported[:2] == (12, 10) and b'does not support' in unsupported[2], unsupported
            service.stdin.close()
            assert service.wait(timeout=10) == 0
            return reply
    if outerloop:
        assert request(b'outer-shell-home') == (23, 9, b'')
        shell = r'\\.\pipe\org.outershell.outershell.' + identity.lower()
        allowlist.write_text(pipe + '\n' + shell + '\n', encoding='ascii')
        assert request(b'outer-shell-home') == (23, 9, shell.encode())
        allowlist.write_text(pipe + '\n', encoding='ascii')
        kind, stream, error = request(b'unknown')
        assert (kind, stream) == (12, 9) and b'outerloop-helper does not support' in error
    else:
        kind, stream, error = request(b'outer-shell-home')
        assert (kind, stream) == (12, 9) and b'does not support' in error
    administrators = r'\\.\pipe\org.outershell.bridgetest.s-1-5-32-544'
    allowlist.write_text(pipe + '\n' + administrators + '\n', encoding='ascii')
    with launch('service') as service:
        assert receive(service) == (1, 0, b'')
        send(service, 11, 1, pipe.encode())
        reply = receive(service)
        assert reply == (15, 1, b'\x41' + identity.encode()), reply
        send(service, 11, 4, administrators.encode())
        reply = receive(service)
        assert reply == (15, 4, b'\x81S-1-5-32-544'), reply
        send(service, 11, 2, (pipe + '-denied').encode())
        kind, stream, error = receive(service)
        assert kind == 12 and stream == 2 and b'allowlist' in error
        send(service, 8, 0, bytes(range(256)))
        assert receive(service) == (9, 0, bytes(range(256)))
        service.stdin.close()
        assert service.wait(timeout=10) == 0
    with launch('service') as service:
        assert receive(service) == (1, 0, b'')
        handle = kernel.CreateNamedPipeW(pipe, 3, 8, 1, 65536, 65536, 1000, c.byref(attributes))
        assert handle != c.c_void_p(-1).value
        try:
            send(service, 13, 3, pipe.encode())
            assert receive(service) == (12, 3, b'')
            assert receive(service) == (10, 3, b'\x01')
            allowlist.write_text('', encoding='ascii')
            kernel.CloseHandle(handle)
            handle = None
            while True:
                kind, stream, state = receive(service)
                assert (kind, stream) == (10, 3)
                if state == b'\x00':
                    break
                assert state == b'\x02'
            send(service, 11, 4, pipe.encode())
            kind, stream, error = receive(service)
            assert kind == 12 and stream == 4 and b'allowlist' in error
        finally:
            if handle is not None:
                kernel.CloseHandle(handle)
            service.stdin.close()
            service.wait(timeout=10)
            allowlist.write_text(pipe + '\n', encoding='ascii')
    payload = bytes(range(256)) * 4096
    errors = []
    servers = []
    handles = [kernel.CreateNamedPipeW(pipe, 3 | (0x80000 if i == 0 else 0), 8, 4, 65536, 65536, 1000, c.byref(attributes)) for i in range(4)]
    assert all(h != c.c_void_p(-1).value for h in handles), c.get_last_error()
    def serve(handle):
        try:
            assert kernel.ConnectNamedPipe(handle, None) or c.get_last_error() == 535
            received = bytearray()
            buffer = c.create_string_buffer(32768)
            while len(received) < len(payload):
                count = w.DWORD()
                assert kernel.ReadFile(handle, buffer, len(buffer), c.byref(count), None) and count.value
                received.extend(buffer.raw[:count.value])
            assert received == payload
            for offset in range(0, len(payload), 32768):
                part = payload[offset:offset+32768]
                count = w.DWORD()
                assert kernel.WriteFile(handle, part, len(part), c.byref(count), None) and count.value == len(part)
            kernel.FlushFileBuffers(handle)
        except BaseException as error:
            errors.append(error)
        finally:
            kernel.DisconnectNamedPipe(handle)
            kernel.CloseHandle(handle)
    for handle in handles:
        thread = threading.Thread(target=serve, args=(handle,), daemon=True)
        thread.start()
        servers.append(thread)
    try:
        with launch('bridge', '--socket', pipe) as bridge:
            assert receive(bridge) == (1, 0, b'')
            for stream in range(1, 5):
                send(bridge, 2, stream)
                assert receive(bridge) == (3, stream, b'')
            def write_requests():
                for offset in range(0, len(payload), 32768):
                    for stream in range(1, 5):
                        send(bridge, 5, stream, payload[offset:offset+32768])
                for stream in range(1, 5): send(bridge, 6, stream)
            writer = threading.Thread(target=write_requests)
            writer.start()
            bodies = {i: bytearray() for i in range(1, 5)}
            closed = set()
            while len(closed) < 4:
                kind, stream, data = receive(bridge)
                if kind == 5: bodies[stream].extend(data)
                elif kind == 7: closed.add(stream)
                else: assert kind == 6
            writer.join(timeout=10)
            assert not writer.is_alive()
            assert all(body == payload for body in bodies.values())
            bridge.stdin.close()
            assert bridge.wait(timeout=10) == 0
        for thread in servers:
            thread.join(timeout=10)
            assert not thread.is_alive()
        assert not errors, errors
    finally:
        kernel.LocalFree(security)
print('PASS: native ORB1 service authorization, pipe owners, denial, binary ping, four concurrent 1 MiB streams, EOF and shutdown')
