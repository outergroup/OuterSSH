#!/usr/bin/env python3
"""Store and fetch endpoint icons through a real socket helper's service mode."""
import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zlib

bridge = str(Path(sys.argv[1]).resolve())
MAGIC, VERSION = 0x3142524f, 1
STORE, GET, ICON, RESULT = 19, 20, 21, 12


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


def png(width=16, height=16, filler=b'x'):
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)) +
            chunk(b'IDAT', filler) + chunk(b'IEND', b''))


with tempfile.TemporaryDirectory(prefix='osb-icons-') as directory:
    root = Path(directory)
    home = root / 'home'
    config = root / 'config'
    home.mkdir()
    config.mkdir()
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(config))
    windows = sys.platform == 'win32'
    if windows:
        folder = Path(os.environ['LOCALAPPDATA']) / 'OuterSSH/endpoint-icons'
        assert not folder.exists(), 'remove the existing Windows icon cache before testing'
    elif sys.platform == 'darwin':
        folder = home / 'Library/Application Support/org.outerssh/endpoint-icons'
    else:
        folder = config / 'outerssh/endpoint-icons'
    with subprocess.Popen([bridge, 'service'], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
        def receive():
            while True:
                header = process.stdout.read(16)
                assert len(header) == 16
                magic, version, kind, ident, length = struct.unpack('<IHHII', header)
                assert magic == MAGIC and version == VERSION
                payload = process.stdout.read(length)
                if kind in (16, 18) and ident == 0:
                    continue
                return kind, ident, payload

        def request(kind, ident, payload):
            process.stdin.write(struct.pack('<IHHII', MAGIC, VERSION, kind, ident, len(payload)) + payload)
            process.stdin.flush()
            reply = receive()
            assert reply[1] == ident, reply
            return reply[0], reply[2]

        assert receive()[0] == 1
        assert request(GET, 1, b'unix /run/user/1000/app') == (ICON, b'')
        assert not folder.exists()
        first = png(filler=b'first')
        assert request(STORE, 2, b'unix /run/user/1000/app\0' + first) == (RESULT, b'')
        name = hashlib.sha256(b'unix /run/user/1000/app').hexdigest() + '.png'
        assert (folder / name).read_bytes() == first
        if not windows:
            assert stat.S_IMODE((folder / name).stat().st_mode) == 0o600
            assert stat.S_IMODE(folder.stat().st_mode) == 0o700
        assert request(GET, 3, b'unix /run/user/1000/app') == (ICON, first)

        second = png(filler=b'second')
        assert request(STORE, 4, b'tcp LocalHost 6006\0' + second) == (RESULT, b'')
        assert request(GET, 5, b'tcp localhost 6006') == (ICON, second)
        assert request(GET, 6, b'tcp LOCALHOST 6006') == (ICON, second)
        assert sorted(p.name for p in folder.iterdir()) == sorted(
            [name, hashlib.sha256(b'tcp localhost 6006').hexdigest() + '.png'])

        for invalid in [b'GIF89a', png(600, 16), png(filler=b'x' * 70000), first[:-4]]:
            kind, payload = request(STORE, 7, b'unix /other\0' + invalid)
            assert kind == RESULT and b'PNG' in payload, payload
        for line in [b'unix relative', b'tcp localhost 0', b'http /a', b'unix /a\nb']:
            kind, payload = request(GET, 8, line)
            assert kind == RESULT and payload == b'Invalid endpoint.', (line, payload)
        assert request(GET, 9, b'unix /a\0')[0] == RESULT
        assert request(STORE, 10, b'unix /a' + first)[0] == RESULT
        assert request(GET, 11, b'unix /other') == (ICON, b'')

        if windows:
            (folder / name).write_bytes(b'corrupt')
            assert request(GET, 12, b'unix /run/user/1000/app')[0] == RESULT
            assert request(STORE, 13, b'unix /run/user/1000/app\0' + first) == (RESULT, b'')
        else:
            (folder / name).chmod(0o666)
            assert request(GET, 12, b'unix /run/user/1000/app')[0] == RESULT
            (folder / name).chmod(0o600)
            folder.chmod(0o777)
            assert request(STORE, 13, b'unix /run/user/1000/app\0' + second)[0] == RESULT
            folder.chmod(0o700)
        assert request(GET, 14, b'unix /run/user/1000/app') == (ICON, first)
        assert request(8, 15, b'') == (9, b'')
        process.stdin.close()
        assert process.wait(timeout=5) == 0
    if windows:
        shutil.rmtree(folder)
print('Endpoint icon service tests passed')
