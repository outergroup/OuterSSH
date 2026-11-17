#!/usr/bin/env python3
"""Measure streaming upload/download throughput through OuterSSH (macOS/Linux)."""
import argparse
import base64
import contextlib
import json
import os
from pathlib import Path
import platform
import pwd
import select
import shlex
import socket
import statistics
import subprocess
import sys
import tempfile
import time

SOURCE = Path(__file__).with_suffix('.c')
OUTER_LOOP = SOURCE.parent.parent


def run(*command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f'{shlex.join(command)} failed:\n{result.stdout}{result.stderr}')
    return result.stdout


def positive(text):
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return value


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def stop_fixture(process):
    if process.stdin:
        try:
            process.stdin.close()
        except BrokenPipeError:
            pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        stop_process(process)


def fixture_port(process, metadata):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if not select.select([process.stdout], [], [], 1)[0]:
            continue
        line = process.stdout.readline().decode().strip()
        if line.startswith('HOSTKEY '):
            metadata.setdefault('host_keys', []).append(line.removeprefix('HOSTKEY '))
        elif line.startswith('PLATFORM '):
            metadata['server_platform'] = line.removeprefix('PLATFORM ')
        elif line.startswith('PORT '):
            return int(line.removeprefix('PORT '))
        elif not line:
            raise RuntimeError('fixture exited before reporting its port')
    raise RuntimeError('fixture startup timed out')


def build_benchmark(args, root):
    if args.binary:
        return args.binary.resolve()
    if platform.system() != 'Darwin' or not args.products:
        raise RuntimeError('provide --products with an Apple Release products directory, or --binary with a CMake-built benchmark')
    products = args.products.resolve()
    if products.name != 'Release':
        raise RuntimeError('--products must point to Release products; do not benchmark Debug or sanitized builds')
    binary = root / 'benchmark-outerssh'
    includes = [products / 'include', OUTER_LOOP / 'OuterSSH',
                OUTER_LOOP / 'OuterSSH/include/OuterSSH', OUTER_LOOP / 'OuterSSH/olibssh/libssh2',
                products / f'openssl-{platform.machine()}/include']
    flags = ['-std=gnu17', '-O3', '-DNDEBUG', '-Wall', '-Wextra', '-Werror',
             *(f'-I{path}' for path in includes)]
    libraries = [str(products / 'libOuterSSH.a'), '-lobjc', '-lz', '-framework', 'Security']
    if args.crypto == 'openssl':
        run('xcrun', 'clang', *flags, str(SOURCE), *libraries, '-o', str(binary))
    else:
        adapter = root / 'cipher.o'
        run('xcrun', 'clang', *flags, '-Wno-unused-function',
            f'-DBENCHMARK_CRYPTOKIT={int(args.crypto == "cryptokit")}', '-c',
            str(SOURCE.parent / 'benchmark_apple_crypto.c'), '-o', str(adapter))
        if args.crypto == 'openssl-packet':
            run('xcrun', 'clang', *flags, str(SOURCE), str(adapter), *libraries, '-o', str(binary))
        else:
            driver = root / 'driver.o'
            swift = root / 'crypto.o'
            run('xcrun', 'clang', *flags, '-c', str(SOURCE), '-o', str(driver))
            target = f'{platform.machine()}-apple-macosx27.0'
            run('xcrun', 'swiftc', '-O', '-parse-as-library', '-target', target,
                '-module-cache-path', str(root / 'modules'), '-emit-object',
                str(SOURCE.parent / 'BenchmarkCryptoKit.swift'), '-o', str(swift))
            run('xcrun', 'swiftc', '-O', '-target', target, str(driver), str(adapter), str(swift),
                *libraries, '-o', str(binary))
    return binary


def local_fixture(args, root, stack, log, metadata):
    for name in ('host', 'client'):
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name))
    (root / 'authorized_keys').write_bytes((root / 'client.pub').read_bytes())
    metadata['host_keys'] = [(root / 'host.pub').read_text()]
    metadata['server_platform'] = platform.platform()
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        ssh_port = probe.getsockname()[1]
    cipher = args.cipher or 'aes128-gcm@openssh.com'
    # Algorithm names go in sshd_config, not a shell command.
    if any(character.isspace() for character in cipher):
        raise ValueError('cipher must be a single algorithm name')
    configuration = root / 'sshd_config'
    configuration.write_text(
        f'Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {root}/host\n'
        f'PidFile {root}/sshd.pid\nAuthorizedKeysFile {root}/authorized_keys\n'
        'StrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n'
        f'AllowTcpForwarding yes\nCompression no\nCiphers {cipher}\nRekeyLimit 4G 1h\nLogLevel ERROR\n')
    sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(configuration)], stdout=log, stderr=log)
    stack.callback(stop_process, sshd)
    deadline = time.monotonic() + 10
    while True:
        if sshd.poll() is not None:
            raise RuntimeError('local sshd exited')
        try:
            with socket.create_connection(('127.0.0.1', ssh_port), timeout=0.1):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError('local sshd startup timed out')
            time.sleep(0.05)
    server = root / 'source-sink'
    run(os.environ.get('CC', 'cc'), '-O3', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
        '-DOUTERSSH_BENCHMARK_SERVER', str(SOURCE), '-o', str(server))
    fixture = subprocess.Popen([str(server)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, bufsize=0)
    stack.callback(stop_fixture, fixture)
    port = fixture_port(fixture, metadata)
    metadata['server_rekey_limit'] = '4G 1h'
    return '127.0.0.1', ssh_port, pwd.getpwuid(os.getuid()).pw_name, root / 'client', port


def remote_fixture(args, root, stack, log, metadata):
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
           '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3']
    if args.config:
        ssh += ['-F', str(args.config.resolve())]
    if args.identity:
        ssh += ['-i', str(args.identity.resolve()), '-o', 'IdentitiesOnly=yes']
    configuration = {}
    for line in run(*ssh, '-G', args.remote).splitlines():
        name, _, value = line.partition(' ')
        configuration.setdefault(name, []).append(value)
    if any(configuration.get(name, ['none'])[0] != 'none' for name in ('proxyjump', 'proxycommand')):
        raise RuntimeError('this benchmark requires a direct SSH connection (no ProxyJump/ProxyCommand)')
    identity = args.identity
    if identity is None:
        identity = next((Path(path).expanduser() for path in configuration.get('identityfile', [])
                         if Path(path).expanduser().is_file()), None)
    if identity is None:
        raise RuntimeError('provide --identity with an unencrypted private key')
    source = SOURCE.read_bytes()
    # The helper exits when its stdin closes; the shell then removes its temporary directory.
    command = (
        'set -eu; d=$(mktemp -d /tmp/outerssh-benchmark.XXXXXX); '
        'trap \'rm -rf "$d"\' EXIT; '
        f'head -c {len(source)} > "$d/benchmark.c"; '
        'cc -O3 -std=gnu17 -DOUTERSSH_BENCHMARK_SERVER "$d/benchmark.c" -o "$d/source-sink"; '
        "printf 'PLATFORM '; uname -srm; "
        "for key in /etc/ssh/ssh_host_*_key.pub; do printf 'HOSTKEY '; cat \"$key\"; done; "
        '"$d/source-sink"')
    fixture = subprocess.Popen([*ssh, '-T', args.remote, command], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=log, bufsize=0)
    stack.callback(stop_fixture, fixture)
    # A raw pipe write may be short. Buffered writes would need a flush before waiting for readiness.
    view = memoryview(source)
    while view:
        written = fixture.stdin.write(view)
        if not written:
            raise RuntimeError('failed to transfer fixture source')
        view = view[written:]
    port = fixture_port(fixture, metadata)
    metadata['server_rekey_limit'] = 'server default (unchanged)'
    return configuration['hostname'][0], int(configuration['port'][0]), configuration['user'][0], identity.resolve(), port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    build = parser.add_mutually_exclusive_group(required=True)
    build.add_argument('--products', type=Path, help='macOS Release products directory; builds the small benchmark driver')
    build.add_argument('--binary', type=Path, help='prebuilt Release benchmark-outerssh (CMake)')
    parser.add_argument('--crypto', choices=['openssl', 'openssl-packet', 'cryptokit'], default='openssl',
                        help='benchmark-only AES-GCM implementation; Apple experiments require --products and a local fixture')
    parser.add_argument('--remote', help='SSH alias such as Pircus; omit for a disposable local sshd')
    parser.add_argument('--config', type=Path, help='OpenSSH config for remote fixture setup')
    parser.add_argument('--identity', type=Path, help='unencrypted private key for remote authentication')
    parser.add_argument('--cipher', help='restrict the disposable local sshd to this cipher (default: aes128-gcm@openssh.com)')
    parser.add_argument('--mib', type=positive, default=512, help='MiB per transfer (default: 512)')
    parser.add_argument('--rounds', type=positive, default=5)
    parser.add_argument('--warmup-mib', type=positive, default=16)
    parser.add_argument('--output', type=Path, help='write metadata, all samples, and medians as JSON')
    args = parser.parse_args()
    if args.crypto != 'openssl':
        if args.binary or args.remote or platform.system() != 'Darwin':
            parser.error('experimental crypto backends require --products and a local macOS fixture')
        if args.cipher and args.cipher not in ('aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'):
            parser.error('experimental crypto backends replace only AES-GCM')
        if args.crypto == 'cryptokit' and int(platform.mac_ver()[0].split('.')[0]) < 27:
            parser.error('the in-place CryptoKit experiment requires macOS 27')
    if args.remote and args.cipher:
        parser.error('--cipher only controls the disposable local sshd; remote runs report actual negotiation')
    if not args.remote and (args.identity or args.config):
        parser.error('--identity and --config require --remote')
    metadata = {'client_platform': platform.platform(), 'target': args.remote or 'local',
                'mib': args.mib, 'rounds': args.rounds, 'warmup_mib': args.warmup_mib,
                'crypto_backend': 'linked-library' if args.binary else args.crypto,
                'cpu_scope': 'benchmark process: OuterSSH threads plus native traffic driver; excludes server',
                'command': shlex.join(sys.argv)}
    records = []
    with tempfile.TemporaryDirectory(prefix='outerssh-benchmark-') as directory:
        root = Path(directory)
        try:
            with contextlib.ExitStack() as stack:
                log = stack.enter_context((root / 'fixture.log').open('w'))
                binary = build_benchmark(args, root)
                metadata['binary'] = str(binary)
                fixture = remote_fixture if args.remote else local_fixture
                host, ssh_port, user, identity, destination_port = fixture(args, root, stack, log, metadata)
                trusted_keys = bytearray()
                for public_key in metadata.pop('host_keys'):
                    blob = base64.b64decode(public_key.split()[1], validate=True)
                    trusted_keys += len(blob).to_bytes(8, 'big') + blob
                (root / 'trusted-key').write_bytes(trusted_keys)
                command = [str(binary), host, str(ssh_port), user, str(identity), str(root / 'trusted-key'),
                           str(destination_port), str(args.mib * 1024 * 1024), str(args.rounds),
                           str(args.warmup_mib * 1024 * 1024)]
                benchmark = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
                stack.callback(stop_process, benchmark)
                for line in benchmark.stdout:
                    record = json.loads(line)
                    records.append(record)
                    if record['type'] == 'algorithms':
                        print(f"Upload: {record['upload_cipher']}; download: {record['download_cipher']}; KEX: {record['kex']}", flush=True)
                    elif record['type'] == 'sample':
                        print(f"{record['direction']:8} {record['round']:2}: {record['mib_per_second']:8.2f} MiB/s, "
                              f"{record['seconds']:.3f}s wall, {record['cpu_seconds']:.3f}s CPU", flush=True)
                if benchmark.wait() != 0:
                    raise RuntimeError('benchmark failed')
        except BaseException:
            if (root / 'fixture.log').exists():
                print((root / 'fixture.log').read_text(), file=sys.stderr)
            raise
    summary = {}
    for direction in ('upload', 'download'):
        samples = [record for record in records if record['type'] == 'sample' and record['direction'] == direction]
        if len(samples) != args.rounds:
            raise RuntimeError('incomplete samples')
        summary[direction] = {field: statistics.median(sample[field] for sample in samples)
                              for field in ('mib_per_second', 'seconds', 'cpu_seconds')}
        print(f"Median {direction}: {summary[direction]['mib_per_second']:.2f} MiB/s")
    if args.output:
        args.output.write_text(json.dumps({'metadata': metadata, 'records': records, 'median': summary}, indent=2) + '\n')


if __name__ == '__main__':
    main()
