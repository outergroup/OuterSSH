#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/endpoint-names.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
cc -std=gnu17 -Wall -Wextra -Werror -fsanitize=address,undefined \
    -I"$root/OuterSSH/include" \
    "$root/OuterSSH/SSHEndpointNames.c" "$root/Scripts/test_endpoint_names.c" -o "$build/test"
"$build/test"
cat > "$build/command.c" <<'SOURCE'
#include <stdio.h>
#include <stdlib.h>
#include "OuterSSH/SSHEndpointRecord.h"
int main(int argc, char **argv) {
    if (argc > 1) {
        OuterSSHEndpointRecord *records; size_t count;
        if (!outerssh_endpoint_names_read_local(&records, &count)) return 1;
        for (size_t i = 0; i < count; i++) printf("%s %s %s %s\n", records[i].transport, records[i].address, records[i].name.user, records[i].name.app);
        free(records); return 0;
    }
    unsigned char *bytes; size_t length; if (!outersshpriv_endpoint_names_read_snapshot(&bytes, &length)) return 1; if (length) fwrite(bytes, 1, length, stdout); free(bytes); return 0;
}
SOURCE
cc -std=gnu17 -I"$root/OuterSSH/include" -I"$root" "$root/OuterSSH/SSHEndpointNames.c" "$build/command.c" -o "$build/command"

python3 - "$build" <<'PY'
import os, pathlib, pwd, subprocess, sys
root = pathlib.Path(sys.argv[1])
home = root / 'home'
folder = home / ('Library/Application Support/org.outerssh/endpoints.d' if sys.platform == 'darwin' else '.config/outerssh/endpoints.d')
folder.mkdir(parents=True, mode=0o700)
entry = folder / 'test'
content = b'outerssh-endpoints-v2\nunix /a\nAlpha\nEditor\n'
entry.write_bytes(content)
entry.chmod(0o600)
env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'))
def read():
    return subprocess.run([str(root/'command')], env=env, capture_output=True)
assert pwd.getpwuid(os.getuid()).pw_name.encode() + b'\0' + content + b'\0' in read().stdout
account = pwd.getpwuid(os.getuid()).pw_name.encode()
assert b'unix /a ' + account + b' Editor\n' in subprocess.run([str(root/'command'), 'records'], env=env, capture_output=True).stdout
(folder / '.pending').write_text('not a registration')
(folder / 'test.123.tmp').write_text('not a registration')
assert read().returncode == 0
entry.write_bytes(content + b'\0root\0outerssh-endpoints-v2\nunix /spoof\n\nApp\n')
assert read().returncode != 0
entry.write_bytes(content)
entry.chmod(0o666)
assert read().returncode != 0
entry.chmod(0o600)
entry.unlink()
entry.symlink_to(root / 'command')
assert read().returncode != 0
print('Endpoint discovery permissions and atomic-write tests passed')
PY

cat > "$build/icon.c" <<'SOURCE'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "OuterSSH/SSHEndpointNames.h"
int main(int argc, char **argv) {
    if (argc < 5) return 2;
    const char *error = NULL;
    unsigned port = (unsigned)strtoul(argv[4], NULL, 10);
    if (!strcmp(argv[1], "read")) {
        unsigned char *png; size_t length;
        if (!outerssh_endpoint_icon_read_local(argv[2], argv[3], strlen(argv[3]), (uint16_t)port, &png, &length, &error)) {
            fprintf(stderr, "%s\n", error); return 1;
        }
        if (!png) return 3;
        fwrite(png, 1, length, stdout); free(png); return 0;
    }
    static unsigned char png[200000];
    size_t length = fread(png, 1, sizeof(png), stdin);
    if (!outerssh_endpoint_icon_store_local(argv[2], argv[3], strlen(argv[3]), (uint16_t)port, png, length, &error)) {
        fprintf(stderr, "%s\n", error); return 1;
    }
    return 0;
}
SOURCE
cc -std=gnu17 -Wall -Wextra -Werror -fsanitize=address,undefined -I"$root/OuterSSH/include" \
    "$root/OuterSSH/SSHEndpointNames.c" "$build/icon.c" -o "$build/icon"

python3 - "$build" <<'PY'
import hashlib, os, pathlib, stat, struct, subprocess, sys, zlib
root = pathlib.Path(sys.argv[1])
home = root / 'icon-home'
home.mkdir(mode=0o700)
folder = home / ('Library/Application Support/org.outerssh/endpoint-icons' if sys.platform == 'darwin' else '.config/outerssh/endpoint-icons')
env = dict(os.environ, HOME=str(home))
env.pop('XDG_CONFIG_HOME', None)
def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
def png(width=16, height=16, filler=b'x'):
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)) + \
        chunk(b'IDAT', filler) + chunk(b'IEND', b'')
def run(*arguments, data=None):
    return subprocess.run([str(root / 'icon'), *arguments], input=data, env=env, capture_output=True)
def store(data, address='/run/user/1000/app', transport='unix', port='0'):
    return run('store', transport, address, port, data=data)
def read(address='/run/user/1000/app', transport='unix', port='0'):
    return run('read', transport, address, port)
name = hashlib.sha256(b'unix /run/user/1000/app').hexdigest() + '.png'

assert read().returncode == 3
assert not folder.exists()
first = png(filler=b'first')
assert store(first).returncode == 0
assert stat.S_IMODE(folder.stat().st_mode) == 0o700
assert stat.S_IMODE((folder / name).stat().st_mode) == 0o600
assert sorted(p.name for p in folder.iterdir()) == [name]
result = read(); assert result.returncode == 0 and result.stdout == first

second = png(filler=b'second')
inode = (folder / name).stat().st_ino
assert store(second).returncode == 0
assert read().stdout == second and (folder / name).stat().st_ino != inode
assert sorted(p.name for p in folder.iterdir()) == [name]

tcp = png(filler=b'tcp')
assert store(tcp, 'LOCALHOST', 'tcp', '6006').returncode == 0
assert read('localhost', 'tcp', '6006').stdout == tcp
assert (folder / (hashlib.sha256(b'tcp localhost 6006').hexdigest() + '.png')).exists()

for invalid in [b'not a png', png(513, 16), png(16, 16, b'x' * 70000), first[:-1]]:
    result = store(invalid, '/other')
    assert result.returncode == 1 and b'PNG' in result.stderr, result
assert store(first, 'relative').returncode == 1
assert read('/other').returncode == 3

(folder / name).chmod(0o620)
assert read().returncode == 1
(folder / name).chmod(0o600)
(folder / name).write_bytes(b'corrupt')
assert read().returncode == 1
(folder / name).unlink()
(folder / name).symlink_to(root / 'icon')
assert read().returncode == 1
(folder / name).unlink()
folder.chmod(0o770)
assert store(first).returncode == 1 and read().returncode == 1
folder.chmod(0o700)

for entry in folder.iterdir(): entry.unlink()
(folder / '.stale.tmp').write_bytes(b'')
for index in range(512):
    assert store(png(filler=b'%d' % index), '/app/%d' % index).returncode == 0
assert len([p for p in folder.iterdir() if p.suffix == '.png']) == 512
assert store(png(filler=b'replace'), '/app/7').returncode == 0
assert read('/app/0').returncode == 0
assert store(png(filler=b'new'), '/app/new').returncode == 0
assert len([p for p in folder.iterdir() if p.suffix == '.png']) == 512
assert read('/app/0').returncode == 3 and read('/app/1').returncode == 0 and read('/app/new').returncode == 0
assert [p.name for p in folder.iterdir() if p.name.startswith('.')] == ['.stale.tmp']

xdg = root / 'xdg'
xdg.mkdir()
if sys.platform != 'darwin':
    env['XDG_CONFIG_HOME'] = str(xdg)
    assert store(first, '/xdg').returncode == 0
    assert (xdg / 'outerssh/endpoint-icons' / (hashlib.sha256(b'unix /xdg').hexdigest() + '.png')).exists()
print('Endpoint icon cache tests passed')
PY
