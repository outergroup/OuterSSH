#!/bin/bash
# Packages a Windows outerssh-helper.exe the way OuterSSH uploads it: a gzip-compressed
# tar archive holding one file, outerssh-helper.exe. The archive is reproducible, so
# packaging the same executable twice gives the same bytes.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 OUTERSSH_HELPER_EXE OUTPUT_ARCHIVE" >&2; exit 1; }
stage="$(mktemp -d "${TMPDIR:-/tmp}/outerssh-helper-windows.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
cp "$1" "$stage/outerssh-helper.exe"
touch -t 198001010000 "$stage/outerssh-helper.exe"
if tar --version 2>/dev/null | grep -q bsdtar; then
    COPYFILE_DISABLE=1 tar --format ustar --no-mac-metadata --uid 0 --gid 0 --uname '' --gname '' \
        -cf - -C "$stage" outerssh-helper.exe | gzip -9 -n > "$2"
else
    tar --format ustar --owner 0 --group 0 --numeric-owner \
        -cf - -C "$stage" outerssh-helper.exe | gzip -9 -n > "$2"
fi
