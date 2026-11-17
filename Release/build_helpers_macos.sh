#!/bin/bash
# Builds outerssh-helper for macOS 11 and later and writes
# outerssh-helper-macos-arm64.gz and outerssh-helper-macos-x86_64.gz to
# OUTPUT_DIRECTORY, named for the platforms in OUTERSSH_EVENT_HELPER_BINARY_NEEDED.
# Run it from the repository root. It builds one universal executable, signs and
# notarizes it as Release/sign_macos.sh describes, then splits it so a server
# downloads only its own architecture.
set -euo pipefail

[[ $# -eq 1 ]] || { echo "Usage: $0 OUTPUT_DIRECTORY" >&2; exit 1; }
output="$(mkdir -p "$1" && cd "$1" && pwd)"
build="$PWD/build/release-macos-helper"

rm -rf "$build"
mkdir -p "$build"
binary="$build/outerssh-helper"
xcrun --sdk macosx clang -arch arm64 -arch x86_64 -mmacosx-version-min=11.0 \
    -std=gnu17 -O2 -Wall -Wextra -Werror \
    OuterSSHHelper/Main.c OuterSSHHelper/Helper.c OuterSSH/SSHEndpointNames.c -o "$binary"
strip -x "$binary"
codesign --force --sign - "$binary"
"$binary" --version

Release/sign_macos.sh "$binary" org.outerssh.outerssh-helper

for architecture in arm64 x86_64; do
    slice="$build/outerssh-helper-$architecture"
    lipo -thin "$architecture" "$binary" -output "$slice"
    codesign --verify --strict "$slice"
    gzip -9 -n -c "$slice" > "$output/outerssh-helper-macos-$architecture.gz"
    echo "Built $output/outerssh-helper-macos-$architecture.gz"
done
