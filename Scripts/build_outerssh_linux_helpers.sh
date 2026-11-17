#!/bin/bash
# Builds outerssh-helper for every Linux platform OuterSSH asks for, in Docker,
# and writes outerssh-helper-<platform>.gz files to OUTPUT_DIRECTORY. <platform>
# is the string in OUTERSSH_EVENT_HELPER_BINARY_NEEDED, such as
# linux-x86_64-glibc, so an application can answer by opening that file.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd "$script_dir/.." && pwd)"

build_variant() {
    local libc="$1" output_dir="$2" arch
    case "$(uname -m)" in
        aarch64|arm64) arch=aarch64 ;;
        x86_64|amd64) arch=x86_64 ;;
        armv7l|armv8l) arch=armv7 ;;
        *) echo "Error: unsupported architecture $(uname -m)." >&2; exit 1 ;;
    esac
    local output="$output_dir/outerssh-helper-linux-$arch-$libc"
    cc -std=gnu17 -O2 -Wall -Wextra -D_FILE_OFFSET_BITS=64 -o "$output" \
        "$source_dir/OuterSSHHelper/Main.c" "$source_dir/OuterSSHHelper/Helper.c" \
        "$source_dir/OuterSSH/SSHEndpointNames.c"
    strip --strip-unneeded "$output"
    "$output" --version
    gzip -9 -n -f "$output"
}

if [[ "${1:-}" == "--build-variant" ]]; then
    build_variant "$2" "$3"
    exit 0
fi

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 OUTPUT_DIRECTORY" >&2
    exit 1
fi
mkdir -p "$1"
output_dir="$(cd "$1" && pwd)"
stage="$(mktemp -d "${TMPDIR:-/tmp}/outerssh-helpers.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

for libc in glibc musl; do
    for arch in aarch64 armv7 x86_64; do
        case "$libc/$arch" in
            musl/armv7) image=quay.io/pypa/musllinux_1_2_armv7l ;;
            musl/*) image="quay.io/pypa/musllinux_1_2_$arch" ;;
            glibc/armv7) image=quay.io/pypa/manylinux_2_31_armv7l ;;
            glibc/*) image="quay.io/pypa/manylinux2014_$arch" ;;
        esac
        case "$arch" in
            aarch64) platform=linux/arm64 ;;
            armv7) platform=linux/arm/v7 ;;
            x86_64) platform=linux/amd64 ;;
        esac
        echo "==> linux-$arch-$libc"
        docker run --rm --platform "$platform" --network none \
            --mount "type=bind,source=$source_dir,target=/source,readonly" \
            --mount "type=bind,source=$stage,target=/out" \
            "$image" bash /source/Scripts/build_outerssh_linux_helpers.sh --build-variant "$libc" /out
    done
done
mv "$stage"/outerssh-helper-linux-*.gz "$output_dir/"
echo "Wrote helpers to $output_dir"
