#!/bin/sh
# Builds a fully static outerssh for this machine's architecture on Alpine Linux.
# Run it from the repository root, as root inside an Alpine container:
#   docker run --rm -v "$PWD:/src" -w /src alpine:3.22 Release/build_linux.sh 1.0.0 dist
set -eu

[ $# -eq 2 ] || { echo "Usage: $0 VERSION OUTPUT_DIRECTORY" >&2; exit 1; }
version="$1"
output="$2"

apk add --no-cache build-base cmake ninja patch linux-headers \
    openssl-dev openssl-libs-static zlib-dev zlib-static >/dev/null

build="build/release-linux"
rm -rf "$build"
cmake -S OuterSSH -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DOUTERSSH_BUILD_CLI=ON -DOUTERSSH_BUILD_TESTS=OFF -DOUTERSSH_CLI_VERSION="$version" \
    -DOPENSSL_USE_STATIC_LIBS=TRUE -DZLIB_USE_STATIC_LIBS=ON \
    -DCMAKE_EXE_LINKER_FLAGS=-static
cmake --build "$build" --target outerssh
strip "$build/outerssh"

"$build/outerssh" --version
if file "$build/outerssh" 2>/dev/null | grep -q dynamically; then
    echo "Error: outerssh is dynamically linked." >&2
    exit 1
fi

architecture="$(uname -m)"
mkdir -p "$output"
package="$build/package"
rm -rf "$package"
mkdir -p "$package"
cp "$build/outerssh" LICENSE "$package/"
tar -czf "$output/outerssh-linux-$architecture.tar.gz" -C "$package" outerssh LICENSE
echo "Built $output/outerssh-linux-$architecture.tar.gz"
