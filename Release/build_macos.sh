#!/bin/bash
# Builds a universal outerssh for macOS 12 and later. It uses CryptoKit and Security
# for cryptography, so it needs nothing beyond the operating system.
# Run it from the repository root. Release/sign_macos.sh describes the environment
# variables that sign and notarize it.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 VERSION OUTPUT_DIRECTORY" >&2; exit 1; }
version="$1"
output="$(mkdir -p "$2" && cd "$2" && pwd)"

deployment_target=12.0
architectures=(arm64 x86_64)
build="$PWD/build/release-macos"

rm -rf "$build"
slices=()
for architecture in "${architectures[@]}"; do
    cmake -S OuterSSH -B "$build/$architecture" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_OSX_ARCHITECTURES="$architecture" -DCMAKE_OSX_DEPLOYMENT_TARGET="$deployment_target" \
        -DCMAKE_Swift_COMPILER_TARGET="$architecture-apple-macos$deployment_target" \
        -DOUTERSSH_APPLE_CRYPTO=ON -DOUTERSSH_BUILD_CLI=ON -DOUTERSSH_BUILD_TESTS=OFF \
        -DOUTERSSH_CLI_VERSION="$version"
    cmake --build "$build/$architecture" --target outerssh
    slices+=("$build/$architecture/outerssh")
done
binary="$build/outerssh"
lipo -create "${slices[@]}" -output "$binary"
strip -x "$binary"
lipo -info "$binary"
if otool -L "$binary" | grep -E '^[[:space:]]' | grep -v -E '^[[:space:]]+(/usr/lib/|/System/Library/)'; then
    echo "Error: outerssh links libraries outside the operating system." >&2
    exit 1
fi
if nm "$binary" | grep -i openssl >/dev/null; then
    echo "Error: outerssh contains OpenSSL." >&2
    exit 1
fi
"$binary" --version

Release/sign_macos.sh "$binary" org.outerssh.outerssh

package="$build/package"
mkdir -p "$package"
cp "$binary" LICENSE "$package/"
tar -czf "$output/outerssh-macos-universal.tar.gz" -C "$package" outerssh LICENSE
echo "Built $output/outerssh-macos-universal.tar.gz"
