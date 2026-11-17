#!/bin/bash
# Builds a universal outerssh for macOS 12 and later. It uses CryptoKit and Security
# for cryptography, so it needs nothing beyond the operating system.
# Run it from the repository root.
#
# Set MACOS_SIGNING_IDENTITY to sign it with a Developer ID Application certificate
# from the keychain. To also notarize it, set NOTARY_KEYCHAIN_PROFILE to a profile
# saved with `xcrun notarytool store-credentials`, or set APPLE_API_KEY_PATH,
# APPLE_API_KEY_ID and APPLE_API_ISSUER_ID to use an App Store Connect API key.
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

if [[ -n "${MACOS_SIGNING_IDENTITY:-}" ]]; then
    codesign --force --options runtime --timestamp --sign "$MACOS_SIGNING_IDENTITY" \
        --identifier org.outerssh.outerssh "$binary"
    codesign --verify --strict --verbose=2 "$binary"
    submission="$build/outerssh-notarization.zip"
    ditto -c -k "$binary" "$submission"
    credentials=()
    if [[ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
        credentials=(--keychain-profile "$NOTARY_KEYCHAIN_PROFILE")
    elif [[ -n "${APPLE_API_KEY_PATH:-}" ]]; then
        credentials=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID")
    fi
    if [[ ${#credentials[@]} -gt 0 ]]; then
        result="$(xcrun notarytool submit "$submission" "${credentials[@]}" --wait --output-format json)"
        echo "$result"
        if [[ "$(plutil -extract status raw -o - - <<<"$result")" != "Accepted" ]]; then
            echo "Error: notarization was not accepted." >&2
            exit 1
        fi
    else
        echo "Signed without notarizing: no notarization credentials were set."
    fi
fi

package="$build/package"
mkdir -p "$package"
cp "$binary" LICENSE "$package/"
tar -czf "$output/outerssh-macos-universal.tar.gz" -C "$package" outerssh LICENSE
echo "Built $output/outerssh-macos-universal.tar.gz"
