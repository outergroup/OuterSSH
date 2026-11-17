#!/bin/bash
# Signs a macOS executable in place, and notarizes it, when the environment says how.
# The build scripts run it; on its own it does nothing unless these are set:
#
#   MACOS_SIGNING_IDENTITY   a Developer ID Application certificate in the keychain
#   NOTARY_KEYCHAIN_PROFILE  a profile saved with `xcrun notarytool store-credentials`,
#                            or APPLE_API_KEY_PATH, APPLE_API_KEY_ID and
#                            APPLE_API_ISSUER_ID for an App Store Connect API key
#
# Notarization records the hash of every architecture slice, so a universal binary
# can be split with `lipo -thin` afterward and each slice stays notarized.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 BINARY IDENTIFIER" >&2; exit 1; }
binary="$1"
identifier="$2"

if [[ -z "${MACOS_SIGNING_IDENTITY:-}" ]]; then
    echo "Not signing $identifier: MACOS_SIGNING_IDENTITY isn't set."
    exit 0
fi
codesign --force --options runtime --timestamp --sign "$MACOS_SIGNING_IDENTITY" \
    --identifier "$identifier" "$binary"
codesign --verify --strict --verbose=2 "$binary"

credentials=()
if [[ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
    credentials=(--keychain-profile "$NOTARY_KEYCHAIN_PROFILE")
elif [[ -n "${APPLE_API_KEY_PATH:-}" ]]; then
    credentials=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID")
fi
if [[ ${#credentials[@]} -eq 0 ]]; then
    echo "Signed $identifier without notarizing: no notarization credentials were set."
    exit 0
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/outerssh-notarization.XXXXXX")"
trap 'rm -rf "$work"' EXIT
ditto -c -k "$binary" "$work/submission.zip"
result="$(xcrun notarytool submit "$work/submission.zip" "${credentials[@]}" --wait --output-format json)"
echo "$result"
if [[ "$(plutil -extract status raw -o - - <<<"$result")" != "Accepted" ]]; then
    echo "Error: notarization of $identifier was not accepted." >&2
    exit 1
fi
