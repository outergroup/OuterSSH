#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTER_LOOP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/outer-loop-socks-flows.XXXXXX")"

cleanup() {
    status=$?
    case "${TEST_ROOT}" in
        "${TMPDIR:-/tmp}"/outer-loop-socks-flows.*)
            find "${TEST_ROOT}" -type f -delete 2>/dev/null || true
            find "${TEST_ROOT}" -depth -type d -exec rmdir {} \; 2>/dev/null || true
            ;;
    esac
    exit "${status}"
}
trap cleanup EXIT

CLANG="$(/usr/bin/xcrun --find clang)"
SDK_PATH="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
TEST_EXECUTABLE="${TEST_ROOT}/test-socks-flows"
TEST_ITERATIONS="${SSH_SOCKS_TEST_ITERATIONS:-1}"
TEST_SANITIZERS="${SSH_SOCKS_TEST_SANITIZERS:-address,undefined}"
case "${TEST_ITERATIONS}" in
    ''|*[!0-9]*)
        echo "SSH_SOCKS_TEST_ITERATIONS must be a positive integer." >&2
        exit 2
        ;;
esac
if [[ "${TEST_ITERATIONS}" -eq 0 ]]; then
    echo "SSH_SOCKS_TEST_ITERATIONS must be a positive integer." >&2
    exit 2
fi


"${CLANG}" \
    -I "${OUTER_LOOP_DIR}/OuterSSH/olibssh/libssh2" \
    -ffunction-sections -fdata-sections -Wl,-dead_strip \
    -std=gnu17 -Wall -Wextra -Werror -Wno-unused-function \
    -fblocks \
    -fno-omit-frame-pointer \
    -fsanitize="${TEST_SANITIZERS}" \
    -isysroot "${SDK_PATH}" \
    -mmacosx-version-min=14.0 \
    -fmodules-cache-path="${TEST_ROOT}/module-cache" \
    -I "${OUTER_LOOP_DIR}/OuterSSH" -I"${OUTER_LOOP_DIR}/OuterSSH/include/OuterSSH" \
    "${OUTER_LOOP_DIR}/OuterSSH/ProxyReactor.c" \
    "${SCRIPT_DIR}/test_proxy_socks_handshake.c" \
    "${OUTER_LOOP_DIR}/OuterSSH/platform/OTQueueApple.c" -lobjc \
    -framework Security \
    -o "${TEST_EXECUTABLE}"

SANITIZER_ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0:halt_on_error=1:abort_on_error=1:strict_string_checks=1"
SANITIZER_UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:halt_on_error=1:abort_on_error=1:print_stacktrace=1"
SANITIZER_TSAN_OPTIONS="${TSAN_OPTIONS:-}:halt_on_error=1:abort_on_error=1"
iteration=1
while [[ "${iteration}" -le "${TEST_ITERATIONS}" ]]; do
    env \
        ASAN_OPTIONS="${SANITIZER_ASAN_OPTIONS}" \
        TSAN_OPTIONS="${SANITIZER_TSAN_OPTIONS}" \
        UBSAN_OPTIONS="${SANITIZER_UBSAN_OPTIONS}" \
        "${TEST_EXECUTABLE}"
    iteration=$((iteration + 1))
done
