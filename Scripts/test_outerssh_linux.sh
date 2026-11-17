#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPILER="${OUTERSSH_LINUX_COMPILER:-clang}"
PLATFORM="${OUTERSSH_LINUX_PLATFORM:-}"
SUFFIX="${PLATFORM//\//-}"
IMAGE="${OUTERSSH_LINUX_IMAGE:-outerssh-linux-test${SUFFIX:+-$SUFFIX}}"
BUILD_VOLUME="${OUTERSSH_LINUX_BUILD_VOLUME:-outerssh-linux-build-$COMPILER${SUFFIX:+-$SUFFIX}}"
BUILD_ARGS=(build)
RUN_ARGS=(run --rm)
if [[ -n "$PLATFORM" ]]; then
    BUILD_ARGS+=(--platform "$PLATFORM")
    RUN_ARGS+=(--platform "$PLATFORM")
fi

docker "${BUILD_ARGS[@]}" -t "$IMAGE" \
    -f "$SCRIPT_DIR/Linux/Dockerfile" "$SCRIPT_DIR/Linux"
docker "${RUN_ARGS[@]}" \
    --mount "type=bind,src=$SOURCE_DIR,dst=/workspace,readonly" \
    --mount "type=volume,src=$BUILD_VOLUME,dst=/build" \
    -e CC="$COMPILER" \
    -e ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 \
    -e UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 \
    "$IMAGE" sh -eu -c '
        cmake -S OuterSSH -B /build -G Ninja -DCMAKE_C_COMPILER="$CC" \
            -DCMAKE_BUILD_TYPE=Debug -DOUTERSSH_SANITIZE=ON -DOUTERSSH_BUILD_TESTS=ON
        cmake --build /build --parallel 4
        ctest --test-dir /build --output-on-failure
        python3 Scripts/Linux/run_integration.py /build
    '
