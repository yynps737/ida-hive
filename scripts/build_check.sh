#!/usr/bin/env bash
# Runs every check that needs no IDA license: the Rust build, the C++ worker build
# and link against the real SDK, the worker reaching idalib's license gate, and the
# coordinator suite. Tool behaviour stays unverified, since idalib will not
# initialize without activation. The public SDK is cloned when $IDASDK is unset.
#
# Usage:
#   scripts/build_check.sh                 # full run, cloning the SDK if needed
#   IDASDK=/path/to/ida-sdk/src scripts/build_check.sh
#   SKIP_WORKER=1 scripts/build_check.sh   # coordinator only (no SDK/C++ build)

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SDK_TAG="v9.2.0-sdk.1"
SDK_CACHE="${SDK_CACHE:-$ROOT/worker/.ida-sdk-cache}"
BUILD_DIR="${BUILD_DIR:-$ROOT/worker/build-linux}"

pass=0; fail=0
step()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()    { printf '  \033[32mOK\033[0m   %s\n' "$*"; pass=$((pass+1)); }
bad()   { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail+1)); }

step "1/4  Rust coordinator (cargo build --release)"
if cargo build --release >/tmp/ida_hive_cargo.log 2>&1; then
    ok "coordinator built: target/release/ida-hive"
else
    bad "cargo build failed — see /tmp/ida_hive_cargo.log"; tail -20 /tmp/ida_hive_cargo.log
fi

if [ "${SKIP_WORKER:-0}" != "1" ]; then
    step "2/4  C++ worker build against the real IDA 9.2 SDK"

    if [ -z "${IDASDK:-}" ]; then
        if [ ! -f "$SDK_CACHE/src/include/ida.hpp" ]; then
            echo "  cloning public IDA SDK $SDK_TAG (headers + ida-cmake submodule)..."
            rm -rf "$SDK_CACHE"
            if git clone --branch "$SDK_TAG" --depth 1 \
                 https://github.com/HexRaysSA/ida-sdk.git "$SDK_CACHE" >/tmp/ida_hive_sdk.log 2>&1 \
               && git -C "$SDK_CACHE" submodule update --init src/cmake >>/tmp/ida_hive_sdk.log 2>&1; then
                echo "  SDK ready at $SDK_CACHE"
            else
                bad "SDK clone failed — see /tmp/ida_hive_sdk.log"; tail -15 /tmp/ida_hive_sdk.log
            fi
        fi
        export IDASDK="$SDK_CACHE/src"
    fi
    # The SDK ships Linux link stubs here; no IDA install needed just to link.
    export IDABIN="${IDABIN:-$IDASDK/lib/x64_linux_gcc_64}"

    if [ -f "$IDASDK/cmake/bootstrap.cmake" ]; then
        if cmake -S worker -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release >/tmp/ida_hive_cmake.log 2>&1 \
           && cmake --build "$BUILD_DIR" -j"$(nproc)" >>/tmp/ida_hive_cmake.log 2>&1; then
            ok "worker compiled + linked via worker/CMakeLists.txt"
        else
            bad "worker build failed — see /tmp/ida_hive_cmake.log"; tail -25 /tmp/ida_hive_cmake.log
        fi
    else
        bad "IDASDK=$IDASDK has no cmake/bootstrap.cmake (submodule not initialized?)"
    fi

    step "3/4  Worker runs up to the license gate (clean init_error)"
    WORKER="$(find "$BUILD_DIR" -name ida_mcp_worker -type f 2>/dev/null | head -1)"
    if [ -n "$WORKER" ]; then
        OUT="$(echo '{"id":1,"method":"ping","params":{}}' \
               | LD_LIBRARY_PATH="$IDABIN" timeout 30 "$WORKER" /bin/ls /tmp 2>/dev/null | head -1)"
        if echo "$OUT" | grep -q 'init_library'; then
            ok "worker reached init_library and reported the license gate cleanly"
            echo "       $OUT"
        else
            bad "unexpected worker startup output: $OUT"
        fi
    else
        bad "no ida_mcp_worker binary produced"
    fi
else
    step "2-3/4  C++ worker  (SKIPPED: SKIP_WORKER=1)"
fi

step "4/4  Coordinator end-to-end suite (mock idalib worker)"
if [ -x target/release/ida-hive ]; then
    if python3 tests/test_coordinator.py; then
        ok "coordinator suite passed"
    else
        bad "coordinator suite reported failures"
    fi
else
    bad "target/release/ida-hive missing — cannot run the coordinator suite"
fi

printf '\n\033[1m== summary ==\033[0m\n'
printf '  %d passed, %d failed\n' "$pass" "$fail"
printf '  NOTE: real idalib analysis behaviour is NOT covered here — it needs an\n'
printf '        activated IDA Pro license. This checks everything up to that gate.\n'
[ "$fail" -eq 0 ]
