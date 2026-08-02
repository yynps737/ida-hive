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
#   RUN_SCALE=1 scripts/build_check.sh     # add the large-binary scale test

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SDK_TAG="v9.4.0-release"
SDK_CACHE="${SDK_CACHE:-$ROOT/worker/.ida-sdk-cache}"
BUILD_DIR="${BUILD_DIR:-$ROOT/worker/build-linux}"

pass=0; fail=0
step()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()    { printf '  \033[32mOK\033[0m   %s\n' "$*"; pass=$((pass+1)); }
bad()   { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail+1)); }

step "1/10  Rust coordinator (cargo build --release)"
if cargo build --release >/tmp/ida_hive_cargo.log 2>&1; then
    ok "coordinator built: target/release/ida-hive"
else
    bad "cargo build failed — see /tmp/ida_hive_cargo.log"; tail -20 /tmp/ida_hive_cargo.log
fi

# The lint policy lives in Cargo.toml at deny level, but only clippy evaluates the
# clippy lints — a plain build passes regardless, so this step is what enforces them.
step "2/10  Rust lints (cargo clippy, warnings denied)"
if cargo clippy --release --all-targets >/tmp/ida_hive_clippy.log 2>&1; then
    ok "no lint findings"
else
    bad "clippy reported findings — see /tmp/ida_hive_clippy.log"
    grep -E "^error" /tmp/ida_hive_clippy.log | head -10
fi

if [ "${SKIP_WORKER:-0}" != "1" ]; then
    step "3/10  C++ worker build against the real IDA 9.4 SDK"

    if [ -z "${IDASDK:-}" ]; then
        if [ ! -f "$SDK_CACHE/src/include/ida.hpp" ]; then
            echo "  cloning public IDA SDK $SDK_TAG..."
            rm -rf "$SDK_CACHE"
            if git clone --branch "$SDK_TAG" --depth 1 \
                 https://github.com/HexRaysSA/ida-sdk.git "$SDK_CACHE" >/tmp/ida_hive_sdk.log 2>&1; then
                echo "  SDK ready at $SDK_CACHE"
            else
                bad "SDK clone failed — see /tmp/ida_hive_sdk.log"; tail -15 /tmp/ida_hive_sdk.log
            fi
        fi
        export IDASDK="$SDK_CACHE/src"
    fi
    # The SDK ships Linux link stubs here; no IDA install needed just to link.
    export IDABIN="${IDABIN:-$IDASDK/lib/x64_linux_64}"

    # IDASDK may name the repo root or its src/ subdirectory; both are valid.
    if [ -f "$IDASDK/cmake/idasdk_init.cmake" ] || [ -f "$IDASDK/src/cmake/idasdk_init.cmake" ]; then
        if cmake -S worker -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release >/tmp/ida_hive_cmake.log 2>&1 \
           && cmake --build "$BUILD_DIR" -j"$(nproc)" >>/tmp/ida_hive_cmake.log 2>&1; then
            ok "worker compiled + linked via worker/CMakeLists.txt"
        else
            bad "worker build failed — see /tmp/ida_hive_cmake.log"; tail -25 /tmp/ida_hive_cmake.log
        fi
    else
        bad "IDASDK=$IDASDK has no cmake/idasdk_init.cmake (SDK older than 9.4?)"
    fi

    step "4/10  Worker starts against a real IDA install"
    WORKER="$(find "$BUILD_DIR" -name ida_mcp_worker -type f 2>/dev/null | head -1)"
    if [ -z "$WORKER" ]; then
        bad "no ida_mcp_worker binary produced"
    # The SDK's lib/ holds link-time stubs only: they satisfy the linker but
    # segfault when called, so this step needs a real install to mean anything.
    elif [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; then
        echo "  SKIPPED: IDABIN=$IDABIN holds link stubs, not a runnable IDA."
        echo "           Set IDABIN to an IDA installation to cover this step."
    else
        # stdout carries the protocol; the [worker] log lines go to stderr.
        OUT="$(echo '{"id":1,"method":"ping","params":{}}' \
               | LD_LIBRARY_PATH="$IDABIN" timeout 60 "$WORKER" /bin/ls /tmp 2>/dev/null | head -1)"
        if echo "$OUT" | grep -qE '"event":"(ready|init_error)"'; then
            ok "worker started and reported its state cleanly"
            echo "       $(echo "$OUT" | cut -c1-100)"
        else
            bad "unexpected worker startup output: ${OUT:-<empty>}"
        fi
    fi
else
    step "4-5/10  C++ worker  (SKIPPED: SKIP_WORKER=1)"
fi

step "5/10  Coordinator end-to-end suite (mock idalib worker)"
if [ -x target/release/ida-hive ]; then
    if python3 tests/test_coordinator.py; then
        ok "coordinator suite passed"
    else
        bad "coordinator suite reported failures"
    fi
else
    bad "target/release/ida-hive missing — cannot run the coordinator suite"
fi

step "6/10  Worker adversarial stress (hostile input, protocol abuse, pipelining)"
WORKER="$(find "$BUILD_DIR" -name ida_mcp_worker -type f 2>/dev/null | head -1)"
if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
    echo "  SKIPPED: needs a built worker and a runnable IDA."
elif IDABIN="$IDABIN" python3 tests/stress_worker.py --worker "$WORKER" >/tmp/ida_hive_stress.log 2>&1; then
    ok "$(tail -1 /tmp/ida_hive_stress.log)"
else
    bad "stress test failed — see /tmp/ida_hive_stress.log"; tail -15 /tmp/ida_hive_stress.log
fi

step "7/10  Worker endurance (memory, descriptors, kill cleanup)"
if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
    echo "  SKIPPED: needs a built worker and a runnable IDA."
elif IDABIN="$IDABIN" python3 tests/endurance_worker.py --worker "$WORKER" >/tmp/ida_hive_endur.log 2>&1; then
    ok "$(tail -1 /tmp/ida_hive_endur.log)"
    grep -E "^  (memory|fds|cycles):" /tmp/ida_hive_endur.log | sed 's/^/     /'
else
    bad "endurance test failed — see /tmp/ida_hive_endur.log"; tail -15 /tmp/ida_hive_endur.log
fi

step "8/10  Tool correctness (invariants over the 9.4 tools)"
if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
    echo "  SKIPPED: needs a built worker and a runnable IDA."
elif IDABIN="$IDABIN" python3 tests/functional_tools.py --worker "$WORKER" >/tmp/ida_hive_func.log 2>&1; then
    ok "$(tail -1 /tmp/ida_hive_func.log)"
else
    bad "tool correctness failed — see /tmp/ida_hive_func.log"
    grep -E "^  - " /tmp/ida_hive_func.log | head -8
fi

step "9/10  Real-IDA integration (concurrent workers, sharing, slot cap)"
if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
    echo "  SKIPPED: needs a built worker and a runnable IDA."
elif IDABIN="$IDABIN" python3 tests/integration_real_ida.py --worker "$WORKER" >/tmp/ida_hive_integ.log 2>&1; then
    ok "$(tail -1 /tmp/ida_hive_integ.log)"
    grep -E "^    " /tmp/ida_hive_integ.log | sed 's/^/  /'
else
    bad "real-IDA integration failed — see /tmp/ida_hive_integ.log"; tail -20 /tmp/ida_hive_integ.log
fi

# Analysis of a large binary runs for minutes, so this is opt-in rather than part
# of every check.
if [ "${RUN_SCALE:-0}" = "1" ]; then
    step "10/10  Worker scale (large binary, table sweeps, paging)"
    if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
        echo "  SKIPPED: needs a built worker and a runnable IDA."
    elif IDABIN="$IDABIN" python3 tests/scale_worker.py --worker "$WORKER" >/tmp/ida_hive_scale.log 2>&1; then
        ok "$(tail -1 /tmp/ida_hive_scale.log)"
        grep -E "^  (target|analysis|final)" /tmp/ida_hive_scale.log | sed 's/^/     /'
    else
        bad "scale test failed — see /tmp/ida_hive_scale.log"; tail -20 /tmp/ida_hive_scale.log
    fi
else
    step "10/10  Worker scale  (SKIPPED: set RUN_SCALE=1, takes several minutes)"
fi

printf '\n\033[1m== summary ==\033[0m\n'
printf '  %d passed, %d failed\n' "$pass" "$fail"
printf '  NOTE: real idalib analysis behaviour is NOT covered here — it needs an\n'
printf '        activated IDA Pro license. This checks everything up to that gate.\n'
[ "$fail" -eq 0 ]
