#!/usr/bin/env bash
# Builds against the selected SDK, then runs mock and real-IDA checks. Real checks
# are skipped without a runnable IDA installation. The public SDK is fetched when
# $IDASDK is unset; SDK_REF selects 9.4 or the pinned 9.5 beta SDK.
#
# Usage:
#   scripts/build_check.sh                 # full run, cloning the SDK if needed
#   IDASDK=/path/to/ida-sdk/src scripts/build_check.sh
#   SKIP_WORKER=1 scripts/build_check.sh   # coordinator only (no SDK/C++ build)
#   RUN_SCALE=1 scripts/build_check.sh     # add the large-binary scale test

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SDK_REF="${SDK_REF:-05a7724800b9e231b3edabf53c5ad4598973edb2}"
SDK_CACHE="${SDK_CACHE:-$ROOT/worker/.ida-sdk-cache/$SDK_REF}"
if [ "$(uname -s)" = "Darwin" ]; then
    default_build_dir="$ROOT/worker/build-macos"
    sdk_platform=mac
else
    default_build_dir="$ROOT/worker/build-linux"
    sdk_platform=linux
fi
BUILD_DIR="${BUILD_DIR:-$default_build_dir}"
JOBS="${CMAKE_BUILD_PARALLEL_LEVEL:-$(python3 -c 'import os; print(os.cpu_count() or 1)')}"
TEST_BINARY="${IDA_HIVE_TEST_BINARY:-/usr/bin/grep}"
IDABIN="${IDABIN:-}"
WORKER=""

pass=0; fail=0; skip=0
declare -a skipped=()
step()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; current_step="$*"; }
skipped() { skip=$((skip+1)); skipped+=("$current_step — $*"); printf '  \033[33mSKIP\033[0m %s\n' "$*"; }
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
step "2/10  Rust lints and deadline/transport unit tests"
if cargo clippy --release --all-targets >/tmp/ida_hive_clippy.log 2>&1; then
    ok "no lint findings"
else
    bad "clippy reported findings — see /tmp/ida_hive_clippy.log"
    grep -E "^error" /tmp/ida_hive_clippy.log | head -10
fi
if cargo test --release --locked >/tmp/ida_hive_rust_tests.log 2>&1; then
    echo "  $(grep '^test result:' /tmp/ida_hive_rust_tests.log)"
else
    bad "Rust unit tests failed — see /tmp/ida_hive_rust_tests.log"
    tail -25 /tmp/ida_hive_rust_tests.log
fi

if [ "${SKIP_WORKER:-0}" != "1" ]; then
    step "3/10  C++ worker build against the selected IDA 9.4/9.5 SDK"

    if [ -z "${IDASDK:-}" ]; then
        if [ ! -f "$SDK_CACHE/src/include/ida.hpp" ]; then
            echo "  fetching public IDA SDK $SDK_REF..."
            if git init "$SDK_CACHE" >/tmp/ida_hive_sdk.log 2>&1 \
               && git -C "$SDK_CACHE" fetch --depth 1 \
                    https://github.com/HexRaysSA/ida-sdk.git "$SDK_REF" >>/tmp/ida_hive_sdk.log 2>&1 \
               && git -C "$SDK_CACHE" checkout --detach FETCH_HEAD >>/tmp/ida_hive_sdk.log 2>&1; then
                echo "  SDK ready at $SDK_CACHE"
            else
                bad "SDK clone failed — see /tmp/ida_hive_sdk.log"; tail -15 /tmp/ida_hive_sdk.log
            fi
        fi
        export IDASDK="$SDK_CACHE/src"
    fi
    # SDK link stubs are sufficient to build. A real installation is supplied
    # explicitly through IDABIN for the runtime checks below.
    sdk_source="$IDASDK"
    if [ -f "$IDASDK/src/include/pro.h" ]; then sdk_source="$IDASDK/src"; fi
    case "$(uname -m)" in arm64|aarch64) sdk_arch=arm64 ;; *) sdk_arch=x64 ;; esac
    export IDABIN="${IDABIN:-$sdk_source/lib/${sdk_arch}_${sdk_platform}_64}"

    # IDASDK may name the repo root or its src/ subdirectory; both are valid.
    if [ -f "$IDASDK/cmake/idasdk_init.cmake" ] || [ -f "$IDASDK/src/cmake/idasdk_init.cmake" ]; then
        if cmake -S worker -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
                 -DIDASDK="$IDASDK" -DIDABIN="$IDABIN" >/tmp/ida_hive_cmake.log 2>&1 \
           && cmake --build "$BUILD_DIR" --parallel "$JOBS" >>/tmp/ida_hive_cmake.log 2>&1; then
            ok "worker compiled + linked via worker/CMakeLists.txt"
        else
            bad "worker build failed — see /tmp/ida_hive_cmake.log"; tail -25 /tmp/ida_hive_cmake.log
        fi
    else
        bad "IDASDK=$IDASDK has no cmake/idasdk_init.cmake (SDK older than 9.4?)"
    fi

    step "4/10  Native worker lifecycle and MCP smoke"
    if [ -f "$BUILD_DIR/worker-path.txt" ]; then WORKER="$(cat "$BUILD_DIR/worker-path.txt")"; fi
    if [ -z "$WORKER" ]; then
        bad "no ida_mcp_worker binary produced"
    # The SDK's lib/ holds link-time stubs only: they satisfy the linker but
    # segfault when called, so this step needs a real install to mean anything.
    elif [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; then
        skipped "IDABIN holds SDK link stubs, not a runnable IDA"
    else
        if IDABIN="$IDABIN" python3 tests/worker_lifecycle.py \
             --worker "$WORKER" >/tmp/ida_hive_lifecycle.log 2>&1 \
           && IDA_MCP_OPEN_TIMEOUT=60 python3 tests/live/test_smoke.py "$TEST_BINARY" \
             --worker "$WORKER" --ida-path "$IDABIN" --skip-batch --skip-decompile \
             >/tmp/ida_hive_startup.log 2>&1; then
            ok "clean EOF/shutdown, loader failures, private files and MCP startup"
            tail -1 /tmp/ida_hive_lifecycle.log
        else
            bad "native lifecycle/startup failed — see /tmp/ida_hive_lifecycle.log and /tmp/ida_hive_startup.log"
            tail -15 /tmp/ida_hive_lifecycle.log
            tail -15 /tmp/ida_hive_startup.log
        fi
    fi
else
    step "3/10  C++ worker build"
    skipped "SKIP_WORKER=1"
    step "4/10  Native worker startup"
    skipped "SKIP_WORKER=1"
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
if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
    skipped "needs a built worker and a runnable IDA"
elif IDABIN="$IDABIN" python3 tests/stress_worker.py --worker "$WORKER" --target "$TEST_BINARY" >/tmp/ida_hive_stress.log 2>&1; then
    ok "$(tail -1 /tmp/ida_hive_stress.log)"
else
    bad "stress test failed — see /tmp/ida_hive_stress.log"; tail -15 /tmp/ida_hive_stress.log
fi

step "7/10  Worker endurance (memory, descriptors, kill cleanup)"
if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
    skipped "needs a built worker and a runnable IDA"
elif IDABIN="$IDABIN" python3 tests/endurance_worker.py --worker "$WORKER" --target "$TEST_BINARY" >/tmp/ida_hive_endur.log 2>&1; then
    ok "$(tail -1 /tmp/ida_hive_endur.log)"
    grep -E "^  (memory|fds|cycles):" /tmp/ida_hive_endur.log | sed 's/^/     /'
else
    bad "endurance test failed — see /tmp/ida_hive_endur.log"; tail -15 /tmp/ida_hive_endur.log
fi

step "8/10  Tool correctness (IDA 9.4/9.5)"
if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
    skipped "needs a built worker and a runnable IDA"
elif IDABIN="$IDABIN" python3 tests/functional_tools.py --worker "$WORKER" --target "$TEST_BINARY" >/tmp/ida_hive_func.log 2>&1; then
    ok "$(tail -1 /tmp/ida_hive_func.log)"
else
    bad "tool correctness failed — see /tmp/ida_hive_func.log"
    grep -E "^  - " /tmp/ida_hive_func.log | head -8
fi

step "9/10  Real-IDA integration (concurrent workers, sharing, slot cap)"
if [ -z "$WORKER" ] || { [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; }; then
    skipped "needs a built worker and a runnable IDA"
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
        skipped "needs a built worker and a runnable IDA"
    elif IDABIN="$IDABIN" python3 tests/scale_worker.py --worker "$WORKER" >/tmp/ida_hive_scale.log 2>&1; then
        ok "$(tail -1 /tmp/ida_hive_scale.log)"
        grep -E "^  (target|analysis|final)" /tmp/ida_hive_scale.log | sed 's/^/     /'
    else
        bad "scale test failed — see /tmp/ida_hive_scale.log"; tail -20 /tmp/ida_hive_scale.log
    fi
else
    step "10/10  Worker scale"
    skipped "set RUN_SCALE=1 to run it (takes several minutes)"
fi

printf '\n\033[1m== summary ==\033[0m\n'
printf '  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
if [ "$skip" -gt 0 ]; then
    printf '\n  \033[33m%d step(s) were skipped\033[0m — a green run here is not a full pass:\n' "$skip"
    for s in "${skipped[@]}"; do printf '    - %s\n' "$s"; done
    if [ ! -x "$IDABIN/idat" ] && [ ! -x "$IDABIN/ida" ]; then
        printf '  Point IDABIN at an activated IDA installation to cover them.\n'
    fi
fi
[ "$fail" -eq 0 ]
