# Tests

ida-hive is a Rust coordinator that manages C++ `idalib` worker processes. The
two halves are tested very differently because only one of them can run without
an activated IDA Pro license.

## What can be tested without a license

| Layer | How | Coverage |
|-------|-----|----------|
| Rust coordinator | `tests/test_coordinator.py` drives the **real** `ida-hive` binary over real MCP stdio, with `tests/mock_worker.py` standing in for the C++ worker | MCP surface, session routing, path dedup, refcounted teardown, concurrency, timeouts, crash recovery, temp-dir lifecycle, batch_convert |
| C++ worker build | `scripts/build_check.sh` compiles **and links** `worker/` against the selected public IDA 9.4/9.5 SDK via `worker/CMakeLists.txt` | API signatures, types and headers compile; the documented build path works |

`scripts/build_check.sh` runs all of the above in one shot and clones the public
SDK automatically if `IDASDK` is unset (`SDK_REF` defaults to the pinned 9.5 commit).
Real-worker startup and analysis checks skip without `IDABIN` pointing at an installation.
Nothing in the test tree needs or
touches a license file.

## What CANNOT be tested without a license

The actual analysis behaviour of the worker tools (`decompile`, `disasm`,
`xrefs`, types, …) and the README's performance numbers. All of it runs inside
`idalib`, which refuses to initialize without activation — the worker emits a
clean `init_error` and never opens a database. `mock_worker.py` exists precisely
to exercise the coordinator around this gate; it does **not** reproduce IDA's
analysis output.

To validate the real tools, run the license-bearing scripts in `tests/live/` on
an activated machine: `python tests/live/test_smoke.py /path/to/binary`.

## Layout

| Path | License needed | Purpose |
|------|----------------|---------|
| `tests/test_coordinator.py`, `tests/mock_worker.py` | no | coordinator suite over real MCP stdio |
| `scripts/build_check.sh` | no for builds/mock tests; **yes** for real-worker checks | full gate, reporting skipped steps |
| `tests/live/` | **yes** | real-tool validation; also shipped at the top level of the release tarball |
| `tests/worker_lifecycle.py` | **yes** | real EOF/shutdown exit codes, decompiler cleanup, private files and failed opens |

## The mock worker

`mock_worker.py` speaks the exact JSON-Lines protocol of `worker/worker.cpp`
(argv `<input> <db_dir>`, a `ready`/`init_error` event, then `{id,result}` /
`{id,error}` replies). Fidelity notes:

- **Serial dispatch by default** — the real `CommandDispatcher::run`
  (`worker/protocol.h`) is single-threaded, so a slow call blocks the next call
  on the same worker. The mock mirrors this; concurrency exists only *across*
  workers. (A `concurrent` marker in the file name opts into threaded dispatch,
  used by one defensive test of the coordinator's id-multiplexing.)
- Behaviour is steered by file-name markers (`initfail`, `hangready`,
  `slowwait`, `concurrent`) and by magic parameter values (`SLEEP:<ms>`,
  `CRASH`, `ERROR:<msg>`, `GARBAGE`).

## Running

```bash
cargo build --release            # once
python3 tests/test_coordinator.py            # coordinator suite
python3 tests/test_coordinator.py -k dedup   # filter
python3 tests/test_coordinator.py -v         # tracebacks
scripts/build_check.sh                          # everything license-free
SKIP_WORKER=1 scripts/build_check.sh            # coordinator only, no SDK/C++ build
SDK_REF=v9.4.0-release scripts/build_check.sh   # select the previous SDK
IDASDK=/path/to/sdk/src IDABIN="/Applications/IDA Professional 9.5.app/Contents/MacOS" scripts/build_check.sh
```

The Linux/macOS harnesses share runtime-path and process/resource probes in
`platform_support.py`. Functional fixtures use the target's stack register, a real pointer
for offset round-trips, and ELF or Mach-O uninitialized-data segments. A compiled-addition
regression exercises native decompilation, including the 9.5 kernel dispatcher path.
Checks that require x86-64 disassembly explicitly print `vacuous` on ARM64.

`worker_lifecycle.py` is part of the gate's native startup step. It leaves stdin open for explicit
`shutdown` cases and closes it for EOF cases, waits for the actual exit code, and captures stderr.
Raw inputs live in a read-only directory with spaces/Unicode (and a backslash on Unix), beside a
guarded `.i64` sentinel. The test checks private database files while the worker is alive and
their cleanup after closing. Saved databases are opened as copies and their original hash must
stay unchanged. Loader failures must still emit `init_error` and exit with a nonzero status.

Known product bugs are asserted as `xfail` tests: they pass while the bug
exists (documenting it) and fail loudly the day it is fixed. A green run lists
them separately from real failures.

## Findings from this pass

The license-free validation surfaced:

- **[FIXED] `server_health` reported `max_slots: 100` unconditionally**
  (`src/tools.rs`), ignoring `IDA_MCP_MAX_SLOTS` / `config.max_slots`. Now reports
  `Coordinator::max_slots()`; guarded by
  `test_server_health_reports_configured_max_slots`.
- **[dead code, not reachable via MCP] `enum_upsert`'s `bitfield` parameter**
  (`worker/commands/cmd_types.cpp`): read, documented in a comment, never
  applied. The Rust `enum_upsert` tool does not expose `bitfield`, so through the
  MCP surface it is always `false` and a plain C enum is always correct. Wiring
  it up is a feature addition that cannot be validated without a license, so it
  was left as-is rather than changed blind.
- **[idalib pass-through, not our bug] license-gate `init_error` `code`**
  (`worker/worker.cpp`): the worker faithfully reports `init_library()`'s return
  value, which is non-deterministic on the failure path. The `message` is
  correct; masking the `code` would hide idalib's real return, so it was left.

The C++ worker is otherwise clean under `-Wall -Wextra` (8 benign warnings) and
`clang-tidy` bugprone/analyzer checks (no real defects; the two empty `catch`
blocks are intentional parse-or-fallback idioms).
