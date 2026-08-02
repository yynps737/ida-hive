# Tests

ida-hive is a Rust coordinator that manages C++ `idalib` worker processes. The
two halves are tested very differently because only one of them can run without
an activated IDA Pro license.

## What can be tested without a license

| Layer | How | Coverage |
|-------|-----|----------|
| Rust coordinator | `tests/test_coordinator.py` drives the **real** `ida-hive` binary over real MCP stdio, with `tests/mock_worker.py` standing in for the C++ worker | MCP surface, session routing, path dedup, refcounted teardown, concurrency, timeouts, crash recovery, temp-dir lifecycle, batch_convert |
| C++ worker build | `scripts/build_check.sh` compiles **and links** `worker/` against the real public IDA 9.2 SDK via the repo's own `worker/CMakeLists.txt` | The C++ uses the IDA 9.2 API correctly (signatures, types, headers); the documented build path works |
| Worker startup | `build_check.sh` runs the linked worker up to `idalib init_library()` | The binary is well-formed right up to the license gate |

`scripts/build_check.sh` runs all of the above in one shot and clones the public
SDK automatically if `IDASDK` is unset. Nothing in the test tree needs or
touches a license file.

## What CANNOT be tested without a license

The actual analysis behaviour of the 64 worker tools (`decompile`, `disasm`,
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
| `scripts/build_check.sh` | no | C++ worker compile + link + startup |
| `tests/live/` | **yes** | real-tool validation; also shipped at the top level of the release tarball |

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
```

Known product bugs are asserted as `xfail` tests: they pass while the bug
exists (documenting it) and fail loudly the day it is fixed. A green run lists
them separately from real failures.

## Findings from this pass

See `../BUGS.md`. In brief, the license-free validation surfaced:

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
