# Tests

ida-hive is a Rust coordinator that manages C++ `idalib` worker processes. The
two halves are tested very differently because only one of them can run without
an activated IDA Pro license.

## What can be tested without a license

| Layer | How | Coverage |
|-------|-----|----------|
| Rust coordinator | `tests/test_coordinator.py` drives the **real** `ida-hive` binary over real MCP stdio, with `tests/mock_worker.py` standing in for the C++ worker | MCP surface, session routing, path dedup, refcounted teardown, concurrency, timeouts, crash recovery, temp-dir lifecycle, batch_convert |
| C++ worker build | `tests/build_check.sh` compiles **and links** `worker/` against the real public IDA 9.2 SDK via the repo's own `worker/CMakeLists.txt` | The C++ uses the IDA 9.2 API correctly (signatures, types, headers); the documented build path works |
| Worker startup | `build_check.sh` runs the linked worker up to `idalib init_library()` | The binary is well-formed right up to the license gate |

`tests/build_check.sh` runs all of the above in one shot and clones the public
SDK automatically if `IDASDK` is unset. Nothing in the test tree needs or
touches a license file.

## What CANNOT be tested without a license

The actual analysis behaviour of the 64 worker tools (`decompile`, `disasm`,
`xrefs`, types, …) and the README's performance numbers. All of it runs inside
`idalib`, which refuses to initialize without activation — the worker emits a
clean `init_error` and never opens a database. `mock_worker.py` exists precisely
to exercise the coordinator around this gate; it does **not** reproduce IDA's
analysis output.

To validate the real tools, run the license-bearing scripts on an activated
machine: `python test_smoke.py /path/to/binary`.

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
tests/build_check.sh                          # everything license-free
SKIP_WORKER=1 tests/build_check.sh            # coordinator only, no SDK/C++ build
```

Known product bugs are asserted as `xfail` tests: they pass while the bug
exists (documenting it) and fail loudly the day it is fixed. A green run lists
them separately from real failures.

## Findings from this pass

See `../BUGS.md`. In brief, the license-free validation surfaced:

- **`server_health` reports `max_slots: 100` unconditionally** (`src/tools.rs`),
  ignoring `IDA_MCP_MAX_SLOTS` / `config.max_slots`. The real cap is enforced
  correctly by `open_file`; only the reported number is wrong. Tracked by the
  `xfail` test `test_server_health_reports_configured_max_slots`.
- **`enum_upsert` silently ignores its `bitfield` parameter**
  (`worker/commands/cmd_types.cpp`): the value is read, documented in the
  comment, then never applied — the enum is always built as a plain C enum.
- **`init_error` for the license gate carries a garbage `code`**
  (`worker/worker.cpp` passes `init_library()`'s return through, which is
  uninitialized on this path) — the `message` is correct, the `code` is noise.

The C++ worker is otherwise clean under `-Wall -Wextra` (8 benign warnings) and
`clang-tidy` bugprone/analyzer checks (no real defects; the two empty `catch`
blocks are intentional parse-or-fallback idioms).
