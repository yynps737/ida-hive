# ida-hive

A native multi-instance IDA Pro MCP server built with Rust and C++.

Each binary or database you open gets its own dedicated `idalib` worker process. No session
switching, no GIL, no Python runtime. AI models can query saved `.i64/.idb` databases — or raw
binaries that IDA can load directly — through a single MCP endpoint.

> **Requires IDA Pro 9.2+** with a valid license. This project uses the IDA SDK `idalib` API.
> No SDK source code or binaries are included.

## Platform status

- **Linux**: built and validated from source on Ubuntu 26.04 with IDA Pro 9.2 and the public
  `HexRaysSA/ida-sdk` tag `v9.2.0-sdk.1`. The behavior and measurements in this README come from
  that validation.
- **Windows**: supported by the same codebase; release assets and the original performance numbers
  were Windows-first. The Windows build path below is unchanged but was not re-validated here.
- **Single codebase**: one MCP contract and one tool surface across both platforms.

## Why

Existing IDA MCP servers are Python-based and single-instance — they load one binary at a time, and
switching databases costs real time. ida-hive spawns a lightweight C++ worker per binary,
coordinates them from Rust, and lets AI models talk to all of them at once.

## Architecture

```
Claude / Codex / any MCP client
          |  stdio (MCP 2026-07-28)
          v
   ┌───────────────────┐
   │  Rust Coordinator  │   rmcp + tokio
   │  session routing   │
   │  process pool      │
   └────────┬──────────┘
            │  JSON Lines over stdin/stdout
     ┌──────┼──────┬──────┬─── ...
     v      v      v      v
   [C++]  [C++]  [C++]  [C++]    idalib worker processes
                                  one database each, isolated
```

- **Coordinator** (Rust): MCP protocol (spec `2026-07-28`), session→worker routing, process-pool
  lifecycle. Built on [rmcp](https://github.com/modelcontextprotocol/rust-sdk) 3.x. Requests are
  handled concurrently — a slow call on one session does not block other sessions.
- **Worker** (C++): a headless `idalib` process. Loads one `.i64/.idb` or raw binary, answers JSON
  commands by calling the IDA SDK directly. No Python layer.

## Concurrency & isolation

- **Private database per worker.** Each worker keeps IDA's database files in its own temp directory
  (raw binaries are redirected there via IDA's `-o`; `.i64/.idb` inputs are copied in and the copy
  is opened). The input file's own directory is never written to, and **two workers — even in
  separate server processes — can open the same binary at once** without colliding on IDA's
  database/lock files.
- **One worker per file (dedup by canonical path).** Within a single coordinator, opening the same
  file path (any spelling — relative, `./`, symlink) from several sessions **reuses one shared
  worker**. That worker holds **one mutable database**: a `rename`/`set_comment`/`set_type` in
  session A is visible in session B. Different files open concurrently; opening one large binary
  does not stall opens of others.
- **Lifecycle.** `close_session` stops a worker only once no other session still references it.
  Workers that die on their own are reaped and their temp directories removed. `kill_on_drop` plus a
  `Drop` cleanup remove temp directories on normal shutdown (a hard `SIGKILL` of the coordinator can
  still orphan workers — see Limitations).

## Analysis model (important)

- Opening a **`.i64/.idb` database is instant** (no re-analysis).
- Opening a **raw binary is synchronous**: `open_file` **does not return until IDA's initial
  auto-analysis finishes**. On large inputs this can take minutes. The startup wait is bounded by
  `IDA_MCP_OPEN_TIMEOUT` (default 600s).
- `analysis_status` and `wait_analysis` exist for the contract, but because the open is synchronous,
  analysis is normally already complete by the time `open_file` returns.

Measured during this validation (Ubuntu 26.04, 18 cores, IDA 9.2):

| Input | Size | open_file (raw, incl. analysis) | Functions |
|-------|------|---------------------------------|-----------|
| `bash` | 1.5 MB | ~7 s | 3,123 |
| `libcrypto.so.3` | 6 MB | ~20 s | 12,556 |
| `python3.14` | 6.8 MB | ~115 s | — |
| `libclang.so` | 75 MB | ~410 s (~1 GB RSS) | 65,868 |
| any `.i64/.idb` | — | instant (no analysis) | — |

Across separate processes these analyses run in parallel; e.g. 8 agents each opening the same 6 MB
library concurrently completed in ~44 s wall.

## Tools

64 MCP tools across 9 categories. Address arguments (`ea` / `target`) accept **either a hex address
(`0x...`) or a function/symbol name**.

| Category | Tools | Count |
|----------|-------|-------|
| Management | open_file, list_instances, close_session, analysis_status, wait_analysis, batch_convert, server_health, server_warmup | 8 |
| Core Query | get_info, list_funcs, func_query, lookup_func, list_segments, list_globals, entity_query, imports, imports_query, int_convert, find_regex, save_idb | 12 |
| Analysis | decompile, disasm, xrefs_to, xrefs_from, xref_query, xrefs_to_field, callees, func_profile, analyze_function, analyze_batch, export_funcs | 11 |
| Search | find_bytes, insn_query, basic_blocks, callgraph | 4 |
| Types | set_type, type_inspect, declare_type, type_query, search_structs, infer_types, enum_upsert, read_struct, type_apply_batch | 9 |
| Modify | rename, set_comment, get_name, append_comments, define_func, define_code, undefine | 7 |
| Memory | get_bytes, get_string, patch_bytes, get_int, put_int, get_global_value | 6 |
| Stack | stack_frame, declare_stack, delete_stack | 3 |
| Composite | survey_binary, trace_data_flow, analyze_component, diff_before_after | 4 |

Modifications (`rename`, `set_comment`, `set_type`, `patch_bytes`, …) change that worker's in-memory
database; call `save_idb` to persist. `save_idb` with no path saves next to the original input
(a raw binary → `<input>.i64`; a database → itself), written atomically (temp file + rename).

Not included by design: debugger tools (use x64dbg/WinDbg) and Python eval (no Python in the stack).

## Build

### Prerequisites

- IDA Pro 9.2+ installed and activated
- The IDA SDK `v9.2.0-sdk.1` tree (below)
- CMake 3.27+
- Rust toolchain (`rustup`)
- GCC/Clang on Linux, or MSVC 2022+ on Windows

### SDK setup

```bash
git clone --branch v9.2.0-sdk.1 --depth 1 https://github.com/HexRaysSA/ida-sdk.git /path/to/ida-sdk
git -C /path/to/ida-sdk submodule update --init --recursive
```

### Build environment

Two variables drive the worker build:

- `IDASDK` — point at the SDK's **`src` subdirectory** (e.g. `/path/to/ida-sdk/src`). This is the
  layout the worker's CMake resolves headers against.
- `IDABIN` — your **IDA install directory** (where `libidalib.so` / `libida.so` live), so the worker
  links against the runtime libraries.

### Linux build

```bash
export IDASDK=/path/to/ida-sdk/src
export IDABIN=/path/to/IDA-install        # e.g. /home/you/idapro-9.2
cmake -S worker -B worker/build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build worker/build-linux -j"$(nproc)"
cargo build --release
```

Artifacts:

```text
target/release/ida-hive
worker/build-linux/ida_mcp_worker
```

### Windows build

```bat
set IDASDK=C:\path\to\ida-sdk\src
set IDABIN=C:\Program Files\IDA Professional 9.2
cmake -S worker -B worker/build
cmake --build worker/build --config Release
cargo build --release --target x86_64-pc-windows-msvc
```

Artifacts:

```text
target\x86_64-pc-windows-msvc\release\ida-hive.exe
worker\build\Release\ida_mcp_worker.exe
```

## Run / configure

The most reliable setup launches `ida-hive` through a small wrapper that injects the runtime
environment. The coordinator reads these variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `IDA_MCP_WORKER_EXE` | path to the `ida_mcp_worker` binary | `ida_mcp_worker` (PATH) |
| `IDA_MCP_MAX_SLOTS` | max concurrent worker processes | `100` |
| `IDA_MCP_OPEN_TIMEOUT` | seconds to wait for a worker to become ready (raw-binary analysis can be long) | `600` |

On Linux the IDA install directory must also be on `LD_LIBRARY_PATH` (for `libidalib.so`); on Windows
it must be on `PATH`.

### Linux wrapper

```bash
#!/usr/bin/env bash
export LD_LIBRARY_PATH="/path/to/IDA-install:${LD_LIBRARY_PATH:-}"
export IDA_MCP_WORKER_EXE="/path/to/worker/build-linux/ida_mcp_worker"
export IDA_MCP_MAX_SLOTS=100
# export IDA_MCP_OPEN_TIMEOUT=1200   # raise if you analyze very large binaries
exec /path/to/target/release/ida-hive
```

### Windows wrapper

```bat
@echo off
set "PATH=C:\Program Files\IDA Professional 9.2;%PATH%"
set "IDA_MCP_WORKER_EXE=C:\path\to\ida_mcp_worker.exe"
set "IDA_MCP_MAX_SLOTS=100"
C:\path\to\ida-hive.exe
```

Point your MCP client at the wrapper:

```json
"ida-hive": {
  "type": "stdio",
  "command": "/path/to/ida-hive-wrapper",
  "args": []
}
```

Restart your MCP client; the 64 tools appear automatically.

## Usage

Typical workflow:

1. Open a saved `.i64/.idb` (instant) or a raw binary (analyzed on open) with `open_file`.
2. Query: `survey_binary`, `decompile`, `disasm`, `xrefs_to/from`, `callees`, `imports`, …
3. Modify if needed (`rename`, `set_comment`, `set_type`), then `save_idb` to persist.
4. Keep several sessions open for cross-binary work; convert sets of raw binaries with
   `batch_convert`.

```
You:  "Open target.dll.i64 and give me an overview"
AI:   → open_file(path="…/target.dll.i64", session="s1")     # instant (database)
      → survey_binary(session="s1")

You:  "Decompile CreateInterface"
AI:   → lookup_func(ea="CreateInterface", session="s1")        # ea accepts a name
      → decompile(ea="CreateInterface", session="s1")          # or a hex address

You:  "Open client.dll directly"
AI:   → open_file(path="…/client.dll", session="raw1")         # blocks until analysis completes
      → survey_binary(session="raw1")

You:  "Batch-convert the plugin folder to .i64"
AI:   → batch_convert(paths=[…], output_dir="…/i64", concurrency=4)
```

## Behavior & limitations

- **`open_file` on a raw binary blocks** until initial analysis completes (see Analysis model).
  Raise `IDA_MCP_OPEN_TIMEOUT` for very large inputs.
- **Same-file sessions share one mutable database** (see Concurrency & isolation). Use distinct
  files, or be aware that modifications are shared, when several sessions target the same binary.
- **Tool errors** are returned as a JSON object with an `"error"` field (the call still completes at
  the protocol level), not as an MCP protocol error.
- A hard `SIGKILL` of the coordinator can orphan worker processes / leave temp directories; normal
  shutdown (client closing the connection) cleans them up.
- Cross-process concurrency is also bounded by your IDA **license seats**; if a worker can't acquire
  a license it fails fast with a clear `init_error`.

## Testing

Local smoke / batch scripts (cross-platform MCP round-trips):

```bash
python tests/live/test_smoke.py /path/to/binary
python tests/live/test_batch.py /path/to/binary1 /path/to/binary2
```

- `tests/live/test_smoke.py` — open → analyze → survey → decompile → batch_convert → close.
- `tests/live/test_batch.py` — exercises `batch_convert` end-to-end.
- `scripts/full_e2e_sample.sh` — a deeper, Windows-oriented sample for a known PE target.

These need an activated IDA license. The release tarball ships them at its top
level, so from an extracted package the path is just `python test_smoke.py`.
See `tests/README.md` for the license-free coordinator suite.

This branch additionally went through a multi-agent production-validation pass that drove the live
tools against real binaries; it found and fixed 19 tool-surface correctness bugs (see `CHANGELOG.md`
and `BUGS.md`).

## License

MIT
