# ida-hive

A native multi-instance IDA Pro MCP server built with Rust and C++.

Each binary or database you open gets its own dedicated idalib worker process. No session switching, no GIL, no Python runtime. AI models can query saved `.i64/.idb` databases or raw binaries that IDA can load directly through a single MCP endpoint.

> **Requires IDA Pro 9.2+** with a valid license. This project uses the IDA SDK `idalib` API. No SDK source code or binaries are included.

## Platform Status

- **Windows**: release assets and original performance measurements are Windows-first.
- **Linux**: validated from source on Debian 13 with IDA Pro 9.2 and public `HexRaysSA/ida-sdk` tag `v9.2.0-sdk.1`.
- **Single codebase**: the goal is one MCP contract and one tool surface across both platforms. Users should only need the platform-specific build artifacts.

## Why

Existing IDA MCP servers are Python-based and single-instance — they load one binary at a time, and switching between databases costs hundreds of milliseconds. ida-hive takes a different approach: spawn a lightweight C++ worker per binary, coordinate them from Rust, and let AI models talk to all of them at once.

## Architecture

```
Claude / Codex / any MCP client
          |  stdio (MCP 2024-11-05)
          v
   ┌──────────────────┐
   │  Rust Coordinator │   rmcp + tokio
   │  session routing  │
   │  process pool     │
   └────────┬─────────┘
            │  JSON Lines over pipe
     ┌──────┼──────┬──────┬─── ...
     v      v      v      v
   [C++]  [C++]  [C++]  [C++]    idalib worker processes
   bin.i64 bin.i64 bin.i64 ...    one IDB each, fully isolated
```

- **Coordinator** (Rust, ~800 LOC): MCP protocol handling, session-to-worker routing, lifecycle management. Built on [rmcp](https://github.com/anthropics/rmcp).
- **Worker** (C++, ~2000 LOC): Headless idalib process. Loads one `.i64/.idb` or raw binary, responds to JSON commands, calls IDA SDK directly. No Python layer in between.

## Performance

Measured on Windows 11, IDA Pro 9.2, using CS2 game binaries:

| Scenario | Result |
|----------|--------|
| Load `.i64` + auto-ready | ~2-4s depending on size |
| Decompile one function | Instant (< 100ms round-trip) |
| 5 binaries analyzed in parallel | 13s total (including a 97,967-function DLL) |
| survey_binary on 12,598 functions | 3s |
| 30 invalid/malformed inputs | Zero crashes, all return clean errors |

Session switching is essentially free — each binary lives in its own process, so querying binary A doesn't block or invalidate binary B.

## Tools

64 MCP tools across 9 categories:

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

Not included by design: debugger tools (use x64dbg/WinDbg) and Python eval (no Python in the stack).

## Build

### Prerequisites

- IDA Pro 9.2+ installed and activated
- IDA SDK 9.2 compatible tree exposed through `IDASDK`
- CMake 3.27+
- Rust toolchain (`rustup`)
- GCC/Clang on Linux, or MSVC 2022+ on Windows

### SDK Setup

Tested SDK source:

```bash
git clone --branch v9.2.0-sdk.1 --depth 1 https://github.com/HexRaysSA/ida-sdk.git /path/to/ida-sdk
git -C /path/to/ida-sdk submodule update --init --recursive
```

### Windows Build

```bash
set IDASDK=C:\path\to\ida-sdk
cmake -S worker -B worker/build
cmake --build worker/build --config Release
cargo build --release --target x86_64-pc-windows-msvc
```

Artifacts:

```text
target/x86_64-pc-windows-msvc/release/ida-hive.exe
worker/build/Release/ida_mcp_worker.exe
```

### Linux Build

```bash
export IDASDK=/path/to/ida-sdk
cmake -S worker -B worker/build-linux
cmake --build worker/build-linux -j"$(nproc)"
cargo build --release
```

Artifacts:

```text
target/release/ida-hive
worker/build-linux/ida_mcp_worker
```

## Setup

The most reliable setup is to launch `ida-hive` through a tiny wrapper that injects the platform-specific runtime environment.

### Windows Wrapper

```bat
@echo off
set "PATH=C:\Program Files\IDA Professional 9.2;%PATH%"
set "IDA_MCP_WORKER_EXE=C:\path\to\ida_mcp_worker.exe"
set "IDA_MCP_MAX_SLOTS=100"
C:\path\to\ida-hive.exe
```

### Linux Wrapper

```bash
#!/usr/bin/env bash
export LD_LIBRARY_PATH="/opt/ida-pro-9.2:${LD_LIBRARY_PATH:-}"
export IDA_MCP_WORKER_EXE="/path/to/ida_mcp_worker"
export IDA_MCP_MAX_SLOTS=100
exec /path/to/ida-hive
```

Then point your MCP client at the wrapper script:

```json
"ida-hive": {
  "type": "stdio",
  "command": "/path/to/ida-hive-wrapper",
  "args": []
}
```

Restart your MCP client. The 64 tools will appear automatically.

## Usage

The intended workflow:

1. **AI** can open either a saved `.i64/.idb` database or a raw binary that IDA can load directly via `open_file`
2. For raw binaries, use `analysis_status` to poll or `wait_analysis` to block until auto-analysis is done
3. Use `batch_convert` when you want to preprocess a set of raw binaries into `.i64`
4. Multiple sessions can stay open simultaneously for cross-binary work

```
You:    "Open C:\analysis\target.dll.i64 and give me an overview"
AI:     → open_file(path="...", session="s1")
        → survey_binary(session="s1")
        "This DLL has 1,284 functions across 5 segments..."

You:    "Decompile CreateInterface"
AI:     → lookup_func(target="CreateInterface", session="s1")
        → decompile(ea="0x180041E00", session="s1")

You:    "Open client.dll directly and wait for analysis"
AI:     → open_file(path="C:\games\client.dll", session="raw1")
        → wait_analysis(session="raw1", max_seconds=300)
        → survey_binary(session="raw1")

You:    "Also batch-convert the whole plugin folder to .i64"
AI:     → batch_convert(paths=[...], output_dir="C:\analysis\i64", concurrency=4)

You:    "Also open steam_api64.dll.i64 and compare"
AI:     → open_file(path="...", session="s2")
        Both sessions respond in parallel.
```

Validated raw-binary paths so far:

- Windows PE inputs (`.dll`, `.exe`, `.sys`) from the original project workflow
- Linux ELF inputs such as `/bin/true`

## Testing

244 test cases across C++ worker and Rust MCP protocol, plus release smoke scripts, covering:
- Worker command coverage for valid inputs
- 30 boundary/invalid inputs (BADADDR, empty strings, wrong types, malformed JSON)
- Large binary stress test (97,967 functions)
- 5-binary concurrent analysis
- Full MCP protocol round-trip across the tool surface
- Raw-binary auto-analysis and batch conversion smoke flows
- Multi-session isolation and cleanup

Zero crashes, zero unhandled errors.

Recommended local smoke tests:

```bash
python test_smoke.py /path/to/binary
python test_batch.py /path/to/binary1 /path/to/binary2
```

Notes:

- `test_smoke.py` is the cross-platform MCP smoke path.
- `test_batch.py` exercises `batch_convert` end-to-end.
- `test_full_e2e.sh` remains a Windows-oriented deep sample for a known PE target.

## License

MIT
