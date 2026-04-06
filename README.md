# ida-hive

A native multi-instance IDA Pro MCP server built with Rust and C++.

Each binary you open gets its own dedicated idalib worker process. No session switching, no GIL, no Python runtime. AI models query multiple binaries in parallel through a single MCP endpoint.

> **Requires IDA Pro 9.2+** with a valid license. This project uses the IDA SDK `idalib` API. No SDK source code or binaries are included.

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
- **Worker** (C++, ~2000 LOC): Headless idalib process. Loads one `.i64`, responds to JSON commands, calls IDA SDK directly. No Python layer in between.

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

60 MCP tools across 9 categories:

| Category | Tools | Count |
|----------|-------|-------|
| Management | open_file, list_instances, close_session, server_health, server_warmup | 5 |
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
- IDA SDK 9.2 (set `IDASDK` environment variable)
- CMake 3.27+, MSVC 2022+ (Windows)
- Rust toolchain (`rustup`)

### C++ Worker

```bash
cd worker
set IDASDK=C:\path\to\ida-sdk
cmake -B build
cmake --build build --config Release
```

### Rust Coordinator

```bash
cargo build --release --target x86_64-pc-windows-msvc
```

Two files are the entire deployment:

```
target/.../release/ida-hive.exe       ~2 MB
worker/build/Release/ida_mcp_worker.exe  ~420 KB
```

## Setup

Add to your Claude Code global config (`~/.claude.json` under `mcpServers`):

```json
"ida-hive": {
  "type": "stdio",
  "command": "C:/path/to/ida-hive.exe",
  "args": [],
  "env": {
    "IDA_MCP_WORKER_EXE": "C:/path/to/ida_mcp_worker.exe",
    "IDA_MCP_MAX_SLOTS": "100",
    "PATH": "C:\\Program Files\\IDA Professional 9.2;%PATH%"
  }
}
```

Restart Claude Code. The 60 tools will appear automatically.

## Usage

The intended workflow:

1. **You** open a binary in IDA Pro GUI, analyze it, save as `.i64`
2. **AI** loads the `.i64` via `open_file`, queries it with the 60 tools
3. Multiple `.i64` files can be open simultaneously in different sessions

```
You:    "Open C:\analysis\target.dll.i64 and give me an overview"
AI:     → open_file(path="...", session="s1")
        → survey_binary(session="s1")
        "This DLL has 1,284 functions across 5 segments..."

You:    "Decompile CreateInterface"
AI:     → lookup_func(target="CreateInterface", session="s1")
        → decompile(ea="0x180041E00", session="s1")

You:    "Also open steam_api64.dll.i64 and compare"
AI:     → open_file(path="...", session="s2")
        Both sessions respond in parallel.
```

## Testing

244 test cases across C++ worker and Rust MCP protocol, covering:
- All 56 C++ commands with valid inputs
- 30 boundary/invalid inputs (BADADDR, empty strings, wrong types, malformed JSON)
- Large binary stress test (97,967 functions)
- 5-binary concurrent analysis
- Full MCP protocol round-trip for all 60 tools
- Multi-session isolation and cleanup

Zero crashes, zero unhandled errors.

## License

MIT
