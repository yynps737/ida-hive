# ida-mcp-rs

Multi-instance IDA MCP Server for AI-driven binary analysis.

Rust coordinator + C++ idalib workers. 60 MCP tools, up to 100 concurrent analysis sessions, zero external dependencies.

> **Requires IDA Pro 9.2+** with a valid license. This project uses the IDA SDK's `idalib` (IDA-as-a-library) API. You must own a licensed copy of IDA Pro to build and run this tool. No IDA SDK source code or binaries are included in this repository.

## Architecture

```
Claude / Codex
      | stdio (JSON-RPC)
      v
+---------------------------+
|  Rust Coordinator         |  MCP protocol + process pool
|  - session routing        |
|  - slot lifecycle         |
+----------+----------------+
           | JSON Lines over pipe
    +------+------+------+--- ...
    v      v      v      v
 [Wrk0] [Wrk1] [Wrk2] [WrkN]   C++ idalib processes
 bin0    bin1    bin2    binN
```

## Prerequisites

- IDA Pro 9.2+ installed and licensed
- IDA SDK 9.2 (`IDASDK` env var set)
- CMake 3.27+
- MSVC 2022 (Windows) / GCC/Clang (Linux/macOS)
- Rust toolchain (rustup)

## Build

### 1. C++ Worker

```bash
cd worker
set IDASDK=C:\path\to\idasdk92
cmake -B build
cmake --build build --config Release
```

Output: `worker/build/Release/ida_mcp_worker.exe`

### 2. Rust Coordinator

```bash
cargo build --release
```

Output: `target/release/ida-mcp-rs.exe`

## Usage

### Quick Test (manual)

```bash
# Terminal 1: Start coordinator
set IDA_MCP_WORKER_EXE=worker/build/Release/ida_mcp_worker.exe
cargo run

# Then type JSON commands on stdin:
{"id":1,"method":"open_file","params":{"path":"C:\\test\\target.exe","session":"s1"}}
{"id":2,"method":"list_funcs","params":{"session":"s1","limit":5}}
{"id":3,"method":"decompile","params":{"session":"s1","ea":"0x1400010A0"}}
```

### As MCP Server

Add to `.mcp.json`:
```json
{
  "mcpServers": {
    "ida-mcp-rs": {
      "command": "path/to/ida-mcp-rs.exe",
      "env": {
        "IDA_MCP_WORKER_EXE": "path/to/ida_mcp_worker.exe",
        "IDA_MCP_MAX_SLOTS": "20"
      }
    }
  }
}
```

## Supported Commands

### Management (Coordinator)
| Command | Params | Description |
|---------|--------|-------------|
| `open_file` | `path, session?` | Open binary in new worker slot |
| `list_slots` | — | List all active worker slots |
| `close_session` | `session` | Stop worker and free slot |

### Analysis (Worker)
| Command | Params | Description |
|---------|--------|-------------|
| `decompile` | `ea` | Hex-Rays decompile function |
| `disasm` | `ea, count?` | Disassemble function |
| `xrefs_to` | `ea` | Cross-references to address |
| `xrefs_from` | `ea` | Cross-references from address |
| `callees` | `ea` | Functions called by function |

### Core (Worker)
| Command | Params | Description |
|---------|--------|-------------|
| `get_info` | — | IDB metadata |
| `list_funcs` | `offset?, limit?, filter?` | List functions |
| `list_segments` | — | List segments |
| `lookup_func` | `target` | Find function by name/address |

### Memory (Worker)
| Command | Params | Description |
|---------|--------|-------------|
| `get_bytes` | `ea, size` | Read bytes |
| `patch_bytes` | `ea, hex` | Write bytes |
| `get_string` | `ea` | Read string literal |

### Modify (Worker)
| Command | Params | Description |
|---------|--------|-------------|
| `rename` | `ea, name` | Rename address |
| `set_comment` | `ea, comment, repeatable?` | Set comment |
| `get_name` | `ea` | Get name at address |

## Status

**PoC** — validates:
1. C++ idalib + Hex-Rays headless decompilation
2. Multi-process architecture (Rust coordinator + C++ workers)
3. JSON Lines IPC protocol

TODO:
- [ ] Proper async response routing in Slot
- [ ] rmcp MCP protocol integration
- [ ] Full 49-tool parity with Python MCP
- [ ] Worker crash recovery / auto-restart
- [ ] Session timeout / LRU eviction
