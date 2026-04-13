#!/usr/bin/env python3
"""Smoke-test batch_convert via MCP stdio (JSONL framing).

Usage:
  python test_batch.py /path/to/binary1 /path/to/binary2

Environment overrides:
  IDA_HIVE_SERVER_EXE
  IDA_HIVE_WORKER_EXE
  IDA_HIVE_BATCH_OUTPUT
  IDA_HIVE_IDA_PATH
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def pick_existing(candidates):
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def default_server():
    system = platform.system()
    if system == "Windows":
        return pick_existing([
            ROOT / "target" / "x86_64-pc-windows-msvc" / "release" / "ida-hive.exe",
        ])
    return pick_existing([
        ROOT / "target" / "release" / "ida-hive",
    ])


def default_worker():
    system = platform.system()
    if system == "Windows":
        return pick_existing([
            ROOT / "worker" / "build" / "Release" / "ida_mcp_worker.exe",
            ROOT / "worker" / "build" / "ida_mcp_worker.exe",
        ])
    return pick_existing([
        ROOT / "worker" / "build-linux" / "ida_mcp_worker",
        ROOT / "worker" / "build" / "ida_mcp_worker",
    ])


DEFAULT_SERVER = default_server()
DEFAULT_WORKER = default_worker()
DEFAULT_OUTPUT = Path(
    os.environ.get(
        "IDA_HIVE_BATCH_OUTPUT",
        str(Path(tempfile.gettempdir()) / "ida_hive_batch_test"),
    )
)

def send_jsonl(proc, obj):
    """Send a JSON object as one line."""
    line = json.dumps(obj) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()

def read_jsonl(proc, timeout=300):
    """Read one JSON line from stdout."""
    line = proc.stdout.readline()
    if not line:
        return None
    return json.loads(line.strip())

def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="Raw binaries to convert (validated on PE and ELF)")
    parser.add_argument("--server", default=os.environ.get("IDA_HIVE_SERVER_EXE", str(DEFAULT_SERVER)))
    parser.add_argument("--worker", default=os.environ.get("IDA_HIVE_WORKER_EXE", str(DEFAULT_WORKER)))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=120, help="Per-file analysis timeout in seconds")
    parser.add_argument(
        "--ida-path",
        default=os.environ.get("IDA_HIVE_IDA_PATH"),
        help="IDA install directory to prepend to PATH on Windows or LD_LIBRARY_PATH on Linux",
    )
    return parser.parse_args()


def prepend_runtime_path(env, ida_path):
    if not ida_path:
        return
    if platform.system() == "Windows":
        env["PATH"] = f"{ida_path}{os.pathsep}{env.get('PATH', '')}"
    else:
        env["LD_LIBRARY_PATH"] = f"{ida_path}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}"


def main():
    args = parse_args()
    server_path = Path(args.server)
    worker_path = Path(args.worker)

    if not server_path.exists():
        raise SystemExit(f"Server not found: {server_path}")
    if not worker_path.exists():
        raise SystemExit(f"Worker not found: {worker_path}")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for child in output_dir.iterdir():
        if child.is_file():
            child.unlink()

    print(f"Server:  {args.server}")
    print(f"Worker:  {args.worker}")
    print(f"Output:  {output_dir}")
    print(f"Inputs:  {len(args.paths)}")
    print()

    env = os.environ.copy()
    env["IDA_MCP_WORKER_EXE"] = str(worker_path)
    env["IDA_MCP_MAX_SLOTS"] = "10"
    prepend_runtime_path(env, args.ida_path)

    proc = subprocess.Popen(
        [str(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        env=env,
        text=True,
        bufsize=1,  # line-buffered
        encoding="utf-8",
        errors="replace",
    )

    try:
        # 1. Initialize
        print("[1] initialize...")
        send_jsonl(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test_batch", "version": "0.1"}
            }
        })

        resp = read_jsonl(proc)
        if resp and "result" in resp:
            info = resp["result"].get("serverInfo", {})
            print(f"    Server: {info.get('name')} v{info.get('version')}")
        else:
            print(f"    ERROR: {resp}")
            return

        # 2. Initialized notification (no id, no response expected)
        send_jsonl(proc, {
            "jsonrpc": "2.0", "method": "notifications/initialized"
        })
        time.sleep(0.3)

        # 3. batch_convert
        print(f"\n[2] batch_convert: {len(args.paths)} inputs, concurrency={args.concurrency}")
        t0 = time.time()

        send_jsonl(proc, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "batch_convert",
                "arguments": {
                    "paths": args.paths,
                    "output_dir": str(output_dir),
                    "concurrency": args.concurrency,
                    "max_analysis_seconds": args.timeout,
                }
            }
        })

        resp = read_jsonl(proc)
        elapsed = time.time() - t0

        print(f"\n[3] Response in {elapsed:.1f}s")

        if resp and "result" in resp:
            content = resp["result"].get("content", [])
            if content:
                text = content[0].get("text", "")
                result = json.loads(text)
                print(f"    Total:     {result.get('total')}")
                print(f"    Completed: {result.get('completed')}")
                print(f"    Failed:    {result.get('failed')}")
                print(f"    Functions: {result.get('total_functions')}")
                print()
                for r in result.get("results", []):
                    status = "OK" if r.get("error") is None else f"ERR: {r['error']}"
                    name = os.path.basename(r["source"])
                    funcs = "?" if r.get("functions") is None else str(r["functions"])
                    t = r.get("elapsed", 0)
                    i64 = os.path.basename(r.get("i64_path", "")) if r.get("i64_path") else "-"
                    print(f"    {name:30s} -> {i64:35s} funcs={funcs:>6}  {t:6.1f}s  {status}")
            else:
                print(f"    Raw: {json.dumps(resp, indent=2)}")
        else:
            print(f"    Error: {json.dumps(resp, indent=2)}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except:
            proc.kill()

    # 4. Verify output files
    print(f"\n[4] Output files:")
    total_size = 0
    for f in sorted(output_dir.iterdir()):
        if not f.is_file():
            continue
        size = f.stat().st_size
        total_size += size
        print(f"    {f.name:40s} {size/1024/1024:6.1f} MB")
    print(f"    {'TOTAL':40s} {total_size/1024/1024:6.1f} MB")

    print("\nDone!")

if __name__ == "__main__":
    main()
