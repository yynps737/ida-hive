#!/usr/bin/env python3
"""Cross-platform MCP smoke test for ida-hive.

Usage:
  python test_smoke.py /path/to/binary

Environment overrides:
  IDA_HIVE_SERVER_EXE
  IDA_HIVE_WORKER_EXE
  IDA_HIVE_IDA_PATH
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def pick_existing(candidates):
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def default_server():
    if platform.system() == "Windows":
        return pick_existing([
            ROOT / "target" / "x86_64-pc-windows-msvc" / "release" / "ida-hive.exe",
        ])
    return pick_existing([
        ROOT / "target" / "release" / "ida-hive",
    ])


def default_worker():
    if platform.system() == "Windows":
        return pick_existing([
            ROOT / "worker" / "build" / "Release" / "ida_mcp_worker.exe",
            ROOT / "worker" / "build" / "ida_mcp_worker.exe",
        ])
    return pick_existing([
        ROOT / "worker" / "build-linux" / "ida_mcp_worker",
        ROOT / "worker" / "build" / "ida_mcp_worker",
    ])


def prepend_runtime_path(env, ida_path):
    if not ida_path:
        return
    if platform.system() == "Windows":
        env["PATH"] = f"{ida_path}{os.pathsep}{env.get('PATH', '')}"
    else:
        env["LD_LIBRARY_PATH"] = f"{ida_path}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Path to a raw binary or existing .i64/.idb")
    parser.add_argument("--server", default=os.environ.get("IDA_HIVE_SERVER_EXE", str(default_server())))
    parser.add_argument("--worker", default=os.environ.get("IDA_HIVE_WORKER_EXE", str(default_worker())))
    parser.add_argument(
        "--ida-path",
        default=os.environ.get("IDA_HIVE_IDA_PATH"),
        help="IDA install directory to prepend to PATH on Windows or LD_LIBRARY_PATH on Linux",
    )
    parser.add_argument("--timeout", type=int, default=60, help="Analysis timeout in seconds for raw binaries")
    parser.add_argument("--session", default="smoke", help="Session identifier")
    parser.add_argument("--skip-batch", action="store_true", help="Skip batch_convert validation")
    parser.add_argument("--skip-decompile", action="store_true", help="Skip best-effort decompile validation")
    return parser.parse_args()


def parse_tool_text(response):
    if response is None:
        raise RuntimeError("No response received from server")
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"Malformed MCP response: {response}")
    if result.get("isError"):
        raise RuntimeError(json.dumps(response, ensure_ascii=True))
    content = result.get("content", [])
    if not content:
        return None
    text = content[0].get("text", "")
    return json.loads(text) if text else None


def send(proc, obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def recv(proc):
    line = proc.stdout.readline()
    return json.loads(line) if line else None


def call_tool(proc, req_id, name, arguments):
    send(
        proc,
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            },
        },
    )
    return recv(proc)


def main():
    args = parse_args()
    server_path = Path(args.server)
    worker_path = Path(args.worker)
    binary_path = Path(args.path)

    if not server_path.exists():
        raise SystemExit(f"Server not found: {server_path}")
    if not worker_path.exists():
        raise SystemExit(f"Worker not found: {worker_path}")
    if not binary_path.exists():
        raise SystemExit(f"Target binary not found: {binary_path}")

    env = os.environ.copy()
    env["IDA_MCP_WORKER_EXE"] = str(worker_path)
    env["IDA_MCP_MAX_SLOTS"] = "4"
    prepend_runtime_path(env, args.ida_path)

    proc = subprocess.Popen(
        [str(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="replace",
    )

    try:
        send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test_smoke", "version": "0.1"},
                },
            },
        )
        init_resp = recv(proc)
        if init_resp is None or "result" not in init_resp:
            raise RuntimeError(f"Initialize failed: {init_resp}")

        send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        opened = parse_tool_text(
            call_tool(proc, 2, "open_file", {"path": str(binary_path), "session": args.session})
        )
        is_database = binary_path.suffix.lower() in {".i64", ".idb"}

        waited = None
        if not is_database:
            waited = parse_tool_text(
                call_tool(
                    proc,
                    3,
                    "wait_analysis",
                    {"session": args.session, "max_seconds": args.timeout},
                )
            )
            if not waited.get("done"):
                raise RuntimeError(f"Analysis did not finish: {waited}")

        info = parse_tool_text(call_tool(proc, 4, "get_info", {"session": args.session}))
        funcs = parse_tool_text(call_tool(proc, 5, "list_funcs", {"session": args.session, "limit": 5}))
        function_list = funcs.get("functions", [])
        if not function_list:
            raise RuntimeError("No functions returned by list_funcs")

        first_func = function_list[0]
        first_ea = first_func["ea"]

        lookup = parse_tool_text(
            call_tool(proc, 6, "lookup_func", {"session": args.session, "target": first_ea})
        )
        disasm = parse_tool_text(
            call_tool(proc, 7, "disasm", {"session": args.session, "ea": first_ea, "count": 5})
        )
        survey = parse_tool_text(call_tool(proc, 8, "survey_binary", {"session": args.session}))
        health = parse_tool_text(call_tool(proc, 9, "server_health", {}))

        decompile_error = None
        if not args.skip_decompile:
            decompile_resp = call_tool(proc, 10, "decompile", {"session": args.session, "ea": first_ea})
            try:
                parse_tool_text(decompile_resp)
            except RuntimeError as exc:
                decompile_error = str(exc)

        batch = None
        if not args.skip_batch and not is_database:
            out_dir = Path(tempfile.mkdtemp(prefix="ida-hive-smoke-"))
            batch = parse_tool_text(
                call_tool(
                    proc,
                    11,
                    "batch_convert",
                    {
                        "paths": [str(binary_path)],
                        "output_dir": str(out_dir),
                        "concurrency": 1,
                        "max_analysis_seconds": args.timeout,
                    },
                )
            )
            if batch.get("failed") != 0:
                raise RuntimeError(f"batch_convert failed: {batch}")

        closed = parse_tool_text(call_tool(proc, 12, "close_session", {"session": args.session}))

        print("SMOKE_OK")
        print(f"Target:      {binary_path}")
        print(f"Server:      {server_path}")
        print(f"Worker:      {worker_path}")
        print(f"Session:     {args.session}")
        print(f"Opened:      {opened}")
        print(f"Waited:      {waited}")
        print(f"Info:        processor={info.get('processor')} bits={info.get('bits')} funcs={info.get('func_count')}")
        print(f"First func:  {lookup.get('name')} @ {lookup.get('ea')}")
        print(f"Disasm:      {len(disasm.get('lines', []))} lines")
        print(f"Survey:      functions={survey.get('function_count')} segments={len(survey.get('segments', []))}")
        print(f"Health:      total_slots={health.get('total_slots')} alive_slots={health.get('alive_slots')}")
        print(f"Batch:       {batch}")
        print(f"Closed:      {closed}")
        if decompile_error:
            print(f"Decompile:   warning: {decompile_error}")
        else:
            print("Decompile:   ok")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

        stderr = proc.stderr.read()
        if stderr:
            print("\n[server stderr tail]")
            print(stderr[-1200:])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"SMOKE_FAIL: {exc}", file=sys.stderr)
        raise
