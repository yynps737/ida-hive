#!/usr/bin/env python3
"""Adversarial stress test for the C++ worker.

Drives every registered command with hostile input and asserts the worker survives:
a handler may fail, but it must fail as a well-formed error reply on the same
connection, never by crashing, hanging, or corrupting the stream.

The command list is read from the sources, so a new command is covered the moment it
is registered — there is no second list to keep in sync.

Usage:
  python3 tests/stress_worker.py [--worker PATH] [--target BINARY] [--ida PATH]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Destructive or flow-control commands are exercised, but not with arguments that
# would end the session or rewrite the input file underneath the rest of the run.
SKIP_ENTIRELY = {"shutdown"}
NO_MUTATE = {"save_idb", "patch_bytes", "put_int", "apply_signature"}

# wait_analysis blocks for max_seconds, defaulting to 300. The worker is
# single-threaded, so leaving that unbounded would stall every later request behind
# one call. The bound is forced down rather than the command skipped.
BOUNDED = {"wait_analysis": {"max_seconds": 1}}


def discover_commands():
    """Command names, taken from the registration tables in the worker sources."""
    names = set()
    table = re.compile(r'\{\s*"([a-z_]+)"\s*,\s+cmd_[a-z_]+\s*\}')
    for path in (ROOT / "worker" / "src" / "commands").glob("cmd_*.cpp"):
        names.update(table.findall(path.read_text()))
    inline = re.compile(r'register_command\("([a-z_]+)"')
    names.update(inline.findall((ROOT / "worker" / "src" / "main.cpp").read_text()))
    return sorted(names - SKIP_ENTIRELY)


# Each entry is one hostile parameter object applied to every command. A handler that
# ignores a key is fine; what matters is that none of these take the worker down.
HOSTILE_PARAMS = [
    ("empty", {}),
    ("null_ea", {"ea": None}),
    ("bad_ea_string", {"ea": "not-an-address"}),
    ("unmapped_ea", {"ea": "0xDEADBEEFCAFE"}),
    ("badaddr", {"ea": "0xFFFFFFFFFFFFFFFF"}),
    ("zero_ea", {"ea": "0x0"}),
    ("negative_ea", {"ea": -1}),
    ("float_ea", {"ea": 3.5}),
    ("array_ea", {"ea": ["0x1000"]}),
    ("object_ea", {"ea": {"nested": 1}}),
    ("huge_limit", {"ea": "0x0", "limit": 10 ** 9}),
    ("negative_limit", {"ea": "0x0", "limit": -5}),
    ("huge_size", {"ea": "0x0", "size": 10 ** 9}),
    ("empty_strings", {"ea": "0x0", "name": "", "type": "", "reg": "",
                       "query": "", "image": "", "flag": "", "comment": ""}),
    ("long_string", {"ea": "0x0", "name": "A" * 8192, "query": "A" * 8192,
                     "type": "A" * 8192, "image": "A" * 8192}),
    ("unicode", {"ea": "0x0", "name": "\u540d\u524d \uffff",
                 "query": "\U0001f525" * 64, "comment": "\u30b3\u30e1\u30f3\u30c8"}),
    ("format_specifiers", {"ea": "0x0", "name": "%s%n%x%p", "comment": "%s%n",
                           "query": "%s%n", "filter": "%s%n"}),
    ("path_traversal", {"ea": "0x0", "output_path": "../../../etc/passwd",
                        "name": "../../x", "image": "../../x"}),
    ("deep_nesting", {"ea": "0x0", "addresses": [{"a": [{"b": [1]}]}]}),
    ("wrong_types", {"ea": True, "limit": "many", "size": [], "reg": 42,
                     "on": "yes", "operand": "first"}),
    ("all_at_once", {"ea": "0x0", "start": "0x0", "end": "0x0", "limit": 0,
                     "offset": 10 ** 9, "size": 0, "min_length": 0,
                     "depth": 10 ** 6, "max_seconds": 0, "concurrency": 0}),
]


class Worker:
    """One worker process, spoken to over its JSON Lines protocol."""

    def __init__(self, worker, target, db_dir, ida_path):
        env = os.environ.copy()
        if ida_path:
            env["LD_LIBRARY_PATH"] = f"{ida_path}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}"
        self.proc = subprocess.Popen(
            [str(worker), str(target), str(db_dir)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, text=True, bufsize=1, encoding="utf-8", errors="replace",
        )
        self.next_id = 1
        self._await_ready()

    def _await_ready(self):
        deadline = time.time() + 300
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("worker exited before becoming ready")
            msg = json.loads(line)
            if msg.get("event") == "ready":
                return
            if msg.get("event") == "init_error":
                raise RuntimeError(f"worker init failed: {msg.get('data')}")
        raise RuntimeError("worker did not become ready within 300s")

    def send_raw(self, text):
        self.proc.stdin.write(text)
        self.proc.stdin.flush()

    def call(self, method, params, timeout=20):
        rid = self.next_id
        self.next_id += 1
        self.send_raw(json.dumps({"id": rid, "method": method, "params": params}) + "\n")
        return self._read_reply(rid, timeout)

    def _read_reply(self, rid, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                return None
            msg = json.loads(line)
            if msg.get("event"):          # progress events interleave with replies
                continue
            if msg.get("id") == rid:
                return msg
        raise TimeoutError(f"no reply to id={rid} within {timeout}s")

    def alive(self):
        return self.proc.poll() is None

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def check_reply(reply, ctx, failures):
    """A reply must exist, be well formed, and be exactly one of result or error."""
    if reply is None:
        failures.append(f"{ctx}: no reply (stream closed)")
        return
    has_result = "result" in reply
    has_error = "error" in reply
    if has_result == has_error:
        failures.append(f"{ctx}: reply has neither or both of result/error: {reply}")
    if has_error:
        err = reply["error"]
        if not isinstance(err, dict) or "message" not in err:
            failures.append(f"{ctx}: malformed error object: {err}")
        elif not str(err["message"]).strip():
            failures.append(f"{ctx}: empty error message")


def run(worker_path, target, ida_path):
    commands = discover_commands()
    print(f"stress: {len(commands)} commands x {len(HOSTILE_PARAMS)} payloads "
          f"= {len(commands) * len(HOSTILE_PARAMS)} calls")

    failures = []
    tmp = tempfile.mkdtemp(prefix="ida-hive-stress-")
    try:
        return _run(worker_path, target, ida_path, tmp, failures, commands)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run(worker_path, target, ida_path, tmp, failures, commands):
    w = Worker(worker_path, target, tmp, ida_path)

    # 1. Every command against every hostile payload.
    calls = 0
    for name in commands:
        for label, params in HOSTILE_PARAMS:
            if name in NO_MUTATE and label in ("path_traversal", "all_at_once"):
                continue
            ctx = f"{name}/{label}"
            payload = dict(params)
            payload.update(BOUNDED.get(name, {}))
            try:
                check_reply(w.call(name, payload), ctx, failures)
            except TimeoutError as exc:
                failures.append(f"{ctx}: {exc}")
            except json.JSONDecodeError as exc:
                failures.append(f"{ctx}: worker emitted invalid JSON: {exc}")
            calls += 1
            if not w.alive():
                failures.append(f"{ctx}: WORKER DIED")
                print(f"  worker died at {ctx}; aborting")
                return failures, calls
    print(f"  {calls} hostile calls survived")

    # 2. Protocol-level abuse on the same connection.
    protocol_junk = [
        "not json at all\n",
        "{unterminated\n",
        "[]\n",
        "null\n",
        '{"id":"string-id","method":"ping","params":{}}\n',
        '{"method":"ping"}\n',                       # no id
        '{"id":9001}\n',                             # no method
        '{"id":9002,"method":"","params":{}}\n',     # empty method
        '{"id":9003,"method":"no_such_command_xyz","params":{}}\n',
        "\n\n\n",                                    # blank lines
        '{"id":9004,"method":"ping","params":' + "[" * 200 + "]" * 200 + "}\n",
    ]
    for junk in protocol_junk:
        w.send_raw(junk)
    time.sleep(0.5)
    if not w.alive():
        failures.append("worker died on malformed protocol input")
        return failures, calls

    # The connection must still serve a normal request afterwards.
    try:
        reply = w.call("ping", {}, timeout=30)
        if reply is None or reply.get("result", {}).get("pong") is not True:
            failures.append(f"ping broken after protocol abuse: {reply}")
        else:
            print("  protocol abuse survived; connection still usable")
    except Exception as exc:
        failures.append(f"ping failed after protocol abuse: {exc}")

    # 3. Sustained load on one worker, checking replies stay matched to requests.
    burst = 400
    for i in range(burst):
        w.send_raw(json.dumps({"id": 20000 + i, "method": "get_info", "params": {}}) + "\n")
    seen = set()
    deadline = time.time() + 120
    while len(seen) < burst and time.time() < deadline:
        line = w.proc.stdout.readline()
        if not line:
            break
        msg = json.loads(line)
        if msg.get("event"):
            continue
        rid = msg.get("id")
        if isinstance(rid, int) and 20000 <= rid < 20000 + burst:
            if rid in seen:
                failures.append(f"duplicate reply for id={rid}")
            seen.add(rid)
    if len(seen) != burst:
        failures.append(f"pipelined burst: got {len(seen)}/{burst} replies")
    else:
        print(f"  {burst} pipelined requests all answered exactly once")

    if not w.alive():
        failures.append("worker died under sustained load")
    w.close()
    return failures, calls


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worker", default=str(ROOT / "worker" / "build-linux" / "ida_mcp_worker"))
    ap.add_argument("--target", default="/usr/bin/grep")
    ap.add_argument("--ida", default=os.environ.get("IDABIN"))
    args = ap.parse_args()

    if not Path(args.worker).exists():
        raise SystemExit(f"worker not found: {args.worker}")
    if not Path(args.target).exists():
        raise SystemExit(f"target not found: {args.target}")

    started = time.time()
    failures, calls = run(args.worker, args.target, args.ida)
    elapsed = time.time() - started

    print()
    if failures:
        print(f"FAILED: {len(failures)} problem(s) over {calls} calls in {elapsed:.1f}s")
        for f in failures[:40]:
            print(f"  - {f}")
        if len(failures) > 40:
            print(f"  ... and {len(failures) - 40} more")
        return 1
    print(f"PASSED: {calls} hostile calls, no crash, in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
