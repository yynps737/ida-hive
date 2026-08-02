#!/usr/bin/env python3
"""Scale test: worker behaviour on a large binary.

Small inputs hide the failures that matter in production. A handler that walks the
whole function table is instant on 500 functions and unusable on 40,000; a response
that is 60 KB on a utility is 60 MB on a library, and the process on the other end
has to hold all of it. This measures the shape of that growth.

Checks, against a binary with tens of thousands of functions:
  * table-walking handlers stay bounded in time, response size and memory
  * paging covers every item exactly once, with no gaps or repeats
  * the heaviest single-function operations complete on the largest function

The target defaults to the biggest shared library the system happens to have, since
the point is scale rather than any particular binary.

Usage:
  python3 tests/scale_worker.py [--worker PATH] [--target BINARY] [--min-funcs N]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Analysis of a large binary is measured in minutes, not seconds.
OPEN_TIMEOUT = 900
CALL_TIMEOUT = 240

SEARCH_DIRS = ["/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib"]


def pick_target(min_bytes):
    """The largest shared object available, which is the closest thing to a
    reproducible 'big binary' across machines."""
    best = None
    for d in SEARCH_DIRS:
        p = Path(d)
        if not p.is_dir():
            continue
        for f in p.glob("*.so*"):
            try:
                size = f.stat().st_size
            except OSError:
                continue
            if size >= min_bytes and (best is None or size > best[1]):
                best = (f, size)
    return best


def rss_mb(pid):
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) // 1024
    except OSError:
        pass
    return -1


class Worker:
    def __init__(self, worker, target, db_dir, ida_path):
        env = os.environ.copy()
        if ida_path:
            env["LD_LIBRARY_PATH"] = f"{ida_path}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}"
        self.proc = subprocess.Popen(
            [str(worker), str(target), str(db_dir)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, text=True, bufsize=1, encoding="utf-8", errors="replace",
        )
        self.next_id = 0
        self.ready = None
        deadline = time.time() + OPEN_TIMEOUT
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("worker exited before ready")
            msg = json.loads(line)
            if msg.get("event") == "ready":
                self.ready = msg["data"]
                return
            if msg.get("event") == "init_error":
                raise RuntimeError(f"init failed: {msg.get('data')}")
        raise RuntimeError(f"analysis did not finish within {OPEN_TIMEOUT}s")

    def call(self, method, params, timeout=CALL_TIMEOUT):
        self.next_id += 1
        rid = self.next_id
        self.proc.stdin.write(json.dumps({"id": rid, "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        started = time.time()
        deadline = started + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                return None, time.time() - started
            msg = json.loads(line)
            if msg.get("event"):
                continue
            if msg.get("id") == rid:
                return msg, time.time() - started
        return "TIMEOUT", timeout

    @property
    def pid(self):
        return self.proc.pid

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


# Handlers that walk a whole table. Each is asked for far more than it should
# return, so the clamp is what keeps the response finite.
SWEEPS = [
    ("list_funcs", {"limit": 10 ** 6}),
    ("function_origins", {"kind": "all", "limit": 10 ** 6}),
    ("entity_query", {"kind": "functions", "limit": 10 ** 6}),
    ("strings", {"limit": 10 ** 6}),
    ("imports", {"limit": 10 ** 6}),
    ("list_globals", {"limit": 10 ** 6}),
    ("problems", {"limit": 10 ** 6}),
    ("fixups", {"limit": 10 ** 6}),
    ("survey_binary", {}),
    ("list_segments", {}),
]

# A response big enough to matter to whoever has to parse it.
MAX_RESPONSE_MB = 24.0
MAX_SWEEP_SECONDS = 60.0


def run(worker_path, target, ida_path, failures, tmp):
    started = time.time()
    w = Worker(worker_path, target, tmp, ida_path)
    analysis = time.time() - started
    total_funcs = w.ready.get("functions", 0)
    baseline = rss_mb(w.pid)

    print(f"  target: {Path(target).name}  {Path(target).stat().st_size / 2**20:.0f} MiB")
    print(f"  analysis: {analysis:.0f}s, {total_funcs} functions, RSS {baseline} MiB")

    # 1. Table sweeps stay bounded.
    for method, params in SWEEPS:
        reply, elapsed = w.call(method, params)
        if reply == "TIMEOUT":
            failures.append(f"{method}: no reply within {elapsed:.0f}s at {total_funcs} functions")
            continue
        if reply is None:
            failures.append(f"{method}: worker died")
            return
        size_mb = len(json.dumps(reply)) / 2 ** 20
        print(f"    {method:20} {elapsed:6.1f}s  {size_mb:6.2f} MiB  RSS {rss_mb(w.pid)} MiB")
        if elapsed > MAX_SWEEP_SECONDS:
            failures.append(f"{method}: took {elapsed:.0f}s (budget {MAX_SWEEP_SECONDS:.0f}s)")
        if size_mb > MAX_RESPONSE_MB:
            failures.append(f"{method}: returned {size_mb:.0f} MiB (budget {MAX_RESPONSE_MB:.0f} MiB) "
                            f"— the limit clamp is not holding")

    after_sweeps = rss_mb(w.pid)
    if after_sweeps > baseline + 400:
        failures.append(f"sweeps grew RSS {baseline} -> {after_sweeps} MiB")

    # 2. Paging covers everything exactly once.
    page = 5000
    seen = set()
    offset = 0
    while offset < total_funcs:
        reply, _ = w.call("list_funcs", {"limit": page, "offset": offset})
        if reply in (None, "TIMEOUT"):
            failures.append(f"paging: no reply at offset {offset}")
            break
        funcs = reply.get("result", {}).get("functions", [])
        if not funcs:
            break
        before = len(seen)
        seen.update(f["ea"] for f in funcs)
        if len(seen) - before != len(funcs):
            failures.append(f"paging: offset {offset} repeated {len(funcs) - (len(seen) - before)} entries")
        offset += page
    print(f"    paging              {len(seen)}/{total_funcs} functions covered")
    if len(seen) != total_funcs:
        failures.append(f"paging: covered {len(seen)} of {total_funcs} functions")

    # 3. The heaviest single-function work, on the largest function present.
    reply, _ = w.call("list_funcs", {"limit": 10000})
    funcs = reply.get("result", {}).get("functions", []) if reply not in (None, "TIMEOUT") else []
    if funcs:
        biggest = max(funcs, key=lambda f: f.get("size", 0))
        ea = biggest["ea"]
        print(f"    largest function    {ea} ({biggest.get('size', 0)} bytes)")
        for method, params in [
            ("decompile", {"ea": ea}),
            ("microcode", {"ea": ea, "limit": 10 ** 6}),
            ("microcode", {"ea": ea, "maturity": "generated", "limit": 10 ** 6}),
            ("analyze_function", {"ea": ea}),
        ]:
            reply, elapsed = w.call(method, params)
            if reply == "TIMEOUT":
                failures.append(f"{method} on the largest function: no reply within {elapsed:.0f}s")
            elif reply is None:
                failures.append(f"{method} on the largest function: worker died")
                return
            else:
                size_mb = len(json.dumps(reply)) / 2 ** 20
                note = ""
                if "error" in reply:
                    msg = reply["error"]["message"]
                    note = f"  refused: {msg[:60]}"
                    # Hex-Rays refuses functions past its own size ceiling. That is a
                    # documented product limit, so it counts as a clean refusal —
                    # but anything else at this size is a real failure.
                    if "too big" not in msg.lower():
                        failures.append(f"{method} on the largest function failed: {msg[:80]}")
                print(f"    {method:20} {elapsed:6.1f}s  {size_mb:6.2f} MiB{note}")
                if size_mb > MAX_RESPONSE_MB:
                    failures.append(f"{method}: {size_mb:.0f} MiB response on one function")

    final = rss_mb(w.pid)
    print(f"  final RSS {final} MiB (baseline {baseline})")
    w.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worker", default=str(ROOT / "worker" / "build-linux" / "ida_mcp_worker"))
    ap.add_argument("--target")
    ap.add_argument("--ida", default=os.environ.get("IDABIN"))
    ap.add_argument("--min-size", type=int, default=20 * 2 ** 20,
                    help="smallest acceptable auto-picked target, in bytes")
    args = ap.parse_args()

    if not Path(args.worker).exists():
        raise SystemExit(f"worker not found: {args.worker}")

    target = args.target
    if not target:
        found = pick_target(args.min_size)
        if not found:
            print("SKIPPED: no shared library large enough to be a scale test")
            return 0
        target = str(found[0])

    failures = []
    started = time.time()
    # The database this builds is measured in gigabytes, and /tmp is a RAM disk on
    # many systems. run() returns early on several failures, so the removal has to be
    # in a finally rather than at the end of the body.
    tmp = tempfile.mkdtemp(prefix="ida-hive-scale-")
    try:
        run(args.worker, target, args.ida, failures, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    elapsed = time.time() - started

    print()
    if failures:
        print(f"FAILED: {len(failures)} problem(s) in {elapsed:.0f}s")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASSED: scale behaviour bounded, in {elapsed:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
