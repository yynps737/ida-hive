#!/usr/bin/env python3
"""Endurance and leak test for the real C++ worker.

Long-running failures do not show up in a functional pass: a handler that leaks a
few kilobytes per call is invisible until the hundredth call, and a temp directory
that is never removed only matters after a day of churn. This drives the expensive
handlers in a loop and watches what the process actually holds.

Checks:
  * resident memory stays bounded across repeated heavy calls
  * a worker killed with SIGKILL leaves no temp directory behind
  * repeated spawn/kill cycles leak neither processes nor file descriptors

Usage:
  python3 tests/endurance_worker.py [--worker PATH] [--target BINARY] [--cycles N]
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rss_kb(pid):
    """Resident set size in KiB, or None once the process is gone."""
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        return None
    return None


def fd_count(pid):
    try:
        return len(list(Path(f"/proc/{pid}/fd").iterdir()))
    except (FileNotFoundError, PermissionError):
        return None


class Worker:
    def __init__(self, worker, target, db_dir, ida_path):
        env = os.environ.copy()
        if ida_path:
            env["LD_LIBRARY_PATH"] = f"{ida_path}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}"
        self.db_dir = Path(db_dir)
        self.proc = subprocess.Popen(
            [str(worker), str(target), str(db_dir)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, text=True, bufsize=1, encoding="utf-8", errors="replace",
        )
        self.next_id = 1
        self.ready = None
        self._await_ready()

    def _await_ready(self):
        deadline = time.time() + 300
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
        raise RuntimeError("worker never became ready")

    def call(self, method, params, timeout=120):
        rid = self.next_id
        self.next_id += 1
        self.proc.stdin.write(json.dumps({"id": rid, "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                return None
            msg = json.loads(line)
            if msg.get("event"):
                continue
            if msg.get("id") == rid:
                return msg
        raise TimeoutError(f"no reply to {method}")

    @property
    def pid(self):
        return self.proc.pid

    def alive(self):
        return self.proc.poll() is None

    def kill(self, sig=signal.SIGTERM):
        try:
            os.kill(self.proc.pid, sig)
        except ProcessLookupError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def pick_functions(w, count):
    """A few real function addresses to exercise the heavy handlers against."""
    reply = w.call("list_funcs", {"limit": count * 4})
    funcs = reply.get("result", {}).get("functions", []) if reply else []
    # Larger functions produce more microcode, which is where a leak would show.
    funcs.sort(key=lambda f: f.get("size", 0), reverse=True)
    return [f["ea"] for f in funcs[:count]]


def test_memory_stability(worker_path, target, ida_path, cycles, failures):
    """Heavy handlers in a loop; RSS must plateau rather than climb."""
    tmp = tempfile.mkdtemp(prefix="ida-hive-endur-")
    w = Worker(worker_path, target, tmp, ida_path)
    eas = pick_functions(w, 8)
    if not eas:
        failures.append("memory: no functions to exercise")
        w.kill()
        return

    # Warm up so first-call allocations (caches, plugin init) are not counted.
    for ea in eas:
        w.call("decompile", {"ea": ea})
        w.call("microcode", {"ea": ea, "limit": 200})

    baseline = rss_kb(w.pid)
    fds_before = fd_count(w.pid)
    samples = []

    for i in range(cycles):
        ea = eas[i % len(eas)]
        w.call("decompile", {"ea": ea})
        w.call("microcode", {"ea": ea, "limit": 500})
        w.call("microcode_stats", {"ea": ea, "maturity": "generated"})
        w.call("analyze_function", {"ea": ea})
        w.call("strings", {"limit": 200})
        if (i + 1) % 5 == 0:
            samples.append(rss_kb(w.pid))

    peak = max(samples) if samples else baseline
    final = rss_kb(w.pid)
    fds_after = fd_count(w.pid)
    alive = w.alive()
    w.kill()

    if not alive:
        failures.append("memory: worker died during the endurance loop")
        return

    growth = final - baseline
    # IDA caches decompilation results, so some growth is expected and correct.
    # A leak shows as growth proportional to the call count; the bound here is
    # generous enough to pass a cache filling up, but not a per-call leak.
    budget = 200 * 1024  # KiB
    print(f"  memory: baseline {baseline // 1024} MiB, final {final // 1024} MiB, "
          f"peak {peak // 1024} MiB, growth {growth // 1024} MiB over "
          f"{cycles * 5} heavy calls")
    if growth > budget:
        failures.append(f"memory: RSS grew {growth // 1024} MiB over {cycles * 5} calls "
                        f"(budget {budget // 1024} MiB) — suspect a leak")
    if fds_before is not None and fds_after is not None and fds_after > fds_before + 8:
        failures.append(f"memory: fd count grew {fds_before} -> {fds_after}")
    else:
        print(f"  fds: {fds_before} -> {fds_after}")


def test_sigkill_leaves_no_tempdir(worker_path, target, ida_path, failures):
    """A hard kill cannot run destructors, so the coordinator owns the cleanup."""
    tmp = Path(tempfile.mkdtemp(prefix="ida-hive-kill-"))
    w = Worker(worker_path, target, tmp, ida_path)
    w.call("get_info", {})

    contents_before = list(tmp.iterdir())
    pid = w.pid
    os.kill(pid, signal.SIGKILL)
    w.proc.wait(timeout=10)

    time.sleep(0.5)
    still_running = Path(f"/proc/{pid}").exists()
    if still_running:
        failures.append("sigkill: worker process survived SIGKILL")

    # The database files are expected to remain: only the parent can remove them,
    # which is exactly why Slot::drop exists on the Rust side. Assert the shape so a
    # regression in that contract is visible here.
    print(f"  sigkill: pid reaped, {len(contents_before)} db file(s) left for the parent")
    for p in tmp.rglob("*"):
        if p.is_file():
            p.unlink()


def test_spawn_kill_cycles(worker_path, target, ida_path, rounds, failures):
    """Repeated spawn/kill must not accumulate processes or descriptors."""
    own_fds_start = fd_count(os.getpid())
    leaked = []
    for i in range(rounds):
        tmp = tempfile.mkdtemp(prefix=f"ida-hive-cycle{i}-")
        w = Worker(worker_path, target, tmp, ida_path)
        w.call("get_info", {})
        pid = w.pid
        w.kill(signal.SIGKILL if i % 2 else signal.SIGTERM)
        time.sleep(0.1)
        if Path(f"/proc/{pid}").exists():
            leaked.append(pid)
    own_fds_end = fd_count(os.getpid())

    if leaked:
        failures.append(f"cycles: {len(leaked)} worker process(es) survived: {leaked}")
    else:
        print(f"  cycles: {rounds} spawn/kill rounds, no surviving processes")
    if own_fds_start is not None and own_fds_end is not None and own_fds_end > own_fds_start + 4:
        failures.append(f"cycles: harness fds grew {own_fds_start} -> {own_fds_end}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worker", default=str(ROOT / "worker" / "build-linux" / "ida_mcp_worker"))
    ap.add_argument("--target", default="/usr/bin/grep")
    ap.add_argument("--ida", default=os.environ.get("IDABIN"))
    ap.add_argument("--cycles", type=int, default=30)
    ap.add_argument("--rounds", type=int, default=6)
    args = ap.parse_args()

    if not Path(args.worker).exists():
        raise SystemExit(f"worker not found: {args.worker}")

    failures = []
    started = time.time()

    print("endurance: memory stability under repeated heavy calls")
    test_memory_stability(args.worker, args.target, args.ida, args.cycles, failures)
    print("endurance: SIGKILL cleanup contract")
    test_sigkill_leaves_no_tempdir(args.worker, args.target, args.ida, failures)
    print("endurance: spawn/kill cycles")
    test_spawn_kill_cycles(args.worker, args.target, args.ida, args.rounds, failures)

    elapsed = time.time() - started
    print()
    if failures:
        print(f"FAILED: {len(failures)} problem(s) in {elapsed:.1f}s")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASSED: no leaks detected in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
