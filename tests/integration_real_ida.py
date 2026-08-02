#!/usr/bin/env python3
"""End-to-end test: the real coordinator driving real IDA workers.

Every other coordinator test substitutes a mock for the C++ worker, which makes them
fast and license-free but hides everything that only real IDA does: it takes seconds
to start, holds hundreds of megabytes, and holds a lock on its database. Those are
the properties that decide whether the pool survives production, so they need a pass
of their own.

Checks, with real idalib workers:
  * several binaries analyse concurrently, and each reply reaches its own session
  * one binary opened from many sessions still costs exactly one worker and one
    process, with the shared database visible to all of them
  * max_slots holds when the workers are real and slow to start
  * closing releases the process, the memory and the temp directory

Needs an activated IDA. Skips cleanly when one is not present.

Usage:
  python3 tests/integration_real_ida.py [--server PATH] [--worker PATH] [--ida PATH]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Real analysis is slow; these bound the wait rather than describe it.
OPEN_TIMEOUT = 300
CALL_TIMEOUT = 120


def small_binaries(count):
    """Distinct, genuinely small ELF files, so analysis stays in seconds."""
    found = []
    for d in ("/usr/bin", "/bin"):
        p = Path(d)
        if not p.is_dir():
            continue
        for f in sorted(p.iterdir()):
            try:
                if not f.is_file() or f.is_symlink():
                    continue
                size = f.stat().st_size
            except OSError:
                continue
            if 20_000 <= size <= 200_000 and os.access(f, os.X_OK):
                found.append(f)
            if len(found) >= count:
                return found
    return found


class Client:
    """Minimal MCP stdio client, with replies matched by request id."""

    def __init__(self, server, worker, ida_path, **env_overrides):
        env = os.environ.copy()
        env["IDA_MCP_WORKER_EXE"] = str(worker)
        env.setdefault("RUST_LOG", "warn")
        if ida_path:
            env["LD_LIBRARY_PATH"] = f"{ida_path}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}"
        for k, v in env_overrides.items():
            env[k] = str(v)

        self.proc = subprocess.Popen(
            [str(server)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1,
            encoding="utf-8", errors="replace",
        )
        self._id = 0
        self._id_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._replies = {}
        self._cv = threading.Condition()
        threading.Thread(target=self._reader, daemon=True).start()
        self._initialize()

    def _reader(self):
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" not in msg:
                continue
            with self._cv:
                self._replies[msg["id"]] = msg
                self._cv.notify_all()

    def _send(self, obj):
        with self._write_lock:
            self.proc.stdin.write(json.dumps(obj) + "\n")
            self.proc.stdin.flush()

    def _rpc(self, method, params, timeout):
        with self._id_lock:
            self._id += 1
            rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.time() + timeout
        with self._cv:
            while rid not in self._replies:
                if not self._cv.wait(timeout=max(0.1, deadline - time.time())):
                    if time.time() > deadline:
                        raise TimeoutError(f"{method} timed out after {timeout}s")
            return self._replies.pop(rid)

    def _initialize(self):
        self._rpc("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "integration", "version": "1"},
        }, 30)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, tool, timeout=CALL_TIMEOUT, **args):
        """Returns the tool's parsed payload, or {'error': msg} on failure."""
        reply = self._rpc("tools/call", {"name": tool, "arguments": args}, timeout)
        result = reply.get("result")
        if not isinstance(result, dict):
            return {"error": json.dumps(reply)[:200]}
        if result.get("isError"):
            return {"error": json.dumps(result)[:300]}
        content = result.get("content", [])
        if not content:
            return {}
        text = content[0].get("text", "")
        try:
            return json.loads(text) if text else {}
        except json.JSONDecodeError:
            return {"raw": text}

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=15)
        except Exception:
            self.proc.kill()


def worker_pids(parent_pid=None, worker_name="ida_mcp_worker"):
    """Live worker processes, optionally only those spawned by one coordinator.

    Matching on the name alone would also count workers left by other phases of a
    test run, so a parent is required whenever the answer is asserted on.
    """
    pids = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
            if worker_name.encode() not in cmdline:
                continue
            if parent_pid is not None:
                status = (entry / "status").read_text()
                ppid = next(int(l.split()[1]) for l in status.splitlines()
                            if l.startswith("PPid:"))
                if ppid != parent_pid:
                    continue
        except (OSError, StopIteration):
            continue
        pids.append(int(entry.name))
    return pids


def err(reply):
    return reply.get("error") if isinstance(reply, dict) else None


def check(cond, msg, failures):
    if not cond:
        failures.append(msg)
    return cond


def test_concurrent_distinct_binaries(server, worker, ida, binaries, failures):
    """Several real workers at once, each reply routed to its own session."""
    started = time.time()
    c = Client(server, worker, ida, IDA_MCP_MAX_SLOTS=8)
    try:
        def opener(item):
            i, path = item
            return i, c.call("open_file", timeout=OPEN_TIMEOUT, path=str(path), session=f"r{i}")

        with ThreadPoolExecutor(max_workers=len(binaries)) as pool:
            results = dict(pool.map(opener, enumerate(binaries)))

        bad = {i: r for i, r in results.items() if err(r)}
        if not check(not bad, f"concurrent opens failed: {bad}", failures):
            return
        print(f"    opened {len(binaries)} real workers concurrently in {time.time() - started:.0f}s")

        # Each session must still see its own binary.
        def verify(i):
            info = c.call("get_info", session=f"r{i}")
            return not err(info)

        with ThreadPoolExecutor(max_workers=len(binaries)) as pool:
            oks = list(pool.map(verify, range(len(binaries))))
        check(all(oks), f"routing broke: {oks.count(False)} of {len(oks)} wrong", failures)

        live = worker_pids(c.proc.pid)
        check(len(live) == len(binaries),
              f"expected {len(binaries)} worker processes, found {len(live)}", failures)
        print(f"    {len(live)} live worker processes, one per binary")
        coord_pid = c.proc.pid
    finally:
        c.close()
    time.sleep(1.0)
    leftover = worker_pids(coord_pid)
    check(not leftover, f"workers outlived the coordinator: {leftover}", failures)


def test_shared_binary_one_process(server, worker, ida, binary, failures):
    """One binary from many sessions: one worker, one process, shared database."""
    c = Client(server, worker, ida, IDA_MCP_MAX_SLOTS=8)
    try:
        sessions = [f"sh{i}" for i in range(5)]
        with ThreadPoolExecutor(max_workers=len(sessions)) as pool:
            opens = list(pool.map(
                lambda s: c.call("open_file", timeout=OPEN_TIMEOUT, path=str(binary), session=s),
                sessions))
        bad = [o for o in opens if err(o)]
        if not check(not bad, f"shared opens failed: {bad[:2]}", failures):
            return

        instances = c.call("list_instances")
        inst = instances if isinstance(instances, list) else instances.get("instances", [])
        check(len(inst) == 1, f"sharing should use one slot, got {len(inst)}", failures)
        check(len(worker_pids(c.proc.pid)) == 1,
              f"one shared worker expected, saw {len(worker_pids(c.proc.pid))}", failures)

        # A rename in one session must be visible from another: same mutable database.
        funcs = c.call("list_funcs", session=sessions[0], limit=1)
        entries = funcs.get("functions", [])
        if entries:
            ea = entries[0]["ea"]
            renamed = c.call("rename", session=sessions[0], ea=ea, name="shared_probe_fn")
            if not err(renamed):
                seen = c.call("get_name", session=sessions[-1], ea=ea)
                check(seen.get("name") == "shared_probe_fn",
                      f"shared database not visible across sessions: {seen}", failures)
                print("    rename in one session visible from another")

        # Closing all but one must keep the worker alive; the last close ends it.
        for s in sessions[:-1]:
            c.call("close_session", session=s)
        check(len(worker_pids(c.proc.pid)) == 1,
              "worker died while sessions still referenced it", failures)
        c.call("close_session", session=sessions[-1])
        time.sleep(0.5)
        check(not worker_pids(c.proc.pid),
              f"worker survived its last session: {worker_pids(c.proc.pid)}", failures)
        print("    refcounted teardown correct with a real worker")
    finally:
        c.close()


def test_slot_cap_with_real_workers(server, worker, ida, binaries, failures):
    """The cap must hold when start() really takes seconds."""
    cap = 2
    c = Client(server, worker, ida, IDA_MCP_MAX_SLOTS=cap)
    try:
        def opener(item):
            i, path = item
            return c.call("open_file", timeout=OPEN_TIMEOUT, path=str(path), session=f"c{i}")

        with ThreadPoolExecutor(max_workers=len(binaries)) as pool:
            results = list(pool.map(opener, enumerate(binaries)))

        ok = [r for r in results if not err(r)]
        check(len(ok) <= cap, f"opened {len(ok)} real workers with max_slots={cap}", failures)
        live = worker_pids(c.proc.pid)
        check(len(live) <= cap, f"{len(live)} worker processes with max_slots={cap}", failures)
        print(f"    max_slots={cap} held under {len(binaries)} concurrent real opens "
              f"({len(ok)} admitted, {len(live)} processes)")
    finally:
        c.close()



def test_batch_convert_real(server, worker, ida, binaries, failures, tmpdir):
    """batch_convert against real IDA: every input accounted for, files on disk."""
    c = Client(server, worker, ida, IDA_MCP_MAX_SLOTS=8)
    try:
        started = time.time()
        result = c.call("batch_convert", timeout=OPEN_TIMEOUT * 2,
                        paths=[str(b) for b in binaries],
                        output_dir=str(tmpdir), concurrency=3, max_analysis_seconds=120)
        if err(result):
            check(False, f"batch_convert failed outright: {result}", failures)
            return

        elapsed = time.time() - started
        results = result.get("results", [])
        check(len(results) == len(binaries),
              f"batch returned {len(results)} results for {len(binaries)} inputs", failures)

        # Order is part of the contract: results line up with the inputs given.
        for i, (b, r) in enumerate(zip(binaries, results)):
            check(r.get("source") == str(b),
                  f"result {i} is for {r.get('source')}, expected {b}", failures)

        done = [r for r in results if r.get("error") is None]
        check(result.get("completed") == len(done),
              f"completed={result.get('completed')} but {len(done)} entries lack an error",
              failures)

        # A converted file must actually exist and be a real database.
        for r in done:
            out = r.get("i64_path")
            if not check(out and Path(out).is_file(), f"missing output for {r.get('source')}", failures):
                continue
            check(Path(out).stat().st_size > 1024,
                  f"suspiciously small database: {out}", failures)

        print(f"    converted {len(done)}/{len(binaries)} in {elapsed:.0f}s, "
              f"{result.get('total_functions', 0)} functions total")

        # Sessions are internal to the batch and must not survive it.
        check(not worker_pids(c.proc.pid),
              f"batch left workers running: {worker_pids(c.proc.pid)}", failures)
        instances = c.call("list_instances")
        inst = instances if isinstance(instances, list) else instances.get("instances", [])
        check(not inst, f"batch left slots allocated: {inst}", failures)
        print("    batch cleaned up its own sessions")
    finally:
        c.close()


def test_batch_concurrency_exceeds_slots(server, worker, ida, binaries, failures, tmpdir):
    """batch concurrency and max_slots are separate limits; the tighter one wins.

    Asking for more parallelism than the pool allows must degrade to partial
    conversion with per-file errors, never to a hang or a bogus success count.
    """
    c = Client(server, worker, ida, IDA_MCP_MAX_SLOTS=1)
    try:
        result = c.call("batch_convert", timeout=OPEN_TIMEOUT * 2,
                        paths=[str(b) for b in binaries],
                        output_dir=str(tmpdir), concurrency=4, max_analysis_seconds=120)
        if err(result):
            check(False, f"batch_convert errored instead of degrading: {result}", failures)
            return

        results = result.get("results", [])
        check(len(results) == len(binaries),
              f"every input needs an entry even when slots run out: got {len(results)}",
              failures)
        failed = [r for r in results if r.get("error")]
        completed = result.get("completed", 0)
        check(completed + len(failed) == len(binaries),
              f"completed({completed}) + failed({len(failed)}) != {len(binaries)}", failures)
        print(f"    max_slots=1 vs concurrency=4: {completed} converted, "
              f"{len(failed)} reported an error, none lost")
        check(not worker_pids(c.proc.pid),
              f"workers survived a contended batch: {worker_pids(c.proc.pid)}", failures)
    finally:
        c.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--server", default=str(ROOT / "target" / "release" / "ida-hive"))
    ap.add_argument("--worker", default=str(ROOT / "worker" / "build-linux" / "ida_mcp_worker"))
    ap.add_argument("--ida", default=os.environ.get("IDABIN"))
    args = ap.parse_args()

    for name, path in (("server", args.server), ("worker", args.worker)):
        if not Path(path).exists():
            print(f"SKIPPED: {name} not built at {path}")
            return 0
    if not args.ida or not (Path(args.ida) / "libidalib.so").exists():
        print("SKIPPED: IDABIN does not point at an IDA installation")
        return 0

    binaries = small_binaries(4)
    if len(binaries) < 3:
        print("SKIPPED: not enough small ELF binaries to drive the test")
        return 0

    failures = []
    started = time.time()
    print(f"  targets: {', '.join(b.name for b in binaries)}")

    print("  concurrent distinct binaries")
    test_concurrent_distinct_binaries(args.server, args.worker, args.ida, binaries[:3], failures)
    print("  shared binary, refcounted teardown")
    test_shared_binary_one_process(args.server, args.worker, args.ida, binaries[0], failures)
    print("  slot cap with real workers")
    test_slot_cap_with_real_workers(args.server, args.worker, args.ida, binaries, failures)

    with tempfile.TemporaryDirectory(prefix="ida-hive-batch-") as td:
        print("  batch_convert with real IDA")
        test_batch_convert_real(args.server, args.worker, args.ida, binaries[:3], failures, Path(td))
        print("  batch concurrency exceeding max_slots")
        test_batch_concurrency_exceeds_slots(args.server, args.worker, args.ida,
                                             binaries[:3], failures, Path(td))

    elapsed = time.time() - started
    print()
    if failures:
        print(f"FAILED: {len(failures)} problem(s) in {elapsed:.0f}s")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASSED: real-IDA integration clean in {elapsed:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
