#!/usr/bin/env python3
"""End-to-end tests for the ida-hive Rust coordinator.

These drive the real `ida-hive` binary over real MCP stdio, but substitute
`tests/mock_worker.py` for the C++ idalib worker — so everything the
coordinator itself is responsible for (MCP surface, session routing, path
dedup, refcounted teardown, concurrency, timeouts, crash recovery, temp-dir
lifecycle) is exercised without IDA Pro being installed.

    python3 tests/test_coordinator.py [-k substring] [-v]

Requires only `cargo build --release` to have run first.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "target" / "release" / "ida-hive"
MOCK_WORKER = ROOT / "tests" / "mock_worker.py"
README = ROOT / "README.md"


# ---- Minimal MCP stdio client (concurrent: responses are matched by request id) ----

class McpError(RuntimeError):
    pass


class McpClient:
    def __init__(self, **env_overrides):
        env = os.environ.copy()
        env["IDA_MCP_WORKER_EXE"] = str(MOCK_WORKER)
        env.setdefault("RUST_LOG", "warn")
        for k, v in env_overrides.items():
            env[k] = str(v)

        self.proc = subprocess.Popen(
            [str(SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1, encoding="utf-8", errors="replace",
        )
        self._next_id = 0
        self._id_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._responses = {}
        self._events = {}
        self._resp_lock = threading.Lock()
        self.stderr_buf = []

        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()
        self._errreader = threading.Thread(target=self._read_stderr, daemon=True)
        self._errreader.start()

        self._initialize()

    # ---- plumbing ----

    def _read_stdout(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            mid = msg.get("id")
            if mid is None:
                continue
            with self._resp_lock:
                self._responses[mid] = msg
                ev = self._events.get(mid)
            if ev:
                ev.set()

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr_buf.append(line)

    def _send(self, obj):
        with self._write_lock:
            self.proc.stdin.write(json.dumps(obj) + "\n")
            self.proc.stdin.flush()

    def _request(self, method, params=None, timeout=60):
        with self._id_lock:
            self._next_id += 1
            mid = self._next_id
        ev = threading.Event()
        with self._resp_lock:
            self._events[mid] = ev
        payload = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)
        if not ev.wait(timeout):
            raise McpError(f"timeout waiting for {method} (id={mid}) after {timeout}s")
        with self._resp_lock:
            return self._responses.pop(mid)

    def _initialize(self):
        resp = self._request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ida-hive-tests", "version": "1.0"},
        }, timeout=20)
        if "result" not in resp:
            raise McpError(f"initialize failed: {resp}")
        self.server_info = resp["result"]
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    # ---- API ----

    def list_tools(self):
        return self._request("tools/list", {})["result"]["tools"]

    def call(self, tool_name, /, _timeout=60, **arguments):
        """Call a tool and return its decoded JSON payload.

        `tool_name` is positional-only and the timeout is underscore-prefixed so
        that every remaining keyword is a genuine tool argument — several tools
        take arguments literally called `name` or `timeout`.
        """
        resp = self._request("tools/call", {"name": tool_name, "arguments": arguments}, timeout=_timeout)
        result = resp.get("result")
        if result is None:
            raise McpError(f"no result for {tool_name}: {resp}")
        if result.get("isError"):
            raise McpError(f"MCP error for {tool_name}: {json.dumps(resp)}")
        content = result.get("content") or []
        if not content:
            return None
        text = content[0].get("text", "")
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---- Helpers ----

def make_bin(dirpath, name, size=256):
    p = Path(dirpath) / name
    p.write_bytes(b"\x7fELF" + os.urandom(size))
    return p


def mock_worker_pids():
    """PIDs of live mock workers — used to prove process cleanup."""
    pids = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if b"mock_worker.py" in cmdline:
            pids.append(int(entry.name))
    return pids


def wait_until(predicate, timeout=5.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def err_of(payload):
    """Return the `error` string of a tool payload, or None."""
    if isinstance(payload, dict):
        return payload.get("error")
    return None


def readme_tools():
    """Tool names + per-category counts as advertised by the README table."""
    names, rows, declared_total = [], [], None
    text = README.read_text(encoding="utf-8")
    m = re.search(r"(\d+)\s+MCP tools", text)
    if m:
        declared_total = int(m.group(1))
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 3 or not cells[2].isdigit():
            continue
        cat, tools, count = cells[0], cells[1], int(cells[2])
        tool_names = [t.strip() for t in tools.split(",") if t.strip()]
        if not all(re.fullmatch(r"[a-z0-9_]+", t) for t in tool_names):
            continue
        rows.append((cat, tool_names, count))
        names.extend(tool_names)
    return names, rows, declared_total


# ---- Test registry ----

TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


def xfail(reason):
    """Mark a test as documenting a KNOWN product bug.

    The test body asserts the CURRENT (buggy) behavior, so it passes while the
    bug exists and will FAIL LOUDLY the day the bug is fixed — at which point the
    marker should be removed. Known bugs are reported separately from failures so
    a green run still surfaces them.
    """
    def deco(fn):
        fn._xfail_reason = reason
        TESTS.append(fn)
        return fn
    return deco


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ---- 1. MCP surface ----

@test
def test_initialize_handshake():
    """initialize returns the ida-hive server identity and tool capability."""
    with McpClient() as c:
        info = c.server_info
        check(info["serverInfo"]["name"] == "ida-hive",
              f"unexpected server name: {info['serverInfo']}")
        check("tools" in info.get("capabilities", {}),
              f"tools capability missing: {info.get('capabilities')}")
        check(info.get("instructions"), "server instructions missing")


@test
def test_tools_list_matches_readme():
    """tools/list exposes exactly the tools the README advertises."""
    with McpClient() as c:
        live = sorted(t["name"] for t in c.list_tools())
    doc_names, rows, declared_total = readme_tools()

    check(len(live) == len(set(live)), "duplicate tool names in tools/list")
    check(declared_total is not None, "README does not state a tool count")
    check(len(live) == declared_total,
          f"README claims {declared_total} tools, server exposes {len(live)}")

    for cat, tool_names, count in rows:
        check(len(tool_names) == count,
              f"README row '{cat}' lists {len(tool_names)} tools but claims {count}")

    missing = sorted(set(doc_names) - set(live))
    extra = sorted(set(live) - set(doc_names))
    check(not missing, f"README documents tools the server does not expose: {missing}")
    check(not extra, f"server exposes undocumented tools: {extra}")


@test
def test_tool_schemas_are_well_formed():
    """Every tool has a description and a JSON-Schema object for its input."""
    with McpClient() as c:
        tools = c.list_tools()
    for t in tools:
        check(t.get("description"), f"{t['name']}: missing description")
        schema = t.get("inputSchema")
        check(isinstance(schema, dict), f"{t['name']}: missing inputSchema")
        check(schema.get("type") == "object", f"{t['name']}: inputSchema is not an object")
    by_name = {t["name"]: t for t in tools}
    # Address-taking tools must require `ea`; session must stay optional.
    for name in ("decompile", "disasm", "xrefs_to", "get_bytes", "rename"):
        req = by_name[name]["inputSchema"].get("required", [])
        check("ea" in req, f"{name}: 'ea' is not required (required={req})")
        check("session" not in req, f"{name}: 'session' should be optional (required={req})")


# ---- 2. Pure-Rust tools (no worker involved) ----

@test
def test_int_convert():
    """int_convert is computed in Rust and matches the worker's output shape."""
    with McpClient() as c:
        r = c.call("int_convert", value="0x1F")
        check(r == {"hex": "0x1F", "dec": "31", "oct": "037", "bin": "0b11111", "signed": 31}, f"0x1F -> {r}")

        r = c.call("int_convert", value="0755")
        check(r["dec"] == "493", f"octal 0755 -> {r}")

        r = c.call("int_convert", value="0")
        check(r["bin"] == "0b0" and r["hex"] == "0x0", f"0 -> {r}")

        r = c.call("int_convert", value="-1")
        check(r["hex"] == "0xFFFFFFFFFFFFFFFF" and r["signed"] == -1, f"-1 -> {r}")

        r = c.call("int_convert", value="not_a_number")
        check(err_of(r), f"garbage input should report an error, got {r}")


@test
def test_server_health_and_empty_state():
    """server_health/list_instances are sane with no sessions open."""
    with McpClient() as c:
        health = c.call("server_health")
        check(health["status"] == "ok", f"health: {health}")
        check(health["total_slots"] == 0 and health["alive_slots"] == 0, f"health: {health}")
        check(c.call("list_instances") == [], "list_instances should be empty")


@test
def test_server_health_reports_configured_max_slots():
    """server_health.max_slots reflects IDA_MCP_MAX_SLOTS (fixed: was hardcoded 100).

    Regression guard for bug V1: server_health used to emit a constant 100
    regardless of configuration, misleading capacity planning. It must now
    report the same limit open_file enforces.
    """
    with McpClient(IDA_MCP_MAX_SLOTS=7) as c:
        health = c.call("server_health")
        check(health["max_slots"] == 7,
              f"server_health should report the configured cap 7, got {health['max_slots']}")
    # And the default when unset stays 100.
    with McpClient() as c:
        health = c.call("server_health")
        check(health["max_slots"] == 100,
              f"default max_slots should be 100, got {health['max_slots']}")


# ---- 3. Sessions, routing, dedup ----

@test
def test_open_route_and_close():
    """open_file → route a query → close_session, and the slot disappears."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "target.bin")

        opened = c.call("open_file", path=str(binary), session="s1")
        check(not err_of(opened), f"open_file failed: {opened}")
        check(opened["session"] == "s1" and opened["slot_id"], f"open_file: {opened}")
        check(opened["info"]["mock"] is True, f"ready data not surfaced: {opened}")

        info = c.call("get_info", session="s1")
        check(info["path"] == str(binary), f"routed to the wrong worker: {info}")

        instances = c.call("list_instances")
        check(len(instances) == 1 and instances[0]["alive"], f"list_instances: {instances}")
        check("analyzing" not in instances[0]["info"],
              "list_instances must strip the stale 'analyzing' flag")

        check(c.call("close_session", session="s1") == {"closed": True}, "close_session failed")
        check(c.call("list_instances") == [], "slot survived close_session")


@test
def test_default_session_name():
    """Omitting `session` uses the 'default' session on both open and route."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "default.bin")
        opened = c.call("open_file", path=str(binary))
        check(opened["session"] == "default", f"open_file: {opened}")
        info = c.call("get_info")
        check(info["path"] == str(binary), f"default routing broken: {info}")


@test
def test_path_dedup_across_spellings():
    """Relative paths, ./, .., and symlinks all collapse onto one worker."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "dedup.bin")
        sub = Path(td) / "sub"
        sub.mkdir()
        link = sub / "link.bin"
        link.symlink_to(binary)

        spellings = [
            str(binary),
            str(Path(td) / "." / "dedup.bin"),
            str(sub / ".." / "dedup.bin"),
            str(link),
        ]
        slot_ids = set()
        for i, spelling in enumerate(spellings):
            opened = c.call("open_file", path=spelling, session=f"s{i}")
            check(not err_of(opened), f"open_file({spelling}) failed: {opened}")
            slot_ids.add(opened["slot_id"])

        check(len(slot_ids) == 1, f"expected one shared worker, got {len(slot_ids)}: {slot_ids}")
        instances = c.call("list_instances")
        check(len(instances) == 1, f"expected 1 slot, got {len(instances)}")
        check(instances[0]["path"] == os.path.realpath(binary),
              f"slot path is not canonical: {instances[0]['path']}")


@test
def test_shared_worker_refcount_on_close():
    """Closing one of several sessions sharing a worker must not kill it."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "shared.bin")
        a = c.call("open_file", path=str(binary), session="a")
        b = c.call("open_file", path=str(binary), session="b")
        check(a["slot_id"] == b["slot_id"], "sessions did not share a worker")

        c.call("close_session", session="a")
        check(len(c.call("list_instances")) == 1, "worker died while session 'b' still held it")
        info = c.call("get_info", session="b")
        check(not err_of(info), f"surviving session broke after sibling close: {info}")

        c.call("close_session", session="b")
        check(c.call("list_instances") == [], "worker outlived its last session")


@test
def test_session_reuse_with_different_binary_is_rejected():
    """Reusing a session id for a different file fails loudly."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        first = make_bin(td, "one.bin")
        second = make_bin(td, "two.bin")
        c.call("open_file", path=str(first), session="s1")
        clash = c.call("open_file", path=str(second), session="s1")
        msg = err_of(clash)
        check(msg and "different binary" in msg, f"expected a clash error, got {clash}")
        info = c.call("get_info", session="s1")
        check(info["path"] == str(first), "the original binary was silently replaced")


@test
def test_route_without_session():
    """Routing to an unopened session returns a helpful error, not a crash."""
    with McpClient() as c:
        r = c.call("get_info", session="ghost")
        msg = err_of(r)
        check(msg and "No active session" in msg and "open_file" in msg, f"unexpected: {r}")


@test
def test_worker_private_db_dir_lifecycle():
    """Each worker gets its own writable temp dir, removed when it stops."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        one = make_bin(td, "dbdir1.bin")
        two = make_bin(td, "dbdir2.bin")
        a = c.call("open_file", path=str(one), session="a")
        b = c.call("open_file", path=str(two), session="b")

        dir_a = Path(a["info"]["db_dir"])
        dir_b = Path(b["info"]["db_dir"])
        check(dir_a != dir_b, f"workers share a db dir: {dir_a}")
        check(dir_a.is_dir() and dir_b.is_dir(), "db dirs missing")
        check((dir_a / "mock.marker").read_text() == str(one), "worker could not write to its db dir")

        c.call("close_session", session="a")
        check(wait_until(lambda: not dir_a.exists()), f"db dir leaked after close: {dir_a}")
        check(dir_b.is_dir(), "closing one session removed another's db dir")
        c.call("close_session", session="b")
        check(wait_until(lambda: not dir_b.exists()), f"db dir leaked after close: {dir_b}")


@test
def test_workers_exit_when_server_exits():
    """Closing the MCP connection reaps every worker process."""
    with tempfile.TemporaryDirectory() as td:
        binary = make_bin(td, "reap.bin")
        before = set(mock_worker_pids())
        c = McpClient()
        c.call("open_file", path=str(binary), session="s1")
        during = set(mock_worker_pids()) - before
        check(len(during) == 1, f"expected exactly one new worker, got {during}")
        c.close()
        check(wait_until(lambda: not (set(mock_worker_pids()) & during), timeout=10),
              f"worker processes leaked after shutdown: {during}")


# ---- 4. Concurrency ----

@test
def test_same_worker_serializes_but_multiplexes_ids():
    """Within ONE worker, calls serialize (real dispatcher is single-threaded),
    yet the coordinator still matches each response to its own request by id.

    This is the faithful counterpart to the cross-worker concurrency test: the
    real worker (worker/protocol.h) runs handlers one at a time, so a slow call
    DOES delay the next call on the same worker. What must never break is id
    multiplexing — two in-flight requests must not cross their replies.
    """
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "serial.bin")
        c.call("open_file", path=str(binary), session="s1")

        with ThreadPoolExecutor(max_workers=2) as pool:
            slow = pool.submit(lambda: c.call("decompile", session="s1", ea="SLEEP:2000"))
            time.sleep(0.2)
            t0 = time.time()
            fast = c.call("get_info", session="s1")
            fast_elapsed = time.time() - t0
            slow_result = slow.result(timeout=30)

        check(not err_of(fast) and not err_of(slow_result), f"fast={fast} slow={slow_result}")
        # id multiplexing: each reply landed on the right request, not swapped.
        check(slow_result["pseudocode"], f"decompile reply mismatched: {slow_result}")
        check(fast["processor"] == "metapc" and "func_count" in fast,
              f"get_info reply mismatched: {fast}")
        # Serial: get_info could only start after decompile drained (~2s), so it
        # returns only once the slow call is nearly done — not early.
        check(fast_elapsed > 1.0,
              f"get_info returned in {fast_elapsed:.2f}s — a single worker must "
              f"serialize behind the 2s call, but it appears to have run in parallel")


@test
def test_coordinator_multiplexes_out_of_order_replies():
    """Defensive: if a worker DOES reply out of order, the coordinator still
    routes each reply to the right caller by id.

    Uses the mock's opt-in concurrent dispatch (not real-worker behavior — the
    real dispatcher is serial — but it exercises the coordinator's pending-map
    id matching under out-of-order completion).
    """
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "concurrent.bin")   # 'concurrent' → threaded worker
        c.call("open_file", path=str(binary), session="s1")

        with ThreadPoolExecutor(max_workers=3) as pool:
            slow = pool.submit(lambda: c.call("decompile", session="s1", ea="SLEEP:2000"))
            time.sleep(0.2)
            t0 = time.time()
            fast = c.call("lookup_func", session="s1", ea="quick")   # finishes first
            fast_elapsed = time.time() - t0
            slow_result = slow.result(timeout=30)

        # Out-of-order: the later-sent fast call returns BEFORE the slow one, and
        # each reply is still matched to its own request.
        check(fast_elapsed < 1.0,
              f"concurrent worker did not let the fast call finish early ({fast_elapsed:.2f}s)")
        check(fast["ea"] == "quick", f"lookup reply mismatched to wrong request: {fast}")
        check(slow_result["pseudocode"], f"decompile reply mismatched: {slow_result}")


@test
def test_concurrent_requests_across_workers():
    """A slow call on one session must not block another session."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        one = make_bin(td, "busy.bin")
        two = make_bin(td, "idle.bin")
        c.call("open_file", path=str(one), session="busy")
        c.call("open_file", path=str(two), session="idle")

        with ThreadPoolExecutor(max_workers=2) as pool:
            slow = pool.submit(lambda: c.call("decompile", session="busy", ea="SLEEP:3000"))
            time.sleep(0.3)
            t0 = time.time()
            fast = c.call("get_info", session="idle")
            fast_elapsed = time.time() - t0
            slow.result(timeout=30)

        check(fast["path"] == str(two), f"cross-session routing broke: {fast}")
        check(fast_elapsed < 1.5,
              f"session 'idle' waited {fast_elapsed:.2f}s behind a slow call in session 'busy'")


@test
def test_concurrent_open_of_same_path_dedups():
    """Racing opens of one path converge on a single worker."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "race.bin")
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(c.call, "open_file", path=str(binary), session=f"r{i}")
                       for i in range(6)]
            results = [f.result(timeout=60) for f in futures]
        for r in results:
            check(not err_of(r), f"racing open failed: {r}")
        slot_ids = {r["slot_id"] for r in results}
        check(len(slot_ids) == 1, f"racing opens spawned {len(slot_ids)} workers: {slot_ids}")
        check(len(c.call("list_instances")) == 1, "duplicate slots registered")


# ---- 4b. Stress & lifecycle edges ----

@test
def test_mixed_high_concurrency_workload():
    """Many workers, many interleaved requests — no deadlock, no reply crossing."""
    with tempfile.TemporaryDirectory() as td, McpClient(IDA_MCP_MAX_SLOTS=8) as c:
        files = [make_bin(td, f"load{i}.bin") for i in range(6)]
        for i, f in enumerate(files):
            c.call("open_file", path=str(f), session=f"s{i}")

        def one(i):
            sess = f"s{i % len(files)}"
            info = c.call("get_info", session=sess)
            # Each reply must belong to the session that asked.
            return info["path"] == str(files[i % len(files)])

        with ThreadPoolExecutor(max_workers=12) as pool:
            oks = list(pool.map(one, range(60)))
        check(all(oks), f"reply routing broke under load: {oks.count(False)}/60 wrong")
        check(len(c.call("list_instances")) == 6, "slot count drifted under load")


@test
def test_slot_exhaustion_under_parallel_open():
    """More concurrent opens than slots: the excess is rejected, never over-committed."""
    slots = 4
    with tempfile.TemporaryDirectory() as td, McpClient(IDA_MCP_MAX_SLOTS=str(slots)) as c:
        files = [make_bin(td, f"exh{i}.bin") for i in range(slots * 3)]

        def opener(i):
            return c.call("open_file", path=str(files[i]), session=f"e{i}", _timeout=30)

        with ThreadPoolExecutor(max_workers=len(files)) as pool:
            results = list(pool.map(opener, range(len(files))))

        ok = [r for r in results if not err_of(r)]
        rejected = [r for r in results if err_of(r)]
        # The cap is the invariant; which particular opens win is a race.
        check(len(ok) <= slots, f"opened {len(ok)} workers with max_slots={slots}")
        check(len(rejected) == len(files) - len(ok),
              "every non-opened request must carry an error")
        check(len(c.call("list_instances")) == len(ok),
              "instance list disagrees with the opens that succeeded")


@test
def test_parallel_close_of_shared_worker():
    """Sessions sharing one worker can all close at once without a double stop."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "sharedclose.bin")
        sessions = [f"sc{i}" for i in range(8)]
        for s in sessions:
            c.call("open_file", path=str(binary), session=s)
        check(len(c.call("list_instances")) == 1, "sharing should dedup to one worker")

        with ThreadPoolExecutor(max_workers=len(sessions)) as pool:
            closes = list(pool.map(lambda s: c.call("close_session", session=s), sessions))

        check(all(not err_of(r) for r in closes), f"a concurrent close failed: {closes}")
        check(c.call("list_instances") == [], "shared worker outlived its last session")


@test
def test_open_close_storm_stays_consistent():
    """Interleaved opens and closes across threads leave no orphan slots."""
    rounds = 40
    with tempfile.TemporaryDirectory() as td, McpClient(IDA_MCP_MAX_SLOTS="6") as c:
        files = [make_bin(td, f"storm{i}.bin") for i in range(4)]

        def churn(i):
            sess = f"st{i}"
            path = files[i % len(files)]
            c.call("open_file", path=str(path), session=sess, _timeout=30)
            c.call("close_session", session=sess, _timeout=30)

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(churn, range(rounds)))

        check(c.call("list_instances") == [],
              "slots survived an open/close storm")
        # And the coordinator still works afterwards.
        c.call("open_file", path=str(files[0]), session="after")
        check(len(c.call("list_instances")) == 1, "coordinator wedged after the storm")


@test
def test_slow_call_does_not_block_other_sessions():
    """A long call on one worker must not stall requests routed elsewhere."""
    with tempfile.TemporaryDirectory() as td, McpClient(IDA_MCP_MAX_SLOTS="4") as c:
        slow_bin = make_bin(td, "slowsess.bin")
        fast_bin = make_bin(td, "fastsess.bin")
        c.call("open_file", path=str(slow_bin), session="slow")
        c.call("open_file", path=str(fast_bin), session="fast")

        with ThreadPoolExecutor(max_workers=2) as pool:
            blocked = pool.submit(
                lambda: c.call("decompile", session="slow", ea="SLEEP:3000", _timeout=30))
            time.sleep(0.3)
            started = time.time()
            c.call("get_info", session="fast", _timeout=30)
            elapsed = time.time() - started
            blocked.result(timeout=30)

        # The write-preferring RwLock regression would push this to the full sleep.
        check(elapsed < 1.5,
              f"a call on an idle worker waited {elapsed:.1f}s behind another session")


@test
def test_close_during_in_flight_request():
    """Closing a session mid-request fails that call cleanly, no coordinator hang."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "closeflight.bin")
        c.call("open_file", path=str(binary), session="s1")

        with ThreadPoolExecutor(max_workers=2) as pool:
            slow = pool.submit(lambda: c.call("decompile", session="s1", ea="SLEEP:2000", _timeout=30))
            time.sleep(0.3)
            closed = c.call("close_session", session="s1")
            slow_result = slow.result(timeout=30)

        check(closed == {"closed": True}, f"close_session failed: {closed}")
        check(err_of(slow_result), f"in-flight call should fail when its worker is stopped: {slow_result}")
        # Coordinator is still healthy afterwards.
        check(c.call("list_instances") == [], "slot survived close")
        again = make_bin(td, "closeflight2.bin")
        check(not err_of(c.call("open_file", path=str(again), session="s2")),
              "coordinator wedged after a close-during-flight")


@test
def test_open_close_churn_does_not_leak():
    """Repeated open/close of the same path leaves no slots or temp dirs behind."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "churn.bin")
        seen_dirs = []
        for i in range(12):
            opened = c.call("open_file", path=str(binary), session="s1")
            check(not err_of(opened), f"churn open {i} failed: {opened}")
            seen_dirs.append(Path(opened["info"]["db_dir"]))
            c.call("close_session", session="s1")
        check(c.call("list_instances") == [], "slots leaked across churn")
        check(wait_until(lambda: all(not d.exists() for d in seen_dirs), timeout=10),
              "temp dirs leaked across churn")


@test
def test_malformed_worker_output_is_tolerated():
    """A non-JSON stdout line from the worker is skipped; the real reply arrives."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "garbage.bin")
        c.call("open_file", path=str(binary), session="s1")
        r = c.call("decompile", session="s1", ea="GARBAGE")
        check(not err_of(r) and r.get("pseudocode"),
              f"coordinator choked on a junk line instead of skipping it: {r}")
        # Still healthy for subsequent calls.
        check(not err_of(c.call("get_info", session="s1")), "worker unusable after junk line")


@test
def test_paths_with_spaces_and_unicode():
    """Odd characters in a path survive canonicalization, dedup and routing."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        weird = make_bin(td, "we ird — 名字.bin")
        opened = c.call("open_file", path=str(weird), session="s1")
        check(not err_of(opened), f"open failed for odd path: {opened}")
        info = c.call("get_info", session="s1")
        check(info["path"] == os.path.realpath(weird), f"odd path mis-routed: {info}")
        # Dedup still works for the same odd path via a different spelling.
        again = c.call("open_file", path=str(Path(td) / "." / "we ird — 名字.bin"), session="s2")
        check(again["slot_id"] == opened["slot_id"], "odd-path dedup failed")


# ---- 5. Failure modes ----

@test
def test_worker_init_error_is_surfaced():
    """A worker that reports init_error propagates its stage and message."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        bad = make_bin(td, "initfail.bin")
        r = c.call("open_file", path=str(bad), session="s1")
        msg = err_of(r)
        check(msg, f"expected an error, got {r}")
        check("open_database" in msg and "mock refuses" in msg, f"error lost detail: {msg}")
        check(c.call("list_instances") == [], "a failed open left a slot behind")


@test
def test_worker_ready_timeout():
    """A worker that never reports ready is bounded by IDA_MCP_OPEN_TIMEOUT."""
    with tempfile.TemporaryDirectory() as td, McpClient(IDA_MCP_OPEN_TIMEOUT=2) as c:
        binary = make_bin(td, "hangready.bin")
        before = set(mock_worker_pids())
        t0 = time.time()
        r = c.call("open_file", path=str(binary), session="s1", _timeout=30)
        elapsed = time.time() - t0
        msg = err_of(r)
        check(msg and "did not become ready within 2s" in msg, f"unexpected: {r}")
        check(1.5 < elapsed < 8, f"timeout fired after {elapsed:.1f}s, expected ~2s")
        check(c.call("list_instances") == [], "hung open left a slot behind")
        leaked = set(mock_worker_pids()) - before
        check(wait_until(lambda: not (set(mock_worker_pids()) & leaked), timeout=10),
              f"hung worker was not killed: {leaked}")


@test
def test_worker_error_response_is_surfaced():
    """A worker-level {"error": ...} reply reaches the caller intact."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "errors.bin")
        c.call("open_file", path=str(binary), session="s1")
        r = c.call("decompile", session="s1", ea="ERROR:no such function")
        check(err_of(r) == "no such function", f"worker error not propagated: {r}")
        check(not err_of(c.call("get_info", session="s1")), "session broke after a worker error")


@test
def test_worker_crash_recovery():
    """A dying worker fails its in-flight call, is reported dead, then reaped."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "crash.bin")
        opened = c.call("open_file", path=str(binary), session="s1")
        db_dir = Path(opened["info"]["db_dir"])

        crashed = c.call("decompile", session="s1", ea="CRASH", _timeout=30)
        check(err_of(crashed), f"crash should fail the in-flight call, got {crashed}")

        check(wait_until(lambda: err_of(c.call("get_info", session="s1")) is not None, timeout=10),
              "calls kept succeeding after the worker died")
        msg = err_of(c.call("get_info", session="s1"))
        check("died" in msg or "dead" in msg, f"unhelpful post-crash error: {msg}")

        # Reopening prunes the corpse and starts a fresh worker.
        reopened = c.call("open_file", path=str(binary), session="s2")
        check(not err_of(reopened), f"could not reopen after a crash: {reopened}")
        check(reopened["slot_id"] != opened["slot_id"], "reused the dead slot")
        instances = c.call("list_instances")
        check(len(instances) == 1 and instances[0]["alive"],
              f"dead slot was not pruned: {instances}")
        check(wait_until(lambda: not db_dir.exists()), f"dead worker's db dir leaked: {db_dir}")


@test
def test_max_slots_limit():
    """The pool refuses to exceed IDA_MCP_MAX_SLOTS and says how to recover."""
    with tempfile.TemporaryDirectory() as td, McpClient(IDA_MCP_MAX_SLOTS=2) as c:
        files = [make_bin(td, f"slot{i}.bin") for i in range(3)]
        for i in range(2):
            r = c.call("open_file", path=str(files[i]), session=f"s{i}")
            check(not err_of(r), f"open {i} failed: {r}")
        r = c.call("open_file", path=str(files[2]), session="s2")
        msg = err_of(r)
        check(msg and "Max slots (2)" in msg, f"expected a capacity error, got {r}")

        # Freeing a slot makes room again.
        c.call("close_session", session="s0")
        r = c.call("open_file", path=str(files[2]), session="s2")
        check(not err_of(r), f"still refused after freeing a slot: {r}")


@test
def test_route_timeout_for_wait_analysis():
    """route() bounds wait_analysis at max_seconds + 10s instead of hanging."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "slowwait.bin")
        c.call("open_file", path=str(binary), session="s1")
        t0 = time.time()
        r = c.call("wait_analysis", session="s1", max_seconds=1, _timeout=40)
        elapsed = time.time() - t0
        msg = err_of(r)
        check(msg and "timeout" in msg.lower(), f"expected a timeout error, got {r}")
        check(9 < elapsed < 16, f"wait_analysis timeout fired after {elapsed:.1f}s, expected ~11s")
        check("11s" in msg, f"timeout error should quote the effective bound: {msg}")


# ---- 6. batch_convert ----

@test
def test_batch_convert():
    """batch_convert opens, waits, saves and closes every input, in order."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        files = [make_bin(td, f"batch{i}.bin") for i in range(4)]
        out_dir = Path(td) / "out"
        r = c.call("batch_convert", paths=[str(f) for f in files],
                   output_dir=str(out_dir), concurrency=2, max_analysis_seconds=30, _timeout=120)

        check(r["total"] == 4 and r["completed"] == 4 and r["failed"] == 0, f"batch_convert: {r}")
        check([res["source"] for res in r["results"]] == [str(f) for f in files],
              "results were not restored to input order")
        check(r["total_functions"] == sum(res["functions"] for res in r["results"]),
              f"total_functions does not add up: {r['total_functions']}")
        for f, res in zip(files, r["results"]):
            produced = out_dir / f"{f.name}.i64"
            check(produced.exists(), f"missing output: {produced}")
            check(res["i64_path"] == str(produced), f"wrong reported path: {res}")
            check(res["error"] is None and res["elapsed"] >= 0, f"bad result entry: {res}")

        check(c.call("list_instances") == [], "batch_convert leaked worker slots")


@test
def test_batch_convert_reports_per_file_failures():
    """One bad input fails on its own without taking the batch down."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        good = make_bin(td, "good.bin")
        bad = make_bin(td, "initfail2.bin")
        out_dir = Path(td) / "out"
        r = c.call("batch_convert", paths=[str(bad), str(good)],
                   output_dir=str(out_dir), concurrency=2, max_analysis_seconds=30, _timeout=120)

        check(r["total"] == 2 and r["completed"] == 1 and r["failed"] == 1, f"batch_convert: {r}")
        failed, ok = r["results"][0], r["results"][1]
        check(failed["source"] == str(bad) and failed["error"], f"bad file not reported: {failed}")
        check(ok["source"] == str(good) and ok["error"] is None, f"good file not converted: {ok}")
        check((out_dir / "good.bin.i64").exists(), "good file produced no database")
        check(c.call("list_instances") == [], "failed batch leaked slots")


# ---- 7. Misc tool plumbing ----

@test
def test_optional_params_are_forwarded():
    """Optional tool arguments reach the worker only when actually supplied."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "params.bin")
        c.call("open_file", path=str(binary), session="s1")

        echo = c.call("find_bytes", session="s1", hex="48 8B ?? 90")
        check(echo["params"] == {"hex": "48 8B ?? 90"}, f"unset optionals leaked: {echo['params']}")

        echo = c.call("find_bytes", session="s1", hex="90", start="0x401000", limit=3)
        check(echo["params"] == {"hex": "90", "start": "0x401000", "limit": 3},
              f"optionals not forwarded: {echo['params']}")

        # JSON-string parameters are parsed before they reach the worker.
        echo = c.call("type_apply_batch", session="s1",
                      items='[{"ea":"0x401000","type":"int"}]')
        check(echo["params"]["items"] == [{"ea": "0x401000", "type": "int"}],
              f"items not parsed into JSON: {echo['params']}")

        echo = c.call("enum_upsert", session="s1", name="E", members='[{"name":"A","value":1}]')
        check(echo["params"]["members"] == [{"name": "A", "value": 1}],
              f"members not parsed into JSON: {echo['params']}")


@test
def test_lookup_func_sends_ea_key():
    """The public `ea` argument is what actually reaches the worker."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "lookup.bin")
        c.call("open_file", path=str(binary), session="s1")
        r = c.call("lookup_func", session="s1", ea="CreateInterface")
        check(r["ea"] == "CreateInterface", f"ea not forwarded: {r}")


@test
def test_server_warmup():
    """server_warmup pings the worker and reports both probes."""
    with tempfile.TemporaryDirectory() as td, McpClient() as c:
        binary = make_bin(td, "warmup.bin")
        c.call("open_file", path=str(binary), session="s1")
        r = c.call("server_warmup", session="s1")
        check(r["warmed_up"] is True, f"warmup: {r}")
        check("metapc" in r["info"], f"warmup lost get_info: {r['info']}")
        check("pong" in r["ping"], f"warmup lost ping: {r['ping']}")


@test
def test_nonexistent_path_is_reported():
    """Opening a path that does not exist fails with the worker's reason."""
    with McpClient() as c:
        r = c.call("open_file", path="/definitely/not/here.bin", session="s1", _timeout=30)
        check(err_of(r), f"expected an error for a missing file, got {r}")
        check(c.call("list_instances") == [], "failed open left a slot behind")


# ---- Runner ----

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-k", dest="filter", help="only run tests whose name contains this")
    ap.add_argument("-v", dest="verbose", action="store_true", help="print tracebacks")
    args = ap.parse_args()

    if not SERVER.exists():
        raise SystemExit(f"server binary not found: {SERVER}\nRun: cargo build --release")
    if not os.access(MOCK_WORKER, os.X_OK):
        os.chmod(MOCK_WORKER, 0o755)

    selected = [t for t in TESTS if not args.filter or args.filter in t.__name__]
    passed, failed, known_bugs, regressed = [], [], [], []

    for fn in selected:
        name = fn.__name__
        xreason = getattr(fn, "_xfail_reason", None)
        sys.stdout.write(f"{name:56s} ")
        sys.stdout.flush()
        t0 = time.time()
        try:
            fn()
        except Exception as exc:
            if xreason:
                # A known-bug test that no longer reproduces = the bug was fixed.
                regressed.append((name, exc))
                print(f"XPASS ({time.time() - t0:.1f}s)  ← known bug seems FIXED")
            else:
                failed.append((name, exc, traceback.format_exc()))
                print(f"FAIL  ({time.time() - t0:.1f}s)")
                print(f"    {type(exc).__name__}: {exc}")
                if args.verbose:
                    print(traceback.format_exc())
        else:
            if xreason:
                known_bugs.append((name, xreason))
                print(f"xfail ({time.time() - t0:.1f}s)  ← known bug reproduced")
            else:
                passed.append(name)
                print(f"ok    ({time.time() - t0:.1f}s)")

    print()
    print(f"{len(passed)} passed, {len(failed)} failed, "
          f"{len(known_bugs)} known-bug(s), {len(selected)} total")
    if known_bugs:
        print("\nKnown product bugs (documented, not counted as failures):")
        for name, reason in known_bugs:
            print(f"  - {name}\n      {reason}")
    if regressed:
        print("\nKnown-bug tests that no longer reproduce (update them!):")
        for name, exc in regressed:
            print(f"  - {name}: {exc}")
    if failed:
        print("\nFailures:")
        for name, exc, _ in failed:
            print(f"  - {name}: {exc}")
    return 1 if (failed or regressed) else 0


if __name__ == "__main__":
    sys.exit(main())
