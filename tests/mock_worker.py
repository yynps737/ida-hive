#!/usr/bin/env python3
"""Mock idalib worker — lets the Rust coordinator be tested without IDA Pro.

Speaks exactly the protocol worker/worker.cpp speaks (see src/slot.rs):

    argv    <input_path> <db_dir>
    stdout  {"event":"ready","data":{...}}          (or "init_error")
            {"id":N,"result":{...}}                 (or {"id":N,"error":{...}})
    stdin   {"id":N,"method":"...","params":{...}}

Startup behaviour is steered by markers in the input FILE NAME, so one
coordinator can host healthy and unhealthy workers side by side:

    *initfail*   emit init_error instead of ready
    *hangready*  never emit ready (exercises IDA_MCP_OPEN_TIMEOUT)

Per-request behaviour is steered by magic values in any string parameter:

    "SLEEP:<ms>"   delay this request by <ms> before replying
    "CRASH"        hard-exit the process (exercises worker-death handling)
    "ERROR:<msg>"  reply with a protocol-level error object
    "GARBAGE"      emit a non-JSON stdout line before the real reply (the
                   coordinator must log-and-skip it, per slot.rs, not choke)

Dispatch fidelity: the real worker (worker/protocol.h CommandDispatcher::run)
is STRICTLY SERIAL — it reads one line, runs the handler to completion, writes
the reply, then reads the next. So a slow call on one worker delays the next
call on THAT worker; concurrency exists only ACROSS workers. This mock mirrors
that: requests are processed serially in the read loop by default.

    *concurrent*  (in the file name) opt into thread-per-request dispatch, to
                  exercise the coordinator's id-multiplexing / out-of-order
                  response matching as a defensive check. This is a coordinator
                  capability, NOT real-worker behavior — the real worker never
                  replies out of order.
"""

import json
import os
import sys
import threading
import time

WRITE_LOCK = threading.Lock()


def emit(obj):
    with WRITE_LOCK:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


def log(msg):
    sys.stderr.write(f"[mock_worker {os.getpid()}] {msg}\n")
    sys.stderr.flush()


def scan_params(params):
    """Return (sleep_ms, crash, error_msg, garbage) from magic values."""
    sleep_ms, crash, err, garbage = 0, False, None, False

    def walk(v):
        nonlocal sleep_ms, crash, err, garbage
        if isinstance(v, str):
            if v.startswith("SLEEP:"):
                sleep_ms = max(sleep_ms, int(v.split(":", 1)[1]))
            elif v == "CRASH":
                crash = True
            elif v == "GARBAGE":
                garbage = True
            elif v.startswith("ERROR:"):
                err = v.split(":", 1)[1]
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(params)
    return sleep_ms, crash, err, garbage


class Worker:
    def __init__(self, path, db_dir):
        self.path = path
        self.db_dir = db_dir
        self.name = os.path.basename(path)
        # wait_analysis takes no string parameter, so its slow path is selected
        # by file name instead of a SLEEP: magic value.
        self.slow_wait = "slowwait" in self.name.lower()
        # Deterministic per-file fake analysis results.
        self.functions = 100 + (sum(self.name.encode()) % 400)
        self.segments = 4

    # ---- individual methods -------------------------------------------------

    def m_ping(self, _p):
        return {"pong": True, "path": self.path}

    def m_get_info(self, _p):
        return {
            "path": self.path,
            "processor": "metapc",
            "bits": 64,
            "entry": "0x401000",
            "min_ea": "0x400000",
            "max_ea": "0x500000",
            "func_count": self.functions,
            "segment_count": self.segments,
        }

    def m_list_funcs(self, p):
        offset = int(p.get("offset", 0))
        limit = int(p.get("limit", 100))
        filt = p.get("filter")
        funcs = [
            {"ea": f"0x{0x401000 + i * 0x20:X}", "name": f"sub_{0x401000 + i * 0x20:X}", "size": 0x20}
            for i in range(self.functions)
        ]
        if filt:
            funcs = [f for f in funcs if filt in f["name"]]
        return {"total": len(funcs), "functions": funcs[offset:offset + limit]}

    def m_lookup_func(self, p):
        ea = p.get("ea") or p.get("target")
        return {"ea": ea, "name": f"func_at_{ea}", "size": 0x20}

    def m_disasm(self, p):
        count = int(p.get("count", 50))
        return {"lines": [{"ea": p.get("ea"), "text": "nop", "size": 1} for _ in range(min(count, 5))]}

    def m_decompile(self, p):
        return {"ea": p.get("ea"), "pseudocode": "__int64 f() { return 0; }"}

    def m_survey_binary(self, _p):
        return {
            "function_count": self.functions,
            "segments": [{"name": f".seg{i}", "start": "0x400000"} for i in range(self.segments)],
            "imports": [],
            "strings": [],
        }

    def m_analysis_status(self, _p):
        return {"done": True, "functions": self.functions, "segments": self.segments, "queue": 0}

    def m_wait_analysis(self, _p):
        if self.slow_wait:
            time.sleep(60)
        return {"done": True, "functions": self.functions, "segments": self.segments, "elapsed": 0.0}

    def m_save_idb(self, p):
        out = p.get("output_path") or (self.path + ".i64")
        try:
            with open(out, "wb") as fh:
                fh.write(b"MOCK_IDB\n")
        except OSError as exc:
            return {"success": False, "error": str(exc)}
        return {"success": True, "path": out}

    # ---- dispatch -----------------------------------------------------------

    def handle(self, method, params):
        fn = getattr(self, "m_" + method, None)
        if fn is not None:
            return fn(params)
        # Everything else: a generic, obviously-mock response. Enough for the
        # coordinator tests, which care about routing and not about IDA output.
        return {"ok": True, "method": method, "params": params, "mock": True}


def serve_request(worker, req):
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params") or {}

    sleep_ms, crash, err, garbage = scan_params(params)
    if sleep_ms:
        time.sleep(sleep_ms / 1000.0)
    if crash:
        log(f"CRASH requested by request id={req_id}")
        os._exit(1)
    if garbage:
        # A non-JSON line on stdout — the coordinator must skip it and still
        # deliver the real reply below.
        with WRITE_LOCK:
            sys.stdout.write("this is not json <<<\n")
            sys.stdout.flush()
    if err is not None:
        emit({"id": req_id, "error": {"code": -32000, "message": err}})
        return

    try:
        result = worker.handle(method, params)
    except Exception as exc:  # pragma: no cover - defensive
        emit({"id": req_id, "error": {"code": -32001, "message": f"{type(exc).__name__}: {exc}"}})
        return
    emit({"id": req_id, "result": result})


def main():
    if len(sys.argv) < 3:
        emit({"event": "init_error", "data": {"stage": "argv", "message": "usage: mock_worker.py <path> <db_dir>"}})
        return 2

    path, db_dir = sys.argv[1], sys.argv[2]
    name = os.path.basename(path).lower()

    if "initfail" in name:
        emit({"event": "init_error",
              "data": {"stage": "open_database", "code": 3, "message": f"mock refuses to open {name}"}})
        return 1

    if "hangready" in name:
        log("hanging without ready (by request)")
        while True:
            time.sleep(3600)

    # A real worker fails here when IDA cannot load the input.
    if not os.path.isfile(path):
        emit({"event": "init_error",
              "data": {"stage": "load_input", "code": 2, "message": f"cannot open input file: {path}"}})
        return 1

    # A real worker writes IDA's database files here; assert the coordinator
    # really handed us a private, writable directory.
    if not os.path.isdir(db_dir):
        emit({"event": "init_error", "data": {"stage": "db_dir", "message": f"db_dir missing: {db_dir}"}})
        return 1
    try:
        with open(os.path.join(db_dir, "mock.marker"), "w") as fh:
            fh.write(path)
    except OSError as exc:
        emit({"event": "init_error", "data": {"stage": "db_dir", "message": f"db_dir not writable: {exc}"}})
        return 1

    worker = Worker(path, db_dir)
    # Fidelity: the real CommandDispatcher::run is single-threaded and serial.
    # Only opt into concurrent dispatch when the file name asks for it.
    concurrent = "concurrent" in name
    emit({"event": "ready", "data": {
        "path": path,
        "db_dir": db_dir,
        "pid": os.getpid(),
        "analyzing": True,          # coordinator must strip this in list_instances
        "functions": worker.functions,
        "segments": worker.segments,
        "processor": "metapc",
        "bits": 64,
        "mock": True,
    }})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            log(f"bad request line: {exc}")
            continue
        if concurrent:
            threading.Thread(target=serve_request, args=(worker, req), daemon=True).start()
        else:
            # Serial dispatch — mirrors the real worker: a slow handler blocks
            # the next request on this worker until it returns.
            serve_request(worker, req)

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
