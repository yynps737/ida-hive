#!/usr/bin/env python3
"""Real-worker exit regression: EOF/shutdown, raw inputs and saved databases.

Requires an activated IDA with a native decompiler and a C compiler. Checks the
process exit status, live database isolation and cleanup, rather than killing the
worker after its last reply (which hides failures in close_database()).
"""

import argparse
import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from platform_support import default_worker, has_runtime, runtime_env


class Worker:
    def __init__(self, worker, target, private, ida_path):
        self.private = private
        self.messages = queue.Queue()
        self.errors = []
        self.next_id = 0
        self.proc = subprocess.Popen(
            [str(worker), str(target), str(private)], env=runtime_env(ida_path),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        self.readers = [
            threading.Thread(target=self._stdout, daemon=True),
            threading.Thread(target=self._stderr, daemon=True),
        ]
        for reader in self.readers:
            reader.start()

    def _stdout(self):
        for line in self.proc.stdout:
            try:
                self.messages.put(json.loads(line))
            except ValueError:
                self.messages.put({"invalid_stdout": line.rstrip()})
        self.messages.put(None)

    def _stderr(self):
        self.errors.extend(self.proc.stderr)

    def receive(self):
        message = self.messages.get(timeout=60)
        assert message is not None, "worker exited before reply: " + "".join(self.errors)
        assert "invalid_stdout" not in message, f"non-JSON stdout: {message}"
        return message

    def ready(self):
        message = self.receive()
        assert message.get("event") == "ready", f"not ready: {message}"
        assert message["data"]["functions"] >= 2, f"fixture not analysed: {message}"
        assert any(p.is_file() for p in self.private.glob("db.*")), \
            "no live database files in the private directory"

    def call(self, method, **params):
        self.next_id += 1
        self.proc.stdin.write(json.dumps({
            "id": self.next_id, "method": method, "params": params,
        }) + "\n")
        self.proc.stdin.flush()
        while True:
            reply = self.receive()
            if "event" in reply:
                continue
            assert reply.get("id") == self.next_id, f"wrong reply: {reply}"
            assert "result" in reply and "error" not in reply, f"{method}: {reply}"
            return reply["result"]

    def finish(self, shutdown=False):
        if shutdown:
            assert self.call("shutdown") == {"shutdown": True}
            # Keep stdin open until exit: shutdown must work without a later EOF.
        else:
            self.proc.stdin.close()
        self.proc.wait(timeout=15)
        for reader in self.readers:
            reader.join(timeout=5)
            assert not reader.is_alive(), "worker output did not close"
        diagnostic = "".join(self.errors)
        assert self.proc.returncode == 0, \
            f"worker exit={self.proc.returncode}: {diagnostic}"
        assert "30500" not in diagnostic and "FATAL ERROR" not in diagnostic, diagnostic
        assert self.messages.get_nowait() is None, "unexpected reply during exit"
        assert self.messages.empty(), "output after EOF"
        leftovers = [p.name for p in self.private.iterdir()
                     if p.suffix.lower() not in (".i64", ".idb")]
        assert not leftovers, f"unpacked database/lock files left after close: {leftovers}"

    def cleanup(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=5)
        for reader in self.readers:
            reader.join(timeout=5)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            stream.close()


def snapshot(directory):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.iterdir() if p.is_file()}


def decompile_and_microcode(worker):
    result = worker.call("decompile", ea="main")
    assert "7" in result["pseudocode"] and "add_values" in result["pseudocode"], result
    stats = worker.call("microcode_stats", ea="main", maturity="generated")
    assert stats["instructions"] > 0 and stats["blocks"] > 0, stats


def run(args, root):
    source = root / "input space 中文"
    source.mkdir()
    c_file = source / "addition.c"
    c_file.write_text(
        "__attribute__((noinline)) int add_values(int a, int b) { return a + b; }\n"
        "int main(int argc, char **argv) { return add_values(argc, 7); }\n"
    )
    compiler = os.environ.get("CC") or shutil.which("cc")
    assert compiler, "a C compiler is required for the native exit fixture"
    binary = source / ("addition space" if os.name == "nt" else "addition space \\ 中文")
    subprocess.run([compiler, "-O0", "-o", str(binary), str(c_file)],
                   check=True, capture_output=True, text=True, timeout=60)
    # The raw open must create its own private database, even when a neighbouring
    # .i64 exists. It must never load or rewrite this deliberately invalid sibling.
    Path(str(binary) + ".i64").write_bytes(b"unchanged neighbouring database sentinel\n")
    original = snapshot(source)
    if os.name != "nt":
        source.chmod(0o555)  # A raw open cannot create even transient files here.
    saved = root / "saved space 中文.i64"
    passed = 0

    private = root / "save private"
    private.mkdir()
    worker = Worker(args.worker, binary, private, args.ida)
    try:
        worker.ready()
        assert snapshot(source) == original, "source directory changed during open"
        decompile_and_microcode(worker)
        worker.call("save_idb", output_path=str(saved))
        assert saved.is_file() and saved.stat().st_size > 0, "database not saved"
        worker.finish()
        assert snapshot(source) == original, "source directory changed during save/exit"
        passed += 1
        print("  ok  raw save + decompile + EOF")
    finally:
        worker.cleanup()

    saved_digest = hashlib.sha256(saved.read_bytes()).hexdigest()
    cases = [
        ("raw idle EOF", binary, False, "idle"),
        ("raw ping EOF", binary, False, "ping"),
        ("raw idle shutdown", binary, True, "idle"),
        ("raw decompile EOF", binary, False, "decompile"),
        ("raw decompile shutdown", binary, True, "decompile"),
        ("saved idle EOF", saved, False, "idle"),
        ("saved decompile EOF", saved, False, "decompile"),
        ("saved decompile shutdown", saved, True, "decompile"),
    ]
    for index, (name, target, shutdown, action) in enumerate(cases):
        private = root / f"private space 中文 {index}"
        private.mkdir()
        worker = Worker(args.worker, target, private, args.ida)
        try:
            worker.ready()
            assert snapshot(source) == original, "source directory changed while worker was live"
            if action == "ping":
                assert worker.call("ping") == {"pong": True}
            elif action == "decompile":
                decompile_and_microcode(worker)
            worker.finish(shutdown)
            assert snapshot(source) == original, "source directory changed during exit"
            assert hashlib.sha256(saved.read_bytes()).hexdigest() == saved_digest, \
                "the original saved database was changed"
            passed += 1
            print(f"  ok  {name}")
        finally:
            worker.cleanup()

    directory_input = root / "input directory"
    directory_input.mkdir()
    for index, target in enumerate((root / "missing input", directory_input)):
        private = root / f"failed open {index}"
        private.mkdir()
        worker = Worker(args.worker, target, private, args.ida)
        try:
            event = worker.receive()
            assert event.get("event") == "init_error", f"missing loader error: {event}"
            assert event["data"]["stage"] in ("init_database", "open_database"), event
            worker.proc.stdin.close()
            worker.proc.wait(timeout=15)
            for reader in worker.readers:
                reader.join(timeout=5)
            assert worker.proc.returncode != 0, "failed loader reported a successful exit"
            diagnostic = "".join(worker.errors)
            assert "30500" not in diagnostic and "FATAL ERROR" not in diagnostic, diagnostic
            assert snapshot(source) == original, "failed open changed source files"
            passed += 1
            print(f"  ok  {target.name}: init_error + nonzero exit")
        finally:
            worker.cleanup()
    print(f"PASSED: {passed} worker lifecycle checks (exit 0, isolated files, clean close)")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", default=str(default_worker()))
    parser.add_argument("--ida", default=os.environ.get("IDABIN"))
    args = parser.parse_args()
    if not Path(args.worker).is_file() or not has_runtime(args.ida):
        print("SKIPPED: worker lifecycle checks need a built worker and a runnable IDA")
        return 0
    args.worker = Path(args.worker).resolve()
    try:
        with tempfile.TemporaryDirectory(prefix="ida-hive-lifecycle-") as directory:
            root = Path(directory).resolve()
            try:
                run(args, root)
            finally:
                source = root / "input space 中文"
                if source.exists():
                    source.chmod(0o755)
    except Exception as error:
        print(f"FAILED: {type(error).__name__}: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
