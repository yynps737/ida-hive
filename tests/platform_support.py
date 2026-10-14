"""Host differences for the repository's real-process tests (Linux/macOS)."""

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def default_worker():
    if sys.platform == "win32":
        return ROOT / "worker" / "build" / "Release" / "ida_mcp_worker.exe"
    build = "build-macos" if sys.platform == "darwin" else "build-linux"
    return ROOT / "worker" / build / "ida_mcp_worker"


def has_runtime(ida_path):
    return bool(ida_path) and any(
        (Path(ida_path) / name).is_file()
        for name in ("libidalib.so", "libidalib.dylib", "idalib.dll")
    )


def runtime_env(ida_path):
    env = os.environ.copy()
    if ida_path:
        key = {"darwin": "DYLD_LIBRARY_PATH", "win32": "PATH"}.get(
            sys.platform, "LD_LIBRARY_PATH"
        )
        env[key] = str(ida_path) + os.pathsep + env.get(key, "")
    return env


def process_pids(command_name, parent_pid=None):
    # /proc does not exist on macOS. ps supplies the same process/parent evidence
    # on both hosts; an unavailable ps must fail the test rather than prove cleanup.
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,args="],
        capture_output=True, text=True, check=True,
    )
    pids = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) != 3 or command_name not in fields[2]:
            continue
        pid, ppid = int(fields[0]), int(fields[1])
        if parent_pid is None or ppid == parent_pid:
            pids.append(pid)
    return pids


def process_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def rss_kb(pid):
    if sys.platform == "darwin":
        result = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True,
        )
        return int(result.stdout.strip()) if result.returncode == 0 else None
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        pass
    return None


def fd_count(pid):
    if sys.platform == "darwin":
        result = subprocess.run(
            ["/usr/sbin/lsof", "-a", "-p", str(pid), "-Ff"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return None
        return sum(line[1:].isdigit() for line in result.stdout.splitlines()
                   if line.startswith("f"))
    try:
        return len(list(Path(f"/proc/{pid}/fd").iterdir()))
    except (FileNotFoundError, PermissionError):
        return None
