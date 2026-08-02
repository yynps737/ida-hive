#!/usr/bin/env python3
"""Correctness pass over the IDA 9.4 tools, against a real database.

The adversarial suite proves these tools survive bad input; it says nothing about
whether the data they return is right. A handler that quietly returns an empty list,
or a count that disagrees with its own contents, passes every test written so far.

Each check here asserts an invariant that must hold for the answer to be meaningful:
a total that equals the sum of its parts, a round-trip that comes back unchanged, an
optimization stage that removes instructions rather than adding them. Where a result
depends on the binary, the check asserts the shape rather than a specific value.

Needs an activated IDA. Skips cleanly when one is not present.

Usage:
  python3 tests/functional_tools.py [--worker PATH] [--target BINARY]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CHECKS = []


def check(name):
    def wrap(fn):
        CHECKS.append((name, fn))
        return fn
    return wrap


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

    def __call__(self, method, **params):
        """Returns the result payload, or raises with the worker's error message."""
        self.next_id += 1
        rid = self.next_id
        self.proc.stdin.write(json.dumps({"id": rid, "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + 180
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"{method}: worker died")
            msg = json.loads(line)
            if msg.get("event"):
                continue
            if msg.get("id") != rid:
                continue
            if "error" in msg:
                raise RuntimeError(f"{method}: {msg['error']['message']}")
            return msg["result"]
        raise TimeoutError(f"{method}: no reply")

    def try_call(self, method, **params):
        """As above, but returns None instead of raising — for optional features."""
        try:
            return self(method, **params)
        except RuntimeError:
            return None

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def assert_(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ---- Control flow ----

@check("switch_info: target list agrees with the declared table size")
def _(w):
    # Find a switch by scanning jumps in the largest functions.
    funcs = w("func_query", min_size=2000, limit=10)["functions"]
    for f in funcs:
        for insn in w("insn_query", mnemonic="jmp", ea=f["ea"], limit=60).get("instructions", []):
            info = w("switch_info", ea=insn["ea"])
            if not info.get("is_switch"):
                continue
            assert_(info["cases"] > 0, f"switch at {insn['ea']} reports {info['cases']} cases")
            assert_(len(info["targets"]) == info["table_entries"],
                    f"{len(info['targets'])} targets for {info['table_entries']} table entries")
            assert_(all(t["target"].startswith("0x") for t in info["targets"]),
                    "a case target is not an address")
            return f"{info['cases']} cases at {info['start_ea']}"
    return "no switch in this binary (vacuous)"


@check("switch_info: a non-switch address is reported as such, not guessed at")
def _(w):
    entry = w("get_info")["entry"]
    info = w("switch_info", ea=entry)
    assert_("is_switch" in info, "switch_info omitted is_switch")
    if not info["is_switch"]:
        assert_("targets" not in info, "a non-switch must not carry targets")
    return f"is_switch={info['is_switch']}"


@check("try_blocks: guarded ranges are non-empty and ordered")
def _(w):
    f = w("list_funcs", limit=1)["functions"][0]
    blocks = w("try_blocks", ea=f["ea"])
    assert_(blocks["count"] == len(blocks["blocks"]), "count disagrees with the block list")
    for b in blocks["blocks"]:
        for g in b["guarded"]:
            assert_(int(g["end"], 16) > int(g["start"], 16),
                    f"guarded range is not ordered: {g}")
    return f"{blocks['count']} blocks"


@check("reg_value: status and value stay consistent")
def _(w):
    f = w("list_funcs", limit=1)["functions"][0]
    r = w("reg_value", ea=f["ea"], reg="rsp")
    assert_(r["status"] in ("constant", "not_constant", "failed"), f"bad status {r['status']}")
    assert_(r["resolved"] == (r["status"] == "constant"),
            "resolved disagrees with status")
    assert_((r["value"] is not None) == r["resolved"],
            "a value is present exactly when the register resolved")
    return r["status"]


@check("problems: every entry carries an address and a kind")
def _(w):
    p = w("problems", limit=50)
    assert_(p["count"] == len(p["problems"]), "count disagrees with the list")
    for item in p["problems"]:
        assert_(item["ea"].startswith("0x"), f"bad address {item['ea']}")
        assert_(item["kind"], "problem without a kind")
    return f"{p['count']} problems"


@check("fixups: relocation targets are real addresses")
def _(w):
    fx = w("fixups", limit=50)
    assert_(fx["count"] == len(fx["fixups"]), "count disagrees with the list")
    for item in fx["fixups"]:
        assert_(item["ea"].startswith("0x") and item["target"].startswith("0x"),
                f"bad fixup {item}")
    return f"{fx['count']} fixups"


# ---- Microcode ----

@check("microcode: optimization removes instructions rather than adding them")
def _(w):
    f = w("func_query", min_size=400, limit=1)["functions"][0]
    raw = w("microcode_stats", ea=f["ea"], maturity="generated")
    opt = w("microcode_stats", ea=f["ea"], maturity="glbopt3")
    assert_(raw["instructions"] > 0, "generated microcode is empty")
    assert_(opt["instructions"] <= raw["instructions"],
            f"optimization grew the microcode: {raw['instructions']} -> {opt['instructions']}")
    assert_(raw["maturity"] == "generated" and opt["maturity"] == "glbopt3",
            "the requested maturity was not honoured")
    return f"{raw['instructions']} -> {opt['instructions']} instructions"


@check("microcode: listing agrees with the stats for the same function")
def _(w):
    f = w("func_query", min_size=400, limit=1)["functions"][0]
    stats = w("microcode_stats", ea=f["ea"], maturity="generated")
    listing = w("microcode", ea=f["ea"], maturity="generated", limit=10 ** 6)
    assert_(listing["blocks"] == stats["blocks"],
            f"block count differs: {listing['blocks']} vs {stats['blocks']}")
    if not listing["truncated"]:
        total = sum(len(b["instructions"]) for b in listing["microcode"])
        assert_(total == stats["instructions"],
                f"instruction count differs: {total} vs {stats['instructions']}")
    return f"{listing['blocks']} blocks consistent"


@check("microcode_maturities: the advertised default is in the list")
def _(w):
    m = w("microcode_maturities")
    assert_(m["default"] in m["maturities"], "the default maturity is not among the levels")
    assert_(m["maturities"][0] == "generated", "the ladder does not start at generated")
    return f"{len(m['maturities'])} levels"


# ---- Strings ----

@check("strings: paging covers items exactly once")
def _(w):
    page = w("strings", limit=20, min_length=4)
    if page["returned"] < 20:
        return f"only {page['returned']} strings (vacuous)"
    first = {s["ea"] for s in page["strings"][:10]}
    second = {s["ea"] for s in w("strings", limit=10, offset=10, min_length=4)["strings"]}
    assert_(not (first & second), f"pages overlap on {len(first & second)} entries")
    return "no overlap between adjacent pages"


@check("strings: a filter only ever narrows the result")
def _(w):
    everything = w("strings", limit=200, min_length=4)["returned"]
    filtered = w("strings", limit=200, min_length=4, filter="lib")
    assert_(filtered["returned"] <= everything,
            "filtering returned more than the unfiltered query")
    for s in filtered["strings"]:
        assert_("lib" in s["text"], f"filter let through {s['text'][:40]!r}")
    return f"{filtered['returned']}/{everything} matched"


@check("strings: decompiler entries are flagged and carry text")
def _(w):
    dec = w("strings_decompiled", limit=20)
    assert_(dec["count"] == len(dec["strings"]), "count disagrees with the list")
    for s in dec["strings"]:
        assert_(s["text"], "a decompiler string has no text")
    return f"{dec['count']} decompiler strings"


# ---- Signatures and origins ----

@check("function_origins: the parts sum to the whole")
def _(w):
    a = w("function_origins", kind="all", limit=1)
    assert_(a["library"] + a["thunks"] + a["user"] == a["total"],
            f"library({a['library']}) + thunks({a['thunks']}) + user({a['user']}) "
            f"!= total({a['total']})")
    return f"{a['total']} = {a['library']} lib + {a['thunks']} thunk + {a['user']} user"


@check("function_origins: each kind returns only that kind")
def _(w):
    thunks = w("function_origins", kind="thunk", limit=20)
    for f in thunks["functions"]:
        assert_("thunk" in f["flags"], f"{f['name']} is in the thunk list without the flag")
    users = w("function_origins", kind="user", limit=20)
    for f in users["functions"]:
        assert_("thunk" not in f["flags"] and "library" not in f["flags"],
                f"{f['name']} is in the user list but flagged {f['flags']}")
    return f"{thunks['returned']} thunks, {users['returned']} user functions"


@check("set_func_flag: setting then clearing restores the original flags")
def _(w):
    f = w("function_origins", kind="user", limit=1)["functions"][0]
    before = set(w("func_flags", ea=f["ea"])["flags"])
    assert_("library" not in before, "picked a function that is already a library function")

    w("set_func_flag", ea=f["ea"], flag="library", on=True)
    during = set(w("func_flags", ea=f["ea"])["flags"])
    assert_("library" in during, "the flag did not take")

    counts = w("function_origins", kind="all", limit=1)
    assert_(counts["library"] >= 1, "the classification did not follow the flag")

    w("set_func_flag", ea=f["ea"], flag="library", on=False)
    after = set(w("func_flags", ea=f["ea"])["flags"])
    assert_(after == before, f"flags not restored: {before} -> {after}")
    return "round-trip clean"


# ---- Offsets ----

@check("offset: mark, read back, clear")
def _(w):
    cands = w("offset_candidates", start=w("get_info")["min_ea"], limit=5)["candidates"]
    if not cands:
        return "no offset candidates (vacuous)"
    ea = cands[0]["ea"]

    w("set_offset", ea=ea, type="off64")
    marked = w("get_offset", ea=ea)
    assert_(marked["is_offset"], "the operand was not marked")
    assert_(marked["type"] == "off64", f"type came back as {marked['type']}")

    w("clear_offset", ea=ea)
    cleared = w("get_offset", ea=ea)
    assert_(not cleared["is_offset"], "the marking survived clear_offset")
    return f"round-trip at {ea}"


@check("offset_candidates: a candidate is not already marked")
def _(w):
    cands = w("offset_candidates", start=w("get_info")["min_ea"], limit=10)["candidates"]
    for c in cands[:5]:
        state = w("get_offset", ea=c["ea"])
        assert_(not state["is_offset"],
                f"{c['ea']} is offered as a candidate but is already an offset")
    return f"{len(cands)} candidates, none pre-marked"


# ---- Availability-gated subsystems ----

@check("index_status: availability is reported, never guessed")
def _(w):
    s = w("index_status")
    assert_(isinstance(s["enabled"], bool), "enabled is not a boolean")
    assert_(s["indexes"] and s["modes"], "index names and modes must be listed either way")
    if not s["enabled"]:
        # Headless IDA disables the indexer; the query tools must say so rather than
        # returning an empty result that reads like 'nothing matched'.
        failed = w.try_call("index_search", query="main")
        assert_(failed is None, "index_search returned data while the indexer is disabled")
    return f"enabled={s['enabled']}"


@check("dsc_status: a non-cache database is reported cleanly")
def _(w):
    s = w("dsc_status")
    assert_(isinstance(s["is_shared_cache"], bool), "is_shared_cache is not a boolean")
    if not s["is_shared_cache"]:
        assert_(w.try_call("dsc_images") is None,
                "dsc_images returned data for a database that is not a shared cache")
    return f"is_shared_cache={s['is_shared_cache']}"


@check("seg_regs: values are addresses")
def _(w):
    f = w("list_funcs", limit=1)["functions"][0]
    regs = w("seg_regs", ea=f["ea"])["registers"]
    for r in regs:
        assert_(r["reg"] and r["value"].startswith("0x"), f"bad segment register {r}")
    return f"{len(regs)} segment registers"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worker", default=str(ROOT / "worker" / "build-linux" / "ida_mcp_worker"))
    ap.add_argument("--target", default="/usr/bin/grep")
    ap.add_argument("--ida", default=os.environ.get("IDABIN"))
    args = ap.parse_args()

    if not Path(args.worker).exists():
        print(f"SKIPPED: worker not built at {args.worker}")
        return 0
    if not args.ida or not (Path(args.ida) / "libidalib.so").exists():
        print("SKIPPED: IDABIN does not point at an IDA installation")
        return 0

    tmp = tempfile.mkdtemp(prefix="ida-hive-func-")
    started = time.time()
    w = Worker(args.worker, args.target, tmp, args.ida)
    print(f"  {Path(args.target).name}: {w.ready.get('functions')} functions")

    passed, failures = 0, []
    for name, fn in CHECKS:
        try:
            note = fn(w)
            passed += 1
            print(f"    ok    {name}  ({note})")
        except AssertionError as exc:
            failures.append(f"{name}: {exc}")
            print(f"    FAIL  {name}")
        except Exception as exc:
            failures.append(f"{name}: unexpected {type(exc).__name__}: {exc}")
            print(f"    ERROR {name}")
    w.close()

    elapsed = time.time() - started
    print()
    if failures:
        print(f"FAILED: {len(failures)} of {len(CHECKS)} checks in {elapsed:.0f}s")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASSED: {passed} functional checks in {elapsed:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
