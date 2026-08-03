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
import shutil
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
        self.worker, self.ida_path = worker, ida_path
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


BITFIELD_SRC = (
    "struct bits_t { unsigned a:1; unsigned b:3; unsigned c:12; signed s:5;\n"
    "                long long pad1; long long pad2; };\n"
    "struct bits_t g_bits;\n"
    "int main(void) { return g_bits.a; }\n")


DWARF_TYPE_SRC = (
    "struct record_t { long a; long b; char pad[64]; };\n"
    "struct record_t g;\n"
    "long f(struct record_t *r) { return r->a + r->b; }\n"
    "int main(void) { return (int)f(&g); }\n")


SIGNED_SRC = (
    "#include <stdint.h>\n"
    "int64_t g_i64 = -2; int32_t g_i32 = -2; int16_t g_i16 = -2; int8_t g_i8 = -2;\n"
    "uint32_t g_u32 = 4294967294u;\n"
    "int main(void){ return (int)(g_i64+g_i32+g_i16+g_i8+g_u32); }\n")


def _build_sample(w, source):
    """Compiles a sample and opens it in its own worker.

    Returns (worker, tempdir) or a note explaining why the check is vacuous. The
    system binaries these tests run against are stripped and carry no struct types,
    so anything type-shaped needs a sample built here.
    """
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        return "no compiler for a debug-info sample (vacuous)"

    tmp = tempfile.mkdtemp(prefix="ida-hive-sample-")
    c_file, binary, db = Path(tmp) / "s.c", Path(tmp) / "s", Path(tmp) / "db"
    c_file.write_text(source)
    if subprocess.run([cc, "-g", "-O0", "-o", str(binary), str(c_file)],
                      capture_output=True).returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        return "the sample did not compile (vacuous)"
    db.mkdir()
    return Worker(w.worker, binary, db, w.ida_path), tmp


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


@check("switch_info: every case target lands inside the database")
def _(w):
    # A table of signed, table-relative entries read as unsigned produces targets that
    # are still well-formed addresses, just impossible ones. Only a range check catches it.
    info = w("get_info")
    lo, hi = int(info["min_ea"], 16), int(info["max_ea"], 16)
    for f in w("func_query", min_size=2000, limit=10)["functions"]:
        for insn in w("insn_query", mnemonic="jmp", ea=f["ea"], limit=60).get("instructions", []):
            sw = w("switch_info", ea=insn["ea"])
            if not sw.get("is_switch"):
                continue
            for t in sw["targets"]:
                addr = int(t["target"], 16)
                assert_(lo <= addr < hi,
                        f"case {t['index']} targets {t['target']}, outside [{info['min_ea']},{info['max_ea']})")
            return f"{len(sw['targets'])} targets in range at {sw['start_ea']}"
    return "no switch in this binary (vacuous)"


@check("switch_info: the idiom resolves from its start, not only from the jump")
def _(w):
    # get_switch_parent answers at the jump targets only; the bounds check and table
    # load that precede the jump resolve through neither it nor get_switch_info.
    for f in w("func_query", min_size=2000, limit=10)["functions"]:
        for insn in w("insn_query", mnemonic="jmp", ea=f["ea"], limit=60).get("instructions", []):
            sw = w("switch_info", ea=insn["ea"])
            if not sw.get("is_switch"):
                continue
            at_start = w("switch_info", ea=sw["start_ea"])
            assert_(at_start.get("is_switch"),
                    f"start_ea {sw['start_ea']} is reported as not a switch by the tool that named it")
            assert_(at_start["jump_table"] == sw["jump_table"],
                    f"start_ea resolves to table {at_start['jump_table']}, the jump to {sw['jump_table']}")
            return f"{sw['start_ea']} and {sw['ea']} agree"
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


@check("get_offset: an operand resolves to its own target, not to the base")
def _(w):
    # refinfo_t.target is unset for most references; the target is computed from the
    # operand value. Reading the field and falling back to base reports address 0,
    # which has a name, so a wrong answer is indistinguishable from a right one.
    for f in w("func_query", min_size=2000, limit=6)["functions"]:
        for insn in w("disasm", ea=f["ea"], count=200).get("lines", []):
            for n in (0, 1):
                off = w("get_offset", ea=insn["ea"], operand=n)
                if not off.get("is_offset"):
                    continue
                assert_(off["target"] is not None,
                        f"{insn['ea']} carries reference info but resolves to nothing")
                refs = [x["to"] for x in w("xrefs_from", ea=insn["ea"]).get("xrefs", [])
                        if x.get("type") == "data"]
                if refs:
                    assert_(off["target"] in refs,
                            f"resolved {off['target']}, xrefs say {refs}")
                return f"{insn['ea']} -> {off['target']} ({off['name']})"
    return "no marked offset operand in this binary (vacuous)"


@check("offset_candidates: a candidate is not already marked")
def _(w):
    cands = w("offset_candidates", start=w("get_info")["min_ea"], limit=10)["candidates"]
    for c in cands[:5]:
        state = w("get_offset", ea=c["ea"])
        assert_(not state["is_offset"],
                f"{c['ea']} is offered as a candidate but is already an offset")
    return f"{len(cands)} candidates, none pre-marked"


@check("wait_analysis: work queued after the initial pass is driven to completion")
def _(w):
    # idalib has no background analysis thread. Anything queued after open — the
    # re-analysis that redefining an applied type schedules, for one — sits there until
    # the host drives it, so polling auto_is_ok() alone can only ever reach the timeout.
    #
    # Redefining a type only queues work where that type is already applied across the
    # database, which on a stripped binary it is not.
    built = _build_sample(w, DWARF_TYPE_SRC)
    if isinstance(built, str):
        return built
    d, tmp = built
    try:
        assert_(d("wait_analysis", max_seconds=60)["done"], "the sample never settles")
        d("declare_type", decl="struct record_t { long long a; long long b; char pad[128]; };")

        pending = d("analysis_status")
        assert_(not pending["done"],
                "redefining an applied type queued nothing; the trigger no longer holds")

        result = d("wait_analysis", max_seconds=60)
        assert_(result["done"] and not result.get("timeout"),
                f"wait_analysis gave up after {result.get('elapsed')}s")
        assert_(d("analysis_status")["done"],
                "the status still reports pending work after wait_analysis returned done")
        return f"queued, then drained in {result['elapsed']:.2f}s"
    finally:
        d.close()
        shutil.rmtree(tmp, ignore_errors=True)


@check("get_bytes: a negative size is named, not reported as too large")
def _(w):
    try:
        w("get_bytes", ea=w("get_info")["min_ea"], size=-16)
    except RuntimeError as exc:
        assert_("negative" in str(exc).lower(), f"a negative size was rejected as: {exc}")
        return "rejected on its own terms"
    raise AssertionError("a negative size was accepted")


@check("read_struct: a bitfield reports its own bits, not the bytes around it")
def _(w):
    # udm_t carries offset and size in bits. Dividing both by 8 truncates anything
    # narrower than a byte to nothing and loses the bit position of the rest, so the
    # answer for a 1-bit flag is either empty or a neighbouring byte's value.
    built = _build_sample(w, BITFIELD_SRC)
    if isinstance(built, str):
        return built
    d, tmp = built
    try:
        ea = next(g["ea"] for g in d("list_globals", limit=400)["globals"] if g["name"] == "g_bits")
        d("patch_bytes", ea=ea, hex="ABCDEF12")   # little-endian uint32 0x12EFCDAB
        got = {f["name"]: f for f in d("read_struct", ea=ea, struct_name="bits_t")["fields"]}

        # Hand-computed from 0x12EFCDAB: bit 0, bits 1-3, bits 4-15, bits 16-20.
        for name, width, want in (("a", 1, 1), ("b", 3, 5), ("c", 12, 0xCDA), ("s", 5, 15)):
            f = got[name]
            assert_(f.get("bit_width") == width,
                    f"{name}: bit_width {f.get('bit_width')}, expected {width}")
            assert_(f.get("value") == want,
                    f"{name}: value {f.get('value')}, expected {want}")

        # The sign bit of a signed bitfield must extend, not read as a large positive.
        d("patch_bytes", ea=ea, hex="00001F00")   # bits 16-20 all set
        s = next(f for f in d("read_struct", ea=ea, struct_name="bits_t")["fields"]
                 if f["name"] == "s")
        assert_(s["value"] == -1, f"a 5-bit signed 0b11111 came back as {s['value']}")
        return "4 widths correct, sign extension correct"
    finally:
        d.close()
        shutil.rmtree(tmp, ignore_errors=True)


@check("an address with no stored bytes is reported as such, never as zeros")
def _(w):
    # get_bytes stops at the first byte the database holds no value for. Ignoring the
    # count leaves the caller's zero-filled buffer in place, so .bss reads back as a
    # variable whose value is 0 rather than one with no value at all.
    built = _build_sample(w, BITFIELD_SRC)
    if isinstance(built, str):
        return built
    d, tmp = built
    try:
        bss = [x for x in d("list_segments")["segments"] if x.get("name") == ".bss"]
        assert_(bss, "the sample has no .bss")
        start = bss[0]["start"]

        raw = d("get_bytes", ea=start, size=32)
        assert_(raw["size"] < 32 and raw.get("truncated") is True,
                f"a read over unstored bytes returned {raw['size']} bytes without saying so")
        assert_(raw.get("requested") == 32, "the requested size is not reported back")

        g = d("get_global_value", target=start)
        assert_(g.get("has_value") is False and g.get("value") is None,
                f"an uninitialized global reported a value: {g.get('value')}")

        ea = next(x["ea"] for x in d("list_globals", limit=400)["globals"] if x["name"] == "g_bits")
        d("patch_bytes", ea=ea, hex="ABCDEF12")   # 4 of the struct's bytes, no more
        st = d("read_struct", ea=ea, struct_name="bits_t")
        assert_(st.get("truncated") is True and st.get("stored") == 4,
                f"read_struct did not report the shortfall: stored={st.get('stored')}")
        beyond = [f for f in st["fields"] if f.get("no_data")]
        assert_(beyond, "fields past the stored bytes were emitted as zeros")
        assert_(all(f["hex"] is None for f in beyond), "a field with no data still carries hex")
        return f"{raw['size']}/32 bytes stored, {len(beyond)} fields without data"
    finally:
        d.close()
        shutil.rmtree(tmp, ignore_errors=True)


@check("get_global_value: a value is read as the type reported beside it")
def _(w):
    # The response carries the variable's type. Reporting the unsigned reading of a
    # signed one contradicts it in the same object: an int32_t holding 0xFFFFFFFE is
    # -2, and 4294967294 is a number that type cannot hold.
    built = _build_sample(w, SIGNED_SRC)
    if isinstance(built, str):
        return built
    d, tmp = built
    try:
        for name, want in (("g_i64", -2), ("g_i32", -2), ("g_i16", -2), ("g_i8", -2),
                           ("g_u32", 4294967294)):
            r = d("get_global_value", target=name)
            assert_(r.get("value") == want,
                    f"{name} ({r.get('type')}) came back as {r.get('value')}, expected {want}")
        return "4 signed widths and 1 unsigned correct"
    finally:
        d.close()
        shutil.rmtree(tmp, ignore_errors=True)


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



# ---- Database internals ----

@check("netnode: a node you own round-trips; IDA's own are refused")
def _(w):
    name = "idahive_functional_probe"
    w("netnode_set", name=name, value="probe-value")
    got = w("netnode_get", name=name)
    assert_(got["value"] == "probe-value", f"value came back as {got.get('value')!r}")
    assert_(not got["reserved"], "a self-named node was reported as reserved")

    # Writing to IDA's own storage must be refused, not attempted.
    refused = w.try_call("netnode_set", name="$ imports", value="x")
    assert_(refused is None, "a reserved netnode accepted a write")
    return "round-trip clean, reserved node protected"


@check("netnode_list: reserved nodes are flagged, and can be filtered out")
def _(w):
    everything = w("netnode_list", limit=200)
    reserved = [n for n in everything["nodes"] if n["reserved"]]
    for n in reserved:
        assert_(n["name"].startswith("$ "), f"{n['name']!r} flagged reserved without the prefix")

    without = w("netnode_list", limit=200, include_reserved=False)
    assert_(all(not n["reserved"] for n in without["nodes"]),
            "include_reserved=false still returned reserved nodes")
    assert_(without["returned"] <= everything["returned"],
            "excluding reserved nodes returned more entries")
    return f"{len(reserved)}/{everything['returned']} reserved"


@check("parser_status: the language list is stable and non-empty")
def _(w):
    s = w("parser_status")
    assert_(s["languages"], "no source languages reported")
    for lang in ("c", "cpp", "swift", "go"):
        assert_(lang in s["languages"], f"{lang} missing from the language list")
    return f"{len(s['languages'])} languages"


@check("select_parser: an unknown language is refused, not silently ignored")
def _(w):
    assert_(w.try_call("select_parser", language="cobol") is None,
            "an unknown language was accepted")
    return "unknown language refused"


@check("undo: status is consistent with what undo/redo will do")
def _(w):
    before = w("undo_status")
    assert_(isinstance(before["can_undo"], bool) and isinstance(before["can_redo"], bool),
            "can_undo/can_redo are not booleans")
    assert_((before["undo"] is not None) == before["can_undo"],
            "a label is present exactly when undo is possible")

    # Undoing with nothing to undo must fail rather than report a false success.
    if not before["can_undo"]:
        assert_(w.try_call("undo") is None, "undo succeeded with an empty history")
    return f"can_undo={before['can_undo']}"


@check("undo_point: creating a point makes undo available")
def _(w):
    w("undo_point", tag="functional-probe")
    f = w("function_origins", kind="user", limit=1)["functions"][0]
    w("set_comment", ea=f["ea"], comment="undo probe")
    after = w("undo_status")
    assert_(after["can_undo"], "an edit after an undo point left nothing to undo")
    # The label comes from IDA's own record of the edits, not from the tag above.
    assert_(after["undo"] is not None, "can_undo is set but no label field came back")
    return "an edit after a point becomes undoable"


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
    try:
        return _run_checks(args, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run_checks(args, tmp):
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
