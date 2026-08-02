# ida-hive — tool-surface bug backlog (production validation, independently re-confirmed)

Found by 20 Opus agents driving the **live MCP tools** through real RE workflows, then
**independently re-confirmed by me** via source review (every `worker/commands/cmd_*.cpp`) AND
live reproduction against `/usr/bin/bash` & `/usr/bin/grep`. Status legend:
**[CONFIRMED]** reproduced or proven at source · **[CLEARED]** could not reproduce / not a bug ·
**[NOT-REPRO]** plausible at source but not reproducible in isolation · **[BY-DESIGN]** intended,
document only.

These are pre-existing defects in the **worker command implementations**, independent of the
concurrency fix (PR #2). The concurrency/stability layer held up: 20/20 agents connected, no
crash/hang/leak. Suggest a separate "tool-surface fixes" PR.

---

## 🔴 HIGH

### H1 — [CONFIRMED] `ea`/address params reject function names → leak `{"error":"stoull"}`
- **Live:** `lookup_func("main")` → `0x33700`, but `decompile(ea="main")` → `{"error":"stoull"}`.
- **Affected:** every handler that calls `parse_ea` — decompile, disasm, xrefs_to, xrefs_from,
  callees, xref_query, xrefs_to_field, analyze_batch, export_funcs, get_int, get_bytes,
  patch_bytes, stack/type/graph/composite tools… (`grep -c parse_ea` across cmd_*.cpp).
- **Root cause:** `worker/util.h::parse_ea` (line 28-36) does `std::stoull(...)` and lets the
  exception (`what()=="stoull"`) propagate. The schema (e.g. `tools.rs:169`) says ea accepts a
  "function name". `lookup_func`/`get_global_value` already do the right thing
  (`cmd_core.cpp:101-104`, `cmd_memory.cpp:133-135`).
- **Fix:** in `parse_ea`, on `stoull` failure fall back to `get_name_ea(BADADDR, s)`; if still
  `BADADDR`, throw a clear message (`"could not resolve '<x>' as address or name"`). Single fix
  unblocks ~20 tools. Highest priority.

### H2 — [CONFIRMED-source] `declare_stack` retype is non-functional; false success
- **Source:** `cmd_stack.cpp:107-127`. The retype path parses the type then calls
  `modify_user_lvar_info(f->start_ea, MLI_TYPE, lsi)` which returns false (agent: every retype of
  size-compatible canonical types failed). And `success = renamed || retyped` (line 127) → a
  rename+retype returns `success:true` while the type is silently dropped.
- **Fix:** make the lvar retype actually apply (verify `lsi.ll`/locator construction; may need
  `MLI_NAME|MLI_TYPE` together or `save_user_lvar_settings`); surface parse/apply errors; never
  report `success:true` when a requested retype failed.

---

## 🟡 MEDIUM

### M1 — [CONFIRMED-source] bogus self-edges / fall-through & jumps counted as "calls"
- **Affected + source:** `callees` (`cmd_analysis.cpp:160-174`, XREF_FAR, no self-exclusion, no
  dedup), `callgraph` (`cmd_graph.cpp:116-129`), `func_profile` (`cmd_graph.cpp:221-233`,
  XREF_ALL), `analyze_function` (`cmd_composite.cpp:81-92`), `analyze_component`
  (`cmd_composite.cpp:324-345`).
- **Root cause:** the callee loops walk `xrefblk_t` over all code xrefs incl. **ordinary
  fall-through flow** (target = next insn → same function → SELF) and intra-function jumps, and
  don't dedup. That's why every function lists itself as its own callee and large funcs show many
  duplicate self-edges.
- **Fix:** only count CALL xrefs (`xb.type == fl_CN || xb.type == fl_CF`), require
  `target->start_ea != f->start_ea`, and dedup. Apply uniformly to all five.

### M2 — [CONFIRMED] `append_comments` returns success but text doesn't appear
- **Live:** `set_comment(0x33704,"FIRST")` shows; `append_comments(0x33704,"SECOND")` → success,
  but `disasm` still shows only `; FIRST`.
- **Root cause:** `cmd_modify.cpp:54-69` joins with `"\n"` → multi-line comment whose continuation
  isn't rendered by `disasm`'s single-line output; also ignores `set_cmt`'s return (always
  `success:true`).
- **Fix:** append with an inline separator (e.g. `" | "`) instead of `\n`; check `set_cmt` return.

### M3 — [CONFIRMED] `disasm` ignores requested ea, snaps to function start
- **Live:** `disasm(ea=0x33710,count=3)` returned lines from **0x33700** (func start).
- **Root cause:** `cmd_analysis.cpp:69-74` sets `start = f->start_ea` and `curr = start`.
- **Fix:** `ea_t start = ea;` (start at the requested address, still bound by `f->end_ea` if in a
  function).

### M4 — [CONFIRMED-source] `diff_before_after` always `changed:false`
- **Source:** `cmd_composite.cpp:370-433`. Decompiles before, applies edit, decompiles after — but
  Hex-Rays returns the **cached** cfunc, so before==after even though the edit persisted.
- **Fix:** `mark_cfunc_dirty(f->start_ea)` (or clear the cache) before the "after" decompile.

### M5 — [CONFIRMED-source] `set_type` fails without a trailing `;`
- **Source:** `cmd_types.cpp:25` `apply_cdecl` requires a complete decl ending `;`. The tool's own
  doc example omits it (`'int __fastcall foo(int a1)'`).
- **Fix:** append `;` if absent before `apply_cdecl`; on failure return a clear message.

### M6 — [NOT-REPRO] `wait_analysis` blocked full timeout on grep (agent), not reproducible solo
- **Solo:** `wait_analysis(grep)` → `done:true, elapsed:0.0`; `analysis_status` → done. Works.
- **Source plausibility:** `worker.cpp` wait loop polls `auto_is_ok()`+`qsleep` and does nothing to
  drive the auto queue, so IF analysis is genuinely incomplete it can never finish. Likely a
  load-dependent state during the 20-agent run. **Investigate under concurrent load.**

### M7 — [CONFIRMED] `int_convert` always errors "No active session: default"
- **Source:** `tools.rs:426` calls `route(..., None, "int_convert", ...)` → routes to session
  "default"; if not open, `route` errors. It's a pure number-conversion utility (`cmd_search.cpp:209`).
- **Fix:** handle `int_convert` in the coordinator/tools.rs directly (compute in Rust, or run on any
  live worker), never requiring a named session.

### M8 — [CONFIRMED-source] `lookup_func` can't resolve export/alias names
- **Source:** `cmd_core.cpp:104` `get_name_ea` matches only the primary/registered name. `malloc`
  whose primary name is `__libc_malloc` / `_IO_getc` for `getc` → "Not found".
- **Fix:** also try import/export/demangled names, or fall back to entrypoint-name lookup.

### M9 — [CONFIRMED-source] `get_global_value` over-reads untyped globals
- **Source:** `cmd_memory.cpp:140-144` defaults `vsize=8` when there's no `tinfo` → reads 8 bytes for
  a 4-byte untyped global, spilling into the adjacent variable.
- **Fix:** when no type, use `get_item_size(ea)` / `get_item_end(ea)-ea` to size the read.

### M10 — [CONFIRMED-source] `save_idb` fails silently on unwritable path
- **Source:** `cmd_core.cpp` save_idb returns `{success:false}` (no error string) when the write
  fails (e.g. `/usr/bin/ls` resolves to a root-owned dir). With the atomic-rename change the tmp
  write/rename fails the same silent way.
- **Fix:** include an error message; consider a writable fallback dir.

### M11 — [CONFIRMED-source] `xref_query` `from` rows put the destination's func in `func`
- **Source:** `cmd_analysis.cpp:217` uses `get_func(xb.to)` for `from`-direction rows (should be
  the source func, as `to`-rows use `get_func(xb.from)` at line 199). Inconsistent.
- **Fix:** for `from` rows, set `func` from the source (the queried ea's function), or document the
  intended semantics and make both directions consistent.

---

## ⚪ LOW (UX / cosmetic)

- **L2 — [CONFIRMED]** `declare_type` returns `parsed:0` on success — `cmd_types.cpp:90` `parse_decls`
  returns the **error count**, not parsed count. Rename field to `errors` or report types added.
- **L3 — [CONFIRMED]** `list_instances` shows stale `info.analyzing:true` — coordinator returns the
  cached `ready_data` snapshot taken at open. Refresh or drop the field.
- **L4 — [CONFIRMED]** `survey_binary` `ordinal` == EA-in-decimal for ELF — `cmd_composite.cpp:192-196`
  (`get_entry_ordinal` returns the EA for ELF). Omit for ELF or label clearly.
- **L5 — [CONFIRMED]** `type_inspect` size = 18446744073709551615 (BADSIZE) for function types —
  `cmd_types.cpp:75`. Return null/0 when `is_func()` or size==BADSIZE.
- **L6 — [CONFIRMED]** `undefine(size=0)` → `success:true` no-op — `cmd_modify.cpp:126-129`
  (`del_items` with 0). Treat size 0 as the item size, or reject.
- **L7 — [CONFIRMED]** `imports` default `limit=500` (`cmd_search.cpp:87`) overflows the MCP token
  cap on libs with many imports. Lower default (e.g. 100) / add pagination hint.
- **L1 — [CONFIRMED]** `lookup_func` uses param `target` while all ea-tools use `ea` — inconsistent.
  (Tied to H1's fix; consider aliasing `ea`.)

---

## ✅ CLEARED / BY-DESIGN

- **X1 — [CLEARED]** No server hang on adversarial input. Live: `decompile(0xdeadbeef)`,
  `get_bytes(size=5e6)`, `xrefs_to(0xdeadbeef)`, `set_type(garbage)`, `rename(BADADDR)` all returned
  promptly with clean errors; server stayed healthy. The 20-agent "stall" was the LLM agent, not the
  server. No fix needed (single-threaded worker + input caps).
- **L8/L9 — [BY-DESIGN]** `close_session` reports `{closed:true}` while a shared worker stays alive
  for a sibling session, and two sessions on the same file share ONE mutable DB. These are the
  intended dedup + refcount behavior from PR #2. **Action:** document; make `close_session` report
  whether the worker was actually stopped; consider an opt-in "private copy per session" if callers
  need isolation for concurrent modification.

---

## Suggested fix order (tomorrow)
1. **H1** (`parse_ea` name fallback) — one change, unblocks ~20 tools. Biggest win.
2. **M7** (int_convert), **M3** (disasm start), **M5** (set_type `;`), **M2** (append separator),
   **M4** (cfunc dirty) — all small, high-value.
3. **M1** (call-graph correctness across 5 tools) — shared helper.
4. **H2** (declare_stack retype) — needs SDK investigation.
5. **M8/M9/M10/M11** + LOW batch.

---

## Appendix — license-free validation pass (coordinator suite + C++ build/static analysis)

Found without an activated IDA license, via `tests/build_check.sh`
(cargo build + real-SDK CMake build of the worker + `clang-tidy`/`-Wall -Wextra`)
and the `tests/test_coordinator.py` end-to-end suite. These are separate from the
tool-surface bugs above.

- **V1 — [FIXED] `server_health` reported `max_slots: 100` unconditionally**
  (`src/tools.rs`, the `server_health` handler). It ignored `IDA_MCP_MAX_SLOTS`
  and `config.max_slots`. The real cap was enforced correctly by `open()`
  (`Max slots (N) reached`), so only the *reported* number was wrong — but it
  misled capacity planning by an MCP client. **Fixed:** added
  `Coordinator::max_slots()` and `server_health` now reports it. Regression
  guard: `test_server_health_reports_configured_max_slots` (asserts the
  configured cap and the default).

- **V2 — [CONFIRMED] `enum_upsert` silently ignores its `bitfield` parameter**
  (`worker/commands/cmd_types.cpp`). The value is read (`params.value("bitfield",
  false)`) and documented in the comment, then never used — the enum is always
  built as a plain C `enum { … }`. A caller passing `bitfield: true` (expecting a
  bitmask enum) gets a plain enum with no error. **Fix:** apply the bitfield flag
  after `parse_decls` (e.g. `set_enum_flag`/tinfo bitmask), or reject the param.

- **V3 — [CONFIRMED, cosmetic] license-gate `init_error` carries a garbage `code`**
  (`worker/worker.cpp`, `init_library()` path). The `code` varies run-to-run
  (uninitialized on the failure path); the `message` (`idalib init_library()
  failed (check IDA license/activation)`) is correct. **Fix:** set a stable code
  or drop the field on this path.

- **[CLEARED] C++ worker static analysis.** All 10 translation units compile +
  link against the real IDA 9.2 SDK. `-Wall -Wextra`: 8 benign warnings
  (unused params/var). `clang-tidy` bugprone/analyzer/cert: no real defects —
  the two empty `catch` blocks (`cmd_core.cpp`, `cmd_memory.cpp`) are intentional
  parse-or-fallback idioms.

- **[CLEARED] Coordinator concurrency/lifecycle.** 34 end-to-end tests pass:
  path dedup across spellings/symlinks, shared-worker refcounting, cross-worker
  concurrency, high-concurrency reply routing, close-during-in-flight, open/close
  churn (no slot/temp-dir leaks), malformed-output tolerance, crash recovery,
  ready/route timeouts, batch_convert ordering + per-file failure isolation.
