# Changelog

## 1.0.0 — IDA 9.4

First release built against the IDA 9.4 SDK. Earlier runtimes no longer configure: 9.4 replaced
the SDK's `bootstrap.cmake` with `cmake/idasdk_init.cmake`.

### Tools

64 → 103, in seven new categories reaching 9.4 subsystems that earlier releases did not expose:

- **Control flow** — `switch_info` resolves jump tables to their case targets; `try_blocks` exposes
  C++/SEH exception structure; `reg_value` asks IDA's value propagation what a register holds;
  plus `problems`, `fixups`, `seg_regs`.
- **Microcode** — the decompiler's IR, at any maturity level. The same function yields 8,242
  microinstructions at `generated` and 952 at `glbopt3`.
- **Strings** — including the entries the decompiler reconstructs, which carry no bytes at their
  address and no data scan finds.
- **Signatures** — FLIRT state, and function classification by origin. 130 of grep's 547 functions
  are thunks; separating them is the largest single noise reduction on a stripped binary.
- **Offsets** — mark an immediate as a reference so IDA resolves it to a name and creates the xref.
- **Index / dyld cache** — `index_*` (disabled by IDA under headless mode) and `dsc_*` for Apple
  shared caches.
- **Database internals** — netnode access, source-language parser selection, undo points.

### Fixed

- The worker aborted on a line that parsed but was not an object (`[]`, `null`), taking every
  in-flight request with it. Serialising a response containing invalid UTF-8 did the same.
- Concurrent opens could overshoot `IDA_MCP_MAX_SLOTS`: the capacity check released its lock
  before the slow `start()`, so opens of different paths all saw room. Capacity is now an atomic
  reservation held for the worker's life.
- A mutex was held across an await while sending to the worker; a full channel blocked every other
  caller in a phase no timeout covered.

### Architecture

- `worker/` split into `include/ida_hive/` and `src/`, with an `ida_hive` namespace. Ten headers
  that each declared one function collapsed into one.
- Commands are named functions registered from a table, not lambdas inline in a 400-line function.
- Shared preconditions and call-edge classification extracted; five duplicated copies of the xref
  walk removed.
- Warnings denied at build time on both sides. The SDK attaches `-w` to every target it defines,
  which had been silencing this project's own warnings as well.

### Testing

Ten gates, six of which need an activated IDA: adversarial (2,050 hostile calls), endurance
(no memory, descriptor or process leaks over 600 heavy calls), tool correctness (26 invariants),
real-IDA integration, and scale (454,461 functions, 2.1 GB, table sweeps still under a second).
CI covers the four that need no license, on Linux and Windows.


## Branch `fix/concurrency-and-locking`

Two waves of fixes. The concurrency/lifecycle work and the tool-surface work are independent and
were each verified (live MCP round-trips + the project smoke script).

### Concurrency, locking & lifecycle

- **Same-file concurrent open no longer fails.** IDA writes its database/lock files next to the
  input; previously the 2nd/3rd worker opening the same binary failed and exited before "ready"
  (the reported "open the same DLL from 3 agents → two die"). Each worker now uses a **private
  database directory** — raw binaries `chdir` into it and redirect via a bare relative `-odb`
  (so paths with spaces/backslashes can't break the redirect); `.i64/.idb` inputs are copied in and
  the copy is opened. The input's own directory is never written. Verified: 8 separate server
  processes opening the same binary concurrently all succeed.
- **Path canonicalization + dedup.** Opens are keyed by canonical path, so relative/`./`/symlink
  spellings of the same file dedup to one worker.
- **Per-path open locking.** Opens of the same binary serialize (dedup), while opens of *different*
  binaries run concurrently — one large, slow open no longer stalls the whole pool. Verified: a
  blocking open on one session does not delay requests on another.
- **`route()` no longer holds the sessions lock across long calls**, which previously let one
  `wait_analysis` stall every other session (tokio `RwLock` is write-preferring).
- **`close_session` is reference-counted.** Closing one session that shares a worker no longer kills
  it for the other sessions; the worker is stopped only when unreferenced.
- **Dead-worker reaping.** Workers that die on their own are pruned (freeing `max_slots` capacity)
  and their temp directories removed; `kill_on_drop` + `Drop` clean up on normal shutdown.
- **Structured startup errors.** A failed worker emits an `init_error` event (license / locked or
  unreadable file / copy / chdir) so the coordinator surfaces the real reason instead of a generic
  "exited before ready".
- **Atomic `save_idb`** (temp sibling + rename) so concurrent saves to the same path can't produce a
  torn database.
- **Configurable startup timeout** `IDA_MCP_OPEN_TIMEOUT` (default 600s) — raw-binary `open_file`
  blocks until initial analysis finishes, which can take minutes on large inputs.
- **Removed the one `unsafe` block** (raw pointer to `AtomicBool` → `Arc<AtomicBool>`); the crate is
  now `unsafe`-free. Preserved `batch_convert` input ordering. Bounded a worker-death race that could
  make a caller wait the full timeout.

### Tool-surface correctness (19 bugs, found by production validation)

- **Address-by-name everywhere.** `parse_ea` now resolves a function/symbol name (via `get_name_ea`)
  when the argument isn't numeric, instead of leaking a raw `{"error":"stoull"}`. This unblocks every
  `ea`-taking tool (`decompile`, `disasm`, `xrefs_*`, …) — names work as the schema always claimed.
  Unresolvable input returns a clear message.
- **Call-graph accuracy.** `callees`, `callgraph`, `func_profile`, `analyze_function`,
  `analyze_component` now count only real **call** xrefs (`fl_CN`/`fl_CF`), exclude the function
  itself, and dedup — previously every function listed itself as its own callee and fall-through /
  intra-function jumps were counted as calls.
- **`disasm`** starts at the requested address (was snapping to the containing function's start).
- **`diff_before_after`** invalidates the Hex-Rays cache before the "after" decompile, so the diff
  reflects the edit (was always `changed:false`).
- **`set_type`** tolerates a missing trailing `;` (the documented example omitted it).
- **`int_convert`** is computed without a worker session (was failing with "No active session").
- **`append_comments`** joins with an inline separator and returns the real result (the previous
  newline join was invisible to `disasm`, and success was hard-coded).
- **`get_global_value`** sizes the read from the item, not a hard-coded 8 bytes (was over-reading
  into the adjacent variable).
- **`lookup_func`** resolves export/alias names via the entry table + demangled match (e.g. `malloc`,
  `getc`), and its parameter is now `ea` for consistency with the other tools.
- **`save_idb`** returns an `error` message when the save fails (was a silent `success:false`).
- **`xref_query`** `from`-rows report the source function (consistent with `to`-rows).
- **`declare_stack`** builds the lvar locator via `locate_lvar` so a retype can apply, and no longer
  reports `success:true` when a requested retype was dropped (it returns an error instead).
- **`declare_type`** reports the parse result as `errors` (was mislabeled `parsed`).
- **`type_inspect`** returns a null size for function types (was the `BADSIZE` sentinel).
- **`undefine(size=0)`** defaults to the item size instead of doing nothing.
- **`imports`** default `limit` lowered to 100 (500 could overflow the response size cap).
- **`list_instances`** no longer reports a stale cached `analyzing` flag.

### Documentation

- README corrected: raw-binary `open_file` is **synchronous/blocking** (not "background"); added the
  concurrency/isolation model, the `IDASDK=…/src` + `IDABIN` build variables, `IDA_MCP_OPEN_TIMEOUT`,
  measured analysis timings, and a behavior/limitations section.
- The MCP server `instructions` and the `open_file` tool description were corrected to match (they
  previously claimed background analysis / immediate return).

### Known / not changed

- `wait_analysis` blocking the full timeout was observed once under heavy concurrent load but could
  not be reproduced in isolation; left for investigation under load.
- Same-file sessions sharing one mutable database, and a hard `SIGKILL` of the coordinator orphaning
  workers, are documented behaviors rather than fixes.
