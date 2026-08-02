# Changelog

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
