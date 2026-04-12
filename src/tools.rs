// tools.rs - MCP tool definitions
//
// Each tool is a thin wrapper that routes to the correct C++ worker via
// the Coordinator. Tools accept a `session` parameter to identify which
// worker slot to target.

use std::sync::Arc;
use rmcp::{ServerHandler, model::{ServerCapabilities, ServerInfo, Implementation}, tool};

use crate::coordinator::Coordinator;

#[derive(Clone)]
pub struct IdaMcpServer {
    pub coordinator: Arc<Coordinator>,
}

// Helper: route a command to a worker by session
async fn route(
    coordinator: &Coordinator,
    session: Option<String>,
    method: &str,
    params: serde_json::Value,
) -> String {
    let session = session.unwrap_or_else(|| "default".to_string());
    match coordinator.route(&session, method, params).await {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| "null".to_string()),
        Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
    }
}

#[tool(tool_box)]
impl IdaMcpServer {
    // =========================================================================
    // Management tools (handled by Rust coordinator)
    // =========================================================================

    /// Open a binary for AI querying.
    /// Supports .i64/.idb (instant) and raw PE files: .dll/.exe/.sys (auto-analysis in background).
    /// For raw binaries, returns immediately with analyzing=true. Poll with analysis_status or wait with wait_analysis.
    #[tool(description = "Open a binary for analysis. Supports .i64/.idb databases (instant load) and raw PE files (.dll/.exe/.sys — auto-analysis runs in background). For raw binaries: returns immediately with analyzing=true, then poll analysis_status or call wait_analysis.")]
    async fn open_file(
        &self,
        #[tool(param)]
        #[schemars(description = "Path to binary file (.i64, .idb, .dll, .exe, .sys)")]
        path: String,
        #[tool(param)]
        #[schemars(description = "Session identifier. Use different sessions for different binaries. Default: 'default'")]
        session: Option<String>,
    ) -> String {
        let session = session.unwrap_or_else(|| "default".to_string());
        match self.coordinator.open(&path, &session).await {
            Ok(slot) => {
                let ready = slot.ready_data.lock().await.clone();
                serde_json::json!({
                    "session": session,
                    "slot_id": slot.id,
                    "info": ready,
                }).to_string()
            }
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// List all active analysis sessions / worker slots.
    #[tool(description = "List all active analysis sessions with their loaded binaries and status")]
    async fn list_instances(&self) -> String {
        let slots = self.coordinator.list_slots().await;
        serde_json::to_string_pretty(&slots).unwrap_or_else(|_| "[]".to_string())
    }

    /// Close an analysis session and free its worker slot.
    #[tool(description = "Close an analysis session, stopping its worker process")]
    async fn close_session(
        &self,
        #[tool(param)]
        #[schemars(description = "Session to close")]
        session: String,
    ) -> String {
        match self.coordinator.close_session(&session).await {
            Ok(()) => r#"{"closed": true}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    // =========================================================================
    // Core query tools (routed to C++ worker)
    // =========================================================================

    /// Get basic metadata about the loaded binary.
    #[tool(description = "Get IDB metadata: processor, bits, entry point, address range, function/segment counts")]
    async fn get_info(
        &self,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "get_info", serde_json::json!({})).await
    }

    /// List functions in the binary with optional filtering.
    #[tool(description = "List functions with pagination and optional name filter. Returns function addresses, names, and sizes.")]
    async fn list_funcs(
        &self,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
        #[tool(param)]
        #[schemars(description = "Substring filter for function names")]
        filter: Option<String>,
        #[tool(param)]
        #[schemars(description = "Number of results to skip (default 0)")]
        offset: Option<i64>,
        #[tool(param)]
        #[schemars(description = "Max results to return (default 100)")]
        limit: Option<i64>,
    ) -> String {
        let mut params = serde_json::json!({});
        if let Some(f) = filter { params["filter"] = f.into(); }
        if let Some(o) = offset { params["offset"] = o.into(); }
        if let Some(l) = limit { params["limit"] = l.into(); }
        route(&self.coordinator, session, "list_funcs", params).await
    }

    /// List all segments in the binary.
    #[tool(description = "List all segments (sections) with names, classes, address ranges, and sizes")]
    async fn list_segments(
        &self,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "list_segments", serde_json::json!({})).await
    }

    /// Look up a function by address or name.
    #[tool(description = "Find a function by hex address (0x...) or name. Returns address, name, and size.")]
    async fn lookup_func(
        &self,
        #[tool(param)]
        #[schemars(description = "Address (hex) or function name to look up")]
        target: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "lookup_func", serde_json::json!({"target": target})).await
    }

    /// Save the current IDB database.
    #[tool(description = "Save the current analysis database as .i64 file")]
    async fn save_idb(
        &self,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "save_idb", serde_json::json!({})).await
    }

    // =========================================================================
    // Analysis tools
    // =========================================================================

    /// Decompile a function to pseudocode using Hex-Rays.
    #[tool(description = "Decompile function at address to C pseudocode using Hex-Rays decompiler. Returns complete pseudocode text.")]
    async fn decompile(
        &self,
        #[tool(param)]
        #[schemars(description = "Function address in hex (e.g. '0x1400010A0') or function name")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "decompile", serde_json::json!({"ea": ea})).await
    }

    /// Disassemble a function or address range.
    #[tool(description = "Disassemble instructions at address. Returns assembly lines with addresses and sizes.")]
    async fn disasm(
        &self,
        #[tool(param)]
        #[schemars(description = "Start address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Max number of instructions (default 50)")]
        count: Option<i64>,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        let mut params = serde_json::json!({"ea": ea});
        if let Some(c) = count { params["count"] = c.into(); }
        route(&self.coordinator, session, "disasm", params).await
    }

    /// Find cross-references to an address.
    #[tool(description = "Find all cross-references pointing TO an address (who calls/references this?)")]
    async fn xrefs_to(
        &self,
        #[tool(param)]
        #[schemars(description = "Target address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "xrefs_to", serde_json::json!({"ea": ea})).await
    }

    /// Find cross-references from an address.
    #[tool(description = "Find all cross-references FROM an address (what does this reference?)")]
    async fn xrefs_from(
        &self,
        #[tool(param)]
        #[schemars(description = "Source address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "xrefs_from", serde_json::json!({"ea": ea})).await
    }

    /// List functions called by a given function.
    #[tool(description = "List all functions called by the function at the given address")]
    async fn callees(
        &self,
        #[tool(param)]
        #[schemars(description = "Function address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "callees", serde_json::json!({"ea": ea})).await
    }

    // =========================================================================
    // Memory tools
    // =========================================================================

    /// Read raw bytes from the binary.
    #[tool(description = "Read raw bytes at address, returned as hex string (max 64KB)")]
    async fn get_bytes(
        &self,
        #[tool(param)]
        #[schemars(description = "Address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Number of bytes to read")]
        size: i64,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "get_bytes", serde_json::json!({"ea": ea, "size": size})).await
    }

    /// Read a string at an address.
    #[tool(description = "Read a C string at the given address")]
    async fn get_string(
        &self,
        #[tool(param)]
        #[schemars(description = "String address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "get_string", serde_json::json!({"ea": ea})).await
    }

    /// Patch bytes in the database.
    #[tool(description = "Patch bytes at address with hex string (e.g. '90909090' for NOPs)")]
    async fn patch_bytes(
        &self,
        #[tool(param)]
        #[schemars(description = "Address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Hex byte string to write (e.g. '4831C0C3')")]
        hex: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "patch_bytes", serde_json::json!({"ea": ea, "hex": hex})).await
    }

    // =========================================================================
    // Modification tools
    // =========================================================================

    /// Rename a function or address.
    #[tool(description = "Rename a function, global, or address")]
    async fn rename(
        &self,
        #[tool(param)]
        #[schemars(description = "Address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "New name")]
        name: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "rename", serde_json::json!({"ea": ea, "name": name})).await
    }

    /// Set a comment at an address.
    #[tool(description = "Set a comment at an address in the disassembly")]
    async fn set_comment(
        &self,
        #[tool(param)]
        #[schemars(description = "Address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Comment text")]
        comment: String,
        #[tool(param)]
        #[schemars(description = "Repeatable comment (shows at all xrefs)")]
        repeatable: Option<bool>,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        let mut params = serde_json::json!({"ea": ea, "comment": comment});
        if let Some(r) = repeatable { params["repeatable"] = r.into(); }
        route(&self.coordinator, session, "set_comment", params).await
    }

    /// Get the name at an address.
    #[tool(description = "Get the name (label) at an address")]
    async fn get_name(
        &self,
        #[tool(param)]
        #[schemars(description = "Address in hex")]
        ea: String,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "get_name", serde_json::json!({"ea": ea})).await
    }

    // =========================================================================
    // Search tools
    // =========================================================================

    #[tool(description = "Search strings by regex pattern")]
    async fn find_regex(
        &self,
        #[tool(param)] #[schemars(description = "Regex pattern")] pattern: String,
        #[tool(param)] #[schemars(description = "Max results (default 30)")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"pattern": pattern});
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "find_regex", p).await
    }

    #[tool(description = "Search byte patterns with ?? wildcards (e.g. '48 8B ?? 90')")]
    async fn find_bytes(
        &self,
        #[tool(param)] #[schemars(description = "Hex byte pattern with optional ?? wildcards")] hex: String,
        #[tool(param)] #[schemars(description = "Start address")] start: Option<String>,
        #[tool(param)] #[schemars(description = "Max results (default 10)")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"hex": hex});
        if let Some(s) = start { p["start"] = s.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "find_bytes", p).await
    }

    #[tool(description = "List imports with optional filtering by name")]
    async fn imports(
        &self,
        #[tool(param)] #[schemars(description = "Name substring filter")] filter: Option<String>,
        #[tool(param)] #[schemars(description = "Max results (default 500)")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "imports", p).await
    }

    #[tool(description = "Advanced function search with size/name filters")]
    async fn func_query(
        &self,
        #[tool(param)] #[schemars(description = "Name substring filter")] filter: Option<String>,
        #[tool(param)] #[schemars(description = "Minimum function size in bytes")] min_size: Option<i64>,
        #[tool(param)] #[schemars(description = "Maximum function size in bytes")] max_size: Option<i64>,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(v) = min_size { p["min_size"] = v.into(); }
        if let Some(v) = max_size { p["max_size"] = v.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "func_query", p).await
    }

    #[tool(description = "List global variables (non-function named addresses)")]
    async fn list_globals(
        &self,
        #[tool(param)] #[schemars(description = "Name substring filter")] filter: Option<String>,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "list_globals", p).await
    }

    #[tool(description = "Convert a number between hex/decimal/octal/binary representations")]
    async fn int_convert(
        &self,
        #[tool(param)] #[schemars(description = "Number value (hex 0x..., decimal, or octal 0...)")] value: String,
    ) -> String {
        route(&self.coordinator, None, "int_convert", serde_json::json!({"value": value})).await
    }

    // =========================================================================
    // Graph / CFG tools
    // =========================================================================

    #[tool(description = "Get control flow graph basic blocks for a function")]
    async fn basic_blocks(
        &self,
        #[tool(param)] #[schemars(description = "Function address")] ea: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "basic_blocks", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Build a call graph from root functions with bounded depth")]
    async fn callgraph(
        &self,
        #[tool(param)] #[schemars(description = "Root function addresses")] roots: Vec<String>,
        #[tool(param)] #[schemars(description = "Max traversal depth (default 3)")] depth: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"roots": roots});
        if let Some(d) = depth { p["depth"] = d.into(); }
        route(&self.coordinator, session, "callgraph", p).await
    }

    #[tool(description = "Search instructions by mnemonic within a function or globally")]
    async fn insn_query(
        &self,
        #[tool(param)] #[schemars(description = "Mnemonic substring (e.g. 'call', 'jmp', 'mov')")] mnemonic: Option<String>,
        #[tool(param)] #[schemars(description = "Function address to search within")] ea: Option<String>,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(m) = mnemonic { p["mnemonic"] = m.into(); }
        if let Some(e) = ea { p["ea"] = e.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "insn_query", p).await
    }

    #[tool(description = "Get function profile: size, callers, callees, referenced strings")]
    async fn func_profile(
        &self,
        #[tool(param)] #[schemars(description = "Function address")] ea: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "func_profile", serde_json::json!({"ea": ea})).await
    }

    // =========================================================================
    // Type system tools
    // =========================================================================

    #[tool(description = "Apply a C type declaration to an address (e.g. 'int __fastcall foo(int a1)')")]
    async fn set_type(
        &self,
        #[tool(param)] #[schemars(description = "Address")] ea: String,
        #[tool(param)] #[schemars(description = "C type string")] r#type: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "set_type", serde_json::json!({"ea": ea, "type": r#type})).await
    }

    #[tool(description = "Inspect type information at an address or by type name")]
    async fn type_inspect(
        &self,
        #[tool(param)] #[schemars(description = "Address in hex")] ea: Option<String>,
        #[tool(param)] #[schemars(description = "Type name to look up")] name: Option<String>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(e) = ea { p["ea"] = e.into(); }
        if let Some(n) = name { p["name"] = n.into(); }
        route(&self.coordinator, session, "type_inspect", p).await
    }

    #[tool(description = "Parse and add C type declarations to the local type library")]
    async fn declare_type(
        &self,
        #[tool(param)] #[schemars(description = "C declaration (e.g. 'struct Foo { int x; float y; };')")] decl: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "declare_type", serde_json::json!({"decl": decl})).await
    }

    #[tool(description = "Search local types by name pattern")]
    async fn type_query(
        &self,
        #[tool(param)] #[schemars(description = "Name substring filter")] filter: Option<String>,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "type_query", p).await
    }

    #[tool(description = "Search struct/union type definitions")]
    async fn search_structs(
        &self,
        #[tool(param)] #[schemars(description = "Name substring filter")] filter: Option<String>,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "search_structs", p).await
    }

    #[tool(description = "Infer variable types for a function using Hex-Rays decompiler")]
    async fn infer_types(
        &self,
        #[tool(param)] #[schemars(description = "Function address")] ea: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "infer_types", serde_json::json!({"ea": ea})).await
    }

    // =========================================================================
    // Stack frame tools
    // =========================================================================

    #[tool(description = "Get stack frame variables for a function (via Hex-Rays)")]
    async fn stack_frame(
        &self,
        #[tool(param)] #[schemars(description = "Function address")] ea: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "stack_frame", serde_json::json!({"ea": ea})).await
    }

    // =========================================================================
    // Extended modify tools
    // =========================================================================

    #[tool(description = "Append text to an existing comment at an address")]
    async fn append_comments(
        &self,
        #[tool(param)] #[schemars(description = "Address")] ea: String,
        #[tool(param)] #[schemars(description = "Comment text to append")] comment: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "append_comments", serde_json::json!({"ea": ea, "comment": comment})).await
    }

    #[tool(description = "Define a function at address")]
    async fn define_func(
        &self,
        #[tool(param)] #[schemars(description = "Start address")] ea: String,
        #[tool(param)] #[schemars(description = "End address (optional, IDA auto-detects)")] end: Option<String>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(e) = end { p["end"] = e.into(); }
        route(&self.coordinator, session, "define_func", p).await
    }

    #[tool(description = "Convert bytes to code instructions")]
    async fn define_code(
        &self,
        #[tool(param)] #[schemars(description = "Address")] ea: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "define_code", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Undefine items (convert back to raw bytes)")]
    async fn undefine(
        &self,
        #[tool(param)] #[schemars(description = "Address")] ea: String,
        #[tool(param)] #[schemars(description = "Number of bytes to undefine")] size: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(s) = size { p["size"] = s.into(); }
        route(&self.coordinator, session, "undefine", p).await
    }

    // =========================================================================
    // Extended memory tools
    // =========================================================================

    #[tool(description = "Read an integer value at address (1/2/4/8 bytes)")]
    async fn get_int(
        &self,
        #[tool(param)] #[schemars(description = "Address")] ea: String,
        #[tool(param)] #[schemars(description = "Size in bytes: 1, 2, 4, or 8 (default 4)")] size: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(s) = size { p["size"] = s.into(); }
        route(&self.coordinator, session, "get_int", p).await
    }

    #[tool(description = "Write an integer value at address")]
    async fn put_int(
        &self,
        #[tool(param)] #[schemars(description = "Address")] ea: String,
        #[tool(param)] #[schemars(description = "Value to write (decimal or 0x hex)")] value: String,
        #[tool(param)] #[schemars(description = "Size in bytes: 1, 2, 4, or 8 (default 4)")] size: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"ea": ea, "value": value});
        if let Some(s) = size { p["size"] = s.into(); }
        route(&self.coordinator, session, "put_int", p).await
    }

    // =========================================================================
    // Composite analysis tools
    // =========================================================================

    #[tool(description = "Deep function analysis: decompile + disasm + xrefs + strings + callees + basic blocks in one call")]
    async fn analyze_function(
        &self,
        #[tool(param)] #[schemars(description = "Function address")] ea: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "analyze_function", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Complete binary triage: metadata, segments, top functions, imports, strings, entries")]
    async fn survey_binary(
        &self,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "survey_binary", serde_json::json!({})).await
    }

    #[tool(description = "Trace data flow by following xrefs forward or backward from an address")]
    async fn trace_data_flow(
        &self,
        #[tool(param)] #[schemars(description = "Start address")] ea: String,
        #[tool(param)] #[schemars(description = "'forward' or 'backward' (default forward)")] direction: Option<String>,
        #[tool(param)] #[schemars(description = "Max traversal depth (default 5)")] depth: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(d) = direction { p["direction"] = d.into(); }
        if let Some(d) = depth { p["depth"] = d.into(); }
        route(&self.coordinator, session, "trace_data_flow", p).await
    }

    // =========================================================================
    // NEW: imports_query, entity_query, xref_query, xrefs_to_field
    // =========================================================================

    #[tool(description = "Query imports with module and name filtering, pagination")]
    async fn imports_query(
        &self,
        #[tool(param)] #[schemars(description = "Import name filter")] filter: Option<String>,
        #[tool(param)] #[schemars(description = "Module name filter")] module: Option<String>,
        #[tool(param)] #[schemars(description = "Skip N results")] offset: Option<i64>,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(m) = module { p["module"] = m.into(); }
        if let Some(o) = offset { p["offset"] = o.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "imports_query", p).await
    }

    #[tool(description = "Generic entity search: query functions, globals, strings, or imports by kind")]
    async fn entity_query(
        &self,
        #[tool(param)] #[schemars(description = "Entity kind: 'functions', 'globals', 'strings', or 'imports'")] kind: String,
        #[tool(param)] #[schemars(description = "Name/content filter")] filter: Option<String>,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"kind": kind});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "entity_query", p).await
    }

    #[tool(description = "Unified xref query with direction and type filtering")]
    async fn xref_query(
        &self,
        #[tool(param)] #[schemars(description = "Address")] ea: String,
        #[tool(param)] #[schemars(description = "'to', 'from', or 'both' (default 'both')")] direction: Option<String>,
        #[tool(param)] #[schemars(description = "Code refs only")] code_only: Option<bool>,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(d) = direction { p["direction"] = d.into(); }
        if let Some(c) = code_only { p["code_only"] = c.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "xref_query", p).await
    }

    #[tool(description = "Find references to a struct field offset within a function")]
    async fn xrefs_to_field(
        &self,
        #[tool(param)] #[schemars(description = "Function address")] ea: String,
        #[tool(param)] #[schemars(description = "Field offset in bytes")] field_offset: i64,
        #[tool(param)] #[schemars(description = "Max results")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"ea": ea, "field_offset": field_offset});
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "xrefs_to_field", p).await
    }

    // =========================================================================
    // NEW: analyze_batch, export_funcs, analyze_component, diff_before_after
    // =========================================================================

    #[tool(description = "Batch decompile multiple functions at once")]
    async fn analyze_batch(
        &self,
        #[tool(param)] #[schemars(description = "Array of function addresses")] addresses: Vec<String>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "analyze_batch", serde_json::json!({"addresses": addresses})).await
    }

    #[tool(description = "Export function info with optional prototypes")]
    async fn export_funcs(
        &self,
        #[tool(param)] #[schemars(description = "Specific addresses to export (omit for all)")] addresses: Option<Vec<String>>,
        #[tool(param)] #[schemars(description = "Max results if no addresses given")] limit: Option<i64>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({});
        if let Some(a) = addresses { p["addresses"] = serde_json::json!(a); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "export_funcs", p).await
    }

    #[tool(description = "Analyze a group of related functions: internal call graph, shared data, per-function summaries")]
    async fn analyze_component(
        &self,
        #[tool(param)] #[schemars(description = "Array of function addresses forming the component")] addresses: Vec<String>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "analyze_component", serde_json::json!({"addresses": addresses})).await
    }

    #[tool(description = "Apply an edit (rename/set_type/set_comment) and show before/after decompilation diff")]
    async fn diff_before_after(
        &self,
        #[tool(param)] #[schemars(description = "Address")] ea: String,
        #[tool(param)] #[schemars(description = "Action: 'rename', 'set_type', or 'set_comment'")] action: String,
        #[tool(param)] #[schemars(description = "New name, type string, or comment text")] value: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "diff_before_after",
            serde_json::json!({"ea": ea, "action": action, "value": value})).await
    }

    // =========================================================================
    // NEW: enum_upsert, read_struct, type_apply_batch
    // =========================================================================

    #[tool(description = "Create or update an enum type with named members")]
    async fn enum_upsert(
        &self,
        #[tool(param)] #[schemars(description = "Enum name")] name: String,
        #[tool(param)] #[schemars(description = "JSON array of {name, value} members")] members: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let members_val: serde_json::Value = serde_json::from_str(&members)
            .unwrap_or(serde_json::json!([]));
        route(&self.coordinator, session, "enum_upsert",
            serde_json::json!({"name": name, "members": members_val})).await
    }

    #[tool(description = "Read struct fields from memory at an address")]
    async fn read_struct(
        &self,
        #[tool(param)] #[schemars(description = "Memory address")] ea: String,
        #[tool(param)] #[schemars(description = "Struct type name")] struct_name: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "read_struct",
            serde_json::json!({"ea": ea, "struct_name": struct_name})).await
    }

    #[tool(description = "Batch apply types to multiple addresses")]
    async fn type_apply_batch(
        &self,
        #[tool(param)] #[schemars(description = "JSON array of {ea, type} items")] items: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let items_val: serde_json::Value = serde_json::from_str(&items)
            .unwrap_or(serde_json::json!([]));
        route(&self.coordinator, session, "type_apply_batch",
            serde_json::json!({"items": items_val})).await
    }

    // =========================================================================
    // NEW: declare_stack, delete_stack, get_global_value, server_health
    // =========================================================================

    #[tool(description = "Rename or retype a local variable in a function (via Hex-Rays)")]
    async fn declare_stack(
        &self,
        #[tool(param)] #[schemars(description = "Function address")] ea: String,
        #[tool(param)] #[schemars(description = "Current variable name")] old_name: String,
        #[tool(param)] #[schemars(description = "New name (empty to keep)")] new_name: Option<String>,
        #[tool(param)] #[schemars(description = "New C type (empty to keep)")] r#type: Option<String>,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        let mut p = serde_json::json!({"ea": ea, "old_name": old_name});
        if let Some(n) = new_name { p["new_name"] = n.into(); }
        if let Some(t) = r#type { p["type"] = t.into(); }
        route(&self.coordinator, session, "declare_stack", p).await
    }

    #[tool(description = "Reset a local variable name back to IDA default")]
    async fn delete_stack(
        &self,
        #[tool(param)] #[schemars(description = "Function address")] ea: String,
        #[tool(param)] #[schemars(description = "Variable name to reset")] name: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "delete_stack", serde_json::json!({"ea": ea, "name": name})).await
    }

    #[tool(description = "Read a global variable's value by name or address")]
    async fn get_global_value(
        &self,
        #[tool(param)] #[schemars(description = "Global variable name or address")] target: String,
        #[tool(param)] #[schemars(description = "Session")] session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "get_global_value", serde_json::json!({"target": target})).await
    }

    #[tool(description = "Warm up a session: trigger Hex-Rays init and ensure analysis is complete")]
    async fn server_warmup(
        &self,
        #[tool(param)] #[schemars(description = "Session to warm up")] session: Option<String>,
    ) -> String {
        // Warmup by calling decompile on the entry point — this forces Hex-Rays init
        let info_result = route(&self.coordinator, session.clone(), "get_info", serde_json::json!({})).await;
        // Then ping to confirm worker is responsive
        let ping_result = route(&self.coordinator, session, "ping", serde_json::json!({})).await;
        serde_json::json!({
            "warmed_up": true,
            "info": info_result,
            "ping": ping_result,
        }).to_string()
    }

    // =========================================================================
    // Batch conversion (raw PE → .i64)
    // =========================================================================

    /// Batch convert raw binaries (DLL/EXE/SYS) to .i64 databases.
    /// Opens multiple workers in parallel, runs auto-analysis, saves .i64 files.
    #[tool(description = "Batch convert raw binaries to .i64 databases. Opens workers in parallel, auto-analyzes, saves .i64. Returns per-file results with function counts and elapsed time.")]
    async fn batch_convert(
        &self,
        #[tool(param)]
        #[schemars(description = "Array of file paths to convert (DLL/EXE/SYS)")]
        paths: Vec<String>,
        #[tool(param)]
        #[schemars(description = "Output directory for .i64 files. If omitted, saves next to original (xxx.dll → xxx.dll.i64)")]
        output_dir: Option<String>,
        #[tool(param)]
        #[schemars(description = "Max parallel workers (default 5, max limited by server max_slots)")]
        concurrency: Option<i64>,
        #[tool(param)]
        #[schemars(description = "Max seconds to wait for each file's analysis (default 600)")]
        max_analysis_seconds: Option<i64>,
    ) -> String {
        let concurrency = concurrency.unwrap_or(5).max(1).min(50) as usize;
        let max_secs = max_analysis_seconds.unwrap_or(600).max(30).min(3600);

        // Create output directory if specified
        if let Some(ref dir) = output_dir {
            let _ = std::fs::create_dir_all(dir);
        }

        let total = paths.len();
        let results = self.coordinator.batch_convert(paths, output_dir, concurrency, max_secs).await;

        let completed = results.iter().filter(|r| r.error.is_none()).count();
        let failed = results.iter().filter(|r| r.error.is_some()).count();
        let total_funcs: u64 = results.iter().filter_map(|r| r.functions).sum();

        serde_json::json!({
            "total": total,
            "completed": completed,
            "failed": failed,
            "total_functions": total_funcs,
            "results": results,
        }).to_string()
    }

    // =========================================================================
    // Analysis lifecycle tools (for raw PE/DLL/EXE loading)
    // =========================================================================

    /// Check auto-analysis status without blocking.
    /// Use after open_file on a raw binary to poll analysis progress.
    #[tool(description = "Check auto-analysis status (non-blocking). Returns whether analysis is done, current queue state, function/segment counts. Use after opening a raw binary (DLL/EXE) to poll progress.")]
    async fn analysis_status(
        &self,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        route(&self.coordinator, session, "analysis_status", serde_json::json!({})).await
    }

    /// Wait for auto-analysis to complete (blocking with timeout).
    /// Sends periodic progress events. Use when you want to explicitly wait.
    #[tool(description = "Wait for auto-analysis to complete with timeout. Blocks until analysis finishes or timeout. Returns final status with elapsed time. Sends progress events every 2s.")]
    async fn wait_analysis(
        &self,
        #[tool(param)]
        #[schemars(description = "Max seconds to wait (default 300, max 600)")]
        max_seconds: Option<i64>,
        #[tool(param)]
        #[schemars(description = "Session identifier")]
        session: Option<String>,
    ) -> String {
        let mut params = serde_json::json!({});
        if let Some(s) = max_seconds { params["max_seconds"] = s.into(); }
        route(&self.coordinator, session, "wait_analysis", params).await
    }

    #[tool(description = "Server health check — returns coordinator status and active slot count")]
    async fn server_health(&self) -> String {
        let slots = self.coordinator.list_slots().await;
        let alive = slots.iter().filter(|s| s.alive).count();
        serde_json::json!({
            "status": "ok",
            "total_slots": slots.len(),
            "alive_slots": alive,
            "max_slots": 100,
        }).to_string()
    }
}

#[tool(tool_box)]
impl ServerHandler for IdaMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "ida-hive".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "Multi-instance IDA Pro MCP server. Open .i64/.idb databases or raw PE files with open_file, \
                 then use analysis tools (decompile, disasm, xrefs, etc.) to query them. \
                 Supports multiple simultaneous sessions for different binaries. \
                 Also supports raw PE files (.dll/.exe/.sys) — auto-analysis runs in background. \
                 Use analysis_status to poll progress, or wait_analysis to block until done."
                    .into(),
            ),
            ..Default::default()
        }
    }
}
