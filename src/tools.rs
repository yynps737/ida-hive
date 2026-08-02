// Tool arguments arrive as typed structs via `Parameters<T>`, the rmcp 3.x form
// that replaced 0.1's inline `#[tool(param)]`. Each struct derives `Deserialize`
// to read the JSON and `schemars::JsonSchema` to publish the input schema, and
// marks optional fields `#[serde(default)]` so an omitted argument yields None.

use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router, ServerHandler,
};
use serde::Deserialize;

use crate::coordinator::Coordinator;

#[derive(Clone)]
pub struct IdaMcpServer {
    pub coordinator: Arc<Coordinator>,
    // Read by the #[tool_handler]-generated dispatch, never by hand.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

// Every tool body funnels through here.
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

// ---- Parameter structs ----
// The two below are shared across many tools; the rest are per-tool.

/// Just a session selector (for whole-database queries).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionReq {
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

/// An address/name plus a session (the most common analysis shape).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EaReq {
    #[schemars(description = "Address in hex (e.g. '0x1400010A0') or a function/symbol name")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OpenFileReq {
    #[schemars(description = "Path to a binary file or IDA database (.i64/.idb). Raw binaries are loaded through IDA's native loaders.")]
    pub path: String,
    #[serde(default)]
    #[schemars(description = "Session identifier. Use different sessions for different binaries. Default: 'default'")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CloseSessionReq {
    #[schemars(description = "Session to close")]
    pub session: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListFuncsReq {
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
    #[serde(default)]
    #[schemars(description = "Substring filter for function names")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Number of results to skip (default 0)")]
    pub offset: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Max results to return (default 100)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DisasmReq {
    #[schemars(description = "Start address in hex")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "Max number of instructions (default 50)")]
    pub count: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetBytesReq {
    #[schemars(description = "Address in hex")]
    pub ea: String,
    #[schemars(description = "Number of bytes to read")]
    pub size: i64,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PatchBytesReq {
    #[schemars(description = "Address in hex")]
    pub ea: String,
    #[schemars(description = "Hex byte string to write (e.g. '4831C0C3')")]
    pub hex: String,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RenameReq {
    #[schemars(description = "Address in hex")]
    pub ea: String,
    #[schemars(description = "New name")]
    pub name: String,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetCommentReq {
    #[schemars(description = "Address in hex")]
    pub ea: String,
    #[schemars(description = "Comment text")]
    pub comment: String,
    #[serde(default)]
    #[schemars(description = "Repeatable comment (shows at all xrefs)")]
    pub repeatable: Option<bool>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindRegexReq {
    #[schemars(description = "Regex pattern")]
    pub pattern: String,
    #[serde(default)]
    #[schemars(description = "Max results (default 30)")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindBytesReq {
    #[schemars(description = "Hex byte pattern with optional ?? wildcards")]
    pub hex: String,
    #[serde(default)]
    #[schemars(description = "Start address")]
    pub start: Option<String>,
    #[serde(default)]
    #[schemars(description = "Max results (default 10)")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ImportsReq {
    #[serde(default)]
    #[schemars(description = "Name substring filter")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Max results (default 100)")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FuncQueryReq {
    #[serde(default)]
    #[schemars(description = "Name substring filter")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Minimum function size in bytes")]
    pub min_size: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Maximum function size in bytes")]
    pub max_size: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Max results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FilterLimitReq {
    #[serde(default)]
    #[schemars(description = "Name substring filter")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Max results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IntConvertReq {
    #[schemars(description = "Number value (hex 0x..., decimal, or octal 0...)")]
    pub value: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CallgraphReq {
    #[schemars(description = "Root function addresses")]
    pub roots: Vec<String>,
    #[serde(default)]
    #[schemars(description = "Max traversal depth (default 3)")]
    pub depth: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InsnQueryReq {
    #[serde(default)]
    #[schemars(description = "Mnemonic substring (e.g. 'call', 'jmp', 'mov')")]
    pub mnemonic: Option<String>,
    #[serde(default)]
    #[schemars(description = "Function address to search within")]
    pub ea: Option<String>,
    #[serde(default)]
    #[schemars(description = "Max results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetTypeReq {
    #[schemars(description = "Address")]
    pub ea: String,
    #[serde(rename = "type")]
    #[schemars(description = "C type string")]
    pub r#type: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TypeInspectReq {
    #[serde(default)]
    #[schemars(description = "Address in hex")]
    pub ea: Option<String>,
    #[serde(default)]
    #[schemars(description = "Type name to look up")]
    pub name: Option<String>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeclareTypeReq {
    #[schemars(description = "C declaration (e.g. 'struct Foo { int x; float y; };')")]
    pub decl: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AppendCommentsReq {
    #[schemars(description = "Address")]
    pub ea: String,
    #[schemars(description = "Comment text to append")]
    pub comment: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DefineFuncReq {
    #[schemars(description = "Start address")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "End address (optional, IDA auto-detects)")]
    pub end: Option<String>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UndefineReq {
    #[schemars(description = "Address")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "Number of bytes to undefine")]
    pub size: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetIntReq {
    #[schemars(description = "Address")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "Size in bytes: 1, 2, 4, or 8 (default 4)")]
    pub size: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PutIntReq {
    #[schemars(description = "Address")]
    pub ea: String,
    #[schemars(description = "Value to write (decimal or 0x hex)")]
    pub value: String,
    #[serde(default)]
    #[schemars(description = "Size in bytes: 1, 2, 4, or 8 (default 4)")]
    pub size: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TraceDataFlowReq {
    #[schemars(description = "Start address")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "'forward' or 'backward' (default forward)")]
    pub direction: Option<String>,
    #[serde(default)]
    #[schemars(description = "Max traversal depth (default 5)")]
    pub depth: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ImportsQueryReq {
    #[serde(default)]
    #[schemars(description = "Import name filter")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Module name filter")]
    pub module: Option<String>,
    #[serde(default)]
    #[schemars(description = "Skip N results")]
    pub offset: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Max results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EntityQueryReq {
    #[schemars(description = "Entity kind: 'functions', 'globals', 'strings', or 'imports'")]
    pub kind: String,
    #[serde(default)]
    #[schemars(description = "Name/content filter")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Max results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct XrefQueryReq {
    #[schemars(description = "Address")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "'to', 'from', or 'both' (default 'both')")]
    pub direction: Option<String>,
    #[serde(default)]
    #[schemars(description = "Code refs only")]
    pub code_only: Option<bool>,
    #[serde(default)]
    #[schemars(description = "Max results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct XrefsToFieldReq {
    #[schemars(description = "Function address")]
    pub ea: String,
    #[schemars(description = "Field offset in bytes")]
    pub field_offset: i64,
    #[serde(default)]
    #[schemars(description = "Max results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddressesReq {
    #[schemars(description = "Array of function addresses")]
    pub addresses: Vec<String>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExportFuncsReq {
    #[serde(default)]
    #[schemars(description = "Specific addresses to export (omit for all)")]
    pub addresses: Option<Vec<String>>,
    #[serde(default)]
    #[schemars(description = "Max results if no addresses given")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DiffBeforeAfterReq {
    #[schemars(description = "Address")]
    pub ea: String,
    #[schemars(description = "Action: 'rename', 'set_type', or 'set_comment'")]
    pub action: String,
    #[schemars(description = "New name, type string, or comment text")]
    pub value: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EnumUpsertReq {
    #[schemars(description = "Enum name")]
    pub name: String,
    #[schemars(description = "JSON array of {name, value} members")]
    pub members: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadStructReq {
    #[schemars(description = "Memory address")]
    pub ea: String,
    #[schemars(description = "Struct type name")]
    pub struct_name: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TypeApplyBatchReq {
    #[schemars(description = "JSON array of {ea, type} items")]
    pub items: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeclareStackReq {
    #[schemars(description = "Function address")]
    pub ea: String,
    #[schemars(description = "Current variable name")]
    pub old_name: String,
    #[serde(default)]
    #[schemars(description = "New name (empty to keep)")]
    pub new_name: Option<String>,
    #[serde(default, rename = "type")]
    #[schemars(description = "New C type (empty to keep)")]
    pub r#type: Option<String>,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteStackReq {
    #[schemars(description = "Function address")]
    pub ea: String,
    #[schemars(description = "Variable name to reset")]
    pub name: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetGlobalValueReq {
    #[schemars(description = "Global variable name or address")]
    pub target: String,
    #[serde(default)]
    #[schemars(description = "Session")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaitAnalysisReq {
    #[serde(default)]
    #[schemars(description = "Max seconds to wait (default 300, max 600)")]
    pub max_seconds: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BatchConvertReq {
    #[schemars(description = "Array of raw binary paths to convert (validated on PE and ELF)")]
    pub paths: Vec<String>,
    #[serde(default)]
    #[schemars(description = "Output directory for .i64 files. If omitted, saves next to original (input.bin -> input.bin.i64)")]
    pub output_dir: Option<String>,
    #[serde(default)]
    #[schemars(description = "Max parallel workers (default 5, max limited by server max_slots)")]
    pub concurrency: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Max seconds to wait for each file's analysis (default 600)")]
    pub max_analysis_seconds: Option<i64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MicrocodeReq {
    #[schemars(description = "Address in hex or a function/symbol name")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "Maturity level: generated, preoptimized, locopt, calls, glbopt1, glbopt2, glbopt3 (default), lvars. Earlier levels show more, less optimized microcode.")]
    pub maturity: Option<String>,
    #[serde(default)]
    #[schemars(description = "Maximum microinstructions to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegValueReq {
    #[schemars(description = "Address in hex or a function/symbol name")]
    pub ea: String,
    #[schemars(description = "Register name, e.g. 'rax', 'esi'")]
    pub reg: String,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LimitOnlyReq {
    #[serde(default)]
    #[schemars(description = "Maximum entries to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StringsReq {
    #[serde(default)]
    #[schemars(description = "Maximum strings to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Skip this many matches before returning")]
    pub offset: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Minimum string length")]
    pub min_length: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Substring the text must contain")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FunctionOriginsReq {
    #[serde(default)]
    #[schemars(description = "Which functions to return: user (default), library, thunk, or all")]
    pub kind: Option<String>,
    #[serde(default)]
    #[schemars(description = "Maximum functions to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetFuncFlagReq {
    #[schemars(description = "Address in hex or a function/symbol name")]
    pub ea: String,
    #[schemars(description = "Flag name: library, thunk, noret, static, hidden, outline, far, frame")]
    pub flag: String,
    #[serde(default)]
    #[schemars(description = "Set the flag when true (default), clear it when false")]
    pub on: Option<bool>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OffsetReq {
    #[schemars(description = "Address of the item whose operand is being marked")]
    pub ea: String,
    #[serde(default)]
    #[schemars(description = "Operand index, 0 by default")]
    pub operand: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Reference type: off8, off16, off32, off64, low8, low16, high8, high16")]
    pub r#type: Option<String>,
    #[serde(default)]
    #[schemars(description = "Base address the offset is relative to")]
    pub base: Option<String>,
    #[serde(default)]
    #[schemars(description = "Explicit target address")]
    pub target: Option<String>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OffsetCandidatesReq {
    #[schemars(description = "Address to start scanning from")]
    pub start: String,
    #[serde(default)]
    #[schemars(description = "Address to stop at; defaults to the end of the database")]
    pub end: Option<String>,
    #[serde(default)]
    #[schemars(description = "Maximum candidates to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IndexSearchReq {
    #[schemars(description = "Text to search for")]
    pub query: String,
    #[serde(default)]
    #[schemars(description = "Matching mode: substring (default) or fuzzy")]
    pub mode: Option<String>,
    #[serde(default)]
    #[schemars(description = "Maximum results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IndexSearchKindReq {
    #[schemars(description = "Text to search for")]
    pub query: String,
    #[schemars(description = "Index to search: functions, types, names, segments, comments, repeatable_comments")]
    pub index: String,
    #[serde(default)]
    #[schemars(description = "Matching mode: substring (default) or fuzzy")]
    pub mode: Option<String>,
    #[serde(default)]
    #[schemars(description = "Maximum results")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DscImagesReq {
    #[serde(default)]
    #[schemars(description = "Substring an image name must contain")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Only images already mapped into the database")]
    pub loaded_only: Option<bool>,
    #[serde(default)]
    #[schemars(description = "Maximum images to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DscImageReq {
    #[schemars(description = "Image name inside the shared cache")]
    pub image: String,
    #[serde(default)]
    #[schemars(description = "How many dependency levels to follow")]
    pub depth: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApplySignatureReq {
    #[schemars(description = "Signature file name, as listed by the signatures tool")]
    pub name: String,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FixupsReq {
    #[serde(default)]
    #[schemars(description = "Skip fixups below this address")]
    pub start: Option<String>,
    #[serde(default)]
    #[schemars(description = "Maximum fixups to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct NetnodeGetReq {
    #[schemars(description = "Netnode name, e.g. '$ entry points' or one you created")]
    pub name: String,
    #[serde(default)]
    #[schemars(description = "Maximum numbered slots and string slots to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct NetnodeListReq {
    #[serde(default)]
    #[schemars(description = "Substring a node name must contain")]
    pub filter: Option<String>,
    #[serde(default)]
    #[schemars(description = "Include IDA's own '$ ...' nodes (default true)")]
    pub include_reserved: Option<bool>,
    #[serde(default)]
    #[schemars(description = "Maximum nodes to return")]
    pub limit: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct NetnodeSetReq {
    #[schemars(description = "Node name. Names starting with '$ ' are reserved by IDA and refused.")]
    pub name: String,
    #[serde(default)]
    #[schemars(description = "String value to store on the node")]
    pub value: Option<String>,
    #[serde(default)]
    #[schemars(description = "Numbered slot to write, paired with alt")]
    pub index: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Value for the numbered slot")]
    pub alt: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SelectParserReq {
    #[serde(default)]
    #[schemars(description = "Source language: c, cpp, objc, swift, go, objcpp")]
    pub language: Option<String>,
    #[serde(default)]
    #[schemars(description = "Parser name, when selecting by name instead of language")]
    pub parser: Option<String>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeclareTypeForReq {
    #[schemars(description = "Source language: c, cpp, objc, swift, go, objcpp")]
    pub language: String,
    #[schemars(description = "Declarations to parse, in that language's syntax")]
    pub decl: String,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UndoPointReq {
    #[serde(default)]
    #[schemars(description = "Opaque tag recorded with the point, for traceability. Not a display label: IDA derives the undo description from the edits that follow the point.")]
    pub tag: Option<String>,
    #[serde(default)]
    #[schemars(description = "Session identifier")]
    pub session: Option<String>,
}

// ---- Tools ----

#[tool_router]
impl IdaMcpServer {
    pub fn new(coordinator: Arc<Coordinator>) -> Self {
        Self {
            coordinator,
            tool_router: Self::tool_router(),
        }
    }

    // ---- Management ----

    #[tool(description = "Open a binary for analysis. .i64/.idb databases load instantly. Raw binaries (e.g. PE/ELF that IDA can load) are analyzed SYNCHRONOUSLY: open_file blocks until IDA's initial auto-analysis completes, which can take minutes on large inputs (raise IDA_MCP_OPEN_TIMEOUT if needed). The response reports functions/segments; analysis is normally already done on return. Opening the same file from multiple sessions reuses one worker.")]
    async fn open_file(&self, Parameters(OpenFileReq { path, session }): Parameters<OpenFileReq>) -> String {
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

    #[tool(description = "List all active analysis sessions with their loaded binaries and status")]
    async fn list_instances(&self) -> String {
        let slots = self.coordinator.list_slots().await;
        serde_json::to_string_pretty(&slots).unwrap_or_else(|_| "[]".to_string())
    }

    #[tool(description = "Close an analysis session, stopping its worker process")]
    async fn close_session(&self, Parameters(CloseSessionReq { session }): Parameters<CloseSessionReq>) -> String {
        match self.coordinator.close_session(&session).await {
            Ok(()) => r#"{"closed": true}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    // ---- Core query ----

    #[tool(description = "Get IDB metadata: processor, bits, entry point, address range, function/segment counts")]
    async fn get_info(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "get_info", serde_json::json!({})).await
    }

    #[tool(description = "List functions with pagination and optional name filter. Returns function addresses, names, and sizes.")]
    async fn list_funcs(&self, Parameters(ListFuncsReq { session, filter, offset, limit }): Parameters<ListFuncsReq>) -> String {
        let mut params = serde_json::json!({});
        if let Some(f) = filter { params["filter"] = f.into(); }
        if let Some(o) = offset { params["offset"] = o.into(); }
        if let Some(l) = limit { params["limit"] = l.into(); }
        route(&self.coordinator, session, "list_funcs", params).await
    }

    #[tool(description = "List all segments (sections) with names, classes, address ranges, and sizes")]
    async fn list_segments(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "list_segments", serde_json::json!({})).await
    }

    #[tool(description = "Find a function by hex address (0x...) or name. Returns address, name, and size.")]
    async fn lookup_func(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "lookup_func", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Save the current analysis database as .i64 file")]
    async fn save_idb(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "save_idb", serde_json::json!({})).await
    }

    // ---- Analysis ----

    #[tool(description = "Decompile function at address to C pseudocode using Hex-Rays decompiler. Returns complete pseudocode text.")]
    async fn decompile(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "decompile", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Disassemble instructions at address. Returns assembly lines with addresses and sizes.")]
    async fn disasm(&self, Parameters(DisasmReq { ea, count, session }): Parameters<DisasmReq>) -> String {
        let mut params = serde_json::json!({"ea": ea});
        if let Some(c) = count { params["count"] = c.into(); }
        route(&self.coordinator, session, "disasm", params).await
    }

    #[tool(description = "Find all cross-references pointing TO an address (who calls/references this?)")]
    async fn xrefs_to(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "xrefs_to", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Find all cross-references FROM an address (what does this reference?)")]
    async fn xrefs_from(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "xrefs_from", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "List all functions called by the function at the given address")]
    async fn callees(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "callees", serde_json::json!({"ea": ea})).await
    }

    // ---- Memory ----

    #[tool(description = "Read raw bytes at address, returned as hex string (max 64KB)")]
    async fn get_bytes(&self, Parameters(GetBytesReq { ea, size, session }): Parameters<GetBytesReq>) -> String {
        route(&self.coordinator, session, "get_bytes", serde_json::json!({"ea": ea, "size": size})).await
    }

    #[tool(description = "Read a C string at the given address")]
    async fn get_string(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "get_string", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Patch bytes at address with hex string (e.g. '90909090' for NOPs)")]
    async fn patch_bytes(&self, Parameters(PatchBytesReq { ea, hex, session }): Parameters<PatchBytesReq>) -> String {
        route(&self.coordinator, session, "patch_bytes", serde_json::json!({"ea": ea, "hex": hex})).await
    }

    // ---- Modify ----

    #[tool(description = "Rename a function, global, or address")]
    async fn rename(&self, Parameters(RenameReq { ea, name, session }): Parameters<RenameReq>) -> String {
        route(&self.coordinator, session, "rename", serde_json::json!({"ea": ea, "name": name})).await
    }

    #[tool(description = "Set a comment at an address in the disassembly")]
    async fn set_comment(&self, Parameters(SetCommentReq { ea, comment, repeatable, session }): Parameters<SetCommentReq>) -> String {
        let mut params = serde_json::json!({"ea": ea, "comment": comment});
        if let Some(r) = repeatable { params["repeatable"] = r.into(); }
        route(&self.coordinator, session, "set_comment", params).await
    }

    #[tool(description = "Get the name (label) at an address")]
    async fn get_name(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "get_name", serde_json::json!({"ea": ea})).await
    }

    // ---- Search ----

    #[tool(description = "Search strings by regex pattern")]
    async fn find_regex(&self, Parameters(FindRegexReq { pattern, limit, session }): Parameters<FindRegexReq>) -> String {
        let mut p = serde_json::json!({"pattern": pattern});
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "find_regex", p).await
    }

    #[tool(description = "Search byte patterns with ?? wildcards (e.g. '48 8B ?? 90')")]
    async fn find_bytes(&self, Parameters(FindBytesReq { hex, start, limit, session }): Parameters<FindBytesReq>) -> String {
        let mut p = serde_json::json!({"hex": hex});
        if let Some(s) = start { p["start"] = s.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "find_bytes", p).await
    }

    #[tool(description = "List imports with optional filtering by name")]
    async fn imports(&self, Parameters(ImportsReq { filter, limit, session }): Parameters<ImportsReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "imports", p).await
    }

    #[tool(description = "Advanced function search with size/name filters")]
    async fn func_query(&self, Parameters(FuncQueryReq { filter, min_size, max_size, limit, session }): Parameters<FuncQueryReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(v) = min_size { p["min_size"] = v.into(); }
        if let Some(v) = max_size { p["max_size"] = v.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "func_query", p).await
    }

    #[tool(description = "List global variables (non-function named addresses)")]
    async fn list_globals(&self, Parameters(FilterLimitReq { filter, limit, session }): Parameters<FilterLimitReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "list_globals", p).await
    }

    #[tool(description = "Convert a number between hex/decimal/octal/binary representations")]
    async fn int_convert(&self, Parameters(IntConvertReq { value }): Parameters<IntConvertReq>) -> String {
        // Needs no worker, so it never opens a session. The output shape mirrors the
        // worker's int_convert in cmd_search.cpp, including base-0 radix detection.
        let s = value.trim();
        let parsed: Option<u64> = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else if s.len() > 1 && s.starts_with('0') && s[1..].bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            u64::from_str_radix(&s[1..], 8).ok()
        } else {
            // A negative literal is accepted and kept as its two's-complement bits,
            // which is what the worker does and what a reverser expects to see.
            s.parse::<u64>().ok().or_else(|| s.parse::<i64>().ok().map(i64::cast_unsigned))
        };

        let val = match parsed {
            Some(v) => v,
            None => return serde_json::json!({"error": format!("could not parse '{}' as a number", value)}).to_string(),
        };

        let bin = if val == 0 { "0b0".to_string() } else { format!("0b{val:b}") };

        serde_json::json!({
            "hex": format!("0x{:X}", val),
            "dec": format!("{}", val),
            "oct": format!("0{:o}", val),
            "bin": bin,
            // The same bits read as signed; this reinterpretation is the point of the tool.
            "signed": val.cast_signed(),
        }).to_string()
    }

    // ---- Graph / CFG ----

    #[tool(description = "Get control flow graph basic blocks for a function")]
    async fn basic_blocks(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "basic_blocks", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Build a call graph from root functions with bounded depth")]
    async fn callgraph(&self, Parameters(CallgraphReq { roots, depth, session }): Parameters<CallgraphReq>) -> String {
        let mut p = serde_json::json!({"roots": roots});
        if let Some(d) = depth { p["depth"] = d.into(); }
        route(&self.coordinator, session, "callgraph", p).await
    }

    #[tool(description = "Search instructions by mnemonic within a function or globally")]
    async fn insn_query(&self, Parameters(InsnQueryReq { mnemonic, ea, limit, session }): Parameters<InsnQueryReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(m) = mnemonic { p["mnemonic"] = m.into(); }
        if let Some(e) = ea { p["ea"] = e.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "insn_query", p).await
    }

    #[tool(description = "Get function profile: size, callers, callees, referenced strings")]
    async fn func_profile(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "func_profile", serde_json::json!({"ea": ea})).await
    }

    // ---- Types ----

    #[tool(description = "Apply a C type declaration to an address (e.g. 'int __fastcall foo(int a1)')")]
    async fn set_type(&self, Parameters(SetTypeReq { ea, r#type, session }): Parameters<SetTypeReq>) -> String {
        route(&self.coordinator, session, "set_type", serde_json::json!({"ea": ea, "type": r#type})).await
    }

    #[tool(description = "Inspect type information at an address or by type name")]
    async fn type_inspect(&self, Parameters(TypeInspectReq { ea, name, session }): Parameters<TypeInspectReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(e) = ea { p["ea"] = e.into(); }
        if let Some(n) = name { p["name"] = n.into(); }
        route(&self.coordinator, session, "type_inspect", p).await
    }

    #[tool(description = "Parse and add C type declarations to the local type library")]
    async fn declare_type(&self, Parameters(DeclareTypeReq { decl, session }): Parameters<DeclareTypeReq>) -> String {
        route(&self.coordinator, session, "declare_type", serde_json::json!({"decl": decl})).await
    }

    #[tool(description = "Search local types by name pattern")]
    async fn type_query(&self, Parameters(FilterLimitReq { filter, limit, session }): Parameters<FilterLimitReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "type_query", p).await
    }

    #[tool(description = "Search struct/union type definitions")]
    async fn search_structs(&self, Parameters(FilterLimitReq { filter, limit, session }): Parameters<FilterLimitReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "search_structs", p).await
    }

    #[tool(description = "Infer variable types for a function using Hex-Rays decompiler")]
    async fn infer_types(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "infer_types", serde_json::json!({"ea": ea})).await
    }

    // ---- Stack ----

    #[tool(description = "Get stack frame variables for a function (via Hex-Rays)")]
    async fn stack_frame(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "stack_frame", serde_json::json!({"ea": ea})).await
    }

    // ---- Extended modify ----

    #[tool(description = "Append text to an existing comment at an address")]
    async fn append_comments(&self, Parameters(AppendCommentsReq { ea, comment, session }): Parameters<AppendCommentsReq>) -> String {
        route(&self.coordinator, session, "append_comments", serde_json::json!({"ea": ea, "comment": comment})).await
    }

    #[tool(description = "Define a function at address")]
    async fn define_func(&self, Parameters(DefineFuncReq { ea, end, session }): Parameters<DefineFuncReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(e) = end { p["end"] = e.into(); }
        route(&self.coordinator, session, "define_func", p).await
    }

    #[tool(description = "Convert bytes to code instructions")]
    async fn define_code(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "define_code", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Undefine items (convert back to raw bytes)")]
    async fn undefine(&self, Parameters(UndefineReq { ea, size, session }): Parameters<UndefineReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(s) = size { p["size"] = s.into(); }
        route(&self.coordinator, session, "undefine", p).await
    }

    // ---- Extended memory ----

    #[tool(description = "Read an integer value at address (1/2/4/8 bytes)")]
    async fn get_int(&self, Parameters(GetIntReq { ea, size, session }): Parameters<GetIntReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(s) = size { p["size"] = s.into(); }
        route(&self.coordinator, session, "get_int", p).await
    }

    #[tool(description = "Write an integer value at address")]
    async fn put_int(&self, Parameters(PutIntReq { ea, value, size, session }): Parameters<PutIntReq>) -> String {
        let mut p = serde_json::json!({"ea": ea, "value": value});
        if let Some(s) = size { p["size"] = s.into(); }
        route(&self.coordinator, session, "put_int", p).await
    }

    // ---- Composite ----

    #[tool(description = "Deep function analysis: decompile + disasm + xrefs + strings + callees + basic blocks in one call")]
    async fn analyze_function(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "analyze_function", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Complete binary triage: metadata, segments, top functions, imports, strings, entries")]
    async fn survey_binary(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "survey_binary", serde_json::json!({})).await
    }

    #[tool(description = "Trace data flow by following xrefs forward or backward from an address")]
    async fn trace_data_flow(&self, Parameters(TraceDataFlowReq { ea, direction, depth, session }): Parameters<TraceDataFlowReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(d) = direction { p["direction"] = d.into(); }
        if let Some(d) = depth { p["depth"] = d.into(); }
        route(&self.coordinator, session, "trace_data_flow", p).await
    }

    // ---- Query variants ----

    #[tool(description = "Query imports with module and name filtering, pagination")]
    async fn imports_query(&self, Parameters(ImportsQueryReq { filter, module, offset, limit, session }): Parameters<ImportsQueryReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(m) = module { p["module"] = m.into(); }
        if let Some(o) = offset { p["offset"] = o.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "imports_query", p).await
    }

    #[tool(description = "Generic entity search: query functions, globals, strings, or imports by kind")]
    async fn entity_query(&self, Parameters(EntityQueryReq { kind, filter, limit, session }): Parameters<EntityQueryReq>) -> String {
        let mut p = serde_json::json!({"kind": kind});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "entity_query", p).await
    }

    #[tool(description = "Unified xref query with direction and type filtering")]
    async fn xref_query(&self, Parameters(XrefQueryReq { ea, direction, code_only, limit, session }): Parameters<XrefQueryReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(d) = direction { p["direction"] = d.into(); }
        if let Some(c) = code_only { p["code_only"] = c.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "xref_query", p).await
    }

    #[tool(description = "Find references to a struct field offset within a function")]
    async fn xrefs_to_field(&self, Parameters(XrefsToFieldReq { ea, field_offset, limit, session }): Parameters<XrefsToFieldReq>) -> String {
        let mut p = serde_json::json!({"ea": ea, "field_offset": field_offset});
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "xrefs_to_field", p).await
    }

    #[tool(description = "Batch decompile multiple functions at once")]
    async fn analyze_batch(&self, Parameters(AddressesReq { addresses, session }): Parameters<AddressesReq>) -> String {
        route(&self.coordinator, session, "analyze_batch", serde_json::json!({"addresses": addresses})).await
    }

    #[tool(description = "Export function info with optional prototypes")]
    async fn export_funcs(&self, Parameters(ExportFuncsReq { addresses, limit, session }): Parameters<ExportFuncsReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(a) = addresses { p["addresses"] = serde_json::json!(a); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "export_funcs", p).await
    }

    #[tool(description = "Analyze a group of related functions: internal call graph, shared data, per-function summaries")]
    async fn analyze_component(&self, Parameters(AddressesReq { addresses, session }): Parameters<AddressesReq>) -> String {
        route(&self.coordinator, session, "analyze_component", serde_json::json!({"addresses": addresses})).await
    }

    #[tool(description = "Apply an edit (rename/set_type/set_comment) and show before/after decompilation diff")]
    async fn diff_before_after(&self, Parameters(DiffBeforeAfterReq { ea, action, value, session }): Parameters<DiffBeforeAfterReq>) -> String {
        route(&self.coordinator, session, "diff_before_after",
            serde_json::json!({"ea": ea, "action": action, "value": value})).await
    }

    #[tool(description = "Create or update an enum type with named members")]
    async fn enum_upsert(&self, Parameters(EnumUpsertReq { name, members, session }): Parameters<EnumUpsertReq>) -> String {
        let members_val: serde_json::Value = serde_json::from_str(&members).unwrap_or(serde_json::json!([]));
        route(&self.coordinator, session, "enum_upsert",
            serde_json::json!({"name": name, "members": members_val})).await
    }

    #[tool(description = "Read struct fields from memory at an address")]
    async fn read_struct(&self, Parameters(ReadStructReq { ea, struct_name, session }): Parameters<ReadStructReq>) -> String {
        route(&self.coordinator, session, "read_struct",
            serde_json::json!({"ea": ea, "struct_name": struct_name})).await
    }

    #[tool(description = "Batch apply types to multiple addresses")]
    async fn type_apply_batch(&self, Parameters(TypeApplyBatchReq { items, session }): Parameters<TypeApplyBatchReq>) -> String {
        let items_val: serde_json::Value = serde_json::from_str(&items).unwrap_or(serde_json::json!([]));
        route(&self.coordinator, session, "type_apply_batch",
            serde_json::json!({"items": items_val})).await
    }

    #[tool(description = "Rename or retype a local variable in a function (via Hex-Rays)")]
    async fn declare_stack(&self, Parameters(DeclareStackReq { ea, old_name, new_name, r#type, session }): Parameters<DeclareStackReq>) -> String {
        let mut p = serde_json::json!({"ea": ea, "old_name": old_name});
        if let Some(n) = new_name { p["new_name"] = n.into(); }
        if let Some(t) = r#type { p["type"] = t.into(); }
        route(&self.coordinator, session, "declare_stack", p).await
    }

    #[tool(description = "Reset a local variable name back to IDA default")]
    async fn delete_stack(&self, Parameters(DeleteStackReq { ea, name, session }): Parameters<DeleteStackReq>) -> String {
        route(&self.coordinator, session, "delete_stack", serde_json::json!({"ea": ea, "name": name})).await
    }

    #[tool(description = "Read a global variable's value by name or address")]
    async fn get_global_value(&self, Parameters(GetGlobalValueReq { target, session }): Parameters<GetGlobalValueReq>) -> String {
        route(&self.coordinator, session, "get_global_value", serde_json::json!({"target": target})).await
    }

    #[tool(description = "Warm up a session: trigger Hex-Rays init and ensure analysis is complete")]
    async fn server_warmup(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        let info_result = route(&self.coordinator, session.clone(), "get_info", serde_json::json!({})).await;
        let ping_result = route(&self.coordinator, session, "ping", serde_json::json!({})).await;
        serde_json::json!({
            "warmed_up": true,
            "info": info_result,
            "ping": ping_result,
        }).to_string()
    }

    // ---- Batch conversion ----

    #[tool(description = "Batch convert raw binaries to .i64 databases. Opens workers in parallel, auto-analyzes, saves .i64. Returns per-file results with function counts and elapsed time. `concurrency` is capped by IDA_MCP_MAX_SLOTS: asking for more parallelism than the pool allows converts what fits and reports the rest as per-file errors, so keep concurrency at or below max_slots.")]
    async fn batch_convert(&self, Parameters(BatchConvertReq { paths, output_dir, concurrency, max_analysis_seconds }): Parameters<BatchConvertReq>) -> String {
        // Two independent limits meet here: this semaphore bounds how many files are
        // in flight, while the coordinator's max_slots bounds how many workers exist
        // at all. When the pool is the tighter one, the excess opens fail rather than
        // queue, and each failure lands in that file's result entry.
        // Clamped to 50 first, so usize holds it on every target width.
        let concurrency = usize::try_from(concurrency.unwrap_or(5).clamp(1, 50)).unwrap_or(5);
        let max_secs = max_analysis_seconds.unwrap_or(600).clamp(30, 3600);

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

    // ---- Control flow ----

    #[tool(description = "Resolve a switch/jump table at an address: case count, jump table location, default target, and every case target with its function name. Works on the switch instruction or any address inside the idiom. Without this an indirect jump reads as an unresolved branch.")]
    async fn switch_info(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "switch_info", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "List the C++ try/catch and SEH exception blocks in a function, with guarded ranges and handler addresses. This structure appears in neither the disassembly nor the pseudocode.")]
    async fn try_blocks(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "try_blocks", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Ask IDA's value propagation what a register holds at an address. Returns the constant when one can be proven, otherwise reports that it is not constant there.")]
    async fn reg_value(&self, Parameters(RegValueReq { ea, reg, session }): Parameters<RegValueReq>) -> String {
        route(&self.coordinator, session, "reg_value", serde_json::json!({"ea": ea, "reg": reg})).await
    }

    #[tool(description = "List the addresses IDA flagged as questionable during analysis: unresolved jumps, bad stack pointers, undisassembled code. A good starting point for finding where analysis went wrong.")]
    async fn problems(&self, Parameters(LimitOnlyReq { limit, session }): Parameters<LimitOnlyReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "problems", p).await
    }

    #[tool(description = "List relocations, showing which operands the loader rewrites at load time and what they point at.")]
    async fn fixups(&self, Parameters(FixupsReq { start, limit, session }): Parameters<FixupsReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(s) = start { p["start"] = s.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "fixups", p).await
    }

    #[tool(description = "Read the segment register values in effect at an address. Relevant on segmented architectures, where addressing depends on them.")]
    async fn seg_regs(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "seg_regs", serde_json::json!({"ea": ea})).await
    }

    // ---- Microcode ----

    #[tool(description = "Dump the decompiler's microcode for a function, block by block. Microcode is the IR the pseudocode is built from and exposes call arguments, register liveness and optimization steps that the printed C hides. Use an earlier maturity to see the unoptimized form.")]
    async fn microcode(&self, Parameters(MicrocodeReq { ea, maturity, limit, session }): Parameters<MicrocodeReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(m) = maturity { p["maturity"] = m.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "microcode", p).await
    }

    #[tool(description = "Microcode shape only — block and instruction counts at a given maturity, without the listing. Cheap enough to run across many functions.")]
    async fn microcode_stats(&self, Parameters(MicrocodeReq { ea, maturity, limit: _, session }): Parameters<MicrocodeReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(m) = maturity { p["maturity"] = m.into(); }
        route(&self.coordinator, session, "microcode_stats", p).await
    }

    #[tool(description = "List the microcode maturity levels in the order the decompiler runs them, so a caller can pick one without guessing at names.")]
    async fn microcode_maturities(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "microcode_maturities", serde_json::json!({})).await
    }

    // ---- Strings ----

    #[tool(description = "List strings with address, length, encoding and text. Includes strings the decompiler recovered, which carry no bytes at their address and are marked from_decompiler.")]
    async fn strings(&self, Parameters(StringsReq { limit, offset, min_length, filter, session }): Parameters<StringsReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(l) = limit { p["limit"] = l.into(); }
        if let Some(o) = offset { p["offset"] = o.into(); }
        if let Some(m) = min_length { p["min_length"] = m.into(); }
        if let Some(f) = filter { p["filter"] = f.into(); }
        route(&self.coordinator, session, "strings", p).await
    }

    #[tool(description = "Only the strings the decompiler reconstructed — assembled at runtime or stored in a form no data scan finds. The list fills lazily, so decompile the functions of interest first.")]
    async fn strings_decompiled(&self, Parameters(LimitOnlyReq { limit, session }): Parameters<LimitOnlyReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "strings_decompiled", p).await
    }

    #[tool(description = "Rebuild the string list. Needed after patching bytes or defining new data, so newly created literals appear.")]
    async fn strings_rebuild(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "strings_rebuild", serde_json::json!({})).await
    }

    // ---- Signatures and function origins ----

    #[tool(description = "List the FLIRT signature files IDA has loaded and how many functions each matched.")]
    async fn signatures(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "signatures", serde_json::json!({})).await
    }

    #[tool(description = "Apply a FLIRT signature file by name. Matching is planned and takes effect as analysis next runs over the candidate addresses.")]
    async fn apply_signature(&self, Parameters(ApplySignatureReq { name, session }): Parameters<ApplySignatureReq>) -> String {
        route(&self.coordinator, session, "apply_signature", serde_json::json!({"name": name})).await
    }

    #[tool(description = "Split the function list by origin: user code, FLIRT-matched library code, or thunks. On a statically linked binary this is the fastest way to cut thousands of uninteresting library functions out of view.")]
    async fn function_origins(&self, Parameters(FunctionOriginsReq { kind, limit, session }): Parameters<FunctionOriginsReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(k) = kind { p["kind"] = k.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "function_origins", p).await
    }

    #[tool(description = "Read a function's flags by name rather than as a bit mask: library, thunk, noret, static, and so on.")]
    async fn func_flags(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "func_flags", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "Set or clear one function flag. Marking a function as library removes it from the user listing, which is how recognised code is pruned by hand.")]
    async fn set_func_flag(&self, Parameters(SetFuncFlagReq { ea, flag, on, session }): Parameters<SetFuncFlagReq>) -> String {
        let mut p = serde_json::json!({"ea": ea, "flag": flag});
        if let Some(o) = on { p["on"] = o.into(); }
        route(&self.coordinator, session, "set_func_flag", p).await
    }

    // ---- Offsets ----

    #[tool(description = "Mark an operand as an address reference. An unmarked immediate stays a magic number; marking it makes IDA resolve the name, create the xref, and carry it into the pseudocode.")]
    async fn set_offset(&self, Parameters(OffsetReq { ea, operand, r#type, base, target, session }): Parameters<OffsetReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(o) = operand { p["operand"] = o.into(); }
        if let Some(t) = r#type { p["type"] = t.into(); }
        if let Some(b) = base { p["base"] = b.into(); }
        if let Some(t) = target { p["target"] = t.into(); }
        route(&self.coordinator, session, "set_offset", p).await
    }

    #[tool(description = "Remove an operand's reference marking, returning it to a plain number.")]
    async fn clear_offset(&self, Parameters(OffsetReq { ea, operand, r#type: _, base: _, target: _, session }): Parameters<OffsetReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(o) = operand { p["operand"] = o.into(); }
        route(&self.coordinator, session, "clear_offset", p).await
    }

    #[tool(description = "Report whether an operand carries reference info, and what address and name it resolves to.")]
    async fn get_offset(&self, Parameters(OffsetReq { ea, operand, r#type: _, base: _, target: _, session }): Parameters<OffsetReq>) -> String {
        let mut p = serde_json::json!({"ea": ea});
        if let Some(o) = operand { p["operand"] = o.into(); }
        route(&self.coordinator, session, "get_offset", p).await
    }

    #[tool(description = "Scan a range for immediates that look like addresses but are not yet marked as references — the sweep that turns an unmarked pointer table into navigable links.")]
    async fn offset_candidates(&self, Parameters(OffsetCandidatesReq { start, end, limit, session }): Parameters<OffsetCandidatesReq>) -> String {
        let mut p = serde_json::json!({"start": start});
        if let Some(e) = end { p["end"] = e.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "offset_candidates", p).await
    }

    // ---- Global index ----

    #[tool(description = "One query across every index — functions, names, types, segments and comments — with optional fuzzy matching. Replaces a fan-out of per-kind list calls with a single ranked lookup. Note: IDA disables the indexer in headless mode, so this reports unavailable there.")]
    async fn index_search(&self, Parameters(IndexSearchReq { query, mode, limit, session }): Parameters<IndexSearchReq>) -> String {
        let mut p = serde_json::json!({"query": query});
        if let Some(m) = mode { p["mode"] = m.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "index_search", p).await
    }

    #[tool(description = "The same index query restricted to one kind, for when the kind is already known.")]
    async fn index_search_kind(&self, Parameters(IndexSearchKindReq { query, index, mode, limit, session }): Parameters<IndexSearchKindReq>) -> String {
        let mut p = serde_json::json!({"query": query, "index": index});
        if let Some(m) = mode { p["mode"] = m.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "index_search_kind", p).await
    }

    #[tool(description = "Report whether the indexer is available and list the index names and matching modes it accepts.")]
    async fn index_status(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "index_status", serde_json::json!({})).await
    }

    // ---- dyld shared cache ----

    #[tool(description = "Report whether this database is an Apple dyld shared cache, and if so its path, image count and ASLR slide. Returns is_shared_cache false for every other input, so it is safe to call first.")]
    async fn dsc_status(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "dsc_status", serde_json::json!({})).await
    }

    #[tool(description = "List the images inside a dyld shared cache, marking which are already mapped into the database.")]
    async fn dsc_images(&self, Parameters(DscImagesReq { filter, loaded_only, limit, session }): Parameters<DscImagesReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(l) = loaded_only { p["loaded_only"] = l.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "dsc_images", p).await
    }

    #[tool(description = "Identify which image and region an address belongs to inside a shared cache — a question the mapped bytes alone cannot answer.")]
    async fn dsc_locate(&self, Parameters(EaReq { ea, session }): Parameters<EaReq>) -> String {
        route(&self.coordinator, session, "dsc_locate", serde_json::json!({"ea": ea})).await
    }

    #[tool(description = "List an image's link dependencies as recorded by the shared cache.")]
    async fn dsc_dependencies(&self, Parameters(DscImageReq { image, depth, session }): Parameters<DscImageReq>) -> String {
        let mut p = serde_json::json!({"image": image});
        if let Some(d) = depth { p["depth"] = d.into(); }
        route(&self.coordinator, session, "dsc_dependencies", p).await
    }

    #[tool(description = "List the regions an image occupies. Images are not contiguous inside a shared cache.")]
    async fn dsc_regions(&self, Parameters(DscImageReq { image, depth: _, session }): Parameters<DscImageReq>) -> String {
        route(&self.coordinator, session, "dsc_regions", serde_json::json!({"image": image})).await
    }

    // ---- Database internals ----

    #[tool(description = "Read a netnode — the key-value store the whole database is built on. Reaches loader metadata, plugin state and anything else no typed API exposes. Names starting with '$ ' belong to IDA.")]
    async fn netnode_get(&self, Parameters(NetnodeGetReq { name, limit, session }): Parameters<NetnodeGetReq>) -> String {
        let mut p = serde_json::json!({"name": name});
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "netnode_get", p).await
    }

    #[tool(description = "Enumerate the netnodes present. The only way to discover what a loader or plugin stored without already knowing the node name.")]
    async fn netnode_list(&self, Parameters(NetnodeListReq { filter, include_reserved, limit, session }): Parameters<NetnodeListReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(f) = filter { p["filter"] = f.into(); }
        if let Some(r) = include_reserved { p["include_reserved"] = r.into(); }
        if let Some(l) = limit { p["limit"] = l.into(); }
        route(&self.coordinator, session, "netnode_list", p).await
    }

    #[tool(description = "Create or update a netnode you own. IDA's own '$ ...' nodes are refused: writing to one corrupts the database with no diagnostic and no way back.")]
    async fn netnode_set(&self, Parameters(NetnodeSetReq { name, value, index, alt, session }): Parameters<NetnodeSetReq>) -> String {
        let mut p = serde_json::json!({"name": name});
        if let Some(v) = value { p["value"] = v.into(); }
        if let Some(i) = index { p["index"] = i.into(); }
        if let Some(a) = alt { p["alt"] = a.into(); }
        route(&self.coordinator, session, "netnode_set", p).await
    }

    #[tool(description = "Report which source-language parser declarations are currently read with, and which languages are available.")]
    async fn parser_status(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "parser_status", serde_json::json!({})).await
    }

    #[tool(description = "Select the parser used by declare_type. Declaring a Swift or Go type through the C parser either fails or silently produces the wrong layout, so set this first.")]
    async fn select_parser(&self, Parameters(SelectParserReq { language, parser, session }): Parameters<SelectParserReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(l) = language { p["language"] = l.into(); }
        if let Some(n) = parser { p["parser"] = n.into(); }
        route(&self.coordinator, session, "select_parser", p).await
    }

    #[tool(description = "Parse declarations with a named language's parser in one call, instead of switching the parser and then calling declare_type.")]
    async fn declare_type_for(&self, Parameters(DeclareTypeForReq { language, decl, session }): Parameters<DeclareTypeForReq>) -> String {
        route(&self.coordinator, session, "declare_type_for", serde_json::json!({"language": language, "decl": decl})).await
    }

    #[tool(description = "Report what the next undo or redo would revert, so a caller can check before acting.")]
    async fn undo_status(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "undo_status", serde_json::json!({})).await
    }

    #[tool(description = "Mark a point to come back to. Call it before a batch of edits, not after. The undo description IDA reports comes from the edits made after the point, not from the tag given here.")]
    async fn undo_point(&self, Parameters(UndoPointReq { tag, session }): Parameters<UndoPointReq>) -> String {
        let mut p = serde_json::json!({});
        if let Some(t) = tag { p["tag"] = t.into(); }
        route(&self.coordinator, session, "undo_point", p).await
    }

    #[tool(description = "Revert to the last undo point. Fails when there is nothing to undo rather than doing nothing.")]
    async fn undo(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "undo", serde_json::json!({})).await
    }

    #[tool(description = "Reapply the last undone change.")]
    async fn redo(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "redo", serde_json::json!({})).await
    }

    // ---- Analysis lifecycle ----

    #[tool(description = "Check auto-analysis status (non-blocking). Returns whether analysis is done, current queue state, function/segment counts. Use after opening a raw binary to poll progress.")]
    async fn analysis_status(&self, Parameters(SessionReq { session }): Parameters<SessionReq>) -> String {
        route(&self.coordinator, session, "analysis_status", serde_json::json!({})).await
    }

    #[tool(description = "Wait for auto-analysis to complete with timeout. Blocks until analysis finishes or timeout. Returns final status with elapsed time. Sends progress events every 2s.")]
    async fn wait_analysis(&self, Parameters(WaitAnalysisReq { max_seconds, session }): Parameters<WaitAnalysisReq>) -> String {
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
            "max_slots": self.coordinator.max_slots(),
        }).to_string()
    }
}

#[tool_handler]
impl ServerHandler for IdaMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            // from_build_env() would resolve env! inside rmcp's own crate and report
            // rmcp's name and version instead of this one's.
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
            .with_instructions(
                "Multi-instance IDA Pro MCP server. Open .i64/.idb databases or raw binaries with open_file, \
                 then use analysis tools (decompile, disasm, xrefs, types, etc.) to query them. \
                 Address arguments (ea/target) accept either a hex address or a function/symbol name. \
                 .i64/.idb databases load instantly; a raw binary is analyzed SYNCHRONOUSLY, so open_file \
                 blocks until IDA's initial auto-analysis completes (can take minutes on large inputs; \
                 raise IDA_MCP_OPEN_TIMEOUT if needed). Multiple sessions can be open at once for \
                 different binaries; opening the SAME file from two sessions shares one worker and one \
                 mutable database."
                    .to_string(),
            )
    }
}
