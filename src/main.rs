// main.rs - IDA MCP Server entry point
//
// Multi-instance IDA MCP server:
// - Rust coordinator manages up to 20 C++ idalib worker processes
// - Each worker loads one pre-analyzed .i64 database in headless mode
// - MCP tools route requests to the correct worker by session
//
// Usage: ida-mcp-rs
// Environment:
//   IDA_MCP_WORKER_EXE  — path to ida_mcp_worker.exe
//   IDA_MCP_MAX_SLOTS   — max concurrent workers (default 20)

mod coordinator;
mod protocol;
mod slot;
mod tools;

use std::sync::Arc;
use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

use rmcp::ServiceExt;

use coordinator::{Coordinator, CoordinatorConfig};
use tools::IdaMcpServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Logs to stderr — stdout is reserved for MCP protocol
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    info!("ida-mcp-rs v{}", env!("CARGO_PKG_VERSION"));

    let worker_exe = std::env::var("IDA_MCP_WORKER_EXE")
        .unwrap_or_else(|_| "ida_mcp_worker".to_string());
    let max_slots: usize = std::env::var("IDA_MCP_MAX_SLOTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let config = CoordinatorConfig {
        worker_exe,
        max_slots,
    };

    info!(max_slots = config.max_slots, worker = %config.worker_exe, "Starting coordinator");

    let coordinator = Arc::new(Coordinator::new(config));
    let server = IdaMcpServer { coordinator };

    // Serve MCP protocol over stdio
    let transport = rmcp::transport::io::stdio();
    let server_handle = server.serve(transport).await?;

    info!("MCP server running on stdio");

    // Block until client disconnects
    let quit_reason = server_handle.waiting().await?;
    info!("Server quit: {:?}", quit_reason);

    Ok(())
}
