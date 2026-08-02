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
    // stdout carries the MCP stream; logs go to stderr.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    info!("ida-hive v{}", env!("CARGO_PKG_VERSION"));

    let worker_exe = std::env::var("IDA_MCP_WORKER_EXE")
        .unwrap_or_else(|_| "ida_mcp_worker".to_string());
    let max_slots: usize = std::env::var("IDA_MCP_MAX_SLOTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    // Bounds the wait for worker readiness. Opening a raw binary blocks until IDA's
    // initial analysis finishes, which runs to minutes on large inputs.
    let open_timeout_secs: u64 = std::env::var("IDA_MCP_OPEN_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);

    let config = CoordinatorConfig {
        worker_exe,
        max_slots,
        open_timeout: std::time::Duration::from_secs(open_timeout_secs),
    };

    info!(max_slots = config.max_slots, worker = %config.worker_exe, "Starting coordinator");

    let coordinator = Arc::new(Coordinator::new(config));
    let server = IdaMcpServer::new(coordinator);

    let transport = rmcp::transport::io::stdio();
    let server_handle = server.serve(transport).await?;

    info!("MCP server running on stdio");

    let quit_reason = server_handle.waiting().await?;
    info!("Server quit: {:?}", quit_reason);

    Ok(())
}
