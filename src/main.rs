mod coordinator;
mod protocol;
mod slot;
mod tools;

use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn, Level};
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
    let server = IdaMcpServer::new(coordinator.clone());

    let transport = rmcp::transport::io::stdio();
    let server_handle = server.serve(transport).await?;

    info!("MCP server running on stdio");

    // A signal has to be caught for the workers' database directories to be removed:
    // terminating on the default disposition skips unwinding, so `Slot::drop` never
    // runs and each directory is stranded. Clients stop their MCP servers this way.
    tokio::select! {
        reason = server_handle.waiting() => {
            info!("Server quit: {:?}", reason?);
            coordinator.shutdown().await;
        }
        () = terminate_signal() => {
            info!("Received a termination signal");
            coordinator.shutdown().await;
            // The stdio transport reads stdin on a blocking task, which the runtime
            // waits for on the way out — and the peer's pipe is still open, so that
            // read never returns. Every worker and directory this process owns was
            // released just above, which is what a signal would otherwise skip.
            std::process::exit(0);
        }
    }

    Ok(())
}

/// Resolves when the process is asked to stop.
#[cfg(unix)]
async fn terminate_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        // Without the handler the default disposition applies, which is the behaviour
        // this function exists to replace; waiting forever leaves the other branch.
        Err(e) => {
            warn!(error = %e, "cannot listen for SIGTERM");
            return std::future::pending().await;
        }
    };
    tokio::select! {
        _ = term.recv() => {},
        r = tokio::signal::ctrl_c() => {
            if let Err(e) = r {
                warn!(error = %e, "cannot listen for Ctrl-C");
            }
        },
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!(error = %e, "cannot listen for Ctrl-C");
        std::future::pending::<()>().await;
    }
}
