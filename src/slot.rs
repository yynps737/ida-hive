// slot.rs - Single worker process management
//
// Each Slot owns one C++ idalib child process. Communication is via
// JSON Lines over stdin/stdout. A background tokio task reads all
// stdout lines and routes responses to waiting callers via oneshot channels.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::protocol::*;

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<serde_json::Value>>>>>;

/// A single worker slot — manages one C++ idalib child process
pub struct Slot {
    pub id: String,
    pub path: String,
    /// Private, writable directory for this worker's database files. Unique per
    /// slot so concurrent opens of the same binary never collide on IDA's
    /// on-disk database/lock files. Created on start, removed on drop.
    db_dir: PathBuf,
    child: Mutex<Option<Child>>,
    pending: PendingMap,
    next_id: AtomicU64,
    stdin_tx: Mutex<Option<mpsc::Sender<String>>>,
    pub ready_data: Mutex<Option<serde_json::Value>>,
    dead: Arc<AtomicBool>,
}

impl Slot {
    pub fn new(id: String, path: String) -> Self {
        let db_dir = std::env::temp_dir().join(format!("ida-hive-{}", id));
        Self {
            id,
            path,
            db_dir,
            child: Mutex::new(None),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            stdin_tx: Mutex::new(None),
            ready_data: Mutex::new(None),
            dead: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Spawn the C++ worker process
    pub async fn start(&self, worker_exe: &str) -> Result<()> {
        info!(slot = %self.id, path = %self.path, "Starting worker");
        self.dead.store(false, Ordering::SeqCst);

        // Give this worker its own private, writable database directory so it
        // never writes next to the input and never collides with another worker
        // opening the same binary.
        tokio::fs::create_dir_all(&self.db_dir).await.map_err(|e| {
            anyhow!("Failed to create db dir {}: {}", self.db_dir.display(), e)
        })?;

        let mut child = Command::new(worker_exe)
            .arg(&self.path)
            .arg(&self.db_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = child.stdout.take().ok_or_else(|| anyhow!("No stdout"))?;
        let stdin = child.stdin.take().ok_or_else(|| anyhow!("No stdin"))?;

        // Stdin writer task
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<String>(64);
        let mut stdin_writer = stdin;
        tokio::spawn(async move {
            while let Some(line) = stdin_rx.recv().await {
                if stdin_writer.write_all(line.as_bytes()).await.is_err() { break; }
                if stdin_writer.flush().await.is_err() { break; }
            }
        });

        *self.stdin_tx.lock().await = Some(stdin_tx);
        *self.child.lock().await = Some(child);

        // Read stdout lines
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        // Wait for the worker's "ready" event, bounded by a timeout. A worker
        // that hangs without emitting output (or closing stdout) must not block
        // start() forever — and because open() serializes opens, an unbounded
        // wait here would stall every other open too.
        let slot_id = self.id.clone();
        let ready = async {
            loop {
                match lines.next_line().await? {
                    Some(line) if !line.is_empty() => {
                        match serde_json::from_str::<WorkerMessage>(&line) {
                            Ok(WorkerMessage::Event(evt)) if evt.event == "ready" => {
                                info!(slot = %slot_id, "Worker ready");
                                *self.ready_data.lock().await = Some(evt.data);
                                return Ok(());
                            }
                            // Worker reported a fatal startup failure (bad license,
                            // locked/unreadable file, copy failure, ...). Surface the
                            // real reason instead of a generic "exited before ready".
                            Ok(WorkerMessage::Event(evt)) if evt.event == "init_error" => {
                                let msg = evt.data.get("message").and_then(|v| v.as_str())
                                    .unwrap_or("worker failed to initialize");
                                let stage = evt.data.get("stage").and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let code = evt.data.get("code").and_then(|v| v.as_i64());
                                return Err(match code {
                                    Some(c) => anyhow!("Worker init failed at {} (code {}): {}", stage, c, msg),
                                    None => anyhow!("Worker init failed at {}: {}", stage, msg),
                                });
                            }
                            Ok(_) => {} // ignore other pre-ready messages
                            Err(e) => warn!(slot = %slot_id, "Parse error during init: {}", e),
                        }
                    }
                    Some(_) => continue,
                    None => return Err(anyhow!("Worker exited before sending ready event")),
                }
            }
        };
        match timeout(Duration::from_secs(120), ready).await {
            Ok(inner) => inner?,
            Err(_) => return Err(anyhow!("Worker did not become ready within 120s")),
        }

        // Spawn background stdout reader task
        let pending = Arc::clone(&self.pending);
        let dead_flag = Arc::clone(&self.dead);
        let slot_id2 = self.id.clone();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                if line.is_empty() { continue; }

                match serde_json::from_str::<WorkerMessage>(&line) {
                    Ok(WorkerMessage::Response(resp)) => {
                        let mut map = pending.lock().await;
                        if let Some(tx) = map.remove(&resp.id) {
                            let result = if let Some(err) = resp.error {
                                Err(anyhow!("{}", err.message))
                            } else {
                                Ok(resp.result.unwrap_or(serde_json::Value::Null))
                            };
                            let _ = tx.send(result);
                        }
                    }
                    Ok(WorkerMessage::Event(evt)) => {
                        info!(slot = %slot_id2, event = %evt.event, "Worker event");
                    }
                    Err(e) => {
                        warn!(slot = %slot_id2, "Failed to parse worker output: {}", e);
                    }
                }
            }

            // Worker stdout closed — process died or exited
            warn!(slot = %slot_id2, "Worker stdout closed");
            dead_flag.store(true, Ordering::SeqCst);

            // Fail all pending requests
            let mut map = pending.lock().await;
            for (_, tx) in map.drain() {
                let _ = tx.send(Err(anyhow!("Worker process died")));
            }
        });

        Ok(())
    }

    /// Send a command to the worker and wait for the response (default 120s timeout)
    #[allow(dead_code)]
    pub async fn send_command(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        self.send_command_with_timeout(method, params, Duration::from_secs(120)).await
    }

    /// Send a command with a custom timeout duration
    pub async fn send_command_with_timeout(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout_dur: Duration,
    ) -> Result<serde_json::Value> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(anyhow!("Worker is dead"));
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Create oneshot for response
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        // Close the death-window: if the worker died between the liveness check
        // above and this insert, the reader task has already drained `pending`
        // and our sender would sit unanswered until the full timeout. Re-check
        // (the reader sets `dead` before draining) and bail immediately.
        if self.dead.load(Ordering::SeqCst) {
            self.pending.lock().await.remove(&id);
            return Err(anyhow!("Worker is dead"));
        }

        // Send request
        let request = WorkerRequest {
            id,
            method: method.to_string(),
            params,
        };
        let line = serde_json::to_string(&request)? + "\n";

        {
            let stdin = self.stdin_tx.lock().await;
            let stdin = stdin.as_ref().ok_or_else(|| anyhow!("Worker not started"))?;
            stdin.send(line).await.map_err(|_| {
                anyhow!("Worker stdin closed")
            })?;
        }

        // Wait for response with timeout
        let timeout_secs = timeout_dur.as_secs();
        match timeout(timeout_dur, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow!("Response channel dropped (worker died)")),
            Err(_) => {
                // Timeout — remove from pending
                self.pending.lock().await.remove(&id);
                Err(anyhow!("Worker response timeout ({}s)", timeout_secs))
            }
        }
    }

    /// Check if worker process is alive
    pub async fn is_alive(&self) -> bool {
        if self.dead.load(Ordering::SeqCst) {
            return false;
        }
        let mut child = self.child.lock().await;
        match child.as_mut() {
            Some(c) => c.try_wait().ok().flatten().is_none(),
            None => false,
        }
    }

    /// Kill the worker process
    pub async fn stop(&self) -> Result<()> {
        self.dead.store(true, Ordering::SeqCst);
        let mut child = self.child.lock().await;
        if let Some(ref mut c) = *child {
            let _ = c.kill().await;
        }
        *child = None;
        *self.stdin_tx.lock().await = None;

        // Fail all pending
        {
            let mut map = self.pending.lock().await;
            for (_, tx) in map.drain() {
                let _ = tx.send(Err(anyhow!("Worker stopped")));
            }
        }

        // Remove this worker's private database directory.
        let _ = tokio::fs::remove_dir_all(&self.db_dir).await;

        info!(slot = %self.id, "Worker stopped");
        Ok(())
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        // Backstop cleanup if the slot is dropped without an explicit stop()
        // (e.g. start() failed). The child is reaped via kill_on_drop; here we
        // just remove the private database directory. Sync removal is fine — the
        // directory is small and local.
        let _ = std::fs::remove_dir_all(&self.db_dir);
    }
}
