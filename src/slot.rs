// slot.rs - Single worker process management
//
// Each Slot owns one C++ idalib child process. Communication is via
// JSON Lines over stdin/stdout. A background tokio task reads all
// stdout lines and routes responses to waiting callers via oneshot channels.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{info, warn, error};

use crate::protocol::*;

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<serde_json::Value>>>>>;

/// A single worker slot — manages one C++ idalib child process
pub struct Slot {
    pub id: String,
    pub path: String,
    child: Mutex<Option<Child>>,
    pending: PendingMap,
    next_id: AtomicU64,
    stdin_tx: Mutex<Option<mpsc::Sender<String>>>,
    pub ready_data: Mutex<Option<serde_json::Value>>,
    dead: AtomicBool,
}

impl Slot {
    pub fn new(id: String, path: String) -> Self {
        Self {
            id,
            path,
            child: Mutex::new(None),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            stdin_tx: Mutex::new(None),
            ready_data: Mutex::new(None),
            dead: AtomicBool::new(false),
        }
    }

    /// Spawn the C++ worker process
    pub async fn start(&self, worker_exe: &str) -> Result<()> {
        info!(slot = %self.id, path = %self.path, "Starting worker");
        self.dead.store(false, Ordering::SeqCst);

        let mut child = Command::new(worker_exe)
            .arg(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
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

        // Wait for "ready" event
        let slot_id = self.id.clone();
        loop {
            match lines.next_line().await? {
                Some(line) if !line.is_empty() => {
                    match serde_json::from_str::<WorkerMessage>(&line) {
                        Ok(WorkerMessage::Event(evt)) if evt.event == "ready" => {
                            info!(slot = %slot_id, "Worker ready");
                            *self.ready_data.lock().await = Some(evt.data);
                            break;
                        }
                        Ok(_) => {} // ignore pre-ready messages
                        Err(e) => warn!(slot = %slot_id, "Parse error during init: {}", e),
                    }
                }
                Some(_) => continue,
                None => return Err(anyhow!("Worker exited before sending ready event")),
            }
        }

        // Spawn background stdout reader task
        let pending = Arc::clone(&self.pending);
        let dead = &self.dead as *const AtomicBool;
        // SAFETY: Slot is always alive while the background task runs because
        // stop() kills the child process which closes stdout which exits the task.
        let dead_flag = unsafe { &*dead };
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

    /// Send a command to the worker and wait for the response
    pub async fn send_command(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(anyhow!("Worker is dead"));
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Create oneshot for response
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

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
                // Remove from pending since we can't send
                anyhow!("Worker stdin closed")
            })?;
        }

        // Wait for response with timeout
        match timeout(Duration::from_secs(120), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow!("Response channel dropped (worker died)")),
            Err(_) => {
                // Timeout — remove from pending
                self.pending.lock().await.remove(&id);
                Err(anyhow!("Worker response timeout (120s)"))
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
        let mut map = self.pending.lock().await;
        for (_, tx) in map.drain() {
            let _ = tx.send(Err(anyhow!("Worker stopped")));
        }

        info!(slot = %self.id, "Worker stopped");
        Ok(())
    }
}
