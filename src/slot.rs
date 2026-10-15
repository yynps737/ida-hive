use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex, OwnedSemaphorePermit};
use tokio::time::{timeout, timeout_at, Duration, Instant};
use tracing::{info, warn};

use crate::protocol::{WorkerMessage, WorkerRequest};

type PendingMap = Arc<StdMutex<HashMap<u64, oneshot::Sender<Result<serde_json::Value>>>>>;

/// Synchronous, short map operations let Drop remove a request even when its
/// future is cancelled. No map guard ever spans an await or external work.
struct PendingRequest {
    id: u64,
    pending: PendingMap,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.pending.lock().expect("pending map poisoned").remove(&self.id);
    }
}

struct QueuedCommand {
    id: u64,
    line: String,
    deadline: Instant,
    timeout: Duration,
}

fn response_timeout(duration: Duration) -> anyhow::Error {
    anyhow!("Worker response timeout ({}s)", duration.as_secs())
}

fn fail_pending(pending: &PendingMap, reason: &str) {
    for (_, tx) in pending.lock().expect("pending map poisoned").drain() {
        let _ = tx.send(Err(anyhow!("{reason}")));
    }
}

async fn write_commands(
    mut writer: impl AsyncWrite + Unpin,
    mut commands: mpsc::Receiver<QueuedCommand>,
    pending: PendingMap,
    dead: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
) {
    while let Some(command) = commands.recv().await {
        {
            let mut map = pending.lock().expect("pending map poisoned");
            if Instant::now() >= command.deadline {
                if let Some(tx) = map.remove(&command.id) {
                    let _ = tx.send(Err(response_timeout(command.timeout)));
                }
                continue;
            }
            // Cancellation or an expired caller must not leave a queued edit to
            // execute later. Already-dispatched IDA work cannot be rolled back.
            if map.get(&command.id).is_none_or(oneshot::Sender::is_closed) {
                map.remove(&command.id);
                continue;
            }
        }
        let write = async {
            writer.write_all(command.line.as_bytes()).await?;
            writer.flush().await
        };
        let error = match timeout_at(command.deadline, write).await {
            Ok(Ok(())) => continue,
            Ok(Err(e)) => format!("Worker stdin write failed: {e}"),
            Err(_) => format!("Worker stdin write timeout ({}s)", command.timeout.as_secs()),
        };

        // A cancelled/failed write may have sent only part of a JSON line. Kill
        // this transport instead of appending another command to that fragment.
        dead.store(true, Ordering::SeqCst);
        fail_pending(&pending, &error);
        if let Some(c) = child.lock().await.as_mut() {
            let _ = c.kill().await;
        }
        break;
    }
}

/// One C++ idalib child process. A background task drains its stdout and routes
/// each response to the waiting caller by request id.
pub struct Slot {
    pub id: String,
    pub path: String,
    /// Private database directory, unique per slot so concurrent opens of the same
    /// binary never collide on IDA's on-disk database and lock files.
    db_dir: PathBuf,
    child: Arc<Mutex<Option<Child>>>,
    pending: PendingMap,
    next_id: AtomicU64,
    stdin_tx: Mutex<Option<mpsc::Sender<QueuedCommand>>>,
    pub ready_data: Mutex<Option<serde_json::Value>>,
    dead: Arc<AtomicBool>,
    /// The coordinator's capacity seat. Held for the worker's whole life and
    /// released on stop or drop, which keeps the pool from overshooting `max_slots`.
    permit: Mutex<Option<OwnedSemaphorePermit>>,
}

impl Slot {
    pub fn new(id: String, path: String) -> Self {
        let db_dir = std::env::temp_dir().join(format!("ida-hive-{id}"));
        Self {
            id,
            path,
            db_dir,
            child: Arc::new(Mutex::new(None)),
            pending: Arc::new(StdMutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            stdin_tx: Mutex::new(None),
            ready_data: Mutex::new(None),
            dead: Arc::new(AtomicBool::new(false)),
            permit: Mutex::new(None),
        }
    }

    /// Takes ownership of the capacity seat reserved for this worker.
    pub async fn hold_permit(&self, permit: OwnedSemaphorePermit) {
        *self.permit.lock().await = Some(permit);
    }

    /// Spawns the worker and waits up to `ready_timeout` for its ready event.
    /// Opening a raw binary blocks until IDA's initial analysis finishes.
    pub async fn start(&self, worker_exe: &str, ready_timeout: Duration) -> Result<()> {
        info!(slot = %self.id, path = %self.path, "Starting worker");
        self.dead.store(false, Ordering::SeqCst);

        // This small local filesystem operation must finish before cancellation
        // can drop the slot; an abandoned async create could recreate it after Drop.
        std::fs::create_dir_all(&self.db_dir).map_err(|e| {
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

        let (stdin_tx, stdin_rx) = mpsc::channel(64);
        *self.stdin_tx.lock().await = Some(stdin_tx);
        *self.child.lock().await = Some(child);
        tokio::spawn(write_commands(
            stdin, stdin_rx, Arc::clone(&self.pending), Arc::clone(&self.dead), Arc::clone(&self.child),
        ));

        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        // Bounds startup while the coordinator holds this session/path's locks.
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
                            // Carries the real failure reason (license, unreadable input,
                            // copy failure) instead of a generic "exited before ready".
                            Ok(WorkerMessage::Event(evt)) if evt.event == "init_error" => {
                                let msg = evt.data.get("message").and_then(|v| v.as_str())
                                    .unwrap_or("worker failed to initialize");
                                let stage = evt.data.get("stage").and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let code = evt.data.get("code").and_then(serde_json::Value::as_i64);
                                return Err(match code {
                                    Some(c) => anyhow!("Worker init failed at {stage} (code {c}): {msg}"),
                                    None => anyhow!("Worker init failed at {stage}: {msg}"),
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
        match timeout(ready_timeout, ready).await {
            Ok(inner) => inner?,
            Err(_) => return Err(anyhow!(
                "Worker did not become ready within {}s",
                ready_timeout.as_secs()
            )),
        }

        // Steady-state reader: owns `lines` from here on.
        let pending = Arc::clone(&self.pending);
        let dead_flag = Arc::clone(&self.dead);
        let slot_id2 = self.id.clone();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                if line.is_empty() { continue; }

                match serde_json::from_str::<WorkerMessage>(&line) {
                    Ok(WorkerMessage::Response(resp)) => {
                        let mut map = pending.lock().expect("pending map poisoned");
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

            // `dead` is set before draining; send_command relies on that order.
            warn!(slot = %slot_id2, "Worker stdout closed");
            dead_flag.store(true, Ordering::SeqCst);

            fail_pending(&pending, "Worker process died");
        });

        Ok(())
    }

    /// Sends a command under the default 120s timeout.
    #[allow(dead_code)]
    pub async fn send_command(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        self.send_command_with_timeout(method, params, Duration::from_mins(2)).await
    }

    /// One deadline covers admission, writing and response. Dropping this future
    /// unregisters it, so the writer can discard commands not yet dispatched.
    pub async fn send_command_with_timeout(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout_dur: Duration,
    ) -> Result<serde_json::Value> {
        let deadline = Instant::now() + timeout_dur;
        if self.dead.load(Ordering::SeqCst) {
            return Err(anyhow!("Worker is dead"));
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let (tx, rx) = oneshot::channel();
        let _pending = PendingRequest { id, pending: Arc::clone(&self.pending) };
        self.pending.lock().expect("pending map poisoned").insert(id, tx);

        // A worker dying between the check above and this insert would leave the
        // sender unanswered until the full timeout, since the reader has already
        // drained `pending`. It sets `dead` first, so re-reading it closes the gap.
        if self.dead.load(Ordering::SeqCst) {
            return Err(anyhow!("Worker is dead"));
        }

        let request = WorkerRequest {
            id,
            method: method.to_string(),
            params,
        };
        let line = serde_json::to_string(&request)? + "\n";

        let command = async {
            let stdin = {
                let guard = self.stdin_tx.lock().await;
                guard.as_ref().cloned().ok_or_else(|| anyhow!("Worker not started"))?
            };
            stdin.send(QueuedCommand { id, line, deadline, timeout: timeout_dur }).await
                .map_err(|_| anyhow!("Worker stdin closed"))?;
            rx.await.map_err(|_| anyhow!("Response channel dropped (worker died)"))?
        };
        match timeout_at(deadline, command).await {
            Ok(result) => result,
            Err(_) => Err(response_timeout(timeout_dur)),
        }
    }

    /// Short-circuits on the `dead` flag before reaping the child via `try_wait`.
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

    /// Kills the worker, fails its pending requests, and removes its database dir.
    pub async fn stop(&self) -> Result<()> {
        self.dead.store(true, Ordering::SeqCst);
        {
            let mut child = self.child.lock().await;
            if let Some(ref mut c) = *child {
                let _ = c.kill().await;
            }
            *child = None;
        }
        *self.stdin_tx.lock().await = None;

        fail_pending(&self.pending, "Worker stopped");
        // Old routing futures may still own Arcs after the process has stopped.
        // Return the seat now, before a close releases its path lock to a reopen.
        self.permit.lock().await.take();

        let _ = tokio::fs::remove_dir_all(&self.db_dir).await;

        info!(slot = %self.id, "Worker stopped");
        Ok(())
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        // A writer also holds the child Arc. Kill immediately on cancellation or
        // a failed start rather than waiting for its queue task to be scheduled.
        if let Ok(mut child) = self.child.try_lock() {
            if let Some(c) = child.as_mut() {
                let _ = c.start_kill();
            }
        }
        let _ = std::fs::remove_dir_all(&self.db_dir);
    }
}

#[cfg(test)]
mod tests;
