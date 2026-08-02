use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::Duration;
use tracing::{info, warn};

use crate::slot::Slot;

pub struct CoordinatorConfig {
    pub worker_exe: String,
    pub max_slots: usize,
    /// Bounds worker startup. Opening a raw binary blocks until IDA's initial
    /// auto-analysis finishes, so this is sized to fail only hung workers.
    pub open_timeout: Duration,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            worker_exe: "ida_mcp_worker".to_string(),
            max_slots: 100,
            open_timeout: Duration::from_mins(10),
        }
    }
}

pub struct Coordinator {
    config: CoordinatorConfig,
    /// Session id → slot. Several sessions may share one slot.
    sessions: RwLock<HashMap<String, Arc<Slot>>>,
    slots: RwLock<Vec<Arc<Slot>>>,
    /// Keyed by canonical path, so opens of the same binary serialize into one
    /// worker while opens of different binaries stay parallel. A global lock would
    /// stall the whole pool behind one large binary's analysis.
    path_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// One permit per slot, taken before a worker is spawned and released when it is
    /// dropped. Counting `slots` instead would leave a window between the check and
    /// the push — `start()` is slow, so concurrent opens of *different* paths would all
    /// see room and overshoot `max_slots` together.
    capacity: Arc<Semaphore>,
}

impl Coordinator {
    pub fn new(config: CoordinatorConfig) -> Self {
        let capacity = Arc::new(Semaphore::new(config.max_slots));
        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
            slots: RwLock::new(Vec::new()),
            path_locks: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// The same cap `open()` enforces.
    pub const fn max_slots(&self) -> usize {
        self.config.max_slots
    }

    /// Interns the lock for a path. Entries held only by the map are dropped first,
    /// which bounds it to the opens currently in flight.
    async fn lock_for_path(&self, path: &str) -> Arc<Mutex<()>> {
        let mut map = self.path_locks.lock().await;
        map.retain(|_, v| Arc::strong_count(v) > 1);
        map.entry(path.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Returns the session's slot, an existing slot for the path, or a new one.
    pub async fn open(&self, path: &str, session_id: &str) -> Result<Arc<Slot>> {
        // Collapses relative paths, "./x" and symlinks onto one worker, and hands
        // the worker an absolute path to save against. An unresolvable path is
        // passed through so the worker reports the real open error.
        let canonical = std::fs::canonicalize(path).map_or_else(|_| path.to_string(), |p| p.to_string_lossy().into_owned());
        let path = canonical.as_str();

        let plock = self.lock_for_path(path).await;
        let _pguard = plock.lock().await;

        // Self-terminated workers are reaped here and in close_session only. Left
        // in place they hold a slot against max_slots forever; dropping the last
        // Arc also runs Slot::drop, which removes the private temp dir.
        {
            let mut slots = self.slots.write().await;
            let mut dead_ids: Vec<String> = Vec::new();
            for s in slots.iter() {
                if !s.is_alive().await {
                    dead_ids.push(s.id.clone());
                }
            }
            if !dead_ids.is_empty() {
                self.sessions.write().await.retain(|_, s| !dead_ids.contains(&s.id));
                slots.retain(|s| !dead_ids.contains(&s.id));
                info!(pruned = dead_ids.len(), "Pruned dead worker slots");
            }
        }

        // A session id reused for a different file fails loudly rather than
        // returning the wrong binary.
        {
            let sessions = self.sessions.read().await;
            if let Some(slot) = sessions.get(session_id) {
                if slot.is_alive().await {
                    if slot.path == path {
                        return Ok(Arc::clone(slot));
                    }
                    return Err(anyhow!(
                        "Session '{}' already has a different binary open ({}). \
                         Use a new session id or close_session first.",
                        session_id, slot.path
                    ));
                }
            }
        }

        // Sessions share one worker per path; the database it holds is mutable and
        // therefore visible to all of them.
        {
            let slots = self.slots.read().await;
            for slot in slots.iter() {
                if slot.path == path && slot.is_alive().await {
                    self.sessions.write().await.insert(session_id.to_string(), Arc::clone(slot));
                    return Ok(Arc::clone(slot));
                }
            }
        }

        // Taken before the spawn and moved into the slot, so the seat is held for the
        // worker's whole life and returned by Slot::drop.
        let permit = match Arc::clone(&self.capacity).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                return Err(anyhow!(
                    "Max slots ({}) reached. Close a session first.",
                    self.config.max_slots
                ))
            }
        };

        let slot_id = uuid::Uuid::new_v4().to_string();
        let slot = Arc::new(Slot::new(slot_id.clone(), path.to_string()));

        slot.start(&self.config.worker_exe, self.config.open_timeout).await?;
        slot.hold_permit(permit).await;

        self.slots.write().await.push(Arc::clone(&slot));
        self.sessions.write().await.insert(session_id.to_string(), Arc::clone(&slot));

        info!(slot = %slot_id, path = %path, session = %session_id, "New slot created");

        Ok(slot)
    }

    /// Dispatches to the session's slot.
    pub async fn route(&self, session_id: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        // The read guard must not span the command await. tokio's RwLock is
        // write-preferring, so one in-flight wait_analysis (~610s) would block every
        // open/route/close behind it. The slot is refcounted and outlives the guard.
        let slot = {
            let sessions = self.sessions.read().await;
            sessions.get(session_id).cloned()
        }
        .ok_or_else(|| anyhow!("No active session: {session_id}. Use open_file first."))?;

        if !slot.is_alive().await {
            return Err(anyhow!("Worker for session {session_id} has died"));
        }

        let timeout = match method {
            // Clears the worker's own bound by 10s so it reports the timeout first.
            "wait_analysis" => {
                // Clamped into range first, so the conversion cannot lose a value.
                let max_sec = params.get("max_seconds")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(300)
                    .clamp(0, 600)
                    .unsigned_abs();
                Duration::from_secs(max_sec + 10)
            }
            // Only bounds stuck-but-alive workers; a dead one surfaces at once via
            // stdout close.
            _ => Duration::from_mins(5),
        };

        slot.send_command_with_timeout(method, params, timeout).await
    }

    /// Reports every slot from cached state, without querying any worker.
    pub async fn list_slots(&self) -> Vec<SlotInfo> {
        let slots = self.slots.read().await;
        let mut infos = Vec::new();

        for slot in slots.iter() {
            let alive = slot.is_alive().await;
            // `ready_data` is the open-time snapshot and is never refreshed, so its
            // `analyzing` flag stays true even once analysis has finished. The rest
            // of the snapshot is immutable and survives.
            let mut ready = slot.ready_data.lock().await.clone();
            if let Some(serde_json::Value::Object(map)) = ready.as_mut() {
                map.remove("analyzing");
            }
            infos.push(SlotInfo {
                id: slot.id.clone(),
                path: slot.path.clone(),
                alive,
                info: ready,
            });
        }

        infos
    }

    /// Unmaps the session, stopping its worker only once nothing else references it.
    pub async fn close_session(&self, session_id: &str) -> Result<()> {
        let slot_to_stop = {
            let mut sessions = self.sessions.write().await;
            match sessions.remove(session_id) {
                Some(s) if !sessions.values().any(|o| o.id == s.id) => Some(s),
                _ => None,
            }
        };

        if let Some(slot) = slot_to_stop {
            slot.stop().await?;

            let mut slots = self.slots.write().await;
            slots.retain(|s| s.id != slot.id);
        }

        Ok(())
    }

    /// Converts each binary to .i64 under a `concurrency` cap. Results come back in
    /// input order; a per-file failure is reported in its entry, not raised.
    pub async fn batch_convert(
        self: &Arc<Self>,
        paths: Vec<String>,
        output_dir: Option<String>,
        concurrency: usize,
        max_analysis_seconds: i64,
    ) -> Vec<ConvertResult> {
        let total = paths.len();
        info!(total, concurrency, "Starting batch convert");

        let semaphore = Arc::new(Semaphore::new(concurrency));

        let mut handles = Vec::with_capacity(total);

        for (idx, path) in paths.into_iter().enumerate() {
            let sem = Arc::clone(&semaphore);
            let coord = Arc::clone(self);
            let out_dir = output_dir.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                let session_id = format!("__batch_{}_{}", idx, uuid::Uuid::new_v4());
                let start = std::time::Instant::now();

                let result = Self::convert_single(
                    &coord, &path, &session_id, out_dir.as_deref(), max_analysis_seconds,
                ).await;

                let elapsed = start.elapsed().as_secs_f64();

                let convert_result = match result {
                    Ok((i64_path, func_count, seg_count)) => {
                        info!(idx, path = %path, funcs = func_count, elapsed, "Converted");
                        ConvertResult {
                            source: path,
                            i64_path: Some(i64_path),
                            functions: Some(func_count),
                            segments: Some(seg_count),
                            elapsed,
                            error: None,
                        }
                    }
                    Err(e) => {
                        warn!(idx, path = %path, error = %e, "Convert failed");
                        ConvertResult {
                            source: path,
                            i64_path: None,
                            functions: None,
                            segments: None,
                            elapsed,
                            error: Some(e.to_string()),
                        }
                    }
                };

                // Runs on the failure path too, so a bad file frees its slot.
                let _ = coord.close_session(&session_id).await;

                (idx, convert_result)
            });

            handles.push(handle);
        }

        // Tasks finish out of order, so the index carried through restores it.
        let mut collected: Vec<(usize, ConvertResult)> = Vec::with_capacity(total);
        for handle in handles {
            if let Ok(pair) = handle.await {
                collected.push(pair);
            }
        }
        collected.sort_by_key(|(idx, _)| *idx);
        collected.into_iter().map(|(_, r)| r).collect()
    }

    /// open → `wait_analysis` → `save_idb`, returning the .i64 path and its counts.
    async fn convert_single(
        coord: &Arc<Self>,
        path: &str,
        session_id: &str,
        output_dir: Option<&str>,
        max_analysis_seconds: i64,
    ) -> Result<(String, u64, u64)> {
        coord.open(path, session_id).await?;

        let wait_params = serde_json::json!({"max_seconds": max_analysis_seconds});
        let wait_result = coord.route(session_id, "wait_analysis", wait_params).await?;

        let done = wait_result.get("done").and_then(serde_json::Value::as_bool).unwrap_or(false);
        if !done {
            return Err(anyhow!("Analysis timed out after {max_analysis_seconds}s"));
        }

        let output_path = if let Some(dir) = output_dir {
            let filename = PathBuf::from(path)
                .file_name().map_or_else(|| "unknown".to_string(), |f| f.to_string_lossy().to_string());
            let mut out = PathBuf::from(dir);
            out.push(format!("{filename}.i64"));
            out.to_string_lossy().to_string()
        } else {
            // Suffixed, not replaced: xxx.dll → xxx.dll.i64
            format!("{path}.i64")
        };

        let save_params = serde_json::json!({"output_path": output_path});
        let save_result = coord.route(session_id, "save_idb", save_params).await?;

        let success = save_result.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false);
        if !success {
            return Err(anyhow!("save_idb failed for {path}"));
        }

        let func_count = wait_result.get("functions").and_then(serde_json::Value::as_u64).unwrap_or(0);
        let seg_count = wait_result.get("segments").and_then(serde_json::Value::as_u64).unwrap_or(0);

        Ok((output_path, func_count, seg_count))
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConvertResult {
    pub source: String,
    pub i64_path: Option<String>,
    pub functions: Option<u64>,
    pub segments: Option<u64>,
    pub elapsed: f64,
    pub error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct SlotInfo {
    pub id: String,
    pub path: String,
    pub alive: bool,
    pub info: Option<serde_json::Value>,
}
