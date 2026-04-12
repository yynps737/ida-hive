// coordinator.rs - Manages a pool of worker slots

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::Duration;
use tracing::{info, warn};

use crate::slot::Slot;

/// Configuration for the coordinator
pub struct CoordinatorConfig {
    /// Path to the C++ worker executable
    pub worker_exe: String,
    /// Maximum number of concurrent slots
    pub max_slots: usize,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            worker_exe: "ida_mcp_worker".to_string(),
            max_slots: 100,
        }
    }
}

/// Manages multiple worker slots
pub struct Coordinator {
    config: CoordinatorConfig,
    /// session_id -> slot mapping
    sessions: RwLock<HashMap<String, Arc<Slot>>>,
    /// All active slots
    slots: RwLock<Vec<Arc<Slot>>>,
}

impl Coordinator {
    pub fn new(config: CoordinatorConfig) -> Self {
        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
            slots: RwLock::new(Vec::new()),
        }
    }

    /// Open a binary in a new slot, or return existing slot for the path
    pub async fn open(&self, path: &str, session_id: &str) -> Result<Arc<Slot>> {
        // Check if session already has a slot
        {
            let sessions = self.sessions.read().await;
            if let Some(slot) = sessions.get(session_id) {
                if slot.is_alive().await {
                    return Ok(Arc::clone(slot));
                }
            }
        }

        // Check if any existing slot has this path
        {
            let slots = self.slots.read().await;
            for slot in slots.iter() {
                if slot.path == path && slot.is_alive().await {
                    self.sessions.write().await.insert(session_id.to_string(), Arc::clone(slot));
                    return Ok(Arc::clone(slot));
                }
            }
        }

        // Check capacity
        {
            let slots = self.slots.read().await;
            if slots.len() >= self.config.max_slots {
                return Err(anyhow!(
                    "Max slots ({}) reached. Close a session first.",
                    self.config.max_slots
                ));
            }
        }

        // Create new slot
        let slot_id = uuid::Uuid::new_v4().to_string();
        let slot = Arc::new(Slot::new(slot_id.clone(), path.to_string()));

        slot.start(&self.config.worker_exe).await?;

        self.slots.write().await.push(Arc::clone(&slot));
        self.sessions.write().await.insert(session_id.to_string(), Arc::clone(&slot));

        info!(slot = %slot_id, path = %path, session = %session_id, "New slot created");

        Ok(slot)
    }

    /// Route a command to the correct slot by session
    pub async fn route(&self, session_id: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let sessions = self.sessions.read().await;
        let slot = sessions.get(session_id)
            .ok_or_else(|| anyhow!("No active session: {}. Use open_file first.", session_id))?;

        if !slot.is_alive().await {
            return Err(anyhow!("Worker for session {} has died", session_id));
        }

        // wait_analysis can block up to 600s on the worker side — match the timeout
        let timeout = match method {
            "wait_analysis" => {
                let max_sec = params.get("max_seconds")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(300)
                    .min(600) as u64;
                // Add 10s buffer over the worker's own timeout
                Duration::from_secs(max_sec + 10)
            }
            _ => Duration::from_secs(120),
        };

        slot.send_command_with_timeout(method, params, timeout).await
    }

    /// List all active slots
    pub async fn list_slots(&self) -> Vec<SlotInfo> {
        let slots = self.slots.read().await;
        let mut infos = Vec::new();

        for slot in slots.iter() {
            let alive = slot.is_alive().await;
            let ready = slot.ready_data.lock().await.clone();
            infos.push(SlotInfo {
                id: slot.id.clone(),
                path: slot.path.clone(),
                alive,
                info: ready,
            });
        }

        infos
    }

    /// Close a session (stop its worker)
    pub async fn close_session(&self, session_id: &str) -> Result<()> {
        let slot = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id)
        };

        if let Some(slot) = slot {
            slot.stop().await?;

            // Remove from slots list
            let mut slots = self.slots.write().await;
            slots.retain(|s| s.id != slot.id);
        }

        Ok(())
    }

    /// Batch convert raw binaries to .i64 databases.
    /// Opens workers in parallel (limited by concurrency), waits for analysis, saves .i64, closes.
    /// Returns results for each file.
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
        let results = Arc::new(RwLock::new(Vec::with_capacity(total)));

        let mut handles = Vec::with_capacity(total);

        for (idx, path) in paths.into_iter().enumerate() {
            let sem = Arc::clone(&semaphore);
            let coord = Arc::clone(self);
            let out_dir = output_dir.clone();
            let results = Arc::clone(&results);

            let handle = tokio::spawn(async move {
                // Acquire semaphore permit — limits concurrency
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

                results.write().await.push(convert_result);

                // Always try to clean up the session
                let _ = coord.close_session(&session_id).await;
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        let results = results.read().await;
        results.clone()
    }

    /// Convert a single binary: open → wait_analysis → save_idb → return path
    async fn convert_single(
        coord: &Arc<Self>,
        path: &str,
        session_id: &str,
        output_dir: Option<&str>,
        max_analysis_seconds: i64,
    ) -> Result<(String, u64, u64)> {
        // Open the binary
        coord.open(path, session_id).await?;

        // Wait for auto-analysis to complete
        let wait_params = serde_json::json!({"max_seconds": max_analysis_seconds});
        let wait_result = coord.route(session_id, "wait_analysis", wait_params).await?;

        let done = wait_result.get("done").and_then(|v| v.as_bool()).unwrap_or(false);
        if !done {
            return Err(anyhow!("Analysis timed out after {}s", max_analysis_seconds));
        }

        // Compute output path
        let output_path = if let Some(dir) = output_dir {
            let filename = PathBuf::from(path)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let mut out = PathBuf::from(dir);
            out.push(format!("{}.i64", filename));
            out.to_string_lossy().to_string()
        } else {
            // Save next to the original file: xxx.dll → xxx.dll.i64
            format!("{}.i64", path)
        };

        // Save the .i64 database
        let save_params = serde_json::json!({"output_path": output_path});
        let save_result = coord.route(session_id, "save_idb", save_params).await?;

        let success = save_result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        if !success {
            return Err(anyhow!("save_idb failed for {}", path));
        }

        let func_count = wait_result.get("functions").and_then(|v| v.as_u64()).unwrap_or(0);
        let seg_count = wait_result.get("segments").and_then(|v| v.as_u64()).unwrap_or(0);

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
