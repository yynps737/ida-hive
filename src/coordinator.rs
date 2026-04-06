// coordinator.rs - Manages a pool of worker slots

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{anyhow, Result};
use tokio::sync::RwLock;
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

        slot.send_command(method, params).await
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
}

#[derive(Debug, serde::Serialize)]
pub struct SlotInfo {
    pub id: String,
    pub path: String,
    pub alive: bool,
    pub info: Option<serde_json::Value>,
}
