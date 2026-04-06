// protocol.rs - JSON-RPC protocol types for worker communication

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Request sent to a C++ worker (JSON Lines over stdin)
#[derive(Debug, Serialize)]
pub struct WorkerRequest {
    pub id: u64,
    pub method: String,
    pub params: Value,
}

/// Message received from a C++ worker (JSON Lines over stdout)
/// Either a response (has "id") or an event (has "event")
#[derive(Debug)]
pub enum WorkerMessage {
    Response(WorkerResponse),
    Event(WorkerEvent),
}

impl<'de> Deserialize<'de> for WorkerMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer)?;

        // Distinguish by field presence: "id" → Response, "event" → Event
        if v.get("id").is_some() {
            let resp: WorkerResponse =
                serde_json::from_value(v).map_err(serde::de::Error::custom)?;
            Ok(WorkerMessage::Response(resp))
        } else if v.get("event").is_some() {
            let evt: WorkerEvent =
                serde_json::from_value(v).map_err(serde::de::Error::custom)?;
            Ok(WorkerMessage::Event(evt))
        } else {
            Err(serde::de::Error::custom(
                "Expected 'id' (response) or 'event' (event) field",
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WorkerResponse {
    pub id: u64,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<WorkerError>,
}

#[derive(Debug, Deserialize)]
pub struct WorkerError {
    pub code: i64,
    pub message: String,
}

/// Worker-initiated event (no id field)
#[derive(Debug, Deserialize)]
pub struct WorkerEvent {
    pub event: String,
    #[serde(default)]
    pub data: Value,
}
