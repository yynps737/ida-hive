use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Request to a worker, one JSON object per stdin line.
#[derive(Debug, Serialize)]
pub struct WorkerRequest {
    pub id: u64,
    pub method: String,
    pub params: Value,
}

/// Message from a worker, one JSON object per stdout line.
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

        // The variant is untagged; `id` and `event` are mutually exclusive on the wire.
        if v.get("id").is_some() {
            let resp: WorkerResponse =
                serde_json::from_value(v).map_err(serde::de::Error::custom)?;
            Ok(Self::Response(resp))
        } else if v.get("event").is_some() {
            let evt: WorkerEvent =
                serde_json::from_value(v).map_err(serde::de::Error::custom)?;
            Ok(Self::Event(evt))
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
    // Parsed for wire fidelity; only `message` is surfaced.
    #[allow(dead_code)]
    pub code: i64,
    pub message: String,
}

/// Worker-initiated event, carrying no `id`.
#[derive(Debug, Deserialize)]
pub struct WorkerEvent {
    pub event: String,
    #[serde(default)]
    pub data: Value,
}
