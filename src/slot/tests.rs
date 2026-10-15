use super::*;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

fn slot() -> Arc<Slot> {
    Arc::new(Slot::new(uuid::Uuid::new_v4().to_string(), "fixture.bin".to_string()))
}

fn queued(id: u64, line: &str, duration: Duration) -> QueuedCommand {
    QueuedCommand { id, line: line.to_string(), deadline: Instant::now() + duration, timeout: duration }
}

fn register(slot: &Slot, id: u64) -> oneshot::Receiver<Result<serde_json::Value>> {
    let (tx, rx) = oneshot::channel();
    slot.pending.lock().unwrap().insert(id, tx);
    rx
}

#[tokio::test]
async fn stopping_returns_capacity_while_old_requests_still_hold_slot() {
    let capacity = Arc::new(Semaphore::new(1));
    let slot = slot();
    slot.hold_permit(Arc::clone(&capacity).acquire_owned().await.unwrap()).await;
    let _in_flight_request = Arc::clone(&slot);
    assert_eq!(capacity.available_permits(), 0);
    slot.stop().await.unwrap();
    assert_eq!(capacity.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn full_queue_respects_deadline_and_cleans_pending() {
    let slot = slot();
    let (tx, _rx) = mpsc::channel(1);
    tx.send(queued(0, "occupied\n", Duration::from_secs(60))).await.unwrap();
    *slot.stdin_tx.lock().await = Some(tx);
    let start = Instant::now();
    let result = timeout(Duration::from_secs(2), slot.send_command_with_timeout(
        "ping", serde_json::json!({}), Duration::from_secs(1),
    )).await.expect("queue admission escaped the deadline");
    assert!(result.unwrap_err().to_string().contains("timeout (1s)"));
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    assert!(slot.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn queue_and_response_share_one_deadline() {
    let slot = slot();
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(queued(0, "occupied\n", Duration::from_secs(60))).await.unwrap();
    *slot.stdin_tx.lock().await = Some(tx);
    let call_slot = Arc::clone(&slot);
    let start = Instant::now();
    let call = tokio::spawn(async move {
        call_slot.send_command_with_timeout("ping", serde_json::json!({}), Duration::from_secs(1)).await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(600)).await;
    rx.recv().await.unwrap();
    let _command = rx.recv().await.unwrap();
    assert!(call.await.unwrap().is_err());
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    assert!(slot.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn sender_lock_wait_is_also_bounded() {
    let slot = slot();
    let _lock = slot.stdin_tx.lock().await;
    let start = Instant::now();
    let result = slot.send_command_with_timeout("ping", serde_json::json!({}), Duration::from_secs(1)).await;
    assert!(result.is_err());
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    assert!(slot.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn cancellation_unregisters_queued_request() {
    let slot = slot();
    let (tx, mut rx) = mpsc::channel(1);
    *slot.stdin_tx.lock().await = Some(tx);
    let call_slot = Arc::clone(&slot);
    let call = tokio::spawn(async move {
        call_slot.send_command_with_timeout("edit", serde_json::json!({}), Duration::from_secs(60)).await
    });
    let command = rx.recv().await.unwrap();
    assert!(slot.pending.lock().unwrap().contains_key(&command.id));
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    assert!(slot.pending.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_enqueue_unregisters_request() {
    let slot = slot();
    let (tx, rx) = mpsc::channel(1);
    *slot.stdin_tx.lock().await = Some(tx);
    drop(rx);
    let result = slot.send_command_with_timeout("ping", serde_json::json!({}), Duration::from_secs(1)).await;
    assert!(result.unwrap_err().to_string().contains("stdin closed"));
    assert!(slot.pending.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn writer_discards_expired_and_cancelled_commands() {
    let slot = slot();
    let expired = register(&slot, 1);
    let cancelled = register(&slot, 2);
    drop(cancelled);
    let _live = register(&slot, 3);
    let (tx, rx) = mpsc::channel(3);
    tx.send(queued(1, "expired edit\n", Duration::ZERO)).await.unwrap();
    tx.send(queued(2, "cancelled edit\n", Duration::from_secs(60))).await.unwrap();
    tx.send(queued(3, "live edit\n", Duration::from_secs(60))).await.unwrap();
    drop(tx);
    let (writer, mut reader) = tokio::io::duplex(1024);
    write_commands(writer, rx, Arc::clone(&slot.pending), Arc::clone(&slot.dead), Arc::clone(&slot.child)).await;
    let mut output = String::new();
    reader.read_to_string(&mut output).await.unwrap();
    assert_eq!(output, "live edit\n");
    assert!(expired.await.unwrap().unwrap_err().to_string().contains("timeout"));
    assert_eq!(slot.pending.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn partial_write_timeout_poison_closes_transport() {
    let slot = slot();
    let first = register(&slot, 1);
    let second = register(&slot, 2);
    let (tx, rx) = mpsc::channel(2);
    let line = "x".repeat(1024) + "\n";
    tx.send(queued(1, &line, Duration::from_secs(1))).await.unwrap();
    tx.send(queued(2, "must not follow a fragment\n", Duration::from_secs(60))).await.unwrap();
    drop(tx);
    // No reader drains this tiny pipe until the deadline fires mid-frame.
    let (writer, mut reader) = tokio::io::duplex(8);
    write_commands(writer, rx, Arc::clone(&slot.pending), Arc::clone(&slot.dead), Arc::clone(&slot.child)).await;
    assert!(slot.dead.load(Ordering::SeqCst));
    assert!(slot.pending.lock().unwrap().is_empty());
    for result in [first, second] {
        assert!(result.await.unwrap().unwrap_err().to_string().contains("stdin write timeout"));
    }
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"xxxxxxxx");
}

#[tokio::test]
async fn broken_pipe_fails_all_pending_requests() {
    let slot = slot();
    let response = register(&slot, 1);
    let (tx, rx) = mpsc::channel(1);
    tx.send(queued(1, "ping\n", Duration::from_secs(60))).await.unwrap();
    drop(tx);
    let (writer, reader) = tokio::io::duplex(8);
    drop(reader);
    write_commands(writer, rx, Arc::clone(&slot.pending), Arc::clone(&slot.dead), Arc::clone(&slot.child)).await;
    assert!(response.await.unwrap().unwrap_err().to_string().contains("stdin write failed"));
    assert!(slot.dead.load(Ordering::SeqCst));
    assert!(slot.pending.lock().unwrap().is_empty());
}
