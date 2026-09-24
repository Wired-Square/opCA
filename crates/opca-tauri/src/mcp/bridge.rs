use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Listener};
use tokio::sync::oneshot;

type Reply = Result<Value, String>;

static NEXT_ID: AtomicU32 = AtomicU32::new(1);
static PENDING: LazyLock<Mutex<HashMap<u32, oneshot::Sender<Reply>>>> = LazyLock::new(Default::default);

#[derive(Deserialize)]
struct HarnessReply {
    id: u32,
    #[serde(default)]
    ok: Value,
    error: Option<String>,
}

fn pending() -> std::sync::MutexGuard<'static, HashMap<u32, oneshot::Sender<Reply>>> {
    PENDING.lock().expect("mutex poisoned")
}

pub fn listen(app: &AppHandle) {
    app.listen("harness:reply", |event| {
        let Ok(reply) = serde_json::from_str::<HarnessReply>(event.payload()) else {
            return;
        };
        if let Some(tx) = pending().remove(&reply.id) {
            let _ = tx.send(reply.error.map_or(Ok(reply.ok), Err));
        }
    });
}

pub async fn request(app: &AppHandle, op: &str, args: Value, timeout: Duration) -> Reply {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    pending().insert(id, tx);
    if let Err(e) = app.emit_to("main", "harness:request", json!({ "id": id, "op": op, "args": args })) {
        pending().remove(&id);
        return Err(e.to_string());
    }
    let outcome = tokio::time::timeout(timeout, rx).await;
    pending().remove(&id);
    match outcome {
        Ok(Ok(reply)) => reply,
        _ => Err("harness bridge not answering — is the dev window open?".into()),
    }
}
