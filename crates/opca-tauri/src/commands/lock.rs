use log::{info, warn};
use tauri::State;

use opca_core::vault_lock::VaultLock;

use crate::state::AppState;

/// Acquire the vault lock for a mutating operation.
#[tauri::command]
pub async fn acquire_lock(
    state: State<'_, AppState>,
    operation: String,
    ttl: Option<u64>,
) -> Result<(), String> {
    info!("[tauri] acquire_lock: operation='{}' ttl={:?}", operation, ttl);
    state.with_op(|op| {
        let mut lock_guard = state.vault_lock.lock().expect("mutex poisoned — a prior operation panicked");
        lock_guard
            .acquire(op, &operation, ttl.unwrap_or(VaultLock::default_ttl()))
            .map_err(|e| {
                warn!("[tauri] acquire_lock failed for '{}': {e}", operation);
                e.to_string()
            })
    })
}

/// Release the vault lock.
#[tauri::command]
pub async fn release_lock(state: State<'_, AppState>) -> Result<(), String> {
    info!("[tauri] release_lock");
    state.with_op(|op| {
        let mut lock_guard = state.vault_lock.lock().expect("mutex poisoned — a prior operation panicked");
        lock_guard.release(op).map_err(|e| {
            warn!("[tauri] release_lock failed: {e}");
            e.to_string()
        })
    })
}
