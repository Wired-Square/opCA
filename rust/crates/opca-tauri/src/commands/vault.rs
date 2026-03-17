use std::collections::HashMap;

use tauri::{Emitter, State, Window};

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::op::Op;
use opca_core::services::backup::{decrypt_payload, encrypt_payload};
use opca_core::services::vault::{BackupPayload, VaultBackup};

use crate::commands::dto::{BackupInfoResult, BackupItemCount, RestoreResult};
use crate::state::AppState;

/// Emit a progress message to the frontend.
fn emit_progress(window: &Window, message: &str) {
    let _ = window.emit("vault-progress", message);
}

/// Create an encrypted vault backup and write it to `path`.
#[tauri::command]
pub async fn vault_backup(
    window: Window,
    path: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    emit_progress(&window, "Enumerating vault items\u{2026}");
    let vb = VaultBackup::new(&ca.op, &ca.op_config);
    let payload = vb.create_backup().map_err(|e| {
        state.log_err("vault_backup", Some(e.to_string()));
        e.to_string()
    })?;

    emit_progress(&window, &format!("Found {} items, encrypting\u{2026}", payload.metadata.item_count));
    let json_bytes = serde_json::to_vec(&payload).map_err(|e| {
        let msg = format!("Failed to serialise backup: {e}");
        state.log_err("vault_backup", Some(msg.clone()));
        msg
    })?;

    let encrypted = encrypt_payload(&json_bytes, &password).map_err(|e| {
        state.log_err("vault_backup", Some(e.to_string()));
        e.to_string()
    })?;

    emit_progress(&window, "Writing backup file\u{2026}");
    write_backup_file(&path, &encrypted).map_err(|e| {
        state.log_err("vault_backup", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok(
        "vault_backup",
        Some(format!(
            "Backup saved to {} ({} items)",
            path, payload.metadata.item_count
        )),
    );
    Ok(())
}

/// Restore a vault from an encrypted backup file.
///
/// Creates a fresh 1Password connection from the provided vault/account
/// because restore targets empty vaults where `ensure_ca()` would have
/// consumed and lost the original `Op` on failure.
#[tauri::command]
pub async fn vault_restore(
    window: Window,
    path: String,
    password: String,
    vault: String,
    account: Option<String>,
    state: State<'_, AppState>,
) -> Result<RestoreResult, String> {
    emit_progress(&window, "Reading backup file\u{2026}");
    let data = tokio::fs::read(&path).await.map_err(|e| {
        let msg = format!("Failed to read '{}': {}", path, e);
        state.log_err("vault_restore", Some(msg.clone()));
        msg
    })?;

    emit_progress(&window, "Decrypting\u{2026}");
    let plaintext = decrypt_payload(&data, &password).map_err(|e| {
        state.log_err("vault_restore", Some(e.to_string()));
        e.to_string()
    })?;

    let payload: BackupPayload = serde_json::from_slice(&plaintext).map_err(|e| {
        let msg = format!("Invalid backup format: {e}");
        state.log_err("vault_restore", Some(msg.clone()));
        msg
    })?;

    emit_progress(&window, "Connecting to 1Password\u{2026}");
    let op = Op::new(&vault, account, None).map_err(|e| {
        state.log_err("vault_restore", Some(e.to_string()));
        e.to_string()
    })?;

    // Acquire vault lock using the fresh Op
    {
        let mut lock_guard = state.vault_lock.lock().unwrap();
        lock_guard.acquire(&op, "vault_restore", opca_core::vault_lock::VaultLock::default_ttl())
            .map_err(|e| e.to_string())?;
    }

    emit_progress(&window, &format!("Restoring {} items\u{2026}", payload.metadata.item_count));
    let vb = VaultBackup::new(&op, &DEFAULT_OP_CONF);
    let on_progress = |item_type: &str, title: &str| {
        emit_progress(&window, &format!("Restoring {}: {}", item_type, title));
    };
    let counts = match vb.restore_backup(&payload, Some(&on_progress)) {
        Ok(c) => {
            let mut lock_guard = state.vault_lock.lock().unwrap();
            let _ = lock_guard.release(&op);
            c
        }
        Err(e) => {
            let mut lock_guard = state.vault_lock.lock().unwrap();
            let _ = lock_guard.release(&op);
            state.log_err("vault_restore", Some(e.to_string()));
            return Err(e.to_string());
        }
    };

    let items_restored: usize = counts.values().sum();
    let item_breakdown = counts_to_breakdown(&counts);

    // Re-install the fresh Op into state so ensure_ca() works without reconnecting.
    let mut conn = state.conn.lock().unwrap();
    conn.ca = None;
    conn.op = Some(op);

    state.log_ok(
        "vault_restore",
        Some(format!("Restored {} items from backup", items_restored)),
    );

    Ok(RestoreResult {
        items_restored,
        item_breakdown,
    })
}

/// Read and decrypt a backup file, returning only its metadata.
#[tauri::command]
pub async fn vault_info(path: String, password: String) -> Result<BackupInfoResult, String> {
    let data = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("Failed to read '{}': {}", path, e))?;

    let plaintext =
        decrypt_payload(&data, &password).map_err(|e| e.to_string())?;

    let payload: BackupPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Invalid backup format: {e}"))?;

    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for item in &payload.items {
        *type_counts.entry(item.item_type.clone()).or_insert(0) += 1;
    }

    Ok(BackupInfoResult {
        opca_version: payload.metadata.opca_version,
        vault_name: payload.metadata.vault_name,
        backup_date: payload.metadata.backup_date,
        item_count: payload.metadata.item_count,
        item_breakdown: counts_to_breakdown(&type_counts),
    })
}

/// Return a default backup filename based on the connected vault name.
#[tauri::command]
pub async fn vault_default_filename(state: State<'_, AppState>) -> Result<String, String> {
    let vault_name = state
        .with_op(|op| Ok(op.vault.clone()))
        .unwrap_or_else(|_| "vault".to_string());

    let timestamp = chrono::Utc::now().format("%Y-%m-%d_%H%M%S");
    let home = dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());

    let filename = format!("{}-{}.opca", vault_name, timestamp);
    let path = std::path::PathBuf::from(home).join(filename);
    Ok(path.to_string_lossy().to_string())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write backup bytes to a file with restrictive permissions (0o600).
fn write_backup_file(path: &str, data: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("Failed to create '{}': {}", path, e))?;
        file.write_all(data)
            .map_err(|e| format!("Failed to write '{}': {}", path, e))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .map_err(|e| format!("Failed to write '{}': {}", path, e))?;
    }

    Ok(())
}

/// Convert a HashMap of type → count into a sorted Vec of BackupItemCount.
fn counts_to_breakdown(counts: &HashMap<String, usize>) -> Vec<BackupItemCount> {
    let mut breakdown: Vec<BackupItemCount> = counts
        .iter()
        .map(|(item_type, &count)| BackupItemCount {
            item_type: item_type.clone(),
            count,
        })
        .collect();
    breakdown.sort_by(|a, b| a.item_type.cmp(&b.item_type));
    breakdown
}
