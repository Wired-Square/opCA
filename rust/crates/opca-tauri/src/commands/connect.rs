use serde::Serialize;
use tauri::State;

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::op::{self, Op, VaultInfo};

use crate::state::AppState;

/// Vault state returned to the frontend.
///
/// - `valid_ca`    – CA item and database exist and can be retrieved
/// - `empty_vault` – the vault contains no items at all
/// - `invalid_ca`  – vault has items but no valid CA (non-CA vault or corrupt CA)
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub connected: bool,
    pub vault: String,
    pub account: Option<String>,
    pub vault_state: String,
}

/// Determine the vault state by probing 1Password.
fn detect_vault_state(op: &Op) -> String {
    let ca_exists = op.item_exists(DEFAULT_OP_CONF.ca_title);

    if ca_exists {
        // CA item exists — check that the database document is also retrievable.
        match op.get_document(DEFAULT_OP_CONF.ca_database_title) {
            Ok(_) => "valid_ca".to_string(),
            Err(_) => "invalid_ca".to_string(),
        }
    } else {
        // No CA item — is the vault completely empty?
        match op.vault_item_count() {
            Ok(0) => "empty_vault".to_string(),
            Ok(_) => "invalid_ca".to_string(),
            Err(_) => "empty_vault".to_string(), // assume empty on error
        }
    }
}

#[tauri::command]
pub async fn connect(
    state: State<'_, AppState>,
    vault: String,
    account: Option<String>,
) -> Result<ConnectionInfo, String> {
    let op = Op::new(&vault, account.clone(), None).map_err(|e| e.to_string())?;

    let vault_state = detect_vault_state(&op);

    let info = ConnectionInfo {
        connected: true,
        vault: op.vault.clone(),
        account: account.clone(),
        vault_state,
    };

    // Clear any stale CA and Op before installing the new connection.
    // This single lock acquisition prevents the race where a stale CA
    // from a previous vault survives into the new session.
    let mut conn = state.conn.lock().expect("mutex poisoned — a prior operation panicked");
    conn.ca = None;
    conn.op = Some(op);

    state.log_ok("connect", Some(format!("Connected to vault '{}'", info.vault)));
    Ok(info)
}

#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    // Acquire the single connection lock — no other command can race us.
    let mut conn = state.conn.lock().expect("mutex poisoned — a prior operation panicked");

    // Release the vault lock (best-effort) using whichever Op is available.
    let op_ref = conn.ca.as_ref().map(|ca| &ca.op).or(conn.op.as_ref());
    if let Some(op) = op_ref {
        let mut lock = state.vault_lock.lock().expect("mutex poisoned — a prior operation panicked");
        let _ = lock.release(op);
    }

    // Drop both CA and Op atomically.
    conn.ca = None;
    conn.op = None;
    Ok(())
}

#[tauri::command]
pub async fn list_vaults(account: Option<String>) -> Result<Vec<VaultInfo>, String> {
    op::list_vaults_standalone(account.as_deref()).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_vault(
    state: State<'_, AppState>,
    name: String,
) -> Result<VaultInfo, String> {
    let result = state.with_op(|op| {
        op.vault_create(&name).map_err(|e| e.to_string())
    })?;

    state.log_ok("create_vault", Some(format!("Created vault '{name}'")));
    Ok(result)
}

/// Re-check the vault state (e.g. after CA init/import/restore).
#[tauri::command]
pub async fn check_vault_state(state: State<'_, AppState>) -> Result<String, String> {
    state.with_op(|op| Ok(detect_vault_state(op)))
}

/// Check whether the 1Password CLI binary is available on PATH.
#[derive(Debug, Clone, Serialize)]
pub struct OpCliStatus {
    pub found: bool,
    pub path: Option<String>,
}

#[tauri::command]
pub async fn check_op_cli() -> OpCliStatus {
    match op::check_cli_available() {
        Some(path) => OpCliStatus {
            found: true,
            path: Some(path),
        },
        None => OpCliStatus {
            found: false,
            path: None,
        },
    }
}
