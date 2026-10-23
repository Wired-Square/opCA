use log::{info, warn, debug};
use serde::Serialize;
use tauri::State;

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::error::OpcaError;
use opca_core::op::{self, AccountInfo, ItemRef, ShellRunner, Vault, VaultInfo};
use opca_core::services::database::CertificateAuthorityDB;

use crate::state::{AppState, Connection, Runner};

/// Vault state returned to the frontend.
///
/// - `valid_ca`    – CA item and database exist and can be retrieved
/// - `empty_vault` – the vault contains no items at all
/// - `invalid_ca`  – vault has items but no valid CA (non-CA vault or corrupt CA)
/// - `database_unreadable` – CA exists but its `CA_Database` dump can't be loaded
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub connected: bool,
    pub vault: String,
    pub account: Option<String>,
    pub vault_state: String,
}

/// Determine the vault state by probing 1Password, recording why the
/// database is unreadable (if it is) for the recovery dialog.
fn detect_vault_state(state: &AppState, op: &Vault<Runner>) -> Result<String, OpcaError> {
    let ca_exists = op.item_exists(&ItemRef::title(DEFAULT_OP_CONF.ca_title))?;
    let mut database_error = state.database_error.lock().expect("mutex poisoned");
    *database_error = None;

    Ok(if ca_exists {
        match op::document_text(op, DEFAULT_OP_CONF.ca_database_title) {
            Ok(sql) => match CertificateAuthorityDB::from_sql_dump(&sql) {
                Ok(_) => "valid_ca".to_string(),
                Err(e) => {
                    warn!("[tauri] CA database unreadable: {e}");
                    *database_error = Some(e.to_string());
                    "database_unreadable".to_string()
                }
            },
            Err(_) => "invalid_ca".to_string(),
        }
    } else {
        // No CA item — is the vault completely empty?
        match op.item_count()? {
            0 => "empty_vault".to_string(),
            _ => "invalid_ca".to_string(),
        }
    })
}

#[tauri::command]
pub async fn connect(
    state: State<'_, AppState>,
    vault: String,
    account: Option<String>,
) -> Result<ConnectionInfo, String> {
    info!("[tauri] connect: vault='{}' account={:?}", vault, account);
    let connected = op::connect(Runner::default(), &vault, account.as_deref())
        .and_then(|op| Ok((detect_vault_state(&state, &op)?, op)));
    let (vault_state, op) = connected.map_err(|e| {
        warn!("[tauri] connect failed: {e}");
        e.to_string()
    })?;

    let info = ConnectionInfo {
        connected: true,
        vault: op.info().name.clone(),
        account: account.clone(),
        vault_state,
    };

    // Clear any stale CA and Op before installing the new connection.
    // This single lock acquisition prevents the race where a stale CA
    // from a previous vault survives into the new session.
    let mut conn = state.conn.lock().expect("mutex poisoned — a prior operation panicked");
    state.replace_connection(&mut conn, Connection { op: Some(op), ..Connection::default() });

    state.log_ok("connect", Some(format!("Connected to vault '{}'", info.vault)));
    Ok(info)
}

#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    info!("[tauri] disconnect");
    // Acquire the single connection lock — no other command can race us.
    let mut conn = state.conn.lock().expect("mutex poisoned — a prior operation panicked");

    // Release the vault lock (best-effort) using whichever Op is available.
    let op_ref = conn.ca.as_ref().map(|ca| &ca.op).or(conn.op.as_ref());
    if let Some(op) = op_ref {
        let mut lock = state.vault_lock.lock().expect("mutex poisoned — a prior operation panicked");
        let _ = lock.release(op);
    }

    // Drop both CA and Op atomically.
    state.replace_connection(&mut conn, Connection::default());
    Ok(())
}

#[tauri::command]
pub async fn list_vaults(account: Option<String>) -> Result<Vec<VaultInfo>, String> {
    op::client(ShellRunner::new(), account.as_deref()).vaults().map_err(|e| e.to_string())
}

/// The accounts configured in the local `op` CLI, for the connect screen's
/// account picker. Works signed out.
#[tauri::command]
pub async fn list_accounts() -> Result<Vec<AccountInfo>, String> {
    op::accounts(&ShellRunner::new()).map_err(|e| e.to_string())
}

/// Works before connecting, so the connect screen can start a CA in a new vault.
#[tauri::command]
pub async fn create_vault(
    state: State<'_, AppState>,
    name: String,
    account: Option<String>,
) -> Result<VaultInfo, String> {
    info!("[tauri] create_vault: name='{name}' account={account:?}");
    let result = op::create_vault(&op::client(ShellRunner::new(), account.as_deref()), &name)
        .map_err(|e| e.to_string())?;
    state.log_ok("create_vault", Some(format!("Created vault '{}'", result.name)));
    Ok(result)
}

/// Re-check the vault state (e.g. after CA init/import/restore).
#[tauri::command]
pub async fn check_vault_state(state: State<'_, AppState>) -> Result<String, String> {
    state.with_op(|op| detect_vault_state(&state, op).map_err(|e| e.to_string()))
}

/// Check whether the 1Password CLI binary is available on PATH.
#[derive(Debug, Clone, Serialize)]
pub struct OpCliStatus {
    pub found: bool,
    pub path: Option<String>,
}

#[tauri::command]
pub async fn check_op_cli() -> OpCliStatus {
    debug!("[tauri] check_op_cli");
    match op::cli_path() {
        Some(path) => OpCliStatus {
            found: true,
            path: Some(path.display().to_string()),
        },
        None => OpCliStatus {
            found: false,
            path: None,
        },
    }
}
