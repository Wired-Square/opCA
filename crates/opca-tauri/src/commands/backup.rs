use std::path::PathBuf;

use log::{info, warn};
use serde::Serialize;
use tauri::State;

use opca_core::services::ca::CertificateAuthority;
use opca_core::op::Op;
use opca_core::services::local_backup::{BackupEntry, BackupSource, LocalBackup};
use opca_core::settings;

use crate::state::{AppState, Runner};

#[derive(Debug, Serialize)]
pub struct LocalBackupsInfo {
    pub enabled: bool,
    pub dir: String,
    pub backups: Vec<BackupEntry>,
    /// Set when the connected vault's database could not be loaded.
    pub database_error: Option<String>,
}

/// The connected account's backup store and the connected vault.
fn connected_store(op: &Op<Runner>) -> Result<(LocalBackup, BackupSource), String> {
    let store = LocalBackup::for_account(op.account()).map_err(|e| e.to_string())?;
    Ok((store, BackupSource::of(op)))
}

/// Local backups for the connected vault, listed even while backups are off.
#[tauri::command]
pub async fn get_local_backups(state: State<'_, AppState>) -> Result<LocalBackupsInfo, String> {
    let (store, source) = state.with_op(connected_store)?;
    Ok(LocalBackupsInfo {
        enabled: settings::local_backup_enabled(),
        dir: store.dir_for(&source).display().to_string(),
        backups: store.list(&source).map_err(|e| e.to_string())?,
        database_error: state.database_error.lock().expect("mutex poisoned").clone(),
    })
}

#[tauri::command]
pub async fn set_local_backup_enabled(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    info!("[tauri] set_local_backup_enabled: {enabled}");
    settings::set_local_backup_enabled(enabled).map_err(|e| e.to_string())?;

    let mut conn = state.conn.lock().expect("mutex poisoned — a prior operation panicked");
    if let Some(ca) = conn.ca.as_mut() {
        ca.local_backup = LocalBackup::if_enabled(ca.op.account());
    }
    Ok(())
}

#[tauri::command]
pub async fn open_local_backups_folder(state: State<'_, AppState>) -> Result<(), String> {
    let (store, source) = state.with_op(connected_store)?;
    let dir = store.dir_for(&source);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(&dir)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open {}: {e}", dir.display()))
}

/// Replace the connected vault's unreadable `CA_Database` with a local backup
/// and load the CA from it.
#[tauri::command]
pub async fn restore_local_backup(state: State<'_, AppState>, path: String) -> Result<String, String> {
    info!("[tauri] restore_local_backup: {path}");
    let mut conn = state.conn.lock().expect("mutex poisoned — a prior operation panicked");
    if conn.ca.is_some() {
        return Err("The CA database is already loaded; restore is only offered when it can't be read".into());
    }
    let op = conn.op.clone().ok_or("Not connected")?;
    let (store, source) = connected_store(&op)?;

    let path = PathBuf::from(path);
    if !store.owns(&source, &path) {
        return Err("That file is not a backup of the connected vault".into());
    }
    let contents = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;

    let mut ca = CertificateAuthority::restore_from_backup(op, &contents, &store).map_err(|e| {
        warn!("[tauri] restore_local_backup failed: {e}");
        state.log_err("restore_local_backup", Some(e.to_string()));
        e.to_string()
    })?;
    ca.local_backup = LocalBackup::if_enabled(ca.op.account());
    conn.op = None;
    conn.ca = Some(ca);
    *state.database_error.lock().expect("mutex poisoned") = None;

    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    state.log_ok("restore_local_backup", Some(format!("CA database restored from {name}")));
    Ok("valid_ca".to_string())
}
