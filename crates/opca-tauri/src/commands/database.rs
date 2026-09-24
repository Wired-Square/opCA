use tauri::State;

use crate::commands::ca::ca_config_to_dto;
use crate::commands::dto::{DatabaseInfo, LogEntry};
use crate::state::AppState;

#[tauri::command]
pub async fn get_database_info(state: State<'_, AppState>) -> Result<DatabaseInfo, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref()
        .ok_or("Database not loaded")?;

    let config = db.get_config().map_err(|e| e.to_string())?;
    let total_certs = db.count_certs().map_err(|e| e.to_string())?;
    let total_external_certs = db.count_external_certs().map_err(|e| e.to_string())?;
    let schema_version = config.schema_version.unwrap_or(0);

    Ok(DatabaseInfo {
        config: ca_config_to_dto(&config),
        total_certs,
        total_external_certs,
        schema_version,
    })
}

#[tauri::command]
pub async fn get_action_log(state: State<'_, AppState>) -> Result<Vec<LogEntry>, String> {
    let log = state.action_log.lock().expect("mutex poisoned — a prior operation panicked");
    Ok(log.clone())
}
