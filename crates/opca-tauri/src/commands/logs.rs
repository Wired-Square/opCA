use tauri::{AppHandle, Manager};

/// Return the contents of the current log file.
#[tauri::command]
pub async fn get_log_contents(app: AppHandle) -> Result<String, String> {
    let log_path = log_file_path(&app)?;
    std::fs::read_to_string(&log_path).map_err(|e| {
        format!("Failed to read log file at {}: {e}", log_path.display())
    })
}

/// Return the absolute path of the log file (for display in the UI).
#[tauri::command]
pub async fn get_log_path(app: AppHandle) -> Result<String, String> {
    Ok(log_file_path(&app)?.to_string_lossy().into_owned())
}

fn log_file_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_log_dir()
        .map(|dir| dir.join("opca.log"))
        .map_err(|e| format!("Failed to resolve log directory: {e}"))
}
