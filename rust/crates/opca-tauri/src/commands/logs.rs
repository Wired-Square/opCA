use std::path::PathBuf;

/// Return the contents of the current log file.
#[tauri::command]
pub async fn get_log_contents() -> Result<String, String> {
    let log_path = log_file_path();
    std::fs::read_to_string(&log_path).map_err(|e| {
        format!("Failed to read log file at {}: {e}", log_path.display())
    })
}

/// Return the absolute path of the log file (for display in the UI).
#[tauri::command]
pub async fn get_log_path() -> Result<String, String> {
    Ok(log_file_path().to_string_lossy().into_owned())
}

fn log_file_path() -> PathBuf {
    crate::paths::app_log_dir().join("opca.log")
}
