/// Read a text file from the filesystem and return its contents.
///
/// Used by the frontend to load PEM files selected via the dialog plugin.
#[tauri::command]
pub async fn read_text_file(path: String) -> Result<String, String> {
    tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| format!("Failed to read '{}': {}", path, e))
}
