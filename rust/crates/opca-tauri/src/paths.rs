use std::path::PathBuf;

/// Return the platform-appropriate log directory for opCA.
///
/// - **macOS:** `~/Library/Application Support/opCA/logs/`
/// - **Linux:** `~/.local/share/opCA/logs/`
/// - **Windows:** `C:\Users\<user>\AppData\Local\opCA\logs\`
pub fn app_log_dir() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("opCA").join("logs")
}
