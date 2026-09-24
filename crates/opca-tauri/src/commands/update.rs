//! Update checking command.
//!
//! Queries the GitHub releases API for the latest published release and
//! compares it against the running application version.

use log::{info, warn, debug};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct UpdateInfo {
    pub version: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
}

fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
    let v = version.trim_start_matches('v');
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() >= 3 {
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts[2].parse().ok()?;
        Some((major, minor, patch))
    } else {
        None
    }
}

fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(cur), Some(lat)) => lat > cur,
        _ => false,
    }
}

#[tauri::command]
pub async fn check_for_updates() -> Result<Option<UpdateInfo>, String> {
    let current_version = env!("CARGO_PKG_VERSION");
    debug!("[tauri] check_for_updates: current={current_version}");

    let client = reqwest::Client::builder()
        .user_agent("opCA-App")
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get("https://api.github.com/repos/Wired-Square/opca/releases/latest")
        .send()
        .await
        .map_err(|e| {
            warn!("[tauri] update check failed: {e}");
            format!("Failed to fetch release info: {}", e)
        })?;

    if !response.status().is_success() {
        warn!("[tauri] update check failed: HTTP {}", response.status());
        return Err(format!("GitHub API returned status: {}", response.status()));
    }

    let release: GitHubRelease = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse release info: {}", e))?;

    if is_newer_version(current_version, &release.tag_name) {
        info!("[tauri] update available: {} -> {}", current_version, release.tag_name);
        Ok(Some(UpdateInfo {
            version: release.tag_name,
            url: release.html_url,
        }))
    } else {
        debug!("[tauri] no update available (latest: {})", release.tag_name);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.99.8"), Some((0, 99, 8)));
        assert_eq!(parse_version("invalid"), None);
    }

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.99.8", "0.99.9"));
        assert!(is_newer_version("0.99.8", "1.0.0"));
        assert!(!is_newer_version("0.99.8", "0.99.8"));
        assert!(!is_newer_version("0.99.8", "0.99.7"));
        assert!(!is_newer_version("1.0.0", "0.99.9"));
    }
}
