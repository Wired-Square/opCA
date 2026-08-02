//! Per-user, per-machine local settings.
//!
//! These are deliberately **not** stored in the CA database: that database
//! lives in the shared 1Password vault, so anything written there applies to
//! every user of the CA.  Settings here are personal to one operator on one
//! machine — most importantly, which 1Password item holds *their* AWS access
//! key.  Several people share a CA but each has their own AWS credentials.
//!
//! Settings are keyed by 1Password account shorthand so that operators who
//! work across multiple tenants keep a separate selection for each.
//!
//! Stored as JSON at the platform config directory, e.g. on macOS
//! `~/Library/Application Support/opca/settings.json`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use log::{debug, warn};
use serde::{Deserialize, Serialize};

use crate::error::OpcaError;

/// Directory name under the platform config directory.
const SETTINGS_DIR: &str = "opca";
/// Settings file name.
const SETTINGS_FILE: &str = "settings.json";
/// Key used when no 1Password account shorthand is configured.
const DEFAULT_ACCOUNT_KEY: &str = "default";

/// Local settings for the current user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Settings {
    /// 1Password account shorthand → item ID of that account's AWS access key.
    #[serde(default)]
    aws_credential_items: BTreeMap<String, String>,
}

/// Normalise an optional account shorthand into a map key.
fn account_key(account: Option<&str>) -> String {
    match account.map(str::trim) {
        Some(acct) if !acct.is_empty() => acct.to_lowercase(),
        _ => DEFAULT_ACCOUNT_KEY.to_string(),
    }
}

/// Path to the settings file. Reading must not create anything, so the
/// parent directory is created by [`save`] instead.
pub fn settings_path() -> Result<PathBuf, OpcaError> {
    Ok(dirs::config_dir()
        .ok_or_else(|| OpcaError::Other("Could not determine the user config directory".into()))?
        .join(SETTINGS_DIR)
        .join(SETTINGS_FILE))
}

/// Load settings, falling back to defaults when the file is missing or
/// unreadable.  A corrupt settings file should never stop the app starting.
fn load() -> Settings {
    let Ok(path) = settings_path() else {
        return Settings::default();
    };

    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
            warn!("[settings] ignoring invalid {}: {e}", path.display());
            Settings::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
        Err(e) => {
            warn!("[settings] could not read {}: {e}", path.display());
            Settings::default()
        }
    }
}

/// Persist settings, replacing the existing file.
fn save(settings: &Settings) -> Result<(), OpcaError> {
    let path = settings_path()?;
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| OpcaError::Other(format!("Could not serialise settings: {e}")))?;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            OpcaError::Other(format!("Could not create {}: {e}", dir.display()))
        })?;
    }

    std::fs::write(&path, json)
        .map_err(|e| OpcaError::Other(format!("Could not write {}: {e}", path.display())))?;

    debug!("[settings] saved {}", path.display());
    Ok(())
}

/// The AWS credential item ID selected for `account`, if any.
pub fn aws_credential_item(account: Option<&str>) -> Option<String> {
    load().aws_credential_items.get(&account_key(account)).cloned()
}

/// Select (or with `None`, clear) the AWS credential item for `account`.
pub fn set_aws_credential_item(
    account: Option<&str>,
    item_id: Option<&str>,
) -> Result<(), OpcaError> {
    let mut settings = load();
    let key = account_key(account);

    match item_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => settings.aws_credential_items.insert(key, id.to_string()),
        None => settings.aws_credential_items.remove(&key),
    };

    save(&settings)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_key_normalises_case_and_whitespace() {
        assert_eq!(account_key(Some("  Xentro.1Password.com ")), "xentro.1password.com");
    }

    #[test]
    fn test_account_key_defaults_when_absent_or_blank() {
        assert_eq!(account_key(None), DEFAULT_ACCOUNT_KEY);
        assert_eq!(account_key(Some("   ")), DEFAULT_ACCOUNT_KEY);
    }

    #[test]
    fn test_settings_round_trip() {
        let mut settings = Settings::default();
        settings
            .aws_credential_items
            .insert("xentro.1password.com".into(), "abc123".into());

        let json = serde_json::to_string(&settings).unwrap();
        let parsed: Settings = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.aws_credential_items.get("xentro.1password.com"),
            Some(&"abc123".to_string())
        );
    }

    #[test]
    fn test_settings_tolerates_missing_keys() {
        let parsed: Settings = serde_json::from_str("{}").unwrap();
        assert!(parsed.aws_credential_items.is_empty());
    }
}
