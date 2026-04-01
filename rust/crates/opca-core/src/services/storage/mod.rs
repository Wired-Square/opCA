//! Storage backends for publishing CA artefacts (certificates, CRLs, database).
//!
//! Each backend lives in its own sub-module:
//! - [`rsync`] — uploads via `rsync -avz` over SSH
//! - [`s3`]    — uploads to AWS S3 using credentials from the `op` CLI plugin
//! - [`sftp`]  — uploads via SFTP using SSH agent or key-file authentication

pub mod rsync;
pub mod s3;
pub mod sftp;

use log::{debug, info};

use crate::error::OpcaError;
use crate::op::CommandRunner;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// A backend that can upload content to a remote location and verify
/// connectivity.
pub trait StorageBackend {
    /// Upload `content` to the given `uri`.
    fn upload(&self, content: &[u8], uri: &str) -> Result<(), OpcaError>;

    /// Test that the backend can reach the remote target.
    fn test_connection(&self, uri: &str) -> Result<(), OpcaError>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Parse a URI scheme and return the appropriate storage backend.
///
/// For `s3://` URIs the `runner` is used to retrieve AWS credentials from
/// the 1Password CLI plugin.  Other schemes ignore the runner.
pub fn storage_from_uri<R: CommandRunner>(
    uri: &str,
    runner: &R,
    account: Option<&str>,
) -> Result<Box<dyn StorageBackend>, OpcaError> {
    let scheme = uri
        .split("://")
        .next()
        .unwrap_or("")
        .to_lowercase();

    match scheme.as_str() {
        "rsync" => Ok(Box::new(rsync::StorageRsync)),
        "sftp" | "scp" => Ok(Box::new(sftp::StorageSftp)),
        "s3" => {
            let creds = get_aws_credentials(runner, account)?;
            Ok(Box::new(s3::StorageS3::new(creds)))
        }
        other => Err(OpcaError::Storage(format!(
            "Unsupported storage scheme: {other}"
        ))),
    }
}

/// Like [`storage_from_uri`] but accepts pre-fetched AWS credentials,
/// avoiding a redundant `op plugin run` call when testing multiple S3 stores.
pub fn storage_from_uri_with_creds(
    uri: &str,
    aws_creds: Option<&AwsCredentials>,
) -> Result<Box<dyn StorageBackend>, OpcaError> {
    let scheme = uri
        .split("://")
        .next()
        .unwrap_or("")
        .to_lowercase();

    match scheme.as_str() {
        "rsync" => Ok(Box::new(rsync::StorageRsync)),
        "sftp" | "scp" => Ok(Box::new(sftp::StorageSftp)),
        "s3" => {
            let creds = aws_creds
                .ok_or_else(|| OpcaError::Storage("AWS credentials required for S3 stores".into()))?;
            Ok(Box::new(s3::StorageS3::new(creds.clone())))
        }
        other => Err(OpcaError::Storage(format!(
            "Unsupported storage scheme: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// AWS credential helpers
// ---------------------------------------------------------------------------

/// AWS credentials retrieved from the 1Password CLI plugin.
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: Option<String>,
}

/// Retrieve AWS credentials by reading the 1Password CLI plugin
/// configuration and fetching the vault item directly via the
/// [`CommandRunner`].
///
/// This avoids `op plugin run` (which spawns a sub-process and can hang
/// in non-interactive / GUI contexts) and instead reads the credential
/// fields with a plain `op item get` call.
pub fn get_aws_credentials<R: CommandRunner>(
    runner: &R,
    account: Option<&str>,
) -> Result<AwsCredentials, OpcaError> {
    info!("[storage] retrieving AWS credentials via op plugin config");

    let plugin = read_aws_plugin_config()?;

    let op_bin = which::which("op")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "op".to_string());

    let mut args: Vec<&str> = vec!["item", "get", &plugin.item_id, "--format=json"];
    if let Some(acct) = account {
        args.push("--account");
        args.push(acct);
    }

    let output = runner.run(&op_bin, &args, None, None)?;
    if !output.success {
        return Err(OpcaError::Storage(format!(
            "Failed to read AWS credentials from 1Password: {}",
            output.stderr.trim()
        )));
    }

    parse_aws_item_json(&output.stdout)
}

/// AWS plugin configuration read from `~/.config/op/plugins/aws.json`.
struct AwsPluginConfig {
    item_id: String,
}

/// Read the 1Password CLI AWS plugin config to find the vault item ID.
fn read_aws_plugin_config() -> Result<AwsPluginConfig, OpcaError> {
    let home = std::env::var("HOME").map_err(|_| {
        OpcaError::Storage("HOME environment variable not set".into())
    })?;
    let config_path = std::path::PathBuf::from(home).join(".config/op/plugins/aws.json");

    let content = std::fs::read_to_string(&config_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OpcaError::Storage(
                "1Password AWS plugin not configured. \
                 Run 'op plugin init aws' to set it up."
                    .into(),
            )
        } else {
            OpcaError::Storage(format!(
                "Could not read AWS plugin config at {}: {e}",
                config_path.display()
            ))
        }
    })?;

    let json: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        OpcaError::Storage(format!("Invalid AWS plugin config: {e}"))
    })?;

    let item_id = json["credentials"]
        .as_array()
        .and_then(|creds| creds.first())
        .and_then(|c| c["item_id"].as_str())
        .ok_or_else(|| OpcaError::Storage("No credential item found in AWS plugin config".into()))?
        .to_string();

    debug!("[storage] AWS plugin item_id: {item_id}");
    Ok(AwsPluginConfig { item_id })
}

/// Parse the JSON output of `op item get` to extract AWS credentials.
fn parse_aws_item_json(json_str: &str) -> Result<AwsCredentials, OpcaError> {
    let item: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
        OpcaError::Storage(format!("Failed to parse op item JSON: {e}"))
    })?;

    let fields = item["fields"]
        .as_array()
        .ok_or_else(|| OpcaError::Storage("No fields in op item response".into()))?;

    let mut access_key_id: Option<String> = None;
    let mut secret_access_key: Option<String> = None;

    for field in fields {
        let label = field["label"].as_str().unwrap_or("");
        let value = field["value"].as_str().unwrap_or("");
        match label {
            "access key id" => access_key_id = Some(value.to_string()),
            "secret access key" => secret_access_key = Some(value.to_string()),
            _ => {}
        }
    }

    let access_key_id = access_key_id
        .ok_or_else(|| OpcaError::Storage("'access key id' field not found in item".into()))?;
    let secret_access_key = secret_access_key
        .ok_or_else(|| OpcaError::Storage("'secret access key' field not found in item".into()))?;

    debug!("[storage] AWS credentials obtained from 1Password item");

    Ok(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token: None,
        region: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::CommandOutput;
    use std::collections::HashMap;

    struct MockRunner {
        stdout: String,
        success: bool,
    }

    impl CommandRunner for MockRunner {
        fn run(
            &self,
            _bin: &str,
            _args: &[&str],
            _input: Option<&str>,
            _env_vars: Option<&HashMap<String, String>>,
        ) -> Result<CommandOutput, OpcaError> {
            if self.success {
                Ok(CommandOutput {
                    stdout: self.stdout.clone(),
                    stderr: String::new(),
                    success: true,
                })
            } else {
                Err(OpcaError::Storage("mock runner failure".into()))
            }
        }
    }

    fn mock_runner() -> MockRunner {
        MockRunner {
            stdout: String::new(),
            success: true,
        }
    }

    #[test]
    fn test_storage_from_uri_rsync() {
        let runner = mock_runner();
        let backend = storage_from_uri("rsync://host/path", &runner, None);
        assert!(backend.is_ok());
    }

    #[test]
    fn test_storage_from_uri_sftp() {
        let runner = mock_runner();
        let backend = storage_from_uri("sftp://user@host/path", &runner, None);
        assert!(backend.is_ok());
    }

    #[test]
    fn test_storage_from_uri_scp() {
        let runner = mock_runner();
        let backend = storage_from_uri("scp://user@host/path", &runner, None);
        assert!(backend.is_ok());
    }

    #[test]
    fn test_storage_from_uri_unknown() {
        let runner = mock_runner();
        let result = storage_from_uri("ftp://host/path", &runner, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_aws_item_json_full() {
        let json = r#"{
            "fields": [
                {"label": "access key id", "value": "AKIA1234", "type": "STRING"},
                {"label": "secret access key", "value": "secret123", "type": "CONCEALED"}
            ]
        }"#;
        let creds = parse_aws_item_json(json).unwrap();
        assert_eq!(creds.access_key_id, "AKIA1234");
        assert_eq!(creds.secret_access_key, "secret123");
        assert!(creds.session_token.is_none());
        assert!(creds.region.is_none());
    }

    #[test]
    fn test_parse_aws_item_json_missing_key() {
        let json = r#"{
            "fields": [
                {"label": "secret access key", "value": "secret123", "type": "CONCEALED"}
            ]
        }"#;
        let result = parse_aws_item_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_aws_item_json_empty_fields() {
        let json = r#"{"fields": []}"#;
        let result = parse_aws_item_json(json);
        assert!(result.is_err());
    }
}
