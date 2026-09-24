//! Storage backends for publishing CA artefacts (certificates, CRLs, database).
//!
//! Each backend lives in its own sub-module:
//! - [`rsync`] — uploads via `rsync -avz` over SSH
//! - [`s3`]    — uploads to AWS S3 using credentials read from 1Password
//! - [`sftp`]  — uploads via SFTP using SSH agent or key-file authentication

pub mod rsync;
pub mod s3;
pub mod sftp;

use std::sync::OnceLock;

use log::{debug, info};
use serde::{Deserialize, Serialize};

use crate::constants::DEFAULT_AWS_REGION;
use crate::error::OpcaError;
use crate::op::{self, CommandRunner};
use crate::settings;

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

/// True when `uri` names an S3 store, and therefore needs AWS credentials.
///
/// Callers use this to resolve credentials only when they are actually
/// required — `rsync://` and `sftp://` uploads must not depend on AWS state.
pub fn needs_aws_credentials(uri: &str) -> bool {
    uri.split("://").next().unwrap_or("").eq_ignore_ascii_case("s3")
}

/// Parse a URI scheme and return the appropriate storage backend.
///
/// `aws_creds` is required for `s3://` URIs (see [`needs_aws_credentials`])
/// and ignored by every other scheme. Passing them in rather than fetching
/// here keeps the expensive `op item get` at the caller, which can reuse one
/// credential across several stores.
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

/// AWS credentials read from a 1Password item.
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: Option<String>,
}

impl AwsCredentials {
    /// The region these credentials should use.
    ///
    /// Completes the precedence `ca_aws_region` → the item's `default region`
    /// field → [`DEFAULT_AWS_REGION`]; the first two are applied when the
    /// credentials are built.
    pub fn region_or_default(&self) -> &str {
        self.region.as_deref().unwrap_or(DEFAULT_AWS_REGION)
    }

    /// These credentials as a static AWS SDK provider, shared by the S3 and
    /// Route53 clients so the two cannot drift apart.
    pub fn sdk_credentials(&self) -> aws_credential_types::Credentials {
        aws_credential_types::Credentials::new(
            &self.access_key_id,
            &self.secret_access_key,
            self.session_token.clone(),
            None, // expiry
            "opca-1password",
        )
    }
}

/// A 1Password item that could hold an AWS access key, as offered to the
/// user when choosing their credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsItemRef {
    pub id: String,
    pub title: String,
    pub vault: String,
}

/// Item categories worth offering as AWS credential candidates.  The `op`
/// AWS shell plugin creates "API Credential" items; hand-made ones are
/// usually "Login".  Everything else (notably the CA's own secure notes and
/// documents) would just be noise in the picker.
///
/// These are `op item list --categories` display names, which differ from
/// the `API_CREDENTIAL` / `LOGIN` forms the JSON output uses.
const AWS_ITEM_CATEGORIES: [&str; 2] = ["API Credential", "Login"];

/// Run an `op` sub-command that is *not* scoped to the CA vault.
///
/// The AWS access key normally lives in the operator's own personal vault,
/// so unlike [`crate::op::Op`]'s item helpers these calls carry no
/// `--vault` flag.  Failures go through [`op::map_cli_error`] so an expired
/// session surfaces as `AuthenticationFailed` rather than an opaque string.
fn run_op<R: CommandRunner>(
    runner: &R,
    account: Option<&str>,
    args: &[&str],
) -> Result<String, OpcaError> {
    // Resolved once per process — this is on the path of every S3 upload.
    static OP_BIN: OnceLock<String> = OnceLock::new();
    let bin = OP_BIN.get_or_init(|| {
        which::which("op")
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "op".to_string())
    });

    let mut args = args.to_vec();
    if let Some(acct) = account {
        args.extend_from_slice(&["--account", acct]);
    }

    let output = runner.run(bin, &args, None, None)?;
    if !output.success {
        return Err(op::map_cli_error(&output));
    }
    Ok(output.stdout)
}

/// List candidate AWS credential items in `account`, so the user can pick
/// the one holding their own access key.
///
/// This is a single `op item list` call — the item contents are not read,
/// so no secrets are fetched until a selection is actually made.
pub fn list_aws_credential_items<R: CommandRunner>(
    runner: &R,
    account: Option<&str>,
) -> Result<Vec<AwsItemRef>, OpcaError> {
    info!("[storage] listing candidate AWS credential items");

    let categories = AWS_ITEM_CATEGORIES.join(",");
    let stdout = run_op(
        runner,
        account,
        &["item", "list", "--categories", &categories, "--format=json"],
    )?;

    parse_aws_item_list(&stdout)
}

/// Retrieve the AWS credentials this user has selected for `account`.
///
/// The selection is per-user local state (see [`crate::settings`]) because
/// several operators share one CA but each has their own AWS access key.
/// `region` comes from the CA config and takes precedence over any region
/// recorded on the item itself.
pub fn get_aws_credentials<R: CommandRunner>(
    runner: &R,
    account: Option<&str>,
    region: Option<&str>,
) -> Result<AwsCredentials, OpcaError> {
    let item_id = settings::aws_credential_item(account).ok_or_else(|| {
        OpcaError::Storage(
            "No AWS credential selected. Pick the 1Password item holding your \
             AWS access key under CA → Stores."
                .into(),
        )
    })?;

    let mut creds = get_aws_credentials_for_item(runner, account, &item_id)?;
    if let Some(region) = region.map(str::trim).filter(|r| !r.is_empty()) {
        creds.region = Some(region.to_string());
    }
    Ok(creds)
}

/// Read AWS credentials from a specific 1Password item.
///
/// Used both by [`get_aws_credentials`] and to validate a selection before
/// it is saved.  Reads the credential fields with a plain `op item get`
/// rather than `op plugin run`, which spawns a sub-process and can hang in
/// non-interactive / GUI contexts.
pub fn get_aws_credentials_for_item<R: CommandRunner>(
    runner: &R,
    account: Option<&str>,
    item_id: &str,
) -> Result<AwsCredentials, OpcaError> {
    info!("[storage] reading AWS credentials from item {item_id}");

    let stdout = run_op(runner, account, &["item", "get", item_id, "--format=json"])?;
    parse_aws_item_json(&stdout)
}

/// Parse the JSON output of `op item list` into credential candidates.
fn parse_aws_item_list(json_str: &str) -> Result<Vec<AwsItemRef>, OpcaError> {
    let items: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
        OpcaError::Storage(format!("Failed to parse op item list JSON: {e}"))
    })?;

    let items = items
        .as_array()
        .ok_or_else(|| OpcaError::Storage("Unexpected op item list response".into()))?;

    let mut refs: Vec<AwsItemRef> = items
        .iter()
        .filter_map(|item| {
            Some(AwsItemRef {
                id: item["id"].as_str()?.to_string(),
                title: item["title"].as_str().unwrap_or("(untitled)").to_string(),
                vault: item["vault"]["name"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();

    refs.sort_by_key(|item| item.title.to_lowercase());
    debug!("[storage] {} candidate AWS credential items", refs.len());
    Ok(refs)
}

/// Parse the JSON output of `op item get` to extract AWS credentials.
///
/// Field labels match those the 1Password AWS shell plugin uses, so items
/// created by `op plugin init aws` work unchanged.
fn parse_aws_item_json(json_str: &str) -> Result<AwsCredentials, OpcaError> {
    let item: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
        OpcaError::Storage(format!("Failed to parse op item JSON: {e}"))
    })?;

    let fields = item["fields"]
        .as_array()
        .ok_or_else(|| OpcaError::Storage("No fields in op item response".into()))?;

    let mut access_key_id: Option<String> = None;
    let mut secret_access_key: Option<String> = None;
    let mut session_token: Option<String> = None;
    let mut region: Option<String> = None;

    for field in fields {
        let label = field["label"].as_str().unwrap_or("").to_lowercase();
        let Some(value) = field["value"].as_str().filter(|v| !v.is_empty()) else {
            continue;
        };
        match label.as_str() {
            "access key id" => access_key_id = Some(value.to_string()),
            "secret access key" => secret_access_key = Some(value.to_string()),
            "session token" => session_token = Some(value.to_string()),
            "default region" | "region" => region = Some(value.to_string()),
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
        session_token,
        region,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(region: Option<&str>) -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIA1234".into(),
            secret_access_key: "secret".into(),
            session_token: None,
            region: region.map(String::from),
        }
    }

    #[test]
    fn test_storage_from_uri_rsync() {
        assert!(storage_from_uri_with_creds("rsync://host/path", None).is_ok());
    }

    #[test]
    fn test_storage_from_uri_sftp() {
        assert!(storage_from_uri_with_creds("sftp://user@host/path", None).is_ok());
        assert!(storage_from_uri_with_creds("scp://user@host/path", None).is_ok());
    }

    #[test]
    fn test_storage_from_uri_unknown() {
        assert!(storage_from_uri_with_creds("ftp://host/path", None).is_err());
    }

    #[test]
    fn test_storage_from_uri_s3_requires_creds() {
        assert!(storage_from_uri_with_creds("s3://bucket/key", None).is_err());
        assert!(storage_from_uri_with_creds("s3://bucket/key", Some(&creds(None))).is_ok());
    }

    #[test]
    fn test_needs_aws_credentials() {
        assert!(needs_aws_credentials("s3://bucket/key"));
        assert!(needs_aws_credentials("S3://bucket/key"));
        assert!(!needs_aws_credentials("rsync://host/path"));
        assert!(!needs_aws_credentials("sftp://user@host/path"));
        assert!(!needs_aws_credentials(""));
    }

    #[test]
    fn test_region_or_default() {
        assert_eq!(creds(Some("us-east-1")).region_or_default(), "us-east-1");
        assert_eq!(creds(None).region_or_default(), DEFAULT_AWS_REGION);
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
    fn test_parse_aws_item_json_optional_fields() {
        let json = r#"{
            "fields": [
                {"label": "Access Key ID", "value": "AKIA1234", "type": "STRING"},
                {"label": "secret access key", "value": "secret123", "type": "CONCEALED"},
                {"label": "session token", "value": "tok", "type": "CONCEALED"},
                {"label": "default region", "value": "us-east-1", "type": "STRING"},
                {"label": "notesPlain", "value": "", "type": "STRING"}
            ]
        }"#;
        let creds = parse_aws_item_json(json).unwrap();
        assert_eq!(creds.access_key_id, "AKIA1234");
        assert_eq!(creds.session_token.as_deref(), Some("tok"));
        assert_eq!(creds.region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn test_parse_aws_item_list() {
        let json = r#"[
            {"id": "bbb", "title": "Zulu key", "vault": {"name": "Employee"}},
            {"id": "aaa", "title": "alpha key", "vault": {"name": "Xentro"}}
        ]"#;
        let items = parse_aws_item_list(json).unwrap();
        assert_eq!(items.len(), 2);
        // Sorted case-insensitively by title.
        assert_eq!(items[0].id, "aaa");
        assert_eq!(items[0].vault, "Xentro");
        assert_eq!(items[1].title, "Zulu key");
    }

    #[test]
    fn test_parse_aws_item_list_skips_malformed() {
        let json = r#"[{"title": "no id"}, {"id": "ok", "title": "fine"}]"#;
        let items = parse_aws_item_list(json).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "ok");
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
