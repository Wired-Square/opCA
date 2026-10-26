//! Storage backends for publishing CA artefacts (certificates, CRLs, database).
//!
//! Each backend lives in its own sub-module:
//! - [`rsync`] — uploads via `rsync -avz` over SSH
//! - [`s3`]    — uploads to AWS S3 using credentials read from 1Password
//! - [`sftp`]  — uploads via SFTP using SSH agent or key-file authentication

pub mod rsync;
pub mod s3;
pub mod sftp;

use log::{debug, info};
use serde::{Deserialize, Serialize};

use crate::constants::DEFAULT_AWS_REGION;
use crate::error::OpcaError;
use crate::op::{Item, ItemRef, ItemSummary, Op, Runner, is_item_id};
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
    uri.split("://")
        .next()
        .unwrap_or("")
        .eq_ignore_ascii_case("s3")
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
    let scheme = uri.split("://").next().unwrap_or("").to_lowercase();

    match scheme.as_str() {
        "rsync" => Ok(Box::new(rsync::StorageRsync)),
        "sftp" | "scp" => Ok(Box::new(sftp::StorageSftp)),
        "s3" => {
            let creds = aws_creds.ok_or_else(|| {
                OpcaError::Storage("AWS credentials required for S3 stores".into())
            })?;
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

/// List candidate AWS credential items in `op`'s account, so the user can pick
/// the one holding their own access key.
///
/// This is a single `op item list` across every vault (the access key normally
/// lives in the operator's own vault, not the CA's) — the item contents are not
/// read, so no secrets are fetched until a selection is actually made.
pub fn list_aws_credential_items<R: Runner>(op: &Op<R>) -> Result<Vec<AwsItemRef>, OpcaError> {
    info!("[storage] listing candidate AWS credential items");
    Ok(aws_item_refs(op.items(&AWS_ITEM_CATEGORIES)?))
}

/// Retrieve the AWS credentials this user has selected for `account`.
///
/// The selection is per-user local state (see [`crate::settings`]) because
/// several operators share one CA but each has their own AWS access key.
/// `region` comes from the CA config and takes precedence over any region
/// recorded on the item itself.
pub fn get_aws_credentials<R: Runner>(
    op: &Op<R>,
    region: Option<&str>,
) -> Result<AwsCredentials, OpcaError> {
    let item_id = settings::aws_credential_item(op.account()).ok_or_else(|| {
        OpcaError::Storage(
            "No AWS credential selected. Pick the 1Password item holding your \
             AWS access key under CA → Stores."
                .into(),
        )
    })?;

    let mut creds = get_aws_credentials_for_item(op, &item_id)?;
    if let Some(region) = region.map(str::trim).filter(|r| !r.is_empty()) {
        creds.region = Some(region.to_string());
    }
    Ok(creds)
}

/// Read AWS credentials from a specific 1Password item, named by id or, as the
/// CLI allows, by title.
///
/// Used both by [`get_aws_credentials`] and to validate a selection before
/// it is saved.  Reads the credential fields with a plain `op item get`
/// rather than `op plugin run`, which spawns a sub-process and can hang in
/// non-interactive / GUI contexts.
pub fn get_aws_credentials_for_item<R: Runner>(
    op: &Op<R>,
    item: &str,
) -> Result<AwsCredentials, OpcaError> {
    info!("[storage] reading AWS credentials from item {item}");
    aws_credentials(&op.item(&id_or_title(item))?)
}

fn id_or_title(item: &str) -> ItemRef {
    if is_item_id(item) {
        ItemRef::id(item)
    } else {
        ItemRef::title(item)
    }
}

fn aws_item_refs(items: Vec<ItemSummary>) -> Vec<AwsItemRef> {
    let mut refs: Vec<AwsItemRef> = items
        .into_iter()
        .map(|item| AwsItemRef {
            id: item.id,
            title: if item.title.is_empty() {
                "(untitled)".into()
            } else {
                item.title
            },
            vault: item.vault.name,
        })
        .collect();

    refs.sort_by_key(|item| item.title.to_lowercase());
    debug!("[storage] {} candidate AWS credential items", refs.len());
    refs
}

/// AWS credentials from an item's fields.
///
/// Field labels match those the 1Password AWS shell plugin uses, so items
/// created by `op plugin init aws` work unchanged.
fn aws_credentials(item: &Item) -> Result<AwsCredentials, OpcaError> {
    let mut access_key_id: Option<String> = None;
    let mut secret_access_key: Option<String> = None;
    let mut session_token: Option<String> = None;
    let mut region: Option<String> = None;

    for field in &item.fields {
        let label = field.label.to_lowercase();
        let Some(value) = field
            .value
            .as_ref()
            .map(|v| v.expose())
            .filter(|v| !v.is_empty())
        else {
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

    fn item(fields: &str) -> Item {
        serde_json::from_str(&format!(
            r#"{{"id":"i1","vault":{{"id":"v1"}},"fields":{fields}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn test_aws_credentials_full() {
        let creds = aws_credentials(&item(
            r#"[
                {"label": "access key id", "value": "AKIA1234", "type": "STRING"},
                {"label": "secret access key", "value": "secret123", "type": "CONCEALED"}
            ]"#,
        ))
        .unwrap();
        assert_eq!(creds.access_key_id, "AKIA1234");
        assert_eq!(creds.secret_access_key, "secret123");
        assert!(creds.session_token.is_none());
        assert!(creds.region.is_none());
    }

    #[test]
    fn test_aws_credentials_optional_fields() {
        let creds = aws_credentials(&item(
            r#"[
                {"label": "Access Key ID", "value": "AKIA1234", "type": "STRING"},
                {"label": "secret access key", "value": "secret123", "type": "CONCEALED"},
                {"label": "session token", "value": "tok", "type": "CONCEALED"},
                {"label": "default region", "value": "us-east-1", "type": "STRING"},
                {"label": "notesPlain", "value": "", "type": "STRING"}
            ]"#,
        ))
        .unwrap();
        assert_eq!(creds.access_key_id, "AKIA1234");
        assert_eq!(creds.session_token.as_deref(), Some("tok"));
        assert_eq!(creds.region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn test_list_aws_credential_items_across_vaults_sorted() {
        use crate::testutil::{FakeRunner, Output};
        let fake = FakeRunner::new();
        fake.respond(Output::ok(
            r#"[
                {"id": "bbb", "title": "Zulu key", "vault": {"id": "v1", "name": "Employee"}},
                {"id": "aaa", "title": "alpha key", "vault": {"id": "v2", "name": "Xentro"}}
            ]"#,
        ));
        let items =
            list_aws_credential_items(&crate::op::client(fake.clone(), Some("ws"))).unwrap();
        assert_eq!(items.len(), 2);
        // Sorted case-insensitively by title.
        assert_eq!(items[0].id, "aaa");
        assert_eq!(items[0].vault, "Xentro");
        assert_eq!(items[1].title, "Zulu key");

        let args = fake.calls()[0].args().to_vec();
        assert_eq!(args[..2], ["item", "list"]);
        assert!(args.contains(&"--categories=API Credential,Login".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("--vault")));
        assert!(args.ends_with(&["--account".to_string(), "ws".to_string()]));
    }

    #[test]
    fn test_aws_credentials_are_read_by_item_id() {
        use crate::testutil::{FakeRunner, Output, item_id};
        let fake = FakeRunner::new();
        fake.respond(Output::ok(format!(
            r#"{{"id":"{}","vault":{{"id":"v1"}},"fields":[
                {{"label":"access key id","value":"AKIA1234"}},
                {{"label":"secret access key","value":"secret123"}}]}}"#,
            item_id(7)
        )));
        let creds =
            get_aws_credentials_for_item(&crate::op::client(fake.clone(), None), &item_id(7))
                .unwrap();
        assert_eq!(creds.access_key_id, "AKIA1234");
        assert_eq!(
            fake.calls()[0].args()[..3],
            ["item", "get", item_id(7).as_str()]
        );
    }

    #[test]
    fn test_aws_credentials_missing_key() {
        let result = aws_credentials(&item(
            r#"[{"label": "secret access key", "value": "secret123", "type": "CONCEALED"}]"#,
        ));
        assert!(result.is_err());
    }

    #[test]
    fn test_aws_credentials_empty_fields() {
        assert!(aws_credentials(&item("[]")).is_err());
    }
}
