//! Vault-level backup and restore operations.
//!
//! Enumerates every item in a 1Password vault (CA, certificates, CRL,
//! database, OpenVPN, CSRs, external certs) and serialises them into a
//! JSON payload suitable for encryption by [`crate::services::backup`].

use serde::{Deserialize, Serialize};

use crate::constants::OpConf;
use crate::error::OpcaError;
use crate::op::{CommandRunner, Op, StoreAction};
use crate::utils::datetime::{self, DateTimeFormat};

// ---------------------------------------------------------------------------
// Item type tags
// ---------------------------------------------------------------------------

pub const ITEM_TYPE_CA: &str = "ca";
pub const ITEM_TYPE_CA_DATABASE: &str = "ca_database";
pub const ITEM_TYPE_CRL: &str = "crl";
pub const ITEM_TYPE_CERTIFICATE: &str = "certificate";
pub const ITEM_TYPE_EXTERNAL_CERT: &str = "external_certificate";
pub const ITEM_TYPE_CSR: &str = "csr";
pub const ITEM_TYPE_OPENVPN: &str = "openvpn";

// ---------------------------------------------------------------------------
// Backup metadata
// ---------------------------------------------------------------------------

/// Metadata section of a vault backup payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub opca_version: String,
    pub backup_date: String,
    pub vault_name: String,
    pub item_count: usize,
}

/// A single backed-up item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupItem {
    #[serde(rename = "type")]
    pub item_type: String,
    pub title: String,
    pub data: String,
}

/// The full backup payload (metadata + items).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPayload {
    pub metadata: BackupMetadata,
    pub items: Vec<BackupItem>,
}

/// Counts of restored items by type.
pub type RestoreCounts = std::collections::HashMap<String, usize>;

// ---------------------------------------------------------------------------
// VaultBackup
// ---------------------------------------------------------------------------

/// Create and restore encrypted vault backups.
pub struct VaultBackup<'a, R: CommandRunner> {
    op: &'a Op<R>,
    op_config: &'a OpConf,
}

impl<'a, R: CommandRunner> VaultBackup<'a, R> {
    pub fn new(op: &'a Op<R>, op_config: &'a OpConf) -> Self {
        Self { op, op_config }
    }

    // -----------------------------------------------------------------------
    // Backup
    // -----------------------------------------------------------------------

    /// Enumerate every item in the vault and return the backup payload.
    pub fn create_backup(&self) -> Result<BackupPayload, OpcaError> {
        let mut items = Vec::new();

        // 1. CA item (Secure Note)
        let ca_json = self.get_item_json(self.op_config.ca_title);
        match ca_json {
            Some(data) => items.push(BackupItem {
                item_type: ITEM_TYPE_CA.to_string(),
                title: self.op_config.ca_title.to_string(),
                data,
            }),
            None => {
                return Err(OpcaError::Other(
                    "CA item not found — nothing to back up.".to_string(),
                ))
            }
        }

        // 2. CA Database (Document)
        if let Some(data) = self.get_document_content(self.op_config.ca_database_title) {
            items.push(BackupItem {
                item_type: ITEM_TYPE_CA_DATABASE.to_string(),
                title: self.op_config.ca_database_title.to_string(),
                data,
            });
        }

        // 3. CRL (Document)
        if let Some(data) = self.get_document_content(self.op_config.crl_title) {
            items.push(BackupItem {
                item_type: ITEM_TYPE_CRL.to_string(),
                title: self.op_config.crl_title.to_string(),
                data,
            });
        }

        // 4. OpenVPN (Secure Note — optional)
        if let Some(data) = self.get_item_json(self.op_config.openvpn_title) {
            items.push(BackupItem {
                item_type: ITEM_TYPE_OPENVPN.to_string(),
                title: self.op_config.openvpn_title.to_string(),
                data,
            });
        }

        // 5. All remaining Secure Notes (certificates, CSRs, external certs)
        let known_titles: std::collections::HashSet<&str> = [
            self.op_config.ca_title,
            self.op_config.openvpn_title,
        ]
        .into_iter()
        .collect();

        let all_notes = self.list_secure_notes()?;

        for note_title in &all_notes {
            if known_titles.contains(note_title.as_str()) {
                continue;
            }

            if let Some(data) = self.get_item_json(note_title) {
                let item_type = classify_item(note_title, &data);
                items.push(BackupItem {
                    item_type,
                    title: note_title.clone(),
                    data,
                });
            }
        }

        let metadata = BackupMetadata {
            opca_version: env!("CARGO_PKG_VERSION").to_string(),
            backup_date: datetime::now_utc_str(DateTimeFormat::Openssl),
            vault_name: self.op.vault.clone(),
            item_count: items.len(),
        };

        Ok(BackupPayload { metadata, items })
    }

    // -----------------------------------------------------------------------
    // Restore
    // -----------------------------------------------------------------------

    /// Restore items from a backup payload into the current vault.
    ///
    /// The vault must be empty (no existing CA item).
    pub fn restore_backup(
        &self,
        payload: &BackupPayload,
        on_progress: Option<&dyn Fn(&str, &str)>,
    ) -> Result<RestoreCounts, OpcaError> {
        if self.op.item_exists(self.op_config.ca_title) {
            return Err(OpcaError::Other(
                "Target vault already contains a CA. Restore requires an empty vault.".to_string(),
            ));
        }

        let mut items = payload.items.clone();
        items.sort_by_key(|i| restore_order(&i.item_type));

        let mut counts = RestoreCounts::new();

        for item in &items {
            if let Some(cb) = on_progress {
                cb(&item.item_type, &item.title);
            }

            if item.item_type == ITEM_TYPE_CA_DATABASE || item.item_type == ITEM_TYPE_CRL {
                self.restore_document(&item.title, &item.data)?;
            } else {
                self.restore_secure_note(&item.title, &item.data)?;
            }

            *counts.entry(item.item_type.clone()).or_insert(0) += 1;
        }

        Ok(counts)
    }

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    /// Return only the metadata section from a backup payload.
    pub fn get_metadata(payload: &BackupPayload) -> &BackupMetadata {
        &payload.metadata
    }

    // -----------------------------------------------------------------------
    // Internal — read helpers
    // -----------------------------------------------------------------------

    /// Return the raw JSON string from `op item get`, or `None`.
    fn get_item_json(&self, title: &str) -> Option<String> {
        self.op.get_item(title, "json").ok()
    }

    /// Return document text from `op document get`, or `None`.
    fn get_document_content(&self, title: &str) -> Option<String> {
        self.op.get_document(title).ok()
    }

    /// Return titles of all Secure Note items in the vault.
    fn list_secure_notes(&self) -> Result<Vec<String>, OpcaError> {
        let json_str = self.op.item_list(self.op_config.category, "json")?;
        let notes: Vec<serde_json::Value> = serde_json::from_str(&json_str)
            .map_err(|e| OpcaError::Other(format!("Failed to parse item list: {e}")))?;

        Ok(notes
            .iter()
            .filter_map(|n| n.get("title")?.as_str().map(|s| s.to_string()))
            .collect())
    }

    // -----------------------------------------------------------------------
    // Internal — restore helpers
    // -----------------------------------------------------------------------

    /// Re-create a Document item in the vault.
    fn restore_document(&self, title: &str, content: &str) -> Result<(), OpcaError> {
        let filename = if title == self.op_config.ca_database_title {
            self.op_config.ca_database_filename
        } else if title == self.op_config.crl_title {
            self.op_config.crl_filename
        } else {
            // Fallback
            title
        };

        self.op
            .store_document(title, filename, content, StoreAction::Create, None)?;
        Ok(())
    }

    /// Re-create a Secure Note item from its saved JSON.
    fn restore_secure_note(&self, title: &str, item_json: &str) -> Result<(), OpcaError> {
        let obj: serde_json::Value = serde_json::from_str(item_json).map_err(|e| {
            OpcaError::Other(format!("Invalid JSON for item {title:?}: {e}"))
        })?;

        let attributes = extract_attributes(&obj);
        let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();

        self.op.store_item(
            title,
            Some(&attr_refs),
            StoreAction::Create,
            self.op_config.category,
            None,
            None,
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine the item type from its title and field content.
pub fn classify_item(title: &str, item_json: &str) -> String {
    if title.starts_with("EXT_") {
        return ITEM_TYPE_EXTERNAL_CERT.to_string();
    }

    let obj: serde_json::Value = match serde_json::from_str(item_json) {
        Ok(v) => v,
        Err(_) => return ITEM_TYPE_CERTIFICATE.to_string(),
    };

    let labels: std::collections::HashSet<String> = obj
        .get("fields")
        .and_then(|f| f.as_array())
        .map(|fields| {
            fields
                .iter()
                .filter_map(|f| f.get("label")?.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if labels.contains("certificate") {
        ITEM_TYPE_CERTIFICATE.to_string()
    } else if labels.contains("certificate_signing_request") {
        ITEM_TYPE_CSR.to_string()
    } else {
        ITEM_TYPE_CERTIFICATE.to_string()
    }
}

/// Return a sort key so items are restored in dependency order.
fn restore_order(item_type: &str) -> u8 {
    match item_type {
        ITEM_TYPE_CA => 0,
        ITEM_TYPE_CA_DATABASE => 1,
        ITEM_TYPE_CRL => 2,
        ITEM_TYPE_OPENVPN => 3,
        ITEM_TYPE_CERTIFICATE => 4,
        ITEM_TYPE_EXTERNAL_CERT => 5,
        ITEM_TYPE_CSR => 6,
        _ => 99,
    }
}

/// Build `label=value` attribute list from an `op item get` JSON object.
///
/// Only includes fields that have a non-empty value and a user-visible label
/// (skips internal 1Password fields like `notesPlain`).
pub fn extract_attributes(item_obj: &serde_json::Value) -> Vec<String> {
    let skip_labels: std::collections::HashSet<&str> =
        ["notesPlain", "password", "username"].into_iter().collect();
    let skip_ids: std::collections::HashSet<&str> =
        ["notesPlain", "password", "username"].into_iter().collect();

    let fields = match item_obj.get("fields").and_then(|f| f.as_array()) {
        Some(f) => f,
        None => return Vec::new(),
    };

    let mut attrs = Vec::new();

    for field in fields {
        let label = field
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let value = field
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let field_id = field.get("id").and_then(|v| v.as_str()).unwrap_or("");

        if label.is_empty() || skip_labels.contains(label) {
            continue;
        }
        if skip_ids.contains(field_id) {
            continue;
        }
        if value.is_empty() {
            continue;
        }

        // Section-qualified labels
        let section_label = field
            .get("section")
            .and_then(|s| s.get("label"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut qualified = if section_label.is_empty() {
            label.to_string()
        } else {
            format!("{section_label}.{label}")
        };

        // STRING fields need [text] suffix
        let field_type = field
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if field_type == "STRING" && !qualified.contains("[text]") {
            qualified = format!("{qualified}[text]");
        }

        attrs.push(format!("{qualified}={value}"));
    }

    attrs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_certificate() {
        let json = r#"{"fields":[{"label":"certificate","value":"pem-data"}]}"#;
        assert_eq!(classify_item("my_cert", json), ITEM_TYPE_CERTIFICATE);
    }

    #[test]
    fn test_classify_csr() {
        let json =
            r#"{"fields":[{"label":"certificate_signing_request","value":"csr-data"}]}"#;
        assert_eq!(classify_item("my_csr", json), ITEM_TYPE_CSR);
    }

    #[test]
    fn test_classify_external_cert() {
        let json = r#"{"fields":[{"label":"certificate","value":"pem-data"}]}"#;
        assert_eq!(classify_item("EXT_example.com", json), ITEM_TYPE_EXTERNAL_CERT);
    }

    #[test]
    fn test_classify_invalid_json() {
        assert_eq!(
            classify_item("something", "not valid json"),
            ITEM_TYPE_CERTIFICATE
        );
    }

    #[test]
    fn test_classify_no_fields() {
        let json = r#"{"fields":[]}"#;
        assert_eq!(classify_item("empty", json), ITEM_TYPE_CERTIFICATE);
    }

    #[test]
    fn test_restore_order() {
        assert!(restore_order(ITEM_TYPE_CA) < restore_order(ITEM_TYPE_CA_DATABASE));
        assert!(restore_order(ITEM_TYPE_CA_DATABASE) < restore_order(ITEM_TYPE_CRL));
        assert!(restore_order(ITEM_TYPE_CRL) < restore_order(ITEM_TYPE_OPENVPN));
        assert!(restore_order(ITEM_TYPE_OPENVPN) < restore_order(ITEM_TYPE_CERTIFICATE));
        assert!(restore_order(ITEM_TYPE_CERTIFICATE) < restore_order(ITEM_TYPE_EXTERNAL_CERT));
        assert!(restore_order(ITEM_TYPE_EXTERNAL_CERT) < restore_order(ITEM_TYPE_CSR));
        assert_eq!(restore_order("unknown"), 99);
    }

    #[test]
    fn test_extract_attributes_basic() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"fields":[
                {"label":"cn","value":"test.example.com","type":"STRING","id":"cn"},
                {"label":"certificate","value":"pem-data","type":"CONCEALED","id":"cert"}
            ]}"#,
        )
        .unwrap();

        let attrs = extract_attributes(&json);
        assert_eq!(attrs.len(), 2);
        assert!(attrs.contains(&"cn[text]=test.example.com".to_string()));
        assert!(attrs.contains(&"certificate=pem-data".to_string()));
    }

    #[test]
    fn test_extract_attributes_skips_internal() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"fields":[
                {"label":"notesPlain","value":"notes","type":"STRING","id":"notesPlain"},
                {"label":"cn","value":"test","type":"STRING","id":"cn"}
            ]}"#,
        )
        .unwrap();

        let attrs = extract_attributes(&json);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], "cn[text]=test");
    }

    #[test]
    fn test_extract_attributes_skips_empty() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"fields":[
                {"label":"cn","value":"","type":"STRING","id":"cn"},
                {"label":"org","value":"Acme","type":"STRING","id":"org"}
            ]}"#,
        )
        .unwrap();

        let attrs = extract_attributes(&json);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], "org[text]=Acme");
    }

    #[test]
    fn test_extract_attributes_section_qualified() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"fields":[
                {"label":"dh_parameters","value":"pem","type":"CONCEALED","id":"dh",
                 "section":{"label":"diffie-hellman"}}
            ]}"#,
        )
        .unwrap();

        let attrs = extract_attributes(&json);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], "diffie-hellman.dh_parameters=pem");
    }

    #[test]
    fn test_extract_attributes_no_fields() {
        let json: serde_json::Value = serde_json::from_str(r#"{"other":"stuff"}"#).unwrap();
        let attrs = extract_attributes(&json);
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_backup_metadata() {
        let payload = BackupPayload {
            metadata: BackupMetadata {
                opca_version: "0.1.0".to_string(),
                backup_date: "20260314120000Z".to_string(),
                vault_name: "TestVault".to_string(),
                item_count: 3,
            },
            items: vec![],
        };

        let meta = VaultBackup::<crate::testutil::MockRunner>::get_metadata(&payload);
        assert_eq!(meta.vault_name, "TestVault");
        assert_eq!(meta.item_count, 3);
    }

    #[test]
    fn test_backup_payload_serialise_roundtrip() {
        let payload = BackupPayload {
            metadata: BackupMetadata {
                opca_version: "0.1.0".to_string(),
                backup_date: "20260314120000Z".to_string(),
                vault_name: "TestVault".to_string(),
                item_count: 1,
            },
            items: vec![BackupItem {
                item_type: ITEM_TYPE_CA.to_string(),
                title: "CA".to_string(),
                data: r#"{"fields":[]}"#.to_string(),
            }],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let parsed: BackupPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.metadata.vault_name, "TestVault");
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].item_type, ITEM_TYPE_CA);
    }
}
