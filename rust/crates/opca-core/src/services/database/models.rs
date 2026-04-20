use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Certificate status values stored in the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertStatus {
    Valid,
    Expired,
    Revoked,
}

impl fmt::Display for CertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertStatus::Valid => write!(f, "Valid"),
            CertStatus::Expired => write!(f, "Expired"),
            CertStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

impl FromStr for CertStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Valid" => Ok(CertStatus::Valid),
            "Expired" => Ok(CertStatus::Expired),
            "Revoked" => Ok(CertStatus::Revoked),
            other => Err(format!("Unknown certificate status: {other}")),
        }
    }
}

/// A CA-issued certificate record (`certificate_authority` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRecord {
    pub serial: String,
    pub cn: Option<String>,
    pub title: Option<String>,
    pub status: Option<String>,
    pub expiry_date: Option<String>,
    pub revocation_date: Option<String>,
    pub subject: Option<String>,
    pub cert_type: Option<String>,
    pub not_before: Option<String>,
    pub key_type: Option<String>,
    pub key_size: Option<i64>,
    pub issuer: Option<String>,
    pub san: Option<String>,
    /// ISO 8601 timestamp the cert was marked as ignored; `None` means active.
    pub ignored_at: Option<String>,
    /// `email (name)` of the 1Password user who set the ignore.
    pub ignored_by: Option<String>,
    /// One of: `renewed`, `rekeyed`, `manual`.
    pub ignored_reason: Option<String>,
    /// Optional free-text note; for auto-ignores, carries `"replaced by <new_serial>"`.
    pub ignored_note: Option<String>,
}

/// Reason a certificate was ignored. Today only manual ignores are written;
/// the enum is retained for future reasons (e.g. auto-ignore triggered by
/// some future automated workflow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    Manual,
}

impl IgnoreReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            IgnoreReason::Manual => "manual",
        }
    }
}

/// An external (third-party signed) certificate record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCertRecord {
    pub serial: String,
    pub cn: Option<String>,
    pub title: Option<String>,
    pub status: Option<String>,
    pub expiry_date: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub issuer_subject: Option<String>,
    pub import_date: Option<String>,
    pub cert_type: Option<String>,
    pub not_before: Option<String>,
    pub key_type: Option<String>,
    pub key_size: Option<i64>,
    pub san: Option<String>,
}

/// A certificate signing request record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CsrRecord {
    pub id: Option<i64>,
    pub cn: Option<String>,
    pub title: Option<String>,
    pub csr_type: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub status: Option<String>,
    pub created_date: Option<String>,
    pub csr_pem: Option<String>,
}

/// CA configuration (singleton row in `config` table).
///
/// Serial fields are stored as `TEXT` in the database but exposed as `i64`
/// here, with conversion at the boundary (matching the Python behaviour).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaConfig {
    /// CA Common Name — used only during init, not persisted to the database.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cn: Option<String>,
    /// CA certificate validity in days — used only during init, not persisted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ca_days: Option<i64>,
    pub next_serial: Option<i64>,
    pub next_crl_serial: Option<i64>,
    pub org: Option<String>,
    pub ou: Option<String>,
    pub email: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub ca_url: Option<String>,
    pub crl_url: Option<String>,
    pub days: Option<i64>,
    pub crl_days: Option<i64>,
    pub schema_version: Option<i64>,
    pub ca_public_store: Option<String>,
    pub ca_private_store: Option<String>,
    pub ca_backup_store: Option<String>,
}

/// CRL cache metadata (singleton row, `id=1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlMetadata {
    pub issuer: Option<String>,
    pub last_update: Option<String>,
    pub next_update: Option<String>,
    pub crl_number: Option<i64>,
    pub revoked_count: Option<i64>,
    pub revoked_json: Option<String>,
}

/// OpenVPN template record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnTemplate {
    pub id: Option<i64>,
    pub name: String,
    pub content: String,
    pub updated_date: Option<String>,
}

/// OpenVPN profile registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnProfile {
    pub id: Option<i64>,
    pub cn: String,
    pub title: String,
    pub created_date: Option<String>,
    pub template: Option<String>,
}

/// Schema migration report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationInfo {
    pub migrated: bool,
    pub from_version: i64,
    pub to_version: i64,
    pub steps: Vec<MigrationStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStep {
    pub to: i64,
    pub ok: bool,
}

/// How to look up a certificate or external certificate.
#[derive(Debug, Clone)]
pub enum CertLookup {
    Serial(String),
    Cn(String),
    Title(String),
}

/// How to look up a CSR.
#[derive(Debug, Clone)]
pub enum CsrLookup {
    Id(i64),
    Cn(String),
}

/// Which serial counter to increment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialType {
    Cert,
    Crl,
}
