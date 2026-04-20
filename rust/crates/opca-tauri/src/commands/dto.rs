//! Data transfer objects for Tauri commands.
//!
//! These structs bridge opca-core domain types to the frontend.
//! They are Serialize-only — the frontend never sends them back.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DashboardData {
    pub ca_valid: bool,
    pub ca_cn: Option<String>,
    pub ca_expiry: Option<String>,
    pub ca_expiry_warning: Option<CaExpiryWarningDto>,
    pub crl_present: bool,
    pub crl_next_update: Option<String>,
    pub crl_expiry_warning: Option<CrlExpiryWarningDto>,
    pub total_certs: i64,
    pub valid_certs: usize,
    pub expired_certs: usize,
    pub expiring_certs: usize,
    pub warning_certs: usize,
    pub revoked_certs: usize,
    pub pending_csrs: usize,
    pub has_public_store: bool,
    pub action_items: Vec<ActionItemDto>,
}

/// Graduated CA certificate expiry warning for the frontend.
#[derive(Debug, Serialize)]
pub struct CaExpiryWarningDto {
    /// Warning level: "critical", "prominent", "cert_lifetime", or "none".
    pub level: String,
    /// Days remaining until CA certificate expires.
    pub days_remaining: Option<i64>,
    /// Human-readable warning message.
    pub message: String,
}

/// Graduated CRL expiry warning for the frontend.
#[derive(Debug, Serialize)]
pub struct CrlExpiryWarningDto {
    /// Warning level: "critical", "prominent", "expired", or "none".
    pub level: String,
    /// Days remaining until the CRL's next_update. Negative when expired.
    pub days_remaining: Option<i64>,
    /// Human-readable warning message.
    pub message: String,
}

/// Actionable item surfaced on the dashboard.
#[derive(Debug, Serialize)]
pub struct ActionItemDto {
    /// Stable identifier, e.g. "crl_regenerate".
    pub id: String,
    /// Severity: "critical", "warning", or "info".
    pub severity: String,
    /// Human-readable description of the issue.
    pub message: String,
    /// Label for the action button.
    pub button_label: String,
    /// Action token the frontend dispatches on, e.g. "regenerate_and_upload_crl".
    pub action: String,
}

// ---------------------------------------------------------------------------
// CA
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CaInfo {
    pub cn: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub key_type: Option<String>,
    pub key_size: Option<String>,
    pub is_valid: bool,
    pub cert_pem: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaConfigDto {
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
    pub ca_public_store: Option<String>,
    pub ca_private_store: Option<String>,
    pub ca_backup_store: Option<String>,
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CertListItem {
    pub serial: Option<String>,
    pub cn: Option<String>,
    pub title: Option<String>,
    pub status: Option<String>,
    pub cert_type: Option<String>,
    pub expiry_date: Option<String>,
    pub key_type: Option<String>,
    pub key_size: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CertDetail {
    pub serial: Option<String>,
    pub cn: Option<String>,
    pub title: Option<String>,
    pub status: Option<String>,
    pub cert_type: Option<String>,
    pub expiry_date: Option<String>,
    pub key_type: Option<String>,
    pub key_size: Option<i64>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub revocation_date: Option<String>,
    pub san: Option<String>,
    pub cert_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCertRequest {
    pub cn: String,
    pub cert_type: String,
    pub alt_dns_names: Option<Vec<String>>,
    pub key_size: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ImportCertRequest {
    /// PEM-encoded certificate (required).
    pub cert_pem: String,
    /// PEM-encoded private key (optional).
    pub key_pem: Option<String>,
    /// Passphrase for encrypted private keys (optional).
    pub passphrase: Option<String>,
    /// PEM-encoded certificate chain / intermediate CAs (optional).
    pub chain_pem: Option<String>,
}

/// Result of an import — includes whether the cert was detected as local or external.
#[derive(Debug, Serialize)]
pub struct ImportCertResult {
    pub cert: CertListItem,
    pub is_external: bool,
}

#[derive(Debug, Serialize)]
pub struct ExternalCertListItem {
    pub serial: Option<String>,
    pub cn: Option<String>,
    pub status: Option<String>,
    pub cert_type: Option<String>,
    pub expiry_date: Option<String>,
    pub issuer: Option<String>,
    pub import_date: Option<String>,
    pub key_type: Option<String>,
    pub key_size: Option<i64>,
}

// ---------------------------------------------------------------------------
// CSR
// ---------------------------------------------------------------------------

/// CSR list item returned to the frontend.
#[derive(Debug, Serialize)]
pub struct CsrListItem {
    pub id: Option<i64>,
    pub cn: Option<String>,
    pub title: Option<String>,
    pub csr_type: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub status: Option<String>,
    pub created_date: Option<String>,
}

/// Request to create a new CSR.
#[derive(Debug, Deserialize)]
pub struct CreateCsrRequest {
    pub cn: String,
    pub csr_type: String,
    pub email: Option<String>,
    pub country: Option<String>,
    pub key_size: Option<u32>,
    pub alt_dns_names: Option<Vec<String>>,
}

/// Result of CSR creation.
#[derive(Debug, Serialize)]
pub struct CreateCsrResult {
    pub item: CsrListItem,
    pub csr_pem: String,
}

/// Decoded CSR information returned after parsing a PEM.
#[derive(Debug, Serialize)]
pub struct DecodeCsrResult {
    pub cn: Option<String>,
    pub subject: String,
    pub alt_dns_names: Vec<String>,
}

/// Request to sign an external CSR with the local CA.
#[derive(Debug, Deserialize)]
pub struct SignCsrRequest {
    pub csr_pem: String,
    pub csr_type: String,
    pub cn: Option<String>,
}

/// Result of signing a CSR.
#[derive(Debug, Serialize)]
pub struct SignCsrResult {
    pub cert: CertListItem,
    pub cert_pem: String,
}

/// Request to import an externally-signed certificate back to a pending CSR.
#[derive(Debug, Deserialize)]
pub struct ImportCsrCertRequest {
    pub cert_pem: String,
    pub cn: Option<String>,
}

// ---------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DkimKeyItem {
    pub domain: String,
    pub selector: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DkimKeyDetail {
    pub domain: String,
    pub selector: String,
    pub key_size: Option<String>,
    pub dns_name: String,
    pub dns_record: Option<String>,
    /// `dns_record` reformatted as 255-byte quoted chunks for AWS Route53.
    pub dns_record_chunked: Option<String>,
    pub created_at: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDkimRequest {
    pub domain: String,
    pub selector: String,
    pub key_size: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CreateDkimResult {
    pub item: DkimKeyItem,
    pub dns_name: String,
    pub dns_record: String,
    /// `dns_record` reformatted as 255-byte quoted chunks for AWS Route53.
    pub dns_record_chunked: String,
}

#[derive(Debug, Serialize)]
pub struct DkimVerifyResult {
    pub verified: bool,
    pub dns_name: String,
    pub message: String,
    pub expected: Option<String>,
    pub found: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DkimRoute53Result {
    pub dns_name: String,
    pub zone_name: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// OpenVPN
// ---------------------------------------------------------------------------

/// Summary of OpenVPN server parameters (DH + TA) from 1Password.
#[derive(Debug, Serialize)]
pub struct OpenVpnServerParams {
    pub has_item: bool,
    pub dh_key_size: Option<String>,
    pub has_dh: bool,
    pub ta_key_size: Option<String>,
    pub has_ta: bool,
    pub hostname: Option<String>,
    pub port: Option<String>,
    pub cipher: Option<String>,
    pub auth: Option<String>,
}

/// Template list item (from database).
#[derive(Debug, Serialize)]
pub struct OpenVpnTemplateItem {
    pub name: String,
    pub updated_date: Option<String>,
}

/// Full template with content.
#[derive(Debug, Serialize)]
pub struct OpenVpnTemplateDetail {
    pub name: String,
    pub content: String,
    pub updated_date: Option<String>,
}

/// Profile list item (from database).
#[derive(Debug, Serialize)]
pub struct OpenVpnProfileItem {
    pub cn: String,
    pub title: String,
    pub created_date: Option<String>,
    pub template: Option<String>,
}

/// Request to generate a VPN profile.
#[derive(Debug, Deserialize)]
pub struct GenerateProfileRequest {
    pub cn: String,
    pub template_name: String,
    pub dest_vault: Option<String>,
}

/// Request to set up the OpenVPN server object.
#[derive(Debug, Deserialize)]
pub struct ServerSetupRequest {
    pub template_name: String,
}

// ---------------------------------------------------------------------------
// CRL
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CrlInfo {
    pub issuer: Option<String>,
    pub last_update: Option<String>,
    pub next_update: Option<String>,
    pub crl_number: Option<i64>,
    pub revoked_count: usize,
    pub crl_pem: Option<String>,
    pub has_public_store: bool,
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DatabaseInfo {
    pub config: CaConfigDto,
    pub total_certs: i64,
    pub total_external_certs: i64,
    pub schema_version: i64,
}

// ---------------------------------------------------------------------------
// Vault Backup
// ---------------------------------------------------------------------------

/// Metadata from a backup file, returned by the info command.
#[derive(Debug, Serialize)]
pub struct BackupInfoResult {
    pub opca_version: String,
    pub vault_name: String,
    pub backup_date: String,
    pub item_count: usize,
    pub item_breakdown: Vec<BackupItemCount>,
}

/// Count of items by type within a backup.
#[derive(Debug, Serialize)]
pub struct BackupItemCount {
    pub item_type: String,
    pub count: usize,
}

/// Summary returned after a successful restore.
#[derive(Debug, Serialize)]
pub struct RestoreResult {
    pub items_restored: usize,
    pub item_breakdown: Vec<BackupItemCount>,
}

// ---------------------------------------------------------------------------
// Action Log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Short action name, e.g. "connect", "create_cert", "store_database".
    pub action: String,
    /// Optional detail message or error text.
    pub detail: Option<String>,
    /// Whether the action succeeded.
    pub success: bool,
}
