use serde::Serialize;
use thiserror::Error;

/// Unified error type for all OPCA operations.
///
/// Maps from the Python `CAError` and `OPError` hierarchies into a single enum.
#[derive(Debug, Error, Serialize, Clone)]
#[serde(tag = "kind", content = "message")]
pub enum OpcaError {
    // ---- Certificate Authority errors ----
    #[error("CA already exists in vault")]
    CaAlreadyExists,

    #[error("CA not found in vault")]
    CaNotFound,

    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),

    #[error("Duplicate certificate: {0}")]
    DuplicateCertificate(String),

    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("Certificate has been revoked: {0}")]
    CertificateRevoked(String),

    #[error("Certificate has expired: {0}")]
    CertificateExpired(String),

    #[error("CSR not found: {0}")]
    CsrNotFound(String),

    // ---- Database errors ----
    #[error("Database error: {0}")]
    Database(String),

    #[error("Schema migration failed: {0}")]
    SchemaMigration(String),

    // ---- 1Password errors ----
    #[error("Vault not found: {0}")]
    VaultNotFound(String),

    #[error("1Password authentication failed")]
    AuthenticationFailed,

    #[error("1Password permission denied: {0}")]
    PermissionDenied(String),

    #[error("Item conflict: {0}")]
    ItemConflict(String),

    #[error("Item not found: {0}")]
    ItemNotFound(String),

    #[error("Vault is locked by {holder_email} ({holder_name}) since {acquired_at} for {operation} (on {hostname})")]
    VaultLocked {
        holder_email: String,
        holder_name: String,
        acquired_at: String,
        operation: String,
        hostname: String,
    },

    #[error("1Password CLI error: {0}")]
    CliError(String),

    #[error("1Password CLI not found")]
    CliNotFound,

    // ---- Storage errors ----
    #[error("Storage error: {0}")]
    Storage(String),

    // ---- Backup errors ----
    #[error("Invalid backup format: {0}")]
    BackupFormat(String),

    #[error("Backup decryption failed — wrong password or corrupted file")]
    BackupDecryption,

    // ---- Route53/DNS errors ----
    #[error("Route53 error: {0}")]
    Route53(String),

    // ---- Crypto errors ----
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    // ---- General ----
    #[error("I/O error: {0}")]
    Io(String),

    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for OpcaError {
    fn from(err: std::io::Error) -> Self {
        OpcaError::Io(err.to_string())
    }
}

impl From<rusqlite::Error> for OpcaError {
    fn from(err: rusqlite::Error) -> Self {
        OpcaError::Database(err.to_string())
    }
}

impl From<openssl::error::ErrorStack> for OpcaError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        OpcaError::Crypto(err.to_string())
    }
}
