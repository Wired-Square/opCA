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

    #[error("CA database is unreadable: {0}")]
    DatabaseUnreadable(String),

    // ---- 1Password errors ----
    #[error("Vault not found: {0}")]
    VaultNotFound(String),

    #[error("Vault already exists: {0}")]
    VaultAlreadyExists(String),

    #[error("1Password authentication failed")]
    AuthenticationFailed,

    #[error("1Password CLI has no accounts it can use: {0}")]
    NoAccountsConfigured(String),

    #[error("1Password permission denied: {0}")]
    PermissionDenied(String),

    #[error("Item conflict: {0}")]
    ItemConflict(String),

    #[error("Item not found: {0}")]
    ItemNotFound(String),

    #[error("{} items are titled {title:?}: {}", ids.len(), ids.join(", "))]
    AmbiguousItem { title: String, ids: Vec<String> },

    #[error(
        "Vault is locked by {holder_email} ({holder_name}) since {acquired_at} for {operation} (on {hostname})"
    )]
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

    #[error("The re-signed CRL batch was not uploaded to the private store: {0}")]
    CrlBatchUpload(String),

    // ---- Backup errors ----
    #[error("Invalid backup format: {0}")]
    BackupFormat(String),

    #[error("Backup decryption failed — wrong password or corrupted file")]
    BackupDecryption,

    // ---- Route53/DNS errors ----
    #[error("Route53 error: {0}")]
    Route53(String),

    #[error("DNS lookup failed: {0}")]
    Dns(String),

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

impl From<wslib_1password::Error> for OpcaError {
    fn from(err: wslib_1password::Error) -> Self {
        use wslib_1password::Error as E;
        match err {
            E::CliNotFound => OpcaError::CliNotFound,
            E::NotSignedIn(_) | E::NotApproved(_) => OpcaError::AuthenticationFailed,
            E::NoAccountsConfigured(m) => OpcaError::NoAccountsConfigured(m),
            E::PermissionDenied(m) => OpcaError::PermissionDenied(m),
            E::VaultNotFound(m) => OpcaError::VaultNotFound(m),
            E::ItemNotFound(m) => OpcaError::ItemNotFound(m),
            E::ItemConflict(m) => OpcaError::ItemConflict(m),
            E::Ambiguous { title, ids } => OpcaError::AmbiguousItem { title, ids },
            E::Cli { message, .. } => OpcaError::CliError(message),
            E::TimedOut | E::Io(_) => OpcaError::Io(err.to_string()),
            other => OpcaError::CliError(other.to_string()),
        }
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

impl From<wslib_crypto::Error> for OpcaError {
    fn from(err: wslib_crypto::Error) -> Self {
        OpcaError::Crypto(err.to_string())
    }
}

impl From<wslib_crypto_ca::Error> for OpcaError {
    fn from(err: wslib_crypto_ca::Error) -> Self {
        OpcaError::Crypto(err.to_string())
    }
}
