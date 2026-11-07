//! The API opCA calls on an ACME broker: the wire types both ends build against.

use serde::{Deserialize, Serialize};

pub const API_VERSION: u32 = 1;

/// The scheme of the pairing string a broker prints for opCA.
pub const PAIRING_SCHEME: &str = "opca-enrol";

pub mod path {
    pub const ENROLMENT: &str = "/v1/enrolment";
    pub const STATUS: &str = "/v1/status";
    pub const CSR: &str = "/v1/csr";
    pub const CHAIN: &str = "/v1/chain";
    pub const REVOKE: &str = "/v1/revoke";
    /// `POST`s with no body, each answered with the [`Status`](super::Status); both idempotent.
    pub const PAUSE: &str = "/v1/pause";
    pub const RESUME: &str = "/v1/resume";
    pub const ISSUED: &str = "/v1/issued";
    /// `POST`s a [`LeafRevocation`](super::LeafRevocation), answered with the [`IssuedCertificate`](super::IssuedCertificate).
    pub const REVOKE_ISSUED: &str = "/v1/issued/{serial}/revoke";

    pub fn revoke_issued(serial: &str) -> String {
        REVOKE_ISSUED.replace("{serial}", serial)
    }
}

/// The RFC 5280 CRLReason codes a leaf may be revoked for, as ACME's `revoke-cert` takes them.
pub const REVOCATION_REASONS: [u8; 9] = [0, 1, 2, 3, 4, 5, 6, 9, 10];

/// The `GET /v1/enrolment` response: what the broker asks opCA to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolmentOffer {
    pub csr_pem: String,
    pub host: String,
    /// Empty when the broker has none and the operator chooses them in opCA.
    pub configured_domains: Vec<String>,
    pub versions: Versions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Versions {
    pub api: u32,
    pub broker: String,
}

/// The `POST /v1/enrolment` body, answered with a [`Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolment {
    pub code: String,
    pub chain_pem: String,
    /// Lower-case hex SHA-256 of the SubjectPublicKeyInfo of opCA's operator client key.
    pub operator_pin: String,
    pub config: IssuanceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceConfig {
    pub permitted_domains: Vec<String>,
    pub leaf_days: u32,
    pub leaf_max_days: u32,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Challenge {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// The `GET /v1/status` response, and the answer to every call that changes the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub state: IssuerState,
    /// Decimal, as opCA records it.
    pub subordinate_serial: String,
    /// RFC 3339.
    pub subordinate_not_after: String,
    pub config: IssuanceConfig,
    pub versions: Versions,
    /// `None` from a broker that could not count them, or one older than the count.
    pub issued: Option<IssuedCounts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedCounts {
    pub total: u64,
    pub revoked: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerState {
    Issuing,
    AcmeDown,
    /// The operator paused issuance: new orders and finalising are refused.
    Paused,
    Revoked,
}

/// The `POST /v1/csr` response: a fresh CSR for the same key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshCsr {
    pub csr_pem: String,
    pub configured_domains: Vec<String>,
}

/// The `PUT /v1/chain` body, answered with a [`Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainUpdate {
    pub chain_pem: String,
    pub config: IssuanceConfig,
}

/// The `GET /v1/issued?after=<cursor>` response: the certificates issued or
/// revoked since `cursor`, oldest change first; a missing cursor is 0, the start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedPage {
    pub certificates: Vec<IssuedCertificate>,
    /// The cursor for the next call: the last change here, or the one asked for when there is none.
    pub next: u64,
    /// Whether more changes wait past `next`.
    pub more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedCertificate {
    /// Decimal.
    pub serial: String,
    pub common_name: Option<String>,
    pub sans: Vec<String>,
    /// RFC 3339.
    pub not_before: String,
    /// RFC 3339.
    pub not_after: String,
    /// The serial of the subordinate that issued it, decimal: after a reopen the list spans subordinates.
    pub issuer_serial: String,
    /// RFC 3339.
    pub revoked_at: Option<String>,
    /// An RFC 5280 CRLReason code; `None` is unspecified.
    pub revocation_reason: Option<u8>,
    /// The change that last touched it, its issue or its revocation: a cursor.
    pub changed: u64,
}

/// The body of a `POST /v1/issued/{serial}/revoke`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafRevocation {
    /// One of [`REVOCATION_REASONS`].
    pub reason: u8,
}

/// The body of every refusal the broker itself makes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    #[serde(flatten)]
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ErrorKind {
    BadRequest,
    WrongCode { remaining: u32 },
    CodeSpent,
    Revoked,
    NotFound,
    Internal,
}

impl ErrorKind {
    pub fn http_status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::WrongCode { .. } => 403,
            Self::NotFound => 404,
            Self::Revoked => 409,
            Self::CodeSpent => 410,
            Self::Internal => 500,
        }
    }
}

#[cfg(test)]
mod tests;
