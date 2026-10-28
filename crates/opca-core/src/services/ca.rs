//! Certificate Authority manager — the capstone module.
//!
//! Orchestrates all PKI operations: CA initialisation, certificate signing,
//! revocation, CRL generation, 1Password storage, and remote uploads.

pub mod operator;
pub mod publish;
pub mod subordinate;

use std::collections::HashMap;

use chrono::{DateTime, SubsecRound, Utc};
use foreign_types::ForeignType;
use log::{debug, error, info, warn};
use openssl::asn1::Asn1Time;
use openssl::ec::Asn1Flag;
use openssl::x509::{X509, X509Req};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::constants::{
    CRL_BATCH_PERIOD_DAYS, CRL_BATCH_SIZE, CRL_BATCH_WINDOW_DAYS, DEFAULT_OP_CONF,
    DEFAULT_STORAGE_CONF, OpConf,
};
use crate::error::OpcaError;
use crate::op::{self, Assignment, Error, ItemRef, Runner, Vault};
use crate::services::cert::{
    APPLE_TLS_MAX_DAYS, CertBundleConfig, CertType, CertificateBundle, KeyAlgorithm,
    crypto_provider, signer_of,
};
use crate::services::database::CertificateAuthorityDB;
use crate::services::database::models::{
    CaConfig, CertLookup, CertRecord, CrlBatch, CrlEntry, CrlMetadata, CsrLookup, CsrRecord,
    ExternalCertRecord, IgnoreReason, SerialType,
};
use crate::services::local_backup::{self, BackupSource, LocalBackup};
use crate::services::storage::{self, Visibility};
use crate::utils::datetime::{self, DateTimeFormat};
use wslib_crypto_ca::{
    Authority, CrlView, Csr, KeyIdentifierMethod, Profile, Revocation, SanPolicy, Serial, Validity,
    X509_CRL,
};
use wslib_crypto_x509::AttributeValue;

/// Identifier for the local user, used as the actor on audit-trail fields
/// like `ignored_by`. Formatted as `username@hostname` — readable and doesn't
/// require a 1Password CLI round-trip.
fn local_user() -> String {
    let user = whoami::username();
    let host = whoami::fallible::hostname().unwrap_or_else(|_| "unknown-host".into());
    format!("{user}@{host}")
}

// ---------------------------------------------------------------------------
// CA init command
// ---------------------------------------------------------------------------

/// How the CA should be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaCommand {
    /// Create a new CA from scratch.
    Init,
    /// Import an existing CA from PEM materials.
    Import,
    /// Retrieve an existing CA from 1Password.
    Retrieve,
    /// Rebuild the CA database by scanning vault items.
    RebuildDatabase,
}

// ---------------------------------------------------------------------------
// CA expiry warnings
// ---------------------------------------------------------------------------

/// Graduated warning level for CA certificate expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "level", rename_all = "snake_case")]
pub enum CaExpiryWarning {
    /// CA has plenty of remaining validity.
    None,
    /// CA has fewer days remaining than the default certificate lifetime.
    CertLifetimeExceedsCa {
        days_remaining: i64,
        cert_lifetime_days: i64,
    },
    /// CA expires within 6 months.
    Prominent { days_remaining: i64 },
    /// CA expires within 30 days.
    Critical { days_remaining: i64 },
}

/// Graduated warning level for CRL expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "level", rename_all = "snake_case")]
pub enum CrlExpiryWarning {
    /// CRL has plenty of remaining validity.
    None,
    /// CRL expires within 14 days.
    Prominent { days_remaining: i64 },
    /// CRL expires within 7 days.
    Critical { days_remaining: i64 },
    /// CRL's next_update is already in the past.
    Expired { days_overdue: i64 },
}

/// Assess the CRL's expiry relative to now.
///
/// Tiers are checked most-urgent first: Expired (past next_update), Critical
/// (<7d), Prominent (<14d), then None.
pub fn assess_crl_expiry(next_update: DateTime<Utc>, now: DateTime<Utc>) -> CrlExpiryWarning {
    let days_remaining = (next_update - now).num_days();

    if next_update <= now {
        CrlExpiryWarning::Expired {
            days_overdue: (now - next_update).num_days(),
        }
    } else if days_remaining < 7 {
        CrlExpiryWarning::Critical { days_remaining }
    } else if days_remaining < 14 {
        CrlExpiryWarning::Prominent { days_remaining }
    } else {
        CrlExpiryWarning::None
    }
}

/// Where a CA in batch mode uploads its CRL batch; `None` when batches are off.
fn crl_batch_uri(config: &CaConfig) -> Result<Option<String>, OpcaError> {
    match (config.crl_batch_enabled, config.ca_private_store.as_deref()) {
        (Some(true), Some(store)) => Ok(Some(format!(
            "{}/{}",
            store.trim_end_matches('/'),
            DEFAULT_STORAGE_CONF.crl_batch_file
        ))),
        (Some(true), None) => Err(OpcaError::Storage(
            "CRL batches need a private store: set one or turn CRL batches off".into(),
        )),
        _ => Ok(None),
    }
}

/// Refuse a config update that would leave CRL batches on without a private store.
pub fn check_crl_batch_update(current: &CaConfig, updates: &CaConfig) -> Result<(), OpcaError> {
    crl_batch_uri(&CaConfig {
        crl_batch_enabled: updates.crl_batch_enabled.or(current.crl_batch_enabled),
        ca_private_store: match &updates.ca_private_store {
            Some(store) => Some(store.clone()).filter(|s| !s.trim().is_empty()),
            None => current.ca_private_store.clone(),
        },
        ..CaConfig::default()
    })
    .map(drop)
}

/// A reason a certificate about to be issued may not work everywhere it is used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertIssuanceWarning {
    pub message: String,
}

/// Assess the CA certificate's expiry relative to now.
///
/// Tiers are checked most-urgent first: Critical (<30d), Prominent (<183d),
/// CertLifetimeExceedsCa (<cert_lifetime_days), then None.
pub fn assess_ca_expiry(
    ca_not_after: DateTime<Utc>,
    cert_lifetime_days: i64,
    now: DateTime<Utc>,
) -> CaExpiryWarning {
    let days_remaining = (ca_not_after - now).num_days();

    if days_remaining < 30 {
        CaExpiryWarning::Critical { days_remaining }
    } else if days_remaining < 183 {
        CaExpiryWarning::Prominent { days_remaining }
    } else if days_remaining < cert_lifetime_days {
        CaExpiryWarning::CertLifetimeExceedsCa {
            days_remaining,
            cert_lifetime_days,
        }
    } else {
        CaExpiryWarning::None
    }
}

/// Check whether a certificate with the given lifetime would outlive the CA.
///
/// Returns `Some(warning)` if `now + cert_days > ca_not_after`.
pub fn assess_cert_issuance(
    ca_not_after: DateTime<Utc>,
    cert_days: i64,
    now: DateTime<Utc>,
) -> Option<CertIssuanceWarning> {
    let cert_not_after = now + chrono::Duration::days(cert_days);
    if cert_not_after > ca_not_after {
        let ca_str = datetime::format_datetime(ca_not_after, DateTimeFormat::Text);
        let cert_str = datetime::format_datetime(cert_not_after, DateTimeFormat::Text);
        Some(CertIssuanceWarning {
            message: format!(
                "This certificate will expire on {cert_str} but the CA expires on {ca_str}. \
                 The certificate will become invalid when the CA expires."
            ),
        })
    } else {
        None
    }
}

fn assess_apple_tls_limit(cert_type: &CertType, days: u32) -> Option<CertIssuanceWarning> {
    (cert_type.is_tls_server() && days > APPLE_TLS_MAX_DAYS).then(|| CertIssuanceWarning {
        message: format!(
            "{days} days exceeds the {APPLE_TLS_MAX_DAYS}-day limit macOS and iOS \
             enforce on TLS server certificates; Apple devices will reject it."
        ),
    })
}

// ---------------------------------------------------------------------------
// CertificateAuthority
// ---------------------------------------------------------------------------

/// Certificate Authority manager for PKI operations.
pub struct CertificateAuthority<R: Runner> {
    pub vault: Vault<R>,
    pub op_config: OpConf,
    pub ca_bundle: Option<CertificateBundle>,
    pub ca_database: Option<CertificateAuthorityDB>,
    pub crl: Option<String>,
    /// Written on every database save when set; see [`LocalBackup`].
    pub local_backup: Option<LocalBackup>,
}

/// A renewed certificate. `republished` is set when the renewed one was published:
/// the URI written, or why the upload failed. The renewal is stored either way.
#[derive(Debug)]
pub struct Renewal {
    pub pem: String,
    pub serial: String,
    pub warnings: Vec<CertIssuanceWarning>,
    pub republished: Option<Result<String, OpcaError>>,
}

/// A self-contained snapshot for uploading the CA database to the private
/// store off the connection lock (see [`CertificateAuthority::private_store_upload_job`]).
#[derive(Debug, Clone)]
pub struct PrivateStoreJob {
    pub bytes: Vec<u8>,
    pub uri: String,
    pub account: Option<String>,
    /// AWS region from the CA config, for `s3://` private stores.
    pub region: Option<String>,
    /// SHA-256 of `bytes`, so callers can skip an upload when unchanged.
    pub fingerprint: String,
}

impl<R: Runner> CertificateAuthority<R> {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Initialise a brand-new CA — generates key, self-signs, stores in 1Password.
    pub fn init(vault: Vault<R>, config: &CaConfig) -> Result<Self, OpcaError> {
        info!("[ca] initialising new Certificate Authority");
        let op_config = DEFAULT_OP_CONF;

        if vault.item_exists(&ItemRef::title(op_config.ca_title))? {
            return Err(OpcaError::CaAlreadyExists);
        }

        let mut db = CertificateAuthorityDB::new(config)?;

        let bundle_config = ca_config_to_bundle(config);
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, op_config.ca_title, bundle_config)?;
        bundle.self_sign_ca()?;

        db.increment_serial(SerialType::Cert, None)?;

        let mut ca = Self {
            vault,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        };

        ca.store_certbundle_internal(false, None, None, true)?;

        Ok(ca)
    }

    /// Import an existing CA from PEM-encoded certificate (and optionally key).
    pub fn import_ca(
        vault: Vault<R>,
        cert_pem: &[u8],
        key_pem: Option<&[u8]>,
        config: &CaConfig,
    ) -> Result<Self, OpcaError> {
        let op_config = DEFAULT_OP_CONF;

        if vault.item_exists(&ItemRef::title(op_config.ca_title))? {
            return Err(OpcaError::CaAlreadyExists);
        }

        let bundle = CertificateBundle::import(
            CertType::Ca,
            op_config.ca_title,
            cert_pem,
            key_pem,
            None,
            None,
            ca_config_to_bundle(config),
        )?;

        let db = CertificateAuthorityDB::new(config)?;

        let mut ca = Self {
            vault,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        };

        ca.store_certbundle_internal(false, None, None, true)?;

        Ok(ca)
    }

    /// Retrieve an existing CA from 1Password.
    pub fn retrieve(vault: Vault<R>) -> Result<Self, OpcaError> {
        info!("[ca] retrieving CA from 1Password");
        let op_config = DEFAULT_OP_CONF;

        // Download database — also proves the CA exists, so we skip a
        // separate `item_exists` probe (one fewer `op` process spawn).
        let ca_database_sql =
            op::document_text(&vault, op_config.ca_database_title).map_err(|e| match e {
                OpcaError::ItemNotFound(_) => OpcaError::CaNotFound,
                other => other,
            })?;

        let fingerprint = sha256_hex(ca_database_sql.as_bytes());
        let (mut db, _migration) = CertificateAuthorityDB::from_sql_dump(&ca_database_sql)?;
        db.download_fingerprint = Some(fingerprint);

        // Retrieve CA bundle
        let bundle = Self::retrieve_certbundle_static(&vault, &op_config, op_config.ca_title)?
            .ok_or(OpcaError::CaNotFound)?;

        Ok(Self {
            vault,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        })
    }

    /// Replace an unreadable `CA_Database` with a local backup's dump.
    ///
    /// Refuses a backup taken from another vault, or whose CA row does not
    /// match this vault's CA certificate. The unreadable 1Password copy is
    /// saved to `unreadable_copy_to` before being overwritten.
    pub fn restore_from_backup(
        vault: Vault<R>,
        backup_contents: &str,
        unreadable_copy_to: &LocalBackup,
    ) -> Result<Self, OpcaError> {
        let op_config = DEFAULT_OP_CONF;

        if let Some(source) = local_backup::read_source(backup_contents)
            && source
                .vault_id
                .as_ref()
                .is_some_and(|id| *id != vault.info().id)
        {
            return Err(OpcaError::Other(format!(
                "Backup is from vault {:?}, not the connected vault {:?}",
                source.vault,
                vault.info().name
            )));
        }

        let sql = local_backup::strip_header(backup_contents);
        let (mut db, _migration) = CertificateAuthorityDB::from_sql_dump(sql)?;

        let bundle = Self::retrieve_certbundle_static(&vault, &op_config, op_config.ca_title)?
            .ok_or(OpcaError::CaNotFound)?;
        let ca_serial = bundle.get_certificate_attrib("serial")?;
        let ca_row = db.query_cert(&CertLookup::Title(op_config.ca_title.into()), false)?;
        if ca_row.is_none_or(|row| Some(row.serial) != ca_serial) {
            return Err(OpcaError::Other(
                "Backup belongs to a different CA than this vault's CA certificate".into(),
            ));
        }

        if let Ok(current) = op::document_text(&vault, op_config.ca_database_title) {
            unreadable_copy_to.write_unreadable(&BackupSource::of(&vault), &current)?;
        }

        vault.edit_document(
            &ItemRef::title(op_config.ca_database_title),
            op_config.ca_database_filename,
            sql.as_bytes(),
        )?;
        db.download_fingerprint = Some(sha256_hex(sql.as_bytes()));

        Ok(Self {
            vault,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        })
    }

    /// Rebuild the CA database by scanning all vault items.
    pub fn rebuild_database(vault: Vault<R>, config: &CaConfig) -> Result<Self, OpcaError> {
        let op_config = DEFAULT_OP_CONF;

        if !vault.item_exists(&ItemRef::title(op_config.ca_title))? {
            return Err(OpcaError::CaNotFound);
        }
        if vault.item_exists(&ItemRef::title(op_config.ca_database_title))? {
            return Err(OpcaError::CaAlreadyExists);
        }

        let db = CertificateAuthorityDB::new(config)?;
        let bundle = Self::retrieve_certbundle_static(&vault, &op_config, op_config.ca_title)?
            .ok_or(OpcaError::CaNotFound)?;

        // Update config from bundle
        let bundle_conf = CaConfig {
            org: bundle.config.org.clone(),
            ou: bundle.config.ou.clone(),
            email: bundle.config.email.clone(),
            city: bundle.config.city.clone(),
            state: bundle.config.state.clone(),
            country: bundle.config.country.clone(),
            ..CaConfig::default()
        };
        db.update_config(&bundle_conf)?;

        let mut ca = Self {
            vault,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        };

        ca.do_rebuild_database()?;

        Ok(ca)
    }

    // -----------------------------------------------------------------------
    // Certificate signing
    // -----------------------------------------------------------------------

    /// Sign a CSR with the CA's private key, adding extensions per `cert_type`.
    fn sign_certificate(
        &mut self,
        csr: &X509Req,
        cert_type: &CertType,
        days: u32,
    ) -> Result<X509, OpcaError> {
        debug!("[ca] signing {cert_type} certificate");
        if *cert_type == CertType::SubordinateCa {
            return Err(OpcaError::Other(
                "A subordinate CA is signed with its permitted domains, not as a certificate type"
                    .into(),
            ));
        }
        if *cert_type == CertType::AppleDev {
            return Err(OpcaError::Other(
                "Apple issues Apple Development certificates: upload the CSR to the Apple Developer portal"
                    .into(),
            ));
        }
        let csr = verified_csr(csr)?;
        let ca_config = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?
            .get_config()?;
        let profile = profile_for(cert_type, csr.has_rsa_key(), &ca_config);
        self.issue(&csr, &profile, days)
    }

    fn issue(&mut self, csr: &Csr, profile: &Profile, days: u32) -> Result<X509, OpcaError> {
        let db = self
            .ca_database
            .as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let ca_bundle = self
            .ca_bundle
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let ca_key = ca_bundle
            .private_key
            .as_ref()
            .ok_or_else(|| OpcaError::Crypto("CA private key not available".into()))?;
        let ca_cert = ca_bundle
            .certificate
            .as_ref()
            .ok_or_else(|| OpcaError::CaNotFound)?;

        let serial = Serial::try_from(db.increment_serial(SerialType::Cert, None)?)?;
        let now = Utc::now();
        let validity = Validity {
            not_before: now.into(),
            not_after: (now + chrono::Duration::days(days.into())).into(),
        };
        let cert = authority_of(ca_cert, ca_key)?.issue(csr, profile, &serial, validity)?;
        Ok(X509::from_der(&cert)?)
    }

    // -----------------------------------------------------------------------
    // Certificate generation / renewal
    // -----------------------------------------------------------------------

    /// Generate a new certificate bundle — key + CSR + CA-signed cert.
    ///
    /// Returns the bundle and an optional warning if the certificate would
    /// outlive the CA.
    pub fn generate_certificate_bundle(
        &mut self,
        cert_type: CertType,
        item_title: &str,
        config: CertBundleConfig,
        days: Option<u32>,
    ) -> Result<(CertificateBundle, Vec<CertIssuanceWarning>), OpcaError> {
        info!("[ca] generating {cert_type} certificate '{item_title}'");
        let mut bundle = CertificateBundle::generate(cert_type.clone(), item_title, config)?;

        let csr_pem = bundle
            .csr_pem()
            .ok_or_else(|| OpcaError::InvalidCertificate("CSR not generated".into()))?;
        let csr = X509Req::from_pem(csr_pem.as_bytes())
            .map_err(|e| OpcaError::Crypto(format!("Parse CSR: {e}")))?;

        let (signed_cert, warnings) = self.issue_certificate(&csr, &cert_type, days)?;
        bundle.update_certificate(signed_cert)?;

        // Update title to CRT_{serial}_{cn}
        let serial = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        bundle.title = format!("CRT_{serial}_{item_title}");

        // Store in 1Password
        self.ca_bundle_for_store(Some(&bundle))?;
        self.store_certbundle_for(&bundle, None, None, true)?;

        Ok((bundle, warnings))
    }

    /// Check whether a certificate was signed by this CA and is within its validity period.
    pub fn is_cert_valid(&self, cert: &X509) -> Result<bool, OpcaError> {
        let ca_bundle = self.ca_bundle.as_ref().ok_or(OpcaError::CaNotFound)?;
        let ca_cert = ca_bundle
            .certificate
            .as_ref()
            .ok_or(OpcaError::CaNotFound)?;

        let ca_pubkey = ca_cert
            .public_key()
            .map_err(|e| OpcaError::Crypto(format!("Get CA public key: {e}")))?;

        // Verify signature
        match cert.verify(&ca_pubkey) {
            Ok(true) => {}
            _ => return Ok(false),
        }

        // Check time validity
        let now =
            Asn1Time::days_from_now(0).map_err(|e| OpcaError::Crypto(format!("Asn1Time: {e}")))?;
        if cert.not_before() > &now || cert.not_after() < &now {
            return Ok(false);
        }

        Ok(true)
    }

    /// Import an existing certificate bundle (cert + optional key + optional chain).
    ///
    /// Auto-detects whether the certificate was signed by this CA (local import)
    /// or by an external issuer. For local imports, the CA serial counter is
    /// advanced if needed.
    pub fn import_certificate_bundle(
        &mut self,
        cert_pem: &[u8],
        key_pem: Option<&[u8]>,
        chain_pem: Option<&[u8]>,
        passphrase: Option<&[u8]>,
        item_title: Option<&str>,
    ) -> Result<CertificateBundle, OpcaError> {
        // Parse the certificate to detect local vs external
        let cert = X509::from_pem(cert_pem).map_err(|e| {
            OpcaError::InvalidCertificate(format!("Failed to parse certificate PEM: {e}"))
        })?;
        let is_local = self.is_cert_valid(&cert)?;

        let cert_type = if is_local {
            CertType::Imported
        } else {
            CertType::External
        };

        let title = item_title.unwrap_or("");

        let mut bundle = CertificateBundle::import(
            cert_type,
            title,
            cert_pem,
            key_pem,
            None, // no CSR for imports
            passphrase,
            CertBundleConfig::default(),
        )?;

        if let Some(cp) = chain_pem {
            bundle.set_chain_from_pem(cp)?;
        }

        // For local imports, advance the serial counter if needed
        if is_local {
            let cert_serial_str = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
            if let Ok(cert_serial) = cert_serial_str.parse::<i64>() {
                let db = self
                    .ca_database
                    .as_mut()
                    .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
                db.increment_serial(SerialType::Cert, Some(cert_serial))?;
            }
        }

        // Extract issuer info for external certs
        let (issuer, issuer_subject) = if !is_local {
            let issuer_cn = bundle.get_certificate_attrib("issuer")?;
            // Extract just the CN from the issuer string
            let issuer_cn_short = issuer_cn
                .as_deref()
                .and_then(|s| {
                    s.split(',')
                        .find(|part| part.trim().starts_with("CN="))
                        .map(|cn_part| cn_part.trim().trim_start_matches("CN=").to_string())
                })
                .unwrap_or_else(|| "Unknown".to_string());
            let issuer_subject_str = issuer_cn.unwrap_or_else(|| "Unknown".to_string());
            (Some(issuer_cn_short), Some(issuer_subject_str))
        } else {
            (None, None)
        };

        // Store in 1Password
        self.store_certbundle_for(&bundle, issuer.as_deref(), issuer_subject.as_deref(), true)?;

        Ok(bundle)
    }

    /// Auto-ignore the predecessor of a renew/rekey so it immediately drops out
    /// of expiry alerts instead of waiting to expire. The caller flushes the DB
    /// afterwards (`store_ca_database`), so this adds no extra `op` round-trips.
    fn auto_ignore_predecessor(
        &mut self,
        old_serial: &str,
        new_serial: &str,
        reason: IgnoreReason,
    ) -> Result<(), OpcaError> {
        if let Some(db) = self.ca_database.as_mut() {
            db.ignore_cert(
                old_serial,
                reason,
                &local_user(),
                Some(&format!("replaced by {new_serial}")),
            )?;
        }
        Ok(())
    }

    /// Renew a previously signed certificate from its stored CSR, and publish
    /// the renewal if the certificate was published.
    pub fn renew_certificate_bundle(
        &mut self,
        lookup: &CertLookup,
        days: Option<u32>,
    ) -> Result<Renewal, OpcaError> {
        info!("[ca] renewing certificate {lookup:?}");
        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let cert_record = db
            .query_cert(lookup, true)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

        let old_serial = cert_record.serial.clone();
        let item_title = cert_record
            .title
            .clone()
            .ok_or_else(|| OpcaError::CertificateNotFound("No title".into()))?;

        let status = cert_record.status.as_deref().unwrap_or("");
        if status == "Revoked" {
            return Err(OpcaError::Other(
                "Cannot renew a revoked certificate".into(),
            ));
        }

        let mut cert_bundle = self
            .retrieve_certbundle(&item_title)?
            .ok_or_else(|| OpcaError::CertificateNotFound(item_title.clone()))?;

        let csr_pem = cert_bundle.csr_pem().ok_or_else(|| {
            OpcaError::Other(format!(
                "CSR not found for certificate '{item_title}'; cannot renew."
            ))
        })?;

        let csr = X509Req::from_pem(csr_pem.as_bytes())
            .map_err(|e| OpcaError::Crypto(format!("Parse CSR: {e}")))?;

        let cert_type = cert_bundle.cert_type.clone();
        let (signed_cert, warnings) = self.issue_certificate(&csr, &cert_type, days)?;
        cert_bundle.update_certificate(signed_cert)?;

        // Update title with new serial
        let new_serial = cert_bundle
            .get_certificate_attrib("serial")?
            .unwrap_or_default();
        let cn = cert_bundle
            .get_certificate_attrib("cn")?
            .unwrap_or_default();
        cert_bundle.title = format!("CRT_{new_serial}_{cn}");

        // Persist the new bundle, then auto-ignore the predecessor so it stops
        // triggering expiry alerts (Lambda + dashboard) the moment it's been
        // replaced, rather than waiting for it to expire and be superseded.
        self.store_certbundle_for(&cert_bundle, None, None, false)?;
        self.auto_ignore_predecessor(&old_serial, &new_serial, IgnoreReason::Renewed)?;
        let pem = cert_bundle.certificate_pem()?;
        let republished = cert_record
            .published_at
            .is_some()
            .then(|| self.upload_published(&new_serial, &cn, &pem));
        if let Some(Err(e)) = &republished {
            warn!("[ca] renewal {new_serial} was not published: {e}");
        }
        self.store_ca_database()?;

        Ok(Renewal {
            pem,
            serial: new_serial,
            warnings,
            republished,
        })
    }

    /// Rekey a previously signed certificate — generate a new private key and
    /// CSR, then sign it to produce a fresh certificate.
    ///
    /// Returns the rekeyed certificate PEM, the new serial, and an optional
    /// warning if the certificate would outlive the CA.
    pub fn rekey_certificate_bundle(
        &mut self,
        lookup: &CertLookup,
        key_algorithm: Option<KeyAlgorithm>,
        days: Option<u32>,
    ) -> Result<(String, String, Vec<CertIssuanceWarning>), OpcaError> {
        info!("[ca] rekeying certificate {lookup:?}");
        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let cert_record = db
            .query_cert(lookup, false)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

        let old_serial = cert_record.serial.clone();
        let item_title = cert_record
            .title
            .clone()
            .ok_or_else(|| OpcaError::CertificateNotFound("No title".into()))?;

        let mut cert_bundle = self
            .retrieve_certbundle(&item_title)?
            .ok_or_else(|| OpcaError::CertificateNotFound(item_title.clone()))?;

        // Generate a new private key and CSR, preserving subject attributes
        cert_bundle.regenerate_key_and_csr(key_algorithm)?;

        let csr_pem = cert_bundle
            .csr_pem()
            .ok_or_else(|| OpcaError::Other("CSR not available after rekeying".into()))?;

        let csr = X509Req::from_pem(csr_pem.as_bytes())
            .map_err(|e| OpcaError::Crypto(format!("Parse CSR: {e}")))?;

        let cert_type = cert_bundle.cert_type.clone();
        let (signed_cert, warnings) = self.issue_certificate(&csr, &cert_type, days)?;
        cert_bundle.update_certificate(signed_cert)?;

        // Update title with new serial
        let new_serial = cert_bundle
            .get_certificate_attrib("serial")?
            .unwrap_or_default();
        let cn = cert_bundle
            .get_certificate_attrib("cn")?
            .unwrap_or_default();
        cert_bundle.title = format!("CRT_{new_serial}_{cn}");

        // Persist the updated bundle (new key, CSR, and cert), then auto-ignore
        // the predecessor so it stops triggering expiry alerts (Lambda +
        // dashboard) immediately.
        self.store_certbundle_for(&cert_bundle, None, None, false)?;
        self.auto_ignore_predecessor(&old_serial, &new_serial, IgnoreReason::Rekeyed)?;
        self.store_ca_database()?;

        let pem = cert_bundle.certificate_pem()?;
        Ok((pem, new_serial, warnings))
    }

    // -----------------------------------------------------------------------
    // Revocation + CRL
    // -----------------------------------------------------------------------

    /// Revoke a valid certificate and update the CA database.
    pub fn revoke_certificate(&mut self, lookup: &CertLookup) -> Result<bool, OpcaError> {
        info!("[ca] revoking certificate {lookup:?}");
        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let cert = db
            .query_cert(lookup, true)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

        let item_serial = cert.serial.clone();

        let db = self.ca_database.as_mut().unwrap();
        db.process_ca_database(Some(&item_serial), false)?;
        db.revoke_brokers_of(&item_serial)?;

        self.store_ca_database()?;

        Ok(true)
    }

    /// Manually mark a certificate as ignored — it drops out of the expired
    /// count on the dashboard. Reason is recorded as `manual`; the caller is
    /// identified from the 1Password session. Persists to 1Password.
    pub fn ignore_certificate(
        &mut self,
        serial: &str,
        note: Option<&str>,
    ) -> Result<(), OpcaError> {
        info!("[ca] ignoring certificate {serial}");
        let by = local_user();

        let db = self
            .ca_database
            .as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        db.ignore_cert(serial, IgnoreReason::Manual, &by, note)?;

        self.store_ca_database()?;
        Ok(())
    }

    /// Clear the ignored state on a certificate (undo). Persists to 1Password.
    pub fn unignore_certificate(&mut self, serial: &str) -> Result<(), OpcaError> {
        info!("[ca] un-ignoring certificate {serial}");
        let db = self
            .ca_database
            .as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        db.unignore_cert(serial)?;

        self.store_ca_database()?;
        Ok(())
    }

    /// Sign the CRL (in batch mode, a batch) and store the first as the `CRL` item.
    /// A batch is uploaded before returning, or the old batch would hide a revocation.
    pub fn generate_crl(&mut self) -> Result<String, OpcaError> {
        info!("[ca] generating CRL");
        let db = self
            .ca_database
            .as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        db.process_ca_database(None, false)?;

        let ca_config = db.get_config()?;
        let batch_uri = crl_batch_uri(&ca_config)?;

        let ca_bundle = self
            .ca_bundle
            .as_ref()
            .ok_or_else(|| OpcaError::CaNotFound)?;
        let ca_cert = ca_bundle
            .certificate
            .as_ref()
            .ok_or_else(|| OpcaError::CaNotFound)?;
        let ca_key = ca_bundle
            .private_key
            .as_ref()
            .ok_or_else(|| OpcaError::Crypto("CA private key not available".into()))?;

        let entries = db.crl_entries()?;
        let (window_days, count) = match batch_uri {
            Some(_) => (CRL_BATCH_WINDOW_DAYS, CRL_BATCH_SIZE),
            None => (ca_config.crl_days.unwrap_or(30), 1),
        };
        let first_number = db.increment_serial(SerialType::Crl, None)?;
        let batch = CrlBatch {
            t0: Utc::now().trunc_subsecs(0),
            period_days: CRL_BATCH_PERIOD_DAYS,
            window_days,
            count,
            first_number,
        };
        let crls = (0..batch.count)
            .map(|i| {
                build_crl(
                    ca_cert,
                    ca_key,
                    first_number + i,
                    batch.this_update(i),
                    batch.next_update(i),
                    &entries,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        if batch_uri.is_some() {
            db.update_config(&CaConfig {
                next_crl_serial: Some(first_number + batch.count),
                ..CaConfig::default()
            })?;
            db.upsert_crl_batch(&batch)?;
        } else {
            db.clear_crl_batch()?;
        }
        db.upsert_crl_metadata(&parse_crl_metadata(&crls[0])?)?;

        op::put_document(
            &self.vault,
            self.op_config.crl_title,
            self.op_config.crl_filename,
            &crls[0],
        )?;
        self.crl = Some(crls[0].clone());
        self.store_ca_database()?;

        if let Some(uri) = batch_uri {
            self.upload_content(crls.concat().as_bytes(), &uri, Visibility::Private)
                .map_err(|e| OpcaError::CrlBatchUpload(e.to_string()))?;
        }

        Ok(crls[0].clone())
    }

    // -----------------------------------------------------------------------
    // Read methods
    // -----------------------------------------------------------------------

    /// Return the CA certificate in PEM format.
    pub fn get_certificate(&self) -> Result<String, OpcaError> {
        self.ca_bundle
            .as_ref()
            .ok_or(OpcaError::CaNotFound)?
            .certificate_pem()
    }

    /// Return the CA private key in PEM format.
    pub fn get_private_key(&self) -> Result<String, OpcaError> {
        self.ca_bundle
            .as_ref()
            .ok_or(OpcaError::CaNotFound)?
            .private_key_pem()
    }

    /// Return the CRL in PEM format from 1Password.
    pub fn get_crl(&mut self) -> Result<Option<String>, OpcaError> {
        if self.crl.is_none() {
            match op::document_text(&self.vault, self.op_config.crl_title) {
                Ok(content) => self.crl = Some(content),
                Err(_) => return Ok(None),
            }
        }
        Ok(self.crl.clone())
    }

    /// Check if the CA is valid.
    pub fn is_valid(&self) -> Result<bool, OpcaError> {
        self.ca_bundle
            .as_ref()
            .ok_or(OpcaError::CaNotFound)?
            .is_valid()
    }

    /// Assess the CA certificate's expiry and return a graduated warning.
    pub fn check_ca_expiry(&self) -> CaExpiryWarning {
        let bundle = match self.ca_bundle.as_ref() {
            Some(b) => b,
            None => return CaExpiryWarning::None,
        };

        let not_after_str = match bundle.get_certificate_attrib("not_after") {
            Ok(Some(s)) => s,
            _ => return CaExpiryWarning::None,
        };

        let ca_not_after = match datetime::parse_datetime(&not_after_str, DateTimeFormat::Openssl) {
            Ok(dt) => dt,
            Err(_) => return CaExpiryWarning::None,
        };

        let cert_lifetime_days = self
            .ca_database
            .as_ref()
            .and_then(|db| db.get_config().ok())
            .and_then(|c| c.days)
            .unwrap_or(365);

        assess_ca_expiry(ca_not_after, cert_lifetime_days, Utc::now())
    }

    /// Get the CA certificate's `not_after` as a parsed UTC datetime.
    fn ca_not_after(&self) -> Result<DateTime<Utc>, OpcaError> {
        let bundle = self.ca_bundle.as_ref().ok_or(OpcaError::CaNotFound)?;
        let not_after_str = bundle
            .get_certificate_attrib("not_after")?
            .ok_or_else(|| OpcaError::InvalidCertificate("CA has no not_after".into()))?;
        datetime::parse_datetime(&not_after_str, DateTimeFormat::Openssl)
    }

    /// Sign `csr` for the requested lifetime, else the CA's `days` capped per
    /// [`CertType::default_days`], with any warnings about where it won't be trusted.
    pub fn issue_certificate(
        &mut self,
        csr: &X509Req,
        cert_type: &CertType,
        days: Option<u32>,
    ) -> Result<(X509, Vec<CertIssuanceWarning>), OpcaError> {
        let days = self.cert_days(cert_type, days)?;
        let cert = self.sign_certificate(csr, cert_type, days)?;
        Ok((cert, self.issuance_warnings(cert_type, days)))
    }

    fn cert_days(&self, cert_type: &CertType, requested: Option<u32>) -> Result<u32, OpcaError> {
        match requested {
            Some(0) => Err(OpcaError::Other(
                "Certificate lifetime must be at least 1 day".into(),
            )),
            Some(days) => Ok(days),
            None => {
                let db = self
                    .ca_database
                    .as_ref()
                    .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
                let ca_days = db.get_config()?.days.unwrap_or(365) as u32;
                Ok(cert_type.default_days(ca_days))
            }
        }
    }

    fn issuance_warnings(&self, cert_type: &CertType, days: u32) -> Vec<CertIssuanceWarning> {
        let outlives_ca = self
            .ca_not_after()
            .ok()
            .and_then(|ca_not_after| assess_cert_issuance(ca_not_after, days.into(), Utc::now()));
        outlives_ca
            .into_iter()
            .chain(assess_apple_tls_limit(cert_type, days))
            .collect()
    }

    // -----------------------------------------------------------------------
    // CA re-sign
    // -----------------------------------------------------------------------

    /// Re-sign the CA certificate with the same key but new validity dates.
    ///
    /// Keeps the same subject, serial, and key pair. Updates the certificate
    /// in 1Password and the CA database.
    pub fn re_sign_ca(&mut self, ca_days: i64) -> Result<(), OpcaError> {
        info!("[ca] re-signing CA certificate for {ca_days} days");
        let bundle = self.ca_bundle.as_mut().ok_or(OpcaError::CaNotFound)?;
        bundle.re_sign_ca(ca_days)?;

        // Extract updated attributes
        let cert_pem = bundle.certificate_pem()?;
        let not_before = bundle
            .get_certificate_attrib("not_before")?
            .unwrap_or_default();
        let not_after = bundle
            .get_certificate_attrib("not_after")?
            .unwrap_or_default();

        let not_before_text = openssl_to_text(&not_before);
        let not_after_text = openssl_to_text(&not_after);

        // Update the CA item in 1Password
        let fields = [
            op::assign(self.op_config.cert_item, cert_pem)?,
            op::assign(self.op_config.start_date_item, not_before_text)?,
            op::assign(self.op_config.expiry_date_item, not_after_text)?,
        ];
        self.vault
            .edit_item(&ItemRef::title(self.op_config.ca_title), &fields)?;

        self.store_ca_database()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Storage — certbundle
    // -----------------------------------------------------------------------

    /// Store a certificate bundle in 1Password and add to the database.
    pub fn store_certbundle_for(
        &mut self,
        bundle: &CertificateBundle,
        issuer: Option<&str>,
        issuer_subject: Option<&str>,
        persist: bool,
    ) -> Result<(), OpcaError> {
        let item_title = &bundle.title;
        let is_external = issuer.is_some();

        let op_title = if is_external {
            format!("EXT_{item_title}")
        } else {
            item_title.clone()
        };

        // Build attributes
        let cert_pem = bundle.certificate_pem()?;
        let cn = bundle.get_certificate_attrib("cn")?.unwrap_or_default();
        let subject = bundle
            .get_certificate_attrib("subject")?
            .unwrap_or_default();
        let not_before = bundle
            .get_certificate_attrib("not_before")?
            .unwrap_or_default();
        let not_after = bundle
            .get_certificate_attrib("not_after")?
            .unwrap_or_default();
        let serial = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        let csr_pem = bundle.csr_pem().unwrap_or_default();

        // 1Password expects human-readable Text format (e.g. "Jan 20 00:00:00 2026 UTC"),
        // but get_certificate_attrib returns Openssl format ("20260120000000Z").
        let not_before_text = openssl_to_text(&not_before);
        let not_after_text = openssl_to_text(&not_after);

        let c = &self.op_config;
        let mut fields = vec![
            op::assign(c.cert_type_item, &bundle.cert_type)?,
            op::assign(c.cn_item, cn)?,
            op::assign(c.subject_item, subject)?,
            op::assign(c.cert_item, cert_pem)?,
            op::assign(c.start_date_item, not_before_text)?,
            op::assign(c.expiry_date_item, not_after_text)?,
            op::assign(c.serial_item, serial)?,
            op::assign(c.csr_item, csr_pem)?,
        ];

        if bundle.private_key.is_some() {
            fields.push(op::assign(c.key_item, bundle.private_key_pem()?)?);
        }

        if let Some(chain_pem) = bundle.chain_pem() {
            fields.push(op::assign(c.chain_item, chain_pem)?);
        }

        self.vault.create_item(&op_title, c.category, &fields)?;

        // Add to database
        let db_item = format_db_item(bundle, item_title, issuer, issuer_subject)?;

        let db = self
            .ca_database
            .as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        if is_external {
            db.add_external_cert(&db_item.into_external(issuer, issuer_subject))?;
        } else {
            db.add_cert(&db_item)?;
        }

        if persist {
            self.store_ca_database()?;
        }

        Ok(())
    }

    /// Internal: store the CA's own certbundle (used during init/import).
    fn store_certbundle_internal(
        &mut self,
        is_external: bool,
        issuer: Option<&str>,
        issuer_subject: Option<&str>,
        persist: bool,
    ) -> Result<(), OpcaError> {
        // Clone the bundle data we need — we can't borrow self mutably twice
        let bundle = self
            .ca_bundle
            .as_ref()
            .ok_or_else(|| OpcaError::Other("No CA bundle".into()))?;

        let item_title = bundle.title.clone();
        let cert_type_str = bundle.cert_type.to_string();
        let cert_pem = bundle.certificate_pem()?;
        let cn = bundle.get_certificate_attrib("cn")?.unwrap_or_default();
        let subject = bundle
            .get_certificate_attrib("subject")?
            .unwrap_or_default();
        let not_before = bundle
            .get_certificate_attrib("not_before")?
            .unwrap_or_default();
        let not_after = bundle
            .get_certificate_attrib("not_after")?
            .unwrap_or_default();
        let serial = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        let csr_pem_str = bundle.csr_pem().unwrap_or_default();
        let has_key = bundle.private_key.is_some();
        let key_pem = if has_key {
            Some(bundle.private_key_pem()?)
        } else {
            None
        };
        let chain_pem = bundle.chain_pem();

        let db_item = format_db_item(bundle, &item_title, issuer, issuer_subject)?;

        let op_title = if is_external {
            format!("EXT_{item_title}")
        } else {
            item_title.clone()
        };

        // 1Password expects human-readable Text format (e.g. "Jan 20 00:00:00 2026 UTC")
        let not_before_text = openssl_to_text(&not_before);
        let not_after_text = openssl_to_text(&not_after);

        let c = &self.op_config;
        let mut fields = vec![
            op::assign(c.cert_type_item, cert_type_str)?,
            op::assign(c.cn_item, cn)?,
            op::assign(c.subject_item, subject)?,
            op::assign(c.cert_item, cert_pem)?,
            op::assign(c.start_date_item, not_before_text)?,
            op::assign(c.expiry_date_item, not_after_text)?,
            op::assign(c.serial_item, serial)?,
            op::assign(c.csr_item, csr_pem_str)?,
        ];

        if let Some(kp) = key_pem {
            fields.push(op::assign(c.key_item, kp)?);
        }

        if let Some(cp) = chain_pem {
            fields.push(op::assign(c.chain_item, cp)?);
        }

        self.vault.create_item(&op_title, c.category, &fields)?;

        let db = self
            .ca_database
            .as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        if is_external {
            db.add_external_cert(&db_item.into_external(issuer, issuer_subject))?;
        } else {
            db.add_cert(&db_item)?;
        }

        if persist {
            self.store_ca_database()?;
        }

        Ok(())
    }

    fn ca_bundle_for_store(&self, _bundle: Option<&CertificateBundle>) -> Result<(), OpcaError> {
        // Placeholder for any pre-store validation
        Ok(())
    }

    /// Retrieve a certificate bundle from 1Password.
    pub fn retrieve_certbundle(
        &self,
        item_title: &str,
    ) -> Result<Option<CertificateBundle>, OpcaError> {
        Self::retrieve_certbundle_static(&self.vault, &self.op_config, item_title)
    }

    /// Static version for use during construction.
    fn retrieve_certbundle_static(
        vault: &Vault<R>,
        _op_config: &OpConf,
        item_title: &str,
    ) -> Result<Option<CertificateBundle>, OpcaError> {
        let Ok(item) = vault.item(&ItemRef::title(item_title)) else {
            return Ok(None);
        };
        let text = |label: &str| op::field_text(&item, label);

        let Some(cert_data) = text("certificate") else {
            return Ok(None);
        };

        let ct = text("type")
            .and_then(|s| s.parse::<CertType>().ok())
            .unwrap_or(CertType::Device);

        let mut bundle = CertificateBundle::import(
            ct,
            item_title,
            cert_data.as_bytes(),
            text("private_key").map(str::as_bytes),
            text("certificate_signing_request").map(str::as_bytes),
            None,
            CertBundleConfig::default(),
        )?;

        if let Some(cp) = text("certificate_chain") {
            bundle.set_chain_from_pem(cp.as_bytes())?;
        }

        Ok(Some(bundle))
    }

    /// Rename a certificate bundle in 1Password and update the database.
    pub fn rename_certbundle(
        &mut self,
        src_title: &str,
        dst_title: &str,
        persist: bool,
    ) -> Result<(), OpcaError> {
        let db = self
            .ca_database
            .as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let mut record = db
            .query_cert(&CertLookup::Title(src_title.to_string()), false)?
            .ok_or_else(|| OpcaError::CertificateNotFound(src_title.to_string()))?;

        self.vault
            .rename_item(&ItemRef::title(src_title), dst_title)?;

        record.title = Some(dst_title.to_string());
        db.update_cert(&record)?;

        if persist {
            self.store_ca_database()?;
        }

        Ok(())
    }

    /// Delete a revoked or expired certificate: archive its item and hide its
    /// row. A valid one must be revoked first, so delete cannot bypass the CRL.
    pub fn delete_certificate(&mut self, serial: &str) -> Result<CertRecord, OpcaError> {
        info!("[ca] deleting certificate {serial}");
        let db = self.ca_database.as_mut().ok_or(OpcaError::CaNotFound)?;
        db.process_ca_database(None, true)?;
        let cert = db
            .query_cert(&CertLookup::Serial(serial.to_string()), false)?
            .filter(|c| c.deleted_at.is_none())
            .ok_or_else(|| OpcaError::CertificateNotFound(serial.to_string()))?;
        if cert.cert_type.as_deref() == Some("ca") {
            return Err(OpcaError::Other(
                "The CA certificate cannot be deleted".into(),
            ));
        }
        if !matches!(cert.status.as_deref(), Some("Revoked" | "Expired")) {
            return Err(OpcaError::Other(format!(
                "Certificate {serial} is still valid; revoke it before deleting"
            )));
        }

        if let Some(title) = cert.title.as_deref() {
            match self.vault.delete_item(&ItemRef::title(title)) {
                Ok(()) | Err(Error::ItemNotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        if cert.ignored_at.is_none() {
            db.ignore_cert(serial, IgnoreReason::Deleted, &local_user(), None)?;
        }
        db.mark_cert_deleted(serial)?;
        self.store_ca_database()?;
        Ok(cert)
    }

    // -----------------------------------------------------------------------
    // Storage — database
    // -----------------------------------------------------------------------

    /// Remove a CSR row. A pending CSR's item (which holds its private key) is
    /// archived; a completed one's was archived when its certificate was imported.
    pub fn delete_csr(&mut self, id: i64) -> Result<CsrRecord, OpcaError> {
        let db = self.ca_database.as_ref().ok_or(OpcaError::CaNotFound)?;
        let record = db
            .query_csr(&CsrLookup::Id(id))?
            .ok_or_else(|| OpcaError::CsrNotFound(id.to_string()))?;
        let title = record
            .title
            .clone()
            .unwrap_or_else(|| format!("CSR_{}", record.cn.as_deref().unwrap_or_default()));
        if record.status.as_deref() == Some("Pending") {
            match self.vault.delete_item(&ItemRef::title(&title)) {
                Ok(()) | Err(Error::ItemNotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        db.delete_csr(id)?;
        self.store_ca_database()?;
        Ok(record)
    }

    /// Store the CA database in 1Password.
    pub fn store_ca_database(&mut self) -> Result<(), OpcaError> {
        self.update_db_fingerprint()?;

        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let sql_bytes = db.export_database()?;
        let sql_text = String::from_utf8_lossy(&sql_bytes).to_string();

        // Before the 1Password write, so a failed or damaged store still
        // leaves a good local copy.
        if let Some(backup) = &self.local_backup
            && let Err(e) = backup.write(&BackupSource::of(&self.vault), &sql_text)
        {
            warn!("[ca] local database backup failed: {e}");
        }

        op::put_document(
            &self.vault,
            self.op_config.ca_database_title,
            self.op_config.ca_database_filename,
            &sql_text,
        )?;

        // NB: the private-store (e.g. S3) copy is intentionally NOT uploaded
        // here. That upload is slow (AWS creds fetch + PUT) and would hold the
        // caller's connection lock; instead the Tauri layer drains
        // `private_store_upload_job()` into a background task after the
        // operation returns. See `sync_private_store`.
        Ok(())
    }

    /// Snapshot everything needed to upload the CA database to the private
    /// store, or `None` when no private store is configured. Returned by value
    /// so the caller can perform the (slow) upload off the connection lock; the
    /// `fingerprint` lets the caller skip an upload when nothing has changed.
    pub fn private_store_upload_job(&self) -> Result<Option<PrivateStoreJob>, OpcaError> {
        let Some(uri) = self.private_store_uri()? else {
            return Ok(None);
        };
        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let bytes = db.export_database_binary()?;
        let fingerprint = sha256_hex(&bytes);
        Ok(Some(PrivateStoreJob {
            bytes,
            uri,
            account: self.vault.op().account().map(String::from),
            region: self.aws_region()?,
            fingerprint,
        }))
    }

    /// The configured private-store URI for this CA's database, or `None` when
    /// no private store is set.
    fn private_store_uri(&self) -> Result<Option<String>, OpcaError> {
        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        Ok(db.get_config()?.ca_private_store.map(|store| {
            let vault_name = self.vault.info().name.trim().to_lowercase();
            format!("{}/{vault_name}.sqlite", store.trim_end_matches('/'))
        }))
    }

    /// Update the stored fingerprint to reflect what we are about to upload.
    ///
    /// Concurrent-modification detection is handled by the vault-level lock
    /// (`VaultLock`), so we no longer re-download the full database just to
    /// compare hashes — that extra `op` process spawn was the single biggest
    /// contributor to latency on macOS production builds.
    fn update_db_fingerprint(&mut self) -> Result<(), OpcaError> {
        if let Some(ref mut db) = self.ca_database {
            let export = db.export_database()?;
            db.download_fingerprint = Some(sha256_hex(&export));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Rebuild database
    // -----------------------------------------------------------------------

    fn do_rebuild_database(&mut self) -> Result<HashMap<String, usize>, OpcaError> {
        let items = self.vault.items(&[self.op_config.category])?;

        let mut result_map: HashMap<String, (X509, String, CertType)> = HashMap::new();
        let mut max_serial: i64 = 0;

        for item in &items {
            let title = item.title.as_str();

            let bundle = match self.retrieve_certbundle(title)? {
                Some(b) => b,
                None => continue,
            };

            let serial_str = bundle.get_certificate_attrib("serial")?.unwrap_or_default();

            if result_map.contains_key(&serial_str) {
                return Err(OpcaError::DuplicateCertificate(format!(
                    "Duplicate serial {serial_str}"
                )));
            }

            let cert = bundle.certificate.clone().unwrap();
            let cert_type = bundle.cert_type.clone();
            result_map.insert(serial_str.clone(), (cert, title.to_string(), cert_type));

            if let Ok(s) = serial_str.parse::<i64>()
                && s > max_serial
            {
                max_serial = s;
            }
        }

        {
            let db = self.ca_database.as_mut().unwrap();

            let mut sorted_keys: Vec<&String> = result_map.keys().collect();
            sorted_keys.sort();

            for serial_str in sorted_keys {
                let (cert, title, cert_type) = &result_map[serial_str];
                let bundle_tmp = CertificateBundle::import(
                    cert_type.clone(),
                    title,
                    &cert
                        .to_pem()
                        .map_err(|e| OpcaError::Crypto(format!("{e}")))?,
                    None,
                    None,
                    None,
                    CertBundleConfig::default(),
                )?;
                let record = format_db_item(&bundle_tmp, title, None, None)?;
                db.add_cert(&record)?;
            }

            let config = db.get_config()?;
            let next_serial = config.next_serial.unwrap_or(0);
            if max_serial < next_serial {
                // Keep existing next_serial if it's higher
            } else {
                let new_serial = max_serial + 1;
                db.update_config(&CaConfig {
                    next_serial: Some(new_serial),
                    ..CaConfig::default()
                })?;
            }
        }

        self.store_ca_database()?;

        let count = self.ca_database.as_ref().unwrap().count_certs()? as usize;
        let mut counts = HashMap::new();
        counts.insert("count".to_string(), count);
        Ok(counts)
    }

    // -----------------------------------------------------------------------
    // Upload helpers
    // -----------------------------------------------------------------------

    /// Upload content to a storage URI.
    ///
    /// AWS credentials are resolved only for `s3://` targets, so `rsync://`
    /// and `sftp://` uploads never touch the CA config or 1Password.
    pub fn upload_content(
        &self,
        content: &[u8],
        store_uri: &str,
        visibility: Visibility,
    ) -> Result<(), OpcaError> {
        let creds = storage::needs_aws_credentials(store_uri)
            .then(|| self.aws_credentials())
            .transpose()?;
        let backend = storage::storage_from_uri_with_creds(store_uri, creds.as_ref())?;
        backend.upload(content, store_uri, visibility)
    }

    /// The AWS region configured for this CA, if any.
    pub fn aws_region(&self) -> Result<Option<String>, OpcaError> {
        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        Ok(db.get_config()?.ca_aws_region)
    }

    /// The AWS credentials this operator has selected, with the CA's
    /// configured region applied.
    pub fn aws_credentials(&self) -> Result<storage::AwsCredentials, OpcaError> {
        storage::get_aws_credentials(self.vault.op(), self.aws_region()?.as_deref())
    }

    /// Upload the CA database to the private store.
    pub fn upload_ca_database(&self, store_uri: &str) -> Result<(), OpcaError> {
        let uri = if store_uri.is_empty() {
            self.private_store_uri()?
                .ok_or_else(|| OpcaError::Storage("No private store configured".into()))?
        } else {
            store_uri.to_string()
        };

        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let binary_db = db.export_database_binary()?;
        self.upload_content(&binary_db, &uri, Visibility::Private)
    }

    /// Upload the CA certificate to the public store.
    pub fn upload_ca_cert(&self, store_uri: &str) -> Result<(), OpcaError> {
        let uri = if store_uri.is_empty() {
            let db = self
                .ca_database
                .as_ref()
                .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
            let config = db.get_config()?;
            let cfg_store = config
                .ca_public_store
                .ok_or_else(|| OpcaError::Storage("No public store configured".into()))?;
            format!(
                "{}/{}",
                cfg_store.trim_end_matches('/'),
                DEFAULT_STORAGE_CONF.ca_cert_file
            )
        } else {
            store_uri.to_string()
        };

        let cert_pem = self.get_certificate()?;
        self.upload_content(cert_pem.as_bytes(), &uri, Visibility::Public)
    }

    /// Upload the CRL to the public store.
    pub fn upload_crl(&self, store_uri: &str) -> Result<(), OpcaError> {
        let uri = if store_uri.is_empty() {
            let db = self
                .ca_database
                .as_ref()
                .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
            let config = db.get_config()?;
            let cfg_store = config
                .ca_public_store
                .ok_or_else(|| OpcaError::Storage("No public store configured".into()))?;
            format!(
                "{}/{}",
                cfg_store.trim_end_matches('/'),
                DEFAULT_STORAGE_CONF.crl_file
            )
        } else {
            store_uri.to_string()
        };

        let crl = self
            .crl
            .as_ref()
            .ok_or_else(|| OpcaError::CertificateNotFound("CRL not found".into()))?;
        self.upload_content(crl.as_bytes(), &uri, Visibility::Public)
    }

    // -----------------------------------------------------------------------
    // Store testing
    // -----------------------------------------------------------------------

    /// Test connectivity for all configured storage backends.
    ///
    /// Returns a map of store name to result string for each configured
    /// store.  A value of `"ok"` indicates success; anything else is an
    /// error message.
    pub fn test_stores(&self) -> Result<HashMap<String, String>, OpcaError> {
        info!("[ca] testing store connections");
        let db = self
            .ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let config = db.get_config()?;

        let stores = [
            ("public", config.ca_public_store),
            ("private", config.ca_private_store),
            ("backup", config.ca_backup_store),
        ];

        // Check if any store needs S3 credentials so we only fetch once
        let needs_s3 = stores
            .iter()
            .any(|(_, uri)| uri.as_deref().is_some_and(|u| u.starts_with("s3://")));

        let aws_creds = if needs_s3 {
            match storage::get_aws_credentials(self.vault.op(), config.ca_aws_region.as_deref()) {
                Ok(creds) => Some(creds),
                Err(e) => {
                    error!("[ca] failed to retrieve AWS credentials: {e}");
                    // Return the error for all S3 stores
                    let mut results = HashMap::new();
                    for (name, uri_opt) in &stores {
                        if uri_opt.as_deref().is_some_and(|u| u.starts_with("s3://")) {
                            results.insert(name.to_string(), e.to_string());
                        }
                    }
                    return Ok(results);
                }
            }
        } else {
            None
        };

        let mut results = HashMap::new();

        for (name, uri_opt) in stores {
            if let Some(ref uri) = uri_opt {
                if uri.is_empty() {
                    continue;
                }
                info!("[ca] testing {name} store: {uri}");
                let result = match storage::storage_from_uri_with_creds(uri, aws_creds.as_ref()) {
                    Ok(backend) => match backend.test_connection(uri) {
                        Ok(()) => {
                            info!("[ca] {name} store: ok");
                            "ok".to_string()
                        }
                        Err(e) => {
                            error!("[ca] {name} store failed: {e}");
                            e.to_string()
                        }
                    },
                    Err(e) => {
                        error!("[ca] {name} store backend error: {e}");
                        e.to_string()
                    }
                };
                results.insert(name.to_string(), result);
            }
        }

        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn verified_csr(csr: &X509Req) -> Result<Csr, OpcaError> {
    if has_explicit_curve_parameters(csr) {
        return Err(OpcaError::InvalidCertificate(
            "CSR: EC keys must use a named curve".into(),
        ));
    }
    Csr::from_der(
        &csr.to_der()?,
        crypto_provider().signature_verification_algorithms.all,
    )
    .map_err(|e| OpcaError::InvalidCertificate(format!("CSR: {e}")))
}

fn has_explicit_curve_parameters(csr: &X509Req) -> bool {
    csr.public_key()
        .and_then(|key| key.ec_key())
        .is_ok_and(|key| key.group().asn1_flag() != Asn1Flag::NAMED_CURVE)
}

fn authority_of(
    ca_cert: &X509,
    ca_key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> Result<Authority, OpcaError> {
    Ok(Authority::new(
        ca_cert.to_der()?.into(),
        signer_of(ca_key)?,
        KeyIdentifierMethod::Sha1,
    )?)
}

/// VPN client CNs are people, not hosts, so only their requested names become SANs.
/// keyEncipherment is claimed for RSA keys only: some TLS stacks reject ECDSA certs claiming it.
fn profile_for(cert_type: &CertType, rsa_subject: bool, ca_config: &CaConfig) -> Profile {
    use wslib_crypto_ca::{BasicConstraints as Bc, Extension};
    use wslib_crypto_x509::{ExtendedKeyUsage as Eku, KeyUsage as Ku};

    if *cert_type == CertType::Ca {
        return Profile {
            basic_constraints: Some(Extension::critical(Bc::Authority { path_length: None })),
            key_usage: Some(Extension::critical(vec![Ku::KeyCertSign, Ku::CrlSign])),
            ..Profile::default()
        };
    }
    let key_usage = |key_encipherment: bool| {
        let mut usages = vec![Ku::DigitalSignature];
        if key_encipherment {
            usages.push(Ku::KeyEncipherment);
        }
        Some(Extension::critical(usages))
    };
    let leaf = Profile {
        basic_constraints: Some(Extension::non_critical(Bc::EndEntity)),
        ..Profile::default()
    };
    match cert_type {
        CertType::Device => Profile {
            key_usage: key_usage(rsa_subject),
            extended_key_usage: Some(Extension::non_critical(vec![Eku::ClientAuth])),
            names: SanPolicy::CommonNameAndRequested,
            ..leaf
        },
        CertType::VpnClient => Profile {
            key_usage: key_usage(false),
            extended_key_usage: Some(Extension::critical(vec![Eku::ClientAuth])),
            names: SanPolicy::Requested,
            ..leaf
        },
        CertType::VpnServer => Profile {
            key_usage: key_usage(rsa_subject),
            extended_key_usage: Some(Extension::critical(vec![Eku::ServerAuth])),
            ..leaf
        },
        CertType::CodeSigning => Profile {
            key_usage: key_usage(false),
            extended_key_usage: Some(Extension::critical(vec![Eku::CodeSigning])),
            ..leaf
        },
        CertType::WebServer => Profile {
            key_usage: key_usage(rsa_subject),
            extended_key_usage: Some(Extension::non_critical(vec![
                Eku::ServerAuth,
                Eku::ClientAuth,
            ])),
            names: SanPolicy::CommonNameAndRequested,
            crl_distribution_points: ca_config.crl_url.iter().cloned().collect(),
            ca_issuers: ca_config.ca_url.iter().cloned().collect(),
            ..leaf
        },
        // Name constraints come from the domains it is signed for.
        CertType::SubordinateCa => Profile {
            basic_constraints: Some(Extension::critical(Bc::Authority {
                path_length: Some(0),
            })),
            key_usage: Some(Extension::critical(vec![Ku::KeyCertSign, Ku::CrlSign])),
            extended_key_usage: Some(Extension::non_critical(vec![Eku::ServerAuth])),
            crl_distribution_points: ca_config.crl_url.iter().cloned().collect(),
            ca_issuers: ca_config.ca_url.iter().cloned().collect(),
            ..Profile::default()
        },
        _ => leaf,
    }
}

/// Convert a `CaConfig` (database model) into a `CertBundleConfig` (cert model).
fn ca_config_to_bundle(config: &CaConfig) -> CertBundleConfig {
    CertBundleConfig {
        cn: config.cn.clone(),
        key_algorithm: config.key_algorithm,
        org: config.org.clone(),
        ou: config.ou.clone(),
        email: config.email.clone(),
        city: config.city.clone(),
        state: config.state.clone(),
        country: config.country.clone(),
        alt_names: None,
        next_serial: config.next_serial,
        ca_days: config.ca_days.or(config.days),
    }
}

/// Convert an Openssl-format timestamp to the human-readable Text format
/// expected by 1Password (e.g. `"20260120000000Z"` → `"Jan 20 00:00:00 2026 UTC"`).
/// Falls back to the original string if parsing fails.
fn openssl_to_text(openssl_str: &str) -> String {
    datetime::parse_datetime(openssl_str, DateTimeFormat::Openssl)
        .map(|dt| datetime::format_datetime(dt, DateTimeFormat::Text))
        .unwrap_or_else(|_| openssl_str.to_string())
}

/// Build a CertRecord from a CertificateBundle for database insertion.
fn format_db_item(
    bundle: &CertificateBundle,
    item_title: &str,
    _issuer: Option<&str>,
    _issuer_subject: Option<&str>,
) -> Result<CertRecord, OpcaError> {
    let cert = bundle
        .certificate
        .as_ref()
        .ok_or_else(|| OpcaError::InvalidCertificate("No certificate".into()))?;

    let cn = bundle.get_certificate_attrib("cn")?.unwrap_or_default();
    let serial = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
    let subject = bundle
        .get_certificate_attrib("subject")?
        .unwrap_or_default();
    let not_before = bundle.get_certificate_attrib("not_before")?;
    let not_after = bundle.get_certificate_attrib("not_after")?;
    let key_type = bundle.get_certificate_attrib("key_type")?;
    let key_size = bundle
        .get_certificate_attrib("key_size")?
        .and_then(|s| s.parse::<i64>().ok());
    let san = bundle.get_certificate_attrib("san")?;
    let issuer_str = bundle.get_certificate_attrib("issuer")?;

    // Check if expired
    let now = Asn1Time::days_from_now(0).map_err(|e| OpcaError::Crypto(format!("{e}")))?;
    let expired = cert.not_after() < &now;
    let status = if expired { "Expired" } else { "Valid" };

    Ok(CertRecord {
        serial,
        cn: Some(cn),
        title: Some(item_title.to_string()),
        status: Some(status.to_string()),
        expiry_date: not_after,
        revocation_date: None,
        subject: Some(subject),
        cert_type: Some(bundle.cert_type.to_string()),
        not_before,
        key_type,
        key_size,
        issuer: issuer_str,
        san,
        ignored_at: None,
        ignored_by: None,
        ignored_reason: None,
        ignored_note: None,
        has_private_key: Some(bundle.private_key.is_some()),
        has_chain: Some(bundle.chain.as_ref().is_some_and(|c| !c.is_empty())),
        deleted_at: None,
        published_at: None,
    })
}

/// Extension trait to convert a CertRecord to an ExternalCertRecord.
trait IntoExternal {
    fn into_external(
        self,
        issuer: Option<&str>,
        issuer_subject: Option<&str>,
    ) -> ExternalCertRecord;
}

impl IntoExternal for CertRecord {
    fn into_external(
        self,
        issuer: Option<&str>,
        issuer_subject: Option<&str>,
    ) -> ExternalCertRecord {
        ExternalCertRecord {
            serial: self.serial,
            cn: self.cn,
            title: self.title,
            status: self.status,
            expiry_date: self.expiry_date,
            subject: self.subject,
            issuer: issuer.map(|s| s.to_string()),
            issuer_subject: issuer_subject.map(|s| s.to_string()),
            import_date: Some(datetime::now_utc_str(DateTimeFormat::Openssl)),
            cert_type: Some("external".to_string()),
            not_before: self.not_before,
            key_type: self.key_type,
            key_size: self.key_size,
            san: self.san,
            has_private_key: self.has_private_key,
            has_chain: self.has_chain,
        }
    }
}

fn build_crl(
    ca_cert: &X509,
    ca_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    crl_number: i64,
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
    entries: &[CrlEntry],
) -> Result<String, OpcaError> {
    let revoked = entries
        .iter()
        .map(|entry| {
            let revoked_at =
                datetime::parse_datetime(&entry.revocation_date, DateTimeFormat::Openssl)?;
            Ok(Revocation::new(entry.serial.parse()?, revoked_at.into()))
        })
        .collect::<Result<Vec<_>, OpcaError>>()?;
    let number = u64::try_from(crl_number)
        .map_err(|_| OpcaError::Crypto(format!("CRL number {crl_number} is negative")))?;
    let der = authority_of(ca_cert, ca_key)?.revocation_list(
        number,
        this_update.into(),
        next_update.into(),
        &revoked,
    )?;
    Ok(wslib_crypto_x509::pem::encode(X509_CRL, &der))
}

/// Compute SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// The fields of a pending CSR's `CSR_<cn>` item, which holds its private key.
pub fn csr_item_fields(
    cert_type: &CertType,
    cn: &str,
    key_pem: &str,
    csr_pem: &str,
) -> Result<Vec<Assignment>, OpcaError> {
    let c = &DEFAULT_OP_CONF;
    Ok(vec![
        op::assign(c.cert_type_item, cert_type)?,
        op::assign(c.cn_item, cn)?,
        op::assign(c.key_item, key_pem)?,
        op::assign(c.csr_item, csr_pem)?,
    ])
}

/// Convenience: prepare a CA by retrieving it from 1Password.
pub fn prepare_cert_authority<R: Runner>(
    vault: Vault<R>,
) -> Result<CertificateAuthority<R>, OpcaError> {
    CertificateAuthority::retrieve(vault)
}

/// Parse CRL metadata from a PEM string without needing a full CA instance.
pub fn parse_crl_metadata(pem: &str) -> Result<CrlMetadata, OpcaError> {
    let view = CrlView::from_pem(pem)
        .map_err(|e| OpcaError::Crypto(format!("Failed to parse CRL PEM: {e}")))?;
    Ok(crl_metadata(&view))
}

pub fn crl_metadata(view: &CrlView) -> CrlMetadata {
    let openssl_time =
        |at: std::time::SystemTime| datetime::format_datetime(at.into(), DateTimeFormat::Openssl);
    CrlMetadata {
        issuer: issuer_text(&view.issuer),
        last_update: Some(openssl_time(view.this_update)),
        next_update: view.next_update.map(openssl_time),
        crl_number: view.number.and_then(|n| i64::try_from(n).ok()),
        revoked_count: Some(view.revoked.len() as i64),
        revoked_json: None,
    }
}

/// OpenSSL's one-line form (`CN=…, C=…, emailAddress=…`), which stored CRL metadata has always held.
fn issuer_text(name: &[u8]) -> Option<String> {
    let attributes = wslib_crypto_x509::name_attributes(name).ok()?;
    let text = attributes
        .into_iter()
        .filter_map(|attribute| match attribute.value {
            AttributeValue::Text(value) => Some(format!("{}={value}", short_name(&attribute.oid))),
            AttributeValue::Der(_) => None,
        })
        .collect::<Vec<_>>()
        .join(", ");
    Some(text)
}

fn short_name(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.8" => "ST",
        "2.5.4.7" => "L",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "emailAddress",
        other => other,
    }
}

/// Render a CRL as `openssl crl -text -noout` style output. The openssl-rs
/// crate doesn't expose `X509_CRL_print`, and openssl-sys' handwritten
/// bindings stop short of CRL-printing helpers, so we declare the symbol
/// locally and call libcrypto directly.
pub fn crl_to_text(crl: &openssl::x509::X509Crl) -> Result<String, OpcaError> {
    use std::os::raw::{c_char, c_int};

    unsafe extern "C" {
        fn X509_CRL_print(bp: *mut openssl_sys::BIO, x: *mut openssl_sys::X509_CRL) -> c_int;
    }

    unsafe {
        let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
        if bio.is_null() {
            return Err(OpcaError::Crypto("BIO_new failed".into()));
        }
        let rc = X509_CRL_print(bio, crl.as_ptr());
        if rc != 1 {
            openssl_sys::BIO_free_all(bio);
            return Err(OpcaError::Crypto("X509_CRL_print failed".into()));
        }
        let mut data: *mut c_char = std::ptr::null_mut();
        let len = openssl_sys::BIO_get_mem_data(bio, &mut data);
        let text = if len > 0 && !data.is_null() {
            std::slice::from_raw_parts(data as *const u8, len as usize).to_vec()
        } else {
            Vec::new()
        };
        openssl_sys::BIO_free_all(bio);
        Ok(String::from_utf8_lossy(&text).to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::cert::{CertBundleConfig, CertType, CertificateBundle, KeyAlgorithm};
    use crate::services::san;
    use crate::testutil::{FakeRunner, Output, VAULT_ID, fake_vault, item_json, not_found};
    use openssl::nid::Nid;

    fn make_ca_bundle() -> CertificateBundle {
        let config = CertBundleConfig {
            cn: Some("Test CA".to_string()),
            key_algorithm: Some(KeyAlgorithm::Rsa2048),
            org: Some("Test Org".to_string()),
            ou: None,
            email: None,
            city: None,
            state: None,
            country: Some("AU".to_string()),
            alt_names: None,
            next_serial: Some(1),
            ca_days: Some(3650),
        };
        let mut bundle = CertificateBundle::generate(CertType::Ca, "CA", config).unwrap();
        bundle.self_sign_ca().unwrap();
        bundle
    }

    /// Scripts `n` empty successes: a document or item write each.
    pub(super) fn answer_writes(ca: &CertificateAuthority<FakeRunner>, n: usize) {
        for _ in 0..n {
            ca.vault.op().runner().respond(Output::ok(""));
        }
    }

    pub(super) fn calls(ca: &CertificateAuthority<FakeRunner>) -> Vec<Vec<String>> {
        ca.vault
            .op()
            .runner()
            .calls()
            .iter()
            .map(|c| c.args().to_vec())
            .collect()
    }

    fn ca_item(bundle: &CertificateBundle) -> Output {
        Output::ok(item_json(
            "CA",
            &[
                ("certificate", &bundle.certificate_pem().unwrap()),
                ("private_key", &bundle.private_key_pem().unwrap()),
                ("type", "ca"),
            ],
        ))
    }

    /// A backup file, as `LocalBackup` writes it, whose `CA` row has `ca_serial`.
    fn backup_contents(
        ca_serial: &str,
        vault_id: &str,
    ) -> (tempfile::TempDir, LocalBackup, String) {
        let mut db = CertificateAuthorityDB::new(&CaConfig::default()).unwrap();
        let ca_row: CertRecord = serde_json::from_value(serde_json::json!({
            "serial": ca_serial, "cn": "Test CA", "title": "CA", "status": "Valid",
        }))
        .unwrap();
        db.add_cert(&ca_row).unwrap();
        let sql = String::from_utf8(db.export_database().unwrap()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let store = LocalBackup::new(dir.path(), "user-uuid", 5);
        let source = BackupSource {
            vault: "TestVault".into(),
            vault_id: Some(vault_id.into()),
        };
        let path = store.write(&source, &sql).unwrap().unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        (dir, store, contents)
    }

    #[test]
    fn restore_from_backup_stores_dump_and_keeps_unreadable_copy() {
        let bundle = make_ca_bundle();
        let serial = bundle.get_certificate_attrib("serial").unwrap().unwrap();
        let (_dir, store, contents) = backup_contents(&serial, VAULT_ID);
        let fake = FakeRunner::new();
        fake.respond(ca_item(&bundle))
            .respond(Output::ok("BEGIN TRANSACTION;\nCREATE TABLE csr ("))
            .respond(Output::ok(""));

        let ca = CertificateAuthority::restore_from_backup(fake_vault(&fake), &contents, &store)
            .unwrap();

        let source = BackupSource::of(&ca.vault);
        let kept: Vec<_> = std::fs::read_dir(store.dir_for(&source))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with("-unreadable.sql"))
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(
            fake.files().last().unwrap(),
            local_backup::strip_header(&contents).as_bytes()
        );
        assert_eq!(
            fake.calls()[2].args()[..3],
            ["document", "edit", "CA_Database"]
        );
    }

    #[test]
    fn restore_from_backup_refuses_backup_from_another_vault() {
        let (_dir, store, contents) = backup_contents("1", "vault-a");
        let fake = FakeRunner::new();

        let result =
            CertificateAuthority::restore_from_backup(fake_vault(&fake), &contents, &store);

        assert!(result.is_err_and(|e| e.to_string().contains("not the connected vault")));
    }

    #[test]
    fn restore_from_backup_refuses_backup_of_another_ca() {
        let bundle = make_ca_bundle();
        let (_dir, store, contents) = backup_contents("999999", VAULT_ID);
        let fake = FakeRunner::new();
        fake.respond(ca_item(&bundle));

        let result =
            CertificateAuthority::restore_from_backup(fake_vault(&fake), &contents, &store);

        assert!(result.is_err_and(|e| e.to_string().contains("different CA")));
        assert_eq!(
            std::fs::read_dir(store.dir_for(&BackupSource {
                vault: "TestVault".into(),
                vault_id: Some(VAULT_ID.into()),
            }))
            .unwrap()
            .count(),
            1
        );
    }

    #[test]
    fn test_ca_config_to_bundle() {
        let config = CaConfig {
            org: Some("Acme".to_string()),
            country: Some("AU".to_string()),
            days: Some(365),
            ..CaConfig::default()
        };
        let bc = ca_config_to_bundle(&config);
        assert_eq!(bc.org, Some("Acme".to_string()));
        assert_eq!(bc.ca_days, Some(365));
    }

    #[test]
    fn test_format_db_item() {
        let bundle = make_ca_bundle();
        let record = format_db_item(&bundle, "CA", None, None).unwrap();

        assert_eq!(record.cn, Some("Test CA".to_string()));
        assert_eq!(record.title, Some("CA".to_string()));
        assert_eq!(record.status, Some("Valid".to_string()));
        assert_eq!(record.cert_type, Some("ca".to_string()));
        assert!(record.serial.len() > 0);
    }

    #[test]
    fn test_format_db_item_external() {
        let bundle = make_ca_bundle();
        let record = format_db_item(&bundle, "External", None, None).unwrap();
        let ext = record.into_external(Some("IssuerCN"), Some("CN=IssuerCN,O=Issuer"));

        assert_eq!(ext.issuer, Some("IssuerCN".to_string()));
        assert_eq!(ext.issuer_subject, Some("CN=IssuerCN,O=Issuer".to_string()));
        assert_eq!(ext.cert_type, Some("external".to_string()));
        assert!(ext.import_date.is_some());
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sign_device_certificate() {
        // Create a CA
        let ca_config = CaConfig {
            next_serial: Some(2),
            org: Some("Test Org".to_string()),
            country: Some("AU".to_string()),
            days: Some(365),
            ..CaConfig::default()
        };
        let mut db = CertificateAuthorityDB::new(&ca_config).unwrap();
        let ca_bundle = make_ca_bundle();

        // Add CA to database
        let ca_record = format_db_item(&ca_bundle, "CA", None, None).unwrap();
        db.add_cert(&ca_record).unwrap();

        // Create a device CSR
        let device_config = CertBundleConfig {
            cn: Some("device.example.com".to_string()),
            key_algorithm: Some(KeyAlgorithm::Rsa2048),
            org: Some("Test Org".to_string()),
            ..CertBundleConfig::default()
        };
        let device_bundle =
            CertificateBundle::generate(CertType::Device, "device.example.com", device_config)
                .unwrap();

        let csr_pem = device_bundle.csr_pem().unwrap();
        let csr = X509Req::from_pem(csr_pem.as_bytes()).unwrap();

        // Sign with mock CA
        let mut ca = CertificateAuthority {
            vault: fake_vault(&FakeRunner::new()),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        };

        let signed = ca.sign_certificate(&csr, &CertType::Device, 365).unwrap();

        // Verify extensions
        let text = signed.to_text().unwrap();
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("CA:FALSE"), "Should have CA:FALSE");
        assert!(
            text.contains("Digital Signature"),
            "Should have Digital Signature"
        );
        assert!(
            text.contains("TLS Web Client Authentication"),
            "Should have Client Auth"
        );
    }

    #[test]
    fn test_sign_webserver_certificate() {
        let ca_config = CaConfig {
            next_serial: Some(2),
            org: Some("Test Org".to_string()),
            country: Some("AU".to_string()),
            days: Some(365),
            crl_url: Some("http://crl.example.com/crl.pem".to_string()),
            ca_url: Some("http://ca.example.com/ca.crt".to_string()),
            ..CaConfig::default()
        };
        let mut db = CertificateAuthorityDB::new(&ca_config).unwrap();
        let ca_bundle = make_ca_bundle();
        let ca_record = format_db_item(&ca_bundle, "CA", None, None).unwrap();
        db.add_cert(&ca_record).unwrap();

        let ws_config = CertBundleConfig {
            cn: Some("www.example.com".to_string()),
            key_algorithm: Some(KeyAlgorithm::Rsa2048),
            alt_names: Some(vec!["example.com".to_string()]),
            ..CertBundleConfig::default()
        };
        let ws_bundle =
            CertificateBundle::generate(CertType::WebServer, "www.example.com", ws_config).unwrap();

        let csr_pem = ws_bundle.csr_pem().unwrap();
        let csr = X509Req::from_pem(csr_pem.as_bytes()).unwrap();

        let mut ca = CertificateAuthority {
            vault: fake_vault(&FakeRunner::new()),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        };

        let signed = ca
            .sign_certificate(&csr, &CertType::WebServer, 365)
            .unwrap();

        let text = signed.to_text().unwrap();
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("TLS Web Server Authentication"));
        assert!(text.contains("TLS Web Client Authentication"));
        assert!(text.contains("crl.example.com"), "Should have CRL DP");
        assert!(text.contains("ca.example.com"), "Should have AIA");
    }

    #[test]
    fn test_sign_vpnclient_certificate() {
        let ca_config = CaConfig {
            next_serial: Some(2),
            days: Some(365),
            ..CaConfig::default()
        };
        let mut db = CertificateAuthorityDB::new(&ca_config).unwrap();
        let ca_bundle = make_ca_bundle();
        let ca_record = format_db_item(&ca_bundle, "CA", None, None).unwrap();
        db.add_cert(&ca_record).unwrap();

        let vpn_config = CertBundleConfig {
            cn: Some("vpn-client-1".to_string()),
            key_algorithm: Some(KeyAlgorithm::Rsa2048),
            ..CertBundleConfig::default()
        };
        let vpn_bundle =
            CertificateBundle::generate(CertType::VpnClient, "vpn-client-1", vpn_config).unwrap();

        let csr_pem = vpn_bundle.csr_pem().unwrap();
        let csr = X509Req::from_pem(csr_pem.as_bytes()).unwrap();

        let mut ca = CertificateAuthority {
            vault: fake_vault(&FakeRunner::new()),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        };

        let signed = ca
            .sign_certificate(&csr, &CertType::VpnClient, 365)
            .unwrap();

        let text = signed.to_text().unwrap();
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("Digital Signature"));
        assert!(text.contains("TLS Web Client Authentication"));
        // VPN client should NOT have server auth
        assert!(!text.contains("TLS Web Server Authentication"));
    }

    #[test]
    fn test_sign_vpnserver_certificate() {
        let ca_config = CaConfig {
            next_serial: Some(2),
            days: Some(365),
            ..CaConfig::default()
        };
        let mut db = CertificateAuthorityDB::new(&ca_config).unwrap();
        let ca_bundle = make_ca_bundle();
        let ca_record = format_db_item(&ca_bundle, "CA", None, None).unwrap();
        db.add_cert(&ca_record).unwrap();

        let vpn_config = CertBundleConfig {
            cn: Some("vpn-server".to_string()),
            key_algorithm: Some(KeyAlgorithm::Rsa2048),
            ..CertBundleConfig::default()
        };
        let vpn_bundle =
            CertificateBundle::generate(CertType::VpnServer, "vpn-server", vpn_config).unwrap();

        let csr_pem = vpn_bundle.csr_pem().unwrap();
        let csr = X509Req::from_pem(csr_pem.as_bytes()).unwrap();

        let mut ca = CertificateAuthority {
            vault: fake_vault(&FakeRunner::new()),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        };

        let signed = ca
            .sign_certificate(&csr, &CertType::VpnServer, 365)
            .unwrap();

        let text = signed.to_text().unwrap();
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("TLS Web Server Authentication"));
        assert!(text.contains("Key Encipherment"));
    }

    #[test]
    fn test_sign_codesigning_certificate() {
        use openssl::stack::Stack;
        use openssl::x509::store::X509StoreBuilder;
        use openssl::x509::{X509PurposeId, X509StoreContext};

        let ca_config = CaConfig {
            next_serial: Some(2),
            days: Some(365),
            crl_url: Some("http://crl.example.com/crl.pem".to_string()),
            ca_url: Some("http://ca.example.com/ca.crt".to_string()),
            ..CaConfig::default()
        };
        let mut db = CertificateAuthorityDB::new(&ca_config).unwrap();
        let ca_bundle = make_ca_bundle();
        let ca_cert = ca_bundle.certificate.clone().unwrap();
        db.add_cert(&format_db_item(&ca_bundle, "CA", None, None).unwrap())
            .unwrap();
        let mut ca = CertificateAuthority {
            vault: fake_vault(&FakeRunner::new()),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        };

        let signed = sign(
            &mut ca,
            CertType::CodeSigning,
            "ApplianceOS Update Signing",
            &[],
            KeyAlgorithm::EcP256,
        );

        let text = text_of(&signed);
        assert!(
            text.contains("X509v3 Extended Key Usage: critical\n                Code Signing\n"),
            "{text}"
        );
        assert!(
            text.contains("X509v3 Key Usage: critical\n                Digital Signature\n"),
            "{text}"
        );
        assert!(text.contains("CA:FALSE"));
        assert!(signed.subject_alt_names().is_none());
        assert!(!text.contains("CRL Distribution Points"));
        assert!(!text.contains("Authority Information Access"));

        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(ca_cert).unwrap();
        store.set_purpose(X509PurposeId::CODE_SIGN).unwrap();
        let store = store.build();
        let mut ctx = X509StoreContext::new().unwrap();
        let verified = ctx
            .init(&store, &signed, &Stack::new().unwrap(), |c| c.verify_cert())
            .unwrap();
        assert!(verified, "{}", ctx.error());
    }

    fn at(timestamp: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(timestamp, 0).unwrap()
    }

    fn validity(crl: &openssl::x509::X509Crl) -> (DateTime<Utc>, DateTime<Utc>) {
        let epoch = Asn1Time::from_unix(0).unwrap();
        let seconds = |t: &openssl::asn1::Asn1TimeRef| {
            let d = epoch.diff(t).unwrap();
            at(i64::from(d.days) * 86_400 + i64::from(d.secs))
        };
        (
            seconds(crl.last_update()),
            seconds(crl.next_update().unwrap()),
        )
    }

    fn crl_number(crl: &openssl::x509::X509Crl) -> Option<i64> {
        parse_crl_metadata(std::str::from_utf8(&crl.to_pem().unwrap()).unwrap())
            .unwrap()
            .crl_number
    }

    #[test]
    fn a_crl_carries_the_validity_window_it_is_given() {
        let ca_bundle = make_ca_bundle();
        let ca_cert = ca_bundle.certificate.as_ref().unwrap();
        let ca_key = ca_bundle.private_key.as_ref().unwrap();
        let (this_update, next_update) = (at(1_900_000_000), at(1_900_000_000 + 10 * 86_400));

        let pem = build_crl(ca_cert, ca_key, 1, this_update, next_update, &[]).unwrap();

        let crl = openssl::x509::X509Crl::from_pem(pem.as_bytes()).unwrap();
        assert_eq!(validity(&crl), (this_update, next_update));
    }

    pub(super) fn ca_with_key(algorithm: KeyAlgorithm) -> CertificateAuthority<FakeRunner> {
        let config = CertBundleConfig {
            cn: Some("Test CA".to_string()),
            key_algorithm: Some(algorithm),
            next_serial: Some(1),
            ca_days: Some(3650),
            ..CertBundleConfig::default()
        };
        let mut ca_bundle = CertificateBundle::generate(CertType::Ca, "CA", config).unwrap();
        ca_bundle.self_sign_ca().unwrap();
        let db = CertificateAuthorityDB::new(&CaConfig {
            next_serial: Some(2),
            days: Some(365),
            ..CaConfig::default()
        })
        .unwrap();
        CertificateAuthority {
            vault: fake_vault(&FakeRunner::new()),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
            local_backup: None,
        }
    }

    fn sign(
        ca: &mut CertificateAuthority<FakeRunner>,
        cert_type: CertType,
        cn: &str,
        alt_names: &[&str],
        algorithm: KeyAlgorithm,
    ) -> X509 {
        let config = CertBundleConfig {
            cn: Some(cn.to_string()),
            key_algorithm: Some(algorithm),
            alt_names: Some(alt_names.iter().map(|s| s.to_string()).collect()),
            ..CertBundleConfig::default()
        };
        let leaf = CertificateBundle::generate(cert_type.clone(), cn, config).unwrap();
        ca.sign_certificate(leaf.csr.as_ref().unwrap(), &cert_type, 365)
            .unwrap()
    }

    fn sign_leaf(ca: &mut CertificateAuthority<FakeRunner>, algorithm: KeyAlgorithm) -> X509 {
        sign(ca, CertType::WebServer, "www.example.com", &[], algorithm)
    }

    fn san_strings(cert: &X509) -> Vec<String> {
        san::of_certificate(cert)
            .iter()
            .map(|n| n.tagged())
            .collect()
    }

    fn text_of(cert: &X509) -> String {
        String::from_utf8_lossy(&cert.to_text().unwrap()).into_owned()
    }

    #[test]
    fn ec_and_rsa_cas_sign_leaves_of_the_other_family() {
        for (ca_alg, leaf_alg) in [
            (KeyAlgorithm::EcP384, KeyAlgorithm::Rsa2048),
            (KeyAlgorithm::Rsa2048, KeyAlgorithm::EcP256),
        ] {
            let mut ca = ca_with_key(ca_alg);
            let signed = sign_leaf(&mut ca, leaf_alg);
            let ca_key = ca.ca_bundle.as_ref().unwrap().private_key.as_ref().unwrap();
            assert!(
                signed.verify(ca_key).unwrap(),
                "{ca_alg} CA → {leaf_alg} leaf"
            );
        }
    }

    #[test]
    fn key_encipherment_is_only_claimed_for_rsa_leaves() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        assert!(!text_of(&sign_leaf(&mut ca, KeyAlgorithm::EcP256)).contains("Key Encipherment"));
        assert!(text_of(&sign_leaf(&mut ca, KeyAlgorithm::Rsa2048)).contains("Key Encipherment"));
    }

    #[test]
    fn p384_ca_signs_with_sha384() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP384);
        assert!(text_of(&sign_leaf(&mut ca, KeyAlgorithm::EcP256)).contains("ecdsa-with-SHA384"));
    }

    #[test]
    fn ec_ca_signs_a_verifiable_crl() {
        let ca = ca_with_key(KeyAlgorithm::EcP384);
        let bundle = ca.ca_bundle.as_ref().unwrap();
        let key = bundle.private_key.as_ref().unwrap();
        let pem = build_crl(
            bundle.certificate.as_ref().unwrap(),
            key,
            1,
            Utc::now(),
            Utc::now(),
            &[],
        )
        .unwrap();
        let crl = openssl::x509::X509Crl::from_pem(pem.as_bytes()).unwrap();
        assert!(crl.verify(key).unwrap());
    }

    #[test]
    fn every_san_kind_survives_signing() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let signed = sign(
            &mut ca,
            CertType::WebServer,
            "www.example.com",
            &[
                "10.0.0.5",
                "2001:db8::1",
                "ops@example.com",
                "spiffe://prod/web",
                "example.com",
            ],
            KeyAlgorithm::EcP256,
        );
        assert_eq!(
            san_strings(&signed),
            [
                "DNS:www.example.com",
                "IP:10.0.0.5",
                "IP:2001:db8::1",
                "email:ops@example.com",
                "URI:spiffe://prod/web",
                "DNS:example.com",
            ]
        );
        let pem = signed.to_pem().unwrap();
        let bundle = CertificateBundle::import(
            CertType::WebServer,
            "www",
            &pem,
            None,
            None,
            None,
            CertBundleConfig::default(),
        )
        .unwrap();
        let stored = bundle.get_certificate_attrib("san").unwrap().unwrap();
        assert!(stored.contains("IP:2001:db8::1"), "{stored}");
    }

    #[test]
    fn an_ip_common_name_becomes_an_ip_san() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let signed = sign(
            &mut ca,
            CertType::Device,
            "192.168.1.20",
            &[],
            KeyAlgorithm::EcP256,
        );
        assert_eq!(san_strings(&signed), ["IP:192.168.1.20"]);
    }

    #[test]
    fn vpn_clients_carry_their_csr_sans_but_not_their_cn() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let signed = sign(
            &mut ca,
            CertType::VpnClient,
            "Alex",
            &["alex@example.com"],
            KeyAlgorithm::EcP256,
        );
        assert_eq!(san_strings(&signed), ["email:alex@example.com"]);
        let bare = sign(
            &mut ca,
            CertType::VpnClient,
            "Sam",
            &[],
            KeyAlgorithm::EcP256,
        );
        assert!(bare.subject_alt_names().is_none());
    }

    #[test]
    fn an_invalid_san_is_refused_before_a_key_is_stored() {
        let config = CertBundleConfig {
            cn: Some("www.example.com".to_string()),
            alt_names: Some(vec!["10.0.0.300".to_string()]),
            ..CertBundleConfig::default()
        };
        assert!(CertificateBundle::generate(CertType::WebServer, "www", config).is_err());
    }

    #[test]
    fn deleting_a_pending_csr_archives_its_key_item() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let db = ca.ca_database.as_ref().unwrap();
        for (cn, status) in [
            ("pending.example.com", "Pending"),
            ("done.example.com", "Complete"),
        ] {
            db.add_csr(&CsrRecord {
                cn: Some(cn.to_string()),
                title: Some(format!("CSR_{cn}")),
                status: Some(status.to_string()),
                ..Default::default()
            })
            .unwrap();
        }

        answer_writes(&ca, 3);
        ca.delete_csr(1).unwrap();
        ca.delete_csr(2).unwrap();

        let deletes: Vec<_> = calls(&ca)
            .into_iter()
            .filter(|c| c[..2] == ["item", "delete"])
            .collect();
        assert_eq!(
            deletes.len(),
            1,
            "only the pending CSR's item is archived: {deletes:?}"
        );
        assert_eq!(deletes[0][2], "CSR_pending.example.com");
        assert!(deletes[0].contains(&"--archive".to_string()));
        assert!(
            ca.ca_database
                .as_ref()
                .unwrap()
                .query_all_csrs(None)
                .unwrap()
                .is_empty()
        );
    }

    fn ca_with_cert_rows() -> CertificateAuthority<FakeRunner> {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let db = ca.ca_database.as_mut().unwrap();
        for (serial, cert_type, expiry, revoked) in [
            ("1", "ca", "20351231235959Z", false),
            ("2", "webserver", "20351231235959Z", false),
            ("3", "webserver", "20351231235959Z", true),
            ("4", "webserver", "20200101000000Z", false),
        ] {
            db.add_cert(&CertRecord {
                serial: serial.to_string(),
                cn: Some(format!("host{serial}.example.com")),
                title: Some(format!("CRT_{serial}_host{serial}.example.com")),
                status: Some(if revoked { "Revoked" } else { "Valid" }.to_string()),
                expiry_date: Some(expiry.to_string()),
                revocation_date: revoked.then(|| "20250101000000Z".to_string()),
                cert_type: Some(cert_type.to_string()),
                ..Default::default()
            })
            .unwrap();
        }
        ca
    }

    #[test]
    fn deleting_refuses_the_ca_and_valid_certificates() {
        let mut ca = ca_with_cert_rows();
        assert!(ca.delete_certificate("1").is_err());
        assert!(ca.delete_certificate("2").is_err());
        assert!(calls(&ca).iter().all(|c| c[..2] != ["item", "delete"]));
        assert_eq!(ca.ca_database.as_ref().unwrap().count_certs().unwrap(), 4);
    }

    #[test]
    fn a_deleted_revoked_certificate_is_archived_hidden_and_still_on_the_crl() {
        let mut ca = ca_with_cert_rows();
        answer_writes(&ca, 4);
        ca.delete_certificate("3").unwrap();

        let deletes: Vec<_> = calls(&ca)
            .into_iter()
            .filter(|c| c[..2] == ["item", "delete"])
            .collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0][2], "CRT_3_host3.example.com");
        assert!(deletes[0].contains(&"--archive".to_string()));

        let db = ca.ca_database.as_mut().unwrap();
        let listed: Vec<_> = db
            .query_all_certs()
            .unwrap()
            .into_iter()
            .map(|c| c.serial)
            .collect();
        assert_eq!(listed, ["1", "2", "4"]);
        let row = db
            .query_cert(&CertLookup::Serial("3".into()), false)
            .unwrap()
            .unwrap();
        assert!(row.deleted_at.is_some());
        assert_eq!(row.ignored_reason.as_deref(), Some("deleted"));

        db.process_ca_database(None, true).unwrap();
        assert!(db.certs_revoked.contains("3"));
        assert_eq!(crl_serials(&ca.generate_crl().unwrap()), ["3"]);

        assert!(matches!(
            ca.delete_certificate("3"),
            Err(OpcaError::CertificateNotFound(_))
        ));
    }

    fn crl_serials(pem: &str) -> Vec<String> {
        let crl = openssl::x509::X509Crl::from_pem(pem.as_bytes()).unwrap();
        crl.get_revoked()
            .map(|stack| {
                stack
                    .iter()
                    .map(|r| {
                        r.serial_number()
                            .to_bn()
                            .unwrap()
                            .to_dec_str()
                            .unwrap()
                            .to_string()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn the_stored_revoked_count_is_the_crls_entry_count() {
        let mut ca = ca_with_cert_rows();
        let db = ca.ca_database.as_mut().unwrap();
        for (serial, expiry, revocation_date) in [
            ("5", "20200101000000Z", Some("20190101000000Z")),
            ("6", "20351231235959Z", None),
        ] {
            db.add_cert(&CertRecord {
                serial: serial.to_string(),
                status: Some("Revoked".to_string()),
                expiry_date: Some(expiry.to_string()),
                revocation_date: revocation_date.map(str::to_string),
                ..Default::default()
            })
            .unwrap();
        }
        answer_writes(&ca, 4);
        ca.delete_certificate("3").unwrap();

        let listed = crl_serials(&ca.generate_crl().unwrap());

        assert_eq!(
            listed,
            ["3"],
            "deleted stays listed; expired or undated revoked certs don't"
        );
        let metadata = ca
            .ca_database
            .as_ref()
            .unwrap()
            .get_crl_metadata()
            .unwrap()
            .unwrap();
        assert_eq!(metadata.revoked_count, Some(listed.len() as i64));
    }

    fn crl_extension(crl: &openssl::x509::X509Crl, nid: Nid) -> (bool, Vec<u8>) {
        unsafe {
            let idx = openssl_sys::X509_CRL_get_ext_by_NID(crl.as_ptr(), nid.as_raw(), -1);
            assert!(idx >= 0, "no {:?} extension", nid.short_name());
            let ext = openssl_sys::X509_CRL_get_ext(crl.as_ptr(), idx);
            let data = <openssl::asn1::Asn1StringRef as foreign_types::ForeignTypeRef>::from_ptr(
                openssl_sys::X509_EXTENSION_get_data(ext).cast(),
            );
            (
                openssl_sys::X509_EXTENSION_get_critical(ext) == 1,
                data.as_slice().to_vec(),
            )
        }
    }

    #[test]
    fn each_crl_carries_the_next_crl_number_and_the_one_it_records() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        answer_writes(&ca, 4);
        for expected in [1, 2] {
            let pem = ca.generate_crl().unwrap();
            let crl = openssl::x509::X509Crl::from_pem(pem.as_bytes()).unwrap();
            assert_eq!(
                crl_extension(&crl, Nid::CRL_NUMBER),
                (false, vec![0x02, 0x01, expected as u8])
            );
            assert_eq!(parse_crl_metadata(&pem).unwrap().crl_number, Some(expected));
            let metadata = ca
                .ca_database
                .as_ref()
                .unwrap()
                .get_crl_metadata()
                .unwrap()
                .unwrap();
            assert_eq!(metadata.crl_number, Some(expected));
        }
        assert_eq!(
            ca.ca_database
                .as_ref()
                .unwrap()
                .get_config()
                .unwrap()
                .next_crl_serial,
            Some(3)
        );
    }

    #[test]
    fn a_crl_names_its_signing_key_by_the_cas_subject_key_identifier() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP384);
        answer_writes(&ca, 2);
        let crl = openssl::x509::X509Crl::from_pem(ca.generate_crl().unwrap().as_bytes()).unwrap();
        let ski = ca
            .ca_bundle
            .as_ref()
            .unwrap()
            .certificate
            .as_ref()
            .unwrap()
            .subject_key_id()
            .unwrap()
            .as_slice()
            .to_vec();

        let (critical, der) = crl_extension(&crl, Nid::AUTHORITY_KEY_IDENTIFIER);
        assert!(!critical);
        assert_eq!(der, [&[0x30, 22, 0x80, 20][..], &ski].concat());
        let hex = ski
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let text = crl_to_text(&crl).unwrap();
        assert!(
            text.contains("X509v3 Authority Key Identifier") && text.contains(&hex),
            "{text}"
        );
    }

    #[test]
    fn the_crl_issuer_keeps_openssls_one_line_form() {
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        for (nid, value) in [
            (Nid::COMMONNAME, "Test CA"),
            (Nid::COUNTRYNAME, "AU"),
            (Nid::STATEORPROVINCENAME, "VIC"),
            (Nid::LOCALITYNAME, "Melbourne"),
            (Nid::ORGANIZATIONNAME, "Test Org"),
            (Nid::ORGANIZATIONALUNITNAME, "Test Unit"),
            (Nid::PKCS9_EMAILADDRESS, "ca@example.com"),
        ] {
            name.append_entry_by_nid(nid, value).unwrap();
        }
        assert_eq!(
            issuer_text(&name.build().to_der().unwrap()).unwrap(),
            "CN=Test CA, C=AU, ST=VIC, L=Melbourne, O=Test Org, OU=Test Unit, emailAddress=ca@example.com"
        );
    }

    fn batch_ca(store: Option<&str>) -> CertificateAuthority<FakeRunner> {
        let ca = ca_with_cert_rows();
        ca.ca_database
            .as_ref()
            .unwrap()
            .update_config(&CaConfig {
                crl_batch_enabled: Some(true),
                ca_private_store: store.map(str::to_string),
                ..CaConfig::default()
            })
            .unwrap();
        ca
    }

    /// A local private store the rsync backend can write the batch into.
    fn private_store() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("pending-crl")).unwrap();
        let uri = format!("rsync://{}", dir.path().display());
        (dir, uri)
    }

    fn uploaded_batch(dir: &tempfile::TempDir) -> Vec<openssl::x509::X509Crl> {
        let pem =
            std::fs::read_to_string(dir.path().join(DEFAULT_STORAGE_CONF.crl_batch_file)).unwrap();
        pem.split_inclusive("-----END X509 CRL-----\n")
            .map(|one| openssl::x509::X509Crl::from_pem(one.as_bytes()).unwrap())
            .collect()
    }

    #[test]
    fn a_batch_is_staggered_numbered_upward_uploaded_and_led_by_the_stored_crl() {
        let (dir, uri) = private_store();
        let mut ca = batch_ca(Some(&uri));
        answer_writes(&ca, 2);

        let stored = ca.generate_crl().unwrap();

        let crls = uploaded_batch(&dir);
        let key = ca.ca_bundle.as_ref().unwrap().private_key.clone().unwrap();
        let db = ca.ca_database.as_ref().unwrap();
        let batch = db.get_crl_batch().unwrap().unwrap();
        assert_eq!(
            (
                batch.count,
                batch.period_days,
                batch.window_days,
                batch.first_number
            ),
            (5, 7, 10, 1)
        );
        assert_eq!(crls.len(), 5);
        for (i, crl) in crls.iter().enumerate() {
            let i = i as i64;
            assert_eq!(crl_number(crl), Some(1 + i));
            assert_eq!(
                validity(crl),
                (
                    batch.t0 + chrono::Duration::days(7 * i),
                    batch.t0 + chrono::Duration::days(7 * i + 10)
                )
            );
            assert_eq!(
                crl_serials(&String::from_utf8(crl.to_pem().unwrap()).unwrap()),
                ["3"]
            );
            assert!(crl.verify(&key).unwrap());
        }
        assert_eq!(stored.as_bytes(), crls[0].to_pem().unwrap());
        assert_eq!(db.get_crl_metadata().unwrap().unwrap().crl_number, Some(1));
        assert_eq!(db.get_config().unwrap().next_crl_serial, Some(6));
    }

    #[test]
    fn re_signing_a_batch_numbers_it_above_the_last_one() {
        let (dir, uri) = private_store();
        let mut ca = batch_ca(Some(&uri));
        answer_writes(&ca, 4);
        ca.generate_crl().unwrap();

        ca.generate_crl().unwrap();

        let numbers: Vec<_> = uploaded_batch(&dir).iter().map(crl_number).collect();
        assert_eq!(numbers, [6, 7, 8, 9, 10].map(Some));
        assert_eq!(
            ca.ca_database
                .as_ref()
                .unwrap()
                .get_crl_batch()
                .unwrap()
                .unwrap()
                .first_number,
            6
        );
    }

    #[test]
    fn a_config_update_cannot_leave_batches_on_without_a_private_store() {
        let on = CaConfig {
            crl_batch_enabled: Some(true),
            ..CaConfig::default()
        };
        let store = |s: &str| CaConfig {
            ca_private_store: Some(s.into()),
            ..CaConfig::default()
        };

        assert!(check_crl_batch_update(&CaConfig::default(), &on).is_err());
        assert!(
            check_crl_batch_update(
                &CaConfig {
                    ca_private_store: Some(" ".into()),
                    ..on.clone()
                },
                &store(" ")
            )
            .is_err()
        );
        assert!(check_crl_batch_update(&store("rsync:///ca"), &on).is_ok());
        assert!(
            check_crl_batch_update(
                &CaConfig {
                    ca_private_store: Some("rsync:///ca".into()),
                    ..on.clone()
                },
                &store("")
            )
            .is_err()
        );
        assert!(
            check_crl_batch_update(
                &on,
                &CaConfig {
                    crl_batch_enabled: Some(false),
                    ..CaConfig::default()
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn batch_mode_without_a_private_store_is_refused_before_anything_is_signed() {
        let mut ca = batch_ca(None);

        let err = ca.generate_crl().unwrap_err();

        assert!(
            matches!(err, OpcaError::Storage(ref m) if m.contains("private store")),
            "{err}"
        );
        let db = ca.ca_database.as_ref().unwrap();
        assert_eq!(db.get_config().unwrap().next_crl_serial, None);
        assert!(db.get_crl_metadata().unwrap().is_none());
        assert!(calls(&ca).is_empty());
    }

    #[test]
    fn a_failed_batch_upload_says_so_after_the_crl_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let mut ca = batch_ca(Some(&format!("rsync://{}/missing", dir.path().display())));
        answer_writes(&ca, 2);

        let err = ca.generate_crl().unwrap_err();

        assert!(matches!(err, OpcaError::CrlBatchUpload(_)), "{err}");
        assert!(ca.crl.is_some());
        assert_eq!(
            ca.ca_database
                .as_ref()
                .unwrap()
                .get_config()
                .unwrap()
                .next_crl_serial,
            Some(6)
        );
    }

    #[test]
    fn with_batches_off_one_crl_lasts_crl_days_and_any_old_batch_record_goes() {
        let (_dir, uri) = private_store();
        let mut ca = batch_ca(Some(&uri));
        answer_writes(&ca, 4);
        ca.generate_crl().unwrap();
        let db = ca.ca_database.as_ref().unwrap();
        db.update_config(&CaConfig {
            crl_batch_enabled: Some(false),
            crl_days: Some(30),
            ..CaConfig::default()
        })
        .unwrap();

        let pem = ca.generate_crl().unwrap();

        let (this_update, next_update) =
            validity(&openssl::x509::X509Crl::from_pem(pem.as_bytes()).unwrap());
        assert_eq!(next_update - this_update, chrono::Duration::days(30));
        let db = ca.ca_database.as_ref().unwrap();
        assert!(db.get_crl_batch().unwrap().is_none());
        assert_eq!(db.get_config().unwrap().next_crl_serial, Some(7));
    }

    #[test]
    fn a_ca_with_only_a_common_name_can_issue() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let config = ca.ca_database.as_ref().unwrap().get_config().unwrap();
        let leaf = CertBundleConfig {
            cn: Some("www.example.com".to_string()),
            org: config.org,
            ou: config.ou,
            email: config.email,
            city: config.city,
            state: config.state,
            country: config.country,
            ..CertBundleConfig::default()
        };
        ca.vault
            .op()
            .runner()
            .respond(crate::testutil::created("CRT_2_www.example.com"));
        answer_writes(&ca, 1);
        ca.generate_certificate_bundle(CertType::WebServer, "www.example.com", leaf, None)
            .unwrap();
        assert!(ca.vault.op().runner().is_done());
    }

    #[test]
    fn deleting_an_expired_certificate_tolerates_a_missing_item() {
        let mut ca = ca_with_cert_rows();
        let fake = FakeRunner::new();
        fake.respond(not_found("CRT_4_host4.example.com"))
            .respond(Output::ok(""));
        ca.vault = fake_vault(&fake);
        ca.delete_certificate("4").unwrap();
        let db = ca.ca_database.as_ref().unwrap();
        assert!(
            db.query_all_certs()
                .unwrap()
                .iter()
                .all(|c| c.serial != "4")
        );
    }

    #[test]
    fn ca_init_config_carries_its_key_algorithm() {
        let config = CaConfig {
            key_algorithm: Some(KeyAlgorithm::Rsa4096),
            ..CaConfig::default()
        };
        assert_eq!(
            ca_config_to_bundle(&config).key_algorithm,
            Some(KeyAlgorithm::Rsa4096)
        );
    }

    // -----------------------------------------------------------------------
    // CA expiry warning tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_assess_ca_expiry_critical() {
        let now = chrono::Utc::now();
        let ca_not_after = now + chrono::Duration::days(15);
        let result = assess_ca_expiry(ca_not_after, 365, now);
        assert!(matches!(
            result,
            CaExpiryWarning::Critical { days_remaining: 15 }
        ));
    }

    #[test]
    fn test_assess_ca_expiry_prominent() {
        let now = chrono::Utc::now();
        let ca_not_after = now + chrono::Duration::days(90);
        let result = assess_ca_expiry(ca_not_after, 365, now);
        assert!(matches!(
            result,
            CaExpiryWarning::Prominent { days_remaining: 90 }
        ));
    }

    #[test]
    fn test_assess_ca_expiry_cert_lifetime() {
        let now = chrono::Utc::now();
        let ca_not_after = now + chrono::Duration::days(200);
        let result = assess_ca_expiry(ca_not_after, 365, now);
        assert!(matches!(
            result,
            CaExpiryWarning::CertLifetimeExceedsCa {
                days_remaining: 200,
                cert_lifetime_days: 365,
            }
        ));
    }

    #[test]
    fn test_assess_ca_expiry_none() {
        let now = chrono::Utc::now();
        let ca_not_after = now + chrono::Duration::days(3000);
        let result = assess_ca_expiry(ca_not_after, 365, now);
        assert!(matches!(result, CaExpiryWarning::None));
    }

    #[test]
    fn test_assess_ca_expiry_tiers_ordered() {
        // 10 days should be Critical, not Prominent or CertLifetime
        let now = chrono::Utc::now();
        let ca_not_after = now + chrono::Duration::days(10);
        let result = assess_ca_expiry(ca_not_after, 365, now);
        assert!(matches!(result, CaExpiryWarning::Critical { .. }));
    }

    #[test]
    fn test_assess_cert_issuance_warning() {
        let now = chrono::Utc::now();
        // CA expires in 200 days, cert would be valid for 365
        let ca_not_after = now + chrono::Duration::days(200);
        let result = assess_cert_issuance(ca_not_after, 365, now);
        assert!(result.is_some());
        let w = result.unwrap();
        assert!(w.message.contains("will expire on"));
    }

    #[test]
    fn issuance_warnings_leave_the_warning_label_to_the_caller() {
        let now = chrono::Utc::now();
        let outlives_ca =
            assess_cert_issuance(now + chrono::Duration::days(200), 365, now).unwrap();
        let over_apple_limit = assess_apple_tls_limit(&CertType::WebServer, 826).unwrap();
        for w in [outlives_ca, over_apple_limit] {
            assert!(!w.message.starts_with("Warning"), "{}", w.message);
        }
    }

    fn issued_days(
        ca_days: i64,
        cert_type: CertType,
        requested: Option<u32>,
    ) -> (i32, Vec<CertIssuanceWarning>) {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let db = ca.ca_database.as_ref().unwrap();
        db.update_config(&CaConfig {
            days: Some(ca_days),
            ..CaConfig::default()
        })
        .unwrap();
        let leaf = CertificateBundle::generate(
            cert_type.clone(),
            "leaf.example.com",
            CertBundleConfig {
                cn: Some("leaf.example.com".into()),
                ..CertBundleConfig::default()
            },
        )
        .unwrap();
        let (cert, warnings) = ca
            .issue_certificate(leaf.csr.as_ref().unwrap(), &cert_type, requested)
            .unwrap();
        (
            cert.not_before().diff(cert.not_after()).unwrap().days,
            warnings,
        )
    }

    #[test]
    fn server_certs_default_to_the_apple_limit_and_client_certs_to_the_ca_days() {
        assert_eq!(issued_days(3000, CertType::WebServer, None), (825, vec![]));
        assert_eq!(issued_days(3000, CertType::VpnServer, None), (825, vec![]));
        assert_eq!(issued_days(3000, CertType::Device, None), (3000, vec![]));
        assert_eq!(
            issued_days(3000, CertType::CodeSigning, None),
            (3000, vec![])
        );
        assert_eq!(issued_days(365, CertType::WebServer, None), (365, vec![]));
    }

    #[test]
    fn a_requested_lifetime_beats_the_ca_days() {
        assert_eq!(issued_days(365, CertType::VpnClient, Some(90)).0, 90);
    }

    #[test]
    fn only_a_server_cert_over_the_apple_limit_warns() {
        let (days, warnings) = issued_days(365, CertType::WebServer, Some(826));
        assert_eq!(days, 826);
        assert!(warnings[0].message.contains("825-day limit"));
        assert!(
            issued_days(365, CertType::WebServer, Some(825))
                .1
                .is_empty()
        );
        assert!(issued_days(365, CertType::Device, Some(3000)).1.is_empty());
    }

    #[test]
    fn a_zero_day_lifetime_is_refused() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let leaf = CertificateBundle::generate(
            CertType::Device,
            "d",
            CertBundleConfig {
                cn: Some("d".into()),
                ..CertBundleConfig::default()
            },
        )
        .unwrap();
        assert!(
            ca.issue_certificate(leaf.csr.as_ref().unwrap(), &CertType::Device, Some(0))
                .is_err()
        );
    }

    #[test]
    fn an_apple_development_csr_is_refused() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let leaf = CertificateBundle::generate(
            CertType::AppleDev,
            "dev",
            CertBundleConfig {
                cn: Some("dev".into()),
                ..CertBundleConfig::default()
            },
        )
        .unwrap();
        let err = ca
            .issue_certificate(leaf.csr.as_ref().unwrap(), &CertType::AppleDev, None)
            .unwrap_err();
        assert!(err.to_string().contains("Apple issues"), "{err}");
    }

    #[test]
    fn an_ec_csr_with_explicit_curve_parameters_is_refused_for_its_curve() {
        use openssl::ec::{EcGroup, EcKey};
        let mut group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        group.set_asn1_flag(Asn1Flag::EXPLICIT_CURVE);
        let key = openssl::pkey::PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "explicit.example")
            .unwrap();
        let mut csr = openssl::x509::X509ReqBuilder::new().unwrap();
        csr.set_subject_name(&name.build()).unwrap();
        csr.set_pubkey(&key).unwrap();
        csr.sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();

        let csr = X509Req::from_der(&csr.build().to_der().unwrap()).unwrap();
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let err = ca
            .sign_certificate(&csr, &CertType::WebServer, 365)
            .unwrap_err();
        assert!(
            err.to_string().contains("EC keys must use a named curve"),
            "{err}"
        );
    }

    // -----------------------------------------------------------------------
    // CRL expiry warning tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_assess_crl_expiry_none() {
        let now = chrono::Utc::now();
        let next_update = now + chrono::Duration::days(20);
        let result = assess_crl_expiry(next_update, now);
        assert!(matches!(result, CrlExpiryWarning::None));
    }

    #[test]
    fn test_assess_crl_expiry_prominent() {
        let now = chrono::Utc::now();
        let next_update = now + chrono::Duration::days(8);
        let result = assess_crl_expiry(next_update, now);
        assert!(matches!(
            result,
            CrlExpiryWarning::Prominent { days_remaining: 8 }
        ));
    }

    #[test]
    fn test_assess_crl_expiry_critical() {
        let now = chrono::Utc::now();
        let next_update = now + chrono::Duration::days(3);
        let result = assess_crl_expiry(next_update, now);
        assert!(matches!(
            result,
            CrlExpiryWarning::Critical { days_remaining: 3 }
        ));
    }

    #[test]
    fn test_assess_crl_expiry_critical_boundary() {
        // Exactly 7 days remaining is NOT critical (< 7) — it is prominent.
        let now = chrono::Utc::now();
        let next_update = now + chrono::Duration::days(7);
        let result = assess_crl_expiry(next_update, now);
        assert!(matches!(
            result,
            CrlExpiryWarning::Prominent { days_remaining: 7 }
        ));
    }

    #[test]
    fn test_assess_crl_expiry_expired() {
        let now = chrono::Utc::now();
        let next_update = now - chrono::Duration::days(1);
        let result = assess_crl_expiry(next_update, now);
        assert!(matches!(
            result,
            CrlExpiryWarning::Expired { days_overdue: 1 }
        ));
    }

    #[test]
    fn test_assess_crl_expiry_expired_far_past() {
        let now = chrono::Utc::now();
        let next_update = now - chrono::Duration::days(60);
        let result = assess_crl_expiry(next_update, now);
        assert!(matches!(
            result,
            CrlExpiryWarning::Expired { days_overdue: 60 }
        ));
    }

    #[test]
    fn test_assess_cert_issuance_ok() {
        let now = chrono::Utc::now();
        // CA expires in 3000 days, cert would be valid for 365
        let ca_not_after = now + chrono::Duration::days(3000);
        let result = assess_cert_issuance(ca_not_after, 365, now);
        assert!(result.is_none());
    }
}
