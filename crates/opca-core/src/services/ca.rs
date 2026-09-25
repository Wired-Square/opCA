//! Certificate Authority manager — the capstone module.
//!
//! Orchestrates all PKI operations: CA initialisation, certificate signing,
//! revocation, CRL generation, 1Password storage, and remote uploads.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use foreign_types::ForeignType;
use log::{debug, error, info};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::nid::Nid;
use openssl::pkey::Id;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
    SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509Req, X509};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::constants::{OpConf, DEFAULT_OP_CONF, DEFAULT_STORAGE_CONF};
use crate::error::OpcaError;
use crate::op::{CommandRunner, Op, StoreAction};
use crate::services::cert::{
    asn1_time_to_openssl_str, signing_digest, CertBundleConfig, CertType, CertificateBundle,
    KeyAlgorithm, APPLE_TLS_MAX_DAYS,
};
use crate::services::database::models::{
    CaConfig, CertLookup, CertRecord, CrlEntry, CrlMetadata, CsrLookup, CsrRecord,
    ExternalCertRecord, IgnoreReason, SerialType,
};
use crate::services::database::CertificateAuthorityDB;
use crate::services::san;
use crate::services::storage;
use crate::utils::datetime::{self, DateTimeFormat};

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
pub struct CertificateAuthority<R: CommandRunner> {
    pub op: Op<R>,
    pub op_config: OpConf,
    pub ca_bundle: Option<CertificateBundle>,
    pub ca_database: Option<CertificateAuthorityDB>,
    pub crl: Option<String>,
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

impl<R: CommandRunner> CertificateAuthority<R> {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Initialise a brand-new CA — generates key, self-signs, stores in 1Password.
    pub fn init(op: Op<R>, config: &CaConfig) -> Result<Self, OpcaError> {
        info!("[ca] initialising new Certificate Authority");
        let op_config = DEFAULT_OP_CONF;

        if op.item_exists(op_config.ca_title) {
            return Err(OpcaError::CaAlreadyExists);
        }

        let mut db = CertificateAuthorityDB::new(config)?;

        let bundle_config = ca_config_to_bundle(config);
        let mut bundle = CertificateBundle::generate(CertType::Ca, op_config.ca_title, bundle_config)?;
        bundle.self_sign_ca()?;

        db.increment_serial(SerialType::Cert, None)?;

        let mut ca = Self {
            op,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
        };

        ca.store_certbundle_internal(false, None, None, true)?;

        Ok(ca)
    }

    /// Import an existing CA from PEM-encoded certificate (and optionally key).
    pub fn import_ca(
        op: Op<R>,
        cert_pem: &[u8],
        key_pem: Option<&[u8]>,
        config: &CaConfig,
    ) -> Result<Self, OpcaError> {
        let op_config = DEFAULT_OP_CONF;

        if op.item_exists(op_config.ca_title) {
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
            op,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
        };

        ca.store_certbundle_internal(false, None, None, true)?;

        Ok(ca)
    }

    /// Retrieve an existing CA from 1Password.
    pub fn retrieve(op: Op<R>) -> Result<Self, OpcaError> {
        info!("[ca] retrieving CA from 1Password");
        let op_config = DEFAULT_OP_CONF;

        // Download database — also proves the CA exists, so we skip a
        // separate `item_exists` probe (one fewer `op` process spawn).
        let ca_database_sql = op.get_document(op_config.ca_database_title)
            .map_err(|e| match e {
                OpcaError::ItemNotFound(_) => OpcaError::CaNotFound,
                other => other,
            })?;

        let fingerprint = sha256_hex(ca_database_sql.as_bytes());
        let (mut db, _migration) =
            CertificateAuthorityDB::from_sql_dump(&ca_database_sql)?;
        db.download_fingerprint = Some(fingerprint);

        // Retrieve CA bundle
        let bundle = Self::retrieve_certbundle_static(&op, &op_config, op_config.ca_title)?
            .ok_or(OpcaError::CaNotFound)?;

        Ok(Self {
            op,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
        })
    }

    /// Rebuild the CA database by scanning all vault items.
    pub fn rebuild_database(op: Op<R>, config: &CaConfig) -> Result<Self, OpcaError> {
        let op_config = DEFAULT_OP_CONF;

        if !op.item_exists(op_config.ca_title) {
            return Err(OpcaError::CaNotFound);
        }
        if op.item_exists(op_config.ca_database_title) {
            return Err(OpcaError::CaAlreadyExists);
        }

        let db = CertificateAuthorityDB::new(config)?;
        let bundle = Self::retrieve_certbundle_static(&op, &op_config, op_config.ca_title)?
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
            op,
            op_config,
            ca_bundle: Some(bundle),
            ca_database: Some(db),
            crl: None,
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

        // Verify CSR signature
        let csr_pub = csr
            .public_key()
            .map_err(|e| OpcaError::Crypto(format!("CSR public key: {e}")))?;
        let csr_valid = csr
            .verify(&csr_pub)
            .map_err(|e| OpcaError::Crypto(format!("CSR verify: {e}")))?;
        if !csr_valid {
            return Err(OpcaError::InvalidCertificate("CSR signature invalid".into()));
        }

        let ca_config = db.get_config()?;
        let serial = db.increment_serial(SerialType::Cert, None)?;

        let serial_bn = BigNum::from_dec_str(&serial.to_string())
            .map_err(|e| OpcaError::Crypto(format!("Serial: {e}")))?;
        let serial_asn1 = serial_bn
            .to_asn1_integer()
            .map_err(|e| OpcaError::Crypto(format!("Serial ASN1: {e}")))?;

        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        let not_after = Asn1Time::days_from_now(days)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;

        let mut builder = X509Builder::new()
            .map_err(|e| OpcaError::Crypto(format!("X509 builder: {e}")))?;
        builder.set_version(2)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        builder.set_subject_name(csr.subject_name())
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        builder.set_issuer_name(ca_cert.subject_name())
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        builder.set_pubkey(&csr_pub)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        builder.set_serial_number(&serial_asn1)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        builder.set_not_before(&not_before)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        builder.set_not_after(&not_after)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;

        // SKI from subject public key
        let ski = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .map_err(|e| OpcaError::Crypto(format!("SKI: {e}")))?;
        builder.append_extension(ski)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;

        // AKI from CA public key
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .map_err(|e| OpcaError::Crypto(format!("AKI: {e}")))?;
        builder.append_extension(aki)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;

        // Type-specific extensions
        match cert_type {
            CertType::Ca => {
                let bc = BasicConstraints::new().critical().ca().build()
                    .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                builder.append_extension(bc)?;

                let ku = KeyUsage::new().critical().key_cert_sign().crl_sign().build()
                    .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                builder.append_extension(ku)?;
            }
            _ => {
                // Non-CA: BasicConstraints(ca=False)
                let bc = BasicConstraints::new().build()
                    .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                builder.append_extension(bc)?;
                let rsa_subject = csr.public_key().is_ok_and(|k| k.id() == Id::RSA);

                match cert_type {
                    CertType::AppleDev | CertType::Device => {
                        builder.append_extension(leaf_key_usage(rsa_subject)?)?;

                        let eku = ExtendedKeyUsage::new()
                            .client_auth()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(eku)?;

                        // SAN from CSR CN + any CSR SANs
                        self.add_san_from_csr(&mut builder, csr, ca_cert, true)?;
                    }
                    CertType::VpnClient => {
                        builder.append_extension(leaf_key_usage(false)?)?;

                        let eku = ExtendedKeyUsage::new()
                            .critical()
                            .client_auth()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(eku)?;

                        self.add_san_from_csr(&mut builder, csr, ca_cert, false)?;
                    }
                    CertType::VpnServer => {
                        builder.append_extension(leaf_key_usage(rsa_subject)?)?;

                        let eku = ExtendedKeyUsage::new()
                            .critical()
                            .server_auth()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(eku)?;
                    }
                    CertType::WebServer => {
                        builder.append_extension(leaf_key_usage(rsa_subject)?)?;

                        let eku = ExtendedKeyUsage::new()
                            .server_auth()
                            .client_auth()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(eku)?;

                        // SAN from CSR
                        self.add_san_from_csr(&mut builder, csr, ca_cert, true)?;

                        // CRL Distribution Points
                        if let Some(ref crl_url) = ca_config.crl_url {
                            let ctx = builder.x509v3_context(Some(ca_cert), None);
                            #[allow(deprecated)]
                            let cdp = openssl::x509::X509Extension::new_nid(
                                None,
                                Some(&ctx),
                                Nid::CRL_DISTRIBUTION_POINTS,
                                &format!("URI:{crl_url}"),
                            )
                            .map_err(|e| OpcaError::Crypto(format!("CDP: {e}")))?;
                            builder.append_extension(cdp)?;
                        }

                        // Authority Information Access
                        if let Some(ref ca_url) = ca_config.ca_url {
                            let ctx = builder.x509v3_context(Some(ca_cert), None);
                            #[allow(deprecated)]
                            let aia = openssl::x509::X509Extension::new_nid(
                                None,
                                Some(&ctx),
                                Nid::INFO_ACCESS,
                                &format!("caIssuers;URI:{ca_url}"),
                            )
                            .map_err(|e| OpcaError::Crypto(format!("AIA: {e}")))?;
                            builder.append_extension(aia)?;
                        }
                    }
                    _ => {}
                }
            }
        }

        builder.sign(ca_key, signing_digest(ca_key))
            .map_err(|e| OpcaError::Crypto(format!("Sign: {e}")))?;

        Ok(builder.build())
    }

    /// Add a SAN extension carrying the CSR's SANs, led by its CN (as an IP SAN
    /// if it is one) when `with_cn`. VPN client CNs are people, not hosts.
    fn add_san_from_csr(
        &self,
        builder: &mut X509Builder,
        csr: &X509Req,
        ca_cert: &X509,
        with_cn: bool,
    ) -> Result<(), OpcaError> {
        let cn = csr
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .filter(|_| with_cn)
            .map(|s| match s.parse() {
                Ok(ip) => san::SubjectAltName::Ip(ip),
                Err(_) => san::SubjectAltName::Dns(s.to_string()),
            });

        let mut names: Vec<san::SubjectAltName> = cn.into_iter().collect();
        for name in san::of_csr(csr) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        if names.is_empty() {
            return Ok(());
        }

        let mut ext = SubjectAlternativeName::new();
        for name in &names {
            name.add_to(&mut ext);
        }
        let san_ext = ext
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .map_err(|e| OpcaError::Crypto(format!("SAN: {e}")))?;
        builder.append_extension(san_ext)?;

        Ok(())
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

        let csr_pem = bundle.csr_pem().ok_or_else(|| {
            OpcaError::InvalidCertificate("CSR not generated".into())
        })?;
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
        let ca_bundle = self.ca_bundle.as_ref()
            .ok_or(OpcaError::CaNotFound)?;
        let ca_cert = ca_bundle.certificate.as_ref()
            .ok_or(OpcaError::CaNotFound)?;

        let ca_pubkey = ca_cert.public_key()
            .map_err(|e| OpcaError::Crypto(format!("Get CA public key: {e}")))?;

        // Verify signature
        match cert.verify(&ca_pubkey) {
            Ok(true) => {}
            _ => return Ok(false),
        }

        // Check time validity
        let now = Asn1Time::days_from_now(0)
            .map_err(|e| OpcaError::Crypto(format!("Asn1Time: {e}")))?;
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
            let cert_serial_str = bundle.get_certificate_attrib("serial")?
                .unwrap_or_default();
            if let Ok(cert_serial) = cert_serial_str.parse::<i64>() {
                let db = self.ca_database.as_mut()
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
        self.store_certbundle_for(
            &bundle,
            issuer.as_deref(),
            issuer_subject.as_deref(),
            true,
        )?;

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

    /// Renew a previously signed certificate from its stored CSR.
    ///
    /// Returns the renewed certificate PEM, the new serial, and an optional
    /// warning if the certificate would outlive the CA.
    pub fn renew_certificate_bundle(
        &mut self,
        lookup: &CertLookup,
        days: Option<u32>,
    ) -> Result<(String, String, Vec<CertIssuanceWarning>), OpcaError> {
        info!("[ca] renewing certificate {lookup:?}");
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let cert_record = db.query_cert(lookup, true)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

        let old_serial = cert_record.serial.clone();
        let item_title = cert_record.title.clone()
            .ok_or_else(|| OpcaError::CertificateNotFound("No title".into()))?;

        let status = cert_record.status.as_deref().unwrap_or("");
        if status == "Revoked" {
            return Err(OpcaError::Other(
                "Cannot renew a revoked certificate".into(),
            ));
        }

        let mut cert_bundle = self.retrieve_certbundle(&item_title)?
            .ok_or_else(|| OpcaError::CertificateNotFound(item_title.clone()))?;

        let csr_pem = cert_bundle.csr_pem()
            .ok_or_else(|| OpcaError::Other(format!(
                "CSR not found for certificate '{item_title}'; cannot renew."
            )))?;

        let csr = X509Req::from_pem(csr_pem.as_bytes())
            .map_err(|e| OpcaError::Crypto(format!("Parse CSR: {e}")))?;

        let cert_type = cert_bundle.cert_type.clone();
        let (signed_cert, warnings) = self.issue_certificate(&csr, &cert_type, days)?;
        cert_bundle.update_certificate(signed_cert)?;

        // Update title with new serial
        let new_serial = cert_bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        let cn = cert_bundle.get_certificate_attrib("cn")?.unwrap_or_default();
        cert_bundle.title = format!("CRT_{new_serial}_{cn}");

        // Persist the new bundle, then auto-ignore the predecessor so it stops
        // triggering expiry alerts (Lambda + dashboard) the moment it's been
        // replaced, rather than waiting for it to expire and be superseded.
        self.store_certbundle_for(&cert_bundle, None, None, false)?;
        self.auto_ignore_predecessor(&old_serial, &new_serial, IgnoreReason::Renewed)?;
        self.store_ca_database()?;

        let pem = cert_bundle.certificate_pem()?;
        Ok((pem, new_serial, warnings))
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
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let cert_record = db.query_cert(lookup, false)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

        let old_serial = cert_record.serial.clone();
        let item_title = cert_record.title.clone()
            .ok_or_else(|| OpcaError::CertificateNotFound("No title".into()))?;

        let mut cert_bundle = self.retrieve_certbundle(&item_title)?
            .ok_or_else(|| OpcaError::CertificateNotFound(item_title.clone()))?;

        // Generate a new private key and CSR, preserving subject attributes
        cert_bundle.regenerate_key_and_csr(key_algorithm)?;

        let csr_pem = cert_bundle.csr_pem()
            .ok_or_else(|| OpcaError::Other(
                "CSR not available after rekeying".into(),
            ))?;

        let csr = X509Req::from_pem(csr_pem.as_bytes())
            .map_err(|e| OpcaError::Crypto(format!("Parse CSR: {e}")))?;

        let cert_type = cert_bundle.cert_type.clone();
        let (signed_cert, warnings) = self.issue_certificate(&csr, &cert_type, days)?;
        cert_bundle.update_certificate(signed_cert)?;

        // Update title with new serial
        let new_serial = cert_bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        let cn = cert_bundle.get_certificate_attrib("cn")?.unwrap_or_default();
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
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let cert = db.query_cert(lookup, true)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

        let item_serial = cert.serial.clone();

        let db = self.ca_database.as_mut().unwrap();
        db.process_ca_database(Some(&item_serial), false)?;

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

        let db = self.ca_database.as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        db.ignore_cert(serial, IgnoreReason::Manual, &by, note)?;

        self.store_ca_database()?;
        Ok(())
    }

    /// Clear the ignored state on a certificate (undo). Persists to 1Password.
    pub fn unignore_certificate(&mut self, serial: &str) -> Result<(), OpcaError> {
        info!("[ca] un-ignoring certificate {serial}");
        let db = self.ca_database.as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        db.unignore_cert(serial)?;

        self.store_ca_database()?;
        Ok(())
    }

    /// Generate a CRL, store it in 1Password, and optionally upload.
    pub fn generate_crl(&mut self) -> Result<String, OpcaError> {
        info!("[ca] generating CRL");
        let db = self.ca_database.as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        db.process_ca_database(None, false)?;

        let ca_config = db.get_config()?;
        let crl_days = ca_config.crl_days.unwrap_or(30) as u32;
        let crl_serial = db.increment_serial(SerialType::Crl, None)?;

        let ca_bundle = self.ca_bundle.as_ref()
            .ok_or_else(|| OpcaError::CaNotFound)?;
        let ca_cert = ca_bundle.certificate.as_ref()
            .ok_or_else(|| OpcaError::CaNotFound)?;
        let ca_key = ca_bundle.private_key.as_ref()
            .ok_or_else(|| OpcaError::Crypto("CA private key not available".into()))?;

        let entries = db.crl_entries()?;
        let crl_pem = build_crl(ca_cert, ca_key, crl_serial, crl_days, &entries)?;

        self.crl = Some(crl_pem.clone());

        // Persist CRL metadata to the database
        let issuer = ca_cert
            .subject_name()
            .entries()
            .map(|e| {
                let sn = e.object().nid().short_name().unwrap_or("?");
                let val = e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default();
                format!("{sn}={val}")
            })
            .collect::<Vec<_>>()
            .join(", ");

        let now = Asn1Time::days_from_now(0)?;
        let next = Asn1Time::days_from_now(crl_days)?;

        db.upsert_crl_metadata(&CrlMetadata {
            issuer: Some(issuer),
            last_update: asn1_time_to_openssl_str(&now),
            next_update: asn1_time_to_openssl_str(&next),
            crl_number: Some(crl_serial),
            revoked_count: Some(entries.len() as i64),
            revoked_json: None,
        })?;

        // Store CRL in 1Password
        self.op.store_document(
            self.op_config.crl_title,
            self.op_config.crl_filename,
            &crl_pem,
            StoreAction::Auto,
            None,
        )?;

        self.store_ca_database()?;

        Ok(crl_pem)
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
            match self.op.get_document(self.op_config.crl_title) {
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
            Some(0) => Err(OpcaError::Other("Certificate lifetime must be at least 1 day".into())),
            Some(days) => Ok(days),
            None => {
                let db = self.ca_database.as_ref()
                    .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
                let ca_days = db.get_config()?.days.unwrap_or(365) as u32;
                Ok(cert_type.default_days(ca_days))
            }
        }
    }

    fn issuance_warnings(&self, cert_type: &CertType, days: u32) -> Vec<CertIssuanceWarning> {
        let outlives_ca = self.ca_not_after().ok()
            .and_then(|ca_not_after| assess_cert_issuance(ca_not_after, days.into(), Utc::now()));
        outlives_ca.into_iter().chain(assess_apple_tls_limit(cert_type, days)).collect()
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
        let not_before = bundle.get_certificate_attrib("not_before")?.unwrap_or_default();
        let not_after = bundle.get_certificate_attrib("not_after")?.unwrap_or_default();

        let not_before_text = openssl_to_text(&not_before);
        let not_after_text = openssl_to_text(&not_after);

        // Update the CA item in 1Password
        let attributes = [
            format!("{}={cert_pem}", self.op_config.cert_item),
            format!("{}={not_before_text}", self.op_config.start_date_item),
            format!("{}={not_after_text}", self.op_config.expiry_date_item),
        ];
        let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();
        self.op.store_item(
            self.op_config.ca_title,
            Some(&attr_refs),
            StoreAction::Edit,
            self.op_config.category,
            None,
            None,
        )?;

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
        let subject = bundle.get_certificate_attrib("subject")?.unwrap_or_default();
        let not_before = bundle.get_certificate_attrib("not_before")?.unwrap_or_default();
        let not_after = bundle.get_certificate_attrib("not_after")?.unwrap_or_default();
        let serial = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        let csr_pem = bundle.csr_pem().unwrap_or_default();

        // 1Password expects human-readable Text format (e.g. "Jan 20 00:00:00 2026 UTC"),
        // but get_certificate_attrib returns Openssl format ("20260120000000Z").
        let not_before_text = openssl_to_text(&not_before);
        let not_after_text = openssl_to_text(&not_after);

        let mut attributes = vec![
            format!("{}={}", self.op_config.cert_type_item, bundle.cert_type),
            format!("{}={cn}", self.op_config.cn_item),
            format!("{}={subject}", self.op_config.subject_item),
            format!("{}={cert_pem}", self.op_config.cert_item),
            format!("{}={not_before_text}", self.op_config.start_date_item),
            format!("{}={not_after_text}", self.op_config.expiry_date_item),
            format!("{}={serial}", self.op_config.serial_item),
            format!("{}={csr_pem}", self.op_config.csr_item),
        ];

        if bundle.private_key.is_some() {
            let key_pem = bundle.private_key_pem()?;
            attributes.push(format!("{}={key_pem}", self.op_config.key_item));
        }

        if let Some(chain_pem) = bundle.chain_pem() {
            attributes.push(format!("{}={chain_pem}", self.op_config.chain_item));
        }

        let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();
        self.op.store_item(
            &op_title,
            Some(&attr_refs),
            StoreAction::Create,
            self.op_config.category,
            None,
            None,
        )?;

        // Add to database
        let db_item = format_db_item(bundle, item_title, issuer, issuer_subject)?;

        let db = self.ca_database.as_mut()
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
        let bundle = self.ca_bundle.as_ref()
            .ok_or_else(|| OpcaError::Other("No CA bundle".into()))?;

        let item_title = bundle.title.clone();
        let cert_type_str = bundle.cert_type.to_string();
        let cert_pem = bundle.certificate_pem()?;
        let cn = bundle.get_certificate_attrib("cn")?.unwrap_or_default();
        let subject = bundle.get_certificate_attrib("subject")?.unwrap_or_default();
        let not_before = bundle.get_certificate_attrib("not_before")?.unwrap_or_default();
        let not_after = bundle.get_certificate_attrib("not_after")?.unwrap_or_default();
        let serial = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        let csr_pem_str = bundle.csr_pem().unwrap_or_default();
        let has_key = bundle.private_key.is_some();
        let key_pem = if has_key { Some(bundle.private_key_pem()?) } else { None };
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

        let mut attributes = vec![
            format!("{}={cert_type_str}", self.op_config.cert_type_item),
            format!("{}={cn}", self.op_config.cn_item),
            format!("{}={subject}", self.op_config.subject_item),
            format!("{}={cert_pem}", self.op_config.cert_item),
            format!("{}={not_before_text}", self.op_config.start_date_item),
            format!("{}={not_after_text}", self.op_config.expiry_date_item),
            format!("{}={serial}", self.op_config.serial_item),
            format!("{}={csr_pem_str}", self.op_config.csr_item),
        ];

        if let Some(ref kp) = key_pem {
            attributes.push(format!("{}={kp}", self.op_config.key_item));
        }

        if let Some(ref cp) = chain_pem {
            attributes.push(format!("{}={cp}", self.op_config.chain_item));
        }

        let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();
        self.op.store_item(
            &op_title,
            Some(&attr_refs),
            StoreAction::Create,
            self.op_config.category,
            None,
            None,
        )?;

        let db = self.ca_database.as_mut()
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
    pub fn retrieve_certbundle(&self, item_title: &str) -> Result<Option<CertificateBundle>, OpcaError> {
        Self::retrieve_certbundle_static(&self.op, &self.op_config, item_title)
    }

    /// Static version for use during construction.
    fn retrieve_certbundle_static(
        op: &Op<R>,
        _op_config: &OpConf,
        item_title: &str,
    ) -> Result<Option<CertificateBundle>, OpcaError> {
        let json_str = match op.get_item(item_title, "json") {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };

        let obj: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| OpcaError::Other(format!("Parse item JSON: {e}")))?;

        let fields = match obj.get("fields").and_then(|f| f.as_array()) {
            Some(f) => f,
            None => return Ok(None),
        };

        let mut cert_pem: Option<Vec<u8>> = None;
        let mut key_pem: Option<Vec<u8>> = None;
        let mut csr_pem: Option<Vec<u8>> = None;
        let mut chain_pem: Option<Vec<u8>> = None;
        let mut cert_type_str: Option<String> = None;

        for field in fields {
            let label = field.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let value = field.get("value").and_then(|v| v.as_str()).unwrap_or("");

            match label {
                "certificate" if !value.is_empty() => {
                    cert_pem = Some(value.as_bytes().to_vec());
                }
                "private_key" if !value.is_empty() => {
                    key_pem = Some(value.as_bytes().to_vec());
                }
                "certificate_signing_request" if !value.is_empty() => {
                    csr_pem = Some(value.as_bytes().to_vec());
                }
                "certificate_chain" if !value.is_empty() => {
                    chain_pem = Some(value.as_bytes().to_vec());
                }
                "type" if !value.is_empty() => {
                    cert_type_str = Some(value.to_string());
                }
                _ => {}
            }
        }

        let cert_data = match cert_pem {
            Some(data) => data,
            None => return Ok(None),
        };

        let ct = cert_type_str
            .as_deref()
            .and_then(|s| s.parse::<CertType>().ok())
            .unwrap_or(CertType::Device);

        let mut bundle = CertificateBundle::import(
            ct,
            item_title,
            &cert_data,
            key_pem.as_deref(),
            csr_pem.as_deref(),
            None,
            CertBundleConfig::default(),
        )?;

        if let Some(ref cp) = chain_pem {
            bundle.set_chain_from_pem(cp)?;
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
        let db = self.ca_database.as_mut()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let mut record = db.query_cert(&CertLookup::Title(src_title.to_string()), false)?
            .ok_or_else(|| OpcaError::CertificateNotFound(src_title.to_string()))?;

        self.op.rename_item(src_title, dst_title)?;

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
            return Err(OpcaError::Other("The CA certificate cannot be deleted".into()));
        }
        if !matches!(cert.status.as_deref(), Some("Revoked" | "Expired")) {
            return Err(OpcaError::Other(format!(
                "Certificate {serial} is still valid; revoke it before deleting"
            )));
        }

        if let Some(title) = cert.title.as_deref() {
            match self.op.delete_item(title, true) {
                Ok(_) | Err(OpcaError::ItemNotFound(_)) => {}
                Err(e) => return Err(e),
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
        if record.status.as_deref() == Some("Pending") && self.op.item_exists(&title) {
            self.op.delete_item(&title, true)?;
        }
        db.delete_csr(id)?;
        self.store_ca_database()?;
        Ok(record)
    }

    /// Store the CA database in 1Password.
    pub fn store_ca_database(&mut self) -> Result<(), OpcaError> {
        self.update_db_fingerprint()?;

        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let sql_bytes = db.export_database()?;
        let sql_text = String::from_utf8_lossy(&sql_bytes).to_string();

        // Use Auto — during init/rebuild the document doesn't exist yet,
        // while during normal operation it does. Auto checks existence first.
        self.op.store_document(
            self.op_config.ca_database_title,
            self.op_config.ca_database_filename,
            &sql_text,
            StoreAction::Auto,
            None,
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
        let Some(uri) = self.private_store_uri()? else { return Ok(None) };
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let bytes = db.export_database_binary()?;
        let fingerprint = sha256_hex(&bytes);
        Ok(Some(PrivateStoreJob {
            bytes,
            uri,
            account: self.op.account().map(String::from),
            region: self.aws_region()?,
            fingerprint,
        }))
    }

    /// The configured private-store URI for this CA's database, or `None` when
    /// no private store is set.
    fn private_store_uri(&self) -> Result<Option<String>, OpcaError> {
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        Ok(db.get_config()?.ca_private_store.map(|store| {
            let vault_name = self.op.vault.trim().to_lowercase();
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
        let items_json = self.op.item_list(self.op_config.category, "json")?;
        let items: Vec<serde_json::Value> = serde_json::from_str(&items_json)
            .map_err(|e| OpcaError::Other(format!("Parse item list: {e}")))?;

        let mut result_map: HashMap<String, (X509, String, CertType)> = HashMap::new();
        let mut max_serial: i64 = 0;

        for item in &items {
            let title = match item.get("title").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => continue,
            };

            let bundle = match self.retrieve_certbundle(title)? {
                Some(b) => b,
                None => continue,
            };

            let serial_str = bundle
                .get_certificate_attrib("serial")?
                .unwrap_or_default();

            if result_map.contains_key(&serial_str) {
                return Err(OpcaError::DuplicateCertificate(format!(
                    "Duplicate serial {serial_str}"
                )));
            }

            let cert = bundle.certificate.clone().unwrap();
            let cert_type = bundle.cert_type.clone();
            result_map.insert(serial_str.clone(), (cert, title.to_string(), cert_type));

            if let Ok(s) = serial_str.parse::<i64>() {
                if s > max_serial {
                    max_serial = s;
                }
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
                    &cert.to_pem().map_err(|e| OpcaError::Crypto(format!("{e}")))?,
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
    pub fn upload_content(&self, content: &[u8], store_uri: &str) -> Result<(), OpcaError> {
        let creds = storage::needs_aws_credentials(store_uri)
            .then(|| self.aws_credentials())
            .transpose()?;
        let backend = storage::storage_from_uri_with_creds(store_uri, creds.as_ref())?;
        backend.upload(content, store_uri)
    }

    /// The AWS region configured for this CA, if any.
    pub fn aws_region(&self) -> Result<Option<String>, OpcaError> {
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        Ok(db.get_config()?.ca_aws_region)
    }

    /// The AWS credentials this operator has selected, with the CA's
    /// configured region applied.
    pub fn aws_credentials(&self) -> Result<storage::AwsCredentials, OpcaError> {
        storage::get_aws_credentials(
            self.op.runner(),
            self.op.account(),
            self.aws_region()?.as_deref(),
        )
    }

    /// Upload the CA database to the private store.
    pub fn upload_ca_database(&self, store_uri: &str) -> Result<(), OpcaError> {
        let uri = if store_uri.is_empty() {
            self.private_store_uri()?
                .ok_or_else(|| OpcaError::Storage("No private store configured".into()))?
        } else {
            store_uri.to_string()
        };

        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let binary_db = db.export_database_binary()?;
        self.upload_content(&binary_db, &uri)
    }

    /// Upload the CA certificate to the public store.
    pub fn upload_ca_cert(&self, store_uri: &str) -> Result<(), OpcaError> {
        let uri = if store_uri.is_empty() {
            let db = self.ca_database.as_ref()
                .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
            let config = db.get_config()?;
            let cfg_store = config.ca_public_store
                .ok_or_else(|| OpcaError::Storage("No public store configured".into()))?;
            format!("{}/{}", cfg_store.trim_end_matches('/'), DEFAULT_STORAGE_CONF.ca_cert_file)
        } else {
            store_uri.to_string()
        };

        let cert_pem = self.get_certificate()?;
        self.upload_content(cert_pem.as_bytes(), &uri)
    }

    /// Upload the CRL to the public store.
    pub fn upload_crl(&self, store_uri: &str) -> Result<(), OpcaError> {
        let uri = if store_uri.is_empty() {
            let db = self.ca_database.as_ref()
                .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
            let config = db.get_config()?;
            let cfg_store = config.ca_public_store
                .ok_or_else(|| OpcaError::Storage("No public store configured".into()))?;
            format!("{}/{}", cfg_store.trim_end_matches('/'), DEFAULT_STORAGE_CONF.crl_file)
        } else {
            store_uri.to_string()
        };

        let crl = self.crl.as_ref()
            .ok_or_else(|| OpcaError::CertificateNotFound("CRL not found".into()))?;
        self.upload_content(crl.as_bytes(), &uri)
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
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let config = db.get_config()?;

        let stores = [
            ("public", config.ca_public_store),
            ("private", config.ca_private_store),
            ("backup", config.ca_backup_store),
        ];

        // Check if any store needs S3 credentials so we only fetch once
        let needs_s3 = stores.iter().any(|(_, uri)| {
            uri.as_deref().is_some_and(|u| u.starts_with("s3://"))
        });

        let aws_creds = if needs_s3 {
            match storage::get_aws_credentials(
                self.op.runner(),
                self.op.account(),
                config.ca_aws_region.as_deref(),
            ) {
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

/// Critical digitalSignature, plus keyEncipherment for RSA keys only: ECDSA
/// keys cannot encipher, and some TLS stacks reject certs claiming they can.
fn leaf_key_usage(key_encipherment: bool) -> Result<openssl::x509::X509Extension, OpcaError> {
    let mut ku = KeyUsage::new();
    ku.critical().digital_signature();
    if key_encipherment {
        ku.key_encipherment();
    }
    ku.build().map_err(|e| OpcaError::Crypto(format!("{e}")))
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
    let cert = bundle.certificate.as_ref()
        .ok_or_else(|| OpcaError::InvalidCertificate("No certificate".into()))?;

    let cn = bundle.get_certificate_attrib("cn")?.unwrap_or_default();
    let serial = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
    let subject = bundle.get_certificate_attrib("subject")?.unwrap_or_default();
    let not_before = bundle.get_certificate_attrib("not_before")?;
    let not_after = bundle.get_certificate_attrib("not_after")?;
    let key_type = bundle.get_certificate_attrib("key_type")?;
    let key_size = bundle.get_certificate_attrib("key_size")?
        .and_then(|s| s.parse::<i64>().ok());
    let san = bundle.get_certificate_attrib("san")?;
    let issuer_str = bundle.get_certificate_attrib("issuer")?;

    // Check if expired
    let now = Asn1Time::days_from_now(0)
        .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
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
    })
}

/// Extension trait to convert a CertRecord to an ExternalCertRecord.
trait IntoExternal {
    fn into_external(self, issuer: Option<&str>, issuer_subject: Option<&str>) -> ExternalCertRecord;
}

impl IntoExternal for CertRecord {
    fn into_external(self, issuer: Option<&str>, issuer_subject: Option<&str>) -> ExternalCertRecord {
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

/// Build a CRL in PEM format using raw OpenSSL FFI.
///
/// The openssl crate (0.10.x) does not expose a CRL builder, so we use
/// the underlying `openssl-sys` bindings directly.
fn build_crl(
    ca_cert: &X509,
    ca_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    crl_number: i64,
    crl_days: u32,
    entries: &[CrlEntry],
) -> Result<String, OpcaError> {
    use openssl::x509::X509Crl;

    fn check(rc: std::os::raw::c_int, what: &str) -> Result<(), OpcaError> {
        if rc == 1 {
            Ok(())
        } else {
            Err(OpcaError::Crypto(format!("Failed to {what}")))
        }
    }

    let number = BigNum::from_dec_str(&crl_number.to_string())?.to_asn1_integer()?;
    let aki = authority_key_identifier(ca_cert)?;

    unsafe {
        let crl_ptr = openssl_sys::X509_CRL_new();
        if crl_ptr.is_null() {
            return Err(OpcaError::Crypto("Failed to create X509_CRL".into()));
        }
        let crl = X509Crl::from_ptr(crl_ptr);

        check(openssl_sys::X509_CRL_set_version(crl_ptr, 1), "set CRL version")?;
        check(
            openssl_sys::X509_CRL_set_issuer_name(crl_ptr, openssl_sys::X509_get_subject_name(ca_cert.as_ptr())),
            "set CRL issuer",
        )?;

        let last_update = Asn1Time::days_from_now(0)?;
        let next_update = Asn1Time::days_from_now(crl_days)?;
        check(openssl_sys::X509_CRL_set1_lastUpdate(crl_ptr, last_update.as_ptr()), "set CRL lastUpdate")?;
        check(openssl_sys::X509_CRL_set1_nextUpdate(crl_ptr, next_update.as_ptr()), "set CRL nextUpdate")?;

        for entry in entries {
            let serial = BigNum::from_dec_str(&entry.serial)
                .map_err(|e| OpcaError::Crypto(format!("Revoked serial: {e}")))?
                .to_asn1_integer()?;
            let revoked_at = Asn1Time::from_str_x509(&entry.revocation_date)?;

            let revoked_ptr = openssl_sys::X509_REVOKED_new();
            if revoked_ptr.is_null() {
                return Err(OpcaError::Crypto("Failed to create X509_REVOKED".into()));
            }
            openssl_sys::X509_REVOKED_set_serialNumber(revoked_ptr, serial.as_ptr());
            openssl_sys::X509_REVOKED_set_revocationDate(revoked_ptr, revoked_at.as_ptr());

            // add0 takes ownership of revoked_ptr only on success
            if openssl_sys::X509_CRL_add0_revoked(crl_ptr, revoked_ptr) != 1 {
                openssl_sys::X509_REVOKED_free(revoked_ptr);
                return Err(OpcaError::Crypto("Failed to add revoked entry".into()));
            }
        }
        openssl_sys::X509_CRL_sort(crl_ptr);

        check(
            openssl_sys::X509_CRL_add1_ext_i2d(crl_ptr, openssl_sys::NID_crl_number, number.as_ptr().cast(), 0, 0),
            "add CRL Number",
        )?;
        if let Some(aki) = aki {
            check(openssl_sys::X509_CRL_add_ext(crl_ptr, aki.as_ptr(), -1), "add Authority Key Identifier")?;
        }

        let md = signing_digest(ca_key).as_ptr();
        if openssl_sys::X509_CRL_sign(crl_ptr, ca_key.as_ptr(), md) == 0 {
            return Err(OpcaError::Crypto("Failed to sign CRL".into()));
        }

        String::from_utf8(crl.to_pem()?)
            .map_err(|e| OpcaError::Crypto(format!("CRL PEM not UTF-8: {e}")))
    }
}

/// The CRL's Authority Key Identifier: the CA's subject key identifier as `keyIdentifier`
/// (RFC 5280 §5.2.1). `None` for an imported CA certificate that carries no SKI.
fn authority_key_identifier(
    ca_cert: &X509,
) -> Result<Option<openssl::x509::X509Extension>, OpcaError> {
    use openssl::asn1::{Asn1Object, Asn1OctetString};

    let Some(ski) = ca_cert.subject_key_id() else {
        return Ok(None);
    };
    let key_id = ski.as_slice();
    let len = u8::try_from(key_id.len())
        .ok()
        .filter(|&n| n < 126)
        .ok_or_else(|| OpcaError::Crypto("CA subject key identifier too long".into()))?;
    // SEQUENCE { [0] IMPLICIT OCTET STRING keyIdentifier }
    let der = [&[0x30, len + 2, 0x80, len][..], key_id].concat();

    let oid = Asn1Object::from_str("2.5.29.35")?;
    let der = Asn1OctetString::new_from_bytes(&der)?;
    Ok(Some(openssl::x509::X509Extension::new_from_der(&oid, false, &der)?))
}

/// Compute SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Convenience: prepare a CA by retrieving it from 1Password.
pub fn prepare_cert_authority<R: CommandRunner>(op: Op<R>) -> Result<CertificateAuthority<R>, OpcaError> {
    CertificateAuthority::retrieve(op)
}

/// Parse CRL metadata from a PEM string without needing a full CA instance.
pub fn parse_crl_metadata(pem: &str) -> Result<CrlMetadata, OpcaError> {
    use openssl::x509::X509Crl;
    let crl = X509Crl::from_pem(pem.as_bytes())
        .map_err(|e| OpcaError::Crypto(format!("Failed to parse CRL PEM: {e}")))?;
    Ok(crl_metadata_from(&crl))
}

/// Pull metadata out of an already-parsed CRL — saves a redundant
/// `X509Crl::from_pem` call when the caller (e.g. `inspect_crl`) also needs
/// the parsed handle for other work.
pub fn crl_metadata_from(crl: &openssl::x509::X509Crl) -> CrlMetadata {
    let issuer = crl
        .issuer_name()
        .entries()
        .filter_map(|e| {
            let sn = e.object().nid().short_name().ok()?;
            let val = e.data().as_utf8().ok()?;
            Some(format!("{sn}={val}"))
        })
        .collect::<Vec<_>>()
        .join(", ");

    let last_update = asn1_time_to_openssl_str(crl.last_update());
    let next_update = crl.next_update().and_then(asn1_time_to_openssl_str);
    let revoked_count = crl.get_revoked().map(|stack| stack.len() as i64).unwrap_or(0);
    let crl_number = extract_crl_number(crl);

    CrlMetadata {
        issuer: Some(issuer),
        last_update,
        next_update,
        crl_number,
        revoked_count: Some(revoked_count),
        revoked_json: None,
    }
}

/// Render a CRL as `openssl crl -text -noout` style output. The openssl-rs
/// crate doesn't expose `X509_CRL_print`, and openssl-sys' handwritten
/// bindings stop short of CRL-printing helpers, so we declare the symbol
/// locally and call libcrypto directly.
pub fn crl_to_text(crl: &openssl::x509::X509Crl) -> Result<String, OpcaError> {
    use std::os::raw::{c_char, c_int};

    extern "C" {
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

/// Extract the CRL Number extension value from a parsed CRL.
fn extract_crl_number(crl: &openssl::x509::X509Crl) -> Option<i64> {
    unsafe {
        let crl_ptr = crl.as_ptr();
        let nid = openssl_sys::NID_crl_number;
        let idx = openssl_sys::X509_CRL_get_ext_by_NID(crl_ptr, nid, -1);
        if idx < 0 {
            return None;
        }
        let ext = openssl_sys::X509_CRL_get_ext(crl_ptr, idx);
        if ext.is_null() {
            return None;
        }
        let octet = openssl_sys::X509_EXTENSION_get_data(ext);
        if octet.is_null() {
            return None;
        }
        let data_ptr = openssl_sys::ASN1_STRING_get0_data(octet as *const _);
        let data_len = openssl_sys::ASN1_STRING_length(octet as *const _) as usize;
        if data_ptr.is_null() || data_len < 3 {
            return None;
        }
        let der = std::slice::from_raw_parts(data_ptr, data_len);
        // DER: 0x02 (INTEGER tag), length, value bytes
        if der[0] != 0x02 {
            return None;
        }
        let val_len = der[1] as usize;
        if der.len() < 2 + val_len {
            return None;
        }
        let mut num: i64 = 0;
        for &b in &der[2..2 + val_len] {
            num = (num << 8) | b as i64;
        }
        Some(num)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::cert::{CertBundleConfig, CertType, CertificateBundle, KeyAlgorithm};

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
        let device_bundle = CertificateBundle::generate(
            CertType::Device,
            "device.example.com",
            device_config,
        ).unwrap();

        let csr_pem = device_bundle.csr_pem().unwrap();
        let csr = X509Req::from_pem(csr_pem.as_bytes()).unwrap();

        // Sign with mock CA
        let mut ca = CertificateAuthority {
            op: crate::testutil::mock_op(vec![]),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
        };

        let signed = ca.sign_certificate(&csr, &CertType::Device, 365).unwrap();

        // Verify extensions
        let text = signed.to_text().unwrap();
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("CA:FALSE"), "Should have CA:FALSE");
        assert!(text.contains("Digital Signature"), "Should have Digital Signature");
        assert!(text.contains("TLS Web Client Authentication"), "Should have Client Auth");
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
        let ws_bundle = CertificateBundle::generate(
            CertType::WebServer,
            "www.example.com",
            ws_config,
        ).unwrap();

        let csr_pem = ws_bundle.csr_pem().unwrap();
        let csr = X509Req::from_pem(csr_pem.as_bytes()).unwrap();

        let mut ca = CertificateAuthority {
            op: crate::testutil::mock_op(vec![]),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
        };

        let signed = ca.sign_certificate(&csr, &CertType::WebServer, 365).unwrap();

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
        let vpn_bundle = CertificateBundle::generate(
            CertType::VpnClient,
            "vpn-client-1",
            vpn_config,
        ).unwrap();

        let csr_pem = vpn_bundle.csr_pem().unwrap();
        let csr = X509Req::from_pem(csr_pem.as_bytes()).unwrap();

        let mut ca = CertificateAuthority {
            op: crate::testutil::mock_op(vec![]),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
        };

        let signed = ca.sign_certificate(&csr, &CertType::VpnClient, 365).unwrap();

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
        let vpn_bundle = CertificateBundle::generate(
            CertType::VpnServer,
            "vpn-server",
            vpn_config,
        ).unwrap();

        let csr_pem = vpn_bundle.csr_pem().unwrap();
        let csr = X509Req::from_pem(csr_pem.as_bytes()).unwrap();

        let mut ca = CertificateAuthority {
            op: crate::testutil::mock_op(vec![]),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
        };

        let signed = ca.sign_certificate(&csr, &CertType::VpnServer, 365).unwrap();

        let text = signed.to_text().unwrap();
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("TLS Web Server Authentication"));
        assert!(text.contains("Key Encipherment"));
    }

    #[test]
    fn test_build_crl_empty() {
        let ca_bundle = make_ca_bundle();
        let ca_cert = ca_bundle.certificate.as_ref().unwrap();
        let ca_key = ca_bundle.private_key.as_ref().unwrap();

        let pem = build_crl(ca_cert, ca_key, 1, 30, &[]).unwrap();
        assert!(pem.contains("BEGIN X509 CRL"));
        assert!(pem.contains("END X509 CRL"));
    }

    fn ca_with_key(algorithm: KeyAlgorithm) -> CertificateAuthority<crate::testutil::MockRunner> {
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
            op: crate::testutil::mock_op(vec![]),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(ca_bundle),
            ca_database: Some(db),
            crl: None,
        }
    }

    fn sign(
        ca: &mut CertificateAuthority<crate::testutil::MockRunner>,
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
        ca.sign_certificate(leaf.csr.as_ref().unwrap(), &cert_type, 365).unwrap()
    }

    fn sign_leaf(ca: &mut CertificateAuthority<crate::testutil::MockRunner>, algorithm: KeyAlgorithm) -> X509 {
        sign(ca, CertType::WebServer, "www.example.com", &[], algorithm)
    }

    fn san_strings(cert: &X509) -> Vec<String> {
        san::of_certificate(cert).iter().map(|n| n.tagged()).collect()
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
            assert!(signed.verify(ca_key).unwrap(), "{ca_alg} CA → {leaf_alg} leaf");
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
        let pem = build_crl(bundle.certificate.as_ref().unwrap(), key, 1, 30, &[]).unwrap();
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
            &["10.0.0.5", "2001:db8::1", "ops@example.com", "spiffe://prod/web", "example.com"],
            KeyAlgorithm::EcP256,
        );
        assert_eq!(
            san_strings(&signed),
            [
                "DNS:www.example.com", "IP:10.0.0.5", "IP:2001:db8::1", "email:ops@example.com",
                "URI:spiffe://prod/web", "DNS:example.com",
            ]
        );
        let pem = signed.to_pem().unwrap();
        let bundle = CertificateBundle::import(
            CertType::WebServer, "www", &pem, None, None, None, CertBundleConfig::default(),
        )
        .unwrap();
        let stored = bundle.get_certificate_attrib("san").unwrap().unwrap();
        assert!(stored.contains("IP:2001:db8::1"), "{stored}");
    }

    #[test]
    fn an_ip_common_name_becomes_an_ip_san() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let signed = sign(&mut ca, CertType::Device, "192.168.1.20", &[], KeyAlgorithm::EcP256);
        assert_eq!(san_strings(&signed), ["IP:192.168.1.20"]);
    }

    #[test]
    fn vpn_clients_carry_their_csr_sans_but_not_their_cn() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let signed = sign(&mut ca, CertType::VpnClient, "Alex", &["alex@example.com"], KeyAlgorithm::EcP256);
        assert_eq!(san_strings(&signed), ["email:alex@example.com"]);
        let bare = sign(&mut ca, CertType::VpnClient, "Sam", &[], KeyAlgorithm::EcP256);
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
        for (cn, status) in [("pending.example.com", "Pending"), ("done.example.com", "Complete")] {
            db.add_csr(&CsrRecord {
                cn: Some(cn.to_string()),
                title: Some(format!("CSR_{cn}")),
                status: Some(status.to_string()),
                ..Default::default()
            })
            .unwrap();
        }

        ca.delete_csr(1).unwrap();
        ca.delete_csr(2).unwrap();

        let deletes: Vec<_> = ca.op.runner().calls().into_iter().filter(|c| c[..2] == ["item", "delete"]).collect();
        assert_eq!(deletes.len(), 1, "only the pending CSR's item is archived: {deletes:?}");
        assert_eq!(deletes[0][2], "CSR_pending.example.com");
        assert!(deletes[0].contains(&"--archive".to_string()));
        assert!(ca.ca_database.as_ref().unwrap().query_all_csrs(None).unwrap().is_empty());
    }

    fn ca_with_cert_rows() -> CertificateAuthority<crate::testutil::MockRunner> {
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
        assert!(ca.op.runner().calls().iter().all(|c| c[..2] != ["item", "delete"]));
        assert_eq!(ca.ca_database.as_ref().unwrap().count_certs().unwrap(), 4);
    }

    #[test]
    fn a_deleted_revoked_certificate_is_archived_hidden_and_still_on_the_crl() {
        let mut ca = ca_with_cert_rows();
        ca.delete_certificate("3").unwrap();

        let deletes: Vec<_> = ca.op.runner().calls().into_iter().filter(|c| c[..2] == ["item", "delete"]).collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0][2], "CRT_3_host3.example.com");
        assert!(deletes[0].contains(&"--archive".to_string()));

        let db = ca.ca_database.as_mut().unwrap();
        let listed: Vec<_> = db.query_all_certs().unwrap().into_iter().map(|c| c.serial).collect();
        assert_eq!(listed, ["1", "2", "4"]);
        let row = db.query_cert(&CertLookup::Serial("3".into()), false).unwrap().unwrap();
        assert!(row.deleted_at.is_some());
        assert_eq!(row.ignored_reason.as_deref(), Some("deleted"));

        db.process_ca_database(None, true).unwrap();
        assert!(db.certs_revoked.contains("3") && db.certs_deleted.contains("3"));
        assert_eq!(crl_serials(&ca.generate_crl().unwrap()), ["3"]);

        assert!(matches!(ca.delete_certificate("3"), Err(OpcaError::CertificateNotFound(_))));
    }

    fn crl_serials(pem: &str) -> Vec<String> {
        let crl = openssl::x509::X509Crl::from_pem(pem.as_bytes()).unwrap();
        crl.get_revoked()
            .map(|stack| {
                stack.iter().map(|r| r.serial_number().to_bn().unwrap().to_dec_str().unwrap().to_string()).collect()
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
        ca.delete_certificate("3").unwrap();

        let listed = crl_serials(&ca.generate_crl().unwrap());

        assert_eq!(listed, ["3"], "deleted stays listed; expired or undated revoked certs don't");
        let metadata = ca.ca_database.as_ref().unwrap().get_crl_metadata().unwrap().unwrap();
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
            (openssl_sys::X509_EXTENSION_get_critical(ext) == 1, data.as_slice().to_vec())
        }
    }

    #[test]
    fn each_crl_carries_the_next_crl_number_and_the_one_it_records() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        for expected in [1, 2] {
            let crl = openssl::x509::X509Crl::from_pem(ca.generate_crl().unwrap().as_bytes()).unwrap();
            assert_eq!(crl_extension(&crl, Nid::CRL_NUMBER), (false, vec![0x02, 0x01, expected as u8]));
            assert_eq!(extract_crl_number(&crl), Some(expected));
            let metadata = ca.ca_database.as_ref().unwrap().get_crl_metadata().unwrap().unwrap();
            assert_eq!(metadata.crl_number, Some(expected));
        }
        assert_eq!(ca.ca_database.as_ref().unwrap().get_config().unwrap().next_crl_serial, Some(3));
    }

    #[test]
    fn a_crl_names_its_signing_key_by_the_cas_subject_key_identifier() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP384);
        let crl = openssl::x509::X509Crl::from_pem(ca.generate_crl().unwrap().as_bytes()).unwrap();
        let ski = ca.ca_bundle.as_ref().unwrap().certificate.as_ref().unwrap().subject_key_id().unwrap().as_slice().to_vec();

        let (critical, der) = crl_extension(&crl, Nid::AUTHORITY_KEY_IDENTIFIER);
        assert!(!critical);
        assert_eq!(der, [&[0x30, 22, 0x80, 20][..], &ski].concat());
        let hex = ski.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        let text = crl_to_text(&crl).unwrap();
        assert!(text.contains("X509v3 Authority Key Identifier") && text.contains(&hex), "{text}");
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
        ca.generate_certificate_bundle(CertType::WebServer, "www.example.com", leaf, None).unwrap();
    }

    #[test]
    fn deleting_an_expired_certificate_tolerates_a_missing_item() {
        let mut ca = ca_with_cert_rows();
        ca.op = crate::testutil::mock_op(vec![crate::testutil::err_output(
            "[ERROR] \"CRT_4_host4.example.com\" isn't an item in the \"CA\" vault.",
        )]);
        ca.delete_certificate("4").unwrap();
        let db = ca.ca_database.as_ref().unwrap();
        assert!(db.query_all_certs().unwrap().iter().all(|c| c.serial != "4"));
    }

    #[test]
    fn ca_init_config_carries_its_key_algorithm() {
        let config = CaConfig { key_algorithm: Some(KeyAlgorithm::Rsa4096), ..CaConfig::default() };
        assert_eq!(ca_config_to_bundle(&config).key_algorithm, Some(KeyAlgorithm::Rsa4096));
    }

    // -----------------------------------------------------------------------
    // CA expiry warning tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_assess_ca_expiry_critical() {
        let now = chrono::Utc::now();
        let ca_not_after = now + chrono::Duration::days(15);
        let result = assess_ca_expiry(ca_not_after, 365, now);
        assert!(matches!(result, CaExpiryWarning::Critical { days_remaining: 15 }));
    }

    #[test]
    fn test_assess_ca_expiry_prominent() {
        let now = chrono::Utc::now();
        let ca_not_after = now + chrono::Duration::days(90);
        let result = assess_ca_expiry(ca_not_after, 365, now);
        assert!(matches!(result, CaExpiryWarning::Prominent { days_remaining: 90 }));
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
        let outlives_ca = assess_cert_issuance(now + chrono::Duration::days(200), 365, now).unwrap();
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
        db.update_config(&CaConfig { days: Some(ca_days), ..CaConfig::default() }).unwrap();
        let leaf = CertificateBundle::generate(
            cert_type.clone(),
            "leaf.example.com",
            CertBundleConfig { cn: Some("leaf.example.com".into()), ..CertBundleConfig::default() },
        )
        .unwrap();
        let (cert, warnings) =
            ca.issue_certificate(leaf.csr.as_ref().unwrap(), &cert_type, requested).unwrap();
        (cert.not_before().diff(cert.not_after()).unwrap().days, warnings)
    }

    #[test]
    fn server_certs_default_to_the_apple_limit_and_client_certs_to_the_ca_days() {
        assert_eq!(issued_days(3000, CertType::WebServer, None), (825, vec![]));
        assert_eq!(issued_days(3000, CertType::VpnServer, None), (825, vec![]));
        assert_eq!(issued_days(3000, CertType::Device, None), (3000, vec![]));
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
        assert!(issued_days(365, CertType::WebServer, Some(825)).1.is_empty());
        assert!(issued_days(365, CertType::Device, Some(3000)).1.is_empty());
    }

    #[test]
    fn a_zero_day_lifetime_is_refused() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let leaf = CertificateBundle::generate(
            CertType::Device,
            "d",
            CertBundleConfig { cn: Some("d".into()), ..CertBundleConfig::default() },
        )
        .unwrap();
        assert!(ca.issue_certificate(leaf.csr.as_ref().unwrap(), &CertType::Device, Some(0)).is_err());
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
