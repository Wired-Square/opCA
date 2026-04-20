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
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
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
use crate::services::cert::{asn1_time_to_openssl_str, CertBundleConfig, CertType, CertificateBundle};
use crate::services::database::models::{
    CaConfig, CertLookup, CertRecord, CrlMetadata, ExternalCertRecord, IgnoreReason, SerialType,
};
use crate::services::database::CertificateAuthorityDB;
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

/// Warning returned when a certificate would outlive the CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertIssuanceWarning {
    pub cert_not_after: String,
    pub ca_not_after: String,
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
            cert_not_after: cert_str.clone(),
            ca_not_after: ca_str.clone(),
            message: format!(
                "Warning: This certificate will expire on {cert_str} but the CA expires on {ca_str}. \
                 The certificate will become invalid when the CA expires."
            ),
        })
    } else {
        None
    }
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
    pub fn sign_certificate(
        &mut self,
        csr: &X509Req,
        cert_type: &CertType,
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
        let days = ca_config.days.unwrap_or(365) as u32;

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

                match cert_type {
                    CertType::AppleDev | CertType::Device => {
                        let ku = KeyUsage::new()
                            .critical()
                            .digital_signature()
                            .key_encipherment()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(ku)?;

                        let eku = ExtendedKeyUsage::new()
                            .client_auth()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(eku)?;

                        // SAN from CSR CN + any CSR SANs
                        self.add_san_from_csr(&mut builder, csr, ca_cert)?;
                    }
                    CertType::VpnClient => {
                        let ku = KeyUsage::new()
                            .critical()
                            .digital_signature()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(ku)?;

                        let eku = ExtendedKeyUsage::new()
                            .critical()
                            .client_auth()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(eku)?;
                    }
                    CertType::VpnServer => {
                        let ku = KeyUsage::new()
                            .critical()
                            .digital_signature()
                            .key_encipherment()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(ku)?;

                        let eku = ExtendedKeyUsage::new()
                            .critical()
                            .server_auth()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(eku)?;
                    }
                    CertType::WebServer => {
                        let ku = KeyUsage::new()
                            .critical()
                            .digital_signature()
                            .key_encipherment()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(ku)?;

                        let eku = ExtendedKeyUsage::new()
                            .server_auth()
                            .client_auth()
                            .build()
                            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;
                        builder.append_extension(eku)?;

                        // SAN from CSR
                        self.add_san_from_csr(&mut builder, csr, ca_cert)?;

                        // CRL Distribution Points
                        if let Some(ref crl_url) = ca_config.crl_url {
                            if !crl_url.is_empty() {
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
                        }

                        // Authority Information Access
                        if let Some(ref ca_url) = ca_config.ca_url {
                            if !ca_url.is_empty() {
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
                    }
                    _ => {}
                }
            }
        }

        builder.sign(ca_key, MessageDigest::sha256())
            .map_err(|e| OpcaError::Crypto(format!("Sign: {e}")))?;

        Ok(builder.build())
    }

    /// Add SAN extension to builder, using CN + any SANs from the CSR.
    fn add_san_from_csr(
        &self,
        builder: &mut X509Builder,
        csr: &X509Req,
        ca_cert: &X509,
    ) -> Result<(), OpcaError> {
        // Get CN from CSR subject
        let cn = csr
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string());

        let mut san = SubjectAlternativeName::new();
        if let Some(ref cn_str) = cn {
            san.dns(cn_str);
        }

        // Copy SANs from CSR extensions — parse the text representation
        // since the openssl crate doesn't expose CSR extension details directly
        let csr_text = csr.to_text()
            .map(|v| String::from_utf8_lossy(&v).to_string())
            .unwrap_or_default();
        for line in csr_text.lines() {
            let trimmed = line.trim();
            // Lines like "DNS:example.com, DNS:www.example.com"
            if trimmed.contains("DNS:") && !trimmed.starts_with("X509v3") {
                for part in trimmed.split(',') {
                    let part = part.trim();
                    if let Some(dns) = part.strip_prefix("DNS:") {
                        if cn.as_deref() != Some(dns) {
                            san.dns(dns);
                        }
                    }
                }
            }
        }

        let san_ext = san
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

    ) -> Result<(CertificateBundle, Option<CertIssuanceWarning>), OpcaError> {
        info!("[ca] generating {cert_type} certificate '{item_title}'");
        let mut bundle = CertificateBundle::generate(cert_type.clone(), item_title, config)?;

        let csr_pem = bundle.csr_pem().ok_or_else(|| {
            OpcaError::InvalidCertificate("CSR not generated".into())
        })?;
        let csr = X509Req::from_pem(csr_pem.as_bytes())
            .map_err(|e| OpcaError::Crypto(format!("Parse CSR: {e}")))?;

        let signed_cert = self.sign_certificate(&csr, &cert_type)?;
        bundle.update_certificate(signed_cert)?;

        // Update title to CRT_{serial}_{cn}
        let serial = bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        bundle.title = format!("CRT_{serial}_{item_title}");

        // Check if the cert will outlive the CA
        let warning = self.check_cert_issuance_warning();

        // Store in 1Password
        self.ca_bundle_for_store(Some(&bundle))?;
        self.store_certbundle_for(&bundle, None, None, true)?;

        Ok((bundle, warning))
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

    /// Renew a previously signed certificate from its stored CSR.
    ///
    /// Returns the renewed certificate PEM and an optional warning if the
    /// certificate would outlive the CA.
    pub fn renew_certificate_bundle(
        &mut self,
        lookup: &CertLookup,
    ) -> Result<(String, Option<CertIssuanceWarning>), OpcaError> {
        info!("[ca] renewing certificate {lookup:?}");
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let cert_record = db.query_cert(lookup, true)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

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
        let signed_cert = self.sign_certificate(&csr, &cert_type)?;
        cert_bundle.update_certificate(signed_cert)?;

        // Update title with new serial
        let new_serial = cert_bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        let cn = cert_bundle.get_certificate_attrib("cn")?.unwrap_or_default();
        cert_bundle.title = format!("CRT_{new_serial}_{cn}");

        // Check if the renewed cert will outlive the CA
        let warning = self.check_cert_issuance_warning();

        // The old serial row stays in the database untouched; once its
        // not_after passes, classification recognises the new Valid cert as
        // a same-CN replacement and marks the old row as superseded.
        self.store_certbundle_for(&cert_bundle, None, None, false)?;
        self.store_ca_database()?;

        let pem = cert_bundle.certificate_pem()?;
        Ok((pem, warning))
    }

    /// Rekey a previously signed certificate — generate a new private key and
    /// CSR, then sign it to produce a fresh certificate.
    ///
    /// Returns the rekeyed certificate PEM and an optional warning if the
    /// certificate would outlive the CA.
    pub fn rekey_certificate_bundle(
        &mut self,
        lookup: &CertLookup,
    ) -> Result<(String, Option<CertIssuanceWarning>), OpcaError> {
        info!("[ca] rekeying certificate {lookup:?}");
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let cert_record = db.query_cert(lookup, false)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

        let item_title = cert_record.title.clone()
            .ok_or_else(|| OpcaError::CertificateNotFound("No title".into()))?;

        let mut cert_bundle = self.retrieve_certbundle(&item_title)?
            .ok_or_else(|| OpcaError::CertificateNotFound(item_title.clone()))?;

        // Generate a new private key and CSR, preserving subject attributes
        cert_bundle.regenerate_key_and_csr()?;

        let csr_pem = cert_bundle.csr_pem()
            .ok_or_else(|| OpcaError::Other(
                "CSR not available after rekeying".into(),
            ))?;

        let csr = X509Req::from_pem(csr_pem.as_bytes())
            .map_err(|e| OpcaError::Crypto(format!("Parse CSR: {e}")))?;

        let cert_type = cert_bundle.cert_type.clone();
        let signed_cert = self.sign_certificate(&csr, &cert_type)?;
        cert_bundle.update_certificate(signed_cert)?;

        // Update title with new serial
        let new_serial = cert_bundle.get_certificate_attrib("serial")?.unwrap_or_default();
        let cn = cert_bundle.get_certificate_attrib("cn")?.unwrap_or_default();
        cert_bundle.title = format!("CRT_{new_serial}_{cn}");

        // Check if the rekeyed cert will outlive the CA
        let warning = self.check_cert_issuance_warning();

        // Store updated bundle (new key, CSR, and cert). The old serial row
        // stays untouched; once its not_after passes, classification will mark
        // it as superseded because this rekeyed cert shares the CN and is Valid.
        self.store_certbundle_for(&cert_bundle, None, None, false)?;
        self.store_ca_database()?;

        let pem = cert_bundle.certificate_pem()?;
        Ok((pem, warning))
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

        // Build CRL
        let crl_pem = build_crl(
            ca_cert,
            ca_key,
            crl_serial,
            crl_days,
            &db.certs_revoked,
            db,
        )?;

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
            revoked_count: Some(db.certs_revoked.len() as i64),
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

    /// Check if a certificate with the default lifetime would outlive the CA.
    fn check_cert_issuance_warning(&self) -> Option<CertIssuanceWarning> {
        let ca_not_after = self.ca_not_after().ok()?;
        let cert_days = self
            .ca_database
            .as_ref()
            .and_then(|db| db.get_config().ok())
            .and_then(|c| c.days)
            .unwrap_or(365);
        assess_cert_issuance(ca_not_after, cert_days, Utc::now())
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

    /// Delete a certificate bundle from 1Password.
    pub fn delete_certbundle(&mut self, item_title: &str, archive: bool) -> Result<(), OpcaError> {
        self.op.delete_item(item_title, archive)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Storage — database
    // -----------------------------------------------------------------------

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

        // Upload to private store if configured
        let ca_config = db.get_config()?;
        if ca_config.ca_private_store.is_some() {
            let _ = self.upload_ca_database("");
        }

        Ok(())
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
    pub fn upload_content(&self, content: &[u8], store_uri: &str) -> Result<(), OpcaError> {
        let backend = storage::storage_from_uri(store_uri, self.op.runner(), self.op.account())?;
        backend.upload(content, store_uri)
    }

    /// Upload the CA database to the private store.
    pub fn upload_ca_database(&self, store_uri: &str) -> Result<(), OpcaError> {
        let db = self.ca_database.as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;

        let uri = if store_uri.is_empty() {
            let config = db.get_config()?;
            let cfg_store = config.ca_private_store
                .ok_or_else(|| OpcaError::Storage("No private store configured".into()))?;
            let vault_name = self.op.vault.trim().to_lowercase();
            format!("{}/{vault_name}.sqlite", cfg_store.trim_end_matches('/'))
        } else {
            store_uri.to_string()
        };

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
            match storage::get_aws_credentials(self.op.runner(), self.op.account()) {
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

/// Convert a `CaConfig` (database model) into a `CertBundleConfig` (cert model).
fn ca_config_to_bundle(config: &CaConfig) -> CertBundleConfig {
    CertBundleConfig {
        cn: config.cn.clone(),
        key_size: None, // Uses default
        org: config.org.clone(),
        ou: config.ou.clone(),
        email: config.email.clone(),
        city: config.city.clone(),
        state: config.state.clone(),
        country: config.country.clone(),
        alt_dns_names: None,
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
    _crl_number: i64,
    crl_days: u32,
    revoked_serials: &std::collections::HashSet<String>,
    db: &CertificateAuthorityDB,
) -> Result<String, OpcaError> {
    use openssl::x509::X509Crl;

    unsafe {
        let crl_ptr = openssl_sys::X509_CRL_new();
        if crl_ptr.is_null() {
            return Err(OpcaError::Crypto("Failed to create X509_CRL".into()));
        }

        // Set version to v2 (value 1)
        if openssl_sys::X509_CRL_set_version(crl_ptr, 1) != 1 {
            openssl_sys::X509_CRL_free(crl_ptr);
            return Err(OpcaError::Crypto("Failed to set CRL version".into()));
        }

        // Set issuer
        if openssl_sys::X509_CRL_set_issuer_name(crl_ptr, openssl_sys::X509_get_subject_name(ca_cert.as_ptr())) != 1 {
            openssl_sys::X509_CRL_free(crl_ptr);
            return Err(OpcaError::Crypto("Failed to set CRL issuer".into()));
        }

        // Set lastUpdate and nextUpdate
        let last_update = Asn1Time::days_from_now(0)?;
        let next_update = Asn1Time::days_from_now(crl_days)?;

        if openssl_sys::X509_CRL_set1_lastUpdate(crl_ptr, last_update.as_ptr()) != 1 {
            openssl_sys::X509_CRL_free(crl_ptr);
            return Err(OpcaError::Crypto("Failed to set CRL lastUpdate".into()));
        }
        if openssl_sys::X509_CRL_set1_nextUpdate(crl_ptr, next_update.as_ptr()) != 1 {
            openssl_sys::X509_CRL_free(crl_ptr);
            return Err(OpcaError::Crypto("Failed to set CRL nextUpdate".into()));
        }

        // Add revoked certificates
        for serial_str in revoked_serials {
            let record = db.query_cert(&CertLookup::Serial(serial_str.clone()), false)?;
            if let Some(record) = record {
                if let Some(ref rev_date_str) = record.revocation_date {
                    let serial_bn = BigNum::from_dec_str(serial_str)
                        .map_err(|e| OpcaError::Crypto(format!("Revoked serial: {e}")))?;
                    let serial_asn1 = serial_bn.to_asn1_integer()?;
                    let rev_time = Asn1Time::from_str_x509(rev_date_str)?;

                    let revoked_ptr = openssl_sys::X509_REVOKED_new();
                    if revoked_ptr.is_null() {
                        openssl_sys::X509_CRL_free(crl_ptr);
                        return Err(OpcaError::Crypto("Failed to create X509_REVOKED".into()));
                    }

                    openssl_sys::X509_REVOKED_set_serialNumber(
                        revoked_ptr,
                        serial_asn1.as_ptr() as *mut _,
                    );
                    openssl_sys::X509_REVOKED_set_revocationDate(
                        revoked_ptr,
                        rev_time.as_ptr() as *mut _,
                    );

                    // add0 takes ownership of revoked_ptr
                    if openssl_sys::X509_CRL_add0_revoked(crl_ptr, revoked_ptr) != 1 {
                        openssl_sys::X509_REVOKED_free(revoked_ptr);
                        openssl_sys::X509_CRL_free(crl_ptr);
                        return Err(OpcaError::Crypto("Failed to add revoked entry".into()));
                    }
                }
            }
        }

        // Sort the revoked entries
        openssl_sys::X509_CRL_sort(crl_ptr);

        // Sign
        let md = openssl_sys::EVP_sha256();
        if openssl_sys::X509_CRL_sign(crl_ptr, ca_key.as_ptr() as *mut _, md) == 0 {
            openssl_sys::X509_CRL_free(crl_ptr);
            return Err(OpcaError::Crypto("Failed to sign CRL".into()));
        }

        // Convert to the safe wrapper and get PEM
        let crl = X509Crl::from_ptr(crl_ptr);
        let pem = crl.to_pem()?;

        String::from_utf8(pem)
            .map_err(|e| OpcaError::Crypto(format!("CRL PEM not UTF-8: {e}")))
    }
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

    let issuer = crl.issuer_name().entries()
        .filter_map(|e| {
            let sn = e.object().nid().short_name().ok()?;
            let val = e.data().as_utf8().ok()?;
            Some(format!("{sn}={val}"))
        })
        .collect::<Vec<_>>()
        .join(", ");

    let last_update = asn1_time_to_openssl_str(crl.last_update());
    let next_update = crl.next_update().and_then(asn1_time_to_openssl_str);
    let revoked_count = crl.get_revoked()
        .map(|stack| stack.len() as i64)
        .unwrap_or(0);

    // Extract CRL Number extension (OID 2.5.29.20 / NID_crl_number)
    let crl_number = extract_crl_number(&crl);

    Ok(CrlMetadata {
        issuer: Some(issuer),
        last_update,
        next_update,
        crl_number,
        revoked_count: Some(revoked_count),
        revoked_json: None,
    })
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
    use crate::services::cert::{CertBundleConfig, CertType, CertificateBundle};

    fn make_ca_bundle() -> CertificateBundle {
        let config = CertBundleConfig {
            cn: Some("Test CA".to_string()),
            key_size: Some(2048),
            org: Some("Test Org".to_string()),
            ou: None,
            email: None,
            city: None,
            state: None,
            country: Some("AU".to_string()),
            alt_dns_names: None,
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
            key_size: Some(2048),
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

        let signed = ca.sign_certificate(&csr, &CertType::Device).unwrap();

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
            key_size: Some(2048),
            alt_dns_names: Some(vec!["example.com".to_string()]),
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

        let signed = ca.sign_certificate(&csr, &CertType::WebServer).unwrap();

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
            key_size: Some(2048),
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

        let signed = ca.sign_certificate(&csr, &CertType::VpnClient).unwrap();

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
            key_size: Some(2048),
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

        let signed = ca.sign_certificate(&csr, &CertType::VpnServer).unwrap();

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

        let ca_config = CaConfig {
            next_serial: Some(2),
            days: Some(365),
            ..CaConfig::default()
        };
        let db = CertificateAuthorityDB::new(&ca_config).unwrap();
        let revoked = std::collections::HashSet::new();

        let pem = build_crl(ca_cert, ca_key, 1, 30, &revoked, &db).unwrap();
        assert!(pem.contains("BEGIN X509 CRL"));
        assert!(pem.contains("END X509 CRL"));
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
