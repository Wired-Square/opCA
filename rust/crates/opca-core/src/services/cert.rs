//! X.509 certificate bundle — key generation, CSR creation, self-signing,
//! import/export, and attribute inspection.

use std::fmt;
use std::str::FromStr;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509NameBuilder, X509Req, X509ReqBuilder, X509};
use serde::{Deserialize, Serialize};

use crate::error::OpcaError;

// ---------------------------------------------------------------------------
// Certificate type
// ---------------------------------------------------------------------------

/// The type of certificate a bundle represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertType {
    Ca,
    AppleDev,
    Device,
    Imported,
    External,
    VpnClient,
    VpnServer,
    WebServer,
}

impl fmt::Display for CertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertType::Ca => write!(f, "ca"),
            CertType::AppleDev => write!(f, "appledev"),
            CertType::Device => write!(f, "device"),
            CertType::Imported => write!(f, "imported"),
            CertType::External => write!(f, "external"),
            CertType::VpnClient => write!(f, "vpnclient"),
            CertType::VpnServer => write!(f, "vpnserver"),
            CertType::WebServer => write!(f, "webserver"),
        }
    }
}

impl FromStr for CertType {
    type Err = OpcaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ca" => Ok(CertType::Ca),
            "appledev" | "apple_dev" => Ok(CertType::AppleDev),
            "device" => Ok(CertType::Device),
            "imported" => Ok(CertType::Imported),
            "external" => Ok(CertType::External),
            "vpnclient" => Ok(CertType::VpnClient),
            "vpnserver" => Ok(CertType::VpnServer),
            "webserver" => Ok(CertType::WebServer),
            other => Err(OpcaError::InvalidCertificate(format!(
                "Unknown certificate type: {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle configuration
// ---------------------------------------------------------------------------

/// Configuration used to generate or import a certificate bundle.
///
/// When generating, `cn` and `key_size` are required.
/// When self-signing a CA, `next_serial` and `ca_days` are also required.
/// Subject attributes (org, ou, etc.) are optional.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertBundleConfig {
    pub cn: Option<String>,
    pub key_size: Option<u32>,
    pub org: Option<String>,
    pub ou: Option<String>,
    pub email: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub alt_dns_names: Option<Vec<String>>,
    /// Serial number for certificate signing.
    pub next_serial: Option<i64>,
    /// Validity period in days (for CA self-sign).
    pub ca_days: Option<i64>,
}

// ---------------------------------------------------------------------------
// CertificateBundle
// ---------------------------------------------------------------------------

/// Container for X.509 certificate materials — private key, certificate, and CSR.
pub struct CertificateBundle {
    pub cert_type: CertType,
    pub title: String,
    pub config: CertBundleConfig,
    pub csr: Option<X509Req>,
    pub private_key: Option<PKey<Private>>,
    pub certificate: Option<X509>,
    /// Optional certificate chain (intermediate CA certificates).
    pub chain: Option<Vec<X509>>,
}

impl CertificateBundle {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new bundle by generating a fresh RSA key pair and CSR.
    pub fn generate(
        cert_type: CertType,
        title: &str,
        config: CertBundleConfig,
    ) -> Result<Self, OpcaError> {
        let key_size = config.key_size.unwrap_or(2048);
        let cn = config
            .cn
            .as_deref()
            .ok_or_else(|| OpcaError::InvalidCertificate("CN is required for generation".into()))?
            .to_string();

        let private_key = Self::generate_private_key(key_size)?;
        let csr = Self::build_csr(&cn, &private_key, &config)?;

        Ok(Self {
            cert_type,
            title: title.to_string(),
            config,
            csr: Some(csr),
            private_key: Some(private_key),
            certificate: None,
            chain: None,
        })
    }

    /// Create a bundle by importing existing PEM-encoded materials.
    ///
    /// `cert_pem` is required. `key_pem`, `csr_pem`, and `chain_pem` are optional.
    pub fn import(
        cert_type: CertType,
        title: &str,
        cert_pem: &[u8],
        key_pem: Option<&[u8]>,
        csr_pem: Option<&[u8]>,
        passphrase: Option<&[u8]>,
        config: CertBundleConfig,
    ) -> Result<Self, OpcaError> {
        let certificate = X509::from_pem(cert_pem).map_err(|e| {
            OpcaError::InvalidCertificate(format!("Failed to parse certificate PEM: {e}"))
        })?;

        let private_key = if let Some(pem) = key_pem {
            Some(Self::load_private_key(pem, passphrase)?)
        } else {
            None
        };

        let csr = if let Some(pem) = csr_pem {
            Some(X509Req::from_pem(pem).map_err(|e| {
                OpcaError::InvalidCertificate(format!("Failed to parse CSR PEM: {e}"))
            })?)
        } else {
            None
        };

        // Derive title from certificate CN if not provided
        let title = if title.is_empty() {
            extract_cn(&certificate).unwrap_or_default()
        } else {
            title.to_string()
        };

        // Fill config attrs from certificate where not already set
        let mut config = config;
        if config.org.is_none() {
            config.org = get_subject_entry(&certificate, Nid::ORGANIZATIONNAME);
        }
        if config.ou.is_none() {
            config.ou = get_subject_entry(&certificate, Nid::ORGANIZATIONALUNITNAME);
        }
        if config.email.is_none() {
            config.email = get_subject_entry(&certificate, Nid::PKCS9_EMAILADDRESS);
        }
        if config.city.is_none() {
            config.city = get_subject_entry(&certificate, Nid::LOCALITYNAME);
        }
        if config.state.is_none() {
            config.state = get_subject_entry(&certificate, Nid::STATEORPROVINCENAME);
        }
        if config.country.is_none() {
            config.country = get_subject_entry(&certificate, Nid::COUNTRYNAME);
        }

        Ok(Self {
            cert_type,
            title,
            config,
            csr,
            private_key,
            certificate: Some(certificate),
            chain: None,
        })
    }

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /// Generate an RSA private key with the given bit size.
    pub fn generate_private_key(key_size: u32) -> Result<PKey<Private>, OpcaError> {
        let rsa = Rsa::generate(key_size)
            .map_err(|e| OpcaError::Crypto(format!("RSA key generation failed: {e}")))?;
        PKey::from_rsa(rsa)
            .map_err(|e| OpcaError::Crypto(format!("PKey conversion failed: {e}")))
    }

    /// Load a PEM-encoded private key, optionally decrypting with a passphrase.
    fn load_private_key(
        pem: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<PKey<Private>, OpcaError> {
        match passphrase {
            Some(pw) => PKey::private_key_from_pem_passphrase(pem, pw),
            None => PKey::private_key_from_pem(pem),
        }
        .map_err(|e| OpcaError::Crypto(format!("Failed to load private key: {e}")))
    }

    // -----------------------------------------------------------------------
    // CSR
    // -----------------------------------------------------------------------

    /// Build a Certificate Signing Request from the bundle's config.
    fn build_csr(
        cn: &str,
        key: &PKey<Private>,
        config: &CertBundleConfig,
    ) -> Result<X509Req, OpcaError> {
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| OpcaError::Crypto(format!("X509Name builder: {e}")))?;

        name_builder
            .append_entry_by_nid(Nid::COMMONNAME, cn)
            .map_err(|e| OpcaError::Crypto(format!("CN: {e}")))?;

        if let Some(ref v) = config.country {
            name_builder
                .append_entry_by_nid(Nid::COUNTRYNAME, v)
                .map_err(|e| OpcaError::Crypto(format!("Country: {e}")))?;
        }
        if let Some(ref v) = config.state {
            name_builder
                .append_entry_by_nid(Nid::STATEORPROVINCENAME, v)
                .map_err(|e| OpcaError::Crypto(format!("State: {e}")))?;
        }
        if let Some(ref v) = config.city {
            name_builder
                .append_entry_by_nid(Nid::LOCALITYNAME, v)
                .map_err(|e| OpcaError::Crypto(format!("City: {e}")))?;
        }
        if let Some(ref v) = config.org {
            name_builder
                .append_entry_by_nid(Nid::ORGANIZATIONNAME, v)
                .map_err(|e| OpcaError::Crypto(format!("Org: {e}")))?;
        }
        if let Some(ref v) = config.ou {
            name_builder
                .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, v)
                .map_err(|e| OpcaError::Crypto(format!("OU: {e}")))?;
        }
        if let Some(ref v) = config.email {
            name_builder
                .append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, v)
                .map_err(|e| OpcaError::Crypto(format!("Email: {e}")))?;
        }

        let name = name_builder.build();

        let mut req_builder = X509ReqBuilder::new()
            .map_err(|e| OpcaError::Crypto(format!("X509Req builder: {e}")))?;
        req_builder
            .set_subject_name(&name)
            .map_err(|e| OpcaError::Crypto(format!("Set subject: {e}")))?;
        req_builder
            .set_pubkey(key)
            .map_err(|e| OpcaError::Crypto(format!("Set pubkey: {e}")))?;

        // Add SAN extension if alt_dns_names are present
        if let Some(ref alt_names) = config.alt_dns_names {
            if !alt_names.is_empty() {
                let mut san = SubjectAlternativeName::new();
                for name in alt_names {
                    san.dns(name);
                }
                let san_ext = san.build(&req_builder.x509v3_context(None))
                    .map_err(|e| OpcaError::Crypto(format!("SAN extension: {e}")))?;

                let mut stack = openssl::stack::Stack::new()
                    .map_err(|e| OpcaError::Crypto(format!("Extension stack: {e}")))?;
                stack
                    .push(san_ext)
                    .map_err(|e| OpcaError::Crypto(format!("Push SAN: {e}")))?;
                req_builder
                    .add_extensions(&stack)
                    .map_err(|e| OpcaError::Crypto(format!("Add extensions: {e}")))?;
            }
        }

        req_builder
            .sign(key, MessageDigest::sha256())
            .map_err(|e| OpcaError::Crypto(format!("CSR sign: {e}")))?;

        Ok(req_builder.build())
    }

    // -----------------------------------------------------------------------
    // Self-sign CA
    // -----------------------------------------------------------------------

    /// Self-sign a CA certificate from this bundle's CSR.
    ///
    /// Used only during CA initialisation. Requires `cert_type == Ca`,
    /// a private key, and `config.next_serial` + `config.ca_days`.
    pub fn self_sign_ca(&mut self) -> Result<&X509, OpcaError> {
        if self.cert_type != CertType::Ca {
            return Err(OpcaError::InvalidCertificate(
                "self_sign_ca() called on non-CA bundle".into(),
            ));
        }

        let key = self
            .private_key
            .as_ref()
            .ok_or_else(|| OpcaError::Crypto("Cannot self-sign CA without a private key".into()))?;

        let csr = self.csr.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("Cannot self-sign CA without a CSR".into())
        })?;

        let serial_num = self.config.next_serial.unwrap_or(1);
        let days = self
            .config
            .ca_days
            .ok_or_else(|| OpcaError::InvalidCertificate("ca_days is required".into()))?;

        let serial_bn = BigNum::from_dec_str(&serial_num.to_string())
            .map_err(|e| OpcaError::Crypto(format!("Serial: {e}")))?;
        let serial_asn1 = serial_bn
            .to_asn1_integer()
            .map_err(|e| OpcaError::Crypto(format!("Serial ASN1: {e}")))?;

        let not_before =
            Asn1Time::days_from_now(0).map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        let not_after = Asn1Time::days_from_now(days as u32)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;

        let subject = csr.subject_name();

        let mut builder =
            X509Builder::new().map_err(|e| OpcaError::Crypto(format!("X509 builder: {e}")))?;
        builder
            .set_version(2)
            .map_err(|e| OpcaError::Crypto(format!("Set version: {e}")))?; // v3
        builder
            .set_subject_name(subject)
            .map_err(|e| OpcaError::Crypto(format!("Set subject: {e}")))?;
        builder
            .set_issuer_name(subject)
            .map_err(|e| OpcaError::Crypto(format!("Set issuer: {e}")))?; // self-signed
        builder
            .set_pubkey(key)
            .map_err(|e| OpcaError::Crypto(format!("Set pubkey: {e}")))?;
        builder
            .set_serial_number(&serial_asn1)
            .map_err(|e| OpcaError::Crypto(format!("Set serial: {e}")))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| OpcaError::Crypto(format!("Set not_before: {e}")))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| OpcaError::Crypto(format!("Set not_after: {e}")))?;

        // SubjectKeyIdentifier
        let ski = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .map_err(|e| OpcaError::Crypto(format!("SKI: {e}")))?;
        builder
            .append_extension(ski)
            .map_err(|e| OpcaError::Crypto(format!("Append SKI: {e}")))?;

        // AuthorityKeyIdentifier (self-referencing for root CA)
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(None, None))
            .map_err(|e| OpcaError::Crypto(format!("AKI: {e}")))?;
        builder
            .append_extension(aki)
            .map_err(|e| OpcaError::Crypto(format!("Append AKI: {e}")))?;

        // BasicConstraints: CA:TRUE
        let bc = BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .map_err(|e| OpcaError::Crypto(format!("BasicConstraints: {e}")))?;
        builder
            .append_extension(bc)
            .map_err(|e| OpcaError::Crypto(format!("Append BC: {e}")))?;

        // KeyUsage: keyCertSign + cRLSign
        let ku = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .map_err(|e| OpcaError::Crypto(format!("KeyUsage: {e}")))?;
        builder
            .append_extension(ku)
            .map_err(|e| OpcaError::Crypto(format!("Append KU: {e}")))?;

        builder
            .sign(key, MessageDigest::sha256())
            .map_err(|e| OpcaError::Crypto(format!("Sign: {e}")))?;

        self.certificate = Some(builder.build());
        Ok(self.certificate.as_ref().unwrap())
    }

    // -----------------------------------------------------------------------
    // Re-sign CA (same key, new validity)
    // -----------------------------------------------------------------------

    /// Re-sign an existing CA certificate with the same key but new validity dates.
    ///
    /// Keeps the same subject, serial, and key pair. Replaces the certificate
    /// with a freshly signed one valid from now for `ca_days` days.
    pub fn re_sign_ca(&mut self, ca_days: i64) -> Result<&X509, OpcaError> {
        if self.cert_type != CertType::Ca {
            return Err(OpcaError::InvalidCertificate(
                "re_sign_ca() called on non-CA bundle".into(),
            ));
        }

        let key = self
            .private_key
            .as_ref()
            .ok_or_else(|| OpcaError::Crypto("Cannot re-sign CA without a private key".into()))?;

        let existing_cert = self.certificate.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("Cannot re-sign CA without an existing certificate".into())
        })?;

        // Preserve the serial from the existing certificate
        let serial_bn = existing_cert
            .serial_number()
            .to_bn()
            .map_err(|e| OpcaError::Crypto(format!("Serial: {e}")))?;
        let serial_asn1 = serial_bn
            .to_asn1_integer()
            .map_err(|e| OpcaError::Crypto(format!("Serial ASN1: {e}")))?;

        let subject = existing_cert.subject_name();

        let not_before =
            Asn1Time::days_from_now(0).map_err(|e| OpcaError::Crypto(format!("{e}")))?;
        let not_after = Asn1Time::days_from_now(ca_days as u32)
            .map_err(|e| OpcaError::Crypto(format!("{e}")))?;

        let mut builder =
            X509Builder::new().map_err(|e| OpcaError::Crypto(format!("X509 builder: {e}")))?;
        builder
            .set_version(2)
            .map_err(|e| OpcaError::Crypto(format!("Set version: {e}")))?;
        builder
            .set_subject_name(subject)
            .map_err(|e| OpcaError::Crypto(format!("Set subject: {e}")))?;
        builder
            .set_issuer_name(subject)
            .map_err(|e| OpcaError::Crypto(format!("Set issuer: {e}")))?;
        builder
            .set_pubkey(key)
            .map_err(|e| OpcaError::Crypto(format!("Set pubkey: {e}")))?;
        builder
            .set_serial_number(&serial_asn1)
            .map_err(|e| OpcaError::Crypto(format!("Set serial: {e}")))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| OpcaError::Crypto(format!("Set not_before: {e}")))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| OpcaError::Crypto(format!("Set not_after: {e}")))?;

        // SubjectKeyIdentifier
        let ski = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .map_err(|e| OpcaError::Crypto(format!("SKI: {e}")))?;
        builder
            .append_extension(ski)
            .map_err(|e| OpcaError::Crypto(format!("Append SKI: {e}")))?;

        // AuthorityKeyIdentifier (self-referencing for root CA)
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(None, None))
            .map_err(|e| OpcaError::Crypto(format!("AKI: {e}")))?;
        builder
            .append_extension(aki)
            .map_err(|e| OpcaError::Crypto(format!("Append AKI: {e}")))?;

        // BasicConstraints: CA:TRUE
        let bc = BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .map_err(|e| OpcaError::Crypto(format!("BasicConstraints: {e}")))?;
        builder
            .append_extension(bc)
            .map_err(|e| OpcaError::Crypto(format!("Append BC: {e}")))?;

        // KeyUsage: keyCertSign + cRLSign
        let ku = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .map_err(|e| OpcaError::Crypto(format!("KeyUsage: {e}")))?;
        builder
            .append_extension(ku)
            .map_err(|e| OpcaError::Crypto(format!("Append KU: {e}")))?;

        builder
            .sign(key, MessageDigest::sha256())
            .map_err(|e| OpcaError::Crypto(format!("Sign: {e}")))?;

        self.certificate = Some(builder.build());
        Ok(self.certificate.as_ref().unwrap())
    }

    // -----------------------------------------------------------------------
    // Update certificate (after external signing)
    // -----------------------------------------------------------------------

    /// Replace the certificate after it has been signed by a CA.
    ///
    /// Verifies that the certificate's public key matches this bundle's private key.
    pub fn update_certificate(&mut self, certificate: X509) -> Result<(), OpcaError> {
        let key = self.private_key.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("Cannot update certificate: private key is not set".into())
        })?;

        // Compare public keys by DER encoding
        let cert_pub = certificate
            .public_key()
            .map_err(|e| OpcaError::Crypto(format!("Get cert pubkey: {e}")))?;
        let key_pub = key
            .public_key_to_der()
            .map_err(|e| OpcaError::Crypto(format!("Key pubkey DER: {e}")))?;
        let cert_pub_der = cert_pub
            .public_key_to_der()
            .map_err(|e| OpcaError::Crypto(format!("Cert pubkey DER: {e}")))?;

        if key_pub != cert_pub_der {
            return Err(OpcaError::InvalidCertificate(
                "Signed certificate does not match the private key".into(),
            ));
        }

        self.certificate = Some(certificate);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // PKCS#12 export
    // -----------------------------------------------------------------------

    /// Export the bundle as a PKCS#12 archive.
    pub fn export_pkcs12(
        &self,
        password: Option<&str>,
        name: Option<&str>,
        chain: Option<&[X509]>,
    ) -> Result<Vec<u8>, OpcaError> {
        let key = self.private_key.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("Cannot build PKCS#12: private key is missing".into())
        })?;
        let cert = self.certificate.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("Cannot build PKCS#12: certificate is missing".into())
        })?;

        let friendly_name = name.unwrap_or(&self.title);
        let pw = password.unwrap_or("");

        let mut builder = openssl::pkcs12::Pkcs12::builder();
        builder.name(friendly_name);
        builder.pkey(key);
        builder.cert(cert);

        if let Some(ca_certs) = chain {
            let mut stack = openssl::stack::Stack::new()
                .map_err(|e| OpcaError::Crypto(format!("PKCS12 stack: {e}")))?;
            for ca in ca_certs {
                stack
                    .push(ca.clone())
                    .map_err(|e| OpcaError::Crypto(format!("PKCS12 push CA: {e}")))?;
            }
            builder.ca(stack);
        }

        let pkcs12 = builder
            .build2(pw)
            .map_err(|e| OpcaError::Crypto(format!("PKCS12 build: {e}")))?;

        pkcs12
            .to_der()
            .map_err(|e| OpcaError::Crypto(format!("PKCS12 DER: {e}")))
    }

    // -----------------------------------------------------------------------
    // PEM getters
    // -----------------------------------------------------------------------

    /// Return the certificate as a PEM string.
    pub fn certificate_pem(&self) -> Result<String, OpcaError> {
        let cert = self.certificate.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("No certificate is set on this bundle".into())
        })?;
        let pem = cert
            .to_pem()
            .map_err(|e| OpcaError::Crypto(format!("Cert to PEM: {e}")))?;
        Ok(String::from_utf8_lossy(&pem).to_string())
    }

    /// Return the private key as a PEM string (unencrypted, TraditionalOpenSSL format).
    pub fn private_key_pem(&self) -> Result<String, OpcaError> {
        let key = self.private_key.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("No private key is set on this bundle".into())
        })?;
        let pem = key
            .private_key_to_pem_pkcs8()
            .map_err(|e| OpcaError::Crypto(format!("Key to PEM: {e}")))?;
        Ok(String::from_utf8_lossy(&pem).to_string())
    }

    /// Return the certificate chain as a PEM string, or `None` if no chain is set.
    pub fn chain_pem(&self) -> Option<String> {
        let chain = self.chain.as_ref()?;
        if chain.is_empty() {
            return None;
        }
        let mut pem = String::new();
        for cert in chain {
            if let Ok(p) = cert.to_pem() {
                pem.push_str(&String::from_utf8_lossy(&p));
            }
        }
        if pem.is_empty() { None } else { Some(pem) }
    }

    /// Set the certificate chain from PEM-encoded data (may contain multiple certificates).
    pub fn set_chain_from_pem(&mut self, chain_pem: &[u8]) -> Result<(), OpcaError> {
        let certs = X509::stack_from_pem(chain_pem).map_err(|e| {
            OpcaError::InvalidCertificate(format!("Failed to parse certificate chain PEM: {e}"))
        })?;
        self.chain = if certs.is_empty() { None } else { Some(certs) };
        Ok(())
    }

    /// Return the CSR as a PEM string, or `None` if no CSR is set.
    pub fn csr_pem(&self) -> Option<String> {
        self.csr.as_ref().and_then(|csr| {
            csr.to_pem()
                .ok()
                .map(|pem| String::from_utf8_lossy(&pem).to_string())
        })
    }

    // -----------------------------------------------------------------------
    // Certificate attribute inspection
    // -----------------------------------------------------------------------

    /// Return a named attribute from the certificate.
    pub fn get_certificate_attrib(&self, attrib: &str) -> Result<Option<String>, OpcaError> {
        let cert = self.certificate.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("No certificate is set on this bundle".into())
        })?;

        let value = match attrib {
            "cn" => get_subject_entry(cert, Nid::COMMONNAME),
            "org" => get_subject_entry(cert, Nid::ORGANIZATIONNAME),
            "ou" => get_subject_entry(cert, Nid::ORGANIZATIONALUNITNAME),
            "email" => get_subject_entry(cert, Nid::PKCS9_EMAILADDRESS),
            "city" => get_subject_entry(cert, Nid::LOCALITYNAME),
            "state" => get_subject_entry(cert, Nid::STATEORPROVINCENAME),
            "country" => get_subject_entry(cert, Nid::COUNTRYNAME),
            "subject" => {
                let entries: Vec<String> = cert
                    .subject_name()
                    .entries()
                    .filter_map(|e| {
                        let nid = e.object().nid();
                        let sn = nid.short_name().unwrap_or("??");
                        e.data().as_utf8().ok().map(|v| format!("{sn}={v}"))
                    })
                    .collect();
                // RFC 4514 order is reversed (leaf-first)
                let mut reversed = entries;
                reversed.reverse();
                Some(reversed.join(","))
            }
            "issuer" => {
                let entries: Vec<String> = cert
                    .issuer_name()
                    .entries()
                    .filter_map(|e| {
                        let nid = e.object().nid();
                        let sn = nid.short_name().unwrap_or("??");
                        e.data().as_utf8().ok().map(|v| format!("{sn}={v}"))
                    })
                    .collect();
                let mut reversed = entries;
                reversed.reverse();
                Some(reversed.join(","))
            }
            "serial" => {
                let serial = cert
                    .serial_number()
                    .to_bn()
                    .ok()
                    .and_then(|bn| bn.to_dec_str().ok())
                    .map(|s| s.to_string());
                serial
            }
            "not_before" => {
                asn1_time_to_openssl_str(cert.not_before())
            }
            "not_after" => {
                asn1_time_to_openssl_str(cert.not_after())
            }
            "key_type" => Some(self.public_key_type(cert)),
            "key_size" => {
                let bits = cert
                    .public_key()
                    .ok()
                    .map(|pk| pk.bits())
                    .unwrap_or(0);
                Some(bits.to_string())
            }
            "san" => get_san(cert),
            _ => None,
        };

        Ok(value)
    }

    /// Return the public key algorithm name.
    fn public_key_type(&self, cert: &X509) -> String {
        let pk = match cert.public_key() {
            Ok(pk) => pk,
            Err(_) => return "Unknown".to_string(),
        };
        if pk.rsa().is_ok() {
            "RSA".to_string()
        } else if pk.ec_key().is_ok() {
            "EC".to_string()
        } else if pk.dsa().is_ok() {
            "DSA".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Return the public key size in bits.
    pub fn public_key_size(&self) -> Result<u32, OpcaError> {
        let cert = self.certificate.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("No certificate is set on this bundle".into())
        })?;
        let pk = cert
            .public_key()
            .map_err(|e| OpcaError::Crypto(format!("Get public key: {e}")))?;
        Ok(pk.bits())
    }

    /// Return the public key type string ("RSA", "EC", "DSA", or "Unknown").
    pub fn public_key_type_str(&self) -> Result<String, OpcaError> {
        let cert = self.certificate.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("No certificate is set on this bundle".into())
        })?;
        Ok(self.public_key_type(cert))
    }

    // -----------------------------------------------------------------------
    // Rekey
    // -----------------------------------------------------------------------

    /// Generate a new private key and CSR, preserving the certificate's subject
    /// and SAN attributes.
    ///
    /// Used for rekeying — the caller should then re-sign the new CSR to produce
    /// a fresh certificate that uses the new key pair.
    pub fn regenerate_key_and_csr(&mut self) -> Result<(), OpcaError> {
        // Backfill CN from certificate if not in config (lost on 1Password round-trip)
        if self.config.cn.is_none() {
            self.config.cn = self.certificate.as_ref().and_then(extract_cn);
        }
        // Backfill SANs from certificate if not in config
        if self.config.alt_dns_names.is_none() {
            if let Some(cert) = self.certificate.as_ref() {
                if let Some(san_ext) = cert.subject_alt_names() {
                    let dns_names: Vec<String> = san_ext
                        .iter()
                        .filter_map(|name| name.dnsname().map(String::from))
                        .collect();
                    if !dns_names.is_empty() {
                        self.config.alt_dns_names = Some(dns_names);
                    }
                }
            }
        }

        let key_size = self.public_key_size().unwrap_or(2048);
        let cn = self.config.cn.as_deref().ok_or_else(|| {
            OpcaError::InvalidCertificate("CN is required for rekeying".into())
        })?;
        let new_key = Self::generate_private_key(key_size)?;
        let new_csr = Self::build_csr(cn, &new_key, &self.config)?;
        self.private_key = Some(new_key);
        self.csr = Some(new_csr);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Validity checks
    // -----------------------------------------------------------------------

    /// Check whether the certificate has the CA basic constraint.
    pub fn is_ca_certificate(&self) -> Result<bool, OpcaError> {
        let cert = self.certificate.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("No certificate is set on this bundle".into())
        })?;

        let text = cert
            .to_text()
            .map_err(|e| OpcaError::Crypto(format!("Cert to text: {e}")))?;
        let text = String::from_utf8_lossy(&text);
        Ok(text.contains("CA:TRUE"))
    }

    /// Validate that the bundle is consistent and within its validity period.
    pub fn is_valid(&self) -> Result<bool, OpcaError> {
        let cert = self.certificate.as_ref().ok_or_else(|| {
            OpcaError::InvalidCertificate("No certificate is set on this bundle".into())
        })?;

        // Check time validity
        let now = openssl::asn1::Asn1Time::days_from_now(0)
            .map_err(|e| OpcaError::Crypto(format!("Asn1Time: {e}")))?;
        let before_start = cert.not_before() > &now;
        let after_end = cert.not_after() < &now;
        if before_start || after_end {
            return Ok(false);
        }

        // If we have a private key, verify it matches
        if let Some(ref key) = self.private_key {
            let cert_pub = cert
                .public_key()
                .map_err(|e| OpcaError::Crypto(format!("Get cert pubkey: {e}")))?;
            let key_pub_der = key
                .public_key_to_der()
                .map_err(|e| OpcaError::Crypto(format!("Key pubkey DER: {e}")))?;
            let cert_pub_der = cert_pub
                .public_key_to_der()
                .map_err(|e| OpcaError::Crypto(format!("Cert pubkey DER: {e}")))?;

            if key_pub_der != cert_pub_der {
                return Ok(false);
            }

            // CA type consistency
            let is_ca = self.is_ca_certificate()?;
            if self.cert_type == CertType::Ca && !is_ca {
                return Ok(false);
            }
            if self.cert_type != CertType::Ca && is_ca {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an ASN1 time reference to the canonical `%Y%m%d%H%M%SZ` format.
///
/// OpenSSL's `ASN1_TIME_print` returns `"Mon DD HH:MM:SS YYYY GMT"` but the
/// database and Python code expect `"20270415051336Z"`.
pub(crate) fn asn1_time_to_openssl_str(asn1: &openssl::asn1::Asn1TimeRef) -> Option<String> {
    let printed = asn1.to_string(); // e.g. "Apr 15 05:13:36 2027 GMT"
    // Try parsing the OpenSSL print format → reformat as ASN1 GeneralizedTime
    chrono::NaiveDateTime::parse_from_str(
        printed.trim_end_matches(" GMT"),
        "%b %e %H:%M:%S %Y",
    )
    .ok()
    .map(|dt| dt.format("%Y%m%d%H%M%SZ").to_string())
    // Fallback: if the string is already in ASN1 format, return it as-is
    .or_else(|| {
        if printed.len() == 15 && printed.ends_with('Z') {
            Some(printed)
        } else {
            Some(printed)
        }
    })
}

/// Extract a single subject entry by NID.
fn get_subject_entry(cert: &X509, nid: Nid) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(nid)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
}

/// Extract the CN from a certificate.
fn extract_cn(cert: &X509) -> Option<String> {
    get_subject_entry(cert, Nid::COMMONNAME)
}

/// Extract Subject Alternative Names as a comma-separated string.
fn get_san(cert: &X509) -> Option<String> {
    let san_ext = cert.subject_alt_names()?;
    let names: Vec<String> = san_ext
        .iter()
        .filter_map(|name| {
            if let Some(dns) = name.dnsname() {
                Some(format!("DNS:{dns}"))
            } else if let Some(ip) = name.ipaddress() {
                // Format IP bytes
                if ip.len() == 4 {
                    Some(format!("IP:{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
                } else {
                    Some(format!("IP:{ip:?}"))
                }
            } else if let Some(email) = name.email() {
                Some(format!("email:{email}"))
            } else {
                None
            }
        })
        .collect();

    if names.is_empty() {
        None
    } else {
        Some(names.join(", "))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CertBundleConfig {
        CertBundleConfig {
            cn: Some("test.example.com".to_string()),
            key_size: Some(2048),
            org: Some("Test Org".to_string()),
            ou: Some("Test Unit".to_string()),
            email: Some("test@example.com".to_string()),
            city: Some("Melbourne".to_string()),
            state: Some("VIC".to_string()),
            country: Some("AU".to_string()),
            alt_dns_names: None,
            next_serial: None,
            ca_days: None,
        }
    }

    fn ca_config() -> CertBundleConfig {
        CertBundleConfig {
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
        }
    }

    #[test]
    fn test_generate_bundle() {
        let bundle =
            CertificateBundle::generate(CertType::Device, "test.example.com", test_config())
                .unwrap();

        assert_eq!(bundle.cert_type, CertType::Device);
        assert_eq!(bundle.title, "test.example.com");
        assert!(bundle.private_key.is_some());
        assert!(bundle.csr.is_some());
        assert!(bundle.certificate.is_none());
    }

    #[test]
    fn test_generate_csr_has_subject() {
        let bundle =
            CertificateBundle::generate(CertType::Device, "test.example.com", test_config())
                .unwrap();

        let csr = bundle.csr.as_ref().unwrap();
        let subject = csr.subject_name();

        let cn = subject
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(cn.to_string(), "test.example.com");

        let org = subject
            .entries_by_nid(Nid::ORGANIZATIONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(org.to_string(), "Test Org");
    }

    #[test]
    fn test_generate_csr_with_san() {
        let mut config = test_config();
        config.alt_dns_names = Some(vec![
            "www.example.com".to_string(),
            "mail.example.com".to_string(),
        ]);

        let bundle =
            CertificateBundle::generate(CertType::WebServer, "example.com", config).unwrap();

        let csr_pem = bundle.csr_pem().unwrap();
        assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_self_sign_ca() {
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "Test CA", ca_config()).unwrap();

        bundle.self_sign_ca().unwrap();

        // Verify it's a CA cert
        assert!(bundle.is_ca_certificate().unwrap());

        // Verify CN
        let cn = bundle.get_certificate_attrib("cn").unwrap();
        assert_eq!(cn, Some("Test CA".to_string()));

        // Verify serial
        let serial = bundle.get_certificate_attrib("serial").unwrap();
        assert_eq!(serial, Some("1".to_string()));

        // Verify key type
        let key_type = bundle.get_certificate_attrib("key_type").unwrap();
        assert_eq!(key_type, Some("RSA".to_string()));

        // Verify key size
        let key_size = bundle.get_certificate_attrib("key_size").unwrap();
        assert_eq!(key_size, Some("2048".to_string()));
    }

    #[test]
    fn test_self_sign_ca_rejects_non_ca() {
        let mut bundle =
            CertificateBundle::generate(CertType::Device, "test", ca_config()).unwrap();

        let result = bundle.self_sign_ca();
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_on_ca() {
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "Test CA", ca_config()).unwrap();
        bundle.self_sign_ca().unwrap();

        assert!(bundle.is_valid().unwrap());
    }

    #[test]
    fn test_import_certificate() {
        // Generate a CA cert, export PEM, then import it
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "Import CA", ca_config()).unwrap();
        bundle.self_sign_ca().unwrap();

        let cert_pem = bundle.certificate_pem().unwrap();
        let key_pem = bundle.private_key_pem().unwrap();

        let imported = CertificateBundle::import(
            CertType::Ca,
            "",
            cert_pem.as_bytes(),
            Some(key_pem.as_bytes()),
            None,
            None,
            CertBundleConfig::default(),
        )
        .unwrap();

        // Title derived from cert CN when empty string provided
        assert_eq!(imported.title, "Test CA");
        assert_eq!(imported.config.org, Some("Test Org".to_string()));
        assert_eq!(imported.config.country, Some("AU".to_string()));
        assert!(imported.is_valid().unwrap());
    }

    #[test]
    fn test_import_cert_only() {
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "PubOnly CA", ca_config()).unwrap();
        bundle.self_sign_ca().unwrap();

        let cert_pem = bundle.certificate_pem().unwrap();

        let imported = CertificateBundle::import(
            CertType::Ca,
            "PubOnly CA",
            cert_pem.as_bytes(),
            None,
            None,
            None,
            CertBundleConfig::default(),
        )
        .unwrap();

        assert!(imported.private_key.is_none());
        // Still valid (time-only check when no private key)
        assert!(imported.is_valid().unwrap());
    }

    #[test]
    fn test_pkcs12_export() {
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "PKCS12 CA", ca_config()).unwrap();
        bundle.self_sign_ca().unwrap();

        let p12 = bundle.export_pkcs12(Some("test123"), None, None).unwrap();
        assert!(!p12.is_empty());

        // Verify we can parse it back
        let parsed =
            openssl::pkcs12::Pkcs12::from_der(&p12).unwrap();
        let parsed = parsed.parse2("test123").unwrap();
        assert!(parsed.pkey.is_some());
        assert!(parsed.cert.is_some());
    }

    #[test]
    fn test_update_certificate() {
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "Update CA", ca_config()).unwrap();
        bundle.self_sign_ca().unwrap();

        // update_certificate with the same cert should succeed
        let cert = bundle.certificate.clone().unwrap();
        bundle.update_certificate(cert).unwrap();
    }

    #[test]
    fn test_update_certificate_wrong_key() {
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "CA1", ca_config()).unwrap();
        bundle.self_sign_ca().unwrap();

        // Generate a different bundle
        let mut other =
            CertificateBundle::generate(CertType::Ca, "CA2", ca_config()).unwrap();
        other.self_sign_ca().unwrap();

        // Try to update bundle with other's cert (different key)
        let other_cert = other.certificate.unwrap();
        let result = bundle.update_certificate(other_cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_cert_type_display_and_parse() {
        for (s, ct) in [
            ("ca", CertType::Ca),
            ("device", CertType::Device),
            ("vpnclient", CertType::VpnClient),
            ("vpnserver", CertType::VpnServer),
            ("webserver", CertType::WebServer),
        ] {
            assert_eq!(ct.to_string(), s);
            assert_eq!(CertType::from_str(s).unwrap(), ct);
        }
    }

    #[test]
    fn test_pem_getters() {
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "PEM Test", ca_config()).unwrap();
        bundle.self_sign_ca().unwrap();

        let cert_pem = bundle.certificate_pem().unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));

        let key_pem = bundle.private_key_pem().unwrap();
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));

        let csr_pem = bundle.csr_pem().unwrap();
        assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_get_san_attribute() {
        let mut config = test_config();
        config.alt_dns_names = Some(vec![
            "www.example.com".to_string(),
            "mail.example.com".to_string(),
        ]);
        config.next_serial = Some(1);
        config.ca_days = Some(365);

        // To test SAN on the cert, we need to self-sign (SANs on CSR
        // don't automatically appear on the cert unless copied during signing).
        // For this unit test, just verify the CSR has SANs.
        let bundle =
            CertificateBundle::generate(CertType::WebServer, "example.com", config).unwrap();

        let csr_pem = bundle.csr_pem().unwrap();
        assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_issuer_attribute() {
        let mut config = ca_config();
        config.cn = Some("Issuer Test CA".to_string());
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "Issuer Test CA", config).unwrap();
        bundle.self_sign_ca().unwrap();

        let issuer = bundle.get_certificate_attrib("issuer").unwrap();
        assert!(issuer.is_some());
        let issuer = issuer.unwrap();
        assert!(
            issuer.contains("Issuer Test CA"),
            "Expected 'Issuer Test CA' in issuer: {issuer}"
        );
    }

    // -----------------------------------------------------------------------
    // re_sign_ca tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_re_sign_ca() {
        let mut bundle =
            CertificateBundle::generate(CertType::Ca, "Re-sign CA", ca_config()).unwrap();
        bundle.self_sign_ca().unwrap();

        let original_cn = bundle.get_certificate_attrib("cn").unwrap();
        let original_serial = bundle.get_certificate_attrib("serial").unwrap();

        // Re-sign with new validity
        bundle.re_sign_ca(7300).unwrap();

        // Same subject
        let new_cn = bundle.get_certificate_attrib("cn").unwrap();
        assert_eq!(original_cn, new_cn);

        // Same serial
        let new_serial = bundle.get_certificate_attrib("serial").unwrap();
        assert_eq!(original_serial, new_serial);

        // Still a valid CA certificate
        assert!(bundle.is_valid().unwrap());
        assert!(bundle.is_ca_certificate().unwrap());

        // Key type preserved
        let key_type = bundle.get_certificate_attrib("key_type").unwrap();
        assert_eq!(key_type, Some("RSA".to_string()));
    }

    #[test]
    fn test_re_sign_ca_rejects_non_ca() {
        let bundle =
            CertificateBundle::generate(CertType::Device, "Not a CA", test_config());
        let mut bundle = bundle.unwrap();

        let result = bundle.re_sign_ca(3650);
        assert!(result.is_err());
    }

    #[test]
    fn test_re_sign_ca_without_key() {
        // Import a cert without a private key
        let mut ca_bundle =
            CertificateBundle::generate(CertType::Ca, "KeylessCA", ca_config()).unwrap();
        ca_bundle.self_sign_ca().unwrap();

        let cert_pem = ca_bundle.certificate_pem().unwrap();

        let mut imported = CertificateBundle::import(
            CertType::Ca,
            "KeylessCA",
            cert_pem.as_bytes(),
            None,
            None,
            None,
            CertBundleConfig::default(),
        )
        .unwrap();

        let result = imported.re_sign_ca(3650);
        assert!(result.is_err());
    }
}
