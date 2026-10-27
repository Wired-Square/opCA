//! The operator's identity towards its ACME brokers: a key kept in the vault,
//! and a client certificate for it that the root signs for one day.

use std::time::Duration;

use chrono::Utc;
use openssl::pkey::{PKey, Private};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use wslib_crypto_ca::{Csr, Serial, Subject, Validity};
use wslib_pairing::SpkiSha256;
use wslib_tls::KeyFingerprint;

use super::{CertificateAuthority, authority_of, profile_for};
use crate::error::OpcaError;
use crate::op::{self, Error, ItemRef, Runner};
use crate::services::cert::{
    CertType, CertificateBundle, KeyAlgorithm, crypto_provider, signer_of,
};
use crate::services::database::models::CaConfig;

const OPERATOR_CN: &str = "opCA operator";
const CERT_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// Backdated so a broker whose clock runs a little behind still accepts it.
const CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// A client certificate and its key, as opCA presents them to a broker.
pub struct Operator {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pin: String,
}

impl Operator {
    pub fn presenting(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, OpcaError> {
        let leaf = chain
            .first()
            .ok_or_else(|| OpcaError::InvalidCertificate("An empty client chain".into()))?;
        let fingerprint =
            KeyFingerprint::of(leaf).map_err(|e| OpcaError::InvalidCertificate(e.to_string()))?;
        let pin = SpkiSha256::from(*fingerprint.0.as_bytes()).to_string();
        Ok(Self { chain, key, pin })
    }

    /// The lower-case hex SHA-256 of the key's SubjectPublicKeyInfo, as a broker pins it.
    pub fn pin(&self) -> &str {
        &self.pin
    }

    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

impl<R: Runner> CertificateAuthority<R> {
    /// The operator's key from the vault's `CA_Operator` item, made and stored
    /// on first use, with a fresh one-day client certificate that is not
    /// recorded and spends no serial.
    pub fn operator(&self) -> Result<Operator, OpcaError> {
        let key = self.operator_key()?;
        let ca = self
            .ca_bundle
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))?;
        let (root, root_key) = (
            ca.certificate.as_ref().ok_or(OpcaError::CaNotFound)?,
            ca.private_key
                .as_ref()
                .ok_or_else(|| OpcaError::Crypto("CA private key not available".into()))?,
        );
        let provider = crypto_provider();
        let csr = wslib_crypto_ca::build_csr(&signer_of(&key)?, &Subject::new(OPERATOR_CN), &[])?;
        let csr = Csr::from_der(&csr, provider.signature_verification_algorithms.all)?;
        let now = Utc::now();
        let cert = authority_of(root, root_key)?.issue(
            &csr,
            &profile_for(&CertType::VpnClient, false, &CaConfig::default()),
            &Serial::random(&provider)?,
            Validity {
                not_before: (now - CLOCK_SKEW).into(),
                not_after: (now + CERT_LIFETIME).into(),
            },
        )?;
        Operator::presenting(
            vec![cert],
            PrivateKeyDer::Pkcs8(key.private_key_to_pkcs8()?.into()),
        )
    }

    fn operator_key(&self) -> Result<PKey<Private>, OpcaError> {
        let c = &self.op_config;
        match self.vault.item(&ItemRef::title(c.operator_title)) {
            Ok(item) => {
                let pem = op::field_text(&item, c.key_item).ok_or_else(|| {
                    OpcaError::Crypto(format!("{} has no private key", c.operator_title))
                })?;
                Ok(PKey::private_key_from_pem(pem.as_bytes())?)
            }
            Err(Error::ItemNotFound(_)) => {
                let key = CertificateBundle::generate_private_key(KeyAlgorithm::EcP256)?;
                let pem = String::from_utf8_lossy(&key.private_key_to_pem_pkcs8()?).into_owned();
                self.vault.create_item(
                    c.operator_title,
                    c.category,
                    &[op::assign(c.key_item, pem)?],
                )?;
                Ok(key)
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::{X509, X509StoreContext};

    use super::*;
    use crate::services::ca::tests::{ca_with_key, calls};
    use crate::testutil::{FakeRunner, Output, created, item_json, not_found};

    type Ca = CertificateAuthority<FakeRunner>;

    fn runner(ca: &Ca) -> &FakeRunner {
        ca.vault.op().runner()
    }

    /// The operator a first use makes, and the fields of the item it stores.
    fn first_operator(ca: &Ca) -> (Operator, Vec<serde_json::Value>) {
        runner(ca).respond(not_found("CA_Operator"));
        runner(ca).respond(created("CA_Operator"));
        let operator = ca.operator().unwrap();
        let create = runner(ca).calls().pop().unwrap();
        let template: serde_json::Value = serde_json::from_slice(create.stdin().unwrap()).unwrap();
        (operator, template["fields"].as_array().unwrap().clone())
    }

    #[test]
    fn the_first_use_stores_a_key_alone_in_its_own_item() {
        let ca = ca_with_key(KeyAlgorithm::EcP256);
        let (_, fields) = first_operator(&ca);
        let create = calls(&ca).pop().unwrap();
        assert!(
            create.contains(&"--title=CA_Operator".to_string()),
            "{create:?}"
        );
        assert_eq!(fields.len(), 1, "{fields:?}");
        assert_eq!(fields[0]["label"], "private_key");
        assert!(
            fields[0]["value"]
                .as_str()
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
    }

    #[test]
    fn later_sessions_mint_for_the_stored_key_and_record_nothing() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let (first, fields) = first_operator(&ca);
        let pem = fields[0]["value"].as_str().unwrap();
        let db = ca.ca_database.as_mut().unwrap();
        let (serial, certs) = (
            db.get_config().unwrap().next_serial,
            db.count_certs().unwrap(),
        );
        runner(&ca).respond(Output::ok(item_json(
            "CA_Operator",
            &[("private_key", pem)],
        )));

        let again = ca.operator().unwrap();

        assert_eq!(again.pin(), first.pin());
        assert_ne!(again.chain()[0], first.chain()[0], "a fresh certificate");
        let db = ca.ca_database.as_ref().unwrap();
        assert_eq!(db.get_config().unwrap().next_serial, serial);
        assert_eq!(db.count_certs().unwrap(), certs);
    }

    #[test]
    fn the_certificate_is_a_day_long_client_certificate_from_the_root() {
        let ca = ca_with_key(KeyAlgorithm::EcP384);
        let (operator, _) = first_operator(&ca);

        let cert = X509::from_der(&operator.chain()[0]).unwrap();
        let root = ca.ca_bundle.as_ref().unwrap().certificate.clone().unwrap();
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(root).unwrap();
        let store = store.build();
        let mut context = X509StoreContext::new().unwrap();
        let verified = context
            .init(&store, &cert, &Stack::new().unwrap(), |c| c.verify_cert())
            .unwrap();
        assert!(verified);
        let text = String::from_utf8(cert.to_text().unwrap()).unwrap();
        assert!(text.contains("TLS Web Client Authentication"), "{text}");
        assert!(!text.contains("Server Authentication"), "{text}");
        let lifetime = cert.not_before().diff(cert.not_after()).unwrap();
        assert_eq!((lifetime.days, lifetime.secs), (1, 300));
    }
}
