//! Certificates published to the public store, for servers that made their own key.

use log::info;
use openssl::asn1::Asn1Time;

use super::CertificateAuthority;
use crate::constants::DEFAULT_STORAGE_CONF;
use crate::error::OpcaError;
use crate::op::Runner;
use crate::services::database::models::{CertLookup, CertRecord};
use crate::services::storage::Visibility;

/// The public-store key of the certificate published for `cn`.
pub fn published_cert_key(cn: &str) -> String {
    let name: String = cn
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '-' => c,
            _ => '_',
        })
        .collect();
    format!("{}/{name}.pem", DEFAULT_STORAGE_CONF.published_cert_dir)
}

impl<R: Runner> CertificateAuthority<R> {
    /// Upload a certificate to the public store as the one published for its CN.
    /// A CN names its latest certificate. Returns the URI written.
    pub fn publish_certificate(&mut self, lookup: &CertLookup) -> Result<String, OpcaError> {
        info!("[ca] publishing certificate {lookup:?}");
        let record = self.publishable(lookup)?;
        let title = record.title.as_deref().unwrap_or(&record.serial);
        let bundle = self
            .retrieve_certbundle(title)?
            .ok_or_else(|| OpcaError::CertificateNotFound(title.to_string()))?;
        let cert = bundle
            .certificate
            .as_ref()
            .ok_or_else(|| OpcaError::CertificateNotFound(title.to_string()))?;
        let now = Asn1Time::days_from_now(0).map_err(|e| OpcaError::Crypto(e.to_string()))?;
        if cert.not_after() < now {
            return Err(OpcaError::CertificateExpired(record.serial));
        }

        let cn = record.cn.as_deref().unwrap_or_default();
        let uri = self.upload_published(&record.serial, cn, &bundle.certificate_pem()?)?;
        self.store_ca_database()?;
        Ok(uri)
    }

    fn publishable(&self, lookup: &CertLookup) -> Result<CertRecord, OpcaError> {
        let db = self.db()?;
        let record = match lookup {
            CertLookup::Cn(cn) => db
                .query_all_certs()?
                .into_iter()
                .filter(|c| c.cn.as_deref() == Some(cn))
                .max_by_key(|c| c.serial.parse::<u128>().unwrap_or(0)),
            other => db.query_cert(other, false)?,
        }
        .ok_or_else(|| OpcaError::CertificateNotFound(format!("{lookup:?}")))?;

        if matches!(record.cert_type.as_deref(), Some("ca" | "subordinateca")) {
            return Err(OpcaError::InvalidCertificate(format!(
                "{} is a CA certificate, which is not published",
                record.serial
            )));
        }
        if record.cn.as_deref().is_none_or(str::is_empty) {
            return Err(OpcaError::InvalidCertificate(format!(
                "{} has no CN to publish it under",
                record.serial
            )));
        }
        if record.status.as_deref() == Some("Revoked") {
            return Err(OpcaError::CertificateRevoked(record.serial));
        }
        Ok(record)
    }

    /// Upload to the CN's key and stamp the row; the caller stores the database.
    pub(super) fn upload_published(
        &mut self,
        serial: &str,
        cn: &str,
        pem: &str,
    ) -> Result<String, OpcaError> {
        let store = self
            .db()?
            .get_config()?
            .ca_public_store
            .ok_or_else(|| OpcaError::Storage("No public store configured".into()))?;
        let uri = format!("{}/{}", store.trim_end_matches('/'), published_cert_key(cn));
        self.upload_content(pem.as_bytes(), &uri, Visibility::Public)?;
        self.ca_database
            .as_mut()
            .ok_or(OpcaError::CaNotFound)?
            .mark_cert_published(serial, cn)?;
        Ok(uri)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{answer_writes, ca_with_key, calls};
    use super::*;
    use crate::services::cert::{CertBundleConfig, CertType, CertificateBundle, KeyAlgorithm};
    use crate::services::database::models::CaConfig;
    use crate::testutil::{FakeRunner, Output, created, item_json};

    type Ca = CertificateAuthority<FakeRunner>;

    /// A CA whose public store is a temp dir the rsync backend can write `certs/` into.
    fn ca_with_store() -> (Ca, tempfile::TempDir) {
        let ca = ca_with_key(KeyAlgorithm::EcP256);
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("certs")).unwrap();
        set_public_store(&ca, &format!("rsync://{}", dir.path().display()));
        (ca, dir)
    }

    fn set_public_store(ca: &Ca, uri: &str) {
        ca.db()
            .unwrap()
            .update_config(&CaConfig {
                ca_public_store: Some(uri.into()),
                ..CaConfig::default()
            })
            .unwrap();
    }

    fn issue(ca: &mut Ca, cert_type: CertType, cn: &str) -> CertificateBundle {
        ca.vault.op().runner().respond(created("CRT"));
        answer_writes(ca, 1);
        let config = CertBundleConfig {
            cn: Some(cn.into()),
            ..CertBundleConfig::default()
        };
        ca.generate_certificate_bundle(cert_type, cn, config, None)
            .unwrap()
            .0
    }

    fn answer_item(ca: &Ca, bundle: &CertificateBundle) {
        ca.vault.op().runner().respond(Output::ok(item_json(
            &bundle.title,
            &[
                ("certificate", &bundle.certificate_pem().unwrap()),
                ("private_key", &bundle.private_key_pem().unwrap()),
                ("certificate_signing_request", &bundle.csr_pem().unwrap()),
                ("type", &bundle.cert_type.to_string()),
            ],
        )));
    }

    fn publish(ca: &mut Ca, bundle: &CertificateBundle, lookup: CertLookup) -> String {
        answer_item(ca, bundle);
        answer_writes(ca, 1);
        ca.publish_certificate(&lookup).unwrap()
    }

    fn serial(bundle: &CertificateBundle) -> String {
        bundle.get_certificate_attrib("serial").unwrap().unwrap()
    }

    fn published_serials(ca: &Ca) -> Vec<String> {
        ca.db()
            .unwrap()
            .query_all_certs()
            .unwrap()
            .into_iter()
            .filter(|c| c.published_at.is_some())
            .map(|c| c.serial)
            .collect()
    }

    fn object(dir: &tempfile::TempDir, cn: &str) -> String {
        std::fs::read_to_string(dir.path().join(published_cert_key(cn))).unwrap()
    }

    #[test]
    fn a_cn_maps_to_one_safe_key() {
        assert_eq!(
            published_cert_key("www.example.com"),
            "certs/www.example.com.pem"
        );
        assert_eq!(
            published_cert_key("*.example.com"),
            "certs/_.example.com.pem"
        );
        assert_eq!(published_cert_key("a/../b c"), "certs/a_.._b_c.pem");
    }

    #[test]
    fn publishing_uploads_the_leaf_pem_and_stamps_the_row() {
        let (mut ca, dir) = ca_with_store();
        let leaf = issue(&mut ca, CertType::WebServer, "*.example.com");

        let uri = publish(&mut ca, &leaf, CertLookup::Serial(serial(&leaf)));

        assert_eq!(
            uri,
            format!("rsync://{}/certs/_.example.com.pem", dir.path().display())
        );
        assert_eq!(
            object(&dir, "*.example.com"),
            leaf.certificate_pem().unwrap()
        );
        assert_eq!(published_serials(&ca), [serial(&leaf)]);
        assert!(ca.vault.op().runner().is_done());
    }

    #[test]
    fn publishing_by_cn_takes_its_latest_cert_and_unpublishes_the_rest() {
        let (mut ca, dir) = ca_with_store();
        let first = issue(&mut ca, CertType::WebServer, "www.example.com");
        let other = issue(&mut ca, CertType::WebServer, "mail.example.com");
        publish(&mut ca, &first, CertLookup::Serial(serial(&first)));
        publish(&mut ca, &other, CertLookup::Serial(serial(&other)));
        let second = issue(&mut ca, CertType::WebServer, "www.example.com");

        publish(&mut ca, &second, CertLookup::Cn("www.example.com".into()));

        assert_eq!(published_serials(&ca), [serial(&other), serial(&second)]);
        assert_eq!(
            object(&dir, "www.example.com"),
            second.certificate_pem().unwrap()
        );
    }

    fn add_row(ca: &mut Ca, serial: &str, cn: &str, cert_type: &str, status: &str) {
        ca.ca_database
            .as_mut()
            .unwrap()
            .add_cert(&CertRecord {
                serial: serial.into(),
                cn: Some(cn.into()),
                title: Some(format!("CRT_{serial}_{cn}")),
                status: Some(status.into()),
                cert_type: Some(cert_type.into()),
                ..CertRecord::default()
            })
            .unwrap();
    }

    #[test]
    fn revoked_and_ca_certs_are_refused_before_anything_is_fetched() {
        let (mut ca, dir) = ca_with_store();
        add_row(&mut ca, "10", "revoked.example.com", "webserver", "Revoked");
        add_row(&mut ca, "11", "Broker CA", "subordinateca", "Valid");
        add_row(&mut ca, "12", "Test CA", "ca", "Valid");

        assert!(matches!(
            ca.publish_certificate(&CertLookup::Cn("revoked.example.com".into())),
            Err(OpcaError::CertificateRevoked(_))
        ));
        for serial in ["11", "12"] {
            assert!(matches!(
                ca.publish_certificate(&CertLookup::Serial(serial.into())),
                Err(OpcaError::InvalidCertificate(_))
            ));
        }

        assert!(calls(&ca).is_empty());
        assert!(published_serials(&ca).is_empty());
        assert_eq!(
            std::fs::read_dir(dir.path().join("certs")).unwrap().count(),
            0
        );
    }

    #[test]
    fn an_expired_cert_is_refused_even_while_its_row_says_valid() {
        let (mut ca, dir) = ca_with_store();
        add_row(&mut ca, "13", "old.example.com", "webserver", "Valid");
        ca.vault.op().runner().respond(Output::ok(item_json(
            "CRT_13_old.example.com",
            &[("certificate", &expired_cert_pem())],
        )));

        assert!(matches!(
            ca.publish_certificate(&CertLookup::Serial("13".into())),
            Err(OpcaError::CertificateExpired(_))
        ));
        assert!(published_serials(&ca).is_empty());
        assert_eq!(
            std::fs::read_dir(dir.path().join("certs")).unwrap().count(),
            0
        );
    }

    fn expired_cert_pem() -> String {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key = openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap())
            .unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "old.example.com").unwrap();
        let name = name.build();
        let mut cert = openssl::x509::X509::builder().unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::from_unix(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::from_unix(86_400).unwrap())
            .unwrap();
        cert.sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        String::from_utf8(cert.build().to_pem().unwrap()).unwrap()
    }

    #[test]
    fn renewing_a_published_cert_publishes_the_renewal() {
        let (mut ca, dir) = ca_with_store();
        let leaf = issue(&mut ca, CertType::WebServer, "www.example.com");
        publish(&mut ca, &leaf, CertLookup::Serial(serial(&leaf)));
        answer_item(&ca, &leaf);
        ca.vault.op().runner().respond(created("CRT"));
        answer_writes(&ca, 1);

        let renewal = ca
            .renew_certificate_bundle(&CertLookup::Serial(serial(&leaf)), None)
            .unwrap();

        assert!(matches!(renewal.republished, Some(Ok(_))));
        assert_eq!(published_serials(&ca), [renewal.serial.as_str()]);
        assert_eq!(object(&dir, "www.example.com"), renewal.pem);
    }

    #[test]
    fn renewing_an_unpublished_cert_publishes_nothing() {
        let (mut ca, dir) = ca_with_store();
        let leaf = issue(&mut ca, CertType::WebServer, "www.example.com");
        answer_item(&ca, &leaf);
        ca.vault.op().runner().respond(created("CRT"));
        answer_writes(&ca, 1);

        let renewal = ca
            .renew_certificate_bundle(&CertLookup::Serial(serial(&leaf)), None)
            .unwrap();

        assert!(renewal.republished.is_none());
        assert_eq!(
            std::fs::read_dir(dir.path().join("certs")).unwrap().count(),
            0
        );
    }

    #[test]
    fn a_failed_republish_is_reported_and_the_renewal_still_stored() {
        let (mut ca, dir) = ca_with_store();
        let leaf = issue(&mut ca, CertType::WebServer, "www.example.com");
        publish(&mut ca, &leaf, CertLookup::Serial(serial(&leaf)));
        set_public_store(&ca, &format!("rsync://{}/missing", dir.path().display()));
        answer_item(&ca, &leaf);
        ca.vault.op().runner().respond(created("CRT"));
        answer_writes(&ca, 1);

        let renewal = ca
            .renew_certificate_bundle(&CertLookup::Serial(serial(&leaf)), None)
            .unwrap();

        assert!(matches!(renewal.republished, Some(Err(_))));
        assert!(ca.vault.op().runner().is_done(), "the database was stored");
        assert!(
            ca.db()
                .unwrap()
                .query_cert(&CertLookup::Serial(renewal.serial.clone()), false)
                .unwrap()
                .is_some()
        );
        assert_eq!(published_serials(&ca), [serial(&leaf)]);
        assert_eq!(
            object(&dir, "www.example.com"),
            leaf.certificate_pem().unwrap()
        );
    }

    #[test]
    fn publishing_needs_a_public_store() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let leaf = issue(&mut ca, CertType::WebServer, "www.example.com");
        answer_item(&ca, &leaf);

        let err = ca
            .publish_certificate(&CertLookup::Serial(serial(&leaf)))
            .unwrap_err();

        assert!(matches!(err, OpcaError::Storage(_)), "{err}");
        assert!(published_serials(&ca).is_empty());
    }
}
