//! Subordinate CAs signed from a broker's CSR, limited to permitted domains.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use log::info;
use openssl::x509::X509Req;
use serde::Serialize;
use wslib_crypto_ca::{Csr, Extension};
use wslib_crypto_x509::{IpSubtree, NameConstraints, NameSubtree, SubjectAltName};

use super::{CertificateAuthority, profile_for, verified_csr};
use crate::error::OpcaError;
use crate::op::Runner;
use crate::services::cert::{CertBundleConfig, CertType, CertificateBundle};
use crate::services::database::CertificateAuthorityDB;
use crate::services::database::models::{Broker, BrokerState, CertLookup, IgnoreReason};
use crate::services::san;
use crate::utils::datetime::{self, DateTimeFormat};

/// A freshly signed subordinate and the broker row that now points at it.
#[derive(Debug, Clone, Serialize)]
pub struct SignedSubordinate {
    pub broker: Broker,
    pub cert_pem: String,
}

/// Lowercased and deduplicated; each covers itself and every name below it.
pub fn permitted_domains(domains: &[String]) -> Result<Vec<String>, OpcaError> {
    let mut out: Vec<String> = Vec::new();
    for raw in domains {
        let domain = raw.trim().to_ascii_lowercase();
        let refuse = |why: &str| {
            Err(OpcaError::InvalidCertificate(format!(
                "Permitted domain '{raw}': {why}"
            )))
        };
        if domain.parse::<IpAddr>().is_ok() {
            return refuse("an IP address, not a domain");
        }
        if domain.contains('*') {
            return refuse("a wildcard; the domain already covers every name below it");
        }
        if !san::is_dns_name(&domain, false) {
            return refuse("not a valid DNS name");
        }
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    if out.is_empty() {
        return Err(OpcaError::InvalidCertificate(
            "A subordinate CA needs at least one permitted domain".into(),
        ));
    }
    Ok(out)
}

fn within(domains: &[String], name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    domains
        .iter()
        .any(|d| name == *d || name.ends_with(&format!(".{d}")))
}

/// The CSR's names are never copied into the certificate, but one naming a
/// host outside the domains is refused, as is a host-like common name.
fn check_requested_names(csr: &Csr, domains: &[String]) -> Result<(), OpcaError> {
    let outside = |name: &dyn std::fmt::Display| {
        Err(OpcaError::InvalidCertificate(format!(
            "The CSR names {name}, outside the permitted domains {}",
            domains.join(", ")
        )))
    };
    for name in csr.names() {
        match name {
            SubjectAltName::Dns(host) if within(domains, host) => {}
            other => return outside(other),
        }
    }
    if let Some(cn) = csr.common_name() {
        let host_like =
            cn.parse::<IpAddr>().is_ok() || (cn.contains('.') && san::is_dns_name(cn, true));
        if host_like && !within(domains, cn) {
            return outside(&cn);
        }
    }
    Ok(())
}

fn name_constraints(domains: &[String]) -> NameConstraints {
    let everything = |address: IpAddr| {
        NameSubtree::Ip(IpSubtree::new(address, 0).expect("a zero-length prefix has no host bits"))
    };
    NameConstraints {
        permitted: domains.iter().cloned().map(NameSubtree::Dns).collect(),
        excluded: vec![
            everything(Ipv4Addr::UNSPECIFIED.into()),
            everything(Ipv6Addr::UNSPECIFIED.into()),
        ],
    }
}

impl<R: Runner> CertificateAuthority<R> {
    /// Sign `csr` (PEM or DER) as a subordinate CA for `domains` and record a
    /// broker row for it with no URL.
    pub fn sign_subordinate(
        &mut self,
        csr: &[u8],
        domains: &[String],
        days: Option<u32>,
    ) -> Result<SignedSubordinate, OpcaError> {
        let domains = permitted_domains(domains)?;
        info!("[ca] signing subordinate CA for {}", domains.join(", "));
        let bundle = self.issue_subordinate(csr, &domains, days)?;
        let id = self.db()?.add_broker(&serial_of(&bundle)?, &domains)?;
        self.store_ca_database()?;
        self.signed(id, &bundle)
    }

    pub fn list_subordinates(&self) -> Result<Vec<Broker>, OpcaError> {
        self.db()?.query_all_brokers()
    }

    fn db(&self) -> Result<&CertificateAuthorityDB, OpcaError> {
        self.ca_database
            .as_ref()
            .ok_or_else(|| OpcaError::Other("CA not initialised".into()))
    }

    fn issue_subordinate(
        &mut self,
        csr: &[u8],
        domains: &[String],
        days: Option<u32>,
    ) -> Result<CertificateBundle, OpcaError> {
        let request = X509Req::from_pem(csr)
            .or_else(|_| X509Req::from_der(csr))
            .map_err(|e| OpcaError::InvalidCertificate(format!("Failed to parse CSR: {e}")))?;
        let csr = verified_csr(&request)?;
        check_requested_names(&csr, domains)?;
        let cn = csr
            .common_name()
            .ok_or_else(|| OpcaError::InvalidCertificate("The CSR has no common name".into()))?
            .to_string();
        let days = self.subordinate_days(days)?;

        let profile = wslib_crypto_ca::Profile {
            name_constraints: Some(Extension::critical(name_constraints(domains))),
            ..profile_for(&CertType::SubordinateCa, false, &self.db()?.get_config()?)
        };
        let cert = self.issue(&csr, &profile, days)?;

        let mut bundle = CertificateBundle::import(
            CertType::SubordinateCa,
            &cn,
            &cert.to_pem()?,
            None,
            Some(&request.to_pem()?),
            None,
            CertBundleConfig::default(),
        )?;
        bundle.title = format!("CRT_{}_{cn}", serial_of(&bundle)?);
        self.store_certbundle_for(&bundle, None, None, false)?;
        Ok(bundle)
    }

    /// Refuses a lifetime the root doesn't cover, rather than signing a
    /// subordinate whose chain dies early.
    fn subordinate_days(&self, requested: Option<u32>) -> Result<u32, OpcaError> {
        let days = self.cert_days(&CertType::SubordinateCa, requested)?;
        let root_not_after = self.ca_not_after()?;
        let not_after = chrono::Utc::now() + chrono::Duration::days(days.into());
        if not_after > root_not_after {
            return Err(OpcaError::InvalidCertificate(format!(
                "A {days}-day subordinate would outlive the root CA, which expires {}",
                datetime::format_datetime(root_not_after, DateTimeFormat::Text)
            )));
        }
        Ok(days)
    }

    fn signed(&self, id: i64, bundle: &CertificateBundle) -> Result<SignedSubordinate, OpcaError> {
        Ok(SignedSubordinate {
            broker: self.broker(id)?,
            cert_pem: bundle.certificate_pem()?,
        })
    }

    fn broker(&self, id: i64) -> Result<Broker, OpcaError> {
        self.db()?
            .query_broker(id)?
            .ok_or_else(|| OpcaError::CertificateNotFound(format!("subordinate {id}")))
    }
}

fn serial_of(bundle: &CertificateBundle) -> Result<String, OpcaError> {
    bundle
        .get_certificate_attrib("serial")?
        .ok_or_else(|| OpcaError::InvalidCertificate("Signed certificate has no serial".into()))
}

impl<R: Runner> CertificateAuthority<R> {
    /// Sign a fresh CSR for subordinate `id` and move its row to the new serial.
    /// `domains` replaces the row's only with `change_domains`, so a renewal
    /// can never quietly widen what the subordinate may issue for.
    pub fn renew_subordinate(
        &mut self,
        id: i64,
        csr: &[u8],
        domains: Option<&[String]>,
        change_domains: bool,
        days: Option<u32>,
    ) -> Result<SignedSubordinate, OpcaError> {
        let broker = self.active_broker(id)?;
        let domains = match domains {
            None => broker.permitted_domains.clone(),
            Some(requested) => {
                let requested = permitted_domains(requested)?;
                let sorted = |domains: &[String]| {
                    let mut domains = domains.to_vec();
                    domains.sort();
                    domains
                };
                if sorted(&requested) != sorted(&broker.permitted_domains) && !change_domains {
                    return Err(OpcaError::Other(format!(
                        "Subordinate {id} is limited to {}; renewing it for {} needs the change confirmed",
                        broker.permitted_domains.join(", "),
                        requested.join(", ")
                    )));
                }
                requested
            }
        };
        info!("[ca] renewing subordinate {id}");
        let bundle = self.issue_subordinate(csr, &domains, days)?;
        let new_serial = serial_of(&bundle)?;
        self.auto_ignore_predecessor(
            &broker.subordinate_serial,
            &new_serial,
            IgnoreReason::Renewed,
        )?;
        self.db()?.move_broker_to(id, &new_serial, &domains)?;
        self.store_ca_database()?;
        self.signed(id, &bundle)
    }

    /// Revoke subordinate `id`'s certificate, which marks its row; the caller
    /// regenerates the CRL, as after any revoke.
    pub fn revoke_subordinate(&mut self, id: i64) -> Result<Broker, OpcaError> {
        let broker = self.active_broker(id)?;
        self.revoke_certificate(&CertLookup::Serial(broker.subordinate_serial))?;
        self.broker(id)
    }

    fn active_broker(&self, id: i64) -> Result<Broker, OpcaError> {
        let broker = self.broker(id)?;
        if broker.state == BrokerState::Revoked {
            return Err(OpcaError::CertificateRevoked(format!("subordinate {id}")));
        }
        Ok(broker)
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use openssl::stack::Stack;
    use openssl::x509::X509;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::{X509StoreContext, X509VerifyResult};
    use wslib_crypto_ca::{Authority, KeyIdentifierMethod, Serial, Validity};

    use super::*;
    use crate::services::ca::tests::{answer_writes, ca_with_key, calls};
    use crate::services::cert::{KeyAlgorithm, signer_of};
    use crate::services::database::models::CaConfig;
    use crate::testutil::{FakeRunner, created};

    type Ca = CertificateAuthority<FakeRunner>;

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn csr_bundle(cn: &str, alt_names: &[&str]) -> CertificateBundle {
        CertificateBundle::generate(
            CertType::SubordinateCa,
            cn,
            CertBundleConfig {
                cn: Some(cn.into()),
                alt_names: Some(names(alt_names)),
                ..CertBundleConfig::default()
            },
        )
        .unwrap()
    }

    fn csr_pem(cn: &str, alt_names: &[&str]) -> Vec<u8> {
        csr_bundle(cn, alt_names).csr.unwrap().to_pem().unwrap()
    }

    /// Scripts the certificate item's create and the database store.
    fn answer_issue(ca: &Ca) {
        ca.vault.op().runner().respond(created("CRT"));
        answer_writes(ca, 1);
    }

    fn sign(ca: &mut Ca, domains: &[&str], days: Option<u32>) -> SignedSubordinate {
        answer_issue(ca);
        ca.sign_subordinate(&csr_pem("Broker CA", &[]), &names(domains), days)
            .unwrap()
    }

    fn next_serial(ca: &Ca) -> Option<i64> {
        ca.db().unwrap().get_config().unwrap().next_serial
    }

    fn x509(pem: &str) -> X509 {
        X509::from_pem(pem.as_bytes()).unwrap()
    }

    fn lifetime_days(cert: &X509) -> i32 {
        cert.not_before().diff(cert.not_after()).unwrap().days
    }

    #[test]
    fn domains_are_lowercased_deduplicated_dns_names() {
        assert_eq!(
            permitted_domains(&names(&["Home.ARPA", " lab.example ", "home.arpa"])).unwrap(),
            ["home.arpa", "lab.example"]
        );
        for refused in [
            &[][..],
            &["*.home.arpa"],
            &["10.0.0.1"],
            &["fd00::1"],
            &["10.0.0.0/8"],
            &["home..arpa"],
            &["bad_name.example"],
            &["home.arpa."],
            &["home.arpa", ""],
        ] {
            assert!(permitted_domains(&names(refused)).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn the_profile_is_a_name_constrained_path_length_zero_server_ca() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        ca.db()
            .unwrap()
            .update_config(&CaConfig {
                crl_url: Some("http://pki.home.arpa/crl.pem".into()),
                ca_url: Some("http://pki.home.arpa/ca.pem".into()),
                ..CaConfig::default()
            })
            .unwrap();
        answer_issue(&ca);
        let csr = csr_pem("Broker CA", &["acme.home.arpa"]);

        let signed = ca
            .sign_subordinate(&csr, &names(&["home.arpa", "lab.example"]), None)
            .unwrap();

        let cert = x509(&signed.cert_pem);
        let text = String::from_utf8(cert.to_text().unwrap()).unwrap();
        for wanted in [
            "X509v3 Basic Constraints: critical\n                CA:TRUE, pathlen:0",
            "X509v3 Key Usage: critical\n                Certificate Sign, CRL Sign",
            "X509v3 Extended Key Usage: \n                TLS Web Server Authentication\n",
            "X509v3 Name Constraints: critical",
            "URI:http://pki.home.arpa/crl.pem",
            "CA Issuers - URI:http://pki.home.arpa/ca.pem",
        ] {
            assert!(text.contains(wanted), "{wanted:?} in {text}");
        }
        let view = wslib_crypto_x509::inspect_pem(&signed.cert_pem).unwrap();
        assert_eq!(
            view.name_constraints,
            Some(name_constraints(&signed.broker.permitted_domains))
        );
        assert_eq!(
            view.name_constraints.unwrap().excluded,
            ["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
        );
        assert!(view.sans.is_empty(), "the CSR's names are not copied");
        assert_eq!(lifetime_days(&cert), 90);
    }

    #[test]
    fn signing_records_a_broker_row_with_no_url() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);

        let signed = sign(&mut ca, &["home.arpa"], None);

        let broker = &signed.broker;
        assert_eq!(
            ca.list_subordinates().unwrap(),
            std::slice::from_ref(broker)
        );
        assert_eq!(
            (broker.url.as_ref(), broker.state),
            (None, BrokerState::Active)
        );
        assert_eq!(broker.cn.as_deref(), Some("Broker CA"));
        let row = ca
            .db()
            .unwrap()
            .query_cert(
                &CertLookup::Serial(broker.subordinate_serial.clone()),
                false,
            )
            .unwrap()
            .unwrap();
        assert_eq!(row.cert_type.as_deref(), Some("subordinateca"));
        assert_eq!(row.expiry_date, broker.expiry_date);
        let writes = calls(&ca);
        assert_eq!(
            writes.len(),
            2,
            "one item and one database store: {writes:?}"
        );
        let title = format!("CRT_{}_Broker CA", broker.subordinate_serial);
        assert!(
            writes[0].contains(&format!("--title={title}")),
            "{:?}",
            writes[0]
        );
    }

    #[test]
    fn a_csr_naming_a_host_outside_the_domains_is_refused_before_a_serial_is_spent() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let before = next_serial(&ca);
        for (cn, alt_names) in [
            ("Broker CA", &["nas.elsewhere.example"][..]),
            ("Broker CA", &["10.0.0.5"]),
            ("Broker CA", &["ops@home.arpa"]),
            ("acme.elsewhere.example", &[]),
            ("10.0.0.5", &[]),
        ] {
            let refused =
                ca.sign_subordinate(&csr_pem(cn, alt_names), &names(&["home.arpa"]), None);
            assert!(refused.is_err(), "{cn} {alt_names:?}");
        }
        answer_issue(&ca);
        ca.sign_subordinate(
            &csr_pem("acme.home.arpa", &["*.lab.home.arpa"]),
            &names(&["home.arpa"]),
            None,
        )
        .unwrap();
        assert_eq!(next_serial(&ca), before.map(|n| n + 1));
    }

    #[test]
    fn a_csr_whose_signature_fails_is_refused_before_a_serial_is_spent() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let before = next_serial(&ca);
        let mut der = csr_bundle("Broker CA", &[]).csr.unwrap().to_der().unwrap();
        let last = der.len() - 1;
        der[last] ^= 0x01;

        let refused = ca.sign_subordinate(&der, &names(&["home.arpa"]), None);

        assert!(refused.is_err());
        assert_eq!(next_serial(&ca), before);
        assert!(calls(&ca).is_empty());
    }

    #[test]
    fn a_lifetime_the_root_does_not_cover_is_refused() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let csr = csr_pem("Broker CA", &[]);
        let domains = names(&["home.arpa"]);
        for days in [0, 3651] {
            assert!(
                ca.sign_subordinate(&csr, &domains, Some(days)).is_err(),
                "{days}"
            );
        }
        assert!(calls(&ca).is_empty());
    }

    #[test]
    fn the_apple_server_cap_does_not_touch_a_subordinate() {
        assert!(!CertType::SubordinateCa.is_tls_server());
        assert_eq!(CertType::SubordinateCa.default_days(3000), 90);
        assert!(super::super::assess_apple_tls_limit(&CertType::SubordinateCa, 900).is_none());

        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let signed = sign(&mut ca, &["home.arpa"], Some(900));
        assert_eq!(lifetime_days(&x509(&signed.cert_pem)), 900);
    }

    #[test]
    fn the_generic_sign_path_will_not_make_a_subordinate() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let csr = csr_bundle("Broker CA", &[]).csr.unwrap();
        let before = next_serial(&ca);

        assert!(
            ca.issue_certificate(&csr, &CertType::SubordinateCa, None)
                .is_err()
        );
        assert_eq!(next_serial(&ca), before);
    }

    /// A leaf for `names`, issued by the subordinate from its own key.
    fn leaf(sub: &X509, sub_key: &CertificateBundle, cn: &str, alt_names: &[&str]) -> X509 {
        let request = CertificateBundle::generate(
            CertType::WebServer,
            cn,
            CertBundleConfig {
                cn: Some(cn.into()),
                alt_names: Some(names(alt_names)),
                ..CertBundleConfig::default()
            },
        )
        .unwrap();
        let authority = Authority::new(
            sub.to_der().unwrap().into(),
            signer_of(sub_key.private_key.as_ref().unwrap()).unwrap(),
            KeyIdentifierMethod::Sha1,
        )
        .unwrap();
        let now = chrono::Utc::now();
        let der = authority
            .issue(
                &verified_csr(request.csr.as_ref().unwrap()).unwrap(),
                &profile_for(&CertType::WebServer, false, &Default::default()),
                &Serial::try_from(7_i64).unwrap(),
                Validity {
                    not_before: now.into(),
                    not_after: (now + chrono::Duration::days(30)).into(),
                },
            )
            .unwrap();
        X509::from_der(&der).unwrap()
    }

    fn verifies(root: &X509, sub: &X509, leaf: &X509) -> X509VerifyResult {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(root.clone()).unwrap();
        let store = store.build();
        let mut chain = Stack::new().unwrap();
        chain.push(sub.clone()).unwrap();
        let mut ctx = X509StoreContext::new().unwrap();
        ctx.init(&store, leaf, &chain, |c| c.verify_cert().map(|_| c.error()))
            .unwrap()
    }

    /// `openssl verify`, or `None` with no `openssl` on `PATH`.
    fn openssl_verifies(root: &X509, sub: &X509, leaf: &X509) -> Option<bool> {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, cert: &X509| {
            let path = dir.path().join(name);
            std::fs::write(&path, cert.to_pem().unwrap()).unwrap();
            path
        };
        let (root, sub, leaf) = (
            write("root.pem", root),
            write("sub.pem", sub),
            write("leaf.pem", leaf),
        );
        let output = Command::new("openssl")
            .arg("verify")
            .arg("-CAfile")
            .arg(root)
            .arg("-untrusted")
            .arg(sub)
            .arg(leaf)
            .output()
            .ok()?;
        Some(output.status.success())
    }

    #[test]
    fn leaves_verify_only_inside_the_permitted_domains() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP384);
        let sub_key = csr_bundle("Broker CA", &[]);
        answer_issue(&ca);
        let signed = ca
            .sign_subordinate(
                &sub_key.csr.as_ref().unwrap().to_pem().unwrap(),
                &names(&["home.arpa"]),
                None,
            )
            .unwrap();
        let root = ca.ca_bundle.as_ref().unwrap().certificate.clone().unwrap();
        let sub = x509(&signed.cert_pem);

        for (cn, alt_names, ok) in [
            ("nas.home.arpa", &["pve.lab.home.arpa"][..], true),
            ("nas.elsewhere.example", &[], false),
            ("nas.home.arpa", &["nas.elsewhere.example"], false),
            ("nas.home.arpa", &["192.168.1.20"], false),
        ] {
            let leaf = leaf(&sub, &sub_key, cn, alt_names);
            let result = verifies(&root, &sub, &leaf).error_string();
            let expected = if ok { "ok" } else { "subtree violation" };
            assert!(result.contains(expected), "{cn} {alt_names:?}: {result}");
            if let Some(cli) = openssl_verifies(&root, &sub, &leaf) {
                assert_eq!(cli, ok, "openssl verify {cn} {alt_names:?}");
            }
        }
    }

    #[test]
    fn renewing_keeps_the_row_and_moves_it_to_the_new_serial() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let first = sign(&mut ca, &["home.arpa"], None).broker;
        answer_issue(&ca);

        let renewed = ca
            .renew_subordinate(first.id, &csr_pem("Broker CA", &[]), None, false, None)
            .unwrap()
            .broker;

        assert_eq!(renewed.id, first.id);
        assert_ne!(renewed.subordinate_serial, first.subordinate_serial);
        assert_eq!(renewed.permitted_domains, first.permitted_domains);
        assert_eq!(
            ca.list_subordinates().unwrap(),
            std::slice::from_ref(&renewed)
        );
        let old = ca
            .db()
            .unwrap()
            .query_cert(&CertLookup::Serial(first.subordinate_serial), false)
            .unwrap()
            .unwrap();
        assert_eq!(old.status.as_deref(), Some("Valid"));
        assert_eq!(old.ignored_reason.as_deref(), Some("renewed"));
        assert_eq!(
            old.ignored_note,
            Some(format!("replaced by {}", renewed.subordinate_serial))
        );
    }

    #[test]
    fn renewing_for_other_domains_needs_the_change_confirmed() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let id = sign(&mut ca, &["home.arpa", "lab.example"], None).broker.id;
        let csr = csr_pem("Broker CA", &[]);
        let wider = names(&["home.arpa", "lab.example", "corp.example"]);

        assert!(
            ca.renew_subordinate(id, &csr, Some(&wider), false, None)
                .is_err()
        );
        assert!(calls(&ca).len() == 2, "nothing written after the refusal");

        answer_issue(&ca);
        answer_issue(&ca);
        let reordered = names(&["LAB.example", "home.arpa"]);
        ca.renew_subordinate(id, &csr, Some(&reordered), false, None)
            .unwrap();
        let widened = ca
            .renew_subordinate(id, &csr, Some(&wider), true, None)
            .unwrap()
            .broker;
        assert_eq!(
            widened.permitted_domains,
            ["home.arpa", "lab.example", "corp.example"]
        );
    }

    #[test]
    fn revoking_puts_the_subordinate_on_the_crl_and_marks_the_row() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let id = sign(&mut ca, &["home.arpa"], None).broker.id;
        answer_writes(&ca, 3);

        let revoked = ca.revoke_subordinate(id).unwrap();
        let crl = ca.generate_crl().unwrap();

        assert_eq!(revoked.state, BrokerState::Revoked);
        let crl = openssl::x509::X509Crl::from_pem(crl.as_bytes()).unwrap();
        let on_crl: Vec<String> = crl
            .get_revoked()
            .into_iter()
            .flatten()
            .map(|r| {
                r.serial_number()
                    .to_bn()
                    .unwrap()
                    .to_dec_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(on_crl, [revoked.subordinate_serial]);
        let csr = csr_pem("Broker CA", &[]);
        assert!(ca.renew_subordinate(id, &csr, None, false, None).is_err());
        assert!(ca.revoke_subordinate(id).is_err());
    }

    #[test]
    fn revoking_the_certificate_from_the_certs_list_marks_the_row_too() {
        let mut ca = ca_with_key(KeyAlgorithm::EcP256);
        let broker = sign(&mut ca, &["home.arpa"], None).broker;
        answer_writes(&ca, 1);

        ca.revoke_certificate(&CertLookup::Serial(broker.subordinate_serial))
            .unwrap();

        assert_eq!(ca.broker(broker.id).unwrap().state, BrokerState::Revoked);
    }
}
