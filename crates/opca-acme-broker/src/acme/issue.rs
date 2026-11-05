//! Finalising an order: its CSR checked against the order and the permitted
//! domains, then a serverAuth leaf issued from the subordinate.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use opca_acme_api::IssuanceConfig;
use wslib_crypto::Signer;
use wslib_crypto_ca::{
    Authority, BasicConstraints, Csr, Extension, KeyIdentifierMethod, Profile, SanPolicy, Serial,
    Validity,
};
use wslib_crypto_x509::pem::{self, CERTIFICATE};
use wslib_crypto_x509::{
    ExtendedKeyUsage, KeyDescription, KeyUsage, SubjectAltName, inspect, name_attributes,
};

use super::store::{Certificate, NewCertificate, Order, Store};
use super::{Problem, ProblemType};
use crate::enrolment::host_within;

const DAY: Duration = Duration::from_secs(86_400);
/// As step-ca does, for clients whose clocks run a little behind.
const BACKDATE: Duration = Duration::from_secs(60);
const COMMON_NAME: &str = "2.5.4.3";

pub struct Issuer {
    authority: Authority,
    /// The subordinate and any intermediates above it, without the root, as step-ca served them.
    chain_pem: String,
    subordinate_not_after: SystemTime,
    config: IssuanceConfig,
}

impl Issuer {
    /// `chain_pem` is the enrolled chain, the subordinate first and the root last; `signer` holds the subordinate's key.
    pub fn new(
        signer: Signer,
        chain_pem: &str,
        config: IssuanceConfig,
    ) -> Result<Self, crate::Error> {
        let mut chain = pem::certificates(chain_pem)?;
        chain.pop();
        let subordinate = chain.first().ok_or("the chain holds no subordinate")?;
        let subordinate_not_after = inspect(subordinate)?.not_after;
        let chain_pem = chain
            .iter()
            .map(|der| pem::encode(CERTIFICATE, der))
            .collect();
        let authority = Authority::new(subordinate.clone(), signer, KeyIdentifierMethod::Sha1)?;
        Ok(Self {
            authority,
            chain_pem,
            subordinate_not_after,
            config,
        })
    }

    /// Issues for `order` from `csr_der` and records the certificate, which makes the order valid.
    pub async fn finalise(
        &self,
        store: &Store,
        order: &Order,
        csr_der: &[u8],
        account_key: &[u8],
    ) -> Result<Certificate, Problem> {
        let issued = self.issue(order, csr_der, account_key, SystemTime::now())?;
        store
            .record_certificate(order.id, &issued)
            .await
            .map_err(internal)
    }

    /// The certificate `csr_der` asks for, if it names exactly the order's
    /// identifiers and nothing else refuses it; `account_key` is the account's
    /// DER SubjectPublicKeyInfo, which the CSR may not reuse.
    pub fn issue(
        &self,
        order: &Order,
        csr_der: &[u8],
        account_key: &[u8],
        now: SystemTime,
    ) -> Result<NewCertificate, Problem> {
        let provider = self.authority.signer().provider();
        let csr = Csr::from_der(csr_der, provider.signature_verification_algorithms.all)
            .map_err(|e| bad_csr(format!("the CSR is unreadable or its signature fails: {e}")))?;
        if csr.spki() == account_key {
            return Err(bad_csr("the CSR's key is the account's key"));
        }
        check_key(csr.key())?;
        let names = self.requested_names(&csr)?;
        check_subject(&csr, &names)?;
        let ordered: BTreeSet<String> = order
            .identifiers
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        if names != ordered {
            return Err(bad_csr(format!(
                "the CSR names {names:?}, and the order {ordered:?}"
            )));
        }

        let validity = self.validity(order, now)?;
        let serial = Serial::random(provider).map_err(internal)?;
        let leaf = self
            .authority
            .issue(&csr, &leaf_profile(&csr), &serial, validity)
            .map_err(internal)?;
        Ok(NewCertificate {
            serial: serial.to_string(),
            common_name: csr.common_name().map(str::to_string),
            sans: names.into_iter().collect(),
            not_before: validity.not_before,
            not_after: validity.not_after,
            chain_pem: pem::encode(CERTIFICATE, &leaf) + &self.chain_pem,
        })
    }

    /// The CSR's DNS names, lower-case, each one the broker may issue for.
    fn requested_names(&self, csr: &Csr) -> Result<BTreeSet<String>, Problem> {
        let mut names = BTreeSet::new();
        for name in csr.names() {
            match name {
                SubjectAltName::Dns(dns) => {
                    let dns = dns.to_ascii_lowercase();
                    check_identifier(&dns, &self.config.permitted_domains)?;
                    names.insert(dns);
                }
                SubjectAltName::Ip(ip) => {
                    return Err(rejected(format!(
                        "{ip} is an IP address, and only DNS names are issued"
                    )));
                }
                other => return Err(bad_csr(format!("{other} is not a DNS name"))),
            }
        }
        if names.is_empty() {
            return Err(bad_csr("the CSR names no DNS names"));
        }
        Ok(names)
    }

    /// From now, less a minute, or the order's later notBefore; for the
    /// order's notAfter or the default lifetime, capped by the longest and by
    /// the subordinate's own end.
    fn validity(&self, order: &Order, now: SystemTime) -> Result<Validity, Problem> {
        let earliest = now - BACKDATE;
        let not_before = order.not_before.map_or(earliest, |at| at.max(earliest));
        let days = |days: u32| not_before + DAY * days;
        let not_after = order
            .not_after
            .unwrap_or(days(self.config.leaf_days))
            .min(days(self.config.leaf_max_days))
            .min(self.subordinate_not_after);
        if not_after <= not_before {
            return Err(Problem::new(
                ProblemType::Malformed,
                "the certificate would end before it begins",
            ));
        }
        Ok(Validity {
            not_before,
            not_after,
        })
    }
}

/// Refuses a DNS name the broker may not issue for: anything but a
/// lower-case A-label name equal to or under one of `permitted_domains`,
/// with a wildcard only as its whole leftmost label. Never an IP address.
pub fn check_identifier(name: &str, permitted_domains: &[String]) -> Result<(), Problem> {
    let refuse = |why: &str| Err(rejected(format!("{name:?} {why}")));
    if name.parse::<std::net::IpAddr>().is_ok() {
        return refuse("is an IP address, and only DNS names are issued");
    }
    let base = name.strip_prefix("*.").unwrap_or(name);
    if base.contains('*') {
        return refuse("has a wildcard other than as its whole leftmost label");
    }
    if base.ends_with('.') || name.to_ascii_lowercase() != name {
        return refuse("is not a lower-case name without a trailing dot");
    }
    if let Err(e) = wslib_dns::validate_hostname(base) {
        return refuse(&format!("is not a host name: {e}"));
    }
    if wslib_dns::to_ascii(base).ok().as_deref() != Some(base) {
        return refuse("is not in A-label form");
    }
    if !host_within(base, permitted_domains) {
        return refuse("is outside the permitted domains");
    }
    Ok(())
}

fn check_key(key: &KeyDescription) -> Result<(), Problem> {
    match key {
        KeyDescription::Rsa { bits: Some(bits) } if (2048..=8192).contains(bits) => Ok(()),
        KeyDescription::Ecdsa { curve: Some(curve) } if curve == "P-256" || curve == "P-384" => {
            Ok(())
        }
        other => Err(bad_csr(format!(
            "an {other} key is not issued for: RSA of 2048 to 8192 bits, P-256 or P-384"
        ))),
    }
}

/// The subject is copied into the leaf as it is, so it may hold one common name, one of the names, and nothing else.
fn check_subject(csr: &Csr, names: &BTreeSet<String>) -> Result<(), Problem> {
    let attributes = name_attributes(csr.subject()).map_err(bad_csr)?;
    match (&attributes[..], csr.common_name()) {
        ([], _) => Ok(()),
        ([only], Some(cn)) if only.oid == COMMON_NAME => {
            if names.contains(&cn.to_ascii_lowercase()) {
                Ok(())
            } else {
                Err(bad_csr(format!(
                    "the common name {cn:?} is not one of the CSR's DNS names"
                )))
            }
        }
        _ => Err(bad_csr(format!(
            "the subject {:?} holds more than one common name",
            csr.subject_text()
        ))),
    }
}

fn leaf_profile(csr: &Csr) -> Profile {
    let mut usages = vec![KeyUsage::DigitalSignature];
    if csr.has_rsa_key() {
        usages.push(KeyUsage::KeyEncipherment);
    }
    Profile {
        basic_constraints: Some(Extension::non_critical(BasicConstraints::EndEntity)),
        key_usage: Some(Extension::critical(usages)),
        extended_key_usage: Some(Extension::non_critical(vec![ExtendedKeyUsage::ServerAuth])),
        names: SanPolicy::Requested,
        ..Profile::default()
    }
}

fn bad_csr(detail: impl std::fmt::Display) -> Problem {
    Problem::new(ProblemType::BadCsr, detail)
}

fn rejected(detail: impl std::fmt::Display) -> Problem {
    Problem::new(ProblemType::RejectedIdentifier, detail)
}

fn internal(error: impl std::fmt::Display) -> Problem {
    tracing::error!(%error, "issuing failed");
    Problem::new(ProblemType::ServerInternal, error)
}
