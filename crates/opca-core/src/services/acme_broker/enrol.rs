use opca_acme_api::{Challenge, Enrolment, EnrolmentOffer, IssuanceConfig, PAIRING_SCHEME, Status};
use openssl::x509::{X509, X509Req};
use serde::Serialize;
use wslib_pairing::PairingUri;

use super::{BrokerClient, Endpoint};
use crate::error::OpcaError;
use crate::op::Runner;
use crate::services::ca::CertificateAuthority;
use crate::services::ca::operator::Operator;
use crate::services::ca::subordinate::{permitted_domains, same_domains};
use crate::services::database::models::{Broker, BrokerState, CertLookup};

const LEAF_DAYS: u32 = 30;
const LEAF_MAX_DAYS: u32 = 45;

/// The terms opCA offers unless the operator changes them.
pub fn issuance(permitted_domains: Vec<String>) -> IssuanceConfig {
    IssuanceConfig {
        permitted_domains,
        leaf_days: LEAF_DAYS,
        leaf_max_days: LEAF_MAX_DAYS,
        challenges: vec![Challenge::Http01, Challenge::Dns01, Challenge::TlsAlpn01],
    }
}

pub fn parse_pairing(text: &str) -> Result<PairingUri, OpcaError> {
    PairingUri::parse(PAIRING_SCHEME, text)
        .map_err(|e| OpcaError::Other(format!("Not a broker pairing string: {e}")))
}

/// What the broker asks opCA to sign, over a connection pinned to the pairing
/// string's key; the code is not sent.
pub fn fetch_offer(pairing: &PairingUri) -> Result<EnrolmentOffer, OpcaError> {
    Ok(BrokerClient::new(Endpoint::of_pairing(pairing), None)?.offer()?)
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrolledBroker {
    pub broker: Broker,
    pub status: Status,
}

/// The broker's configured domains when it has any, which the operator may
/// not change; otherwise the operator's.
fn enrolment_domains(configured: &[String], chosen: &[String]) -> Result<Vec<String>, OpcaError> {
    if configured.is_empty() {
        return permitted_domains(chosen);
    }
    let configured = permitted_domains(configured)?;
    if !chosen.is_empty() && !same_domains(&permitted_domains(chosen)?, &configured) {
        return Err(OpcaError::Other(format!(
            "The broker is configured for {}; its domains are changed on the broker, not in opCA",
            configured.join(", ")
        )));
    }
    Ok(configured)
}

impl<R: Runner> CertificateAuthority<R> {
    /// Signs the subordinate `shown` asks for and hands it to the broker with
    /// the pairing code. One signed earlier for this broker that never reached
    /// it is sent again, never signed twice.
    pub fn enrol_broker(
        &mut self,
        operator: &Operator,
        pairing: &PairingUri,
        shown: &EnrolmentOffer,
        terms: IssuanceConfig,
    ) -> Result<EnrolledBroker, OpcaError> {
        let endpoint = Endpoint::of_pairing(pairing);
        let client = BrokerClient::new(endpoint.clone(), None)?;
        if client.offer()? != *shown {
            return Err(OpcaError::Other(
                "The broker's request has changed since it was shown; review it again".into(),
            ));
        }
        let domains = enrolment_domains(&shown.configured_domains, &terms.permitted_domains)?;
        let (id, chain_pem) = match self.undelivered(&endpoint, shown, &domains)? {
            Some(pending) => pending,
            None => {
                let signed = self.sign_subordinate_at(
                    shown.csr_pem.as_bytes(),
                    &domains,
                    None,
                    Some(&endpoint),
                )?;
                (signed.broker.id, self.chain_of(&signed.cert_pem)?)
            }
        };
        let enrolment = Enrolment {
            code: pairing.code().expose().into(),
            chain_pem,
            operator_pin: operator.pin().into(),
            config: IssuanceConfig {
                permitted_domains: domains,
                ..terms
            },
        };
        let status = client.enrol(&enrolment).map_err(|e| {
            OpcaError::Other(format!(
                "Subordinate {id} is signed, but the broker did not take it ({e}). \
                 Enrol with the same pairing string to send it again; it is not signed twice."
            ))
        })?;
        self.contacted(id)?;
        self.store_ca_database()?;
        Ok(EnrolledBroker {
            broker: self.broker(id)?,
            status,
        })
    }

    /// The row and chain of a subordinate signed for this broker that has
    /// never reached it, when it still matches what the broker asks for.
    fn undelivered(
        &self,
        endpoint: &Endpoint,
        offer: &EnrolmentOffer,
        domains: &[String],
    ) -> Result<Option<(i64, String)>, OpcaError> {
        let pin = endpoint.pin().to_string();
        let Some(broker) = self
            .list_subordinates()?
            .into_iter()
            .find(|b| b.state == BrokerState::Active && b.pinned_key.as_deref() == Some(&pin))
        else {
            return Ok(None);
        };
        let id = broker.id;
        if broker.last_contact.is_some() {
            return Err(OpcaError::Other(format!(
                "This broker is already enrolled as subordinate {id}"
            )));
        }
        let cert_pem = self.subordinate_pem(&broker)?;
        let requested = X509Req::from_pem(offer.csr_pem.as_bytes())?.public_key()?;
        let same_key = X509::from_pem(cert_pem.as_bytes())?
            .public_key()?
            .public_eq(&requested);
        if !same_key || !same_domains(&broker.permitted_domains, domains) {
            return Err(OpcaError::Other(format!(
                "Subordinate {id} was signed for this broker with another key or other domains \
                 and never reached it; revoke it before enrolling again"
            )));
        }
        Ok(Some((id, self.chain_of(&cert_pem)?)))
    }

    fn subordinate_pem(&self, broker: &Broker) -> Result<String, OpcaError> {
        let serial = &broker.subordinate_serial;
        let missing = || OpcaError::CertificateNotFound(format!("subordinate serial {serial}"));
        let title = self
            .db()?
            .query_cert(&CertLookup::Serial(serial.clone()), false)?
            .and_then(|row| row.title)
            .ok_or_else(missing)?;
        self.retrieve_certbundle(&title)?
            .ok_or_else(missing)?
            .certificate_pem()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn the_brokers_domains_win_and_cannot_be_overridden() {
        let configured = names(&["home.arpa", "lab.example"]);
        assert_eq!(
            enrolment_domains(&configured, &[]).unwrap(),
            ["home.arpa", "lab.example"]
        );
        assert_eq!(
            enrolment_domains(&configured, &names(&["LAB.example", "home.arpa"])).unwrap(),
            ["home.arpa", "lab.example"]
        );
        assert!(enrolment_domains(&configured, &names(&["home.arpa"])).is_err());
        assert!(enrolment_domains(&configured, &names(&["corp.example"])).is_err());
    }

    #[test]
    fn with_none_on_the_broker_the_operator_chooses() {
        assert_eq!(
            enrolment_domains(&[], &names(&["Home.ARPA"])).unwrap(),
            ["home.arpa"]
        );
        assert!(enrolment_domains(&[], &[]).is_err());
    }

    #[test]
    fn only_an_opca_pairing_string_parses() {
        let text = format!(
            "opca-enrol://acme.home.arpa:9443#pin={}&code={}",
            "ab".repeat(32),
            "A".repeat(26)
        );
        let pairing = parse_pairing(&text).unwrap();
        assert_eq!((pairing.host(), pairing.port()), ("acme.home.arpa", 9443));
        assert!(parse_pairing(&text.replace("opca-enrol", "other")).is_err());
        assert!(parse_pairing("acme.home.arpa:9443").is_err());
    }
}
