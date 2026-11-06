//! opCA's client for its ACME brokers' API, and the enrolment, renewal and
//! revocation that go through it.

mod concern;
mod enrol;
mod renew;

pub use concern::{Concern, concerns};
pub use enrol::{EnrolledBroker, fetch_offer, issuance, parse_pairing};
pub use opca_acme_api as api;
pub use renew::{BrokerNotice, BrokerRenewal, BrokerRevocation, Renewal};

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use chrono::DateTime;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use log::warn;
use opca_acme_api::{
    ChainUpdate, Enrolment, EnrolmentOffer, ErrorBody, ErrorKind, FreshCsr, IssuedCertificate,
    IssuedPage, Status, path,
};
use rustls_pki_types::ServerName;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use wslib_pairing::{PairingUri, SpkiSha256};
use wslib_tls::{Cause, KeyFingerprint, Outbound, Rejection, Trust};

use crate::error::OpcaError;
use crate::op::Runner;
use crate::services::ca::CertificateAuthority;
use crate::services::ca::operator::Operator;
use crate::services::cert::crypto_provider;
use crate::services::database::models::{Broker, BrokerCert};
use crate::utils::block_on;
use crate::utils::datetime::{DateTimeFormat, format_datetime};

const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// Why a call to a broker got no usable answer.
#[derive(Debug, Clone, PartialEq, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrokerError {
    #[error("{message}")]
    Unreachable { message: String },
    #[error("{message}")]
    WrongKey { message: String },
    #[error("the broker refused: {message}")]
    Refused { refusal: ErrorKind, message: String },
    #[error("the broker answered HTTP {status}")]
    Status { status: u16 },
    #[error("the broker's answer is not understood: {message}")]
    Malformed { message: String },
}

/// Where a broker's API listens, and the key it must present there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
    pin: SpkiSha256,
}

impl Endpoint {
    pub fn of_pairing(pairing: &PairingUri) -> Self {
        Self {
            host: pairing.host().into(),
            port: pairing.port(),
            pin: pairing.pin(),
        }
    }

    pub fn of_broker(broker: &Broker) -> Result<Self, OpcaError> {
        let id = broker.id;
        let (Some(url), Some(pin)) = (&broker.url, &broker.pinned_key) else {
            return Err(OpcaError::Other(format!(
                "Subordinate {id} has no broker to call"
            )));
        };
        let unreadable = || OpcaError::Other(format!("Broker {id} has an unreadable URL {url}"));
        let (host, port) = url
            .strip_prefix("https://")
            .and_then(|authority| authority.rsplit_once(':'))
            .ok_or_else(unreadable)?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        Ok(Self {
            host: host.into(),
            port: port.parse().map_err(|_| unreadable())?,
            pin: pin.parse().map_err(|_| unreadable())?,
        })
    }

    pub fn url(&self) -> String {
        format!("https://{}", self.authority())
    }

    pub fn pin(&self) -> SpkiSha256 {
        self.pin
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A client for one broker that pins its key, presenting the operator's
/// certificate when given one.
pub struct BrokerClient {
    endpoint: Endpoint,
    tls: TlsConnector,
}

impl BrokerClient {
    pub fn new(endpoint: Endpoint, operator: Option<&Operator>) -> Result<Self, OpcaError> {
        let tls_error = |e: rustls::Error| OpcaError::Crypto(e.to_string());
        let mut trust = Trust::default();
        let pin = wslib_crypto::Fingerprint::from(*endpoint.pin.as_bytes());
        trust.pin_key(&endpoint.host, KeyFingerprint(pin));
        let outbound = Arc::new(Outbound::new(crypto_provider(), trust).map_err(tls_error)?);
        let config = match operator {
            Some(operator) => outbound
                .client_config_presenting(operator.chain().to_vec(), operator.key())
                .map_err(tls_error)?,
            None => outbound.client_config(),
        };
        Ok(Self {
            endpoint,
            tls: TlsConnector::from(Arc::new(config)),
        })
    }

    pub fn offer(&self) -> Result<EnrolmentOffer, BrokerError> {
        self.call(Method::GET, path::ENROLMENT, Vec::new())
    }

    pub fn enrol(&self, enrolment: &Enrolment) -> Result<Status, BrokerError> {
        self.call(Method::POST, path::ENROLMENT, json(enrolment))
    }

    pub fn status(&self) -> Result<Status, BrokerError> {
        self.call(Method::GET, path::STATUS, Vec::new())
    }

    pub fn fresh_csr(&self) -> Result<FreshCsr, BrokerError> {
        self.call(Method::POST, path::CSR, Vec::new())
    }

    pub fn put_chain(&self, update: &ChainUpdate) -> Result<Status, BrokerError> {
        self.call(Method::PUT, path::CHAIN, json(update))
    }

    pub fn revoke(&self) -> Result<Status, BrokerError> {
        self.call(Method::POST, path::REVOKE, Vec::new())
    }

    pub fn issued(&self, after: u64) -> Result<IssuedPage, BrokerError> {
        let path = format!("{}?after={after}", path::ISSUED);
        self.call(Method::GET, &path, Vec::new())
    }

    fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<T, BrokerError> {
        let answer = block_on(async {
            tokio::time::timeout(CALL_TIMEOUT, self.exchange(method, path, body)).await
        });
        let (status, body) = answer.map_err(|_| BrokerError::Unreachable {
            message: format!(
                "{} gave no answer within {} s",
                self.endpoint.authority(),
                CALL_TIMEOUT.as_secs()
            ),
        })??;
        if status == StatusCode::OK {
            return serde_json::from_slice(&body).map_err(|e| BrokerError::Malformed {
                message: e.to_string(),
            });
        }
        Err(match serde_json::from_slice::<ErrorBody>(&body) {
            Ok(refusal) => BrokerError::Refused {
                refusal: refusal.kind,
                message: refusal.message,
            },
            Err(_) => BrokerError::Status {
                status: status.as_u16(),
            },
        })
    }

    async fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Bytes), BrokerError> {
        let failed = |e: &(dyn Error + 'static)| self.failure(e);
        let Endpoint { host, port, .. } = &self.endpoint;
        let tcp = TcpStream::connect((host.as_str(), *port))
            .await
            .map_err(|e| failed(&e))?;
        let name = ServerName::try_from(host.clone()).map_err(|e| failed(&e))?;
        let tls = self.tls.connect(name, tcp).await.map_err(|e| failed(&e))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| failed(&e))?;
        tokio::spawn(connection);
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, self.endpoint.authority())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .expect("a method, a path and two fixed headers make a request");
        let response = sender.send_request(request).await.map_err(|e| failed(&e))?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| failed(&e))?
            .to_bytes();
        Ok((status, body))
    }

    fn failure(&self, error: &(dyn Error + 'static)) -> BrokerError {
        if let Some(Cause::Rejected(pinned @ Rejection::KeyPinMismatch { .. })) =
            wslib_tls::cause(error)
        {
            return BrokerError::WrongKey {
                message: pinned.to_string(),
            };
        }
        let mut message = self.endpoint.authority();
        let mut next = Some(error);
        while let Some(error) = next {
            message = format!("{message}: {error}");
            next = error.source();
        }
        BrokerError::Unreachable { message }
    }
}

fn broker_cert(broker_id: i64, cert: IssuedCertificate) -> Result<BrokerCert, OpcaError> {
    Ok(BrokerCert {
        broker_id,
        serial: cert.serial,
        common_name: cert.common_name,
        sans: cert.sans,
        not_before: openssl_time(&cert.not_before)?,
        not_after: openssl_time(&cert.not_after)?,
        issuer_serial: cert.issuer_serial,
        revoked_at: cert.revoked_at.as_deref().map(openssl_time).transpose()?,
        revocation_reason: cert.revocation_reason,
        changed: i64::try_from(cert.changed)
            .map_err(|_| OpcaError::Other(format!("change {} is out of range", cert.changed)))?,
    })
}

/// An RFC 3339 time from the broker, as the database keeps times.
fn openssl_time(rfc_3339: &str) -> Result<String, OpcaError> {
    let at = DateTime::parse_from_rfc3339(rfc_3339)
        .map_err(|e| OpcaError::Other(format!("the broker's time {rfc_3339}: {e}")))?;
    Ok(format_datetime(at.to_utc(), DateTimeFormat::Openssl))
}

fn json(body: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(body).expect("the API's types serialise")
}

impl<R: Runner> CertificateAuthority<R> {
    /// The broker's status, as the operator asks for it.
    pub fn broker_status(&mut self, operator: &Operator, id: i64) -> Result<Status, OpcaError> {
        let endpoint = Endpoint::of_broker(&self.broker(id)?)?;
        let client = BrokerClient::new(endpoint, Some(operator))?;
        let status = client.status()?;
        self.contacted(id)?;
        self.sync_issued(&client, id);
        self.store_ca_database()?;
        Ok(status)
    }

    /// What every broker issued, as last synced.
    pub fn list_broker_certs(&self) -> Result<Vec<BrokerCert>, OpcaError> {
        self.db()?.query_broker_certs()
    }

    /// Pulls what broker `id` issued or revoked since the last sync, for the next store to
    /// persist; a failure is only logged, since the call it rides on has succeeded.
    fn sync_issued(&self, client: &BrokerClient, id: i64) {
        if let Err(e) = self.try_sync_issued(client, id) {
            warn!("[broker] syncing broker {id}'s issued certificates: {e}");
        }
    }

    fn try_sync_issued(&self, client: &BrokerClient, id: i64) -> Result<(), OpcaError> {
        let db = self.db()?;
        let mut after = db.broker_cursor(id)? as u64;
        loop {
            let page = client.issued(after)?;
            let certs = page
                .certificates
                .into_iter()
                .map(|cert| broker_cert(id, cert))
                .collect::<Result<Vec<_>, _>>()?;
            db.record_broker_certs(&certs)?;
            if !page.more || page.next <= after {
                return Ok(());
            }
            after = page.next;
        }
    }

    /// Stamps `last_contact`, which the next database store persists.
    fn contacted(&self, id: i64) -> Result<(), OpcaError> {
        self.db()?.touch_broker(id)
    }

    /// The subordinate, then the root, as a broker takes them.
    fn chain_of(&self, cert_pem: &str) -> Result<String, OpcaError> {
        Ok(format!("{cert_pem}{}", self.get_certificate()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::database::models::BrokerState;

    fn broker(url: &str) -> Broker {
        Broker {
            id: 7,
            subordinate_serial: "100".into(),
            url: Some(url.into()),
            pinned_key: Some("ab".repeat(32)),
            permitted_domains: vec!["home.arpa".into()],
            state: BrokerState::Active,
            last_contact: None,
            created_at: String::new(),
            updated_at: String::new(),
            cn: None,
            expiry_date: None,
        }
    }

    #[test]
    fn a_broker_url_reads_back_as_its_endpoint() {
        for url in ["https://acme.home.arpa:9443", "https://[fd00::5]:9443"] {
            let endpoint = Endpoint::of_broker(&broker(url)).unwrap();
            assert_eq!(endpoint.url(), url);
            assert_eq!(endpoint.pin().to_string(), "ab".repeat(32));
        }
        assert_eq!(
            Endpoint::of_broker(&broker("https://[fd00::5]:9443"))
                .unwrap()
                .host,
            "fd00::5"
        );
        for unreadable in [
            "acme.home.arpa:9443",
            "https://acme.home.arpa",
            "https://h:x",
        ] {
            assert!(
                Endpoint::of_broker(&broker(unreadable)).is_err(),
                "{unreadable}"
            );
        }
        let unpaired = Broker {
            url: None,
            ..broker("https://acme.home.arpa:9443")
        };
        assert!(Endpoint::of_broker(&unpaired).is_err());
    }
}
