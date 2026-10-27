use std::sync::Arc;

use opca_acme_api::{ChainUpdate, ErrorBody, ErrorKind, FreshCsr, IssuerState, Status};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme,
};
use wslib_crypto_x509::{CertificateView, inspect, pem};
use wslib_http_server::PeerCertificates;
use wslib_pairing::SpkiSha256;
use wslib_tls::{KeyFingerprint, Serving};

use crate::enrolment::{Enrolled, Mode, bad_request, decimal, internal, rfc_3339, versions};
use crate::{Broker, Error};

/// The API's TLS once enrolled: a client must chain to `root` and present the operator's key.
pub(crate) fn operator_config(
    provider: &Arc<CryptoProvider>,
    serving: &Serving,
    root: CertificateDer<'static>,
    operator_pin: &str,
) -> Result<Arc<ServerConfig>, Error> {
    let mut roots = RootCertStore::empty();
    roots.add(root)?;
    let chained =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let verifier = OperatorOnly {
        chained,
        operator_pin: operator_pin.into(),
    };
    let config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cert_resolver(serving.config().cert_resolver.clone());
    Ok(Arc::new(config))
}

pub(crate) fn root_of(chain_pem: &str) -> Result<CertificateDer<'static>, Error> {
    pem::certificates(chain_pem)?
        .pop()
        .ok_or_else(|| "the stored chain is empty".into())
}

fn key_pin(certificate: &CertificateDer<'_>) -> Option<String> {
    let fingerprint = KeyFingerprint::of(certificate).ok()?;
    Some(SpkiSha256::from(*fingerprint.0.as_bytes()).to_string())
}

/// The root also issues VPN and device certificates for client auth, so
/// chaining to it is not enough: the key must be the operator's too.
#[derive(Debug)]
struct OperatorOnly {
    chained: Arc<dyn ClientCertVerifier>,
    operator_pin: String,
}

impl ClientCertVerifier for OperatorOnly {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.chained.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .chained
            .verify_client_cert(end_entity, intermediates, now)?;
        match key_pin(end_entity) {
            Some(pin) if pin == self.operator_pin => Ok(verified),
            _ => Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.chained.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.chained.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chained.supported_verify_schemes()
    }
}

impl Broker {
    /// The enrolment, when `peer` is the operator; a connection opened before
    /// the swap to client auth presented nothing and is refused here.
    pub(crate) fn admits(&self, peer: Option<&PeerCertificates>) -> Option<Enrolled> {
        let Mode::Enrolled(enrolled) = self.mode() else {
            return None;
        };
        let presented = key_pin(peer?.end_entity()?)?;
        (presented == enrolled.operator_pin).then_some(enrolled)
    }

    pub(crate) fn status(&self, enrolled: &Enrolled) -> Result<Status, ErrorBody> {
        let subordinate = pem::certificates(&enrolled.chain_pem)
            .map_err(internal)?
            .first()
            .map(|der| inspect(der))
            .ok_or_else(|| internal("the stored chain is empty"))?
            .map_err(internal)?;
        Ok(self.status_from(&subordinate, enrolled))
    }

    pub(crate) fn status_from(&self, subordinate: &CertificateView, enrolled: &Enrolled) -> Status {
        Status {
            state: if enrolled.revoked {
                IssuerState::Revoked
            } else {
                self.issuer_state()
            },
            subordinate_serial: decimal(&subordinate.serial),
            subordinate_not_after: rfc_3339(subordinate.not_after),
            config: enrolled.config.clone(),
            versions: versions(),
        }
    }

    pub(crate) fn fresh_csr(&self, enrolled: &Enrolled) -> Result<FreshCsr, ErrorBody> {
        refuse_if_revoked(enrolled)?;
        Ok(FreshCsr {
            csr_pem: self.subordinate.fresh_csr().map_err(internal)?,
            configured_domains: self.domains.clone(),
        })
    }

    /// A renewed chain over the same key and root, with its config, checked as enrolment checks them.
    pub(crate) fn update_chain(&self, update: ChainUpdate) -> Result<Status, ErrorBody> {
        let _one_at_a_time = self.changing.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.enrolled()?;
        refuse_if_revoked(&current)?;
        let (subordinate, root) = self.check_chain(&update.chain_pem)?;
        if root != root_of(&current.chain_pem).map_err(internal)? {
            return Err(bad_request(
                "the chain ends in another root than the one enrolled",
            ));
        }
        self.check_config(&update.config, &subordinate)?;
        let renewed = Enrolled {
            chain_pem: update.chain_pem,
            config: update.config,
            ..current
        };
        self.store(renewed.clone())?;
        self.on_new_chain();
        Ok(self.status_from(&subordinate, &renewed))
    }

    /// Final: a revoked broker answers its status and further revokes, and nothing else.
    pub(crate) fn revoke(&self) -> Result<Status, ErrorBody> {
        let _one_at_a_time = self.changing.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.enrolled()?;
        if current.revoked {
            return self.status(&current);
        }
        let revoked = Enrolled {
            revoked: true,
            ..current
        };
        self.store(revoked.clone())?;
        tracing::warn!("revoked by opCA");
        self.on_revoked();
        self.status(&revoked)
    }

    fn enrolled(&self) -> Result<Enrolled, ErrorBody> {
        match self.mode() {
            Mode::Enrolled(enrolled) => Ok(enrolled),
            Mode::Enrolling => Err(internal("not enrolled")),
        }
    }

    fn store(&self, enrolled: Enrolled) -> Result<(), ErrorBody> {
        let json = serde_json::to_vec_pretty(&enrolled).map_err(internal)?;
        wslib_file_atomic::replace_private(&self.enrolment_path(), &json).map_err(internal)?;
        *self.mode.write().unwrap_or_else(|e| e.into_inner()) = Mode::Enrolled(enrolled);
        Ok(())
    }

    /// step-ca's seam: what it reports once it runs as the broker's child.
    fn issuer_state(&self) -> IssuerState {
        IssuerState::StepCaDown
    }

    /// step-ca's seam: start it, or reload it with the stored chain.
    pub(crate) fn on_new_chain(&self) {}

    /// step-ca's seam: stop it for good.
    fn on_revoked(&self) {}
}

fn refuse_if_revoked(enrolled: &Enrolled) -> Result<(), ErrorBody> {
    if enrolled.revoked {
        return Err(ErrorBody {
            kind: ErrorKind::Revoked,
            message: "the broker's subordinate is revoked".into(),
        });
    }
    Ok(())
}
