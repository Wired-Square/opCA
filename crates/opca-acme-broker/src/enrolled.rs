use std::sync::Arc;

use opca_acme_api::{
    API_VERSION, ChainUpdate, ErrorBody, ErrorKind, FreshCsr, IssuerState, Status, Versions,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use wslib_crypto::KeyAlgorithm;
use wslib_crypto_x509::{CertificateView, inspect, pem};
use wslib_http_server::PeerCertificates;
use wslib_pairing::SpkiSha256;
use wslib_tls::{KeyFingerprint, Location, Serving};

use crate::enrolment::{Enrolled, Mode, bad_request, decimal, internal, rfc_3339};
use crate::step_ca::Files;
use crate::{Broker, Error};

/// The API's TLS once enrolled: a client must chain to `root` and present the operator's key.
/// Blocks: the pinned `Serving` is a second one, read from the same files.
pub(crate) fn operator_config(
    provider: &Arc<CryptoProvider>,
    serving: &Serving,
    root: CertificateDer<'static>,
    operator_pin: &str,
) -> Result<Arc<ServerConfig>, Error> {
    let pin = operator_pin.parse()?;
    let location = serving.location();
    let pinned = Serving::load_or_mint(
        provider.clone(),
        Location::named(location.cert(), location.key()),
        Vec::new,
        KeyAlgorithm::EcP256,
    )?;
    if pinned.key_fingerprint() != serving.key_fingerprint() {
        return Err("the API key on disk is not the one being served".into());
    }
    Ok(pinned.with_client_auth_pinned(&[root], pin)?.config())
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
            versions: self.versions(),
        }
    }

    pub(crate) fn fresh_csr(&self, enrolled: &Enrolled) -> Result<FreshCsr, ErrorBody> {
        refuse_if_revoked(enrolled)?;
        Ok(FreshCsr {
            csr_pem: self.subordinate().fresh_csr().map_err(internal)?,
            configured_domains: self.domains.clone(),
        })
    }

    /// A renewed chain over the same key and root, with its config, checked as enrolment checks them.
    pub(crate) async fn update_chain(
        self: Arc<Self>,
        update: ChainUpdate,
    ) -> Result<Status, ErrorBody> {
        self.locked(|broker| broker.store_chain(update)).await
    }

    fn store_chain(&self, update: ChainUpdate) -> Result<Status, ErrorBody> {
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
    pub(crate) async fn revoke(self: Arc<Self>) -> Result<Status, ErrorBody> {
        self.locked(Broker::store_revocation).await
    }

    fn store_revocation(&self) -> Result<Status, ErrorBody> {
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

    /// From disk, not memory, so that a reopen the daemon has yet to reload is not undone.
    fn enrolled(&self) -> Result<Enrolled, ErrorBody> {
        match crate::enrolment::load(&self.state).map_err(internal)? {
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

    fn issuer_state(&self) -> IssuerState {
        if self.step_ca.is_running() {
            IssuerState::Issuing
        } else {
            IssuerState::StepCaDown
        }
    }

    /// Writes step-ca's config from the stored enrolment, then starts it or has it reload.
    pub(crate) fn on_new_chain(&self) {
        let Mode::Enrolled(enrolled) = self.mode() else {
            return;
        };
        if enrolled.revoked {
            return;
        }
        let written = Files::in_state(&self.state).write(
            &enrolled.chain_pem,
            &self.host,
            self.acme_listen,
            &enrolled.config,
        );
        match written {
            Ok(()) => self.step_ca.start_or_reload(),
            Err(error) => tracing::error!(%error, "could not write step-ca's config"),
        }
    }

    fn on_revoked(&self) {
        self.step_ca.stop();
    }

    /// Starts step-ca when enrolled and not revoked; needs a Tokio runtime.
    pub fn start_issuing(&self) {
        self.on_new_chain();
    }

    /// Stops step-ca, killing it if it hasn't gone within `patience`.
    pub async fn stop_issuing(&self, patience: std::time::Duration) {
        self.step_ca.stop_and_wait(patience).await;
    }

    pub(crate) fn versions(&self) -> Versions {
        Versions {
            api: API_VERSION,
            broker: env!("CARGO_PKG_VERSION").into(),
            step_ca: self.step_ca.version.to_string(),
        }
    }
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
