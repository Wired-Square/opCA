use std::sync::Arc;

use opca_acme_api::{
    API_VERSION, ChainUpdate, ErrorBody, ErrorKind, FreshCsr, IssuedCertificate, IssuedPage,
    IssuerState, Status, Versions,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use wslib_crypto::KeyAlgorithm;
use wslib_crypto_x509::{CertificateView, inspect, pem};
use wslib_http_server::PeerCertificates;
use wslib_pairing::SpkiSha256;
use wslib_tls::{KeyFingerprint, Location, Serving};

use crate::acme::store::Certificate;
use crate::enrolment::{Enrolled, Mode, bad_request, decimal, internal, rfc_3339};
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
            issued: None,
        }
    }

    /// `status` with the issued counts, or without them when `acme.db` can't count.
    pub(crate) async fn counted(
        &self,
        status: Result<Status, ErrorBody>,
    ) -> Result<Status, ErrorBody> {
        let mut status = status?;
        let issuers = match self.mode() {
            Mode::Enrolled(enrolled) => enrolled.issuers,
            Mode::Enrolling => None,
        };
        status.issued = self
            .acme()
            .counts(issuers.as_deref())
            .await
            .inspect_err(|error| tracing::error!(%error, "counting the issued certificates"))
            .ok();
        Ok(status)
    }

    pub(crate) async fn issued(
        &self,
        enrolled: &Enrolled,
        after: u64,
    ) -> Result<IssuedPage, ErrorBody> {
        let cursor = i64::try_from(after).map_err(bad_request)?;
        let changes = self
            .acme()
            .changed_after(cursor, enrolled.issuers.as_deref(), self.issued_page)
            .await
            .map_err(internal)?;
        let certificates: Vec<_> = changes.certificates.into_iter().map(issued).collect();
        Ok(IssuedPage {
            next: certificates.last().map_or(after, |last| last.changed),
            more: changes.more,
            certificates,
        })
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
        let issuers = current
            .issuers
            .map(|serials| [serials, vec![decimal(&subordinate.serial)]].concat());
        let renewed = Enrolled {
            chain_pem: update.chain_pem,
            config: update.config,
            issuers,
            ..current
        };
        self.store(renewed.clone())?;
        self.refresh_acme();
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
        self.refresh_acme();
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
        if self.acme_listener.serving().is_some() {
            IssuerState::Issuing
        } else {
            IssuerState::AcmeDown
        }
    }

    pub(crate) fn versions(&self) -> Versions {
        Versions {
            api: API_VERSION,
            broker: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

pub(crate) fn issued(certificate: Certificate) -> IssuedCertificate {
    IssuedCertificate {
        serial: certificate.serial,
        common_name: certificate.common_name,
        sans: certificate.sans,
        not_before: rfc_3339(certificate.not_before),
        not_after: rfc_3339(certificate.not_after),
        issuer_serial: certificate.issuer_serial,
        revoked_at: certificate.revoked_at.map(rfc_3339),
        revocation_reason: certificate.revocation_reason,
        changed: certificate.changed as u64,
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
