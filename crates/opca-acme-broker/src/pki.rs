//! The subordinate's certificate and its leaves' CRL: signed from `acme.db`,
//! kept fresh, and served over plain HTTP on the PKI listener and over HTTPS on
//! the ACME listener.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rustls::pki_types::CertificateDer;
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;
use wslib_crypto_ca::{Authority, CrlView, KeyIdentifierMethod, Reason, Revocation};
use wslib_crypto_x509::pem;
use wslib_http_server::{Listener, serve_http};

use crate::acme::issue::BACKDATE;
use crate::acme::store::Certificate;
use crate::enrolment::{Enrolled, Mode, internal};
use crate::{Broker, Error};

pub const CA_PATH: &str = "/ca.crt";
pub const CRL_PATH: &str = "/crl";
pub(crate) const CA_FILE: &str = "ca.crt";
pub(crate) const CRL_FILE: &str = "leaves.crl";

const CRL_LIFE: Duration = Duration::from_secs(4 * 86_400);
const RESIGN_WITHIN: Duration = Duration::from_secs(3 * 86_400);
const CHECK_EVERY: Duration = Duration::from_secs(3600);
const RETRY_AFTER: Duration = Duration::from_secs(60);

/// `scheme://host:port`, an IPv6 address in brackets, and the port left out when it is the scheme's own.
pub(crate) fn origin(scheme: &str, host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match (scheme, port) {
        ("http", 80) | ("https", 443) => format!("{scheme}://{host}"),
        _ => format!("{scheme}://{host}:{port}"),
    }
}

/// The files the PKI routes serve, and whether they serve them: only while
/// enrolled with a subordinate that isn't revoked.
pub(crate) struct Published {
    state: PathBuf,
    live: AtomicBool,
    stale: AtomicBool,
    due: Notify,
    signing: Mutex<()>,
}

impl Published {
    pub(crate) fn new(state: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            state,
            live: AtomicBool::new(false),
            stale: AtomicBool::new(false),
            due: Notify::new(),
            signing: Mutex::new(()),
        })
    }

    /// Serves while `live`, and has the CRL looked at again.
    pub(crate) fn set_live(&self, live: bool) {
        self.live.store(live, Ordering::SeqCst);
        self.due.notify_one();
    }

    /// Has the CRL signed afresh, as after a revocation.
    pub(crate) fn resign(&self) {
        self.stale.store(true, Ordering::SeqCst);
        self.due.notify_one();
    }

    fn read(&self, file: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.state.join(file))
    }

    fn served(&self, file: &str) -> Option<Vec<u8>> {
        self.live
            .load(Ordering::SeqCst)
            .then(|| self.read(file).ok())
            .flatten()
    }

    /// The CRL being served.
    pub(crate) fn crl(&self) -> Option<CrlView> {
        CrlView::from_der(&self.served(CRL_FILE)?).ok()
    }

    /// How long the CRL on disk has left, if `subordinate` signed it and is the certificate on disk.
    fn fresh_for(&self, subordinate: &CertificateDer<'_>, now: SystemTime) -> Option<Duration> {
        if self.read(CA_FILE).ok()? != subordinate[..] {
            return None;
        }
        let crl = CrlView::from_der(&self.read(CRL_FILE).ok()?).ok()?;
        let algorithms = rustls_openssl::default_provider().signature_verification_algorithms;
        crl.verify(subordinate, algorithms.all).ok()?;
        crl.next_update?.duration_since(now).ok()
    }
}

/// `GET` and `HEAD` of [`CA_PATH`] and [`CRL_PATH`], DER, cached for the CRL's remaining life.
pub(crate) fn routes(published: Arc<Published>) -> Router {
    Router::new()
        .route(CA_PATH, get(ca))
        .route(CRL_PATH, get(crl))
        .with_state(published)
}

async fn ca(State(published): State<Arc<Published>>) -> Response {
    serve(&published, CA_FILE, "application/pkix-cert")
}

async fn crl(State(published): State<Arc<Published>>) -> Response {
    serve(&published, CRL_FILE, "application/pkix-crl")
}

fn serve(published: &Published, file: &str, content_type: &'static str) -> Response {
    let Some(body) = published.served(file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let left = published
        .crl()
        .and_then(|crl| crl.next_update?.duration_since(SystemTime::now()).ok())
        .unwrap_or_default();
    let cache = format!("max-age={}", left.as_secs());
    (
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CACHE_CONTROL, cache),
        ],
        body,
    )
        .into_response()
}

fn reason(code: Option<u8>) -> Option<Reason> {
    Some(match code? {
        1 => Reason::KeyCompromise,
        2 => Reason::CaCompromise,
        3 => Reason::AffiliationChanged,
        4 => Reason::Superseded,
        5 => Reason::CessationOfOperation,
        6 => Reason::CertificateHold,
        8 => Reason::RemoveFromCrl,
        9 => Reason::PrivilegeWithdrawn,
        10 => Reason::AaCompromise,
        _ => return None,
    })
}

fn revocation(certificate: Certificate) -> Result<Revocation, Error> {
    Ok(Revocation {
        reason: reason(certificate.revocation_reason),
        ..Revocation::new(
            certificate.serial.parse()?,
            certificate.revoked_at.ok_or("not revoked")?,
        )
    })
}

impl Broker {
    /// Serves the PKI routes on `listener`, and keeps the CRL fresh, until `stop`.
    pub async fn serve_pki(
        self: Arc<Self>,
        listener: Listener,
        stop: CancellationToken,
    ) -> io::Result<()> {
        let routes = routes(self.published.clone());
        let (served, ()) = tokio::join!(
            serve_http(listener, routes, stop.clone().cancelled_owned()),
            self.keep_crl_fresh(stop),
        );
        served
    }

    async fn keep_crl_fresh(self: &Arc<Self>, stop: CancellationToken) {
        loop {
            let force = self.published.stale.swap(false, Ordering::SeqCst);
            let wait = self.refresh_crl(force).await.unwrap_or_else(|error| {
                tracing::error!(%error, "could not sign the CRL");
                if force {
                    self.published.stale.store(true, Ordering::SeqCst);
                }
                RETRY_AFTER
            });
            tokio::select! {
                () = stop.cancelled() => return,
                () = self.published.due.notified() => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// Signs a CRL when `force`d, or when the one on disk isn't the current
    /// subordinate's or has under [`RESIGN_WITHIN`] left, one signing at a
    /// time. How long until it wants another look.
    pub(crate) async fn refresh_crl(self: &Arc<Self>, force: bool) -> Result<Duration, Error> {
        let _one_at_a_time = self.published.signing.lock().await;
        let enrolled = match self.mode() {
            Mode::Enrolled(enrolled) if !enrolled.revoked => enrolled,
            _ => return Ok(CHECK_EVERY),
        };
        let subordinate = pem::certificates(&enrolled.chain_pem)?
            .into_iter()
            .next()
            .ok_or("the stored chain is empty")?;
        let now = SystemTime::now();
        match self.published.fresh_for(&subordinate, now) {
            Some(left) if !force && left > RESIGN_WITHIN => {
                Ok((left - RESIGN_WITHIN).min(CHECK_EVERY))
            }
            _ => {
                self.sign_crl(&enrolled, subordinate, now).await?;
                Ok(CHECK_EVERY)
            }
        }
    }

    /// Every unexpired revoked leaf of this enrolment's subordinates, which
    /// share the current one's key and name, signed under the next number.
    async fn sign_crl(
        self: &Arc<Self>,
        enrolled: &Enrolled,
        subordinate: CertificateDer<'static>,
        now: SystemTime,
    ) -> Result<(), Error> {
        let revoked = self
            .acme()
            .revoked_unexpired(enrolled.issuers.as_deref(), now)
            .await?
            .into_iter()
            .map(revocation)
            .collect::<Result<Vec<_>, _>>()?;
        let number = self.acme().next_crl_number().await?;
        let authority = Authority::new(
            subordinate.clone(),
            self.subordinate().signer()?,
            KeyIdentifierMethod::Sha1,
        )?;
        let this_update = now - BACKDATE;
        let crl =
            authority.revocation_list(number, this_update, this_update + CRL_LIFE, &revoked)?;
        self.locked(move |broker| {
            let write = |file, der: &[u8]| {
                wslib_file_atomic::replace_readable(&broker.state.join(file), der).map_err(internal)
            };
            write(CA_FILE, &subordinate)?;
            write(CRL_FILE, &crl)
        })
        .await
        .map_err(|refused| refused.message)?;
        tracing::info!(number, revoked = revoked.len(), "signed the CRL");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_acme_takes_but_unspecified_reaches_the_crl() {
        for code in opca_acme_api::REVOCATION_REASONS {
            assert_eq!(reason(Some(code)).is_some(), code != 0, "{code}");
        }
        assert_eq!(reason(None), None);
    }

    #[test]
    fn origins_bracket_ipv6_addresses_and_leave_out_the_default_port() {
        assert_eq!(
            origin("http", "acme.home.example", 8080),
            "http://acme.home.example:8080"
        );
        assert_eq!(origin("https", "fd00::5", 8443), "https://[fd00::5]:8443");
        assert_eq!(
            origin("http", "acme.home.example", 80),
            "http://acme.home.example"
        );
        assert_eq!(origin("https", "fd00::5", 443), "https://[fd00::5]");
        assert_eq!(
            origin("http", "acme.home.example", 443),
            "http://acme.home.example:443"
        );
    }
}
