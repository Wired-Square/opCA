//! The ACME listener on `acme_listen`, and its own TLS certificate for `host`,
//! issued from the subordinate and never recorded as an ACME certificate.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use tokio::net::TcpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use wslib_crypto::{KeyAlgorithm, Signer, key_matches};
use wslib_crypto_ca::{Csr, Subject, Validity, build_csr};
use wslib_crypto_x509::pem::{self, PRIVATE_KEY};
use wslib_crypto_x509::{SubjectAltName, inspect};
use wslib_http_server::{Bounds, Listener, Tls, server_config_from_pem_files};

use super::issue::{BACKDATE, Issuer};
use super::server::{Server, router};
use super::validate::Validate;
use crate::enrolment::{Enrolled, Mode};
use crate::{Broker, Error};

const CERT: &str = "acme.crt";
const KEY: &str = "acme.key";
const LIFETIME: Duration = Duration::from_secs(30 * 86_400);
const CHECK_EVERY: Duration = Duration::from_secs(3600);
const RETRY_AFTER: Duration = Duration::from_secs(10);

pub(crate) struct AcmeListener {
    address: SocketAddr,
    server: Arc<Server>,
    running: Mutex<Option<Running>>,
}

struct Running {
    tls: Tls,
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    served: JoinHandle<()>,
}

impl AcmeListener {
    pub(crate) fn new(address: SocketAddr, server: Server) -> Self {
        Self {
            address,
            server: Arc::new(server),
            running: Mutex::default(),
        }
    }

    /// The address bound, while serving.
    pub(crate) fn serving(&self) -> Option<SocketAddr> {
        self.lock()
            .as_ref()
            .filter(|running| !running.served.is_finished())
            .map(|running| running.address)
    }

    /// Serves `config` from now on, binding first unless already serving; needs a Tokio runtime.
    fn serve(&self, config: Arc<ServerConfig>) -> io::Result<()> {
        let mut running = self.lock();
        if let Some(serving) = running.as_ref().filter(|r| !r.served.is_finished()) {
            serving.tls.reload(config);
            return Ok(());
        }
        let listener = bind(self.address)?;
        let address = listener.local_addr();
        let tls = Tls::new(config);
        let (stop, stopped) = oneshot::channel();
        self.server.resume();
        let served = tokio::spawn({
            let tls = tls.clone();
            let router = router(self.server.clone());
            async move {
                let stopped = async {
                    let _ = stopped.await;
                };
                if let Err(error) =
                    wslib_http_server::serve_https(listener, router, tls, stopped).await
                {
                    tracing::error!(%error, "the ACME listener failed");
                }
            }
        });
        *running = Some(Running {
            tls,
            address,
            stop,
            served,
        });
        Ok(())
    }

    /// Stops accepting; what it was serving drains behind the handle.
    fn stop(&self) -> Option<JoinHandle<()>> {
        let running = self.lock().take()?;
        let _ = running.stop.send(());
        Some(running.served)
    }

    fn lock(&self) -> MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// As `TcpListener::bind` does, but without awaiting, so that it runs under the state lock.
fn bind(address: SocketAddr) -> io::Result<Listener> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    Listener::from_tcp(socket.listen(1024)?, Bounds::SERVING)
        .map_err(|e| io::Error::new(e.kind(), format!("listening on {address}: {e}")))
}

impl Broker {
    /// The ACME listener's address, while it serves.
    pub fn acme_address(&self) -> Option<SocketAddr> {
        self.acme_listener.serving()
    }

    /// What validates challenges; a [`Validator`](super::validate::Validator) over the system's resolvers unless set.
    pub fn with_validator(mut self, validator: impl Validate) -> Self {
        self.acme_server().validator = Arc::new(validator);
        self
    }

    /// How long an order and its authorisations live; [`ORDER_LIFETIME`](super::ORDER_LIFETIME) unless set.
    pub fn with_order_lifetime(mut self, lifetime: Duration) -> Self {
        self.acme_server().lifetime = lifetime;
        self
    }

    fn acme_server(&mut self) -> &mut Server {
        Arc::get_mut(&mut self.acme_listener.server).expect("configured before it serves")
    }

    /// Keeps the ACME listener and its certificate current until `stop`
    /// completes, then stops it and waits for it to drain.
    pub async fn serve_acme(self: Arc<Self>, stop: impl Future<Output = ()>) {
        let mut stop = std::pin::pin!(stop);
        loop {
            let refreshed = self.locked(|broker| Ok(broker.refresh_acme())).await;
            let wait = if refreshed == Ok(true) {
                CHECK_EVERY
            } else {
                RETRY_AFTER
            };
            if tokio::time::timeout(wait, &mut stop).await.is_ok() {
                break;
            }
        }
        if let Some(served) = self.acme_listener.stop() {
            let _ = served.await;
        }
    }

    /// Serves ACME while enrolled and not revoked, reissuing the certificate
    /// when it is no longer current; under the state lock. `false` when it
    /// should serve and can't.
    pub(crate) fn refresh_acme(&self) -> bool {
        let enrolled = match self.mode() {
            Mode::Enrolled(enrolled) if !enrolled.revoked => enrolled,
            _ => {
                if self.acme_listener.stop().is_some() {
                    tracing::info!("stopped serving ACME");
                }
                return true;
            }
        };
        match self.serve_acme_under(&enrolled, SystemTime::now()) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(%error, "could not serve ACME");
                false
            }
        }
    }

    fn serve_acme_under(&self, enrolled: &Enrolled, now: SystemTime) -> Result<(), Error> {
        let (cert, key) = (self.state.join(CERT), self.state.join(KEY));
        let current = still_current(
            &self.provider,
            &read(&cert),
            &read(&key),
            &enrolled.chain_pem,
            &self.host,
            now,
        );
        let issuer = Issuer::new(
            self.subordinate().signer()?,
            &enrolled.chain_pem,
            enrolled.config.clone(),
        )?;
        if !current {
            let (cert_pem, key_pem) = issue_pair(&self.provider, &issuer, &self.host, now)?;
            wslib_file_atomic::replace_private(&key, key_pem.as_bytes())?;
            wslib_file_atomic::replace_readable(&cert, cert_pem.as_bytes())?;
            tracing::info!(host = %self.host, "issued the ACME listener's certificate");
        }
        self.acme_listener.server.set_issuer(issuer);
        if current && self.acme_listener.serving().is_some() {
            return Ok(());
        }
        let config = server_config_from_pem_files(self.provider.clone(), &cert, &key)?;
        self.acme_listener.serve(config)?;
        Ok(())
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// A serverAuth leaf for `host` over a new P-256 key, followed by the chain
/// without the root, and the key; for [`LIFETIME`], capped by the subordinate's end.
fn issue_pair(
    provider: &Arc<CryptoProvider>,
    issuer: &Issuer,
    host: &str,
    now: SystemTime,
) -> Result<(String, String), Error> {
    let validity = Validity {
        not_before: now - BACKDATE,
        not_after: (now + LIFETIME).min(issuer.subordinate_not_after()),
    };
    if validity.not_after <= now {
        return Err("the subordinate has expired".into());
    }
    let key = KeyAlgorithm::EcP256.generate()?;
    let key_pem = pem::encode(PRIVATE_KEY, key.secret_pkcs8_der());
    let signer = Signer::new(provider.clone(), &PrivateKeyDer::Pkcs8(key))?;
    let csr_der = build_csr(&signer, &Subject::new(host), &[host.parse()?])?;
    let csr = Csr::from_der(&csr_der, provider.signature_verification_algorithms.all)?;
    let (_, cert_pem) = issuer.sign(&csr, Some(host), validity)?;
    Ok((cert_pem, key_pem))
}

/// Whether the pair on disk is for `host`, served with `chain_pem`'s subordinate,
/// holds together and is short of two-thirds of its life at `now`. The leaf was
/// capped by that subordinate's end, so a new chain is always a reissue.
fn still_current(
    provider: &CryptoProvider,
    cert_pem: &str,
    key_pem: &str,
    chain_pem: &str,
    host: &str,
    now: SystemTime,
) -> bool {
    let check = || -> Option<bool> {
        let served = pem::certificates(cert_pem).ok()?;
        let mut chain = pem::certificates(chain_pem).ok()?;
        chain.pop();
        let (leaf, served_chain) = served.split_first()?;
        let leaf = inspect(leaf).ok()?;
        let lifetime = leaf.not_after.duration_since(leaf.not_before).ok()?;
        let key = pem::private_key(key_pem).ok()?;
        Some(
            served_chain == chain
                && leaf.sans == [SubjectAltName::Dns(host.into())]
                && now < leaf.not_before + lifetime * 2 / 3
                && key_matches(provider, &key, &leaf.spki).ok()?,
        )
    };
    check().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use opca_acme_api::{Challenge, IssuanceConfig};
    use wslib_crypto_ca::{
        Authority, BasicConstraints, Extension, KeyIdentifierMethod, Profile, Serial,
    };
    use wslib_crypto_x509::pem::CERTIFICATE;
    use wslib_crypto_x509::{ExtendedKeyUsage, KeyUsage};

    use super::*;

    const HOST: &str = "acme.home.example";
    const DAY: Duration = Duration::from_secs(86_400);

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls_openssl::default_provider())
    }

    /// A self-signed CA, standing in for both the subordinate and the root, that ends `days` from `now`.
    fn chain(now: SystemTime, days: u32) -> (String, Issuer) {
        let key = KeyAlgorithm::EcP256.generate().unwrap();
        let signer = || Signer::new(provider(), &PrivateKeyDer::Pkcs8(key.clone_key())).unwrap();
        let profile = Profile {
            basic_constraints: Some(Extension::critical(BasicConstraints::Authority {
                path_length: Some(0),
            })),
            key_usage: Some(Extension::critical(vec![KeyUsage::KeyCertSign])),
            ..Profile::default()
        };
        let ca = Authority::self_signed(
            signer(),
            &Subject::new("Test Subordinate").to_der().unwrap(),
            &profile,
            &Serial::try_from(1u64).unwrap(),
            Validity {
                not_before: now - DAY,
                not_after: now + DAY * days,
            },
            KeyIdentifierMethod::Sha1,
        )
        .unwrap();
        let ca_pem = pem::encode(CERTIFICATE, ca.certificate());
        let chain_pem = ca_pem.repeat(2);
        let config = IssuanceConfig {
            permitted_domains: vec!["home.example".into()],
            leaf_days: 30,
            leaf_max_days: 45,
            challenges: vec![Challenge::Http01],
        };
        let issuer = Issuer::new(signer(), &chain_pem, config).unwrap();
        (chain_pem, issuer)
    }

    #[test]
    fn the_certificate_is_a_server_leaf_for_the_host_served_with_the_subordinate() {
        let now = SystemTime::now();
        let (chain_pem, issuer) = chain(now, 365);
        let (cert_pem, _) = issue_pair(&provider(), &issuer, HOST, now).unwrap();
        let served = pem::certificates(&cert_pem).unwrap();
        assert_eq!(served[1..], pem::certificates(&chain_pem).unwrap()[..1]);
        let leaf = inspect(&served[0]).unwrap();
        assert_eq!(leaf.sans, [SubjectAltName::Dns(HOST.into())]);
        assert_eq!(leaf.subject, format!("CN={HOST}"));
        assert!(!leaf.ca);
        assert_eq!(
            leaf.extended_key_usages,
            Some(vec![ExtendedKeyUsage::ServerAuth])
        );
        let short_of_lifetime = (now + LIFETIME).duration_since(leaf.not_after).unwrap();
        assert!(short_of_lifetime < Duration::from_secs(1));
    }

    #[test]
    fn the_certificate_is_capped_by_the_subordinates_end_and_refused_past_it() {
        let now = SystemTime::now();
        let (_, issuer) = chain(now, 3);
        let (cert_pem, _) = issue_pair(&provider(), &issuer, HOST, now).unwrap();
        let leaf = inspect(&pem::certificates(&cert_pem).unwrap()[0]).unwrap();
        assert_eq!(leaf.not_after, issuer.subordinate_not_after());
        assert!(issue_pair(&provider(), &issuer, HOST, now + DAY * 4).is_err());
    }

    #[test]
    fn the_certificate_is_reissued_once_stale() {
        let provider = provider();
        let now = SystemTime::now();
        let (chain_pem, issuer) = chain(now, 365);
        let (cert_pem, key_pem) = issue_pair(&provider, &issuer, HOST, now).unwrap();
        let current = |cert: &str, key: &str, chain: &str, host: &str, at: SystemTime| {
            still_current(&provider, cert, key, chain, host, at)
        };
        assert!(current(&cert_pem, &key_pem, &chain_pem, HOST, now));
        assert!(current(
            &cert_pem,
            &key_pem,
            &chain_pem,
            HOST,
            now + DAY * 19
        ));

        let (_, other_key) = issue_pair(&provider, &issuer, HOST, now).unwrap();
        let (other_chain, _) = chain(now, 365);
        for (why, stale) in [
            (
                "two-thirds through",
                current(&cert_pem, &key_pem, &chain_pem, HOST, now + DAY * 21),
            ),
            (
                "another host",
                current(&cert_pem, &key_pem, &chain_pem, "www.home.example", now),
            ),
            (
                "another key",
                current(&cert_pem, &other_key, &chain_pem, HOST, now),
            ),
            (
                "another subordinate",
                current(&cert_pem, &key_pem, &other_chain, HOST, now),
            ),
            ("missing", current("", "", &chain_pem, HOST, now)),
        ] {
            assert!(!stale, "{why}");
        }
    }
}
