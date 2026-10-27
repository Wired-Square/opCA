use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use rustls::crypto::CryptoProvider;
use rustls_openssl::default_provider;
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_ca::{CERTIFICATE_REQUEST, CsrView, Subject, build_csr};
use wslib_crypto_x509::SubjectAltName;
use wslib_crypto_x509::pem::{self, PRIVATE_KEY};
use wslib_http_server::Tls;
use wslib_pairing::{OneTimeCode, PairingCode, PairingUri, SpkiSha256, Status};
use wslib_service::Held;
use wslib_tls::{Location, Serving};

use crate::enrolled::{operator_config, root_of};
use crate::enrolment::{self, Mode, host_within};
use crate::step_ca::{Files, StepCa, check_version};
use crate::{Config, Error};

pub const SCHEME: &str = "opca-enrol";
pub const ATTEMPTS: NonZeroU32 = NonZeroU32::new(5).unwrap();

/// The broker's state: its subordinate key and CSR, its API identity, its
/// pairing code, and whether it is enrolled.
pub struct Broker {
    pub(crate) provider: Arc<CryptoProvider>,
    pub(crate) serving: Serving,
    pub(crate) tls: Tls,
    pub(crate) subordinate: Subordinate,
    pub(crate) code: Arc<OneTimeCode>,
    pub(crate) mode: RwLock<Mode>,
    pub(crate) changing: Mutex<()>,
    pub(crate) host: String,
    port: u16,
    pub(crate) domains: Vec<String>,
    pub(crate) state: PathBuf,
    pub(crate) step_ca: Arc<StepCa>,
    pub(crate) acme_listen: SocketAddr,
    _held: Held,
}

impl Broker {
    /// Loads the state in `config.state_dir`, making only what is missing, and
    /// blocks; the URI is `Some` when this start issued the pairing code.
    pub fn start(config: &Config) -> Result<(Self, Option<PairingUri>), Error> {
        let name = config.host.parse::<SubjectAltName>()?;
        if !name.is_host() {
            return Err(format!("{} is not a host name or address", config.host).into());
        }
        let version = check_version(&config.step_ca)?;
        let state = config.state_dir.as_path();
        let held = wslib_service::private_directory(state)?;
        let provider = Arc::new(default_provider());
        let subordinate = Subordinate::load_or_generate(provider.clone(), state, &config.host)?;
        let location = Location::managed(state.join("api.crt"), state.join("api.key"));
        let serving = Serving::load_or_mint(
            provider.clone(),
            location,
            || vec![name],
            KeyAlgorithm::EcP256,
        )?;
        let code_path = state.join("pairing-code");
        let (code, issued) = match OneTimeCode::open(&code_path)? {
            Some(code) => (code, None),
            None => {
                let (code, plain) = OneTimeCode::issue(&code_path, ATTEMPTS)?;
                (code, Some(plain))
            }
        };
        let mode = enrolment::load(state)?;
        let tls = Tls::new(match &mode {
            Mode::Enrolling => serving.config(),
            Mode::Enrolled(enrolled) => operator_config(
                &provider,
                &serving,
                root_of(&enrolled.chain_pem)?,
                &enrolled.operator_pin,
            )?,
        });
        let broker = Self {
            provider,
            serving,
            tls,
            subordinate,
            code: Arc::new(code),
            mode: RwLock::new(mode),
            changing: Mutex::new(()),
            host: config.host.clone(),
            port: config.listen.port(),
            domains: config.domains.clone(),
            state: state.into(),
            step_ca: StepCa::new(
                config.step_ca.clone(),
                Files::in_state(state).config,
                version,
            ),
            acme_listen: config.acme_listen,
            _held: held,
        };
        if let Mode::Enrolled(enrolled) = broker.mode()
            && enrolled.api_pin != broker.pin().to_string()
        {
            tracing::error!(
                recorded = %enrolled.api_pin,
                serving = %broker.pin(),
                "the API key is not the one opCA pinned at enrolment, so opCA will refuse it"
            );
        }
        if issued.is_some()
            && (config.host.parse::<std::net::IpAddr>().is_ok()
                || !(config.domains.is_empty() || host_within(&config.host, &config.domains)))
        {
            tracing::warn!(
                host = %config.host,
                "the host is not a name within the configured domains, so enrolment will be \
                 refused: step-ca's own TLS certificate is issued for it"
            );
        }
        let uri = issued.map(|plain| broker.uri(plain)).transpose()?;
        Ok((broker, uri))
    }

    pub fn serving(&self) -> &Serving {
        &self.serving
    }

    pub fn subordinate(&self) -> &Subordinate {
        &self.subordinate
    }

    /// The SHA-256 of the API key's SubjectPublicKeyInfo, as the pairing URI carries it.
    pub fn pin(&self) -> SpkiSha256 {
        SpkiSha256::from(*self.serving.key_fingerprint().0.as_bytes())
    }

    pub fn mode(&self) -> Mode {
        self.mode.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn code_status(&self) -> Result<Status, Error> {
        Ok(self.code.status()?)
    }

    fn uri(&self, code: PairingCode) -> Result<PairingUri, Error> {
        Ok(PairingUri::new(
            SCHEME,
            &self.host,
            self.port,
            self.pin(),
            code,
        )?)
    }
}

/// The subordinate CA's key, unencrypted and owner-only, and its CSR.
pub struct Subordinate {
    signer: Signer,
    subject: Subject,
    csr_pem: String,
}

impl Subordinate {
    fn load_or_generate(
        provider: Arc<CryptoProvider>,
        state: &Path,
        host: &str,
    ) -> Result<Self, Error> {
        let key_path = state.join("subordinate.key");
        if !key_path.try_exists()? {
            let key = KeyAlgorithm::EcP256.generate()?;
            let key_pem = pem::encode(PRIVATE_KEY, key.secret_pkcs8_der());
            wslib_file_atomic::replace_private(&key_path, key_pem.as_bytes())?;
            tracing::info!(key = %key_path.display(), "made the subordinate key");
        }
        let key = pem::private_key(&read(&key_path)?)
            .map_err(|e| format!("{}: {e}", key_path.display()))?;
        let signer = Signer::new(provider, &key)?;

        let subject = Subject::new(format!("opCA ACME broker {host}"));
        let csr_path = state.join("subordinate.csr");
        let stored = match read(&csr_path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            read => Some(read?),
        };
        let csr_pem = match stored.filter(|pem| carries(pem, &signer, &subject)) {
            Some(pem) => pem,
            None => {
                let csr_pem = csr(&signer, &subject)?;
                wslib_file_atomic::replace_readable(&csr_path, csr_pem.as_bytes())?;
                csr_pem
            }
        };
        Ok(Self {
            signer,
            subject,
            csr_pem,
        })
    }

    /// A new CSR over the same key, for a renewal.
    pub fn fresh_csr(&self) -> Result<String, Error> {
        csr(&self.signer, &self.subject)
    }

    /// The DER SubjectPublicKeyInfo of the subordinate key.
    pub fn spki(&self) -> &[u8] {
        self.signer.spki()
    }

    pub fn csr_pem(&self) -> &str {
        &self.csr_pem
    }
}

fn csr(signer: &Signer, subject: &Subject) -> Result<String, Error> {
    Ok(pem::encode(
        CERTIFICATE_REQUEST,
        &build_csr(signer, subject, &[])?,
    ))
}

fn carries(csr_pem: &str, signer: &Signer, subject: &Subject) -> bool {
    CsrView::from_pem(csr_pem).is_ok_and(|csr| {
        csr.spki() == signer.spki() && csr.common_name() == Some(&subject.common_name)
    })
}

fn read(path: &Path) -> io::Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}
