#![allow(dead_code)]

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use opca_acme_api::{Challenge, Enrolment, ErrorBody, ErrorKind, IssuanceConfig};
use opca_acme_broker::{Broker, Config};
use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::cert::{CertBundleConfig, CertType, CertificateBundle, KeyAlgorithm};
use opca_core::services::database::CertificateAuthorityDB;
use opca_core::services::database::models::CaConfig;
use opca_core::testutil::{FakeRunner, Output, created, fake_vault};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use wslib_crypto_x509::pem;
use wslib_http_server::{Bounds, Listener};
use wslib_pairing::{PairingUri, SpkiSha256};
use wslib_tls::{KeyFingerprint, Outbound, Trust};

pub const HOST: &str = "127.0.0.1";
pub const OPERATOR_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// An in-memory opCA root over a scripted `op`.
pub struct TestCa {
    pub ca: CertificateAuthority<FakeRunner>,
    op: FakeRunner,
}

/// A client certificate and its key, as the operator or anyone else presents it.
#[derive(Clone)]
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: Arc<PrivateKeyDer<'static>>,
}

impl Identity {
    pub fn key_pin(&self) -> String {
        let fingerprint = KeyFingerprint::of(&self.chain[0]).unwrap();
        SpkiSha256::from(*fingerprint.0.as_bytes()).to_string()
    }
}

impl TestCa {
    pub fn new() -> Self {
        let mut root = CertificateBundle::generate(
            CertType::Ca,
            "CA",
            CertBundleConfig {
                cn: Some("Test Root".into()),
                key_algorithm: Some(KeyAlgorithm::EcP256),
                next_serial: Some(1),
                ca_days: Some(3650),
                ..CertBundleConfig::default()
            },
        )
        .unwrap();
        root.self_sign_ca().unwrap();
        let op = FakeRunner::new();
        let ca = CertificateAuthority {
            vault: fake_vault(&op),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: Some(root),
            ca_database: Some(
                CertificateAuthorityDB::new(&CaConfig {
                    next_serial: Some(2),
                    days: Some(365),
                    ..CaConfig::default()
                })
                .unwrap(),
            ),
            crl: None,
            local_backup: None,
        };
        Self { ca, op }
    }

    /// Scripts the certificate item's create and the database store each issue makes.
    fn answer_issue(&self) {
        self.op.respond(created("CRT"));
        self.op.respond(Output::ok(""));
    }

    fn root_pem(&self) -> String {
        self.ca
            .ca_bundle
            .as_ref()
            .unwrap()
            .certificate_pem()
            .unwrap()
    }

    /// The subordinate signed through phase 21's `sign_subordinate`, then the
    /// root; its serial; and the broker row's id.
    pub fn sign(&mut self, csr_pem: &str, domains: &[&str]) -> (String, String, i64) {
        self.answer_issue();
        let domains: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        let signed = self
            .ca
            .sign_subordinate(csr_pem.as_bytes(), &domains, None)
            .unwrap();
        (
            format!("{}{}", signed.cert_pem, self.root_pem()),
            signed.broker.subordinate_serial,
            signed.broker.id,
        )
    }

    /// As [`sign`](Self::sign), through `renew_subordinate`.
    pub fn renew(&mut self, id: i64, csr_pem: &str) -> (String, String) {
        self.answer_issue();
        let signed = self
            .ca
            .renew_subordinate(id, csr_pem.as_bytes(), None, false, None)
            .unwrap();
        (
            format!("{}{}", signed.cert_pem, self.root_pem()),
            signed.broker.subordinate_serial,
        )
    }

    /// A VPN client certificate: one with client auth that the root signs for anyone.
    pub fn client(&mut self, cn: &str) -> Identity {
        self.answer_issue();
        let (bundle, _) = self
            .ca
            .generate_certificate_bundle(
                CertType::VpnClient,
                cn,
                CertBundleConfig {
                    cn: Some(cn.into()),
                    key_algorithm: Some(KeyAlgorithm::EcP256),
                    ..CertBundleConfig::default()
                },
                Some(30),
            )
            .unwrap();
        Identity {
            chain: pem::certificates(&bundle.certificate_pem().unwrap()).unwrap(),
            key: Arc::new(pem::private_key(&bundle.private_key_pem().unwrap()).unwrap()),
        }
    }
}

pub struct Running {
    pub state: TempDir,
    pub broker: Arc<Broker>,
    pub uri: PairingUri,
    pub port: u16,
}

pub fn private_tempdir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

pub fn config(state: &Path, domains: &[&str]) -> Config {
    Config {
        host: HOST.into(),
        domains: domains.iter().map(|d| d.to_string()).collect(),
        state_dir: state.into(),
        ..Config::parse(r#"host = "unused.example""#).unwrap()
    }
}

/// Starts a broker in `state` and serves it on a loopback port of its own.
pub async fn start(state: TempDir, domains: &[&str], uri: Option<PairingUri>) -> Running {
    let (broker, issued) = Broker::start(&config(state.path(), domains)).unwrap();
    let broker = Arc::new(broker);
    let listener = Listener::bind(format!("{HOST}:0").parse().unwrap(), Bounds::SERVING)
        .await
        .unwrap();
    let port = listener.local_addr().port();
    tokio::spawn(opca_acme_broker::serve(
        broker.clone(),
        listener,
        std::future::pending(),
    ));
    Running {
        state,
        broker,
        uri: issued
            .or(uri)
            .expect("a URI, issued now or kept from before"),
        port,
    }
}

pub async fn serve(state: TempDir, domains: &[&str]) -> Running {
    start(state, domains, None).await
}

impl Running {
    /// A connection that pins the URI's key, as opCA dials, presenting `identity` if given.
    pub async fn connect(&self, identity: Option<&Identity>) -> io::Result<Connection> {
        let mut trust = Trust::default();
        let pin = KeyFingerprint(wslib_crypto::Fingerprint::from(*self.uri.pin().as_bytes()));
        trust.pin_key(self.uri.host(), pin);
        let provider = Arc::new(rustls_openssl::default_provider());
        let outbound = Arc::new(Outbound::new(provider, trust).unwrap());
        let client = match identity {
            Some(identity) => outbound
                .client_config_presenting(identity.chain.clone(), identity.key.clone_key())
                .unwrap(),
            None => outbound.client_config(),
        };
        let tcp = TcpStream::connect((HOST, self.port)).await?;
        let tls = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from(HOST).unwrap(), tcp)
            .await?;
        Ok(Connection(tls))
    }

    /// One request on a connection of its own.
    pub async fn call(
        &self,
        identity: Option<&Identity>,
        method: &str,
        path: &str,
        body: &str,
    ) -> io::Result<(u16, String)> {
        self.connect(identity).await?.call(method, path, body).await
    }

    pub async fn post(&self, enrolment: &Enrolment) -> (u16, String) {
        let body = serde_json::to_string(enrolment).unwrap();
        self.call(None, "POST", opca_acme_api::path::ENROLMENT, &body)
            .await
            .unwrap()
    }

    pub fn enrolment(&self, chain_pem: &str, domains: &[&str]) -> Enrolment {
        Enrolment {
            code: self.uri.code().expose().into(),
            chain_pem: chain_pem.into(),
            operator_pin: OPERATOR_PIN.into(),
            config: IssuanceConfig {
                permitted_domains: domains.iter().map(|d| d.to_string()).collect(),
                leaf_days: 30,
                leaf_max_days: 45,
                challenges: vec![Challenge::Http01, Challenge::Dns01],
            },
        }
    }

    pub fn remaining(&self) -> u32 {
        match self.broker.code_status().unwrap() {
            wslib_pairing::Status::Pending { remaining, .. } => remaining,
            spent => panic!("{spent:?}"),
        }
    }
}

/// An HTTP/1.1 connection kept open across requests.
pub struct Connection(TlsStream<TcpStream>);

impl Connection {
    /// The status and body; an error when the server refused the connection,
    /// which under TLS 1.3 shows only once the client reads.
    pub async fn call(
        &mut self,
        method: &str,
        path: &str,
        body: &str,
    ) -> io::Result<(u16, String)> {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        self.0.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        let head_end = loop {
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
            let mut chunk = [0; 4096];
            match self.0.read(&mut chunk).await? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                read => response.extend_from_slice(&chunk[..read]),
            }
        };
        let head = String::from_utf8(response[..head_end].to_vec()).unwrap();
        let length: usize = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .map_or(0, |length| length.trim().parse().unwrap());
        let mut body = response[head_end..].to_vec();
        body.resize(length, 0);
        let already = response.len() - head_end;
        self.0.read_exact(&mut body[already..]).await?;
        Ok((
            head[9..12].parse().unwrap(),
            String::from_utf8(body).unwrap(),
        ))
    }
}

pub fn wrong(code: &str) -> String {
    let flipped = if code.starts_with('A') { 'B' } else { 'A' };
    format!("{flipped}{}", &code[1..])
}

pub fn error(body: &str) -> ErrorKind {
    serde_json::from_str::<ErrorBody>(body).unwrap().kind
}
