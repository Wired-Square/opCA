#![allow(dead_code)]

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use opca_acme_api::{Challenge, Enrolment, ErrorBody, ErrorKind, IssuanceConfig, Status};
use opca_acme_broker::acme::Store;
use opca_acme_broker::acme::store::{ChallengeStatus, NewAuthorisation, NewCertificate, NewOrder};
use opca_acme_broker::app::{APP_SOCKET, App, HOOKS_SOCKET, Hooked};
use opca_acme_broker::{Broker, Config};
use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::cert::{CertBundleConfig, CertType, CertificateBundle, KeyAlgorithm};
use opca_core::services::database::CertificateAuthorityDB;
use opca_core::services::database::models::CaConfig;
use opca_core::testutil::{FakeRunner, Output, created, fake_vault};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use wslib_crypto_ca::CrlView;
use wslib_crypto_x509::pem;
use wslib_http_server::{Bounds, Listener};
use wslib_pairing::{PairingUri, SpkiSha256};
use wslib_tls::{KeyFingerprint, Outbound, Trust};

/// The broker's host, inside the test domain; it is dialled at [`LOOPBACK`].
pub const HOST: &str = "acme.home.example";
pub const LOOPBACK: &str = "127.0.0.1";
pub const OPERATOR_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const DOMAINS: &[&str] = &["home.example"];

/// An in-memory opCA root over a scripted `op`.
pub struct TestCa {
    pub ca: CertificateAuthority<FakeRunner>,
    pub op: FakeRunner,
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
    pub api: Api,
    /// Where the PKI listener serves, on loopback.
    pub pki: SocketAddr,
}

impl std::ops::Deref for Running {
    type Target = Api;

    fn deref(&self) -> &Api {
        &self.api
    }
}

/// A broker's API as opCA reaches it: pinned by the URI, dialled at `address`.
pub struct Api {
    pub uri: PairingUri,
    pub address: SocketAddr,
}

pub fn private_tempdir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// The uid this test runs as.
pub fn own_uid() -> u32 {
    fs::metadata(private_tempdir().path()).unwrap().uid()
}

/// `app`'s two sockets for `hooked`, in a directory of their own, once both answer.
pub async fn serve_console(app: App, hooked: Hooked) -> TempDir {
    let sockets = private_tempdir();
    let path = sockets.path().to_owned();
    let logs = wslib_appliance_server::logs(&[]);
    tokio::spawn(async move {
        let stop = std::future::pending();
        app.serve_console(&path, hooked, logs, stop).await.unwrap()
    });
    for socket in [APP_SOCKET, HOOKS_SOCKET] {
        let socket = sockets.path().join(socket);
        for tried in 1.. {
            match UnixStream::connect(&socket).await {
                Ok(_) => break,
                Err(e) if tried == 200 => panic!("{}: {e}", socket.display()),
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    }
    sockets
}

/// The app on `data`, its console this test's own uid, with `env` besides.
pub fn console_app(data: &Path, env: &[(&str, &str)]) -> App {
    let uid = own_uid().to_string();
    App::load(data, |name| {
        env.iter()
            .chain(&[("APPLIANCE_CONSOLE_UID", uid.as_str())])
            .find(|(set, _)| *set == name)
            .map(|(_, value)| value.to_string())
    })
    .unwrap()
}

pub fn config(state: &Path, domains: &[&str]) -> Config {
    Config {
        host: HOST.into(),
        domains: domains.iter().map(|d| d.to_string()).collect(),
        state_dir: state.into(),
        acme_listen: format!("{LOOPBACK}:0").parse().unwrap(),
        ..Config::parse(r#"host = "unused.example""#).unwrap()
    }
}

/// Starts a broker in `state` and serves it on a loopback port of its own.
pub async fn start(state: TempDir, domains: &[&str], uri: Option<PairingUri>) -> Running {
    let (broker, issued) = Broker::start(&config(state.path(), domains)).await.unwrap();
    run(state, broker, issued.or(uri)).await
}

/// Serves `broker`, started in `state`, as `start` does.
pub async fn run(state: TempDir, broker: Broker, uri: Option<PairingUri>) -> Running {
    let broker = Arc::new(broker);
    let bind = || Listener::bind(format!("{LOOPBACK}:0").parse().unwrap(), Bounds::SERVING);
    let (listener, pki) = (bind().await.unwrap(), bind().await.unwrap());
    let (address, pki_address) = (listener.local_addr(), pki.local_addr());
    tokio::spawn(broker.clone().serve_acme(std::future::pending()));
    tokio::spawn(broker.clone().serve_pki(pki, Default::default()));
    tokio::spawn(opca_acme_broker::serve(
        broker.clone(),
        listener,
        std::future::pending(),
    ));
    Running {
        state,
        broker,
        api: Api {
            uri: uri.expect("a URI, issued now or kept from before"),
            address,
        },
        pki: pki_address,
    }
}

pub async fn serve(state: TempDir, domains: &[&str]) -> Running {
    start(state, domains, None).await
}

impl Api {
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
        let tcp = TcpStream::connect(self.address).await?;
        let name = ServerName::try_from(self.uri.host().to_owned()).unwrap();
        let tls = TlsConnector::from(Arc::new(client))
            .connect(name, tcp)
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
}

/// A connection to the ACME listener at `address`, by [`HOST`], from a client
/// trusting only `root`; and the chain the listener presented.
pub async fn acme_connect(
    address: SocketAddr,
    root: &CertificateDer<'static>,
) -> io::Result<(Connection, Vec<CertificateDer<'static>>)> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let client = ClientConfig::builder_with_provider(Arc::new(rustls_openssl::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect(address).await?;
    let tls = TlsConnector::from(Arc::new(client))
        .connect(ServerName::try_from(HOST).unwrap(), tcp)
        .await?;
    let presented = tls.get_ref().1.peer_certificates().unwrap().to_vec();
    Ok((Connection(tls), presented))
}

impl Running {
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
        let (status, _, body) = exchange(&mut self.0, method, path, body).await?;
        Ok((status, String::from_utf8(body).unwrap()))
    }

    /// As [`call`](Self::call), with the head and the body as bytes.
    pub async fn fetch(&mut self, method: &str, path: &str) -> io::Result<(u16, String, Vec<u8>)> {
        exchange(&mut self.0, method, path, "").await
    }
}

/// One HTTP/1.1 request on `stream`: the status, the head, and the body.
async fn exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    method: &str,
    path: &str,
    body: &str,
) -> io::Result<(u16, String, Vec<u8>)> {
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let head_end = loop {
        if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let mut chunk = [0; 4096];
        match stream.read(&mut chunk).await? {
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
        .filter(|_| method != "HEAD")
        .map_or(0, |length| length.trim().parse().unwrap());
    let mut body = response[head_end..].to_vec();
    body.resize(length, 0);
    let already = response.len() - head_end;
    stream.read_exact(&mut body[already..]).await?;
    Ok((head[9..12].parse().unwrap(), head, body))
}

/// One plain-HTTP request to the PKI listener at `address`.
pub async fn pki_fetch(address: SocketAddr, method: &str, path: &str) -> (u16, String, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    exchange(&mut stream, method, path, "").await.unwrap()
}

/// The CRL the PKI listener at `address` serves, once it serves one numbered past `after`.
pub async fn crl_after(address: SocketAddr, after: u64) -> CrlView {
    for _ in 0..200 {
        let (status, _, body) = pki_fetch(address, "GET", "/crl").await;
        if status == 200 {
            let crl = CrlView::from_der(&body).unwrap();
            if crl.number.unwrap() > after {
                return crl;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no CRL past number {after} at {address}");
}

/// A broker enrolled by its own opCA, with an operator, within [`DOMAINS`].
pub struct Enrolled {
    pub running: Running,
    pub ca: TestCa,
    pub operator: Identity,
    pub id: i64,
    pub chain: Vec<CertificateDer<'static>>,
    pub status: Status,
}

pub async fn enrol(running: Running) -> Enrolled {
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (chain, _, id) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let enrolment = Enrolment {
        operator_pin: operator.key_pin(),
        ..running.enrolment(&chain, DOMAINS)
    };
    let (code, body) = running.post(&enrolment).await;
    assert_eq!(code, 200, "{body}");
    Enrolled {
        running,
        ca,
        operator,
        id,
        chain: pem::certificates(&chain).unwrap(),
        status: serde_json::from_str(&body).unwrap(),
    }
}

impl Enrolled {
    pub fn root(&self) -> &CertificateDer<'static> {
        self.chain.last().unwrap()
    }

    pub async fn as_operator(&self, method: &str, route: &str, body: &str) -> String {
        let (code, answer) = self
            .running
            .call(Some(&self.operator), method, route, body)
            .await
            .unwrap();
        assert_eq!(code, 200, "{route}: {answer}");
        answer
    }
}

pub fn wrong(code: &str) -> String {
    let flipped = if code.starts_with('A') { 'B' } else { 'A' };
    format!("{flipped}{}", &code[1..])
}

pub fn error(body: &str) -> ErrorKind {
    serde_json::from_str::<ErrorBody>(body).unwrap().kind
}

/// Records a certificate for `name` as finalising its order would.
pub async fn record(store: &Store, serial: &str, name: &str) {
    record_by(store, "4096", serial, name).await;
}

/// As [`record`], issued by the subordinate with serial `issuer`.
pub async fn record_by(store: &Store, issuer: &str, serial: &str, name: &str) {
    let not_after = SystemTime::now() + Duration::from_secs(30 * 86_400);
    record_chain(store, issuer, serial, name, "", not_after).await;
}

/// As [`record_by`], with `chain_pem` and `not_after`.
pub async fn record_chain(
    store: &Store,
    issuer: &str,
    serial: &str,
    name: &str,
    chain_pem: &str,
    not_after: SystemTime,
) {
    let expires = SystemTime::now() + Duration::from_secs(3600);
    let (account, _) = store
        .create_account(r#"{"kty":"EC"}"#, &format!("thumb-{serial}"), &[])
        .await
        .unwrap();
    let order = store
        .create_order(&NewOrder {
            account: account.id,
            identifiers: vec![name.into()],
            not_before: None,
            not_after: None,
            expires,
            authorisations: vec![NewAuthorisation {
                identifier: name.into(),
                wildcard: false,
                expires,
                challenges: vec![Challenge::Http01],
            }],
        })
        .await
        .unwrap();
    let authorisation = store
        .authorisation(order.authorisations[0])
        .await
        .unwrap()
        .unwrap();
    for status in [ChallengeStatus::Processing, ChallengeStatus::Valid] {
        store
            .set_challenge_status(authorisation.challenges[0].id, status, None)
            .await
            .unwrap();
    }
    store
        .record_certificate(
            order.id,
            &NewCertificate {
                serial: serial.into(),
                common_name: Some(name.into()),
                sans: vec![name.into()],
                not_before: not_after - Duration::from_secs(30 * 86_400),
                not_after,
                chain_pem: chain_pem.into(),
                issuer_serial: issuer.into(),
            },
        )
        .await
        .unwrap();
}
