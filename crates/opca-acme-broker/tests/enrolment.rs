#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use opca_acme_api::{
    Challenge, Enrolment, EnrolmentOffer, ErrorBody, ErrorKind, IssuanceConfig, Status, path,
};
use opca_acme_broker::{Broker, Config, Mode};
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
use tokio_rustls::rustls::pki_types::ServerName;
use wslib_http_server::{Bounds, Listener};
use wslib_pairing::PairingUri;
use wslib_tls::{KeyFingerprint, Outbound, Trust};

const HOST: &str = "127.0.0.1";
const OPERATOR_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct TestCa {
    ca: CertificateAuthority<FakeRunner>,
    op: FakeRunner,
}

impl TestCa {
    fn new() -> Self {
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

    /// The subordinate signed through phase 21's `sign_subordinate`, then the root, and its serial.
    fn sign(&mut self, csr_pem: &str, domains: &[&str]) -> (String, String) {
        self.op.respond(created("CRT"));
        self.op.respond(Output::ok(""));
        let domains: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        let signed = self
            .ca
            .sign_subordinate(csr_pem.as_bytes(), &domains, None)
            .unwrap();
        let root = self
            .ca
            .ca_bundle
            .as_ref()
            .unwrap()
            .certificate_pem()
            .unwrap();
        (
            format!("{}{root}", signed.cert_pem),
            signed.broker.subordinate_serial,
        )
    }
}

struct Running {
    state: TempDir,
    broker: Arc<Broker>,
    uri: PairingUri,
    port: u16,
}

fn private_tempdir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn config(state: &Path, domains: &[&str]) -> Config {
    Config {
        host: HOST.into(),
        domains: domains.iter().map(|d| d.to_string()).collect(),
        state_dir: state.into(),
        ..Config::parse(r#"host = "unused.example""#).unwrap()
    }
}

async fn serve(state: TempDir, domains: &[&str]) -> Running {
    let (broker, uri) = Broker::start(&config(state.path(), domains)).unwrap();
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
        uri: uri.expect("a first start issues a code"),
        port,
    }
}

impl Running {
    /// One request over a connection that pins the URI's key, as opCA dials.
    async fn call(&self, method: &str, body: &str) -> (u16, String) {
        let mut trust = Trust::default();
        let pin = KeyFingerprint(wslib_crypto::Fingerprint::from(*self.uri.pin().as_bytes()));
        trust.pin_key(self.uri.host(), pin);
        let provider = Arc::new(rustls_openssl::default_provider());
        let client = Arc::new(Outbound::new(provider, trust).unwrap()).client_config();
        let tcp = TcpStream::connect((HOST, self.port)).await.unwrap();
        let mut tls = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from(HOST).unwrap(), tcp)
            .await
            .unwrap();
        let request = format!(
            "{method} {} HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            path::ENROLMENT,
            body.len()
        );
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        let response = String::from_utf8(response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        (head[9..12].parse().unwrap(), body.into())
    }

    async fn post(&self, enrolment: &Enrolment) -> (u16, String) {
        self.call("POST", &serde_json::to_string(enrolment).unwrap())
            .await
    }

    fn enrolment(&self, chain_pem: &str, domains: &[&str]) -> Enrolment {
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

    fn remaining(&self) -> u32 {
        match self.broker.code_status().unwrap() {
            wslib_pairing::Status::Pending { remaining, .. } => remaining,
            spent => panic!("{spent:?}"),
        }
    }
}

fn wrong(code: &str) -> String {
    let flipped = if code.starts_with('A') { 'B' } else { 'A' };
    format!("{flipped}{}", &code[1..])
}

fn error(body: &str) -> ErrorKind {
    serde_json::from_str::<ErrorBody>(body).unwrap().kind
}

#[tokio::test]
async fn the_offer_needs_no_code_and_carries_the_csr() {
    let running = serve(private_tempdir(), &["home.example"]).await;
    let (status, body) = running.call("GET", "").await;
    assert_eq!(status, 200);

    let offer: EnrolmentOffer = serde_json::from_str(&body).unwrap();
    assert_eq!(offer.csr_pem, running.broker.subordinate().csr_pem());
    assert_eq!(offer.host, HOST);
    assert_eq!(offer.configured_domains, ["home.example"]);
    assert_eq!(offer.versions.api, opca_acme_api::API_VERSION);
    assert_eq!(running.remaining(), opca_acme_broker::ATTEMPTS.get());
}

#[tokio::test]
async fn opca_signs_the_csr_and_the_broker_enrols_once() {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let (chain, serial) = ca.sign(running.broker.subordinate().csr_pem(), &["home.example"]);
    let enrolment = running.enrolment(&chain, &["home.example"]);

    let wrong_code = Enrolment {
        code: wrong(&enrolment.code),
        ..enrolment.clone()
    };
    let (status, body) = running.post(&wrong_code).await;
    assert_eq!(
        (status, error(&body)),
        (403, ErrorKind::WrongCode { remaining: 4 })
    );

    let (status, body) = running.post(&enrolment).await;
    assert_eq!(status, 200, "{body}");
    let answered: Status = serde_json::from_str(&body).unwrap();
    assert_eq!(answered.subordinate_serial, serial);
    assert_eq!(answered.config, enrolment.config);
    assert!(answered.subordinate_not_after.ends_with('Z'));

    assert!(matches!(running.broker.mode(), Mode::Enrolled(_)));
    assert_eq!(
        running
            .call("POST", &serde_json::to_string(&enrolment).unwrap())
            .await
            .0,
        404
    );
    assert_eq!(running.call("GET", "").await.0, 404);
}

#[tokio::test]
async fn bad_input_is_a_bad_request_that_costs_no_attempt() {
    let running = serve(private_tempdir(), &["home.example"]).await;
    let mut ca = TestCa::new();
    let (chain, _) = ca.sign(running.broker.subordinate().csr_pem(), &["home.example"]);
    let good = running.enrolment(&chain, &["home.example"]);

    let other = serve(private_tempdir(), &[]).await;
    let (other_chain, _) = ca.sign(other.broker.subordinate().csr_pem(), &["home.example"]);
    let subordinate_only = chain
        .split_inclusive("-----END CERTIFICATE-----\n")
        .next()
        .unwrap();
    let (wider, _) = ca.sign(
        running.broker.subordinate().csr_pem(),
        &["home.example", "lab.example"],
    );

    let mut refused = vec![
        Enrolment {
            code: "not-a-code".into(),
            ..good.clone()
        },
        Enrolment {
            operator_pin: OPERATOR_PIN.to_uppercase(),
            ..good.clone()
        },
        Enrolment {
            chain_pem: "not PEM".into(),
            ..good.clone()
        },
        Enrolment {
            chain_pem: other_chain,
            ..good.clone()
        },
        Enrolment {
            chain_pem: subordinate_only.into(),
            ..good.clone()
        },
        running.enrolment(&chain, &["lab.example"]),
        running.enrolment(&wider, &["home.example", "lab.example"]),
    ];
    let breaks: [fn(&mut IssuanceConfig); 3] = [
        |config| config.leaf_days = 0,
        |config| config.leaf_max_days = 29,
        |config| config.challenges.clear(),
    ];
    for broken in breaks {
        let mut enrolment = good.clone();
        broken(&mut enrolment.config);
        refused.push(enrolment);
    }

    for enrolment in &refused {
        let (status, body) = running.post(enrolment).await;
        assert_eq!(
            (status, error(&body)),
            (400, ErrorKind::BadRequest),
            "{body}"
        );
    }
    let (status, _) = running.call("POST", "{\"code\":").await;
    assert_eq!(status, 400);
    assert_eq!(running.remaining(), opca_acme_broker::ATTEMPTS.get());
    assert_eq!(running.post(&good).await.0, 200);
}

#[tokio::test]
async fn the_last_wrong_code_spends_it() {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let (chain, _) = ca.sign(running.broker.subordinate().csr_pem(), &["home.example"]);
    let enrolment = running.enrolment(&chain, &["home.example"]);
    let wrong_code = Enrolment {
        code: wrong(&enrolment.code),
        ..enrolment.clone()
    };

    for _ in 1..opca_acme_broker::ATTEMPTS.get() {
        assert_eq!(running.post(&wrong_code).await.0, 403);
    }
    let (status, body) = running.post(&wrong_code).await;
    assert_eq!((status, error(&body)), (410, ErrorKind::CodeSpent));
    let (status, body) = running.post(&enrolment).await;
    assert_eq!((status, error(&body)), (410, ErrorKind::CodeSpent));
    assert_eq!(running.broker.mode(), Mode::Enrolling);
    assert!(!running.state.path().join("enrolment.json").exists());
}

#[tokio::test]
async fn a_restart_after_enrolment_reads_back_enrolled() {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let (chain, _) = ca.sign(running.broker.subordinate().csr_pem(), &["home.example"]);
    assert_eq!(
        running
            .post(&running.enrolment(&chain, &["home.example"]))
            .await
            .0,
        200
    );
    let Running { state, broker, .. } = running;
    let pin = broker.pin().to_string();
    let enrolled_before = broker.mode();
    drop(broker);

    let stored = state.path().join("enrolment.json");
    assert_eq!(
        fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let (restarted, uri) = Broker::start(&config(state.path(), &[])).unwrap();
    assert!(uri.is_none());
    let Mode::Enrolled(enrolled) = restarted.mode() else {
        panic!("not enrolled after a restart");
    };
    assert_eq!(Mode::Enrolled(enrolled.clone()), enrolled_before);
    assert_eq!(enrolled.chain_pem, chain);
    assert_eq!(enrolled.operator_pin, OPERATOR_PIN);
    assert_eq!(enrolled.api_pin, pin);
    assert!(restarted.offer().is_none());
}
