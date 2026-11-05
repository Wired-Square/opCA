#![cfg(unix)]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use opca_acme_api::{ChainUpdate, Enrolment, IssuerState, Status, path};
use opca_acme_broker::Broker;
use support::*;
use tokio_rustls::rustls::pki_types::CertificateDer;
use wslib_crypto_x509::pem;
use wslib_crypto_x509::{ExtendedKeyUsage, SubjectAltName, inspect};

const DOMAINS: &[&str] = &["home.example"];

struct Enrolled {
    running: Running,
    ca: TestCa,
    operator: Identity,
    id: i64,
    chain: Vec<CertificateDer<'static>>,
    status: Status,
}

async fn enrol(running: Running) -> Enrolled {
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
    fn root(&self) -> &CertificateDer<'static> {
        self.chain.last().unwrap()
    }

    async fn presented(&self) -> Vec<CertificateDer<'static>> {
        let address = self.running.broker.acme_address().expect("serving ACME");
        acme_connect(address, self.root()).await.unwrap().1
    }

    async fn as_operator(&self, method: &str, route: &str, body: &str) -> String {
        let (code, answer) = self
            .running
            .call(Some(&self.operator), method, route, body)
            .await
            .unwrap();
        assert_eq!(code, 200, "{route}: {answer}");
        answer
    }
}

fn read(running: &Running, name: &str) -> Vec<u8> {
    fs::read(running.state.path().join(name)).unwrap()
}

#[tokio::test]
async fn enrolment_serves_acme_with_a_certificate_for_the_host_from_the_subordinate() {
    let running = serve(private_tempdir(), &[]).await;
    assert_eq!(running.broker.acme_address(), None);
    let enrolled = enrol(running).await;
    assert_eq!(enrolled.status.state, IssuerState::Issuing);

    let presented = enrolled.presented().await;
    assert_eq!(presented[1..], enrolled.chain[..1]);
    let leaf = inspect(&presented[0]).unwrap();
    let subordinate = inspect(&enrolled.chain[0]).unwrap();
    assert_eq!(leaf.sans, [SubjectAltName::Dns(HOST.into())]);
    assert_eq!(
        leaf.extended_key_usages,
        Some(vec![ExtendedKeyUsage::ServerAuth])
    );
    assert!(leaf.not_after <= subordinate.not_after);
    let mode = |name: &str| {
        fs::metadata(enrolled.running.state.path().join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("acme.key"), 0o600);

    let address = enrolled.running.broker.acme_address().unwrap();
    let (mut acme, _) = acme_connect(address, enrolled.root()).await.unwrap();
    let (code, body) = acme.call("GET", "/acme/directory", "").await.unwrap();
    assert_eq!(code, 503);
    let problem: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:serverInternal");
}

#[tokio::test]
async fn a_renewed_chain_is_served_live_on_the_same_address() {
    let mut enrolled = enrol(serve(private_tempdir(), &[]).await).await;
    let address = enrolled.running.broker.acme_address().unwrap();
    let (mut opened_before, _) = acme_connect(address, enrolled.root()).await.unwrap();

    let fresh = enrolled.running.broker.subordinate().fresh_csr().unwrap();
    let (renewed, _) = enrolled.ca.renew(enrolled.id, &fresh);
    let update = serde_json::to_string(&ChainUpdate {
        chain_pem: renewed.clone(),
        config: enrolled.status.config.clone(),
    })
    .unwrap();
    let answered: Status =
        serde_json::from_str(&enrolled.as_operator("PUT", path::CHAIN, &update).await).unwrap();
    assert_eq!(answered.state, IssuerState::Issuing);

    assert_eq!(enrolled.running.broker.acme_address(), Some(address));
    let renewed = pem::certificates(&renewed).unwrap();
    assert_ne!(renewed[0], enrolled.chain[0]);
    assert_eq!(enrolled.presented().await[1], renewed[0]);
    let (code, _) = opened_before
        .call("GET", "/acme/directory", "")
        .await
        .unwrap();
    assert_eq!(code, 503);
}

#[tokio::test]
async fn revocation_stops_the_listener() {
    let enrolled = enrol(serve(private_tempdir(), &[]).await).await;
    let address = enrolled.running.broker.acme_address().unwrap();

    let revoked: Status =
        serde_json::from_str(&enrolled.as_operator("POST", path::REVOKE, "").await).unwrap();
    assert_eq!(revoked.state, IssuerState::Revoked);
    assert_eq!(enrolled.running.broker.acme_address(), None);
    let mut refused = false;
    for _ in 0..100 {
        refused = acme_connect(address, enrolled.root()).await.is_err();
        if refused {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(refused, "still serving ACME once revoked");
}

#[tokio::test]
async fn a_restart_keeps_a_current_certificate_and_replaces_a_broken_one() {
    let enrolled = enrol(serve(private_tempdir(), &[]).await).await;
    let issued = read(&enrolled.running, "acme.crt");
    let Enrolled { running, chain, .. } = enrolled;
    let restarted = start(running.state, &[], Some(running.api.uri)).await;
    let mut address = None;
    for _ in 0..100 {
        address = restarted.broker.acme_address();
        if address.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let root = chain.last().unwrap();
    let presented = acme_connect(address.expect("serving ACME"), root)
        .await
        .unwrap()
        .1;
    assert_eq!(read(&restarted, "acme.crt"), issued);
    assert_eq!(
        pem::certificates(&String::from_utf8(issued.clone()).unwrap()).unwrap(),
        presented
    );

    let other_key = pem::encode(
        pem::PRIVATE_KEY,
        wslib_crypto::KeyAlgorithm::EcP256
            .generate()
            .unwrap()
            .secret_pkcs8_der(),
    );
    fs::write(restarted.state.path().join("acme.key"), other_key).unwrap();
    restarted.broker.reload().await.unwrap();
    let reissued = read(&restarted, "acme.crt");
    assert_ne!(reissued, issued);
    let address = restarted.broker.acme_address().unwrap();
    assert_eq!(
        acme_connect(address, root).await.unwrap().1[0],
        pem::certificates(&String::from_utf8(reissued).unwrap()).unwrap()[0]
    );
}

#[tokio::test]
async fn a_listener_that_cannot_bind_reports_acme_down() {
    let taken = std::net::TcpListener::bind(format!("{LOOPBACK}:0")).unwrap();
    let state = private_tempdir();
    let config = opca_acme_broker::Config {
        acme_listen: taken.local_addr().unwrap(),
        ..config(state.path(), &[])
    };
    let (broker, uri) = Broker::start(&config).await.unwrap();
    let enrolled = enrol(run(state, broker, uri).await).await;

    assert_eq!(enrolled.status.state, IssuerState::AcmeDown);
    assert_eq!(enrolled.running.broker.acme_address(), None);
}
