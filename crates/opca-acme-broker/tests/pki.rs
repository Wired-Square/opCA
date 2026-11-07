//! The PKI listener's CA certificate and CRL, the HTTPS copy on the ACME
//! listener, and opCA's revocation of one leaf.

#![cfg(unix)]

mod support;

use std::process::Command;
use std::time::{Duration, SystemTime};

use opca_acme_api::{ErrorKind, IssuedCertificate, path};
use support::*;
use wslib_crypto_ca::{CrlView, Reason};
use wslib_crypto_x509::pem::{self, CERTIFICATE};

const DAY: Duration = Duration::from_secs(86_400);

async fn enrolled() -> Enrolled {
    enrol(serve(private_tempdir(), DOMAINS).await).await
}

fn subordinate(enrolled: &Enrolled) -> &[u8] {
    &enrolled.chain[0]
}

fn serials(crl: &CrlView) -> Vec<(String, Option<Reason>)> {
    crl.revoked
        .iter()
        .map(|entry| (entry.serial.to_string(), entry.reason))
        .collect()
}

async fn revoke(enrolled: &Enrolled, serial: &str, reason: u8) -> (u16, String) {
    let body = format!(r#"{{"reason": {reason}}}"#);
    let route = path::revoke_issued(serial);
    let operator = Some(&enrolled.operator);
    enrolled
        .running
        .call(operator, "POST", &route, &body)
        .await
        .unwrap()
}

fn max_age(head: &str) -> u64 {
    head.lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("cache-control: max-age=")?
                .trim()
                .parse()
                .ok()
        })
        .expect("a max-age")
}

#[tokio::test]
async fn before_enrolment_the_pki_listener_answers_404() {
    let running = serve(private_tempdir(), DOMAINS).await;
    for route in ["/ca.crt", "/crl", "/"] {
        let (status, ..) = pki_fetch(running.pki, "GET", route).await;
        assert_eq!(status, 404, "{route}");
    }
}

#[tokio::test]
async fn once_enrolled_it_serves_the_subordinate_and_a_crl_it_signed_for_four_days() {
    let enrolled = enrolled().await;
    let crl = crl_after(enrolled.running.pki, 0).await;
    let algorithms = rustls_openssl::default_provider().signature_verification_algorithms;
    crl.verify(&enrolled.chain[0], algorithms.all).unwrap();
    assert_eq!(
        crl.next_update
            .unwrap()
            .duration_since(crl.this_update)
            .unwrap(),
        4 * DAY
    );
    assert!(crl.this_update <= SystemTime::now());
    assert!(crl.revoked.is_empty());

    let (status, head, body) = pki_fetch(enrolled.running.pki, "GET", "/ca.crt").await;
    assert_eq!(status, 200);
    assert_eq!(body, subordinate(&enrolled));
    assert!(
        head.contains("content-type: application/pkix-cert"),
        "{head}"
    );
    let age = max_age(&head);
    assert!(age > 4 * 86_400 - 120 && age <= 4 * 86_400, "{age}");

    let (status, head, body) = pki_fetch(enrolled.running.pki, "HEAD", "/crl").await;
    assert_eq!(status, 200);
    assert!(
        head.contains("content-type: application/pkix-crl"),
        "{head}"
    );
    assert!(body.is_empty());
    let (status, ..) = pki_fetch(enrolled.running.pki, "POST", "/crl").await;
    assert_eq!(status, 405);
    let (status, ..) = pki_fetch(enrolled.running.pki, "GET", "/acme/directory").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn the_acme_listener_serves_the_same_files_over_https() {
    let enrolled = enrolled().await;
    crl_after(enrolled.running.pki, 0).await;
    let address = enrolled
        .running
        .broker
        .acme_address()
        .expect("serving ACME");
    let (mut https, _) = acme_connect(address, enrolled.root()).await.unwrap();
    for route in ["/ca.crt", "/crl"] {
        let (status, _, body) = https.fetch("GET", route).await.unwrap();
        let (_, _, plain) = pki_fetch(enrolled.running.pki, "GET", route).await;
        assert_eq!((status, body), (200, plain), "{route}");
    }
}

#[tokio::test]
async fn on_the_default_port_the_leaves_name_the_urls_without_it() {
    let enrolled = enrolled().await;
    let address = enrolled
        .running
        .broker
        .acme_address()
        .expect("serving ACME");
    let (_, presented) = acme_connect(address, enrolled.root()).await.unwrap();
    let names = |url: &str| presented[0].windows(url.len()).any(|w| w == url.as_bytes());
    assert!(names(&format!("http://{HOST}/crl")));
    assert!(names(&format!("http://{HOST}/ca.crt")));
    assert!(!names(&format!("http://{HOST}:80/")));
}

#[tokio::test]
async fn opca_revokes_a_leaf_onto_a_fresh_crl_once_and_only_its_own() {
    let enrolled = enrolled().await;
    let ours = &enrolled.status.subordinate_serial;
    let store = enrolled.running.broker.acme();
    for serial in ["11", "12"] {
        record_by(store, ours, serial, &format!("s{serial}.home.example")).await;
    }
    record_by(store, "4096", "13", "other.home.example").await;
    let first = crl_after(enrolled.running.pki, 0).await.number.unwrap();

    let (status, body) = revoke(&enrolled, "11", 1).await;
    assert_eq!(status, 200, "{body}");
    let revoked: IssuedCertificate = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (revoked.serial.as_str(), revoked.revocation_reason),
        ("11", Some(1))
    );
    assert!(revoked.revoked_at.is_some());
    let crl = crl_after(enrolled.running.pki, first).await;
    assert_eq!(serials(&crl), [("11".into(), Some(Reason::KeyCompromise))]);

    let (status, again) = revoke(&enrolled, "11", 4).await;
    assert_eq!(
        (
            status,
            serde_json::from_str::<IssuedCertificate>(&again).unwrap()
        ),
        (200, revoked)
    );
    let (status, body) = revoke(&enrolled, "12", 0).await;
    assert_eq!(status, 200, "{body}");
    let crl = crl_after(enrolled.running.pki, crl.number.unwrap()).await;
    assert_eq!(
        serials(&crl),
        [
            ("11".into(), Some(Reason::KeyCompromise)),
            ("12".into(), None)
        ]
    );

    for unknown in ["13", "99"] {
        let (status, body) = revoke(&enrolled, unknown, 1).await;
        assert_eq!(
            (status, error(&body)),
            (404, ErrorKind::NotFound),
            "{unknown}"
        );
    }
    let (status, body) = revoke(&enrolled, "13", 7).await;
    assert_eq!((status, error(&body)), (400, ErrorKind::BadRequest));
    assert!(
        store
            .certificate_by_serial("13")
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn an_expired_leaf_leaves_the_crl() {
    let enrolled = enrolled().await;
    let ours = &enrolled.status.subordinate_serial;
    let store = enrolled.running.broker.acme();
    let ended = SystemTime::now() - DAY;
    record_chain(store, ours, "21", "gone.home.example", "", ended).await;
    record_by(store, ours, "22", "live.home.example").await;
    store.revoke("21", Some(1)).await.unwrap();
    let (status, body) = revoke(&enrolled, "22", 5).await;
    assert_eq!(status, 200, "{body}");
    let crl = crl_after(enrolled.running.pki, 1).await;
    assert_eq!(
        serials(&crl),
        [("22".into(), Some(Reason::CessationOfOperation))]
    );
}

#[tokio::test]
async fn a_renewal_keeps_the_crl_number_rising_and_the_earlier_subordinates_leaves_on_it() {
    let mut enrolled = enrolled().await;
    let first_serial = enrolled.status.subordinate_serial.clone();
    record_by(
        enrolled.running.broker.acme(),
        &first_serial,
        "31",
        "a.home.example",
    )
    .await;
    let (status, body) = revoke(&enrolled, "31", 1).await;
    assert_eq!(status, 200, "{body}");
    let before = crl_after(enrolled.running.pki, 0).await.number.unwrap();

    let csr = enrolled.running.broker.subordinate().fresh_csr().unwrap();
    let (chain_pem, _) = enrolled.ca.renew(enrolled.id, &csr);
    let update = opca_acme_api::ChainUpdate {
        chain_pem: chain_pem.clone(),
        config: enrolled.status.config.clone(),
    };
    enrolled
        .as_operator("PUT", path::CHAIN, &serde_json::to_string(&update).unwrap())
        .await;

    let renewed = pem::certificates(&chain_pem).unwrap().remove(0);
    for _ in 0..200 {
        let (_, _, ca) = pki_fetch(enrolled.running.pki, "GET", "/ca.crt").await;
        if ca == renewed[..] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let crl = crl_after(enrolled.running.pki, before).await;
    let algorithms = rustls_openssl::default_provider().signature_verification_algorithms;
    crl.verify(&renewed, algorithms.all).unwrap();
    assert_eq!(serials(&crl), [("31".into(), Some(Reason::KeyCompromise))]);
}

#[tokio::test]
async fn a_revoked_subordinate_stops_publishing_and_refuses_to_revoke_leaves() {
    let enrolled = enrolled().await;
    crl_after(enrolled.running.pki, 0).await;
    enrolled.as_operator("POST", path::REVOKE, "").await;
    for route in ["/ca.crt", "/crl"] {
        let (status, ..) = pki_fetch(enrolled.running.pki, "GET", route).await;
        assert_eq!(status, 404, "{route}");
    }
    let (status, body) = revoke(&enrolled, "11", 1).await;
    assert_eq!((status, error(&body)), (409, ErrorKind::Revoked));
}

/// OpenSSL 3 checks the CRL's signature against the subordinate, as a relying party would.
#[tokio::test]
#[ignore = "shells out to OpenSSL 3; set OPENSSL to its path, then run with --ignored"]
async fn openssl_accepts_the_crl_against_the_subordinate() {
    let enrolled = enrolled().await;
    let serial = &enrolled.status.subordinate_serial;
    record_by(
        enrolled.running.broker.acme(),
        serial,
        "41",
        "a.home.example",
    )
    .await;
    let (status, body) = revoke(&enrolled, "41", 1).await;
    assert_eq!(status, 200, "{body}");
    crl_after(enrolled.running.pki, 1).await;
    let (_, _, crl) = pki_fetch(enrolled.running.pki, "GET", "/crl").await;

    let dir = private_tempdir();
    let (crl_path, ca_path) = (dir.path().join("leaves.crl"), dir.path().join("chain.pem"));
    std::fs::write(&crl_path, crl).unwrap();
    let chain: String = enrolled
        .chain
        .iter()
        .map(|der| pem::encode(CERTIFICATE, der))
        .collect();
    std::fs::write(&ca_path, chain).unwrap();
    let openssl = std::env::var("OPENSSL").unwrap_or_else(|_| "openssl".into());
    let checked = Command::new(openssl)
        .args([
            "crl", "-inform", "DER", "-noout", "-text", "-verify", "-CAfile",
        ])
        .arg(&ca_path)
        .arg("-in")
        .arg(&crl_path)
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&checked.stderr);
    let text = String::from_utf8_lossy(&checked.stdout);
    assert!(
        checked.status.success() && said.contains("verify OK"),
        "{said}"
    );
    assert!(text.contains("Serial Number: 29"), "{text}");
    assert!(text.contains("Key Compromise"), "{text}");
}
