#![cfg(unix)]

mod support;

use std::fs;

use opca_acme_api::{Enrolment, EnrolmentOffer, ErrorKind, path};
use opca_acme_broker::cli;
use support::*;
use wslib_crypto_ca::CsrView;

const DOMAINS: &[&str] = &["home.example"];

/// A served broker that `operator` enrolled, signed by `ca`.
async fn enrolled() -> (Running, TestCa, Identity, String) {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (chain, serial, _) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let enrolment = Enrolment {
        operator_pin: operator.key_pin(),
        ..running.enrolment(&chain, DOMAINS)
    };
    assert_eq!(running.post(&enrolment).await.0, 200);
    (running, ca, operator, serial)
}

fn config_of(running: &Running) -> opca_acme_broker::Config {
    config(running.state.path(), &[])
}

async fn status_until(running: &Running, wanted: &str) -> String {
    let mut text = String::new();
    for _ in 0..100 {
        text = cli::status(&config_of(running)).unwrap();
        if text.contains(wanted) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    text
}

#[tokio::test]
async fn pairing_issues_a_code_the_running_broker_accepts() {
    let running = serve(private_tempdir(), &[]).await;
    let uri = cli::pairing(&config_of(&running)).unwrap();
    assert_eq!(uri.pin(), running.uri.pin());
    assert_ne!(uri.code().expose(), running.uri.code().expose());

    let mut ca = TestCa::new();
    let (chain, _, _) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let (code, body) = running.post(&running.enrolment(&chain, DOMAINS)).await;
    assert_eq!(
        (code, error(&body)),
        (403, ErrorKind::WrongCode { remaining: 4 })
    );
    let paired = Api {
        uri,
        address: running.address,
    };
    assert_eq!(paired.post(&paired.enrolment(&chain, DOMAINS)).await.0, 200);
}

#[tokio::test]
async fn pairing_is_refused_once_enrolled_or_revoked() {
    let (running, _, operator, _) = enrolled().await;
    let refused = cli::pairing(&config_of(&running)).unwrap_err().to_string();
    assert!(
        refused.contains("enrolled") && refused.contains("enrol --reopen"),
        "{refused}"
    );

    let (code, _) = running
        .call(Some(&operator), "POST", path::REVOKE, "")
        .await
        .unwrap();
    assert_eq!(code, 200);
    let refused = cli::pairing(&config_of(&running)).unwrap_err().to_string();
    assert!(refused.contains("revoked"), "{refused}");
}

#[tokio::test]
async fn status_reads_each_mode_from_the_files() {
    let running = serve(private_tempdir(), &[]).await;
    let enrolling = cli::status(&config_of(&running)).unwrap();
    for line in [
        "mode: enrolling",
        "pairing code: pending, 5 of 5 attempts left",
        "broker: not running",
        "step-ca: not running",
    ] {
        assert!(enrolling.contains(line), "{enrolling}");
    }
    assert!(!enrolling.contains("subordinate:"));

    let (running, _, operator, serial) = enrolled().await;
    let enrolled = status_until(&running, "step-ca: running").await;
    for line in [
        "mode: enrolled",
        "pairing code: spent by enrolment",
        &format!("subordinate: serial {serial}, expires 20"),
        "permitted domains: home.example",
        "step-ca: running (pid ",
    ] {
        assert!(enrolled.contains(line), "{enrolled}");
    }

    running
        .call(Some(&operator), "POST", path::REVOKE, "")
        .await
        .unwrap();
    let revoked = status_until(&running, "step-ca: not running").await;
    for line in ["mode: revoked", "step-ca: not running"] {
        assert!(revoked.contains(line), "{revoked}");
    }
}

#[tokio::test]
async fn reopening_pairs_again_with_a_new_key_and_the_same_pin() {
    let (running, _, operator, _) = enrolled().await;
    let state = running.state.path();
    let old_key = fs::read(state.join("subordinate.key")).unwrap();
    let old_spki = running.broker.subordinate().spki().to_vec();

    let uri = cli::reopen(&config_of(&running)).unwrap();
    running.broker.reload().await.unwrap();

    assert_eq!(uri.pin(), running.uri.pin());
    assert_ne!(fs::read(state.join("subordinate.key")).unwrap(), old_key);
    let archived: Vec<_> = fs::read_dir(state.join("archive")).unwrap().collect();
    assert_eq!(archived.len(), 1);
    let archive = archived[0].as_ref().unwrap().path();
    assert!(archive.join("enrolment.json").is_file());
    assert!(!archive.join("subordinate.key").exists());
    assert!(!state.join("enrolment.json").exists());
    let after = status_until(&running, "step-ca: not running").await;
    assert!(after.contains("mode: enrolling"), "{after}");

    let paired = Api {
        uri,
        address: running.address,
    };
    let (code, body) = paired.call(None, "GET", path::ENROLMENT, "").await.unwrap();
    assert_eq!(code, 200, "{body}");
    let offer: EnrolmentOffer = serde_json::from_str(&body).unwrap();
    let csr = CsrView::from_pem(&offer.csr_pem).unwrap();
    assert_ne!(csr.spki(), old_spki);
    assert_eq!(csr.spki(), running.broker.subordinate().spki());

    let (code, _) = paired
        .call(Some(&operator), "GET", path::STATUS, "")
        .await
        .unwrap();
    assert_eq!(code, 404);

    let mut other_ca = TestCa::new();
    let new_operator = other_ca.client("another opCA");
    let (chain, _, _) = other_ca.sign(&offer.csr_pem, DOMAINS);
    let enrolment = Enrolment {
        operator_pin: new_operator.key_pin(),
        ..paired.enrolment(&chain, DOMAINS)
    };
    assert_eq!(paired.post(&enrolment).await.0, 200);
    let (code, _) = paired
        .call(Some(&new_operator), "GET", path::STATUS, "")
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(
        paired
            .call(Some(&operator), "GET", path::STATUS, "")
            .await
            .is_err()
    );
}
