#![cfg(unix)]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use opca_acme_api::{Enrolment, EnrolmentOffer, ErrorKind, IssuanceConfig, Status, path};
use opca_acme_broker::{Broker, Mode};
use support::*;

#[tokio::test]
async fn the_offer_needs_no_code_and_carries_the_csr() {
    let running = serve(private_tempdir(), &["home.example"]).await;
    let (status, body) = running
        .call(None, "GET", path::ENROLMENT, "")
        .await
        .unwrap();
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
    let (chain, serial, _) = ca.sign(running.broker.subordinate().csr_pem(), &["home.example"]);
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
    let again = serde_json::to_string(&enrolment).unwrap();
    let refused = running.call(None, "POST", path::ENROLMENT, &again).await;
    assert!(refused.is_err(), "{refused:?}");
}

#[tokio::test]
async fn bad_input_is_a_bad_request_that_costs_no_attempt() {
    let running = serve(private_tempdir(), &["home.example"]).await;
    let mut ca = TestCa::new();
    let (chain, _, _) = ca.sign(running.broker.subordinate().csr_pem(), &["home.example"]);
    let good = running.enrolment(&chain, &["home.example"]);

    let other = serve(private_tempdir(), &[]).await;
    let (other_chain, _, _) = ca.sign(other.broker.subordinate().csr_pem(), &["home.example"]);
    let subordinate_only = chain
        .split_inclusive("-----END CERTIFICATE-----\n")
        .next()
        .unwrap();
    let (elsewhere, _, _) = ca.sign(running.broker.subordinate().csr_pem(), &["lab.example"]);
    let (wider, _, _) = ca.sign(
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
        running.enrolment(&elsewhere, &["lab.example"]),
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
    let (status, _) = running
        .call(None, "POST", path::ENROLMENT, "{\"code\":")
        .await
        .unwrap();
    assert_eq!(status, 400);
    assert_eq!(running.remaining(), opca_acme_broker::ATTEMPTS.get());
    assert_eq!(running.post(&good).await.0, 200);
}

#[tokio::test]
async fn the_last_wrong_code_spends_it() {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let (chain, _, _) = ca.sign(running.broker.subordinate().csr_pem(), &["home.example"]);
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
    let (chain, _, _) = ca.sign(running.broker.subordinate().csr_pem(), &["home.example"]);
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
