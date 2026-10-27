#![cfg(unix)]

mod support;

use opca_acme_api::{ChainUpdate, ErrorKind, FreshCsr, IssuanceConfig, IssuerState, Status, path};
use opca_acme_broker::Mode;
use support::*;
use wslib_crypto_ca::CsrView;

const DOMAINS: &[&str] = &["home.example"];

struct Enrolled {
    running: Running,
    ca: TestCa,
    operator: Identity,
    id: i64,
    serial: String,
    config: IssuanceConfig,
}

async fn enrolled() -> Enrolled {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (chain, serial, id) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let enrolment = opca_acme_api::Enrolment {
        operator_pin: operator.key_pin(),
        ..running.enrolment(&chain, DOMAINS)
    };
    let (status, body) = running.post(&enrolment).await;
    assert_eq!(status, 200, "{body}");
    Enrolled {
        running,
        ca,
        operator,
        id,
        serial,
        config: enrolment.config,
    }
}

impl Enrolled {
    async fn as_operator(&self, method: &str, path: &str, body: &str) -> (u16, String) {
        self.running
            .call(Some(&self.operator), method, path, body)
            .await
            .unwrap()
    }

    async fn status(&self) -> Status {
        let (code, body) = self.as_operator("GET", path::STATUS, "").await;
        assert_eq!(code, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    fn update(&self, chain_pem: String) -> String {
        serde_json::to_string(&ChainUpdate {
            chain_pem,
            config: self.config.clone(),
        })
        .unwrap()
    }
}

async fn refused(running: &Running, identity: Option<&Identity>) -> bool {
    running
        .call(identity, "GET", path::STATUS, "")
        .await
        .is_err()
}

#[tokio::test]
async fn enrolment_swaps_the_open_listener_to_client_auth_and_a_stale_connection_gets_nothing() {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let mut opened_before = running.connect(None).await.unwrap();
    let (code, _) = opened_before
        .call("GET", path::ENROLMENT, "")
        .await
        .unwrap();
    assert_eq!(code, 200);

    let (chain, _, _) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let enrolment = opca_acme_api::Enrolment {
        operator_pin: operator.key_pin(),
        ..running.enrolment(&chain, DOMAINS)
    };
    assert_eq!(running.post(&enrolment).await.0, 200);

    assert!(refused(&running, None).await);
    let (code, _) = running
        .call(Some(&operator), "GET", path::STATUS, "")
        .await
        .unwrap();
    assert_eq!(code, 200);
    for (method, route) in [("GET", path::STATUS), ("POST", path::REVOKE)] {
        let (code, body) = opened_before.call(method, route, "").await.unwrap();
        assert_eq!((code, body.as_str()), (404, ""), "{route}");
    }
    assert!(matches!(running.broker.mode(), Mode::Enrolled(e) if !e.revoked));
}

#[tokio::test]
async fn only_the_operators_certificate_is_admitted() {
    let mut enrolled = enrolled().await;
    let same_root_other_key = enrolled.ca.client("VPN laptop");
    let other_root = TestCa::new().client("opCA operator");

    assert!(refused(&enrolled.running, None).await);
    assert!(refused(&enrolled.running, Some(&same_root_other_key)).await);
    assert!(refused(&enrolled.running, Some(&other_root)).await);
    assert_eq!(enrolled.status().await.subordinate_serial, enrolled.serial);
}

#[tokio::test]
async fn the_operator_reaches_every_route_and_the_enrolment_routes_are_gone() {
    let mut enrolled = enrolled().await;
    let status = enrolled.status().await;
    assert_eq!(status.state, IssuerState::Issuing);
    let state = enrolled.running.state.path();
    assert_eq!(step_ca_log(state, &["start"]).await, ["start"]);
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state.join("step-ca.json")).unwrap()).unwrap();
    assert_eq!(
        written["authority"]["policy"]["x509"]["allow"]["dns"][0],
        "home.example"
    );
    assert_eq!(status.config, enrolled.config);

    let (code, body) = enrolled.as_operator("POST", path::CSR, "").await;
    assert_eq!(code, 200, "{body}");
    let fresh: FreshCsr = serde_json::from_str(&body).unwrap();
    let csr = CsrView::from_pem(&fresh.csr_pem).unwrap();
    assert_eq!(csr.spki(), enrolled.running.broker.subordinate().spki());
    assert_ne!(
        fresh.csr_pem,
        enrolled.running.broker.subordinate().csr_pem()
    );

    let (renewed, serial) = enrolled.ca.renew(enrolled.id, &fresh.csr_pem);
    let (code, body) = enrolled
        .as_operator("PUT", path::CHAIN, &enrolled.update(renewed.clone()))
        .await;
    assert_eq!(code, 200, "{body}");
    let answered: Status = serde_json::from_str(&body).unwrap();
    assert_eq!(answered.subordinate_serial, serial);
    assert_ne!(serial, enrolled.serial);
    let Mode::Enrolled(stored) = enrolled.running.broker.mode() else {
        panic!("not enrolled");
    };
    assert_eq!(stored.chain_pem, renewed);
    assert_eq!(answered.state, IssuerState::Issuing);
    assert_eq!(
        step_ca_log(state, &["start", "hup"]).await,
        ["start", "hup"]
    );
    let intermediate = std::fs::read_to_string(state.join("step-ca-intermediate.crt")).unwrap();
    assert!(renewed.starts_with(intermediate.trim_end()));

    let (code, body) = enrolled.as_operator("POST", path::REVOKE, "").await;
    assert_eq!(code, 200, "{body}");
    let revoked: Status = serde_json::from_str(&body).unwrap();
    assert_eq!(revoked.state, IssuerState::Revoked);

    for method in ["GET", "POST"] {
        let (code, _) = enrolled.as_operator(method, path::ENROLMENT, "{}").await;
        assert_eq!(code, 404, "{method}");
    }
}

#[tokio::test]
async fn a_chain_over_another_key_or_from_another_root_is_refused() {
    let mut enrolled = enrolled().await;
    let other_broker = serve(private_tempdir(), &[]).await;
    let (other_key, _, _) = enrolled
        .ca
        .sign(other_broker.broker.subordinate().csr_pem(), DOMAINS);
    let (other_root, _, _) =
        TestCa::new().sign(enrolled.running.broker.subordinate().csr_pem(), DOMAINS);

    for chain in [other_key, other_root] {
        let (code, body) = enrolled
            .as_operator("PUT", path::CHAIN, &enrolled.update(chain))
            .await;
        assert_eq!((code, error(&body)), (400, ErrorKind::BadRequest), "{body}");
    }
    assert_eq!(enrolled.status().await.subordinate_serial, enrolled.serial);
}

#[tokio::test]
async fn a_revoked_broker_answers_only_status_and_revoke_and_stays_revoked() {
    let mut enrolled = enrolled().await;
    let fresh = enrolled.running.broker.subordinate().fresh_csr().unwrap();
    let (renewed, _) = enrolled.ca.renew(enrolled.id, &fresh);
    assert_eq!(enrolled.as_operator("POST", path::REVOKE, "").await.0, 200);

    for (method, route, body) in [
        ("POST", path::CSR, String::new()),
        ("PUT", path::CHAIN, enrolled.update(renewed)),
    ] {
        let (code, answer) = enrolled.as_operator(method, route, &body).await;
        assert_eq!((code, error(&answer)), (409, ErrorKind::Revoked), "{route}");
    }
    let (code, body) = enrolled.as_operator("POST", path::REVOKE, "").await;
    assert_eq!(code, 200);
    assert_eq!(
        serde_json::from_str::<Status>(&body).unwrap().state,
        IssuerState::Revoked
    );

    let Enrolled { running, .. } = enrolled;
    let restarted = start(running.state, &[], Some(running.api.uri)).await;
    assert!(matches!(restarted.broker.mode(), Mode::Enrolled(e) if e.revoked));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        step_ca_log(restarted.state.path(), &["start"]).await,
        ["start"]
    );
}

#[tokio::test]
async fn a_restart_while_enrolled_comes_up_requiring_the_operator() {
    let enrolled = enrolled().await;
    let Enrolled {
        running,
        operator,
        serial,
        ..
    } = enrolled;
    let restarted = start(running.state, &[], Some(running.api.uri)).await;

    assert!(refused(&restarted, None).await);
    let (code, body) = restarted
        .call(Some(&operator), "GET", path::STATUS, "")
        .await
        .unwrap();
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<Status>(&body)
            .unwrap()
            .subordinate_serial,
        serial
    );
}

#[tokio::test]
async fn opca_that_lost_the_enrolment_answer_finds_it_through_status() {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (chain, serial, _) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let enrolment = opca_acme_api::Enrolment {
        operator_pin: operator.key_pin(),
        ..running.enrolment(&chain, DOMAINS)
    };
    running
        .broker
        .clone()
        .enrol(enrolment.clone())
        .await
        .unwrap();

    let retried = serde_json::to_string(&enrolment).unwrap();
    assert!(
        running
            .call(None, "POST", path::ENROLMENT, &retried)
            .await
            .is_err()
    );
    let (code, body) = running
        .call(Some(&operator), "GET", path::STATUS, "")
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(
        serde_json::from_str::<Status>(&body)
            .unwrap()
            .subordinate_serial,
        serial
    );
}

#[tokio::test]
async fn a_held_state_lock_times_out_a_change_while_status_still_answers() {
    let state = private_tempdir();
    let (broker, uri) = opca_acme_broker::Broker::start(&config(state.path(), &[])).unwrap();
    let patience = std::time::Duration::from_millis(300);
    let running = run(state, broker.with_lock_timeout(patience), uri).await;
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (chain, serial, id) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let enrolment = opca_acme_api::Enrolment {
        operator_pin: operator.key_pin(),
        ..running.enrolment(&chain, DOMAINS)
    };
    assert_eq!(running.post(&enrolment).await.0, 200);
    let fresh = running.broker.subordinate().fresh_csr().unwrap();
    let (renewed, renewed_serial) = ca.renew(id, &fresh);
    let update = serde_json::to_string(&ChainUpdate {
        chain_pem: renewed,
        config: enrolment.config,
    })
    .unwrap();

    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(running.state.path().join("state.lock"))
        .unwrap();
    held.lock().unwrap();
    let started = std::time::Instant::now();
    let (put, status) = tokio::join!(
        running.call(Some(&operator), "PUT", path::CHAIN, &update),
        running.call(Some(&operator), "GET", path::STATUS, ""),
    );
    let (code, body) = put.unwrap();
    assert_eq!((code, error(&body)), (500, ErrorKind::Internal), "{body}");
    assert!(started.elapsed() < patience * 4, "{:?}", started.elapsed());
    let (code, body) = status.unwrap();
    assert_eq!(code, 200);
    assert_eq!(
        serde_json::from_str::<Status>(&body)
            .unwrap()
            .subordinate_serial,
        serial
    );

    drop(held);
    let mut finished = String::new();
    for _ in 0..100 {
        let (_, body) = running
            .call(Some(&operator), "GET", path::STATUS, "")
            .await
            .unwrap();
        finished = serde_json::from_str::<Status>(&body)
            .unwrap()
            .subordinate_serial;
        if finished == renewed_serial {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        finished, renewed_serial,
        "the change finished once the lock was free"
    );
}
