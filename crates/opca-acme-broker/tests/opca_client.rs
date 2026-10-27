#![cfg(unix)]

//! opca-core's broker client against a real broker on loopback.

mod support;

use opca_acme_api::IssuerState;
use opca_acme_broker::{ATTEMPTS, Mode, SCHEME};
use opca_core::error::OpcaError;
use opca_core::services::acme_broker::{BrokerError, BrokerNotice, Renewal, fetch_offer, issuance};
use opca_core::services::ca::operator::Operator;
use opca_core::services::database::models::{Broker, BrokerState};
use opca_core::testutil::{Output, created, item_json, not_found};
use support::*;
use wslib_crypto_x509::inspect_pem;
use wslib_pairing::{PairingCode, PairingUri, SpkiSha256};

const DOMAINS: &[&str] = &["home.example"];

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| n.to_string()).collect()
}

/// The broker's pairing string, dialled on loopback.
fn pairing_at(running: &Running, pin: SpkiSha256, code: &PairingCode) -> PairingUri {
    PairingUri::new(SCHEME, LOOPBACK, running.address.port(), pin, code.clone()).unwrap()
}

fn pairing(running: &Running) -> PairingUri {
    pairing_at(running, running.uri.pin(), running.uri.code())
}

/// Scripts `n` certificate items, each followed by a database store.
fn issues(ca: &TestCa, n: usize) {
    for _ in 0..n {
        ca.op.respond(created("CRT"));
        ca.op.respond(Output::ok(""));
    }
}

fn stores(ca: &TestCa, n: usize) {
    for _ in 0..n {
        ca.op.respond(Output::ok(""));
    }
}

fn first_operator(ca: &TestCa) -> Operator {
    ca.op.respond(not_found("CA_Operator"));
    ca.op.respond(created("CA_Operator"));
    ca.ca.operator().unwrap()
}

fn next_serial(ca: &TestCa) -> Option<i64> {
    let db = ca.ca.ca_database.as_ref().unwrap();
    db.get_config().unwrap().next_serial
}

fn row(ca: &TestCa, id: i64) -> Broker {
    let rows = ca.ca.list_subordinates().unwrap();
    rows.into_iter().find(|b| b.id == id).unwrap()
}

struct Enrolled {
    running: Running,
    ca: TestCa,
    operator: Operator,
    id: i64,
}

async fn enrolled(configured: &[&str]) -> Enrolled {
    let running = serve(private_tempdir(), configured).await;
    let mut ca = TestCa::new();
    let operator = first_operator(&ca);
    let pairing = pairing(&running);
    let offer = fetch_offer(&pairing).unwrap();
    issues(&ca, 1);
    stores(&ca, 1);
    let enrolled = ca
        .ca
        .enrol_broker(&operator, &pairing, &offer, issuance(names(DOMAINS)))
        .unwrap();
    assert!(ca.op.is_done());
    Enrolled {
        running,
        ca,
        operator,
        id: enrolled.broker.id,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_pin_fails_before_the_code_is_sent() {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let operator = first_operator(&ca);
    let offer = fetch_offer(&pairing(&running)).unwrap();
    let wrong = pairing_at(&running, SpkiSha256::from([7; 32]), running.uri.code());

    let fetched = fetch_offer(&wrong);
    let enrolled = ca
        .ca
        .enrol_broker(&operator, &wrong, &offer, issuance(names(DOMAINS)));

    for refused in [fetched.map(drop), enrolled.map(drop)] {
        assert!(
            matches!(
                refused,
                Err(OpcaError::Broker(BrokerError::WrongKey { .. }))
            ),
            "{refused:?}"
        );
    }
    assert_eq!(running.remaining(), ATTEMPTS.get());
    assert_eq!(running.broker.mode(), Mode::Enrolling);
    assert!(ca.ca.list_subordinates().unwrap().is_empty());
    assert!(ca.op.is_done(), "nothing signed or stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn enrolment_signs_hands_over_and_records_the_broker() {
    let Enrolled {
        running,
        ca,
        operator,
        id,
    } = enrolled(&[]).await;

    let broker = row(&ca, id);
    assert_eq!(
        broker.url,
        Some(format!("https://{LOOPBACK}:{}", running.address.port()))
    );
    assert_eq!(broker.pinned_key, Some(running.uri.pin().to_string()));
    assert_eq!(broker.permitted_domains, DOMAINS);
    assert!(broker.last_contact.is_some(), "stamped by the hand-over");
    let Mode::Enrolled(on_broker) = running.broker.mode() else {
        panic!("not enrolled");
    };
    assert_eq!(on_broker.operator_pin, operator.pin());
    let leaf = inspect_pem(&on_broker.chain_pem).unwrap();
    assert_eq!(leaf.spki, running.broker.subordinate().spki());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_brokers_own_domains_are_signed_and_cannot_be_widened() {
    let running = serve(private_tempdir(), DOMAINS).await;
    let mut ca = TestCa::new();
    let operator = first_operator(&ca);
    let pairing = pairing(&running);
    let offer = fetch_offer(&pairing).unwrap();
    assert_eq!(offer.configured_domains, DOMAINS);
    let before = next_serial(&ca);

    let wider = issuance(names(&["home.example", "lab.example"]));
    assert!(
        ca.ca
            .enrol_broker(&operator, &pairing, &offer, wider)
            .is_err()
    );
    assert_eq!(next_serial(&ca), before);

    issues(&ca, 1);
    stores(&ca, 1);
    let enrolled = ca
        .ca
        .enrol_broker(&operator, &pairing, &offer, issuance(vec![]))
        .unwrap();
    assert_eq!(enrolled.broker.permitted_domains, DOMAINS);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hand_over_that_failed_is_sent_again_not_signed_again() {
    let running = serve(private_tempdir(), &[]).await;
    let mut ca = TestCa::new();
    let operator = first_operator(&ca);
    let pairing = pairing(&running);
    let offer = fetch_offer(&pairing).unwrap();
    let wrong_code: PairingCode = wrong(running.uri.code().expose()).parse().unwrap();
    let mistyped = pairing_at(&running, running.uri.pin(), &wrong_code);
    issues(&ca, 1);

    let failed = ca
        .ca
        .enrol_broker(&operator, &mistyped, &offer, issuance(names(DOMAINS)));

    assert!(failed.is_err());
    assert_eq!(running.remaining(), ATTEMPTS.get() - 1);
    let [pending] = &ca.ca.list_subordinates().unwrap()[..] else {
        panic!("one row for the signed subordinate");
    };
    assert_eq!(pending.last_contact, None);
    let serial = next_serial(&ca);
    let create = ca.op.calls().into_iter().rev().nth(1).unwrap();
    let template: serde_json::Value = serde_json::from_slice(create.stdin().unwrap()).unwrap();
    let cert_pem = template["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "certificate")
        .unwrap()["value"]
        .as_str()
        .unwrap()
        .to_owned();
    ca.op
        .respond(Output::ok(item_json("CRT", &[("certificate", &cert_pem)])));
    stores(&ca, 1);

    let enrolled = ca
        .ca
        .enrol_broker(&operator, &pairing, &offer, issuance(names(DOMAINS)))
        .unwrap();

    assert_eq!(next_serial(&ca), serial, "nothing signed the second time");
    assert_eq!(enrolled.broker.id, pending.id);
    assert_eq!(
        enrolled.status.subordinate_serial,
        pending.subordinate_serial
    );
    assert!(enrolled.broker.last_contact.is_some());
    assert!(ca.op.is_done());
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_keeps_the_key_and_moves_to_a_new_serial() {
    let Enrolled {
        running,
        mut ca,
        operator,
        id,
    } = enrolled(&[]).await;
    let old = row(&ca, id).subordinate_serial;
    issues(&ca, 1);
    stores(&ca, 1);

    let renewal = ca.ca.renew_broker(&operator, id, false).unwrap();

    let Renewal::Renewed { serial, status } = renewal else {
        panic!("{renewal:?}");
    };
    assert_ne!(serial, old);
    assert_eq!(status.subordinate_serial, serial);
    assert_eq!(row(&ca, id).subordinate_serial, serial);
    let Mode::Enrolled(on_broker) = running.broker.mode() else {
        panic!("not enrolled");
    };
    let leaf = inspect_pem(&on_broker.chain_pem).unwrap();
    assert_eq!(
        leaf.spki,
        running.broker.subordinate().spki(),
        "the same key"
    );
    assert!(ca.op.is_done());
}

#[tokio::test(flavor = "multi_thread")]
async fn other_domains_on_the_broker_are_flagged_until_the_change_is_confirmed() {
    let Enrolled {
        running,
        mut ca,
        operator,
        id,
    } = enrolled(DOMAINS).await;
    let wider = ["home.example", "lab.example"];
    let moved = start(running.state, &wider, Some(running.api.uri)).await;
    let url = format!("https://{LOOPBACK}:{}", moved.address.port());
    let db = ca.ca.ca_database.as_ref().unwrap();
    db.set_broker_endpoint(id, &url, &moved.uri.pin().to_string())
        .unwrap();
    let before = next_serial(&ca);
    stores(&ca, 1);

    let flagged = ca.ca.renew_broker(&operator, id, false).unwrap();

    let Renewal::DomainsChanged {
        recorded,
        configured,
    } = flagged
    else {
        panic!("{flagged:?}");
    };
    assert_eq!((recorded, configured), (names(DOMAINS), names(&wider)));
    assert_eq!(next_serial(&ca), before, "nothing signed");

    issues(&ca, 1);
    stores(&ca, 1);
    let confirmed = ca.ca.renew_broker(&operator, id, true).unwrap();

    assert!(
        matches!(&confirmed, Renewal::Renewed { status, .. }
            if status.config.permitted_domains == wider),
        "{confirmed:?}"
    );
    assert_eq!(row(&ca, id).permitted_domains, wider);
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_puts_it_on_the_crl_and_stops_the_broker() {
    let Enrolled {
        running,
        mut ca,
        operator,
        id,
    } = enrolled(&[]).await;
    let serial = row(&ca, id).subordinate_serial;
    stores(&ca, 2);

    let revocation = ca.ca.revoke_broker(&operator, id).unwrap();

    assert_eq!(revocation.broker.state, BrokerState::Revoked);
    assert!(
        matches!(&revocation.notice, BrokerNotice::Told { status }
            if status.state == IssuerState::Revoked),
        "{:?}",
        revocation.notice
    );
    assert!(matches!(running.broker.mode(), Mode::Enrolled(e) if e.revoked));
    stores(&ca, 2);
    let crl = ca.ca.generate_crl().unwrap();
    let crl = wslib_crypto_ca::CrlView::from_pem(&crl).unwrap();
    let on_crl: Vec<_> = crl.revoked.into_iter().map(|r| r.serial).collect();
    assert_eq!(on_crl, [serial.parse().unwrap()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_stands_when_the_broker_cannot_be_told() {
    let Enrolled {
        mut ca,
        operator,
        id,
        running: _running,
    } = enrolled(&[]).await;
    let pin = row(&ca, id).pinned_key.unwrap();
    move_to_a_closed_port(&ca, id, &pin);
    stores(&ca, 1);

    let revocation = ca.ca.revoke_broker(&operator, id).unwrap();

    assert_eq!(revocation.broker.state, BrokerState::Revoked);
    assert!(
        matches!(
            revocation.notice,
            BrokerNotice::NotTold {
                error: BrokerError::Unreachable { .. }
            }
        ),
        "{:?}",
        revocation.notice
    );
}

fn move_to_a_closed_port(ca: &TestCa, id: i64, pin: &str) {
    let closed = std::net::TcpListener::bind((LOOPBACK, 0)).unwrap();
    let url = format!("https://{LOOPBACK}:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let db = ca.ca.ca_database.as_ref().unwrap();
    db.set_broker_endpoint(id, &url, pin).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn renewing_all_reports_an_unreachable_broker_and_renews_the_rest() {
    let Enrolled {
        mut ca,
        operator,
        id,
        running: _running,
    } = enrolled(&[]).await;
    let other = serve(private_tempdir(), &[]).await;
    issues(&ca, 1);
    let unreachable = ca
        .ca
        .sign_subordinate(
            other.broker.subordinate().csr_pem().as_bytes(),
            &names(DOMAINS),
            None,
        )
        .unwrap()
        .broker
        .id;
    move_to_a_closed_port(&ca, unreachable, &other.uri.pin().to_string());
    issues(&ca, 1);
    stores(&ca, 1);

    let renewals = ca.ca.renew_all_brokers(&operator).unwrap();

    let outcomes: Vec<_> = renewals.iter().map(|r| (r.id, &r.renewal)).collect();
    assert!(
        matches!(
            &outcomes[..],
            [(a, Renewal::Renewed { .. }), (b, Renewal::Unreachable { .. })]
                if (*a, *b) == (id, unreachable)
        ),
        "{outcomes:?}"
    );
    assert_eq!(row(&ca, unreachable).last_contact, None);
    assert!(ca.op.is_done());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vpn_client_of_the_same_root_is_refused_where_the_operator_is_accepted() {
    let Enrolled {
        mut ca,
        operator,
        id,
        running: _running,
    } = enrolled(&[]).await;
    let vpn = ca.client("someone");
    let vpn = Operator::presenting(vpn.chain, vpn.key.clone_key()).unwrap();
    let stamped = row(&ca, id).last_contact;

    let refused = ca.ca.broker_status(&vpn, id);

    assert!(
        matches!(
            refused,
            Err(OpcaError::Broker(BrokerError::Unreachable { .. }))
        ),
        "{refused:?}"
    );
    assert_eq!(row(&ca, id).last_contact, stamped);
    stores(&ca, 1);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let status = ca.ca.broker_status(&operator, id).unwrap();
    assert_eq!(status.subordinate_serial, row(&ca, id).subordinate_serial);
    assert!(row(&ca, id).last_contact > stamped, "stamped again");
}
