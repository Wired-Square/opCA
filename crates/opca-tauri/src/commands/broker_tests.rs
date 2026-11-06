use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use opca_acme_broker::{Broker, Config};
use opca_core::testutil::{created, not_found};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use wslib_http_server::{Bounds, Listener};

use super::broker::*;
use crate::test_harness::{Handler, Harness};

const HOST: &str = "acme.home.example";
const LOOPBACK: &str = "127.0.0.1";

fn handler() -> impl Handler {
    tauri::generate_handler![
        fetch_broker_offer,
        enrol_broker,
        list_brokers,
        list_broker_certs,
        broker_status,
        renew_broker,
        renew_all_brokers,
        revoke_broker,
        super::dashboard::get_dashboard
    ]
}

/// A broker serving on loopback, with the pairing string it printed.
struct Running {
    _state: TempDir,
    runtime: Runtime,
    pairing: String,
}

fn serve(domains: &[&str]) -> Running {
    let state = tempfile::tempdir().unwrap();
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = Runtime::new().unwrap();
    let listener = runtime
        .block_on(Listener::bind(
            format!("{LOOPBACK}:0").parse().unwrap(),
            Bounds::SERVING,
        ))
        .unwrap();
    let config = Config {
        host: HOST.into(),
        listen: listener.local_addr(),
        domains: domains.iter().map(|d| d.to_string()).collect(),
        state_dir: state.path().into(),
        acme_listen: format!("{LOOPBACK}:0").parse().unwrap(),
        ..Config::parse(r#"host = "unused.example""#).unwrap()
    };
    let (broker, uri) = runtime.block_on(Broker::start(&config)).unwrap();
    let broker = Arc::new(broker);
    runtime.spawn(broker.clone().serve_acme(std::future::pending()));
    runtime.spawn(opca_acme_broker::serve(
        broker,
        listener,
        std::future::pending(),
    ));
    Running {
        _state: state,
        runtime,
        pairing: uri.unwrap().expose().replace(HOST, LOOPBACK),
    }
}

fn answer_operator_minted(h: &Harness) {
    h.answer([not_found("CA_Operator"), created("CA_Operator")]);
}

fn operator_lookups(h: &Harness) -> usize {
    h.op_calls(&["item", "get"])
        .iter()
        .filter(|c| c.iter().any(|a| a == "CA_Operator"))
        .count()
}

fn enrol(h: &Harness, running: &Running, domains: Value) -> Value {
    let offered = h
        .invoke("fetch_broker_offer", json!({ "pairing": running.pairing }))
        .unwrap();
    h.answer([created("CRT")]);
    h.answer_writes(2);
    h.invoke(
        "enrol_broker",
        json!({ "request": {
            "pairing": running.pairing,
            "offer": offered["offer"],
            "domains": domains,
        } }),
    )
    .unwrap()
}

#[test]
fn listing_without_a_broker_call_never_mints_the_operator() {
    let h = Harness::with_ca(vec![], handler());

    let listed = h.invoke("list_brokers", json!({})).unwrap();
    let certs = h.invoke("list_broker_certs", json!({})).unwrap();

    assert_eq!((listed, certs), (json!([]), json!([])));
    assert!(h.op_calls(&[]).is_empty());
}

#[test]
fn the_offer_shows_the_pinned_key_and_the_brokers_domains() {
    let running = serve(&["home.example"]);
    let h = Harness::with_ca(vec![], handler());

    let offered = h
        .invoke("fetch_broker_offer", json!({ "pairing": running.pairing }))
        .unwrap();

    assert_eq!(offered["offer"]["host"], HOST);
    assert_eq!(
        offered["offer"]["configured_domains"],
        json!(["home.example"])
    );
    assert!(
        offered["address"]
            .as_str()
            .unwrap()
            .starts_with("https://127.0.0.1:")
    );
    assert!(running.pairing.contains(offered["pin"].as_str().unwrap()));
    assert!(h.op_calls(&[]).is_empty(), "nothing is minted to look");

    let refused = h.invoke(
        "fetch_broker_offer",
        json!({ "pairing": "acme.home.example:9443" }),
    );
    assert!(
        refused
            .unwrap_err()
            .as_str()
            .unwrap()
            .contains("pairing string")
    );
    assert!(!h.last_log().success);
}

#[test]
fn enrol_status_renew_and_revoke_mint_the_operator_once() {
    let running = serve(&[]);
    let h = Harness::with_ca(vec![], handler());
    answer_operator_minted(&h);

    let enrolled = enrol(&h, &running, json!(["home.example"]));
    let id = enrolled["broker"]["id"].clone();
    assert_eq!(
        enrolled["broker"]["permitted_domains"],
        json!(["home.example"])
    );
    assert!(h.last_log().detail.unwrap().starts_with("Enrolled broker"));

    let listed = h.invoke("list_brokers", json!({})).unwrap();
    let [row] = &listed.as_array().unwrap()[..] else {
        panic!("one broker");
    };
    assert_eq!(row["concerns"], json!([]));
    assert!(row["last_contact"].is_string());

    h.answer_writes(1);
    let status = h.invoke("broker_status", json!({ "id": id })).unwrap();
    assert_eq!(
        status["subordinate_serial"],
        enrolled["broker"]["subordinate_serial"]
    );

    h.answer([created("CRT")]);
    h.answer_writes(2);
    let renewed = h
        .invoke("renew_broker", json!({ "id": id, "changeDomains": null }))
        .unwrap();
    assert_eq!(renewed["outcome"], "renewed");
    assert!(h.last_log().success);

    h.answer([created("CRT")]);
    h.answer_writes(2);
    let all = h.invoke("renew_all_brokers", json!({})).unwrap();
    assert_eq!(all[0]["id"], id);
    assert_eq!(all[0]["outcome"], "renewed");

    h.answer_writes(4);
    let revoked = h.invoke("revoke_broker", json!({ "id": id })).unwrap();
    assert_eq!(revoked["broker"]["state"], "revoked");
    assert_eq!(revoked["notice"], "told");
    let logged = h.last_log();
    assert!(logged.success);
    assert!(logged.detail.unwrap().contains("regenerated the CRL"));

    assert_eq!(operator_lookups(&h), 1, "minted once for the session");
    drop(running);
}

#[test]
fn renew_all_reports_an_unreachable_broker() {
    let running = serve(&["home.example"]);
    let h = Harness::with_ca(vec![], handler());
    answer_operator_minted(&h);
    let id = enrol(&h, &running, json!([]))["broker"]["id"].clone();
    running.runtime.shutdown_background();
    h.answer_writes(1);

    let all = h.invoke("renew_all_brokers", json!({})).unwrap();

    assert_eq!(all[0]["id"], id);
    assert_eq!(all[0]["outcome"], "unreachable");
    let logged = h.last_log();
    assert!(!logged.success);
    assert!(logged.detail.unwrap().contains("unreachable"));

    let dashboard = h.invoke("get_dashboard", json!({})).unwrap();
    assert_eq!(dashboard["brokers"], 1);
    assert_eq!(
        dashboard["brokers_flagged"],
        json!([]),
        "heard from today, 90 days left"
    );
}

#[test]
fn a_signed_but_undelivered_broker_is_flagged() {
    let running = serve(&[]);
    let h = Harness::with_ca(vec![], handler());
    answer_operator_minted(&h);
    let offered = h
        .invoke("fetch_broker_offer", json!({ "pairing": running.pairing }))
        .unwrap();
    let mistyped = wrong_code(&running.pairing);
    h.answer([created("CRT")]);
    h.answer_writes(1);

    let refused = h.invoke(
        "enrol_broker",
        json!({ "request": { "pairing": mistyped, "offer": offered["offer"], "domains": ["home.example"] } }),
    );

    assert!(
        refused
            .unwrap_err()
            .as_str()
            .unwrap()
            .contains("send it again")
    );
    let dashboard = h.invoke("get_dashboard", json!({})).unwrap();
    let [flagged] = &dashboard["brokers_flagged"].as_array().unwrap()[..] else {
        panic!("{dashboard}");
    };
    assert_eq!(flagged["concerns"], json!([{ "concern": "not_delivered" }]));
}

fn wrong_code(pairing: &str) -> String {
    let (head, code) = pairing.rsplit_once("code=").unwrap();
    let flipped = if code.starts_with('A') { 'B' } else { 'A' };
    format!("{head}code={flipped}{}", &code[1..])
}
