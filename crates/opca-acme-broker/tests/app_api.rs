//! The API the app's page calls on `app.sock`: the status, the issued certificates newest first,
//! and a new pairing code for an admin.

#![cfg(unix)]

mod support;

use std::fs;
use std::path::Path;

use opca_acme_api::{Enrolment, ErrorKind, path};
use opca_acme_broker::app::{
    APP_SOCKET, AppState, AppStatus, Hooked, IssuedNewest, Issuer, NewPairing,
};
use opca_acme_broker::{Broker, SCHEME};
use support::{
    Api, DOMAINS, HOST, Running, TestCa, config, console_app, enrol, error, private_tempdir,
    record, run, serve_console, wrong,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use wslib_pairing::{PairingUri, SpentBy, Status};

const VIEWER: &str = "v1; id=a1; user=someone; role=viewer";
const OPERATOR: &str = "v1; id=a2; user=hand; role=operator";
const ADMIN: &str = "v1; id=a3; user=boss; role=admin";
const STATUS: &str = "/apps/opca-acme/api/status";
const ISSUED: &str = "/apps/opca-acme/api/issued";
const PAIRING: &str = "/apps/opca-acme/api/pairing";

/// `method path` on `app.sock` in `sockets`, as the console asserting `identity`: its status and body.
async fn call(sockets: &Path, method: &str, path: &str, identity: Option<&str>) -> (u16, String) {
    let mut stream = UnixStream::connect(sockets.join(APP_SOCKET)).await.unwrap();
    let asserted = identity.map_or(String::new(), |identity| {
        format!("Appliance-Identity: {identity}\r\n")
    });
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n{asserted}\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head[9..12].parse().unwrap(), body.into())
}

async fn read<T: serde::de::DeserializeOwned>(sockets: &Path, path: &str) -> T {
    let (code, body) = call(sockets, "GET", path, Some(VIEWER)).await;
    assert_eq!(code, 200, "{path}: {body}");
    serde_json::from_str(&body).unwrap()
}

async fn console(data: &Path, hooked: Hooked) -> TempDir {
    serve_console(console_app(data, &[]), hooked).await
}

fn serials(page: &IssuedNewest) -> Vec<&str> {
    page.certificates
        .iter()
        .map(|c| c.serial.as_str())
        .collect()
}

#[tokio::test]
async fn needing_a_host_it_has_the_configured_domains_and_nothing_issued() {
    let data = private_tempdir();
    fs::write(
        data.path().join("options.json"),
        r#"{"domains": ["home.example"]}"#,
    )
    .unwrap();
    let sockets = console(data.path(), Hooked::NeedsHost(data.path().join("state"))).await;

    let status: AppStatus = read(sockets.path(), STATUS).await;
    assert_eq!(
        status,
        AppStatus {
            state: AppState::NeedsHost,
            host: None,
            api_url: None,
            acme_directory: None,
            ca_url: None,
            crl_url: None,
            crl: None,
            domains: vec!["home.example".into()],
            subordinate: None,
        }
    );
    let issued: IssuedNewest = read(sockets.path(), ISSUED).await;
    assert_eq!((issued.certificates.len(), issued.before), (0, None));
}

#[tokio::test]
async fn awaiting_enrolment_it_has_its_host_and_no_subordinate() {
    let state = private_tempdir();
    let (broker, uri) = Broker::start(&config(state.path(), DOMAINS)).await.unwrap();
    let running = run(state, broker, uri).await;
    let sockets = console(
        private_tempdir().path(),
        Hooked::Running(running.broker.clone()),
    )
    .await;

    let status: AppStatus = read(sockets.path(), STATUS).await;
    assert_eq!(
        (status.state, status.host.as_deref(), status.subordinate),
        (AppState::Enrolling, Some(HOST), None)
    );
    assert_eq!(status.domains, DOMAINS);
    assert_eq!(
        (status.api_url.unwrap(), status.acme_directory.unwrap()),
        (
            format!("https://{HOST}:9443"),
            format!("https://{HOST}:8443/acme/directory")
        )
    );
}

#[tokio::test]
async fn the_urls_name_the_ports_the_console_mapped() {
    let state = private_tempdir();
    let (broker, uri) = Broker::start(&config(state.path(), DOMAINS)).await.unwrap();
    let running = run(state, broker, uri).await;
    let mapped = [
        ("APPLIANCE_LISTENER_API_PORT", "19443"),
        ("APPLIANCE_LISTENER_ACME_PORT", "443"),
        ("APPLIANCE_LISTENER_PKI_PORT", "80"),
    ];
    let app = console_app(private_tempdir().path(), &mapped);
    let sockets = serve_console(app, Hooked::Running(running.broker.clone())).await;

    let status: AppStatus = read(sockets.path(), STATUS).await;
    assert_eq!(
        (status.api_url.unwrap(), status.acme_directory.unwrap()),
        (
            format!("https://{HOST}:19443"),
            format!("https://{HOST}/acme/directory")
        )
    );
    assert_eq!(
        (status.ca_url.unwrap(), status.crl_url.unwrap()),
        (
            format!("http://{HOST}/ca.crt"),
            format!("http://{HOST}/crl")
        )
    );
}

#[tokio::test]
async fn enrolled_it_names_its_subordinate_and_pages_the_issued_newest_first() {
    let state = private_tempdir();
    let (broker, uri) = Broker::start(&config(state.path(), DOMAINS)).await.unwrap();
    let enrolled = enrol(run(state, broker.with_issued_page(2), uri).await).await;
    let store = enrolled.running.broker.acme();
    for serial in ["1", "2", "3"] {
        record(store, serial, &format!("host{serial}.home.example")).await;
    }
    store.revoke("2", Some(4)).await.unwrap();
    let sockets = console(
        private_tempdir().path(),
        Hooked::Running(enrolled.running.broker.clone()),
    )
    .await;

    let status: AppStatus = read(sockets.path(), STATUS).await;
    assert_eq!(
        status,
        AppStatus {
            state: AppState::Enrolled,
            host: Some(HOST.into()),
            api_url: Some(format!("https://{HOST}:9443")),
            acme_directory: Some(format!("https://{HOST}:8443/acme/directory")),
            ca_url: Some(format!("http://{HOST}:8080/ca.crt")),
            crl_url: Some(format!("http://{HOST}:8080/crl")),
            crl: status.crl.clone(),
            domains: DOMAINS.iter().map(|d| d.to_string()).collect(),
            subordinate: Some(Issuer {
                serial: enrolled.status.subordinate_serial.clone(),
                not_after: enrolled.status.subordinate_not_after.clone(),
            }),
        }
    );

    let first: IssuedNewest = read(sockets.path(), ISSUED).await;
    assert_eq!(serials(&first), ["3", "2"]);
    assert_eq!(first.certificates[1].revocation_reason, Some(4));
    let before = first.before.expect("an older page");
    let last: IssuedNewest = read(sockets.path(), &format!("{ISSUED}?before={before}")).await;
    assert_eq!((serials(&last), last.before), (vec!["1"], None));

    let revoked: IssuedNewest = read(sockets.path(), &format!("{ISSUED}?revoked=true")).await;
    assert_eq!((serials(&revoked), revoked.before), (vec!["2"], None));
    let unrevoked: IssuedNewest = read(sockets.path(), &format!("{ISSUED}?revoked=false")).await;
    assert_eq!(
        (serials(&unrevoked), unrevoked.before),
        (vec!["3", "1"], None)
    );

    enrolled.as_operator("POST", path::PAUSE, "").await;
    let paused: AppStatus = read(sockets.path(), STATUS).await;
    assert_eq!(paused.state, AppState::Paused);

    for query in ["before=soon", "revoked=yes"] {
        let (code, body) = call(
            sockets.path(),
            "GET",
            &format!("{ISSUED}?{query}"),
            Some(VIEWER),
        )
        .await;
        assert_eq!(code, 400, "{query}: {body}");
    }
}

#[tokio::test]
async fn without_the_consoles_identity_the_api_refuses_and_health_still_answers() {
    let data = private_tempdir();
    let sockets = console(data.path(), Hooked::NeedsHost(data.path().join("state"))).await;

    for path in [STATUS, ISSUED] {
        for (identity, refused) in [
            (None, 401),
            (Some("v2; id=a1; user=someone; role=viewer"), 400),
            (Some("v1; id=a1"), 400),
        ] {
            let (code, _) = call(sockets.path(), "GET", path, identity).await;
            assert_eq!(code, refused, "{path} as {identity:?}");
        }
    }
    let (code, _) = call(sockets.path(), "GET", "/apps/opca-acme/healthz", None).await;
    assert_eq!(code, 200);
}

#[tokio::test]
async fn the_chassis_answers_the_session_and_branding_under_the_base() {
    let data = private_tempdir();
    let sockets = console(data.path(), Hooked::NeedsHost(data.path().join("state"))).await;

    let (code, body) = call(
        sockets.path(),
        "GET",
        "/apps/opca-acme/api/session",
        Some(VIEWER),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"id": "a1", "username": "someone", "role": "viewer"})
    );
    let (code, body) = call(sockets.path(), "GET", "/apps/opca-acme/api/branding", None).await;
    assert_eq!(code, 200, "{body}");
    let branding: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(branding["app_name"], "opCA ACME broker");
}

async fn running_console() -> (Running, TempDir) {
    let state = private_tempdir();
    let (broker, uri) = Broker::start(&config(state.path(), DOMAINS)).await.unwrap();
    let running = run(state, broker, uri).await;
    let sockets = console(
        private_tempdir().path(),
        Hooked::Running(running.broker.clone()),
    )
    .await;
    (running, sockets)
}

/// A new pairing URI from the page, as an admin, for the broker `running` serves.
async fn new_pairing(sockets: &Path, running: &Running) -> Api {
    let (code, body) = call(sockets, "POST", PAIRING, Some(ADMIN)).await;
    assert_eq!(code, 200, "{body}");
    let NewPairing { uri } = serde_json::from_str(&body).unwrap();
    Api {
        uri: PairingUri::parse(SCHEME, &uri).unwrap(),
        address: running.address,
    }
}

async fn refused_pairing(sockets: &Path, identity: &str) -> (u16, String) {
    call(sockets, "POST", PAIRING, Some(identity)).await
}

#[tokio::test]
async fn an_admin_issues_a_pairing_uri_whose_code_alone_redeems_until_enrolled() {
    let (running, sockets) = running_console().await;
    for identity in [VIEWER, OPERATOR] {
        assert_eq!(
            refused_pairing(sockets.path(), identity).await.0,
            403,
            "{identity}"
        );
    }
    assert_eq!(running.remaining(), 5);

    let paired = new_pairing(sockets.path(), &running).await;
    assert_eq!(paired.uri.pin(), running.uri.pin());
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (chain, _, _) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let (code, body) = running.post(&running.enrolment(&chain, DOMAINS)).await;
    assert_eq!(
        (code, error(&body)),
        (403, ErrorKind::WrongCode { remaining: 4 })
    );
    let enrolment = Enrolment {
        operator_pin: operator.key_pin(),
        ..paired.enrolment(&chain, DOMAINS)
    };
    let (code, body) = paired.post(&enrolment).await;
    assert_eq!(code, 200, "{body}");

    let (code, body) = refused_pairing(sockets.path(), ADMIN).await;
    assert_eq!(code, 409);
    assert!(body.contains("the broker is enrolled"), "{body}");
    let (code, _) = paired
        .call(Some(&operator), "POST", path::REVOKE, "")
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (code, body) = refused_pairing(sockets.path(), ADMIN).await;
    assert_eq!(code, 409);
    assert!(body.contains("the broker is revoked"), "{body}");
    assert_eq!(refused_pairing(sockets.path(), VIEWER).await.0, 403);
}

#[tokio::test]
async fn a_new_pairing_uri_replaces_a_code_locked_out_by_wrong_attempts() {
    let (running, sockets) = running_console().await;
    let mut ca = TestCa::new();
    let (chain, _, _) = ca.sign(running.broker.subordinate().csr_pem(), DOMAINS);
    let enrolment = running.enrolment(&chain, DOMAINS);
    let guess = Enrolment {
        code: wrong(&enrolment.code),
        ..enrolment.clone()
    };
    for _ in 0..5 {
        running.post(&guess).await;
    }
    assert_eq!(
        running.broker.code_status().unwrap(),
        Status::Spent(SpentBy::Lockout)
    );

    let paired = new_pairing(sockets.path(), &running).await;
    assert_eq!(running.remaining(), 5);
    let (code, body) = paired.post(&paired.enrolment(&chain, DOMAINS)).await;
    assert_eq!(code, 200, "{body}");
}

#[tokio::test]
async fn needing_a_host_there_is_no_pairing_code_to_issue() {
    let data = private_tempdir();
    let sockets = console(data.path(), Hooked::NeedsHost(data.path().join("state"))).await;
    let (code, body) = refused_pairing(sockets.path(), ADMIN).await;
    assert_eq!(code, 409);
    assert!(body.contains("needs a host"), "{body}");
    assert_eq!(refused_pairing(sockets.path(), OPERATOR).await.0, 403);
}
