//! The read API the app's page calls on `app.sock`: the status, and the issued certificates newest first.

#![cfg(unix)]

mod support;

use std::fs;
use std::path::Path;

use opca_acme_broker::Broker;
use opca_acme_broker::app::{APP_SOCKET, AppState, AppStatus, Hooked, IssuedNewest, Issuer};
use support::{
    DOMAINS, HOST, config, console_app, enrol, private_tempdir, record, run, serve_console,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const VIEWER: &str = "v1; id=a1; user=someone; role=viewer";
const STATUS: &str = "/apps/opca-acme/api/status";
const ISSUED: &str = "/apps/opca-acme/api/issued";

/// `GET path` on `app.sock` in `sockets`, as the console asserting `identity`: its status and body.
async fn get(sockets: &Path, path: &str, identity: Option<&str>) -> (u16, String) {
    let mut stream = UnixStream::connect(sockets.join(APP_SOCKET)).await.unwrap();
    let asserted = identity.map_or(String::new(), |identity| {
        format!("Appliance-Identity: {identity}\r\n")
    });
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{asserted}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head[9..12].parse().unwrap(), body.into())
}

async fn read<T: serde::de::DeserializeOwned>(sockets: &Path, path: &str) -> T {
    let (code, body) = get(sockets, path, Some(VIEWER)).await;
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

    for query in ["before=soon", "revoked=yes"] {
        let (code, body) = get(sockets.path(), &format!("{ISSUED}?{query}"), Some(VIEWER)).await;
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
            let (code, _) = get(sockets.path(), path, identity).await;
            assert_eq!(code, refused, "{path} as {identity:?}");
        }
    }
    let (code, _) = get(sockets.path(), "/apps/opca-acme/healthz", None).await;
    assert_eq!(code, 200);
}

#[tokio::test]
async fn the_chassis_answers_the_session_and_branding_under_the_base() {
    let data = private_tempdir();
    let sockets = console(data.path(), Hooked::NeedsHost(data.path().join("state"))).await;

    let (code, body) = get(sockets.path(), "/apps/opca-acme/api/session", Some(VIEWER)).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"id": "a1", "username": "someone", "role": "viewer"})
    );
    let (code, body) = get(sockets.path(), "/apps/opca-acme/api/branding", None).await;
    assert_eq!(code, 200, "{body}");
    let branding: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(branding["app_name"], "opCA ACME broker");
}
