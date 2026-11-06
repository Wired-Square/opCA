//! The app's hot backup on `hooks.sock`: capture, inspect and restore, as the ApplianceOS console calls them.

#![cfg(unix)]

mod support;

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use opca_acme_api::path;
use opca_acme_broker::Mode;
use opca_acme_broker::acme::from_base64url;
use opca_acme_broker::app::{AppState, HOOKS_SOCKET, Health, Hooked, serve_console};
use serde_json::{Value, json};
use support::{DOMAINS, Enrolled, Running, enrol, private_tempdir, record, record_chain, serve};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;
use wslib_appliance_types::backup::RestoreReport;
use wslib_appliance_types::hooks::{AppInspection, HookIndex};
use wslib_crypto_x509::pem;

/// The console's sockets for `hooked`, in a directory of their own.
fn console(hooked: Hooked) -> TempDir {
    let sockets = private_tempdir();
    let health = Health {
        state: AppState::Enrolled,
        api_port: 1,
        acme_port: 2,
    };
    let served = serve_console(
        sockets.path(),
        hooked,
        move || health.clone(),
        CancellationToken::new(),
    )
    .unwrap();
    tokio::spawn(served);
    sockets
}

async fn hook(sockets: &Path, method: &str, route: &str, body: &str) -> (u16, String) {
    let mut stream = UnixStream::connect(sockets.join(HOOKS_SOCKET))
        .await
        .unwrap();
    let request = format!(
        "{method} {route} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head[9..12].parse().unwrap(), body.into())
}

async fn capture(sockets: &Path) -> String {
    let (code, body) = hook(sockets, "POST", "/v1/backup/capture", "").await;
    assert_eq!(code, 200, "{body}");
    body
}

async fn inspect(sockets: &Path, capture: &str) -> AppInspection {
    let (code, body) = hook(sockets, "POST", "/v1/backup/inspect", capture).await;
    assert_eq!(code, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

/// As the console restores: everything the inspection says the capture holds.
async fn restore(sockets: &Path, capture: &str) -> (u16, String) {
    let chosen: Vec<String> = inspect(sockets, capture)
        .await
        .contains
        .app
        .into_keys()
        .collect();
    let body = format!(r#"{{"chosen": {{"app": {chosen:?}}}, "sections": {capture}}}"#);
    hook(sockets, "POST", "/v1/backup/restore", &body).await
}

async fn enrolled() -> (Enrolled, TempDir) {
    let enrolled = enrol(serve(private_tempdir(), DOMAINS).await).await;
    let sockets = console(Hooked::Running(enrolled.running.broker.clone()));
    (enrolled, sockets)
}

async fn total(running: &Running) -> u64 {
    running.broker.acme().counts().await.unwrap().total
}

fn inflated_db(capture: &str) -> Vec<u8> {
    let capture: Value = serde_json::from_str(capture).unwrap();
    let deflated = from_base64url(capture["acme"]["db"].as_str().unwrap()).unwrap();
    let mut db = Vec::new();
    flate2::read::DeflateDecoder::new(&deflated[..])
        .read_to_end(&mut db)
        .unwrap();
    db
}

#[tokio::test]
async fn the_hooks_say_the_app_takes_its_own_backups_on_a_socket_the_console_can_reach() {
    let (_enrolled, sockets) = enrolled().await;
    let socket = sockets.path().join(HOOKS_SOCKET);
    let mode = fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    let (code, body) = hook(sockets.path(), "GET", "/v1", "").await;
    assert_eq!(code, 200, "{body}");
    assert!(serde_json::from_str::<HookIndex>(&body).unwrap().backup);
    let (code, body) = hook(sockets.path(), "GET", "/v1/about", "").await;
    assert_eq!(code, 200, "{body}");
}

#[tokio::test]
async fn a_restore_puts_back_the_capture_and_moves_the_sync_cursor_past_every_change() {
    let (enrolled, sockets) = enrolled().await;
    let store = enrolled.running.broker.acme();
    record(store, "11", "a.home.example").await;
    let captured = capture(sockets.path()).await;
    record(store, "12", "b.home.example").await;
    store.revoke("11", Some(1)).await.unwrap();
    let synced = store.changed_after(0, 10).await.unwrap();
    let cursor = synced.certificates.last().unwrap().changed;

    let (code, body) = restore(sockets.path(), &captured).await;
    assert_eq!(code, 200, "{body}");
    let report: RestoreReport = serde_json::from_str(&body).unwrap();
    assert_eq!(
        report.applied.app,
        ["acme", "enrolment"].map(String::from).into()
    );
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);

    let after = store.changed_after(cursor, 10).await.unwrap().certificates;
    assert_eq!(
        after.len(),
        1,
        "the restored row reaches a client already past it"
    );
    assert_eq!(
        (after[0].serial.as_str(), after[0].revoked_at),
        ("11", None)
    );
    assert!(matches!(enrolled.running.broker.mode(), Mode::Enrolled(e) if !e.revoked));
    record(store, "13", "c.home.example").await;
    let next = store.changed_after(after[0].changed, 10).await.unwrap();
    assert_eq!(next.certificates[0].serial, "13");
    assert!(!enrolled.running.state.path().join("restore.db").exists());
}

#[tokio::test]
async fn a_capture_never_holds_the_subordinate_key_or_any_other() {
    let (enrolled, sockets) = enrolled().await;
    let state = enrolled.running.state.path();
    record(enrolled.running.broker.acme(), "11", "a.home.example").await;
    let captured = capture(sockets.path()).await;
    let db = inflated_db(&captured);
    let key_pem = fs::read_to_string(state.join("subordinate.key")).unwrap();
    let key_der = pem::private_key(&key_pem).unwrap();
    let key_der = key_der.secret_der();
    for held in [captured.as_bytes(), &db[..]] {
        assert!(!contains(held, b"PRIVATE KEY"));
        assert!(!contains(held, key_der));
        for line in key_pem.lines().filter(|line| !line.starts_with("-----")) {
            assert!(!contains(held, line.as_bytes()), "{line}");
        }
    }
    assert!(
        contains(&db, b"a.home.example"),
        "the capture holds the issued certificates"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn a_restore_that_fails_partway_leaves_the_database_and_enrolment_as_they_were() {
    let (enrolled, sockets) = enrolled().await;
    let (running, state) = (&enrolled.running, enrolled.running.state.path());
    record(running.broker.acme(), "11", "a.home.example").await;
    let captured = capture(sockets.path()).await;
    record(running.broker.acme(), "12", "b.home.example").await;
    let enrolment = fs::read(state.join("enrolment.json")).unwrap();
    let blocker = state.join("enrolment.json.new");
    fs::create_dir_all(blocker.join("in-the-way")).unwrap();

    let (code, body) = restore(sockets.path(), &captured).await;
    assert_eq!(code, 500, "{body}");
    assert_eq!(
        total(running).await,
        2,
        "the rows copied over are rolled back"
    );
    assert_eq!(fs::read(state.join("enrolment.json")).unwrap(), enrolment);
    assert!(!state.join("restore.db").exists());

    fs::remove_dir_all(blocker).unwrap();
    let (code, body) = restore(sockets.path(), &captured).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(total(running).await, 1);
}

#[tokio::test]
async fn a_fresh_broker_takes_the_certificates_and_wants_enrolling_again() {
    let (enrolled, sockets) = enrolled().await;
    record(enrolled.running.broker.acme(), "11", "a.home.example").await;
    let captured = capture(sockets.path()).await;
    let old_serial = &enrolled.status.subordinate_serial;

    let fresh = serve(private_tempdir(), DOMAINS).await;
    let fresh_sockets = console(Hooked::Running(fresh.broker.clone()));
    let (code, body) = restore(fresh_sockets.path(), &captured).await;
    assert_eq!(code, 200, "{body}");
    let report: RestoreReport = serde_json::from_str(&body).unwrap();
    assert_eq!(report.applied.app, ["acme".to_string()].into());
    let [warning] = &report.warnings[..] else {
        panic!("{:?}", report.warnings);
    };
    assert!(
        warning.contains("enrol the broker with opCA again"),
        "{warning}"
    );
    assert!(warning.contains(old_serial.as_str()), "{warning}");
    assert_eq!(fresh.broker.mode(), Mode::Enrolling);
    assert!(fresh.broker.offer().is_some());
    assert_eq!(total(&fresh).await, 1);
}

#[tokio::test]
async fn inspect_blocks_a_capture_that_cannot_be_restored_and_restore_refuses_it() {
    let (enrolled, sockets) = enrolled().await;
    let captured: Value = serde_json::from_str(&capture(sockets.path()).await).unwrap();
    let with = |pointer: &str, value: Value| {
        let mut changed = captured.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        changed.to_string()
    };
    let deflated_text = {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, b"not a database").unwrap();
        opca_acme_broker::acme::base64url(&encoder.finish().unwrap())
    };
    let cases = [
        (
            json!({"format": "something-else", "version": 1}).to_string(),
            "acme",
            "not an opCA",
        ),
        (
            with("/version", json!(2)),
            "enrolment",
            "newer than this broker's",
        ),
        (
            with("/acme/schema", json!(99)),
            "acme",
            "update the app first",
        ),
        (
            with("/acme/db", json!("not base64url!")),
            "acme",
            "not deflated",
        ),
        (
            with("/acme/db", json!(deflated_text)),
            "acme",
            "cannot be restored",
        ),
        (
            with("/enrolment/chain_pem", json!("")),
            "enrolment",
            "chain did not parse",
        ),
    ];
    let before = total(&enrolled.running).await;
    for (capture, section, why) in cases {
        let inspection = inspect(sockets.path(), &capture).await;
        let blocked = inspection.blocked.get(section);
        assert!(
            blocked.is_some_and(|b| b.contains(why)),
            "{section}: {blocked:?}"
        );
        let warned = |w: &String| {
            w.starts_with("This backup will not be restored")
                && w.contains(section)
                && w.contains(why)
        };
        assert!(
            inspection.warnings.iter().any(warned),
            "{:?}",
            inspection.warnings
        );
        let body =
            format!(r#"{{"chosen": {{"app": ["acme", "enrolment"]}}, "sections": {capture}}}"#);
        let (code, body) = hook(sockets.path(), "POST", "/v1/backup/restore", &body).await;
        assert_eq!(code, 400, "{body}");
    }
    assert_eq!(total(&enrolled.running).await, before);
    assert!(!enrolled.running.state.path().join("restore.db").exists());
}

#[tokio::test]
async fn an_enrolment_for_another_key_or_one_undoing_a_revocation_is_blocked() {
    let (first, first_sockets) = enrolled().await;
    let captured = capture(first_sockets.path()).await;
    let (_second, second_sockets) = enrolled().await;
    let inspection = inspect(second_sockets.path(), &captured).await;
    assert!(
        inspection.blocked["enrolment"].contains("another subordinate key"),
        "{inspection:?}"
    );
    assert!(
        inspection.warnings.iter().any(|w| w.starts_with(
            "This backup will not be restored (enrolment): it is for another subordinate key"
        )),
        "{:?}",
        inspection.warnings
    );

    first.as_operator("POST", path::REVOKE, "").await;
    let inspection = inspect(first_sockets.path(), &captured).await;
    assert!(
        inspection.blocked["enrolment"].contains("revoked"),
        "{inspection:?}"
    );
}

#[tokio::test]
async fn without_a_host_the_capture_is_empty_and_only_an_empty_one_restores() {
    let data = private_tempdir();
    let sockets = console(Hooked::NeedsHost(data.path().join("state")));
    let empty = capture(sockets.path()).await;
    let parsed: Value = serde_json::from_str(&empty).unwrap();
    assert_eq!(
        (&parsed["acme"], &parsed["enrolment"]),
        (&Value::Null, &Value::Null)
    );
    assert!(inspect(sockets.path(), &empty).await.blocked.is_empty());
    let (code, body) = restore(sockets.path(), &empty).await;
    assert_eq!(code, 200, "{body}");

    let (_enrolled, enrolled_sockets) = enrolled().await;
    let full = capture(enrolled_sockets.path()).await;
    let inspection = inspect(sockets.path(), &full).await;
    assert!(
        inspection.blocked["acme"].contains("needs a host"),
        "{inspection:?}"
    );
    assert_eq!(
        inspection.warnings,
        [
            "This backup will not be restored (acme, enrolment): the broker needs a host first: \
          set host (and domains) in the app's options, then restore."
        ]
    );
    let (code, _) = restore(sockets.path(), &full).await;
    assert_eq!(code, 400);

    fs::create_dir(data.path().join("state")).unwrap();
    let (code, body) = hook(sockets.path(), "POST", "/v1/backup/capture", "").await;
    assert_eq!(
        code, 500,
        "a broker with state but no host does not hand over nothing"
    );
    assert!(body.contains("no host"), "{body}");
}

/// Measures, and pins well under, what a certificate costs a capture: the console caps it at 7 MiB.
#[tokio::test]
async fn a_capture_costs_little_per_certificate_and_less_once_one_expires() {
    const CERTIFICATES: usize = 200;
    const CAP: usize = 7 << 20;
    let (mut enrolled, sockets) = enrolled().await;
    let subordinate = pem::encode(pem::CERTIFICATE, &enrolled.chain[0]);
    let base = capture(sockets.path()).await.len();
    let leaves: Vec<String> = (0..CERTIFICATES)
        .map(|n| {
            let leaf = enrolled.ca.client(&format!("host-{n}.home.example"));
            pem::encode(pem::CERTIFICATE, &leaf.chain[0]) + &subordinate
        })
        .collect();
    let store = enrolled.running.broker.acme();
    let live = SystemTime::now() + Duration::from_secs(30 * 86_400);
    for (n, chain) in leaves.iter().enumerate() {
        record_chain(
            store,
            &format!("{}", 1000 + n),
            &format!("host-{n}.home.example"),
            chain,
            live,
        )
        .await;
    }
    let live_size = capture(sockets.path()).await.len();
    let expired = SystemTime::now() - Duration::from_secs(86_400);
    for (n, chain) in leaves.iter().enumerate() {
        let name = format!("old-{n}.home.example");
        record_chain(store, &format!("{}", 5000 + n), &name, chain, expired).await;
    }
    let both_size = capture(sockets.path()).await.len();

    let per_live = (live_size - base) / CERTIFICATES;
    let per_expired = (both_size - live_size) / CERTIFICATES;
    eprintln!(
        "capture: {base} B empty; {per_live} B per live certificate, {per_expired} B per expired \
         one; the cap is reached at about {} live certificates",
        (CAP - base) / per_live
    );
    assert!(per_live < 2048, "{per_live} B per live certificate");
    assert!(
        per_expired < per_live * 2 / 3,
        "{per_expired} B per expired certificate"
    );
}
