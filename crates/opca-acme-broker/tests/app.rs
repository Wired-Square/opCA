//! The broker as an ApplianceOS app: where its host comes from, the ports it
//! names, its sockets to the console alone, and health and refusal while it has no host.

#![cfg(unix)]

mod support;

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use opca_acme_broker::Broker;
use opca_acme_broker::app::{
    ACME_PORT, API_PORT, APP_SOCKET, App, AppState, CONSOLE_UID, HOOKS_SOCKET, Health, Hooked,
};
use support::{LOOPBACK, console_app, private_tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio_util::sync::CancellationToken;
use wslib_http_server::{Bounds, Listener};

fn load(data: &Path, env: &[(&str, &str)]) -> App {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    App::load(data, |name| env.get(name).cloned()).unwrap()
}

#[test]
fn options_come_before_the_apps_own_config() {
    let data = private_tempdir();
    fs::write(
        data.path().join("options.json"),
        r#"{"host": "acme.home.example", "domains": ["home.example"]}"#,
    )
    .unwrap();
    fs::write(
        data.path().join("broker.toml"),
        "host = \"own.lab.example\"\ndomains = [\"lab.example\"]\n",
    )
    .unwrap();
    let app = load(data.path(), &[]);
    assert_eq!(app.host.as_deref(), Some("acme.home.example"));
    assert_eq!(app.domains, ["home.example"]);
}

#[test]
fn a_blank_or_missing_option_gives_way_to_the_apps_own_config() {
    let data = private_tempdir();
    fs::write(
        data.path().join("options.json"),
        r#"{"host": " ", "domains": []}"#,
    )
    .unwrap();
    fs::write(
        data.path().join("broker.toml"),
        "host = \"own.lab.example\"\ndomains = [\"lab.example\"]\n",
    )
    .unwrap();
    let app = load(data.path(), &[]);
    assert_eq!(app.host.as_deref(), Some("own.lab.example"));
    assert_eq!(app.domains, ["lab.example"]);

    fs::write(data.path().join("options.json"), "{}").unwrap();
    assert_eq!(load(data.path(), &[]), app);
}

#[test]
fn with_no_host_anywhere_there_is_no_config_and_no_state() {
    let data = private_tempdir();
    let app = load(data.path(), &[]);
    assert_eq!((app.host.as_ref(), app.domains.len()), (None, 0));
    assert_eq!(app.config().unwrap(), None);
    assert_eq!(fs::read_dir(data.path()).unwrap().count(), 0);
}

#[test]
fn the_console_ports_are_named_when_given_else_the_manifests() {
    let data = private_tempdir();
    let app = load(data.path(), &[]);
    assert_eq!((app.api_port, app.acme_port), (API_PORT, ACME_PORT));

    let app = load(
        data.path(),
        &[
            ("APPLIANCE_LISTENER_API_PORT", "19443"),
            ("APPLIANCE_LISTENER_ACME_PORT", "443"),
        ],
    );
    assert_eq!((app.api_port, app.acme_port), (19443, 443));

    let refused = App::load(data.path(), |name| {
        (name == "APPLIANCE_LISTENER_API_PORT").then(|| "port".into())
    });
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("APPLIANCE_LISTENER_API_PORT")
    );
}

#[test]
fn the_console_is_root_unless_named_and_never_the_overflow_uid() {
    let data = private_tempdir();
    assert_eq!(load(data.path(), &[]).console_uid, CONSOLE_UID);
    let named = load(data.path(), &[("APPLIANCE_CONSOLE_UID", "4242")]);
    assert_eq!(named.console_uid, 4242);
    for uid in ["65534", "root", "-1"] {
        let refused = App::load(data.path(), |name| {
            (name == "APPLIANCE_CONSOLE_UID").then(|| uid.into())
        });
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .contains("APPLIANCE_CONSOLE_UID"),
            "{uid}"
        );
    }
}

#[test]
fn an_unreadable_option_file_is_refused() {
    let data = private_tempdir();
    fs::write(data.path().join("options.json"), r#"{"host": 5}"#).unwrap();
    let refused = App::load(data.path(), |_| None).unwrap_err().to_string();
    assert!(refused.contains("options.json"), "{refused}");
}

#[tokio::test]
async fn the_config_listens_on_the_manifest_ports_and_pairs_on_the_consoles() {
    let data = private_tempdir();
    fs::write(
        data.path().join("options.json"),
        r#"{"host": "acme.home.example"}"#,
    )
    .unwrap();
    let app = load(data.path(), &[("APPLIANCE_LISTENER_API_PORT", "19443")]);
    let config = app.config().unwrap().unwrap();
    assert_eq!(
        (config.listen.port(), config.acme_listen.port()),
        (API_PORT, ACME_PORT)
    );
    let state = data.path().join("state");
    assert_eq!(config.state_dir, state);
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let (broker, uri) = Broker::start(&config).await.unwrap();
    assert_eq!(uri.unwrap().port(), 19443);
    assert_eq!(AppState::from(&broker.mode()), AppState::Enrolling);
}

/// One HTTP/1.1 request on `stream`; its status line and body.
async fn exchange(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    path: &str,
) -> (String, String) {
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.lines().next().unwrap().into(), body.into())
}

async fn socket_answer(socket: &Path, path: &str) -> (String, String) {
    for _ in 0..100 {
        if let Ok(stream) = UnixStream::connect(socket).await {
            return exchange(stream, path).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing answered on {}", socket.display());
}

#[tokio::test]
async fn app_sock_answers_healthz_only_under_the_apps_base() {
    let (data, sockets) = (private_tempdir(), private_tempdir());
    let socket = sockets.path().join(APP_SOCKET);
    fs::write(&socket, "a stale socket").unwrap();
    let stop = CancellationToken::new();
    let served = console_app(data.path(), &[])
        .serve_console(
            sockets.path(),
            Hooked::NeedsHost(data.path().join("state")),
            stop.clone(),
        )
        .unwrap();

    let (status, body) = socket_answer(&socket, "/apps/opca-acme/healthz").await;
    assert!(status.ends_with("200 OK"), "{status}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"state": "needs_host", "api_port": API_PORT, "acme_port": ACME_PORT})
    );
    for socket in [APP_SOCKET, HOOKS_SOCKET] {
        let mode = fs::metadata(sockets.path().join(socket))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o660,
            "the console connects through the group"
        );
    }
    let (status, _) = socket_answer(&socket, "/healthz").await;
    assert!(status.ends_with("404 Not Found"), "{status}");

    stop.cancel();
    served.await.unwrap().unwrap();
}

#[tokio::test]
async fn both_sockets_hang_up_on_a_peer_that_isnt_the_console() {
    let (data, sockets) = (private_tempdir(), private_tempdir());
    let mut app = console_app(data.path(), &[]);
    app.console_uid += 1;
    let stop = CancellationToken::new();
    let served = app
        .serve_console(
            sockets.path(),
            Hooked::NeedsHost(data.path().join("state")),
            stop.clone(),
        )
        .unwrap();

    for (socket, path) in [
        (APP_SOCKET, "/apps/opca-acme/healthz"),
        (HOOKS_SOCKET, "/v1"),
    ] {
        let mut stream = UnixStream::connect(sockets.path().join(socket))
            .await
            .unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let _ = stream.write_all(request.as_bytes()).await;
        let mut answer = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer));
        let _ = read.await.expect("hung up, not left waiting");
        assert!(answer.is_empty(), "{socket} answered a foreign uid");
    }

    stop.cancel();
    served.await.unwrap().unwrap();
}

#[tokio::test]
async fn without_a_host_it_is_healthy_and_refuses_on_both_listeners() {
    let (data, sockets) = (private_tempdir(), private_tempdir());
    let socket = sockets.path().join(APP_SOCKET);
    let app = console_app(data.path(), &[("APPLIANCE_LISTENER_ACME_PORT", "443")]);
    let bind = || Listener::bind(format!("{LOOPBACK}:0").parse().unwrap(), Bounds::SERVING);
    let (api, acme) = (bind().await.unwrap(), bind().await.unwrap());
    let addresses = [api.local_addr(), acme.local_addr()];
    let stop = CancellationToken::new();
    let served = tokio::spawn({
        let (sockets, stop) = (sockets.path().to_owned(), stop.clone());
        async move { app.serve_needing_host(&sockets, api, acme, stop).await }
    });

    let (status, body) = socket_answer(&socket, "/apps/opca-acme/healthz").await;
    assert!(status.ends_with("200 OK"), "{status}");
    let health: Health = serde_json::from_str(&body).unwrap();
    assert_eq!(
        health,
        Health {
            state: AppState::NeedsHost,
            api_port: API_PORT,
            acme_port: 443,
        }
    );
    for (address, path) in addresses
        .into_iter()
        .zip(["/v1/enrolment", "/acme/directory"])
    {
        let (status, body) = exchange(TcpStream::connect(address).await.unwrap(), path).await;
        assert!(status.ends_with("503 Service Unavailable"), "{status}");
        assert!(body.contains("needs a host"), "{body}");
    }
    assert_eq!(fs::read_dir(data.path()).unwrap().count(), 0, "no state");
    assert!(sockets.path().join(HOOKS_SOCKET).exists());

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(15), served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
