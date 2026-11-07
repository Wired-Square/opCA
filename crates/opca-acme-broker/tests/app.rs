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
    ACME_PORT, API_PORT, APP_SOCKET, App, AppState, AppStatus, CONSOLE_UID, HOOKS_SOCKET, Hooked,
    PKI_PORT,
};
use support::{LOOPBACK, console_app, private_tempdir, serve_console};
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
    let ports = |app: &App| (app.api_port, app.acme_port, app.pki_port);
    assert_eq!(ports(&app), (API_PORT, ACME_PORT, PKI_PORT));

    let app = load(
        data.path(),
        &[
            ("APPLIANCE_LISTENER_API_PORT", "19443"),
            ("APPLIANCE_LISTENER_ACME_PORT", "443"),
            ("APPLIANCE_LISTENER_PKI_PORT", "80"),
        ],
    );
    assert_eq!(ports(&app), (19443, 443, 80));

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
fn the_console_is_root_unless_named() {
    let data = private_tempdir();
    assert_eq!(load(data.path(), &[]).console_uid, CONSOLE_UID);
    let named = load(data.path(), &[("APPLIANCE_CONSOLE_UID", "4242")]);
    assert_eq!(named.console_uid, 4242);
    for uid in ["root", "-1"] {
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

const VIEWER: &str = "v1; id=a1; user=someone; role=viewer";

/// One HTTP/1.1 request on `stream`, as the console asserting `identity`; its status line and body.
async fn exchange(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    path: &str,
    identity: Option<&str>,
) -> (String, String) {
    let asserted = identity.map_or(String::new(), |who| {
        format!("Appliance-Identity: {who}\r\n")
    });
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{asserted}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.lines().next().unwrap().into(), body.into())
}

async fn socket_answer(socket: &Path, path: &str, identity: Option<&str>) -> (String, String) {
    for _ in 0..100 {
        if let Ok(stream) = UnixStream::connect(socket).await {
            return exchange(stream, path, identity).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing answered on {}", socket.display());
}

#[tokio::test]
async fn app_sock_answers_healthz_only_under_the_apps_base() {
    let data = private_tempdir();
    let sockets = serve_console(
        console_app(data.path(), &[]),
        Hooked::NeedsHost(data.path().join("state")),
    )
    .await;
    let socket = sockets.path().join(APP_SOCKET);

    let (status, _) = socket_answer(&socket, "/apps/opca-acme/healthz", None).await;
    assert!(status.ends_with("200 OK"), "{status}");
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
    let (status, _) = socket_answer(&socket, "/healthz", None).await;
    assert!(status.ends_with("404 Not Found"), "{status}");
}

#[tokio::test]
async fn a_socket_left_by_an_earlier_run_is_replaced() {
    let (data, sockets) = (private_tempdir(), private_tempdir());
    drop(std::os::unix::net::UnixListener::bind(sockets.path().join(APP_SOCKET)).unwrap());
    let path = sockets.path().to_owned();
    tokio::spawn(async move {
        let hooked = Hooked::NeedsHost(data.path().join("state"));
        let logs = wslib_appliance_server::logs(&[]);
        let app = console_app(data.path(), &[]);
        app.serve_console(&path, hooked, logs, std::future::pending())
            .await
            .unwrap()
    });

    let socket = sockets.path().join(APP_SOCKET);
    let (status, _) = socket_answer(&socket, "/apps/opca-acme/healthz", None).await;
    assert!(status.ends_with("200 OK"), "{status}");
}

#[tokio::test]
async fn a_peer_that_isnt_the_console_is_nobody_on_app_sock_and_hung_up_on_hooks_sock() {
    let data = private_tempdir();
    let mut app = console_app(data.path(), &[]);
    app.console_uid += 1;
    let hooked = Hooked::NeedsHost(data.path().join("state"));
    let sockets = serve_console(app, hooked).await;

    let app_sock = sockets.path().join(APP_SOCKET);
    let (status, _) = socket_answer(&app_sock, "/apps/opca-acme/api/status", Some(VIEWER)).await;
    assert!(status.ends_with("401 Unauthorized"), "{status}");

    let mut stream = UnixStream::connect(sockets.path().join(HOOKS_SOCKET))
        .await
        .unwrap();
    let _ = stream
        .write_all(b"GET /v1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await;
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer));
    let _ = read.await.expect("hung up, not left waiting");
    assert!(answer.is_empty(), "hooks.sock answered a foreign uid");
}

#[tokio::test]
async fn the_overflow_uid_is_refused_as_the_console() {
    let (data, sockets) = (private_tempdir(), private_tempdir());
    let mut app = console_app(data.path(), &[]);
    app.console_uid = 65534;
    let hooked = Hooked::NeedsHost(data.path().join("state"));
    let logs = wslib_appliance_server::logs(&[]);
    let refused = app
        .serve_console(sockets.path(), hooked, logs, std::future::pending())
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("overflow"), "{refused}");
}

#[tokio::test]
async fn without_a_host_it_is_healthy_and_refuses_on_every_listener() {
    let (data, sockets) = (private_tempdir(), private_tempdir());
    let socket = sockets.path().join(APP_SOCKET);
    let app = console_app(data.path(), &[("APPLIANCE_LISTENER_ACME_PORT", "443")]);
    let bind = || Listener::bind(format!("{LOOPBACK}:0").parse().unwrap(), Bounds::SERVING);
    let listeners = [
        bind().await.unwrap(),
        bind().await.unwrap(),
        bind().await.unwrap(),
    ];
    let addresses = listeners.each_ref().map(Listener::local_addr);
    let stop = CancellationToken::new();
    let served = tokio::spawn({
        let (sockets, stop) = (sockets.path().to_owned(), stop.clone());
        let logs = wslib_appliance_server::logs(&[]);
        async move {
            app.serve_needing_host(&sockets, logs, listeners, stop)
                .await
        }
    });

    let (status, _) = socket_answer(&socket, "/apps/opca-acme/healthz", None).await;
    assert!(status.ends_with("200 OK"), "{status}");
    let (_, body) = socket_answer(&socket, "/apps/opca-acme/api/status", Some(VIEWER)).await;
    let status: AppStatus = serde_json::from_str(&body).unwrap();
    assert_eq!(status.state, AppState::NeedsHost);
    for (address, path) in addresses
        .into_iter()
        .zip(["/v1/enrolment", "/acme/directory", "/crl"])
    {
        let stream = TcpStream::connect(address).await.unwrap();
        let (status, body) = exchange(stream, path, None).await;
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
