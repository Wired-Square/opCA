//! The page's files on `app.sock`: the index with its base, gzipped assets, and the page's own routes.

#![cfg(unix)]

mod support;

use std::fs;
use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use opca_acme_broker::app::{APP_SOCKET, Hooked};
use support::{console_app, private_tempdir};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

const VIEWER: &str = "appliance-identity: v1; id=a1; user=someone; role=viewer";
const INDEX: &str = r#"<html><head><base href="/apps/opca-acme/" /></head></html>"#;
const SCRIPT: &str = "console.log('the page')";

struct Answer {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(": ")?;
            key.eq_ignore_ascii_case(name).then_some(value)
        })
    }

    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }
}

async fn get(sockets: &Path, path: &str, headers: &[&str]) -> Answer {
    let mut stream = UnixStream::connect(sockets.join(APP_SOCKET)).await.unwrap();
    let headers: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    Answer {
        status: head[9..12].parse().unwrap(),
        head,
        body: response[split + 4..].to_vec(),
    }
}

fn gzipped(text: &str) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(text.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

/// The sockets, serving the files in `ui`.
fn console(ui: &Path) -> TempDir {
    let (data, sockets) = (private_tempdir(), private_tempdir());
    let mut app = console_app(data.path(), &[]);
    app.ui = ui.into();
    let served = app
        .serve_console(
            sockets.path(),
            Hooked::NeedsHost(data.path().join("state")),
            CancellationToken::new(),
        )
        .unwrap();
    tokio::spawn(served);
    sockets
}

fn built() -> TempDir {
    let ui = private_tempdir();
    fs::create_dir(ui.path().join("assets")).unwrap();
    fs::write(ui.path().join("index.html"), INDEX).unwrap();
    fs::write(ui.path().join("assets/page.js.gz"), gzipped(SCRIPT)).unwrap();
    fs::write(ui.path().join("assets/logo.svg"), "<svg/>").unwrap();
    ui
}

#[tokio::test]
async fn the_index_takes_its_base_from_the_consoles_prefix() {
    let ui = built();
    let sockets = console(ui.path());

    let page = get(sockets.path(), "/apps/opca-acme/", &[VIEWER]).await;
    assert_eq!(page.status, 200);
    assert_eq!(
        page.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(page.header("cache-control"), Some("no-cache"));
    assert_eq!(page.text(), INDEX);

    let moved = [VIEWER, "x-forwarded-prefix: /apps/renamed/"];
    let page = get(sockets.path(), "/apps/opca-acme/", &moved).await;
    assert!(
        page.text().contains(r#"<base href="/apps/renamed/" />"#),
        "{}",
        page.text()
    );

    for prefix in [r#"/apps/x"><script>"#, "apps/relative", "/apps/../up", "/"] {
        let header = format!("x-forwarded-prefix: {prefix}");
        let page = get(sockets.path(), "/apps/opca-acme/", &[VIEWER, &header]).await;
        assert_eq!(page.text(), INDEX, "{prefix}");
    }

    let bare = get(sockets.path(), "/apps/opca-acme", &moved).await;
    assert_eq!(
        (bare.status, bare.header("location")),
        (308, Some("/apps/renamed/"))
    );
}

#[tokio::test]
async fn a_gzipped_asset_is_sent_as_it_is_to_a_client_that_takes_gzip() {
    let ui = built();
    let sockets = console(ui.path());
    let path = "/apps/opca-acme/assets/page.js";

    let taken = get(sockets.path(), path, &[VIEWER, "accept-encoding: br, gzip"]).await;
    assert_eq!(taken.status, 200);
    assert_eq!(taken.header("content-encoding"), Some("gzip"));
    assert_eq!(taken.body, gzipped(SCRIPT));
    assert_eq!(
        taken.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(
        taken.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );

    for refusing in [None, Some("accept-encoding: gzip;q=0")] {
        let headers: Vec<_> = [VIEWER].into_iter().chain(refusing).collect();
        let plain = get(sockets.path(), path, &headers).await;
        assert_eq!(plain.header("content-encoding"), None, "{refusing:?}");
        assert_eq!(plain.text(), SCRIPT);
    }

    let svg = get(sockets.path(), "/apps/opca-acme/assets/logo.svg", &[VIEWER]).await;
    assert_eq!(
        (svg.header("content-type"), svg.text()),
        (Some("image/svg+xml"), "<svg/>")
    );
}

#[tokio::test]
async fn a_route_of_the_pages_is_its_index_and_a_missing_file_is_404() {
    let ui = built();
    let sockets = console(ui.path());

    let routed = get(sockets.path(), "/apps/opca-acme/issued/recent", &[VIEWER]).await;
    assert_eq!((routed.status, routed.text()), (200, INDEX));
    for missing in ["assets/gone.js", "api/nothing", "../index.html"] {
        let answer = get(
            sockets.path(),
            &format!("/apps/opca-acme/{missing}"),
            &[VIEWER],
        )
        .await;
        assert_eq!(answer.status, 404, "{missing}");
    }
}

#[tokio::test]
async fn without_the_consoles_identity_no_file_is_sent() {
    let ui = built();
    let sockets = console(ui.path());

    for path in [
        "/apps/opca-acme",
        "/apps/opca-acme/",
        "/apps/opca-acme/assets/logo.svg",
    ] {
        let answer = get(sockets.path(), path, &["appliance-identity: v1; id=a1"]).await;
        assert_eq!(answer.status, 401, "{path}");
    }
}

#[tokio::test]
async fn with_no_page_installed_health_still_answers() {
    let sockets = console(&private_tempdir().path().join("nowhere"));

    let index = get(sockets.path(), "/apps/opca-acme/", &[VIEWER]).await;
    assert_eq!(index.status, 404);
    let health = get(sockets.path(), "/apps/opca-acme/healthz", &[]).await;
    assert_eq!(health.status, 200);
}
