//! The page's files as the chassis serves them on `app.sock`: the index with its base, gzipped assets, and the page's own routes.

#![cfg(unix)]

mod support;

use std::fs;
use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use opca_acme_broker::app::{APP_SOCKET, Hooked};
use support::{console_app, private_tempdir, serve_console};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const INDEX: &str = r#"<html><head><base href="/"></head></html>"#;
const BASED: &str = r#"<html><head><base href="/apps/opca-acme/"></head></html>"#;
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
async fn console(ui: &Path) -> TempDir {
    let data = private_tempdir();
    let mut app = console_app(data.path(), &[]);
    app.ui = ui.into();
    serve_console(app, Hooked::NeedsHost(data.path().join("state"))).await
}

fn built() -> TempDir {
    let ui = private_tempdir();
    fs::create_dir(ui.path().join("assets")).unwrap();
    fs::write(ui.path().join("index.html"), INDEX).unwrap();
    fs::write(ui.path().join("assets/page.js"), SCRIPT).unwrap();
    fs::write(ui.path().join("assets/page.js.gz"), gzipped(SCRIPT)).unwrap();
    fs::write(ui.path().join("assets/logo.svg"), "<svg/>").unwrap();
    ui
}

#[tokio::test]
async fn the_index_names_the_apps_base_to_anyone() {
    let ui = built();
    let sockets = console(ui.path()).await;

    for path in ["/apps/opca-acme", "/apps/opca-acme/"] {
        let page = get(sockets.path(), path, &[]).await;
        assert_eq!((page.status, page.text()), (200, BASED), "{path}");
        assert!(
            page.header("content-type")
                .unwrap()
                .starts_with("text/html")
        );
    }
}

#[tokio::test]
async fn a_gzipped_asset_is_sent_as_it_is_to_a_client_that_takes_gzip() {
    let ui = built();
    let sockets = console(ui.path()).await;
    let path = "/apps/opca-acme/assets/page.js";

    let taken = get(sockets.path(), path, &["accept-encoding: br, gzip"]).await;
    assert_eq!(taken.status, 200);
    assert_eq!(taken.header("content-encoding"), Some("gzip"));
    assert_eq!(taken.body, gzipped(SCRIPT));
    assert!(
        taken
            .header("content-type")
            .unwrap()
            .starts_with("text/javascript")
    );

    for refusing in [None, Some("accept-encoding: gzip;q=0")] {
        let headers: Vec<_> = refusing.into_iter().collect();
        let plain = get(sockets.path(), path, &headers).await;
        assert_eq!(plain.header("content-encoding"), None, "{refusing:?}");
        assert_eq!(plain.text(), SCRIPT);
    }
}

#[tokio::test]
async fn a_route_of_the_pages_is_its_index_and_a_missing_file_or_endpoint_is_404() {
    let ui = built();
    let sockets = console(ui.path()).await;

    let routed = get(sockets.path(), "/apps/opca-acme/issued/recent", &[]).await;
    assert_eq!((routed.status, routed.text()), (200, BASED));
    for missing in ["assets/gone.js", "api/nothing"] {
        let path = format!("/apps/opca-acme/{missing}");
        assert_eq!(
            get(sockets.path(), &path, &[]).await.status,
            404,
            "{missing}"
        );
    }
}

#[tokio::test]
async fn with_no_page_installed_health_still_answers() {
    let sockets = console(&private_tempdir().path().join("nowhere")).await;

    let index = get(sockets.path(), "/apps/opca-acme/", &[]).await;
    assert_eq!(index.status, 404);
    let health = get(sockets.path(), "/apps/opca-acme/healthz", &[]).await;
    assert_eq!(health.status, 200);
}
