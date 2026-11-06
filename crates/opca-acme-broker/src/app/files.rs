//! The page's files under `/apps/opca-acme/`, read whole from the image when the sockets bind.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{self, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use flate2::read::GzDecoder;

use super::NAME;
use super::api::Viewer;

const INDEX: &str = "index.html";
/// As `index.html` is built, before [`base_href`] rewrites it.
const BUILT_BASE: &str = r#"<base href="/apps/opca-acme/""#;

/// Each file by its path from the root, with `/` between segments.
#[derive(Default)]
struct Files(HashMap<String, Bytes>);

pub(super) fn routes(root: &Path) -> io::Result<Router> {
    let files = Arc::new(Files::read(root)?);
    if !files.0.contains_key(INDEX) {
        tracing::warn!(root = %root.display(), "no {INDEX} to serve: the page is not installed");
    }
    Ok(Router::new()
        .route(&format!("/apps/{NAME}"), get(to_index))
        .route(&format!("/apps/{NAME}/"), get(index))
        .route(&format!("/apps/{NAME}/{{*path}}"), get(file))
        .with_state(files))
}

impl Files {
    /// Every file below `root`, or none when there is no `root`.
    fn read(root: &Path) -> io::Result<Self> {
        let mut files = Self::default();
        match files.add(root, "") {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            added => added.map(|()| files),
        }
    }

    fn add(&mut self, dir: &Path, prefix: &str) -> io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|name| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{name:?} isn't UTF-8"))
            })?;
            let path = format!("{prefix}{name}");
            if entry.file_type()?.is_dir() {
                self.add(&entry.path(), &format!("{path}/"))?;
            } else {
                self.0.insert(path, std::fs::read(entry.path())?.into());
            }
        }
        Ok(())
    }

    /// `path`'s bytes, or its `.gz`'s, gzipped only when `gzip` allows; and whether they are.
    fn get(&self, path: &str, gzip: bool) -> Option<(Bytes, bool)> {
        if let Some(plain) = self.0.get(path) {
            return Some((plain.clone(), false));
        }
        let gzipped = self.0.get(&format!("{path}.gz"))?;
        if gzip {
            return Some((gzipped.clone(), true));
        }
        let mut plain = Vec::new();
        GzDecoder::new(&gzipped[..]).read_to_end(&mut plain).ok()?;
        Some((plain.into(), false))
    }
}

async fn to_index(_: Viewer, headers: HeaderMap) -> Redirect {
    Redirect::permanent(&format!("{}/", prefix(&headers)))
}

async fn index(State(files): State<Arc<Files>>, _: Viewer, headers: HeaderMap) -> Response {
    let Some((page, _)) = files.get(INDEX, false) else {
        return (StatusCode::NOT_FOUND, "the page is not installed").into_response();
    };
    let page = String::from_utf8_lossy(&page).replacen(BUILT_BASE, &base_href(&headers), 1);
    sent(INDEX, page.into(), false)
}

async fn file(
    State(files): State<Arc<Files>>,
    viewer: Viewer,
    extract::Path(path): extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let gzip = accepts_gzip(&headers);
    match files.get(&path, gzip) {
        Some((body, gzipped)) => sent(&path, body, gzipped),
        // A route of the page's own, which it reads from the location; a missing asset is a 404.
        None if !path.rsplit('/').next().unwrap_or_default().contains('.') => {
            index(State(files), viewer, headers).await
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn sent(path: &str, body: Bytes, gzipped: bool) -> Response {
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let mut response = (
        [
            (header::CONTENT_TYPE, content_type(path)),
            (header::CACHE_CONTROL, cache),
            (header::VARY, "accept-encoding"),
        ],
        body,
    )
        .into_response();
    if gzipped {
        response
            .headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    response
}

/// The `<base href>` for where the console mounts the page (ApplianceOS D122).
fn base_href(headers: &HeaderMap) -> String {
    format!(r#"<base href="{}/""#, prefix(headers))
}

/// `X-Forwarded-Prefix` when it is a plain absolute path, else the app's own base.
fn prefix(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-prefix")
        .and_then(|value| value.to_str().ok())
        .map(|prefix| prefix.trim_end_matches('/'))
        .filter(|prefix| {
            prefix
                .strip_prefix('/')
                .is_some_and(|path| path.split('/').all(plain_segment))
        })
        .map_or_else(|| format!("/apps/{NAME}"), str::to_owned)
}

fn plain_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|coding| {
            let mut parts = coding.split(';').map(str::trim);
            parts.next() == Some("gzip") && parts.all(|param| param.replace(' ', "") != "q=0")
        })
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
