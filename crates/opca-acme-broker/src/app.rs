//! The broker as an ApplianceOS app: its host and domains from the data
//! volume, the host ports the console maps, and its page and hooks, the backup
//! among them, on the chassis's `app.sock` and `hooks.sock`.

use std::fmt::Display;
use std::fs::DirBuilder;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRef, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use wslib_appliance_config::{ApplianceArgs, Bootstrap, Resolver};
use wslib_appliance_server::{AppSocket, ApplianceState, BackupHooks, Logs, Server};
use wslib_appliance_store::Store;
use wslib_appliance_types::Branding;
use wslib_appliance_types::backup::{MAX_BUNDLE_LEN, RestoreReport};
use wslib_appliance_types::hooks::{AppInspection, AppRestore};
use wslib_http_server::{Listener, serve_http};

use crate::api::reply;
use crate::backup::{Capture, both_blocked, capture_left, failed, warned_of_blocked};
use crate::enrolment::bad_request;
use crate::{Broker, Config, Error, Mode};

mod api;

pub use api::{AppStatus, IssuedNewest, Issuer, NewPairing, PublishedCrl};

pub const NAME: &str = "opca-acme";
pub const DATA: &str = "/data";
/// Where the console reaches the app, at `app.sock` and `hooks.sock`.
pub const SOCKETS: &str = "/run/appliance";
pub const APP_SOCKET: &str = "app.sock";
pub const HOOKS_SOCKET: &str = "hooks.sock";
/// The listeners' ports inside the container, as the manifest declares them.
pub const API_PORT: u16 = 9443;
pub const ACME_PORT: u16 = 8443;
pub const PKI_PORT: u16 = 8080;
/// Where the image holds the page's files.
pub const UI: &str = "/usr/share/opca-acme/ui";
/// The console's uid inside the container: Docker runs rootful, with no userns-remap (ApplianceOS D63).
pub const CONSOLE_UID: u32 = 0;
/// What the about hook and the page's masthead name.
const PRODUCT: &str = "opCA ACME broker";

const NEEDS_HOST: &str = "the broker needs a host: set the app's host option";
const NEEDS_HOST_TO_RESTORE: &str = "the broker needs a host first: set host (and domains) in \
                                     the app's options, then restore";

/// The settings the console's options and the app's own config can give.
#[derive(Default, Deserialize)]
struct Chosen {
    host: Option<String>,
    domains: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    /// `None` until the operator sets one.
    pub host: Option<String>,
    pub domains: Vec<String>,
    pub data: PathBuf,
    /// The host ports opCA and ACME clients dial.
    pub api_port: u16,
    pub acme_port: u16,
    /// The host port the leaves' CRL and CA certificate URLs name.
    pub pki_port: u16,
    /// The uid the chassis hears as the console.
    pub console_uid: u32,
    /// The page's files.
    pub ui: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppState {
    NeedsHost,
    Enrolling,
    Enrolled,
    Paused,
    Revoked,
}

impl From<&Mode> for AppState {
    fn from(mode: &Mode) -> Self {
        match mode {
            Mode::Enrolling => Self::Enrolling,
            Mode::Enrolled(enrolled) if enrolled.revoked => Self::Revoked,
            Mode::Enrolled(enrolled) if enrolled.paused => Self::Paused,
            Mode::Enrolled(_) => Self::Enrolled,
        }
    }
}

impl App {
    /// `data`'s `options.json` first and its `broker.toml` second, a blank
    /// value giving way to the next; `env` gives `APPLIANCE_LISTENER_*_PORT`
    /// and `APPLIANCE_CONSOLE_UID`.
    pub fn load(data: &Path, env: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let options: Chosen = read(&data.join("options.json"), |text| {
            serde_json::from_str(text)
        })?;
        let own: Chosen = read(&data.join("broker.toml"), |text| toml::from_str(text))?;
        Ok(Self {
            host: [options.host, own.host]
                .into_iter()
                .flatten()
                .find(|host| !host.trim().is_empty()),
            domains: [options.domains, own.domains]
                .into_iter()
                .flatten()
                .find(|domains| !domains.is_empty())
                .unwrap_or_default(),
            data: data.into(),
            api_port: variable(&env, "APPLIANCE_LISTENER_API_PORT", API_PORT)?,
            acme_port: variable(&env, "APPLIANCE_LISTENER_ACME_PORT", ACME_PORT)?,
            pki_port: variable(&env, "APPLIANCE_LISTENER_PKI_PORT", PKI_PORT)?,
            console_uid: variable(&env, "APPLIANCE_CONSOLE_UID", CONSOLE_UID)?,
            ui: UI.into(),
        })
    }

    /// The broker's config once a host is set, making its state directory in the data volume.
    pub fn config(&self) -> Result<Option<Config>, Error> {
        let Some(host) = &self.host else {
            return Ok(None);
        };
        let state_dir = self.data.join("state");
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&state_dir)?;
        Ok(Some(Config {
            host: host.clone(),
            listen: any(API_PORT),
            domains: self.domains.clone(),
            state_dir,
            acme_listen: any(ACME_PORT),
            advertised_port: Some(self.api_port),
            pki_listen: any(PKI_PORT),
            pki_port: Some(self.pki_port),
        }))
    }

    /// Healthy in `sockets` with no host set, refusing every request on each listener, until `stop`.
    pub async fn serve_needing_host(
        &self,
        sockets: &Path,
        logs: Logs,
        [api, acme, pki]: [Listener; 3],
        stop: CancellationToken,
    ) -> Result<(), Error> {
        tracing::warn!("{NEEDS_HOST}; answering only the page and the hooks until then");
        let refuse =
            Router::new().fallback(|| async { (StatusCode::SERVICE_UNAVAILABLE, NEEDS_HOST) });
        let hooked = Hooked::NeedsHost(self.data.join("state"));
        let refusing = |listener, stop: CancellationToken| {
            let refuse = refuse.clone();
            async move { Ok(serve_http(listener, refuse, stop.cancelled_owned()).await?) }
        };
        tokio::try_join!(
            self.serve_console(sockets, hooked, logs, stop.clone().cancelled_owned()),
            refusing(acme, stop.clone()),
            refusing(pki, stop.clone()),
            refusing(api, stop),
        )?;
        Ok(())
    }

    /// The page and its API on `sockets`' `app.sock`, and the hooks on its
    /// `hooks.sock`, both bound before `stop` is first polled, until `stop`.
    pub async fn serve_console(
        &self,
        sockets: &Path,
        hooked: Hooked,
        logs: Logs,
        stop: impl Future<Output = ()>,
    ) -> Result<(), Error> {
        let _ = rustls_openssl::default_provider().install_default();
        let mut branding = Branding::unbranded();
        branding.app_name = PRODUCT.into();
        let server = Server::new(
            Store::open_in_memory(None).await?,
            branding,
            env!("CARGO_PKG_VERSION"),
            logs,
        );
        let socket = AppSocket::new(sockets.join(APP_SOCKET), self.console_uid)
            .hooks(sockets.join(HOOKS_SOCKET));
        server
            .ui(Some(self.ui.clone()))
            .api(api::routes(self, &hooked))
            .backup_hooks(hooks(hooked))
            .serve(&bootstrap()?, socket, stop)
            .await?;
        Ok(())
    }
}

/// The chassis's settings: only the base path matters behind the console, and the broker resolves the rest itself.
fn bootstrap() -> Result<Bootstrap, Error> {
    let args = ApplianceArgs {
        base_path: Some(format!("/apps/{NAME}/").parse()?),
        ..ApplianceArgs::default()
    };
    Ok(Resolver::new(NAME, "OPCA_ACME").resolve(&args)?)
}

/// What the hooks and the page answer for: a running broker, or the state directory of one that needs a host.
#[derive(Clone)]
pub enum Hooked {
    Running(Arc<Broker>),
    NeedsHost(PathBuf),
}

#[derive(Clone)]
struct Hooks {
    appliance: ApplianceState,
    hooked: Hooked,
    one_at_a_time: Arc<Mutex<()>>,
}

impl FromRef<Hooks> for ApplianceState {
    fn from_ref(hooks: &Hooks) -> Self {
        hooks.appliance.clone()
    }
}

/// The backup hooks (ApplianceOS D62), one call at a time.
fn hooks(hooked: Hooked) -> BackupHooks {
    let one_at_a_time = Arc::default();
    let routes = Router::new()
        .route("/capture", post(capture))
        .route("/inspect", post(inspect))
        .route("/restore", post(restore))
        .layer(DefaultBodyLimit::max(MAX_BUNDLE_LEN));
    BackupHooks::routes(routes, move |appliance| Hooks {
        appliance,
        hooked: hooked.clone(),
        one_at_a_time: Arc::clone(&one_at_a_time),
    })
}

async fn capture(State(hooks): State<Hooks>) -> Response {
    let _turn = hooks.one_at_a_time.lock().await;
    reply(match &hooks.hooked {
        Hooked::Running(broker) => broker.capture().await.map_err(failed),
        Hooked::NeedsHost(state) => capture_left(state).await.map_err(failed),
    })
}

async fn inspect(State(hooks): State<Hooks>, body: Bytes) -> Response {
    let blob = match serde_json::from_slice(&body) {
        Ok(blob) => blob,
        Err(e) => return reply::<()>(Err(bad_request(e))),
    };
    let _turn = hooks.one_at_a_time.lock().await;
    let inspected = match &hooks.hooked {
        Hooked::Running(broker) => broker.inspect(blob).await,
        Hooked::NeedsHost(_) => Ok(inspected_needing_host(blob)),
    };
    reply(inspected.map(warned_of_blocked))
}

async fn restore(State(hooks): State<Hooks>, body: Bytes) -> Response {
    let body: AppRestore<Value> = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(e) => return reply::<()>(Err(bad_request(e))),
    };
    let turn = hooks.one_at_a_time.clone().lock_owned().await;
    reply(match hooks.hooked {
        // Spawned, so a console that stops waiting does not cut it off partway.
        Hooked::Running(broker) => tokio::spawn(async move {
            let _turn = turn;
            broker.restore(body).await
        })
        .await
        .unwrap_or_else(|panicked| Err(failed(panicked))),
        Hooked::NeedsHost(_) if inspected_needing_host(body.sections).blocked.is_empty() => {
            Ok(RestoreReport::default())
        }
        Hooked::NeedsHost(_) => Err(bad_request(NEEDS_HOST_TO_RESTORE)),
    })
}

/// Nothing to restore, or everything blocked until there is a host.
fn inspected_needing_host(blob: Value) -> AppInspection {
    let mut inspection = AppInspection::default();
    match Capture::read(blob) {
        Err(why) => inspection.blocked = both_blocked(&why),
        Ok(Capture {
            acme: None,
            enrolment: None,
            ..
        }) => {}
        Ok(_) => inspection.blocked = both_blocked(NEEDS_HOST_TO_RESTORE),
    }
    inspection
}

/// `port` on every address.
pub fn any(port: u16) -> SocketAddr {
    (Ipv6Addr::UNSPECIFIED, port).into()
}

/// The environment variable `name` parsed, or `default` when it isn't set.
fn variable<T: FromStr<Err: Display>>(
    env: impl Fn(&str) -> Option<String>,
    name: &str,
    default: T,
) -> Result<T, Error> {
    env(name).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|e| format!("{name}={value}: {e}").into())
    })
}

/// `path` parsed, or the default when it isn't there.
fn read<T: Default + DeserializeOwned, E: std::error::Error + Send + Sync + 'static>(
    path: &Path,
    parse: impl FnOnce(&str) -> Result<T, E>,
) -> Result<T, Error> {
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display()).into()),
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display()).into()),
    }
}
