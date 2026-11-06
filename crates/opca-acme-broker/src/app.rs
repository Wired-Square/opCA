//! The broker as an ApplianceOS app: its host and domains from the data
//! volume, the host ports the console maps, its health on `app.sock`, and its
//! hooks, the backup among them, on `hooks.sock`, both to the console's uid alone.

use std::fmt::Display;
use std::fs::DirBuilder;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wslib_appliance_types::backup::{MAX_BUNDLE_LEN, RestoreReport};
use wslib_appliance_types::hooks::{AppAbout, AppInspection, AppRestore, HookIndex};
use wslib_http_server::{Listener, serve_http};

use crate::api::{json, reply};
use crate::backup::{Capture, both_blocked, capture_left, failed, warned_of_blocked};
use crate::enrolment::bad_request;
use crate::{Broker, Config, Error, Mode};

mod api;
mod files;

pub use api::{AppStatus, IssuedNewest, Issuer};

pub const NAME: &str = "opca-acme";
pub const DATA: &str = "/data";
/// Where the console reaches the app, at `app.sock` and `hooks.sock`.
pub const SOCKETS: &str = "/run/appliance";
pub const APP_SOCKET: &str = "app.sock";
pub const HOOKS_SOCKET: &str = "hooks.sock";
/// The listeners' ports inside the container, as the manifest declares them.
pub const API_PORT: u16 = 9443;
pub const ACME_PORT: u16 = 8443;
/// Where the image holds the page's files.
pub const UI: &str = "/usr/share/opca-acme/ui";
/// The console's uid inside the container: Docker runs rootful, with no userns-remap (ApplianceOS D63).
pub const CONSOLE_UID: u32 = 0;
/// What every uid outside a user namespace appears as inside it, so it can't tell the console apart.
const OVERFLOW_UID: u32 = 65534;

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
    /// The only peer either socket answers.
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
    Revoked,
}

/// The healthz body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub state: AppState,
    pub api_port: u16,
    pub acme_port: u16,
}

impl From<&Mode> for AppState {
    fn from(mode: &Mode) -> Self {
        match mode {
            Mode::Enrolling => Self::Enrolling,
            Mode::Enrolled(enrolled) if enrolled.revoked => Self::Revoked,
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
        let console_uid = variable(&env, "APPLIANCE_CONSOLE_UID", CONSOLE_UID)?;
        if console_uid == OVERFLOW_UID {
            return Err(format!(
                "APPLIANCE_CONSOLE_UID={console_uid} is the overflow uid, which every process \
                 outside a user namespace appears as"
            )
            .into());
        }
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
            console_uid,
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
        }))
    }

    pub fn health(&self, state: AppState) -> Health {
        Health {
            state,
            api_port: self.api_port,
            acme_port: self.acme_port,
        }
    }

    /// Healthy in `sockets` with no host set, refusing every request on either listener, until `stop`.
    pub async fn serve_needing_host(
        &self,
        sockets: &Path,
        api: Listener,
        acme: Listener,
        stop: CancellationToken,
    ) -> Result<(), Error> {
        tracing::warn!("{NEEDS_HOST}; answering only health and the hooks until then");
        let refuse =
            Router::new().fallback(|| async { (StatusCode::SERVICE_UNAVAILABLE, NEEDS_HOST) });
        let console = self.serve_console(
            sockets,
            Hooked::NeedsHost(self.data.join("state")),
            stop.clone(),
        )?;
        let acme = tokio::spawn(serve_http(
            acme,
            refuse.clone(),
            stop.clone().cancelled_owned(),
        ));
        serve_http(api, refuse, stop.cancelled_owned()).await?;
        acme.await??;
        console.await??;
        Ok(())
    }

    /// The console's two sockets in `sockets`, until `stop`; both are bound
    /// before this returns, so the hooks answer by the time health first says healthy.
    pub fn serve_console(
        &self,
        sockets: &Path,
        hooked: Hooked,
        stop: CancellationToken,
    ) -> io::Result<JoinHandle<io::Result<()>>> {
        let hooks = ConsoleOnly::bind(&sockets.join(HOOKS_SOCKET), self.console_uid)?;
        let app = ConsoleOnly::bind(&sockets.join(APP_SOCKET), self.console_uid)?;
        let router = self.app_routes(&hooked)?;
        let hooks = tokio::spawn(serve_hooks(hooks, hooked, stop.clone().cancelled_owned()));
        let app = tokio::spawn(async move {
            axum::serve(app, router)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
        });
        Ok(tokio::spawn(async move {
            hooks.await??;
            app.await?
        }))
    }

    /// What `app.sock` answers under `/apps/opca-acme/`: `healthz`, the page's API, and its files.
    fn app_routes(&self, hooked: &Hooked) -> io::Result<Router> {
        let (app, answering) = (self.clone(), hooked.clone());
        let healthz = move || {
            let body =
                serde_json::to_vec(&app.health(answering.state())).expect("the health serialises");
            async move { ([(header::CONTENT_TYPE, "application/json")], body).into_response() }
        };
        Ok(Router::new()
            .route(&format!("/apps/{NAME}/healthz"), get(healthz))
            .merge(api::routes(self, hooked))
            .merge(files::routes(&self.ui)?))
    }
}

/// What the hooks and the page answer for: a running broker, or the state directory of one that needs a host.
#[derive(Clone)]
pub enum Hooked {
    Running(Arc<Broker>),
    NeedsHost(PathBuf),
}

impl Hooked {
    fn state(&self) -> AppState {
        match self {
            Self::Running(broker) => AppState::from(&broker.mode()),
            Self::NeedsHost(_) => AppState::NeedsHost,
        }
    }
}

/// `app.sock` or `hooks.sock`: a connection from any uid but the console's is
/// closed unanswered (ApplianceOS D62).
struct ConsoleOnly {
    listener: UnixListener,
    console_uid: u32,
}

impl ConsoleOnly {
    /// Binds `socket`, replacing a stale one.
    fn bind(socket: &Path, console_uid: u32) -> io::Result<Self> {
        match std::fs::remove_file(socket) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            removed => removed?,
        }
        let listener = UnixListener::bind(socket)?;
        // The console connects as group root without DAC override, so it needs the group's write bit.
        std::fs::set_permissions(socket, PermissionsExt::from_mode(0o660))?;
        Ok(Self {
            listener,
            console_uid,
        })
    }
}

impl axum::serve::Listener for ConsoleOnly {
    type Io = UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = axum::serve::Listener::accept(&mut self.listener).await;
            match stream.peer_cred() {
                Ok(peer) if peer.uid() == self.console_uid => return (stream, address),
                Ok(peer) => {
                    tracing::warn!(uid = peer.uid(), "refused a peer that isn't the console")
                }
                Err(error) => tracing::warn!(%error, "refused a peer whose uid can't be read"),
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[derive(Clone)]
struct Hooks {
    hooked: Hooked,
    one_at_a_time: Arc<Mutex<()>>,
}

/// The console's hooks (ApplianceOS D62) on `listener`, until `stop`: the index, About, and the backup.
async fn serve_hooks(
    listener: ConsoleOnly,
    hooked: Hooked,
    stop: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let index = || async {
        let mut index = HookIndex::default();
        index.backup = true;
        json(StatusCode::OK, &index)
    };
    let about = || async {
        let mut about = AppAbout::default();
        about.product = "opCA ACME broker".into();
        about.version = env!("CARGO_PKG_VERSION").into();
        json(StatusCode::OK, &about)
    };
    let hooks = Hooks {
        hooked,
        one_at_a_time: Arc::default(),
    };
    let router = Router::new()
        .route("/v1", get(index))
        .route("/v1/about", get(about))
        .route("/v1/backup/capture", post(capture))
        .route("/v1/backup/inspect", post(inspect))
        .route("/v1/backup/restore", post(restore))
        .layer(DefaultBodyLimit::max(MAX_BUNDLE_LEN))
        .with_state(hooks);
    axum::serve(listener, router)
        .with_graceful_shutdown(stop)
        .await
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
