use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use opca_acme_broker::app::{self, App, AppState};
use opca_acme_broker::{Broker, CONFIG_PATH, Config, Error, Mode, cli};
use tokio::signal::unix::{SignalKind, signal};
use wslib_http_server::{Bounds, Listener};
use wslib_pairing::{SpentBy, Status};

/// Past the listeners' 10 s drain.
const GRACE: Duration = Duration::from_secs(20);

/// How the broker was asked to run.
enum Run {
    Config(PathBuf),
    /// As an ApplianceOS app.
    App,
}

fn main() -> ExitCode {
    let run = match run() {
        Ok(run) => run,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    wslib_service::Daemon::new("opca-acme-broker")
        .grace(GRACE)
        .run(|stop| async move {
            wslib_telemetry::Telemetry::new("info").init();
            let mut reopened = signal(SignalKind::hangup())?;
            let (config, app) = match run {
                Run::Config(path) => (Config::load(&path)?, None),
                Run::App => {
                    let app = App::load(Path::new(app::DATA), |name| std::env::var(name).ok())?;
                    match app.config()? {
                        Some(config) => (config, Some(app)),
                        None => {
                            let bind = |port| Listener::bind(app::any(port), Bounds::SERVING);
                            let (api, acme) =
                                (bind(app::API_PORT).await?, bind(app::ACME_PORT).await?);
                            return app
                                .serve_needing_host(app::SOCKET.into(), api, acme, stop.token())
                                .await;
                        }
                    }
                }
            };
            let pid_file = cli::daemon_pid_file(&config.state_dir);
            let listen = config.listen;
            let (broker, uri) = Broker::start(&config).await?;
            match (uri, broker.mode(), broker.code_status()?) {
                (Some(uri), ..) => tracing::info!("pairing URI: {}", uri.expose()),
                (None, Mode::Enrolled(enrolled), _) if enrolled.revoked => {
                    tracing::warn!("revoked: answering only status and revoke")
                }
                (None, Mode::Enrolled(_), _) => {
                    tracing::info!("enrolled: requiring the operator's client certificate")
                }
                (None, _, Status::Pending { remaining, .. }) => tracing::info!(
                    remaining,
                    "awaiting pairing with the code issued earlier; its URI was logged then"
                ),
                (None, _, Status::Spent(SpentBy::Lockout)) => {
                    tracing::warn!("the pairing code is locked out by wrong attempts")
                }
                (None, ..) => {}
            }
            let listener = Listener::bind(listen, Bounds::SERVING)
                .await
                .map_err(|e| format!("listening on {listen}: {e}"))?;
            let broker = Arc::new(broker);
            wslib_file_atomic::replace_readable(
                &pid_file,
                std::process::id().to_string().as_bytes(),
            )?;
            tokio::spawn({
                let broker = broker.clone();
                async move {
                    while reopened.recv().await.is_some() {
                        if let Err(error) = broker.reload().await {
                            tracing::error!(error = %error.message, "could not reload the state");
                        }
                    }
                }
            });
            let health = app.map(|app| {
                let broker = broker.clone();
                tokio::spawn(app::serve_health(
                    app::SOCKET.into(),
                    move || app.health(AppState::from(&broker.mode())),
                    stop.token().cancelled_owned(),
                ))
            });
            let token = stop.token();
            let acme = tokio::spawn(
                broker
                    .clone()
                    .serve_acme(async move { token.cancelled().await }),
            );
            let served = opca_acme_broker::serve(broker.clone(), listener, stop).await;
            let _ = acme.await;
            if let Some(health) = health {
                health.await??;
            }
            let _ = std::fs::remove_file(&pid_file);
            served?;
            Ok::<_, Error>(())
        })
        .map_or_else(ExitCode::from, |()| ExitCode::SUCCESS)
}

fn run() -> Result<Run, &'static str> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (None, ..) => Ok(Run::Config(CONFIG_PATH.into())),
        (Some(flag), Some(path), None) if flag == "--config" => Ok(Run::Config(path.into())),
        (Some(flag), None, _) if flag == "--app" => Ok(Run::App),
        _ => Err("usage: opca-acme-broker [--config <path> | --app]"),
    }
}
