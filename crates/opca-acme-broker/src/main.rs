use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use opca_acme_broker::{Broker, CONFIG_PATH, Config, Error, Mode};
use wslib_http_server::{Bounds, Listener};
use wslib_pairing::{SpentBy, Status};

/// The listener's 10 s drain, then step-ca's stop.
const STEP_CA_PATIENCE: Duration = Duration::from_secs(5);
const GRACE: Duration = Duration::from_secs(20);

fn main() -> ExitCode {
    let path = match config_path() {
        Ok(path) => path,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    wslib_service::Daemon::new("opca-acme-broker")
        .grace(GRACE)
        .run(|stop| async move {
            wslib_telemetry::Telemetry::new("info").init();
            let config = Config::load(&path)?;
            let listen = config.listen;
            let (broker, uri) =
                tokio::task::spawn_blocking(move || Broker::start(&config)).await??;
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
            broker.start_issuing();
            let served = opca_acme_broker::serve(broker.clone(), listener, stop).await;
            broker.stop_issuing(STEP_CA_PATIENCE).await;
            served?;
            Ok::<_, Error>(())
        })
        .map_or_else(ExitCode::from, |()| ExitCode::SUCCESS)
}

fn config_path() -> Result<PathBuf, &'static str> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (None, ..) => Ok(CONFIG_PATH.into()),
        (Some(flag), Some(path), None) if flag == "--config" => Ok(path.into()),
        _ => Err("usage: opca-acme-broker [--config <path>]"),
    }
}
