use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use opca_acme_broker::{Broker, CONFIG_PATH, Config, Error};
use wslib_http_server::{Bounds, Listener};
use wslib_pairing::{SpentBy, Status};

fn main() -> ExitCode {
    let path = match config_path() {
        Ok(path) => path,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    wslib_service::Daemon::new("opca-acme-broker")
        .run(|stop| async move {
            wslib_telemetry::Telemetry::new("info").init();
            let config = Config::load(&path)?;
            let listen = config.listen;
            let (broker, uri) =
                tokio::task::spawn_blocking(move || Broker::start(&config)).await??;
            match (uri, broker.code_status()?) {
                (Some(uri), _) => tracing::info!("pairing URI: {}", uri.expose()),
                (None, Status::Pending { remaining, .. }) => tracing::info!(
                    remaining,
                    "awaiting pairing with the code issued earlier; its URI was logged then"
                ),
                (None, Status::Spent(SpentBy::Lockout)) => {
                    tracing::warn!("the pairing code is locked out by wrong attempts")
                }
                (None, _) => {}
            }
            let listener = Listener::bind(listen, Bounds::SERVING)
                .await
                .map_err(|e| format!("listening on {listen}: {e}"))?;
            opca_acme_broker::serve(Arc::new(broker), listener, stop).await?;
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
