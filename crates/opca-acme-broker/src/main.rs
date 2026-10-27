use std::path::PathBuf;
use std::process::ExitCode;

use opca_acme_broker::{Broker, CONFIG_PATH, Config, Error};
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
            stop.await;
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
