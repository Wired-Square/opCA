mod tools;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use log::{info, warn};
use tauri::{AppHandle, Manager};
use wiredai_mcp::CancellationToken;
use wiredai_mcp::http::{self, HttpConfig};
use wiredai_mcp::server::ToolServer;

use tools::OpcaTools;

const DEFAULT_PORT: u16 = 8790;

pub fn start(app: AppHandle) {
    if let Err(e) = try_start(app) {
        warn!("[mcp] not started: {e}");
    }
}

fn try_start(app: AppHandle) -> Result<(), String> {
    let port = std::env::var("OPCA_MCP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let token = std::env::var("OPCA_MCP_TOKEN").unwrap_or_else(|_| random_token());
    let listener = http::bind_with_retry(SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(2))
        .map_err(|e| e.to_string())?;

    let url = format!("http://127.0.0.1:{port}/mcp");
    let handoff = app.path().app_data_dir().map_err(|e| e.to_string())?.join("mcp.json");
    write_handoff(&handoff, &serde_json::json!({ "url": url, "token": token }))?;

    let router = Arc::new(OpcaTools::router());
    let identity = OpcaTools::identity();
    let config = HttpConfig {
        bearer_token: Some(token),
        allowed_origins: http::loopback_origins(port),
        ..HttpConfig::default()
    };
    let factory = move || ToolServer::new(OpcaTools { app: app.clone() }, router.clone(), identity.clone());
    tauri::async_runtime::spawn(async move {
        if let Err(e) = http::serve(listener, factory, config, CancellationToken::new()).await {
            warn!("[mcp] server stopped: {e}");
        }
    });
    info!("[mcp] dev server on {url}; token in {}", handoff.display());
    Ok(())
}

fn random_token() -> String {
    rand::random::<[u8; 24]>().iter().map(|b| format!("{b:02x}")).collect()
}

fn write_handoff(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .and_then(|mut f| f.write_all(value.to_string().as_bytes()))
        .map_err(|e| format!("{}: {e}", path.display()))
}
