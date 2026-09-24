use std::time::Duration;

use wiredai_mcp::rmcp;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{ErrorData, tool, tool_router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, LogicalSize, Manager};
use wiredai_mcp::dom::{self, DomBridge, BRIDGE_TIMEOUT};
use wiredai_mcp::result::{ok_json, tool_error};
use wiredai_mcp::router::mark_read_only;
use wiredai_mcp::server::ServerIdentity;

use super::bridge;
use crate::commands::cert::cert_items;
use crate::state::AppState;

#[derive(Clone)]
pub struct OpcaTools {
    pub app: AppHandle,
}

impl OpcaTools {
    pub fn router() -> ToolRouter<Self> {
        let mut read = Self::read_router();
        mark_read_only(&mut read);
        read + dom::read_router() + Self::ui_router() + dom::drive_router()
    }

    pub fn identity() -> ServerIdentity {
        ServerIdentity::new("opca", env!("CARGO_PKG_VERSION"))
            .with_title("opCA (dev)")
            .with_instructions(
                "Development-build harness for the opCA desktop app. App tools read state the \
                 app already holds and never call 1Password; every change goes through the UI. \
                 UI tools drive the main window's DOM by CSS selector and need it open.",
            )
    }

    fn state(&self) -> tauri::State<'_, AppState> {
        self.app.state::<AppState>()
    }

    async fn relay(&self, op: &str, args: impl Serialize) -> Result<CallToolResult, ErrorData> {
        let args = serde_json::to_value(args).expect("tool params serialise");
        match self.call(op, args, BRIDGE_TIMEOUT).await {
            Ok(value) => ok_json(value),
            Err(e) => Ok(tool_error(e)),
        }
    }
}

impl DomBridge for OpcaTools {
    async fn call(&self, op: &str, args: Value, timeout: Duration) -> Result<Value, String> {
        bridge::request(&self.app, op, args, timeout).await
    }
}

#[derive(Deserialize, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct NavigateParams {
    /// App route, e.g. `/certs`.
    path: String,
}

#[derive(Deserialize, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
#[schemars(crate = "rmcp::schemars")]
enum ThemeMode {
    Dark,
    Light,
}

#[derive(Deserialize, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct ThemeParams {
    mode: ThemeMode,
}

#[derive(Deserialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct SizeParams {
    /// Inner width in logical pixels.
    width: f64,
    /// Inner height in logical pixels.
    height: f64,
}

#[tool_router(router = read_router)]
impl OpcaTools {
    #[tool(description = "Connection state: the 1Password account and vault, and whether the CA is loaded.")]
    async fn app_status(&self) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let conn = state.conn.lock().expect("mutex poisoned");
        let op = conn.ca.as_ref().map(|ca| &ca.op).or(conn.op.as_ref());
        ok_json(json!({
            "connected": op.is_some(),
            "account": op.and_then(|op| op.account()),
            "vault": op.map(|op| &op.vault),
            "ca_loaded": conn.ca.is_some(),
        }))
    }

    #[tool(description = "Certificates in the loaded CA's local database, as the Certs page lists them. Fails if the CA is not loaded yet.")]
    async fn list_certs(&self) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let mut conn = state.conn.lock().expect("mutex poisoned");
        if conn.ca.is_none() {
            return Ok(tool_error("CA not loaded — open it in the app first"));
        }
        match cert_items(&mut conn) {
            Ok(certs) => ok_json(json!({ "certs": certs })),
            Err(e) => Ok(tool_error(e)),
        }
    }
}

#[tool_router(router = ui_router)]
impl OpcaTools {
    #[tool(description = "Navigate the app to a route.")]
    async fn navigate(&self, Parameters(p): Parameters<NavigateParams>) -> Result<CallToolResult, ErrorData> {
        self.relay("navigate", p).await
    }

    #[tool(description = "Switch the app theme.")]
    async fn set_theme(&self, Parameters(p): Parameters<ThemeParams>) -> Result<CallToolResult, ErrorData> {
        self.relay("set_theme", p).await
    }

    #[tool(description = "Resize the main window's content area.")]
    async fn resize_window(&self, Parameters(p): Parameters<SizeParams>) -> Result<CallToolResult, ErrorData> {
        let Some(window) = self.app.get_webview_window("main") else {
            return Ok(tool_error("main window not open"));
        };
        match window.set_size(LogicalSize::new(p.width, p.height)) {
            Ok(()) => ok_json(json!({ "width": p.width, "height": p.height })),
            Err(e) => Ok(tool_error(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_read_tools_are_marked_read_only() {
        let read_only: Vec<_> = OpcaTools::router()
            .list_all()
            .into_iter()
            .map(|t| (t.name.to_string(), t.annotations.and_then(|a| a.read_only_hint) == Some(true)))
            .collect();
        assert_eq!(
            read_only,
            [
                ("app_status", true),
                ("click", false),
                ("list_certs", true),
                ("navigate", false),
                ("press", false),
                ("query", true),
                ("resize_window", false),
                ("set_theme", false),
                ("type", false),
                ("wait_for", true),
            ]
            .map(|(n, r)| (n.to_string(), r))
        );
    }

    #[test]
    fn the_vendored_dom_ops_match_the_library() {
        assert_eq!(include_str!("../../../../frontend/src/harness/domOps.ts"), dom::OPS_TS);
    }
}
