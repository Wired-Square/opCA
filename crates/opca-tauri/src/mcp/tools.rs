use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{ErrorData, tool, tool_router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tauri::{AppHandle, LogicalSize, Manager, Wry};
use wslib_mcp::dom::{self, BRIDGE_TIMEOUT, DomBridge};
use wslib_mcp::result::{ok_json, tool_error};
use wslib_mcp::rmcp;
use wslib_mcp::router::mark_read_only;
use wslib_mcp::server::ServerIdentity;
use wslib_mcp::tauri_bridge::TauriBridge;

use crate::commands::cert::cert_items;
use crate::state::AppState;

#[derive(Clone)]
pub struct OpcaTools {
    pub app: AppHandle,
    pub page: TauriBridge<Wry>,
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
        match self.page.request(op, args, BRIDGE_TIMEOUT).await {
            Ok(value) => ok_json(value),
            Err(e) => Ok(tool_error(e)),
        }
    }
}

impl DomBridge for OpcaTools {
    async fn call(&self, op: &str, args: Value, timeout: Duration) -> Result<Value, String> {
        self.page.call(op, args, timeout).await
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct NavigateParams {
    /// App route, e.g. `/certs`.
    path: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ThemeMode {
    System,
    Dark,
    Light,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct ThemeParams {
    mode: ThemeMode,
}

#[derive(Deserialize, JsonSchema)]
struct SizeParams {
    /// Inner width in logical pixels.
    width: f64,
    /// Inner height in logical pixels.
    height: f64,
}

#[tool_router(router = read_router)]
impl OpcaTools {
    #[tool(
        description = "Connection state: the 1Password account and vault, and whether the CA is loaded."
    )]
    async fn app_status(&self) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let conn = state.conn.lock().expect("mutex poisoned");
        let vault = conn.ca.as_ref().map(|ca| &ca.vault).or(conn.vault.as_ref());
        ok_json(json!({
            "connected": vault.is_some(),
            "account": vault.and_then(|vault| vault.op().account()),
            "vault": vault.map(|vault| &vault.info().name),
            "ca_loaded": conn.ca.is_some(),
        }))
    }

    #[tool(
        description = "Certificates in the loaded CA's local database, as the Certs page lists them. Fails if the CA is not loaded yet."
    )]
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
    async fn navigate(
        &self,
        Parameters(p): Parameters<NavigateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.relay("navigate", p).await
    }

    #[tool(description = "Switch the app theme.")]
    async fn set_theme(
        &self,
        Parameters(p): Parameters<ThemeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.relay("set_theme", p).await
    }

    #[tool(description = "Resize the main window's content area.")]
    async fn resize_window(
        &self,
        Parameters(p): Parameters<SizeParams>,
    ) -> Result<CallToolResult, ErrorData> {
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
            .map(|t| {
                (
                    t.name.to_string(),
                    t.annotations.and_then(|a| a.read_only_hint) == Some(true),
                )
            })
            .collect();
        assert_eq!(
            read_only,
            [
                ("app_status", true),
                ("click", false),
                ("console", true),
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
}
