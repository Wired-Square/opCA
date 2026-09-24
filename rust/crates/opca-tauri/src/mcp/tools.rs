use wiredai_mcp::rmcp;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::CallToolResult;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::json;
use tauri::{AppHandle, Manager};
use wiredai_mcp::result::{ok_json, tool_error};
use wiredai_mcp::router::mark_read_only;
use wiredai_mcp::server::ServerIdentity;

use crate::commands::cert::cert_items;
use crate::state::AppState;

#[derive(Clone)]
pub struct OpcaTools {
    pub app: AppHandle,
}

impl OpcaTools {
    pub fn router() -> ToolRouter<Self> {
        let mut router = Self::read_router();
        mark_read_only(&mut router);
        router
    }

    pub fn identity() -> ServerIdentity {
        ServerIdentity::new("opca", env!("CARGO_PKG_VERSION"))
            .with_title("opCA (dev)")
            .with_instructions(
                "Development-build harness for the opCA desktop app. App tools read state the \
                 app already holds and never call 1Password; every change goes through the UI.",
            )
    }

    fn state(&self) -> tauri::State<'_, AppState> {
        self.app.state::<AppState>()
    }
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
