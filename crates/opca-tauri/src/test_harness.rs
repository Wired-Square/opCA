use std::sync::{Arc, Mutex};

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::op::{CommandOutput, Op};
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::cert::{CertBundleConfig, CertType, CertificateBundle, KeyAlgorithm};
use opca_core::services::database::{CaConfig, CertificateAuthorityDB};
use opca_core::testutil::MockRunner;
use serde_json::Value;
use tauri::ipc::{CallbackFn, Invoke, InvokeBody};
use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{App, Listener, Manager, State, WebviewWindow, WebviewWindowBuilder};

use crate::commands::dto::LogEntry;
use crate::state::{AppState, Connection};

/// A mock Tauri app running the commands in `handler` (a `tauri::generate_handler![..]`)
/// against an `AppState` whose `op` is a scripted `MockRunner`.
pub struct Harness {
    app: App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
    runner: MockRunner,
}

pub trait Handler: Fn(Invoke<MockRuntime>) -> bool + Send + Sync + 'static {}
impl<H: Fn(Invoke<MockRuntime>) -> bool + Send + Sync + 'static> Handler for H {}

impl Harness {
    /// A loaded, empty CA whose `op` answers with `op_responses` in turn, then empty successes.
    pub fn with_ca(op_responses: Vec<CommandOutput>, handler: impl Handler) -> Self {
        let runner = MockRunner::new(op_responses);
        let conn = Connection { ca: Some(test_ca(runner.clone())), ..Connection::default() };
        Self::build(conn, runner, handler)
    }

    pub fn disconnected(handler: impl Handler) -> Self {
        Self::build(Connection::default(), MockRunner::default(), handler)
    }

    fn build(conn: Connection, runner: MockRunner, handler: impl Handler) -> Self {
        let state = AppState::default();
        *state.conn.lock().unwrap() = conn;
        let app = mock_builder()
            .manage(state)
            .invoke_handler(handler)
            .build(mock_context(noop_assets()))
            .unwrap();
        let webview = WebviewWindowBuilder::new(&app, "main", Default::default()).build().unwrap();
        Self { app, webview, runner }
    }

    /// Invoke `cmd` over IPC as the frontend's `tauriInvoke(cmd, args)` does.
    pub fn invoke(&self, cmd: &str, args: Value) -> Result<Value, Value> {
        tauri::test::get_ipc_response(
            &self.webview,
            InvokeRequest {
                cmd: cmd.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: "tauri://localhost".parse().unwrap(),
                body: InvokeBody::Json(args),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.to_string(),
            },
        )
        .map(|body| body.deserialize().unwrap())
    }

    pub fn state(&self) -> State<'_, AppState> {
        self.app.state()
    }

    pub fn last_log(&self) -> LogEntry {
        self.state().action_log.lock().unwrap().last().cloned().unwrap()
    }

    /// The argument lists of every `op` call so far that start with `prefix`.
    pub fn op_calls(&self, prefix: &[&str]) -> Vec<Vec<String>> {
        let starts = |c: &Vec<String>| c.iter().map(String::as_str).take(prefix.len()).eq(prefix.iter().copied());
        self.runner.calls().into_iter().filter(starts).collect()
    }

    /// Collects the payload of every `event` emitted from now on.
    pub fn record_events(&self, event: &str) -> Arc<Mutex<Vec<Value>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        self.app.listen_any(event, move |e| {
            sink.lock().unwrap().push(serde_json::from_str(e.payload()).unwrap());
        });
        seen
    }
}

fn test_ca(runner: MockRunner) -> CertificateAuthority<MockRunner> {
    let config = CertBundleConfig {
        cn: Some("Test CA".into()),
        key_algorithm: Some(KeyAlgorithm::EcP256),
        next_serial: Some(1),
        ca_days: Some(3650),
        ..CertBundleConfig::default()
    };
    let mut ca_bundle = CertificateBundle::generate(CertType::Ca, "CA", config).unwrap();
    ca_bundle.self_sign_ca().unwrap();
    let db = CertificateAuthorityDB::new(&CaConfig {
        next_serial: Some(2),
        days: Some(365),
        org: Some("Test Org".into()),
        ou: Some("Test".into()),
        email: Some("ca@example.com".into()),
        city: Some("Sydney".into()),
        state: Some("NSW".into()),
        country: Some("AU".into()),
        ..CaConfig::default()
    })
    .unwrap();
    CertificateAuthority {
        op: Op::with_runner("TestVault", None, "op", runner),
        op_config: DEFAULT_OP_CONF,
        ca_bundle: Some(ca_bundle),
        ca_database: Some(db),
        crl: None,
    }
}
