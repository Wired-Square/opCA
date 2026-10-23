use std::sync::{Arc, Mutex};

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::cert::{CertBundleConfig, CertType, CertificateBundle, KeyAlgorithm};
use opca_core::services::database::{CaConfig, CertificateAuthorityDB};
use opca_core::testutil::{fake_vault, FakeRunner, Output};
use serde_json::Value;
use tauri::ipc::{CallbackFn, Invoke, InvokeBody};
use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{App, Listener, Manager, State, WebviewWindow, WebviewWindowBuilder};

use crate::commands::dto::LogEntry;
use crate::state::{AppState, Connection};

/// A mock Tauri app running the commands in `handler` (a `tauri::generate_handler![..]`)
/// against an `AppState` whose `op` is a scripted `FakeRunner`.
pub struct Harness {
    app: App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
    runner: FakeRunner,
}

pub trait Handler: Fn(Invoke<MockRuntime>) -> bool + Send + Sync + 'static {}
impl<H: Fn(Invoke<MockRuntime>) -> bool + Send + Sync + 'static> Handler for H {}

impl Harness {
    /// A loaded, empty CA whose `op` answers with `op_responses` in turn; any
    /// call past them fails.
    pub fn with_ca(op_responses: Vec<Output>, handler: impl Handler) -> Self {
        let runner = FakeRunner::new();
        Self::script(&runner, op_responses);
        let conn = Connection { ca: Some(test_ca(&runner)), ..Connection::default() };
        Self::build(conn, runner, handler)
    }

    pub fn disconnected(handler: impl Handler) -> Self {
        Self::build(Connection::default(), FakeRunner::new(), handler)
    }

    /// Answers the next `op` calls with `responses`.
    pub fn answer(&self, responses: impl IntoIterator<Item = Output>) {
        Self::script(&self.runner, responses);
    }

    /// Answers the next `n` calls with an empty success, as `op` gives for an edit or delete.
    pub fn answer_writes(&self, n: usize) {
        self.answer((0..n).map(|_| Output::ok("")));
    }

    fn script(runner: &FakeRunner, responses: impl IntoIterator<Item = Output>) {
        for response in responses {
            runner.respond(response);
        }
    }

    fn build(conn: Connection, runner: FakeRunner, handler: impl Handler) -> Self {
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
        self.runner.calls().iter().map(|c| c.args().to_vec()).filter(starts).collect()
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

fn test_ca(runner: &FakeRunner) -> CertificateAuthority<FakeRunner> {
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
        op: fake_vault(runner),
        op_config: DEFAULT_OP_CONF,
        ca_bundle: Some(ca_bundle),
        ca_database: Some(db),
        crl: None,
        local_backup: None,
    }
}
