use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{info, warn};
use opca_core::op::{Op, ShellRunner};
use opca_core::services::ca::CertificateAuthority;
use opca_core::vault_lock::VaultLock;

use crate::commands::dto::LogEntry;

/// Connection state: holds the `Op` handle and, once loaded, the `CertificateAuthority`.
///
/// Both fields are guarded by a single mutex on `AppState` so that
/// connect/disconnect transitions are atomic with respect to in-flight
/// operations — preventing stale-vault races.
pub struct Connection {
    pub op: Option<Op>,
    pub ca: Option<CertificateAuthority<ShellRunner>>,
}

/// Shared application state managed by Tauri.
///
/// The `conn` mutex serialises all 1Password access, mirroring the Python
/// `@work(exclusive=True, group="op")` pattern.
pub struct AppState {
    pub conn: Mutex<Connection>,
    pub vault_lock: Mutex<VaultLock>,
    pub action_log: Mutex<Vec<LogEntry>>,
}

impl AppState {
    /// Ensure the CA is loaded, lazily retrieving it from 1Password on first call.
    ///
    /// Returns a `MutexGuard<Connection>` so the caller holds the lock for the
    /// duration of the operation.  If `ca` is already populated the guard is
    /// returned immediately; otherwise `Op` is consumed to retrieve the CA.
    pub fn ensure_ca(&self) -> Result<MutexGuard<'_, Connection>, String> {
        let mut conn = self.conn.lock().expect("mutex poisoned — a prior operation panicked");

        if conn.ca.is_none() {
            let op = conn.op.take()
                .ok_or("Not connected")?;

            info!("[tauri] loading CA from 1Password");
            let ca = CertificateAuthority::retrieve(op)
                .map_err(|e| {
                    warn!("[tauri] failed to load CA: {e}");
                    self.log_err("retrieve_ca", Some(e.to_string()));
                    e.to_string()
                })?;
            self.log_ok("retrieve_ca", Some("CA loaded from 1Password".to_string()));
            conn.ca = Some(ca);
        }

        Ok(conn)
    }

    /// Run a closure with a reference to the connected `Op`.
    ///
    /// Checks `ca.op` first (if CA is loaded), then falls back to raw `op`.
    pub fn with_op<F, T>(&self, f: F) -> Result<T, String>
    where
        F: FnOnce(&Op) -> Result<T, String>,
    {
        let conn = self.conn.lock().expect("mutex poisoned — a prior operation panicked");
        if let Some(ref ca) = conn.ca {
            return f(&ca.op);
        }
        let op = conn.op.as_ref().ok_or("Not connected")?;
        f(op)
    }
}

impl AppState {
    /// Append an entry to the in-memory action log.
    pub fn log_action(&self, action: &str, detail: Option<String>, success: bool) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let entry = LogEntry {
            timestamp: secs,
            action: action.to_string(),
            detail,
            success,
        };
        self.action_log.lock().expect("mutex poisoned — a prior operation panicked").push(entry);
    }

    /// Convenience: log a successful action.
    pub fn log_ok(&self, action: &str, detail: impl Into<Option<String>>) {
        self.log_action(action, detail.into(), true);
    }

    /// Convenience: log a failed action.
    pub fn log_err(&self, action: &str, detail: impl Into<Option<String>>) {
        self.log_action(action, detail.into(), false);
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            conn: Mutex::new(Connection { op: None, ca: None }),
            vault_lock: Mutex::new(VaultLock::new(None)),
            action_log: Mutex::new(Vec::new()),
        }
    }
}
