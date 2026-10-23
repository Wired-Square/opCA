use opca_core::error::OpcaError;
use opca_core::op::{self, Runner, ShellRunner, Vault};
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::local_backup::{age_phrase, BackupSource, LocalBackup};
use opca_core::vault_lock::VaultLock;

/// CLI application context.
///
/// Mirrors the Tauri `AppState` pattern: the vault moves into
/// `CertificateAuthority` when the CA is loaded, so `op()` checks
/// `ca.op` first, then falls back to the standalone vault.
pub struct AppContext<R: Runner> {
    standalone_op: Option<Vault<R>>,
    pub ca: Option<CertificateAuthority<R>>,
    pub vault_lock: VaultLock,
}

impl AppContext<ShellRunner> {
    /// Create a new context by connecting to 1Password.
    pub fn new(vault: &str, account: Option<String>) -> Result<Self, OpcaError> {
        let op = op::connect(ShellRunner::new(), vault, account.as_deref())?;
        Ok(Self {
            standalone_op: Some(op),
            ca: None,
            vault_lock: VaultLock::new(None),
        })
    }
}

impl<R: Runner> AppContext<R> {
    /// The connected vault, whether it is held standalone or inside the
    /// `CertificateAuthority`.
    pub fn op(&self) -> Result<&Vault<R>, OpcaError> {
        match &self.ca {
            Some(ca) => Ok(&ca.op),
            None => self
                .standalone_op
                .as_ref()
                .ok_or_else(|| OpcaError::Other("Not connected".into())),
        }
    }

    /// Ensure the CA is loaded, lazily retrieving from 1Password.
    pub fn ensure_ca(&mut self) -> Result<(), OpcaError> {
        if self.ca.is_some() {
            return Ok(());
        }
        let op = self
            .standalone_op
            .take()
            .ok_or_else(|| OpcaError::Other("Not connected".into()))?;
        let source = BackupSource::of(&op);
        let account = op.op().account().map(String::from);
        match CertificateAuthority::retrieve(op) {
            Ok(mut ca) => {
                ca.local_backup = LocalBackup::if_enabled(ca.op.op().account());
                self.ca = Some(ca);
                Ok(())
            }
            Err(OpcaError::DatabaseUnreadable(msg)) => {
                Err(OpcaError::DatabaseUnreadable(format!("{msg}. {}", backup_hint(account.as_deref(), &source))))
            }
            Err(e) => Err(e),
        }
    }

    /// Take the standalone vault out of the context (consumes it).
    /// Used by init-like commands that need to pass it to a CA constructor.
    pub fn take_op(&mut self) -> Result<Vault<R>, OpcaError> {
        self.standalone_op
            .take()
            .ok_or_else(|| OpcaError::Other("Not connected".into()))
    }

    /// Acquire the vault lock for a mutating operation.
    pub fn lock(&mut self, operation: &str) -> Result<(), OpcaError> {
        let vault = match &self.ca {
            Some(ca) => &ca.op,
            None => self.standalone_op.as_ref().ok_or_else(|| OpcaError::Other("Not connected".into()))?,
        };
        self.vault_lock.acquire(vault, operation, VaultLock::default_ttl())
    }

    /// Release the vault lock.
    pub fn unlock(&mut self) -> Result<(), OpcaError> {
        if !self.vault_lock.held() {
            return Ok(());
        }
        let vault = match &self.ca {
            Some(ca) => &ca.op,
            None => self.standalone_op.as_ref().ok_or_else(|| OpcaError::Other("Not connected".into()))?,
        };
        self.vault_lock.release(vault)
    }
}

/// Execute a closure while holding the vault lock, ensuring the lock
/// is released even if the closure returns an error.
pub fn with_lock<R, F>(app: &mut AppContext<R>, operation: &str, f: F) -> Result<(), OpcaError>
where
    R: Runner,
    F: FnOnce(&mut AppContext<R>) -> Result<(), OpcaError>,
{
    app.lock(operation)?;
    let result = f(app);
    let _ = app.unlock();
    result
}

/// Where to find a good copy when the vault's database can't be read.
fn backup_hint(account: Option<&str>, source: &BackupSource) -> String {
    let store = match LocalBackup::for_account(account) {
        Ok(store) => store,
        Err(e) => return e.to_string(),
    };
    match store.list(source).ok().and_then(|b| b.into_iter().next()) {
        Some(newest) => format!(
            "Newest local backup: {} ({}). Restore it from the opCA app, or upload it as the ca-db-export.sql file of CA_Database in 1Password",
            newest.path.display(),
            age_phrase(newest.taken_at, chrono::Utc::now()),
        ),
        None => format!("No local backups in {}", store.dir_for(source).display()),
    }
}
