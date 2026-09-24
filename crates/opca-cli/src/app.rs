use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, Op, ShellRunner};
use opca_core::services::ca::CertificateAuthority;
use opca_core::vault_lock::VaultLock;

/// CLI application context.
///
/// Mirrors the Tauri `AppState` pattern: `Op` ownership moves into
/// `CertificateAuthority` when the CA is loaded, so `op()` checks
/// `ca.op` first, then falls back to the standalone `op`.
pub struct AppContext<R: CommandRunner> {
    standalone_op: Option<Op<R>>,
    pub ca: Option<CertificateAuthority<R>>,
    pub vault_lock: VaultLock,
}

impl AppContext<ShellRunner> {
    /// Create a new context by connecting to 1Password.
    pub fn new(vault: &str, account: Option<String>) -> Result<Self, OpcaError> {
        let op = Op::new(vault, account, None)?;
        Ok(Self {
            standalone_op: Some(op),
            ca: None,
            vault_lock: VaultLock::new(None),
        })
    }
}

impl<R: CommandRunner> AppContext<R> {
    /// Get a reference to the `Op` client, whether it is held standalone
    /// or inside the `CertificateAuthority`.
    pub fn op(&self) -> Result<&Op<R>, OpcaError> {
        if let Some(ref ca) = self.ca {
            return Ok(&ca.op);
        }
        self.standalone_op
            .as_ref()
            .ok_or_else(|| OpcaError::Other("Not connected".into()))
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
        match CertificateAuthority::retrieve(op) {
            Ok(ca) => {
                self.ca = Some(ca);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Take the standalone `Op` out of the context (consumes it).
    /// Used by init-like commands that need to pass `Op` to a CA constructor.
    pub fn take_op(&mut self) -> Result<Op<R>, OpcaError> {
        self.standalone_op
            .take()
            .ok_or_else(|| OpcaError::Other("Not connected".into()))
    }

    /// Acquire the vault lock for a mutating operation.
    pub fn lock(&mut self, operation: &str) -> Result<(), OpcaError> {
        // Get a raw pointer to Op to break the borrow overlap with vault_lock.
        // This is safe because vault_lock.acquire only reads Op, and we hold
        // &mut self so no other references exist.
        let op_ref: &Op<R> = if let Some(ref ca) = self.ca {
            &ca.op
        } else {
            self.standalone_op
                .as_ref()
                .ok_or_else(|| OpcaError::Other("Not connected".into()))?
        };
        // SAFETY: op_ref is a reborrow that does not alias vault_lock.
        // The borrow checker cannot see through the disjoint fields, so we
        // use an unsafe pointer cast to convince it.
        let op_ptr: *const Op<R> = op_ref;
        unsafe { self.vault_lock.acquire(&*op_ptr, operation, VaultLock::default_ttl()) }
    }

    /// Release the vault lock.
    pub fn unlock(&mut self) -> Result<(), OpcaError> {
        if self.vault_lock.held() {
            let op_ref: &Op<R> = if let Some(ref ca) = self.ca {
                &ca.op
            } else {
                self.standalone_op
                    .as_ref()
                    .ok_or_else(|| OpcaError::Other("Not connected".into()))?
            };
            let op_ptr: *const Op<R> = op_ref;
            unsafe { self.vault_lock.release(&*op_ptr)? };
        }
        Ok(())
    }
}

/// Execute a closure while holding the vault lock, ensuring the lock
/// is released even if the closure returns an error.
pub fn with_lock<R, F>(app: &mut AppContext<R>, operation: &str, f: F) -> Result<(), OpcaError>
where
    R: CommandRunner,
    F: FnOnce(&mut AppContext<R>) -> Result<(), OpcaError>,
{
    app.lock(operation)?;
    let result = f(app);
    let _ = app.unlock();
    result
}
