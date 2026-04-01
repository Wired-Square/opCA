//! Thin wrapper around the 1Password CLI (`op`).
//!
//! Mirrors the Python `Op` class in `python/src/opca/services/one_password.py`.
//!
//! The [`CommandRunner`] trait allows unit tests to inject a mock runner,
//! while production code uses [`ShellRunner`] (the default).

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use log::{debug, error, warn};
use serde::Deserialize;

use crate::constants::OP_BIN;
use crate::error::OpcaError;

/// Maximum time (in seconds) to wait for an `op` CLI command to complete.
const OP_TIMEOUT_SECS: u64 = 30;

// ------------------------------------------------------------------
// CommandRunner abstraction
// ------------------------------------------------------------------

/// Outcome of a CLI invocation, capturing stdout and stderr.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

/// Trait abstracting how `op` commands are executed.
///
/// The default [`ShellRunner`] shells out via `std::process::Command`.
/// Tests substitute a mock runner to avoid real CLI calls.
pub trait CommandRunner {
    fn run(
        &self,
        bin: &str,
        args: &[&str],
        input: Option<&str>,
        env_vars: Option<&HashMap<String, String>>,
    ) -> Result<CommandOutput, OpcaError>;
}

/// Default runner — shells out to the real `op` binary.
pub struct ShellRunner;

impl CommandRunner for ShellRunner {
    fn run(
        &self,
        bin: &str,
        args: &[&str],
        input: Option<&str>,
        env_vars: Option<&HashMap<String, String>>,
    ) -> Result<CommandOutput, OpcaError> {
        let redacted: Vec<&str> = args
            .iter()
            .map(|a| {
                if a.contains("PRIVATE KEY") {
                    "[REDACTED]"
                } else {
                    a
                }
            })
            .collect();
        debug!("[op] running: {} {}", bin, redacted.join(" "));

        let mut cmd = Command::new(bin);
        cmd.args(args);

        if let Some(vars) = env_vars {
            for (k, v) in vars {
                cmd.env(k, v);
            }
        }

        if input.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                OpcaError::CliNotFound
            } else {
                OpcaError::Io(e.to_string())
            }
        })?;

        if let Some(text) = input {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes()).ok();
                drop(stdin); // Close stdin so `op` sees EOF
            }
        }

        let timeout = Duration::from_secs(OP_TIMEOUT_SECS);
        let start = Instant::now();

        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        error!("[op] command timed out after {}s: {} {}", OP_TIMEOUT_SECS, bin, redacted.join(" "));
                        return Err(OpcaError::Io(format!(
                            "op command timed out after {}s",
                            OP_TIMEOUT_SECS
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(OpcaError::from(e)),
            }
        }

        let output = child.wait_with_output().map_err(OpcaError::from)?;

        let result = CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
        };

        if result.success {
            debug!("[op] command succeeded in {:.1}s", start.elapsed().as_secs_f64());
        } else {
            error!("[op] command failed (exit {:?}): {} {}", output.status.code(), bin, redacted.join(" "));
            if !result.stderr.is_empty() {
                error!("[op] stderr: {}", result.stderr.trim());
            }
        }

        Ok(result)
    }
}

// ------------------------------------------------------------------
// Data types
// ------------------------------------------------------------------

/// 1Password vault metadata returned by `op vault list`.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
}

/// Action to take when storing an item or document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreAction {
    /// Check if item exists, then create or edit accordingly.
    Auto,
    /// Always create a new item.
    Create,
    /// Always edit an existing item.
    Edit,
}

// ------------------------------------------------------------------
// Op struct
// ------------------------------------------------------------------

/// Thin wrapper that shells out to the `op` CLI binary.
pub struct Op<R: CommandRunner = ShellRunner> {
    bin: String,
    pub vault: String,
    pub account: Option<String>,
    runner: R,
}

impl<R: CommandRunner> std::fmt::Debug for Op<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Op")
            .field("bin", &self.bin)
            .field("vault", &self.vault)
            .field("account", &self.account)
            .finish()
    }
}

impl Op<ShellRunner> {
    /// Create a new `Op` instance, verifying authentication and vault access.
    ///
    /// This mirrors the Python `Op.__init__` flow:
    /// 1. Resolve the `op` binary on `$PATH`.
    /// 2. Ensure the user is signed in (`op whoami`).
    /// 3. Ensure the requested vault exists and is accessible.
    pub fn new(
        vault: impl Into<String>,
        account: Option<String>,
        bin: Option<String>,
    ) -> Result<Self, OpcaError> {
        let bin_name = bin.unwrap_or_else(|| OP_BIN.to_string());

        let resolved = which::which(&bin_name)
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|_| OpcaError::CliNotFound)?;

        let mut op = Self {
            bin: resolved,
            vault: vault.into().trim().to_string(),
            account,
            runner: ShellRunner,
        };

        op.ensure_signed_in()?;
        op.ensure_vault_exists()?;

        Ok(op)
    }
}

impl<R: CommandRunner> Op<R> {
    /// Create an `Op` with a custom [`CommandRunner`] (for testing).
    ///
    /// Skips signin and vault validation — the caller is responsible for
    /// providing a runner that returns appropriate responses.
    #[cfg(test)]
    pub fn with_runner(
        vault: impl Into<String>,
        account: Option<String>,
        bin: impl Into<String>,
        runner: R,
    ) -> Self {
        Self {
            bin: bin.into(),
            vault: vault.into(),
            account,
            runner,
        }
    }

    /// Access the underlying command runner.
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// The 1Password account shorthand (if set).
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Return `["--account", acct]` when an account is configured.
    fn account_args(&self) -> Vec<String> {
        match &self.account {
            Some(acct) => vec!["--account".to_string(), acct.clone()],
            None => vec![],
        }
    }

    /// Run a command via the runner.
    fn run_command(&self, args: &[&str], input: Option<&str>) -> Result<CommandOutput, OpcaError> {
        self.runner.run(&self.bin, args, input, None)
    }

    /// Run a command with optional environment variables.
    fn run_command_env(
        &self,
        args: &[&str],
        input: Option<&str>,
        env_vars: Option<&HashMap<String, String>>,
    ) -> Result<CommandOutput, OpcaError> {
        self.runner.run(&self.bin, args, input, env_vars)
    }

    /// Run a command and map non-zero exit codes to `OpcaError`.
    fn checked(&self, args: &[&str], input: Option<&str>) -> Result<CommandOutput, OpcaError> {
        let mut full_args: Vec<&str> = args.to_vec();
        let acct = self.account_args();
        let acct_refs: Vec<&str> = acct.iter().map(|s| s.as_str()).collect();
        full_args.extend_from_slice(&acct_refs);

        let out = self.run_command(&full_args, input)?;
        if out.success {
            return Ok(out);
        }
        Err(map_cli_error(&out))
    }

    /// Ensure the user is signed in to 1Password.
    ///
    /// Mirrors the Python flow: try `op whoami`, and if that fails attempt
    /// `op signin` (which triggers biometric/system auth on macOS) then
    /// retry `op whoami` once.
    fn ensure_signed_in(&self) -> Result<(), OpcaError> {
        let mut args = vec!["whoami"];
        let acct = self.account_args();
        let acct_refs: Vec<&str> = acct.iter().map(|s| s.as_str()).collect();
        args.extend_from_slice(&acct_refs);

        let out = self.run_command(&args, None)?;
        if out.success {
            return Ok(());
        }

        // Attempt a signin (triggers biometric/system auth prompt).
        warn!("[op] not signed in, attempting op signin…");
        self.attempt_signin()?;

        // Retry whoami after signin.
        let retry = self.run_command(&args, None)?;
        if retry.success {
            return Ok(());
        }

        Err(OpcaError::AuthenticationFailed)
    }

    /// Attempt `op signin`, which triggers biometric or system
    /// authentication when configured.
    fn attempt_signin(&self) -> Result<(), OpcaError> {
        let mut args = vec!["signin"];
        let acct = self.account_args();
        let acct_refs: Vec<&str> = acct.iter().map(|s| s.as_str()).collect();
        args.extend_from_slice(&acct_refs);

        let out = self.run_command(&args, None)?;
        if out.success {
            return Ok(());
        }

        Err(OpcaError::AuthenticationFailed)
    }

    /// Ensure the configured vault exists and is accessible.
    fn ensure_vault_exists(&mut self) -> Result<(), OpcaError> {
        if self.vault.is_empty() {
            return Err(OpcaError::VaultNotFound(
                "No 1Password vault configured.".to_string(),
            ));
        }

        let vault = self.vault.clone();
        let mut args: Vec<&str> = vec!["vault", "get", &vault];
        let acct = self.account_args();
        let acct_refs: Vec<&str> = acct.iter().map(|s| s.as_str()).collect();
        args.extend_from_slice(&acct_refs);

        let out = self.run_command(&args, None)?;
        if out.success {
            return Ok(());
        }

        // Fall back to a descriptive default if map_cli_error returns generic.
        let err = map_cli_error(&out);
        match &err {
            OpcaError::CliError(_) => Err(OpcaError::VaultNotFound(format!(
                "1Password vault {:?} not found.",
                self.vault
            ))),
            _ => Err(err),
        }
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Check whether an item exists in the vault (non-failing).
    pub fn item_exists(&self, item_title: &str) -> bool {
        let vault_flag = format!("--vault={}", self.vault);
        let args_owned = self.account_args();
        let mut args: Vec<&str> = vec!["item", "get", item_title, &vault_flag, "--format=json"];
        let acct_refs: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
        args.extend_from_slice(&acct_refs);

        match self.run_command(&args, None) {
            Ok(out) => out.success,
            Err(_) => false,
        }
    }

    /// Retrieve an item from 1Password.
    pub fn get_item(&self, item_title: &str, output_format: &str) -> Result<String, OpcaError> {
        let vault_flag = format!("--vault={}", self.vault);
        let format_flag = format!("--format={}", output_format);
        let out = self.checked(&["item", "get", item_title, &vault_flag, &format_flag], None)?;
        Ok(out.stdout)
    }

    /// Retrieve the contents of a document from 1Password.
    pub fn get_document(&self, item_title: &str) -> Result<String, OpcaError> {
        let vault_flag = format!("--vault={}", self.vault);
        let out = self.checked(&["document", "get", item_title, &vault_flag], None)?;
        Ok(out.stdout)
    }

    /// Return the number of items in the vault (all categories).
    pub fn vault_item_count(&self) -> Result<usize, OpcaError> {
        let json = self.item_list("", "json")?;
        let items: Vec<serde_json::Value> = serde_json::from_str(&json)
            .map_err(|e| OpcaError::CliError(format!("failed to parse vault item list: {e}")))?;
        Ok(items.len())
    }

    /// List items in the vault filtered by category.
    pub fn item_list(&self, categories: &str, output_format: &str) -> Result<String, OpcaError> {
        let vault_flag = format!("--vault={}", self.vault);
        let cat_flag = format!("--categories={}", categories);
        let format_flag = format!("--format={}", output_format);
        let out = self.checked(
            &["item", "list", &vault_flag, &cat_flag, &format_flag],
            None,
        )?;
        Ok(out.stdout)
    }

    /// Delete an item from 1Password (archived by default).
    pub fn delete_item(&self, item_title: &str, archive: bool) -> Result<String, OpcaError> {
        let vault_flag = format!("--vault={}", self.vault);
        let mut args = vec!["item", "delete", item_title, &vault_flag];
        if archive {
            args.push("--archive");
        }
        let out = self.checked(&args, None)?;
        Ok(out.stdout)
    }

    /// Rename an item in 1Password.
    pub fn rename_item(&self, src_title: &str, dst_title: &str) -> Result<String, OpcaError> {
        let vault_flag = format!("--vault={}", self.vault);
        let out = self.checked(
            &["item", "edit", src_title, "--title", dst_title, &vault_flag],
            None,
        )?;
        Ok(out.stdout)
    }

    /// Read an item at a 1Password secret reference URL.
    pub fn read_item(&self, url: &str) -> Result<String, OpcaError> {
        let out = self.checked(&["read", url], None)?;
        Ok(out.stdout)
    }

    /// Fill a template using `op inject`.
    pub fn inject_item(
        &self,
        template: &str,
        env_vars: Option<&HashMap<String, String>>,
    ) -> Result<String, OpcaError> {
        let acct = self.account_args();
        let mut args: Vec<&str> = vec!["inject"];
        let acct_refs: Vec<&str> = acct.iter().map(|s| s.as_str()).collect();
        args.extend_from_slice(&acct_refs);

        let out = self.run_command_env(&args, Some(template), env_vars)?;
        if !out.success {
            return Err(map_cli_error(&out));
        }
        Ok(out.stdout)
    }

    /// Store an item in 1Password.
    ///
    /// Mirrors the Python `store_item` method with auto/create/edit logic.
    pub fn store_item(
        &self,
        item_title: &str,
        attributes: Option<&[&str]>,
        action: StoreAction,
        category: &str,
        input: Option<&str>,
        vault: Option<&str>,
    ) -> Result<String, OpcaError> {
        let (op_action, title_arg) = self.resolve_store_action(item_title, action)?;

        let op_vault = vault.unwrap_or(&self.vault);
        let vault_flag = format!("--vault={}", op_vault);
        let mut args = vec!["item", op_action, &title_arg, &vault_flag];

        let cat_flag;
        if op_action == "create" {
            cat_flag = format!("--category={}", category);
            args.push(&cat_flag);
        }

        if let Some(attrs) = attributes {
            for attrib in attrs {
                if attrib.starts_with("--field") {
                    return Err(OpcaError::CliError(
                        "OPCA expects op v2 assignment syntax only; do not use '--field'.".into(),
                    ));
                }
                if !attrib.contains('=') {
                    return Err(OpcaError::CliError(format!(
                        "Invalid attribute token {:?}. Expected 'label=value'.",
                        attrib
                    )));
                }
                args.push(attrib);
            }
        }

        let out = self.checked(&args, input)?;
        Ok(out.stdout)
    }

    /// Store a document in 1Password.
    ///
    /// Mirrors the Python `store_document` method with auto/create/edit logic.
    pub fn store_document(
        &self,
        item_title: &str,
        filename: &str,
        input: &str,
        action: StoreAction,
        vault: Option<&str>,
    ) -> Result<String, OpcaError> {
        let (op_action, title_arg) = self.resolve_store_action(item_title, action)?;

        let op_vault = vault.unwrap_or(&self.vault);
        let vault_flag = format!("--vault={}", op_vault);
        let file_flag = format!("--file-name={}", filename);

        let out = self.checked(
            &["document", op_action, &title_arg, &vault_flag, &file_flag],
            Some(input),
        )?;
        Ok(out.stdout)
    }

    /// Build a 1Password secret reference URL.
    pub fn mk_url(&self, item_title: &str, value_key: Option<&str>) -> String {
        match value_key {
            Some(key) => format!("op://{}/{}/{}", self.vault, item_title, key),
            None => format!("op://{}/{}", self.vault, item_title),
        }
    }

    /// Return the current 1Password CLI user details as a raw string.
    pub fn whoami(&self) -> Result<String, OpcaError> {
        let out = self.checked(&["whoami"], None)?;
        Ok(out.stdout)
    }

    /// Return the current 1Password CLI user details.
    pub fn get_current_user_details(&self) -> Result<String, OpcaError> {
        let out = self.checked(&["user", "get", "--me"], None)?;
        Ok(out.stdout)
    }

    /// Return the current vault details.
    pub fn get_vault(&self) -> Result<String, OpcaError> {
        let out = self.checked(&["vault", "get", &self.vault], None)?;
        Ok(out.stdout)
    }

    /// Create a new 1Password vault and return its metadata.
    pub fn vault_create(&self, name: &str) -> Result<VaultInfo, OpcaError> {
        let out = self.checked(&["vault", "create", name, "--format=json"], None)?;
        let vault: VaultInfo = serde_json::from_str(&out.stdout)
            .map_err(|e| OpcaError::CliError(format!("Failed to parse vault create output: {e}")))?;
        Ok(vault)
    }

    /// Delete (archive) a 1Password vault.
    pub fn vault_delete(&self, name: &str) -> Result<(), OpcaError> {
        self.checked(&["vault", "delete", name, "--archive"], None)?;
        Ok(())
    }

    /// List all accessible 1Password vaults.
    pub fn vault_list(&self) -> Result<Vec<VaultInfo>, OpcaError> {
        let out = self.checked(&["vault", "list", "--format=json"], None)?;
        let vaults: Vec<VaultInfo> = serde_json::from_str(&out.stdout)
            .map_err(|e| OpcaError::CliError(format!("Failed to parse vault list: {e}")))?;
        Ok(vaults)
    }

    // ------------------------------------------------------------------
    // Store helpers
    // ------------------------------------------------------------------

    /// Resolve auto/create/edit into an `op` sub-command and a title argument.
    ///
    /// For `create`, the title is passed as `--title=<title>`.
    /// For `edit`, the title is passed as a bare positional argument.
    fn resolve_store_action(
        &self,
        item_title: &str,
        action: StoreAction,
    ) -> Result<(&'static str, String), OpcaError> {
        match action {
            StoreAction::Auto => {
                if self.item_exists(item_title) {
                    Ok(("edit", item_title.to_string()))
                } else {
                    Ok(("create", format!("--title={}", item_title)))
                }
            }
            StoreAction::Create => Ok(("create", format!("--title={}", item_title))),
            StoreAction::Edit => Ok(("edit", item_title.to_string())),
        }
    }
}

// ------------------------------------------------------------------
// Free functions
// ------------------------------------------------------------------

/// Check whether the `op` CLI binary is available on `$PATH`.
///
/// Returns `Some(path)` if found, `None` otherwise.
pub fn check_cli_available() -> Option<String> {
    which::which(OP_BIN)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Run `op vault list` without an existing `Op` instance.
///
/// Used by the connect screen to populate the vault picker before
/// the user has selected a vault.
pub fn list_vaults_standalone(account: Option<&str>) -> Result<Vec<VaultInfo>, OpcaError> {
    let bin = which::which(OP_BIN)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| OpcaError::CliNotFound)?;

    let runner = ShellRunner;
    let mut args = vec!["vault", "list", "--format=json"];
    let acct_flag;
    if let Some(acct) = account {
        acct_flag = acct.to_string();
        args.push("--account");
        args.push(&acct_flag);
    }

    let out = runner.run(&bin, &args, None, None)?;
    if !out.success {
        return Err(map_cli_error(&out));
    }

    let vaults: Vec<VaultInfo> = serde_json::from_str(&out.stdout)
        .map_err(|e| OpcaError::CliError(format!("Failed to parse vault list: {e}")))?;
    Ok(vaults)
}

/// Map stderr/stdout text to a specific `OpcaError` variant.
///
/// Mirrors the Python `_raise_mapped_error()` function.
pub fn map_cli_error(out: &CommandOutput) -> OpcaError {
    let msg = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let low = msg.to_lowercase();

    if low.contains("vault") && low.contains("not found") {
        return OpcaError::VaultNotFound(msg.to_string());
    }
    if low.contains("sign in")
        || low.contains("unauthenticated")
        || low.contains("not authenticated")
    {
        return OpcaError::AuthenticationFailed;
    }
    if low.contains("permission") || low.contains("denied") || low.contains("forbidden") {
        return OpcaError::PermissionDenied(msg.to_string());
    }
    if low.contains("already exists") || low.contains("duplicate") || low.contains("archived") {
        return OpcaError::ItemConflict(msg.to_string());
    }
    if low.contains("not found") && low.contains("item") {
        return OpcaError::ItemNotFound(msg.to_string());
    }

    OpcaError::CliError(msg.to_string())
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{err_output, mock_op, mock_op_with_account, ok_output};

    // -- mk_url -------------------------------------------------------

    #[test]
    fn mk_url_without_key() {
        let op = mock_op(vec![]);
        assert_eq!(op.mk_url("CA", None), "op://TestVault/CA");
    }

    #[test]
    fn mk_url_with_key() {
        let op = mock_op(vec![]);
        assert_eq!(
            op.mk_url("MyCert", Some("private_key")),
            "op://TestVault/MyCert/private_key"
        );
    }

    // -- item_exists --------------------------------------------------

    #[test]
    fn item_exists_returns_true_on_success() {
        let op = mock_op(vec![ok_output("{}")]);
        assert!(op.item_exists("CA"));
    }

    #[test]
    fn item_exists_returns_false_on_failure() {
        let op = mock_op(vec![err_output("[ERROR] item not found")]);
        assert!(!op.item_exists("CA"));
    }

    // -- get_item -----------------------------------------------------

    #[test]
    fn get_item_returns_stdout() {
        let op = mock_op(vec![ok_output("{\"id\":\"abc\"}")]);
        let result = op.get_item("CA", "json").unwrap();
        assert_eq!(result, "{\"id\":\"abc\"}");
    }

    #[test]
    fn get_item_maps_error() {
        let op = mock_op(vec![err_output("[ERROR] item \"CA\" not found")]);
        let err = op.get_item("CA", "json").unwrap_err();
        assert!(matches!(err, OpcaError::ItemNotFound(_)));
    }

    // -- get_document -------------------------------------------------

    #[test]
    fn get_document_returns_stdout() {
        let op = mock_op(vec![ok_output("SQL DUMP CONTENTS")]);
        let result = op.get_document("CA_Database").unwrap();
        assert_eq!(result, "SQL DUMP CONTENTS");
    }

    // -- delete_item --------------------------------------------------

    #[test]
    fn delete_item_includes_archive_flag() {
        let op = mock_op(vec![ok_output("")]);
        op.delete_item("OldCert", true).unwrap();
        let calls = op.runner().calls();
        assert!(calls[0].contains(&"--archive".to_string()));
    }

    #[test]
    fn delete_item_omits_archive_flag() {
        let op = mock_op(vec![ok_output("")]);
        op.delete_item("OldCert", false).unwrap();
        let calls = op.runner().calls();
        assert!(!calls[0].contains(&"--archive".to_string()));
    }

    // -- store_item ---------------------------------------------------

    #[test]
    fn store_item_create_uses_title_flag() {
        let op = mock_op(vec![ok_output("")]);
        op.store_item("NewCert", None, StoreAction::Create, "Secure Note", None, None)
            .unwrap();
        let calls = op.runner().calls();
        assert!(calls[0].contains(&"--title=NewCert".to_string()));
        assert!(calls[0].contains(&"create".to_string()));
    }

    #[test]
    fn store_item_edit_uses_bare_title() {
        let op = mock_op(vec![ok_output("")]);
        op.store_item("ExistingCert", None, StoreAction::Edit, "Secure Note", None, None)
            .unwrap();
        let calls = op.runner().calls();
        assert!(calls[0].contains(&"ExistingCert".to_string()));
        assert!(calls[0].contains(&"edit".to_string()));
    }

    #[test]
    fn store_item_auto_creates_when_not_exists() {
        // First call: item_exists (fails), second: the create.
        let op = mock_op(vec![err_output("not found"), ok_output("")]);
        op.store_item("NewCert", None, StoreAction::Auto, "Secure Note", None, None)
            .unwrap();
        let calls = op.runner().calls();
        assert!(calls[1].contains(&"create".to_string()));
        assert!(calls[1].contains(&"--title=NewCert".to_string()));
    }

    #[test]
    fn store_item_auto_edits_when_exists() {
        // First call: item_exists (succeeds), second: the edit.
        let op = mock_op(vec![ok_output("{}"), ok_output("")]);
        op.store_item("ExistingCert", None, StoreAction::Auto, "Secure Note", None, None)
            .unwrap();
        let calls = op.runner().calls();
        assert!(calls[1].contains(&"edit".to_string()));
        assert!(calls[1].contains(&"ExistingCert".to_string()));
    }

    #[test]
    fn store_item_rejects_field_flag() {
        let op = mock_op(vec![]);
        let err = op
            .store_item(
                "Cert",
                Some(&["--field=foo"]),
                StoreAction::Create,
                "Secure Note",
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, OpcaError::CliError(_)));
    }

    #[test]
    fn store_item_rejects_invalid_attribute() {
        let op = mock_op(vec![]);
        let err = op
            .store_item(
                "Cert",
                Some(&["no_equals_sign"]),
                StoreAction::Create,
                "Secure Note",
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, OpcaError::CliError(_)));
    }

    // -- account_args -------------------------------------------------

    #[test]
    fn account_args_appended_when_set() {
        let op = mock_op_with_account(vec![ok_output("")]);
        op.whoami().unwrap();
        let calls = op.runner().calls();
        assert!(calls[0].contains(&"--account".to_string()));
        assert!(calls[0].contains(&"test.1password.com".to_string()));
    }

    #[test]
    fn account_args_empty_when_none() {
        let op = mock_op(vec![ok_output("")]);
        op.whoami().unwrap();
        let calls = op.runner().calls();
        assert!(!calls[0].contains(&"--account".to_string()));
    }

    // -- map_cli_error ------------------------------------------------

    #[test]
    fn map_error_vault_not_found() {
        let out = err_output("[ERROR] vault \"Foo\" not found");
        assert!(matches!(map_cli_error(&out), OpcaError::VaultNotFound(_)));
    }

    #[test]
    fn map_error_authentication() {
        let out = err_output("[ERROR] You are not currently sign in");
        assert!(matches!(
            map_cli_error(&out),
            OpcaError::AuthenticationFailed
        ));
    }

    #[test]
    fn map_error_permission_denied() {
        let out = err_output("[ERROR] permission denied for this vault");
        assert!(matches!(
            map_cli_error(&out),
            OpcaError::PermissionDenied(_)
        ));
    }

    #[test]
    fn map_error_item_conflict() {
        let out = err_output("[ERROR] item already exists");
        assert!(matches!(map_cli_error(&out), OpcaError::ItemConflict(_)));
    }

    #[test]
    fn map_error_item_not_found() {
        let out = err_output("[ERROR] item \"CA\" not found");
        assert!(matches!(map_cli_error(&out), OpcaError::ItemNotFound(_)));
    }

    #[test]
    fn map_error_generic() {
        let out = err_output("[ERROR] something unexpected happened");
        assert!(matches!(map_cli_error(&out), OpcaError::CliError(_)));
    }

    #[test]
    fn map_error_uses_stdout_when_stderr_empty() {
        let out = CommandOutput {
            stdout: "vault not found".to_string(),
            stderr: "".to_string(),
            success: false,
        };
        assert!(matches!(map_cli_error(&out), OpcaError::VaultNotFound(_)));
    }

    // -- vault_item_count ------------------------------------------------

    #[test]
    fn vault_item_count_parses_valid_json() {
        let op = mock_op(vec![ok_output(r#"[{"id":"a"},{"id":"b"}]"#)]);
        assert_eq!(op.vault_item_count().unwrap(), 2);
    }

    #[test]
    fn vault_item_count_errors_on_malformed_json() {
        let op = mock_op(vec![ok_output("not valid json")]);
        let err = op.vault_item_count().unwrap_err();
        assert!(matches!(err, OpcaError::CliError(_)));
    }

    #[test]
    fn vault_item_count_handles_empty_array() {
        let op = mock_op(vec![ok_output("[]")]);
        assert_eq!(op.vault_item_count().unwrap(), 0);
    }
}
