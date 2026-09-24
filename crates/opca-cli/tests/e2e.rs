//! End-to-end integration tests for the opca CLI binary.
//!
//! Mirrors the Python e2e test suite (`python/tests/e2e/`, removed after `cc7d913`). Tests invoke the
//! compiled `opca` binary via `std::process::Command` against a real 1Password
//! vault, verifying exit codes and stdout content.
//!
//! Gated by `OPCA_INTEGRATION_TEST=1`. Run with:
//!   OPCA_INTEGRATION_TEST=1 cargo test -p opca-cli --test e2e -- --test-threads=1
//!
//! Optionally set `OPCA_TEST_ACCOUNT` for a specific 1Password account.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Shared state across sequential tests
// ---------------------------------------------------------------------------

struct TestState {
    vault: String,
    account: Option<String>,
    bin: PathBuf,
    import_vault: String,
    tmp_dir: PathBuf,
}

static STATE: Mutex<Option<TestState>> = Mutex::new(None);
/// Set to true on first failure — all subsequent tests bail immediately.
static FAILED: AtomicBool = AtomicBool::new(false);

fn test_account() -> Option<String> {
    std::env::var("OPCA_TEST_ACCOUNT").ok()
}

fn opca_bin() -> PathBuf {
    let mut path = std::env::current_exe().expect("cannot determine test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("opca");
    assert!(
        path.exists(),
        "opca binary not found at {}. Run `cargo build -p opca-cli` first.",
        path.display()
    );
    path
}

macro_rules! skip_unless_integration {
    () => {
        if std::env::var("OPCA_INTEGRATION_TEST").is_err() {
            eprintln!("Skipping: set OPCA_INTEGRATION_TEST=1");
            return;
        }
    };
}

/// Bail immediately if a prior test has already failed.
macro_rules! bail_if_failed {
    () => {
        if FAILED.load(Ordering::SeqCst) {
            panic!("skipped — prior test failed");
        }
    };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_opca(state: &TestState, args: &[&str]) -> Output {
    let mut cmd = Command::new(&state.bin);
    if let Some(ref acct) = state.account {
        cmd.arg("-a").arg(acct);
    }
    cmd.arg("-v").arg(&state.vault);
    cmd.args(args);
    eprintln!("[e2e] Running: opca -v {} {}", state.vault, args.join(" "));
    cmd.output().expect("failed to execute opca")
}

fn run_opca_vault(state: &TestState, vault: &str, args: &[&str]) -> Output {
    let mut cmd = Command::new(&state.bin);
    if let Some(ref acct) = state.account {
        cmd.arg("-a").arg(acct);
    }
    cmd.arg("-v").arg(vault);
    cmd.args(args);
    eprintln!("[e2e] Running: opca -v {vault} {}", args.join(" "));
    cmd.output().expect("failed to execute opca")
}

fn assert_ok(output: &Output, step: &str) {
    if !output.status.success() {
        FAILED.store(true, Ordering::SeqCst);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "{step} FAILED (code {:?})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--------------",
            output.status.code()
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
}

fn combined_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("{stdout}{stderr}")
}

fn get_state() -> std::sync::MutexGuard<'static, Option<TestState>> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Test sequence
// ---------------------------------------------------------------------------

#[test]
fn t01_setup() {
    skip_unless_integration!();

    let account = test_account();
    let bin = opca_bin();

    let vault_name = format!(
        "opca-cli-e2e-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );

    let mut cmd = Command::new("op");
    if let Some(ref acct) = account {
        cmd.arg("--account").arg(acct);
    }
    cmd.args(["vault", "create", &vault_name, "--icon", "wrench"]);
    let output = cmd.output().expect("failed to run op vault create");
    if !output.status.success() {
        FAILED.store(true, Ordering::SeqCst);
        panic!(
            "Failed to create vault: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    eprintln!("[e2e] Created vault: {vault_name}");

    let tmp_dir = std::env::temp_dir().join(format!("opca-cli-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("failed to create temp dir");

    let mut state = get_state();
    *state = Some(TestState {
        vault: vault_name,
        account,
        bin,
        import_vault: String::new(),
        tmp_dir,
    });
}

// ---------------------------------------------------------------------------
// CA tests
// ---------------------------------------------------------------------------

#[test]
fn t10_ca_init() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");

    let output = run_opca(s, &[
        "ca", "init",
        "-e", "no1@home.com",
        "-o", "Test Organisation",
        "-n", "Test Certificate Authority",
        "--ou", "Web Services",
        "--city", "Canberra",
        "--state", "ACT",
        "--country", "AU",
        "--ca-days", "3650",
        "--crl-days", "45",
        "--days", "365",
        "--ca-url", "https://ca.home.com/ca.crt",
        "--crl-url", "https://ca.home.com/crl.pem",
    ]);
    assert_ok(&output, "CA init");
}

#[test]
fn t12_ca_export() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");

    let cert_path = s.tmp_dir.join("exported-ca.crt");
    let key_path = s.tmp_dir.join("exported-ca.key");

    let output = run_opca(s, &[
        "ca", "export",
        "--with-key",
        "--cert-out", cert_path.to_str().unwrap(),
        "--key-out", key_path.to_str().unwrap(),
    ]);
    assert_ok(&output, "CA export with key");

    assert!(cert_path.exists(), "Exported certificate file is missing");
    assert!(key_path.exists(), "Exported private key file is missing");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Expected key perms 0600, got {:#o}", mode);
    }

    let cert_content = std::fs::read_to_string(&cert_path).expect("read cert");
    assert!(cert_content.contains("BEGIN CERTIFICATE"));
}

#[test]
fn t15_ca_import_into_new_vault() {
    skip_unless_integration!();
    bail_if_failed!();
    let mut state = get_state();
    let s = state.as_mut().expect("t01 must run first");

    let import_vault_name = format!("{}-import", s.vault);
    let mut cmd = Command::new("op");
    if let Some(ref acct) = s.account {
        cmd.arg("--account").arg(acct);
    }
    cmd.args(["vault", "create", &import_vault_name, "--icon", "wrench"]);
    let output = cmd.output().expect("failed to run op vault create");
    assert!(
        output.status.success(),
        "Failed to create import vault: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    s.import_vault = import_vault_name.clone();
    eprintln!("[e2e] Created import vault: {import_vault_name}");

    let cert_path = s.tmp_dir.join("exported-ca.crt");
    let key_path = s.tmp_dir.join("exported-ca.key");

    let output = run_opca_vault(s, &import_vault_name, &[
        "ca", "import",
        "-c", cert_path.to_str().unwrap(),
        "-k", key_path.to_str().unwrap(),
        "--days", "365",
        "--crl-days", "30",
    ]);
    assert_ok(&output, "CA import into new vault");
}

// ---------------------------------------------------------------------------
// Certificate tests
// ---------------------------------------------------------------------------

#[test]
fn t20_cert_create_vpnserver() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["cert", "create", "-t", "vpnserver", "-n", "vpnserver-cert", "--key", "rsa-2048"]);
    assert_ok(&output, "cert create vpnserver");
}

#[test]
fn t21_cert_create_vpnclient() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["cert", "create", "-t", "vpnclient", "-n", "vpnclient-cert"]);
    assert_ok(&output, "cert create vpnclient");
}

#[test]
fn t22_cert_create_webserver_a() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &[
        "cert", "create", "-t", "webserver", "-n", "webserver-cert",
        "--alt", "www.webserver.com", "--alt", "10.0.0.1",
    ]);
    assert_ok(&output, "cert create webserver-cert");
}

#[test]
fn t23_cert_create_webserver_b() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &[
        "cert", "create", "-t", "webserver", "-n", "mailserver-cert",
        "--alt", "mail.webserver.com",
    ]);
    assert_ok(&output, "cert create mailserver-cert");
}

#[test]
fn t24_cert_renew_mailserver() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["cert", "renew", "-n", "mailserver-cert"]);
    assert_ok(&output, "cert renew mailserver-cert");
}

#[test]
fn t25_cert_revoke_webserver() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["cert", "revoke", "-n", "webserver-cert"]);
    assert_ok(&output, "cert revoke webserver-cert");
}

#[test]
fn t26_cert_revoke_serial_5() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["cert", "revoke", "-s", "5"]);
    assert_ok(&output, "cert revoke serial 5");
}

#[test]
fn t27_cert_export_vpnclient() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");

    let cert_path = s.tmp_dir.join("vpnclient-cert.crt");
    let key_path = s.tmp_dir.join("vpnclient-cert.key");

    let output = run_opca(s, &[
        "cert", "export", "-n", "vpnclient-cert",
        "--with-key",
        "--cert-out", cert_path.to_str().unwrap(),
        "--key-out", key_path.to_str().unwrap(),
    ]);
    assert_ok(&output, "cert export vpnclient-cert");

    assert!(cert_path.exists(), "Exported cert file is missing");
    assert!(std::fs::metadata(&cert_path).unwrap().len() > 0, "Exported cert file is empty");
    assert!(key_path.exists(), "Exported key file is missing");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Expected key perms 0600, got {:#o}", mode);
    }
}

#[test]
fn t28_cert_import_into_new_vault() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");

    if s.import_vault.is_empty() {
        eprintln!("[e2e] Skipping: import vault not created");
        return;
    }

    let cert_path = s.tmp_dir.join("vpnclient-cert.crt");
    let key_path = s.tmp_dir.join("vpnclient-cert.key");

    let output = run_opca_vault(s, &s.import_vault, &[
        "cert", "import",
        "-n", "vpnclient-cert",
        "-c", cert_path.to_str().unwrap(),
        "-k", key_path.to_str().unwrap(),
    ]);
    assert_ok(&output, "cert import into new vault");

    let output = run_opca_vault(s, &s.import_vault, &[
        "cert", "export", "-n", "vpnclient-cert",
        "--cert-only", "--to-stdout",
    ]);
    assert_ok(&output, "cert export from import vault");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BEGIN CERTIFICATE"));
}

// ---------------------------------------------------------------------------
// CRL tests
// ---------------------------------------------------------------------------

#[test]
fn t30_crl_create() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["crl", "create"]);
    assert_ok(&output, "crl create");
}

#[test]
fn t31_crl_export_and_verify() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");

    let ca_pem_path = s.tmp_dir.join("ca-verify.pem");
    if !ca_pem_path.exists() {
        let output = run_opca(s, &[
            "ca", "export", "--cert-out", ca_pem_path.to_str().unwrap(),
        ]);
        assert_ok(&output, "ca export for CRL verification");
    }

    let crl_pem_path = s.tmp_dir.join("crl.pem");
    let output = run_opca(s, &["crl", "export", "-o", crl_pem_path.to_str().unwrap()]);
    assert_ok(&output, "crl export PEM");
    assert!(crl_pem_path.exists());

    let crl_der_path = s.tmp_dir.join("crl.der");
    let output = run_opca(s, &["crl", "export", "-f", "der", "-o", crl_der_path.to_str().unwrap()]);
    assert_ok(&output, "crl export DER");
    assert!(crl_der_path.exists());

    let output = Command::new("openssl")
        .args(["crl", "-in", crl_pem_path.to_str().unwrap(), "-noout", "-verify", "-CAfile", ca_pem_path.to_str().unwrap()])
        .output().expect("failed to run openssl");
    assert!(output.status.success(), "openssl CRL PEM verify failed: {}", String::from_utf8_lossy(&output.stderr));

    let output = Command::new("openssl")
        .args(["crl", "-in", crl_der_path.to_str().unwrap(), "-inform", "der", "-noout", "-verify", "-CAfile", ca_pem_path.to_str().unwrap()])
        .output().expect("failed to run openssl");
    assert!(output.status.success(), "openssl CRL DER verify failed: {}", String::from_utf8_lossy(&output.stderr));

    eprintln!("[e2e] CRL verified with openssl (PEM + DER)");
}

#[test]
fn t32_crl_info() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["crl", "info"]);
    assert_ok(&output, "crl info");

    let text = combined_output(&output);
    assert!(text.contains("Certificate Revocation List"));
    assert!(text.contains("Issuer"));
}

#[test]
fn t33_ca_list() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["ca", "list"]);
    assert_ok(&output, "ca list");

    let text = combined_output(&output);
    assert!(
        text.contains("vpnserver-cert") || text.contains("vpnclient-cert"),
        "ca list should show at least one certificate"
    );
}

// ---------------------------------------------------------------------------
// OpenVPN tests
// ---------------------------------------------------------------------------

#[test]
fn t40_openvpn_server() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["openvpn", "generate", "--server"]);
    assert_ok(&output, "openvpn generate --server");
}

#[test]
fn t41_openvpn_dh() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["openvpn", "generate", "--dh"]);
    assert_ok(&output, "openvpn generate --dh");
}

#[test]
fn t42_openvpn_ta_key() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["openvpn", "generate", "--ta-key"]);
    assert_ok(&output, "openvpn generate --ta-key");
}

// ---------------------------------------------------------------------------
// Database tests
// ---------------------------------------------------------------------------

#[test]
fn t50_database_config_get() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["database", "config-get"]);
    assert_ok(&output, "database config-get");

    let text = combined_output(&output);
    assert!(text.contains("Organisation") || text.contains("Test Organisation"));
}

#[test]
fn t51_database_export() {
    skip_unless_integration!();
    bail_if_failed!();
    let state = get_state();
    let s = state.as_ref().expect("t01 must run first");
    let output = run_opca(s, &["database", "export"]);
    assert_ok(&output, "database export");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CREATE TABLE") || stdout.contains("INSERT"));
}

// ---------------------------------------------------------------------------
// Cleanup — always runs, even after failures
// ---------------------------------------------------------------------------

#[test]
fn t90_cleanup() {
    skip_unless_integration!();

    let state = get_state();
    let s = match state.as_ref() {
        Some(s) => s,
        None => return,
    };

    let delete_vault = |name: &str| {
        if name.is_empty() {
            return;
        }
        let mut cmd = Command::new("op");
        if let Some(ref acct) = s.account {
            cmd.arg("--account").arg(acct);
        }
        cmd.args(["vault", "delete", name]);
        match cmd.output() {
            Ok(o) if o.status.success() => eprintln!("[e2e] Deleted vault: {name}"),
            Ok(o) => eprintln!("[e2e] Warning: delete '{name}': {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => eprintln!("[e2e] Warning: op failed for '{name}': {e}"),
        }
    };

    delete_vault(&s.vault);
    delete_vault(&s.import_vault);
    let _ = std::fs::remove_dir_all(&s.tmp_dir);
}
