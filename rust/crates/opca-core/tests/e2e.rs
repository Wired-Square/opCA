//! End-to-end integration tests for opca-core.
//!
//! Mirrors the Python e2e test suite in `python/tests/e2e/`. Tests run against
//! a real 1Password vault and exercise the full CA lifecycle: init, cert
//! creation, renewal, revocation, CRL generation, database queries, and
//! backup/restore.
//!
//! Gated by `OPCA_INTEGRATION_TEST=1`. Run with:
//!   OPCA_INTEGRATION_TEST=1 cargo test -p opca-core --test e2e -- --test-threads=1
//!
//! Optionally set `OPCA_TEST_ACCOUNT` for a specific 1Password account.

use std::sync::Mutex;

use opca_core::constants::DEFAULT_OP_CONF;
use opca_core::op::Op;
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::cert::CertType;
use opca_core::services::database::models::{CaConfig, CertLookup};
use opca_core::services::vault::VaultBackup;

// ---------------------------------------------------------------------------
// Shared state across sequential tests
// ---------------------------------------------------------------------------

struct TestState {
    vault: String,
    account: Option<String>,
    /// Track serial of the server cert for verification
    server_cert_title: String,
    /// Track the client cert title for revocation
    client_cert_title: String,
    /// Second vault used for backup/restore
    restore_vault: String,
}

static STATE: Mutex<Option<TestState>> = Mutex::new(None);

fn test_account() -> Option<String> {
    std::env::var("OPCA_TEST_ACCOUNT").ok()
}

fn make_op(vault: &str) -> Op {
    Op::new(vault, test_account(), None).expect("Op::new failed")
}

/// Skip the test if `OPCA_INTEGRATION_TEST` is not set.
macro_rules! skip_unless_integration {
    () => {
        if std::env::var("OPCA_INTEGRATION_TEST").is_err() {
            eprintln!("Skipping e2e test: set OPCA_INTEGRATION_TEST=1 to run");
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// Test sequence
// ---------------------------------------------------------------------------

#[test]
fn t01_create_vault() {
    skip_unless_integration!();

    let account = test_account();
    // Use a temporary Op on any vault just to call vault_create
    let tmp_op = Op::new("Private", account.clone(), None)
        .expect("Need at least a 'Private' vault to bootstrap");

    let vault_name = format!("opca-e2e-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let info = tmp_op.vault_create(&vault_name).expect("vault_create failed");
    eprintln!("[e2e] Created vault: {} (id={})", info.name, info.id);

    let mut state = STATE.lock().unwrap();
    *state = Some(TestState {
        vault: vault_name,
        account,
        server_cert_title: String::new(),
        client_cert_title: String::new(),
        restore_vault: String::new(),
    });
}

#[test]
fn t10_ca_init() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let config = CaConfig {
        org: Some("OPCA E2E Test".to_string()),
        ou: Some("Testing".to_string()),
        country: Some("AU".to_string()),
        state: Some("NSW".to_string()),
        city: Some("Sydney".to_string()),
        days: Some(365),
        crl_days: Some(30),
        ..CaConfig::default()
    };

    let ca = CertificateAuthority::init(op, &config).expect("CA init failed");
    let bundle = ca.ca_bundle.as_ref().expect("CA bundle missing");
    assert!(bundle.certificate.is_some(), "CA certificate missing");
    eprintln!("[e2e] CA initialised successfully");
}

#[test]
fn t11_ca_retrieve() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");
    let bundle = ca.ca_bundle.as_ref().expect("CA bundle missing");
    let cert = bundle.certificate.as_ref().expect("certificate missing");

    // Verify subject contains our org
    let subject = cert.subject_name();
    let org = subject
        .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());
    assert_eq!(org.as_deref(), Some("OPCA E2E Test"));
    eprintln!("[e2e] CA retrieved — org={:?}", org);
}

#[test]
fn t12_ca_export() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");
    let pem = ca
        .ca_bundle
        .as_ref()
        .expect("bundle")
        .certificate_pem()
        .expect("certificate_pem failed");
    assert!(pem.contains("BEGIN CERTIFICATE"), "PEM missing header");
    assert!(pem.contains("END CERTIFICATE"), "PEM missing footer");
    eprintln!("[e2e] CA cert exported ({} bytes)", pem.len());
}

#[test]
fn t20_cert_create_server() {
    skip_unless_integration!();

    let mut state = STATE.lock().unwrap();
    let s = state.as_mut().expect("t01 must run first");
    let op = make_op(&s.vault);

    let mut ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");

    let config = opca_core::services::cert::CertBundleConfig {
        cn: Some("e2e-webserver.example.com".to_string()),
        key_size: Some(2048),
        alt_dns_names: Some(vec!["www.e2e-webserver.example.com".to_string()]),
        ..Default::default()
    };

    let title = "e2e-webserver";
    let (bundle, _warning) = ca
        .generate_certificate_bundle(CertType::WebServer, title, config)
        .expect("generate webserver cert failed");

    assert!(bundle.certificate.is_some());
    let pem = bundle.certificate_pem().expect("cert pem");
    assert!(pem.contains("BEGIN CERTIFICATE"));
    s.server_cert_title = title.to_string();
    eprintln!("[e2e] Webserver cert created: {}", title);
}

#[test]
fn t21_cert_create_client() {
    skip_unless_integration!();

    let mut state = STATE.lock().unwrap();
    let s = state.as_mut().expect("t01 must run first");
    let op = make_op(&s.vault);

    let mut ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");

    let config = opca_core::services::cert::CertBundleConfig {
        cn: Some("e2e-vpnclient".to_string()),
        key_size: Some(2048),
        ..Default::default()
    };

    let title = "e2e-vpnclient";
    let (bundle, _warning) = ca
        .generate_certificate_bundle(CertType::VpnClient, title, config)
        .expect("generate vpnclient cert failed");

    assert!(bundle.certificate.is_some());
    s.client_cert_title = title.to_string();
    eprintln!("[e2e] VPN client cert created: {}", title);
}

#[test]
fn t22_cert_list() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");
    let db = ca.ca_database.as_ref().expect("database missing");
    let certs = db.query_all_certs().expect("query_all_certs failed");

    assert!(
        certs.len() >= 2,
        "Expected at least 2 certs, got {}",
        certs.len()
    );
    eprintln!("[e2e] cert list: {} certificates", certs.len());
}

#[test]
fn t23_cert_renew() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let mut ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");

    let lookup = CertLookup::Title(s.server_cert_title.clone());
    let (new_pem, _warning) = ca
        .renew_certificate_bundle(&lookup)
        .expect("renew failed");

    assert!(new_pem.contains("BEGIN CERTIFICATE"));
    eprintln!("[e2e] Renewed cert for {}", s.server_cert_title);
}

#[test]
fn t23b_cert_rekey() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let mut ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");

    let lookup = CertLookup::Title(s.server_cert_title.clone());
    let (new_pem, _warning) = ca
        .rekey_certificate_bundle(&lookup)
        .expect("rekey failed");

    assert!(new_pem.contains("BEGIN CERTIFICATE"));
    eprintln!("[e2e] Rekeyed cert for {}", s.server_cert_title);
}

#[test]
fn t24_cert_revoke() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let mut ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");

    let lookup = CertLookup::Title(s.client_cert_title.clone());
    let result = ca.revoke_certificate(&lookup).expect("revoke failed");
    assert!(result, "revoke_certificate returned false");
    eprintln!("[e2e] Revoked cert: {}", s.client_cert_title);
}

#[test]
fn t30_crl_generate() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let mut ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");
    let crl_pem = ca.generate_crl().expect("generate_crl failed");

    assert!(crl_pem.contains("BEGIN X509 CRL"), "CRL missing header");
    assert!(crl_pem.contains("END X509 CRL"), "CRL missing footer");
    eprintln!("[e2e] CRL generated ({} bytes)", crl_pem.len());
}

#[test]
fn t31_crl_verify() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    // Re-retrieve — CRL was stored in 1Password by t30
    let crl_pem = op
        .get_document(DEFAULT_OP_CONF.crl_title)
        .expect("CRL document not found in vault");

    assert!(crl_pem.contains("BEGIN X509 CRL"));
    eprintln!("[e2e] CRL verified from vault ({} bytes)", crl_pem.len());
}

#[test]
fn t40_database_counts() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");
    let op = make_op(&s.vault);

    let mut ca = CertificateAuthority::retrieve(op).expect("CA retrieve failed");
    let db = ca.ca_database.as_mut().expect("database missing");
    db.process_ca_database(None).expect("process_ca_database failed");

    let total = db.count_certs().expect("count_certs failed");
    assert!(total >= 2, "Expected at least 2 certs, got {total}");

    // At least one revoked (the vpnclient)
    assert!(
        !db.certs_revoked.is_empty(),
        "Expected at least one revoked cert"
    );
    // At least one valid
    assert!(
        !db.certs_valid.is_empty(),
        "Expected at least one valid cert"
    );

    eprintln!(
        "[e2e] DB counts — total: {}, valid: {}, revoked: {}",
        total,
        db.certs_valid.len(),
        db.certs_revoked.len()
    );
}

#[test]
fn t50_vault_backup_restore() {
    skip_unless_integration!();

    let mut state = STATE.lock().unwrap();
    let s = state.as_mut().expect("t01 must run first");

    // --- Backup from source vault ---
    let op_src = make_op(&s.vault);
    let vb = VaultBackup::new(&op_src, &DEFAULT_OP_CONF);
    let payload = vb.create_backup().expect("create_backup failed");

    assert!(payload.items.len() >= 3, "Expected at least CA + DB + certs");
    assert_eq!(payload.metadata.vault_name, s.vault);
    eprintln!(
        "[e2e] Backup created: {} items from '{}'",
        payload.items.len(),
        s.vault
    );

    // --- Create a new empty vault for restore ---
    let restore_vault_name = format!("{}-restore", s.vault);
    let restore_info = op_src
        .vault_create(&restore_vault_name)
        .expect("restore vault create failed");
    eprintln!(
        "[e2e] Created restore vault: {} (id={})",
        restore_info.name, restore_info.id
    );
    s.restore_vault = restore_vault_name.clone();

    // --- Restore into the new vault ---
    let op_dst = make_op(&restore_vault_name);
    let vb_dst = VaultBackup::new(&op_dst, &DEFAULT_OP_CONF);
    let counts = vb_dst
        .restore_backup(&payload, None)
        .expect("restore_backup failed");

    let total_restored: usize = counts.values().sum();
    assert!(total_restored >= 3, "Expected at least 3 restored items");
    eprintln!("[e2e] Restore complete: {:?}", counts);

    // --- Verify CA exists in restored vault ---
    assert!(
        op_dst.item_exists(DEFAULT_OP_CONF.ca_title),
        "CA item not found in restored vault"
    );

    let ca = CertificateAuthority::retrieve(op_dst).expect("retrieve from restored vault failed");
    let bundle = ca.ca_bundle.as_ref().expect("CA bundle missing");
    assert!(bundle.certificate.is_some(), "Restored CA has no certificate");
    eprintln!("[e2e] Verified CA in restored vault");
}

#[test]
fn t90_cleanup() {
    skip_unless_integration!();

    let state = STATE.lock().unwrap();
    let s = state.as_ref().expect("t01 must run first");

    // Archive the test vaults — use a temporary Op on Private to run vault_delete
    let tmp_op = Op::new("Private", s.account.clone(), None)
        .expect("Need 'Private' vault for cleanup");

    // Archive main test vault
    match tmp_op.vault_delete(&s.vault) {
        Ok(()) => eprintln!("[e2e] Archived vault: {}", s.vault),
        Err(e) => eprintln!("[e2e] Warning: failed to archive vault '{}': {}", s.vault, e),
    }

    // Archive restore vault if created
    if !s.restore_vault.is_empty() {
        match tmp_op.vault_delete(&s.restore_vault) {
            Ok(()) => eprintln!("[e2e] Archived vault: {}", s.restore_vault),
            Err(e) => eprintln!(
                "[e2e] Warning: failed to archive vault '{}': {}",
                s.restore_vault, e
            ),
        }
    }
}
