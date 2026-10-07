//! Integration tests for the `Op` struct against a real 1Password CLI session.
//!
//! These tests are guarded by the `OPCA_INTEGRATION_TEST` environment variable.
//! To run them you need:
//! - `op` CLI installed and on `$PATH`
//! - A signed-in 1Password session (or biometric unlock configured)
//! - A test vault accessible to the signed-in account
//!
//! Usage:
//!   OPCA_INTEGRATION_TEST=1 OPCA_TEST_VAULT=MyVault cargo test -p opca-core --test op_integration

use opca_core::op::{list_accounts_standalone, whoami_standalone, Op, StoreAction};

/// Return the test vault name from `OPCA_TEST_VAULT`, or a sensible default.
fn test_vault() -> String {
    std::env::var("OPCA_TEST_VAULT").unwrap_or_else(|_| "Private".to_string())
}

/// Return the optional account from `OPCA_TEST_ACCOUNT`.
fn test_account() -> Option<String> {
    std::env::var("OPCA_TEST_ACCOUNT").ok()
}

/// Skip the test if `OPCA_INTEGRATION_TEST` is not set.
macro_rules! skip_unless_integration {
    () => {
        if std::env::var("OPCA_INTEGRATION_TEST").is_err() {
            eprintln!("Skipping integration test: set OPCA_INTEGRATION_TEST=1 to run");
            return;
        }
    };
}

#[test]
fn op_new_succeeds_with_valid_vault() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None);
    assert!(op.is_ok(), "Op::new failed: {:?}", op.unwrap_err());
}

#[test]
fn op_new_fails_with_nonexistent_vault() {
    skip_unless_integration!();
    let result = Op::new("__nonexistent_vault_99999__", test_account(), None);
    assert!(result.is_err());
}

#[test]
fn whoami_returns_nonempty_string() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    let who = op.whoami().unwrap();
    assert!(!who.trim().is_empty(), "whoami returned empty string");
}

/// The settings account key is a `user_uuid` from `op account list`, matched
/// against `op whoami` when no account was given — so the two must agree on
/// that field. This is the only place the real payload shape is checked.
///
/// Note `whoami` reports the url as a full `https://host/` while `account list`
/// reports a bare host, so only the UUID is safe to match on.
#[test]
fn whoami_user_uuid_appears_in_the_account_list() {
    skip_unless_integration!();
    // Establish a session the way production does before settings ever asks.
    Op::new(test_vault(), test_account(), None).expect("could not sign in");

    let who = whoami_standalone().expect("op whoami --format=json failed");
    assert!(!who.user_uuid.is_empty(), "whoami reported no user_uuid: {who:?}");

    let accounts = list_accounts_standalone().expect("op account list failed");
    assert!(
        accounts.iter().any(|a| a.user_uuid == who.user_uuid),
        "whoami user_uuid {} is in no configured account: {accounts:?}",
        who.user_uuid,
    );
}

#[test]
fn vault_list_returns_at_least_one() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    let vaults = op.vault_list().unwrap();
    assert!(!vaults.is_empty(), "vault_list returned no vaults");
}

#[test]
fn item_exists_returns_false_for_nonexistent() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    assert!(!op.item_exists("__nonexistent_item_99999__"));
}

#[test]
fn op_new_learns_vault_id() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    assert!(op.vault_id.is_some());
}

#[test]
fn store_document_keeps_documents_larger_than_a_pipe_buffer() {
    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    let title = format!("__opca_large_doc_{}__", std::process::id());
    let content: String = (0..4000).map(|i| format!("INSERT INTO t VALUES({i});\n")).collect();
    assert!(content.len() > 64 * 1024);

    op.store_document(&title, "large.sql", &content, StoreAction::Create, None).unwrap();
    let stored = op.get_document(&title);
    op.delete_item(&title, false).unwrap();

    assert_eq!(stored.unwrap(), content);
}

/// Run `op` directly, for checks the `Op` API has no call for (archived items).
fn op_cli(args: &[&str]) -> String {
    let mut cmd = std::process::Command::new("op");
    cmd.args(args).arg(format!("--vault={}", test_vault()));
    if let Some(account) = test_account() {
        cmd.arg(format!("--account={account}"));
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "op {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn openvpn_templates_import_then_archive_without_losing_any() {
    use opca_core::constants::DEFAULT_OP_CONF;
    use opca_core::services::ca::CertificateAuthority;
    use opca_core::services::database::models::CaConfig;
    use opca_core::services::database::{CertificateAuthorityDB, TemplateImport};
    use opca_core::services::openvpn;

    skip_unless_integration!();
    let op = Op::new(test_vault(), test_account(), None).unwrap();
    // The flow writes the fixed `OpenVPN` and `CA_Database` titles, so never
    // run it in a vault that holds a real CA.
    for title in [DEFAULT_OP_CONF.openvpn_title, DEFAULT_OP_CONF.ca_database_title] {
        assert!(!op.item_exists(title), "'{title}' already exists in the test vault; use a scratch vault");
    }

    let multi_line = "client\ndev tun\nremote {{ op://v/OpenVPN/server/hostname }} 1194";
    op.store_item(
        DEFAULT_OP_CONF.openvpn_title,
        Some(&[
            "server.hostname[text]=vpn.example.com",
            &format!("template.default[text]={multi_line}"),
            "template.tcp[text]=client\nproto tcp",
        ]),
        StoreAction::Create,
        DEFAULT_OP_CONF.category,
        None,
        None,
    )
    .unwrap();

    let mut ca = CertificateAuthority {
        op,
        op_config: DEFAULT_OP_CONF,
        ca_bundle: None,
        ca_database: Some(CertificateAuthorityDB::new(&CaConfig::default()).unwrap()),
        crl: None,
        local_backup: None,
    };

    let result = || {
        assert_eq!(openvpn::import_templates_from_vault(&mut ca).unwrap(), Some(2));
        assert_eq!(openvpn::get_template(&mut ca, "default").unwrap().content, multi_line);
        assert_eq!(openvpn::templates_awaiting_cleanup(&mut ca).unwrap(), vec!["default", "tcp"]);

        assert_eq!(openvpn::archive_vault_templates(&mut ca).unwrap(), 2);

        let item: serde_json::Value =
            serde_json::from_str(&ca.op.get_item(DEFAULT_OP_CONF.openvpn_title, "json").unwrap()).unwrap();
        let labels: Vec<&str> = item["fields"].as_array().unwrap().iter()
            .filter_map(|f| f["label"].as_str()).collect();
        assert!(labels.contains(&"hostname"), "server settings must survive: {labels:?}");
        assert!(!labels.contains(&"default") && !labels.contains(&"tcp"), "templates left behind: {labels:?}");

        let archived: serde_json::Value = serde_json::from_str(&op_cli(&[
            "item", "list", "--include-archive", "--format=json",
        ]))
        .unwrap();
        let note = archived.as_array().unwrap().iter()
            .find(|i| i["title"].as_str().unwrap_or_default().starts_with("OpenVPN_Templates_"))
            .expect("archived templates note");
        assert_eq!(note["state"].as_str(), Some("ARCHIVED"));
        let note_id = note["id"].as_str().unwrap().to_string();
        let note: serde_json::Value = serde_json::from_str(&op_cli(&[
            "item", "get", &note_id, "--include-archive", "--format=json",
        ]))
        .unwrap();
        let default = note["fields"].as_array().unwrap().iter()
            .find(|f| f["label"] == "default").expect("archived default template");
        assert_eq!(default["value"].as_str().unwrap().trim(), multi_line);

        assert_eq!(ca.ca_database.as_ref().unwrap().openvpn_template_import().unwrap(), TemplateImport::Settled);
        note_id
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(result));

    if let Ok(note_id) = &outcome {
        op_cli(&["item", "delete", note_id]);
    }
    ca.op.delete_item(DEFAULT_OP_CONF.openvpn_title, false).ok();
    ca.op.delete_item(DEFAULT_OP_CONF.ca_database_title, false).ok();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
