//! Integration tests for opCA's 1Password client against a real CLI session.
//!
//! These tests are guarded by the `OPCA_INTEGRATION_TEST` environment variable.
//! To run them you need:
//! - `op` CLI installed and on `$PATH`
//! - A signed-in 1Password session (or biometric unlock configured)
//! - A test vault accessible to the signed-in account
//!
//! Usage:
//!   OPCA_INTEGRATION_TEST=1 OPCA_TEST_VAULT=MyVault cargo test -p opca-core --test op_integration

use opca_core::op::{self, ItemRef, ShellRunner, Vault};

/// Return the test vault name from `OPCA_TEST_VAULT`, or a sensible default.
fn test_vault() -> String {
    std::env::var("OPCA_TEST_VAULT").unwrap_or_else(|_| "Private".to_string())
}

/// Return the optional account from `OPCA_TEST_ACCOUNT`.
fn test_account() -> Option<String> {
    std::env::var("OPCA_TEST_ACCOUNT").ok()
}

fn connect() -> Vault {
    op::connect(ShellRunner::new(), &test_vault(), test_account().as_deref())
        .expect("could not connect")
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
fn connect_succeeds_with_valid_vault() {
    skip_unless_integration!();
    let vault = op::connect(ShellRunner::new(), &test_vault(), test_account().as_deref());
    assert!(vault.is_ok(), "connect failed: {:?}", vault.err());
}

#[test]
fn connect_fails_with_nonexistent_vault() {
    skip_unless_integration!();
    let result = op::connect(
        ShellRunner::new(),
        "__nonexistent_vault_99999__",
        test_account().as_deref(),
    );
    assert!(matches!(
        result,
        Err(opca_core::error::OpcaError::VaultNotFound(_))
    ));
}

#[test]
fn whoami_names_a_user() {
    skip_unless_integration!();
    let who = connect().op().whoami().unwrap();
    assert!(
        !who.user_uuid.is_empty(),
        "whoami reported no user_uuid: {who:?}"
    );
}

/// The settings account key is a `user_uuid` from `op account list`, matched
/// against `op whoami` when no account was given — so the two must agree on
/// that field. This is the only place the real payload shape is checked.
#[test]
fn whoami_user_uuid_appears_in_the_account_list() {
    skip_unless_integration!();
    // Establish a session the way production does before settings ever asks.
    let vault = connect();

    let who = vault.op().whoami().expect("op whoami --format=json failed");
    assert!(
        !who.user_uuid.is_empty(),
        "whoami reported no user_uuid: {who:?}"
    );

    let accounts = op::accounts(&ShellRunner::new()).expect("op account list failed");
    assert!(
        accounts.iter().any(|a| a.user_uuid == who.user_uuid),
        "whoami user_uuid {} is in no configured account: {accounts:?}",
        who.user_uuid,
    );
    assert!(
        accounts.iter().any(|a| a.url == who.url),
        "whoami url {} matches no account",
        who.url
    );
}

#[test]
fn vault_list_returns_at_least_one() {
    skip_unless_integration!();
    let vaults = connect().op().vaults().unwrap();
    assert!(!vaults.is_empty(), "vault list returned no vaults");
}

#[test]
fn item_exists_returns_false_for_nonexistent() {
    skip_unless_integration!();
    assert!(
        !connect()
            .item_exists(&ItemRef::title("__nonexistent_item_99999__"))
            .unwrap()
    );
}

#[test]
fn connect_learns_the_vault_id() {
    skip_unless_integration!();
    let vault = connect();
    assert!(!vault.info().id.is_empty());
    assert!(vault.info().is_named(&test_vault()));
}

#[test]
fn put_document_creates_then_replaces_documents_larger_than_a_pipe_buffer() {
    skip_unless_integration!();
    let vault = connect();
    let title = format!("__opca_large_doc_{}__", std::process::id());
    let content: String = (0..4000)
        .map(|i| format!("INSERT INTO t VALUES({i});\n"))
        .collect();
    assert!(content.len() > 64 * 1024);

    op::put_document(&vault, &title, "large.sql", &content).unwrap();
    let created = op::document_text(&vault, &title);
    op::put_document(&vault, &title, "large.sql", "replaced\n").unwrap();
    let replaced = op::document_text(&vault, &title);
    let found = vault.items_titled(&title).unwrap();
    vault
        .delete_item_permanently(&ItemRef::title(&title))
        .unwrap();

    assert_eq!(created.unwrap(), content);
    assert_eq!(replaced.unwrap(), "replaced\n");
    assert_eq!(
        found.len(),
        1,
        "put_document must edit, not add a second document"
    );
}

#[test]
fn openvpn_templates_import_then_archive_without_losing_any() {
    use opca_core::constants::DEFAULT_OP_CONF;
    use opca_core::services::ca::CertificateAuthority;
    use opca_core::services::database::models::CaConfig;
    use opca_core::services::database::{CertificateAuthorityDB, TemplateImport};
    use opca_core::services::openvpn;

    skip_unless_integration!();
    let vault = connect();
    // The flow writes the fixed `OpenVPN` and `CA_Database` titles, so never
    // run it in a vault that holds a real CA.
    for title in [
        DEFAULT_OP_CONF.openvpn_title,
        DEFAULT_OP_CONF.ca_database_title,
    ] {
        assert!(
            !vault.item_exists(&ItemRef::title(title)).unwrap(),
            "'{title}' already exists in the test vault; use a scratch vault"
        );
    }

    let multi_line = "client\ndev tun\nremote {{ op://v/OpenVPN/server/hostname }} 1194";
    vault
        .create_item(
            DEFAULT_OP_CONF.openvpn_title,
            DEFAULT_OP_CONF.category,
            &[
                op::assign("server.hostname[text]", "vpn.example.com").unwrap(),
                op::assign("template.default[text]", multi_line).unwrap(),
                op::assign("template.tcp[text]", "client\nproto tcp").unwrap(),
            ],
        )
        .unwrap();

    let mut ca = CertificateAuthority {
        vault,
        op_config: DEFAULT_OP_CONF,
        ca_bundle: None,
        ca_database: Some(CertificateAuthorityDB::new(&CaConfig::default()).unwrap()),
        crl: None,
        local_backup: None,
    };

    let result = || {
        assert_eq!(
            openvpn::import_templates_from_vault(&mut ca).unwrap(),
            Some(2)
        );
        assert_eq!(
            openvpn::get_template(&mut ca, "default").unwrap().content,
            multi_line
        );
        assert_eq!(
            openvpn::templates_awaiting_cleanup(&mut ca).unwrap(),
            vec!["default", "tcp"]
        );

        assert_eq!(openvpn::archive_vault_templates(&mut ca).unwrap(), 2);

        let item = ca
            .vault
            .item(&ItemRef::title(DEFAULT_OP_CONF.openvpn_title))
            .unwrap();
        let labels: Vec<&str> = item.fields.iter().map(|f| f.label.as_str()).collect();
        assert!(
            labels.contains(&"hostname"),
            "server settings must survive: {labels:?}"
        );
        assert!(
            !labels.contains(&"default") && !labels.contains(&"tcp"),
            "templates left behind: {labels:?}"
        );

        let archive = ca.vault.clone().including_archive();
        let note = archive
            .items(&[])
            .unwrap()
            .into_iter()
            .find(|i| i.title.starts_with("OpenVPN_Templates_"))
            .expect("archived templates note");
        let json: serde_json::Value =
            serde_json::from_str(archive.item_json(&ItemRef::from(&note)).unwrap().expose())
                .unwrap();
        assert_eq!(json["state"].as_str(), Some("ARCHIVED"));
        let archived = archive.item(&ItemRef::from(&note)).unwrap();
        assert_eq!(
            op::field_text(&archived, "default")
                .expect("archived default template")
                .trim(),
            multi_line
        );
        let note_id = note.id;

        assert_eq!(
            ca.ca_database
                .as_ref()
                .unwrap()
                .openvpn_template_import()
                .unwrap(),
            TemplateImport::Settled
        );
        note_id
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(result));

    if let Ok(note_id) = &outcome {
        ca.vault.delete_item_permanently(&ItemRef::id(note_id)).ok();
    }
    ca.vault
        .delete_item_permanently(&ItemRef::title(DEFAULT_OP_CONF.openvpn_title))
        .ok();
    ca.vault
        .delete_item_permanently(&ItemRef::title(DEFAULT_OP_CONF.ca_database_title))
        .ok();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
