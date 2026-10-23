//! opCA's side of `wslib_1password`: connecting to the CA vault, and the
//! writes the vault format needs.

use std::fmt::Display;

pub use wslib_1password::{
    accounts, cli_path, find_account, is_item_id, AccountInfo, Assignment, Error, FieldType, Item,
    ItemRef, ItemSummary, Runner, VaultInfo,
};
use wslib_1password::{map_cli_error, Call, Output};

use crate::error::OpcaError;

pub type ShellRunner = RetryOnConflict<wslib_1password::ShellRunner>;
pub type Op<R = ShellRunner> = wslib_1password::Op<R>;
pub type Vault<R = ShellRunner> = wslib_1password::Vault<R>;

/// Makes a call once more when 1Password refused it with a 409, which it
/// refuses only to a write that did not land.
#[derive(Clone, Debug, Default)]
pub struct RetryOnConflict<R>(pub R);

impl ShellRunner {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<R: Runner> Runner for RetryOnConflict<R> {
    fn run(&self, call: &Call) -> std::io::Result<Output> {
        let out = self.0.run(call)?;
        if out.success() || !map_cli_error(&out).is_retryable() {
            return Ok(out);
        }
        log::warn!("{call} raced another write; trying once more");
        self.0.run(call)
    }
}

/// A client for `account`, or for whichever account `op` picks when `None`.
pub fn client<R: Runner>(runner: R, account: Option<&str>) -> Op<R> {
    match account {
        Some(account) => Op::new(runner, account),
        None => Op::unscoped(runner),
    }
}

/// Signs in and opens the CA vault.
pub fn connect<R: Runner + Clone>(
    runner: R,
    vault: &str,
    account: Option<&str>,
) -> Result<Vault<R>, OpcaError> {
    let vault = vault.trim();
    if vault.is_empty() {
        return Err(OpcaError::VaultNotFound("No 1Password vault configured.".into()));
    }
    let op = client(runner, account);
    op.sign_in()?;
    op.open_vault(vault).map_err(|e| match e {
        Error::Cli { .. } => OpcaError::VaultNotFound(format!("1Password vault {vault:?} not found.")),
        other => other.into(),
    })
}

/// Creates a vault, refusing a name already in use, which `op` allows.
pub fn create_vault<R: Runner>(op: &Op<R>, name: &str) -> Result<VaultInfo, OpcaError> {
    let name = name.trim();
    if op.vaults()?.iter().any(|v| v.is_named(name)) {
        return Err(OpcaError::VaultAlreadyExists(name.to_string()));
    }
    Ok(op.create_vault(name)?)
}

/// One field, `label` written as `DEFAULT_OP_CONF` writes it (`section.label[type]`).
pub fn assign(label: &str, value: impl Display) -> Result<Assignment, OpcaError> {
    Ok(Assignment::parse(&format!("{label}={value}"))?)
}

/// The field's value, when it has a non-empty one.
pub fn field_text<'a>(item: &'a Item, label: &str) -> Option<&'a str> {
    Some(item.field(label)?.text()?.expose())
}

pub fn document_text<R: Runner>(vault: &Vault<R>, title: &str) -> Result<String, OpcaError> {
    let bytes = vault.document(&ItemRef::title(title))?;
    Ok(String::from_utf8_lossy(bytes.expose()).into_owned())
}

/// Replaces the document's file, creating the document when there is none:
/// one `op` call once it exists.
pub fn put_document<R: Runner>(
    vault: &Vault<R>,
    title: &str,
    file_name: &str,
    content: &str,
) -> Result<(), OpcaError> {
    match vault.edit_document(&ItemRef::title(title), file_name, content.as_bytes()) {
        Err(Error::ItemNotFound(_)) => vault.create_document(title, file_name, content.as_bytes())?,
        edited => edited?,
    }
    Ok(())
}

/// Sets the item's fields, creating the item when there is none: one `op`
/// call once it exists.
pub fn put_item<R: Runner>(
    vault: &Vault<R>,
    title: &str,
    category: &str,
    fields: &[Assignment],
) -> Result<(), OpcaError> {
    match vault.edit_item(&ItemRef::title(title), fields) {
        Err(Error::ItemNotFound(_)) => drop(vault.create_item(title, category, fields)?),
        edited => edited?,
    }
    Ok(())
}

/// The text `reference` names, as `op read` prints it.
pub fn read_text<R: Runner>(vault: &Vault<R>, reference: &str) -> Result<String, OpcaError> {
    Ok(vault.op().read(reference)?.into_text()?.expose().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{fake_vault, FakeRunner, Output};

    #[test]
    fn put_document_edits_an_existing_document_in_one_call() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(""));
        put_document(&fake_vault(&fake), "CA_Database", "ca-db-export.sql", &"x".repeat(200 * 1024)).unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(&calls[0].args()[..3], ["document", "edit", "CA_Database"]);
        assert!(calls[0].args().contains(&"--file-name=ca-db-export.sql".to_string()));
        assert_eq!(calls[0].stdin(), None);
        assert_eq!(fake.files(), [b"x".repeat(200 * 1024)]);
    }

    #[test]
    fn put_document_creates_a_missing_document() {
        let fake = FakeRunner::new();
        fake.respond(Output::fail("[ERROR] \"CRL\" isn't an item in the \"TestVault\" vault."))
            .respond(Output::ok(""));
        put_document(&fake_vault(&fake), "CRL", "crl.pem", "pem").unwrap();

        let calls = fake.calls();
        assert_eq!(&calls[1].args()[..2], ["document", "create"]);
        assert!(calls[1].args().contains(&"--title=CRL".to_string()));
    }

    #[test]
    fn put_item_edits_and_creates_only_a_missing_item() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(""))
            .respond(Output::fail("[ERROR] \"OpenVPN\" isn't an item in the \"TestVault\" vault."))
            .respond(crate::testutil::created("OpenVPN"));
        let vault = fake_vault(&fake);
        let fields = [assign("server.port[text]", 1194).unwrap()];
        put_item(&vault, "OpenVPN", "Secure Note", &fields).unwrap();
        put_item(&vault, "OpenVPN", "Secure Note", &fields).unwrap();

        let verbs: Vec<_> = fake.calls().iter().map(|c| c.args()[1].clone()).collect();
        assert_eq!(verbs, ["edit", "edit", "create"]);
        assert!(fake.calls()[2].stdin().is_some());
    }

    #[test]
    fn put_document_does_not_create_over_any_other_failure() {
        let fake = FakeRunner::new();
        fake.respond(Output::fail("[ERROR] You are not currently signed in."));
        let err = put_document(&fake_vault(&fake), "CRL", "crl.pem", "pem").unwrap_err();
        assert!(matches!(err, OpcaError::AuthenticationFailed));
        assert_eq!(fake.calls().len(), 1);
    }

    const CONFLICT: &str = "[ERROR] 2026/10/23 12:41:55 unable to process line 1: Network: (DB: (409) (Conflict), \
                            Internal server conflict.), DB: (409) (Conflict), Internal server conflict.";

    fn retrying_vault(fake: &FakeRunner) -> Vault<RetryOnConflict<FakeRunner>> {
        client(RetryOnConflict(fake.clone()), None).vault(fake_vault(fake).info().clone())
    }

    #[test]
    fn a_write_refused_by_a_racing_write_is_made_once_more() {
        let fake = FakeRunner::new();
        fake.respond(Output::fail(CONFLICT)).respond(crate::testutil::created("CRT_1_a"));
        let fields = [assign("cn[text]", "host.example.com").unwrap()];
        retrying_vault(&fake).create_item("CRT_1_a", "Secure Note", &fields).unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|c| c.args()[..2] == ["item", "create"]));
    }

    #[test]
    fn a_second_write_conflict_surfaces() {
        let fake = FakeRunner::new();
        fake.respond(Output::fail(CONFLICT)).respond(Output::fail(CONFLICT));
        let fields = [assign("cn[text]", "host.example.com").unwrap()];
        let err = retrying_vault(&fake).edit_item(&ItemRef::title("CRT_1_a"), &fields).unwrap_err();

        assert!(matches!(err, Error::WriteConflict(_)));
        assert_eq!(fake.calls().len(), 2);
    }

    #[test]
    fn create_vault_refuses_a_name_in_use_ignoring_case() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok(r#"[{"id":"abc123","name":"Café"}]"#));
        let err = create_vault(&client(fake.clone(), None), " CAFÉ ").unwrap_err();
        assert!(matches!(err, OpcaError::VaultAlreadyExists(name) if name == "CAFÉ"));
        assert_eq!(fake.calls().len(), 1);
    }

    #[test]
    fn create_vault_makes_a_new_name() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok("[]")).respond(Output::ok(r#"{"id":"v9","name":"New CA"}"#));
        assert_eq!(create_vault(&client(fake.clone(), None), "New CA").unwrap().id, "v9");
    }

    #[test]
    fn an_empty_vault_name_is_refused_unsent() {
        let fake = FakeRunner::new();
        assert!(matches!(connect(fake.clone(), " ", None), Err(OpcaError::VaultNotFound(_))));
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn a_vault_op_cannot_name_is_vault_not_found() {
        let fake = FakeRunner::new();
        fake.respond(Output::ok("{}")).respond(Output::fail("[ERROR] something odd"));
        let err = connect(fake.clone(), "Private CA", Some("test.1password.com")).unwrap_err();
        assert!(matches!(err, OpcaError::VaultNotFound(m) if m.contains("Private CA")));
        assert!(fake.calls().iter().all(|c| c.args().ends_with(&["--account".into(), "test.1password.com".into()])));
    }

    #[test]
    fn an_assignment_keeps_the_conf_label_whole() {
        let a = assign("diffie-hellman.key_size[text]", 2048).unwrap();
        assert_eq!(a.shown(), "diffie-hellman.key_size[text]=<redacted>");
    }
}
