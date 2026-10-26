//! A scripted `op` and the CA vault it answers for.

pub use wslib_1password::Output;
pub use wslib_1password::testing::FakeRunner;

use crate::op::{Vault, VaultInfo};

pub const VAULT_ID: &str = "testvault";

pub fn fake_vault(fake: &FakeRunner) -> Vault<FakeRunner> {
    crate::op::client(fake.clone(), None).vault(VaultInfo {
        id: VAULT_ID.into(),
        name: "TestVault".into(),
    })
}

/// A 26-character item id, as `op` gives, distinct for each `n`.
pub fn item_id(n: u32) -> String {
    format!("{n:0>26}")
}

/// `op item get --format=json` for an item with these `(label, value)` fields.
pub fn item_json(title: &str, fields: &[(&str, &str)]) -> String {
    item_with_sections(
        title,
        &fields
            .iter()
            .map(|&(l, v)| (None, l, v))
            .collect::<Vec<_>>(),
    )
}

/// [`item_json`] with each field in an optional section.
pub fn item_with_sections(title: &str, fields: &[(Option<&str>, &str, &str)]) -> String {
    let fields: Vec<_> = fields
        .iter()
        .map(|(section, label, value)| {
            let mut field = serde_json::json!({ "label": label, "value": value, "type": "STRING" });
            if let Some(section) = section {
                field["section"] = serde_json::json!({ "id": section, "label": section });
            }
            field
        })
        .collect();
    serde_json::json!({
        "id": item_id(1),
        "title": title,
        "vault": { "id": VAULT_ID, "name": "TestVault" },
        "fields": fields,
    })
    .to_string()
}

/// What `op item create --format=json` answers.
pub fn created(title: &str) -> Output {
    Output::ok(summary_json(&item_id(1), title))
}

pub fn summary_json(id: &str, title: &str) -> String {
    serde_json::json!({ "id": id, "title": title, "vault": { "id": VAULT_ID, "name": "TestVault" } })
        .to_string()
}

pub fn not_found(title: &str) -> Output {
    Output::fail(format!(
        "[ERROR] \"{title}\" isn't an item in the \"TestVault\" vault."
    ))
}
