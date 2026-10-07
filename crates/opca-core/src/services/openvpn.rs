//! OpenVPN client-profile templates, stored canonically in the CA database.

use log::info;

use crate::constants::DEFAULT_OP_CONF;
use crate::error::OpcaError;
use crate::op::{CommandRunner, Op, StoreAction};
use crate::services::ca::CertificateAuthority;
use crate::services::database::{CertificateAuthorityDB, OpenVpnTemplate, TemplateImport};
use crate::utils::datetime::{self, DateTimeFormat};

/// The starter client template, written with `op://` references that
/// `op inject` resolves against the vault when a profile is generated.
pub fn template_boilerplate(vault: &str) -> String {
    let ovpn = DEFAULT_OP_CONF.openvpn_title;
    let ca_title = DEFAULT_OP_CONF.ca_title;
    let cert_item = DEFAULT_OP_CONF.cert_item;
    let key_item = DEFAULT_OP_CONF.key_item;
    // ta_item is "tls_authentication.static_key"; op:// uses "/" as the separator.
    let ta_path = DEFAULT_OP_CONF.ta_item.replace('.', "/");

    format!(
        r#"#
# Client - {{{{ op://{vault}/$OPCA_USER/cn }}}}
#

# Brought to you by Wired Square - www.wiredsquare.com

client
dev tun
proto udp
remote {{{{ op://{vault}/{ovpn}/server/hostname }}}} {{{{ op://{vault}/{ovpn}/server/port }}}}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher {{{{ op://{vault}/{ovpn}/server/cipher }}}}
auth {{{{ op://{vault}/{ovpn}/server/auth }}}}
verb 3
key-direction 1
mssfix 1300
<ca>
{{{{ op://{vault}/{ca_title}/{cert_item} }}}}
</ca>
<cert>
{{{{ op://{vault}/$OPCA_USER/{cert_item} }}}}
</cert>
<key>
{{{{ op://{vault}/$OPCA_USER/{key_item} }}}}
</key>
<tls-auth>
{{{{ op://{vault}/{ovpn}/{ta_path} }}}}
</tls-auth>
"#
    )
}

/// Template fields (`template` section) of the 1Password `OpenVPN` item's JSON.
fn templates_in_item(item_json: &str) -> Result<Vec<(String, String)>, OpcaError> {
    let item: serde_json::Value = serde_json::from_str(item_json)
        .map_err(|e| OpcaError::Other(format!("Unreadable OpenVPN item: {e}")))?;

    Ok(item["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["section"]["label"].as_str() == Some("template"))
        .filter_map(|f| {
            let label = f["label"].as_str().filter(|l| !l.is_empty())?;
            let content = f["value"].as_str().unwrap_or_default().trim();
            Some((label.to_string(), content.to_string()))
        })
        .collect())
}

fn database<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
) -> Result<&mut CertificateAuthorityDB, OpcaError> {
    ca.ca_database
        .as_mut()
        .ok_or_else(|| OpcaError::Other("Database not loaded".into()))
}

fn vault_templates<R: CommandRunner>(op: &Op<R>) -> Result<Vec<(String, String)>, OpcaError> {
    let title = DEFAULT_OP_CONF.openvpn_title;
    if !op.item_exists(title) {
        return Ok(Vec::new());
    }
    templates_in_item(&op.get_item(title, "json")?)
}

fn set_import_state<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
    state: TemplateImport,
) -> Result<(), OpcaError> {
    database(ca)?.set_openvpn_template_import(state)?;
    ca.store_ca_database()
}

/// Copy the templates that older versions kept on the 1Password `OpenVPN` item
/// into the database, once per CA. The item's template fields stay put until
/// an operator archives or keeps them.
///
/// Returns the number of templates imported, or `None` if the import had
/// already run.
pub fn import_templates_from_vault<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
) -> Result<Option<usize>, OpcaError> {
    if database(ca)?.openvpn_template_import()? != TemplateImport::NotImported {
        return Ok(None);
    }

    let found = vault_templates(&ca.op)?;
    let db = database(ca)?;
    for (name, content) in &found {
        db.upsert_openvpn_template(name, content, None)?;
    }
    let state = if found.is_empty() {
        TemplateImport::Settled
    } else {
        TemplateImport::AwaitingCleanup
    };
    set_import_state(ca, state)?;

    info!("[openvpn] imported {} template(s) from 1Password", found.len());
    Ok(Some(found.len()))
}

/// Add any 1Password template the database lacks — e.g. one an older client
/// created after the import — without overwriting the database's copies.
fn copy_missing_templates<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
    found: &[(String, String)],
) -> Result<(), OpcaError> {
    let db = database(ca)?;
    let mut copied = false;
    for (name, content) in found {
        if db.get_openvpn_template(name)?.is_none() {
            db.upsert_openvpn_template(name, content, None)?;
            copied = true;
        }
    }
    if copied {
        ca.store_ca_database()?;
    }
    Ok(())
}

/// After a successful import, the template fields still on the 1Password
/// `OpenVPN` item — each confirmed present in the database — for an operator
/// to archive or keep. Empty once that decision is made.
pub fn templates_awaiting_cleanup<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
) -> Result<Vec<String>, OpcaError> {
    if database(ca)?.openvpn_template_import()? != TemplateImport::AwaitingCleanup {
        return Ok(Vec::new());
    }

    let found = vault_templates(&ca.op)?;
    if found.is_empty() {
        set_import_state(ca, TemplateImport::Settled)?;
        return Ok(Vec::new());
    }
    copy_missing_templates(ca, &found)?;
    Ok(found.into_iter().map(|(name, _)| name).collect())
}

/// Move the old template fields off the 1Password `OpenVPN` item into a new,
/// archived Secure Note, so they can be restored from 1Password's Archive.
/// 1Password archives whole items, and the `OpenVPN` item also holds the DH
/// parameters, TLS-auth key and server settings, so it can't be archived itself.
///
/// Returns the number of templates archived.
pub fn archive_vault_templates<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
) -> Result<usize, OpcaError> {
    let found = vault_templates(&ca.op)?;
    if !found.is_empty() {
        copy_missing_templates(ca, &found)?;
        let openvpn_title = DEFAULT_OP_CONF.openvpn_title;
        let archive_title = format!(
            "{openvpn_title}_Templates_{}",
            datetime::now_utc_str(DateTimeFormat::Openssl)
        );
        let copies: Vec<String> = found
            .iter()
            .map(|(name, content)| format!("template.{name}[text]={content}"))
            .collect();
        let removals: Vec<String> = found
            .iter()
            .map(|(name, _)| format!("template.{name}[delete]"))
            .collect();

        // Copy and archive before removing, so a failure part-way never loses a template.
        store_fields(&ca.op, &archive_title, &copies, StoreAction::Create)?;
        ca.op.delete_item(&archive_title, true)?;
        store_fields(&ca.op, openvpn_title, &removals, StoreAction::Edit)?;
        info!("[openvpn] archived {} template(s) as '{archive_title}'", found.len());
    }

    set_import_state(ca, TemplateImport::Settled)?;
    Ok(found.len())
}

/// Leave the old template fields on the 1Password `OpenVPN` item and stop asking.
pub fn keep_vault_templates<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
) -> Result<(), OpcaError> {
    set_import_state(ca, TemplateImport::Settled)
}

fn store_fields<R: CommandRunner>(
    op: &Op<R>,
    title: &str,
    fields: &[String],
    action: StoreAction,
) -> Result<(), OpcaError> {
    let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
    op.store_item(title, Some(&refs), action, DEFAULT_OP_CONF.category, None, None)?;
    Ok(())
}

/// The database, once any templates still on the 1Password item are imported,
/// so a write can't later be overwritten by the import.
fn templates_db<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
) -> Result<&mut CertificateAuthorityDB, OpcaError> {
    import_templates_from_vault(ca)?;
    database(ca)
}

pub fn list_templates<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
) -> Result<Vec<OpenVpnTemplate>, OpcaError> {
    templates_db(ca)?.query_all_openvpn_templates()
}

pub fn get_template<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
    name: &str,
) -> Result<OpenVpnTemplate, OpcaError> {
    templates_db(ca)?
        .get_openvpn_template(name)?
        .ok_or_else(|| OpcaError::Other(format!("OpenVPN template '{name}' not found")))
}

pub fn save_template<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
    name: &str,
    content: &str,
) -> Result<(), OpcaError> {
    templates_db(ca)?.upsert_openvpn_template(name, content, None)?;
    ca.store_ca_database()
}

/// Add the starter template under `name` unless one exists. Returns whether it was added.
pub fn add_starter_template<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
    name: &str,
) -> Result<bool, OpcaError> {
    if templates_db(ca)?.get_openvpn_template(name)?.is_some() {
        return Ok(false);
    }
    let content = template_boilerplate(&ca.op.vault);
    save_template(ca, name, &content)?;
    Ok(true)
}

/// Returns whether a template of that name existed.
pub fn delete_template<R: CommandRunner>(
    ca: &mut CertificateAuthority<R>,
    name: &str,
) -> Result<bool, OpcaError> {
    if !templates_db(ca)?.delete_openvpn_template(name)? {
        return Ok(false);
    }
    ca.store_ca_database()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::database::models::CaConfig;
    use crate::testutil::{err_output, mock_op, ok_output, MockRunner};

    const ITEM_JSON: &str = r#"{
        "fields": [
            {"label": "hostname", "value": "vpn.example.com", "section": {"label": "server"}},
            {"label": "default", "value": "client\ndev tun\n", "section": {"label": "template"}},
            {"label": "tcp", "value": "client\nproto tcp", "section": {"label": "template"}},
            {"label": "static_key", "value": "secret", "section": {"label": "tls_authentication"}}
        ]
    }"#;

    fn ca(responses: Vec<crate::op::CommandOutput>) -> CertificateAuthority<MockRunner> {
        CertificateAuthority {
            op: mock_op(responses),
            op_config: DEFAULT_OP_CONF,
            ca_bundle: None,
            ca_database: Some(CertificateAuthorityDB::new(&CaConfig::default()).unwrap()),
            crl: None,
            local_backup: None,
        }
    }

    #[test]
    fn only_template_section_fields_are_templates() {
        assert_eq!(
            templates_in_item(ITEM_JSON).unwrap(),
            vec![
                ("default".to_string(), "client\ndev tun".to_string()),
                ("tcp".to_string(), "client\nproto tcp".to_string()),
            ]
        );
    }

    fn db(ca: &CertificateAuthority<MockRunner>) -> &CertificateAuthorityDB {
        ca.ca_database.as_ref().unwrap()
    }

    #[test]
    fn import_copies_vault_templates_once_and_awaits_cleanup() {
        let mut ca = ca(vec![ok_output(ITEM_JSON), ok_output(ITEM_JSON)]);

        assert_eq!(import_templates_from_vault(&mut ca).unwrap(), Some(2));
        assert_eq!(get_template(&mut ca, "tcp").unwrap().content, "client\nproto tcp");
        assert_eq!(db(&ca).openvpn_template_import().unwrap(), TemplateImport::AwaitingCleanup);

        let calls_after_import = ca.op.runner().calls().len();
        assert_eq!(import_templates_from_vault(&mut ca).unwrap(), None);
        assert_eq!(ca.op.runner().calls().len(), calls_after_import);
    }

    #[test]
    fn import_without_an_openvpn_item_has_nothing_to_clean_up() {
        let mut ca = ca(vec![err_output("isn't an item")]);

        assert_eq!(import_templates_from_vault(&mut ca).unwrap(), Some(0));
        assert_eq!(db(&ca).openvpn_template_import().unwrap(), TemplateImport::Settled);
    }

    #[test]
    fn import_keeps_templates_already_in_the_database() {
        let mut ca = ca(vec![ok_output(ITEM_JSON), ok_output(ITEM_JSON)]);
        db(&ca).upsert_openvpn_template("db-only", "client", None).unwrap();

        import_templates_from_vault(&mut ca).unwrap();

        assert_eq!(get_template(&mut ca, "db-only").unwrap().content, "client");
    }

    #[test]
    fn archive_copies_to_an_archived_note_before_removing_the_fields() {
        let mut ca = ca(vec![ok_output(ITEM_JSON), ok_output(ITEM_JSON)]);

        assert_eq!(archive_vault_templates(&mut ca).unwrap(), 2);

        let calls = ca.op.runner().calls();
        let position = |pred: &dyn Fn(&Vec<String>) -> bool| calls.iter().position(pred).unwrap();
        let created = position(&|c| {
            c[1] == "create"
                && c[2].starts_with("--title=OpenVPN_Templates_")
                && c.contains(&"template.tcp[text]=client\nproto tcp".to_string())
        });
        let archived = position(&|c| c[1] == "delete" && c.contains(&"--archive".to_string()));
        let removed = position(&|c| {
            c[1] == "edit"
                && c[2] == "OpenVPN"
                && c.contains(&"template.default[delete]".to_string())
                && c.contains(&"template.tcp[delete]".to_string())
        });
        assert!(created < archived && archived < removed);
        assert_eq!(db(&ca).openvpn_template_import().unwrap(), TemplateImport::Settled);
    }

    #[test]
    fn cleanup_is_only_offered_after_a_successful_import() {
        let mut ca = ca(vec![]);

        assert!(templates_awaiting_cleanup(&mut ca).unwrap().is_empty());
        assert!(ca.op.runner().calls().is_empty());
    }

    #[test]
    fn cleanup_lists_vault_templates_and_copies_any_the_database_lacks() {
        let mut ca = ca(vec![ok_output(ITEM_JSON), ok_output(ITEM_JSON)]);
        db(&ca).upsert_openvpn_template("default", "edited since import", None).unwrap();
        db(&ca).set_openvpn_template_import(TemplateImport::AwaitingCleanup).unwrap();

        assert_eq!(templates_awaiting_cleanup(&mut ca).unwrap(), vec!["default", "tcp"]);
        assert_eq!(get_template(&mut ca, "default").unwrap().content, "edited since import");
        assert_eq!(get_template(&mut ca, "tcp").unwrap().content, "client\nproto tcp");
    }

    #[test]
    fn cleanup_settles_once_the_vault_holds_no_templates() {
        let mut ca = ca(vec![err_output("isn't an item")]);
        db(&ca).set_openvpn_template_import(TemplateImport::AwaitingCleanup).unwrap();

        assert!(templates_awaiting_cleanup(&mut ca).unwrap().is_empty());
        assert_eq!(db(&ca).openvpn_template_import().unwrap(), TemplateImport::Settled);
    }

    #[test]
    fn keep_leaves_the_vault_untouched() {
        let mut ca = ca(vec![]);

        keep_vault_templates(&mut ca).unwrap();

        let touched_vault = |c: &Vec<String>| c.iter().any(|a| a.ends_with("[delete]") || a == "--archive");
        assert!(!ca.op.runner().calls().iter().any(touched_vault));
        assert_eq!(db(&ca).openvpn_template_import().unwrap(), TemplateImport::Settled);
    }

    #[test]
    fn a_save_before_the_import_is_not_overwritten_by_it() {
        let mut ca = ca(vec![ok_output(ITEM_JSON), ok_output(ITEM_JSON)]);

        save_template(&mut ca, "tcp", "saved after the move").unwrap();

        assert_eq!(get_template(&mut ca, "tcp").unwrap().content, "saved after the move");
    }

    #[test]
    fn the_starter_template_never_replaces_an_existing_one() {
        let mut ca = ca(vec![err_output("isn't an item")]);
        save_template(&mut ca, "default", "client").unwrap();

        assert!(!add_starter_template(&mut ca, "default").unwrap());
        assert!(add_starter_template(&mut ca, "udp").unwrap());
        assert_eq!(get_template(&mut ca, "default").unwrap().content, "client");
        assert!(get_template(&mut ca, "udp").unwrap().content.contains("op://TestVault/OpenVPN/server/hostname"));
    }

    #[test]
    fn delete_reports_whether_the_template_existed() {
        let mut ca = ca(vec![err_output("isn't an item")]);
        save_template(&mut ca, "default", "client").unwrap();

        assert!(delete_template(&mut ca, "default").unwrap());
        assert!(!delete_template(&mut ca, "default").unwrap());
        assert!(get_template(&mut ca, "default").is_err());
    }
}
