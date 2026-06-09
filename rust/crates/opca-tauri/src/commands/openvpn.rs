use std::collections::HashMap;

use chrono::Utc;
use log::info;
use tauri::State;

use opca_core::constants::{DEFAULT_KEY_SIZE, DEFAULT_OP_CONF};
use opca_core::crypto::utils::{generate_dh_params, generate_ta_key, verify_dh_params, verify_ta_key};
use opca_core::op::StoreAction;
use opca_core::services::cert::CertType;
use opca_core::services::database::models::OpenVpnProfile;
use opca_core::services::database::CertLookup;

use crate::commands::cert::cert_list_item;
use crate::commands::dto::{
    CertListItem, GenerateProfileRequest, OpenVpnProfileItem, OpenVpnServerParams,
    OpenVpnTemplateDetail, OpenVpnTemplateItem, ServerSetupRequest,
};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read all field labels and values from the OpenVPN 1Password item.
fn read_openvpn_fields(
    op: &opca_core::op::Op,
) -> Result<(bool, HashMap<String, String>), String> {
    let title = DEFAULT_OP_CONF.openvpn_title;
    if !op.item_exists(title) {
        return Ok((false, HashMap::new()));
    }

    let json_str = op
        .get_item(title, "json")
        .map_err(|e| e.to_string())?;

    let item: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| e.to_string())?;

    let mut fields = HashMap::new();
    if let Some(arr) = item["fields"].as_array() {
        for field in arr {
            let label = field["label"].as_str().unwrap_or_default();
            let value = field["value"].as_str().unwrap_or_default();
            if !label.is_empty() {
                fields.insert(label.to_string(), value.to_string());
            }
        }
    }

    Ok((true, fields))
}

/// Read every template (name + content) from the OpenVPN 1Password item in a
/// single `get_item` JSON parse. Templates are `[text]` fields under the
/// "template" section, so each field's value *is* its content — no per-template
/// `op read` spawn needed (the same optimisation `backfill_dkim` uses).
fn read_openvpn_templates(op: &opca_core::op::Op) -> Result<Vec<(String, String)>, String> {
    let title = DEFAULT_OP_CONF.openvpn_title;
    if !op.item_exists(title) {
        return Ok(Vec::new());
    }

    let json_str = op
        .get_item(title, "json")
        .map_err(|e| e.to_string())?;

    let item: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| e.to_string())?;

    let mut templates = Vec::new();
    if let Some(arr) = item["fields"].as_array() {
        for field in arr {
            let label = field["label"].as_str().unwrap_or_default();
            let section_label = field["section"]["label"].as_str().unwrap_or_default();
            if section_label == "template" && !label.is_empty() {
                let content = field["value"].as_str().unwrap_or_default().trim().to_string();
                templates.push((label.to_string(), content));
            }
        }
    }

    templates.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(templates)
}

/// Determine create vs edit action for the OpenVPN item.
fn resolve_store_action(op: &opca_core::op::Op) -> StoreAction {
    if op.item_exists(DEFAULT_OP_CONF.openvpn_title) {
        StoreAction::Edit
    } else {
        StoreAction::Create
    }
}

/// Build the boilerplate template with op:// references.
fn build_template_boilerplate(vault: &str) -> String {
    let ovpn = DEFAULT_OP_CONF.openvpn_title;
    let ca_title = DEFAULT_OP_CONF.ca_title;
    let cert_item = DEFAULT_OP_CONF.cert_item;
    let key_item = DEFAULT_OP_CONF.key_item;

    // ta_item is "tls_authentication.static_key" — op:// uses "/" separator
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

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Get OpenVPN server parameters (DH, TA, server config) from 1Password.
#[tauri::command]
pub async fn get_openvpn_params(
    state: State<'_, AppState>,
) -> Result<OpenVpnServerParams, String> {
    state.with_op(|op| {
        let (has_item, fields) = read_openvpn_fields(op)?;

        Ok(OpenVpnServerParams {
            has_item,
            has_dh: fields.contains_key("dh_parameters"),
            dh_key_size: fields.get("key_size").cloned().or_else(|| {
                // DH key_size is in the diffie-hellman section
                // Try reading via op:// if present
                if fields.contains_key("dh_parameters") {
                    let url = op.mk_url(
                        DEFAULT_OP_CONF.openvpn_title,
                        Some(&DEFAULT_OP_CONF.dh_key_size_item.replace('.', "/")),
                    );
                    op.read_item(&url).ok().map(|s| s.trim().to_string())
                } else {
                    None
                }
            }),
            has_ta: fields.contains_key("static_key"),
            ta_key_size: if fields.contains_key("static_key") {
                let url = op.mk_url(
                    DEFAULT_OP_CONF.openvpn_title,
                    Some(&DEFAULT_OP_CONF.ta_key_size_item.replace('.', "/")),
                );
                op.read_item(&url).ok().map(|s| s.trim().to_string())
            } else {
                None
            },
            hostname: fields.get("hostname").cloned(),
            port: fields.get("port").cloned(),
            cipher: fields.get("cipher").cloned(),
            auth: fields.get("auth").cloned(),
        })
    })
}

/// Generate DH parameters and store in 1Password.
#[tauri::command]
pub async fn generate_openvpn_dh(
    state: State<'_, AppState>,
) -> Result<OpenVpnServerParams, String> {
    info!("[tauri] generate_openvpn_dh");
    state.with_op(|op| {
        let dh_pem = generate_dh_params(DEFAULT_KEY_SIZE.dh)
            .map_err(|e| format!("Failed to generate DH parameters: {e}"))?;

        let dh_keysize = verify_dh_params(dh_pem.as_bytes())
            .map_err(|e| format!("Failed to verify DH parameters: {e}"))?;

        if dh_keysize < DEFAULT_KEY_SIZE.dh {
            return Err("Generated DH parameters do not meet minimum key size".to_string());
        }

        let action = resolve_store_action(op);
        let attrs: Vec<String> = vec![
            format!("{}={}", DEFAULT_OP_CONF.dh_item, dh_pem),
            format!("{}={}", DEFAULT_OP_CONF.dh_key_size_item, dh_keysize),
        ];
        let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

        op.store_item(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&attr_refs),
            action,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )
        .map_err(|e| format!("Failed to store DH parameters: {e}"))?;

        // Re-read full state
        let (has_item, fields) = read_openvpn_fields(op)?;
        Ok(OpenVpnServerParams {
            has_item,
            has_dh: true,
            dh_key_size: Some(dh_keysize.to_string()),
            has_ta: fields.contains_key("static_key"),
            ta_key_size: None,
            hostname: fields.get("hostname").cloned(),
            port: fields.get("port").cloned(),
            cipher: fields.get("cipher").cloned(),
            auth: fields.get("auth").cloned(),
        })
    })?;

    state.log_ok("generate_dh", Some("Generated DH parameters".to_string()));
    get_openvpn_params(state).await
}

/// Generate TLS Authentication key and store in 1Password.
#[tauri::command]
pub async fn generate_openvpn_ta(
    state: State<'_, AppState>,
) -> Result<OpenVpnServerParams, String> {
    info!("[tauri] generate_openvpn_ta");
    state.with_op(|op| {
        let ta_pem = generate_ta_key(DEFAULT_KEY_SIZE.ta)
            .map_err(|e| format!("Failed to generate TA key: {e}"))?;

        let ta_keysize = verify_ta_key(ta_pem.as_bytes())
            .map_err(|e| format!("Failed to verify TA key: {e}"))?;

        if ta_keysize < DEFAULT_KEY_SIZE.ta {
            return Err("Generated TA key does not meet minimum key size".to_string());
        }

        let action = resolve_store_action(op);
        let attrs: Vec<String> = vec![
            format!("{}={}", DEFAULT_OP_CONF.ta_item, ta_pem),
            format!("{}={}", DEFAULT_OP_CONF.ta_key_size_item, ta_keysize),
        ];
        let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

        op.store_item(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&attr_refs),
            action,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )
        .map_err(|e| format!("Failed to store TA key: {e}"))?;

        Ok(())
    })?;

    state.log_ok("generate_ta", Some("Generated TLS Authentication key".to_string()));
    get_openvpn_params(state).await
}

/// Set up the OpenVPN server object (server config, DH, TA, template).
/// Only writes fields that do not already exist.
#[tauri::command]
pub async fn setup_openvpn_server(
    state: State<'_, AppState>,
    request: ServerSetupRequest,
) -> Result<OpenVpnServerParams, String> {
    let template_name = request.template_name;

    info!("[tauri] setup_openvpn_server: template='{template_name}'");
    state.with_op(|op| {
        let (item_exists, fields) = read_openvpn_fields(op)?;
        let mut attrs: Vec<String> = Vec::new();

        // Server defaults — only add if missing
        if !fields.contains_key("hostname") {
            attrs.push("server.hostname[text]=vpn.domain.com.au".to_string());
        }
        if !fields.contains_key("port") {
            attrs.push("server.port[text]=1194".to_string());
        }
        if !fields.contains_key("cipher") {
            attrs.push("server.cipher[text]=aes-256-gcm".to_string());
        }
        if !fields.contains_key("auth") {
            attrs.push("server.auth[text]=sha256".to_string());
        }

        // Template — only add if this specific template doesn't exist
        if !fields.contains_key(&template_name) {
            let boilerplate = build_template_boilerplate(&op.vault);
            attrs.push(format!("template.{template_name}[text]={boilerplate}"));
        }

        // DH parameters — generate if missing
        if !fields.contains_key("dh_parameters") {
            let dh_pem = generate_dh_params(DEFAULT_KEY_SIZE.dh)
                .map_err(|e| format!("Failed to generate DH parameters: {e}"))?;
            let dh_keysize = verify_dh_params(dh_pem.as_bytes())
                .map_err(|e| format!("Failed to verify DH parameters: {e}"))?;
            attrs.push(format!("{}={}", DEFAULT_OP_CONF.dh_item, dh_pem));
            attrs.push(format!("{}={}", DEFAULT_OP_CONF.dh_key_size_item, dh_keysize));
        }

        // TA key — generate if missing
        if !fields.contains_key("static_key") {
            let ta_pem = generate_ta_key(DEFAULT_KEY_SIZE.ta)
                .map_err(|e| format!("Failed to generate TA key: {e}"))?;
            let ta_keysize = verify_ta_key(ta_pem.as_bytes())
                .map_err(|e| format!("Failed to verify TA key: {e}"))?;
            attrs.push(format!("{}={}", DEFAULT_OP_CONF.ta_item, ta_pem));
            attrs.push(format!("{}={}", DEFAULT_OP_CONF.ta_key_size_item, ta_keysize));
        }

        if attrs.is_empty() {
            return Ok(());
        }

        let action = if item_exists {
            StoreAction::Edit
        } else {
            StoreAction::Create
        };

        let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();
        op.store_item(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&attr_refs),
            action,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )
        .map_err(|e| format!("Failed to store OpenVPN configuration: {e}"))?;

        Ok(())
    })?;

    // Mirror the (possibly newly created) template into the DB so it shows up
    // in the picker without a manual refresh.
    do_sync_openvpn_templates(&state)?;

    state.log_ok(
        "setup_openvpn",
        Some(format!("OpenVPN server setup complete (template: {template_name})")),
    );
    get_openvpn_params(state).await
}

/// Pull every template field out of the OpenVPN 1Password item and mirror it
/// into the `openvpn_template` table, reconciling deletions, then persist the
/// DB. Mirrors `do_sync_dkim_keys` — used once when the table is first found
/// empty, and behind the Configuration tab's Refresh button.
fn do_sync_openvpn_templates(state: &State<'_, AppState>) -> Result<usize, String> {
    info!("[tauri] sync_openvpn_templates");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let found = read_openvpn_templates(&ca.op)?;

    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    let mut changed = false;
    for (name, content) in &found {
        db.upsert_openvpn_template(name, content, None)
            .map_err(|e| e.to_string())?;
        changed = true;
    }

    // Reconcile deletions: drop DB rows whose template field no longer exists
    // on the 1Password item.
    let live: std::collections::HashSet<&str> =
        found.iter().map(|(n, _)| n.as_str()).collect();
    for existing in db.query_all_openvpn_templates().map_err(|e| e.to_string())? {
        if !live.contains(existing.name.as_str()) {
            db.delete_openvpn_template(&existing.name)
                .map_err(|e| e.to_string())?;
            changed = true;
        }
    }

    // Only re-upload the DB when the mirror actually moved. A CA with no
    // templates would otherwise upload on every Profiles load (the table stays
    // empty, so the sync-on-empty fires each time).
    if changed {
        ca.store_ca_database().map_err(|e| {
            state.log_err("sync_openvpn_templates", Some(e.to_string()));
            e.to_string()
        })?;
    }

    Ok(found.len())
}

/// Re-sync templates from 1Password (Configuration tab Refresh).
#[tauri::command]
pub async fn sync_openvpn_templates(state: State<'_, AppState>) -> Result<usize, String> {
    let count = do_sync_openvpn_templates(&state)?;
    state.log_ok(
        "sync_templates",
        Some(format!("Synced {count} OpenVPN template(s) from 1Password")),
    );
    Ok(count)
}

/// List templates from the local DB mirror (no `op` round-trip). On first call
/// after the table is created, seeds it from 1Password so the dropdown is
/// populated immediately — the lazy `op`-backed fetch was what left the picker
/// empty on a deep-link.
#[tauri::command]
pub async fn list_openvpn_templates(
    state: State<'_, AppState>,
) -> Result<Vec<OpenVpnTemplateItem>, String> {
    let needs_sync = {
        let conn = state.ensure_ca()?;
        conn.db()?.count_openvpn_template().map_err(|e| e.to_string())? == 0
    };

    if needs_sync {
        do_sync_openvpn_templates(&state)?;
    }

    let conn = state.ensure_ca()?;
    Ok(conn
        .db()?
        .query_all_openvpn_templates()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|t| OpenVpnTemplateItem {
            name: t.name,
            updated_date: t.updated_date,
        })
        .collect())
}

/// Read a specific template's content from the local DB mirror, falling back to
/// 1Password if the row is missing (e.g. created by an older client).
#[tauri::command]
pub async fn get_openvpn_template(
    state: State<'_, AppState>,
    name: String,
) -> Result<OpenVpnTemplateDetail, String> {
    {
        let conn = state.ensure_ca()?;
        if let Some(t) = conn.db()?.get_openvpn_template(&name).map_err(|e| e.to_string())? {
            return Ok(OpenVpnTemplateDetail {
                name: t.name,
                content: t.content,
                updated_date: t.updated_date,
            });
        }
    }

    state.with_op(|op| {
        let url = op.mk_url(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&format!("template/{name}")),
        );
        let content = op
            .read_item(&url)
            .map_err(|e| format!("Template '{name}' not found: {e}"))?;

        Ok(OpenVpnTemplateDetail {
            name,
            content: content.trim().to_string(),
            updated_date: None,
        })
    })
}

/// Save template content to the OpenVPN 1Password item and the DB mirror.
#[tauri::command]
pub async fn save_openvpn_template(
    state: State<'_, AppState>,
    name: String,
    content: String,
) -> Result<bool, String> {
    if name.is_empty() {
        return Err("Template name is required".to_string());
    }
    if content.is_empty() {
        return Err("Template content is required".to_string());
    }

    info!("[tauri] save_openvpn_template: name='{name}'");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let attrs = vec![format!("template.{name}[text]={content}")];
    let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();
    ca.op
        .store_item(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&attr_refs),
            StoreAction::Edit,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )
        .map_err(|e| format!("Failed to save template: {e}"))?;

    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    db.upsert_openvpn_template(&name, &content, None)
        .map_err(|e| e.to_string())?;
    ca.store_ca_database().map_err(|e| {
        state.log_err("save_template", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok(
        "save_template",
        Some(format!("Saved OpenVPN template '{name}'")),
    );
    Ok(true)
}

/// List valid VPN certificates (cert_type "vpnclient" or "vpnserver", status
/// "valid"), enriched with serial / expiry / expiring-soon so the picker can
/// render a coloured serial badge per row. The Add-profile flow infers the
/// profile's client/server type from the chosen cert's `cert_type`. Renewal
/// duplicates (two valid certs sharing a CN) are both returned; rows sort by CN,
/// then serial descending so the current (highest-serial) cert leads within a
/// duplicated CN.
#[tauri::command]
pub async fn list_vpn_certs(
    state: State<'_, AppState>,
) -> Result<Vec<CertListItem>, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca
        .ca_database
        .as_mut()
        .ok_or("Database not loaded")?;

    db.process_ca_database(None, false).map_err(|e| e.to_string())?;

    let certs = db.query_all_certs().map_err(|e| e.to_string())?;
    let replacements = db.replacements.clone();
    let expires_soon = db.certs_expires_soon.clone();

    let mut vpn_certs: Vec<CertListItem> = certs
        .into_iter()
        .filter(|c| {
            c.cert_type.as_deref().is_some_and(|t| {
                t.eq_ignore_ascii_case("vpnclient") || t.eq_ignore_ascii_case("vpnserver")
            }) && c
                .status
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("valid"))
        })
        .map(|c| cert_list_item(c, &replacements, &expires_soon))
        .collect();

    vpn_certs.sort_by(|a, b| {
        a.cn
            .cmp(&b.cn)
            .then_with(|| serial_sort_key(&b.serial).cmp(&serial_sort_key(&a.serial)))
    });
    Ok(vpn_certs)
}

/// Numeric sort key for a serial string, falling back to 0 for non-numeric
/// serials so sorting stays total. Used to order renewal duplicates by recency.
fn serial_sort_key(serial: &Option<String>) -> i64 {
    serial
        .as_deref()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
}

/// Look up the VPN profile previously generated for a CN, straight from the
/// local database (no `op` round-trip). Returns the most recently recorded
/// match, so the cert detail page can offer to regenerate it after a
/// renew/rekey using the same template.
#[tauri::command]
pub async fn get_vpn_profile_for_cn(
    state: State<'_, AppState>,
    cn: String,
) -> Result<Option<OpenVpnProfileItem>, String> {
    let conn = state.ensure_ca()?;
    let profile = conn
        .db()?
        .query_openvpn_profile_for_cn(&cn)
        .map_err(|e| e.to_string())?
        .map(|p| OpenVpnProfileItem {
            cn: p.cn,
            title: p.title,
            created_date: p.created_date,
            template: p.template,
            serial: p.serial,
            profile_type: None,
        });

    Ok(profile)
}

/// Generate a VPN profile for a client CN using a template.
#[tauri::command]
pub async fn generate_openvpn_profile(
    state: State<'_, AppState>,
    request: GenerateProfileRequest,
) -> Result<OpenVpnProfileItem, String> {
    let cn = request.cn;
    let template_name = request.template_name;
    let dest_vault = request.dest_vault;
    let serial = request.serial.filter(|s| !s.is_empty());

    let created_date = Utc::now().format("%Y-%m-%d").to_string();

    // Resolve which 1Password item to pull the cert/key from. The DB `title` is
    // the item name — `CRT_{serial}_{cn}` for new certs, or just the bare CN for
    // legacy ones. When two valid certs share a CN we must address the chosen
    // one by its serial's title; otherwise `op://.../$OPCA_USER/...` resolves the
    // CN to whichever item matches first (often the older, legacy-named cert).
    // Falls back to the CN when no serial is supplied.
    let opca_user = match serial.as_deref() {
        Some(serial) => {
            let conn = state.ensure_ca()?;
            conn.db()?
                .query_cert(&CertLookup::Serial(serial.to_string()), false)
                .map_err(|e| e.to_string())?
                .and_then(|r| r.title)
                .unwrap_or_else(|| cn.clone())
        }
        None => cn.clone(),
    };

    info!(
        "[tauri] generate_openvpn_profile: cn='{}' serial={:?} template='{}' -> item '{}'",
        cn, serial, template_name, opca_user
    );

    // Document title carries the cert serial — `VPN_{serial}_{cn}`, mirroring the
    // cert's own `CRT_{serial}_{cn}` item — so a renewed cert (new serial) yields
    // a distinct profile rather than clobbering the previous one. Regenerating
    // the same cert (same serial) reuses the title and overwrites. Falls back to
    // `VPN_{cn}` when no serial is supplied.
    let title = match serial.as_deref() {
        Some(s) => format!("VPN_{s}_{cn}"),
        None => format!("VPN_{cn}"),
    };

    // Template content comes from the local DB mirror (no `op` round-trip);
    // fall back to 1Password for templates not yet synced into the DB.
    let db_template_content: Option<String> = {
        let conn = state.ensure_ca()?;
        conn.db()?
            .get_openvpn_template(&template_name)
            .map_err(|e| e.to_string())?
            .map(|t| t.content)
    };

    state.with_op(|op| {
        let template_content = match db_template_content {
            Some(content) => content,
            None => {
                let url = op.mk_url(
                    DEFAULT_OP_CONF.openvpn_title,
                    Some(&format!("template/{template_name}")),
                );
                op.read_item(&url)
                    .map_err(|e| format!("Failed to read template '{template_name}': {e}"))?
            }
        };

        // Inject op:// references with OPCA_USER pointing at the resolved item.
        let mut env_vars = HashMap::new();
        env_vars.insert("OPCA_USER".to_string(), opca_user.clone());

        let profile_content = op
            .inject_item(&template_content, Some(&env_vars))
            .map_err(|e| format!("Failed to inject template references: {e}"))?;

        // Auto (create-or-edit) so regenerating the same cert overwrites its
        // existing document instead of failing/duplicating.
        op.store_document(
            &title,
            &format!("{cn}-{template_name}.ovpn"),
            &profile_content,
            StoreAction::Auto,
            dest_vault.as_deref(),
        )
        .map_err(|e| format!("Failed to store VPN profile: {e}"))?;

        Ok(())
    })?;

    // Record the profile in the database and persist it, so the Profiles list
    // survives a restart. Upsert by title (delete any existing row first) so
    // regenerating the same cert replaces its row rather than duplicating it,
    // then export the DB back to 1Password — mirroring the DKIM commands. The
    // `.ovpn` document is already stored, so a persist failure here is
    // recoverable; we surface it rather than silently dropping the row (the
    // silent drop was the original "profiles vanish on restart" bug).
    {
        let mut conn = state.ensure_ca()?;
        let ca = conn.ca.as_mut().ok_or("CA not available")?;
        let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
        db.delete_openvpn_profile(&title).map_err(|e| e.to_string())?;
        db.add_openvpn_profile(&OpenVpnProfile {
            id: None,
            cn: cn.clone(),
            title: title.clone(),
            created_date: Some(created_date.clone()),
            template: Some(template_name.clone()),
            serial: serial.clone(),
        })
        .map_err(|e| e.to_string())?;
        ca.store_ca_database().map_err(|e| {
            state.log_err("generate_profile", Some(e.to_string()));
            e.to_string()
        })?;
    }

    let profile_item = OpenVpnProfileItem {
        cn: cn.clone(),
        title: title.clone(),
        created_date: Some(created_date),
        template: Some(template_name.clone()),
        serial: serial.clone(),
        profile_type: None,
    };

    state.log_ok(
        "generate_profile",
        Some(format!("Generated VPN profile for '{cn}' with template '{template_name}'")),
    );
    Ok(profile_item)
}

/// Friendly "Client"/"Server" label from a cert's type, for the profiles list.
/// Falls back to the raw type for anything that isn't a VPN client/server cert.
fn vpn_profile_type_label(cert_type: Option<&str>) -> Option<String> {
    let t = cert_type?;
    Some(match t.parse::<CertType>() {
        Ok(CertType::VpnServer) => "Server".to_string(),
        Ok(CertType::VpnClient) => "Client".to_string(),
        _ => t.to_string(),
    })
}

/// List VPN profiles from the local database (no 1Password round-trip). Each
/// profile's type is derived from the cert it was generated from — preferring
/// the recorded serial, falling back to the CN for pre-v11 rows.
#[tauri::command]
pub async fn list_openvpn_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<OpenVpnProfileItem>, String> {
    let conn = state.ensure_ca()?;
    let db = conn.db()?;

    let profiles = db.query_all_openvpn_profiles().map_err(|e| e.to_string())?;

    // Index cert types once (by serial and by CN) so profile rows resolve their
    // type with map lookups instead of a SQL query each.
    let certs = db.query_all_certs().map_err(|e| e.to_string())?;
    let mut type_by_serial: HashMap<&str, &str> = HashMap::new();
    let mut type_by_cn: HashMap<&str, &str> = HashMap::new();
    for c in &certs {
        if let Some(t) = c.cert_type.as_deref() {
            type_by_serial.insert(c.serial.as_str(), t);
            if let Some(cn) = c.cn.as_deref() {
                type_by_cn.insert(cn, t);
            }
        }
    }

    Ok(profiles
        .into_iter()
        .map(|p| {
            let cert_type = p
                .serial
                .as_deref()
                .and_then(|s| type_by_serial.get(s).copied())
                .or_else(|| type_by_cn.get(p.cn.as_str()).copied());
            let profile_type = vpn_profile_type_label(cert_type);
            OpenVpnProfileItem {
                cn: p.cn,
                title: p.title,
                created_date: p.created_date,
                template: p.template,
                serial: p.serial,
                profile_type,
            }
        })
        .collect())
}

/// Send a VPN profile document to another vault.
#[tauri::command]
pub async fn send_profile_to_vault(
    state: State<'_, AppState>,
    title: String,
    cn: String,
    dest_vault: String,
) -> Result<bool, String> {
    if dest_vault.is_empty() {
        return Err("Destination vault is required".to_string());
    }

    info!("[tauri] send_profile_to_vault: title='{title}' dest='{dest_vault}'");
    state.with_op(|op| {
        let content = op
            .get_document(&title)
            .map_err(|e| format!("Failed to read profile '{title}': {e}"))?;

        op.store_document(
            &title,
            &format!("{cn}.ovpn"),
            &content,
            StoreAction::Create,
            Some(&dest_vault),
        )
        .map_err(|e| format!("Failed to send profile to vault '{dest_vault}': {e}"))?;

        Ok(true)
    })?;

    state.log_ok(
        "send_profile",
        Some(format!("Sent {title} to vault '{dest_vault}'")),
    );
    Ok(true)
}
