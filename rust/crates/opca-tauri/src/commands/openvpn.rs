use std::collections::HashMap;

use chrono::Utc;
use log::info;
use tauri::State;

use opca_core::constants::{DEFAULT_KEY_SIZE, DEFAULT_OP_CONF};
use opca_core::crypto::utils::{generate_dh_params, generate_ta_key, verify_dh_params, verify_ta_key};
use opca_core::op::StoreAction;
use opca_core::services::database::models::OpenVpnProfile;

use crate::commands::dto::{
    GenerateProfileRequest, OpenVpnProfileItem, OpenVpnServerParams, OpenVpnTemplateDetail,
    OpenVpnTemplateItem, ServerSetupRequest,
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

/// Extract template names from OpenVPN item fields (section label = "template").
fn extract_template_names(op: &opca_core::op::Op) -> Result<Vec<String>, String> {
    let title = DEFAULT_OP_CONF.openvpn_title;
    if !op.item_exists(title) {
        return Ok(Vec::new());
    }

    let json_str = op
        .get_item(title, "json")
        .map_err(|e| e.to_string())?;

    let item: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| e.to_string())?;

    let mut names = Vec::new();
    if let Some(arr) = item["fields"].as_array() {
        for field in arr {
            let label = field["label"].as_str().unwrap_or_default();
            let section_label = field["section"]["label"].as_str().unwrap_or_default();
            if section_label == "template" && !label.is_empty() {
                names.push(label.to_string());
            }
        }
    }

    names.sort();
    Ok(names)
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

    state.log_ok(
        "setup_openvpn",
        Some(format!("OpenVPN server setup complete (template: {template_name})")),
    );
    get_openvpn_params(state).await
}

/// List template names from the OpenVPN 1Password item.
#[tauri::command]
pub async fn list_openvpn_templates(
    state: State<'_, AppState>,
) -> Result<Vec<OpenVpnTemplateItem>, String> {
    state.with_op(|op| {
        let names = extract_template_names(op)?;
        Ok(names
            .into_iter()
            .map(|name| OpenVpnTemplateItem {
                name,
                updated_date: None,
            })
            .collect())
    })
}

/// Read a specific template's content from 1Password.
#[tauri::command]
pub async fn get_openvpn_template(
    state: State<'_, AppState>,
    name: String,
) -> Result<OpenVpnTemplateDetail, String> {
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

/// Save template content to the OpenVPN 1Password item.
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
    state.with_op(|op| {
        let attrs = vec![format!("template.{name}[text]={content}")];
        let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

        op.store_item(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&attr_refs),
            StoreAction::Edit,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )
        .map_err(|e| format!("Failed to save template: {e}"))?;

        Ok(true)
    })?;

    state.log_ok(
        "save_template",
        Some(format!("Saved OpenVPN template '{name}'")),
    );
    Ok(true)
}

/// List VPN client certificates (cert_type = "vpnclient", status = "valid").
#[tauri::command]
pub async fn list_vpn_clients(
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca
        .ca_database
        .as_mut()
        .ok_or("Database not loaded")?;

    db.process_ca_database(None).map_err(|e| e.to_string())?;

    let certs = db.query_all_certs().map_err(|e| e.to_string())?;

    let mut vpn_clients: Vec<String> = certs
        .into_iter()
        .filter(|c| {
            c.cert_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("vpnclient"))
                && c.status
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case("valid"))
        })
        .filter_map(|c| c.cn)
        .collect();

    vpn_clients.sort();
    Ok(vpn_clients)
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

    info!("[tauri] generate_openvpn_profile: cn='{}' template='{}'", cn, template_name);
    let created_date = Utc::now().format("%Y-%m-%d").to_string();

    state.with_op(|op| {
        // Read the template from 1Password
        let url = op.mk_url(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&format!("template/{template_name}")),
        );
        let template_content = op
            .read_item(&url)
            .map_err(|e| format!("Failed to read template '{template_name}': {e}"))?;

        // Inject op:// references with OPCA_USER env var set
        let mut env_vars = HashMap::new();
        env_vars.insert("OPCA_USER".to_string(), cn.clone());

        let profile_content = op
            .inject_item(&template_content, Some(&env_vars))
            .map_err(|e| format!("Failed to inject template references: {e}"))?;

        // Store as a document
        let item_title = format!("VPN_{cn}");
        let filename = format!("{cn}-{template_name}.ovpn");

        op.store_document(
            &item_title,
            &filename,
            &profile_content,
            StoreAction::Create,
            dest_vault.as_deref(),
        )
        .map_err(|e| format!("Failed to store VPN profile: {e}"))?;

        Ok(OpenVpnProfileItem {
            cn: cn.clone(),
            title: item_title,
            created_date: Some(created_date.clone()),
            template: Some(template_name.clone()),
        })
    })?;

    // Record in database
    let title = format!("VPN_{cn}");
    let profile_item = OpenVpnProfileItem {
        cn: cn.clone(),
        title: title.clone(),
        created_date: Some(created_date.clone()),
        template: Some(template_name.clone()),
    };

    // Try to record in database (best effort — profile is already in 1Password)
    if let Ok(mut conn) = state.ensure_ca() {
        if let Some(ref mut ca) = conn.ca {
            if let Some(ref mut db) = ca.ca_database {
                let _ = db.add_openvpn_profile(&OpenVpnProfile {
                    id: None,
                    cn: cn.clone(),
                    title: title.clone(),
                    created_date: Some(created_date),
                    template: Some(template_name.clone()),
                });
            }
        }
    }

    state.log_ok(
        "generate_profile",
        Some(format!("Generated VPN profile for '{cn}' with template '{template_name}'")),
    );
    Ok(profile_item)
}

/// List VPN profiles from 1Password (documents with VPN_ prefix).
#[tauri::command]
pub async fn list_openvpn_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<OpenVpnProfileItem>, String> {
    state.with_op(|op| {
        let json_str = op
            .item_list("Document", "json")
            .map_err(|e| e.to_string())?;

        let items: Vec<serde_json::Value> =
            serde_json::from_str(&json_str).map_err(|e| e.to_string())?;

        let mut profiles: Vec<OpenVpnProfileItem> = Vec::new();
        for item in &items {
            let title = item["title"].as_str().unwrap_or_default();
            if let Some(cn) = title.strip_prefix("VPN_") {
                let created = item["created_at"]
                    .as_str()
                    .map(|s| s[..10].to_string());
                profiles.push(OpenVpnProfileItem {
                    cn: cn.to_string(),
                    title: title.to_string(),
                    created_date: created,
                    template: None,
                });
            }
        }

        profiles.sort_by(|a, b| a.cn.cmp(&b.cn));
        Ok(profiles)
    })
}

/// Send a VPN profile document to another vault.
#[tauri::command]
pub async fn send_profile_to_vault(
    state: State<'_, AppState>,
    cn: String,
    dest_vault: String,
) -> Result<bool, String> {
    if dest_vault.is_empty() {
        return Err("Destination vault is required".to_string());
    }

    info!("[tauri] send_profile_to_vault: cn='{cn}' dest='{dest_vault}'");
    state.with_op(|op| {
        let item_title = format!("VPN_{cn}");
        let content = op
            .get_document(&item_title)
            .map_err(|e| format!("Failed to read profile '{item_title}': {e}"))?;

        op.store_document(
            &item_title,
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
        Some(format!("Sent VPN_{cn} to vault '{dest_vault}'")),
    );
    Ok(true)
}
