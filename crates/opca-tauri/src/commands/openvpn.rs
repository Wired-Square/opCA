use std::collections::HashMap;

use chrono::Utc;
use log::{info, warn};
use tauri::{AppHandle, State};

use opca_core::constants::{DEFAULT_KEY_SIZE, DEFAULT_OP_CONF};
use opca_core::crypto::utils::{generate_dh_params, generate_ta_key, verify_dh_params, verify_ta_key};
use opca_core::error::OpcaError;
use opca_core::op::StoreAction;
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::cert::CertType;
use opca_core::services::database::models::OpenVpnProfile;
use opca_core::services::database::CertLookup;
use opca_core::services::openvpn;

use crate::commands::cert::cert_list_item;
use crate::commands::dto::{
    BulkGenerateProfileItem, BulkProgress, BulkProfileResult, CertListItem, GenerateProfileRequest,
    OpenVpnProfileItem, OpenVpnServerParams, OpenVpnTemplateDetail, OpenVpnTemplateItem,
    ServerSetupRequest,
};
use crate::state::{AppState, Runner};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read all field labels and values from the OpenVPN 1Password item.
fn read_openvpn_fields(
    op: &opca_core::op::Op<Runner>,
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

/// Determine create vs edit action for the OpenVPN item.
fn resolve_store_action(op: &opca_core::op::Op<Runner>) -> StoreAction {
    if op.item_exists(DEFAULT_OP_CONF.openvpn_title) {
        StoreAction::Edit
    } else {
        StoreAction::Create
    }
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

    with_ca(&state, "setup_openvpn", |ca| openvpn::add_starter_template(ca, &template_name))?;

    state.log_ok(
        "setup_openvpn",
        Some(format!("OpenVPN server setup complete (template: {template_name})")),
    );
    get_openvpn_params(state).await
}

/// Run `f` against the loaded CA, logging a failure under `action`.
fn with_ca<T>(
    state: &AppState,
    action: &str,
    f: impl FnOnce(&mut CertificateAuthority<Runner>) -> Result<T, OpcaError>,
) -> Result<T, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    f(ca).map_err(|e| {
        state.log_err(action, Some(e.to_string()));
        e.to_string()
    })
}

#[tauri::command]
pub async fn list_openvpn_templates(
    state: State<'_, AppState>,
) -> Result<Vec<OpenVpnTemplateItem>, String> {
    Ok(with_ca(&state, "list_templates", openvpn::list_templates)?
        .into_iter()
        .map(|t| OpenVpnTemplateItem {
            name: t.name,
            updated_date: t.updated_date,
        })
        .collect())
}

#[tauri::command]
pub async fn get_openvpn_template(
    state: State<'_, AppState>,
    name: String,
) -> Result<OpenVpnTemplateDetail, String> {
    let t = with_ca(&state, "get_template", |ca| openvpn::get_template(ca, &name))?;
    Ok(OpenVpnTemplateDetail {
        name: t.name,
        content: t.content,
        updated_date: t.updated_date,
    })
}

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
    with_ca(&state, "save_template", |ca| openvpn::save_template(ca, &name, &content))?;
    state.log_ok("save_template", Some(format!("Saved OpenVPN template '{name}'")));
    Ok(true)
}

#[tauri::command]
pub async fn delete_openvpn_template(
    state: State<'_, AppState>,
    name: String,
) -> Result<bool, String> {
    info!("[tauri] delete_openvpn_template: name='{name}'");
    let deleted = with_ca(&state, "delete_template", |ca| openvpn::delete_template(ca, &name))?;
    if deleted {
        state.log_ok("delete_template", Some(format!("Deleted OpenVPN template '{name}'")));
    }
    Ok(deleted)
}

/// Names of the template fields still on the 1Password `OpenVPN` item after a
/// successful import, each confirmed present in the database. Empty when
/// there is nothing to ask the operator about.
#[tauri::command]
pub async fn list_openvpn_vault_templates(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    with_ca(&state, "import_templates", openvpn::templates_awaiting_cleanup)
}

#[tauri::command]
pub async fn archive_openvpn_vault_templates(state: State<'_, AppState>) -> Result<usize, String> {
    let n = with_ca(&state, "archive_templates", openvpn::archive_vault_templates)?;
    state.log_ok(
        "archive_templates",
        Some(format!("Archived {n} OpenVPN template(s) from the 1Password OpenVPN item")),
    );
    Ok(n)
}

#[tauri::command]
pub async fn keep_openvpn_vault_templates(state: State<'_, AppState>) -> Result<(), String> {
    with_ca(&state, "keep_templates", openvpn::keep_vault_templates)?;
    state.log_ok(
        "keep_templates",
        Some("Kept the old OpenVPN templates on the 1Password OpenVPN item".to_string()),
    );
    Ok(())
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
            profile_status: None,
            replacement_serial: None,
        });

    Ok(profile)
}

/// Document/registry title for a profile — `VPN_{serial}_{cn}`, mirroring the
/// cert's own `CRT_{serial}_{cn}` item so a renewed cert (new serial) yields a
/// distinct profile. Falls back to `VPN_{cn}` when no serial is supplied.
fn profile_title(cn: &str, serial: Option<&str>) -> String {
    match serial.filter(|s| !s.is_empty()) {
        Some(s) => format!("VPN_{s}_{cn}"),
        None => format!("VPN_{cn}"),
    }
}

/// Core of a single profile generation: resolve the cert item, inject the
/// template, store the `.ovpn` document, and upsert + persist the profile row.
/// Returns the stored `OpenVpnProfile` (without classification context). Assumes
/// the caller holds the vault lock — both the single command and the bulk
/// command call this, so a bulk run is one lock cycle around the whole loop.
fn do_generate_openvpn_profile(
    state: &State<'_, AppState>,
    cn: &str,
    serial: Option<&str>,
    template_name: &str,
    dest_vault: Option<&str>,
) -> Result<OpenVpnProfile, String> {
    let serial = serial.filter(|s| !s.is_empty());
    let created_date = Utc::now().format("%Y-%m-%d").to_string();

    // Resolve which 1Password item to pull the cert/key from. The DB `title` is
    // the item name — `CRT_{serial}_{cn}` for new certs, or just the bare CN for
    // legacy ones. When two valid certs share a CN we must address the chosen
    // one by its serial's title; otherwise `op://.../$OPCA_USER/...` resolves the
    // CN to whichever item matches first (often the older, legacy-named cert).
    // Falls back to the CN when no serial is supplied.
    let opca_user = match serial {
        Some(serial) => {
            let conn = state.ensure_ca()?;
            conn.db()?
                .query_cert(&CertLookup::Serial(serial.to_string()), false)
                .map_err(|e| e.to_string())?
                .and_then(|r| r.title)
                .unwrap_or_else(|| cn.to_string())
        }
        None => cn.to_string(),
    };

    info!(
        "[tauri] generate_openvpn_profile: cn='{}' serial={:?} template='{}' -> item '{}'",
        cn, serial, template_name, opca_user
    );

    let title = profile_title(cn, serial);

    let template_content =
        with_ca(state, "generate_profile", |ca| openvpn::get_template(ca, template_name))?.content;

    state.with_op(|op| {
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
            dest_vault,
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
    let profile = OpenVpnProfile {
        id: None,
        cn: cn.to_string(),
        title: title.clone(),
        created_date: Some(created_date),
        template: Some(template_name.to_string()),
        serial: serial.map(str::to_string),
        generated: true,
    };
    {
        let mut conn = state.ensure_ca()?;
        let ca = conn.ca.as_mut().ok_or("CA not available")?;
        let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
        db.delete_openvpn_profile(&title).map_err(|e| e.to_string())?;
        db.add_openvpn_profile(&profile).map_err(|e| e.to_string())?;
        ca.store_ca_database().map_err(|e| {
            state.log_err("generate_profile", Some(e.to_string()));
            e.to_string()
        })?;
    }

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

    let profile = do_generate_openvpn_profile(
        &state,
        &cn,
        request.serial.as_deref(),
        &template_name,
        request.dest_vault.as_deref(),
    )?;

    state.log_ok(
        "generate_profile",
        Some(format!("Generated VPN profile for '{cn}' with template '{template_name}'")),
    );
    Ok(OpenVpnProfileItem {
        cn: profile.cn,
        title: profile.title,
        created_date: profile.created_date,
        template: profile.template,
        serial: profile.serial,
        profile_type: None,
        profile_status: None,
        replacement_serial: None,
    })
}

/// Generate VPN profiles for many certs in one vault-lock cycle (the frontend
/// wraps this in a single `withLock`). Each item is generated independently;
/// per-item failures are collected and the loop continues. Typically called to
/// regenerate "needs regen" profiles against their replacement cert serials.
#[tauri::command]
pub async fn bulk_generate_openvpn_profiles(
    app: AppHandle,
    state: State<'_, AppState>,
    items: Vec<BulkGenerateProfileItem>,
) -> Result<Vec<BulkProfileResult>, String> {
    let total = items.len();
    info!("[tauri] bulk_generate_openvpn_profiles: {total} profile(s)");
    let mut results = Vec::with_capacity(total);
    let (mut ok, mut fail) = (0usize, 0usize);
    for (i, it) in items.into_iter().enumerate() {
        BulkProgress::emit(&app, "Regenerating", i + 1, total);
        match do_generate_openvpn_profile(
            &state,
            &it.cn,
            it.serial.as_deref(),
            &it.template_name,
            it.dest_vault.as_deref(),
        ) {
            Ok(profile) => {
                results.push(BulkProfileResult { cn: it.cn, title: Some(profile.title), ok: true, error: None });
                ok += 1;
            }
            Err(e) => {
                warn!("[tauri] bulk_generate_openvpn_profiles: {} failed: {e}", it.cn);
                results.push(BulkProfileResult { cn: it.cn, title: None, ok: false, error: Some(e) });
                fail += 1;
            }
        }
    }

    state.log_ok("bulk_generate_profile", Some(format!("Bulk regenerate: {ok} ok, {fail} failed")));
    Ok(results)
}

/// Register one or more VPN profiles WITHOUT generating their `.ovpn` documents
/// (Add with "Generate Profile" unticked). Each row is recorded as not-generated
/// so the Profiles list flags it for generation; one DB persist covers the
/// batch (no `op` document writes). The user generates later via Regenerate.
#[tauri::command]
pub async fn add_openvpn_profile_entries(
    app: AppHandle,
    state: State<'_, AppState>,
    items: Vec<BulkGenerateProfileItem>,
) -> Result<Vec<BulkProfileResult>, String> {
    let total = items.len();
    info!("[tauri] add_openvpn_profile_entries: {total} profile(s)");
    let created_date = Utc::now().format("%Y-%m-%d").to_string();

    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;

    let mut results = Vec::with_capacity(total);
    let (mut ok, mut fail) = (0usize, 0usize);
    for (i, it) in items.into_iter().enumerate() {
        BulkProgress::emit(&app, "Adding", i + 1, total);
        let serial = it.serial.filter(|s| !s.is_empty());
        let title = profile_title(&it.cn, serial.as_deref());
        // Upsert by title so re-adding replaces rather than duplicating.
        let res = db.delete_openvpn_profile(&title).and_then(|_| {
            db.add_openvpn_profile(&OpenVpnProfile {
                id: None,
                cn: it.cn.clone(),
                title: title.clone(),
                created_date: Some(created_date.clone()),
                template: Some(it.template_name.clone()),
                serial,
                generated: false,
            })
        });
        match res {
            Ok(_) => { results.push(BulkProfileResult { cn: it.cn, title: Some(title), ok: true, error: None }); ok += 1; }
            Err(e) => {
                warn!("[tauri] add_openvpn_profile_entries: {} failed: {e}", it.cn);
                results.push(BulkProfileResult { cn: it.cn, title: None, ok: false, error: Some(e.to_string()) });
                fail += 1;
            }
        }
    }

    ca.store_ca_database().map_err(|e| {
        state.log_err("add_profile_entry", Some(e.to_string()));
        e.to_string()
    })?;
    state.log_ok("add_profile_entry", Some(format!("Added {ok} profile entr(y/ies), {fail} failed")));
    Ok(results)
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
/// the recorded serial, falling back to the CN for pre-v11 rows — and each
/// carries a derived lifecycle status (current / expiring_soon / needs_regen /
/// revoked / expired) computed against the live CA classification, so the
/// Profiles view can flag profiles whose cert was rekeyed/renewed/revoked/
/// expired or is nearing expiry.
#[tauri::command]
pub async fn list_openvpn_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<OpenVpnProfileItem>, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;

    // Refresh the classification sets so status derivation reflects the current
    // state of every cert (same as `list_vpn_certs`).
    db.process_ca_database(None, false).map_err(|e| e.to_string())?;

    let profiles = db.query_all_openvpn_profiles().map_err(|e| e.to_string())?;

    // Index cert types once (by serial and by CN) so profile rows resolve their
    // type with map lookups instead of a SQL query each. Deleted certs stay in,
    // since a profile can still pin one.
    let certs = db.query_all_certs_including_deleted().map_err(|e| e.to_string())?;
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
            let (status, replacement_serial) =
                db.derive_vpn_profile_status(p.serial.as_deref(), &p.cn, p.generated);
            OpenVpnProfileItem {
                cn: p.cn,
                title: p.title,
                created_date: p.created_date,
                template: p.template,
                serial: p.serial,
                profile_type,
                profile_status: Some(status.as_str().to_string()),
                replacement_serial,
            }
        })
        .collect())
}

/// Remove a VPN profile from the registry (DB row + persist). This deletes the
/// list entry only — the generated `.ovpn` document is left in the vault.
#[tauri::command]
pub async fn delete_openvpn_profile(
    state: State<'_, AppState>,
    title: String,
) -> Result<bool, String> {
    info!("[tauri] delete_openvpn_profile: title='{title}'");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    let removed = db.delete_openvpn_profile(&title).map_err(|e| e.to_string())?;
    ca.store_ca_database().map_err(|e| {
        state.log_err("delete_profile", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok("delete_profile", Some(format!("Deleted VPN profile {title}")));
    Ok(removed)
}

/// Remove many VPN profiles from the registry in one persist (the frontend
/// wraps this in a single `withLock`). Row-only, like the single delete; only
/// the final `store_ca_database` touches `op`.
#[tauri::command]
pub async fn bulk_delete_openvpn_profiles(
    state: State<'_, AppState>,
    titles: Vec<String>,
) -> Result<Vec<BulkProfileResult>, String> {
    info!("[tauri] bulk_delete_openvpn_profiles: {} profile(s)", titles.len());
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;

    let mut results = Vec::with_capacity(titles.len());
    let (mut ok, mut fail) = (0usize, 0usize);
    for title in &titles {
        match db.delete_openvpn_profile(title) {
            Ok(_) => {
                results.push(BulkProfileResult { cn: String::new(), title: Some(title.clone()), ok: true, error: None });
                ok += 1;
            }
            Err(e) => {
                warn!("[tauri] bulk_delete_openvpn_profiles: {title} failed: {e}");
                results.push(BulkProfileResult { cn: String::new(), title: Some(title.clone()), ok: false, error: Some(e.to_string()) });
                fail += 1;
            }
        }
    }

    ca.store_ca_database().map_err(|e| {
        state.log_err("bulk_delete_profile", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok("bulk_delete_profile", Some(format!("Bulk delete profiles: {ok} ok, {fail} failed")));
    Ok(results)
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
