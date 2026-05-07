use chrono::Utc;
use log::{debug, info};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use serde::Deserialize;
use tauri::State;

use opca_core::constants::{DEFAULT_KEY_SIZE, DEFAULT_OP_CONF};
use opca_core::op::StoreAction;
use opca_core::services::database::DkimRecord;
use opca_core::services::route53::{format_txt_value, split_txt_value, Route53Client};
use opca_core::services::storage::get_aws_credentials;

use crate::commands::dto::{
    CreateDkimRequest, CreateDkimResult, DkimKeyDetail, DkimKeyItem, DkimRoute53Result,
    DkimVerifyResult,
};
use crate::state::AppState;

/// 1Password item title prefix for DKIM keys.
const DKIM_ITEM_PREFIX: &str = "DKIM";

fn make_dkim_title(domain: &str, selector: &str) -> String {
    format!("{DKIM_ITEM_PREFIX}_{domain}_{selector}")
}

fn make_dns_name(domain: &str, selector: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

/// Format a PEM-encoded public key as a DKIM DNS TXT record value.
fn format_dkim_dns_record(public_key_pem: &str) -> String {
    let base64: String = public_key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    format!("v=DKIM1; k=rsa; p={base64}")
}

/// Re-format a TXT value as Route53 expects long records: 255-byte chunks,
/// each wrapped in double quotes and space-separated.
fn chunk_for_route53(record: &str) -> String {
    format_txt_value(&split_txt_value(record, 255))
}

fn item_to_dkim_record(domain: &str, selector: &str, created_at: Option<String>) -> DkimRecord {
    DkimRecord {
        domain: domain.to_string(),
        selector: selector.to_string(),
        title: Some(make_dkim_title(domain, selector)),
        key_size: None,
        created_at,
        has_private_key: None,
        has_public_key: None,
        has_dns_record: None,
    }
}

fn record_to_item(record: &DkimRecord) -> DkimKeyItem {
    DkimKeyItem {
        domain: record.domain.clone(),
        selector: record.selector.clone(),
        key_size: record.key_size,
        created_at: record.created_at.as_ref().map(|s| {
            // Trim to YYYY-MM-DD for the list display, matching the legacy shape.
            s.chars().take(10).collect()
        }),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkimCopyKind {
    Selector,
    PublicKey,
    DnsRecord,
}

impl DkimCopyKind {
    fn token(&self) -> &'static str {
        match self {
            DkimCopyKind::Selector => "selector",
            DkimCopyKind::PublicKey => "public_key",
            DkimCopyKind::DnsRecord => "dns_record",
        }
    }
    fn label(&self) -> &'static str {
        match self {
            DkimCopyKind::Selector => "DKIM selector",
            DkimCopyKind::PublicKey => "DKIM public key",
            DkimCopyKind::DnsRecord => "DKIM DNS record",
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Fast path: DKIM list straight from the local SQLite mirror. The first
/// call after the v10 migration finds an empty table and runs an inline
/// sync from 1Password so the user doesn't have to click Refresh manually.
#[tauri::command]
pub async fn list_dkim_keys(state: State<'_, AppState>) -> Result<Vec<DkimKeyItem>, String> {
    let needs_sync = {
        let conn = state.ensure_ca()?;
        let ca = conn.ca.as_ref().ok_or("CA not available")?;
        let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;
        db.count_dkim().map_err(|e| e.to_string())? == 0
    };

    if needs_sync {
        do_sync_dkim_keys(&state)?;
    }

    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;
    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;
    let records = db.query_all_dkim().map_err(|e| e.to_string())?;
    Ok(records.iter().map(record_to_item).collect())
}

/// Pull every `DKIM_<domain>_<selector>` item out of 1Password and seed the
/// `dkim_key` table. Used once after the v10 migration and as the action
/// behind the Refresh button on the keys list.
#[tauri::command]
pub async fn sync_dkim_keys(state: State<'_, AppState>) -> Result<usize, String> {
    do_sync_dkim_keys(&state)
}

fn do_sync_dkim_keys(state: &State<'_, AppState>) -> Result<usize, String> {
    info!("[tauri] sync_dkim_keys");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let json_str = ca
        .op
        .item_list(DEFAULT_OP_CONF.category, "json")
        .map_err(|e| e.to_string())?;
    let items: Vec<serde_json::Value> =
        serde_json::from_str(&json_str).map_err(|e| e.to_string())?;

    let prefix = format!("{DKIM_ITEM_PREFIX}_");
    let mut found = Vec::new();
    for item in &items {
        let title = item["title"].as_str().unwrap_or_default();
        let Some(rest) = title.strip_prefix(&prefix) else { continue };
        // Title format: DKIM_<domain>_<selector> — split on the LAST underscore
        // because domains never contain '_' but selectors might (rare).
        let Some(pos) = rest.rfind('_') else { continue };
        let domain = &rest[..pos];
        let selector = &rest[pos + 1..];
        if domain.is_empty() || selector.is_empty() {
            continue;
        }
        let created_at = item["created_at"].as_str().map(|s| s.to_string());
        found.push(item_to_dkim_record(domain, selector, created_at));
    }

    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    for record in &found {
        db.upsert_dkim(record).map_err(|e| e.to_string())?;
    }

    // Reconcile deletions: drop DB rows whose 1Password item no longer
    // exists. Without this, a key deleted by an older client (or via
    // `op item delete` directly) would linger as a ghost row that throws
    // on detail-page open.
    let live: std::collections::HashSet<(String, String)> = found
        .iter()
        .map(|r| (r.domain.clone(), r.selector.clone()))
        .collect();
    let mut removed = 0usize;
    for stale in db.query_all_dkim().map_err(|e| e.to_string())? {
        if !live.contains(&(stale.domain.clone(), stale.selector.clone())) {
            db.delete_dkim(&stale.domain, &stale.selector)
                .map_err(|e| e.to_string())?;
            removed += 1;
        }
    }

    ca.store_ca_database().map_err(|e| {
        state.log_err("sync_dkim_keys", Some(e.to_string()));
        e.to_string()
    })?;

    let summary = if removed > 0 {
        format!(
            "Synced {} DKIM key(s) from 1Password ({} stale row(s) removed)",
            found.len(),
            removed
        )
    } else {
        format!("Synced {} DKIM key(s) from 1Password", found.len())
    };
    state.log_ok("sync_dkim_keys", Some(summary));
    Ok(found.len())
}

/// Fast path: DKIM detail purely from the DB. Returns just the metadata —
/// no PEM, no DNS record. The frontend follows up with [`backfill_dkim`].
#[tauri::command]
pub async fn get_dkim_info(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<DkimKeyDetail, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;
    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;

    let record = db
        .query_dkim(&domain, &selector)
        .map_err(|e| e.to_string())?
        .ok_or("DKIM key not found")?;

    Ok(DkimKeyDetail {
        domain: record.domain.clone(),
        selector: record.selector.clone(),
        key_size: record.key_size,
        dns_name: make_dns_name(&record.domain, &record.selector),
        dns_record: None,
        dns_record_chunked: None,
        created_at: record.created_at.clone(),
        public_key: None,
        has_private_key: record.has_private_key,
        has_public_key: record.has_public_key,
        has_dns_record: record.has_dns_record,
        key_pair_match: None,
    })
}

/// Slow path: fetch the DKIM bundle from 1Password, return the public key and
/// DNS record, validate that the stored private key matches the public key,
/// and persist any newly-discovered flags back to the DB.
#[tauri::command]
pub async fn backfill_dkim(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<DkimKeyDetail, String> {
    debug!("[tauri] backfill_dkim: domain='{domain}' selector='{selector}'");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let item_title = make_dkim_title(&domain, &selector);

    // Fetch the whole item once and pull each field out of the JSON. The
    // previous implementation invoked `op read` four or five separate times,
    // which dominated the page-open latency.
    let json_str = ca
        .op
        .get_item(&item_title, "json")
        .map_err(|e| format!("DKIM key '{item_title}' not found: {e}"))?;
    let obj: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("Failed to parse 1Password item: {e}"))?;

    let mut public_key: Option<String> = None;
    let mut dns_record_raw: Option<String> = None;
    let mut private_key: Option<String> = None;
    let mut key_size_str: Option<String> = None;
    let mut created_at: Option<String> = None;

    if let Some(fields) = obj.get("fields").and_then(|f| f.as_array()) {
        for field in fields {
            let label = field.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let value = field
                .get("value")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            match label {
                "public_key" => public_key = value,
                "dns_record" => dns_record_raw = value,
                "private_key" => private_key = value,
                "key_size" => key_size_str = value,
                "created_at" => created_at = value,
                _ => {}
            }
        }
    }

    let has_public_key = Some(public_key.as_ref().is_some_and(|s| !s.is_empty()));
    let has_private_key = Some(private_key.as_ref().is_some_and(|s| !s.is_empty()));
    let has_dns_record = Some(dns_record_raw.as_ref().is_some_and(|s| !s.is_empty()));

    let key_pair_match = match (private_key.as_deref(), public_key.as_deref()) {
        (Some(priv_pem), Some(pub_pem)) if !priv_pem.is_empty() && !pub_pem.is_empty() => {
            // `None` here means the PEM didn't parse; the UI shows that as
            // "—" rather than misreporting it as a mismatch.
            verify_key_pair(priv_pem, pub_pem)
        }
        _ => None,
    };

    let key_size = key_size_str
        .as_deref()
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| {
            // Fall back to deriving from the public key bit length if the
            // field is missing — older items may not have stored it.
            public_key.as_deref().and_then(|pem| {
                PKey::public_key_from_pem(pem.as_bytes())
                    .ok()
                    .map(|k| k.bits() as i64)
            })
        });

    // Persist any newly observed metadata back to the DB so future fast-path
    // reads have it.
    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    db.upsert_dkim(&DkimRecord {
        domain: domain.clone(),
        selector: selector.clone(),
        title: Some(item_title),
        key_size,
        created_at: created_at.clone(),
        has_private_key,
        has_public_key,
        has_dns_record,
    })
    .map_err(|e| e.to_string())?;

    let dns_record = dns_record_raw;
    let dns_record_chunked = dns_record.as_deref().map(chunk_for_route53);
    let dns_name = make_dns_name(&domain, &selector);

    Ok(DkimKeyDetail {
        domain,
        selector,
        key_size,
        dns_name,
        dns_record,
        dns_record_chunked,
        created_at,
        public_key,
        has_private_key,
        has_public_key,
        has_dns_record,
        key_pair_match,
    })
}

/// Compare the SubjectPublicKeyInfo derived from the private key against the
/// stored public key. `Some(true)` = matched, `Some(false)` = mismatch,
/// `None` = either PEM failed to parse (key is corrupt or in an unexpected
/// format). Distinguishing the third state matters: a parse failure should
/// not look the same as deliberate tampering.
fn verify_key_pair(private_pem: &str, public_pem: &str) -> Option<bool> {
    let priv_key = PKey::private_key_from_pem(private_pem.as_bytes()).ok()?;
    let pub_key = PKey::public_key_from_pem(public_pem.as_bytes()).ok()?;
    let priv_der = priv_key.public_key_to_der().ok()?;
    let pub_der = pub_key.public_key_to_der().ok()?;
    Some(priv_der == pub_der)
}

/// Return the DKIM private key PEM. Heavy security warning + audit log apply
/// the same way as the cert-key export.
#[tauri::command]
pub async fn get_dkim_private_key(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<String, String> {
    info!("[tauri] get_dkim_private_key: domain='{domain}' selector='{selector}'");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let item_title = make_dkim_title(&domain, &selector);

    if !ca.op.item_exists(&item_title) {
        return Err(format!("DKIM key '{}' not found.", item_title));
    }

    let url = ca.op.mk_url(&item_title, Some("private_key"));
    let key_pem = ca.op.read_item(&url).map_err(|e| e.to_string())?;
    let trimmed = key_pem.trim();
    if trimmed.is_empty() {
        return Err("No private key stored alongside this DKIM key".into());
    }

    state.log_ok(
        "get_dkim_private_key",
        Some(format!(
            "Exported private key for DKIM key {selector}._domainkey.{domain}"
        )),
    );
    Ok(trimmed.to_string())
}

/// Audit-log a clipboard copy of a non-secret DKIM artefact (selector,
/// public key, or DNS record). Mirrors `record_cert_copy`.
#[tauri::command]
pub async fn record_dkim_copy(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
    kind: DkimCopyKind,
) -> Result<(), String> {
    let action = format!("copy_dkim_{}", kind.token());
    state.log_ok(
        &action,
        Some(format!(
            "Copied {} for {selector}._domainkey.{domain}",
            kind.label()
        )),
    );
    Ok(())
}

#[tauri::command]
pub async fn create_dkim_key(
    state: State<'_, AppState>,
    request: CreateDkimRequest,
) -> Result<CreateDkimResult, String> {
    info!(
        "[tauri] create_dkim_key: domain='{}' selector='{}'",
        request.domain, request.selector
    );
    let key_size = request.key_size.unwrap_or(DEFAULT_KEY_SIZE.dkim);
    let domain = request.domain;
    let selector = request.selector;
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    if ca.op.item_exists(&item_title) {
        return Err(format!(
            "DKIM key '{}' already exists. Delete it first or use a different selector.",
            item_title
        ));
    }

    let rsa = Rsa::generate(key_size).map_err(|e| format!("Failed to generate RSA key: {e}"))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| format!("Failed to wrap RSA key: {e}"))?;

    let private_pem = String::from_utf8(
        pkey.private_key_to_pem_pkcs8()
            .map_err(|e| format!("Failed to encode private key: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let public_pem = String::from_utf8(
        pkey.public_key_to_pem()
            .map_err(|e| format!("Failed to encode public key: {e}"))?,
    )
    .map_err(|e| e.to_string())?;

    let dns_record = format_dkim_dns_record(&public_pem);
    let created_at = Utc::now().to_rfc3339();

    let attrs: Vec<String> = vec![
        format!("domain[text]={domain}"),
        format!("selector[text]={selector}"),
        format!("key_size[text]={key_size}"),
        format!("private_key={private_pem}"),
        format!("public_key[text]={public_pem}"),
        format!("dns_record[text]={dns_record}"),
        format!("dns_name[text]={dns_name}"),
        format!("created_at[text]={created_at}"),
    ];
    let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

    ca.op
        .store_item(
            &item_title,
            Some(&attr_refs),
            StoreAction::Create,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )
        .map_err(|e| format!("Failed to store DKIM key in 1Password: {e}"))?;

    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    db.upsert_dkim(&DkimRecord {
        domain: domain.clone(),
        selector: selector.clone(),
        title: Some(item_title),
        key_size: Some(key_size as i64),
        created_at: Some(created_at.clone()),
        has_private_key: Some(true),
        has_public_key: Some(true),
        has_dns_record: Some(true),
    })
    .map_err(|e| e.to_string())?;
    ca.store_ca_database().map_err(|e| {
        state.log_err("create_dkim_key", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok(
        "create_dkim",
        Some(format!("Created DKIM key for {selector}._domainkey.{domain}")),
    );

    let dns_record_chunked = chunk_for_route53(&dns_record);

    Ok(CreateDkimResult {
        item: DkimKeyItem {
            domain,
            selector,
            key_size: Some(key_size as i64),
            created_at: Some(created_at[..10].to_string()),
        },
        dns_name,
        dns_record,
        dns_record_chunked,
    })
}

#[tauri::command]
pub async fn delete_dkim_key(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<bool, String> {
    info!("[tauri] delete_dkim_key: domain='{domain}' selector='{selector}'");
    let item_title = make_dkim_title(&domain, &selector);

    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    if !ca.op.item_exists(&item_title) {
        return Err(format!("DKIM key '{}' not found.", item_title));
    }

    ca.op
        .delete_item(&item_title, true)
        .map_err(|e| format!("Failed to delete DKIM key: {e}"))?;

    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    db.delete_dkim(&domain, &selector)
        .map_err(|e| e.to_string())?;
    ca.store_ca_database().map_err(|e| {
        state.log_err("delete_dkim_key", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok(
        "delete_dkim",
        Some(format!("Deleted DKIM key for {selector}._domainkey.{domain}")),
    );

    Ok(true)
}

#[tauri::command]
pub async fn verify_dkim_dns(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<DkimVerifyResult, String> {
    debug!("[tauri] verify_dkim_dns: domain='{domain}' selector='{selector}'");
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let expected_record = state.with_op(|op| {
        if !op.item_exists(&item_title) {
            return Err(format!("DKIM key '{}' not found.", item_title));
        }
        let url = op.mk_url(&item_title, Some("dns_record"));
        let record = op.read_item(&url).map_err(|e| e.to_string())?;
        Ok(record.trim().to_string())
    })?;

    let found_records = opca_core::services::route53::lookup_txt(&dns_name)
        .await
        .map_err(|e| e.to_string())?;

    let expected_key = opca_core::services::route53::extract_dkim_key(&expected_record);
    let verified = found_records.iter().any(|rec| {
        match (&expected_key, opca_core::services::route53::extract_dkim_key(rec)) {
            (Some(ek), Some(fk)) => ek == &fk,
            _ => rec.contains(&expected_record),
        }
    });

    let found_txt = found_records.join("\n");
    let mismatch = !verified && !found_txt.is_empty();

    let message = if verified {
        "DNS record verified — published and matching.".to_string()
    } else if found_txt.is_empty() {
        "No TXT record found. DNS may not have propagated yet.".to_string()
    } else {
        "TXT record found but does not match the expected value.".to_string()
    };

    Ok(DkimVerifyResult {
        verified,
        dns_name,
        message,
        expected: if mismatch { Some(expected_record) } else { None },
        found: if mismatch { Some(found_txt) } else { None },
    })
}

/// Default TTL for DKIM TXT records (5 minutes).
const DKIM_DNS_TTL: u64 = 300;

#[tauri::command]
pub async fn deploy_dkim_route53(
    state: State<'_, AppState>,
    domain: String,
    selector: String,
) -> Result<DkimRoute53Result, String> {
    info!("[tauri] deploy_dkim_route53: domain='{domain}' selector='{selector}'");
    let item_title = make_dkim_title(&domain, &selector);
    let dns_name = make_dns_name(&domain, &selector);

    let dns_record = state.with_op(|op| {
        if !op.item_exists(&item_title) {
            return Err(format!("DKIM key '{}' not found.", item_title));
        }
        let url = op.mk_url(&item_title, Some("dns_record"));
        let record = op.read_item(&url).map_err(|e| e.to_string())?;
        Ok(record.trim().to_string())
    })?;

    let creds = state.with_op(|op| {
        get_aws_credentials(op.runner(), op.account()).map_err(|e| e.to_string())
    })?;

    let client = Route53Client::new(creds);
    let result = client
        .deploy_txt_record(&dns_name, &dns_record, DKIM_DNS_TTL)
        .await
        .map_err(|e| e.to_string())?;

    let message = format!(
        "Deployed TXT record to zone {} (change: {})",
        result.zone_name, result.change_id
    );
    state.log_ok("deploy_dkim_route53", Some(message.clone()));

    Ok(DkimRoute53Result {
        dns_name,
        zone_name: result.zone_name,
        message,
    })
}
