use log::{info, warn, debug};
use openssl::nid::Nid;
use openssl::x509::X509;
use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager, State};

use opca_core::error::OpcaError;
use opca_core::op::ShellRunner;
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::cert::{CertBundleConfig, CertificateBundle, CertType, KeyAlgorithm};
use opca_core::services::database::{is_expiring_soon, CertLookup, CertRecord, ExternalCertRecord};
use opca_core::crypto::utils::encrypt_private_key_pem;
use opca_core::services::san;
use zeroize::Zeroizing;

use crate::commands::inspect_helpers::{
    public_key_summary, signature_algorithm_from_text, x509_name_to_rdn_string,
};

/// 1Password title for an external cert is always `EXT_<cn>` ([ca.rs] convention),
/// even though the DB row stores the un-prefixed CN in `title`. Compute the
/// real vault title from the CN so legacy DB rows still resolve correctly.
fn external_item_title(record: &ExternalCertRecord) -> Result<String, String> {
    let cn = record
        .cn
        .as_deref()
        .ok_or("External certificate has no CN")?;
    Ok(format!("EXT_{cn}"))
}

use crate::commands::dto::{
    BulkCertResult, BulkProgress, CertDetail, CertListItem, CreateCertRequest, ExternalCertDetail,
    ExternalCertListItem, ImportCertRequest, ImportCertResult, InspectCertificateResult,
    RenewRekeyResult,
};
use crate::state::{AppState, Connection};

/// Build a `CertListItem` from a raw `CertRecord`, folding in the classification
/// state (`replacements`, `certs_expires_soon`) computed by `process_ca_database`.
/// Shared by `list_certs` and `list_vpn_certs` so both surface the same
/// superseded / expiring-soon flags.
pub(crate) fn cert_list_item(
    r: CertRecord,
    replacements: &std::collections::HashMap<String, String>,
    expires_soon: &std::collections::HashSet<String>,
) -> CertListItem {
    let superseded_by = replacements.get(&r.serial).cloned();
    let expiring_soon = expires_soon.contains(&r.serial);
    CertListItem {
        serial: r.serial.into(),
        cn: r.cn,
        title: r.title,
        status: r.status,
        cert_type: r.cert_type,
        expiry_date: r.expiry_date,
        key_type: r.key_type,
        key_size: r.key_size,
        ignored_at: r.ignored_at,
        superseded_by,
        expiring_soon,
    }
}

#[tauri::command]
pub async fn list_certs(state: State<'_, AppState>) -> Result<Vec<CertListItem>, String> {
    cert_items(&mut *state.ensure_ca()?)
}

pub(crate) fn cert_items(conn: &mut Connection) -> Result<Vec<CertListItem>, String> {
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca.ca_database.as_mut()
        .ok_or("Database not loaded")?;

    db.process_ca_database(None, false).map_err(|e| e.to_string())?;

    let certs = db.query_all_certs().map_err(|e| e.to_string())?;
    let replacements = db.replacements.clone();
    let expires_soon = db.certs_expires_soon.clone();

    Ok(certs
        .into_iter()
        .map(|r| cert_list_item(r, &replacements, &expires_soon))
        .collect())
}

#[tauri::command]
pub async fn list_external_certs(state: State<'_, AppState>) -> Result<Vec<ExternalCertListItem>, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca.ca_database.as_mut()
        .ok_or("Database not loaded")?;

    db.process_ca_database(None, false).map_err(|e| e.to_string())?;

    let certs = db.query_all_external_certs(None).map_err(|e| e.to_string())?;

    Ok(certs.into_iter().map(|r| ExternalCertListItem {
        serial: Some(r.serial),
        cn: r.cn,
        status: r.status,
        cert_type: r.cert_type,
        expiry_date: r.expiry_date,
        issuer: r.issuer,
        import_date: r.import_date,
        key_type: r.key_type,
        key_size: r.key_size,
    }).collect())
}

/// Fast path: return whatever the local database already knows.
#[tauri::command]
pub async fn get_cert_info(
    state: State<'_, AppState>,
    serial: String,
) -> Result<CertDetail, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref()
        .ok_or("Database not loaded")?;

    let record = db.query_cert(&CertLookup::Serial(serial), false)
        .map_err(|e| e.to_string())?
        .ok_or("Certificate not found")?;

    let superseded_by = db.replacements.get(&record.serial).cloned();
    Ok(record_to_detail(&record, None, None, superseded_by))
}

/// Slow path: fetch the certificate bundle from 1Password, backfill any
/// missing metadata into the database, and return the enriched detail + PEM.
///
/// The 1Password database persist is deferred to a background task so the
/// user sees the result as soon as the cert bundle is retrieved — the
/// expensive `op document edit` no longer blocks the UI.
#[tauri::command]
pub async fn backfill_cert(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    serial: String,
) -> Result<CertDetail, String> {
    debug!("[tauri] backfill_cert: serial={serial}");
    let (result, needs_persist) = {
        let mut conn = state.ensure_ca()?;
        let ca = conn.ca.as_mut().ok_or("CA not available")?;

        let db = ca.ca_database.as_ref()
            .ok_or("Database not loaded")?;

        let mut record = db.query_cert(&CertLookup::Serial(serial), false)
            .map_err(|e| e.to_string())?
            .ok_or("Certificate not found")?;

        // Determine if metadata is missing — if so backfill from the bundle.
        // The has_*_key/has_chain flags also need backfilling for legacy
        // rows that pre-date the v9 schema.
        let needs_backfill = record.cert_type.is_none()
            || record.key_type.is_none()
            || record.subject.is_none()
            || record.not_before.is_none()
            || record.san.is_none()
            || record.issuer.is_none()
            || record.has_private_key.is_none()
            || record.has_chain.is_none();

        // Reuse the freshly-issued PEM captured during renew/rekey to skip the
        // 1Password round-trip — but only when the row is already complete and
        // has no chain to fetch (the cache holds the leaf cert only).
        let fresh_pem = state.take_fresh_pem(&record.serial);
        let skip_fetch = fresh_pem.is_some()
            && !needs_backfill
            && record.has_chain == Some(false);

        // Retrieve cert bundle from 1Password (for PEM and/or backfill)
        let title = record.title.as_deref().unwrap_or(&record.serial);
        let bundle = if skip_fetch {
            None
        } else {
            ca.retrieve_certbundle(title).ok().flatten()
        };
        if let Some(b) = &bundle {
            preload_unless_ca(&state, title, record.cert_type.as_deref(), b);
        }

        let cert_pem = fresh_pem
            .or_else(|| bundle.as_ref().and_then(|b| b.certificate_pem().ok()));
        let chain_pem = bundle.as_ref().and_then(|b| b.chain_pem());

        // A bundle can lack what the row is missing; upload only a row that changed.
        let did_backfill = needs_backfill
            && bundle.as_ref().is_some_and(|b| {
                let before = record.clone();
                backfill_record(&mut record, b);
                record != before
            });
        if did_backfill {
            if let Some(db) = ca.ca_database.as_mut() {
                let _ = db.update_cert(&record);
            }
        }

        let superseded_by = ca
            .ca_database
            .as_ref()
            .and_then(|db| db.replacements.get(&record.serial).cloned());
        (
            record_to_detail(&record, cert_pem, chain_pem, superseded_by),
            did_backfill,
        )
    }; // conn lock dropped — user gets result immediately

    // Persist updated database to 1Password in the background so the UI
    // is not blocked by the extra `op document edit` round-trip.
    if needs_persist {
        tauri::async_runtime::spawn_blocking(move || {
            let state: State<'_, AppState> = app.state();
            let _ = app.emit("op-status", Some("store_database"));
            let mut conn = state.conn.lock().expect("mutex poisoned — a prior operation panicked");
            if let Some(ca) = conn.ca.as_mut() {
                if let Err(e) = ca.store_ca_database() {
                    state.log_err("store_database", Some(e.to_string()));
                }
            }
            drop(conn);
            let _ = app.emit("op-status", None::<String>);
        });
    }

    Ok(result)
}

fn record_to_detail(
    record: &CertRecord,
    cert_pem: Option<String>,
    chain_pem: Option<String>,
    superseded_by: Option<String>,
) -> CertDetail {
    // Expiring-soon is a property of a still-valid cert; revoked/expired ones
    // never show the badge. Computed from the date so it's correct even before
    // a full classification scan has run for this session.
    let revoked = record.revocation_date.as_deref().is_some_and(|r| !r.is_empty())
        || record.status.as_deref() == Some("Revoked");
    let expiring_soon = !revoked
        && record.expiry_date.as_deref().is_some_and(is_expiring_soon);
    CertDetail {
        serial: Some(record.serial.clone()),
        cn: record.cn.clone(),
        title: record.title.clone(),
        status: record.status.clone(),
        cert_type: record.cert_type.clone(),
        expiry_date: record.expiry_date.clone(),
        key_type: record.key_type.clone(),
        key_size: record.key_size,
        subject: record.subject.clone(),
        issuer: record.issuer.clone(),
        not_before: record.not_before.clone(),
        revocation_date: record.revocation_date.clone(),
        san: record.san.clone(),
        cert_pem,
        ignored_at: record.ignored_at.clone(),
        ignored_by: record.ignored_by.clone(),
        ignored_reason: record.ignored_reason.clone(),
        ignored_note: record.ignored_note.clone(),
        superseded_by,
        has_private_key: record.has_private_key,
        has_chain: record.has_chain,
        chain_pem,
        expiring_soon,
    }
}

fn external_record_to_detail(
    record: &ExternalCertRecord,
    cert_pem: Option<String>,
    chain_pem: Option<String>,
) -> ExternalCertDetail {
    ExternalCertDetail {
        serial: Some(record.serial.clone()),
        cn: record.cn.clone(),
        title: record.title.clone(),
        status: record.status.clone(),
        cert_type: record.cert_type.clone(),
        expiry_date: record.expiry_date.clone(),
        key_type: record.key_type.clone(),
        key_size: record.key_size,
        subject: record.subject.clone(),
        issuer: record.issuer.clone(),
        issuer_subject: record.issuer_subject.clone(),
        not_before: record.not_before.clone(),
        import_date: record.import_date.clone(),
        san: record.san.clone(),
        cert_pem,
        has_private_key: record.has_private_key,
        has_chain: record.has_chain,
        chain_pem,
    }
}

/// Fill in missing fields on a CertRecord from a CertificateBundle.
fn backfill_record(record: &mut CertRecord, bundle: &CertificateBundle) {
    let attr = |name: &str| -> Option<String> {
        bundle.get_certificate_attrib(name).ok().flatten()
    };

    if record.cert_type.is_none() {
        record.cert_type = Some(bundle.cert_type.to_string());
    }
    if record.key_type.is_none() {
        record.key_type = attr("key_type");
    }
    if record.key_size.is_none() {
        record.key_size = attr("key_size").and_then(|s| s.parse().ok());
    }
    if record.subject.is_none() {
        record.subject = attr("subject");
    }
    if record.issuer.is_none() {
        record.issuer = attr("issuer");
    }
    if record.not_before.is_none() {
        record.not_before = attr("not_before");
    }
    if record.expiry_date.is_none() {
        record.expiry_date = attr("not_after");
    }
    if record.san.is_none() {
        record.san = attr("san");
    }
    if record.cn.as_ref().is_none_or(|s| s.is_empty()) {
        record.cn = attr("cn");
    }
    if record.has_private_key.is_none() {
        record.has_private_key = Some(bundle.private_key.is_some());
    }
    if record.has_chain.is_none() {
        record.has_chain = Some(bundle.chain.as_ref().is_some_and(|c| !c.is_empty()));
    }
}

#[tauri::command]
pub async fn create_cert(
    state: State<'_, AppState>,
    request: CreateCertRequest,
) -> Result<CertListItem, String> {
    info!("[tauri] create_cert: cn='{}' type='{}'", request.cn, request.cert_type);
    let cert_type: CertType = request.cert_type.parse()
        .map_err(|e: opca_core::error::OpcaError| e.to_string())?;

    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    // Build config from CA's current config + request
    let db = ca.ca_database.as_ref()
        .ok_or("Database not loaded")?;
    let ca_config = db.get_config().map_err(|e| e.to_string())?;

    let bundle_config = CertBundleConfig {
        cn: Some(request.cn.clone()),
        key_algorithm: request.key_algorithm,
        org: ca_config.org,
        ou: ca_config.ou,
        email: ca_config.email,
        city: ca_config.city,
        state: ca_config.state,
        country: ca_config.country,
        alt_names: request.alt_names,
        next_serial: ca_config.next_serial,
        ca_days: ca_config.days,
    };

    let (bundle, issuance_warnings) = ca.generate_certificate_bundle(cert_type.clone(), &request.cn, bundle_config, None)
        .map_err(|e| {
            warn!("[tauri] create_cert failed: {e}");
            state.log_err("create_cert", Some(e.to_string()));
            e.to_string()
        })?;

    for w in &issuance_warnings {
        state.log_ok("create_cert", Some(w.message.clone()));
    }

    state.log_ok("create_cert", Some(format!("Created {} cert '{}'", cert_type, request.cn)));

    let serial = bundle.get_certificate_attrib("serial")
        .ok()
        .flatten()
        .unwrap_or_default();

    Ok(CertListItem {
        serial: Some(serial),
        cn: Some(request.cn),
        title: Some(bundle.title.clone()),
        status: Some("Valid".to_string()),
        cert_type: Some(cert_type.to_string()),
        expiry_date: bundle.get_certificate_attrib("not_after").ok().flatten(),
        key_type: bundle.get_certificate_attrib("key_type").ok().flatten(),
        key_size: bundle.get_certificate_attrib("key_size")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok()),
        ignored_at: None,
        superseded_by: None,
        expiring_soon: false,
    })
}

#[tauri::command]
pub async fn revoke_cert(
    state: State<'_, AppState>,
    serial: String,
) -> Result<bool, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] revoke_cert: serial={serial}");
    ca.revoke_certificate(&CertLookup::Serial(serial.clone()))
        .map_err(|e| {
            warn!("[tauri] revoke_cert failed: {e}");
            state.log_err("revoke_cert", Some(e.to_string()));
            e.to_string()
        })?;

    state.log_ok("revoke_cert", Some(format!("Revoked certificate {}", serial)));
    Ok(true)
}

#[tauri::command]
pub async fn renew_cert(
    state: State<'_, AppState>,
    serial: String,
) -> Result<RenewRekeyResult, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] renew_cert: serial={serial}");
    let (new_pem, new_serial, issuance_warnings) = ca.renew_certificate_bundle(&CertLookup::Serial(serial.clone()), None)
        .map_err(|e| {
            warn!("[tauri] renew_cert failed: {e}");
            state.log_err("renew_cert", Some(e.to_string()));
            e.to_string()
        })?;

    for w in &issuance_warnings {
        state.log_ok("renew_cert", Some(w.message.clone()));
    }

    state.log_ok("renew_cert", Some(format!("Renewed certificate {serial} → {new_serial}")));
    state.cache_fresh_pem(new_serial.clone(), new_pem.clone());
    Ok(RenewRekeyResult { serial: new_serial, pem: new_pem })
}

#[tauri::command]
pub async fn rekey_cert(
    state: State<'_, AppState>,
    serial: String,
    key_algorithm: Option<KeyAlgorithm>,
) -> Result<RenewRekeyResult, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] rekey_cert: serial={serial}");
    let (new_pem, new_serial, issuance_warnings) = ca.rekey_certificate_bundle(&CertLookup::Serial(serial.clone()), key_algorithm, None)
        .map_err(|e| {
            warn!("[tauri] rekey_cert failed: {e}");
            state.log_err("rekey_cert", Some(e.to_string()));
            e.to_string()
        })?;

    for w in &issuance_warnings {
        state.log_ok("rekey_cert", Some(w.message.clone()));
    }

    state.log_ok("rekey_cert", Some(format!("Rekeyed certificate {serial} → {new_serial}")));
    state.cache_fresh_pem(new_serial.clone(), new_pem.clone());
    Ok(RenewRekeyResult { serial: new_serial, pem: new_pem })
}

#[tauri::command]
pub async fn ignore_cert(
    state: State<'_, AppState>,
    serial: String,
    note: Option<String>,
) -> Result<(), String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] ignore_cert: serial={serial}");
    ca.ignore_certificate(&serial, note.as_deref())
        .map_err(|e| {
            warn!("[tauri] ignore_cert failed: {e}");
            state.log_err("ignore_cert", Some(e.to_string()));
            e.to_string()
        })?;

    state.log_ok("ignore_cert", Some(format!("Ignored certificate {serial}")));
    Ok(())
}

#[tauri::command]
pub async fn unignore_cert(
    state: State<'_, AppState>,
    serial: String,
) -> Result<(), String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] unignore_cert: serial={serial}");
    ca.unignore_certificate(&serial)
        .map_err(|e| {
            warn!("[tauri] unignore_cert failed: {e}");
            state.log_err("unignore_cert", Some(e.to_string()));
            e.to_string()
        })?;

    state.log_ok("unignore_cert", Some(format!("Cleared ignore on certificate {serial}")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bulk operations
// ---------------------------------------------------------------------------
//
// Each bulk command takes ONE CA borrow for the whole loop, calling the same
// `ca.*` core method the single command uses. The frontend wraps the single
// invocation in one `withLock`, so a batch of N certs costs one vault-lock
// cycle rather than N. Per-cert failures are collected into the result vec and
// the loop continues; the command-level `Err` is reserved for the CA being
// unavailable. Each `ca.*` flushes to 1Password internally, so a batch of N
// still does N flushes — acceptable for now; batching them is future work.

/// Run a per-cert action across `serials` under one CA borrow, collecting a
/// `BulkCertResult` each. `action` returns the new serial for rekey/renew (and
/// is where they cache the fresh PEM), or `None` for revoke/ignore/unignore.
/// A `bulk-progress` event is emitted before each item ("{verb} {n}/{total}")
/// so the status indicator climbs through the batch rather than showing the
/// raw command name.
fn run_bulk_cert_op<F>(
    app: &AppHandle,
    state: &State<'_, AppState>,
    serials: Vec<String>,
    label: &str,
    verb: &str,
    mut action: F,
) -> Result<Vec<BulkCertResult>, String>
where
    F: FnMut(&mut CertificateAuthority<ShellRunner>, &str) -> Result<Option<String>, OpcaError>,
{
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let total = serials.len();
    info!("[tauri] {label}: {total} cert(s)");
    let mut results = Vec::with_capacity(total);
    let (mut ok, mut fail) = (0usize, 0usize);
    for (i, serial) in serials.into_iter().enumerate() {
        BulkProgress::emit(app, verb, i + 1, total);
        match action(ca, &serial) {
            Ok(new_serial) => {
                results.push(BulkCertResult { serial, ok: true, error: None, new_serial });
                ok += 1;
            }
            Err(e) => {
                warn!("[tauri] {label}: {serial} failed: {e}");
                results.push(BulkCertResult { serial, ok: false, error: Some(e.to_string()), new_serial: None });
                fail += 1;
            }
        }
    }

    state.log_ok(label, Some(format!("{ok} succeeded, {fail} failed")));
    Ok(results)
}

#[tauri::command]
pub async fn bulk_rekey_certs(
    app: AppHandle,
    state: State<'_, AppState>,
    serials: Vec<String>,
    key_algorithm: Option<KeyAlgorithm>,
) -> Result<Vec<BulkCertResult>, String> {
    run_bulk_cert_op(&app, &state, serials, "bulk_rekey", "Rekeying", |ca, serial| {
        let (new_pem, new_serial, warnings) =
            ca.rekey_certificate_bundle(&CertLookup::Serial(serial.to_string()), key_algorithm, None)?;
        for w in warnings {
            state.log_ok("bulk_rekey", Some(w.message));
        }
        state.cache_fresh_pem(new_serial.clone(), new_pem);
        Ok(Some(new_serial))
    })
}

#[tauri::command]
pub async fn bulk_renew_certs(
    app: AppHandle,
    state: State<'_, AppState>,
    serials: Vec<String>,
) -> Result<Vec<BulkCertResult>, String> {
    run_bulk_cert_op(&app, &state, serials, "bulk_renew", "Renewing", |ca, serial| {
        let (new_pem, new_serial, warnings) =
            ca.renew_certificate_bundle(&CertLookup::Serial(serial.to_string()), None)?;
        for w in warnings {
            state.log_ok("bulk_renew", Some(w.message));
        }
        state.cache_fresh_pem(new_serial.clone(), new_pem);
        Ok(Some(new_serial))
    })
}

#[tauri::command]
pub async fn bulk_revoke_certs(
    app: AppHandle,
    state: State<'_, AppState>,
    serials: Vec<String>,
) -> Result<Vec<BulkCertResult>, String> {
    run_bulk_cert_op(&app, &state, serials, "bulk_revoke", "Revoking", |ca, serial| {
        ca.revoke_certificate(&CertLookup::Serial(serial.to_string())).map(|_| None)
    })
}

#[tauri::command]
pub async fn bulk_ignore_certs(
    app: AppHandle,
    state: State<'_, AppState>,
    serials: Vec<String>,
    note: Option<String>,
) -> Result<Vec<BulkCertResult>, String> {
    run_bulk_cert_op(&app, &state, serials, "bulk_ignore", "Ignoring", |ca, serial| {
        ca.ignore_certificate(serial, note.as_deref()).map(|_| None)
    })
}

#[tauri::command]
pub async fn bulk_unignore_certs(
    app: AppHandle,
    state: State<'_, AppState>,
    serials: Vec<String>,
) -> Result<Vec<BulkCertResult>, String> {
    run_bulk_cert_op(&app, &state, serials, "bulk_unignore", "Clearing ignore on", |ca, serial| {
        ca.unignore_certificate(serial).map(|_| None)
    })
}

#[tauri::command]
pub async fn import_cert(
    state: State<'_, AppState>,
    request: ImportCertRequest,
) -> Result<ImportCertResult, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] import_cert");
    let cert_pem = request.cert_pem.as_bytes();
    let key_pem = request.key_pem.as_deref().map(|s| s.as_bytes());
    let chain_pem = request.chain_pem.as_deref().map(|s| s.as_bytes());
    let passphrase = request.passphrase.as_deref().map(|s| s.as_bytes());

    let bundle = ca.import_certificate_bundle(
        cert_pem,
        key_pem,
        chain_pem,
        passphrase,
        None, // title derived from certificate CN
    ).map_err(|e| {
        state.log_err("import_cert", Some(e.to_string()));
        e.to_string()
    })?;

    let is_external = matches!(bundle.cert_type, CertType::External);
    let cn = bundle.get_certificate_attrib("cn").ok().flatten().unwrap_or_default();
    let serial = bundle.get_certificate_attrib("serial").ok().flatten().unwrap_or_default();

    state.log_ok("import_cert", Some(format!(
        "Imported {} cert '{}'",
        if is_external { "external" } else { "local" },
        cn,
    )));

    Ok(ImportCertResult {
        cert: CertListItem {
            serial: Some(serial),
            cn: Some(cn),
            title: Some(bundle.title.clone()),
            status: Some("Valid".to_string()),
            cert_type: Some(bundle.cert_type.to_string()),
            expiry_date: bundle.get_certificate_attrib("not_after").ok().flatten(),
            key_type: bundle.get_certificate_attrib("key_type").ok().flatten(),
            key_size: bundle.get_certificate_attrib("key_size")
                .ok()
                .flatten()
                .and_then(|s| s.parse().ok()),
            ignored_at: None,
            superseded_by: None,
            expiring_soon: false,
        },
        is_external,
    })
}

/// Fast path: external cert detail from the local database only.
#[tauri::command]
pub async fn get_external_cert_info(
    state: State<'_, AppState>,
    serial: String,
) -> Result<ExternalCertDetail, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;

    let record = db
        .query_external_cert(&CertLookup::Serial(serial), false)
        .map_err(|e| e.to_string())?
        .ok_or("External certificate not found")?;

    Ok(external_record_to_detail(&record, None, None))
}

/// Slow path: fetch the external cert bundle from 1Password, return cert
/// and chain PEM, and persist any missing has_private_key / has_chain flags
/// so subsequent fast-path reads can show availability without a roundtrip.
#[tauri::command]
pub async fn backfill_external_cert(
    state: State<'_, AppState>,
    serial: String,
) -> Result<ExternalCertDetail, String> {
    debug!("[tauri] backfill_external_cert: serial={serial}");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;
    let mut record = db
        .query_external_cert(&CertLookup::Serial(serial), false)
        .map_err(|e| e.to_string())?
        .ok_or("External certificate not found")?;

    let title = external_item_title(&record)?;
    let bundle = ca.retrieve_certbundle(&title).ok().flatten();
    if let Some(b) = &bundle {
        preload_unless_ca(&state, &title, record.cert_type.as_deref(), b);
    }

    let cert_pem = bundle.as_ref().and_then(|b| b.certificate_pem().ok());
    let chain_pem = bundle.as_ref().and_then(|b| b.chain_pem());

    if let Some(ref b) = bundle {
        let new_pk = Some(b.private_key.is_some());
        let new_chain = Some(b.chain.as_ref().is_some_and(|c| !c.is_empty()));
        if record.has_private_key != new_pk || record.has_chain != new_chain {
            record.has_private_key = new_pk;
            record.has_chain = new_chain;
            if let Some(db) = ca.ca_database.as_mut() {
                let _ = db.update_external_cert(&record);
            }
        }
    }

    Ok(external_record_to_detail(&record, cert_pem, chain_pem))
}

/// Return the PEM-encoded private key for a CA-issued certificate, optionally
/// passphrase-encrypted, so the user can copy it to the clipboard. Never log or
/// persist the key value.
///
/// Refuses to export CA private keys: the CA key is the root of trust for
/// every cert OPCA has issued, and we don't want a stray clipboard write to be
/// the way it leaves the vault. Anyone needing the CA key for a legitimate
/// migration can fetch it directly via `op` against the `CA` item.
#[tauri::command]
pub async fn get_cert_private_key(
    state: State<'_, AppState>,
    serial: String,
    passphrase: Option<String>,
) -> Result<String, String> {
    info!("[tauri] get_cert_private_key: serial={serial}");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;
    let record = db
        .query_cert(&CertLookup::Serial(serial.clone()), false)
        .map_err(|e| e.to_string())?
        .ok_or("Certificate not found")?;

    let title = record.title.as_deref().unwrap_or(&record.serial);
    let key = export_leaf_key(&state, ca, title, record.cert_type.as_deref(), passphrase.as_deref())?;
    state.log_ok(
        "get_cert_private_key",
        Some(format!("Exported private key for cert {serial}{}", encrypted_note(passphrase.as_deref()))),
    );
    Ok(key)
}

/// A leaf certificate's private key — preloaded by its backfill, else fetched —
/// optionally re-encrypted with `passphrase`.
fn export_leaf_key(
    state: &AppState,
    ca: &mut CertificateAuthority<ShellRunner>,
    title: &str,
    cert_type: Option<&str>,
    passphrase: Option<&str>,
) -> Result<String, String> {
    let pem = match state.preloaded_key(title) {
        Some(pem) => pem,
        None => {
            let bundle = ca
                .retrieve_certbundle(title)
                .map_err(|e| e.to_string())?
                .ok_or("Certificate item not found in 1Password")?;
            bail_if_ca_certificate(cert_type, &bundle)?;
            Zeroizing::new(
                bundle
                    .private_key_pem()
                    .map_err(|_| "No private key stored for this certificate".to_string())?,
            )
        }
    };
    encrypt_if_asked(&pem, passphrase)
}

pub(crate) fn encrypt_if_asked(pem: &str, passphrase: Option<&str>) -> Result<String, String> {
    match passphrase.filter(|p| !p.is_empty()) {
        Some(p) => encrypt_private_key_pem(pem, p).map_err(|e| e.to_string()),
        None => Ok(pem.to_string()),
    }
}

pub(crate) fn encrypted_note(passphrase: Option<&str>) -> &'static str {
    if passphrase.is_some_and(|p| !p.is_empty()) {
        " (passphrase-encrypted)"
    } else {
        ""
    }
}

/// Keep the bundle's key for a quick copy, but never a CA's.
fn preload_unless_ca(state: &AppState, title: &str, cert_type: Option<&str>, bundle: &CertificateBundle) {
    if bail_if_ca_certificate(cert_type, bundle).is_ok() {
        state.preload_key(title, bundle);
    } else {
        state.forget_preloaded_key();
    }
}

#[tauri::command]
pub async fn forget_preloaded_key(state: State<'_, AppState>) -> Result<(), String> {
    state.forget_preloaded_key();
    Ok(())
}

fn is_ca_cert_type(cert_type: Option<&str>) -> bool {
    cert_type.is_some_and(|t| t.eq_ignore_ascii_case("ca"))
}

/// Refuse to surface the private key when the cert is — or appears to be —
/// a CA. Two checks deliberately:
///
/// - `cert_type` from the local DB row is fast but can be stale or wrong if
///   an import mislabelled the type.
/// - The X.509 BasicConstraints flag on the actual bundle is authoritative,
///   but only available after a vault round-trip.
///
/// Both layers must say "not CA" before we expose the key.
fn bail_if_ca_certificate(
    cert_type: Option<&str>,
    bundle: &CertificateBundle,
) -> Result<(), String> {
    let by_type = is_ca_cert_type(cert_type);
    let by_constraints = bundle.is_ca_certificate().unwrap_or(false);
    if by_type || by_constraints {
        return Err(
            "Refusing to export a CA private key. If you genuinely need it, retrieve it from 1Password directly."
                .into(),
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertScope {
    Local,
    External,
}

impl CertScope {
    fn label(&self) -> &'static str {
        match self {
            CertScope::Local => "cert",
            CertScope::External => "external cert",
        }
    }
    fn token(&self) -> &'static str {
        match self {
            CertScope::Local => "local",
            CertScope::External => "external",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertCopyKind {
    Certificate,
    Chain,
}

impl CertCopyKind {
    fn label(&self) -> &'static str {
        match self {
            CertCopyKind::Certificate => "certificate PEM",
            CertCopyKind::Chain => "issuer chain",
        }
    }
    fn token(&self) -> &'static str {
        match self {
            CertCopyKind::Certificate => "certificate",
            CertCopyKind::Chain => "chain",
        }
    }
}

/// Frontend tells us when the user copied a non-secret cert artefact (the
/// cert PEM or chain PEM) so it lands in the audit log alongside the
/// private-key exports. The artefact bytes don't cross this boundary — the
/// frontend already has them from `backfill_cert` / `backfill_external_cert`
/// and writes directly to the clipboard. We're only recording the action.
#[tauri::command]
pub async fn record_cert_copy(
    state: State<'_, AppState>,
    scope: CertScope,
    serial: String,
    kind: CertCopyKind,
) -> Result<(), String> {
    let action = format!("copy_{}_{}", scope.token(), kind.token());
    state.log_ok(
        &action,
        Some(format!(
            "Copied {} for {} {serial}",
            kind.label(),
            scope.label()
        )),
    );
    Ok(())
}

/// External-cert counterpart of `get_cert_private_key`. Refuses to export
/// keys belonging to imported CA certificates for the same reason as the
/// local-cert version.
#[tauri::command]
pub async fn get_external_cert_private_key(
    state: State<'_, AppState>,
    serial: String,
    passphrase: Option<String>,
) -> Result<String, String> {
    info!("[tauri] get_external_cert_private_key: serial={serial}");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;
    let record = db
        .query_external_cert(&CertLookup::Serial(serial.clone()), false)
        .map_err(|e| e.to_string())?
        .ok_or("External certificate not found")?;

    let title = external_item_title(&record)?;
    let key = export_leaf_key(&state, ca, &title, record.cert_type.as_deref(), passphrase.as_deref())?;
    state.log_ok(
        "get_external_cert_private_key",
        Some(format!("Exported private key for external cert {serial}{}", encrypted_note(passphrase.as_deref()))),
    );
    Ok(key)
}

#[tauri::command]
pub async fn inspect_certificate(cert_pem: String) -> Result<InspectCertificateResult, String> {
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| format!("Failed to parse certificate PEM: {e}"))?;

    let text_bytes = cert
        .to_text()
        .map_err(|e| format!("Failed to render certificate text: {e}"))?;
    let text_dump = String::from_utf8_lossy(&text_bytes).to_string();

    let public_key = cert
        .public_key()
        .map_err(|e| format!("Failed to read public key: {e}"))?;
    let (key_type, key_size, public_key_fingerprint_sha256) = public_key_summary(&public_key)?;

    let signature_algorithm = signature_algorithm_from_text(&text_dump);

    let cn = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());

    let subject = x509_name_to_rdn_string(cert.subject_name());
    let issuer = x509_name_to_rdn_string(cert.issuer_name());

    let serial = cert
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_dec_str().ok())
        .map(|s| s.to_string());

    let not_before = asn1_time_to_string(cert.not_before());
    let not_after = asn1_time_to_string(cert.not_after());

    let alt_names = san::of_certificate(&cert).iter().map(ToString::to_string).collect();

    let is_ca = text_dump.contains("CA:TRUE");

    Ok(InspectCertificateResult {
        cn,
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        alt_names,
        key_type,
        key_size,
        signature_algorithm,
        public_key_fingerprint_sha256,
        is_ca,
        text_dump,
    })
}

fn asn1_time_to_string(time: &openssl::asn1::Asn1TimeRef) -> Option<String> {
    let s = time.to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod preload_tests {
    use super::*;
    use opca_core::services::cert::KeyAlgorithm;

    fn bundle(cert_type: CertType) -> CertificateBundle {
        let config = CertBundleConfig {
            cn: Some("t".into()),
            key_algorithm: Some(KeyAlgorithm::EcP256),
            next_serial: Some(1),
            ca_days: Some(1),
            ..CertBundleConfig::default()
        };
        let mut b = CertificateBundle::generate(cert_type.clone(), "t", config).unwrap();
        if cert_type == CertType::Ca {
            b.self_sign_ca().unwrap();
        }
        b
    }

    #[test]
    fn a_leaf_key_is_preloaded_for_its_own_item_only() {
        let state = AppState::default();
        let leaf = bundle(CertType::WebServer);
        preload_unless_ca(&state, "CRT_1_web", Some("webserver"), &leaf);
        assert_eq!(*state.preloaded_key("CRT_1_web").unwrap(), leaf.private_key_pem().unwrap());
        assert!(state.preloaded_key("CRT_2_other").is_none());
        state.forget_preloaded_key();
        assert!(state.preloaded_key("CRT_1_web").is_none());
    }

    #[test]
    fn a_ca_key_is_never_preloaded_and_clears_the_slot() {
        let state = AppState::default();
        preload_unless_ca(&state, "CRT_1_web", Some("webserver"), &bundle(CertType::WebServer));
        preload_unless_ca(&state, "CA", Some("ca"), &bundle(CertType::Ca));
        assert!(state.preloaded_key("CA").is_none());
        assert!(state.preloaded_key("CRT_1_web").is_none());
    }

    #[test]
    fn an_empty_passphrase_means_unencrypted() {
        let pem = bundle(CertType::WebServer).private_key_pem().unwrap();
        assert_eq!(encrypt_if_asked(&pem, Some("")).unwrap(), pem);
        assert!(encrypt_if_asked(&pem, Some("pw")).unwrap().contains("ENCRYPTED PRIVATE KEY"));
    }
}
