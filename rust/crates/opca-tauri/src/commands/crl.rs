use log::{debug, info, warn};
use openssl::x509::X509Crl;
use tauri::State;

use opca_core::services::ca::{crl_metadata_from, crl_to_text, parse_crl_metadata};
use opca_core::services::database::CrlMetadata;

use crate::commands::dto::{CrlInfo, InspectCrlResult};
use crate::state::AppState;

/// Project the database CRL metadata (and optionally the just-fetched PEM)
/// into the wire DTO. Pulls the three near-duplicate constructions in
/// `get_crl_info`, `backfill_crl`, and `generate_crl` into one place.
fn make_crl_info(
    metadata: Option<CrlMetadata>,
    crl_pem: Option<String>,
    has_public_store: bool,
    has_crl: Option<bool>,
) -> CrlInfo {
    let (issuer, last_update, next_update, crl_number, revoked_count) = match metadata {
        Some(m) => (
            m.issuer,
            m.last_update,
            m.next_update,
            m.crl_number,
            m.revoked_count.unwrap_or(0) as usize,
        ),
        None => (None, None, None, None, 0),
    };
    CrlInfo {
        issuer,
        last_update,
        next_update,
        crl_number,
        revoked_count,
        crl_pem,
        has_public_store,
        has_crl,
    }
}

/// Fast path: CRL detail purely from the local SQLite mirror, no vault
/// round-trip. The frontend invokes [`backfill_crl`] afterwards to load the
/// PEM and confirm presence in 1Password.
#[tauri::command]
pub async fn get_crl_info(state: State<'_, AppState>) -> Result<CrlInfo, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;

    let metadata = db.get_crl_metadata().map_err(|e| e.to_string())?;
    let has_public_store = db
        .get_config()
        .map(|c| c.ca_public_store.is_some())
        .unwrap_or(false);

    Ok(make_crl_info(metadata, None, has_public_store, None))
}

/// Slow path: fetch the CRL PEM from 1Password. If the local DB row is
/// missing, parse metadata directly out of the PEM so the detail page still
/// has something to render.
#[tauri::command]
pub async fn backfill_crl(state: State<'_, AppState>) -> Result<CrlInfo, String> {
    debug!("[tauri] backfill_crl");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let crl_pem = ca.get_crl().map_err(|e| e.to_string())?.map(|s| s.to_string());

    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;
    let mut metadata = db.get_crl_metadata().map_err(|e| e.to_string())?;
    let has_public_store = db
        .get_config()
        .map(|c| c.ca_public_store.is_some())
        .unwrap_or(false);
    let has_crl = Some(crl_pem.is_some());

    if metadata.is_none() {
        if let Some(ref pem) = crl_pem {
            metadata = parse_crl_metadata(pem).ok();
        }
    }

    Ok(make_crl_info(metadata, crl_pem, has_public_store, has_crl))
}

#[tauri::command]
pub async fn inspect_crl(crl_pem: String) -> Result<InspectCrlResult, String> {
    let crl = X509Crl::from_pem(crl_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CRL PEM: {e}"))?;

    let text_dump = crl_to_text(&crl).map_err(|e| format!("Failed to render CRL text: {e}"))?;
    let metadata = crl_metadata_from(&crl);

    // openssl-rs doesn't surface signature_algorithm() on X509Crl, so recover
    // it from the text dump (every dump has a "Signature Algorithm:" line).
    let signature_algorithm = text_dump
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("Signature Algorithm:")
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "Unknown".to_string());

    Ok(InspectCrlResult {
        issuer: metadata.issuer.unwrap_or_default(),
        last_update: metadata.last_update,
        next_update: metadata.next_update,
        crl_number: metadata.crl_number,
        revoked_count: metadata.revoked_count.unwrap_or(0),
        signature_algorithm,
        text_dump,
    })
}

#[tauri::command]
pub async fn generate_crl(state: State<'_, AppState>) -> Result<CrlInfo, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] generate_crl");
    let crl_pem = ca.generate_crl().map_err(|e| {
        warn!("[tauri] generate_crl failed: {e}");
        state.log_err("generate_crl", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok("generate_crl", Some("CRL generated and stored".to_string()));

    let db = ca.ca_database.as_ref().ok_or("Database not loaded")?;
    let metadata = db.get_crl_metadata().map_err(|e| e.to_string())?;
    let has_public_store = db
        .get_config()
        .map(|c| c.ca_public_store.is_some())
        .unwrap_or(false);

    Ok(make_crl_info(
        metadata,
        Some(crl_pem),
        has_public_store,
        Some(true),
    ))
}

#[tauri::command]
pub async fn upload_crl(state: State<'_, AppState>) -> Result<(), String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    info!("[tauri] upload_crl");
    ca.upload_crl("").map_err(|e| {
        warn!("[tauri] upload_crl failed: {e}");
        state.log_err("upload_crl", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok("upload_crl", Some("CRL uploaded to public store".to_string()));
    Ok(())
}

/// Audit-log a clipboard copy of the CRL document. The PEM doesn't cross
/// this boundary — the frontend already has it from `backfill_crl` or
/// `generate_crl`. Mirrors `record_cert_copy`.
#[tauri::command]
pub async fn record_crl_copy(state: State<'_, AppState>) -> Result<(), String> {
    state.log_ok("copy_crl", Some("Copied CRL document".to_string()));
    Ok(())
}
