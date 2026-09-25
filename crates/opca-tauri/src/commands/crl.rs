use chrono::Utc;
use log::{debug, info, warn};
use openssl::x509::X509Crl;
use tauri::State;

use opca_core::constants::CRL_BATCH_LOW_COVER;
use opca_core::services::ca::{crl_metadata_from, crl_to_text, parse_crl_metadata};
use opca_core::services::database::{CertificateAuthorityDB, CrlMetadata};
use opca_core::utils::datetime::{format_datetime, DateTimeFormat};

use crate::commands::dto::{CrlBatchDto, CrlInfo, InspectCrlResult};
use crate::commands::inspect_helpers::signature_algorithm_from_text;
use crate::state::AppState;

/// Project the database CRL metadata (and optionally the just-fetched PEM)
/// into the wire DTO, with the store and batch state beside it.
fn make_crl_info(
    db: &CertificateAuthorityDB,
    metadata: Option<CrlMetadata>,
    crl_pem: Option<String>,
    has_crl: Option<bool>,
) -> Result<CrlInfo, String> {
    let config = db.get_config().unwrap_or_default();
    let crl_batch_enabled = config.crl_batch_enabled == Some(true);
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
    Ok(CrlInfo {
        issuer,
        last_update,
        next_update,
        crl_number,
        revoked_count,
        crl_pem,
        has_public_store: config.ca_public_store.is_some(),
        has_crl,
        crl_batch_enabled,
        crl_batch: crl_batch_dto(db, crl_batch_enabled)?,
    })
}

/// The Lambda ignores a batch while batches are off, so a leftover record covers nothing.
pub(crate) fn crl_batch_dto(db: &CertificateAuthorityDB, enabled: bool) -> Result<Option<CrlBatchDto>, String> {
    if !enabled {
        return Ok(None);
    }
    let batch = db.get_crl_batch().map_err(|e| e.to_string())?;
    Ok(batch.map(|batch| {
        let status = batch.status(Utc::now());
        CrlBatchDto {
            first_number: batch.first_number,
            last_number: batch.first_number + batch.count - 1,
            due_number: status.due_number,
            signed_until: format_datetime(status.signed_until, DateTimeFormat::Openssl),
            remaining: status.remaining,
            count: status.count,
            low_cover: status.remaining < CRL_BATCH_LOW_COVER,
        }
    }))
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
    make_crl_info(db, metadata, None, None)
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
    let has_crl = Some(crl_pem.is_some());

    if metadata.is_none() {
        if let Some(ref pem) = crl_pem {
            metadata = parse_crl_metadata(pem).ok();
        }
    }

    make_crl_info(db, metadata, crl_pem, has_crl)
}

#[tauri::command]
pub async fn inspect_crl(crl_pem: String) -> Result<InspectCrlResult, String> {
    let crl = X509Crl::from_pem(crl_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CRL PEM: {e}"))?;

    let text_dump = crl_to_text(&crl).map_err(|e| format!("Failed to render CRL text: {e}"))?;
    let metadata = crl_metadata_from(&crl);
    let signature_algorithm = signature_algorithm_from_text(&text_dump);

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
    make_crl_info(db, metadata, Some(crl_pem), Some(true))
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
