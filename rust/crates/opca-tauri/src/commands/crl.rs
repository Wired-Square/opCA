use log::{info, warn};
use tauri::State;

use opca_core::services::ca::parse_crl_metadata;

use crate::commands::dto::CrlInfo;
use crate::state::AppState;

#[tauri::command]
pub async fn get_crl_info(state: State<'_, AppState>) -> Result<CrlInfo, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref()
        .ok_or("Database not loaded")?;

    let metadata = db.get_crl_metadata().map_err(|e| e.to_string())?;
    let has_public_store = db.get_config()
        .map(|c| c.ca_public_store.is_some())
        .unwrap_or(false);

    // Get the CRL PEM from 1Password
    let crl_pem = ca.get_crl()
        .map_err(|e| e.to_string())?
        .map(|s| s.to_string());

    // If we have DB metadata, use it directly
    if let Some(m) = metadata {
        return Ok(CrlInfo {
            issuer: m.issuer,
            last_update: m.last_update,
            next_update: m.next_update,
            crl_number: m.crl_number,
            revoked_count: m.revoked_count.unwrap_or(0) as usize,
            crl_pem,
            has_public_store,
        });
    }

    // No metadata in DB — try to parse from the CRL PEM
    if let Some(ref pem) = crl_pem {
        if let Ok(m) = parse_crl_metadata(pem) {
            return Ok(CrlInfo {
                issuer: m.issuer,
                last_update: m.last_update,
                next_update: m.next_update,
                crl_number: m.crl_number,
                revoked_count: m.revoked_count.unwrap_or(0) as usize,
                crl_pem,
                has_public_store,
            });
        }
    }

    Ok(CrlInfo {
        issuer: None,
        last_update: None,
        next_update: None,
        crl_number: None,
        revoked_count: 0,
        crl_pem,
        has_public_store,
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

    // Re-read metadata after generation
    let db = ca.ca_database.as_ref()
        .ok_or("Database not loaded")?;

    let metadata = db.get_crl_metadata().map_err(|e| e.to_string())?;
    let has_public_store = db.get_config()
        .map(|c| c.ca_public_store.is_some())
        .unwrap_or(false);

    match metadata {
        Some(m) => Ok(CrlInfo {
            issuer: m.issuer,
            last_update: m.last_update,
            next_update: m.next_update,
            crl_number: m.crl_number,
            revoked_count: m.revoked_count.unwrap_or(0) as usize,
            crl_pem: Some(crl_pem),
            has_public_store,
        }),
        None => Ok(CrlInfo {
            issuer: None,
            last_update: None,
            next_update: None,
            crl_number: None,
            revoked_count: 0,
            crl_pem: Some(crl_pem),
            has_public_store,
        }),
    }
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
