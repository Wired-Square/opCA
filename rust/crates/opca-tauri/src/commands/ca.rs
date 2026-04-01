use std::collections::HashMap;

use log::{info, warn, error, debug};
use tauri::State;

use opca_core::services::ca::CertificateAuthority;
use opca_core::services::database::CaConfig;

use crate::commands::dto::{CaConfigDto, CaInfo};
use crate::state::AppState;

#[tauri::command]
pub async fn get_ca_info(state: State<'_, AppState>) -> Result<CaInfo, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    let bundle = ca.ca_bundle.as_ref()
        .ok_or("CA certificate not loaded")?;

    let attr = |name: &str| -> Option<String> {
        bundle.get_certificate_attrib(name).ok().flatten()
    };

    let is_valid = ca.is_valid().unwrap_or(false);
    let cert_pem = bundle.certificate_pem().ok();

    Ok(CaInfo {
        cn: attr("cn"),
        subject: attr("subject"),
        issuer: attr("issuer"),
        serial: attr("serial"),
        not_before: attr("not_before"),
        not_after: attr("not_after"),
        key_type: attr("key_type"),
        key_size: attr("key_size"),
        is_valid,
        cert_pem,
    })
}

#[tauri::command]
pub async fn get_ca_config(state: State<'_, AppState>) -> Result<CaConfigDto, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    let db = ca.ca_database.as_ref()
        .ok_or("Database not loaded")?;

    let config = db.get_config().map_err(|e| e.to_string())?;
    Ok(ca_config_to_dto(&config))
}

#[tauri::command]
pub async fn update_ca_config(
    state: State<'_, AppState>,
    config: CaConfigDto,
) -> Result<(), String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] update_ca_config");
    let updates = dto_to_ca_config(&config);

    {
        let db = ca.ca_database.as_ref()
            .ok_or("Database not loaded")?;
        db.update_config(&updates).map_err(|e| e.to_string())?;
    }

    ca.store_ca_database().map_err(|e| {
        warn!("[tauri] update_ca_config: store failed: {e}");
        state.log_err("update_config", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok("update_config", Some("CA configuration updated".to_string()));
    Ok(())
}

#[tauri::command]
pub async fn init_ca(
    state: State<'_, AppState>,
    config: CaConfigDto,
) -> Result<(), String> {
    // Take Op — it must be in `op` (CA shouldn't exist yet)
    let mut conn = state.conn.lock().expect("mutex poisoned — a prior operation panicked");
    let op = conn.op.take()
        .ok_or("Not connected")?;

    info!("[tauri] init_ca");
    let ca_config = dto_to_ca_config(&config);

    match CertificateAuthority::init(op, &ca_config) {
        Ok(ca) => {
            conn.ca = Some(ca);
            state.log_ok("init_ca", Some("Certificate Authority initialised".to_string()));
            Ok(())
        }
        Err(e) => {
            error!("[tauri] init_ca failed: {e}");
            state.log_err("init_ca", Some(e.to_string()));
            // On failure, we've lost the Op — caller must reconnect
            Err(e.to_string())
        }
    }
}

#[tauri::command]
pub async fn test_stores(
    state: State<'_, AppState>,
) -> Result<HashMap<String, String>, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    debug!("[tauri] test_stores");
    ca.test_stores().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn upload_ca_cert(state: State<'_, AppState>) -> Result<(), String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    info!("[tauri] upload_ca_cert");
    ca.upload_ca_cert("").map_err(|e| {
        warn!("[tauri] upload_ca_cert failed: {e}");
        state.log_err("upload_ca_cert", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok("upload_ca_cert", Some("CA certificate uploaded to public store".to_string()));
    Ok(())
}

#[tauri::command]
pub async fn upload_ca_database(state: State<'_, AppState>) -> Result<(), String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;

    info!("[tauri] upload_ca_database");
    ca.upload_ca_database("").map_err(|e| {
        warn!("[tauri] upload_ca_database failed: {e}");
        state.log_err("upload_ca_database", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok("upload_ca_database", Some("Database uploaded to private store".to_string()));
    Ok(())
}

#[tauri::command]
pub async fn resign_ca(
    state: State<'_, AppState>,
    ca_days: i64,
) -> Result<CaInfo, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    info!("[tauri] resign_ca: days={ca_days}");
    ca.re_sign_ca(ca_days).map_err(|e| {
        warn!("[tauri] resign_ca failed: {e}");
        state.log_err("resign_ca", Some(e.to_string()));
        e.to_string()
    })?;

    state.log_ok("resign_ca", Some(format!("CA certificate re-signed for {ca_days} days")));

    let bundle = ca.ca_bundle.as_ref()
        .ok_or("CA certificate not loaded")?;

    let attr = |name: &str| -> Option<String> {
        bundle.get_certificate_attrib(name).ok().flatten()
    };

    let is_valid = ca.is_valid().unwrap_or(false);
    let cert_pem = bundle.certificate_pem().ok();

    Ok(CaInfo {
        cn: attr("cn"),
        subject: attr("subject"),
        issuer: attr("issuer"),
        serial: attr("serial"),
        not_before: attr("not_before"),
        not_after: attr("not_after"),
        key_type: attr("key_type"),
        key_size: attr("key_size"),
        is_valid,
        cert_pem,
    })
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

pub(crate) fn ca_config_to_dto(config: &CaConfig) -> CaConfigDto {
    CaConfigDto {
        next_serial: config.next_serial,
        next_crl_serial: config.next_crl_serial,
        org: config.org.clone(),
        ou: config.ou.clone(),
        email: config.email.clone(),
        city: config.city.clone(),
        state: config.state.clone(),
        country: config.country.clone(),
        ca_url: config.ca_url.clone(),
        crl_url: config.crl_url.clone(),
        days: config.days,
        crl_days: config.crl_days,
        ca_public_store: config.ca_public_store.clone(),
        ca_private_store: config.ca_private_store.clone(),
        ca_backup_store: config.ca_backup_store.clone(),
    }
}

fn dto_to_ca_config(dto: &CaConfigDto) -> CaConfig {
    CaConfig {
        cn: None,
        ca_days: None,
        next_serial: dto.next_serial,
        next_crl_serial: dto.next_crl_serial,
        org: dto.org.clone(),
        ou: dto.ou.clone(),
        email: dto.email.clone(),
        city: dto.city.clone(),
        state: dto.state.clone(),
        country: dto.country.clone(),
        ca_url: dto.ca_url.clone(),
        crl_url: dto.crl_url.clone(),
        days: dto.days,
        crl_days: dto.crl_days,
        schema_version: None,
        ca_public_store: dto.ca_public_store.clone(),
        ca_private_store: dto.ca_private_store.clone(),
        ca_backup_store: dto.ca_backup_store.clone(),
    }
}
