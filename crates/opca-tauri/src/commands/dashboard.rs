use chrono::Utc;
use log::warn;
use tauri::State;

use opca_core::services::ca::{assess_crl_expiry, CaExpiryWarning, CrlExpiryWarning};
use opca_core::services::cert::APPLE_TLS_MAX_DAYS;
use opca_core::utils::datetime::{self, DateTimeFormat};

use crate::commands::dto::{
    ActionItemDto, CaExpiryWarningDto, CrlExpiryWarningDto, DashboardData,
};
use crate::commands::crl::crl_batch_dto;
use crate::state::AppState;

#[tauri::command]
pub async fn get_dashboard(state: State<'_, AppState>) -> Result<DashboardData, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    // Extract CA bundle info first (immutable borrow)
    let ca_valid = ca.is_valid().unwrap_or(false);
    let ca_cn = ca.ca_bundle.as_ref()
        .and_then(|b| b.get_certificate_attrib("cn").ok().flatten());
    let ca_expiry = ca.ca_bundle.as_ref()
        .and_then(|b| b.get_certificate_attrib("not_after").ok().flatten());

    // Check CA expiry warning
    let ca_warning_raw = ca.check_ca_expiry();
    let ca_expiry_warning = match &ca_warning_raw {
        CaExpiryWarning::Critical { days_remaining } => Some(CaExpiryWarningDto {
            level: "critical".to_string(),
            days_remaining: Some(*days_remaining),
            message: format!("CA certificate expires in {days_remaining} days!"),
        }),
        CaExpiryWarning::Prominent { days_remaining } => Some(CaExpiryWarningDto {
            level: "prominent".to_string(),
            days_remaining: Some(*days_remaining),
            message: format!("CA certificate expires in {days_remaining} days"),
        }),
        CaExpiryWarning::CertLifetimeExceedsCa { days_remaining, cert_lifetime_days } => {
            Some(CaExpiryWarningDto {
                level: "cert_lifetime".to_string(),
                days_remaining: Some(*days_remaining),
                message: format!(
                    "CA has {days_remaining} days remaining but default cert lifetime is {cert_lifetime_days} days"
                ),
            })
        }
        CaExpiryWarning::None => None,
    };

    // Read CRL metadata and public-store config (immutable DB borrow)
    let db_ref = ca.ca_database.as_ref().ok_or("Database not loaded")?;
    let crl_metadata = db_ref.get_crl_metadata().map_err(|e| e.to_string())?;
    let config = db_ref.get_config().ok();
    let has_public_store = config.as_ref().is_some_and(|c| c.ca_public_store.is_some());
    let crl_batch_enabled = config.as_ref().is_some_and(|c| c.crl_batch_enabled == Some(true));
    let cert_days = config.and_then(|c| c.days);
    let crl_batch = crl_batch_dto(db_ref, crl_batch_enabled)?;

    let crl_next_update = crl_metadata.as_ref().and_then(|m| m.next_update.clone());
    let crl_present = crl_next_update.is_some();

    // A batch's later CRLs are released without the app, so the batch's end is what lapses.
    let (crl_subject, crl_cover_end) = match &crl_batch {
        Some(batch) => ("CRL batch", Some(batch.signed_until.clone())),
        None => ("CRL", crl_next_update.clone()),
    };
    let crl_expiry_warning = crl_cover_end
        .as_deref()
        .and_then(|s| datetime::parse_datetime(s, DateTimeFormat::Openssl).ok())
        .and_then(|dt| crl_expiry_warning_dto(&assess_crl_expiry(dt, Utc::now()), crl_subject));

    // Force a rescan so passage-of-time expirations are detected even if the
    // database wasn't mutated since last call. Persist to 1Password when the
    // scan flips any rows (e.g. a certificate transitioned to Expired).
    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    let db_changed = db
        .process_ca_database(None, true)
        .map_err(|e| e.to_string())?;

    let total_certs = db.count_certs().unwrap_or(0);
    // "Valid" = passes validation (not expired, not revoked). That includes
    // certs in the expiry-warning window (still valid, just expiring) and
    // ignored-but-valid certs. `certs_valid` (beyond the caution window) and
    // `certs_expires_warning` (within it, and already a superset of
    // `certs_expires_soon`) are disjoint and together cover every non-expired,
    // non-revoked cert.
    let valid_certs = db.certs_valid.len() + db.certs_expires_warning.len();
    // The "problem" counts subtract ignored certs so an acknowledged cert stops
    // nagging here and in the action items — "ignored" means "don't notify about
    // problems". (A still-valid ignored cert remains counted as valid above.)
    let expired_certs = db.certs_expired.difference(&db.certs_ignored).count();
    let expiring_certs = db.certs_expires_soon.difference(&db.certs_ignored).count();
    let warning_certs = db.certs_expires_warning.difference(&db.certs_ignored).count();
    let revoked_certs = db.crl_entries().map_err(|e| e.to_string())?.len();

    let pending_csrs = db
        .query_all_csrs(Some("Pending"))
        .map(|rows| rows.len())
        .unwrap_or(0);

    if db_changed {
        if let Err(e) = ca.store_ca_database() {
            warn!("[tauri] get_dashboard: failed to persist database after rescan: {e}");
            state.log_err("dashboard_persist", Some(e.to_string()));
        } else {
            state.log_ok(
                "dashboard_persist",
                Some("certificate state changes persisted".to_string()),
            );
        }
    }

    let action_items = build_action_items(
        &ca_warning_raw,
        crl_expiry_warning.as_ref(),
        has_public_store,
        cert_days,
        expired_certs,
        pending_csrs,
    );

    Ok(DashboardData {
        ca_valid,
        ca_cn,
        ca_expiry,
        ca_expiry_warning,
        crl_present,
        crl_next_update,
        crl_expiry_warning,
        total_certs,
        valid_certs,
        expired_certs,
        expiring_certs,
        warning_certs,
        revoked_certs,
        pending_csrs,
        has_public_store,
        crl_batch_enabled,
        crl_batch,
        action_items,
    })
}

fn crl_expiry_warning_dto(warning: &CrlExpiryWarning, subject: &str) -> Option<CrlExpiryWarningDto> {
    let (level, days_remaining, message) = match *warning {
        CrlExpiryWarning::Expired { days_overdue: 0 } => ("expired", 0, format!("{subject} has expired today")),
        CrlExpiryWarning::Expired { days_overdue } => {
            ("expired", -days_overdue, format!("{subject} expired {days_overdue} days ago"))
        }
        CrlExpiryWarning::Critical { days_remaining } => {
            ("critical", days_remaining, format!("{subject} expires in {days_remaining} days"))
        }
        CrlExpiryWarning::Prominent { days_remaining } => {
            ("prominent", days_remaining, format!("{subject} expires in {days_remaining} days"))
        }
        CrlExpiryWarning::None => return None,
    };
    Some(CrlExpiryWarningDto { level: level.to_string(), days_remaining: Some(days_remaining), message })
}

/// Build the dashboard's action-items list. Rules are centralised here so the
/// frontend only needs to dispatch on `action`.
fn build_action_items(
    ca_warning: &CaExpiryWarning,
    crl_warning: Option<&CrlExpiryWarningDto>,
    has_public_store: bool,
    cert_days: Option<i64>,
    expired_certs: usize,
    pending_csrs: usize,
) -> Vec<ActionItemDto> {
    let mut items = Vec::new();

    // CRL: expired / critical / prominent all warrant a regenerate action.
    if let Some(warning) = crl_warning {
        let severity = if warning.level == "prominent" { "warning" } else { "critical" };
        let (action, button_label) = if has_public_store {
            ("regenerate_and_upload_crl", "Regenerate & Upload CRL")
        } else {
            ("regenerate_crl", "Regenerate CRL")
        };
        items.push(ActionItemDto {
            id: "crl_regenerate".to_string(),
            severity: severity.to_string(),
            message: warning.message.clone(),
            button_label: button_label.to_string(),
            action: action.to_string(),
        });
    }

    if let CaExpiryWarning::Critical { days_remaining } = ca_warning {
        items.push(ActionItemDto {
            id: "ca_review".to_string(),
            severity: "critical".to_string(),
            message: format!("CA certificate expires in {days_remaining} days"),
            button_label: "Review CA".to_string(),
            action: "view_ca".to_string(),
        });
    }

    if let Some(days) = cert_days.filter(|&d| d > APPLE_TLS_MAX_DAYS.into()) {
        items.push(ActionItemDto {
            id: "cert_days_over_apple_limit".to_string(),
            severity: "info".to_string(),
            message: format!(
                "Default certificate lifetime is {days} days; server certificates are capped at \
                 {APPLE_TLS_MAX_DAYS} for Apple devices"
            ),
            button_label: "Review CA".to_string(),
            action: "view_ca".to_string(),
        });
    }

    if expired_certs > 0 {
        let noun = if expired_certs == 1 { "certificate has" } else { "certificates have" };
        items.push(ActionItemDto {
            id: "expired_certs".to_string(),
            severity: "info".to_string(),
            message: format!("{expired_certs} {noun} expired"),
            button_label: "View".to_string(),
            action: "view_expired_certs".to_string(),
        });
    }

    if pending_csrs > 0 {
        let noun = if pending_csrs == 1 { "CSR" } else { "CSRs" };
        items.push(ActionItemDto {
            id: "pending_csrs".to_string(),
            severity: "info".to_string(),
            message: format!("{pending_csrs} {noun} awaiting signature"),
            button_label: "View".to_string(),
            action: "view_pending_csrs".to_string(),
        });
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item_ids(cert_days: Option<i64>) -> Vec<String> {
        build_action_items(&CaExpiryWarning::None, None, false, cert_days, 0, 0)
            .into_iter()
            .map(|i| i.id)
            .collect()
    }

    #[test]
    fn flags_a_default_lifetime_over_the_apple_limit() {
        assert_eq!(item_ids(Some(3650)), ["cert_days_over_apple_limit"]);
        assert!(item_ids(Some(825)).is_empty());
        assert!(item_ids(None).is_empty());
    }
}
