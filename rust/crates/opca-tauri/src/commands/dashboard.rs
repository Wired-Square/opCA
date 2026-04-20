use chrono::Utc;
use log::warn;
use tauri::State;

use opca_core::services::ca::{assess_crl_expiry, CaExpiryWarning, CrlExpiryWarning};
use opca_core::utils::datetime::{self, DateTimeFormat};

use crate::commands::dto::{
    ActionItemDto, CaExpiryWarningDto, CrlExpiryWarningDto, DashboardData,
};
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
    let has_public_store = db_ref
        .get_config()
        .map(|c| c.ca_public_store.is_some())
        .unwrap_or(false);

    let crl_next_update = crl_metadata.as_ref().and_then(|m| m.next_update.clone());
    let crl_present = crl_next_update.is_some();

    // Assess CRL expiry from the stored next_update
    let crl_warning_raw = crl_next_update.as_deref().and_then(|s| {
        datetime::parse_datetime(s, DateTimeFormat::Openssl)
            .ok()
            .map(|dt| assess_crl_expiry(dt, Utc::now()))
    });

    let crl_expiry_warning = match crl_warning_raw.as_ref() {
        Some(CrlExpiryWarning::Critical { days_remaining }) => Some(CrlExpiryWarningDto {
            level: "critical".to_string(),
            days_remaining: Some(*days_remaining),
            message: format!("CRL expires in {days_remaining} days"),
        }),
        Some(CrlExpiryWarning::Prominent { days_remaining }) => Some(CrlExpiryWarningDto {
            level: "prominent".to_string(),
            days_remaining: Some(*days_remaining),
            message: format!("CRL expires in {days_remaining} days"),
        }),
        Some(CrlExpiryWarning::Expired { days_overdue }) => Some(CrlExpiryWarningDto {
            level: "expired".to_string(),
            days_remaining: Some(-(*days_overdue)),
            message: if *days_overdue == 0 {
                "CRL has expired today".to_string()
            } else {
                format!("CRL expired {days_overdue} days ago")
            },
        }),
        Some(CrlExpiryWarning::None) | None => None,
    };

    // Force a rescan so passage-of-time expirations are detected even if the
    // database wasn't mutated since last call. Persist to 1Password when the
    // scan flips any rows (e.g. a certificate transitioned to Expired).
    let db = ca.ca_database.as_mut().ok_or("Database not loaded")?;
    let db_changed = db
        .process_ca_database(None, true)
        .map_err(|e| e.to_string())?;

    let total_certs = db.count_certs().unwrap_or(0);
    let valid_certs = db.certs_valid.len();
    let expired_certs = db.certs_expired.len();
    let expiring_certs = db.certs_expires_soon.len();
    let warning_certs = db.certs_expires_warning.len();
    let revoked_certs = db.certs_revoked.len();

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
        crl_warning_raw.as_ref(),
        has_public_store,
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
        action_items,
    })
}

/// Build the dashboard's action-items list. Rules are centralised here so the
/// frontend only needs to dispatch on `action`.
fn build_action_items(
    ca_warning: &CaExpiryWarning,
    crl_warning: Option<&CrlExpiryWarning>,
    has_public_store: bool,
    expired_certs: usize,
    pending_csrs: usize,
) -> Vec<ActionItemDto> {
    let mut items = Vec::new();

    // CRL: expired / critical / prominent all warrant a regenerate action.
    let (crl_severity, crl_message) = match crl_warning {
        Some(CrlExpiryWarning::Expired { days_overdue }) => Some((
            "critical",
            if *days_overdue == 0 {
                "CRL has expired today".to_string()
            } else {
                format!("CRL expired {days_overdue} days ago")
            },
        )),
        Some(CrlExpiryWarning::Critical { days_remaining }) => Some((
            "critical",
            format!("CRL expires in {days_remaining} days"),
        )),
        Some(CrlExpiryWarning::Prominent { days_remaining }) => Some((
            "warning",
            format!("CRL expires in {days_remaining} days"),
        )),
        _ => None,
    }
    .map(|(sev, msg)| (sev.to_string(), msg))
    .unzip();

    if let (Some(severity), Some(message)) = (crl_severity, crl_message) {
        let (action, button_label) = if has_public_store {
            ("regenerate_and_upload_crl", "Regenerate & Upload CRL")
        } else {
            ("regenerate_crl", "Regenerate CRL")
        };
        items.push(ActionItemDto {
            id: "crl_regenerate".to_string(),
            severity,
            message,
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
