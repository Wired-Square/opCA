use std::time::{Duration, Instant};

use chrono::Utc;
use log::info;
use tauri::State;

use opca_core::services::acme_broker::api::Status;
use opca_core::services::acme_broker::{
    BrokerNotice, BrokerRenewal, BrokerRevocation, Endpoint, EnrolledBroker, Renewal, concerns,
    fetch_offer, issuance, parse_pairing,
};
use opca_core::services::ca::CertificateAuthority;
use opca_core::services::ca::operator::Operator;
use opca_core::services::database::Broker;

use crate::commands::cert::regenerate_crl_after_revoke;
use crate::commands::dto::{BrokerOfferDto, BrokerRow, EnrolBrokerRequest};
use crate::commands::subordinate::logged;
use crate::state::{AppState, Connection, Runner};

/// The operator's client certificate lasts a day; a session that outlives most of it mints another.
const OPERATOR_REMINT_AFTER: Duration = Duration::from_secs(20 * 60 * 60);

fn with_operator<'c>(
    state: &AppState,
    action: &str,
    conn: &'c mut Connection,
) -> Result<(&'c mut CertificateAuthority<Runner>, &'c Operator), String> {
    let Connection { ca, operator, .. } = conn;
    let ca = ca.as_mut().ok_or("CA not available")?;
    if operator
        .as_ref()
        .is_none_or(|(minted, _)| minted.elapsed() > OPERATOR_REMINT_AFTER)
    {
        let minted = ca.operator().map_err(logged(state, action))?;
        *operator = Some((Instant::now(), minted));
    }
    let (_, operator) = operator.as_ref().expect("minted above");
    Ok((ca, operator))
}

pub(crate) fn broker_rows(brokers: Vec<Broker>) -> Vec<BrokerRow> {
    let now = Utc::now();
    brokers
        .into_iter()
        .filter(|b| b.url.is_some())
        .map(|broker| BrokerRow {
            concerns: concerns(&broker, now),
            broker,
        })
        .collect()
}

fn log_renewal(state: &AppState, action: &str, id: i64, renewal: &Renewal) {
    let line = format!("Broker {id}: {renewal}");
    if renewal.is_renewed() {
        state.log_ok(action, line);
    } else {
        state.log_err(action, line);
    }
}

#[tauri::command]
pub async fn fetch_broker_offer(
    state: State<'_, AppState>,
    pairing: String,
) -> Result<BrokerOfferDto, String> {
    let action = "fetch_broker_offer";
    let pairing = parse_pairing(&pairing).map_err(logged(&state, action))?;
    let endpoint = Endpoint::of_pairing(&pairing);
    info!("[tauri] {action}: {}", endpoint.url());
    let offer = fetch_offer(&pairing).map_err(logged(&state, action))?;
    Ok(BrokerOfferDto {
        address: endpoint.url(),
        pin: endpoint.pin().to_string(),
        offer,
    })
}

#[tauri::command]
pub async fn enrol_broker(
    state: State<'_, AppState>,
    request: EnrolBrokerRequest,
) -> Result<EnrolledBroker, String> {
    let action = "enrol_broker";
    info!("[tauri] {action}: {}", request.offer.host);
    let pairing = parse_pairing(&request.pairing).map_err(logged(&state, action))?;
    let mut conn = state.ensure_ca()?;
    let (ca, operator) = with_operator(&state, action, &mut conn)?;
    let enrolled = ca
        .enrol_broker(
            operator,
            &pairing,
            &request.offer,
            issuance(request.domains),
        )
        .map_err(logged(&state, action))?;
    let broker = &enrolled.broker;
    state.log_ok(
        action,
        format!(
            "Enrolled broker {} at {} (serial {}) for {}",
            broker.id,
            broker.url.as_deref().unwrap_or_default(),
            broker.subordinate_serial,
            broker.permitted_domains.join(", ")
        ),
    );
    Ok(enrolled)
}

#[tauri::command]
pub async fn list_brokers(state: State<'_, AppState>) -> Result<Vec<BrokerRow>, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;
    Ok(broker_rows(
        ca.list_subordinates().map_err(|e| e.to_string())?,
    ))
}

#[tauri::command]
pub async fn broker_status(state: State<'_, AppState>, id: i64) -> Result<Status, String> {
    let action = "broker_status";
    let mut conn = state.ensure_ca()?;
    let (ca, operator) = with_operator(&state, action, &mut conn)?;
    ca.broker_status(operator, id)
        .map_err(logged(&state, action))
}

#[tauri::command]
pub async fn renew_broker(
    state: State<'_, AppState>,
    id: i64,
    change_domains: Option<bool>,
) -> Result<Renewal, String> {
    let action = "renew_broker";
    info!("[tauri] {action}: id={id}");
    let mut conn = state.ensure_ca()?;
    let (ca, operator) = with_operator(&state, action, &mut conn)?;
    let renewal = ca
        .renew_broker(operator, id, change_domains.unwrap_or(false))
        .map_err(logged(&state, action))?;
    log_renewal(&state, action, id, &renewal);
    Ok(renewal)
}

#[tauri::command]
pub async fn renew_all_brokers(state: State<'_, AppState>) -> Result<Vec<BrokerRenewal>, String> {
    let action = "renew_all_brokers";
    info!("[tauri] {action}");
    let mut conn = state.ensure_ca()?;
    let (ca, operator) = with_operator(&state, action, &mut conn)?;
    let renewals = ca
        .renew_all_brokers(operator)
        .map_err(logged(&state, action))?;
    for r in &renewals {
        log_renewal(&state, action, r.id, &r.renewal);
    }
    Ok(renewals)
}

#[tauri::command]
pub async fn revoke_broker(
    state: State<'_, AppState>,
    id: i64,
) -> Result<BrokerRevocation, String> {
    let action = "revoke_broker";
    info!("[tauri] {action}: id={id}");
    let mut conn = state.ensure_ca()?;
    let (ca, operator) = with_operator(&state, action, &mut conn)?;
    let revocation = ca
        .revoke_broker(operator, id)
        .map_err(logged(&state, action))?;
    regenerate_crl_after_revoke(&state, action, ca)?;
    let serial = &revocation.broker.subordinate_serial;
    match &revocation.notice {
        BrokerNotice::Told { .. } => state.log_ok(
            action,
            format!(
                "Revoked broker {id} (serial {serial}), regenerated the CRL and told the broker"
            ),
        ),
        BrokerNotice::NotTold { error } => state.log_err(
            action,
            format!(
                "Revoked broker {id} (serial {serial}) and regenerated the CRL, but the broker was \
                 not told: {error}"
            ),
        ),
    }
    Ok(revocation)
}
