use log::info;
use tauri::State;

use opca_core::error::OpcaError;
use opca_core::services::ca::subordinate::SignedSubordinate;
use opca_core::services::database::Broker;

use crate::commands::cert::regenerate_crl_after_revoke;
use crate::commands::dto::{RenewSubordinateRequest, SignSubordinateRequest};
use crate::state::AppState;

pub(crate) fn logged<'a>(
    state: &'a AppState,
    action: &'a str,
) -> impl Fn(OpcaError) -> String + 'a {
    move |e| {
        state.log_err(action, Some(e.to_string()));
        e.to_string()
    }
}

fn log_signed(state: &AppState, action: &str, verb: &str, signed: &SignedSubordinate) {
    let broker = &signed.broker;
    state.log_ok(
        action,
        Some(format!(
            "{verb} subordinate {} (serial {}) for {}",
            broker.id,
            broker.subordinate_serial,
            broker.permitted_domains.join(", ")
        )),
    );
}

#[tauri::command]
pub async fn sign_subordinate(
    state: State<'_, AppState>,
    request: SignSubordinateRequest,
) -> Result<SignedSubordinate, String> {
    info!("[tauri] sign_subordinate: {:?}", request.domains);
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let signed = ca
        .sign_subordinate(request.csr_pem.as_bytes(), &request.domains, request.days)
        .map_err(logged(&state, "sign_subordinate"))?;
    log_signed(&state, "sign_subordinate", "Signed", &signed);
    Ok(signed)
}

#[tauri::command]
pub async fn renew_subordinate(
    state: State<'_, AppState>,
    request: RenewSubordinateRequest,
) -> Result<SignedSubordinate, String> {
    info!("[tauri] renew_subordinate: id={}", request.id);
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let signed = ca
        .renew_subordinate(
            request.id,
            request.csr_pem.as_bytes(),
            request.domains.as_deref(),
            request.change_domains,
            request.days,
        )
        .map_err(logged(&state, "renew_subordinate"))?;
    log_signed(&state, "renew_subordinate", "Renewed", &signed);
    Ok(signed)
}

#[tauri::command]
pub async fn revoke_subordinate(state: State<'_, AppState>, id: i64) -> Result<Broker, String> {
    info!("[tauri] revoke_subordinate: id={id}");
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;
    let broker = ca
        .revoke_subordinate(id)
        .map_err(logged(&state, "revoke_subordinate"))?;
    regenerate_crl_after_revoke(&state, "revoke_subordinate", ca)?;
    state.log_ok(
        "revoke_subordinate",
        Some(format!(
            "Revoked subordinate {id} (serial {}) and regenerated the CRL",
            broker.subordinate_serial
        )),
    );
    Ok(broker)
}

#[tauri::command]
pub async fn list_subordinates(state: State<'_, AppState>) -> Result<Vec<Broker>, String> {
    let conn = state.ensure_ca()?;
    let ca = conn.ca.as_ref().ok_or("CA not available")?;
    ca.list_subordinates().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use opca_core::services::cert::{CertBundleConfig, CertType, CertificateBundle};
    use opca_core::services::database::CertLookup;
    use opca_core::testutil::created;
    use serde_json::json;

    use super::*;
    use crate::commands::cert::record_to_detail;
    use crate::test_harness::{Handler, Harness};

    fn handler() -> impl Handler {
        tauri::generate_handler![
            sign_subordinate,
            renew_subordinate,
            revoke_subordinate,
            list_subordinates
        ]
    }

    fn csr_pem() -> String {
        let bundle = CertificateBundle::generate(
            CertType::SubordinateCa,
            "Broker CA",
            CertBundleConfig {
                cn: Some("Broker CA".into()),
                ..CertBundleConfig::default()
            },
        )
        .unwrap();
        String::from_utf8(bundle.csr.unwrap().to_pem().unwrap()).unwrap()
    }

    fn answer_issue(h: &Harness) {
        h.answer([created("CRT")]);
        h.answer_writes(1);
    }

    #[test]
    fn sign_renew_revoke_and_list_cross_the_bridge() {
        let h = Harness::with_ca(vec![], handler());
        answer_issue(&h);
        let signed = h
            .invoke(
                "sign_subordinate",
                json!({ "request": { "csr_pem": csr_pem(), "domains": ["Home.arpa"], "days": null } }),
            )
            .unwrap();
        let broker = &signed["broker"];
        assert_eq!(broker["permitted_domains"], json!(["home.arpa"]));
        assert_eq!(
            (&broker["state"], &broker["url"]),
            (&json!("active"), &json!(null))
        );
        assert!(
            signed["cert_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        let id = broker["id"].clone();

        let refused = h.invoke(
            "renew_subordinate",
            json!({ "request": { "id": id, "csr_pem": csr_pem(), "domains": ["example.com"], "days": null } }),
        );
        assert!(refused.unwrap_err().as_str().unwrap().contains("confirmed"));

        answer_issue(&h);
        let renewed = h
            .invoke(
                "renew_subordinate",
                json!({ "request": { "id": id, "csr_pem": csr_pem(), "domains": null, "days": null } }),
            )
            .unwrap();
        assert_ne!(
            renewed["broker"]["subordinate_serial"],
            broker["subordinate_serial"]
        );

        h.answer_writes(3);
        let revoked = h.invoke("revoke_subordinate", json!({ "id": id })).unwrap();
        assert_eq!(revoked["state"], json!("revoked"));
        assert!(h.last_log().detail.unwrap().contains("regenerated the CRL"));

        let listed = h.invoke("list_subordinates", json!({})).unwrap();
        assert_eq!(listed, json!([revoked]));
    }

    #[test]
    fn the_certificate_detail_shows_the_name_constraints() {
        let h = Harness::with_ca(vec![], handler());
        answer_issue(&h);
        let signed = h
            .invoke(
                "sign_subordinate",
                json!({ "request": { "csr_pem": csr_pem(), "domains": ["home.arpa"], "days": null } }),
            )
            .unwrap();
        let serial = signed["broker"]["subordinate_serial"].as_str().unwrap();
        let state = h.state();
        let conn = state.conn.lock().unwrap();
        let record = conn
            .db()
            .unwrap()
            .query_cert(&CertLookup::Serial(serial.into()), false)
            .unwrap()
            .unwrap();
        let pem = signed["cert_pem"].as_str().map(String::from);

        let detail = serde_json::to_value(record_to_detail(&record, pem, None, None)).unwrap();

        assert_eq!(
            detail["name_constraints"],
            json!({ "permitted": ["home.arpa"], "excluded": ["0.0.0.0/0", "::/0"] })
        );
    }
}
