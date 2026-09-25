use opca_core::services::database::CertLookup;
use opca_core::testutil::err_output;
use serde_json::{json, Value};

use super::cert::*;
use crate::test_harness::{Handler, Harness};

fn handler() -> impl Handler {
    tauri::generate_handler![create_cert, revoke_cert, delete_cert, bulk_revoke_certs, bulk_delete_certs]
}

fn issue(h: &Harness, cn: &str) -> String {
    let item = h.invoke("create_cert", json!({ "request": { "cn": cn, "cert_type": "webserver" } })).unwrap();
    item["serial"].as_str().unwrap().to_string()
}

fn issue_revoked(h: &Harness, cn: &str) -> String {
    let serial = issue(h, cn);
    assert_eq!(h.invoke("revoke_cert", json!({ "serial": serial })), Ok(json!(true)));
    serial
}

fn deleted_at(h: &Harness, serial: &str) -> Option<String> {
    let state = h.state();
    let conn = state.conn.lock().unwrap();
    conn.db().unwrap().query_cert(&CertLookup::Serial(serial.into()), false).unwrap().unwrap().deleted_at
}

fn crl_stores(h: &Harness) -> usize {
    h.op_calls(&["document", "edit", "CRL"]).len()
}

fn crl_serials(h: &Harness) -> Vec<String> {
    let state = h.state();
    let conn = state.conn.lock().unwrap();
    let pem = conn.ca.as_ref().unwrap().crl.clone().unwrap();
    let crl = openssl::x509::X509Crl::from_pem(pem.as_bytes()).unwrap();
    let mut serials: Vec<_> = crl
        .get_revoked()
        .unwrap()
        .iter()
        .map(|r| r.serial_number().to_bn().unwrap().to_dec_str().unwrap().to_string())
        .collect();
    serials.sort();
    serials
}

#[test]
fn revoke_cert_regenerates_and_stores_the_crl() {
    let h = Harness::with_ca(vec![], handler());
    let serial = issue_revoked(&h, "www.example.com");

    assert_eq!(crl_stores(&h), 1);
    assert_eq!(crl_serials(&h), [serial.as_str()]);
    let log = h.last_log();
    assert_eq!(log.detail, Some(format!("Revoked certificate {serial} and regenerated the CRL")));
}

#[test]
fn bulk_revoke_regenerates_the_crl_once_for_the_batch() {
    let h = Harness::with_ca(vec![], handler());
    let serials = [issue(&h, "a.example.com"), issue(&h, "b.example.com")];

    let results = h.invoke("bulk_revoke_certs", json!({ "serials": serials })).unwrap();

    assert!(results.as_array().unwrap().iter().all(|r| r["ok"] == true), "{results}");
    assert_eq!(crl_stores(&h), 1);
    assert_eq!(crl_serials(&h), serials);
}

#[test]
fn bulk_revoke_leaves_the_crl_alone_when_nothing_was_revoked() {
    let h = Harness::with_ca(vec![], handler());
    h.invoke("bulk_revoke_certs", json!({ "serials": ["99"] })).unwrap();
    assert_eq!(crl_stores(&h), 0);
}

#[test]
fn create_cert_returns_the_list_item_and_stores_the_bundle_and_the_database() {
    let h = Harness::with_ca(vec![], handler());
    let item = h
        .invoke(
            "create_cert",
            json!({ "request": { "cn": "www.example.com", "cert_type": "webserver", "key_algorithm": "ec-p384", "days": 30 } }),
        )
        .unwrap();

    assert_eq!(item["serial"], "2");
    assert_eq!(item["title"], "CRT_2_www.example.com");
    assert_eq!(item["status"], "Valid");
    assert_eq!(item["cert_type"], "webserver");
    assert_eq!((&item["key_type"], &item["key_size"]), (&json!("EC"), &json!(384)));
    assert_eq!(item["expiring_soon"], false);

    let creates = h.op_calls(&["item", "create"]);
    assert_eq!(creates.len(), 1);
    assert_eq!(creates[0][2], "--title=CRT_2_www.example.com");
    assert_eq!(h.op_calls(&["document", "edit", "CA_Database"]).len(), 1);
    assert!(h.last_log().success);
}

#[test]
fn create_cert_rejects_an_unknown_type_without_calling_op() {
    let h = Harness::with_ca(vec![], handler());
    let err = h.invoke("create_cert", json!({ "request": { "cn": "x", "cert_type": "bogus" } })).unwrap_err();
    assert!(err.as_str().unwrap().contains("bogus"), "{err}");
    assert!(h.op_calls(&[]).is_empty());
}

#[test]
fn create_cert_surfaces_an_op_failure_and_logs_it() {
    let h = Harness::with_ca(vec![err_output("[ERROR] vault is read-only")], handler());
    let err = h.invoke("create_cert", json!({ "request": { "cn": "www.example.com", "cert_type": "webserver" } })).unwrap_err();
    let log = h.last_log();
    assert_eq!((log.action.as_str(), log.success), ("create_cert", false));
    assert_eq!(log.detail.as_deref(), err.as_str());
    assert!(h.op_calls(&["document", "edit"]).is_empty(), "the database is not stored after a failed issue");
}

#[test]
fn delete_cert_archives_a_revoked_cert_and_hides_its_row() {
    let h = Harness::with_ca(vec![], handler());
    let serial = issue_revoked(&h, "www.example.com");

    assert_eq!(h.invoke("delete_cert", json!({ "serial": serial })), Ok(Value::Null));
    let deletes = h.op_calls(&["item", "delete"]);
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0][2], "CRT_2_www.example.com");
    assert!(deletes[0].iter().any(|a| a == "--archive"));
    assert!(deleted_at(&h, &serial).is_some());
}

#[test]
fn delete_cert_refuses_a_valid_cert_and_leaves_1password_alone() {
    let h = Harness::with_ca(vec![], handler());
    let serial = issue(&h, "www.example.com");

    let err = h.invoke("delete_cert", json!({ "serial": serial })).unwrap_err();
    assert!(err.as_str().unwrap().contains("revoke it before deleting"), "{err}");
    assert!(h.op_calls(&["item", "delete"]).is_empty());
    assert!(!h.last_log().success);
}

#[test]
fn a_bulk_op_reports_each_serial_and_carries_on_past_a_failure() {
    let h = Harness::with_ca(vec![], handler());
    let first = issue(&h, "a.example.com");
    let second = issue(&h, "b.example.com");
    let progress = h.record_events("bulk-progress");

    let results = h.invoke("bulk_revoke_certs", json!({ "serials": [first, "99", second] })).unwrap();

    let outcomes: Vec<_> = results.as_array().unwrap().iter().map(|r| (r["serial"].clone(), r["ok"].clone())).collect();
    assert_eq!(outcomes, [(json!(first), json!(true)), (json!("99"), json!(false)), (json!(second), json!(true))]);
    assert!(results[1]["error"].as_str().unwrap().contains("99"));
    assert_eq!(results[0]["new_serial"], Value::Null);

    let steps: Vec<_> = progress.lock().unwrap().iter().map(|p| (p["verb"].clone(), p["current"].clone(), p["total"].clone())).collect();
    assert_eq!(steps, [1, 2, 3].map(|n| (json!("Revoking"), json!(n), json!(3))));
    let log = h.last_log();
    assert_eq!((log.action.as_str(), log.detail.as_deref()), ("bulk_revoke", Some("2 succeeded, 1 failed")));
}

#[test]
fn bulk_delete_archives_every_revoked_cert() {
    let h = Harness::with_ca(vec![], handler());
    let serials = [issue_revoked(&h, "a.example.com"), issue_revoked(&h, "b.example.com")];

    let results = h.invoke("bulk_delete_certs", json!({ "serials": serials })).unwrap();

    assert!(results.as_array().unwrap().iter().all(|r| r["ok"] == true), "{results}");
    let archived: Vec<_> = h.op_calls(&["item", "delete"]).into_iter().map(|c| c[2].clone()).collect();
    assert_eq!(archived, ["CRT_2_a.example.com", "CRT_3_b.example.com"]);
    assert!(serials.iter().all(|s| deleted_at(&h, s).is_some()));
}

#[test]
fn a_bulk_op_fails_whole_when_not_connected() {
    let h = Harness::disconnected(handler());
    assert_eq!(h.invoke("bulk_delete_certs", json!({ "serials": ["2"] })), Err(json!("Not connected")));
}
