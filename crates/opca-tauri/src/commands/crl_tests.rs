use opca_core::services::database::CaConfig;
use serde_json::{json, Value};

use super::ca::*;
use super::crl::*;
use super::dashboard::*;
use crate::test_harness::{Handler, Harness};

fn handler() -> impl Handler {
    tauri::generate_handler![generate_crl, get_crl_info, get_dashboard, update_ca_config]
}

fn set_config(h: &Harness, config: CaConfig) {
    let state = h.state();
    let conn = state.conn.lock().unwrap();
    conn.db().unwrap().update_config(&config).unwrap();
}

/// A local rsync private store with batches on, so generating uploads nowhere real.
fn batch_mode(h: &Harness) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("pending-crl")).unwrap();
    set_config(h, CaConfig {
        crl_batch_enabled: Some(true),
        ca_private_store: Some(format!("rsync://{}", dir.path().display())),
        ..CaConfig::default()
    });
    dir
}

fn crl_regenerate_items(dashboard: &Value) -> Vec<&Value> {
    dashboard["action_items"].as_array().unwrap().iter().filter(|i| i["id"] == "crl_regenerate").collect()
}

#[test]
fn crl_info_reports_the_signed_batch_and_its_cover() {
    let h = Harness::with_ca(vec![], handler());
    let info = h.invoke("get_crl_info", json!({})).unwrap();
    assert_eq!((&info["crl_batch_enabled"], &info["crl_batch"]), (&json!(false), &Value::Null));

    let _store = batch_mode(&h);
    let generated = h.invoke("generate_crl", json!({})).unwrap();
    let info = h.invoke("get_crl_info", json!({})).unwrap();

    assert_eq!(generated["crl_batch"], info["crl_batch"]);
    let batch = &info["crl_batch"];
    assert_eq!(info["crl_batch_enabled"], json!(true));
    assert_eq!(
        (&batch["first_number"], &batch["last_number"], &batch["due_number"], &batch["remaining"], &batch["count"]),
        (&json!(1), &json!(5), &json!(1), &json!(4), &json!(5))
    );
    assert_eq!(batch["low_cover"], json!(false));
    assert!(batch["signed_until"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn the_dashboard_judges_crl_expiry_by_the_batch_only_while_batches_are_on() {
    let h = Harness::with_ca(vec![], handler());
    set_config(&h, CaConfig { crl_days: Some(10), ..CaConfig::default() });
    h.invoke("generate_crl", json!({})).unwrap();
    let single = h.invoke("get_dashboard", json!({})).unwrap();
    assert_eq!(crl_regenerate_items(&single)[0]["message"], json!("CRL expires in 9 days"));

    let _store = batch_mode(&h);
    h.invoke("generate_crl", json!({})).unwrap();
    let batched = h.invoke("get_dashboard", json!({})).unwrap();

    assert!(crl_regenerate_items(&batched).is_empty(), "{batched}");
    assert_eq!(batched["crl_expiry_warning"], Value::Null);
    assert_eq!(batched["crl_batch"]["remaining"], json!(4));

    set_config(&h, CaConfig { crl_batch_enabled: Some(false), ..CaConfig::default() });
    let switched_off = h.invoke("get_dashboard", json!({})).unwrap();

    assert_eq!(switched_off["crl_batch"], Value::Null);
    assert_eq!(crl_regenerate_items(&switched_off)[0]["message"], json!("CRL expires in 9 days"));
    assert_eq!(h.invoke("get_crl_info", json!({})).unwrap()["crl_batch"], Value::Null);
}

#[test]
fn crl_batches_cannot_be_turned_on_without_a_private_store() {
    let h = Harness::with_ca(vec![], handler());

    let err = h.invoke("update_ca_config", json!({ "config": { "crl_batch_enabled": true } })).unwrap_err();
    assert!(err.as_str().unwrap().contains("CRL batches need a private store"), "{err}");
    let err = h
        .invoke("update_ca_config", json!({ "config": { "crl_batch_enabled": true, "ca_private_store": " " } }))
        .unwrap_err();
    assert!(err.as_str().unwrap().contains("private store"), "{err}");

    h.invoke("update_ca_config", json!({ "config": { "crl_batch_enabled": true, "ca_private_store": "rsync:///nonexistent-opca-store" } }))
        .unwrap();
    h.invoke("update_ca_config", json!({ "config": { "crl_batch_enabled": false } })).unwrap();
    let info = h.invoke("get_crl_info", json!({})).unwrap();
    assert_eq!(info["crl_batch_enabled"], json!(false));
}
