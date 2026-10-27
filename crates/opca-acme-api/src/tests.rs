use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::*;

fn pinned<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: T, wire: Value) {
    assert_eq!(serde_json::to_value(&value).unwrap(), wire);
    assert_eq!(serde_json::from_value::<T>(wire).unwrap(), value);
}

fn versions() -> (Versions, Value) {
    (
        Versions {
            api: API_VERSION,
            broker: "0.103.0".into(),
            step_ca: "0.28.1".into(),
        },
        json!({"api": 1, "broker": "0.103.0", "step_ca": "0.28.1"}),
    )
}

fn config() -> (IssuanceConfig, Value) {
    (
        IssuanceConfig {
            permitted_domains: vec!["home.arpa".into()],
            leaf_days: 30,
            leaf_max_days: 45,
            challenges: vec![Challenge::Http01, Challenge::Dns01, Challenge::TlsAlpn01],
        },
        json!({
            "permitted_domains": ["home.arpa"],
            "leaf_days": 30,
            "leaf_max_days": 45,
            "challenges": ["http-01", "dns-01", "tls-alpn-01"],
        }),
    )
}

#[test]
fn paths_carry_the_api_version() {
    for p in [
        path::ENROLMENT,
        path::STATUS,
        path::CSR,
        path::CHAIN,
        path::REVOKE,
    ] {
        assert!(p.starts_with(&format!("/v{API_VERSION}/")), "{p}");
    }
}

#[test]
fn versions_wire_format() {
    let (value, wire) = versions();
    pinned(value, wire);
}

#[test]
fn issuance_config_wire_format() {
    let (value, wire) = config();
    pinned(value, wire);
}

#[test]
fn enrolment_offer_wire_format() {
    let (versions, versions_wire) = versions();
    pinned(
        EnrolmentOffer {
            csr_pem: "CSR".into(),
            host: "acme.home.arpa".into(),
            configured_domains: vec![],
            versions,
        },
        json!({
            "csr_pem": "CSR",
            "host": "acme.home.arpa",
            "configured_domains": [],
            "versions": versions_wire,
        }),
    );
}

#[test]
fn enrolment_wire_format() {
    let (config, config_wire) = config();
    pinned(
        Enrolment {
            code: "ABCDEFGHIJKLMNOP".into(),
            chain_pem: "CHAIN".into(),
            operator_pin: "ab".repeat(32),
            config,
        },
        json!({
            "code": "ABCDEFGHIJKLMNOP",
            "chain_pem": "CHAIN",
            "operator_pin": "ab".repeat(32),
            "config": config_wire,
        }),
    );
}

#[test]
fn status_wire_format() {
    let (config, config_wire) = config();
    let (versions, versions_wire) = versions();
    pinned(
        Status {
            state: IssuerState::StepCaDown,
            subordinate_serial: "4096".into(),
            subordinate_not_after: "2027-01-25T00:00:00Z".into(),
            config,
            versions,
        },
        json!({
            "state": "step_ca_down",
            "subordinate_serial": "4096",
            "subordinate_not_after": "2027-01-25T00:00:00Z",
            "config": config_wire,
            "versions": versions_wire,
        }),
    );
}

#[test]
fn issuer_state_wire_format() {
    pinned(IssuerState::Issuing, json!("issuing"));
    pinned(IssuerState::StepCaDown, json!("step_ca_down"));
    pinned(IssuerState::Revoked, json!("revoked"));
}

#[test]
fn fresh_csr_wire_format() {
    pinned(
        FreshCsr {
            csr_pem: "CSR".into(),
            configured_domains: vec!["home.arpa".into()],
        },
        json!({"csr_pem": "CSR", "configured_domains": ["home.arpa"]}),
    );
}

#[test]
fn chain_update_wire_format() {
    let (config, config_wire) = config();
    pinned(
        ChainUpdate {
            chain_pem: "CHAIN".into(),
            config,
        },
        json!({"chain_pem": "CHAIN", "config": config_wire}),
    );
}

#[test]
fn error_body_wire_format() {
    let error = |kind| ErrorBody {
        kind,
        message: "no".into(),
    };
    pinned(
        error(ErrorKind::WrongCode { remaining: 2 }),
        json!({"error": "wrong_code", "remaining": 2, "message": "no"}),
    );
    for (kind, tag) in [
        (ErrorKind::BadRequest, "bad_request"),
        (ErrorKind::CodeSpent, "code_spent"),
        (ErrorKind::Revoked, "revoked"),
        (ErrorKind::Internal, "internal"),
    ] {
        pinned(error(kind), json!({"error": tag, "message": "no"}));
    }
}

#[test]
fn error_kinds_map_to_http_statuses() {
    let statuses = [
        ErrorKind::BadRequest,
        ErrorKind::WrongCode { remaining: 0 },
        ErrorKind::Revoked,
        ErrorKind::CodeSpent,
        ErrorKind::Internal,
    ]
    .map(ErrorKind::http_status);
    assert_eq!(statuses, [400, 403, 409, 410, 500]);
}

#[test]
fn unknown_fields_are_ignored_so_older_ends_accept_newer_bodies() {
    let (versions, mut wire) = versions();
    wire["added_later"] = json!(true);
    assert_eq!(serde_json::from_value::<Versions>(wire).unwrap(), versions);
}
