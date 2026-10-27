#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use opca_acme_broker::{ATTEMPTS, Broker, Config, SCHEME};
use tempfile::TempDir;
use wslib_crypto::KeyAlgorithm;
use wslib_crypto_ca::Csr;
use wslib_pairing::{OneTimeCode, PairingUri, Redemption, Status};

fn config(state: &Path) -> Config {
    Config {
        state_dir: state.into(),
        ..Config::parse(r#"host = "acme.home.example""#).unwrap()
    }
}

fn private_tempdir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn first_start() -> (TempDir, Broker, PairingUri) {
    let state = private_tempdir();
    let (broker, uri) = Broker::start(&config(state.path())).unwrap();
    (state, broker, uri.expect("a first start issues a code"))
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_first_start_makes_every_secret_owner_only() {
    let (state, _, _) = first_start();
    for secret in ["subordinate.key", "api.key", "pairing-code"] {
        assert_eq!(mode(&state.path().join(secret)), 0o600, "{secret}");
    }
    for public in ["subordinate.csr", "api.crt"] {
        assert!(state.path().join(public).is_file(), "{public}");
    }
}

#[test]
fn a_restart_issues_nothing_new() {
    let (state, broker, uri) = first_start();
    let files = [
        "subordinate.key",
        "subordinate.csr",
        "api.crt",
        "api.key",
        "pairing-code",
    ];
    let before = files.map(|file| fs::read(state.path().join(file)).unwrap());
    let (pin, spki) = (broker.pin(), broker.subordinate().spki().to_vec());
    drop(broker);

    let (restarted, again) = Broker::start(&config(state.path())).unwrap();
    assert!(again.is_none());
    assert_eq!(
        files.map(|file| fs::read(state.path().join(file)).unwrap()),
        before
    );
    assert_eq!(
        (restarted.pin(), restarted.subordinate().spki()),
        (pin, &spki[..])
    );
    assert_eq!(
        restarted.code_status().unwrap(),
        Status::Pending {
            remaining: ATTEMPTS.get(),
            limit: ATTEMPTS.get()
        }
    );
    let code = OneTimeCode::open(state.path().join("pairing-code"))
        .unwrap()
        .unwrap();
    assert_eq!(code.redeem(uri.code()).unwrap(), Redemption::Accepted);
}

#[test]
fn the_uri_names_the_host_and_port_and_pins_the_api_key() {
    let (_state, broker, uri) = first_start();
    let printed = uri.expose();
    assert!(printed.starts_with("opca-enrol://acme.home.example:9443#pin="));

    let parsed = PairingUri::parse(SCHEME, &printed).unwrap();
    assert_eq!(parsed.pin(), broker.pin());
    assert_eq!(
        parsed.pin().as_bytes(),
        broker.serving().key_fingerprint().0.as_bytes()
    );
}

#[test]
fn the_csr_verifies_and_carries_the_subordinate_key_on_p256() {
    let (_state, broker, _) = first_start();
    let provider = rustls_openssl::default_provider();
    let csr = Csr::from_pem(
        broker.subordinate().csr_pem(),
        provider.signature_verification_algorithms.all,
    )
    .unwrap();

    assert_eq!(csr.spki(), broker.subordinate().spki());
    assert_eq!(csr.key_algorithm(), Some(KeyAlgorithm::EcP256));
    assert_eq!(
        csr.common_name(),
        Some("opCA ACME broker acme.home.example")
    );
    assert!(csr.names().is_empty());
}

#[test]
fn a_lost_or_stale_csr_is_remade_over_the_same_key() {
    let (state, broker, _) = first_start();
    let key = fs::read(state.path().join("subordinate.key")).unwrap();
    let spki = broker.subordinate().spki().to_vec();
    drop(broker);

    fs::remove_file(state.path().join("subordinate.csr")).unwrap();
    let (remade, _) = Broker::start(&config(state.path())).unwrap();
    assert_eq!(remade.subordinate().spki(), spki);
    drop(remade);

    let moved = Config {
        host: "broker.home.example".into(),
        ..config(state.path())
    };
    let (rehosted, _) = Broker::start(&moved).unwrap();
    let csr = wslib_crypto_ca::CsrView::from_pem(rehosted.subordinate().csr_pem()).unwrap();
    assert_eq!(
        csr.common_name(),
        Some("opCA ACME broker broker.home.example")
    );
    assert_eq!(csr.spki(), spki);
    assert_eq!(fs::read(state.path().join("subordinate.key")).unwrap(), key);
}

#[test]
fn an_unreadable_key_stops_the_start_and_is_never_replaced() {
    let state = private_tempdir();
    let key = state.path().join("subordinate.key");
    fs::write(&key, "not a key").unwrap();

    assert!(Broker::start(&config(state.path())).is_err());
    assert_eq!(fs::read_to_string(&key).unwrap(), "not a key");
}

#[test]
fn a_state_dir_others_can_read_is_refused_before_anything_is_written() {
    let state = private_tempdir();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755)).unwrap();

    assert!(Broker::start(&config(state.path())).is_err());
    assert_eq!(fs::read_dir(state.path()).unwrap().count(), 0);
}

#[test]
fn a_host_that_is_not_a_name_or_address_is_refused() {
    let state = private_tempdir();
    let config = Config {
        host: "ops@home.example".into(),
        ..config(state.path())
    };
    assert!(Broker::start(&config).is_err());
    assert_eq!(fs::read_dir(state.path()).unwrap().count(), 0);
}

#[test]
fn the_config_needs_only_a_host() {
    let config = Config::parse(r#"host = "acme.home.example""#).unwrap();
    assert_eq!(config.listen, "[::]:9443".parse().unwrap());
    assert!(config.domains.is_empty());
    assert_eq!(config.state_dir, Path::new("/var/lib/opca-acme"));

    let full = Config::parse(
        r#"
        host = "10.0.0.5"
        listen = "10.0.0.5:8443"
        domains = ["home.example", "lab.example"]
        state_dir = "/srv/opca-acme"
        "#,
    )
    .unwrap();
    assert_eq!(full.listen.port(), 8443);
    assert_eq!(full.domains, ["home.example", "lab.example"]);
}

#[test]
fn a_config_with_no_host_or_an_unknown_key_is_refused() {
    assert!(Config::parse("").is_err());
    assert!(Config::parse("host = \"a.example\"\ndomain = [\"a.example\"]").is_err());
}
