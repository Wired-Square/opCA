use std::sync::Arc;
use std::time::{Duration, SystemTime};

use opca_acme_api::{Challenge, IssuanceConfig};
use opca_acme_broker::acme::store::{
    ChallengeStatus, NewAuthorisation, NewOrder, Order, OrderStatus,
};
use opca_acme_broker::acme::{Issuer, ProblemType, Store, check_identifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use wslib_crypto::{KeyAlgorithm, Signer};
use wslib_crypto_ca::{
    Authority, BasicConstraints, Csr, Extension, KeyIdentifierMethod, Profile, Serial, Subject,
    Validity, build_csr,
};
use wslib_crypto_x509::chain::{self, Purpose};
use wslib_crypto_x509::pem::{self, CERTIFICATE};
use wslib_crypto_x509::{
    ExtendedKeyUsage, KeyUsage, NameConstraints, NameSubtree, SubjectAltName, inspect,
};

const DAY: Duration = Duration::from_secs(86_400);
const DOMAIN: &str = "home.example";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_openssl::default_provider())
}

fn signer(algorithm: KeyAlgorithm) -> Signer {
    Signer::new(
        provider(),
        &PrivateKeyDer::Pkcs8(algorithm.generate().unwrap()),
    )
    .unwrap()
}

fn config() -> IssuanceConfig {
    IssuanceConfig {
        permitted_domains: vec![DOMAIN.into()],
        leaf_days: 30,
        leaf_max_days: 45,
        challenges: vec![Challenge::Http01, Challenge::Dns01],
    }
}

fn authority_profile(name_constraints: Option<NameConstraints>) -> Profile {
    Profile {
        basic_constraints: Some(Extension::critical(BasicConstraints::Authority {
            path_length: name_constraints.as_ref().map(|_| 0),
        })),
        key_usage: Some(Extension::critical(vec![
            KeyUsage::KeyCertSign,
            KeyUsage::CrlSign,
        ])),
        name_constraints: name_constraints.map(Extension::critical),
        ..Profile::default()
    }
}

/// An opCA-like root, and a subordinate under it constrained to [`DOMAIN`].
struct Pki {
    root: CertificateDer<'static>,
    subordinate: CertificateDer<'static>,
    issuer: Issuer,
}

fn pki(subordinate_lifetime: Duration) -> Pki {
    let now = SystemTime::now();
    let validity = |days| Validity {
        not_before: now - DAY,
        not_after: now + days,
    };
    let root = Authority::self_signed(
        signer(KeyAlgorithm::EcP384),
        &Subject::new("Test Root").to_der().unwrap(),
        &authority_profile(None),
        &Serial::try_from(1u64).unwrap(),
        validity(3650 * DAY),
        KeyIdentifierMethod::Sha1,
    )
    .unwrap();
    let key = signer(KeyAlgorithm::EcP256);
    let request = csr(&key, &Subject::new("opCA ACME broker"), &[]);
    let constraints = NameConstraints {
        permitted: vec![NameSubtree::Dns(DOMAIN.into())],
        excluded: Vec::new(),
    };
    let subordinate = root
        .issue(
            &request,
            &authority_profile(Some(constraints)),
            &Serial::try_from(2u64).unwrap(),
            validity(subordinate_lifetime),
        )
        .unwrap();
    let chain_pem = [&subordinate, root.certificate()]
        .map(|der| pem::encode(CERTIFICATE, der))
        .concat();
    Pki {
        root: root.certificate().clone(),
        issuer: Issuer::new(key, &chain_pem, config()).unwrap(),
        subordinate,
    }
}

fn csr(key: &Signer, subject: &Subject, names: &[SubjectAltName]) -> Csr {
    let der = build_csr(key, subject, names).unwrap();
    Csr::from_der(&der, provider().signature_verification_algorithms.all).unwrap()
}

fn dns(names: &[&str]) -> Vec<SubjectAltName> {
    names
        .iter()
        .map(|name| SubjectAltName::Dns(name.to_string()))
        .collect()
}

fn order_for(names: &[&str]) -> Order {
    Order {
        id: 1,
        account: 1,
        status: OrderStatus::Ready,
        identifiers: names.iter().map(|name| name.to_string()).collect(),
        not_before: None,
        not_after: None,
        expires: SystemTime::now() + DAY,
        error: None,
        certificate: None,
        authorisations: Vec::new(),
    }
}

const ACCOUNT_KEY: &[u8] = b"not the CSR's key";

/// The problem type issuing `csr` for an order of `ordered` meets, if any.
fn refusal(pki: &Pki, ordered: &[&str], csr_der: &[u8]) -> Option<ProblemType> {
    pki.issuer
        .issue(&order_for(ordered), csr_der, ACCOUNT_KEY, SystemTime::now())
        .err()
        .map(|problem| problem.kind)
}

fn request(cn: &str, names: &[&str]) -> Vec<u8> {
    let key = signer(KeyAlgorithm::EcP256);
    build_csr(&key, &Subject::new(cn), &dns(names))
        .unwrap()
        .to_vec()
}

#[test]
fn a_name_must_be_a_lower_case_a_label_name_within_the_permitted_domains() {
    let domains = [DOMAIN.to_string()];
    let ok = |name| check_identifier(name, &domains).is_ok();
    assert!(ok("home.example"));
    assert!(ok("www.home.example"));
    assert!(ok("*.home.example"));
    assert!(ok("*.lab.home.example"));
    assert!(ok("xn--bcher-kva.home.example"));

    for refused in [
        "www.other.example",
        "evilhome.example",
        "*.example",
        "w*w.home.example",
        "*w.home.example",
        "www.*.home.example",
        "*",
        "10.0.0.1",
        "::1",
        "WWW.home.example",
        "www.home.example.",
        "bücher.home.example",
        "xn--zz.home.example",
        "under_score.home.example",
        "-dash.home.example",
    ] {
        let problem = check_identifier(refused, &domains).expect_err(refused);
        assert_eq!(problem.kind, ProblemType::RejectedIdentifier, "{refused}");
    }
}

#[test]
fn a_csr_must_name_exactly_the_orders_identifiers() {
    let pki = pki(365 * DAY);
    let names = ["a.home.example", "b.home.example"];
    assert_eq!(
        refusal(&pki, &names, &request("a.home.example", &names)),
        None
    );
    assert_eq!(
        refusal(
            &pki,
            &["a.home.example"],
            &request("a.home.example", &names)
        ),
        Some(ProblemType::BadCsr)
    );
    assert_eq!(
        refusal(
            &pki,
            &names,
            &request("a.home.example", &["a.home.example"])
        ),
        Some(ProblemType::BadCsr)
    );
    assert_eq!(
        refusal(
            &pki,
            &names,
            &request("A.Home.Example", &["B.home.example", "a.HOME.example"])
        ),
        None,
        "names compare without case"
    );
}

#[test]
fn a_common_name_is_optional_but_must_be_one_of_the_names() {
    let pki = pki(365 * DAY);
    let names = ["a.home.example"];
    assert_eq!(
        refusal(&pki, &names, &request("c.home.example", &names)),
        Some(ProblemType::BadCsr)
    );

    let key = signer(KeyAlgorithm::EcP256);
    let mut params = rcgen::CertificateParams::new(vec!["a.home.example".to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let nameless = params.serialize_request(&key).unwrap();
    assert_eq!(refusal(&pki, &names, nameless.der()), None);
}

#[test]
fn a_subject_with_more_than_a_common_name_is_refused() {
    let pki = pki(365 * DAY);
    let key = signer(KeyAlgorithm::EcP256);
    let subject = Subject {
        organisation: Some("Not Verified Ltd".into()),
        ..Subject::new("a.home.example")
    };
    let der = build_csr(&key, &subject, &dns(&["a.home.example"])).unwrap();
    assert_eq!(
        refusal(&pki, &["a.home.example"], &der),
        Some(ProblemType::BadCsr)
    );
}

#[test]
fn a_name_outside_the_domains_or_a_mid_label_wildcard_is_a_rejected_identifier() {
    let pki = pki(365 * DAY);
    for name in ["www.other.example", "w*w.home.example"] {
        assert_eq!(
            refusal(&pki, &[name], &request(name, &[name])),
            Some(ProblemType::RejectedIdentifier),
            "{name}"
        );
    }
}

#[test]
fn an_ip_address_is_a_rejected_identifier() {
    let pki = pki(365 * DAY);
    let key = signer(KeyAlgorithm::EcP256);
    let names = [
        SubjectAltName::Dns("a.home.example".into()),
        SubjectAltName::Ip("10.0.0.5".parse().unwrap()),
    ];
    let der = build_csr(&key, &Subject::new("a.home.example"), &names).unwrap();
    assert_eq!(
        refusal(&pki, &["a.home.example", "10.0.0.5"], &der),
        Some(ProblemType::RejectedIdentifier)
    );
}

#[test]
fn the_account_key_cannot_be_the_certificates() {
    let pki = pki(365 * DAY);
    let key = signer(KeyAlgorithm::EcP256);
    let der = build_csr(
        &key,
        &Subject::new("a.home.example"),
        &dns(&["a.home.example"]),
    )
    .unwrap();
    let problem = pki
        .issuer
        .issue(
            &order_for(&["a.home.example"]),
            &der,
            key.spki(),
            SystemTime::now(),
        )
        .unwrap_err();
    assert_eq!(problem.kind, ProblemType::BadCsr);
}

#[test]
fn a_csr_whose_signature_fails_is_refused() {
    let pki = pki(365 * DAY);
    let mut der = request("a.home.example", &["a.home.example"]);
    let last = der.len() - 1;
    der[last] ^= 0x01;
    assert_eq!(
        refusal(&pki, &["a.home.example"], &der),
        Some(ProblemType::BadCsr)
    );
    assert_eq!(
        refusal(&pki, &["a.home.example"], b"not DER"),
        Some(ProblemType::BadCsr)
    );
}

async fn ready_order(store: &Store, names: &[&str], not_after: Option<SystemTime>) -> Order {
    let (account, _) = store.create_account("{}", "thumb", &[]).await.unwrap();
    let expires = SystemTime::now() + DAY;
    let order = store
        .create_order(&NewOrder {
            account: account.id,
            identifiers: names.iter().map(|name| name.to_string()).collect(),
            not_before: None,
            not_after,
            expires,
            authorisations: names
                .iter()
                .map(|name| NewAuthorisation {
                    identifier: name.trim_start_matches("*.").into(),
                    wildcard: name.starts_with("*."),
                    expires,
                    challenges: vec![Challenge::Dns01],
                })
                .collect(),
        })
        .await
        .unwrap();
    for &id in &order.authorisations {
        let challenge = store.authorisation(id).await.unwrap().unwrap().challenges[0].id;
        for status in [ChallengeStatus::Processing, ChallengeStatus::Valid] {
            store
                .set_challenge_status(challenge, status, None)
                .await
                .unwrap();
        }
    }
    store.order(order.id).await.unwrap().unwrap()
}

#[tokio::test]
async fn a_good_csr_is_issued_a_server_leaf_that_chains_to_the_subordinate_and_is_recorded() {
    let pki = pki(365 * DAY);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("acme.db"), provider())
        .await
        .unwrap();
    let names = ["www.home.example", "*.lab.home.example"];
    let order = ready_order(&store, &names, None).await;
    assert_eq!(order.status, OrderStatus::Ready);

    let der = request("www.home.example", &names);
    let before = SystemTime::now();
    let recorded = pki
        .issuer
        .finalise(&store, &order, &der, ACCOUNT_KEY)
        .await
        .unwrap();

    let chain = pem::certificates(&recorded.chain_pem).unwrap();
    assert_eq!(chain.len(), 2, "the leaf and the subordinate, not the root");
    assert_eq!(chain[1], pki.subordinate);
    let anchors = [chain::trust_anchor(&pki.root).unwrap()];
    chain::verify(
        &chain[0],
        &chain[1..],
        &anchors,
        Purpose::SERVER_AUTH,
        SystemTime::now(),
        provider().signature_verification_algorithms.all,
    )
    .unwrap();

    let leaf = inspect(&chain[0]).unwrap();
    assert!(!leaf.ca);
    assert_eq!(
        leaf.extended_key_usages,
        Some(vec![ExtendedKeyUsage::ServerAuth])
    );
    assert_eq!(leaf.key_usages, Some(vec![KeyUsage::DigitalSignature]));
    assert_eq!(leaf.sans, dns(&names));
    assert_eq!(
        leaf.not_after.duration_since(leaf.not_before).unwrap(),
        30 * DAY
    );
    assert!(leaf.not_before <= before && leaf.not_before >= before - 2 * Duration::from_secs(60));

    assert_eq!(
        recorded.serial.parse::<Serial>().unwrap().to_string(),
        recorded.serial
    );
    assert_eq!(recorded.common_name.as_deref(), Some("www.home.example"));
    assert_eq!(recorded.sans, ["*.lab.home.example", "www.home.example"]);
    let order = store.order(order.id).await.unwrap().unwrap();
    assert_eq!(
        (order.status, order.certificate),
        (OrderStatus::Valid, Some(recorded.id))
    );
    assert_eq!(store.issued_after(0, 10).await.unwrap(), [recorded]);
}

#[test]
fn the_lifetime_is_the_orders_up_to_the_cap_and_never_past_the_subordinate() {
    let now = SystemTime::now();
    let lifetime = |pki: &Pki, not_after: Option<SystemTime>| {
        let order = Order {
            not_after,
            ..order_for(&["a.home.example"])
        };
        let issued = pki
            .issuer
            .issue(
                &order,
                &request("a.home.example", &["a.home.example"]),
                ACCOUNT_KEY,
                now,
            )
            .unwrap();
        (issued.not_after.duration_since(now).unwrap() + Duration::from_secs(60)).as_secs() / 86_400
    };
    let lasting = pki(365 * DAY);
    assert_eq!(lifetime(&lasting, None), 30);
    assert_eq!(lifetime(&lasting, Some(now + 10 * DAY)), 10);
    assert_eq!(lifetime(&lasting, Some(now + 90 * DAY)), 45);

    let ending = pki(20 * DAY);
    assert_eq!(lifetime(&ending, None), 20);
}

#[test]
fn an_rsa_leaf_also_has_key_encipherment() {
    let pki = pki(365 * DAY);
    let key = signer(KeyAlgorithm::Rsa2048);
    let der = build_csr(
        &key,
        &Subject::new("a.home.example"),
        &dns(&["a.home.example"]),
    )
    .unwrap();
    let issued = pki
        .issuer
        .issue(
            &order_for(&["a.home.example"]),
            &der,
            ACCOUNT_KEY,
            SystemTime::now(),
        )
        .unwrap();
    let leaf = inspect(&pem::certificates(&issued.chain_pem).unwrap()[0]).unwrap();
    assert_eq!(
        leaf.key_usages,
        Some(vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment])
    );
}
