use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use instant_acme::{BodyWrapper, BytesResponse, HttpClient, NewAccount, NewOrder};
use opca_acme_broker::acme::request::{KeyChange, KeyRule, Nonces, Requests, Signer};
use opca_acme_broker::acme::store::{Account, AccountStatus};
use opca_acme_broker::acme::{Problem, ProblemType, Store, base64url};
use ring::rand::SystemRandom;
use ring::rsa::PublicKeyComponents;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use rustls::crypto::CryptoProvider;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use wslib_crypto::KeyAlgorithm;
use wslib_crypto_ca::Csr;
use wslib_crypto_jose::Jwk;

const ACCOUNTS: &str = "https://broker.home.example/acme/account/";
const NEW_ACCOUNT: &str = "https://broker.home.example/acme/new-account";
const NEW_ORDER: &str = "https://broker.home.example/acme/new-order";
const KEY_CHANGE: &str = "https://broker.home.example/acme/key-change";
const ALGORITHMS: [&str; 4] = ["ES256", "ES384", "RS256", "EdDSA"];
const WAIT: Duration = Duration::from_secs(30);

enum Pair {
    Ecdsa(EcdsaKeyPair, &'static str),
    Rsa(RsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

struct TestKey {
    alg: &'static str,
    pair: Pair,
    pkcs8: Vec<u8>,
}

fn rsa_pkcs8() -> Vec<u8> {
    static PKCS8: OnceLock<Vec<u8>> = OnceLock::new();
    PKCS8
        .get_or_init(|| {
            KeyAlgorithm::Rsa2048
                .generate()
                .unwrap()
                .secret_pkcs8_der()
                .to_vec()
        })
        .clone()
}

fn key(alg: &'static str) -> TestKey {
    let rng = SystemRandom::new();
    let ecdsa = |signing, crv| {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(signing, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(signing, pkcs8.as_ref(), &rng).unwrap();
        (Pair::Ecdsa(pair, crv), pkcs8.as_ref().to_vec())
    };
    let (pair, pkcs8) = match alg {
        "ES256" => ecdsa(&ECDSA_P256_SHA256_FIXED_SIGNING, "P-256"),
        "ES384" => ecdsa(&ECDSA_P384_SHA384_FIXED_SIGNING, "P-384"),
        "RS256" => {
            let pkcs8 = rsa_pkcs8();
            (Pair::Rsa(RsaKeyPair::from_pkcs8(&pkcs8).unwrap()), pkcs8)
        }
        _ => {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
            (Pair::Ed25519(pair), pkcs8.as_ref().to_vec())
        }
    };
    TestKey { alg, pair, pkcs8 }
}

impl TestKey {
    fn jwk(&self) -> Value {
        match &self.pair {
            Pair::Ecdsa(pair, crv) => {
                let point = &pair.public_key().as_ref()[1..];
                let (x, y) = point.split_at(point.len() / 2);
                json!({"kty": "EC", "crv": crv, "x": base64url(x), "y": base64url(y)})
            }
            Pair::Rsa(pair) => {
                let PublicKeyComponents { n, e } =
                    PublicKeyComponents::<Vec<u8>>::from(pair.public());
                json!({"kty": "RSA", "n": base64url(&n), "e": base64url(&e)})
            }
            Pair::Ed25519(pair) => {
                json!({"kty": "OKP", "crv": "Ed25519", "x": base64url(pair.public_key().as_ref())})
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match &self.pair {
            Pair::Ecdsa(pair, _) => pair.sign(&rng, message).unwrap().as_ref().to_vec(),
            Pair::Rsa(pair) => {
                let mut signature = vec![0; pair.public().modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
                    .unwrap();
                signature
            }
            Pair::Ed25519(pair) => pair.sign(message).as_ref().to_vec(),
        }
    }

    fn parsed(&self) -> Jwk {
        Jwk::from_json(&self.jwk().to_string()).unwrap()
    }

    fn jws(&self, protected: Value, payload: &[u8]) -> Vec<u8> {
        let protected = base64url(protected.to_string().as_bytes());
        let payload = base64url(payload);
        let signature = base64url(&self.sign(format!("{protected}.{payload}").as_bytes()));
        json!({"protected": protected, "payload": payload, "signature": signature})
            .to_string()
            .into_bytes()
    }
}

struct Fixture {
    _dir: TempDir,
    store: Store,
    nonces: Nonces,
    provider: Arc<CryptoProvider>,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(rustls_openssl::default_provider());
    let store = Store::open(&dir.path().join("acme.db"), provider.clone())
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        nonces: Nonces::new(provider.clone(), 64),
        provider,
    }
}

impl Fixture {
    fn requests(&self) -> Requests<'_> {
        Requests {
            nonces: &self.nonces,
            store: &self.store,
            provider: &self.provider,
            accounts_url: ACCOUNTS,
        }
    }

    fn by_jwk(&self, key: &TestKey, url: &str) -> Value {
        json!({"alg": key.alg, "nonce": self.nonces.issue().unwrap(), "url": url, "jwk": key.jwk()})
    }

    fn by_kid(&self, key: &TestKey, kid: &str, url: &str) -> Value {
        json!({"alg": key.alg, "nonce": self.nonces.issue().unwrap(), "url": url, "kid": kid})
    }

    async fn register(&self, key: &TestKey) -> (Account, String) {
        let jwk = key.parsed();
        let (account, _) = self
            .store
            .create_account(&jwk.to_canonical_json(), &jwk.thumbprint(), &[])
            .await
            .unwrap();
        let kid = self.requests().account_url(account.id);
        (account, kid)
    }

    async fn refusal(&self, body: &[u8], url: &str, rule: KeyRule) -> ProblemType {
        self.requests()
            .verify(body, url, rule)
            .await
            .unwrap_err()
            .kind
    }
}

#[tokio::test]
async fn each_algorithm_signs_by_jwk_and_by_kid() {
    let f = fixture().await;
    for alg in ALGORITHMS {
        let key = key(alg);
        let body = key.jws(f.by_jwk(&key, NEW_ACCOUNT), b"{}");
        let verified = f
            .requests()
            .verify(&body, NEW_ACCOUNT, KeyRule::Jwk)
            .await
            .unwrap();
        assert!(
            matches!(&verified.signer, Signer::Key(jwk) if *jwk == key.parsed()),
            "{alg}"
        );
        assert_eq!(verified.payload, b"{}");

        let (account, kid) = f.register(&key).await;
        let body = key.jws(f.by_kid(&key, &kid, NEW_ORDER), b"");
        let verified = f
            .requests()
            .verify(&body, NEW_ORDER, KeyRule::Either)
            .await
            .unwrap();
        assert!(
            matches!(verified.signer, Signer::Account { account: a, .. } if a.id == account.id)
        );
        assert!(verified.payload.is_empty(), "{alg}: a POST-as-GET");
    }
}

#[test]
fn the_stored_jwk_round_trips_with_its_thumbprint() {
    for alg in ALGORITHMS {
        let jwk = key(alg).parsed();
        let stored = Jwk::from_json(&jwk.to_canonical_json()).unwrap();
        assert_eq!(stored, jwk, "{alg}");
        assert_eq!(stored.to_canonical_json(), jwk.to_canonical_json());
        assert_eq!(stored.thumbprint(), jwk.thumbprint());
    }
}

#[test]
fn the_account_key_spki_is_what_a_csr_with_that_key_carries() {
    let provider = rustls_openssl::default_provider();
    for alg in ALGORITHMS {
        let key = key(alg);
        let pair = match alg {
            "RS256" => rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
                &key.pkcs8.as_slice().into(),
                &rcgen::PKCS_RSA_SHA256,
            ),
            _ => rcgen::KeyPair::try_from(key.pkcs8.as_slice()),
        }
        .unwrap();
        let csr = rcgen::CertificateParams::new(vec!["a.home.example".to_string()])
            .unwrap()
            .serialize_request(&pair)
            .unwrap();
        let csr = Csr::from_der(csr.der(), provider.signature_verification_algorithms.all).unwrap();
        assert_eq!(key.parsed().subject_public_key_info(), csr.spki(), "{alg}");
    }
}

#[tokio::test]
async fn a_jws_for_another_url_is_unauthorized() {
    let f = fixture().await;
    let key = key("ES256");
    let body = key.jws(f.by_jwk(&key, NEW_ORDER), b"{}");
    assert_eq!(
        f.refusal(&body, NEW_ACCOUNT, KeyRule::Jwk).await,
        ProblemType::Unauthorized
    );
}

#[tokio::test]
async fn a_nonce_is_redeemed_once() {
    let f = fixture().await;
    let key = key("ES256");
    let body = key.jws(f.by_jwk(&key, NEW_ACCOUNT), b"{}");
    f.requests()
        .verify(&body, NEW_ACCOUNT, KeyRule::Jwk)
        .await
        .unwrap();
    assert_eq!(
        f.refusal(&body, NEW_ACCOUNT, KeyRule::Jwk).await,
        ProblemType::BadNonce
    );
}

#[tokio::test]
async fn a_missing_or_unissued_nonce_is_bad() {
    let f = fixture().await;
    let key = key("ES256");
    let mut header = f.by_jwk(&key, NEW_ACCOUNT);
    header.as_object_mut().unwrap().remove("nonce");
    let body = key.jws(header.clone(), b"{}");
    assert_eq!(
        f.refusal(&body, NEW_ACCOUNT, KeyRule::Jwk).await,
        ProblemType::BadNonce
    );
    header["nonce"] = json!("bm90LWlzc3VlZA");
    let body = key.jws(header, b"{}");
    assert_eq!(
        f.refusal(&body, NEW_ACCOUNT, KeyRule::Jwk).await,
        ProblemType::BadNonce
    );
}

#[tokio::test]
async fn the_key_must_be_named_as_the_endpoint_asks() {
    let f = fixture().await;
    let key = key("ES256");
    let (_, kid) = f.register(&key).await;
    let body = key.jws(f.by_jwk(&key, NEW_ORDER), b"{}");
    assert_eq!(
        f.refusal(&body, NEW_ORDER, KeyRule::Kid).await,
        ProblemType::Malformed
    );
    let body = key.jws(f.by_kid(&key, &kid, NEW_ACCOUNT), b"{}");
    assert_eq!(
        f.refusal(&body, NEW_ACCOUNT, KeyRule::Jwk).await,
        ProblemType::Malformed
    );
}

#[tokio::test]
async fn an_unknown_kid_is_no_account() {
    let f = fixture().await;
    let key = key("ES256");
    let (account, _) = f.register(&key).await;
    for kid in [
        format!("{ACCOUNTS}{}", account.id + 1),
        format!("{ACCOUNTS}0{}", account.id),
        format!("https://elsewhere.example/acme/account/{}", account.id),
    ] {
        let body = key.jws(f.by_kid(&key, &kid, NEW_ORDER), b"{}");
        assert_eq!(
            f.refusal(&body, NEW_ORDER, KeyRule::Kid).await,
            ProblemType::AccountDoesNotExist,
            "{kid}"
        );
    }
}

#[tokio::test]
async fn a_deactivated_account_is_unauthorized() {
    let f = fixture().await;
    let key = key("ES256");
    let (account, kid) = f.register(&key).await;
    f.store
        .set_account_status(account.id, AccountStatus::Deactivated)
        .await
        .unwrap();
    let body = key.jws(f.by_kid(&key, &kid, NEW_ORDER), b"{}");
    assert_eq!(
        f.refusal(&body, NEW_ORDER, KeyRule::Kid).await,
        ProblemType::Unauthorized
    );
}

#[tokio::test]
async fn a_tampered_payload_fails_and_leaves_the_nonce() {
    let f = fixture().await;
    let key = key("ES256");
    let header = f.by_jwk(&key, NEW_ACCOUNT);
    let mut body: Value = serde_json::from_slice(&key.jws(header.clone(), b"{}")).unwrap();
    body["payload"] = json!(base64url(br#"{"contact":[]}"#));
    let forged = body.to_string().into_bytes();
    assert_eq!(
        f.refusal(&forged, NEW_ACCOUNT, KeyRule::Jwk).await,
        ProblemType::Malformed
    );
    assert!(f.nonces.redeem(header["nonce"].as_str().unwrap()));
}

#[tokio::test]
async fn rsa_1024_is_a_bad_public_key() {
    let f = fixture().await;
    let jwk = json!({"kty": "RSA", "n": base64url(&[0xc5; 128]), "e": "AQAB"});
    let header =
        json!({"alg": "RS256", "nonce": f.nonces.issue().unwrap(), "url": NEW_ACCOUNT, "jwk": jwk});
    let body = json!({
        "protected": base64url(header.to_string().as_bytes()),
        "payload": base64url(b"{}"),
        "signature": base64url(&[1; 128]),
    })
    .to_string();
    assert_eq!(
        f.refusal(body.as_bytes(), NEW_ACCOUNT, KeyRule::Jwk).await,
        ProblemType::BadPublicKey
    );
}

#[tokio::test]
async fn an_algorithm_the_key_does_not_suit_or_none_is_refused() {
    let f = fixture().await;
    let key = key("ES256");
    for alg in ["ES384", "none", "HS256"] {
        let mut header = f.by_jwk(&key, NEW_ACCOUNT);
        header["alg"] = json!(alg);
        let body = key.jws(header, b"{}");
        assert_eq!(
            f.refusal(&body, NEW_ACCOUNT, KeyRule::Jwk).await,
            ProblemType::BadSignatureAlgorithm,
            "{alg}"
        );
    }
}

#[tokio::test]
async fn an_unprotected_header_is_malformed() {
    let f = fixture().await;
    let key = key("ES256");
    let mut body: Value =
        serde_json::from_slice(&key.jws(f.by_jwk(&key, NEW_ACCOUNT), b"{}")).unwrap();
    body["header"] = json!({"kid": "x"});
    let body = body.to_string().into_bytes();
    assert_eq!(
        f.refusal(&body, NEW_ACCOUNT, KeyRule::Jwk).await,
        ProblemType::Malformed
    );
}

/// A key change from `old` to `new`, with `edit` applied to the inner header and payload.
fn key_change(
    f: &Fixture,
    old: &TestKey,
    new: &TestKey,
    kid: &str,
    edit: impl FnOnce(&mut Value, &mut Value),
) -> Vec<u8> {
    let mut header = json!({"alg": new.alg, "url": KEY_CHANGE, "jwk": new.jwk()});
    let mut payload = json!({"account": kid, "oldKey": old.jwk()});
    edit(&mut header, &mut payload);
    let inner = new.jws(header, payload.to_string().as_bytes());
    old.jws(f.by_kid(old, kid, KEY_CHANGE), &inner)
}

async fn change(f: &Fixture, body: &[u8]) -> Result<KeyChange, Problem> {
    f.requests().verify_key_change(body, KEY_CHANGE).await
}

#[tokio::test]
async fn a_key_change_names_both_keys_across_algorithms() {
    let f = fixture().await;
    for (from, to) in [("ES256", "EdDSA"), ("RS256", "ES384"), ("EdDSA", "RS256")] {
        let (old, new) = (key(from), key(to));
        let (account, kid) = f.register(&old).await;
        let changed = change(&f, &key_change(&f, &old, &new, &kid, |_, _| {}))
            .await
            .unwrap();
        assert_eq!(changed.account.id, account.id);
        assert_eq!(changed.new_key, new.parsed(), "{from} to {to}");
    }
}

#[tokio::test]
async fn a_key_change_with_a_mismatched_inner_jws_is_refused() {
    let f = fixture().await;
    let (old, new, stranger) = (key("ES256"), key("ES256"), key("ES384"));
    let (_, kid) = f.register(&old).await;
    type Edit<'a> = Box<dyn FnOnce(&mut Value, &mut Value) + 'a>;
    let edits: [(&str, Edit); 5] = [
        ("inner url", Box::new(|h, _| h["url"] = json!(NEW_ORDER))),
        (
            "account",
            Box::new(|_, p| p["account"] = json!(format!("{ACCOUNTS}999"))),
        ),
        (
            "inner nonce",
            Box::new(|h, _| h["nonce"] = json!("bm9uY2U")),
        ),
        (
            "inner kid",
            Box::new(|h, _| {
                let h = h.as_object_mut().unwrap();
                h.remove("jwk");
                h.insert("kid".into(), json!("x"));
            }),
        ),
        ("old key", Box::new(|_, p| p["oldKey"] = stranger.jwk())),
    ];
    for (what, edit) in edits {
        let problem = change(&f, &key_change(&f, &old, &new, &kid, edit))
            .await
            .unwrap_err();
        assert_eq!(problem.kind, ProblemType::Malformed, "{what}: {problem}");
    }
}

#[tokio::test]
async fn a_key_change_whose_inner_signature_fails_is_malformed() {
    let f = fixture().await;
    let (old, new) = (key("ES256"), key("EdDSA"));
    let (_, kid) = f.register(&old).await;
    let inner = new.jws(
        json!({"alg": "EdDSA", "url": KEY_CHANGE, "jwk": new.jwk()}),
        json!({"account": kid, "oldKey": old.jwk()})
            .to_string()
            .as_bytes(),
    );
    let mut inner: Value = serde_json::from_slice(&inner).unwrap();
    inner["payload"] = json!(base64url(b"{}"));
    let body = old.jws(
        f.by_kid(&old, &kid, KEY_CHANGE),
        inner.to_string().as_bytes(),
    );
    assert_eq!(
        change(&f, &body).await.unwrap_err().kind,
        ProblemType::Malformed
    );
}

type Post = (String, Vec<u8>, Result<(), ProblemType>);

/// instant-acme against a loopback stub that answers through `Requests`, recording each POST's body and outcome.
struct Stub {
    base: String,
    accounts_url: String,
    fixture: Fixture,
    posts: Mutex<Vec<Post>>,
}

impl Stub {
    fn requests(&self) -> Requests<'_> {
        Requests {
            accounts_url: &self.accounts_url,
            ..self.fixture.requests()
        }
    }
}

async fn directory(State(stub): State<Arc<Stub>>) -> Response {
    let url = |path: &str| format!("{}/acme/{path}", stub.base);
    axum::Json(json!({
        "newNonce": url("new-nonce"),
        "newAccount": url("new-account"),
        "newOrder": url("new-order"),
        "revokeCert": url("revoke-cert"),
        "keyChange": url("key-change"),
    }))
    .into_response()
}

async fn new_nonce(State(stub): State<Arc<Stub>>) -> Response {
    [("Replay-Nonce", stub.fixture.nonces.issue().unwrap())].into_response()
}

async fn post(State(stub): State<Arc<Stub>>, uri: Uri, body: Bytes) -> Response {
    let path = uri.path().to_owned();
    let outcome = answer(&stub, &path, &body).await;
    stub.posts.lock().unwrap().push((
        path,
        body.to_vec(),
        outcome.as_ref().map(|_| ()).map_err(|p| p.kind),
    ));
    let nonce = [("Replay-Nonce", stub.fixture.nonces.issue().unwrap())];
    match outcome {
        Ok(response) => (nonce, response).into_response(),
        Err(problem) => (
            StatusCode::BAD_REQUEST,
            nonce,
            [(header::CONTENT_TYPE, "application/problem+json")],
            serde_json::to_string(&problem).unwrap(),
        )
            .into_response(),
    }
}

async fn answer(stub: &Stub, path: &str, body: &[u8]) -> Result<Response, Problem> {
    let requests = stub.requests();
    let url = format!("{}{path}", stub.base);
    let created = |location: String, body: Value| {
        (
            StatusCode::CREATED,
            [(header::LOCATION, location)],
            axum::Json(body),
        )
            .into_response()
    };
    match path {
        "/acme/new-account" => {
            let verified = requests.verify(body, &url, KeyRule::Jwk).await?;
            let key = verified.signer.key();
            let (account, _) = stub
                .fixture
                .store
                .create_account(&key.to_canonical_json(), &key.thumbprint(), &[])
                .await
                .unwrap();
            Ok(created(
                requests.account_url(account.id),
                json!({"status": "valid"}),
            ))
        }
        "/acme/new-order" => {
            requests.verify(body, &url, KeyRule::Kid).await?;
            Ok(created(
                format!("{}/acme/order/1", stub.base),
                json!({
                    "status": "pending",
                    "identifiers": [{"type": "dns", "value": "a.home.example"}],
                    "authorizations": [format!("{}/acme/authz/1", stub.base)],
                    "finalize": format!("{}/acme/order/1/finalize", stub.base),
                }),
            ))
        }
        "/acme/key-change" => {
            requests.verify_key_change(body, &url).await?;
            Ok(StatusCode::OK.into_response())
        }
        _ => {
            let verified = requests.verify(body, &url, KeyRule::Kid).await?;
            let Signer::Account { account, .. } = verified.signer else {
                unreachable!()
            };
            let update: Value = serde_json::from_slice(&verified.payload).unwrap();
            let status = if update["status"] == "deactivated" {
                stub.fixture
                    .store
                    .set_account_status(account.id, AccountStatus::Deactivated)
                    .await
                    .unwrap();
                AccountStatus::Deactivated
            } else {
                account.status
            };
            Ok(axum::Json(json!({"status": status.as_str()})).into_response())
        }
    }
}

struct Loopback(Client<HttpConnector, BodyWrapper<Bytes>>);

impl HttpClient for Loopback {
    fn request(
        &self,
        request: axum::http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let response = self.0.request(request);
        Box::pin(async move {
            response
                .await
                .map(BytesResponse::from)
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))
        })
    }
}

fn loopback() -> Box<dyn HttpClient> {
    Box::new(Loopback(
        Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn instant_acme_requests_verify() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let stub = Arc::new(Stub {
        accounts_url: format!("{base}/acme/account/"),
        base: base.clone(),
        fixture: fixture().await,
        posts: Mutex::default(),
    });
    let app = Router::new()
        .route("/acme/directory", get(directory))
        .route("/acme/new-nonce", get(new_nonce).head(new_nonce))
        .fallback(post)
        .with_state(stub.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let new_account = NewAccount {
        contact: &[],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let directory_url = format!("{base}/acme/directory");
    tokio::time::timeout(WAIT, async {
        let (mut account, _) = instant_acme::Account::builder_with_http(loopback())
            .create(&new_account, directory_url.clone(), None)
            .await
            .unwrap();
        let stored = stub
            .fixture
            .store
            .account_by_thumbprint(account.key_thumbprint())
            .await
            .unwrap()
            .expect("the account's key, stored by its RFC 7638 thumbprint");
        assert_eq!(account.id(), stub.requests().account_url(stored.id));

        let identifiers = [instant_acme::Identifier::Dns("a.home.example".into())];
        account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .unwrap();
        account
            .update_contacts(&["mailto:a@home.example"])
            .await
            .unwrap();
        let _ = account.update_key().await.unwrap();

        let (doomed, credentials) = instant_acme::Account::builder_with_http(loopback())
            .create(&new_account, directory_url.clone(), None)
            .await
            .unwrap();
        doomed.deactivate().await.unwrap();
        let revived = instant_acme::Account::builder_with_http(loopback())
            .from_credentials(credentials)
            .await
            .unwrap();
        let Err(refused) = revived.new_order(&NewOrder::new(&identifiers)).await else {
            panic!("a deactivated account's order is refused");
        };
        assert!(refused.to_string().contains("unauthorized"), "{refused}");
    })
    .await
    .expect("instant-acme finishes against the stub");

    let posts = stub.posts.lock().unwrap().clone();
    let outcomes: Vec<_> = posts
        .iter()
        .map(|(path, _, outcome)| (path.split('/').nth(2).unwrap(), *outcome))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("new-account", Ok(())),
            ("new-order", Ok(())),
            ("account", Ok(())),
            ("key-change", Ok(())),
            ("new-account", Ok(())),
            ("account", Ok(())),
            ("new-order", Err(ProblemType::Unauthorized)),
        ]
    );

    let (path, replayed, _) = &posts[1];
    let replay = tokio::time::timeout(
        WAIT,
        stub.requests()
            .verify(replayed, &format!("{base}{path}"), KeyRule::Kid),
    )
    .await
    .unwrap();
    assert_eq!(replay.unwrap_err().kind, ProblemType::BadNonce);
}
