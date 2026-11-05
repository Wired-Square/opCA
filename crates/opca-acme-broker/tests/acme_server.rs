#![cfg(unix)]

mod support;

use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::get;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes};
use hyper_util::rt::TokioIo;
use instant_acme::{
    Account, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType, HttpClient,
    Identifier, NewOrder, Order, OrderStatus, RetryPolicy, RevocationReason, RevocationRequest,
};
use opca_acme_broker::Broker;
use opca_acme_broker::acme::base64url;
use opca_acme_broker::acme::validate::{Ports, Validator};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use support::*;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use wslib_crypto_x509::{SubjectAltName, inspect, pem};
use wslib_dns::FakeResolver;

const NAME: &str = "a.home.example";
const OTHER: &str = "b.home.example";
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const WAIT: Duration = Duration::from_secs(30);

type Tokens = Arc<Mutex<HashMap<String, String>>>;

/// An enrolled broker whose validator reaches only a loopback http-01 server.
struct Acme {
    enrolled: Enrolled,
    https: Https,
    directory: String,
    tokens: Tokens,
}

async fn acme(lifetime: Option<Duration>) -> Acme {
    let tokens = Tokens::default();
    let http = challenge_server(tokens.clone()).await;
    let resolver = FakeResolver::new()
        .with_ip(NAME, [LOCALHOST])
        .with_ip(OTHER, [LOCALHOST]);
    let validator = Validator::new(resolver, provider())
        .unwrap()
        .with_ports(Ports { http, https: http })
        .with_timeout(Duration::from_secs(5));
    let state = private_tempdir();
    let (broker, uri) = Broker::start(&config(state.path(), &[])).await.unwrap();
    let mut broker = broker.with_validator(validator);
    if let Some(lifetime) = lifetime {
        broker = broker.with_order_lifetime(lifetime);
    }
    let enrolled = enrol(run(state, broker, uri).await).await;
    let address = enrolled
        .running
        .broker
        .acme_address()
        .expect("serving ACME");
    let https = Https::new(address, enrolled.root());
    Acme {
        directory: format!("https://{HOST}:{}/acme/directory", address.port()),
        enrolled,
        https,
        tokens,
    }
}

fn provider() -> Arc<tokio_rustls::rustls::crypto::CryptoProvider> {
    Arc::new(rustls_openssl::default_provider())
}

/// Answers `/.well-known/acme-challenge/<token>` with what `tokens` holds for it.
async fn challenge_server(tokens: Tokens) -> u16 {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(
                async |State(tokens): State<Tokens>, Path(token): Path<String>| match tokens
                    .lock()
                    .unwrap()
                    .get(&token)
                {
                    Some(answer) => (StatusCode::OK, answer.clone()),
                    None => (StatusCode::NOT_FOUND, String::new()),
                },
            ),
        )
        .with_state(tokens);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

/// HTTPS to the broker's ACME listener whatever the URL's host, trusting only the test root.
#[derive(Clone)]
struct Https {
    address: SocketAddr,
    tls: Arc<ClientConfig>,
}

type Failure = Box<dyn Error + Send + Sync>;

impl Https {
    fn new(address: SocketAddr, root: &CertificateDer<'static>) -> Self {
        let mut roots = RootCertStore::empty();
        roots.add(root.clone()).unwrap();
        let tls = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            address,
            tls: Arc::new(tls),
        }
    }

    async fn send<B>(
        &self,
        mut request: Request<B>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, Failure>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Failure>,
    {
        let tcp = TcpStream::connect(self.address).await?;
        let tls = TlsConnector::from(self.tls.clone())
            .connect(ServerName::try_from(HOST)?, tcp)
            .await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(connection);
        let authority = request.uri().authority().ok_or("no authority")?.to_string();
        *request.uri_mut() = request.uri().path().parse()?;
        request
            .headers_mut()
            .insert(header::HOST, authority.parse()?);
        Ok(sender.send_request(request).await?)
    }

    /// A JWS POST without instant-acme: the status, headers and body.
    async fn post(&self, url: &str, jws: Vec<u8>) -> (StatusCode, HeaderMap, Value) {
        let request = Request::post(url)
            .header(header::CONTENT_TYPE, "application/jose+json")
            .body(Full::new(Bytes::from(jws)))
            .unwrap();
        let response = self.send(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (parts.status, parts.headers, body)
    }

    async fn nonce(&self, base: &str) -> String {
        let request = Request::head(format!("{base}/acme/new-nonce"))
            .body(Full::<Bytes>::default())
            .unwrap();
        let response = self.send(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        replay_nonce(response.headers())
    }
}

impl HttpClient for Https {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let https = self.clone();
        Box::pin(async move {
            https
                .send(request)
                .await
                .map(BytesResponse::from)
                .map_err(instant_acme::Error::Other)
        })
    }
}

fn replay_nonce(headers: &HeaderMap) -> String {
    headers["replay-nonce"].to_str().unwrap().to_owned()
}

/// An ES256 key, as an account or a certificate holds it.
struct Key {
    pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
}

fn key() -> Key {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .unwrap()
        .as_ref()
        .to_vec();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).unwrap();
    Key { pair, pkcs8 }
}

impl Key {
    fn jwk(&self) -> Value {
        let point = &self.pair.public_key().as_ref()[1..];
        let (x, y) = point.split_at(32);
        json!({"kty": "EC", "crv": "P-256", "x": base64url(x), "y": base64url(y)})
    }

    fn jws(&self, mut protected: Value, payload: &[u8]) -> Vec<u8> {
        protected["alg"] = json!("ES256");
        let protected = base64url(protected.to_string().as_bytes());
        let payload = base64url(payload);
        let signature = self
            .pair
            .sign(
                &SystemRandom::new(),
                format!("{protected}.{payload}").as_bytes(),
            )
            .unwrap();
        json!({"protected": protected, "payload": payload, "signature": base64url(signature.as_ref())})
            .to_string()
            .into_bytes()
    }

    fn for_acme(&self) -> (instant_acme::Key, PrivateKeyDer<'static>) {
        let pkcs8 = PrivatePkcs8KeyDer::from(self.pkcs8.clone());
        (
            instant_acme::Key::from_pkcs8_der(pkcs8.clone_key()).unwrap(),
            PrivateKeyDer::Pkcs8(pkcs8),
        )
    }

    /// A CSR for `names` over this key.
    fn csr(&self, names: &[&str]) -> Vec<u8> {
        let pair = rcgen::KeyPair::try_from(self.pkcs8.as_slice()).unwrap();
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.serialize_request(&pair).unwrap().der().to_vec()
    }
}

fn retries() -> RetryPolicy {
    RetryPolicy::new()
        .initial_delay(Duration::from_millis(50))
        .timeout(WAIT)
}

impl Acme {
    fn base(&self) -> String {
        self.directory
            .trim_end_matches("/acme/directory")
            .to_owned()
    }

    fn client(&self) -> instant_acme::AccountBuilder {
        Account::builder_with_http(Box::new(self.https.clone()))
    }

    async fn account(&self, key: &Key) -> Account {
        self.client()
            .create_from_key(key.for_acme(), self.directory.clone())
            .await
            .unwrap()
            .0
    }

    /// An order for `names`, each answered over http-01.
    async fn validated(&self, account: &Account, names: &[&str]) -> Order {
        let identifiers: Vec<Identifier> = names
            .iter()
            .map(|n| Identifier::Dns(n.to_string()))
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .unwrap();
        let mut authorisations = order.authorizations();
        while let Some(authorisation) = authorisations.next().await {
            let mut authorisation = authorisation.unwrap();
            let mut challenge = authorisation.challenge(ChallengeType::Http01).unwrap();
            self.tokens.lock().unwrap().insert(
                challenge.token.clone(),
                challenge.key_authorization().as_str().to_owned(),
            );
            challenge.set_ready().await.unwrap();
        }
        assert_eq!(
            order.poll_ready(&retries()).await.unwrap(),
            OrderStatus::Ready
        );
        order
    }

    /// A certificate for `name` and the key it certifies.
    async fn issue(&self, account: &Account, name: &str) -> (String, Key) {
        let mut order = self.validated(account, &[name]).await;
        let key = key();
        order.finalize_csr(&key.csr(&[name])).await.unwrap();
        (order.poll_certificate(&retries()).await.unwrap(), key)
    }
}

fn kind(error: instant_acme::Error) -> String {
    match error {
        instant_acme::Error::Api(problem) => problem.r#type.unwrap_or_default(),
        other => panic!("not a problem document: {other}"),
    }
}

fn urn(kind: &str) -> String {
    format!("urn:ietf:params:acme:error:{kind}")
}

fn leaf(chain_pem: &str) -> CertificateDer<'static> {
    pem::certificates(chain_pem).unwrap().remove(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_account_orders_validates_finalises_and_downloads() {
    let acme = acme(None).await;
    tokio::time::timeout(WAIT, async {
        let account_key = key();
        let account = acme.account(&account_key).await;
        assert!(
            account
                .id()
                .starts_with(&format!("{}/acme/account/", acme.base()))
        );
        let found = acme
            .client()
            .from_key(account_key.for_acme(), acme.directory.clone())
            .await
            .unwrap()
            .0;
        assert_eq!(found.id(), account.id());
        let Err(unknown) = acme
            .client()
            .from_key(key().for_acme(), acme.directory.clone())
            .await
        else {
            panic!("onlyReturnExisting found an account for a new key");
        };
        assert_eq!(kind(unknown), urn("accountDoesNotExist"));

        let (chain_pem, _) = acme.issue(&account, NAME).await;
        let chain = pem::certificates(&chain_pem).unwrap();
        assert_eq!(chain[1..], acme.enrolled.chain[..1]);
        let view = inspect(&chain[0]).unwrap();
        assert_eq!(view.sans, [SubjectAltName::Dns(NAME.into())]);

        let changes = acme
            .enrolled
            .running
            .broker
            .acme()
            .changed_after(0, 10)
            .await
            .unwrap();
        assert_eq!(changes.certificates.len(), 1);
        assert_eq!(changes.certificates[0].chain_pem, chain_pem);
    })
    .await
    .expect("the flow finishes");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_challenge_carries_its_error_and_fails_the_order() {
    let acme = acme(None).await;
    tokio::time::timeout(WAIT, async {
        let account = acme.account(&key()).await;
        let mut order = account
            .new_order(&NewOrder::new(&[Identifier::Dns(NAME.into())]))
            .await
            .unwrap();
        order
            .authorizations()
            .next()
            .await
            .unwrap()
            .unwrap()
            .challenge(ChallengeType::Http01)
            .unwrap()
            .set_ready()
            .await
            .unwrap();
        assert_eq!(
            order.poll_ready(&retries()).await.unwrap(),
            OrderStatus::Invalid
        );

        let mut authorisations = order.authorizations();
        let mut authorisation = authorisations.next().await.unwrap().unwrap();
        let state = authorisation.refresh().await.unwrap();
        assert_eq!(state.status, AuthorizationStatus::Invalid);
        let error = state.challenges[0]
            .error
            .clone()
            .expect("the challenge's error");
        assert_eq!(error.r#type.unwrap(), urn("unauthorized"));
    })
    .await
    .expect("the flow finishes");
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_by_the_account_key_or_the_certificates_key() {
    let acme = acme(None).await;
    tokio::time::timeout(WAIT, async {
        let account = acme.account(&key()).await;
        let stranger = acme.account(&key()).await;
        let (by_account, _) = acme.issue(&account, NAME).await;
        let (by_key, cert_key) = acme.issue(&account, OTHER).await;
        let store = acme.enrolled.running.broker.acme();
        let before = store.changed_after(0, 10).await.unwrap().certificates;

        let certificate = leaf(&by_account);
        let request = RevocationRequest {
            certificate: &certificate,
            reason: Some(RevocationReason::KeyCompromise),
        };
        let Err(refused) = stranger.revoke(&request).await else {
            panic!("another account revoked the certificate");
        };
        assert_eq!(kind(refused), urn("unauthorized"));
        account.revoke(&request).await.unwrap();
        let Err(again) = account.revoke(&request).await else {
            panic!("revoked twice");
        };
        assert_eq!(kind(again), urn("alreadyRevoked"));

        let base = acme.base();
        let url = format!("{base}/acme/revoke-cert");
        let payload = json!({"certificate": base64url(&leaf(&by_key)), "reason": 4});
        let header =
            json!({"nonce": acme.https.nonce(&base).await, "url": url, "jwk": cert_key.jwk()});
        let (status, _, body) = acme
            .https
            .post(&url, cert_key.jws(header, payload.to_string().as_bytes()))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let after = store.changed_after(0, 10).await.unwrap().certificates;
        assert!(
            after
                .iter()
                .all(|certificate| certificate.revoked_at.is_some())
        );
        let reasons: Vec<_> = after.iter().map(|c| c.revocation_reason).collect();
        assert_eq!(reasons, [Some(1), Some(4)]);
        let newest_before = before.iter().map(|c| c.changed).max().unwrap();
        assert!(after.iter().all(|c| c.changed > newest_before));
    })
    .await
    .expect("the flow finishes");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_change_moves_the_account_and_a_key_in_use_conflicts() {
    let acme = acme(None).await;
    tokio::time::timeout(WAIT, async {
        let old_key = key();
        let mut account = acme.account(&old_key).await;
        let _ = account.update_key().await.unwrap();
        acme.validated(&account, &[NAME]).await;
        let Err(gone) = acme
            .client()
            .from_key(old_key.for_acme(), acme.directory.clone())
            .await
        else {
            panic!("the old key still names an account");
        };
        assert_eq!(kind(gone), urn("accountDoesNotExist"));

        let (mover_key, holder_key) = (key(), key());
        let mover = acme.account(&mover_key).await;
        let holder = acme.account(&holder_key).await;
        let base = acme.base();
        let url = format!("{base}/acme/key-change");
        let inner = holder_key.jws(
            json!({"url": url, "jwk": holder_key.jwk()}),
            json!({"account": mover.id(), "oldKey": mover_key.jwk()})
                .to_string()
                .as_bytes(),
        );
        let header = json!({"nonce": acme.https.nonce(&base).await, "url": url, "kid": mover.id()});
        let (status, headers, body) = acme.https.post(&url, mover_key.jws(header, &inner)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(headers[header::LOCATION], holder.id());
        assert_eq!(body["type"], urn("malformed"));
    })
    .await
    .expect("the flow finishes");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deactivated_account_is_refused() {
    let acme = acme(None).await;
    tokio::time::timeout(WAIT, async {
        let key = key();
        let account = acme.account(&key).await;
        account.clone().deactivate().await.unwrap();
        let Err(refused) = account
            .new_order(&NewOrder::new(&[Identifier::Dns(NAME.into())]))
            .await
        else {
            panic!("a deactivated account ordered");
        };
        assert_eq!(kind(refused), urn("unauthorized"));
        let Err(refused) = acme
            .client()
            .create_from_key(key.for_acme(), acme.directory.clone())
            .await
        else {
            panic!("a deactivated account was found");
        };
        assert_eq!(kind(refused), urn("unauthorized"));
    })
    .await
    .expect("the flow finishes");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_nonce_is_refused_with_a_fresh_one() {
    let acme = acme(None).await;
    let key = key();
    let base = acme.base();
    let url = format!("{base}/acme/new-account");
    let header = |nonce: &str| json!({"nonce": nonce, "url": url, "jwk": key.jwk()});
    let payload = br#"{"termsOfServiceAgreed":true}"#;

    let (status, headers, body) = acme
        .https
        .post(&url, key.jws(header("bm9uY2U"), payload))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    assert_eq!(body["type"], urn("badNonce"));
    assert_eq!(
        headers[header::LINK],
        format!("<{base}/acme/directory>;rel=\"index\"")
    );

    let fresh = replay_nonce(&headers);
    let (status, headers, body) = acme
        .https
        .post(&url, key.jws(header(&fresh), payload))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(
        headers[header::LOCATION]
            .to_str()
            .unwrap()
            .starts_with(&format!("{base}/acme/account/"))
    );
    assert_eq!(body["status"], "valid");
    assert_ne!(replay_nonce(&headers), fresh);
}

#[tokio::test(flavor = "multi_thread")]
async fn names_outside_the_permitted_domains_and_addresses_are_rejected() {
    let acme = acme(None).await;
    tokio::time::timeout(WAIT, async {
        let account = acme.account(&key()).await;
        for identifier in [
            Identifier::Dns("a.elsewhere.example".into()),
            Identifier::Ip(LOCALHOST),
        ] {
            let Err(refused) = account
                .new_order(&NewOrder::new(std::slice::from_ref(&identifier)))
                .await
            else {
                panic!("{identifier:?} was ordered");
            };
            assert_eq!(kind(refused), urn("rejectedIdentifier"), "{identifier:?}");
        }

        let mut order = account
            .new_order(&NewOrder::new(&[Identifier::Dns("*.home.example".into())]))
            .await
            .unwrap();
        let mut authorisations = order.authorizations();
        let mut authorisation = authorisations.next().await.unwrap().unwrap();
        let state = authorisation.refresh().await.unwrap();
        assert!(state.wildcard);
        let offered: Vec<_> = state.challenges.iter().map(|c| c.r#type.clone()).collect();
        assert_eq!(offered, [ChallengeType::Dns01]);
    })
    .await
    .expect("the flow finishes");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_order_is_invalid() {
    let acme = acme(Some(Duration::ZERO)).await;
    tokio::time::timeout(WAIT, async {
        let account = acme.account(&key()).await;
        let mut order = account
            .new_order(&NewOrder::new(&[Identifier::Dns(NAME.into())]))
            .await
            .unwrap();
        assert_eq!(order.refresh().await.unwrap().status, OrderStatus::Invalid);
        let mut authorisations = order.authorizations();
        let mut authorisation = authorisations.next().await.unwrap().unwrap();
        assert_eq!(
            authorisation.refresh().await.unwrap().status,
            AuthorizationStatus::Expired
        );
    })
    .await
    .expect("the flow finishes");
}
