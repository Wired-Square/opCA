//! The ACME API (RFC 8555) on the ACME listener. Its URLs are built from the
//! authority each request was sent to, so they hold behind a mapped port.

use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use opca_acme_api::Challenge as ChallengeType;
use rustls::crypto::CryptoProvider;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use wslib_crypto_jose::Jwk;
use wslib_crypto_x509::{inspect, pem};

use super::issue::{Issuer, check_identifier};
use super::request::{KeyRule, Nonces, Requests, Signer};
use super::store::{
    self, Account, AccountStatus, Authorisation, AuthorisationStatus, Challenge, ChallengeStatus,
    NewAuthorisation, NewOrder, Order, OrderStatus, Store, Validation,
};
use super::validate::Validate;
use super::{Problem, ProblemType, from_base64url};
use crate::enrolment::decimal;

/// How long an order and its authorisations live, as step-ca's default.
pub const ORDER_LIFETIME: Duration = Duration::from_secs(86_400);
const NONCES: usize = 4096;
const MAX_IDENTIFIERS: usize = 100;
const RETRY_AFTER: [(HeaderName, &str); 1] = [(header::RETRY_AFTER, "2")];
const NO_STORE: [(HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];
const REPLAY_NONCE: HeaderName = HeaderName::from_static("replay-nonce");

type Shared = State<Arc<Server>>;

pub(crate) struct Server {
    store: Store,
    nonces: Nonces,
    provider: Arc<CryptoProvider>,
    pub(crate) validator: Arc<dyn Validate>,
    pub(crate) lifetime: Duration,
    issuer: RwLock<Option<Arc<Issuer>>>,
    resumed: AtomicBool,
}

impl Server {
    pub(crate) fn new(
        store: Store,
        provider: Arc<CryptoProvider>,
        validator: Arc<dyn Validate>,
    ) -> Self {
        Self {
            store,
            nonces: Nonces::new(provider.clone(), NONCES),
            provider,
            validator,
            lifetime: ORDER_LIFETIME,
            issuer: RwLock::default(),
            resumed: AtomicBool::new(false),
        }
    }

    pub(crate) fn set_issuer(&self, issuer: Issuer) {
        *self.issuer.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(issuer));
    }

    fn issuer(&self) -> Result<Arc<Issuer>, Problem> {
        self.issuer
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| Problem::new(ProblemType::ServerInternal, "not issuing yet"))
    }

    /// Validates again, once a process, the challenges a restart left processing.
    pub(crate) fn resume(self: &Arc<Self>) {
        if self.resumed.swap(true, Ordering::SeqCst) {
            return;
        }
        let server = self.clone();
        tokio::spawn(async move {
            match server.store.processing().await {
                Ok(validations) => validations
                    .into_iter()
                    .for_each(|validation| server.validate_in_background(validation)),
                Err(error) => tracing::error!(%error, "could not resume validations"),
            }
        });
    }

    fn validate_in_background(self: &Arc<Self>, validation: Validation) {
        let server = self.clone();
        tokio::spawn(async move {
            let outcome = server
                .validator
                .validate(
                    validation.kind,
                    &validation.identifier,
                    &validation.key_authorisation,
                )
                .await;
            let (status, error) = match outcome {
                Ok(()) => (ChallengeStatus::Valid, None),
                Err(problem) => (ChallengeStatus::Invalid, Some(problem)),
            };
            if let Err(error) = server
                .store
                .set_challenge_status(validation.challenge, status, error.as_ref())
                .await
            {
                tracing::error!(%error, challenge = validation.challenge, "could not record a validation");
            }
        });
    }

    /// The order `id`, once stale orders have expired, if `account` placed it.
    async fn order_of(&self, id: i64, account: &Account) -> Result<Order, Refusal> {
        self.expire_stale().await?;
        self.owned_order(id, account).await
    }

    async fn authorisation_of(&self, id: i64, account: &Account) -> Result<Authorisation, Refusal> {
        self.expire_stale().await?;
        let authorisation = found(
            self.store.authorisation(id).await.map_err(stored)?,
            "authorisation",
        )?;
        self.owned_order(authorisation.order, account).await?;
        Ok(authorisation)
    }

    async fn owned_order(&self, id: i64, account: &Account) -> Result<Order, Refusal> {
        let order = found(self.store.order(id).await.map_err(stored)?, "order")?;
        owned_by(account, order.account)?;
        Ok(order)
    }

    async fn expire_stale(&self) -> Result<(), Refusal> {
        self.store
            .expire_stale(SystemTime::now())
            .await
            .map(drop)
            .map_err(stored)
    }
}

pub(crate) fn router(server: Arc<Server>) -> Router {
    Router::new()
        .route("/acme/directory", get(directory))
        .route("/acme/new-nonce", get(new_nonce).head(new_nonce_head))
        .route("/acme/new-account", post(new_account))
        .route("/acme/account/{id}", post(account))
        .route("/acme/account/{id}/orders", post(orders))
        .route("/acme/key-change", post(key_change))
        .route("/acme/new-order", post(new_order))
        .route("/acme/order/{id}", post(order))
        .route("/acme/order/{id}/finalize", post(finalise))
        .route("/acme/authz/{id}", post(authorisation))
        .route("/acme/challenge/{id}", post(challenge))
        .route("/acme/cert/{id}", post(certificate))
        .route("/acme/revoke-cert", post(revoke))
        .fallback(async || not_found("resource"))
        .layer(middleware::from_fn_with_state(server.clone(), stamp))
        .with_state(server)
}

/// A fresh nonce on every response, and the directory as its index.
async fn stamp(State(server): Shared, request: Request, next: Next) -> Response {
    let index = base(request.uri(), request.headers())
        .ok()
        .and_then(|base| {
            HeaderValue::try_from(format!("<{base}/acme/directory>;rel=\"index\"")).ok()
        });
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    match server.nonces.issue() {
        Ok(nonce) => {
            headers.insert(
                REPLAY_NONCE,
                HeaderValue::try_from(nonce).expect("base64url"),
            );
        }
        Err(error) => tracing::error!(%error, "could not mint a nonce"),
    }
    if let Some(index) = index {
        headers.append(header::LINK, index);
    }
    response
}

/// `https://` and the authority the request was sent to.
fn base(uri: &Uri, headers: &HeaderMap) -> Result<String, Problem> {
    uri.authority()
        .cloned()
        .or_else(|| {
            let host = headers.get(header::HOST)?.to_str().ok()?;
            Authority::from_str(host).ok()
        })
        .filter(|authority| !authority.as_str().contains('@'))
        .map(|authority| format!("https://{authority}"))
        .ok_or_else(|| malformed("the request names no host"))
}

async fn directory(uri: Uri, headers: HeaderMap) -> Result<Response, Refusal> {
    let base = base(&uri, &headers)?;
    let url = |path: &str| format!("{base}/acme/{path}");
    Ok(json(&json!({
        "newNonce": url("new-nonce"),
        "newAccount": url("new-account"),
        "newOrder": url("new-order"),
        "revokeCert": url("revoke-cert"),
        "keyChange": url("key-change"),
    }))
    .into_response())
}

async fn new_nonce() -> impl IntoResponse {
    (StatusCode::NO_CONTENT, NO_STORE)
}

async fn new_nonce_head() -> impl IntoResponse {
    (StatusCode::OK, NO_STORE)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountRequest {
    contact: Option<Vec<String>>,
    #[serde(default)]
    only_return_existing: bool,
    status: Option<String>,
}

async fn new_account(State(server): Shared, post: Post) -> Result<Response, Refusal> {
    let verified = post.verify(&server, KeyRule::Jwk).await?;
    let request: AccountRequest = parse(&verified.payload)?;
    let key = verified.signer.key();
    let thumbprint = key.thumbprint();
    let existing = server
        .store
        .account_by_thumbprint(&thumbprint)
        .await
        .map_err(stored)?;
    let (account, made) = match existing {
        Some(account) => (account, false),
        None if request.only_return_existing => {
            return Err(
                Problem::new(ProblemType::AccountDoesNotExist, "no account has this key").into(),
            );
        }
        None => server
            .store
            .create_account(
                &key.to_canonical_json(),
                &thumbprint,
                &contacts(request.contact.unwrap_or_default())?,
            )
            .await
            .map_err(stored)?,
    };
    if account.status != AccountStatus::Valid {
        return Err(unauthorized(format!("the account is {}", account.status.as_str())).into());
    }
    let status = if made {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        [(header::LOCATION, post.account_url(account.id))],
        json(&post.account_json(&account)),
    )
        .into_response())
}

async fn account(State(server): Shared, Id(id): Id, post: Post) -> Result<Response, Refusal> {
    let (account, _, payload) = post.by_account(&server).await?;
    owned_by(&account, id)?;
    if !payload.is_empty() {
        let request: AccountRequest = parse(&payload)?;
        if let Some(contact) = request.contact {
            server
                .store
                .set_contacts(id, &contacts(contact)?)
                .await
                .map_err(stored)?;
        }
        match request.status.as_deref() {
            None | Some("valid") => {}
            Some("deactivated") => server
                .store
                .set_account_status(id, AccountStatus::Deactivated)
                .await
                .map_err(stored)?,
            Some(other) => {
                return Err(malformed(format!("an account can't become {other:?}")).into());
            }
        }
    }
    let account = found(server.store.account(id).await.map_err(stored)?, "account")?;
    Ok(json(&post.account_json(&account)).into_response())
}

async fn orders(State(server): Shared, Id(id): Id, post: Post) -> Result<Response, Refusal> {
    let (account, _, payload) = post.by_account(&server).await?;
    as_get(&payload)?;
    owned_by(&account, id)?;
    let orders = server.store.orders_of(id).await.map_err(stored)?;
    let urls: Vec<String> = orders
        .into_iter()
        .map(|id| post.url_of("order", id))
        .collect();
    Ok(json(&json!({ "orders": urls })).into_response())
}

async fn key_change(State(server): Shared, post: Post) -> Result<Response, Refusal> {
    let change = post
        .requests(&server)
        .verify_key_change(&post.body, &post.url)
        .await?;
    let id = change.account.id;
    let key = &change.new_key;
    match server
        .store
        .change_key(id, &key.to_canonical_json(), &key.thumbprint())
        .await
    {
        Ok(()) => {}
        Err(store::Error::KeyInUse { account }) => {
            return Err(Refusal {
                problem: malformed("another account holds the new key"),
                status: StatusCode::CONFLICT,
                location: Some(post.account_url(account)),
            });
        }
        Err(error) => return Err(stored(error)),
    }
    let account = found(server.store.account(id).await.map_err(stored)?, "account")?;
    Ok(json(&post.account_json(&account)).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrderRequest {
    identifiers: Vec<Identifier>,
    not_before: Option<String>,
    not_after: Option<String>,
}

#[derive(Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

async fn new_order(State(server): Shared, post: Post) -> Result<Response, Refusal> {
    let (account, _, payload) = post.by_account(&server).await?;
    let request: OrderRequest = parse(&payload)?;
    let issuer = server.issuer()?;
    let config = issuer.config();
    let names = names(&request.identifiers, &config.permitted_domains)?;
    let expires = SystemTime::now() + server.lifetime;
    let authorisations = names
        .iter()
        .map(|name| authorisation_for(name, &config.challenges, expires))
        .collect::<Result<_, _>>()?;
    let order = server
        .store
        .create_order(&NewOrder {
            account: account.id,
            identifiers: names.into_iter().collect(),
            not_before: instant(request.not_before, "notBefore")?,
            not_after: instant(request.not_after, "notAfter")?,
            expires,
            authorisations,
        })
        .await
        .map_err(stored)?;
    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, post.url_of("order", order.id))],
        json(&post.order_json(&order)),
    )
        .into_response())
}

/// The DNS names `identifiers` ask for, lower-case, each one the broker issues for.
fn names(identifiers: &[Identifier], permitted: &[String]) -> Result<BTreeSet<String>, Problem> {
    if identifiers.is_empty() || identifiers.len() > MAX_IDENTIFIERS {
        return Err(malformed(format!(
            "an order names 1 to {MAX_IDENTIFIERS} identifiers"
        )));
    }
    identifiers
        .iter()
        .map(|identifier| match identifier.kind.as_str() {
            "dns" => {
                let name = identifier.value.to_ascii_lowercase();
                check_identifier(&name, permitted)?;
                Ok(name)
            }
            "ip" => Err(Problem::new(
                ProblemType::RejectedIdentifier,
                format!(
                    "{} is an IP address, and only DNS names are issued",
                    identifier.value
                ),
            )),
            other => Err(Problem::new(
                ProblemType::UnsupportedIdentifier,
                format!("{other:?} identifiers are not issued"),
            )),
        })
        .collect()
}

/// A wildcard is validated only by dns-01, as RFC 8555 §7.1.3 has it.
fn authorisation_for(
    name: &str,
    offered: &[ChallengeType],
    expires: SystemTime,
) -> Result<NewAuthorisation, Problem> {
    let (identifier, wildcard) = match name.strip_prefix("*.") {
        Some(base) => (base, true),
        None => (name, false),
    };
    let challenges: Vec<ChallengeType> = offered
        .iter()
        .copied()
        .filter(|kind| !wildcard || *kind == ChallengeType::Dns01)
        .collect();
    if challenges.is_empty() {
        return Err(Problem::new(
            ProblemType::RejectedIdentifier,
            format!("{name} needs dns-01, which is not offered"),
        ));
    }
    Ok(NewAuthorisation {
        identifier: identifier.into(),
        wildcard,
        expires,
        challenges,
    })
}

fn instant(text: Option<String>, what: &'static str) -> Result<Option<SystemTime>, Problem> {
    text.map(|text| {
        wslib_db_sqlite::stamp::parse("order", what, &text)
            .map(SystemTime::from)
            .map_err(|_| malformed(format!("{what} {text:?} is not an RFC 3339 time")))
    })
    .transpose()
}

async fn order(State(server): Shared, Id(id): Id, post: Post) -> Result<Response, Refusal> {
    let (account, _, payload) = post.by_account(&server).await?;
    as_get(&payload)?;
    let order = server.order_of(id, &account).await?;
    let processing = order.status == OrderStatus::Processing;
    Ok((
        processing.then_some(RETRY_AFTER),
        json(&post.order_json(&order)),
    )
        .into_response())
}

#[derive(Deserialize)]
struct FinaliseRequest {
    csr: String,
}

async fn finalise(State(server): Shared, Id(id): Id, post: Post) -> Result<Response, Refusal> {
    let (account, key, payload) = post.by_account(&server).await?;
    let order = server.order_of(id, &account).await?;
    if order.status != OrderStatus::Ready {
        return Err(Problem::new(
            ProblemType::OrderNotReady,
            format!("the order is {}", order.status.as_str()),
        )
        .into());
    }
    let request: FinaliseRequest = parse(&payload)?;
    let csr = from_base64url(&request.csr)
        .ok_or_else(|| Problem::new(ProblemType::BadCsr, "the CSR is not base64url"))?;
    server
        .issuer()?
        .finalise(&server.store, &order, &csr, &key.subject_public_key_info())
        .await?;
    let order = server.order_of(id, &account).await?;
    Ok((
        [(header::LOCATION, post.url_of("order", id))],
        json(&post.order_json(&order)),
    )
        .into_response())
}

#[derive(Deserialize)]
struct Deactivation {
    status: String,
}

async fn authorisation(State(server): Shared, Id(id): Id, post: Post) -> Result<Response, Refusal> {
    let (account, _, payload) = post.by_account(&server).await?;
    let mut authorisation = server.authorisation_of(id, &account).await?;
    if !payload.is_empty() {
        let request: Deactivation = parse(&payload)?;
        if request.status != "deactivated" {
            return Err(malformed("an authorisation can only be deactivated").into());
        }
        server
            .store
            .set_authorisation_status(id, AuthorisationStatus::Deactivated)
            .await
            .map_err(stored)?;
        authorisation = server.authorisation_of(id, &account).await?;
    }
    let processing = authorisation
        .challenges
        .iter()
        .any(|challenge| challenge.status == ChallengeStatus::Processing);
    Ok((
        processing.then_some(RETRY_AFTER),
        json(&post.authorisation_json(&authorisation)),
    )
        .into_response())
}

async fn challenge(State(server): Shared, Id(id): Id, post: Post) -> Result<Response, Refusal> {
    let (account, _, payload) = post.by_account(&server).await?;
    let mut challenge = found(
        server.store.challenge(id).await.map_err(stored)?,
        "challenge",
    )?;
    let authorisation = server
        .authorisation_of(challenge.authorisation, &account)
        .await?;
    if !payload.is_empty()
        && challenge.status == ChallengeStatus::Pending
        && authorisation.status == AuthorisationStatus::Pending
    {
        parse::<serde_json::Map<String, Value>>(&payload)?;
        server
            .store
            .set_challenge_status(id, ChallengeStatus::Processing, None)
            .await
            .map_err(stored)?;
        server.validate_in_background(Validation {
            challenge: id,
            kind: challenge.kind,
            identifier: authorisation.identifier.clone(),
            key_authorisation: format!("{}.{}", challenge.token, account.thumbprint),
        });
        challenge = found(
            server.store.challenge(id).await.map_err(stored)?,
            "challenge",
        )?;
    }
    let up = format!("<{}>;rel=\"up\"", post.url_of("authz", authorisation.id));
    Ok((
        [(header::LINK, up)],
        (challenge.status == ChallengeStatus::Processing).then_some(RETRY_AFTER),
        json(&post.challenge_json(&challenge)),
    )
        .into_response())
}

async fn certificate(State(server): Shared, Id(id): Id, post: Post) -> Result<Response, Refusal> {
    let (account, _, payload) = post.by_account(&server).await?;
    as_get(&payload)?;
    let certificate = found(
        server.store.certificate(id).await.map_err(stored)?,
        "certificate",
    )?;
    owned_by(&account, certificate.account)?;
    Ok((
        [(header::CONTENT_TYPE, "application/pem-certificate-chain")],
        certificate.chain_pem,
    )
        .into_response())
}

#[derive(Deserialize)]
struct RevocationRequest {
    certificate: String,
    reason: Option<u8>,
}

/// By the account that ordered the certificate, or by the certificate's own key (RFC 8555 §7.6).
async fn revoke(State(server): Shared, post: Post) -> Result<Response, Refusal> {
    let verified = post.verify(&server, KeyRule::Either).await?;
    let request: RevocationRequest = parse(&verified.payload)?;
    let der = from_base64url(&request.certificate)
        .ok_or_else(|| malformed("the certificate is not base64url"))?;
    let leaf = inspect(&der).map_err(malformed)?;
    let serial = decimal(&leaf.serial);
    let issued = server
        .store
        .certificate_by_serial(&serial)
        .await
        .map_err(stored)?
        .filter(|issued| {
            pem::certificates(&issued.chain_pem)
                .is_ok_and(|chain| chain.first().is_some_and(|first| first[..] == der[..]))
        });
    let issued = found(issued, "certificate")?;
    let permitted = match &verified.signer {
        Signer::Account { account, .. } => account.id == issued.account,
        Signer::Key(key) => key.subject_public_key_info() == leaf.spki,
    };
    if !permitted {
        return Err(unauthorized("neither its account nor its key signed this").into());
    }
    let reason = match request.reason {
        None | Some(0) => None,
        Some(reason @ (1..=6 | 9 | 10)) => Some(reason),
        Some(other) => {
            return Err(Problem::new(
                ProblemType::BadRevocationReason,
                format!("{other} is not a revocation reason"),
            )
            .into());
        }
    };
    server.store.revoke(&serial, reason).await.map_err(stored)?;
    Ok(StatusCode::OK.into_response())
}

/// A JWS-signed POST to its URL, `application/jose+json`.
struct Post {
    base: String,
    url: String,
    accounts: String,
    body: Bytes,
}

impl<S: Send + Sync> FromRequest<S> for Post {
    type Rejection = Refusal;

    async fn from_request(request: Request, state: &S) -> Result<Self, Refusal> {
        let jose = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split(';').next().map(str::trim) == Some("application/jose+json")
            });
        if !jose {
            return Err(Refusal {
                status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ..malformed("a request must be application/jose+json").into()
            });
        }
        let base = base(request.uri(), request.headers())?;
        let url = format!("{base}{}", request.uri().path());
        let body = Bytes::from_request(request, state)
            .await
            .map_err(|e| malformed(e.body_text()))?;
        Ok(Self {
            accounts: format!("{base}/acme/account/"),
            base,
            url,
            body,
        })
    }
}

impl Post {
    fn requests<'a>(&'a self, server: &'a Server) -> Requests<'a> {
        Requests {
            nonces: &server.nonces,
            store: &server.store,
            provider: &server.provider,
            accounts_url: &self.accounts,
        }
    }

    async fn verify(
        &self,
        server: &Server,
        rule: KeyRule,
    ) -> Result<super::request::Verified, Problem> {
        self.requests(server)
            .verify(&self.body, &self.url, rule)
            .await
    }

    /// The account that signed this by `kid`, its key, and the payload.
    async fn by_account(&self, server: &Server) -> Result<(Account, Jwk, Vec<u8>), Problem> {
        let verified = self.verify(server, KeyRule::Kid).await?;
        let Signer::Account { account, key } = verified.signer else {
            unreachable!("KeyRule::Kid yields an account")
        };
        Ok((account, key, verified.payload))
    }

    fn account_url(&self, id: i64) -> String {
        format!("{}{id}", self.accounts)
    }

    fn url_of(&self, kind: &str, id: i64) -> String {
        format!("{}/acme/{kind}/{id}", self.base)
    }

    fn account_json(&self, account: &Account) -> Value {
        json!({
            "status": account.status.as_str(),
            "contact": account.contacts,
            "orders": format!("{}/orders", self.account_url(account.id)),
        })
    }

    fn order_json(&self, order: &Order) -> Value {
        let identifiers: Vec<Value> = order
            .identifiers
            .iter()
            .map(|name| json!({ "type": "dns", "value": name }))
            .collect();
        let authorisations: Vec<String> = order
            .authorisations
            .iter()
            .map(|&id| self.url_of("authz", id))
            .collect();
        let mut body = json!({
            "status": order.status.as_str(),
            "expires": store::format(order.expires),
            "identifiers": identifiers,
            "authorizations": authorisations,
            "finalize": format!("{}/finalize", self.url_of("order", order.id)),
        });
        if let Some(at) = order.not_before {
            body["notBefore"] = json!(store::format(at));
        }
        if let Some(at) = order.not_after {
            body["notAfter"] = json!(store::format(at));
        }
        if let Some(error) = &order.error {
            body["error"] = json!(error);
        }
        if let Some(id) = order.certificate {
            body["certificate"] = json!(self.url_of("cert", id));
        }
        body
    }

    fn authorisation_json(&self, authorisation: &Authorisation) -> Value {
        let challenges: Vec<Value> = authorisation
            .challenges
            .iter()
            .map(|challenge| self.challenge_json(challenge))
            .collect();
        let mut body = json!({
            "identifier": { "type": "dns", "value": authorisation.identifier },
            "status": authorisation.status.as_str(),
            "expires": store::format(authorisation.expires),
            "challenges": challenges,
        });
        if authorisation.wildcard {
            body["wildcard"] = json!(true);
        }
        body
    }

    fn challenge_json(&self, challenge: &Challenge) -> Value {
        let mut body = json!({
            "type": challenge.kind,
            "url": self.url_of("challenge", challenge.id),
            "status": challenge.status.as_str(),
            "token": challenge.token,
        });
        if let Some(at) = challenge.validated {
            body["validated"] = json!(store::format(at));
        }
        if let Some(error) = &challenge.error {
            body["error"] = json!(error);
        }
        body
    }
}

/// A path's numeric id; anything else names nothing.
struct Id(i64);

impl<S: Send + Sync> FromRequestParts<S> for Id {
    type Rejection = Refusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Refusal> {
        let Path(id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| not_found("resource"))?;
        id.parse().map(Id).map_err(|_| not_found("resource"))
    }
}

/// An `application/problem+json` answer.
struct Refusal {
    problem: Problem,
    status: StatusCode,
    location: Option<String>,
}

impl From<Problem> for Refusal {
    fn from(problem: Problem) -> Self {
        use ProblemType::*;
        let status = match problem.kind {
            Unauthorized | OrderNotReady | UserActionRequired | Caa | ExternalAccountRequired => {
                StatusCode::FORBIDDEN
            }
            RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ServerInternal => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };
        Self {
            problem,
            status,
            location: None,
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&self.problem).expect("a problem serialises");
        (
            self.status,
            self.location.map(|location| [(header::LOCATION, location)]),
            [(header::CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response()
    }
}

fn not_found(what: &str) -> Refusal {
    Refusal {
        status: StatusCode::NOT_FOUND,
        ..malformed(format!("no such {what}")).into()
    }
}

fn found<T>(row: Option<T>, what: &str) -> Result<T, Refusal> {
    row.ok_or_else(|| not_found(what))
}

fn owned_by(account: &Account, owner: i64) -> Result<(), Problem> {
    if account.id == owner {
        Ok(())
    } else {
        Err(unauthorized("that belongs to another account"))
    }
}

fn stored(error: store::Error) -> Refusal {
    match error {
        store::Error::NotFound { table, .. } => not_found(table),
        store::Error::Transition { .. } => malformed(error).into(),
        store::Error::AlreadyRevoked { .. } => {
            Problem::new(ProblemType::AlreadyRevoked, error).into()
        }
        error => {
            tracing::error!(%error, "the ACME store failed");
            Problem::new(ProblemType::ServerInternal, error).into()
        }
    }
}

/// A POST-as-GET (RFC 8555 §6.3) carries an empty payload.
fn as_get(payload: &[u8]) -> Result<(), Problem> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(malformed("a POST-as-GET has an empty payload"))
    }
}

fn parse<T: DeserializeOwned>(payload: &[u8]) -> Result<T, Problem> {
    serde_json::from_slice(payload).map_err(|e| malformed(format!("the payload: {e}")))
}

fn contacts(contacts: Vec<String>) -> Result<Vec<String>, Problem> {
    for contact in &contacts {
        let Some(address) = contact.strip_prefix("mailto:") else {
            return Err(Problem::new(
                ProblemType::UnsupportedContact,
                format!("{contact:?} is not a mailto: URL"),
            ));
        };
        let valid = address
            .split_once('@')
            .is_some_and(|(user, host)| !user.is_empty() && !host.is_empty())
            && !address.contains([',', '?', ' ']);
        if !valid {
            return Err(Problem::new(
                ProblemType::InvalidContact,
                format!("{contact:?} is not one email address"),
            ));
        }
    }
    Ok(contacts)
}

fn json(body: &Value) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
}

fn malformed(detail: impl std::fmt::Display) -> Problem {
    Problem::new(ProblemType::Malformed, detail)
}

fn unauthorized(detail: impl std::fmt::Display) -> Problem {
    Problem::new(ProblemType::Unauthorized, detail)
}
