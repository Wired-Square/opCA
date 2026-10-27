use std::io;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use opca_acme_api::{ErrorBody, ErrorKind, path};
use serde::Serialize;
use serde::de::DeserializeOwned;
use wslib_http_server::{Listener, PeerCertificates};

use crate::{Broker, Enrolled, Mode};

type Shared = State<Arc<Broker>>;

/// Serves the API on `listener` until `stop` completes.
pub async fn serve(
    broker: Arc<Broker>,
    listener: Listener,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    let tls = broker.tls.clone();
    wslib_http_server::serve_https(listener, router(broker), tls, stop).await
}

fn router(broker: Arc<Broker>) -> Router {
    Router::new()
        .route(path::ENROLMENT, get(offer).post(enrol))
        .route(path::STATUS, get(status))
        .route(path::CSR, post(fresh_csr))
        .route(path::CHAIN, put(chain))
        .route(path::REVOKE, post(revoke))
        .with_state(broker)
}

async fn offer(State(broker): Shared) -> Response {
    match broker.offer() {
        Some(offer) => json(StatusCode::OK, &offer),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn enrol(State(broker): Shared, body: Bytes) -> Response {
    if broker.mode() != Mode::Enrolling {
        return StatusCode::NOT_FOUND.into_response();
    }
    match parse(&body) {
        Ok(enrolment) => reply(broker.enrol(enrolment).await),
        Err(refusal) => reply::<()>(Err(refusal)),
    }
}

async fn status(State(broker): Shared, Operator(enrolled): Operator) -> Response {
    reply(broker.status(&enrolled))
}

async fn fresh_csr(State(broker): Shared, Operator(enrolled): Operator) -> Response {
    reply(broker.fresh_csr(&enrolled))
}

async fn chain(State(broker): Shared, _: Operator, body: Bytes) -> Response {
    reply(parse(&body).and_then(|update| broker.update_chain(update)))
}

async fn revoke(State(broker): Shared, _: Operator) -> Response {
    reply(broker.revoke())
}

/// The enrolment, for a request on a connection that presented the operator's
/// certificate; any other request finds no route.
struct Operator(Enrolled);

impl FromRequestParts<Arc<Broker>> for Operator {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        broker: &Arc<Broker>,
    ) -> Result<Self, StatusCode> {
        broker
            .admits(parts.extensions.get::<PeerCertificates>())
            .map(Operator)
            .ok_or(StatusCode::NOT_FOUND)
    }
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ErrorBody> {
    serde_json::from_slice(body).map_err(|e| ErrorBody {
        kind: ErrorKind::BadRequest,
        message: e.to_string(),
    })
}

fn reply<T: Serialize>(answer: Result<T, ErrorBody>) -> Response {
    match answer {
        Ok(body) => json(StatusCode::OK, &body),
        Err(refusal) => json(
            StatusCode::from_u16(refusal.kind.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &refusal,
        ),
    }
}

fn json(status: StatusCode, body: &impl Serialize) -> Response {
    let body = serde_json::to_vec(body).expect("the API's types serialise");
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}
