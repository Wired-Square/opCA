use std::io;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use opca_acme_api::{ErrorBody, ErrorKind, path};
use serde::Serialize;
use wslib_http_server::{Listener, Tls};

use crate::{Broker, Mode};

/// Serves the enrolment API on `listener` until `stop` completes.
pub async fn serve(
    broker: Arc<Broker>,
    listener: Listener,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    let tls = Tls::new(broker.serving().config());
    wslib_http_server::serve_https(listener, router(broker), tls, stop).await
}

fn router(broker: Arc<Broker>) -> Router {
    Router::new()
        .route(path::ENROLMENT, get(offer).post(enrol))
        .with_state(broker)
}

async fn offer(State(broker): State<Arc<Broker>>) -> Response {
    match broker.offer() {
        Some(offer) => json(StatusCode::OK, &offer),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn enrol(State(broker): State<Arc<Broker>>, body: Bytes) -> Response {
    if broker.mode() != Mode::Enrolling {
        return StatusCode::NOT_FOUND.into_response();
    }
    let answer = match serde_json::from_slice(&body) {
        Ok(enrolment) => broker.enrol(enrolment).await,
        Err(e) => Err(ErrorBody {
            kind: ErrorKind::BadRequest,
            message: e.to_string(),
        }),
    };
    match answer {
        Ok(status) => json(StatusCode::OK, &status),
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
