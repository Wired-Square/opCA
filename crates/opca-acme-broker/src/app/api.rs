//! The API the app's page calls on `app.sock`: reads for every console role (opCA phase 26-2),
//! and a new pairing code for an admin.

use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use opca_acme_api::{ErrorBody, IssuedCertificate};
use serde::{Deserialize, Serialize};
use wslib_appliance_server::{Admin, ApplianceState, Mount, Viewer};

use super::{App, AppState, Hooked, NEEDS_HOST};
use crate::api::{json, param, reply};
use crate::cli::pairing_locked;
use crate::enrolled::issued;
use crate::enrolment::{bad_request, internal, rfc_3339};
use crate::pki::{CA_PATH, CRL_PATH, origin};
use crate::{Broker, Mode};

/// The `GET /apps/opca-acme/api/status` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStatus {
    pub state: AppState,
    pub host: Option<String>,
    /// `https://<host>:<api port>`, the host port opCA dials; `None` until a host is set.
    pub api_url: Option<String>,
    /// `https://<host>:<acme port>/acme/directory`, for ACME clients; `None` until a host is set.
    pub acme_directory: Option<String>,
    /// `http://<host>:<pki port>/ca.crt` and `/crl`, as new leaves name them; `None` until a host is set.
    pub ca_url: Option<String>,
    pub crl_url: Option<String>,
    /// The CRL being published, if one is.
    pub crl: Option<PublishedCrl>,
    /// The permitted domains once enrolled; before, the configured ones, empty when opCA chooses them.
    pub domains: Vec<String>,
    /// Once enrolled.
    pub subordinate: Option<Issuer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer {
    /// Decimal.
    pub serial: String,
    /// RFC 3339.
    pub not_after: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedCrl {
    pub number: Option<u64>,
    /// RFC 3339.
    pub this_update: String,
    /// RFC 3339.
    pub next_update: Option<String>,
}

/// The `POST /apps/opca-acme/api/pairing` response: a new code's URI, the old code spent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewPairing {
    pub uri: String,
}

/// The `GET /apps/opca-acme/api/issued?before=<cursor>&revoked=<bool>` response, newest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedNewest {
    pub certificates: Vec<IssuedCertificate>,
    /// The `before` of the next, older page; `None` on the last.
    pub before: Option<u64>,
}

#[derive(Clone)]
struct Read {
    appliance: ApplianceState,
    hooked: Hooked,
    domains: Vec<String>,
    api_port: u16,
    acme_port: u16,
    pki_port: u16,
}

impl FromRef<Read> for ApplianceState {
    fn from_ref(read: &Read) -> Self {
        read.appliance.clone()
    }
}

/// Under the chassis's `/api`.
pub(super) fn routes(app: &App, hooked: &Hooked) -> Mount {
    let (hooked, app) = (hooked.clone(), app.clone());
    let routes = Router::new()
        .route("/status", get(status))
        .route("/issued", get(issued_newest))
        .route("/pairing", post(new_pairing));
    Mount::new(routes, move |appliance| Read {
        appliance,
        hooked: hooked.clone(),
        domains: app.domains.clone(),
        api_port: app.api_port,
        acme_port: app.acme_port,
        pki_port: app.pki_port,
    })
}

async fn status(State(read): State<Read>, _: Viewer) -> Response {
    reply(read.status())
}

async fn issued_newest(State(read): State<Read>, _: Viewer, uri: Uri) -> Response {
    reply(read.issued_newest(&uri).await)
}

async fn new_pairing(State(read): State<Read>, _: Admin) -> Response {
    let Hooked::Running(broker) = &read.hooked else {
        return conflict(NEEDS_HOST);
    };
    match broker.new_pairing().await {
        Ok(Ok(uri)) => reply(Ok(NewPairing { uri })),
        Ok(Err(why)) => conflict(&why),
        Err(failed) => reply::<()>(Err(failed)),
    }
}

fn conflict(message: &str) -> Response {
    json(
        StatusCode::CONFLICT,
        &serde_json::json!({ "message": message }),
    )
}

impl Read {
    fn status(&self) -> Result<AppStatus, ErrorBody> {
        let mut status = match &self.hooked {
            Hooked::Running(broker) => broker.app_status()?,
            Hooked::NeedsHost(_) => AppStatus {
                state: AppState::NeedsHost,
                host: None,
                api_url: None,
                acme_directory: None,
                ca_url: None,
                crl_url: None,
                crl: None,
                domains: self.domains.clone(),
                subordinate: None,
            },
        };
        let at = |scheme, port, path| {
            (status.host.as_deref()).map(|host| format!("{}{path}", origin(scheme, host, port)))
        };
        status.api_url = at("https", self.api_port, "");
        status.acme_directory = at("https", self.acme_port, "/acme/directory");
        status.ca_url = at("http", self.pki_port, CA_PATH);
        status.crl_url = at("http", self.pki_port, CRL_PATH);
        Ok(status)
    }

    async fn issued_newest(&self, uri: &Uri) -> Result<IssuedNewest, ErrorBody> {
        let (before, revoked) = (parsed(uri, "before")?, parsed(uri, "revoked")?);
        match &self.hooked {
            Hooked::Running(broker) => broker.issued_newest(before, revoked).await,
            Hooked::NeedsHost(_) => Ok(IssuedNewest {
                certificates: Vec::new(),
                before: None,
            }),
        }
    }
}

fn parsed<T: FromStr<Err: Display>>(uri: &Uri, name: &str) -> Result<Option<T>, ErrorBody> {
    param(uri.query(), name)
        .map(|value| {
            value
                .parse()
                .map_err(|e| bad_request(format!("{name}={value}: {e}")))
        })
        .transpose()
}

impl Broker {
    fn app_status(&self) -> Result<AppStatus, ErrorBody> {
        let mode = self.mode();
        let (domains, subordinate) = match &mode {
            Mode::Enrolling => (self.domains.clone(), None),
            Mode::Enrolled(enrolled) => {
                let status = self.status(enrolled)?;
                let issuer = Issuer {
                    serial: status.subordinate_serial,
                    not_after: status.subordinate_not_after,
                };
                (status.config.permitted_domains, Some(issuer))
            }
        };
        Ok(AppStatus {
            state: AppState::from(&mode),
            host: Some(self.host.clone()),
            api_url: None,
            acme_directory: None,
            ca_url: None,
            crl_url: None,
            crl: self.published.crl().map(|crl| PublishedCrl {
                number: crl.number,
                this_update: rfc_3339(crl.this_update),
                next_update: crl.next_update.map(rfc_3339),
            }),
            domains,
            subordinate,
        })
    }

    /// As `opca-acme pairing`; the inner `Err` says why the broker is not enrolling.
    async fn new_pairing(self: &Arc<Self>) -> Result<Result<String, String>, ErrorBody> {
        let issued = self
            .locked(|broker| {
                pairing_locked(&broker.state, &broker.host, broker.port).map_err(internal)
            })
            .await?;
        if issued.is_ok() {
            tracing::info!("issued a new pairing code for an admin on the app's page");
        }
        Ok(issued.map(|uri| uri.expose()))
    }

    async fn issued_newest(
        &self,
        before: Option<i64>,
        revoked: Option<bool>,
    ) -> Result<IssuedNewest, ErrorBody> {
        let page = self
            .acme()
            .newest(before, revoked, self.issued_page)
            .await
            .map_err(internal)?;
        Ok(IssuedNewest {
            before: (page.certificates.last())
                .filter(|_| page.more)
                .map(|last| last.id as u64),
            certificates: page.certificates.into_iter().map(issued).collect(),
        })
    }
}
