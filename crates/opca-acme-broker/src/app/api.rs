//! The read API the app's page calls on `app.sock`, for every console role (opCA phase 26-2).

use std::fmt::Display;
use std::str::FromStr;

use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::Uri;
use axum::response::Response;
use axum::routing::get;
use opca_acme_api::{ErrorBody, IssuedCertificate};
use serde::{Deserialize, Serialize};
use wslib_appliance_server::{ApplianceState, Mount, Viewer};

use super::{App, AppState, Hooked};
use crate::api::{param, reply};
use crate::enrolled::issued;
use crate::enrolment::{bad_request, internal};
use crate::{Broker, Mode};

/// The `GET /apps/opca-acme/api/status` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStatus {
    pub state: AppState,
    pub host: Option<String>,
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
}

impl FromRef<Read> for ApplianceState {
    fn from_ref(read: &Read) -> Self {
        read.appliance.clone()
    }
}

/// Under the chassis's `/api`, for every console role (opCA phase 26-2).
pub(super) fn routes(app: &App, hooked: &Hooked) -> Mount {
    let (hooked, app) = (hooked.clone(), app.clone());
    let routes = Router::new()
        .route("/status", get(status))
        .route("/issued", get(issued_newest));
    Mount::new(routes, move |appliance| Read {
        appliance,
        hooked: hooked.clone(),
        domains: app.domains.clone(),
    })
}

async fn status(State(read): State<Read>, _: Viewer) -> Response {
    reply(match read.hooked {
        Hooked::Running(broker) => broker.app_status(),
        Hooked::NeedsHost(_) => Ok(AppStatus {
            state: AppState::NeedsHost,
            host: None,
            domains: read.domains,
            subordinate: None,
        }),
    })
}

async fn issued_newest(State(read): State<Read>, _: Viewer, uri: Uri) -> Response {
    reply(read.issued_newest(&uri).await)
}

impl Read {
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
            domains,
            subordinate,
        })
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
