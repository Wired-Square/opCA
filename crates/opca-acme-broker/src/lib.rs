//! The ACME broker: it holds an opCA subordinate CA's key and pairs with opCA.

pub mod acme;
mod api;
pub mod app;
pub mod backup;
mod broker;
pub mod cli;
mod config;
mod enrolled;
mod enrolment;
mod pki;

pub use api::serve;
pub use broker::{ATTEMPTS, Broker, SCHEME, Subordinate};
pub use config::{CONFIG_PATH, Config};
pub use enrolment::{Enrolled, Mode};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
