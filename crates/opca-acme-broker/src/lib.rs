//! The ACME broker: it holds an opCA subordinate CA's key and pairs with opCA.

mod api;
mod broker;
mod config;
mod enrolled;
mod enrolment;
mod step_ca;

pub use api::serve;
pub use broker::{ATTEMPTS, Broker, SCHEME, Subordinate};
pub use config::{CONFIG_PATH, Config};
pub use enrolment::{Enrolled, Mode};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
