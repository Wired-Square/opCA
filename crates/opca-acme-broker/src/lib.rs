//! The ACME broker: it holds an opCA subordinate CA's key and pairs with opCA.

mod broker;
mod config;

pub use broker::{ATTEMPTS, Broker, SCHEME, Subordinate};
pub use config::{CONFIG_PATH, Config};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
