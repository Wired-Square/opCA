use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Error;

pub const CONFIG_PATH: &str = "/etc/opca-acme/broker.toml";

/// The broker's settings, as `broker.toml` gives them.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The name or address opCA dials, named by the pairing URI and the API certificate.
    pub host: String,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The permitted domains the broker asks for; empty leaves them to opCA.
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Where the broker serves ACME.
    #[serde(default = "default_acme_listen")]
    pub acme_listen: SocketAddr,
    /// The port opCA dials when it isn't `listen`'s, as behind a container's mapped port.
    #[serde(skip)]
    pub advertised_port: Option<u16>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()).into())
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        Ok(toml::from_str(text)?)
    }

    /// The port the pairing URI names.
    pub fn port(&self) -> u16 {
        self.advertised_port.unwrap_or(self.listen.port())
    }
}

fn default_listen() -> SocketAddr {
    (Ipv6Addr::UNSPECIFIED, 9443).into()
}

fn default_state_dir() -> PathBuf {
    "/var/lib/opca-acme".into()
}

fn default_acme_listen() -> SocketAddr {
    (Ipv6Addr::UNSPECIFIED, 443).into()
}
