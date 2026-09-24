//! SFTP storage backend.
//!
//! Uploads content to remote servers via SFTP using the `ssh2` crate.
//! URI format: `sftp://[user@]host[:port]/path/to/destination`
//!
//! Authentication is attempted in order:
//! 1. SSH agent (ssh-agent / Pageant on Windows)
//! 2. Default key files (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`)

use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use log::{debug, info};
use ssh2::Session;

use crate::error::OpcaError;

use super::StorageBackend;

/// SFTP-based storage backend.
pub struct StorageSftp;

/// Parsed components of an SFTP URI.
struct SftpUri {
    user: String,
    host: String,
    port: u16,
    path: String,
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

impl StorageSftp {
    /// Parse an SFTP (or SCP) URI into its components.
    ///
    /// Format: `sftp://[user@]host[:port]/path/to/destination`
    ///         `scp://[user@]host[:port]/path/to/destination`
    fn parse_uri(uri: &str) -> Result<SftpUri, OpcaError> {
        let rest = uri
            .strip_prefix("sftp://")
            .or_else(|| uri.strip_prefix("scp://"))
            .ok_or_else(|| OpcaError::Storage(format!("Invalid SFTP URI: {uri}")))?;

        if rest.is_empty() {
            return Err(OpcaError::Storage("Empty SFTP destination".to_string()));
        }

        // Split user@host-and-port from path at the first '/'
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => {
                return Err(OpcaError::Storage(format!(
                    "SFTP URI missing path component: {uri}"
                )));
            }
        };

        if path.is_empty() || path == "/" {
            return Err(OpcaError::Storage(format!(
                "SFTP URI missing path component: {uri}"
            )));
        }

        // Split user@host:port
        let (user, host_port) = match authority.find('@') {
            Some(idx) => (&authority[..idx], &authority[idx + 1..]),
            None => {
                let default_user = whoami::username();
                return Self::parse_host_port(authority, &default_user, uri, path);
            }
        };

        if user.is_empty() {
            return Err(OpcaError::Storage(format!(
                "Empty username in SFTP URI: {uri}"
            )));
        }

        Self::parse_host_port(host_port, user, uri, path)
    }

    fn parse_host_port(
        host_port: &str,
        user: &str,
        uri: &str,
        path: &str,
    ) -> Result<SftpUri, OpcaError> {
        let (host, port) = match host_port.rfind(':') {
            Some(idx) => {
                let port_str = &host_port[idx + 1..];
                let port: u16 = port_str.parse().map_err(|_| {
                    OpcaError::Storage(format!("Invalid port in SFTP URI: {uri}"))
                })?;
                (&host_port[..idx], port)
            }
            None => (host_port, 22),
        };

        if host.is_empty() {
            return Err(OpcaError::Storage(format!(
                "Empty host in SFTP URI: {uri}"
            )));
        }

        Ok(SftpUri {
            user: user.to_string(),
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// Establish an SSH session and authenticate.
    fn connect(parsed: &SftpUri) -> Result<Session, OpcaError> {
        let addr = format!("{}:{}", parsed.host, parsed.port);
        debug!("[sftp] connecting to {addr}");

        let sock_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            OpcaError::Storage(format!("Invalid address {addr}: {e}"))
        })?;
        let tcp = TcpStream::connect_timeout(&sock_addr, CONNECT_TIMEOUT).map_err(|e| {
            OpcaError::Storage(format!("Failed to connect to {addr}: {e}"))
        })?;

        let mut session = Session::new().map_err(|e| {
            OpcaError::Storage(format!("Failed to create SSH session: {e}"))
        })?;

        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| {
            OpcaError::Storage(format!("SSH handshake failed with {addr}: {e}"))
        })?;

        // Try SSH agent first
        if session.userauth_agent(&parsed.user).is_ok() {
            debug!("[sftp] authenticated via SSH agent as {}", parsed.user);
            return Ok(session);
        }

        // Fall back to default key files
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let key_candidates = [
            home.join(".ssh/id_ed25519"),
            home.join(".ssh/id_rsa"),
        ];

        for key_path in &key_candidates {
            if key_path.exists() {
                debug!("[sftp] trying key {}", key_path.display());
                if session
                    .userauth_pubkey_file(&parsed.user, None, key_path, None)
                    .is_ok()
                {
                    debug!("[sftp] authenticated with {}", key_path.display());
                    return Ok(session);
                }
            }
        }

        Err(OpcaError::Storage(format!(
            "SSH authentication failed for {}@{}: no agent key or default key file worked",
            parsed.user, parsed.host
        )))
    }
}

impl StorageBackend for StorageSftp {
    fn upload(&self, content: &[u8], uri: &str) -> Result<(), OpcaError> {
        info!("[sftp] uploading {} bytes to {}", content.len(), uri);
        let parsed = Self::parse_uri(uri)?;
        let session = Self::connect(&parsed)?;

        let sftp = session.sftp().map_err(|e| {
            OpcaError::Storage(format!("Failed to open SFTP session: {e}"))
        })?;

        // Ensure the parent directory exists
        let remote_path = std::path::Path::new(&parsed.path);
        if let Some(parent) = remote_path.parent() {
            if parent != std::path::Path::new("/") {
                // Attempt to create parent directories; ignore errors (they may
                // already exist).
                let mut cumulative = PathBuf::from("/");
                for component in parent.components().skip(1) {
                    cumulative.push(component);
                    let _ = sftp.mkdir(&cumulative, 0o755);
                }
            }
        }

        let mut remote_file = sftp
            .create(remote_path)
            .map_err(|e| {
                OpcaError::Storage(format!(
                    "Failed to create remote file {}: {e}",
                    parsed.path
                ))
            })?;

        remote_file.write_all(content).map_err(|e| {
            OpcaError::Storage(format!(
                "Failed to write to remote file {}: {e}",
                parsed.path
            ))
        })?;

        debug!("[sftp] uploaded {} bytes to {}", content.len(), parsed.path);
        Ok(())
    }

    fn test_connection(&self, uri: &str) -> Result<(), OpcaError> {
        info!("[sftp] testing connection to {}", uri);
        let parsed = Self::parse_uri(uri)?;
        let session = Self::connect(&parsed)?;

        let sftp = session.sftp().map_err(|e| {
            OpcaError::Storage(format!("Failed to open SFTP session: {e}"))
        })?;

        // Verify the remote path (or its parent) is reachable
        let remote_path = std::path::Path::new(&parsed.path);
        let check_path = remote_path.parent().unwrap_or(remote_path);
        sftp.stat(check_path).map_err(|e| {
            OpcaError::Storage(format!(
                "Remote path {} not accessible: {e}",
                check_path.display()
            ))
        })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uri_full() {
        let parsed = StorageSftp::parse_uri("sftp://deploy@backup.example.com:2222/var/www/pki/")
            .unwrap();
        assert_eq!(parsed.user, "deploy");
        assert_eq!(parsed.host, "backup.example.com");
        assert_eq!(parsed.port, 2222);
        assert_eq!(parsed.path, "/var/www/pki/");
    }

    #[test]
    fn test_parse_uri_default_port() {
        let parsed =
            StorageSftp::parse_uri("sftp://user@host.example.com/home/user/files").unwrap();
        assert_eq!(parsed.user, "user");
        assert_eq!(parsed.host, "host.example.com");
        assert_eq!(parsed.port, 22);
        assert_eq!(parsed.path, "/home/user/files");
    }

    #[test]
    fn test_parse_uri_no_user() {
        let parsed = StorageSftp::parse_uri("sftp://host.example.com/srv/pki/").unwrap();
        assert_eq!(parsed.host, "host.example.com");
        assert_eq!(parsed.port, 22);
        assert_eq!(parsed.path, "/srv/pki/");
        // user defaults to current system user
        assert!(!parsed.user.is_empty());
    }

    #[test]
    fn test_parse_uri_invalid_scheme() {
        let result = StorageSftp::parse_uri("rsync://host/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uri_empty() {
        let result = StorageSftp::parse_uri("sftp://");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uri_missing_path() {
        let result = StorageSftp::parse_uri("sftp://host.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uri_root_only_path() {
        let result = StorageSftp::parse_uri("sftp://host.example.com/");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uri_empty_user() {
        let result = StorageSftp::parse_uri("sftp://@host.example.com/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uri_invalid_port() {
        let result = StorageSftp::parse_uri("sftp://user@host:notaport/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uri_port_with_no_user() {
        let parsed = StorageSftp::parse_uri("sftp://host.example.com:2222/data/backup").unwrap();
        assert_eq!(parsed.host, "host.example.com");
        assert_eq!(parsed.port, 2222);
        assert_eq!(parsed.path, "/data/backup");
    }

    #[test]
    fn test_parse_uri_scp_scheme() {
        let parsed =
            StorageSftp::parse_uri("scp://deploy@backup.example.com/var/www/pki/").unwrap();
        assert_eq!(parsed.user, "deploy");
        assert_eq!(parsed.host, "backup.example.com");
        assert_eq!(parsed.port, 22);
        assert_eq!(parsed.path, "/var/www/pki/");
    }
}
