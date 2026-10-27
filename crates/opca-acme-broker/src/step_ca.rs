use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use opca_acme_api::{Challenge, IssuanceConfig};
use serde_json::{Value, json};
use tokio::sync::watch;
use wslib_crypto_x509::pem::{self, CERTIFICATE};

use crate::Error;

/// The oldest step-ca the broker runs: the one its config and SIGHUP reload were tried on.
pub const MINIMUM: Version = Version(0, 28, 1);

/// Short enough that a crash costs ACME clients little, long enough that a
/// config step-ca refuses doesn't spin.
const RESTART_DELAY: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The version in `step-ca version`'s first line, `Smallstep CA/0.28.1 (linux/amd64)`.
pub fn parse_version(output: &str) -> Option<Version> {
    let (_, rest) = output.split_once("Smallstep CA/")?;
    let digits = rest.trim_start_matches('v');
    let end = digits
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(digits.len());
    let mut parts = digits[..end].split('.').map(str::parse::<u32>);
    let version = Version(
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    );
    parts.next().is_none().then_some(version)
}

/// Runs `binary version` and refuses a step-ca older than [`MINIMUM`]; blocks.
pub fn check_version(binary: &Path) -> Result<Version, Error> {
    let output = Command::new(binary)
        .arg("version")
        .output()
        .map_err(|e| format!("running {} version: {e}", binary.display()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let version = parse_version(&text)
        .ok_or_else(|| format!("{} version printed no version: {text:?}", binary.display()))?;
    if version < MINIMUM {
        return Err(
            format!("step-ca {version} is older than {MINIMUM}, the oldest supported").into(),
        );
    }
    Ok(version)
}

/// Where step-ca's files go in the state directory.
pub(crate) struct Files {
    pub config: PathBuf,
    pub root: PathBuf,
    pub intermediate: PathBuf,
    pub key: PathBuf,
    pub db: PathBuf,
}

impl Files {
    pub fn in_state(state: &Path) -> Self {
        Self {
            config: state.join("step-ca.json"),
            root: state.join("step-ca-root.crt"),
            intermediate: state.join("step-ca-intermediate.crt"),
            key: state.join("subordinate.key"),
            db: state.join("step-ca-db"),
        }
    }

    /// Writes the certificates, then the config naming them, each atomically.
    pub fn write(
        &self,
        chain_pem: &str,
        host: &str,
        address: SocketAddr,
        issuance: &IssuanceConfig,
    ) -> Result<(), Error> {
        let mut chain = pem::certificates(chain_pem)?;
        let root = chain.pop().ok_or("the chain is empty")?;
        let intermediates: String = chain
            .iter()
            .map(|certificate| pem::encode(CERTIFICATE, certificate))
            .collect();
        wslib_file_atomic::replace_readable(
            &self.root,
            pem::encode(CERTIFICATE, &root).as_bytes(),
        )?;
        wslib_file_atomic::replace_readable(&self.intermediate, intermediates.as_bytes())?;
        let config = serde_json::to_vec_pretty(&self.ca_json(host, address, issuance))?;
        wslib_file_atomic::replace_private(&self.config, &config)?;
        Ok(())
    }

    /// The key is passed unencrypted, as the broker keeps it, so step-ca needs no password.
    pub fn ca_json(&self, host: &str, address: SocketAddr, issuance: &IssuanceConfig) -> Value {
        let mut allowed = Vec::new();
        for domain in &issuance.permitted_domains {
            allowed.push(domain.clone());
            allowed.push(format!("*.{domain}"));
        }
        let hours = |days: u32| format!("{}h", u64::from(days) * 24);
        let challenges: Vec<&str> = issuance
            .challenges
            .iter()
            .map(|challenge| match challenge {
                Challenge::Http01 => "http-01",
                Challenge::Dns01 => "dns-01",
                Challenge::TlsAlpn01 => "tls-alpn-01",
            })
            .collect();
        json!({
            "root": self.root,
            "crt": self.intermediate,
            "key": self.key,
            "address": address.to_string(),
            "dnsNames": [host],
            "logger": { "format": "text" },
            "db": { "type": "badgerv2", "dataSource": self.db },
            "authority": {
                "policy": { "x509": { "allow": { "dns": allowed } } },
                "provisioners": [{
                    "type": "ACME",
                    "name": "acme",
                    "challenges": challenges,
                    "claims": {
                        "defaultTLSCertDuration": hours(issuance.leaf_days),
                        "maxTLSCertDuration": hours(issuance.leaf_max_days),
                    },
                }],
            },
        })
    }
}

/// step-ca as the broker's child: started when wanted, reloaded by SIGHUP,
/// restarted after [`RESTART_DELAY`] if it dies, and stopped on request.
pub(crate) struct StepCa {
    binary: PathBuf,
    config: PathBuf,
    pub version: Version,
    restart_delay: Duration,
    supervised: Mutex<Supervised>,
    running: watch::Sender<Option<u32>>,
}

#[derive(Default)]
struct Supervised {
    wanted: bool,
    generation: u64,
}

impl StepCa {
    pub fn new(binary: PathBuf, config: PathBuf, version: Version) -> Arc<Self> {
        Self::with_restart_delay(binary, config, version, RESTART_DELAY)
    }

    fn with_restart_delay(
        binary: PathBuf,
        config: PathBuf,
        version: Version,
        restart_delay: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            binary,
            config,
            version,
            restart_delay,
            supervised: Mutex::default(),
            running: watch::Sender::new(None),
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.borrow().is_some()
    }

    /// Starts step-ca, or has a running one reload its config; needs a Tokio runtime.
    pub fn start_or_reload(self: &Arc<Self>) {
        let mut supervised = self.lock();
        if supervised.wanted {
            if let Some(pid) = *self.running.borrow() {
                signal(pid, libc::SIGHUP);
            }
            return;
        }
        supervised.wanted = true;
        supervised.generation += 1;
        let child = self.spawn();
        tokio::spawn(self.clone().supervise(supervised.generation, child));
    }

    pub fn stop(&self) {
        let mut supervised = self.lock();
        supervised.wanted = false;
        supervised.generation += 1;
        if let Some(pid) = *self.running.borrow() {
            signal(pid, libc::SIGTERM);
        }
    }

    /// Stops step-ca and waits up to `patience` for it to go, then kills it.
    pub async fn stop_and_wait(&self, patience: Duration) {
        self.stop();
        let mut running = self.running.subscribe();
        let gone = tokio::time::timeout(patience, running.wait_for(Option::is_none)).await;
        if gone.is_err()
            && let Some(pid) = *self.running.borrow()
        {
            signal(pid, libc::SIGKILL);
        }
    }

    fn lock(&self) -> MutexGuard<'_, Supervised> {
        self.supervised.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Called with the lock held, so that a stop cannot slip between the spawn and its pid.
    fn spawn(&self) -> Option<tokio::process::Child> {
        match tokio::process::Command::new(&self.binary)
            .arg(&self.config)
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => {
                self.running.send_replace(child.id());
                tracing::info!(pid = child.id(), "started step-ca");
                Some(child)
            }
            Err(error) => {
                tracing::error!(%error, binary = %self.binary.display(), "could not start step-ca");
                None
            }
        }
    }

    async fn supervise(self: Arc<Self>, generation: u64, mut child: Option<tokio::process::Child>) {
        loop {
            if let Some(mut running) = child.take() {
                let exit = running.wait().await;
                self.running.send_replace(None);
                if !self.is_current(generation) {
                    tracing::info!(?exit, "step-ca stopped");
                    return;
                }
                tracing::error!(?exit, delay = ?self.restart_delay, "step-ca exited; restarting it");
            }
            tokio::time::sleep(self.restart_delay).await;
            let supervised = self.lock();
            if !(supervised.wanted && supervised.generation == generation) {
                return;
            }
            child = self.spawn();
        }
    }

    fn is_current(&self, generation: u64) -> bool {
        let supervised = self.lock();
        supervised.wanted && supervised.generation == generation
    }
}

fn signal(pid: u32, signal: libc::c_int) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: kill takes plain integers; a stale pid is at worst refused.
        unsafe { libc::kill(pid, signal) };
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn versions_are_read_from_the_first_line_and_compared_numerically() {
        let read = |text| parse_version(text);
        assert_eq!(
            read("Smallstep CA/0.28.1 (linux/amd64)\nRelease Date: 2024-10-08"),
            Some(Version(0, 28, 1))
        );
        assert_eq!(
            read("Smallstep CA/v0.29.0 (darwin/arm64)"),
            Some(Version(0, 29, 0))
        );
        assert_eq!(read("Smallstep CA/0.28 (linux/amd64)"), None);
        assert_eq!(read("step 0.28.1"), None);
        assert!(Version(0, 28, 10) > Version(0, 28, 9));
        assert!(Version(0, 27, 99) < MINIMUM);
        assert!(Version(1, 0, 0) > MINIMUM);
    }

    fn issuance() -> IssuanceConfig {
        IssuanceConfig {
            permitted_domains: vec!["home.example".into(), "lab.example".into()],
            leaf_days: 30,
            leaf_max_days: 45,
            challenges: vec![Challenge::Http01, Challenge::TlsAlpn01],
        }
    }

    #[test]
    fn the_config_names_the_subordinate_and_mirrors_the_issuance_config() {
        let files = Files::in_state(Path::new("/var/lib/opca-acme"));
        let config = files.ca_json(
            "acme.home.example",
            "[::]:443".parse().unwrap(),
            &issuance(),
        );
        assert_eq!(
            config,
            json!({
                "root": "/var/lib/opca-acme/step-ca-root.crt",
                "crt": "/var/lib/opca-acme/step-ca-intermediate.crt",
                "key": "/var/lib/opca-acme/subordinate.key",
                "address": "[::]:443",
                "dnsNames": ["acme.home.example"],
                "logger": { "format": "text" },
                "db": { "type": "badgerv2", "dataSource": "/var/lib/opca-acme/step-ca-db" },
                "authority": {
                    "policy": { "x509": { "allow": { "dns": [
                        "home.example", "*.home.example", "lab.example", "*.lab.example"
                    ] } } },
                    "provisioners": [{
                        "type": "ACME",
                        "name": "acme",
                        "challenges": ["http-01", "tls-alpn-01"],
                        "claims": {
                            "defaultTLSCertDuration": "720h",
                            "maxTLSCertDuration": "1080h",
                        },
                    }],
                },
            })
        );
    }

    /// A stand-in step-ca that counts its starts and reloads beside its config.
    fn fake(dir: &Path) -> PathBuf {
        let path = dir.join("fake-step-ca");
        std::fs::write(
            &path,
            "#!/bin/sh\n\
             [ \"$1\" = version ] && { echo 'Smallstep CA/0.28.1 (fake)'; exit 0; }\n\
             log=\"$(dirname \"$1\")/fake-step-ca.log\"\n\
             trap 'echo hup >> \"$log\"' HUP\n\
             trap 'exit 0' TERM\n\
             echo start >> \"$log\"\n\
             while :; do sleep 1 & wait $!; done\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    async fn logged(dir: &Path, expected: &[&str]) {
        let path = dir.join("fake-step-ca.log");
        for _ in 0..100 {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            if text.lines().collect::<Vec<_>>() == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{:?}", std::fs::read_to_string(&path));
    }

    #[tokio::test]
    async fn the_child_starts_reloads_restarts_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let binary = fake(dir.path());
        assert_eq!(check_version(&binary).unwrap(), MINIMUM);
        let step_ca = StepCa::with_restart_delay(
            binary,
            dir.path().join("step-ca.json"),
            MINIMUM,
            Duration::from_millis(50),
        );
        assert!(!step_ca.is_running());

        step_ca.start_or_reload();
        assert!(step_ca.is_running());
        logged(dir.path(), &["start"]).await;
        step_ca.start_or_reload();
        logged(dir.path(), &["start", "hup"]).await;

        let pid = step_ca.running.borrow().unwrap();
        signal(pid, libc::SIGKILL);
        logged(dir.path(), &["start", "hup", "start"]).await;
        assert!(step_ca.is_running());
        assert_ne!(step_ca.running.borrow().unwrap(), pid);

        step_ca.stop_and_wait(Duration::from_secs(5)).await;
        assert!(!step_ca.is_running());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!step_ca.is_running());
    }

    #[test]
    fn an_old_or_missing_step_ca_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old-step-ca");
        std::fs::write(
            &old,
            "#!/bin/sh\necho 'Smallstep CA/0.27.4 (linux/amd64)'\n",
        )
        .unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_version(&old).is_err());
        assert!(check_version(&dir.path().join("absent")).is_err());
    }
}
