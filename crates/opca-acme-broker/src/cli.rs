use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use wslib_crypto_x509::{inspect, pem};
use wslib_pairing::{OneTimeCode, PairingUri, SpentBy, SpkiSha256, Status};
use wslib_tls::KeyFingerprint;

use crate::broker::{Subordinate, code_path, lock_state};
use crate::enrolment::{self, Mode, decimal, rfc_3339};
use crate::step_ca::{self, Files, signal};
use crate::{ATTEMPTS, Config, Error, SCHEME};

/// What a reopen moves aside; the subordinate key is deleted instead.
const ARCHIVED: &[&str] = &[
    "enrolment.json",
    "subordinate.csr",
    "step-ca.json",
    "step-ca-root.crt",
    "step-ca-intermediate.crt",
    "step-ca-db",
];

/// Runs as the owner of `state`: drops to it from root with setgid and
/// setuid, carries on as it, and refuses anyone else; `root_only` refuses the
/// owner too.
pub fn become_owner(state: &Path, root_only: bool) -> Result<(), Error> {
    let owner = fs::metadata(state).map_err(|e| format!("{}: {e}", state.display()))?;
    // SAFETY: these take and return plain integers.
    let euid = unsafe { libc::geteuid() };
    if root_only && euid != 0 {
        return Err("only root can reopen enrolment".into());
    }
    if euid == owner.uid() {
        return Ok(());
    }
    if euid != 0 {
        return Err(format!(
            "run this as root or as the owner of {} (uid {})",
            state.display(),
            owner.uid()
        )
        .into());
    }
    let gid = owner.gid();
    // SAFETY: as above; the group list is one valid gid.
    let dropped = unsafe {
        libc::setgroups(1, &gid) == 0 && libc::setgid(gid) == 0 && libc::setuid(owner.uid()) == 0
    };
    if !dropped || unsafe { libc::geteuid() } != owner.uid() {
        return Err(format!(
            "could not become uid {}: {}",
            owner.uid(),
            io::Error::last_os_error()
        )
        .into());
    }
    Ok(())
}

/// Issues a new pairing code, while enrolling only, and its URI.
pub fn pairing(config: &Config) -> Result<PairingUri, Error> {
    let state = &config.state_dir;
    let _lock = lock_state(state)?;
    if let Mode::Enrolled(enrolled) = enrolment::load(state)? {
        let now = if enrolled.revoked {
            "revoked"
        } else {
            "enrolled"
        };
        return Err(format!(
            "the broker is {now}; `opca-acme enrol --reopen` pairs it again with a new subordinate key"
        )
        .into());
    }
    issue(config)
}

/// Archives the enrolment and step-ca's state, deletes the subordinate key,
/// makes a new one and its CSR, and issues a new pairing code.
pub fn reopen(config: &Config) -> Result<PairingUri, Error> {
    let state = &config.state_dir;
    let _lock = lock_state(state)?;
    let archive = state.join("archive").join(rfc_3339(SystemTime::now()));
    fs::create_dir_all(&archive)?;
    for name in ARCHIVED {
        match fs::rename(state.join(name), archive.join(name)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            moved => moved?,
        }
    }
    match fs::remove_file(state.join("subordinate.key")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        removed => removed?,
    }
    let provider = Arc::new(rustls_openssl::default_provider());
    Subordinate::load_or_generate(provider, state, &config.host)?;
    issue(config)
}

/// Asks a running daemon to reload; `false` when none is running.
pub fn tell_daemon(state: &Path) -> bool {
    running(&daemon_pid_file(state)).is_some_and(|pid| signal(pid, libc::SIGHUP))
}

pub fn daemon_pid_file(state: &Path) -> PathBuf {
    state.join("broker.pid")
}

/// The broker's state as its files have it.
pub fn status(config: &Config) -> Result<String, Error> {
    let state = &config.state_dir;
    let mut lines = Vec::new();
    let mode = enrolment::load(state)?;
    lines.push(format!(
        "mode: {}",
        match &mode {
            Mode::Enrolling => "enrolling",
            Mode::Enrolled(enrolled) if enrolled.revoked => "revoked",
            Mode::Enrolled(_) => "enrolled",
        }
    ));
    let code = match OneTimeCode::open(code_path(state))? {
        None => "none".into(),
        Some(code) => match code.status()? {
            Status::Pending { remaining, limit } => {
                format!("pending, {remaining} of {limit} attempts left")
            }
            Status::Spent(SpentBy::Acceptance) => "spent by enrolment".into(),
            Status::Spent(SpentBy::Lockout) => "locked out by wrong attempts".into(),
            other => format!("{other:?}"),
        },
    };
    lines.push(format!("pairing code: {code}"));
    if let Mode::Enrolled(enrolled) = &mode {
        let chain = pem::certificates(&enrolled.chain_pem)?;
        let subordinate = inspect(chain.first().ok_or("the stored chain is empty")?)?;
        lines.push(format!(
            "subordinate: serial {}, expires {}",
            decimal(&subordinate.serial),
            rfc_3339(subordinate.not_after)
        ));
        lines.push(format!(
            "permitted domains: {}",
            enrolled.config.permitted_domains.join(", ")
        ));
    }
    for (name, pid_file) in [
        ("broker", daemon_pid_file(state)),
        ("step-ca", step_ca::pid_file(&Files::in_state(state).config)),
    ] {
        lines.push(match running(&pid_file) {
            Some(pid) => format!("{name}: running (pid {pid})"),
            None => format!("{name}: not running"),
        });
    }
    Ok(lines.join("\n"))
}

fn issue(config: &Config) -> Result<PairingUri, Error> {
    let state = &config.state_dir;
    let api_crt = state.join("api.crt");
    let certificates = fs::read_to_string(&api_crt)
        .map_err(|e| format!("{}: {e}; start the broker once first", api_crt.display()))?;
    let leaf = pem::certificates(&certificates)?;
    let fingerprint = KeyFingerprint::of(leaf.first().ok_or("api.crt holds no certificate")?)?;
    let (_, code) = OneTimeCode::issue(code_path(state), ATTEMPTS)?;
    Ok(PairingUri::new(
        SCHEME,
        &config.host,
        config.listen.port(),
        SpkiSha256::from(*fingerprint.0.as_bytes()),
        code,
    )?)
}

fn running(pid_file: &Path) -> Option<u32> {
    let pid = fs::read_to_string(pid_file).ok()?.trim().parse().ok()?;
    signal(pid, 0).then_some(pid)
}
