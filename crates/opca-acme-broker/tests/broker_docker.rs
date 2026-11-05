//! The broker's Linux build in Docker: the command line's privilege drop, and
//! the `.deb` installed, enrolled and serving ACME under systemd. Runs only
//! with `OPCA_ACME_DOCKER_TEST=1`, `OPCA_ACME_DOCKER_PLATFORM`, and
//! `OPCA_ACME_DOCKER_BIN` and `OPCA_ACME_DOCKER_DEB` naming that platform's
//! binaries and `.deb`; see `docker.sh`.

#![cfg(unix)]

mod support;

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use opca_acme_api::{Enrolment, EnrolmentOffer, IssuerState, Status, path};
use opca_acme_broker::SCHEME;
use support::{Api, TestCa, acme_connect};
use wslib_crypto_x509::pem;
use wslib_pairing::PairingUri;

const RUNTIME: &str = "rust:1.99-bookworm";
const SYSTEMD: &str = "debian:bookworm";
const DOMAINS: &[&str] = &["home.example"];
/// Generous for amd64 under emulation, which is many times slower than native.
const SLOW: u64 = 900;

/// Every container and the network this run made, removed when it drops.
struct Docker {
    prefix: String,
    containers: Vec<String>,
}

impl Docker {
    fn new() -> Self {
        static RUNS: AtomicUsize = AtomicUsize::new(0);
        let run = RUNS.fetch_add(1, Ordering::Relaxed);
        let prefix = format!("opca-e-{}-{run}", std::process::id());
        let made = docker(&["network", "create", &prefix], 30);
        assert!(made.status.success(), "{}", text(&made.stderr));
        Self {
            prefix,
            containers: Vec::new(),
        }
    }

    fn name(&mut self, role: &str) -> String {
        let name = format!("{}-{role}", self.prefix);
        self.containers.push(name.clone());
        name
    }
}

impl Drop for Docker {
    fn drop(&mut self) {
        for container in &self.containers {
            docker(&["rm", "-f", container], 30);
        }
        docker(&["network", "rm", &self.prefix], 30);
    }
}

/// `docker args`, killed after `seconds`.
fn docker(args: &[&str], seconds: u64) -> Output {
    let mut child = Command::new("docker")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("docker {args:?} ran past {seconds} s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn wait_for<T>(what: &str, seconds: u64, mut ready: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Some(value) = ready() {
            return value;
        }
        assert!(Instant::now() < deadline, "waited {seconds} s for {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// What `docker.sh` built, for one platform.
struct Built {
    platform: String,
    bin: PathBuf,
    deb: PathBuf,
}

fn enabled() -> Option<Built> {
    if std::env::var("OPCA_ACME_DOCKER_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: set OPCA_ACME_DOCKER_TEST=1 to run the broker in Docker");
        return None;
    }
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name}"));
    Some(Built {
        platform: var("OPCA_ACME_DOCKER_PLATFORM"),
        bin: var("OPCA_ACME_DOCKER_BIN").into(),
        deb: var("OPCA_ACME_DOCKER_DEB").into(),
    })
}

const PRIVILEGES: &str = r#"set -u
useradd --system --no-create-home opca-acme
useradd --no-create-home other
install -d -m 700 -o opca-acme -g opca-acme /state
printf 'host = "acme.home.example"\nlisten = "127.0.0.1:9443"\nstate_dir = "/state"\nacme_listen = "127.0.0.1:8443"\n' > /etc/broker.toml
runuser -u opca-acme -- /opt/opca/opca-acme-broker --config /etc/broker.toml > /tmp/broker.log 2>&1 &
for _ in $(seq 100); do [ -f /state/broker.pid ] && break; sleep 0.1; done
cli="/opt/opca/opca-acme --config /etc/broker.toml"
no_root_files() { [ -z "$(find /state -user root)" ]; }
$cli pairing | grep -q '^opca-enrol://acme.home.example:9443#pin=' && echo PAIRING-AS-ROOT
no_root_files && echo NO-ROOT-FILES
runuser -u opca-acme -- $cli status | grep -q 'broker: running' && echo STATUS-AS-OWNER
runuser -u other -- $cli status 2> /tmp/err || grep -q 'as root or as the owner' /tmp/err && echo OTHER-REFUSED
runuser -u opca-acme -- $cli enrol --reopen --yes 2> /tmp/err || grep -q 'only root' /tmp/err && echo OWNER-REOPEN-REFUSED
before=$(sha256sum < /state/subordinate.key)
$cli enrol --reopen --yes | grep -q '^opca-enrol://' && echo REOPEN-AS-ROOT
[ "$before" != "$(sha256sum < /state/subordinate.key)" ] && echo NEW-KEY
for _ in $(seq 50); do grep -q 'reloaded the state from disk' /tmp/broker.log && break; sleep 0.1; done
grep -q 'reloaded the state from disk' /tmp/broker.log && echo DAEMON-RELOADED
kill -0 "$(cat /state/broker.pid)" && echo DAEMON-ALIVE
no_root_files && echo STILL-NO-ROOT-FILES
"#;

#[test]
fn the_cli_drops_to_the_state_owner_and_reopen_reaches_the_daemon() {
    let Some(built) = enabled() else {
        return;
    };
    let mut run = Docker::new();
    let name = run.name("cli");
    let mount = format!("{}:/opt/opca:ro", built.bin.display());
    let ran = docker(
        &[
            "run",
            "--rm",
            "--platform",
            &built.platform,
            "--name",
            &name,
            "-v",
            &mount,
            RUNTIME,
            "sh",
            "-c",
            PRIVILEGES,
        ],
        SLOW,
    );
    let said = text(&ran.stdout);
    for marker in [
        "PAIRING-AS-ROOT",
        "NO-ROOT-FILES",
        "STATUS-AS-OWNER",
        "OTHER-REFUSED",
        "OWNER-REOPEN-REFUSED",
        "REOPEN-AS-ROOT",
        "NEW-KEY",
        "DAEMON-RELOADED",
        "DAEMON-ALIVE",
        "STILL-NO-ROOT-FILES",
    ] {
        assert!(
            said.lines().any(|line| line == marker),
            "{marker} missing:\n{said}\n{}",
            text(&ran.stderr)
        );
    }
}

/// `script` run by `sh` in `container`; its output, failing the test if it fails.
fn shell(container: &str, script: &str, seconds: u64) -> String {
    let ran = docker(&["exec", container, "sh", "-ec", script], seconds);
    let said = text(&ran.stdout);
    assert!(
        ran.status.success(),
        "{script}\n{said}\n{}",
        text(&ran.stderr)
    );
    said
}

fn published(container: &str, port: &str) -> std::net::SocketAddr {
    let port = text(&docker(&["port", container, port], 30).stdout);
    port.lines().next().unwrap().trim().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_deb_installs_enrols_and_serves_acme_under_systemd() {
    let Some(built) = enabled() else {
        return;
    };
    let mut run = Docker::new();
    let host = run.name("systemd");
    let mount = format!("{}:/deb:ro", built.deb.display());
    let boot = "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                systemd systemd-sysv dbus curl ca-certificates procps > /dev/null && exec /sbin/init";
    let started = docker(
        &[
            "run",
            "-d",
            "--rm",
            "--platform",
            &built.platform,
            "--name",
            &host,
            "--privileged",
            "--cgroupns=private",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "-p",
            "127.0.0.1::9443",
            "-p",
            "127.0.0.1::443",
            "-v",
            &mount,
            SYSTEMD,
            "sh",
            "-c",
            boot,
        ],
        SLOW,
    );
    assert!(started.status.success(), "{}", text(&started.stderr));
    wait_for("systemd to boot", SLOW, || {
        let state = docker(&["exec", &host, "systemctl", "is-system-running"], 60);
        let state = text(&state.stdout);
        ["running", "degraded"]
            .contains(&state.trim())
            .then_some(())
    });

    let installed = shell(
        &host,
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /deb/*.deb
         echo arch=$(dpkg --print-architecture)
         echo enabled=$(systemctl is-enabled opca-acme-broker) active=$(systemctl is-active opca-acme-broker || true)
         id opca-acme",
        SLOW,
    );
    let arch = built.platform.trim_start_matches("linux/");
    for expected in [
        format!("arch={arch}"),
        "enabled=disabled active=inactive".into(),
        "set host in /etc/opca-acme/broker.toml".into(),
    ] {
        assert!(installed.contains(&expected), "{expected}:\n{installed}");
    }

    shell(
        &host,
        "sed -i 's/^#host = .*/host = \"acme.home.example\"/' /etc/opca-acme/broker.toml
         systemctl enable --now opca-acme-broker
         [ \"$(systemctl is-active opca-acme-broker)\" = active ]",
        120,
    );
    let uri = shell(&host, "opca-acme pairing", 60);
    let status = shell(&host, "opca-acme status", 60);
    assert!(
        status.contains("mode: enrolling") && status.contains("broker: running"),
        "{status}"
    );
    shell(
        &host,
        "systemctl reload opca-acme-broker
         for _ in $(seq 150); do
             journalctl -u opca-acme-broker | grep -q 'reloaded the state from disk' && exit 0
             sleep 0.2
         done
         exit 1",
        60,
    );

    let api = Api {
        uri: PairingUri::parse(SCHEME, uri.trim()).unwrap(),
        address: published(&host, "9443/tcp"),
    };
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (_, body) = api.call(None, "GET", path::ENROLMENT, "").await.unwrap();
    let offer: EnrolmentOffer = serde_json::from_str(&body).unwrap();
    assert!(
        offer.versions.broker.starts_with(env!("CARGO_PKG_VERSION")),
        "{body}"
    );
    let (chain, _, _) = ca.sign(&offer.csr_pem, DOMAINS);
    let enrolment = Enrolment {
        operator_pin: operator.key_pin(),
        ..api.enrolment(&chain, DOMAINS)
    };
    let (code, body) = api.post(&enrolment).await;
    assert_eq!(code, 200, "{body}");
    let status: Status = serde_json::from_str(&body).unwrap();
    assert_eq!(status.state, IssuerState::Issuing, "{body}");

    let chain = pem::certificates(&chain).unwrap();
    let (mut acme, presented) = acme_connect(published(&host, "443/tcp"), chain.last().unwrap())
        .await
        .unwrap();
    assert_eq!(presented[1], chain[0]);
    let (code, _) = acme.call("GET", "/acme/directory", "").await.unwrap();
    assert_eq!(code, 503);
    let serving = shell(
        &host,
        "echo directory=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/acme/directory)
         echo acme-key=$(stat -c %a:%U /var/lib/opca-acme/acme.key)
         echo root-owned=$(find /var/lib/opca-acme -user root | wc -l)
         opca-acme status",
        60,
    );
    for expected in [
        "directory=503",
        "acme-key=600:opca-acme",
        "root-owned=0",
        "mode: enrolled",
    ] {
        assert!(serving.contains(expected), "{expected}:\n{serving}");
    }

    let stopped = shell(
        &host,
        "start=$(date +%s)
         systemctl stop opca-acme-broker
         echo seconds=$(( $(date +%s) - start ))
         echo result=$(systemctl show -p Result --value opca-acme-broker)",
        120,
    );
    assert!(stopped.contains("result=success"), "{stopped}");
    let seconds: u64 = stopped
        .lines()
        .find_map(|line| line.strip_prefix("seconds="))
        .unwrap()
        .parse()
        .unwrap();
    assert!(seconds < 30, "{stopped}");
}
