//! step-ca as the broker's child, with lego as the ACME client, all in Docker.
//! Runs only with `OPCA_ACME_DOCKER_TEST=1` and `OPCA_ACME_DOCKER_BIN` naming a
//! directory holding a Linux `opca-acme-broker` and `step-ca`; see `docker.sh`.

#![cfg(unix)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use opca_acme_api::{
    ChainUpdate, Challenge, Enrolment, EnrolmentOffer, FreshCsr, IssuerState, Status, path,
};
use opca_acme_broker::SCHEME;
use support::{Api, Identity, TestCa};
use wslib_crypto_x509::pem;
use wslib_pairing::PairingUri;

const LEGO: &str = "goacme/lego:v4.19.2";
const RUNTIME: &str = "rust:1.99-bookworm";
const ACME_HOST: &str = "acme.home.example";
const DOMAINS: &[&str] = &["home.example"];

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

fn enabled() -> Option<PathBuf> {
    if std::env::var("OPCA_ACME_DOCKER_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: set OPCA_ACME_DOCKER_TEST=1 to run step-ca in Docker");
        return None;
    }
    Some(
        std::env::var_os("OPCA_ACME_DOCKER_BIN")
            .expect("OPCA_ACME_DOCKER_BIN")
            .into(),
    )
}

fn start_broker(run: &mut Docker, bin: &Path) -> (String, Api) {
    let name = run.name("broker");
    let config = format!(
        "host = \"{ACME_HOST}\"\nlisten = \"0.0.0.0:9443\"\nstate_dir = \"/state\"\n\
         step_ca = \"/opt/opca/step-ca\"\nacme_listen = \"0.0.0.0:443\"\n"
    );
    let script = format!(
        "mkdir -m 700 /state && printf '%s' '{config}' > /etc/broker.toml && \
         exec /opt/opca/opca-acme-broker --config /etc/broker.toml"
    );
    let mount = format!("{}:/opt/opca:ro", bin.display());
    let started = docker(
        &[
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            "--network",
            &run.prefix,
            "--network-alias",
            ACME_HOST,
            "-p",
            "127.0.0.1::9443",
            "-v",
            &mount,
            RUNTIME,
            "sh",
            "-c",
            &script,
        ],
        60,
    );
    assert!(started.status.success(), "{}", text(&started.stderr));
    let uri = wait_for("the pairing URI", 30, || {
        let logs = docker(&["logs", &name], 30);
        let logs = text(&logs.stdout) + &text(&logs.stderr);
        let line = logs.lines().find(|line| line.contains("pairing URI: "))?;
        Some(line.split("pairing URI: ").nth(1)?.trim().to_owned())
    });
    let port = text(&docker(&["port", &name, "9443/tcp"], 30).stdout);
    let api = Api {
        uri: PairingUri::parse(SCHEME, &uri).unwrap(),
        address: port.lines().next().unwrap().trim().parse().unwrap(),
    };
    (name, api)
}

/// The step-ca pid inside the broker's container, once its ACME directory answers.
fn step_ca_serving(broker: &str) -> String {
    wait_for("step-ca's ACME directory", 60, || {
        let probe = docker(
            &[
                "exec",
                broker,
                "curl",
                "-sfk",
                "-o",
                "/dev/null",
                "https://localhost/acme/acme/directory",
            ],
            30,
        );
        probe.status.success().then_some(())?;
        let pid = docker(&["exec", broker, "pgrep", "-x", "step-ca"], 30);
        Some(text(&pid.stdout).trim().to_owned()).filter(|pid| !pid.is_empty())
    })
}

/// lego for `domain` over http-01; the certificate chain it got, or its error output.
fn lego(run: &mut Docker, out: &Path, role: &str, domain: &str) -> Result<Vec<Vec<u8>>, String> {
    let name = run.name(role);
    let mount = format!("{}:/out", out.display());
    let server = format!("https://{ACME_HOST}/acme/acme/directory");
    let ran = docker(
        &[
            "run",
            "--rm",
            "--name",
            &name,
            "--network",
            &run.prefix,
            "--network-alias",
            domain,
            "-v",
            &mount,
            "-e",
            "LEGO_CA_CERTIFICATES=/out/root.pem",
            LEGO,
            "--server",
            &server,
            "--email",
            "ops@home.example",
            "--accept-tos",
            "--domains",
            domain,
            "--http",
            "--path",
            "/out/lego",
            "run",
        ],
        180,
    );
    if !ran.status.success() {
        return Err(text(&ran.stderr) + &text(&ran.stdout));
    }
    let bundle = std::fs::read_to_string(out.join(format!("lego/certificates/{domain}.crt")))
        .map_err(|e| e.to_string())?;
    Ok(pem::certificates(&bundle)
        .unwrap()
        .into_iter()
        .map(|der| der.to_vec())
        .collect())
}

async fn as_operator(
    api: &Api,
    operator: &Identity,
    method: &str,
    route: &str,
    body: &str,
) -> String {
    let (code, answer) = api.call(Some(operator), method, route, body).await.unwrap();
    assert_eq!(code, 200, "{method} {route}: {answer}");
    answer
}

fn first_der(chain_pem: &str) -> Vec<u8> {
    pem::certificates(chain_pem).unwrap()[0].to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn step_ca_issues_inside_the_policy_and_reloads_on_a_renewal() {
    let Some(bin) = enabled() else {
        return;
    };
    let mut run = Docker::new();
    let (broker, api) = start_broker(&mut run, &bin);
    let logs = |broker: &str| {
        let logs = docker(&["logs", broker], 30);
        text(&logs.stdout) + &text(&logs.stderr)
    };

    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (code, body) = api.call(None, "GET", path::ENROLMENT, "").await.unwrap();
    assert_eq!(code, 200, "{body}");
    let offer: EnrolmentOffer = serde_json::from_str(&body).unwrap();
    let (chain, _, id) = ca.sign(&offer.csr_pem, DOMAINS);
    let mut enrolment = Enrolment {
        code: api.uri.code().expose().into(),
        chain_pem: chain.clone(),
        operator_pin: operator.key_pin(),
        config: api.enrolment(&chain, DOMAINS).config,
    };
    enrolment.config.challenges = vec![Challenge::Http01];
    let (code, body) = api.post(&enrolment).await;
    assert_eq!(code, 200, "{body}");

    let pid = step_ca_serving(&broker);
    let status: Status =
        serde_json::from_str(&as_operator(&api, &operator, "GET", path::STATUS, "").await).unwrap();
    assert_eq!(status.state, IssuerState::Issuing, "{}", logs(&broker));
    assert_eq!(status.versions.step_ca, "0.28.1");

    let out = tempfile::tempdir().unwrap();
    let root = pem::certificates(&chain).unwrap().pop().unwrap();
    std::fs::write(
        out.path().join("root.pem"),
        pem::encode("CERTIFICATE", &root),
    )
    .unwrap();

    let issued = lego(&mut run, out.path(), "lego-in", "app.home.example")
        .unwrap_or_else(|e| panic!("{e}\n{}", logs(&broker)));
    assert_eq!(issued[1], first_der(&chain));
    let refused = lego(&mut run, out.path(), "lego-out", "app.other.example");
    assert!(refused.is_err(), "issued outside the policy");

    let fresh: FreshCsr =
        serde_json::from_str(&as_operator(&api, &operator, "POST", path::CSR, "").await).unwrap();
    let (renewed, serial) = ca.renew(id, &fresh.csr_pem);
    let update = serde_json::to_string(&ChainUpdate {
        chain_pem: renewed.clone(),
        config: enrolment.config.clone(),
    })
    .unwrap();
    let answered: Status =
        serde_json::from_str(&as_operator(&api, &operator, "PUT", path::CHAIN, &update).await)
            .unwrap();
    assert_eq!(answered.subordinate_serial, serial);
    assert_eq!(
        step_ca_serving(&broker),
        pid,
        "step-ca was restarted, not reloaded"
    );

    let reissued = lego(&mut run, out.path(), "lego-renewed", "www.home.example")
        .unwrap_or_else(|e| panic!("{e}\n{}", logs(&broker)));
    assert_eq!(reissued[1], first_der(&renewed));
    assert_ne!(reissued[1], issued[1]);

    as_operator(&api, &operator, "POST", path::REVOKE, "").await;
    wait_for("step-ca to stop on revoke", 30, || {
        let found = docker(&["exec", &broker, "pgrep", "-x", "step-ca"], 30);
        (!found.status.success()).then_some(())
    });
}

const PRIVILEGES: &str = r#"set -u
useradd --system --no-create-home opca-acme
useradd --no-create-home other
install -d -m 700 -o opca-acme -g opca-acme /state
printf 'host = "acme.home.example"\nlisten = "127.0.0.1:9443"\nstate_dir = "/state"\nstep_ca = "/opt/opca/step-ca"\nacme_listen = "127.0.0.1:8443"\n' > /etc/broker.toml
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
    let Some(bin) = enabled() else {
        return;
    };
    let mut run = Docker::new();
    let name = run.name("cli");
    let mount = format!("{}:/opt/opca:ro", bin.display());
    let ran = docker(
        &[
            "run", "--rm", "--name", &name, "-v", &mount, RUNTIME, "sh", "-c", PRIVILEGES,
        ],
        120,
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

const SYSTEMD: &str = "debian:bookworm";
const STEP_CA_DEB: &str = "https://github.com/smallstep/certificates/releases/download/v0.28.1/step-ca_0.28.1-1_$(dpkg --print-architecture).deb";

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

#[tokio::test(flavor = "multi_thread")]
async fn the_deb_installs_and_runs_under_systemd() {
    let Some(_) = enabled() else {
        return;
    };
    let deb = std::env::var("OPCA_ACME_DOCKER_DEB").expect("OPCA_ACME_DOCKER_DEB");
    let mut run = Docker::new();
    let host = run.name("systemd");
    let mount = format!("{deb}:/deb:ro");
    let boot = "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                systemd systemd-sysv dbus curl ca-certificates procps > /dev/null && exec /sbin/init";
    let started = docker(
        &[
            "run",
            "-d",
            "--rm",
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
            "-v",
            &mount,
            SYSTEMD,
            "sh",
            "-c",
            boot,
        ],
        60,
    );
    assert!(started.status.success(), "{}", text(&started.stderr));
    wait_for("systemd to boot", 300, || {
        let state = docker(&["exec", &host, "systemctl", "is-system-running"], 30);
        let state = text(&state.stdout);
        ["running", "degraded"]
            .contains(&state.trim())
            .then_some(())
    });

    let installed = shell(
        &host,
        &format!(
            "curl -fsSLo /tmp/step-ca.deb {STEP_CA_DEB}
             DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/step-ca.deb /deb/*.deb
             echo enabled=$(systemctl is-enabled opca-acme-broker) active=$(systemctl is-active opca-acme-broker || true)
             id opca-acme"
        ),
        300,
    );
    assert!(
        installed.contains("enabled=disabled active=inactive"),
        "{installed}"
    );
    assert!(
        installed.contains("set host in /etc/opca-acme/broker.toml"),
        "{installed}"
    );

    shell(
        &host,
        "sed -i 's/^#host = .*/host = \"acme.home.example\"/' /etc/opca-acme/broker.toml
         systemctl enable --now opca-acme-broker
         [ \"$(systemctl is-active opca-acme-broker)\" = active ]",
        60,
    );
    let uri = shell(&host, "opca-acme pairing", 30);
    let status = shell(&host, "opca-acme status", 30);
    assert!(
        status.contains("mode: enrolling") && status.contains("broker: running"),
        "{status}"
    );
    shell(
        &host,
        "systemctl reload opca-acme-broker
         for _ in $(seq 50); do
             journalctl -u opca-acme-broker | grep -q 'reloaded the state from disk' && exit 0
             sleep 0.2
         done
         exit 1",
        30,
    );

    let port = text(&docker(&["port", &host, "9443/tcp"], 30).stdout);
    let api = Api {
        uri: PairingUri::parse(SCHEME, uri.trim()).unwrap(),
        address: port.lines().next().unwrap().trim().parse().unwrap(),
    };
    let mut ca = TestCa::new();
    let operator = ca.client("opCA operator");
    let (_, body) = api.call(None, "GET", path::ENROLMENT, "").await.unwrap();
    let offer: EnrolmentOffer = serde_json::from_str(&body).unwrap();
    let (chain, _, _) = ca.sign(&offer.csr_pem, DOMAINS);
    let enrolment = Enrolment {
        operator_pin: operator.key_pin(),
        ..api.enrolment(&chain, DOMAINS)
    };
    let (code, body) = api.post(&enrolment).await;
    assert_eq!(code, 200, "{body}");

    let issuing = shell(
        &host,
        "for _ in $(seq 100); do
             curl -sfk -o /dev/null https://localhost/acme/acme/directory && break
             sleep 0.2
         done
         curl -sfk -o /dev/null https://localhost/acme/acme/directory
         echo step-ca-user=$(ps -o user= -C step-ca)
         echo root-owned=$(find /var/lib/opca-acme -user root | wc -l)
         opca-acme status",
        60,
    );
    for expected in [
        "step-ca-user=opca-acme",
        "root-owned=0",
        "mode: enrolled",
        "step-ca: running",
    ] {
        assert!(issuing.contains(expected), "{expected}:\n{issuing}");
    }

    let stopped = shell(
        &host,
        "start=$(date +%s)
         systemctl stop opca-acme-broker
         echo seconds=$(( $(date +%s) - start ))
         echo result=$(systemctl show -p Result --value opca-acme-broker)
         echo step-ca=$(pgrep -x step-ca | wc -l)",
        60,
    );
    assert!(
        stopped.contains("result=success") && stopped.contains("step-ca=0"),
        "{stopped}"
    );
    let seconds: u64 = stopped
        .lines()
        .find_map(|line| line.strip_prefix("seconds="))
        .unwrap()
        .parse()
        .unwrap();
    assert!(seconds < 30, "{stopped}");
}
