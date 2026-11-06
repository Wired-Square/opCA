//! The broker's Linux build in Docker: the command line's privilege drop, and
//! the `.deb` installed, enrolled and serving real ACME clients under systemd,
//! on a network of its own with an authoritative DNS server. Runs only
//! with `OPCA_ACME_DOCKER_TEST=1`, `OPCA_ACME_DOCKER_PLATFORM`, and
//! `OPCA_ACME_DOCKER_BIN` and `OPCA_ACME_DOCKER_DEB` naming that platform's
//! binaries and `.deb`; see `docker.sh`. The ApplianceOS app image runs as the
//! console would run it, with `OPCA_ACME_APP_IMAGE` naming its docker-load
//! tarball; see `scripts/build-acme-app.sh`.

#![cfg(unix)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use opca_acme_api::{
    Challenge, Enrolment, EnrolmentOffer, IssuanceConfig, IssuedPage, IssuerState, Status, path,
};
use opca_acme_broker::SCHEME;
use opca_acme_broker::app::{AppState, AppStatus, IssuedNewest};
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
    /// The network's first three octets: hosts below .128 are ours to assign.
    subnet: String,
    containers: Vec<String>,
    volumes: Vec<String>,
}

impl Docker {
    fn new() -> Self {
        static RUNS: AtomicUsize = AtomicUsize::new(0);
        let run = RUNS.fetch_add(1, Ordering::Relaxed);
        let prefix = format!("opca-e-{}-{run}", std::process::id());
        let first = std::process::id() as usize + run;
        let mut refusals = String::new();
        for subnet in (first..first + 8).map(|n| format!("10.231.{}", n % 256)) {
            let made = docker(
                &[
                    "network",
                    "create",
                    "--subnet",
                    &format!("{subnet}.0/24"),
                    "--ip-range",
                    &format!("{subnet}.128/25"),
                    &prefix,
                ],
                30,
            );
            if made.status.success() {
                return Self {
                    prefix,
                    subnet,
                    containers: Vec::new(),
                    volumes: Vec::new(),
                };
            }
            refusals += &text(&made.stderr);
        }
        panic!("no free subnet:\n{refusals}");
    }

    fn ip(&self, host: u8) -> String {
        format!("{}.{host}", self.subnet)
    }

    fn name(&mut self, role: &str) -> String {
        let name = format!("{}-{role}", self.prefix);
        self.containers.push(name.clone());
        name
    }

    fn volume(&mut self, role: &str) -> String {
        let name = format!("{}-{role}", self.prefix);
        let made = docker(&["volume", "create", &name], 30);
        assert!(made.status.success(), "{}", text(&made.stderr));
        self.volumes.push(name.clone());
        name
    }
}

impl Drop for Docker {
    fn drop(&mut self) {
        for container in &self.containers {
            docker(&["rm", "-f", container], 30);
        }
        for volume in &self.volumes {
            docker(&["volume", "rm", volume], 30);
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

const LEGO: &str = "goacme/lego:v4.25.2";
const CERTBOT: &str = "certbot/certbot:v4.2.0";
const ACME_SH: &str = "neilpang/acme.sh:3.1.1";
const KNOT: &str = "cznic/knot:3.4";
const DIRECTORY: &str = "https://acme.home.example/acme/directory";
/// One real client's whole run.
const CLIENT: u64 = 240;

const BROKER: u8 = 10;
const DNS: u8 = 53;
const LEGO_HTTP: u8 = 20;
const LEGO_ALPN: u8 = 21;
const CERTBOT_HTTP: u8 = 22;
/// The test zone's address records, as hosts on the test network.
const HOSTS: &[(&str, u8)] = &[
    ("acme", BROKER),
    ("ns", DNS),
    ("lego", LEGO_HTTP),
    ("alpn", LEGO_ALPN),
    ("certbot", CERTBOT_HTTP),
];

const TSIG_SECRET: &str = "b3BjYS1hY21lLWNvbmZvcm1hbmNlLXRlc3QtdHNpZy1rZXk=";

const KNOT_CONF: &str = r#"server:
    rundir: "/rundir"
    user: knot:knot
    listen: 0.0.0.0@53
log:
  - target: stdout
    any: info
key:
  - id: acme
    algorithm: hmac-sha256
    secret: TSIG_SECRET
acl:
  - id: update
    key: acme
    action: update
database:
    storage: "/storage"
zone:
  - domain: home.example
    file: /storage/home.example.zone
    acl: update
"#;

/// acme.sh's dns-01 hook for the restart: it publishes the TXT, then holds
/// the order open until the test has restarted the broker.
const PAUSE_HOOK: &str = r#"dns_pause_add() {
    printf 'server %s\nzone home.example.\nupdate add %s. 60 txt "%s"\nsend\n' \
        "$NSUPDATE_SERVER" "$1" "$2" | nsupdate -k "$NSUPDATE_KEY" || return 1
    touch /work/paused
    for _ in $(seq 120); do [ -f /work/resume ] && return 0; sleep 1; done
    return 1
}
dns_pause_rm() { :; }
"#;

/// The authoritative zone, TSIG key and hook the clients and the broker share at `/work`.
fn write_shared_files(run: &Docker, work: &Path) {
    let mut zone =
        "$ORIGIN home.example.\n$TTL 60\n@ SOA ns hostmaster 1 60 60 3600 60\n@ NS ns\n".to_owned();
    for (name, host) in HOSTS {
        zone += &format!("{name} A {}\n", run.ip(*host));
    }
    let files = [
        ("home.example.zone", zone),
        ("knot.conf", KNOT_CONF.replace("TSIG_SECRET", TSIG_SECRET)),
        (
            "tsig.key",
            format!("key \"acme\" {{\n algorithm hmac-sha256;\n secret \"{TSIG_SECRET}\";\n}};\n"),
        ),
        ("dns_pause.sh", PAUSE_HOOK.into()),
    ];
    for (name, contents) in files {
        std::fs::write(work.join(name), contents).unwrap();
    }
}

fn start_dns(run: &mut Docker, built: &Built, work: &str) {
    let dns = run.name("dns");
    let ip = run.ip(DNS);
    let started = docker(
        &[
            "run",
            "-d",
            "--rm",
            "--platform",
            &built.platform,
            "--name",
            &dns,
            "--network",
            &run.prefix,
            "--ip",
            &ip,
            "-v",
            work,
            KNOT,
            "sh",
            "-c",
            "cp /work/home.example.zone /storage/ && chown knot:knot /storage/* \
             && exec knotd -c /work/knot.conf",
        ],
        SLOW,
    );
    assert!(started.status.success(), "{}", text(&started.stderr));
    let broker = run.ip(BROKER);
    wait_for("the test zone to be served", 60, || {
        let answer = docker(
            &[
                "exec",
                &dns,
                "kdig",
                "+short",
                "@127.0.0.1",
                "acme.home.example",
            ],
            30,
        );
        (text(&answer.stdout).trim() == broker).then_some(())
    });
}

/// Real ACME clients on the test network, resolving through its DNS.
struct Clients<'a> {
    docker: &'a mut Docker,
    platform: &'a str,
    work: &'a str,
}

impl Clients<'_> {
    fn command(&mut self, role: &str, options: &[&str], image: &str, args: &[&str]) -> Vec<String> {
        let name = self.docker.name(role);
        let dns = self.docker.ip(DNS);
        let head = [
            "run",
            "--rm",
            "--platform",
            self.platform,
            "--name",
            &name,
            "--network",
            &self.docker.prefix,
            "--dns",
            &dns,
            "-v",
            self.work,
        ];
        [&head[..], options, &[image], args]
            .concat()
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn run(&mut self, role: &str, options: &[&str], image: &str, args: &[&str]) -> Output {
        run_client(&self.command(role, options, image, args))
    }

    fn lego(&mut self, role: &str, host: u8, args: &[&str]) -> Output {
        let ip = self.docker.ip(host);
        let common = [
            "--server",
            DIRECTORY,
            "--accept-tos",
            "--email",
            "ops@home.example",
            "--path",
            "/work/lego",
        ];
        let options = ["--ip", &ip, "-e", "LEGO_CA_CERTIFICATES=/work/root.pem"];
        self.run(role, &options, LEGO, &[&common[..], args].concat())
    }

    /// acme.sh issuing `names` over dns-01 through `hook`, updating the test zone.
    fn acme_sh(&mut self, role: &str, hook: &str, names: &[&str], options: &[&str]) -> Vec<String> {
        let server = format!("NSUPDATE_SERVER={}", self.docker.ip(DNS));
        let env = [
            "-e",
            &server,
            "-e",
            "NSUPDATE_KEY=/work/tsig.key",
            "-e",
            "NSUPDATE_ZONE=home.example",
        ];
        let mut args = vec![
            "acme.sh",
            "--issue",
            "--server",
            DIRECTORY,
            "--ca-bundle",
            "/work/root.pem",
            "--dns",
            hook,
            "--dnssleep",
            "1",
        ];
        for name in names {
            args.extend(["-d", name]);
        }
        self.command(role, &[&env[..], options].concat(), ACME_SH, &args)
    }
}

fn run_client(command: &[String]) -> Output {
    docker(
        &command.iter().map(String::as_str).collect::<Vec<_>>(),
        CLIENT,
    )
}

fn said(ran: &Output) -> String {
    format!("{}{}", text(&ran.stdout), text(&ran.stderr))
}

fn succeeded(what: &str, ran: &Output) {
    assert!(ran.status.success(), "{what} failed:\n{}", said(ran));
}

/// lego over http-01 and tls-alpn-01, with a renewal, a revocation and a refusal;
/// certbot over http-01; acme.sh over dns-01 for a wildcard, and again across a
/// restart of the broker mid-order.
fn run_real_clients(run: &mut Docker, built: &Built, host: &str, work: &Path) {
    let mount = format!("{}:/work", work.display());
    let mut clients = Clients {
        docker: run,
        platform: &built.platform,
        work: &mount,
    };
    let http = ["--domains", "lego.home.example", "--http"];
    succeeded(
        "lego http-01",
        &clients.lego("lego-http", LEGO_HTTP, &[&http[..], &["run"]].concat()),
    );
    succeeded(
        "lego tls-alpn-01",
        &clients.lego(
            "lego-alpn",
            LEGO_ALPN,
            &["--domains", "alpn.home.example", "--tls", "run"],
        ),
    );
    succeeded(
        "lego renewal",
        &clients.lego(
            "lego-renew",
            LEGO_HTTP,
            &[&http[..], &["renew", "--days", "45", "--no-random-sleep"]].concat(),
        ),
    );
    succeeded(
        "lego revocation",
        &clients.lego(
            "lego-revoke",
            LEGO_HTTP,
            &["--domains", "lego.home.example", "revoke", "--reason", "4"],
        ),
    );
    let outside = clients.lego(
        "lego-outside",
        LEGO_HTTP,
        &["--domains", "outside.example.net", "--http", "run"],
    );
    let refused = said(&outside);
    assert!(
        !outside.status.success() && refused.contains("rejectedIdentifier"),
        "{refused}"
    );

    let certbot_ip = clients.docker.ip(CERTBOT_HTTP);
    succeeded(
        "certbot http-01",
        &clients.run(
            "certbot",
            &[
                "--ip",
                &certbot_ip,
                "-e",
                "REQUESTS_CA_BUNDLE=/work/root.pem",
            ],
            CERTBOT,
            &[
                "certonly",
                "--standalone",
                "--non-interactive",
                "--agree-tos",
                "--register-unsafely-without-email",
                "--server",
                DIRECTORY,
                "-d",
                "certbot.home.example",
                "--config-dir",
                "/work/certbot",
                "--work-dir",
                "/tmp/certbot",
                "--logs-dir",
                "/tmp/certbot",
            ],
        ),
    );

    let wildcard = clients.acme_sh(
        "acme-sh-dns",
        "dns_nsupdate",
        &["dns.home.example", "*.dns.home.example"],
        &[],
    );
    succeeded("acme.sh dns-01", &run_client(&wildcard));

    let hook = format!(
        "{}/dns_pause.sh:/root/.acme.sh/dnsapi/dns_pause.sh:ro",
        work.display()
    );
    let paused = clients.acme_sh(
        "acme-sh-restart",
        "dns_pause",
        &["pause.home.example"],
        &["-v", &hook],
    );
    let client = std::thread::spawn(move || run_client(&paused));
    wait_for("acme.sh to hold its order open", CLIENT, || {
        work.join("paused").exists().then_some(())
    });
    shell(
        host,
        "systemctl restart opca-acme-broker
         for _ in $(seq 150); do
             curl -sfk -o /dev/null https://localhost/acme/directory && exit 0
             sleep 0.2
         done
         exit 1",
        120,
    );
    std::fs::write(work.join("resume"), "").unwrap();
    succeeded("acme.sh across a restart", &client.join().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_deb_installs_enrols_and_serves_real_acme_clients_under_systemd() {
    let Some(built) = enabled() else {
        return;
    };
    for image in [KNOT, LEGO, CERTBOT, ACME_SH] {
        let pulled = docker(&["pull", "-q", "--platform", &built.platform, image], SLOW);
        assert!(pulled.status.success(), "{}", text(&pulled.stderr));
    }
    let mut run = Docker::new();
    let work = tempfile::tempdir().unwrap();
    let work_mount = format!("{}:/work", work.path().display());
    write_shared_files(&run, work.path());
    start_dns(&mut run, &built, &work_mount);

    let host = run.name("systemd");
    let mount = format!("{}:/deb:ro", built.deb.display());
    let broker_ip = run.ip(BROKER);
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
            "--network",
            &run.prefix,
            "--ip",
            &broker_ip,
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
        &format!(
            "printf 'nameserver {}\\n' > /etc/resolv.conf
             sed -i 's/^#host = .*/host = \"acme.home.example\"/' /etc/opca-acme/broker.toml
             systemctl enable --now opca-acme-broker
             [ \"$(systemctl is-active opca-acme-broker)\" = active ]",
            run.ip(DNS)
        ),
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
    let offered = api.enrolment(&chain, DOMAINS);
    let enrolment = Enrolment {
        operator_pin: operator.key_pin(),
        config: IssuanceConfig {
            challenges: vec![Challenge::Http01, Challenge::Dns01, Challenge::TlsAlpn01],
            ..offered.config.clone()
        },
        ..offered
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
    assert_eq!(code, 200);
    let serving = shell(
        &host,
        "echo directory=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/acme/directory)
         echo acme-key=$(stat -c %a:%U /var/lib/opca-acme/acme.key)
         echo root-owned=$(find /var/lib/opca-acme -user root | wc -l)
         opca-acme status",
        60,
    );
    for expected in [
        "directory=200",
        "acme-key=600:opca-acme",
        "root-owned=0",
        "mode: enrolled",
    ] {
        assert!(serving.contains(expected), "{expected}:\n{serving}");
    }

    let root = pem::encode("CERTIFICATE", chain.last().unwrap());
    std::fs::write(work.path().join("root.pem"), root).unwrap();
    run_real_clients(&mut run, &built, &host, work.path());
    let (code, body) = api
        .call(Some(&operator), "GET", path::ISSUED, "")
        .await
        .unwrap();
    assert_eq!(code, 200, "{body}");
    let page: IssuedPage = serde_json::from_str(&body).unwrap();
    let mut issued: Vec<String> = page
        .certificates
        .iter()
        .map(|certificate| {
            let mut sans = certificate.sans.clone();
            sans.sort();
            sans.join(" ")
        })
        .collect();
    issued.sort();
    assert_eq!(
        issued,
        [
            "*.dns.home.example dns.home.example",
            "alpn.home.example",
            "certbot.home.example",
            "lego.home.example",
            "lego.home.example",
            "pause.home.example",
        ],
        "{body}"
    );
    let revoked: Vec<_> = page
        .certificates
        .iter()
        .filter(|certificate| certificate.revoked_at.is_some())
        .map(|certificate| (certificate.sans.clone(), certificate.revocation_reason))
        .collect();
    assert_eq!(
        revoked,
        [(vec!["lego.home.example".to_owned()], Some(4))],
        "{body}"
    );

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

/// The console's uid for an app is its own, not the image's.
const APP_USER: &str = "70000:0";
const APP_API_PORT: &str = "19443";

/// `GET path` on the app's socket from a container running as `user`, with `headers`: curl's output, the head included.
fn app_sock(socket: &str, user: &str, path: &str, headers: &[&str]) -> Output {
    let mount = format!("{socket}:/run/appliance");
    let url = format!("http://localhost{path}");
    let mut args = vec![
        "run", "--rm", "--user", user, "-v", &mount, RUNTIME, "curl", "-s", "-i",
    ];
    for header in headers {
        args.extend(["-H", header]);
    }
    args.extend(["--unix-socket", "/run/appliance/app.sock", &url]);
    docker(&args, 60)
}

const VIEWER: &str = "Appliance-Identity: v1; id=a1; user=someone; role=viewer";

/// As the console asks it, as root with `headers`: the status, the head and the body.
fn console_get(socket: &str, path: &str, headers: &[&str]) -> (u16, String, String) {
    let ran = app_sock(socket, "0:0", path, headers);
    let answer = text(&ran.stdout);
    let (head, body) = answer
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("{answer}"));
    (head[9..12].parse().unwrap(), head.into(), body.into())
}

/// The page and its API through `app.sock`, as the console proxies them for a viewer.
fn the_page_answers_a_viewer(socket: &str) {
    let (code, _, page) = console_get(socket, "/apps/opca-acme/", &[VIEWER]);
    assert_eq!(code, 200, "{page}");
    assert!(page.contains(r#"<base href="/apps/opca-acme/""#), "{page}");
    let script = page
        .split('"')
        .find(|part| part.starts_with("./assets/") && part.ends_with(".js"))
        .unwrap_or_else(|| panic!("no script in {page}"));
    let asset = format!("/apps/opca-acme/{}", &script[2..]);
    let (code, head, _) = console_get(socket, &asset, &[VIEWER, "Accept-Encoding: gzip"]);
    assert_eq!(code, 200, "{head}");
    assert!(
        head.to_lowercase().contains("content-encoding: gzip"),
        "{head}"
    );

    let (code, _, body) = console_get(socket, "/apps/opca-acme/api/status", &[VIEWER]);
    assert_eq!(code, 200, "{body}");
    let status: AppStatus = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (status.state, status.host.as_deref()),
        (AppState::Enrolled, Some("acme.home.example"))
    );
    assert!(status.subordinate.is_some(), "{body}");
    let (code, _, body) = console_get(socket, "/apps/opca-acme/api/issued", &[VIEWER]);
    assert_eq!(code, 200, "{body}");
    let issued: IssuedNewest = serde_json::from_str(&body).unwrap();
    assert_eq!(issued.before, None, "{body}");

    let (code, _, _) = console_get(socket, "/apps/opca-acme/api/status", &[]);
    assert_eq!(code, 401);

    let (code, _, body) = console_get(socket, "/apps/opca-acme/api/session", &[VIEWER]);
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(r#""role":"viewer""#), "{body}");
    let (code, _, body) = console_get(socket, "/apps/opca-acme/api/branding", &[VIEWER]);
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(r#""app_name":"opCA ACME broker""#), "{body}");
}

/// The status the page reads, once the app answers it in `state`.
fn wait_for_state(socket: &str, state: AppState) -> AppStatus {
    wait_for(&format!("the app to report {state:?}"), 120, || {
        let ran = app_sock(socket, "0:0", "/apps/opca-acme/api/status", &[VIEWER]);
        let answer = text(&ran.stdout);
        let (_, body) = answer.split_once("\r\n\r\n")?;
        serde_json::from_str(body)
            .ok()
            .filter(|status: &AppStatus| status.state == state)
    })
}

/// A plain HTTP GET of `path` at `address`: its status line and body.
fn plain_get(address: std::net::SocketAddr, path: &str) -> (String, String) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.lines().next().unwrap().into(), body.into())
}

const HOT_BACKUP: &str = r#"set -eu
hook() { curl -sf --unix-socket /run/appliance/hooks.sock -H 'Content-Type: application/json' "$@"; }
hook http://localhost/v1 | grep -q '"backup":true' && echo INDEX-SAYS-BACKUP
hook -X POST http://localhost/v1/backup/capture > /tmp/capture.json
grep -q '"format":"opca-acme-broker"' /tmp/capture.json && echo CAPTURED
hook -X POST --data-binary @/tmp/capture.json http://localhost/v1/backup/inspect > /tmp/inspection.json
grep -q '"blocked":{}' /tmp/inspection.json && echo NOTHING-BLOCKED
{ printf '{"chosen": {"app": ["acme", "enrolment"]}, "sections": '; cat /tmp/capture.json; printf '}'; } > /tmp/restore.json
hook -X POST --data-binary @/tmp/restore.json http://localhost/v1/backup/restore > /tmp/report.json
grep -q '"app":\["acme","enrolment"\]' /tmp/report.json && echo RESTORED
"#;

/// Captures, inspects and restores as the console would, through a container sharing the socket volume.
fn hot_backup_round_trip(socket: &str) {
    let mount = format!("{socket}:/run/appliance");
    let ran = docker(
        &["run", "--rm", "-v", &mount, RUNTIME, "sh", "-c", HOT_BACKUP],
        120,
    );
    let said = text(&ran.stdout);
    for step in [
        "INDEX-SAYS-BACKUP",
        "CAPTURED",
        "NOTHING-BLOCKED",
        "RESTORED",
    ] {
        assert!(
            said.contains(step),
            "{step}:\n{said}\n{}",
            text(&ran.stderr)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_app_image_needs_a_host_then_enrols() {
    let Ok(tarball) = std::env::var("OPCA_ACME_APP_IMAGE") else {
        eprintln!("skipped: set OPCA_ACME_APP_IMAGE to run the ApplianceOS app image");
        return;
    };
    let loaded = docker(&["load", "-q", "-i", &tarball], 120);
    assert!(loaded.status.success(), "{}", text(&loaded.stderr));
    let loaded = text(&loaded.stdout);
    let image = loaded
        .lines()
        .find_map(|line| line.strip_prefix("Loaded image: "))
        .unwrap_or_else(|| panic!("{loaded}"))
        .trim()
        .to_owned();
    let mut run = Docker::new();
    let (data, socket) = (run.volume("data"), run.volume("socket"));
    let app = run.name("app");
    let (data_mount, socket_mount) = (format!("{data}:/data"), format!("{socket}:/run/appliance"));
    let api_port = format!("APPLIANCE_LISTENER_API_PORT={APP_API_PORT}");
    let started = docker(
        &[
            "run",
            "-d",
            "--init",
            "--name",
            &app,
            "--network",
            &run.prefix,
            "--user",
            APP_USER,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "-v",
            &data_mount,
            "-v",
            &socket_mount,
            "-p",
            "127.0.0.1::9443",
            "-p",
            "127.0.0.1::8443",
            "-e",
            &api_port,
            &image,
        ],
        60,
    );
    assert!(started.status.success(), "{}", text(&started.stderr));

    wait_for_state(&socket, AppState::NeedsHost);
    let (code, _, body) = console_get(&socket, "/apps/opca-acme/healthz", &[]);
    assert_eq!(code, 200, "{body}");
    let foreign = app_sock(&socket, "4242:0", "/apps/opca-acme/api/status", &[VIEWER]);
    let foreign = text(&foreign.stdout);
    assert!(
        foreign.starts_with("HTTP/1.1 401"),
        "a uid that isn't the console's was heard: {foreign}"
    );
    for (port, path) in [
        ("9443/tcp", path::ENROLMENT),
        ("8443/tcp", "/acme/directory"),
    ] {
        let (status, body) = plain_get(published(&app, port), path);
        assert!(status.ends_with("503 Service Unavailable"), "{status}");
        assert!(body.contains("needs a host"), "{body}");
    }

    let options = format!(
        "printf '%s' '{{\"host\": \"acme.home.example\", \"domains\": [\"home.example\"]}}' \
         > /data/options.json && chown {APP_USER} /data/options.json"
    );
    let written = docker(
        &[
            "run",
            "--rm",
            "-v",
            &data_mount,
            RUNTIME,
            "sh",
            "-c",
            &options,
        ],
        60,
    );
    assert!(written.status.success(), "{}", text(&written.stderr));
    let restarted = docker(&["restart", "-t", "30", &app], 60);
    assert!(restarted.status.success(), "{}", text(&restarted.stderr));
    wait_for_state(&socket, AppState::Enrolling);

    let logs = docker(&["logs", &app], 30);
    let logs = text(&logs.stdout) + &text(&logs.stderr);
    let uri = logs
        .split_whitespace()
        .find(|word| word.starts_with("opca-enrol://"))
        .unwrap_or_else(|| panic!("no pairing URI logged:\n{logs}"));
    let api = Api {
        uri: PairingUri::parse(SCHEME, uri).unwrap(),
        address: published(&app, "9443/tcp"),
    };
    assert_eq!(api.uri.port(), 19443);
    let (_, body) = api.call(None, "GET", path::ENROLMENT, "").await.unwrap();
    let offer: EnrolmentOffer = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (offer.host.as_str(), offer.configured_domains.as_slice()),
        ("acme.home.example", &["home.example".to_owned()][..])
    );
    let mut ca = TestCa::new();
    let (chain, _, _) = ca.sign(&offer.csr_pem, DOMAINS);
    let (code, body) = api.post(&api.enrolment(&chain, DOMAINS)).await;
    assert_eq!(code, 200, "{body}");
    let status: Status = serde_json::from_str(&body).unwrap();
    assert_eq!(status.state, IssuerState::Issuing, "{body}");
    wait_for_state(&socket, AppState::Enrolled);
    the_page_answers_a_viewer(&socket);

    let chain = pem::certificates(&chain).unwrap();
    let (mut acme, presented) = acme_connect(published(&app, "8443/tcp"), chain.last().unwrap())
        .await
        .unwrap();
    assert_eq!(presented[1], chain[0]);
    let (code, _) = acme.call("GET", "/acme/directory", "").await.unwrap();
    assert_eq!(code, 200);
    hot_backup_round_trip(&socket);
    wait_for_state(&socket, AppState::Enrolled);

    let stopped = docker(&["stop", "-t", "30", &app], 60);
    assert!(stopped.status.success(), "{}", text(&stopped.stderr));
    let exit = docker(&["inspect", "-f", "{{.State.ExitCode}}", &app], 30);
    assert_eq!(text(&exit.stdout).trim(), "0", "{}", text(&exit.stderr));
}
