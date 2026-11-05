use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opca_acme_api::Challenge;
use opca_acme_broker::acme::ProblemType;
use opca_acme_broker::acme::validate::{Ports, Validator, digest};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use wslib_crypto::{Fingerprint, KeyAlgorithm, Signer};
use wslib_dns::{FakeResolver, LookupError, RecordType};

const NAME: &str = "device.home.example";
const OTHER: &str = "elsewhere.home.example";
const TOKEN: &str = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
const KEY_AUTHORISATION: &str =
    "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypzEt62jcerQ";
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_openssl::default_provider())
}

fn resolver() -> FakeResolver {
    FakeResolver::new()
        .with_ip(NAME, [LOOPBACK])
        .with_ip(OTHER, [LOOPBACK])
}

fn validator(resolver: FakeResolver, ports: Ports) -> Validator<FakeResolver> {
    Validator::new(resolver, provider())
        .unwrap()
        .with_ports(ports)
        .with_timeout(Duration::from_secs(2))
}

/// What a test server saw of one request.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    path: String,
    host: String,
}

type Respond = Arc<dyn Fn(&Seen) -> String + Send + Sync>;

fn answer(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n{body}",
        body.len()
    )
}

fn ok(body: &str) -> String {
    answer("200 OK", "", body)
}

fn redirect(location: &str) -> String {
    answer("302 Found", &format!("location: {location}\r\n"), "")
}

async fn serve_http<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    respond: &Respond,
    log: &Mutex<Vec<Seen>>,
) {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    let path = head.split(' ').nth(1).unwrap_or_default().to_string();
    let host = head
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap_or_default()
        .to_string();
    let seen = Seen { path, host };
    let response = respond(&seen);
    log.lock().unwrap().push(seen);
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// A loopback HTTP server, or HTTPS when given a TLS config; returns its port and what it saw.
async fn server(tls: Option<Arc<ServerConfig>>, respond: Respond) -> (u16, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (respond, log, tls) = (respond.clone(), log.clone(), tls.clone());
            tokio::spawn(async move {
                match tls {
                    Some(config) => {
                        if let Ok(stream) = TlsAcceptor::from(config).accept(tcp).await {
                            serve_http(stream, &respond, &log).await;
                        }
                    }
                    None => serve_http(tcp, &respond, &log).await,
                }
            });
        }
    });
    (port, seen)
}

async fn http(
    respond: impl Fn(&Seen) -> String + Send + Sync + 'static,
) -> (u16, Arc<Mutex<Vec<Seen>>>) {
    server(None, Arc::new(respond)).await
}

fn key() -> (Signer, PrivateKeyDer<'static>) {
    let key = KeyAlgorithm::EcP256.generate().unwrap();
    let signer = Signer::new(provider(), &PrivateKeyDer::Pkcs8(key.clone_key())).unwrap();
    (signer, PrivateKeyDer::Pkcs8(key))
}

/// A self-signed certificate for `names`, with an acmeIdentifier of `identifier` marked `critical`, if any.
fn certificate(
    names: &[&str],
    identifier: Option<(&[u8], bool)>,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let (signer, key) = key();
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&[1]));
    if let Some((digest, critical)) = identifier {
        let mut extension = rcgen::CustomExtension::new_acme_identifier(digest);
        extension.set_criticality(critical);
        params.custom_extensions.push(extension);
    }
    (params.self_signed(&signer).unwrap().der().clone(), key)
}

fn tls_config(
    pair: (CertificateDer<'static>, PrivateKeyDer<'static>),
    alpn: &[&[u8]],
) -> Arc<ServerConfig> {
    tls_config_for(pair, alpn, rustls::DEFAULT_VERSIONS)
}

/// Served through a resolver: `with_single_cert` refuses an unknown critical extension.
fn tls_config_for(
    (certificate, key): (CertificateDer<'static>, PrivateKeyDer<'static>),
    alpn: &[&[u8]],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let provider = provider();
    let signing = provider.key_provider.load_private_key(key).unwrap();
    let certified = CertifiedKey::new(vec![certificate], signing);
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// A port nothing listens on.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn http_01(ports: Ports) -> Result<(), ProblemType> {
    validator(resolver(), ports)
        .validate(Challenge::Http01, NAME, KEY_AUTHORISATION)
        .await
        .map_err(|problem| problem.kind)
}

fn http_only(http: u16) -> Ports {
    Ports { http, https: 1 }
}

#[tokio::test]
async fn http_01_passes_on_the_key_authorisation_and_asks_for_the_token_by_name() {
    let (port, seen) = http(|_| ok(&format!("{KEY_AUTHORISATION}\r\n"))).await;
    assert_eq!(http_01(http_only(port)).await, Ok(()));
    assert_eq!(
        *seen.lock().unwrap(),
        [Seen {
            path: format!("/.well-known/acme-challenge/{TOKEN}"),
            host: NAME.into(),
        }]
    );
}

#[tokio::test]
async fn http_01_refuses_another_body_an_error_status_or_an_oversized_body() {
    let (wrong, _) = http(|_| ok("something else")).await;
    assert_eq!(
        http_01(http_only(wrong)).await,
        Err(ProblemType::IncorrectResponse)
    );
    let (missing, _) = http(|_| answer("404 Not Found", "", "")).await;
    assert_eq!(
        http_01(http_only(missing)).await,
        Err(ProblemType::Unauthorized)
    );
    let (oversized, _) = http(|_| ok(&format!("{KEY_AUTHORISATION}{}", " ".repeat(2000)))).await;
    assert_eq!(
        http_01(http_only(oversized)).await,
        Err(ProblemType::IncorrectResponse)
    );
}

#[tokio::test]
async fn http_01_follows_redirects_to_http_and_https_on_their_ports() {
    let (https, seen_https) = server(
        Some(tls_config(
            certificate(&["anything.example"], None),
            &[b"http/1.1"],
        )),
        Arc::new(|_| ok(KEY_AUTHORISATION)),
    )
    .await;
    let (http, seen_http) = http(move |seen| {
        if seen.path.starts_with("/.well-known/") {
            redirect("/moved")
        } else {
            redirect(&format!("https://{OTHER}:{https}/final"))
        }
    })
    .await;

    assert_eq!(http_01(Ports { http, https }).await, Ok(()));
    let paths: Vec<String> = seen_http
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        paths,
        [
            format!("/.well-known/acme-challenge/{TOKEN}"),
            "/moved".into()
        ]
    );
    assert_eq!(
        *seen_https.lock().unwrap(),
        [Seen {
            path: "/final".into(),
            host: OTHER.into()
        }]
    );
}

#[tokio::test]
async fn http_01_refuses_a_redirect_off_port_off_scheme_to_an_address_or_without_end() {
    let target = |location: &'static str| async move {
        let (port, _) = http(move |_| redirect(location)).await;
        http_01(http_only(port)).await
    };
    for location in [
        "http://device.home.example:8080/x",
        "https://device.home.example:8443/x",
        "ftp://device.home.example/x",
        "http://127.0.0.1/x",
        "http://[::1]/x",
        "relative/path",
    ] {
        assert_eq!(
            target(location).await,
            Err(ProblemType::Connection),
            "{location}"
        );
    }
    let (looping, seen) = http(|_| redirect("/again")).await;
    assert_eq!(
        http_01(http_only(looping)).await,
        Err(ProblemType::Connection)
    );
    assert_eq!(seen.lock().unwrap().len(), 11);
}

#[tokio::test]
async fn http_01_fails_on_nothing_listening_a_silent_server_or_an_unknown_name() {
    assert_eq!(
        http_01(http_only(closed_port().await)).await,
        Err(ProblemType::Connection)
    );

    let silent = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let port = silent.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = silent.accept().await {
            held.push(tcp);
        }
    });
    let started = std::time::Instant::now();
    let refused = validator(resolver(), http_only(port))
        .with_timeout(Duration::from_millis(300))
        .validate(Challenge::Http01, NAME, KEY_AUTHORISATION)
        .await
        .unwrap_err();
    assert_eq!(refused.kind, ProblemType::Connection);
    assert!(started.elapsed() < Duration::from_secs(2));

    let refused = validator(FakeResolver::new(), http_only(port))
        .validate(Challenge::Http01, NAME, KEY_AUTHORISATION)
        .await
        .unwrap_err();
    assert_eq!(refused.kind, ProblemType::Dns);
}

#[test]
fn the_dns_01_digest_is_base64url_sha_256() {
    assert_eq!(digest("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
}

async fn dns_01(resolver: FakeResolver, name: &str) -> Result<(), ProblemType> {
    validator(resolver, Ports::default())
        .validate(Challenge::Dns01, name, KEY_AUTHORISATION)
        .await
        .map_err(|problem| problem.kind)
}

#[tokio::test]
async fn dns_01_passes_when_any_txt_record_holds_the_digest() {
    let expected = digest(KEY_AUTHORISATION);
    let records =
        FakeResolver::new().with_txt("_acme-challenge.home.example", ["stale", expected.as_str()]);
    assert_eq!(dns_01(records, "home.example").await, Ok(()));
    let records = FakeResolver::new().with_txt("_acme-challenge.home.example", [expected.as_str()]);
    assert_eq!(
        dns_01(records, "*.home.example").await,
        Ok(()),
        "a wildcard is validated at its base"
    );
}

#[tokio::test]
async fn dns_01_refuses_a_mismatch_an_absence_or_a_failed_lookup() {
    let record = "_acme-challenge.home.example";
    assert_eq!(
        dns_01(
            FakeResolver::new().with_txt(record, ["not it"]),
            "home.example"
        )
        .await,
        Err(ProblemType::IncorrectResponse)
    );
    assert_eq!(
        dns_01(FakeResolver::new(), "home.example").await,
        Err(ProblemType::Unauthorized)
    );
    let failing = FakeResolver::new().with_error(record, RecordType::Txt, LookupError::ServFail);
    assert_eq!(dns_01(failing, "home.example").await, Err(ProblemType::Dns));
}

async fn tls_alpn_01(config: Arc<ServerConfig>) -> Result<(), ProblemType> {
    let (https, _) = server(Some(config), Arc::new(|_| String::new())).await;
    validator(resolver(), Ports { http: 1, https })
        .validate(Challenge::TlsAlpn01, NAME, KEY_AUTHORISATION)
        .await
        .map_err(|problem| problem.kind)
}

fn key_authorisation_digest() -> Vec<u8> {
    Fingerprint::of(KEY_AUTHORISATION.as_bytes())
        .as_bytes()
        .to_vec()
}

#[tokio::test]
async fn tls_alpn_01_passes_on_a_certificate_for_the_name_with_the_critical_digest() {
    let digest = key_authorisation_digest();
    let config = tls_config(
        certificate(&[NAME], Some((&digest, true))),
        &[b"acme-tls/1"],
    );
    assert_eq!(tls_alpn_01(config).await, Ok(()));
}

#[tokio::test]
async fn tls_alpn_01_passes_over_tls_1_2_too() {
    let digest = key_authorisation_digest();
    let config = tls_config_for(
        certificate(&[NAME], Some((&digest, true))),
        &[b"acme-tls/1"],
        &[&rustls::version::TLS12],
    );
    assert_eq!(tls_alpn_01(config).await, Ok(()));
}

#[tokio::test]
async fn tls_alpn_01_fails_a_handshake_signed_by_another_key_than_the_certificates() {
    let digest = key_authorisation_digest();
    let (certificate, _) = certificate(&[NAME], Some((&digest, true)));
    let (_, other_key) = key();
    let config = tls_config((certificate, other_key), &[b"acme-tls/1"]);
    assert_eq!(tls_alpn_01(config).await, Err(ProblemType::Tls));
}

#[tokio::test]
async fn tls_alpn_01_needs_acme_tls_1_negotiated() {
    let digest = key_authorisation_digest();
    let good = || certificate(&[NAME], Some((&digest, true)));
    assert_eq!(
        tls_alpn_01(tls_config(good(), &[b"http/1.1"])).await,
        Err(ProblemType::Tls)
    );
    assert_eq!(
        tls_alpn_01(tls_config(good(), &[])).await,
        Err(ProblemType::Tls)
    );
}

#[tokio::test]
async fn tls_alpn_01_refuses_a_certificate_without_exactly_the_name_and_critical_digest() {
    let digest = key_authorisation_digest();
    let wrong = Fingerprint::of(b"another key authorisation")
        .as_bytes()
        .to_vec();
    for (names, identifier, case) in [
        (&[NAME][..], None, "no acmeIdentifier"),
        (
            &[NAME],
            Some((&digest[..], false)),
            "a non-critical acmeIdentifier",
        ),
        (&[NAME], Some((&wrong[..], true)), "the wrong digest"),
        (&[NAME, OTHER], Some((&digest[..], true)), "a second name"),
        (&[OTHER], Some((&digest[..], true)), "another name"),
    ] {
        let config = tls_config(certificate(names, identifier), &[b"acme-tls/1"]);
        assert_eq!(
            tls_alpn_01(config).await,
            Err(ProblemType::Unauthorized),
            "{case}"
        );
    }
}

#[tokio::test]
async fn tls_alpn_01_fails_to_connect_where_nothing_listens() {
    let refused = validator(
        resolver(),
        Ports {
            http: 1,
            https: closed_port().await,
        },
    )
    .validate(Challenge::TlsAlpn01, NAME, KEY_AUTHORISATION)
    .await
    .unwrap_err();
    assert_eq!(refused.kind, ProblemType::Connection);
}
