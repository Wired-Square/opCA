//! Challenge validation: http-01 and dns-01 (RFC 8555 §8.3, §8.4) and
//! tls-alpn-01 (RFC 8737), each given the name and the key authorisation.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode, Uri, header};
use hyper_util::rt::TokioIo;
use opca_acme_api::Challenge as ChallengeType;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use wslib_crypto::Fingerprint;
use wslib_dns::Resolver;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::ProblemType::{Connection, Dns, IncorrectResponse, Tls, Unauthorized};
use super::{Problem, base64url};

pub const ACME_TLS_1: &[u8] = b"acme-tls/1";
const ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";
/// Boulder's limit.
const MAX_REDIRECTS: usize = 10;
/// A key authorisation is 87 bytes; this leaves room for trailing whitespace and little else.
const MAX_BODY: usize = 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Where the challenges are answered: 80 and 443, except in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ports {
    pub http: u16,
    pub https: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Self {
            http: 80,
            https: 443,
        }
    }
}

pub struct Validator<R> {
    resolver: R,
    ports: Ports,
    timeout: Duration,
    redirected_tls: Arc<ClientConfig>,
    acme_tls: Arc<ClientConfig>,
}

impl<R: Resolver> Validator<R> {
    pub fn new(resolver: R, provider: Arc<CryptoProvider>) -> Result<Self, rustls::Error> {
        Ok(Self {
            resolver,
            ports: Ports::default(),
            timeout: TIMEOUT,
            redirected_tls: trusting_any(provider.clone(), b"http/1.1")?,
            acme_tls: trusting_any(provider, ACME_TLS_1)?,
        })
    }

    pub fn with_ports(self, ports: Ports) -> Self {
        Self { ports, ..self }
    }

    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// Whether `name` answers a challenge of `kind` with `key_authorisation`, `token.thumbprint`.
    pub async fn validate(
        &self,
        kind: ChallengeType,
        name: &str,
        key_authorisation: &str,
    ) -> Result<(), Problem> {
        let validating = async {
            match kind {
                ChallengeType::Http01 => self.http_01(name, key_authorisation).await,
                ChallengeType::Dns01 => self.dns_01(name, key_authorisation).await,
                ChallengeType::TlsAlpn01 => self.tls_alpn_01(name, key_authorisation).await,
            }
        };
        tokio::time::timeout(self.timeout, validating)
            .await
            .unwrap_or_else(|_| {
                Err(Problem::new(
                    Connection,
                    format!(
                        "{name} did not answer within {} s",
                        self.timeout.as_secs_f32()
                    ),
                ))
            })
    }

    async fn http_01(&self, name: &str, key_authorisation: &str) -> Result<(), Problem> {
        let token = key_authorisation.split('.').next().unwrap_or_default();
        let mut target = Target {
            https: false,
            host: name.to_string(),
            port: self.ports.http,
            path: format!("/.well-known/acme-challenge/{token}"),
        };
        for _ in 0..=MAX_REDIRECTS {
            let response = self.get(&target).await?;
            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|location| location.to_str().ok())
                    .ok_or_else(|| {
                        Problem::new(Connection, format!("{target} redirected nowhere"))
                    })?;
                target = self.redirect(&target, location)?;
                continue;
            }
            if status != StatusCode::OK {
                return Err(Problem::new(
                    Unauthorized,
                    format!("{target} answered {status}"),
                ));
            }
            let body = Limited::new(response.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|e| match e.downcast_ref::<LengthLimitError>() {
                    Some(_) => Problem::new(
                        IncorrectResponse,
                        format!("{target} answered more than {MAX_BODY} bytes"),
                    ),
                    None => Problem::new(Connection, format!("reading {target}: {e}")),
                })?
                .to_bytes();
            let body = String::from_utf8_lossy(&body);
            return if body.trim_end() == key_authorisation {
                Ok(())
            } else {
                Err(Problem::new(
                    IncorrectResponse,
                    format!("{target} answered {body:?}, not the key authorisation"),
                ))
            };
        }
        Err(Problem::new(
            Connection,
            format!("{name} redirected more than {MAX_REDIRECTS} times"),
        ))
    }

    async fn get(&self, target: &Target) -> Result<Response<Incoming>, Problem> {
        let tcp = self.connect(&target.host, target.port).await?;
        let request = Request::get(&target.path)
            .header(header::HOST, &target.host)
            .header(header::USER_AGENT, "opca-acme-broker")
            .body(Empty::<Bytes>::new())
            .map_err(|e| Problem::new(Connection, format!("{target}: {e}")))?;
        let sent = if target.https {
            let tls = TlsConnector::from(self.redirected_tls.clone())
                .connect(server_name(&target.host)?, tcp)
                .await
                .map_err(|e| Problem::new(Tls, format!("{target}: {e}")))?;
            send(TokioIo::new(tls), request, self.timeout).await
        } else {
            send(TokioIo::new(tcp), request, self.timeout).await
        };
        sent.map_err(|e| Problem::new(Connection, format!("{target}: {e}")))
    }

    /// Only to a DNS name over http on the http port, or https on the https port.
    fn redirect(&self, from: &Target, location: &str) -> Result<Target, Problem> {
        let refuse = |why: &str| {
            Err(Problem::new(
                Connection,
                format!("{from} redirected to {location:?}, {why}"),
            ))
        };
        let Ok(uri) = location.parse::<Uri>() else {
            return refuse("which is not a URL");
        };
        let path = uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_string();
        let Some(scheme) = uri.scheme_str() else {
            return if location.starts_with('/') {
                Ok(Target {
                    path,
                    ..from.clone()
                })
            } else {
                refuse("a relative path")
            };
        };
        let (https, port) = match scheme {
            "http" => (false, self.ports.http),
            "https" => (true, self.ports.https),
            _ => return refuse("which is neither http nor https"),
        };
        if uri.port_u16().is_some_and(|asked| asked != port) {
            return refuse(&format!("a port other than {port}"));
        }
        let host = uri.host().unwrap_or_default().to_ascii_lowercase();
        if host.is_empty() || host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
            return refuse("which does not name a DNS host");
        }
        Ok(Target {
            https,
            host,
            port,
            path,
        })
    }

    async fn dns_01(&self, name: &str, key_authorisation: &str) -> Result<(), Problem> {
        let base = name.strip_prefix("*.").unwrap_or(name);
        let record = format!("_acme-challenge.{base}");
        let expected = digest(key_authorisation);
        match self.resolver.txt(&record).await {
            Ok(answer) => {
                let found: Vec<String> = answer.records.iter().map(|txt| txt.joined()).collect();
                if found.contains(&expected) {
                    Ok(())
                } else {
                    Err(Problem::new(
                        IncorrectResponse,
                        format!("{record} holds {found:?}, not {expected:?}"),
                    ))
                }
            }
            Err(e) if e.is_absent() => Err(Problem::new(
                Unauthorized,
                format!("{record} has no TXT record: {e}"),
            )),
            Err(e) => Err(Problem::new(Dns, format!("looking up {record}: {e}"))),
        }
    }

    async fn tls_alpn_01(&self, name: &str, key_authorisation: &str) -> Result<(), Problem> {
        let port = self.ports.https;
        let tcp = self.connect(name, port).await?;
        let tls = TlsConnector::from(self.acme_tls.clone())
            .connect(server_name(name)?, tcp)
            .await
            .map_err(|e| Problem::new(Tls, format!("{name}:{port}: {e}")))?;
        let (_, session) = tls.get_ref();
        if session.alpn_protocol() != Some(ACME_TLS_1) {
            return Err(Problem::new(
                Tls,
                format!("{name}:{port} did not negotiate acme-tls/1"),
            ));
        }
        let certificate = session
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| Problem::new(Tls, format!("{name}:{port} sent no certificate")))?;
        check_validation_certificate(certificate, name, key_authorisation)
            .map_err(|why| Problem::new(Unauthorized, format!("{name}:{port}'s certificate {why}")))
    }

    async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, Problem> {
        let addresses = self
            .resolver
            .ip(host)
            .await
            .map_err(|e| Problem::new(Dns, format!("looking up {host}: {e}")))?
            .records;
        let mut refused = None;
        for address in addresses {
            match TcpStream::connect((address, port)).await {
                Ok(tcp) => return Ok(tcp),
                Err(e) => refused = Some(e),
            }
        }
        Err(Problem::new(
            Connection,
            format!(
                "connecting to {host} on port {port}: {}",
                refused.map_or_else(|| "no address".into(), |e| e.to_string())
            ),
        ))
    }
}

/// RFC 8737 §3: exactly one SAN, the name, and the critical acmeIdentifier holding the key authorisation's SHA-256.
fn check_validation_certificate(
    der: &CertificateDer<'_>,
    name: &str,
    key_authorisation: &str,
) -> Result<(), String> {
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|e| format!("does not decode: {e}"))?;
    let sans = certificate
        .subject_alternative_name()
        .map_err(|e| format!("has an unreadable SAN: {e}"))?
        .map(|extension| extension.value.general_names.as_slice())
        .unwrap_or_default();
    match sans {
        [GeneralName::DNSName(only)] if only.eq_ignore_ascii_case(name) => {}
        _ => return Err(format!("names {sans:?}, not just {name}")),
    }
    let identifier = certificate
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == ACME_IDENTIFIER)
        .ok_or("has no acmeIdentifier")?;
    if !identifier.critical {
        return Err("has an acmeIdentifier that is not critical".into());
    }
    let digest = Fingerprint::of(key_authorisation.as_bytes());
    if identifier.value != [&[0x04, 0x20][..], digest.as_bytes()].concat() {
        return Err("has an acmeIdentifier that is not the key authorisation's digest".into());
    }
    Ok(())
}

/// What a dns-01 TXT record holds: base64url(SHA-256(key authorisation)).
pub fn digest(key_authorisation: &str) -> String {
    base64url(Fingerprint::of(key_authorisation.as_bytes()).as_bytes())
}

#[derive(Clone, Debug)]
struct Target {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = if self.https { "https" } else { "http" };
        write!(f, "{scheme}://{}:{}{}", self.host, self.port, self.path)
    }
}

/// One request on a connection of its own, which is left to close within `timeout`.
async fn send<T>(
    io: T,
    request: Request<Empty<Bytes>>,
    timeout: Duration,
) -> Result<Response<Incoming>, hyper::Error>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(tokio::time::timeout(timeout, connection));
    sender.send_request(request).await
}

fn server_name(host: &str) -> Result<ServerName<'static>, Problem> {
    ServerName::try_from(host.to_string()).map_err(|e| {
        Problem::new(
            Connection,
            format!("{host} is not a name TLS can send: {e}"),
        )
    })
}

/// A validator looks only at what is presented, so any certificate is taken; the handshake's own signatures are still checked.
fn trusting_any(
    provider: Arc<CryptoProvider>,
    alpn: &[u8],
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl AnyCertificate {
    /// Against the certificate's key alone: rustls's own check parses the
    /// certificate with webpki, which refuses the critical acmeIdentifier.
    fn verify_by_key(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let refused = rustls::Error::InvalidCertificate(CertificateError::BadSignature);
        let (_, certificate) = X509Certificate::from_der(cert).map_err(|_| refused.clone())?;
        let key = &certificate.public_key().subject_public_key.data;
        self.0
            .signature_verification_algorithms
            .mapping
            .iter()
            .filter(|(scheme, _)| *scheme == dss.scheme)
            .flat_map(|(_, algorithms)| algorithms.iter())
            .any(|algorithm| {
                algorithm
                    .verify_signature(key, message, dss.signature())
                    .is_ok()
            })
            .then(HandshakeSignatureValid::assertion)
            .ok_or(refused)
    }
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_by_key(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_by_key(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
