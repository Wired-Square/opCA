//! Subject Alternative Names: parsing user input, and reading them back out of
//! certificates and CSRs.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::str::FromStr;

use foreign_types::ForeignType;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName as SanBuilder;
use openssl::x509::{GeneralName, GeneralNameRef, X509Ref, X509ReqRef};

use crate::error::OpcaError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectAltName {
    Dns(String),
    Ip(IpAddr),
    Email(String),
    Uri(String),
}

impl SubjectAltName {
    pub fn add_to(&self, builder: &mut SanBuilder) {
        match self {
            Self::Dns(v) => builder.dns(v),
            Self::Ip(ip) => builder.ip(&ip.to_string()),
            Self::Email(v) => builder.email(v),
            Self::Uri(v) => builder.uri(v),
        };
    }

    /// OpenSSL's `DNS:` / `IP:` / `email:` / `URI:` form, as stored in the `san` column.
    pub fn tagged(&self) -> String {
        match self {
            Self::Dns(v) => format!("DNS:{v}"),
            Self::Ip(ip) => format!("IP:{ip}"),
            Self::Email(v) => format!("email:{v}"),
            Self::Uri(v) => format!("URI:{v}"),
        }
    }

    fn from_general_name(name: &GeneralNameRef) -> Option<Self> {
        if let Some(v) = name.dnsname() {
            return Some(Self::Dns(v.to_string()));
        }
        if let Some(bytes) = name.ipaddress() {
            return match bytes.len() {
                4 => <[u8; 4]>::try_from(bytes).ok().map(|b| Self::Ip(Ipv4Addr::from(b).into())),
                16 => <[u8; 16]>::try_from(bytes).ok().map(|b| Self::Ip(Ipv6Addr::from(b).into())),
                _ => None,
            };
        }
        if let Some(v) = name.email() {
            return Some(Self::Email(v.to_string()));
        }
        name.uri().map(|v| Self::Uri(v.to_string()))
    }
}

impl fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(v) | Self::Email(v) | Self::Uri(v) => f.write_str(v),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Classifies as IP, then email (has `@`), then URI (`scheme://…` or `urn:…`),
/// then DNS name. The frontend's `lib/san.ts` applies the same rules.
impl FromStr for SubjectAltName {
    type Err = OpcaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = s.trim();
        let invalid = |why: &str| OpcaError::InvalidCertificate(format!("Invalid SAN '{v}': {why}"));
        if v.is_empty() {
            return Err(invalid("empty"));
        }
        if let Ok(ip) = v.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if let Some((local, domain)) = v.split_once('@') {
            if local.is_empty() || !local.bytes().all(|b| b.is_ascii_graphic() && b != b'@') {
                return Err(invalid("not a valid email address"));
            }
            if !is_dns_name(domain, false) {
                return Err(invalid("email domain is not a valid hostname"));
            }
            return Ok(Self::Email(v.to_string()));
        }
        if is_uri(v) {
            return Ok(Self::Uri(v.to_string()));
        }
        if is_dns_name(v, true) {
            return Ok(Self::Dns(v.to_string()));
        }
        Err(invalid("not a valid hostname, IP address, email or URI"))
    }
}

/// Requiring `://` (or `urn:`) keeps `host:port` from reading as a URI.
fn is_uri(v: &str) -> bool {
    let rest = match v.split_once("://") {
        Some((scheme, rest)) => {
            let mut chars = scheme.chars();
            let valid_scheme = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
            if !valid_scheme {
                return false;
            }
            rest
        }
        None if v.len() > 4 && v[..4].eq_ignore_ascii_case("urn:") => &v[4..],
        None => return false,
    };
    !rest.is_empty() && v.bytes().all(|b| b.is_ascii_graphic())
}

/// RFC 1123 hostname; a wildcard is allowed only as the whole first label, and
/// an all-numeric last label is refused so a mistyped IP isn't taken as a name.
fn is_dns_name(v: &str, allow_wildcard: bool) -> bool {
    let name = match v.strip_prefix("*.") {
        Some(rest) if allow_wildcard => rest,
        _ => v,
    };
    name.len() <= 253
        && !name.rsplit('.').next().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

pub fn of_certificate(cert: &X509Ref) -> Vec<SubjectAltName> {
    cert.subject_alt_names()
        .map(|names| names.iter().filter_map(SubjectAltName::from_general_name).collect())
        .unwrap_or_default()
}

pub fn of_csr(csr: &X509ReqRef) -> Vec<SubjectAltName> {
    let Ok(extensions) = csr.extensions() else {
        return Vec::new();
    };
    // SAFETY: X509V3_get_d2i returns a newly allocated GENERAL_NAMES (or null),
    // whose ownership the Stack takes.
    let names = unsafe {
        let raw = openssl_sys::X509V3_get_d2i(
            extensions.as_ptr(),
            openssl_sys::NID_subject_alt_name,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if raw.is_null() {
            return Vec::new();
        }
        Stack::<GeneralName>::from_ptr(raw.cast())
    };
    names.iter().filter_map(SubjectAltName::from_general_name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_valid_input() {
        for (input, expected) in [
            ("www.example.com", SubjectAltName::Dns("www.example.com".into())),
            ("*.example.com", SubjectAltName::Dns("*.example.com".into())),
            ("localhost", SubjectAltName::Dns("localhost".into())),
            ("10.0.0.5", SubjectAltName::Ip("10.0.0.5".parse().unwrap())),
            ("2001:db8::1", SubjectAltName::Ip("2001:db8::1".parse().unwrap())),
            ("ops@example.com", SubjectAltName::Email("ops@example.com".into())),
            ("spiffe://prod/web", SubjectAltName::Uri("spiffe://prod/web".into())),
            ("https://example.com/id", SubjectAltName::Uri("https://example.com/id".into())),
            ("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", SubjectAltName::Uri("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66".into())),
        ] {
            assert_eq!(input.parse::<SubjectAltName>().unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn rejects_invalid_input() {
        for input in [
            "", "   ", "10.0.0.300", "1.2.3", "a@b@c", "@example.com", "user@bad_domain",
            "user@*.example.com", "-bad.example.com", "bad-.example.com", "foo..com",
            "no-scheme/path", "example.com:443", "https://", "has space.com", "*.*.example.com",
            "www.*.example.com",
        ] {
            assert!(input.parse::<SubjectAltName>().is_err(), "{input:?} should be rejected");
        }
    }

    #[test]
    fn a_63_character_label_is_the_limit() {
        assert!(is_dns_name(&"a".repeat(63), false));
        assert!(!is_dns_name(&"a".repeat(64), false));
    }
}
