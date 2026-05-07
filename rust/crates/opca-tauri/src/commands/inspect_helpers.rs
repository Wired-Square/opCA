//! Helpers shared between the certificate / CSR / CRL Inspect commands.
//!
//! The three `inspect_*` commands all need to: render an RFC-4514-flavoured
//! DN, recover the signature algorithm string from an openssl text dump, and
//! summarise a public key (type + bits + SHA-256 fingerprint). Centralising
//! the helpers keeps the three commands consistent if openssl-rs grows
//! structured APIs for any of these later.

use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Public};
use openssl::x509::X509NameRef;

/// Build a flattened DN: leaf-first `short-name=value` tokens joined by
/// commas, matching `get_certificate_attrib("subject")` on `CertificateBundle`.
pub fn x509_name_to_rdn_string(name: &X509NameRef) -> String {
    let mut entries: Vec<String> = name
        .entries()
        .filter_map(|e| {
            let nid = e.object().nid();
            let sn = nid.short_name().unwrap_or("??");
            e.data().as_utf8().ok().map(|v| format!("{sn}={v}"))
        })
        .collect();
    entries.reverse();
    entries.join(",")
}

/// Recover the signature algorithm name from an `openssl ... -text` dump.
/// openssl-rs doesn't expose `signature_algorithm()` on `X509Req` or
/// `X509Crl`, so all three inspectors fall back to scanning the text dump.
pub fn signature_algorithm_from_text(text: &str) -> String {
    text.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("Signature Algorithm:")
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Identify the public-key algorithm and return its bit size plus a
/// colon-separated lowercase hex SHA-256 fingerprint of the DER encoding.
pub fn public_key_summary(key: &PKey<Public>) -> Result<(String, u32, String), String> {
    let key_type = if key.rsa().is_ok() {
        "RSA"
    } else if key.ec_key().is_ok() {
        "EC"
    } else if key.dsa().is_ok() {
        "DSA"
    } else {
        "Unknown"
    }
    .to_string();

    let key_size = key.bits();

    let pub_der = key
        .public_key_to_der()
        .map_err(|e| format!("Failed to encode public key: {e}"))?;
    let mut hasher =
        Hasher::new(MessageDigest::sha256()).map_err(|e| format!("Hasher init: {e}"))?;
    hasher
        .update(&pub_der)
        .map_err(|e| format!("Hash update: {e}"))?;
    let hash = hasher
        .finish()
        .map_err(|e| format!("Hash finish: {e}"))?;
    let fingerprint = hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");

    Ok((key_type, key_size, fingerprint))
}
