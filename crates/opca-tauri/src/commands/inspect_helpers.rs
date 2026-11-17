//! Helpers shared between the certificate and CSR Inspect commands.

use wslib_crypto_x509::KeyDescription;

/// In `CertificateBundle`'s vocabulary, so Inspect and the stored certificates agree.
pub fn key_type(key: &KeyDescription) -> String {
    match key {
        KeyDescription::Rsa { .. } => "RSA".to_string(),
        KeyDescription::Ecdsa { .. } => "EC".to_string(),
        KeyDescription::Ed25519 => "Ed25519".to_string(),
        KeyDescription::Other { oid } => oid.clone(),
        _ => "Unknown".to_string(),
    }
}

pub fn spki_fingerprint(spki: &[u8]) -> String {
    openssl::sha::sha256(spki)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Pasted PEM often arrives indented (from an email, a YAML file or a terminal); OpenSSL rejects that.
pub fn strip_line_indentation(pem: &str) -> String {
    pem.lines()
        .map(str::trim_start)
        .collect::<Vec<_>>()
        .join("\n")
}
